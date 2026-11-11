//! Read-after-write on an edge (docs/EDGE.md 11.4): what the edge knows about transactions that
//! were executed through it and that it has not applied yet.
//!
//! - `ExecMode`: `hold` keeps the execute answer back until the edge applied the transaction;
//!   `reads` answers at once and makes only the reads that could see the transaction's writes
//!   wait; `off` does neither.
//! - `Pending`: the table. Per transaction digest, when it was executed and (mode `reads`) the
//!   object ids it wrote and the addresses whose owned-object or balance view it changed. A
//!   read asks `touch` with the ids and addresses it names; the forwarder's tick drops what the
//!   store now holds (`resolve`) and wakes the waiters.
//! - The write set is exact: it is read from the BCS `TransactionEffects` in the execute answer
//!   (`writesOf`). When the client's read mask does not select `effects.bcs`, the edge adds that
//!   one path to the request it sends the core (`withEffectsBcs`) and takes the field out of
//!   the answer again (`stripEffectsBcs`), so the client gets the bytes the core would have sent
//!   for the client's own mask. When the edge cannot have the effects (no room to add the path,
//!   an answer it cannot read), that execute is held instead: never a guessed set.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const bcs = @import("bcs");
const types = @import("types");

pub const ExecMode = enum {
    /// Answer as soon as the core does; reads are not made to wait.
    off,
    /// Hold a successful execute answer until the edge has applied the transaction, at most
    /// `--edge-execute-wait-ms`. One serve worker per held execute.
    hold,
    /// Answer at once; a read that touches what the transaction wrote waits (same bound), then
    /// is passed to the core if the edge still has not applied it.
    reads,

    pub fn parse(text: []const u8) ?ExecMode {
        return std.meta.stringToEnum(ExecMode, text);
    }
};

pub const StopFn = struct { ctx: *anyopaque, f: *const fn (ctx: *anyopaque) bool };

/// How often a waiting thread looks at its client (a client that left, a deadline): waits are
/// event-driven, this only bounds how long a cancelled call keeps its thread.
pub const slice_ns: u64 = 20 * std.time.ns_per_ms;

fn monoNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const Kind = enum(u8) { object, address };
/// Something a read can name: an object id (also the parent of a dynamic field), or an address.
pub const Key = struct { kind: Kind, id: [32]u8 };

/// What one transaction wrote, as far as reads are concerned.
pub const Writes = struct {
    /// Every object created, mutated, deleted, wrapped or unwrapped, and the parent object of
    /// every dynamic field among them.
    objects: []const [32]u8 = &.{},
    /// The sender, and every address that owned one of those objects before or owns it after
    /// (its owned-object list and its balances), and every address-balance account written.
    addresses: []const [32]u8 = &.{},
};

/// Transactions executed through this edge whose checkpoint the edge has not applied yet, and
/// the apply notification. The follower's commit calls `applied` (one atomic add and a wake);
/// `resolve` (the forwarder's tick) drops the digests the store now holds and wakes the waiters.
pub const Pending = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    map: std.AutoHashMapUnmanaged([32]u8, Entry) = .empty,
    keys: std.AutoHashMapUnmanaged(Key, Slot) = .empty,
    /// Entries in `map`, readable without the lock: a read path pays one load while nothing is
    /// pending (`idle`).
    n: Atomic(usize) = .init(0),
    /// Bumped by every commit (`applied`): the tick waits on it.
    commits: Atomic(u32) = .init(0),
    /// Bumped when `resolve` removed something: waiters sleep on it.
    ev: Atomic(u32) = .init(0),
    /// An entry older than this is dropped unapplied (a transaction that never reached a
    /// checkpoint the edge saw): no read waits or forwards for it after that.
    ttl_ns: u64 = 30 * std.time.ns_per_s,
    /// Bounds: transactions, and keys over all of them. Past either, `addWrites` refuses and
    /// the caller holds that execute instead; nothing already in the table is dropped for it.
    max: usize = 4096,
    max_keys: usize = 1 << 16,
    n_keys: usize = 0,
    /// `resolve`'s copy of the digests (the tick thread only).
    scan: std.ArrayList(Cand) = .empty,

    const Cand = struct { digest: [32]u8, added: u64, gone: bool = false };

    const Entry = struct {
        added: u64,
        /// A read naming this digest waits until then (0: `hold`'s entry, nobody waits on it).
        until: u64 = 0,
        keys: []Key = &.{},
    };
    const Slot = struct {
        refs: u32,
        /// The latest end of a wait among the transactions that wrote this key.
        until: u64,
    };

    pub const AppliedFn = struct {
        ctx: *anyopaque,
        /// True once the edge serves the transaction (its checkpoint is at or under the tip).
        f: *const fn (ctx: *anyopaque, digest: *const [32]u8) bool,
    };

    pub fn deinit(p: *Pending) void {
        var it = p.map.valueIterator();
        while (it.next()) |e| p.gpa.free(e.keys);
        p.map.deinit(p.gpa);
        p.keys.deinit(p.gpa);
        p.scan.deinit(p.gpa);
    }

    /// Nothing is pending (one atomic load).
    pub inline fn idle(p: *const Pending) bool {
        return p.n.load(.acquire) == 0;
    }

    /// The follower committed a checkpoint. Cheap: called on the commit path.
    pub fn applied(p: *Pending) void {
        _ = p.commits.fetchAdd(1, .release);
        p.io.futexWake(u32, &p.commits.raw, std.math.maxInt(u32));
    }

    /// `hold`: the digest alone (no read waits on it).
    pub fn add(p: *Pending, digest: *const [32]u8, now_ns: u64) void {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        if (p.map.count() >= p.max or p.map.contains(digest.*)) return;
        p.map.put(p.gpa, digest.*, .{ .added = now_ns }) catch return;
        p.n.store(p.map.count(), .release);
    }

    /// `reads`: the digest with what it wrote; reads touching any of it wait until `until_ns`.
    /// False when the table has no room (or no memory): the caller holds that execute instead.
    pub fn addWrites(p: *Pending, digest: *const [32]u8, now_ns: u64, until_ns: u64, w: Writes) bool {
        const total = w.objects.len + w.addresses.len;
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        if (p.map.contains(digest.*)) return true; // executed twice through this edge: one entry
        if (p.map.count() >= p.max or total > p.max_keys -| p.n_keys) return false;
        const ks = p.gpa.alloc(Key, total) catch return false;
        for (w.objects, ks[0..w.objects.len]) |*id, *k| k.* = .{ .kind = .object, .id = id.* };
        for (w.addresses, ks[w.objects.len..]) |*id, *k| k.* = .{ .kind = .address, .id = id.* };
        p.keys.ensureUnusedCapacity(p.gpa, @intCast(total)) catch {
            p.gpa.free(ks);
            return false;
        };
        p.map.put(p.gpa, digest.*, .{ .added = now_ns, .until = until_ns, .keys = ks }) catch {
            p.gpa.free(ks);
            return false;
        };
        for (ks) |k| {
            const g = p.keys.getOrPutAssumeCapacity(k);
            if (g.found_existing) {
                g.value_ptr.refs += 1;
                g.value_ptr.until = @max(g.value_ptr.until, until_ns);
            } else g.value_ptr.* = .{ .refs = 1, .until = until_ns };
        }
        p.n_keys += total;
        p.n.store(p.map.count(), .release);
        return true;
    }

    pub fn contains(p: *Pending, digest: *const [32]u8) bool {
        if (p.idle()) return false;
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        return p.map.contains(digest.*);
    }

    /// Under `mu`.
    fn dropLocked(p: *Pending, digest: *const [32]u8) bool {
        const kv = p.map.fetchRemove(digest.*) orelse return false;
        for (kv.value.keys) |k| {
            const s = p.keys.getPtr(k) orelse continue;
            s.refs -= 1;
            if (s.refs == 0) _ = p.keys.remove(k);
        }
        p.n_keys -|= kv.value.keys.len;
        p.gpa.free(kv.value.keys);
        return true;
    }

    fn wake(p: *Pending) void {
        _ = p.ev.fetchAdd(1, .release);
        p.io.futexWake(u32, &p.ev.raw, std.math.maxInt(u32));
    }

    pub fn remove(p: *Pending, digest: *const [32]u8) void {
        p.mu.lockUncancelable(p.io);
        const gone = p.dropLocked(digest);
        p.n.store(p.map.count(), .release);
        p.mu.unlock(p.io);
        if (gone) p.wake();
    }

    /// Drops the digests `ap` says are applied and the ones past `ttl_ns`; wakes the waiters
    /// when anything left. Returns how many were applied. One caller at a time (the tick). The
    /// store is asked without the table's lock: reads looking the table up never wait behind it.
    pub fn resolve(p: *Pending, now_ns: u64, ap: AppliedFn) usize {
        if (p.idle()) return 0;
        p.scan.clearRetainingCapacity();
        {
            p.mu.lockUncancelable(p.io);
            defer p.mu.unlock(p.io);
            p.scan.ensureTotalCapacity(p.gpa, p.map.count()) catch {};
            var it = p.map.iterator();
            while (it.next()) |kv| {
                if (p.scan.items.len == p.scan.capacity) break; // no memory: the rest next time
                p.scan.appendAssumeCapacity(.{ .digest = kv.key_ptr.*, .added = kv.value_ptr.added });
            }
        }
        var n_gone: usize = 0;
        var n_applied: usize = 0;
        for (p.scan.items) |*c| {
            if (ap.f(ap.ctx, &c.digest)) {
                c.gone = true;
                n_applied += 1;
            } else if (now_ns -| c.added > p.ttl_ns) c.gone = true;
            if (c.gone) n_gone += 1;
        }
        if (n_gone == 0) return 0;
        {
            p.mu.lockUncancelable(p.io);
            defer p.mu.unlock(p.io);
            for (p.scan.items) |*c| if (c.gone) {
                _ = p.dropLocked(&c.digest);
            };
            p.n.store(p.map.count(), .release);
        }
        p.wake();
        return n_applied;
    }

    /// `hold`: waits until `digest` has left the table or `timeout_ns` passed (or `stop` says
    /// so). True: it left. Sleeps on `ev`.
    pub fn wait(p: *Pending, digest: *const [32]u8, timeout_ns: u64, stop: ?StopFn) bool {
        const t0 = monoNs();
        while (true) {
            const seen = p.ev.load(.acquire);
            if (!p.contains(digest)) return true;
            const spent = monoNs() -| t0;
            if (spent >= timeout_ns) return false;
            if (stop) |s| if (s.f(s.ctx)) return false;
            const left = @min(timeout_ns - spent, slice_ns);
            p.io.futexWaitTimeout(u32, &p.ev.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(@intCast(left)), .clock = .awake } }) catch {};
        }
    }

    pub const Touch = union(enum) {
        /// Nothing pending wrote what the read names: answer as usual.
        clear,
        /// A pending transaction did, and its wait is still open until this time.
        wait: u64,
        /// A pending transaction did, and its wait is over: the edge's answer would be stale.
        late,
    };

    /// What the pending transactions mean for a read that names `keys` (and `digest`, for a
    /// read of a transaction). Call only when not `idle`.
    pub fn touch(p: *Pending, keys: []const Key, digest: ?*const [32]u8, now_ns: u64) Touch {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        var until: u64 = 0;
        var hit = false;
        for (keys) |k| if (p.keys.get(k)) |s| {
            hit = true;
            until = @max(until, s.until);
        };
        if (digest) |d| if (p.map.get(d.*)) |e| if (e.until != 0) {
            hit = true;
            until = @max(until, e.until);
        };
        if (!hit) return .clear;
        return if (now_ns < until) .{ .wait = until } else .late;
    }

    /// Waits until nothing pending touches `keys` / `digest` (true), or their wait is over, or
    /// `stop` says so (false). Sleeps on `ev`.
    pub fn waitClear(p: *Pending, keys: []const Key, digest: ?*const [32]u8, stop: ?StopFn) bool {
        while (true) {
            const seen = p.ev.load(.acquire);
            if (p.idle()) return true;
            const now = monoNs();
            switch (p.touch(keys, digest, now)) {
                .clear => return true,
                .late => return false,
                .wait => |until| {
                    if (stop) |s| if (s.f(s.ctx)) return false;
                    const left = @min(until - now, slice_ns);
                    p.io.futexWaitTimeout(u32, &p.ev.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromNanoseconds(@intCast(@max(left, 1))), .clock = .awake } }) catch {};
                },
            }
        }
    }
};

// ---------------------------------------------------------------- the write set

fn addUnique(list: *std.ArrayList([32]u8), a: Allocator, id: [32]u8) Allocator.Error!void {
    for (list.items) |*x| if (std.mem.eql(u8, x, &id)) return;
    try list.append(a, id);
}

fn ownerInto(a: Allocator, objects: *std.ArrayList([32]u8), addresses: *std.ArrayList([32]u8), owner: types.Owner) Allocator.Error!void {
    switch (owner) {
        .AddressOwner => |x| try addUnique(addresses, a, x.@"0"),
        // a dynamic field (or a child object): its parent's field list changes
        .ObjectOwner => |x| try addUnique(objects, a, x.@"0"),
        .ConsensusAddressOwner => |x| try addUnique(addresses, a, x.owner.@"0"),
        .Shared, .Immutable, .Party => {},
    }
}

/// The write set of a transaction from its BCS `TransactionEffects` (and its BCS
/// `TransactionData` when the request carried it, for the sender). Slices live in `a`.
pub fn writesOf(a: Allocator, effects_bcs: []const u8, tx_data: ?[]const u8) !Writes {
    var objects: std.ArrayList([32]u8) = .empty;
    var addresses: std.ArrayList([32]u8) = .empty;
    const eff = try bcs.decode(types.TransactionEffects, a, effects_bcs);
    switch (eff) {
        .V2 => |v| for (v.changed_objects) |c| {
            try addUnique(&objects, a, c[0].@"0".@"0");
            switch (c[1].input_state) {
                .NotExist => {},
                .Exist => |x| try ownerInto(a, &objects, &addresses, x[1]),
            }
            switch (c[1].output_state) {
                .NotExist, .PackageWrite => {},
                .ObjectWrite => |x| try ownerInto(a, &objects, &addresses, x[1]),
                .AccumulatorWriteV1 => |x| try addUnique(&addresses, a, x.address.address.@"0"),
            }
        },
        .V1 => |v| {
            inline for (.{ v.created, v.mutated, v.unwrapped }) |list| for (list) |c| {
                try addUnique(&objects, a, c[0][0].@"0".@"0");
                try ownerInto(a, &objects, &addresses, c[1]);
            };
            inline for (.{ v.deleted, v.unwrapped_then_deleted, v.wrapped }) |list| for (list) |c| try addUnique(&objects, a, c[0].@"0".@"0");
            try addUnique(&objects, a, v.gas_object[0][0].@"0".@"0");
            try ownerInto(a, &objects, &addresses, v.gas_object[1]);
        },
    }
    if (tx_data) |raw| if (bcs.decode(types.TransactionData, a, raw)) |td| switch (td) {
        .V1 => |v| try addUnique(&addresses, a, v.sender.@"0"),
    } else |_| {};
    return .{ .objects = objects.items, .addresses = addresses.items };
}

// ---------------------------------------------------------------- the read mask, and the answer

const Field = struct { number: u32, wire: u3, start: usize, body: usize, end: usize };

/// The fields of a protobuf message with their byte ranges (`start..end` the whole field,
/// `body..end` a length-delimited field's payload).
const Fields = struct {
    b: []const u8,
    pos: usize = 0,

    fn varint(it: *Fields) !u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (it.pos >= it.b.len or shift > 63) return error.Malformed;
            const c = it.b[it.pos];
            it.pos += 1;
            v |= @as(u64, c & 0x7f) << @intCast(shift);
            if (c & 0x80 == 0) return v;
            shift += 7;
        }
    }

    fn next(it: *Fields) !?Field {
        if (it.pos >= it.b.len) return null;
        const start = it.pos;
        const tag = try it.varint();
        const wire: u3 = @intCast(tag & 7);
        var body = it.pos;
        switch (wire) {
            0 => _ = try it.varint(),
            1 => it.pos += 8,
            5 => it.pos += 4,
            2 => {
                const n = try it.varint();
                body = it.pos;
                if (n > it.b.len - it.pos) return error.Malformed;
                it.pos += @intCast(n);
            },
            else => return error.Malformed,
        }
        if (it.pos > it.b.len) return error.Malformed;
        return .{ .number = @intCast(tag >> 3), .wire = wire, .start = start, .body = body, .end = it.pos };
    }
};

fn putVarint(out: *std.ArrayList(u8), a: Allocator, value: u64) !void {
    var v = value;
    while (v >= 0x80) : (v >>= 7) try out.append(a, @as(u8, @truncate(v)) | 0x80);
    try out.append(a, @truncate(v));
}

/// How an ExecuteTransactionRequest's read mask relates to `effects.bcs`.
pub const MaskUse = struct {
    /// The answer will carry `effects.bcs` as the client asked (no mask at all: the default
    /// mask is `effects`). Also true whenever this cannot tell, so nothing is added or removed.
    has_bcs: bool,
    /// The client selected something under `effects` (the `effects` message is in its answer).
    any_effects: bool,
};

/// ExecuteTransactionRequest { transaction = 1, signatures = 2, read_mask = 3 { paths = 1 } }.
pub fn maskUse(request: []const u8) MaskUse {
    var seen_mask = false;
    var use: MaskUse = .{ .has_bcs = false, .any_effects = false };
    var it: Fields = .{ .b = request };
    while (it.next() catch return .{ .has_bcs = true, .any_effects = true }) |f| {
        if (f.number != 3 or f.wire != 2) continue;
        seen_mask = true;
        var ps: Fields = .{ .b = request[f.body..f.end] };
        while (ps.next() catch return .{ .has_bcs = true, .any_effects = true }) |p| {
            if (p.number != 1 or p.wire != 2) continue;
            const path = ps.b[p.body..p.end];
            if (std.mem.eql(u8, path, "*") or std.mem.eql(u8, path, "effects") or std.mem.startsWith(u8, path, "effects.bcs")) use.has_bcs = true;
            if (std.mem.eql(u8, path, "effects") or std.mem.startsWith(u8, path, "effects.")) use.any_effects = true;
        }
    }
    if (!seen_mask) return .{ .has_bcs = true, .any_effects = true };
    return use;
}

/// One more `read_mask` occurrence naming `effects.bcs` (a repeated message field merges: the
/// paths add up).
const extra_mask = "\x1a\x0d\x0a\x0beffects.bcs";

/// The request to send the core so its answer carries `effects.bcs`: `request` with one more
/// read mask path. Null when the result would not be a request the core accepts as it would
/// have accepted the client's (tonic's 4 MiB decode limit).
pub fn withEffectsBcs(a: Allocator, request: []const u8) !?[]u8 {
    if (request.len + extra_mask.len > (4 << 20)) return null;
    const out = try a.alloc(u8, request.len + extra_mask.len);
    @memcpy(out[0..request.len], request);
    @memcpy(out[request.len..], extra_mask);
    return out;
}

/// `payload` (an ExecuteTransactionResponse) without `transaction.effects.bcs`
/// (ExecuteTransactionResponse.transaction = 1, ExecutedTransaction.effects = 4,
/// TransactionEffects.bcs = 1). `keep_effects`: the client selected other paths under `effects`,
/// so the (possibly empty) `effects` message stays; otherwise it goes with its only field. Every
/// other byte is copied; the lengths around the removed field are written again in their
/// shortest form, as the core's encoder writes them.
pub fn stripEffectsBcs(a: Allocator, payload: []const u8, keep_effects: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    try dropAt(&out, a, payload, &.{ 1, 4, 1 }, keep_effects);
    return out.items;
}

fn dropAt(out: *std.ArrayList(u8), a: Allocator, msg: []const u8, path: []const u32, keep_parent: bool) !void {
    var it: Fields = .{ .b = msg };
    while (try it.next()) |f| {
        if (f.number != path[0] or f.wire != 2) {
            try out.appendSlice(a, msg[f.start..f.end]);
            continue;
        }
        if (path.len == 1) continue; // the field itself
        var inner: std.ArrayList(u8) = .empty;
        defer inner.deinit(a);
        try dropAt(&inner, a, msg[f.body..f.end], path[1..], keep_parent);
        // the parent of the removed field goes with it when that was all it held
        if (path.len == 2 and inner.items.len == 0 and !keep_parent) continue;
        try putVarint(out, a, (@as(u64, f.number) << 3) | 2);
        try putVarint(out, a, inner.items.len);
        try out.appendSlice(a, inner.items);
    }
}

/// The bytes of the length-delimited field at `path` (last occurrence at each level).
pub fn nested(msg: []const u8, path: []const u32) ?[]const u8 {
    var cur = msg;
    for (path) |n| {
        var found: ?[]const u8 = null;
        var it: Fields = .{ .b = cur };
        while (it.next() catch return null) |f| if (f.number == n and f.wire == 2) {
            found = cur[f.body..f.end];
        };
        cur = found orelse return null;
    }
    return cur;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn tid(b: u8) [32]u8 {
    return @splat(b);
}

test "pending: reads wait on what a transaction wrote, until it is applied or its wait is over" {
    var p: Pending = .{ .gpa = testing.allocator, .io = testing.io };
    defer p.deinit();
    const s = std.time.ns_per_s;
    try testing.expect(p.idle());
    const obj: Key = .{ .kind = .object, .id = tid(1) };
    const addr: Key = .{ .kind = .address, .id = tid(1) }; // the same bytes as an address are another key
    const other: Key = .{ .kind = .object, .id = tid(9) };
    try testing.expect(p.addWrites(&tid(0xd1), 10 * s, 12 * s, .{ .objects = &.{ tid(1), tid(2) }, .addresses = &.{tid(7)} }));
    try testing.expect(!p.idle());
    try testing.expectEqual(@as(usize, 3), p.n_keys);
    // inside the wait: wait until its end; other keys are clear
    try testing.expectEqual(Pending.Touch{ .wait = 12 * s }, p.touch(&.{obj}, null, 11 * s));
    try testing.expectEqual(Pending.Touch.clear, p.touch(&.{other}, null, 11 * s));
    try testing.expectEqual(Pending.Touch.clear, p.touch(&.{addr}, null, 11 * s));
    try testing.expectEqual(Pending.Touch{ .wait = 12 * s }, p.touch(&.{ other, .{ .kind = .address, .id = tid(7) } }, null, 11 * s));
    try testing.expectEqual(Pending.Touch{ .wait = 12 * s }, p.touch(&.{}, &tid(0xd1), 11 * s));
    try testing.expectEqual(Pending.Touch.clear, p.touch(&.{}, &tid(0xd2), 11 * s));
    // past it: late (the edge's answer would be stale), until the entry leaves
    try testing.expectEqual(Pending.Touch.late, p.touch(&.{obj}, null, 12 * s));
    // a second transaction on the same object: its wait counts
    try testing.expect(p.addWrites(&tid(0xd2), 13 * s, 15 * s, .{ .objects = &.{tid(1)} }));
    try testing.expectEqual(Pending.Touch{ .wait = 15 * s }, p.touch(&.{obj}, null, 14 * s));
    // the first is applied: the object is still pending for the second
    const Ap = struct {
        var done: [32]u8 = @splat(0);
        fn f(_: *anyopaque, d: *const [32]u8) bool {
            return std.mem.eql(u8, d, &done);
        }
    };
    var unit: u8 = 0;
    Ap.done = tid(0xd1);
    try testing.expectEqual(@as(usize, 1), p.resolve(14 * s, .{ .ctx = &unit, .f = Ap.f }));
    try testing.expectEqual(Pending.Touch{ .wait = 15 * s }, p.touch(&.{obj}, null, 14 * s));
    try testing.expectEqual(Pending.Touch.clear, p.touch(&.{.{ .kind = .object, .id = tid(2) }}, null, 14 * s));
    try testing.expectEqual(@as(usize, 1), p.n_keys);
    // the second never lands: dropped at the hard expiry, and the object is clear again
    Ap.done = tid(0);
    try testing.expectEqual(@as(usize, 0), p.resolve(13 * s + p.ttl_ns, .{ .ctx = &unit, .f = Ap.f }));
    try testing.expect(!p.idle());
    try testing.expectEqual(@as(usize, 0), p.resolve(13 * s + p.ttl_ns + 1, .{ .ctx = &unit, .f = Ap.f }));
    try testing.expect(p.idle());
    try testing.expectEqual(@as(usize, 0), p.n_keys);
    try testing.expectEqual(@as(u32, 0), p.keys.count());
}

test "pending: a full table refuses new transactions and keeps the ones it has" {
    var p: Pending = .{ .gpa = testing.allocator, .io = testing.io, .max = 2, .max_keys = 5 };
    defer p.deinit();
    try testing.expect(p.addWrites(&tid(1), 1, 100, .{ .objects = &.{ tid(1), tid(2) } }));
    // too many keys for what is left
    try testing.expect(!p.addWrites(&tid(2), 1, 100, .{ .objects = &.{ tid(3), tid(4), tid(5), tid(6) } }));
    try testing.expect(p.addWrites(&tid(2), 1, 100, .{ .objects = &.{ tid(3), tid(4) }, .addresses = &.{tid(5)} }));
    // too many transactions
    try testing.expect(!p.addWrites(&tid(3), 1, 100, .{}));
    try testing.expectEqual(@as(usize, 2), p.n.load(.acquire));
    try testing.expectEqual(Pending.Touch{ .wait = 100 }, p.touch(&.{.{ .kind = .object, .id = tid(1) }}, null, 50));
    try testing.expectEqual(Pending.Touch.clear, p.touch(&.{.{ .kind = .object, .id = tid(6) }}, null, 50));
    // the same digest again is the entry it already has
    try testing.expect(p.addWrites(&tid(1), 1, 100, .{ .objects = &.{tid(1)} }));
    p.remove(&tid(1));
    try testing.expectEqual(Pending.Touch.clear, p.touch(&.{.{ .kind = .object, .id = tid(1) }}, null, 50));
    try testing.expect(p.addWrites(&tid(3), 1, 100, .{ .objects = &.{tid(6)} }));
}

fn testEffects(a: Allocator, changed: []const struct { types.ObjectID, types.EffectsObjectChange }) ![]u8 {
    const eff: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 7,
        .gas_used = .{ .computationCost = 1, .storageCost = 2, .storageRebate = 3, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = tid(0xdd) } },
        .gas_object_index = 0,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 12 },
        .changed_objects = changed,
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    return bcs.encodeAlloc(types.TransactionEffects, a, &eff);
}

fn oid(b: u8) types.ObjectID {
    return .{ .@"0" = .{ .@"0" = tid(b) } };
}
fn dg(b: u8) types.ObjectDigest {
    return .{ .@"0" = .{ .@"0" = tid(b) } };
}

test "writesOf: every changed object, dynamic field parents, owners before and after" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const raw = try testEffects(a, &.{
        // the gas coin: mutated, owned by the payer
        .{ oid(1), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 5 }, dg(1) }, .{ .AddressOwner = .{ .@"0" = tid(0xa1) } } } }, .output_state = .{ .ObjectWrite = .{ dg(2), .{ .AddressOwner = .{ .@"0" = tid(0xa1) } } } }, .id_operation = .None } },
        // an object transferred from one address to another
        .{ oid(2), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 6 }, dg(3) }, .{ .AddressOwner = .{ .@"0" = tid(0xa1) } } } }, .output_state = .{ .ObjectWrite = .{ dg(4), .{ .AddressOwner = .{ .@"0" = tid(0xa2) } } } }, .id_operation = .None } },
        // a dynamic field created under a parent
        .{ oid(3), .{ .input_state = .NotExist, .output_state = .{ .ObjectWrite = .{ dg(5), .{ .ObjectOwner = .{ .@"0" = tid(0x50) } } } }, .id_operation = .Created } },
        // a shared object mutated, one deleted, one wrapped
        .{ oid(4), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 8 }, dg(6) }, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } } } }, .output_state = .{ .ObjectWrite = .{ dg(7), .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } } } }, .id_operation = .None } },
        .{ oid(5), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 9 }, dg(8) }, .{ .AddressOwner = .{ .@"0" = tid(0xa3) } } } }, .output_state = .NotExist, .id_operation = .Deleted } },
    });
    const w = try writesOf(a, raw, null);
    try testing.expectEqual(@as(usize, 6), w.objects.len); // five changed and the field's parent
    for ([_]u8{ 1, 2, 3, 0x50, 4, 5 }) |b| {
        var found = false;
        for (w.objects) |*x| if (std.mem.eql(u8, x, &tid(b))) {
            found = true;
        };
        try testing.expect(found);
    }
    try testing.expectEqual(@as(usize, 3), w.addresses.len);
    for ([_]u8{ 0xa1, 0xa2, 0xa3 }) |b| {
        var found = false;
        for (w.addresses) |*x| if (std.mem.eql(u8, x, &tid(b))) {
            found = true;
        };
        try testing.expect(found);
    }
    // bytes that are not effects are an error, never a guess
    if (writesOf(a, raw[0 .. raw.len / 2], null)) |_| return error.TestUnexpectedResult else |_| {}
}

fn buildResponse(a: Allocator, digest: bool, bcs_value: ?[]const u8, status: bool, events: bool) ![]u8 {
    // ExecuteTransactionResponse { transaction = 1 { digest = 1, effects = 4 { bcs = 1 { name = 1,
    // value = 2 }, status = 4 {} ... }, events = 5 } }, as the renderer orders it
    var eff: std.ArrayList(u8) = .empty;
    if (bcs_value) |v| {
        var b: std.ArrayList(u8) = .empty;
        try b.appendSlice(a, "\x0a\x12TransactionEffects\x12");
        try putVarint(&b, a, v.len);
        try b.appendSlice(a, v);
        try eff.append(a, 0x0a);
        try putVarint(&eff, a, b.items.len);
        try eff.appendSlice(a, b.items);
    }
    if (status) try eff.appendSlice(a, "\x22\x02\x08\x01");
    var tx: std.ArrayList(u8) = .empty;
    if (digest) try tx.appendSlice(a, "\x0a\x03abc");
    if (bcs_value != null or status) {
        try tx.append(a, 0x22);
        try putVarint(&tx, a, eff.items.len);
        try tx.appendSlice(a, eff.items);
    }
    if (events) try tx.appendSlice(a, "\x2a\x02\x12\x00");
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, 0x0a);
    try putVarint(&out, a, tx.items.len);
    try out.appendSlice(a, tx.items);
    return out.items;
}

test "stripEffectsBcs: the answer for the client's own mask, byte for byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // values of several sizes: the lengths around the field cross the 1, 2 and 3 byte varints
    for ([_]usize{ 0, 1, 90, 127, 128, 300, 16_383, 16_384, 70_000 }) |n| {
        const value = try a.alloc(u8, n);
        for (value, 0..) |*x, i| x.* = @truncate(i *% 7 +% n);
        inline for (.{ true, false }) |digest| inline for (.{ true, false }) |events| {
            // the client selected nothing under effects: the whole message goes
            const with = try buildResponse(a, digest, value, false, events);
            try testing.expectEqualSlices(u8, try buildResponse(a, digest, null, false, events), try stripEffectsBcs(a, with, false));
            // the client selected effects.status: the message stays, without bcs
            const with_status = try buildResponse(a, digest, value, true, events);
            try testing.expectEqualSlices(u8, try buildResponse(a, digest, null, true, events), try stripEffectsBcs(a, with_status, true));
            // what the edge reads the write set from
            try testing.expectEqualSlices(u8, value, nested(with, &.{ 1, 4, 1, 2 }).?);
        };
    }
    // the client selected a path under effects that rendered nothing: an empty message stays
    const only_bcs = try buildResponse(a, true, "x", false, false);
    try testing.expectEqualSlices(u8, "\x0a\x07\x0a\x03abc\x22\x00", try stripEffectsBcs(a, only_bcs, true));
    // no effects in the answer at all: unchanged
    const none = try buildResponse(a, true, null, false, true);
    try testing.expectEqualSlices(u8, none, try stripEffectsBcs(a, none, false));
    try testing.expectError(error.Malformed, stripEffectsBcs(a, "\x0a\x7f\x01", false));
}

test "maskUse and withEffectsBcs: one path is added only when the client's mask lacks it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const Case = struct { mask: ?[]const []const u8, has_bcs: bool, any_effects: bool };
    const cases = [_]Case{
        .{ .mask = null, .has_bcs = true, .any_effects = true }, // the default mask is `effects`
        .{ .mask = &.{"effects"}, .has_bcs = true, .any_effects = true },
        .{ .mask = &.{"effects.bcs"}, .has_bcs = true, .any_effects = true },
        .{ .mask = &.{"effects.bcs.name"}, .has_bcs = true, .any_effects = true }, // never added to, never stripped
        .{ .mask = &.{"*"}, .has_bcs = true, .any_effects = false },
        .{ .mask = &.{ "digest", "effects.status" }, .has_bcs = false, .any_effects = true },
        .{ .mask = &.{ "digest", "events" }, .has_bcs = false, .any_effects = false },
        .{ .mask = &.{"effects_digest"}, .has_bcs = false, .any_effects = false },
        .{ .mask = &.{}, .has_bcs = false, .any_effects = false },
    };
    for (cases) |c| {
        var req: std.ArrayList(u8) = .empty;
        try req.appendSlice(a, "\x0a\x02\x0a\x00"); // transaction { bcs {} }
        if (c.mask) |paths| {
            var m: std.ArrayList(u8) = .empty;
            for (paths) |p| {
                try m.append(a, 0x0a);
                try putVarint(&m, a, p.len);
                try m.appendSlice(a, p);
            }
            try req.append(a, 0x1a);
            try putVarint(&req, a, m.items.len);
            try req.appendSlice(a, m.items);
        }
        const use = maskUse(req.items);
        try testing.expectEqual(c.has_bcs, use.has_bcs);
        if (!c.has_bcs) try testing.expectEqual(c.any_effects, use.any_effects);
        // the request with the path added selects effects.bcs, and is the client's plus one field
        const more = (try withEffectsBcs(a, req.items)).?;
        try testing.expect(std.mem.startsWith(u8, more, req.items));
        try testing.expect(maskUse(more).has_bcs);
    }
    // a request this cannot read is left alone
    try testing.expect(maskUse("\x1a\x7f").has_bcs);
    // no room under the core's decode limit: not added
    const big = try a.alloc(u8, (4 << 20) - 4);
    @memset(big, 0);
    try testing.expectEqual(@as(?[]u8, null), try withEffectsBcs(a, big));
}
