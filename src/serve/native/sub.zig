//! zui/1 subscriptions (NATIVE-PROTOCOL.md section 5): request parsing and per-checkpoint frame
//! production. Pull model: the listener asks for the next checkpoint only while the data stream's
//! unsent backlog is small, reading from the store, so a slow client costs no memory and never
//! holds back anyone else; replay (`From`) and live are the same loop.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("index");
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const txfilter = serve.txfilter;
const W = proto.W;
const R = proto.R;

pub const Filter = union(enum) {
    checkpoints,
    address: struct { addr: [32]u8, roles: u8 },
    /// Up to 1024 ids. After `own`: sorted and owned by the listener.
    objects: []const [32]u8,
    /// The type prefix as sent; after `own`: the long form (`0x<64 hex>::m::S<...>`).
    event_type: []const u8,
    package: [32]u8,
};

pub const Req = struct {
    filter: Filter,
    start: ?u64,
    parts: u8,
    max_lag: u32,
    /// VERIFY on the subscribe request: Proof frames before matches (Checkpoints: contents).
    verify: bool = false,
    owned: bool = false,
};

/// Copies the filter's slices (which point into the request bytes) into `gpa` memory and
/// normalizes them: object ids sorted, the event type prefix in long form.
pub fn own(gpa: Allocator, r: *Req) !void {
    switch (r.filter) {
        .objects => |ids| {
            const c = try gpa.dupe([32]u8, ids);
            std.mem.sort([32]u8, c, {}, lessId);
            r.filter = .{ .objects = c };
        },
        .event_type => |t| r.filter = .{ .event_type = try normalizeTypePrefix(gpa, t) },
        else => {},
    }
    if (r.verify and r.filter == .checkpoints) r.parts |= proto.part_contents;
    r.owned = true;
}

pub fn deinit(gpa: Allocator, r: *Req) void {
    if (!r.owned) return;
    switch (r.filter) {
        .objects => |ids| gpa.free(ids),
        .event_type => |t| gpa.free(t),
        else => {},
    }
    r.owned = false;
}

fn lessId(_: void, a: [32]u8, b: [32]u8) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn orderId(key: [32]u8, item: [32]u8) std.math.Order {
    return std.mem.order(u8, &key, &item);
}

fn hasId(ids: []const [32]u8, id: *const [32]u8) bool {
    return std.sort.binarySearch([32]u8, ids, id.*, orderId) != null;
}

/// "0x2::coin" -> "0x000..02::coin". A prefix with generics is parsed as a full type and
/// printed canonically (inner addresses long too).
pub fn normalizeTypePrefix(gpa: Allocator, t: []const u8) ![]const u8 {
    if (std.mem.indexOfScalar(u8, t, '<') != null) {
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const st = index.typeparse.structTag(a, t) catch return error.Malformed;
        var buf: [4096]u8 = undefined;
        var o: serve.typestr.Out = .{ .buf = &buf };
        serve.typestr.typeTag(&o, .{ .@"struct" = st }) catch return error.Malformed;
        return gpa.dupe(u8, o.str());
    }
    const sep = std.mem.indexOf(u8, t, "::") orelse t.len;
    var hex = t[0..sep];
    if (std.mem.startsWith(u8, hex, "0x") or std.mem.startsWith(u8, hex, "0X")) hex = hex[2..];
    if (hex.len == 0 or hex.len > 64) return error.Malformed;
    for (hex) |ch| if (!std.ascii.isHex(ch)) return error.Malformed;
    const rest = t[sep..];
    if (rest.len > 0) {
        // "::module" or "::module::Name": identifiers only
        var it = std.mem.splitSequence(u8, rest[2..], "::");
        var parts: usize = 0;
        while (it.next()) |id| : (parts += 1) {
            if (id.len == 0 or parts >= 2) return error.Malformed;
            for (id) |ch| if (!(std.ascii.isAlphanumeric(ch) or ch == '_')) return error.Malformed;
        }
    }
    const out = try gpa.alloc(u8, 2 + 64 + rest.len);
    out[0] = '0';
    out[1] = 'x';
    @memset(out[2 .. 66 - hex.len], '0');
    for (hex, 0..) |ch, i| out[66 - hex.len + i] = std.ascii.toLower(ch);
    @memcpy(out[66..], rest);
    return out;
}

/// `ty` (long form) is `prefix` or extends it at a `::` or `<` boundary.
pub fn typeMatches(prefix: []const u8, ty: []const u8) bool {
    if (!std.mem.startsWith(u8, ty, prefix)) return false;
    if (ty.len == prefix.len) return true;
    return ty[prefix.len] == ':' or ty[prefix.len] == '<';
}

pub const ParseError = error{ Malformed, Unimplemented };

/// Parses a SubscribeReq body. `error.Malformed` also means "not all bytes yet" while the stream
/// is open.
pub fn parse(body: []const u8) ParseError!Req {
    var r: R = .{ .b = body };
    const filter: Filter = switch (try r.uleb()) {
        0 => .checkpoints,
        1 => .{ .address = .{ .addr = (try r.fixed(32)).*, .roles = try r.u8_() } },
        2 => blk: { // Objects
            const n = try r.uleb();
            if (n > 1024) return error.Malformed;
            if (n * 32 > r.b.len - r.p) return error.Malformed; // not all bytes yet
            const ids = std.mem.bytesAsSlice([32]u8, r.b[r.p..][0..@intCast(n * 32)]);
            r.p += @intCast(n * 32);
            break :blk .{ .objects = ids };
        },
        3 => blk: {
            const t = try r.str();
            if (t.len == 0 or t.len > 1024) return error.Malformed;
            break :blk .{ .event_type = t };
        },
        4 => .{ .package = (try r.fixed(32)).* },
        else => return error.Malformed,
    };
    const start: ?u64 = switch (try r.uleb()) {
        0 => null,
        1 => try r.int(u64),
        else => return error.Malformed,
    };
    const parts = try r.u8_();
    const max_lag = try r.int(u32);
    // bytes after the body are credit varints (kept-open request, spec 2.1): see `bodyLen`
    return .{ .filter = filter, .start = start, .parts = parts, .max_lag = if (max_lag == 0) 64 else @min(max_lag, 1024) };
}

/// Length of the SubscribeReq at the start of `body` (it is self-delimiting).
pub fn bodyLen(body: []const u8) ParseError!usize {
    var r: R = .{ .b = body };
    switch (try r.uleb()) {
        0 => {},
        1 => {
            _ = try r.fixed(32);
            _ = try r.u8_();
        },
        2 => {
            const n = try r.uleb();
            if (n > 1024 or n * 32 > r.b.len - r.p) return error.Malformed;
            r.p += @intCast(n * 32);
        },
        3 => _ = try r.str(),
        4 => _ = try r.fixed(32),
        else => return error.Malformed,
    }
    if (try r.uleb() == 1) _ = try r.int(u64);
    _ = try r.u8_();
    _ = try r.int(u32);
    return r.p;
}

/// Per-transaction filter keys of a checkpoint (its pre-state: the loaded input objects at their
/// old versions, read from the store), computed once per checkpoint and shared by every
/// subscription of the listener: the subscription workers (subjobs.zig) take entries from here
/// on any thread. An ask for a checkpoint whose computation another worker is running gets
/// `error.Pending` at once instead of repeating it, and never waits: a worker holds a store
/// snapshot, and none is held across a wait on another thread (the subscription asks again on
/// a later pass). Bounded: at most `cap` checkpoints are kept, the lowest sequence number unused
/// at the moment goes first.
pub const KeyCache = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    entries: [cap]?*Entry = @splat(null),
    stats: Stats = .{},
    /// Tests: called on the computing thread before each computation (a slow store read).
    test_stall: ?*const fn (seq: u64) void = null,
    /// Arenas of freed entries, reset and kept for the next computation: a fresh arena per
    /// checkpoint mapped (and on free unmapped) its large blocks every time (bufs.zig).
    spares: [2]?std.heap.ArenaAllocator = @splat(null),

    pub const cap = 16;
    /// Bytes a spare arena keeps.
    pub const spare_keep: usize = 32 << 20;

    pub const Stats = struct {
        /// Asks answered from a kept entry, asks that found another's computation running
        /// (answered `error.Pending`), and computations.
        hits: std.atomic.Value(u64) = .init(0),
        coalesced: std.atomic.Value(u64) = .init(0),
        misses: std.atomic.Value(u64) = .init(0),
        /// Time spent computing, in total and the longest one.
        compute_ns: std.atomic.Value(u64) = .init(0),
        compute_max_ns: std.atomic.Value(u64) = .init(0),
    };

    pub const Entry = struct {
        seq: u64,
        arena: std.heap.ArenaAllocator,
        keys: []txfilter.KeySet = &.{},
        ready: bool = false,
        err: ?anyerror = null,
        refs: u32 = 1,
        /// In `entries` (false: freed when the last user releases it).
        kept: bool = false,
    };

    pub fn init(gpa: Allocator, io: Io) KeyCache {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(k: *KeyCache) void {
        for (&k.entries) |*slot| if (slot.*) |e| {
            e.arena.deinit();
            k.gpa.destroy(e);
            slot.* = null;
        };
        for (&k.spares) |*s| if (s.*) |*a| {
            a.deinit();
            s.* = null;
        };
    }

    /// A spare arena, or a new one (caller holds the lock).
    fn arena(k: *KeyCache) std.heap.ArenaAllocator {
        for (&k.spares) |*s| if (s.*) |a| {
            s.* = null;
            return a;
        };
        return .init(k.gpa);
    }

    /// Frees `e`, keeping its arena as a spare if there is room (caller holds the lock).
    fn retire(k: *KeyCache, e: *Entry) void {
        defer k.gpa.destroy(e);
        for (&k.spares) |*s| if (s.* == null) {
            _ = e.arena.reset(.{ .retain_with_limit = spare_keep });
            s.* = e.arena;
            return;
        };
        e.arena.deinit();
    }

    /// The keys of checkpoint `rec`, held until `release`.
    pub fn acquire(k: *KeyCache, svc: *serve.service.Service, snap: *store.Snapshot, rec: store.CheckpointRecord) !*Entry {
        k.mu.lockUncancelable(k.io);
        for (k.entries) |slot| if (slot) |e| if (e.seq == rec.seq) {
            if (!e.ready) {
                _ = k.stats.coalesced.fetchAdd(1, .monotonic);
                k.mu.unlock(k.io);
                return error.Pending;
            }
            // (a failed computation is never kept)
            e.refs += 1;
            _ = k.stats.hits.fetchAdd(1, .monotonic);
            k.mu.unlock(k.io);
            return e;
        };
        _ = k.stats.misses.fetchAdd(1, .monotonic);
        const e = k.gpa.create(Entry) catch |err| {
            k.mu.unlock(k.io);
            return err;
        };
        e.* = .{ .seq = rec.seq, .arena = k.arena() };
        k.keep(e);
        k.mu.unlock(k.io);

        const t0 = nowNs();
        if (k.test_stall) |f| f(rec.seq);
        const got = compute(e.arena.allocator(), svc, snap, rec);
        const dt = nowNs() -| t0;
        _ = k.stats.compute_ns.fetchAdd(dt, .monotonic);
        _ = k.stats.compute_max_ns.fetchMax(dt, .monotonic);

        k.mu.lockUncancelable(k.io);
        if (got) |keys| e.keys = keys else |err| {
            e.err = err;
            // not kept: the next ask computes again
            for (&k.entries) |*slot| if (slot.* == e) {
                slot.* = null;
                e.kept = false;
            };
        }
        e.ready = true;
        k.mu.unlock(k.io);
        if (e.err) |err| {
            k.release(e);
            return err;
        }
        return e;
    }

    pub fn release(k: *KeyCache, e: *Entry) void {
        k.mu.lockUncancelable(k.io);
        defer k.mu.unlock(k.io);
        e.refs -= 1;
        if (e.refs == 0 and !e.kept) k.retire(e);
    }

    /// Puts `e` in a free place, or in place of the lowest-numbered entry nobody holds (caller
    /// holds the lock). With every place in use `e` is not kept.
    fn keep(k: *KeyCache, e: *Entry) void {
        var victim: ?usize = null;
        for (&k.entries, 0..) |*slot, i| {
            const x = slot.* orelse {
                slot.* = e;
                e.kept = true;
                return;
            };
            if (x.refs != 0 or !x.ready) continue;
            if (victim == null or x.seq < k.entries[victim.?].?.seq) victim = i;
        }
        const i = victim orelse return;
        k.retire(k.entries[i].?);
        k.entries[i] = e;
        e.kept = true;
    }

    fn compute(a: Allocator, svc: *serve.service.Service, snap: *store.Snapshot, rec: store.CheckpointRecord) ![]txfilter.KeySet {
        const d = try serve.service.loadCheckpointData(svc, a, snap, rec, true, true);
        var set = try serve.objset.ObjSet.build(a, d.objects);
        const keys = try a.alloc(txfilter.KeySet, d.txs.len);
        for (d.txs, keys) |t, *ks| ks.* = try txfilter.transactionKeys(a, t.transaction, t.effects, t.events, &set);
        return keys;
    }
};

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// A copy of `r` that owns its own filter (a subscription worker's, freed with `deinit`).
pub fn clone(gpa: Allocator, r: *const Req) !Req {
    var c = r.*;
    switch (r.filter) {
        .objects => |ids| c.filter = .{ .objects = try gpa.dupe([32]u8, ids) },
        .event_type => |t| c.filter = .{ .event_type = try gpa.dupe(u8, t) },
        else => {},
    }
    c.owned = true;
    return c;
}

fn has(ks: *const txfilter.KeySet, dim: txfilter.Dim, v: []const u8) bool {
    var b: [64]u8 = undefined;
    b[0] = @intFromEnum(dim);
    @memcpy(b[1..][0..v.len], v);
    return ks.contains(b[0 .. 1 + v.len]);
}

/// Appends the frames for checkpoint `rec` to `out`: `Checkpoint` for the Checkpoints filter;
/// for the others, in verified mode a `Proof` frame when anything matched, then the matches
/// (`TxMatch`, `ObjectChange` or `EventMatch`), then `CheckpointEnd`. Returns the matches.
pub fn produce(gpa: Allocator, a: Allocator, svc: *serve.service.Service, snap: *store.Snapshot, kc: *KeyCache, req: *const Req, rec: store.CheckpointRecord, out: *std.ArrayList(u8)) !u32 {
    var body: std.ArrayList(u8) = .empty;
    const w: W = .{ .gpa = a, .out = &body };
    if (req.filter == .checkpoints) {
        try dispatch.writeCheckpoint(a, snap, w, rec, req.parts);
        try proto.frame(out, gpa, .checkpoint, body.items);
        return 1;
    }
    var frames: std.ArrayList(u8) = .empty;
    const ds = try dispatch.contentDigests(a, rec.contents);
    var n: u32 = 0;
    switch (req.filter) {
        .address, .package => {
            const held = try kc.acquire(svc, snap, rec);
            defer kc.release(held);
            const keys = held.keys;
            if (ds.len != keys.len) return error.Internal;
            for (keys, ds) |*ks, *dg| {
                const hit = switch (req.filter) {
                    .address => |f| blk: {
                        const roles = if (f.roles == 0) 0x03 else f.roles;
                        break :blk (roles & 0x01 != 0 and has(ks, .sender, &f.addr)) or
                            (roles & 0x02 != 0 and has(ks, .affected_address, &f.addr));
                    },
                    .package => |p| has(ks, .move_call, &p),
                    else => unreachable,
                };
                if (!hit) continue;
                const t = snap.transaction(dg) orelse continue;
                body.clearRetainingCapacity();
                try dispatch.writeTx(w, t, req.parts);
                try proto.frame(&frames, a, .tx_match, body.items);
                n += 1;
            }
        },
        .objects => |ids| for (ds) |*dg| {
            const t = snap.transaction(dg) orelse continue;
            const eff = bcs.decode(types.TransactionEffects, a, t.effects) catch continue;
            const v2 = switch (eff) {
                .V2 => |v| v,
                .V1 => continue, // pre-V2 effects: not matched (history before effects V2)
            };
            for (v2.changed_objects) |e| {
                const id = &e.@"0".@"0".@"0";
                if (!hasId(ids, id)) continue;
                body.clearRetainingCapacity();
                try w.int(u64, rec.seq);
                try w.fixed(dg);
                try w.fixed(id);
                switch (e.@"1".output_state) {
                    .ObjectWrite, .PackageWrite => {
                        const ver = switch (e.@"1".output_state) {
                            .PackageWrite => |p| p.@"0".@"0",
                            else => v2.lamport_version.@"0",
                        };
                        if (try snap.objectAtChecked(id, ver)) |o| {
                            try w.uleb(0);
                            try w.int(u64, o.version);
                            try w.fixed(&o.digest);
                            try w.bytes(o.bytes);
                        } else try w.uleb(3); // VersionNotFound: pruned
                    },
                    .NotExist => {
                        try w.uleb(2);
                        try w.int(u64, v2.lamport_version.@"0");
                        try w.u8_(if (e.@"1".id_operation == .Deleted) 0 else 1);
                    },
                    .AccumulatorWriteV1 => continue,
                }
                try proto.frame(&frames, a, .object_change, body.items);
                n += 1;
            }
        },
        .event_type => |prefix| for (ds) |*dg| {
            const t = snap.transaction(dg) orelse continue;
            const evb = t.events orelse continue;
            const evs = bcs.decode(types.TransactionEvents, a, evb) catch continue;
            for (evs.data, 0..) |ev, i| {
                var buf: [4096]u8 = undefined;
                var o: serve.typestr.Out = .{ .buf = &buf };
                serve.typestr.typeTag(&o, .{ .@"struct" = ev.type_ }) catch continue;
                if (!typeMatches(prefix, o.str())) continue;
                body.clearRetainingCapacity();
                try w.int(u64, rec.seq);
                try w.fixed(dg);
                try w.int(u32, @intCast(i));
                try w.bytes(try bcs.encodeAlloc(types.Event, a, &ev));
                try proto.frame(&frames, a, .event_match, body.items);
                n += 1;
            }
        },
        .checkpoints => unreachable,
    }
    if (n > 0 and req.verify) {
        body.clearRetainingCapacity();
        try dispatch.writeProofCheckpoint(w, rec);
        try proto.frame(out, gpa, .proof, body.items);
    }
    try out.appendSlice(gpa, frames.items);
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, rec.seq, .little);
    try proto.frame(out, gpa, .checkpoint_end, &b);
    return n;
}

pub fn ack(out: *std.ArrayList(u8), gpa: Allocator, sub_id: u64, start: u64, lowest: u64) !void {
    try proto.okHeader(out, gpa, 0);
    const w: W = .{ .gpa = gpa, .out = out };
    try w.int(u64, sub_id);
    try w.int(u64, start);
    try w.int(u64, lowest);
}

test "subscribe request parses" {
    var b: [64]u8 = undefined;
    b[0] = 1; // Address
    @memset(b[1..33], 0xab);
    b[33] = 0x01;
    b[34] = 1; // From
    std.mem.writeInt(u64, b[35..43], 42, .little);
    b[43] = proto.part_effects;
    std.mem.writeInt(u32, b[44..48], 0, .little);
    const r = try parse(b[0..48]);
    try std.testing.expectEqual(@as(?u64, 42), r.start);
    try std.testing.expectEqual(@as(u32, 64), r.max_lag);
    try std.testing.expectError(error.Malformed, parse(b[0..40]));
    try std.testing.expect((try parse(&.{ 0, 0, 0, 0, 0, 0, 0 })).filter == .checkpoints);
    try std.testing.expectEqual(@as(usize, 48), try bodyLen(b[0..48]));
}

test "objects and event type filters parse, own and match" {
    const gpa = std.testing.allocator;
    var b: [128]u8 = undefined;
    b[0] = 2;
    b[1] = 2;
    @memset(b[2..34], 0xbb);
    @memset(b[34..66], 0xaa);
    b[66] = 0; // Tip
    b[67] = 0;
    std.mem.writeInt(u32, b[68..72], 8, .little);
    try std.testing.expectError(error.Malformed, parse(b[0..40]));
    var r = try parse(b[0..72]);
    try std.testing.expectEqual(@as(usize, 72), try bodyLen(b[0..80]));
    try own(gpa, &r);
    defer deinit(gpa, &r);
    try std.testing.expectEqual(@as(u8, 0xaa), r.filter.objects[0][0]);
    const aa: [32]u8 = @splat(0xaa);
    const cc: [32]u8 = @splat(0xcc);
    try std.testing.expect(hasId(r.filter.objects, &aa));
    try std.testing.expect(!hasId(r.filter.objects, &cc));

    const t = "0x2::coin";
    var e: [64]u8 = undefined;
    e[0] = 3;
    e[1] = t.len;
    @memcpy(e[2..][0..t.len], t);
    @memset(e[2 + t.len ..][0..6], 0);
    var r2 = try parse(e[0 .. 2 + t.len + 6]);
    r2.verify = true;
    try own(gpa, &r2);
    defer deinit(gpa, &r2);
    const long = "0x0000000000000000000000000000000000000000000000000000000000000002::coin";
    try std.testing.expectEqualStrings(long, r2.filter.event_type);
    try std.testing.expect(typeMatches(long, long ++ "::CoinCreated<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>"));
    try std.testing.expect(!typeMatches(long, long ++ "2::X"));
    try std.testing.expect(typeMatches(long ++ "::S", long ++ "::S<u64>"));
    try std.testing.expectError(error.Malformed, normalizeTypePrefix(gpa, "0xzz::m"));
    const g = try normalizeTypePrefix(gpa, "0x2::coin::Coin<0x2::sui::SUI>");
    defer gpa.free(g);
    try std.testing.expectEqualStrings(long ++ "::Coin<0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>", g);
}
