//! Transaction envelopes served in place of the stored ones: the submitted signature order of
//! sponsored and multi-signer transactions that were stored in the checkpoint contents' order.
//!
//! sui-node 1.83.1 answers a transaction's `signatures` from its stored `SenderSignedData`, in
//! the order the submitter sent them; checkpoint contents V2 certify the same signatures in
//! `required_signers` order (sender, then gas owner), and no digest covers the order. A
//! checkpoint converted from Mysten's bucket therefore stores the contents order, and the node's
//! signature-order sweep (node/sigorder.zig `Sweep`) later learns the submitted order from a full
//! node. It installs the reordered envelope here; every transaction read (`Snapshot.transaction`,
//! `transactionChecked`, `transactionNear`) then returns it. Only the signature order differs: the
//! caller (`put`) checks the same TransactionData bytes and the same signatures as a multiset, so
//! the envelope has the stored length and every digest still holds.
//!
//! About half of the multi-signer transactions of a catch-up range need a fix, so the table holds
//! tens of thousands. Layout: an immutable base sorted by digest plus an append-only delta of at
//! most about 2 sqrt(N) slots (`deltaCap`); a full delta is merged into a new base. A put costs
//! one slot and an amortized O(sqrt N) of merge work, and memory stays linear: the live base and
//! delta, the envelopes, and the sets retired since the oldest live snapshot.
//!
//! Readers are lock-free: one atomic load (null: no fixes, the common case), a backward scan of
//! the delta's 8-byte keys (newest first, so a replacement shadows the slot it replaces) and a
//! binary search of the base. Every slot carries its digest, checkpoint and generation inline,
//! so `changedSince` and merges never dereference an envelope. Reclamation follows the store's
//! snapshot epochs (`cache.Readers`, which every `Snapshot` registers in and which `quiesce`
//! re-enters): a retired set, base, delta or envelope is stamped with the epoch handed out
//! before it was unpublished, and freed once no live snapshot is at or below that epoch. An
//! envelope returned by `find` therefore stays valid for the snapshot that read it.
const std = @import("std");
const cache = @import("cache.zig");
const Spin = cache.Spin;
const Readers = cache.Readers;
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;

pub const Fix = struct {
    digest: [32]u8,
    /// Checkpoint holding the transaction.
    seq: u64,
    /// Table generation that installed it (`Table.changedSince`).
    gen: u64,
    tx: []const u8,
};

/// A fix to install (`putMany`, `load`): `tx` is copied.
pub const Entry = struct { seq: u64, digest: [32]u8, tx: []const u8 };

/// A fix with its search and staleness fields inline.
const Slot = struct {
    digest: [32]u8,
    seq: u64,
    gen: u64,
    fix: *const Fix,
};

const SeqGen = struct { seq: u64, gen: u64 };

/// Immutable once published: `slots` sorted by digest, one per digest; `seqs` sorted by
/// checkpoint, each with the newest generation of its slots.
const Base = struct {
    slots: []const Slot,
    seqs: []const SeqGen,
    max_gen: u64,
};

const empty_base: Base = .{ .slots = &.{}, .seqs = &.{}, .max_gen = 0 };

/// Append-only once published: slots in install order (generations non-decreasing); readers
/// read the first `len`. `keys` are the digests' first 8 bytes (the scan touches only them).
const Delta = struct {
    keys: []u64,
    slots: []Slot,
    len: Atomic(usize) = .init(0),
};

const Set = struct { base: *const Base, delta: *Delta };

const Garbage = union(enum) { set: *Set, base: *Base, delta: *Delta, fix: *Fix };
const Retired = struct { g: Garbage, stamp: u64 };

fn key(d: *const [32]u8) u64 {
    return std.mem.readInt(u64, d[0..8], .little);
}

/// Delta size for a base of `n` slots: merges every ~2 sqrt(n) puts, each O(n).
pub fn deltaCap(n: usize) usize {
    return std.math.clamp(2 * std.math.sqrt(n), 64, 4096);
}

pub const Table = struct {
    cur: Atomic(?*const Set) = .init(null),
    gen: Atomic(u64) = .init(0),
    n: Atomic(usize) = .init(0),
    /// Bytes allocated: live structures, envelopes and retired sets not yet freed (a gauge).
    bytes: Atomic(usize) = .init(0),
    retired_n: Atomic(usize) = .init(0),
    lock: Spin = .{},
    /// Set by the store (`Store.create`): the allocator of every structure here and the snapshot
    /// epochs that gate reclamation. Without `readers` nothing is freed before `deinit`.
    gpa: ?Allocator = null,
    readers: ?*Readers = null,
    // ---- writer only, under `lock`
    set: ?*Set = null,
    min_seq: u64 = std.math.maxInt(u64),
    retired: std.ArrayList(Retired) = .empty,

    /// No readers may exist: frees everything, keeps `gpa` and `readers`.
    pub fn reset(t: *Table) void {
        const gpa = t.gpa orelse return;
        for (t.retired.items) |r| t.free(r.g);
        t.retired.deinit(gpa);
        if (t.set) |s| {
            // Live envelopes: the newest slot of each digest (superseded ones were retired).
            var none: std.ArrayList(Garbage) = .empty;
            if (t.build(s.base.slots, s.delta.slots[0..s.delta.len.raw], 0, &none)) |live| {
                for (live) |sl| t.free(.{ .fix = @constCast(sl.fix) });
                gpa.free(live);
            } else |_| {
                // Out of memory: fall back to a quadratic pass (shutdown only).
                const d = s.delta.slots[0..s.delta.len.raw];
                for (d, 0..) |sl, i| {
                    const newer = for (d[i + 1 ..]) |o| {
                        if (std.mem.eql(u8, &o.digest, &sl.digest)) break true;
                    } else false;
                    if (!newer) t.free(.{ .fix = @constCast(sl.fix) });
                }
                for (s.base.slots) |sl| {
                    const shadowed = for (d) |o| {
                        if (std.mem.eql(u8, &o.digest, &sl.digest)) break true;
                    } else false;
                    if (!shadowed) t.free(.{ .fix = @constCast(sl.fix) });
                }
            }
            t.free(.{ .base = @constCast(s.base) });
            t.free(.{ .delta = s.delta });
            t.free(.{ .set = s });
        }
        t.* = .{ .gpa = t.gpa, .readers = t.readers };
    }

    pub fn deinit(t: *Table) void {
        t.reset();
        t.* = .{};
    }

    fn lessSlot(_: void, a: Slot, b: Slot) bool {
        return std.mem.order(u8, &a.digest, &b.digest) == .lt;
    }

    fn search(slots: []const Slot, digest: *const [32]u8) ?usize {
        var lo: usize = 0;
        var hi: usize = slots.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            switch (std.mem.order(u8, &slots[mid].digest, digest)) {
                .lt => lo = mid + 1,
                .gt => hi = mid,
                .eq => return mid,
            }
        }
        return null;
    }

    fn findIn(s: *const Set, digest: *const [32]u8) ?*const Fix {
        const d = s.delta;
        const k = key(digest);
        var i = d.len.load(.acquire);
        while (i > 0) {
            i -= 1;
            if (d.keys[i] == k and std.mem.eql(u8, &d.slots[i].digest, digest)) return d.slots[i].fix;
        }
        const j = search(s.base.slots, digest) orelse return null;
        return s.base.slots[j].fix;
    }

    /// The envelope to serve for transaction `digest`, if one was installed. The caller holds a
    /// store snapshot (the envelope lives at least until it is released or quiesced).
    pub fn find(t: *const Table, digest: *const [32]u8) ?*const Fix {
        const s = t.cur.load(.acquire) orelse return null;
        return findIn(s, digest);
    }

    /// Writer side (no snapshot needed): whether `tx` is the installed envelope of `digest`.
    pub fn installed(t: *Table, digest: *const [32]u8, tx: []const u8) bool {
        t.lock.lock();
        defer t.lock.unlock();
        const s = t.set orelse return false;
        const f = findIn(s, digest) orelse return false;
        return std.mem.eql(u8, f.tx, tx);
    }

    /// Generation of the newest fix (0: none).
    pub fn generation(t: *const Table) u64 {
        return t.gen.load(.acquire);
    }

    /// Whether a fix newer than generation `gen` touches checkpoint `seq` (a GetCheckpoint
    /// response encoded at `gen` is then stale). The caller holds a store snapshot. May answer
    /// true for a slot since superseded (a spare re-render), never false for a newer fix.
    pub fn changedSince(t: *const Table, seq: u64, gen: u64) bool {
        if (t.gen.load(.acquire) <= gen) return false;
        const s = t.cur.load(.acquire) orelse return false;
        const d = s.delta;
        var i = d.len.load(.acquire);
        while (i > 0) {
            i -= 1;
            const sl = &d.slots[i];
            if (sl.gen <= gen) break;
            if (sl.seq == seq) return true;
        }
        const b = s.base;
        if (b.max_gen <= gen) return false;
        var lo: usize = 0;
        var hi: usize = b.seqs.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (b.seqs[mid].seq < seq) lo = mid + 1 else hi = mid;
        }
        return lo < b.seqs.len and b.seqs[lo].seq == seq and b.seqs[lo].gen > gen;
    }

    pub fn count(t: *const Table) usize {
        return t.n.load(.monotonic);
    }

    pub fn heldBytes(t: *const Table) usize {
        return t.bytes.load(.monotonic);
    }

    /// Installs `tx` (copied) for transaction `digest` in checkpoint `seq`, replacing an earlier
    /// fix. False when the same bytes were already installed. The caller has checked that `tx`
    /// differs from the stored envelope only in signature order.
    pub fn put(t: *Table, seq: u64, digest: *const [32]u8, tx: []const u8) !bool {
        return try t.putMany(&.{.{ .seq = seq, .digest = digest.*, .tx = tx }}) == 1;
    }

    /// `put` for each entry in order (a later entry for the same digest replaces an earlier
    /// one), under one generation. Returns how many installed new bytes. On error the entries
    /// before the failing one stay installed.
    pub fn putMany(t: *Table, entries: []const Entry) !usize {
        t.lock.lock();
        defer t.lock.unlock();
        t.collectLocked();
        const gpa = t.gpa.?;
        var garbage: std.ArrayList(Garbage) = .empty;
        defer garbage.deinit(gpa);
        const g = t.gen.load(.monotonic) + 1;
        var added: usize = 0;
        defer t.finish(g, added, &garbage);
        try garbage.ensureUnusedCapacity(gpa, 4);
        if (t.set == null) try t.publish(&empty_base, &.{}, 0, &garbage);
        for (entries) |*e| {
            const old = findIn(t.set.?, &e.digest);
            if (old) |o| if (std.mem.eql(u8, o.tx, e.tx)) continue;
            // Room for this fix's garbage and a merge's (old set, base, delta).
            try garbage.ensureUnusedCapacity(gpa, 4);
            if (t.set.?.delta.len.raw == t.set.?.delta.slots.len) try t.merge(&garbage);
            const f = try t.newFix(e, g);
            const d = t.set.?.delta;
            const i = d.len.raw;
            d.keys[i] = key(&e.digest);
            d.slots[i] = .{ .digest = e.digest, .seq = e.seq, .gen = g, .fix = f };
            d.len.store(i + 1, .release);
            if (old) |o| garbage.appendAssumeCapacity(.{ .fix = @constCast(o) }) else _ = t.n.fetchAdd(1, .monotonic);
            t.min_seq = @min(t.min_seq, e.seq);
            added += 1;
        }
        return added;
    }

    /// Bulk install (a restart's log replay): every entry in one merge and one published set.
    /// A later entry for a digest wins over an earlier one. Returns how many installed new bytes.
    pub fn load(t: *Table, entries: []const Entry) !usize {
        t.lock.lock();
        defer t.lock.unlock();
        t.collectLocked();
        const gpa = t.gpa.?;
        var garbage: std.ArrayList(Garbage) = .empty;
        defer garbage.deinit(gpa);
        const g = t.gen.load(.monotonic) + 1;
        // The last entry of each digest.
        const order = try gpa.alloc(u32, entries.len);
        defer gpa.free(order);
        for (order, 0..) |*o, i| o.* = @intCast(entries.len - 1 - i);
        std.sort.block(u32, order, entries, struct {
            fn lt(es: []const Entry, a: u32, b: u32) bool {
                return std.mem.order(u8, &es[a].digest, &es[b].digest) == .lt;
            }
        }.lt);
        var slots: std.ArrayList(Slot) = .empty;
        defer slots.deinit(gpa);
        try slots.ensureTotalCapacity(gpa, entries.len);
        var replaced: std.ArrayList(Garbage) = .empty;
        defer replaced.deinit(gpa);
        errdefer for (slots.items) |sl| t.free(.{ .fix = @constCast(sl.fix) });
        var fresh: usize = 0;
        var prev: ?*const [32]u8 = null;
        for (order) |oi| {
            const e = &entries[oi];
            if (prev) |p| if (std.mem.eql(u8, p, &e.digest)) continue;
            prev = &e.digest;
            const old = if (t.set) |s| findIn(s, &e.digest) else null;
            if (old) |o| {
                if (std.mem.eql(u8, o.tx, e.tx)) continue;
                try replaced.append(gpa, .{ .fix = @constCast(o) });
            } else fresh += 1;
            const f = try t.newFix(e, g);
            slots.appendAssumeCapacity(.{ .digest = e.digest, .seq = e.seq, .gen = g, .fix = f });
            t.min_seq = @min(t.min_seq, e.seq);
        }
        if (slots.items.len == 0) return 0;
        // Old base, then the delta and the loaded slots as newer (a loaded slot wins).
        const s = t.set;
        const delta_len = if (s) |x| x.delta.len.raw else 0;
        const newer = try gpa.alloc(Slot, delta_len + slots.items.len);
        defer gpa.free(newer);
        if (s) |x| @memcpy(newer[0..delta_len], x.delta.slots[0..delta_len]);
        @memcpy(newer[delta_len..], slots.items);
        try garbage.ensureUnusedCapacity(gpa, replaced.items.len + 3);
        try t.publish(t.baseOf(), newer, 0, &garbage);
        garbage.appendSliceAssumeCapacity(replaced.items);
        const n = slots.items.len;
        slots.clearRetainingCapacity();
        _ = t.n.fetchAdd(fresh, .monotonic);
        t.finish(g, n, &garbage);
        return n;
    }

    /// Drops the fixes of checkpoints below `floor` (pruned: never served again). Returns how
    /// many. One O(N) rebuild, only when some fix is below the floor.
    pub fn dropBelow(t: *Table, floor: u64) !usize {
        t.lock.lock();
        defer t.lock.unlock();
        t.collectLocked();
        if (t.set == null or t.min_seq >= floor) return 0;
        const gpa = t.gpa.?;
        var garbage: std.ArrayList(Garbage) = .empty;
        defer garbage.deinit(gpa);
        const s = t.set.?;
        try garbage.ensureUnusedCapacity(gpa, 3);
        const before = t.n.load(.monotonic);
        try t.publish(s.base, s.delta.slots[0..s.delta.len.raw], floor, &garbage);
        const after = t.set.?.base.slots.len;
        t.n.store(after, .monotonic);
        t.min_seq = if (t.set.?.base.seqs.len > 0) t.set.?.base.seqs[0].seq else std.math.maxInt(u64);
        t.finish(t.gen.load(.monotonic), 0, &garbage);
        return before - after;
    }

    /// Frees what no live snapshot can hold any more (also done by every write).
    pub fn collect(t: *Table) void {
        if (t.retired_n.load(.monotonic) == 0) return;
        t.lock.lock();
        defer t.lock.unlock();
        t.collectLocked();
    }

    // ------------------------------------------------------------------ writer internals

    fn collectLocked(t: *Table) void {
        if (t.retired.items.len == 0) return;
        const rd = t.readers orelse return;
        const oldest = rd.oldest();
        var k: usize = 0;
        for (t.retired.items) |r| {
            if (oldest) |o| if (r.stamp >= o) break;
            t.free(r.g);
            k += 1;
        }
        if (k == 0) return;
        const rest = t.retired.items.len - k;
        std.mem.copyForwards(Retired, t.retired.items[0..rest], t.retired.items[k..]);
        t.retired.shrinkRetainingCapacity(rest);
        t.retired_n.store(rest, .monotonic);
    }

    /// Publishes the generation, then stamps `garbage` (already unpublished) past every
    /// snapshot that may have seen it.
    fn finish(t: *Table, g: u64, added: usize, garbage: *std.ArrayList(Garbage)) void {
        // The fix is visible before the generation that names it: a reader that sees `g` (a
        // GetCheckpoint cache check) also sees the envelope.
        if (added > 0) t.gen.store(g, .release);
        if (garbage.items.len == 0) return;
        // Snapshots registered after `bump` load the new pointers (its lock orders them after
        // the stores above); those at or below the stamp may still hold the old ones.
        const stamp = if (t.readers) |rd| rd.bump() else std.math.maxInt(u64);
        const gpa = t.gpa.?;
        t.retired.ensureUnusedCapacity(gpa, garbage.items.len) catch {
            // Out of memory for the list: leak rather than free under a reader.
            garbage.clearRetainingCapacity();
            return;
        };
        for (garbage.items) |x| t.retired.appendAssumeCapacity(.{ .g = x, .stamp = stamp });
        garbage.clearRetainingCapacity();
        t.retired_n.store(t.retired.items.len, .monotonic);
    }

    fn newFix(t: *Table, e: *const Entry, g: u64) !*Fix {
        const gpa = t.gpa.?;
        const f = try gpa.create(Fix);
        errdefer gpa.destroy(f);
        f.* = .{ .digest = e.digest, .seq = e.seq, .gen = g, .tx = try gpa.dupe(u8, e.tx) };
        _ = t.bytes.fetchAdd(@sizeOf(Fix) + e.tx.len, .monotonic);
        return f;
    }

    fn free(t: *Table, x: Garbage) void {
        const gpa = t.gpa.?;
        var n: usize = 0;
        switch (x) {
            .set => |s| {
                n = @sizeOf(Set);
                gpa.destroy(s);
            },
            .base => |b| {
                n = @sizeOf(Base) + b.slots.len * @sizeOf(Slot) + b.seqs.len * @sizeOf(SeqGen);
                gpa.free(b.slots);
                gpa.free(b.seqs);
                gpa.destroy(b);
            },
            .delta => |d| {
                n = @sizeOf(Delta) + d.slots.len * (@sizeOf(Slot) + @sizeOf(u64));
                gpa.free(d.keys);
                gpa.free(d.slots);
                gpa.destroy(d);
            },
            .fix => |f| {
                n = @sizeOf(Fix) + f.tx.len;
                gpa.free(f.tx);
                gpa.destroy(f);
            },
        }
        _ = t.bytes.fetchSub(n, .monotonic);
    }

    /// The live slots of `base` overlaid with `newer` (install order: a later slot for a digest
    /// wins), sorted by digest, one per digest. Superseded slots are dropped silently (their
    /// envelopes were retired when superseded); live slots below `floor` go to `garbage`
    /// (capacity reserved by the caller is not assumed: appended with `gpa`).
    fn build(t: *Table, base: []const Slot, newer: []const Slot, floor: u64, garbage: *std.ArrayList(Garbage)) ![]Slot {
        const gpa = t.gpa.?;
        const tmp = try gpa.alloc(Slot, newer.len);
        defer gpa.free(tmp);
        for (newer, 0..) |sl, i| tmp[newer.len - 1 - i] = sl; // newest first
        std.sort.block(Slot, tmp, {}, lessSlot); // stable: the newest of a digest stays first
        var u: usize = 0;
        for (tmp) |sl| {
            if (u > 0 and std.mem.eql(u8, &tmp[u - 1].digest, &sl.digest)) continue;
            tmp[u] = sl;
            u += 1;
        }
        const nw = tmp[0..u];
        var out = try gpa.alloc(Slot, base.len + nw.len);
        errdefer gpa.free(out);
        var dropped: std.ArrayList(Garbage) = .empty;
        defer dropped.deinit(gpa);
        var k: usize = 0;
        var i: usize = 0;
        var j: usize = 0;
        while (i < base.len or j < nw.len) {
            var sl: Slot = undefined;
            if (j == nw.len) {
                sl = base[i];
                i += 1;
            } else if (i == base.len) {
                sl = nw[j];
                j += 1;
            } else switch (std.mem.order(u8, &base[i].digest, &nw[j].digest)) {
                .lt => {
                    sl = base[i];
                    i += 1;
                },
                .gt => {
                    sl = nw[j];
                    j += 1;
                },
                .eq => {
                    sl = nw[j];
                    i += 1;
                    j += 1;
                },
            }
            if (sl.seq < floor) {
                try dropped.append(gpa, .{ .fix = @constCast(sl.fix) });
                continue;
            }
            out[k] = sl;
            k += 1;
        }
        out = try gpa.realloc(out, k);
        try garbage.appendSlice(gpa, dropped.items);
        return out;
    }

    /// Builds a new base from `base` ++ `newer` (see `build`) with an empty delta, publishes
    /// it and retires the old set (to `garbage`).
    fn publish(t: *Table, base: *const Base, newer: []const Slot, floor: u64, garbage: *std.ArrayList(Garbage)) !void {
        const gpa = t.gpa.?;
        const mark = garbage.items.len;
        errdefer garbage.shrinkRetainingCapacity(mark); // nothing dropped was unpublished
        const slots = try t.build(base.slots, newer, floor, garbage);
        errdefer gpa.free(slots);
        try garbage.ensureUnusedCapacity(gpa, 3);
        // Per checkpoint, the newest generation: the old index (at or above the floor) merged
        // with the newer slots'. A checkpoint whose slots were all superseded keeps its entry
        // (a replacement is for the same transaction, so the same checkpoint).
        const ns = try gpa.alloc(SeqGen, newer.len);
        defer gpa.free(ns);
        var nn: usize = 0;
        for (newer) |sl| if (sl.seq >= floor) {
            ns[nn] = .{ .seq = sl.seq, .gen = sl.gen };
            nn += 1;
        };
        std.mem.sortUnstable(SeqGen, ns[0..nn], {}, struct {
            fn lt(_: void, a: SeqGen, b: SeqGen) bool {
                return a.seq < b.seq;
            }
        }.lt);
        var sg = try gpa.alloc(SeqGen, base.seqs.len + nn);
        errdefer gpa.free(sg);
        var m: usize = 0;
        var max_gen: u64 = 0;
        var i: usize = 0;
        var j: usize = 0;
        while (i < base.seqs.len or j < nn) {
            var x: SeqGen = undefined;
            if (j == nn or (i < base.seqs.len and base.seqs[i].seq <= ns[j].seq)) {
                x = base.seqs[i];
                i += 1;
            } else {
                x = ns[j];
                j += 1;
            }
            if (x.seq < floor) continue;
            max_gen = @max(max_gen, x.gen);
            if (m > 0 and sg[m - 1].seq == x.seq) {
                sg[m - 1].gen = @max(sg[m - 1].gen, x.gen);
                continue;
            }
            sg[m] = x;
            m += 1;
        }
        sg = try gpa.realloc(sg, m);
        const b = try gpa.create(Base);
        errdefer gpa.destroy(b);
        b.* = .{ .slots = slots, .seqs = sg, .max_gen = max_gen };
        const cap = deltaCap(slots.len);
        const keys = try gpa.alloc(u64, cap);
        errdefer gpa.free(keys);
        const dslots = try gpa.alloc(Slot, cap);
        errdefer gpa.free(dslots);
        const d = try gpa.create(Delta);
        errdefer gpa.destroy(d);
        d.* = .{ .keys = keys, .slots = dslots };
        const s = try gpa.create(Set);
        s.* = .{ .base = b, .delta = d };
        _ = t.bytes.fetchAdd(@sizeOf(Set) + @sizeOf(Base) + slots.len * @sizeOf(Slot) + m * @sizeOf(SeqGen) +
            @sizeOf(Delta) + cap * (@sizeOf(Slot) + @sizeOf(u64)), .monotonic);
        t.cur.store(s, .release);
        if (t.set) |old| {
            garbage.appendAssumeCapacity(.{ .set = old });
            garbage.appendAssumeCapacity(.{ .base = @constCast(old.base) });
            garbage.appendAssumeCapacity(.{ .delta = old.delta });
        }
        t.set = s;
    }

    fn baseOf(t: *const Table) *const Base {
        return if (t.set) |s| s.base else &empty_base;
    }

    /// The delta is full: base ++ delta become the new base.
    fn merge(t: *Table, garbage: *std.ArrayList(Garbage)) !void {
        const s = t.set.?;
        try t.publish(s.base, s.delta.slots[0..s.delta.len.raw], 0, garbage);
    }
};

// ---------------------------------------------------------------------------------- tests

const testing = std.testing;

fn testTable(rd: *Readers) Table {
    return .{ .gpa = testing.allocator, .readers = rd };
}

test "txfix: find, replace, generations and per-checkpoint staleness" {
    var rd: Readers = .{};
    var t = testTable(&rd);
    defer t.deinit();
    const d1: [32]u8 = @splat(1);
    const d2: [32]u8 = @splat(2);
    const d0: [32]u8 = @splat(0);
    try testing.expect(t.find(&d1) == null);
    try testing.expect(!t.changedSince(5, 0));
    try testing.expect(try t.put(5, &d2, "bb"));
    try testing.expect(try t.put(7, &d1, "aa"));
    try testing.expectEqual(@as(u64, 2), t.generation());
    try testing.expectEqualStrings("aa", t.find(&d1).?.tx);
    try testing.expectEqualStrings("bb", t.find(&d2).?.tx);
    try testing.expect(t.find(&d0) == null);
    // Same bytes again: nothing new.
    try testing.expect(!try t.put(7, &d1, "aa"));
    try testing.expectEqual(@as(u64, 2), t.generation());
    try testing.expect(t.installed(&d1, "aa"));
    try testing.expect(!t.installed(&d1, "ab"));
    // Staleness is per checkpoint.
    try testing.expect(t.changedSince(5, 0));
    try testing.expect(!t.changedSince(5, 1));
    try testing.expect(t.changedSince(7, 1));
    try testing.expect(!t.changedSince(6, 0));
    // Replaced in place.
    try testing.expect(try t.put(7, &d1, "AA"));
    try testing.expectEqualStrings("AA", t.find(&d1).?.tx);
    try testing.expectEqual(@as(usize, 2), t.count());
    try testing.expect(t.changedSince(7, 2));
    // With no snapshot live, the replaced envelope is freed at the next write.
    t.collect();
    try testing.expectEqual(@as(usize, 0), t.retired.items.len);
}

fn testDigest(i: u64) [32]u8 {
    var d: [32]u8 = undefined;
    // Spread over the key space (a stride through u64), the index recoverable from bytes 8..16.
    std.mem.writeInt(u64, d[0..8], i *% 0x9E3779B97F4A7C15, .little);
    std.mem.writeInt(u64, d[8..16], i, .little);
    @memset(d[16..], @truncate(i));
    return d;
}

fn testTx(buf: *[96]u8, i: u64, ver: u8) []const u8 {
    std.mem.writeInt(u64, buf[0..8], i, .little);
    buf[8] = ver;
    for (buf[9..], 9..) |*b, k| b.* = @truncate(i *% 31 +% k +% ver);
    return buf;
}

/// Counts live and peak bytes (the writer's allocations).
const Counting = struct {
    child: Allocator,
    live: Atomic(usize) = .init(0),
    peak: Atomic(usize) = .init(0),

    fn allocator(c: *Counting) Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = freeFn } };
    }
    fn add(c: *Counting, n: usize) void {
        const v = c.live.fetchAdd(n, .monotonic) + n;
        _ = c.peak.fetchMax(v, .monotonic);
    }
    fn alloc(p: *anyopaque, n: usize, a: std.mem.Alignment, r: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(p));
        const m = c.child.rawAlloc(n, a, r) orelse return null;
        c.add(n);
        return m;
    }
    fn resize(p: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, r: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(p));
        if (!c.child.rawResize(m, a, n, r)) return false;
        if (n > m.len) c.add(n - m.len) else _ = c.live.fetchSub(m.len - n, .monotonic);
        return true;
    }
    fn remap(p: *anyopaque, m: []u8, a: std.mem.Alignment, n: usize, r: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(p));
        const x = c.child.rawRemap(m, a, n, r) orelse return null;
        if (n > m.len) c.add(n - m.len) else _ = c.live.fetchSub(m.len - n, .monotonic);
        return x;
    }
    fn freeFn(p: *anyopaque, m: []u8, a: std.mem.Alignment, r: usize) void {
        const c: *Counting = @ptrCast(@alignCast(p));
        c.child.rawFree(m, a, r);
        _ = c.live.fetchSub(m.len, .monotonic);
    }
};

test "txfix: 100k fixes stay linear in memory; concurrent readers stay correct" {
    const n: u64 = 100_000;
    var counting: Counting = .{ .child = testing.allocator };
    var rd: Readers = .{};
    var t: Table = .{ .gpa = counting.allocator(), .readers = &rd };
    defer t.deinit();
    // Fixes 0..published are installed (version 1, or 2 for every 50th once replaced).
    var published: Atomic(u64) = .init(0);
    var replaced: Atomic(u64) = .init(0);
    var stop: Atomic(bool) = .init(false);
    var bad: Atomic(u64) = .init(0);
    var reads: Atomic(u64) = .init(0);
    const Reader = struct {
        fn run(tb: *Table, r: *Readers, pub_: *Atomic(u64), rep: *Atomic(u64), st: *Atomic(bool), bd: *Atomic(u64), rs: *Atomic(u64), seed: u64) void {
            var prng: std.Random.DefaultPrng = .init(seed);
            const rand = prng.random();
            var buf: [96]u8 = undefined;
            while (!st.load(.acquire)) {
                // As a Snapshot: register, read, hold the envelopes a while, leave.
                const e = r.enter();
                const p = pub_.load(.acquire);
                const done_rep = rep.load(.acquire);
                var held: [8]?*const Fix = @splat(null);
                var want: [8]u64 = undefined;
                for (&held, &want) |*h, *w| {
                    if (p == 0) break;
                    const i = rand.uintLessThan(u64, p);
                    w.* = i;
                    h.* = tb.find(&testDigest(i));
                }
                std.atomic.spinLoopHint();
                for (held, want) |h, i| {
                    if (p == 0) break;
                    const f = h orelse {
                        _ = bd.fetchAdd(1, .monotonic);
                        continue;
                    };
                    const v1 = testTx(&buf, i, 1);
                    const ok1 = std.mem.eql(u8, f.tx, v1);
                    const ok2 = i % 50 == 0 and std.mem.eql(u8, f.tx, testTx(&buf, i, 2));
                    // Once replaced (and seen as such before the lookup), never version 1 again.
                    const must2 = i % 50 == 0 and i < done_rep;
                    if (!(ok2 or (ok1 and !must2))) _ = bd.fetchAdd(1, .monotonic);
                    if (!std.mem.eql(u8, &f.digest, &testDigest(i))) _ = bd.fetchAdd(1, .monotonic);
                }
                _ = rs.fetchAdd(1, .monotonic);
                _ = r.exit(e);
            }
        }
    };
    var threads: [3]std.Thread = undefined;
    for (&threads, 0..) |*th, k| th.* = try std.Thread.spawn(.{}, Reader.run, .{ &t, &rd, &published, &replaced, &stop, &bad, &reads, k + 1 });
    var bufs: [200][96]u8 = undefined;
    var batch: [200]Entry = undefined;
    var i: u64 = 0;
    while (i < n) {
        const m: usize = @intCast(@min(200, n - i));
        for (batch[0..m], bufs[0..m], 0..) |*e, *b, k| {
            const x = i + k;
            e.* = .{ .seq = 1000 + x / 10, .digest = testDigest(x), .tx = testTx(b, x, 1) };
        }
        // Single puts as well as batches.
        if ((i / 200) % 4 == 0) {
            for (batch[0..m]) |*e| try testing.expect(try t.put(e.seq, &e.digest, e.tx));
        } else try testing.expectEqual(m, try t.putMany(batch[0..m]));
        i += m;
        published.store(i, .release);
        // Replace every 50th fix of the first half once the writer is past it.
        if (i % 10_000 == 0 and i <= n / 2) {
            var r = replaced.load(.monotonic);
            while (r < i) : (r += 50) {
                var b: [96]u8 = undefined;
                try testing.expect(try t.put(1000 + r / 10, &testDigest(r), testTx(&b, r, 2)));
            }
            replaced.store(i, .release);
        }
    }
    stop.store(true, .release);
    for (threads) |th| th.join();
    try testing.expectEqual(@as(u64, 0), bad.load(.monotonic));
    try testing.expect(reads.load(.monotonic) > 0);
    try testing.expectEqual(@as(usize, n), t.count());
    t.collect();
    // Every fix reads back; staleness answers agree with a direct scan.
    var buf: [96]u8 = undefined;
    var k: u64 = 0;
    while (k < n) : (k += 1) {
        const f = t.find(&testDigest(k)).?;
        const ver: u8 = if (k % 50 == 0 and k < n / 2) 2 else 1;
        try testing.expectEqualSlices(u8, testTx(&buf, k, ver), f.tx);
    }
    // Linear: the live set is about n * (envelope + Fix + slot + seq index), and the peak at
    // most a base and a delta more (no snapshot held a retired base for long). The old table
    // kept every published array: about 4 n^2 bytes, 40 GB here.
    const per_fix = 96 + @sizeOf(Fix) + @sizeOf(Slot) + @sizeOf(SeqGen);
    const live = counting.live.load(.monotonic);
    const peak = counting.peak.load(.monotonic);
    try testing.expect(live <= n * per_fix + (1 << 20));
    // Loose: a reader thread descheduled while registered holds the bases retired meanwhile.
    try testing.expect(peak <= 8 * n * per_fix);
    try testing.expectEqual(t.heldBytes(), live - t.retired.capacity * @sizeOf(Retired));
    std.debug.print("txfix 100k: live {d} B ({d} B/fix), peak {d} B, reads {d}\n", .{ live, live / n, peak, reads.load(.monotonic) });
}

test "txfix: a held snapshot keeps retired envelopes; release frees them" {
    var rd: Readers = .{};
    var t = testTable(&rd);
    defer t.deinit();
    const d1: [32]u8 = @splat(1);
    try testing.expect(try t.put(5, &d1, "v1"));
    const e = rd.enter();
    const held = t.find(&d1).?;
    try testing.expect(try t.put(5, &d1, "v2"));
    // Many more puts force merges: the held envelope and the sets it was reached through stay.
    var k: u64 = 0;
    while (k < 1000) : (k += 1) _ = try t.put(6, &testDigest(k + 100), "x");
    try testing.expectEqualStrings("v1", held.tx);
    try testing.expect(t.retired.items.len > 0);
    _ = rd.exit(e);
    t.collect();
    try testing.expectEqual(@as(usize, 0), t.retired.items.len);
    try testing.expectEqualStrings("v2", t.find(&d1).?.tx);
}

test "txfix: load builds one set; later entries win; dropBelow prunes" {
    var rd: Readers = .{};
    var t = testTable(&rd);
    defer t.deinit();
    var entries: std.ArrayList(Entry) = .empty;
    defer entries.deinit(testing.allocator);
    var bufs: [3000][96]u8 = undefined;
    for (0..3000) |k| {
        const x: u64 = k % 2500; // the last 500 replace earlier ones
        try entries.append(testing.allocator, .{ .seq = 10 + x / 100, .digest = testDigest(x), .tx = testTx(&bufs[k], x, if (k >= 2500) 2 else 1) });
    }
    try testing.expectEqual(@as(usize, 2500), try t.load(entries.items));
    try testing.expectEqual(@as(u64, 1), t.generation()); // one publish
    try testing.expectEqual(@as(usize, 2500), t.count());
    try testing.expectEqual(@as(usize, 0), t.set.?.delta.len.raw);
    var buf: [96]u8 = undefined;
    for (0..2500) |k| {
        const ver: u8 = if (k < 500) 2 else 1;
        try testing.expectEqualSlices(u8, testTx(&buf, k, ver), t.find(&testDigest(k)).?.tx);
    }
    // Same bytes again: nothing.
    try testing.expectEqual(@as(usize, 0), try t.load(entries.items[2500..]));
    try testing.expectEqual(@as(u64, 1), t.generation());
    try testing.expect(t.changedSince(12, 0));
    try testing.expect(!t.changedSince(12, 1));
    // A put after the load lands in the delta; a drop rebuilds without the pruned checkpoints.
    try testing.expect(try t.put(30, &testDigest(5000), "late"));
    try testing.expectEqual(@as(usize, 1000), try t.dropBelow(20));
    try testing.expectEqual(@as(usize, 1501), t.count());
    try testing.expect(t.find(&testDigest(5)) == null); // checkpoint 10
    try testing.expect(t.find(&testDigest(1000)) != null); // checkpoint 20
    try testing.expectEqualStrings("late", t.find(&testDigest(5000)).?.tx);
    try testing.expectEqual(@as(usize, 0), try t.dropBelow(20));
    t.collect();
    try testing.expectEqual(@as(usize, 0), t.retired.items.len);
}
