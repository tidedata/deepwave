//! `suggested_gas_price` (sui-core 1.83.1 `congestion_tracker.rs`): per consensus object, the
//! clearing price learnt from the checkpoints executed since the process started. A transaction
//! cancelled for congestion records its gas price as a cancelled bid on the congested objects;
//! any other transaction records its price as an executed bid on the consensus objects it
//! mutated (only for objects already known as congested). Simulate answers the maximum clearing
//! price over the transaction's exclusively accessed (mutable) shared inputs.
//!
//! sui-node feeds it from the checkpoint executor, every executed checkpoint; deepwave feeds it
//! from one background thread that follows the store's committed checkpoints (`catchUpLocked`
//! over `SnapshotSource`), so the request path only reads the price.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

pub const Info = struct {
    last_cancellation_time: u64,
    highest_cancelled_gas_price: u64,
    last_success_time: ?u64 = null,
    lowest_executed_gas_price: ?u64 = null,

    fn updateForNewCheckpoint(self: *Info, new: *const Info) void {
        if (new.last_cancellation_time > self.last_cancellation_time) {
            self.last_cancellation_time = new.last_cancellation_time;
            self.highest_cancelled_gas_price = new.highest_cancelled_gas_price;
        }
        // Option ordering: None < Some
        if (optGt(new.last_success_time, self.last_success_time)) {
            self.last_success_time = new.last_success_time;
            self.lowest_executed_gas_price = new.lowest_executed_gas_price;
        }
    }
};

fn optGt(a: ?u64, b: ?u64) bool {
    const x = a orelse return false;
    const y = b orelse return true;
    return x > y;
}

/// One transaction of a checkpoint, as the tracker sees it.
pub const Event = struct {
    gas_price: u64,
    /// Cancelled for congestion: the congested objects. Otherwise null.
    congested: ?[]const Id,
    /// The consensus objects the transaction mutated (`InputConsensusObject::Mutate`).
    mutated: []const Id,
};

/// Rust's moka cache holds 10,000 objects; over that, the oldest entry goes.
const capacity = 10_000;

pub const Tracker = struct {
    gpa: Allocator,
    map: std.AutoArrayHashMapUnmanaged(Id, Info) = .empty,
    /// The next checkpoint `catchUp` reads; null until the first call (which starts at the tip,
    /// as a freshly started sui-node does).
    next_seq: ?u64 = null,

    pub fn deinit(t: *Tracker) void {
        t.map.deinit(t.gpa);
    }

    pub fn get(t: *const Tracker, id: *const Id) ?Info {
        return t.map.get(id.*);
    }

    /// `process_per_checkpoint_events`.
    pub fn processCheckpoint(t: *Tracker, arena: Allocator, now: u64, events: []const Event) Allocator.Error!void {
        var per: std.AutoArrayHashMapUnmanaged(Id, Info) = .empty;
        for (events) |e| if (e.congested) |objs| for (objs) |id| {
            const gop = try per.getOrPut(arena, id);
            if (gop.found_existing) {
                gop.value_ptr.highest_cancelled_gas_price = @max(gop.value_ptr.highest_cancelled_gas_price, e.gas_price);
            } else gop.value_ptr.* = .{ .last_cancellation_time = now, .highest_cancelled_gas_price = e.gas_price };
        };
        for (events) |e| if (e.congested == null) for (e.mutated) |id| {
            if (per.getPtr(id)) |info| {
                info.last_success_time = now;
                info.lowest_executed_gas_price = if (info.lowest_executed_gas_price) |m| @min(m, e.gas_price) else e.gas_price;
            } else if (t.map.get(id)) |prev| {
                try per.put(arena, id, .{
                    .last_cancellation_time = prev.last_cancellation_time,
                    .highest_cancelled_gas_price = prev.highest_cancelled_gas_price,
                    .last_success_time = now,
                    .lowest_executed_gas_price = e.gas_price,
                });
            }
        };
        var it = per.iterator();
        while (it.next()) |kv| {
            if (t.map.getPtr(kv.key_ptr.*)) |cur| {
                cur.updateForNewCheckpoint(kv.value_ptr);
            } else {
                if (t.map.count() >= capacity) t.map.orderedRemoveAt(0);
                try t.map.put(t.gpa, kv.key_ptr.*, kv.value_ptr.*);
            }
        }
    }

    /// `get_suggested_gas_price_for_objects`.
    pub fn suggested(t: *const Tracker, ids: []const Id) ?u64 {
        var price: ?u64 = null;
        for (ids) |id| {
            const info = t.map.get(id) orelse continue;
            const cancel: ?u64 = info.last_cancellation_time;
            const for_obj: ?u64 = if (optGt(info.last_success_time, cancel))
                null
            else if (optGt(cancel, info.last_success_time))
                info.highest_cancelled_gas_price
            else
                info.lowest_executed_gas_price;
            if (for_obj) |p| price = if (price) |q| @max(p, q) else p;
        }
        return price;
    }

    /// Reads every checkpoint `src` committed after the last one read, up to `src`'s own tip
    /// (never a tip read elsewhere: a checkpoint the source cannot see yet stays pending). The
    /// first call starts after the tip, as a freshly started sui-node does. A checkpoint below
    /// the tip that the source does not hold (pruned) or cannot decode is skipped; on OOM the
    /// rest stays pending. `src`: `tip() ?u64` and `events(arena, seq) !?CheckpointEvents`
    /// (`SnapshotSource`). Returns how many checkpoints were processed.
    pub fn catchUp(t: *Tracker, src: anytype) usize {
        return t.catchUpLocked(src, null);
    }

    /// `catchUp` with `processCheckpoint` under `lock` (decoding stays outside it), for a tracker
    /// read by other threads. Only one thread may call it.
    pub fn catchUpLocked(t: *Tracker, src: anytype, lock: ?Lock) usize {
        const tip = src.tip() orelse return 0;
        var seq = t.next_seq orelse {
            t.next_seq = tip + 1;
            return 0;
        };
        var n: usize = 0;
        defer t.next_seq = seq;
        while (seq <= tip) : (seq += 1) {
            var arena: std.heap.ArenaAllocator = .init(t.gpa);
            defer arena.deinit();
            const cp = (src.events(arena.allocator(), seq) catch |e| {
                if (e == error.OutOfMemory) return n;
                continue;
            }) orelse continue;
            if (lock) |l| l.mu.lockUncancelable(l.io);
            defer if (lock) |l| l.mu.unlock(l.io);
            t.processCheckpoint(arena.allocator(), cp.timestamp_ms, cp.events) catch return n;
            n += 1;
        }
        return n;
    }
};

pub const Lock = struct { mu: *std.Io.Mutex, io: std.Io };

pub const CheckpointEvents = struct { timestamp_ms: u64, events: []const Event };

/// A store snapshot as a tracker source: its own committed tip and checkpoints.
pub const SnapshotSource = struct {
    snap: *const store.Snapshot,

    pub fn tip(s: SnapshotSource) ?u64 {
        return s.snap.highestCommitted();
    }

    /// The tracker's events of checkpoint `seq` (null: the snapshot does not hold it).
    pub fn events(s: SnapshotSource, arena: Allocator, seq: u64) !?CheckpointEvents {
        const rec = s.snap.checkpoint(seq) orelse return null;
        var rd = bcs.Reader.init(rec.summary_cert);
        const summary = try bcs.decodeFrom(types.CheckpointSummary, arena, &rd);
        const contents = try bcs.decode(types.CheckpointContents, arena, rec.contents);
        var digests: std.ArrayList(Id) = .empty;
        switch (contents) {
            .V1 => |c| for (c.transactions) |x| try digests.append(arena, x.transaction.@"0".@"0"),
            .V2 => |c| for (c.transactions) |x| try digests.append(arena, x.digest.transaction.@"0".@"0"),
        }
        var evs: std.ArrayList(Event) = .empty;
        for (digests.items) |*d| {
            const tr = s.snap.transaction(d) orelse continue;
            if (try eventOf(arena, tr.tx, tr.effects)) |e| try evs.append(arena, e);
        }
        return .{ .timestamp_ms = summary.timestamp_ms, .events = evs.items };
    }
};

/// The tracker's view of one executed transaction (`process_checkpoint_effects`).
pub fn eventOf(arena: Allocator, tx_bcs: []const u8, effects_bcs: []const u8) !?Event {
    const ssd = try bcs.decode(types.SenderSignedData, arena, tx_bcs);
    const td = switch (ssd.@"0".element().intent_message.value) {
        .V1 => |v| v,
    };
    const eff = try bcs.decode(types.TransactionEffects, arena, effects_bcs);
    const v2 = switch (eff) {
        .V2 => |v| v,
        .V1 => return null, // no consensus-object congestion before effects v2
    };
    var ev: Event = .{ .gas_price = td.gas_data.price, .congested = null, .mutated = &.{} };
    switch (v2.status) {
        .Success => {},
        .Failure => |f| switch (f.@"error") {
            .ExecutionCancelledDueToSharedObjectCongestion => |c| {
                const out = try arena.alloc(Id, c.congested_objects.@"0".len);
                for (c.congested_objects.@"0", out) |o, *id| id.* = o.@"0".@"0";
                ev.congested = out;
                return ev;
            },
            else => {},
        },
    }
    // InputConsensusObject::Mutate: changed objects whose input owner is consensus-owned
    var mutated: std.ArrayList(Id) = .empty;
    for (v2.changed_objects) |c| switch (c[1].input_state) {
        .Exist => |ex| switch (ex[1]) {
            .Shared, .ConsensusAddressOwner => try mutated.append(arena, c[0].@"0".@"0"),
            else => {},
        },
        .NotExist => {},
    };
    ev.mutated = mutated.items;
    return ev;
}

/// The transaction's exclusively accessed shared inputs (`shared_input_objects` with
/// `is_accessed_exclusively`).
pub fn exclusiveShared(arena: Allocator, td: *const types.TransactionDataV1) Allocator.Error![]const Id {
    var out: std.ArrayList(Id) = .empty;
    switch (td.kind) {
        .ProgrammableTransaction => |pt| for (pt.inputs) |*a| switch (a.*) {
            .Object => |o| switch (o) {
                .SharedObject => |s| if (s.mutability == .Mutable) try out.append(arena, s.id.@"0".@"0"),
                else => {},
            },
            else => {},
        },
        else => {},
    }
    return out.items;
}

test "clearing price follows cancellations then successes" {
    const gpa = std.testing.allocator;
    var t: Tracker = .{ .gpa = gpa };
    defer t.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a: Id = @splat(1);
    const b: Id = @splat(2);
    // checkpoint 1: two cancelled bids on a, one success elsewhere
    try t.processCheckpoint(arena.allocator(), 1000, &.{
        .{ .gas_price = 700, .congested = &.{a}, .mutated = &.{} },
        .{ .gas_price = 900, .congested = &.{a}, .mutated = &.{} },
        .{ .gas_price = 500, .congested = null, .mutated = &.{b} },
    });
    try std.testing.expect(t.get(&b) == null); // b was never congested
    try std.testing.expectEqual(@as(?u64, 900), t.suggested(&.{ a, b }));
    // checkpoint 2: a clears at 800 with no new cancellation: no longer congested
    try t.processCheckpoint(arena.allocator(), 2000, &.{.{ .gas_price = 800, .congested = null, .mutated = &.{a} }});
    try std.testing.expectEqual(@as(?u64, null), t.suggested(&.{a}));
    // checkpoint 3: both cancellations and successes on a: the lowest executed price
    try t.processCheckpoint(arena.allocator(), 3000, &.{
        .{ .gas_price = 1200, .congested = &.{a}, .mutated = &.{} },
        .{ .gas_price = 1500, .congested = null, .mutated = &.{a} },
        .{ .gas_price = 1300, .congested = null, .mutated = &.{a} },
    });
    try std.testing.expectEqual(@as(?u64, 1300), t.suggested(&.{a}));
}

test "catch-up reads every checkpoint up to the source's own tip, with no cap" {
    const gpa = std.testing.allocator;
    var t: Tracker = .{ .gpa = gpa };
    defer t.deinit();
    const a: Id = @splat(3);
    const Fake = struct {
        tip_seq: ?u64,
        /// sequence of the only checkpoint with a cancellation
        cancel_at: u64,
        missing: u64 = std.math.maxInt(u64),
        pub fn tip(f: @This()) ?u64 {
            return f.tip_seq;
        }
        pub fn events(f: @This(), arena: Allocator, seq: u64) !?CheckpointEvents {
            if (seq == f.missing) return null;
            if (seq != f.cancel_at) return .{ .timestamp_ms = seq, .events = &.{} };
            const objs = try arena.dupe(Id, &.{@as(Id, @splat(3))});
            const evs = try arena.dupe(Event, &.{.{ .gas_price = 4242, .congested = objs, .mutated = &.{} }});
            return .{ .timestamp_ms = seq, .events = evs };
        }
    };
    // first call starts after the tip
    try std.testing.expectEqual(@as(usize, 0), t.catchUp(Fake{ .tip_seq = 10, .cancel_at = 5 }));
    try std.testing.expectEqual(@as(?u64, 11), t.next_seq);
    // 500 checkpoints later (far past the old 64 cap), the cancellation in the first one counts
    try std.testing.expectEqual(@as(usize, 499), t.catchUp(Fake{ .tip_seq = 510, .cancel_at = 11, .missing = 300 }));
    try std.testing.expectEqual(@as(?u64, 511), t.next_seq);
    try std.testing.expectEqual(@as(?u64, 4242), t.suggested(&.{a}));
    // a source whose tip is behind the tracker reads nothing and moves nothing
    try std.testing.expectEqual(@as(usize, 0), t.catchUp(Fake{ .tip_seq = 400, .cancel_at = 0 }));
    try std.testing.expectEqual(@as(?u64, 511), t.next_seq);
    // an empty source (nothing committed) reads nothing
    try std.testing.expectEqual(@as(usize, 0), t.catchUp(Fake{ .tip_seq = null, .cancel_at = 0 }));
}
