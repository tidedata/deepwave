//! Per-stage latency tracer (docs/VALIDATOR-DESIGN.md 10.1). Implements both tracer seams:
//! `validator/iface.zig` Tracer (stages keyed by a 32-byte transaction, block or checkpoint
//! digest) and `consensus/iface.zig` Tracer (stages keyed by BlockRef).
//!
//! Each key gets a timeline of marks in a fixed open-addressing table. When a mark lands, the
//! time since the nearest earlier mark of the same chain goes into the histogram of that stage
//! (the "segment" ending at the stage), and when a chain's last stage lands the whole span goes
//! into the chain's total histogram and the slot is released. No allocation after init, one
//! short spin lock per mark, histograms are plain atomics. A null tracer costs the callers one
//! branch (the Tracer structs are optional). Off by default: nothing creates a StageTracer
//! unless `Flags.trace` is set.
const std = @import("std");
const consensus = @import("consensus");
const iface = @import("../iface.zig");
const hist = @import("hist.zig");

/// Every measurable point of the pipeline: the union of validator `iface.Stage` and
/// `consensus.iface.Tracer.Stage`.
pub const Point = enum(u8) {
    // transaction chain
    tx_received,
    tx_validated,
    tx_submitted,
    tx_in_proposed_block,
    tx_sequenced,
    tx_executed,
    effects_served,
    // block chain
    block_received,
    block_verified,
    block_accepted,
    block_proposed,
    leader_committed,
    sub_dag_finalized,
    // checkpoint chain
    checkpoint_built,
    checkpoint_signed,
    checkpoint_certified,

    pub const count = std.enums.values(Point).len;

    pub fn name(p: Point) []const u8 {
        return @tagName(p);
    }
    pub fn chain(p: Point) Chain {
        return switch (p) {
            .tx_received, .tx_validated, .tx_submitted, .tx_in_proposed_block, .tx_sequenced, .tx_executed, .effects_served => .tx,
            .block_received, .block_verified, .block_accepted, .block_proposed, .leader_committed, .sub_dag_finalized => .block,
            .checkpoint_built, .checkpoint_signed, .checkpoint_certified => .checkpoint,
        };
    }
};

pub const Chain = enum(u8) {
    tx,
    block,
    checkpoint,

    pub const count = std.enums.values(Chain).len;

    /// Stages in pipeline order.
    pub fn points(c: Chain) []const Point {
        return switch (c) {
            .tx => &.{ .tx_received, .tx_validated, .tx_submitted, .tx_in_proposed_block, .tx_sequenced, .tx_executed, .effects_served },
            .block => &.{ .block_received, .block_verified, .block_accepted, .block_proposed, .leader_committed, .sub_dag_finalized },
            .checkpoint => &.{ .checkpoint_built, .checkpoint_signed, .checkpoint_certified },
        };
    }
    /// Points that start a complete timeline; a chain total is recorded only when one is set.
    /// Block: received, or proposed for our own blocks (never received). Tx and checkpoint:
    /// their first stage.
    pub fn isStart(c: Chain, p: Point) bool {
        return switch (c) {
            .tx => p == .tx_received,
            .block => p == .block_received or p == .block_proposed,
            .checkpoint => p == .checkpoint_built,
        };
    }
    pub fn last(c: Chain) Point {
        const p = c.points();
        return p[p.len - 1];
    }
};

pub fn fromValidatorStage(s: iface.Stage) Point {
    return switch (s) {
        .tx_received => .tx_received,
        .tx_validated => .tx_validated,
        .tx_submitted => .tx_submitted,
        .tx_in_proposed_block => .tx_in_proposed_block,
        .block_received => .block_received,
        .block_verified => .block_verified,
        .leader_committed => .leader_committed,
        .sub_dag_finalized => .sub_dag_finalized,
        .tx_sequenced => .tx_sequenced,
        .tx_executed => .tx_executed,
        .checkpoint_built => .checkpoint_built,
        .checkpoint_signed => .checkpoint_signed,
        .checkpoint_certified => .checkpoint_certified,
        .effects_served => .effects_served,
    };
}

pub fn fromConsensusStage(s: consensus.iface.Tracer.Stage) Point {
    return switch (s) {
        .block_received => .block_received,
        .block_verified => .block_verified,
        .block_accepted => .block_accepted,
        .block_proposed => .block_proposed,
        .leader_committed => .leader_committed,
        .sub_dag_emitted => .sub_dag_finalized,
    };
}

/// The collected numbers: one histogram per segment (indexed by the stage the segment ends at)
/// and one per chain total. Plain atomics, so it can also live in shared memory.
pub const Budget = struct {
    segments: [Point.count]hist.Hist = @splat(.{}),
    totals: [Chain.count]hist.Hist = @splat(.{}),
    /// Timelines evicted before finishing (table full) and marks that arrived for a stage that
    /// was already marked on that key.
    evicted: std.atomic.Value(u64) = .init(0),
    duplicates: std.atomic.Value(u64) = .init(0),
    /// Timelines that reached the last stage without a start mark (transactions submitted via
    /// other validators, timelines re-created after eviction): kept out of the totals.
    partial: std.atomic.Value(u64) = .init(0),

    pub fn segment(b: *const Budget, p: Point) *const hist.Hist {
        return &b.segments[@intFromEnum(p)];
    }
    pub fn total(b: *const Budget, c: Chain) *const hist.Hist {
        return &b.totals[@intFromEnum(c)];
    }
};

const Slot = struct {
    used: bool = false,
    key: [32]u8 = undefined,
    /// Mono ns per Point, 0 = unset.
    marks: [Point.count]u64 = @splat(0),
    first: u64 = 0,
};

const SpinLock = struct {
    locked: std.atomic.Value(bool) = .init(false),
    fn lock(l: *SpinLock) void {
        while (l.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn unlock(l: *SpinLock) void {
        l.locked.store(false, .release);
    }
};

pub const probe_len = 8;

pub const StageTracer = struct {
    gpa: std.mem.Allocator,
    slots: []Slot,
    mask: usize,
    lock: SpinLock = .{},
    budget: Budget = .{},

    /// `capacity` timelines in flight (rounded up to a power of two). A timeline lives from its
    /// first mark to the last stage of its chain, so this bounds in-flight transactions plus
    /// blocks; 1 << 14 is plenty for the localnet.
    pub fn create(gpa: std.mem.Allocator, capacity: usize) std.mem.Allocator.Error!*StageTracer {
        const cap = std.math.ceilPowerOfTwo(usize, @max(capacity, probe_len)) catch return error.OutOfMemory;
        const t = try gpa.create(StageTracer);
        errdefer gpa.destroy(t);
        const slots = try gpa.alloc(Slot, cap);
        for (slots) |*s| s.* = .{};
        t.* = .{ .gpa = gpa, .slots = slots, .mask = cap - 1 };
        return t;
    }

    pub fn destroy(t: *StageTracer) void {
        t.gpa.free(t.slots);
        t.gpa.destroy(t);
    }

    /// Records a mark at `ns` (monotonic) for `key`.
    pub fn mark(t: *StageTracer, p: Point, key: *const [32]u8, ns_in: u64) void {
        const ns = if (ns_in == 0) 1 else ns_in;
        const c = p.chain();
        var seg_ns: ?u64 = null;
        var total_ns: ?u64 = null;
        var partial = false;
        var dup = false;
        var evicted = false;
        t.lock.lock();
        {
            const s = t.find(key, ns, &evicted);
            const pi = @intFromEnum(p);
            if (s.marks[pi] != 0) {
                dup = true;
            } else {
                s.marks[pi] = ns;
                if (s.first == 0 or ns < s.first) s.first = ns;
                // nearest earlier mark in this chain
                const pts = c.points();
                var idx: usize = 0;
                while (pts[idx] != p) idx += 1;
                var prev_ns: u64 = 0;
                var j = idx;
                while (j > 0) {
                    j -= 1;
                    const m = s.marks[@intFromEnum(pts[j])];
                    if (m != 0) {
                        prev_ns = m;
                        break;
                    }
                }
                if (prev_ns != 0) seg_ns = ns -| prev_ns;
                if (p == c.last()) {
                    // Only a timeline that has its start mark is a real end-to-end span.
                    var start: u64 = 0;
                    for (pts) |q| {
                        if (!c.isStart(q)) continue;
                        const m = s.marks[@intFromEnum(q)];
                        if (m != 0 and (start == 0 or m < start)) start = m;
                    }
                    if (start != 0) {
                        if (start != ns) total_ns = ns -| start;
                    } else partial = true;
                    s.used = false;
                }
            }
        }
        t.lock.unlock();
        if (dup) _ = t.budget.duplicates.fetchAdd(1, .monotonic);
        if (evicted) _ = t.budget.evicted.fetchAdd(1, .monotonic);
        if (partial) _ = t.budget.partial.fetchAdd(1, .monotonic);
        if (seg_ns) |d| t.budget.segments[@intFromEnum(p)].record(d);
        if (total_ns) |d| t.budget.totals[@intFromEnum(c)].record(d);
    }

    fn find(t: *StageTracer, key: *const [32]u8, ns: u64, evicted: *bool) *Slot {
        const h = std.mem.readInt(u64, key[0..8], .little);
        const base: usize = @intCast(h & t.mask);
        var free: ?*Slot = null;
        var oldest: *Slot = &t.slots[base];
        var i: usize = 0;
        while (i < probe_len) : (i += 1) {
            const s = &t.slots[(base + i) & t.mask];
            if (s.used) {
                if (std.mem.eql(u8, &s.key, key)) return s;
                if (s.first < oldest.first or !oldest.used) oldest = s;
            } else if (free == null) free = s;
        }
        const s = free orelse blk: {
            evicted.* = true;
            break :blk oldest;
        };
        s.* = .{ .used = true, .key = key.*, .first = ns };
        return s;
    }

    /// Closes `sub_dag_finalized` for every block of a committed sub-dag. The consensus tracer
    /// marks `leader_committed` and `sub_dag_emitted` with the leader's ref only, so callers at
    /// the seam must use this for the whole sub-dag; otherwise non-leader block timelines never
    /// finish and age out as evictions.
    pub fn markSubDag(t: *StageTracer, refs: []const consensus.types.BlockRef, ns: u64) void {
        for (refs) |r| t.mark(.sub_dag_finalized, &r.digest, ns);
    }

    pub fn validatorTracer(t: *StageTracer) iface.Tracer {
        return .{ .ctx = t, .vtable = &validator_vtable };
    }
    pub fn consensusTracer(t: *StageTracer) consensus.iface.Tracer {
        return .{ .ctx = t, .vtable = &consensus_vtable };
    }

    fn validatorMark(ctx: *anyopaque, stage: iface.Stage, key: *const [32]u8, ns: u64) void {
        const t: *StageTracer = @ptrCast(@alignCast(ctx));
        t.mark(fromValidatorStage(stage), key, ns);
    }
    fn consensusMark(ctx: *anyopaque, stage: consensus.iface.Tracer.Stage, ref: consensus.types.BlockRef, ns: u64) void {
        const t: *StageTracer = @ptrCast(@alignCast(ctx));
        t.mark(fromConsensusStage(stage), &ref.digest, ns);
    }
    const validator_vtable: iface.Tracer.VTable = .{ .mark = validatorMark };
    const consensus_vtable: consensus.iface.Tracer.VTable = .{ .mark = consensusMark };
};

test "tx chain segments and total" {
    const t = try StageTracer.create(std.testing.allocator, 64);
    defer t.destroy();
    var key: [32]u8 = @as([32]u8, @splat(7));
    const tr = t.validatorTracer();
    tr.mark(.tx_received, &key, 1_000_000);
    tr.mark(.tx_validated, &key, 1_300_000); // 300 us
    tr.mark(.tx_submitted, &key, 1_400_000);
    tr.mark(.tx_in_proposed_block, &key, 51_400_000); // 50 ms in queue
    tr.mark(.tx_sequenced, &key, 151_400_000); // 100 ms
    tr.mark(.tx_executed, &key, 153_400_000);
    tr.mark(.effects_served, &key, 153_900_000);
    try std.testing.expectEqual(@as(u64, 1), t.budget.segment(.tx_in_proposed_block).count());
    const q = t.budget.segment(.tx_in_proposed_block).percentileUs(0.5);
    try std.testing.expect(q >= 46_000 and q <= 54_000);
    try std.testing.expectEqual(@as(u64, 1), t.budget.total(.tx).count());
    const tot = t.budget.total(.tx).percentileUs(0.5);
    try std.testing.expect(tot >= 140_000 and tot <= 160_000);
    // slot released: marking again starts a fresh timeline
    tr.mark(.tx_received, &key, 200_000_000);
    try std.testing.expectEqual(@as(u64, 0), t.budget.duplicates.load(.monotonic));
}

test "block chain through the consensus tracer, skipping unset stages" {
    const t = try StageTracer.create(std.testing.allocator, 64);
    defer t.destroy();
    const ref: consensus.types.BlockRef = .{ .round = 9, .author = 2, .digest = @as([32]u8, @splat(3)) };
    const tr = t.consensusTracer();
    tr.mark(.block_received, ref, 10_000);
    tr.mark(.block_verified, ref, 110_000);
    tr.mark(.block_accepted, ref, 130_000);
    tr.mark(.leader_committed, ref, 80_130_000); // proposed never set: segment is from accepted
    tr.mark(.sub_dag_emitted, ref, 80_230_000);
    try std.testing.expectEqual(@as(u64, 1), t.budget.segment(.leader_committed).count());
    try std.testing.expect(t.budget.segment(.leader_committed).percentileUs(0.5) > 70_000);
    try std.testing.expectEqual(@as(u64, 1), t.budget.total(.block).count());
}

test "duplicate marks are counted and eviction does not crash" {
    const t = try StageTracer.create(std.testing.allocator, 8);
    defer t.destroy();
    var key: [32]u8 = @as([32]u8, @splat(1));
    t.mark(.tx_received, &key, 5);
    t.mark(.tx_received, &key, 6);
    try std.testing.expectEqual(@as(u64, 1), t.budget.duplicates.load(.monotonic));
    // fill beyond capacity with colliding keys
    var i: u8 = 0;
    while (i < 40) : (i += 1) {
        var k: [32]u8 = @as([32]u8, @splat(0));
        k[8] = i;
        t.mark(.tx_received, &k, 10 + i);
    }
    try std.testing.expect(t.budget.evicted.load(.monotonic) > 0);
}

test "partial timelines stay out of the totals" {
    const t = try StageTracer.create(std.testing.allocator, 64);
    defer t.destroy();
    const key: [32]u8 = @as([32]u8, @splat(9));
    // tx submitted through another validator: only the later stages are seen here
    t.mark(.tx_sequenced, &key, 1_000_000);
    t.mark(.tx_executed, &key, 1_500_000);
    t.mark(.effects_served, &key, 1_600_000);
    try std.testing.expectEqual(@as(u64, 0), t.budget.total(.tx).count());
    try std.testing.expectEqual(@as(u64, 1), t.budget.partial.load(.monotonic));
    // sub-dag closes every block, our own proposal counts as a start
    const refs = [_]consensus.types.BlockRef{
        .{ .round = 1, .author = 0, .digest = @as([32]u8, @splat(1)) },
        .{ .round = 1, .author = 1, .digest = @as([32]u8, @splat(2)) },
    };
    t.mark(.block_proposed, &refs[0].digest, 10_000);
    t.mark(.block_received, &refs[1].digest, 20_000);
    t.markSubDag(&refs, 90_000);
    try std.testing.expectEqual(@as(u64, 2), t.budget.total(.block).count());
}
