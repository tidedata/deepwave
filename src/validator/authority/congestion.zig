//! Congestion control at mainnet-v1.83.1 protocol 141 (`per_object_congestion_control_mode:
//! ExecutionTimeEstimate`): `execution_time_estimator.rs` (the stake weighted median estimate of
//! each command) and `shared_object_congestion_tracker.rs` (per-object execution cost, budget per
//! commit, deferral, debt carried to later commits).
//!
//! All times are integer nanoseconds (Rust's Duration) except the tracker, which works in
//! microseconds as Rust does (`as_micros`). The estimator is deterministic across validators: it
//! only consumes sequenced ExecutionTimeObservation transactions.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const tx_mod = @import("tx.zig");
const deferral = @import("deferral.zig");
const bcs = @import("bcs");

const Allocator = std.mem.Allocator;
pub const Id = tx_mod.Id;
pub const Params = protocol.ExecutionTimeEstimateParams;

// ------------------------------------------------------------------------ estimator

/// `ExecutionTimeObservationKey` as an opaque canonical byte string (hash map key).
pub const ObsKey = []const u8;

const tag_move: u8 = 0;
const tag_transfer: u8 = 1;
const tag_split: u8 = 2;
const tag_merge: u8 = 3;
const tag_publish: u8 = 4;
const tag_make_vec: u8 = 5;
const tag_upgrade: u8 = 6;

/// `ExecutionTimeObservationKey::from_command`, canonical bytes. MoveEntryPoint is
/// tag, package (32), u32 module len, module, u32 function len, function, BCS type arguments
/// (always empty in `from_command`: one zero byte).
pub fn keyOfCommand(arena: Allocator, c: *const types.Command) Allocator.Error![]const u8 {
    return switch (c.*) {
        .MoveCall => |m| blk: {
            var b: std.ArrayList(u8) = .empty;
            try b.append(arena, tag_move);
            try b.appendSlice(arena, &m.package.@"0".@"0");
            try appendLen(arena, &b, m.module.@"0".len);
            try b.appendSlice(arena, m.module.@"0");
            try appendLen(arena, &b, m.function.@"0".len);
            try b.appendSlice(arena, m.function.@"0");
            // type_arguments is empty in `from_command` (BCS: one zero length byte)
            try b.append(arena, 0);
            break :blk b.items;
        },
        .TransferObjects => try arena.dupe(u8, &.{tag_transfer}),
        .SplitCoins => try arena.dupe(u8, &.{tag_split}),
        .MergeCoins => try arena.dupe(u8, &.{tag_merge}),
        .Publish => try arena.dupe(u8, &.{tag_publish}),
        .MakeMoveVec => try arena.dupe(u8, &.{tag_make_vec}),
        .Upgrade => try arena.dupe(u8, &.{tag_upgrade}),
    };
}

const StoredEntry = @typeInfo(@FieldType(types.StoredExecutionTimeObservations, "V1")).pointer.child;

/// `filter_and_sort_v1` over a key-sorted `storedObservations` snapshot: the entries whose key
/// (canonical bytes) is in `included`, at most `limit`.
pub fn filterStored(arena: Allocator, sorted: types.StoredExecutionTimeObservations, included: *const std.StringHashMapUnmanaged(void), limit: usize) Allocator.Error!types.StoredExecutionTimeObservations {
    var out: std.ArrayList(StoredEntry) = .empty;
    for (sorted.V1) |ent| {
        if (out.items.len == limit) break;
        if (included.contains(try keyBytes(arena, &ent.@"0"))) try out.append(arena, ent);
    }
    return .{ .V1 = out.items };
}

/// Canonical bytes of a key (`keyOfCommand` for MoveEntryPoint with its type arguments).
pub fn keyBytes(arena: Allocator, k: *const types.ExecutionTimeObservationKey) Allocator.Error![]const u8 {
    return @import("handler.zig").obsKeyBytes(arena, k);
}

/// The key of canonical bytes (`keyOfCommand`, handler.obsKeyBytes).
pub fn keyFromBytes(arena: Allocator, b: []const u8) (Allocator.Error || error{Corrupt})!types.ExecutionTimeObservationKey {
    if (b.len == 0) return error.Corrupt;
    return switch (b[0]) {
        tag_move => blk: {
            if (b.len < 1 + 32 + 4) return error.Corrupt;
            var p: usize = 33;
            const ml = std.mem.readInt(u32, b[p..][0..4], .little);
            p += 4;
            if (b.len < p + ml + 4) return error.Corrupt;
            const module = b[p .. p + ml];
            p += ml;
            const fl = std.mem.readInt(u32, b[p..][0..4], .little);
            p += 4;
            if (b.len < p + fl) return error.Corrupt;
            const function = b[p .. p + fl];
            p += fl;
            const ta = bcs.decode([]const types.TypeInput, arena, b[p..]) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.Corrupt,
            };
            break :blk .{ .MoveEntryPoint = .{ .package = .{ .@"0" = .{ .@"0" = b[1..33].* } }, .module = .{ .@"0" = module }, .function = .{ .@"0" = function }, .type_arguments = ta } };
        },
        tag_transfer => .{ .TransferObjects = {} },
        tag_split => .{ .SplitCoins = {} },
        tag_merge => .{ .MergeCoins = {} },
        tag_publish => .{ .Publish = {} },
        tag_make_vec => .{ .MakeMoveVec = {} },
        tag_upgrade => .{ .Upgrade = {} },
        else => error.Corrupt,
    };
}

/// Rust's derived `Ord` of `ExecutionTimeObservationKey`: variant, then package, module and
/// function (byte order), then the type arguments (lexicographic over `TypeInput`'s derived Ord).
pub fn orderKey(a: *const types.ExecutionTimeObservationKey, b: *const types.ExecutionTimeObservationKey) std.math.Order {
    const ta = @intFromEnum(std.meta.activeTag(a.*));
    const tb = @intFromEnum(std.meta.activeTag(b.*));
    if (ta != tb) return std.math.order(ta, tb);
    const ma = switch (a.*) {
        .MoveEntryPoint => |m| m,
        else => return .eq,
    };
    const mb = b.MoveEntryPoint;
    var o = std.mem.order(u8, &ma.package.@"0".@"0", &mb.package.@"0".@"0");
    if (o == .eq) o = std.mem.order(u8, ma.module.@"0", mb.module.@"0");
    if (o == .eq) o = std.mem.order(u8, ma.function.@"0", mb.function.@"0");
    if (o == .eq) o = orderTypes(ma.type_arguments, mb.type_arguments);
    return o;
}

fn orderTypes(a: []const types.TypeInput, b: []const types.TypeInput) std.math.Order {
    for (a[0..@min(a.len, b.len)], b[0..@min(a.len, b.len)]) |*x, *y| {
        const o = orderType(x, y);
        if (o != .eq) return o;
    }
    return std.math.order(a.len, b.len);
}

fn orderType(a: *const types.TypeInput, b: *const types.TypeInput) std.math.Order {
    const ta = @intFromEnum(std.meta.activeTag(a.*));
    const tb = @intFromEnum(std.meta.activeTag(b.*));
    if (ta != tb) return std.math.order(ta, tb);
    return switch (a.*) {
        .vector => |v| orderType(v, b.vector),
        .@"struct" => |s| blk: {
            const t = b.@"struct";
            var o = std.mem.order(u8, &s.address.@"0", &t.address.@"0");
            if (o == .eq) o = std.mem.order(u8, s.module.@"0", t.module.@"0");
            if (o == .eq) o = std.mem.order(u8, s.name.@"0", t.name.@"0");
            if (o == .eq) o = orderTypes(s.type_args, t.type_args);
            break :blk o;
        },
        else => .eq,
    };
}

fn appendLen(arena: Allocator, b: *std.ArrayList(u8), n: usize) Allocator.Error!void {
    var l: [4]u8 = undefined;
    std.mem.writeInt(u32, &l, @intCast(n), .little);
    try b.appendSlice(arena, &l);
}

/// `ExecutionTimeObservationKey::default_duration`, nanoseconds.
pub fn defaultDurationNs(key: []const u8) u64 {
    const ms: u64 = 1_000_000;
    return switch (key[0]) {
        tag_publish, tag_upgrade => 3 * ms,
        else => ms,
    };
}

/// `command_length` (never zero).
fn commandLength(c: *const types.Command) u64 {
    return switch (c.*) {
        .MoveCall => 1,
        .TransferObjects => |t| t.@"0".len + 1,
        .SplitCoins => |t| t.@"1".len + 1,
        .MergeCoins => |t| t.@"1".len + 1,
        .Publish => 1,
        .MakeMoveVec => |t| t.@"1".len + 1,
        .Upgrade => 1,
    };
}

const Observations = struct {
    /// per authority index: (generation, duration ns)
    obs: []Slot,
    /// cached `stake_weighted_median`; `none_` = None
    median: ?u64,

    const Slot = struct { generation: u64 = 0, dur: ?u64 = null };

    fn updateMedian(o: *Observations, stakes: []const u64, params: *const Params) void {
        updateMedianImpl(o, stakes, params);
    }
};

pub const Estimator = struct {
    gpa: Allocator,
    /// Stake by authority index.
    stakes: []const u64,
    params: Params,
    map: std.StringHashMapUnmanaged(Observations) = .empty,

    pub fn init(gpa: Allocator, stakes: []const u64, params: Params) Estimator {
        return .{ .gpa = gpa, .stakes = stakes, .params = params };
    }

    pub fn deinit(e: *Estimator) void {
        var it = e.map.iterator();
        while (it.next()) |kv| {
            e.gpa.free(kv.key_ptr.*);
            e.gpa.free(kv.value_ptr.obs);
        }
        e.map.deinit(e.gpa);
    }

    /// `process_observations_from_consensus` for one sequenced ExecutionTimeObservation.
    /// `arena` only holds temporaries; keys are copied into the estimator.
    pub fn processObservation(e: *Estimator, arena: Allocator, source: u32, generation: ?u64, key: []const u8, duration_ns: u64, skip_update: bool) Allocator.Error!void {
        _ = arena;
        // Publish observations are ignored (hard-coded default only).
        if (key[0] == tag_publish) return;
        if (source >= e.stakes.len) return;
        const gop = try e.map.getOrPut(e.gpa, key);
        if (!gop.found_existing) {
            errdefer _ = e.map.remove(key);
            gop.key_ptr.* = try e.gpa.dupe(u8, key);
            const slots = try e.gpa.alloc(Observations.Slot, e.stakes.len);
            @memset(slots, .{});
            gop.value_ptr.* = .{
                .obs = slots,
                .median = if (e.params.default_none_duration_for_new_keys) null else 0,
            };
        }
        const o = gop.value_ptr;
        const slot = &o.obs[source];
        if (generation) |g| if (slot.generation >= g) return;
        slot.generation = generation orelse 0;
        slot.dur = duration_ns;
        if (!skip_update) o.updateMedian(e.stakes, &e.params);
    }

    /// `ExecutionTimeEstimator::new` tail: recompute every cached median once after loading
    /// observations with `skip_update`.
    pub fn recomputeAll(e: *Estimator) void {
        var it = e.map.valueIterator();
        while (it.next()) |o| o.updateMedian(e.stakes, &e.params);
    }

    /// `take_observations`, sorted by the key's derived `Ord` (the order `filter_and_sort_v1`
    /// keeps): every key with the authorities that have a duration, in authority index order
    /// (`names[i]` is authority i). The estimator is left as is.
    pub fn storedObservations(e: *const Estimator, arena: Allocator, names: []const [96]u8) (Allocator.Error || error{Corrupt})!types.StoredExecutionTimeObservations {
        const Entry = StoredEntry;
        const Obs = @typeInfo(@FieldType(Entry, "1")).pointer.child;
        var out: std.ArrayList(Entry) = .empty;
        var it = e.map.iterator();
        while (it.next()) |kv| {
            var obs: std.ArrayList(Obs) = .empty;
            for (kv.value_ptr.obs, 0..) |slot, i| if (slot.dur) |d| {
                if (i >= names.len) continue;
                try obs.append(arena, .{ .{ .@"0" = names[i] }, .{ .secs = d / 1_000_000_000, .nanos = @intCast(d % 1_000_000_000) } });
            };
            try out.append(arena, .{ try keyFromBytes(arena, kv.key_ptr.*), obs.items });
        }
        std.mem.sort(Entry, out.items, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                return orderKey(&a.@"0", &b.@"0") == .lt;
            }
        }.lt);
        return .{ .V1 = out.items };
    }

    /// `get_estimate`: sum over commands of (median or default) * command_length, capped at
    /// `max_estimate_us`. Result in nanoseconds. Non-programmable transactions estimate zero.
    pub fn getEstimateNs(e: *const Estimator, arena: Allocator, td: *const types.TransactionDataV1) Allocator.Error!u64 {
        const pt = switch (td.kind) {
            .ProgrammableTransaction => |*p| p,
            else => return 0,
        };
        var total: u64 = 0;
        for (pt.commands) |*c| {
            const key = try keyOfCommand(arena, c);
            const per: u64 = blk: {
                if (e.map.get(key)) |o| if (o.median) |m| break :blk m;
                break :blk defaultDurationNs(key);
            };
            total +|= per *| commandLength(c);
        }
        const cap = e.params.max_estimate_us *| 1000;
        return @min(total, cap);
    }
};

fn Sorted(comptime T: type) type {
    return struct {
        fn less(_: void, a: T, b: T) bool {
            if (a.dur != b.dur) return a.dur < b.dur;
            return a.idx < b.idx;
        }
    };
}

fn updateMedianImpl(o: *Observations, stakes: []const u64, params: *const Params) void {
    const Item = struct { dur: u64, idx: u32 };
    var items: [256]Item = undefined;
    var n: usize = 0;
    var stake_with: u64 = 0;
    for (o.obs, 0..) |s, i| if (s.dur) |d| {
        if (n == items.len) break;
        items[n] = .{ .dur = d, .idx = @intCast(i) };
        n += 1;
        stake_with += stakes[i];
    };
    if (stake_with < params.stake_weighted_median_threshold) {
        o.median = null;
        return;
    }
    std.mem.sort(Item, items[0..n], {}, Sorted(Item).less);
    const median_stake = stake_with / 2;
    var running: u64 = 0;
    for (items[0..n]) |it| {
        running += stakes[it.idx];
        if (running > median_stake) {
            o.median = it.dur;
            break;
        }
    }
}


// ------------------------------------------------------------------------ tracker

pub const PrevDeferred = std.AutoHashMapUnmanaged(Id, deferral.DeferralKey);

pub const Deferral = struct {
    key: deferral.DeferralKey,
    congested: []const Id,
};

pub const Debt = struct { id: Id, debt: u64 };

pub const Tracker = struct {
    cost: std.AutoHashMapUnmanaged(Id, u64) = .empty,
    params: Params,
    for_randomness: bool,

    /// `SharedObjectCongestionTracker::new`; `initial` are the (id, debt) pairs.
    pub fn init(arena: Allocator, initial: []const Debt, params: Params, for_randomness: bool) Allocator.Error!Tracker {
        var t: Tracker = .{ .params = params, .for_randomness = for_randomness };
        try t.cost.ensureTotalCapacity(arena, @intCast(initial.len));
        for (initial) |d| t.cost.putAssumeCapacity(d.id, d.debt);
        return t;
    }

    /// `Params::commit_budget`, microseconds.
    pub fn commitBudget(t: *const Tracker, commit_period_us: u64) u64 {
        var budget = (commit_period_us *| t.params.target_utilization) / 100;
        if (t.for_randomness) budget = (budget *| t.params.randomness_scalar) / 100;
        return budget;
    }

    /// `Params::max_burst`.
    pub fn maxBurst(t: *const Tracker) u64 {
        var burst = t.params.allowed_txn_cost_overage_burst_limit_us;
        if (t.for_randomness) burst = (burst *| t.params.randomness_scalar) / 100;
        return burst;
    }

    fn costOf(t: *const Tracker, id: *const Id) u64 {
        return t.cost.get(id.*) orelse 0;
    }

    /// `compute_tx_start_at_cost`: the maximum cost over the shared inputs (at least one).
    pub fn computeTxStartAtCost(t: *const Tracker, shared: []const tx_mod.SharedInput) u64 {
        var m: u64 = 0;
        for (shared) |s| m = @max(m, t.costOf(&s.id));
        return m;
    }

    /// `get_tx_cost` in microseconds (the estimate truncated by `as_micros`).
    pub fn txCostUs(estimate_ns: u64) u64 {
        return estimate_ns / 1000;
    }

    /// `should_defer_due_to_object_congestion`.
    pub fn shouldDefer(t: *const Tracker, arena: Allocator, u: *const tx_mod.UserTx, prev: *const PrevDeferred, commit_round: u64, commit_period_us: u64) Allocator.Error!?Deferral {
        if (u.shared.len == 0) return null;
        const start = t.computeTxStartAtCost(u.shared);
        const budget = t.commitBudget(commit_period_us);
        const burst_limit = budget +| t.maxBurst();
        if (start <= burst_limit) return null;
        var congested: std.ArrayList(Id) = .empty;
        for (u.shared) |s| if (start == t.costOf(&s.id)) try congested.append(arena, s.id);
        std.debug.assert(congested.items.len != 0);
        const key: deferral.DeferralKey = if (prev.get(u.digest)) |pk|
            deferral.DeferralKey.newForConsensusRound(commit_round + 1, pk.deferredFromRound())
        else
            deferral.DeferralKey.newForConsensusRound(commit_round + 1, commit_round);
        return .{ .key = key, .congested = congested.items };
    }

    /// `bump_object_execution_cost`.
    pub fn bump(t: *Tracker, arena: Allocator, tx_cost_us: u64, u: *const tx_mod.UserTx) Allocator.Error!void {
        if (u.shared.len == 0) return;
        const start = t.computeTxStartAtCost(u.shared);
        const end = start +| tx_cost_us;
        for (u.shared) |s| if (s.exclusive()) {
            const old = try t.cost.fetchPut(arena, s.id, end);
            if (old) |o| std.debug.assert(o.value <= end);
        };
    }

    pub fn maxCost(t: *const Tracker) u64 {
        var m: u64 = 0;
        var it = t.cost.valueIterator();
        while (it.next()) |v| m = @max(m, v.*);
        return m;
    }

    /// `finish_commit`: the accumulated debts (cost beyond the commit budget), sorted by id.
    pub fn finishCommit(t: *const Tracker, arena: Allocator, commit_period_us: u64) Allocator.Error![]Debt {
        const budget = t.commitBudget(commit_period_us);
        var out: std.ArrayList(Debt) = .empty;
        var it = t.cost.iterator();
        while (it.next()) |kv| {
            const rem = kv.value_ptr.* -| budget;
            if (rem > 0) try out.append(arena, .{ .id = kv.key_ptr.*, .debt = rem });
        }
        std.mem.sort(Debt, out.items, {}, struct {
            fn less(_: void, a: Debt, b: Debt) bool {
                return std.mem.order(u8, &a.id, &b.id) == .lt;
            }
        }.less);
        return out.items;
    }
};

/// `load_initial_object_debts` decay: a debt stored at `stored_round` loses one budget per round
/// elapsed since (the stored value already accounts for its own round's budget).
pub fn decayedDebt(debt: u64, stored_round: u64, current_round: u64, per_commit_budget: u64) u64 {
    std.debug.assert(current_round > stored_round);
    const rounds = current_round - stored_round - 1;
    return debt -| (per_commit_budget *| rounds);
}

// ------------------------------------------------------------------------ tests

fn testShared(id: Id, mut: bool) tx_mod.SharedInput {
    return .{ .id = id, .isv = 1, .mutability = if (mut) .mutable else .immutable };
}

test "tracker start cost, defer and debts" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var o0: Id = @splat(0);
    o0[0] = 1;
    var o1: Id = @splat(0);
    o1[0] = 2;
    const params: Params = .{ .target_utilization = 50, .allowed_txn_cost_overage_burst_limit_us = 100 };
    var t = try Tracker.init(arena, &.{ .{ .id = o0, .debt = 5 }, .{ .id = o1, .debt = 10 } }, params, false);
    try std.testing.expectEqual(@as(u64, 10), t.computeTxStartAtCost(&.{ testShared(o0, true), testShared(o1, false) }));
    try std.testing.expectEqual(@as(u64, 0), t.computeTxStartAtCost(&.{testShared(@as(Id, @splat(1)), true)}));
    // commit period 1000us at 50% = 500us budget, burst 100: limit 600
    try std.testing.expectEqual(@as(u64, 500), t.commitBudget(1000));
    try std.testing.expectEqual(@as(u64, 100), t.maxBurst());
    // randomness scales both
    var tr = try Tracker.init(arena, &.{}, .{ .target_utilization = 50, .randomness_scalar = 10, .allowed_txn_cost_overage_burst_limit_us = 100 }, true);
    try std.testing.expectEqual(@as(u64, 50), tr.commitBudget(1000));
    try std.testing.expectEqual(@as(u64, 10), tr.maxBurst());
    _ = &tr;
    _ = &t;
}

test "decayed debt" {
    try std.testing.expectEqual(@as(u64, 70), decayedDebt(100, 5, 8, 15));
    try std.testing.expectEqual(@as(u64, 0), decayedDebt(10, 5, 100, 15));
    try std.testing.expectEqual(@as(u64, 100), decayedDebt(100, 5, 6, 15));
}

test "estimator default and median" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const stakes = [_]u64{ 25, 25, 25, 25 };
    var e = Estimator.init(std.testing.allocator, &stakes, .{ .max_estimate_us = std.math.maxInt(u64) / 2000, .stake_weighted_median_threshold = 50, .default_none_duration_for_new_keys = true });
    defer e.deinit();
    const key = [_]u8{tag_transfer};
    try e.processObservation(arena, 0, 1, &key, 4_000_000, false);
    // below threshold: no median yet
    try std.testing.expectEqual(@as(?u64, null), e.map.get(&key).?.median);
    try e.processObservation(arena, 1, 1, &key, 2_000_000, false);
    try e.processObservation(arena, 2, 1, &key, 8_000_000, false);
    // sorted 2,4,8 stake 25 each, total 75, median_stake 37: running 25,50>37 -> 4ms
    try std.testing.expectEqual(@as(?u64, 4_000_000), e.map.get(&key).?.median);
    // stale generation ignored
    try e.processObservation(arena, 1, 1, &key, 99_000_000, false);
    try std.testing.expectEqual(@as(?u64, 4_000_000), e.map.get(&key).?.median);
}

test "end-of-epoch observations: key order, authority names, window filter and limit" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const stakes = [_]u64{ 25, 25, 25, 25 };
    var e = Estimator.init(std.testing.allocator, &stakes, .{ .max_estimate_us = 1_500_000, .stake_weighted_median_threshold = 50, .default_none_duration_for_new_keys = true });
    defer e.deinit();
    const call = struct {
        fn key(a: Allocator, pkg: u8, module: []const u8, function: []const u8) ![]const u8 {
            const c: types.Command = .{ .MoveCall = .{ .package = .{ .@"0" = .{ .@"0" = @splat(pkg) } }, .module = .{ .@"0" = module }, .function = .{ .@"0" = function }, .type_arguments = &.{}, .arguments = &.{} } };
            return keyOfCommand(a, &c);
        }
    }.key;
    const random_new = try call(arena, 0xae, "random", "new");
    const counter_inc = try call(arena, 0xae, "counter", "increment");
    const other = try call(arena, 0x01, "zz", "f");
    const transfer = [_]u8{tag_transfer};
    // authority 2 never observes; durations carry seconds and nanos
    for ([_]u32{ 3, 0, 1 }) |src| try e.processObservation(arena, src, 1, random_new, 700_000 + src, false);
    try e.processObservation(arena, 1, 1, counter_inc, 1_000_000_123, false);
    try e.processObservation(arena, 0, 1, other, 5, false);
    try e.processObservation(arena, 0, 1, &transfer, 6, false);
    try e.processObservation(arena, 0, 1, &[_]u8{tag_publish}, 7, false); // never stored

    var names: [4][96]u8 = undefined;
    for (&names, 0..) |*n, i| n.* = @splat(@intCast(i + 1));
    const all = try e.storedObservations(arena, &names);
    // derived Ord: MoveEntryPoint before TransferObjects; package, then module, then function
    try std.testing.expectEqual(@as(usize, 4), all.V1.len);
    try std.testing.expectEqualSlices(u8, "zz", all.V1[0].@"0".MoveEntryPoint.module.@"0");
    try std.testing.expectEqualSlices(u8, "counter", all.V1[1].@"0".MoveEntryPoint.module.@"0");
    try std.testing.expectEqualSlices(u8, "random", all.V1[2].@"0".MoveEntryPoint.module.@"0");
    try std.testing.expect(all.V1[3].@"0" == .TransferObjects);
    // observers in authority index order, by name
    const obs = all.V1[2].@"1";
    try std.testing.expectEqual(@as(usize, 3), obs.len);
    try std.testing.expectEqual(names[0], obs[0].@"0".@"0");
    try std.testing.expectEqual(names[1], obs[1].@"0".@"0");
    try std.testing.expectEqual(names[3], obs[2].@"0".@"0");
    try std.testing.expectEqual(@as(u32, 700_003), obs[2].@"1".nanos);
    try std.testing.expectEqual(@as(u64, 1), all.V1[1].@"1"[0].@"1".secs);
    try std.testing.expectEqual(@as(u32, 123), all.V1[1].@"1"[0].@"1".nanos);
    // each key round-trips through its canonical bytes
    for (all.V1) |ent| {
        const b = try keyBytes(arena, &ent.@"0");
        try std.testing.expect(e.map.contains(b));
    }

    // only keys of the window's commands, sorted, at most `limit`
    var included: std.StringHashMapUnmanaged(void) = .empty;
    try included.put(arena, random_new, {});
    try included.put(arena, counter_inc, {});
    try included.put(arena, &transfer, {});
    const kept = try filterStored(arena, all, &included, 2);
    try std.testing.expectEqual(@as(usize, 2), kept.V1.len);
    try std.testing.expectEqualSlices(u8, "counter", kept.V1[0].@"0".MoveEntryPoint.module.@"0");
    try std.testing.expectEqualSlices(u8, "random", kept.V1[1].@"0".MoveEntryPoint.module.@"0");
    try std.testing.expectEqual(@as(usize, 3), (try filterStored(arena, all, &included, std.math.maxInt(usize))).V1.len);
}
