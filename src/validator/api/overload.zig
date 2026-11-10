//! Overload protection at mainnet-v1.83.1: `overload_monitor.rs` (load shedding percentage from the
//! execution queueing latency and the ready/execution rates, per-transaction deterministic shedding
//! keyed by the digest and a 30 s temporal seed) and `AuthorityState::check_system_overload`
//! (execution queue length, per-object queue length and age, cache backpressure). The numeric
//! functions are line for line the Rust ones and carry its unit-test vectors.
//!
//! The monitor loop itself (every `overload_monitor_interval`) belongs to the node's scheduler;
//! this file holds the state it updates (`Info`) and the checks the API runs per transaction.
const std = @import("std");
const config = @import("../keys/config.zig");
const sui_error = @import("rpc_exec").driver.sui_error;

pub const SuiErrorKind = sui_error.SuiErrorKind;
pub const Config = config.Overload;

const steady_overload_reduction_percentage: u32 = 10;
const execution_rate_ratio_for_comparison: f64 = 0.95;
const additional_load_shedding: f64 = 0.02;
pub const seed_update_duration_secs: u64 = 30;

/// `AuthorityOverloadInfo`.
pub const Info = struct {
    is_overload: std.atomic.Value(bool) = .init(false),
    load_shedding_percentage: std.atomic.Value(u32) = .init(0),

    pub fn setOverload(i: *Info, pct: u32) void {
        i.is_overload.store(true, .monotonic);
        i.load_shedding_percentage.store(@min(pct, 100), .monotonic);
    }
    pub fn clearOverload(i: *Info) void {
        i.is_overload.store(false, .monotonic);
        i.load_shedding_percentage.store(0, .monotonic);
    }
};

/// `calculate_load_shedding_percentage`.
pub fn calculateLoadSheddingPercentage(txn_ready_rate: f64, execution_rate: f64) u32 {
    if (txn_ready_rate < 1e-10) return 0;
    if (execution_rate * execution_rate_ratio_for_comparison > txn_ready_rate) return 0;
    const v = @min((1.0 - execution_rate * execution_rate_ratio_for_comparison / txn_ready_rate) + additional_load_shedding, 1.0) * 100.0;
    return @intFromFloat(@round(v));
}

pub const Verdict = struct { overload: bool, percentage: u32 };

/// `check_overload_signals`. Latencies in milliseconds.
pub fn checkOverloadSignals(cfg: *const Config, current: u32, queueing_latency_ms: u64, txn_ready_rate: f64, execution_rate: f64) Verdict {
    const additional: u32 = if (queueing_latency_ms > cfg.execution_queue_latency_hard_limit_ms) blk: {
        const calc = calculateLoadSheddingPercentage(txn_ready_rate, execution_rate);
        if (calc > 0 or txn_ready_rate >= @as(f64, @floatFromInt(cfg.safe_transaction_ready_rate))) {
            break :blk @max(calc, cfg.min_load_shedding_percentage_above_hard_limit);
        }
        break :blk 0;
    } else if (queueing_latency_ms > cfg.execution_queue_latency_soft_limit_ms)
        calculateLoadSheddingPercentage(txn_ready_rate, execution_rate)
    else
        0;
    var pct: u32 = if (additional > 0)
        current + (100 - current) * additional / 100
    else if (txn_ready_rate > @as(f64, @floatFromInt(cfg.safe_transaction_ready_rate)) and current > 10)
        current - steady_overload_reduction_percentage
    else
        0;
    pct = @min(pct, cfg.max_load_shedding_percentage);
    return .{ .overload = pct > 0, .percentage = pct };
}

/// One monitor tick: updates `info` from the current signals.
pub fn tick(info: *Info, cfg: *const Config, queueing_latency_ms: u64, txn_ready_rate: f64, execution_rate: f64) Verdict {
    const v = checkOverloadSignals(cfg, info.load_shedding_percentage.load(.monotonic), queueing_latency_ms, txn_ready_rate, execution_rate);
    if (v.overload) info.setOverload(v.percentage) else info.clearOverload();
    return v;
}

/// `should_reject_tx`: XxHash64 of the digest seeded with the temporal seed, mod 100.
pub fn shouldRejectTx(load_shedding_percentage: u32, digest: *const [32]u8, temporal_seed: u64) bool {
    const value = std.hash.XxHash64.hash(temporal_seed, digest);
    return value % 100 < load_shedding_percentage;
}

/// `overload_monitor_accept_tx`: null accepts, else the error to answer with.
pub fn acceptTx(load_shedding_percentage: u32, digest: *const [32]u8, now_unix_secs: u64) ?SuiErrorKind {
    const seed = now_unix_secs / seed_update_duration_secs;
    if (shouldRejectTx(load_shedding_percentage, digest, seed)) {
        return .{ .ValidatorOverloadedRetryAfter = .{ .retry_after_secs = seed_update_duration_secs } };
    }
    return null;
}

/// What the execution scheduler reports about one transaction's shared inputs.
pub const ObjectQueue = struct {
    object_id: [32]u8,
    queue_len: usize,
    /// Age of the oldest pending transaction on the object, ms.
    oldest_age_ms: ?u64,
};

/// Inputs of `check_system_overload`.
pub const Load = struct {
    /// `num_pending_certificates` (pending plus executing).
    inflight_execution: usize,
    /// Queues of the exclusively accessed shared objects of the transaction.
    object_queues: []const ObjectQueue = &.{},
    /// Uncommitted transactions in the execution cache, and the RPC backpressure threshold.
    pending_cache_commits: u64 = 0,
    backpressure_threshold_for_rpc: u64 = std.math.maxInt(u64),
};

/// `check_system_overload`: authority-level shedding first, then the execution queue checks, then
/// cache backpressure. Null accepts.
pub fn checkSystemOverload(cfg: *const Config, info: *const Info, load: Load, digest: *const [32]u8, now_unix_secs: u64) ?SuiErrorKind {
    if (cfg.check_system_overload_at_signing and info.is_overload.load(.monotonic)) {
        if (acceptTx(info.load_shedding_percentage.load(.monotonic), digest, now_unix_secs)) |e| return e;
    }
    if (load.inflight_execution >= cfg.max_transaction_manager_queue_length) {
        return .{ .TooManyTransactionsPendingExecution = .{ .queue_len = load.inflight_execution, .threshold = cfg.max_transaction_manager_queue_length } };
    }
    for (load.object_queues) |q| {
        if (q.queue_len >= cfg.max_transaction_manager_per_object_queue_length) {
            return .{ .TooManyTransactionsPendingOnObject = .{
                .object_id = .{ .@"0" = .{ .@"0" = q.object_id } },
                .queue_len = q.queue_len,
                .threshold = cfg.max_transaction_manager_per_object_queue_length,
            } };
        }
        if (q.oldest_age_ms) |age| {
            if (age >= cfg.max_txn_age_in_queue_ms) {
                return .{ .TooOldTransactionPendingOnObject = .{
                    .object_id = .{ .@"0" = .{ .@"0" = q.object_id } },
                    .txn_age_sec = age / 1000,
                    .threshold = cfg.max_txn_age_in_queue_ms / 1000,
                } };
            }
        }
    }
    if (load.pending_cache_commits > load.backpressure_threshold_for_rpc) {
        return .{ .ValidatorOverloadedRetryAfter = .{ .retry_after_secs = 10 } };
    }
    return null;
}

test "load shedding percentage vectors of overload_monitor.rs" {
    try std.testing.expectEqual(@as(u32, 0), calculateLoadSheddingPercentage(95.0, 100.1));
    try std.testing.expectEqual(@as(u32, 2), calculateLoadSheddingPercentage(95.0, 100.0));
    try std.testing.expectEqual(@as(u32, 7), calculateLoadSheddingPercentage(100.0, 100.0));
    try std.testing.expectEqual(@as(u32, 16), calculateLoadSheddingPercentage(110.0, 100.0));
    try std.testing.expectEqual(@as(u32, 49), calculateLoadSheddingPercentage(180.0, 100.0));
    try std.testing.expectEqual(@as(u32, 100), calculateLoadSheddingPercentage(100.0, 0.0));
    try std.testing.expectEqual(@as(u32, 0), calculateLoadSheddingPercentage(0.0, 1.0));
}

fn expectVerdict(v: Verdict, overload: bool, pct: u32) !void {
    try std.testing.expectEqual(overload, v.overload);
    try std.testing.expectEqual(pct, v.percentage);
}

test "overload signal vectors of overload_monitor.rs" {
    var cfg: Config = .{ .execution_queue_latency_hard_limit_ms = 10_000, .execution_queue_latency_soft_limit_ms = 1_000, .max_load_shedding_percentage = 90 };
    try expectVerdict(checkOverloadSignals(&cfg, 0, 500, 1000.0, 10.0), false, 0);
    try expectVerdict(checkOverloadSignals(&cfg, 0, 2000, 100.0, 120.0), false, 0);
    try expectVerdict(checkOverloadSignals(&cfg, 0, 2000, 100.0, 100.0), true, 7);
    try expectVerdict(checkOverloadSignals(&cfg, 0, 11_000, 100.0, 100.0), true, 50);
    try expectVerdict(checkOverloadSignals(&cfg, 0, 11_000, 240.0, 100.0), true, 62);
    try expectVerdict(checkOverloadSignals(&cfg, 0, 11_000, 20.0, 100.0), false, 0);
    try expectVerdict(checkOverloadSignals(&cfg, 0, 11_000, 100.0, 0.0), true, 90);
    // gradual reduction when the ready rate is lower than the execution rate
    try expectVerdict(checkOverloadSignals(&cfg, 90, 2000, 200.0, 300.0), true, 80);
    // above the hard limit another 50% is shed every time
    try expectVerdict(checkOverloadSignals(&cfg, 50, 11_000, 100.0, 100.0), true, 75);
}

test "info set and clear follow AuthorityOverloadInfo" {
    var i: Info = .{};
    try std.testing.expect(!i.is_overload.load(.monotonic));
    i.setOverload(20);
    try std.testing.expectEqual(@as(u32, 20), i.load_shedding_percentage.load(.monotonic));
    i.setOverload(110);
    try std.testing.expectEqual(@as(u32, 100), i.load_shedding_percentage.load(.monotonic));
    i.clearOverload();
    try std.testing.expect(!i.is_overload.load(.monotonic));
    const cfg: Config = .{};
    const v = tick(&i, &cfg, 20_000, 1000.0, 10.0);
    try std.testing.expect(v.overload and i.is_overload.load(.monotonic));
}

test "shedding is deterministic per digest and seed, 100 percent rejects everything" {
    var rejected: u32 = 0;
    for (0..1000) |n| {
        var d: [32]u8 = @splat(0);
        std.mem.writeInt(u64, d[0..8], n, .little);
        if (shouldRejectTx(50, &d, 7)) rejected += 1;
        try std.testing.expect(shouldRejectTx(100, &d, 7));
        try std.testing.expect(!shouldRejectTx(0, &d, 7));
        try std.testing.expectEqual(shouldRejectTx(50, &d, 7), shouldRejectTx(50, &d, 7));
    }
    try std.testing.expect(rejected > 350 and rejected < 650);
}

test "system overload checks in order" {
    var info: Info = .{};
    const cfg: Config = .{};
    const d: [32]u8 = @splat(1);
    try std.testing.expect(checkSystemOverload(&cfg, &info, .{ .inflight_execution = 5 }, &d, 1000) == null);
    const e1 = checkSystemOverload(&cfg, &info, .{ .inflight_execution = 100_000 }, &d, 1000).?;
    try std.testing.expect(e1 == .TooManyTransactionsPendingExecution);
    const qs = [_]ObjectQueue{.{ .object_id = @splat(9), .queue_len = 2000, .oldest_age_ms = null }};
    try std.testing.expect(checkSystemOverload(&cfg, &info, .{ .inflight_execution = 1, .object_queues = &qs }, &d, 1000).? == .TooManyTransactionsPendingOnObject);
    const old = [_]ObjectQueue{.{ .object_id = @splat(9), .queue_len = 1, .oldest_age_ms = 1500 }};
    try std.testing.expect(checkSystemOverload(&cfg, &info, .{ .inflight_execution = 1, .object_queues = &old }, &d, 1000).? == .TooOldTransactionPendingOnObject);
    try std.testing.expect(checkSystemOverload(&cfg, &info, .{ .inflight_execution = 1, .pending_cache_commits = 10, .backpressure_threshold_for_rpc = 5 }, &d, 1000).? == .ValidatorOverloadedRetryAfter);
    info.setOverload(100);
    try std.testing.expect(checkSystemOverload(&cfg, &info, .{ .inflight_execution = 1 }, &d, 1000).? == .ValidatorOverloadedRetryAfter);
}
