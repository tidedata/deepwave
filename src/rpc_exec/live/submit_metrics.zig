//! sui-node 1.83.1's submit-path families (lane ops-metrics), fed by the live executor
//! (validators.zig) and the driver's feedback, same names, labels, help texts and buckets:
//!
//!   TransactionOrchestratorMetrics (sui-core transaction_orchestrator.rs)
//!     tx_orchestrator_total_req_received{tx_type}, _good_response{tx_type}   counters
//!     tx_orchestrator_req_in_flight{tx_type}                                 gauge
//!     tx_orchestrator_wait_for_finality_in_flight, _fnished (sic), _timeout
//!     tx_orchestrator_local_execution_{in_flight,success,timeout}            (JSON-RPC only: 0)
//!     tx_orchestrator_early_cached_response, _concurrent_execution           counters
//!     tx_orchestrator_early_validation_rejections{reason}                    counter
//!     tx_orchestrator_background_retry_started                               gauge (inc only)
//!     tx_orchestrator_background_retry_attempts{status}                      counter
//!     tx_orchestrator_request_latency{route,tx_type,wait_for_local_execution} COARSE buckets
//!     tx_orchestrator_settlement_finality_latency{driver_type,tx_type}       LATENCY buckets
//!   TransactionDriverMetrics (sui-core transaction_driver/metrics.rs)
//!     transaction_driver_total_transactions_submitted{ping,tx_type}
//!     transaction_driver_settlement_finality_latency{ping,tx_type}
//!     transaction_driver_drive_transaction_errors{error_type,ping,tx_type}   per failed attempt
//!     transaction_driver_transaction_retries{ping,result,tx_type}            REQUEST_COUNT buckets
//!     transaction_driver_validator_submit_transaction_successes{ping,tx_type,validator}
//!     transaction_driver_executed_transactions, _effects_digest_mismatches, _latency_check_runs
//!   ValidatorClientMetrics (sui-core validator_client_monitor/metrics.rs)
//!     validator_client_observed_latency{operation_type,ping,validator}       SUBSECOND buckets
//!     validator_client_operation_success_total, _failure_total{operation_type,ping,validator}
//!     validator_client_observed_performance{validator}                       gauge (seconds)
//!
//! One process-wide instance (`global`), as sui-node's registry. Hot path: relaxed atomic adds;
//! a validator's slot is interned once by display name.
const std = @import("std");
const prom = @import("core").prom;
const drv = @import("../driver/root.zig").driver;
const se = @import("../driver/root.zig").sui_error;
const types = @import("types");
const Atomic = std.atomic.Value;
const Writer = std.Io.Writer;

pub const TxType = enum(u1) {
    single_writer,
    shared_object,

    /// `TransactionData::is_consensus_tx`: a shared input or a funds withdrawal.
    pub fn of(data: *const types.TransactionData) TxType {
        const v1 = switch (data.*) {
            .V1 => |*v| v,
        };
        switch (v1.kind) {
            .ProgrammableTransaction => |pt| for (pt.inputs) |in| switch (in) {
                .Object => |o| if (o == .SharedObject) return .shared_object,
                .FundsWithdrawal => return .shared_object,
                else => {},
            },
            else => {},
        }
        return .single_writer;
    }
};

const n_cat = @typeInfo(se.ErrorCategory).@"enum".field_names.len;
const tx_names = [_][]const u8{ "single_writer", "shared_object" };
const bool_names = [_][]const u8{ "false", "true" };

const Coarse = prom.Histogram(&prom.buckets.coarse_latency_sec, prom.ns);
const Lat = prom.Histogram(&prom.buckets.latency_sec, prom.ns);
const Sub = prom.Histogram(&prom.buckets.subsecond_latency_sec, prom.ns);
const Retries = prom.Histogram(&prom.buckets.request_count, prom.one);

/// The driver's op as `OperationType::as_str` (finality by the transaction's kind).
fn opIndex(op: drv.Op, tx: TxType) usize {
    return switch (op) {
        .submit => 0,
        .effects => 1,
        .finality => if (tx == .shared_object) 3 else 2,
    };
}
const op_names = [_][]const u8{ "submit", "effects", "single_writer_finality", "shared_object_finality" };

const Validator = struct {
    latency: [op_names.len][2]Sub = @splat(@splat(.{})),
    success: [op_names.len][2]Atomic(u64) = @splat(@splat(.init(0))),
    failure: [op_names.len][2]Atomic(u64) = @splat(@splat(.init(0))),
    /// observed_performance in ns (0: not reported yet).
    performance_ns: Atomic(u64) = .init(0),
    submit_successes: [2][2]Atomic(u64) = @splat(@splat(.init(0))),
};

const Reason = struct { n: Atomic(u64) = .init(0) };

pub const SubmitMetrics = struct {
    // orchestrator
    req_received: [2]Atomic(u64) = @splat(.init(0)),
    good_response: [2]Atomic(u64) = @splat(.init(0)),
    req_in_flight: [2]Atomic(i64) = @splat(.init(0)),
    wait_in_flight: Atomic(i64) = .init(0),
    wait_finished: Atomic(u64) = .init(0),
    wait_timeout: Atomic(u64) = .init(0),
    early_cached: Atomic(u64) = .init(0),
    concurrent: Atomic(u64) = .init(0),
    early_rejections: prom.Labeled(Reason, 32) = .{},
    retry_started: Atomic(i64) = .init(0),
    /// background_retry_attempts{status}: success, retriable, non-retriable
    retry_attempts: [3]Atomic(u64) = @splat(.init(0)),
    request_latency: [2]Coarse = @splat(.{}),
    settlement: [2]Lat = @splat(.{}),
    // driver
    submitted: [2][2]Atomic(u64) = @splat(@splat(.init(0))),
    driver_settlement: [2][2]Lat = @splat(@splat(.{})),
    drive_errors: [n_cat][2][2]Atomic(u64) = @splat(@splat(@splat(.init(0)))),
    retries: [2][2][2]Retries = @splat(@splat(@splat(.{}))),
    executed: Atomic(u64) = .init(0),
    latency_check_runs: Atomic(u64) = .init(0),
    // validator client
    validators: prom.Labeled(Validator, 512) = .{},

    // ------------------------------------------------------------ orchestrator

    /// `execute_transaction_impl` started: received, in flight, waiting for finality.
    pub fn driveBegin(m: *SubmitMetrics, tx: TxType) void {
        _ = m.req_received[@intFromEnum(tx)].fetchAdd(1, .monotonic);
        _ = m.req_in_flight[@intFromEnum(tx)].fetchAdd(1, .monotonic);
        _ = m.wait_in_flight.fetchAdd(1, .monotonic);
    }

    /// It ended (`ok`: finality reached, `elapsed_ns` since driveBegin).
    pub fn driveEnd(m: *SubmitMetrics, tx: TxType, ok: bool, elapsed_ns: u64) void {
        _ = m.req_in_flight[@intFromEnum(tx)].fetchSub(1, .monotonic);
        _ = m.wait_in_flight.fetchSub(1, .monotonic);
        if (!ok) return;
        _ = m.wait_finished.fetchAdd(1, .monotonic);
        m.settlement[@intFromEnum(tx)].observe(elapsed_ns);
        _ = m.good_response[@intFromEnum(tx)].fetchAdd(1, .monotonic);
    }

    /// `execute_transaction_v3` answered Ok after `elapsed_ns`.
    pub fn requestOk(m: *SubmitMetrics, tx: TxType, elapsed_ns: u64) void {
        m.request_latency[@intFromEnum(tx)].observe(elapsed_ns);
    }

    /// `early_validation_rejections{reason}`: the SuiErrorKind variant (`to_variant_name`).
    pub fn earlyRejected(m: *SubmitMetrics, reason: []const u8) void {
        if (m.early_rejections.get(reason)) |r| _ = r.n.fetchAdd(1, .monotonic);
    }

    pub const RetryStatus = enum { success, retriable, non_retriable };
    pub fn retryAttempt(m: *SubmitMetrics, s: RetryStatus) void {
        _ = m.retry_attempts[@intFromEnum(s)].fetchAdd(1, .monotonic);
    }

    // ------------------------------------------------------------ driver

    pub fn submitted_(m: *SubmitMetrics, tx: TxType, ping: bool) void {
        _ = m.submitted[@intFromEnum(tx)][@intFromBool(ping)].fetchAdd(1, .monotonic);
    }

    /// `drive_transaction` returned: Ok after `elapsed_ns` and `attempts` retries, or a
    /// non-retriable error (`final_failure`); a timeout records neither (as sui-node).
    pub fn driveDone(m: *SubmitMetrics, tx: TxType, ping: bool, ok: bool, final_failure: bool, attempts: u32, elapsed_ns: u64) void {
        const t = @intFromEnum(tx);
        const p = @intFromBool(ping);
        if (ok) {
            m.driver_settlement[t][p].observe(elapsed_ns);
            m.retries[0][t][p].observe(attempts);
            _ = m.executed.fetchAdd(1, .monotonic);
        } else if (final_failure) m.retries[1][t][p].observe(attempts);
    }

    /// One failed attempt (`drive_transaction_errors`, the error's category).
    pub fn attemptError(m: *SubmitMetrics, cat: se.ErrorCategory, tx: TxType, ping: bool) void {
        _ = m.drive_errors[@intFromEnum(cat)][@intFromEnum(tx)][@intFromBool(ping)].fetchAdd(1, .monotonic);
    }

    // ------------------------------------------------------------ validator client

    /// `record_interaction_result` for validator `name` (its display name).
    pub fn interaction(m: *SubmitMetrics, name: []const u8, op: drv.Op, tx: TxType, ping: bool, latency_ns: ?u64) void {
        const v = m.validators.get(name) orelse return;
        const o = opIndex(op, tx);
        const p = @intFromBool(ping);
        if (latency_ns) |l| {
            v.latency[o][p].observe(l);
            _ = v.success[o][p].fetchAdd(1, .monotonic);
            if (op == .submit) _ = v.submit_successes[@intFromEnum(tx)][p].fetchAdd(1, .monotonic);
        } else _ = v.failure[o][p].fetchAdd(1, .monotonic);
    }

    pub fn performance(m: *SubmitMetrics, name: []const u8, ns: u64) void {
        const v = m.validators.get(name) orelse return;
        v.performance_ns.store(@max(ns, 1), .monotonic);
    }

    // ------------------------------------------------------------ render

    pub fn render(m: *SubmitMetrics, w: *Writer) Writer.Error!void {
        try m.renderOrchestrator(w);
        try m.renderDriver(w);
        try m.renderValidators(w);
    }

    fn txPairs(w: *Writer, name: []const u8, help: []const u8, kind: []const u8, vals: anytype) Writer.Error!void {
        try prom.head(w, name, help, kind);
        for (tx_names, 0..) |t, i| try w.print("{s}{{tx_type=\"{s}\"}} {d}\n", .{ name, t, vals[i].load(.monotonic) });
    }

    fn renderOrchestrator(m: *SubmitMetrics, w: *Writer) Writer.Error!void {
        try txPairs(w, "tx_orchestrator_total_req_received", "Total number of executions request Transaction Orchestrator receives, group by tx type", "counter", &m.req_received);
        try txPairs(w, "tx_orchestrator_good_response", "Total number of good responses Transaction Orchestrator generates, group by tx type", "counter", &m.good_response);
        try txPairs(w, "tx_orchestrator_req_in_flight", "Number of requests in flights Transaction Orchestrator processes, group by tx type", "gauge", &m.req_in_flight);
        try prom.scalar(w, "tx_orchestrator_wait_for_finality_in_flight", "Number of in flight txns Transaction Orchestrator are waiting for finality for", "gauge", m.wait_in_flight.load(.monotonic));
        try prom.scalar(w, "tx_orchestrator_wait_for_finality_fnished", "Total number of txns Transaction Orchestrator gets responses from Quorum Driver before timeout, either success or failure", "counter", m.wait_finished.load(.monotonic));
        try prom.scalar(w, "tx_orchestrator_wait_for_finality_timeout", "Total number of txns timing out in waiting for finality Transaction Orchestrator handles", "counter", m.wait_timeout.load(.monotonic));
        try prom.scalar(w, "tx_orchestrator_local_execution_in_flight", "Number of local execution txns in flights Transaction Orchestrator handles", "gauge", 0);
        try prom.scalar(w, "tx_orchestrator_local_execution_success", "Total number of successful local execution txns Transaction Orchestrator handles", "counter", 0);
        try prom.scalar(w, "tx_orchestrator_local_execution_timeout", "Total number of timed-out local execution txns Transaction Orchestrator handles", "counter", 0);
        try prom.scalar(w, "tx_orchestrator_early_cached_response", "Total number of requests returning cached results for already-executed transactions", "counter", m.early_cached.load(.monotonic));
        try prom.scalar(w, "tx_orchestrator_concurrent_execution", "Total number of concurrent execution where effects are available locally finishing driving the transaction to finality", "counter", m.concurrent.load(.monotonic));
        if (m.early_rejections.len() > 0) {
            var buf: [32]*prom.Labeled(Reason, 32).Slot = undefined;
            try prom.head(w, "tx_orchestrator_early_validation_rejections", "Total number of transactions rejected during early validation before submission, by reason", "counter");
            for (m.early_rejections.sorted(&buf)) |s| try w.print("tx_orchestrator_early_validation_rejections{{reason=\"{s}\"}} {d}\n", .{ s.name, s.v.n.load(.monotonic) });
        }
        try prom.scalar(w, "tx_orchestrator_background_retry_started", "Number of background retry tasks kicked off for transactions with retriable errors", "gauge", m.retry_started.load(.monotonic));
        {
            const names = [_][]const u8{ "success", "retriable", "non-retriable" };
            var any = false;
            for (&m.retry_attempts) |*a| any = any or a.load(.monotonic) > 0;
            if (any) {
                try prom.head(w, "tx_orchestrator_background_retry_attempts", "Total number of background retry attempts, by status", "counter");
                // label values sorted as text
                for ([_]usize{ 2, 1, 0 }) |i| {
                    const v = m.retry_attempts[i].load(.monotonic);
                    if (v > 0) try w.print("tx_orchestrator_background_retry_attempts{{status=\"{s}\"}} {d}\n", .{ names[i], v });
                }
            }
        }
        var lb: [160]u8 = undefined;
        if (m.request_latency[0].count() + m.request_latency[1].count() > 0) {
            try prom.head(w, "tx_orchestrator_request_latency", "Time spent in processing one Transaction Orchestrator request", "histogram");
            for (&m.request_latency, 0..) |*h, i| if (h.count() > 0)
                try h.renderSeries(w, "tx_orchestrator_request_latency", std.fmt.bufPrint(&lb, "route=\"execute_transaction_v3\",tx_type=\"{s}\",wait_for_local_execution=\"false\"", .{tx_names[i]}) catch unreachable);
        }
        if (m.settlement[0].count() + m.settlement[1].count() > 0) {
            try prom.head(w, "tx_orchestrator_settlement_finality_latency", "Time spent in waiting for one Transaction Orchestrator gets settled and finalized", "histogram");
            for (&m.settlement, 0..) |*h, i| if (h.count() > 0)
                try h.renderSeries(w, "tx_orchestrator_settlement_finality_latency", std.fmt.bufPrint(&lb, "driver_type=\"transaction_driver\",tx_type=\"{s}\"", .{tx_names[i]}) catch unreachable);
        }
    }

    fn renderDriver(m: *SubmitMetrics, w: *Writer) Writer.Error!void {
        var lb: [200]u8 = undefined;
        {
            var any = false;
            for (&m.submitted) |*r| for (r) |*x| {
                any = any or x.load(.monotonic) > 0;
            };
            if (any) {
                try prom.head(w, "transaction_driver_total_transactions_submitted", "Total number of transactions submitted through the transaction driver", "counter");
                for (bool_names, 0..) |pn, p| for (tx_names, 0..) |tn, t| {
                    const v = m.submitted[t][p].load(.monotonic);
                    if (v > 0) try w.print("transaction_driver_total_transactions_submitted{{ping=\"{s}\",tx_type=\"{s}\"}} {d}\n", .{ pn, tn, v });
                };
            }
        }
        {
            var any = false;
            for (&m.drive_errors) |*a| for (a) |*b| for (b) |*x| {
                any = any or x.load(.monotonic) > 0;
            };
            if (any) {
                try prom.head(w, "transaction_driver_drive_transaction_errors", "Number of errors observed from drive_transaction() attempts.", "counter");
                for (0..n_cat) |c| for (bool_names, 0..) |pn, p| for (tx_names, 0..) |tn, t| {
                    const v = m.drive_errors[c][t][p].load(.monotonic);
                    if (v > 0) try w.print("transaction_driver_drive_transaction_errors{{error_type=\"{s}\",ping=\"{s}\",tx_type=\"{s}\"}} {d}\n", .{ @tagName(@as(se.ErrorCategory, @enumFromInt(c))), pn, tn, v });
                };
            }
        }
        {
            var any = false;
            for (&m.driver_settlement) |*a| for (a) |*h| {
                any = any or h.count() > 0;
            };
            if (any) {
                try prom.head(w, "transaction_driver_settlement_finality_latency", "Settlement finality latency observed from transaction driver", "histogram");
                for (bool_names, 0..) |pn, p| for (tx_names, 0..) |tn, t| if (m.driver_settlement[t][p].count() > 0)
                    try m.driver_settlement[t][p].renderSeries(w, "transaction_driver_settlement_finality_latency", std.fmt.bufPrint(&lb, "ping=\"{s}\",tx_type=\"{s}\"", .{ pn, tn }) catch unreachable);
            }
        }
        {
            var any = false;
            for (&m.retries) |*a| for (a) |*b| for (b) |*h| {
                any = any or h.count() > 0;
            };
            if (any) {
                const results = [_][]const u8{ "success", "failure" };
                try prom.head(w, "transaction_driver_transaction_retries", "Number of retries per transaction attempt in drive_transaction", "histogram");
                for (bool_names, 0..) |pn, p| for ([_]usize{ 1, 0 }) |r| for (tx_names, 0..) |tn, t| if (m.retries[r][t][p].count() > 0)
                    try m.retries[r][t][p].renderSeries(w, "transaction_driver_transaction_retries", std.fmt.bufPrint(&lb, "ping=\"{s}\",result=\"{s}\",tx_type=\"{s}\"", .{ pn, results[r], tn }) catch unreachable);
            }
        }
        try prom.scalar(w, "transaction_driver_executed_transactions", "Number of transactions executed observed by the transaction driver", "counter", m.executed.load(.monotonic));
        try prom.scalar(w, "transaction_driver_effects_digest_mismatches", "Number of effects digest mismatches detected by the transaction driver", "counter", 0);
        try prom.scalar(w, "transaction_driver_latency_check_runs", "Number of times the latency check runs for consensus path", "counter", m.latency_check_runs.load(.monotonic));
    }

    fn renderValidators(m: *SubmitMetrics, w: *Writer) Writer.Error!void {
        if (m.validators.len() == 0) return;
        var buf: [512]*prom.Labeled(Validator, 512).Slot = undefined;
        const vs = m.validators.sorted(&buf);
        var lb: [400]u8 = undefined;
        {
            var any = false;
            for (vs) |s| for (&s.v.submit_successes) |*a| for (a) |*x| {
                any = any or x.load(.monotonic) > 0;
            };
            if (any) {
                try prom.head(w, "transaction_driver_validator_submit_transaction_successes", "Number of successful submit transactions by validator", "counter");
                for (vs) |s| for (bool_names, 0..) |pn, p| for (tx_names, 0..) |tn, t| {
                    const v = s.v.submit_successes[t][p].load(.monotonic);
                    if (v > 0) {
                        try w.print("transaction_driver_validator_submit_transaction_successes{{ping=\"{s}\",tx_type=\"{s}\",validator=\"", .{ pn, tn });
                        try prom.writeLabelValue(w, s.name);
                        try w.print("\"}} {d}\n", .{v});
                    }
                };
            }
        }
        {
            try prom.head(w, "validator_client_observed_latency", "Client-observed latency of operations per validator", "histogram");
            for (vs) |s| for (op_names, 0..) |on, o| for (bool_names, 0..) |pn, p| {
                const h = &s.v.latency[o][p];
                if (h.count() == 0) continue;
                var lw = std.Io.Writer.fixed(&lb);
                lw.print("operation_type=\"{s}\",ping=\"{s}\",validator=\"", .{ on, pn }) catch continue;
                prom.writeLabelValue(&lw, s.name) catch continue;
                lw.writeAll("\"") catch continue;
                try h.renderSeries(w, "validator_client_observed_latency", lw.buffered());
            };
        }
        inline for (.{ .{ "validator_client_operation_success_total", "Total successful operations observed by client per validator", "success" }, .{ "validator_client_operation_failure_total", "Total failed operations observed by client per validator", "failure" } }) |f| {
            var any = false;
            for (vs) |s| for (&@field(s.v, f[2])) |*a| for (a) |*x| {
                any = any or x.load(.monotonic) > 0;
            };
            if (any) {
                try prom.head(w, f[0], f[1], "counter");
                for (vs) |s| for (op_names, 0..) |on, o| for (bool_names, 0..) |pn, p| {
                    const v = @field(s.v, f[2])[o][p].load(.monotonic);
                    if (v == 0) continue;
                    try w.print(f[0] ++ "{{operation_type=\"{s}\",ping=\"{s}\",validator=\"", .{ on, pn });
                    try prom.writeLabelValue(w, s.name);
                    try w.print("\"}} {d}\n", .{v});
                };
            }
        }
        {
            var any = false;
            for (vs) |s| any = any or s.v.performance_ns.load(.monotonic) > 0;
            if (any) {
                try prom.head(w, "validator_client_observed_performance", "Current client-observed performance per validator. The performance is the average latency of the validator\n                weighted by the reliability of the validator.", "gauge");
                for (vs) |s| {
                    const v = s.v.performance_ns.load(.monotonic);
                    if (v == 0) continue;
                    try w.writeAll("validator_client_observed_performance{validator=\"");
                    try prom.writeLabelValue(w, s.name);
                    try w.writeAll("\"} ");
                    try prom.writeFloat(w, @as(f64, @floatFromInt(v)) / 1e9);
                    try w.writeByte('\n');
                }
            }
        }
    }
};

/// The process-wide instance (sui-node's default registry).
pub var global: SubmitMetrics = .{};

/// The transaction kind and ping flag of the drive running on this thread (the driver's
/// feedback and the pool's records read them).
pub threadlocal var cur_tx: TxType = .single_writer;
pub threadlocal var cur_ping: bool = false;

test "submit metrics: orchestrator, driver and validator families" {
    var m: SubmitMetrics = .{};
    m.driveBegin(.shared_object);
    m.driveEnd(.shared_object, true, 400 * std.time.ns_per_ms);
    m.requestOk(.shared_object, 450 * std.time.ns_per_ms);
    m.submitted_(.shared_object, false);
    m.attemptError(.Unavailable, .shared_object, false);
    m.driveDone(.shared_object, false, true, false, 1, 400 * std.time.ns_per_ms);
    m.earlyRejected("UserInputError");
    m.interaction("Mysten-1", .submit, .shared_object, false, 20 * std.time.ns_per_ms);
    m.interaction("Mysten-1", .finality, .shared_object, true, null);
    m.performance("Mysten-1", 350 * std.time.ns_per_ms);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.render(&out.writer);
    const t = out.writer.buffered();
    const has = struct {
        fn f(text: []const u8, s: []const u8) bool {
            return std.mem.indexOf(u8, text, s) != null;
        }
    }.f;
    try std.testing.expect(has(t, "tx_orchestrator_total_req_received{tx_type=\"shared_object\"} 1\n"));
    try std.testing.expect(has(t, "tx_orchestrator_total_req_received{tx_type=\"single_writer\"} 0\n"));
    try std.testing.expect(has(t, "tx_orchestrator_good_response{tx_type=\"shared_object\"} 1\n"));
    try std.testing.expect(has(t, "tx_orchestrator_req_in_flight{tx_type=\"shared_object\"} 0\n"));
    try std.testing.expect(has(t, "tx_orchestrator_request_latency_bucket{route=\"execute_transaction_v3\",tx_type=\"shared_object\",wait_for_local_execution=\"false\",le=\"0.5\"} 1\n"));
    try std.testing.expect(has(t, "tx_orchestrator_settlement_finality_latency_count{driver_type=\"transaction_driver\",tx_type=\"shared_object\"} 1\n"));
    try std.testing.expect(has(t, "tx_orchestrator_early_validation_rejections{reason=\"UserInputError\"} 1\n"));
    try std.testing.expect(has(t, "transaction_driver_total_transactions_submitted{ping=\"false\",tx_type=\"shared_object\"} 1\n"));
    try std.testing.expect(has(t, "transaction_driver_drive_transaction_errors{error_type=\"Unavailable\",ping=\"false\",tx_type=\"shared_object\"} 1\n"));
    try std.testing.expect(has(t, "transaction_driver_transaction_retries_bucket{ping=\"false\",result=\"success\",tx_type=\"shared_object\",le=\"1\"} 1\n"));
    try std.testing.expect(has(t, "\ntransaction_driver_executed_transactions 1\n"));
    try std.testing.expect(has(t, "validator_client_observed_latency_count{operation_type=\"submit\",ping=\"false\",validator=\"Mysten-1\"} 1\n"));
    try std.testing.expect(has(t, "validator_client_operation_failure_total{operation_type=\"shared_object_finality\",ping=\"true\",validator=\"Mysten-1\"} 1\n"));
    try std.testing.expect(has(t, "validator_client_observed_performance{validator=\"Mysten-1\"} 0.35\n"));
    try std.testing.expect(has(t, "transaction_driver_validator_submit_transaction_successes{ping=\"false\",tx_type=\"shared_object\",validator=\"Mysten-1\"} 1\n"));
}
