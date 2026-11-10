//! Validator metrics with the names, help strings, label names and bucket sets of
//! `ValidatorServiceMetrics` (authority_server.rs), the overload gauges of `AuthorityMetrics`
//! (authority.rs) and the epoch gauges sui-node exports (`current_epoch`, `sui_current_protocol_version`,
//! `epoch_total_duration`; metrics that have no Rust counterpart carry a `zui_` prefix), in the Prometheus text format served on
//! `metrics-address` (`GET /metrics`). One registry per process; every counter and gauge is an
//! atomic, histograms are atomic bucket arrays, labelled families create their series on first use.
//! Names are a compatibility surface (Mysten's validator dashboards and alerts), so a
//! rename needs the Rust name next to it.
const std = @import("std");
const Io = std.Io;

pub const subsecond_latency_buckets = [_]f64{
    0.001, 0.005, 0.01,  0.025, 0.05, 0.075, 0.1,  0.125, 0.15, 0.175, 0.2,  0.225, 0.25, 0.275, 0.3,
    0.325, 0.35,  0.375, 0.4,   0.425, 0.45, 0.475, 0.5,   0.55, 0.6,   0.65, 0.7,   0.75, 0.8,   0.85,
    0.9,   0.95,  1,     2,     5,     10,   20,    30,    60,   90,
};
pub const coarse_latency_buckets = [_]f64{ 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.2, 0.3, 0.5, 0.7, 1, 2, 3, 5, 10, 20, 30, 60, 90 };
pub const bytes_buckets = [_]f64{ 1, 4, 16, 64, 256, 1024, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864 };
pub const count_buckets = [_]f64{ 1, 2, 3, 4, 5, 7, 10, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200, 500, 1000, 2000, 5000, 10000 };

pub const Kind = enum { counter, gauge, histogram };

pub const Spec = struct {
    name: []const u8,
    help: []const u8,
    kind: Kind,
    /// One label name, or null for an unlabelled metric.
    label: ?[]const u8 = null,
    buckets: []const f64 = &.{},
};

const max_series = 64;
const max_buckets = 48;

const Series = struct {
    /// Label value (empty for unlabelled), owned.
    value: []const u8 = &.{},
    used: std.atomic.Value(bool) = .init(false),
    /// counter/gauge value; for histograms the observation count.
    n: std.atomic.Value(u64) = .init(0),
    /// histogram sum in nanoseconds-style fixed point (value * 1e9), saturating.
    sum: std.atomic.Value(u64) = .init(0),
    buckets: [max_buckets]std.atomic.Value(u64) = @splat(.init(0)),
};

pub const Family = struct {
    spec: Spec,
    series: [max_series]Series = @splat(.{}),
    mutex: Io.Mutex = .init,

    fn find(f: *Family, io: Io, label: []const u8) ?*Series {
        for (&f.series) |*s| {
            if (s.used.load(.acquire) and std.mem.eql(u8, s.value, label)) return s;
        }
        f.mutex.lockUncancelable(io);
        defer f.mutex.unlock(io);
        for (&f.series) |*s| {
            if (s.used.load(.acquire) and std.mem.eql(u8, s.value, label)) return s;
        }
        for (&f.series) |*s| {
            if (!s.used.load(.acquire)) {
                s.value = std.heap.page_allocator.dupe(u8, label) catch return null;
                s.used.store(true, .release);
                return s;
            }
        }
        return null; // label cardinality bound: further values are dropped, never grown
    }
};

pub const Counter = struct {
    f: *Family,
    io: Io,
    pub fn inc(c: Counter) void {
        c.add("", 1);
    }
    pub fn add(c: Counter, label: []const u8, v: u64) void {
        if (c.f.find(c.io, label)) |s| _ = s.n.fetchAdd(v, .monotonic);
    }
    pub fn incLabel(c: Counter, label: []const u8) void {
        c.add(label, 1);
    }
};

pub const Gauge = struct {
    f: *Family,
    io: Io,
    pub fn set(g: Gauge, v: i64) void {
        if (g.f.find(g.io, "")) |s| s.n.store(@bitCast(v), .monotonic);
    }
    pub fn get(g: Gauge) i64 {
        return if (g.f.find(g.io, "")) |s| @bitCast(s.n.load(.monotonic)) else 0;
    }
};

pub const Histogram = struct {
    f: *Family,
    io: Io,
    pub fn observe(h: Histogram, label: []const u8, v: f64) void {
        const s = h.f.find(h.io, label) orelse return;
        _ = s.n.fetchAdd(1, .monotonic);
        const fixed: u64 = if (v <= 0) 0 else @intFromFloat(@min(v * 1e9, 1.8e19));
        _ = s.sum.fetchAdd(fixed, .monotonic);
        for (h.f.spec.buckets, 0..) |b, i| {
            if (v <= b) _ = s.buckets[i].fetchAdd(1, .monotonic);
        }
    }
};

/// The metric set of the validator. `Registry.init` registers everything below.
pub const specs = [_]Spec{
    // ValidatorServiceMetrics
    .{ .name = "total_signature_errors", .help = "Number of transaction signature errors", .kind = .counter },
    .{ .name = "validator_service_tx_verification_latency", .help = "Latency of verifying a transaction", .kind = .histogram, .buckets = &subsecond_latency_buckets },
    .{ .name = "validator_service_handle_transaction_latency", .help = "Latency of handling a transaction", .kind = .histogram, .buckets = &subsecond_latency_buckets },
    .{ .name = "validator_service_handle_transaction_consensus_latency", .help = "Latency of handling a user transaction sent through consensus", .kind = .histogram, .buckets = &coarse_latency_buckets },
    .{ .name = "validator_service_submit_transaction_consensus_latency", .help = "Latency of submitting a user transaction sent through consensus", .kind = .histogram, .label = "req_type", .buckets = &subsecond_latency_buckets },
    .{ .name = "validator_service_submit_transaction_latency", .help = "Latency of submit transaction handler", .kind = .histogram, .label = "req_type", .buckets = &subsecond_latency_buckets },
    .{ .name = "validator_service_handle_wait_for_effects_ping_latency", .help = "Latency of handling a ping request for wait_for_effects", .kind = .histogram, .label = "req_type", .buckets = &subsecond_latency_buckets },
    .{ .name = "validator_service_submit_transaction_bytes", .help = "The size of transactions in the submit transaction request", .kind = .histogram, .label = "req_type", .buckets = &bytes_buckets },
    .{ .name = "validator_service_submit_transaction_batch_size", .help = "The number of transactions in the submit transaction request", .kind = .histogram, .label = "req_type", .buckets = &count_buckets },
    .{ .name = "validator_service_num_rejected_tx_during_overload", .help = "Number of rejected transaction due to system overload", .kind = .counter, .label = "error_type" },
    .{ .name = "validator_service_submission_rejected_transactions", .help = "Number of transactions rejected during submission", .kind = .counter, .label = "reason" },
    .{ .name = "validator_service_submission_suppressed_already_processed", .help = "Number of submitted transactions suppressed because consensus had already processed them this epoch (re-submission of already-processed transactions)", .kind = .counter, .label = "req_type" },
    .{ .name = "validator_service_submission_suppressed_recently_submitted", .help = "Number of submitted transactions suppressed because the same transaction was submitted within the recent-submission window", .kind = .counter, .label = "req_type" },
    .{ .name = "validator_service_recently_submitted_cache_size", .help = "Approximate number of transaction digests held in the recent-submission duplicate-suppression cache", .kind = .gauge },
    .{ .name = "validator_service_submission_suppressed_inflight", .help = "Number of submitted transactions suppressed because the same transaction was already being handled by a concurrent in-flight submit request", .kind = .counter, .label = "req_type" },
    .{ .name = "validator_service_inflight_transactions", .help = "Number of transactions from inflight submit requests", .kind = .gauge },
    .{ .name = "validator_service_connection_ip_not_found", .help = "Number of times connection IP was not extractable from request", .kind = .counter },
    // AuthorityMetrics (overload)
    .{ .name = "authority_overload_status", .help = "Whether authority is current experiencing overload and trying to shed load (1 or 0)", .kind = .gauge },
    .{ .name = "authority_load_shedding_percentage", .help = "The percentage of transactions is shed when the authority is in load shedding mode", .kind = .gauge },
    .{ .name = "transaction_overload_sources", .help = "Number of times each source indicates transaction overload.", .kind = .counter, .label = "source" },
    // epoch gauges: Rust names and help texts (epoch_metrics.rs, sui-node metrics.rs)
    .{ .name = "current_epoch", .help = "Current epoch ID", .kind = .gauge },
    .{ .name = "sui_current_protocol_version", .help = "Current protocol version in this epoch", .kind = .gauge },
    .{ .name = "epoch_total_duration", .help = "Total duration of the epoch", .kind = .gauge },
    // deepwave only (no Rust counterpart)
    .{ .name = "zui_epoch_start_timestamp_ms", .help = "Start timestamp of the current epoch in milliseconds", .kind = .gauge },
    .{ .name = "zui_epoch_reconfig_state", .help = "Reconfig state of the epoch (0 accept all certs, 1 reject user certs, 2 reject all certs, 3 reject all tx)", .kind = .gauge },
    .{ .name = "zui_epoch_end_of_publish_stake", .help = "Stake that has sent EndOfPublish this epoch", .kind = .gauge },
    .{ .name = "zui_epoch_safe_mode", .help = "Whether the system runs in safe mode (1 or 0)", .kind = .gauge },
    .{ .name = "zui_epoch_switches_total", .help = "Number of epoch switches since process start", .kind = .counter },
    .{ .name = "zui_validator_grpc_requests", .help = "Validator gRPC requests by method", .kind = .counter, .label = "method" },
};

pub const Registry = struct {
    families: [specs.len]Family,
    io: Io,

    pub fn init(io: Io) Registry {
        var r: Registry = .{ .families = undefined, .io = io };
        inline for (specs, 0..) |s, i| r.families[i] = .{ .spec = s };
        return r;
    }

    fn idx(comptime name: []const u8) usize {
        inline for (specs, 0..) |s, i| if (comptime std.mem.eql(u8, s.name, name)) return i;
        @compileError("unknown metric " ++ name);
    }

    pub fn counter(r: *Registry, comptime name: []const u8) Counter {
        comptime std.debug.assert(specs[idx(name)].kind == .counter);
        return .{ .f = &r.families[idx(name)], .io = r.io };
    }
    pub fn gauge(r: *Registry, comptime name: []const u8) Gauge {
        comptime std.debug.assert(specs[idx(name)].kind == .gauge);
        return .{ .f = &r.families[idx(name)], .io = r.io };
    }
    pub fn histogram(r: *Registry, comptime name: []const u8) Histogram {
        comptime std.debug.assert(specs[idx(name)].kind == .histogram);
        return .{ .f = &r.families[idx(name)], .io = r.io };
    }

    /// Prometheus text exposition of every series that exists (unlabelled counters and gauges
    /// always, as the Rust registry exports zero values).
    pub fn render(r: *Registry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        for (&r.families) |*f| {
            const sp = f.spec;
            try w.print("# HELP {s} {s}\n# TYPE {s} {s}\n", .{ sp.name, sp.help, sp.name, @tagName(sp.kind) });
            if (sp.label == null) _ = f.find(r.io, "");
            for (&f.series) |*s| {
                if (!s.used.load(.acquire)) continue;
                switch (sp.kind) {
                    .counter => try printSample(w, sp, s, "", s.n.load(.monotonic)),
                    .gauge => {
                        const v: i64 = @bitCast(s.n.load(.monotonic));
                        if (sp.label) |l| try w.print("{s}{{{s}=\"{s}\"}} {d}\n", .{ sp.name, l, s.value, v }) else try w.print("{s} {d}\n", .{ sp.name, v });
                    },
                    .histogram => {
                        for (sp.buckets, 0..) |b, i| {
                            try w.print("{s}_bucket{{", .{sp.name});
                            if (sp.label) |l| try w.print("{s}=\"{s}\",", .{ l, s.value });
                            try w.print("le=\"{d}\"}} {d}\n", .{ b, s.buckets[i].load(.monotonic) });
                        }
                        try w.print("{s}_bucket{{", .{sp.name});
                        if (sp.label) |l| try w.print("{s}=\"{s}\",", .{ l, s.value });
                        try w.print("le=\"+Inf\"}} {d}\n", .{s.n.load(.monotonic)});
                        const sum = @as(f64, @floatFromInt(s.sum.load(.monotonic))) / 1e9;
                        if (sp.label) |l| {
                            try w.print("{s}_sum{{{s}=\"{s}\"}} {d}\n{s}_count{{{s}=\"{s}\"}} {d}\n", .{ sp.name, l, s.value, sum, sp.name, l, s.value, s.n.load(.monotonic) });
                        } else {
                            try w.print("{s}_sum {d}\n{s}_count {d}\n", .{ sp.name, sum, sp.name, s.n.load(.monotonic) });
                        }
                    },
                }
            }
        }
    }

    fn printSample(w: *std.Io.Writer, sp: Spec, s: *const Series, suffix: []const u8, v: u64) std.Io.Writer.Error!void {
        if (sp.label) |l| {
            try w.print("{s}{s}{{{s}=\"{s}\"}} {d}\n", .{ sp.name, suffix, l, s.value, v });
        } else try w.print("{s}{s} {d}\n", .{ sp.name, suffix, v });
    }
};

test "registry renders counters, gauges and histograms in the Prometheus text format" {
    var r = Registry.init(std.testing.io);
    r.counter("total_signature_errors").inc();
    r.counter("validator_service_num_rejected_tx_during_overload").incLabel("execution_pending");
    r.gauge("authority_load_shedding_percentage").set(42);
    r.histogram("validator_service_handle_transaction_latency").observe("", 0.03);
    r.histogram("validator_service_submit_transaction_latency").observe("submit", 2.0);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try r.render(&out.writer);
    const s = out.written();
    try std.testing.expect(std.mem.indexOf(u8, s, "# TYPE total_signature_errors counter\ntotal_signature_errors 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "validator_service_num_rejected_tx_during_overload{error_type=\"execution_pending\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "authority_load_shedding_percentage 42\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "validator_service_handle_transaction_latency_bucket{le=\"0.05\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "validator_service_handle_transaction_latency_bucket{le=\"0.025\"} 0\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, s, "validator_service_submit_transaction_latency_count{req_type=\"submit\"} 1\n") != null);
    // unlabelled gauges that were never set still appear (zero)
    try std.testing.expect(std.mem.indexOf(u8, s, "current_epoch 0\n") != null);
}
