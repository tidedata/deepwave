//! sui-node 1.83.1's RPC metrics (sui-rpc-api `metrics.rs` `RpcMetrics`), same names, labels,
//! help texts and buckets, fed by the transport's request observer (serve/h2/obs.zig):
//!
//!   rpc_inflight_requests{path}            gauge
//!   rpc_requests{path,status}              counter; status = gRPC code name from the response
//!                                          head (`ok` when the head has none), else the HTTP
//!                                          status; `canceled` when no response head was sent
//!   rpc_request_latency{path}              histogram, until the response finished (Drop)
//!   rpc_request_handler_latency{path}      histogram, until the response head
//!   rpc_first_chunk_latency{path}          histogram, until the first body chunk
//!
//! The `path` label (`compute_metric_label`): a gRPC request (content-type `application/grpc*`)
//! to a method of the registered descriptor sets (sui.rpc.v2, v2alpha, grpc.health) is labelled
//! with its path; any other request to a mounted service with the route pattern
//! `/<service>/{*rest}` (reflection is always this); `/health` with itself; anything else
//! `unknown`. Bounded: at most `max_labels` labels, the rest share `unknown`.
const std = @import("std");
const serve = @import("serve");
const obs = serve.h2.obs;
const Atomic = std.atomic.Value;

/// LATENCY_SEC_BUCKETS.
pub const buckets_s = [_]f64{ 0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 30, 60, 90 };
const bucket_ns = blk: {
    var out: [buckets_s.len]u64 = undefined;
    for (buckets_s, 0..) |b, i| out[i] = @intFromFloat(b * 1e9);
    break :blk out;
};
const bucket_le = [_][]const u8{ "0.001", "0.005", "0.01", "0.05", "0.1", "0.25", "0.5", "1", "2.5", "5", "10", "20", "30", "60", "90" };

/// tonic `code_as_str` (metrics.rs).
const grpc_names = [_][]const u8{ "ok", "canceled", "unknown", "invalid-argument", "deadline-exceeded", "not-found", "already-exists", "permission-denied", "resource-exhausted", "failed-precondition", "aborted", "out-of-range", "unimplemented", "internal", "unavailable", "data-loss", "unauthenticated" };
/// HTTP statuses the transport answers.
const http_codes = [_]u16{ 200, 400, 404, 405, 413, 415, 431, 500, 503 };
const http_names = [_][]const u8{ "200", "400", "404", "405", "413", "415", "431", "500", "503" };
const n_status = grpc_names.len + http_codes.len;
const canceled: usize = 1;

pub const max_labels = 256;

const Hist = struct {
    counts: [buckets_s.len]Atomic(u64) = @splat(.init(0)),
    sum_ns: Atomic(u64) = .init(0),
    n: Atomic(u64) = .init(0),

    fn observe(h: *Hist, ns: u64) void {
        for (bucket_ns, 0..) |b, i| if (ns <= b) {
            _ = h.counts[i].fetchAdd(1, .monotonic);
            break;
        };
        _ = h.sum_ns.fetchAdd(ns, .monotonic);
        _ = h.n.fetchAdd(1, .monotonic);
    }
};

const Label = struct {
    name: []const u8,
    inflight: Atomic(i64) = .init(0),
    status: [n_status]Atomic(u64) = @splat(.init(0)),
    latency: Hist = .{},
    handler: Hist = .{},
    first: Hist = .{},
};

pub const RpcMetrics = struct {
    gpa: std.mem.Allocator,
    lock: Atomic(u32) = .init(0),
    labels: [max_labels]?*Label = @splat(null),
    n: Atomic(u32) = .init(0),
    /// Path checks of the served router (tests pass their own).
    known: *const fn (path: []const u8) bool = routerKnown,
    method: *const fn (path: []const u8) bool = routerMethod,
    observer: obs.Observer = undefined,

    pub fn init(gpa: std.mem.Allocator) RpcMetrics {
        return .{ .gpa = gpa };
    }

    pub fn deinit(m: *RpcMetrics) void {
        for (m.labels[0..m.n.load(.acquire)]) |l| if (l) |x| {
            m.gpa.free(x.name);
            m.gpa.destroy(x);
        };
    }

    /// Makes this the process-wide request observer (serve/h2/obs.zig).
    pub fn install(m: *RpcMetrics) void {
        m.observer = .{ .ctx = m, .begin = beginFn, .status = statusFn, .first_chunk = firstFn, .end = endFn };
        obs.global.store(&m.observer, .release);
    }

    pub fn uninstall(m: *RpcMetrics) void {
        _ = obs.global.cmpxchgStrong(&m.observer, null, .acq_rel, .monotonic);
    }

    /// sui-rpc-api `compute_metric_label`, with the router's path rules.
    pub fn labelOf(m: *const RpcMetrics, path: []const u8, grpc: bool, buf: []u8) []const u8 {
        if (m.known(path)) {
            const svc = serve.router.serviceOf(path);
            const reflection = std.mem.startsWith(u8, svc, "grpc.reflection.");
            if (grpc and !reflection and m.method(path)) return path;
            return std.fmt.bufPrint(buf, "/{s}/{{*rest}}", .{svc}) catch "unknown";
        }
        if (std.mem.eql(u8, path, "/health")) return "/health";
        return "unknown";
    }

    fn acquire(m: *RpcMetrics) void {
        while (m.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn release(m: *RpcMetrics) void {
        m.lock.store(0, .release);
    }

    /// The label's index, created on first use (null: out of memory).
    pub fn intern(m: *RpcMetrics, name: []const u8) ?u16 {
        const n = m.n.load(.acquire);
        for (m.labels[0..n], 0..) |l, i| if (std.mem.eql(u8, l.?.name, name)) return @intCast(i);
        m.acquire();
        defer m.release();
        const n2 = m.n.load(.acquire);
        for (m.labels[n..n2], n..) |l, i| if (std.mem.eql(u8, l.?.name, name)) return @intCast(i);
        if (n2 == max_labels) {
            // bounded: everything past the cap is `unknown`
            for (m.labels[0..n2], 0..) |l, i| if (std.mem.eql(u8, l.?.name, "unknown")) return @intCast(i);
            return null;
        }
        const l = m.gpa.create(Label) catch return null;
        l.* = .{ .name = m.gpa.dupe(u8, name) catch {
            m.gpa.destroy(l);
            return null;
        } };
        m.labels[n2] = l;
        m.n.store(n2 + 1, .release);
        return @intCast(n2);
    }

    fn get(m: *RpcMetrics, label: u16) *Label {
        return m.labels[label].?;
    }

    fn beginFn(ctx: *anyopaque, path: []const u8, grpc: bool) u16 {
        const m: *RpcMetrics = @ptrCast(@alignCast(ctx));
        var buf: [320]u8 = undefined;
        const id = m.intern(m.labelOf(path, grpc, &buf)) orelse return obs.none;
        _ = m.get(id).inflight.fetchAdd(1, .monotonic);
        return id;
    }

    fn statusIndex(status: u16) ?usize {
        if (status < grpc_names.len) return status;
        if (status >= obs.http_base) {
            const code = status - obs.http_base;
            for (http_codes, 0..) |c, i| if (c == code) return grpc_names.len + i;
        }
        return null;
    }

    fn statusFn(ctx: *anyopaque, label: u16, status: u16, elapsed_ns: u64) void {
        const m: *RpcMetrics = @ptrCast(@alignCast(ctx));
        const l = m.get(label);
        l.handler.observe(elapsed_ns);
        if (statusIndex(status)) |i| _ = l.status[i].fetchAdd(1, .monotonic);
    }

    fn firstFn(ctx: *anyopaque, label: u16, elapsed_ns: u64) void {
        const m: *RpcMetrics = @ptrCast(@alignCast(ctx));
        m.get(label).first.observe(elapsed_ns);
    }

    fn endFn(ctx: *anyopaque, label: u16, counted: bool, elapsed_ns: u64) void {
        const m: *RpcMetrics = @ptrCast(@alignCast(ctx));
        const l = m.get(label);
        _ = l.inflight.fetchSub(1, .monotonic);
        l.latency.observe(elapsed_ns);
        if (!counted) _ = l.status[canceled].fetchAdd(1, .monotonic);
    }

    /// Prometheus text, families in sui-node's order of names, series sorted by label.
    pub fn render(m: *RpcMetrics, w: *std.Io.Writer) !void {
        const n = m.n.load(.acquire);
        var order: [max_labels]u16 = undefined;
        for (0..n) |i| order[i] = @intCast(i);
        const Ctx = struct {
            m: *RpcMetrics,
            fn lt(c: @This(), a: u16, b: u16) bool {
                return std.mem.lessThan(u8, c.m.get(a).name, c.m.get(b).name);
            }
        };
        std.sort.pdq(u16, order[0..n], Ctx{ .m = m }, Ctx.lt);
        const ids = order[0..n];

        try m.hist(w, ids, "rpc_first_chunk_latency", "Latency of RPC requests per route, measured from receipt of the request until the first response body data chunk is produced. For streaming responses this is when the first chunk is handed to the transport, which for gRPC typically carries the first encoded message; response headers are excluded. Responses whose body never yields a data chunk are not observed.", "first");
        try w.writeAll("# HELP rpc_inflight_requests Total in-flight RPC requests per route\n# TYPE rpc_inflight_requests gauge\n");
        for (ids) |i| {
            const l = m.get(i);
            try w.print("rpc_inflight_requests{{path=\"{s}\"}} {d}\n", .{ l.name, @max(0, l.inflight.load(.monotonic)) });
        }
        try m.hist(w, ids, "rpc_request_handler_latency", "Latency of RPC requests per route, measured from receipt of the request until the request handler produced a response, excluding the time spent streaming the response body back to the client", "handler");
        try m.hist(w, ids, "rpc_request_latency", "Latency of RPC requests per route, measured from receipt of the request until the response body finished streaming back to the client", "latency");
        try w.writeAll("# HELP rpc_requests Total RPC requests per route and their http status\n# TYPE rpc_requests counter\n");
        // status names sorted as text, as the prometheus crate sorts label values
        var sorder: [n_status]usize = undefined;
        for (0..n_status) |i| sorder[i] = i;
        std.sort.pdq(usize, &sorder, {}, struct {
            fn lt(_: void, a: usize, b: usize) bool {
                return std.mem.lessThan(u8, statusName(a), statusName(b));
            }
        }.lt);
        for (ids) |i| {
            const l = m.get(i);
            for (sorder) |s| {
                const v = l.status[s].load(.monotonic);
                if (v > 0) try w.print("rpc_requests{{path=\"{s}\",status=\"{s}\"}} {d}\n", .{ l.name, statusName(s), v });
            }
        }
    }

    fn statusName(i: usize) []const u8 {
        return if (i < grpc_names.len) grpc_names[i] else http_names[i - grpc_names.len];
    }

    fn hist(m: *RpcMetrics, w: *std.Io.Writer, ids: []const u16, comptime name: []const u8, comptime help: []const u8, comptime field: []const u8) !void {
        try w.writeAll("# HELP " ++ name ++ " " ++ help ++ "\n# TYPE " ++ name ++ " histogram\n");
        for (ids) |i| {
            const l = m.get(i);
            const h = &@field(l, field);
            const total = h.n.load(.monotonic);
            if (total == 0) continue;
            var cum: u64 = 0;
            for (bucket_le, 0..) |le, b| {
                cum += h.counts[b].load(.monotonic);
                try w.print(name ++ "_bucket{{path=\"{s}\",le=\"{s}\"}} {d}\n", .{ l.name, le, cum });
            }
            try w.print(name ++ "_bucket{{path=\"{s}\",le=\"+Inf\"}} {d}\n", .{ l.name, total });
            const sum_s = @as(f64, @floatFromInt(h.sum_ns.load(.monotonic))) / 1e9;
            try w.print(name ++ "_sum{{path=\"{s}\"}} {d}\n" ++ name ++ "_count{{path=\"{s}\"}} {d}\n", .{ l.name, sum_s, l.name, total });
        }
    }
};

fn routerKnown(path: []const u8) bool {
    return serve.router.known(undefined, path);
}
fn routerMethod(path: []const u8) bool {
    return serve.router.method(undefined, path);
}

test "rpc metrics: labels, statuses, buckets as sui-node" {
    const gpa = std.testing.allocator;
    var m = RpcMetrics.init(gpa);
    defer m.deinit();
    m.known = struct {
        fn f(p: []const u8) bool {
            return std.mem.startsWith(u8, p, "/sui.rpc.v2.LedgerService/") or std.mem.startsWith(u8, p, "/grpc.reflection.v1.ServerReflection/");
        }
    }.f;
    m.method = struct {
        fn f(p: []const u8) bool {
            return std.mem.eql(u8, p, "/sui.rpc.v2.LedgerService/GetObject") or std.mem.eql(u8, p, "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo");
        }
    }.f;
    m.install();
    defer m.uninstall();
    var buf: [320]u8 = undefined;
    try std.testing.expectEqualStrings("/sui.rpc.v2.LedgerService/GetObject", m.labelOf("/sui.rpc.v2.LedgerService/GetObject", true, &buf));
    try std.testing.expectEqualStrings("/sui.rpc.v2.LedgerService/{*rest}", m.labelOf("/sui.rpc.v2.LedgerService/GetObject", false, &buf));
    try std.testing.expectEqualStrings("/sui.rpc.v2.LedgerService/{*rest}", m.labelOf("/sui.rpc.v2.LedgerService/Nope", true, &buf));
    try std.testing.expectEqualStrings("/grpc.reflection.v1.ServerReflection/{*rest}", m.labelOf("/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", true, &buf));
    try std.testing.expectEqualStrings("/health", m.labelOf("/health", false, &buf));
    try std.testing.expectEqualStrings("unknown", m.labelOf("/x/y", true, &buf));

    // one ok at 3 ms, one not-found trailers-only at 0.5 ms, one dropped before a head
    var t1: obs.Track = .{};
    t1.begin("/sui.rpc.v2.LedgerService/GetObject", true, 0);
    t1.status(obs.grpcLabel(.ok), 2_000_000);
    t1.firstChunk(2_500_000);
    t1.end(3_000_000);
    var t2: obs.Track = .{};
    t2.begin("/sui.rpc.v2.LedgerService/GetObject", true, 0);
    t2.status(obs.grpcLabel(.not_found), 500_000);
    t2.end(500_000);
    var t3: obs.Track = .{};
    t3.begin("/sui.rpc.v2.LedgerService/GetObject", true, 0);
    var t4: obs.Track = .{};
    t4.begin("/health", false, 0);
    t4.status(obs.httpLabel(200), 100);
    t4.end(100);

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try m.render(&out.writer);
    const text = out.writer.buffered();
    const has = struct {
        fn f(t: []const u8, line: []const u8) bool {
            var it = std.mem.splitScalar(u8, t, '\n');
            while (it.next()) |l| if (std.mem.eql(u8, l, line)) return true;
            return false;
        }
    }.f;
    try std.testing.expect(has(text, "rpc_inflight_requests{path=\"/sui.rpc.v2.LedgerService/GetObject\"} 1"));
    try std.testing.expect(has(text, "rpc_requests{path=\"/sui.rpc.v2.LedgerService/GetObject\",status=\"not-found\"} 1"));
    try std.testing.expect(has(text, "rpc_requests{path=\"/sui.rpc.v2.LedgerService/GetObject\",status=\"ok\"} 1"));
    try std.testing.expect(has(text, "rpc_requests{path=\"/health\",status=\"200\"} 1"));
    try std.testing.expect(has(text, "rpc_request_latency_bucket{path=\"/sui.rpc.v2.LedgerService/GetObject\",le=\"0.001\"} 1"));
    try std.testing.expect(has(text, "rpc_request_latency_bucket{path=\"/sui.rpc.v2.LedgerService/GetObject\",le=\"0.005\"} 2"));
    try std.testing.expect(has(text, "rpc_request_latency_bucket{path=\"/sui.rpc.v2.LedgerService/GetObject\",le=\"+Inf\"} 2"));
    try std.testing.expect(has(text, "rpc_request_latency_count{path=\"/sui.rpc.v2.LedgerService/GetObject\"} 2"));
    try std.testing.expect(has(text, "rpc_first_chunk_latency_count{path=\"/sui.rpc.v2.LedgerService/GetObject\"} 1"));
    t3.end(1_000);
    var out2: std.Io.Writer.Allocating = .init(gpa);
    defer out2.deinit();
    try m.render(&out2.writer);
    try std.testing.expect(has(out2.writer.buffered(), "rpc_requests{path=\"/sui.rpc.v2.LedgerService/GetObject\",status=\"canceled\"} 1"));
    try std.testing.expect(has(out2.writer.buffered(), "rpc_inflight_requests{path=\"/sui.rpc.v2.LedgerService/GetObject\"} 0"));
}
