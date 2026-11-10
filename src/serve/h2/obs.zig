//! Request observer: the hook sui-node's `RpcMetricsMakeCallbackHandler` sits on (sui-rpc-api
//! `metrics.rs`, 1.83.1). The transport calls it for every request on both protocols:
//!
//!   begin        request headers complete (tonic's `make_handler`): returns the label id;
//!   status       response head decided (`on_response`): a gRPC response is labelled with its
//!                head's grpc-status (trailers-only) or `ok`; anything else with its HTTP status;
//!   first_chunk  first response body bytes handed to the transport (`on_body_chunk`);
//!   end          the request is gone (`Drop`): ended, reset, or its connection closed. A request
//!                that never reached `status` is counted `canceled` by the observer.
//!
//! One process-wide observer (`global`), set by the node before it serves; null costs one load
//! per request. Labels are small integers chosen by the observer (bounded label set).
const std = @import("std");
const Status = @import("conn.zig").Status;

pub const none: u16 = std.math.maxInt(u16);

/// A response status label: a gRPC code (0..16) or an HTTP status (`http_base` + code).
pub const http_base: u16 = 1000;
pub fn grpcLabel(s: Status) u16 {
    return @intFromEnum(s);
}
pub fn httpLabel(code: u16) u16 {
    return http_base + code;
}

pub const Observer = struct {
    ctx: *anyopaque,
    begin: *const fn (ctx: *anyopaque, path: []const u8, grpc: bool) u16,
    status: *const fn (ctx: *anyopaque, label: u16, status: u16, elapsed_ns: u64) void,
    first_chunk: *const fn (ctx: *anyopaque, label: u16, elapsed_ns: u64) void,
    end: *const fn (ctx: *anyopaque, label: u16, counted: bool, elapsed_ns: u64) void,
};

pub var global: std.atomic.Value(?*const Observer) = .init(null);

/// Per-request state the transport keeps (h2 `Stream`, HTTP/1.1 request).
pub const Track = struct {
    label: u16 = none,
    t0: u64 = 0,
    counted: bool = false,
    first: bool = false,
    obs: ?*const Observer = null,

    pub fn begin(t: *Track, path: []const u8, content_type_grpc: bool, now_ns: u64) void {
        if (t.label != none) return;
        const o = global.load(.acquire) orelse return;
        t.obs = o;
        t.t0 = now_ns;
        t.label = o.begin(o.ctx, path, content_type_grpc);
    }
    pub fn status(t: *Track, label: u16, now_ns: u64) void {
        if (t.label == none or t.counted) return;
        t.counted = true;
        t.obs.?.status(t.obs.?.ctx, t.label, label, now_ns -| t.t0);
    }
    pub fn firstChunk(t: *Track, now_ns: u64) void {
        if (t.label == none or t.first) return;
        t.first = true;
        t.obs.?.first_chunk(t.obs.?.ctx, t.label, now_ns -| t.t0);
    }
    pub fn end(t: *Track, now_ns: u64) void {
        if (t.label == none) return;
        const o = t.obs.?;
        o.end(o.ctx, t.label, t.counted, now_ns -| t.t0);
        t.label = none;
    }
};

/// tonic's `is_grpc_content_type`: the value starts with `application/grpc` (gRPC-web too).
pub fn isGrpcContentType(v: []const u8) bool {
    return std.mem.startsWith(u8, v, "application/grpc");
}

/// HTTP/1.1 requests run on their connection thread: the request in flight there.
pub threadlocal var current: ?*Track = null;

test "track: begin once, status once, end once" {
    const Rec = struct {
        begins: u32 = 0,
        statuses: u32 = 0,
        last_status: u16 = 0,
        ends: u32 = 0,
        counted_at_end: bool = false,
        fn b(ctx: *anyopaque, _: []const u8, _: bool) u16 {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.begins += 1;
            return 7;
        }
        fn s(ctx: *anyopaque, _: u16, st: u16, _: u64) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.statuses += 1;
            r.last_status = st;
        }
        fn f(_: *anyopaque, _: u16, _: u64) void {}
        fn e(ctx: *anyopaque, _: u16, counted: bool, _: u64) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.ends += 1;
            r.counted_at_end = counted;
        }
    };
    var rec: Rec = .{};
    const o: Observer = .{ .ctx = &rec, .begin = Rec.b, .status = Rec.s, .first_chunk = Rec.f, .end = Rec.e };
    global.store(&o, .release);
    defer global.store(null, .release);
    var t: Track = .{};
    t.begin("/a/b", true, 10);
    t.begin("/a/b", true, 11);
    t.status(grpcLabel(.not_found), 20);
    t.status(grpcLabel(.ok), 21);
    t.end(30);
    t.end(31);
    try std.testing.expectEqual(@as(u32, 1), rec.begins);
    try std.testing.expectEqual(@as(u32, 1), rec.statuses);
    try std.testing.expectEqual(@as(u16, 5), rec.last_status);
    try std.testing.expectEqual(@as(u32, 1), rec.ends);
    try std.testing.expect(rec.counted_at_end);
    try std.testing.expect(isGrpcContentType("application/grpc-web+proto"));
    try std.testing.expect(!isGrpcContentType("text/plain"));
}
