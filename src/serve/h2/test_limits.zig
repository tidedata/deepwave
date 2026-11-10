//! Transport limits at sui-node 1.83.1's values (docs/FULLNODE-PARITY.md task 9) and the request
//! observer (obs.zig): behaviour at each limit.
//!   - 200 concurrent streams: advertised in SETTINGS, stream 201 refused (RST_STREAM REFUSED_STREAM);
//!   - 4 MiB request message: one byte over answers trailers-only OUT_OF_RANGE with tonic 0.14.6's
//!     text (`decode.rs`), as soon as the body passes the limit;
//!   - 60 s server timeout (or a shorter grpc-timeout): a unary call still running on a worker is
//!     answered DEADLINE_EXCEEDED "Timeout expired" at the deadline, trailers-only, as sui-http's
//!     GrpcTimeout; the connection stays usable and the late result is dropped.
const std = @import("std");
const testing = std.testing;
// Not root.zig: these tests run on their own too (`zig test src/serve/h2/test_limits.zig`).
const h2 = struct {
    const conn = @import("conn.zig");
    const server = @import("server.zig");
    const sock = @import("sock.zig");
    const meta = @import("meta.zig");
    const Conn = conn.Conn;
    const Handler = conn.Handler;
    const Request = conn.Request;
    const ResponseStream = conn.ResponseStream;
    const Status = conn.Status;
    const ServerOptions = server.Options;
};
const hpack = @import("hpack.zig");
const obs = @import("obs.zig");

fn frame(out: *std.ArrayList(u8), t: u8, flags: u8, sid: u32, payload: []const u8) !void {
    const gpa = testing.allocator;
    try out.appendSlice(gpa, &.{ @intCast(payload.len >> 16), @intCast((payload.len >> 8) & 0xff), @intCast(payload.len & 0xff), t, flags });
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, sid, .big);
    try out.appendSlice(gpa, &s);
    try out.appendSlice(gpa, payload);
}

fn requestHeaders(out: *std.ArrayList(u8), path: []const u8, timeout: ?[]const u8) !void {
    const gpa = testing.allocator;
    try out.appendSlice(gpa, &.{ 0x83, 0x86 });
    try hpack.encodeLiteral(out, gpa, ":path", path);
    try hpack.encodeLiteral(out, gpa, ":authority", "localhost");
    try hpack.encodeLiteral(out, gpa, "content-type", "application/grpc");
    try hpack.encodeLiteral(out, gpa, "te", "trailers");
    if (timeout) |t| try hpack.encodeLiteral(out, gpa, "grpc-timeout", t);
}

const Out = struct { t: u8, flags: u8, sid: u32, payload: []const u8 };

fn parseOut(buf: []const u8, list: *std.ArrayList(Out)) void {
    var pos: usize = 0;
    while (pos + 9 <= buf.len) {
        const len = (@as(usize, buf[pos]) << 16) | (@as(usize, buf[pos + 1]) << 8) | buf[pos + 2];
        if (pos + 9 + len > buf.len) break;
        list.append(testing.allocator, .{ .t = buf[pos + 3], .flags = buf[pos + 4], .sid = std.mem.readInt(u32, buf[pos + 5 ..][0..4], .big) & 0x7fffffff, .payload = buf[pos + 9 ..][0..len] }) catch unreachable;
        pos += 9 + len;
    }
}

const Svc = struct {
    sleep_ms: u64 = 0,
    calls: std.atomic.Value(u32) = .init(0),
    fn method(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t.S/");
    }
    fn known(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t.S/");
    }
    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const self: *Svc = @ptrCast(@alignCast(ctx));
        _ = self.calls.fetchAdd(1, .monotonic);
        if (std.mem.eql(u8, req.path, "/t.S/Slow")) h2.sock.sleepMs(self.sleep_ms);
        if (std.mem.eql(u8, req.path, "/t.S/Missing")) return .not_found;
        rs.message(req.body) catch return .internal;
        return .ok;
    }
    fn handler(self: *Svc) h2.Handler {
        return .{ .ctx = self, .call = call, .method = method, .known = known };
    }
};

fn openConn(c: *h2.Conn) !void {
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    try in.appendSlice(testing.allocator, h2.conn.preface);
    try frame(&in, 4, 0, 0, &.{});
    try c.feed(in.items);
}

test "limits: 200 concurrent streams advertised, stream 201 refused" {
    var svc: Svc = .{};
    var c = try h2.Conn.init(testing.allocator, .{ .max_streams = 200 }, svc.handler());
    defer c.deinit();
    try openConn(&c);
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(testing.allocator);
    parseOut(c.pending(), &frames);
    // SETTINGS_MAX_CONCURRENT_STREAMS (id 3) = 200
    var advertised = false;
    for (frames.items) |f| if (f.t == 4 and f.flags & 1 == 0) {
        var i: usize = 0;
        while (i + 6 <= f.payload.len) : (i += 6) {
            if (std.mem.readInt(u16, f.payload[i..][0..2], .big) == 3) advertised = std.mem.readInt(u32, f.payload[i + 2 ..][0..4], .big) == 200;
        }
    };
    try testing.expect(advertised);
    c.consumed(c.pending().len);

    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(testing.allocator);
    try requestHeaders(&hb, "/t.S/Echo", null);
    var sid: u32 = 1;
    for (0..201) |_| {
        // headers without END_STREAM: each stream stays open
        try frame(&in, 1, 4, sid, hb.items);
        sid += 2;
    }
    try c.feed(in.items);
    frames.clearRetainingCapacity();
    parseOut(c.pending(), &frames);
    var refused: u32 = 0;
    for (frames.items) |f| if (f.t == 3) {
        try testing.expectEqual(@as(u32, 401), f.sid);
        try testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, f.payload[0..4], .big));
        refused += 1;
    };
    try testing.expectEqual(@as(u32, 1), refused);
    try testing.expectEqual(@as(usize, 200), c.openStreams());
}

test "limits: a request message one byte over 4 MiB is OUT_OF_RANGE with tonic's text" {
    var svc: Svc = .{};
    var c = try h2.Conn.init(testing.allocator, .{ .max_streams = 200, .max_request_bytes = 4 << 20, .window = 64 << 20 }, svc.handler());
    defer c.deinit();
    try openConn(&c);
    c.consumed(c.pending().len);
    const gpa = testing.allocator;
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    // the peer's connection window is 64 KiB by default: raise it with a WINDOW_UPDATE first
    try requestHeaders(&hb, "/t.S/Echo", null);
    try frame(&in, 1, 4, 1, hb.items);
    const n: usize = (4 << 20) + 1;
    const body = try gpa.alloc(u8, 5 + n);
    defer gpa.free(body);
    @memset(body, 'x');
    body[0] = 0;
    std.mem.writeInt(u32, body[1..5], @intCast(n), .big);
    var off: usize = 0;
    while (off < body.len) {
        const k = @min(16384, body.len - off);
        try frame(&in, 0, if (off + k == body.len) 1 else 0, 1, body[off..][0..k]);
        off += k;
    }
    try c.feed(in.items);
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(gpa);
    parseOut(c.pending(), &frames);
    var found = false;
    for (frames.items) |f| if (f.t == 1 and f.sid == 1 and f.flags & 1 != 0) {
        try testing.expect(std.mem.indexOf(u8, f.payload, "\x0bgrpc-status\x0211") != null);
        try testing.expect(std.mem.indexOf(u8, f.payload, "the%20limit%20is:%204194304%20bytes") != null);
        found = true;
    };
    try testing.expect(found);
    try testing.expectEqual(@as(u32, 0), svc.calls.load(.monotonic));
}

/// Client side of one h2c exchange over loopback: sends `requests` (each a path and an optional
/// grpc-timeout) and collects the END_STREAM HEADERS frame of each stream, with its arrival time.
const Client = struct {
    const Done = struct { sid: u32, payload: []u8, ms: u64 };
    fn run(gpa: std.mem.Allocator, port: u16, reqs: []const struct { path: []const u8, timeout: ?[]const u8 }, done: *std.ArrayList(Done)) !void {
        const io = testing.io;
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var in: std.ArrayList(u8) = .empty;
        defer in.deinit(gpa);
        try in.appendSlice(gpa, h2.conn.preface);
        try frame(&in, 4, 0, 0, &.{});
        const t0 = h2.meta.monoNs();
        for (reqs, 0..) |r, i| {
            var hb: std.ArrayList(u8) = .empty;
            defer hb.deinit(gpa);
            try requestHeaders(&hb, r.path, r.timeout);
            const sid: u32 = @intCast(1 + 2 * i);
            try frame(&in, 1, 4, sid, hb.items);
            try frame(&in, 0, 1, sid, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
        }
        try h2.sock.writeAll(stream.socket.handle, in.items);
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(gpa);
        var rbuf: [4096]u8 = undefined;
        var pos: usize = 0;
        while (done.items.len < reqs.len) {
            if (!(try h2.sock.waitReadable(stream.socket.handle, 5000))) return error.Timeout;
            const n = try h2.sock.read(stream.socket.handle, &rbuf);
            if (n == 0) break;
            try got.appendSlice(gpa, rbuf[0..n]);
            while (pos + 9 <= got.items.len) {
                const len = (@as(usize, got.items[pos]) << 16) | (@as(usize, got.items[pos + 1]) << 8) | got.items[pos + 2];
                if (pos + 9 + len > got.items.len) break;
                const ty = got.items[pos + 3];
                const fl = got.items[pos + 4];
                const sid = std.mem.readInt(u32, got.items[pos + 5 ..][0..4], .big) & 0x7fffffff;
                if (ty == 1 and fl & 1 != 0) try done.append(gpa, .{ .sid = sid, .payload = try gpa.dupe(u8, got.items[pos + 9 ..][0..len]), .ms = (h2.meta.monoNs() - t0) / std.time.ns_per_ms });
                pos += 9 + len;
            }
        }
        stream.shutdown(io, .both) catch {};
    }
};

test "limits: server timeout answers DEADLINE_EXCEEDED at the deadline for a call on a worker; a shorter grpc-timeout wins" {
    const gpa = testing.allocator;
    const io = testing.io;
    var svc: Svc = .{ .sleep_ms = 700 };
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    // The 60 s default scaled down to 250 ms; everything else as sui-node.
    const opts: h2.ServerOptions = .{ .h2 = .{ .default_timeout_ns = 250 * std.time.ns_per_ms } };
    const t = try std.Thread.spawn(.{}, struct {
        fn run(i: std.Io, s: *std.Io.net.Server, o: h2.ServerOptions, h: h2.Handler) void {
            const st = s.accept(i) catch return;
            h2.server.serveStreamOpts(testing.allocator, i, st, o, h);
        }
    }.run, .{ io, &server, opts, svc.handler() });
    defer t.join();

    var done: std.ArrayList(Client.Done) = .empty;
    defer {
        for (done.items) |d| gpa.free(d.payload);
        done.deinit(gpa);
    }
    // 1: slow, server default 250 ms; 3: slow with grpc-timeout 100m (100 ms); 5: fast echo.
    try Client.run(gpa, port, &.{ .{ .path = "/t.S/Slow", .timeout = null }, .{ .path = "/t.S/Slow", .timeout = "100m" }, .{ .path = "/t.S/Echo", .timeout = null } }, &done);
    try testing.expectEqual(@as(usize, 3), done.items.len);
    // Bounds that hold on a loaded box: grpc-status 4 can only come from the deadline (the
    // handler's late result is dropped, a finished handler would answer 0), never before it,
    // and the shorter grpc-timeout is answered no later than the server default.
    var ms: [6]u64 = @splat(0);
    for (done.items) |d| switch (d.sid) {
        1 => {
            try testing.expect(std.mem.indexOf(u8, d.payload, "\x0bgrpc-status\x014") != null);
            try testing.expect(std.mem.indexOf(u8, d.payload, "Timeout%20expired") != null);
            try testing.expect(d.ms >= 240);
            ms[1] = d.ms;
        },
        3 => {
            try testing.expect(std.mem.indexOf(u8, d.payload, "\x0bgrpc-status\x014") != null);
            try testing.expect(d.ms >= 90);
            ms[3] = d.ms;
        },
        5 => try testing.expect(std.mem.indexOf(u8, d.payload, "\x0bgrpc-status\x010") != null),
        else => return error.TestUnexpectedResult,
    };
    try testing.expect(ms[3] <= ms[1]);
}

test "observer: path label, status label and end for each request kind" {
    const Rec = struct {
        log: std.ArrayList(u8) = .empty,
        fn b(ctx: *anyopaque, path: []const u8, grpc: bool) u16 {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.log.print(testing.allocator, "begin {s} {};", .{ path, grpc }) catch {};
            return 1;
        }
        fn s(ctx: *anyopaque, _: u16, st: u16, _: u64) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.log.print(testing.allocator, "status {d};", .{st}) catch {};
        }
        fn f(_: *anyopaque, _: u16, _: u64) void {}
        fn e(ctx: *anyopaque, _: u16, counted: bool, _: u64) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.log.print(testing.allocator, "end {};", .{counted}) catch {};
        }
    };
    var rec: Rec = .{};
    defer rec.log.deinit(testing.allocator);
    const o: obs.Observer = .{ .ctx = &rec, .begin = Rec.b, .status = Rec.s, .first_chunk = Rec.f, .end = Rec.e };
    obs.global.store(&o, .release);
    defer obs.global.store(null, .release);
    var svc: Svc = .{};
    var c = try h2.Conn.init(testing.allocator, .{}, svc.handler());
    defer c.deinit();
    try openConn(&c);
    c.consumed(c.pending().len);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(testing.allocator);
    try requestHeaders(&hb, "/t.S/Echo", null);
    try frame(&in, 1, 4, 1, hb.items);
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
    hb.clearRetainingCapacity();
    try requestHeaders(&hb, "/t.S/Missing", null);
    try frame(&in, 1, 4, 3, hb.items);
    try frame(&in, 0, 1, 3, &.{ 0, 0, 0, 0, 0 });
    hb.clearRetainingCapacity();
    try requestHeaders(&hb, "/elsewhere", null);
    try frame(&in, 1, 4 | 1, 5, hb.items);
    // a stream reset before any answer is counted at its end without a status (canceled)
    hb.clearRetainingCapacity();
    try requestHeaders(&hb, "/t.S/Echo", null);
    try frame(&in, 1, 4, 7, hb.items);
    try frame(&in, 3, 0, 7, &.{ 0, 0, 0, 8 });
    try c.feed(in.items);
    try testing.expectEqualStrings("begin /t.S/Echo true;status 0;end true;" ++
        "begin /t.S/Missing true;status 5;end true;" ++
        "begin /elsewhere true;status 1404;end true;" ++
        "begin /t.S/Echo true;end false;", rec.log.items);
}
