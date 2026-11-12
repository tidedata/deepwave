//! Who is calling, for a handler that asks an access gate: the request's `x-api-key` and
//! `x-forwarded-for` and the socket's peer reach `Request` over h2 and over gRPC-web, and a
//! refusal may carry a `retry-after-ms` trailer. No reply changes because of the headers.
const std = @import("std");
const testing = std.testing;
const h2 = @import("root.zig");
const hpack = @import("hpack.zig");

const Seen = struct {
    lock: std.atomic.Value(bool) = .init(false),
    calls: u32 = 0,
    key: [300]u8 = undefined,
    key_len: usize = 0,
    xff: [64]u8 = undefined,
    xff_len: usize = 0,
    peer: [54]u8 = undefined,
    peer_len: usize = 0,

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const s: *Seen = @ptrCast(@alignCast(ctx));
        while (s.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer s.lock.store(false, .release);
        s.calls += 1;
        s.key_len = @min(req.api_key.len, s.key.len);
        @memcpy(s.key[0..s.key_len], req.api_key[0..s.key_len]);
        s.xff_len = @min(req.forwarded_for.len, s.xff.len);
        @memcpy(s.xff[0..s.xff_len], req.forwarded_for[0..s.xff_len]);
        s.peer_len = @min(req.peer.len, s.peer.len);
        @memcpy(s.peer[0..s.peer_len], req.peer[0..s.peer_len]);
        if (std.mem.endsWith(u8, req.path, "/Limited")) {
            rs.setMessage("rate limit exceeded");
            rs.retry_after_ms = 250;
            return .resource_exhausted;
        }
        if (std.mem.endsWith(u8, req.path, "/Denied")) {
            rs.setMessage("key revoked");
            return .permission_denied;
        }
        rs.message(req.body) catch return .internal;
        return .ok;
    }
    fn known(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t.S/");
    }
    fn handler(s: *Seen) h2.Handler {
        return .{ .ctx = s, .call = call, .known = known };
    }
};

fn frame(out: *std.ArrayList(u8), t: u8, flags: u8, sid: u32, payload: []const u8) !void {
    const gpa = testing.allocator;
    try out.appendSlice(gpa, &.{ @intCast(payload.len >> 16), @intCast((payload.len >> 8) & 0xff), @intCast(payload.len & 0xff), t, flags });
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, sid, .big);
    try out.appendSlice(gpa, &s);
    try out.appendSlice(gpa, payload);
}

fn request(out: *std.ArrayList(u8), sid: u32, path: []const u8, key: ?[]const u8, xff: ?[]const u8) !void {
    const gpa = testing.allocator;
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try hb.appendSlice(gpa, &.{ 0x83, 0x86 });
    try hpack.encodeLiteral(&hb, gpa, ":path", path);
    try hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    if (key) |k| try hpack.encodeLiteral(&hb, gpa, "x-api-key", k);
    if (xff) |x| try hpack.encodeLiteral(&hb, gpa, "x-forwarded-for", x);
    try frame(out, 1, 4, sid, hb.items);
    try frame(out, 0, 1, sid, &.{ 0, 0, 0, 0, 1, 'x' });
}

fn open(c: *h2.Conn) !void {
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    try in.appendSlice(testing.allocator, h2.conn.preface);
    try frame(&in, 4, 0, 0, &.{});
    try c.feed(in.items);
    c.consumed(c.pending().len);
}

test "caller: the key and the forwarded-for header reach the handler, a refusal carries retry-after-ms" {
    const gpa = testing.allocator;
    var seen: Seen = .{};
    var c = try h2.Conn.init(gpa, .{}, seen.handler());
    defer c.deinit();
    c.peer.set("198.51.100.7:4444");
    try open(&c);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    try request(&in, 1, "/t.S/Limited", "key-abc", "203.0.113.9, 10.0.0.1");
    try c.feed(in.items);
    try testing.expectEqualStrings("key-abc", seen.key[0..seen.key_len]);
    try testing.expectEqualStrings("203.0.113.9, 10.0.0.1", seen.xff[0..seen.xff_len]);
    try testing.expectEqualStrings("198.51.100.7:4444", seen.peer[0..seen.peer_len]);
    // trailers-only: grpc-status 8, the message, then retry-after-ms, before the common headers
    const out = c.pending();
    const st = std.mem.indexOf(u8, out, "\x0bgrpc-status\x018").?;
    const msg = std.mem.indexOf(u8, out, "rate%20limit%20exceeded").?;
    const ra = std.mem.indexOf(u8, out, "\x0eretry-after-ms\x03250").?;
    try testing.expect(st < msg and msg < ra);
    c.consumed(c.pending().len);
    // a refusal without a retry time has no such trailer
    in.clearRetainingCapacity();
    try request(&in, 3, "/t.S/Denied", "key-abc", null);
    try c.feed(in.items);
    try testing.expect(std.mem.indexOf(u8, c.pending(), "\x0bgrpc-status\x017") != null);
    try testing.expect(std.mem.indexOf(u8, c.pending(), "key%20revoked") != null);
    try testing.expect(std.mem.indexOf(u8, c.pending(), "retry-after-ms") == null);
    try testing.expectEqual(@as(usize, 0), seen.xff_len);
    c.consumed(c.pending().len);
    // an oversized key is cut one byte past the longest any gate takes (so it stays refused),
    // an oversized forwarded-for list is not kept at all
    in.clearRetainingCapacity();
    const long_key: [400]u8 = @splat('k');
    const long_xff: [1100]u8 = @splat('1');
    try request(&in, 5, "/t.S/Echo", &long_key, &long_xff);
    try c.feed(in.items);
    try testing.expectEqual(@as(usize, h2.conn.max_api_key), seen.key_len);
    try testing.expectEqual(@as(usize, 0), seen.xff_len);
    // a stream without the headers starts clean (nothing left over from another stream)
    in.clearRetainingCapacity();
    c.consumed(c.pending().len);
    try request(&in, 7, "/t.S/Echo", null, null);
    try c.feed(in.items);
    try testing.expectEqual(@as(usize, 0), seen.key_len);
    try testing.expectEqual(@as(u32, 4), seen.calls);
}

test "caller: the same request gets the same bytes with and without the caller's headers" {
    const gpa = testing.allocator;
    var replies: [2]std.ArrayList(u8) = .{ .empty, .empty };
    defer for (&replies) |*r| r.deinit(gpa);
    for (&replies, 0..) |*reply, with_headers| {
        var seen: Seen = .{};
        var c = try h2.Conn.init(gpa, .{}, seen.handler());
        defer c.deinit();
        try open(&c);
        var in: std.ArrayList(u8) = .empty;
        defer in.deinit(gpa);
        if (with_headers == 1) try request(&in, 1, "/t.S/Echo", "key-abc", "203.0.113.9") else try request(&in, 1, "/t.S/Echo", null, null);
        try c.feed(in.items);
        try testing.expectEqual(@as(usize, if (with_headers == 1) 7 else 0), seen.key_len);
        // (the date and timing headers aside)
        const out = c.pending();
        const cut = std.mem.indexOf(u8, out, "server-timing") orelse out.len;
        try reply.appendSlice(gpa, out[0..cut]);
    }
    try testing.expectEqualSlices(u8, replies[0].items, replies[1].items);
}

const Client = struct {
    server: std.Io.net.Server,
    t: std.Thread,
    stream: std.Io.net.Stream,
    seen: *Seen,

    fn start(seen: *Seen) !*Client {
        const io = testing.io;
        const c = try testing.allocator.create(Client);
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        c.seen = seen;
        c.server = try addr.listen(io, .{ .reuse_address = true });
        const port = c.server.socket.address.getPort();
        c.t = try std.Thread.spawn(.{}, struct {
            fn run(cl: *Client) void {
                const st = cl.server.accept(testing.io) catch return;
                // unary h2 calls on the worker pool, as the node serves them
                h2.server.serveStreamOpts(testing.allocator, testing.io, st, .{}, cl.seen.handler());
            }
        }.run, .{c});
        var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
        c.stream = try caddr.connect(io, .{ .mode = .stream });
        return c;
    }
    fn exchange(c: *Client, req: []const u8, out: *std.ArrayList(u8), comptime done: fn ([]const u8) bool) !void {
        const io = testing.io;
        var wbuf: [256]u8 = undefined;
        var w = c.stream.writer(io, &wbuf);
        try w.interface.writeAll(req);
        try w.interface.flush();
        out.clearRetainingCapacity();
        var rbuf: [4096]u8 = undefined;
        while (!done(out.items)) {
            var iov = [_][]u8{&rbuf};
            const n = try c.stream.read(io, &iov);
            if (n == 0) break;
            try out.appendSlice(testing.allocator, rbuf[0..n]);
        }
    }
    fn stop(c: *Client) void {
        c.stream.shutdown(testing.io, .both) catch {};
        c.stream.close(testing.io);
        c.t.join();
        c.server.deinit(testing.io);
        testing.allocator.destroy(c);
    }
};

fn h1Done(b: []const u8) bool {
    return std.mem.endsWith(u8, b, "\r\n0\r\n\r\n") or (std.mem.indexOf(u8, b, "content-length: 0\r\n") != null and std.mem.endsWith(u8, b, "\r\n\r\n"));
}

fn h2Done(b: []const u8) bool {
    var pos: usize = 0;
    while (pos + 9 <= b.len) {
        const len = (@as(usize, b[pos]) << 16) | (@as(usize, b[pos + 1]) << 8) | b[pos + 2];
        if (pos + 9 + len > b.len) return false;
        if (b[pos + 3] == 1 and b[pos + 4] & 1 != 0) return true;
        pos += 9 + len;
    }
    return false;
}

test "caller on a socket: the key, the forwarded-for header and the peer, over gRPC-web and over h2c on a worker" {
    const gpa = testing.allocator;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    {
        var seen: Seen = .{};
        const c = try Client.start(&seen);
        defer c.stop();
        try c.exchange("POST /t.S/Limited HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\nX-Api-Key: key-web\r\nx-forwarded-for: 203.0.113.9\r\ncontent-length: 6\r\n\r\n\x00\x00\x00\x00\x01x", &got, h1Done);
        try testing.expectEqualStrings("key-web", seen.key[0..seen.key_len]);
        try testing.expectEqualStrings("203.0.113.9", seen.xff[0..seen.xff_len]);
        try testing.expect(std.mem.startsWith(u8, seen.peer[0..seen.peer_len], "127.0.0.1:"));
        // the same status for gRPC-web, with the retry time among the headers of the reply
        try testing.expect(std.mem.indexOf(u8, got.items, "grpc-status: 8\r\ngrpc-message: rate%20limit%20exceeded\r\nretry-after-ms: 250\r\n") != null);
        try c.exchange("POST /t.S/Denied HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 6\r\n\r\n\x00\x00\x00\x00\x01x", &got, h1Done);
        try testing.expect(std.mem.indexOf(u8, got.items, "grpc-status: 7\r\ngrpc-message: key%20revoked\r\n") != null);
        try testing.expect(std.mem.indexOf(u8, got.items, "retry-after-ms") == null);
        try testing.expectEqual(@as(usize, 0), seen.key_len);
    }
    {
        var seen: Seen = .{};
        const c = try Client.start(&seen);
        defer c.stop();
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        try req.appendSlice(gpa, h2.conn.preface);
        try frame(&req, 4, 0, 0, &.{});
        try request(&req, 1, "/t.S/Limited", "key-h2", "198.51.100.3");
        try c.exchange(req.items, &got, h2Done);
        try testing.expectEqualStrings("key-h2", seen.key[0..seen.key_len]);
        try testing.expectEqualStrings("198.51.100.3", seen.xff[0..seen.xff_len]);
        try testing.expect(std.mem.startsWith(u8, seen.peer[0..seen.peer_len], "127.0.0.1:"));
        try testing.expect(std.mem.indexOf(u8, got.items, "\x0bgrpc-status\x018") != null);
        try testing.expect(std.mem.indexOf(u8, got.items, "\x0eretry-after-ms\x03250") != null);
    }
}
