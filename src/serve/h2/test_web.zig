//! The shared-port runtime over real sockets (testing.allocator: leaks and bad frees fail):
//! gRPC-web binary, text, zstd and gzip, trailers-only errors, GET /health, CORS preflight,
//! deferred server streams over HTTP/1.1 and h2c.
const std = @import("std");
const testing = std.testing;
const h2 = @import("root.zig");
const hpack = @import("hpack.zig");

const Web = struct {
    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        if (std.mem.eql(u8, req.path, "/t.S/Echo")) {
            rs.message(req.body) catch return .internal;
            return .ok;
        }
        if (std.mem.eql(u8, req.path, "/t.S/Fail")) {
            rs.setMessage("bad thing");
            return .not_found;
        }
        if (std.mem.eql(u8, req.path, "/t.S/Stream")) {
            if (!h2.attach(req.stream_id, .{ .ctx = &pump_ctx, .run = run, .wake = wake })) return .unimplemented;
            return .deferred;
        }
        return .unimplemented;
    }
    var pump_ctx: u8 = 0;
    fn run(_: *anyopaque, link: *h2.Link) void {
        var i: u8 = 0;
        while (i < 3) : (i += 1) link.send(&.{ 'm', '0' + i }) catch return;
        link.finish(.ok, "");
    }
    fn wake(_: *anyopaque) void {}
    fn known(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t.S/");
    }
    fn compress(_: *anyopaque, path: []const u8) bool {
        return std.mem.eql(u8, path, "/t.S/Echo");
    }
    fn info(_: *anyopaque, out: *h2.meta.Info) void {
        out.* = .{ .chain_id = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S", .chain = "mainnet", .tip = .{ .epoch = 1305, .height = 342933304, .timestamp_ms = 1794125248393 }, .lowest = 342390380, .server = "zui" };
    }
    var dummy: u8 = 0;
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call, .known = known, .compress = compress, .info = info };
};

/// One connection to a fresh server thread; `exchange` writes `req` and reads until `done(got)`.
const Client = struct {
    server: std.Io.net.Server,
    t: std.Thread,
    stream: std.Io.net.Stream,

    fn start() !*Client {
        const io = testing.io;
        const c = try testing.allocator.create(Client);
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        c.server = try addr.listen(io, .{ .reuse_address = true });
        const port = c.server.socket.address.getPort();
        c.t = try std.Thread.spawn(.{}, struct {
            fn run(s: *std.Io.net.Server) void {
                const st = s.accept(testing.io) catch return;
                h2.serveStream(testing.allocator, testing.io, st, .{}, Web.handler);
            }
        }.run, .{&c.server});
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

fn chunkedDone(b: []const u8) bool {
    return std.mem.endsWith(u8, b, "\r\n0\r\n\r\n") or (std.mem.indexOf(u8, b, "content-length: 0\r\n") != null and std.mem.endsWith(u8, b, "\r\n\r\n")) or
        (std.mem.indexOf(u8, b, "content-length: 2\r\n") != null and std.mem.endsWith(u8, b, "up"));
}

/// The body of a chunked response, chunks joined.
fn unchunk(a: std.mem.Allocator, resp: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var p = (std.mem.indexOf(u8, resp, "\r\n\r\n") orelse return error.Bad) + 4;
    while (true) {
        const e = std.mem.indexOfPos(u8, resp, p, "\r\n") orelse return error.Bad;
        const n = try std.fmt.parseInt(usize, resp[p..e], 16);
        if (n == 0) break;
        try out.appendSlice(a, resp[e + 2 ..][0..n]);
        p = e + 2 + n + 2;
    }
    return out.toOwnedSlice(a);
}

test "gRPC-web over HTTP/1.1 on the shared port" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const c = try Client.start();
    defer c.stop();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);

    // binary unary, keep-alive
    const msg = "\x00\x00\x00\x00\x05hello";
    try c.exchange("POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\nx-grpc-web: 1\r\ncontent-length: 10\r\n\r\n" ++ msg, &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\nx-sui-chain-id: 4btiui"));
    try testing.expect(std.mem.indexOf(u8, got.items, "server: zui\r\nvary: origin, access-control-request-method, access-control-request-headers\r\naccess-control-allow-origin: *\r\naccess-control-expose-headers: *\r\nserver-timing: finish_request;dur=") != null);
    try testing.expect(std.mem.indexOf(u8, got.items, "transfer-encoding: chunked\r\ndate: ") != null);
    try testing.expectEqualSlices(u8, msg ++ "\x80\x00\x00\x00\x0fgrpc-status:0\r\n", try unchunk(a, got.items));

    // zstd response compression (flag 1, grpc-encoding header), decodable by std's decoder
    try c.exchange("POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ngrpc-accept-encoding: zstd\r\ncontent-length: 10\r\n\r\n" ++ msg, &got, chunkedDone);
    try testing.expect(std.mem.indexOf(u8, got.items, "content-type: application/grpc-web+proto\r\ngrpc-encoding: zstd\r\n") != null);
    const zb = try unchunk(a, got.items);
    try testing.expectEqual(@as(u8, 1), zb[0]);
    const zl = std.mem.readInt(u32, zb[1..5], .big);
    var in: std.Io.Reader = .fixed(zb[5..][0..zl]);
    const dbuf = try a.alloc(u8, std.compress.zstd.default_window_len + std.compress.zstd.block_size_max);
    var dz: std.compress.zstd.Decompress = .init(&in, dbuf, .{});
    try testing.expectEqualStrings("hello", try dz.reader.allocRemaining(a, .unlimited));

    // gzip too
    try c.exchange("POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ngrpc-accept-encoding: gzip\r\ncontent-length: 10\r\n\r\n" ++ msg, &got, chunkedDone);
    try testing.expect(std.mem.indexOf(u8, got.items, "grpc-encoding: gzip\r\n") != null);

    // text in, text out (accept decides), each frame base64 in its own chunk
    try c.exchange("POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web-text\r\naccept: application/grpc-web-text\r\ncontent-length: 16\r\n\r\nAAAAAAVoZWxsbw==", &got, chunkedDone);
    try testing.expect(std.mem.indexOf(u8, got.items, "content-type: application/grpc-web-text+proto\r\n") != null);
    try testing.expectEqualStrings("AAAAAAVoZWxsbw==gAAAAA9ncnBjLXN0YXR1czowDQo=", try unchunk(a, got.items));

    // error with no message: trailers-only, status first in the headers
    try c.exchange("POST /t.S/Fail HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00", &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-status: 5\r\ngrpc-message: bad%20thing\r\nx-sui-chain-id: "));
    try testing.expect(std.mem.indexOf(u8, got.items, "content-length: 0\r\ndate: ") != null);

    // unknown method of a known service; unknown service
    try c.exchange("POST /t.S/Nope HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00", &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\ngrpc-status: 12\r\ncontent-type: application/grpc-web+proto\r\n"));
    try c.exchange("POST /foo.Bar/Baz HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00", &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 404 Not Found\r\nx-sui-chain-id: "));

    // compressed request: UNIMPLEMENTED with grpc-accept-encoding: identity
    try c.exchange("POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ngrpc-encoding: gzip\r\ncontent-length: 5\r\n\r\n\x01\x00\x00\x00\x00", &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-accept-encoding: identity\r\ngrpc-status: 12\r\ngrpc-message: Content%20is%20compressed%20with%20%60gzip%60%20which%20isn't%20supported\r\n"));

    // health and CORS preflight
    try c.exchange("GET /health HTTP/1.1\r\nhost: x\r\n\r\n", &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\nx-sui-chain-id: "));
    try testing.expect(std.mem.endsWith(u8, got.items, "\r\n\r\nup"));
    try c.exchange("OPTIONS /t.S/Echo HTTP/1.1\r\nhost: x\r\norigin: https://a.b\r\naccess-control-request-method: POST\r\n\r\n", &got, chunkedDone);
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\nvary: origin, access-control-request-method, access-control-request-headers\r\naccess-control-allow-methods: GET,POST\r\naccess-control-allow-headers: *\r\naccess-control-allow-origin: *\r\nserver-timing: "));

    // server stream: headers, one chunk per message, trailers
    try c.exchange("POST /t.S/Stream HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00", &got, chunkedDone);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x02m0\x00\x00\x00\x00\x02m1\x00\x00\x00\x00\x02m2\x80\x00\x00\x00\x0fgrpc-status:0\r\n", try unchunk(a, got.items));
}

fn h2Done(b: []const u8) bool {
    // the stream's END_STREAM HEADERS frame (type 1, flag 1) has arrived
    var pos: usize = 0;
    while (pos + 9 <= b.len) {
        const len = (@as(usize, b[pos]) << 16) | (@as(usize, b[pos + 1]) << 8) | b[pos + 2];
        if (pos + 9 + len > b.len) return false;
        if (b[pos + 3] == 1 and b[pos + 4] & 1 != 0) return true;
        pos += 9 + len;
    }
    return false;
}

test "h2c on the shared port: deferred server stream on a pump thread" {
    const c = try Client.start();
    defer c.stop();
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(testing.allocator);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(testing.allocator);
    const gpa = testing.allocator;
    try req.appendSlice(gpa, h2.conn.preface);
    try req.appendSlice(gpa, &.{ 0, 0, 0, 4, 0, 0, 0, 0, 0 });
    try hb.appendSlice(gpa, &.{ 0x83, 0x86 });
    try hpack.encodeLiteral(&hb, gpa, ":path", "/t.S/Stream");
    try hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    try req.appendSlice(gpa, &.{ 0, 0, @intCast(hb.items.len), 1, 4, 0, 0, 0, 1 });
    try req.appendSlice(gpa, hb.items);
    try req.appendSlice(gpa, &.{ 0, 0, 5, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0 });
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    try c.exchange(req.items, &got, h2Done);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    var pos: usize = 0;
    while (pos + 9 <= got.items.len) {
        const len = (@as(usize, got.items[pos]) << 16) | (@as(usize, got.items[pos + 1]) << 8) | got.items[pos + 2];
        if (got.items[pos + 3] == 0) try data.appendSlice(gpa, got.items[pos + 9 ..][0..len]);
        pos += 9 + len;
    }
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x02m0\x00\x00\x00\x00\x02m1\x00\x00\x00\x00\x02m2", data.items);
}

test "chunked request bodies: decoded, and bounded (size line, trailers, total)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    const head = "POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ntransfer-encoding: chunked\r\n\r\n";
    {
        // a message split over 1-byte and larger chunks, an extension and a trailer
        const c = try Client.start();
        defer c.stop();
        try c.exchange(head ++ "1;ext=1\r\n\x00\r\n4\r\n\x00\x00\x00\x05\r\n5\r\nhello\r\n0\r\nx-t: 1\r\n\r\n", &got, chunkedDone);
        try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\n"));
        try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x05hello\x80\x00\x00\x00\x0fgrpc-status:0\r\n", try unchunk(a, got.items));
    }
    {
        // a chunk-size line that never ends (hex digits past 4 KiB): 400 and close
        const c = try Client.start();
        defer c.stop();
        const long = try a.alloc(u8, 6000);
        @memset(long, '0');
        const req = try std.mem.concat(a, u8, &.{ head, long });
        try c.exchange(req, &got, closedOr400);
        try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 400 Bad Request\r\n"));
    }
    {
        // endless trailer lines: 400 once they pass max_head
        const c = try Client.start();
        defer c.stop();
        var req: std.ArrayList(u8) = .empty;
        try req.appendSlice(a, head ++ "0\r\n");
        var i: usize = 0;
        while (i < 8000) : (i += 1) try req.appendSlice(a, "x-trailer: aaaaaaaa\r\n");
        try c.exchange(req.items, &got, closedOr400);
        try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 400 Bad Request\r\n"));
    }
    {
        // a chunk size near 2^64 is refused without overflow
        const c = try Client.start();
        defer c.stop();
        try c.exchange(head ++ "fffffffffffffff0\r\n", &got, closedOr400);
        try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 413 Payload Too Large\r\n"));
    }
}

fn closedOr400(b: []const u8) bool {
    return std.mem.endsWith(u8, b, "\r\n\r\n") and std.mem.indexOf(u8, b, "connection: close") != null;
}
