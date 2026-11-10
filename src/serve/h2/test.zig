//! In-process HTTP/2 + gRPC exchanges with hand-built frames.
const std = @import("std");
const testing = std.testing;
const h2 = @import("root.zig");
const hpack = @import("hpack.zig");

fn frame(out: *std.ArrayList(u8), t: u8, flags: u8, sid: u32, payload: []const u8) !void {
    const gpa = testing.allocator;
    try out.appendSlice(gpa, &.{ @intCast(payload.len >> 16), @intCast((payload.len >> 8) & 0xff), @intCast(payload.len & 0xff), t, flags });
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, sid, .big);
    try out.appendSlice(gpa, &s);
    try out.appendSlice(gpa, payload);
}

fn requestHeaders(out: *std.ArrayList(u8), path: []const u8) !void {
    const gpa = testing.allocator;
    try out.appendSlice(gpa, &.{ 0x83, 0x86 }); // :method POST, :scheme http
    try hpack.encodeLiteral(out, gpa, ":path", path);
    try hpack.encodeLiteral(out, gpa, ":authority", "localhost");
    try hpack.encodeLiteral(out, gpa, "content-type", "application/grpc");
    try hpack.encodeLiteral(out, gpa, "te", "trailers");
}

const Echo = struct {
    big: []const u8 = "",
    fn method(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t/");
    }
    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const self: *Echo = @ptrCast(@alignCast(ctx));
        if (std.mem.eql(u8, req.path, "/t/Echo")) {
            rs.message(req.body) catch return .internal;
            return .ok;
        }
        if (std.mem.eql(u8, req.path, "/t/Big")) {
            rs.message(self.big) catch return .internal;
            return .ok;
        }
        if (std.mem.eql(u8, req.path, "/t/Fail")) {
            rs.setMessage("bad thing: 100%");
            return .invalid_argument;
        }
        return .unimplemented;
    }
};

/// Parsed frames of the server output.
const Out = struct { t: u8, flags: u8, sid: u32, payload: []const u8 };

fn parseOut(buf: []const u8, list: *std.ArrayList(Out)) !void {
    var pos: usize = 0;
    while (pos + 9 <= buf.len) {
        const len = (@as(usize, buf[pos]) << 16) | (@as(usize, buf[pos + 1]) << 8) | buf[pos + 2];
        try list.append(testing.allocator, .{ .t = buf[pos + 3], .flags = buf[pos + 4], .sid = std.mem.readInt(u32, buf[pos + 5 ..][0..4], .big) & 0x7fffffff, .payload = buf[pos + 9 ..][0..len] });
        pos += 9 + len;
    }
    try testing.expectEqual(buf.len, pos);
}

fn open(c: *h2.Conn) !void {
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    try in.appendSlice(testing.allocator, h2.conn.preface);
    try frame(&in, 4, 0, 0, &.{});
    try c.feed(in.items);
    c.consumed(c.pending().len);
}

test "unary echo, trailers-only error, unimplemented" {
    var echo: Echo = .{};
    var c = try h2.Conn.init(testing.allocator, .{}, .{ .ctx = &echo, .call = Echo.call, .method = Echo.method });
    defer c.deinit();
    try open(&c);

    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(testing.allocator);
    try requestHeaders(&hb, "/t/Echo");
    try frame(&in, 1, 4, 1, hb.items); // HEADERS END_HEADERS
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 3, 'a', 'b', 'c' }); // DATA END_STREAM
    try c.feed(in.items);
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(testing.allocator);
    try parseOut(c.pending(), &frames);
    // WINDOW_UPDATEs for the data, HEADERS, DATA, trailers
    var got_data = false;
    var got_trailers = false;
    for (frames.items) |f| {
        if (f.t == 0 and f.sid == 1) {
            try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 3, 'a', 'b', 'c' }, f.payload);
            got_data = true;
        }
        if (f.t == 1 and f.flags & 1 != 0) {
            try testing.expect(std.mem.indexOf(u8, f.payload, "grpc-status") != null);
            got_trailers = true;
        }
    }
    try testing.expect(got_data and got_trailers);
    c.consumed(c.pending().len);

    // error before any message: one HEADERS frame with END_STREAM carrying everything
    in.clearRetainingCapacity();
    hb.clearRetainingCapacity();
    try requestHeaders(&hb, "/t/Fail");
    try frame(&in, 1, 4, 3, hb.items);
    try frame(&in, 0, 1, 3, &.{ 0, 0, 0, 0, 0 }); // one empty message
    try c.feed(in.items);
    frames.clearRetainingCapacity();
    try parseOut(c.pending(), &frames);
    // a connection WINDOW_UPDATE for the DATA, then one HEADERS frame with END_STREAM
    try testing.expectEqual(@as(usize, 2), frames.items.len);
    try testing.expectEqual(@as(u8, 8), frames.items[0].t);
    try testing.expectEqual(@as(u8, 1), frames.items[1].t);
    try testing.expect(std.mem.indexOf(u8, frames.items[1].payload, "bad%20thing:%20100%25") != null);
    c.consumed(c.pending().len);

    in.clearRetainingCapacity();
    hb.clearRetainingCapacity();
    // no message at all (END_STREAM on HEADERS): tonic's map_request_unary answers
    // INTERNAL "Missing request message." (vectors/h2-empty-body.hdr)
    in.clearRetainingCapacity();
    hb.clearRetainingCapacity();
    try requestHeaders(&hb, "/t/Echo");
    try frame(&in, 1, 4 | 1, 7, hb.items);
    try c.feed(in.items);
    frames.clearRetainingCapacity();
    try parseOut(c.pending(), &frames);
    try testing.expectEqual(@as(usize, 1), frames.items.len);
    try testing.expect(std.mem.indexOf(u8, frames.items[0].payload, "\x0bgrpc-status\x0213") != null);
    try testing.expect(std.mem.indexOf(u8, frames.items[0].payload, "Missing%20request%20message.") != null);
    c.consumed(c.pending().len);

    in.clearRetainingCapacity();
    hb.clearRetainingCapacity();
    try requestHeaders(&hb, "/nope");
    try frame(&in, 1, 4 | 1, 9, hb.items);
    try c.feed(in.items);
    frames.clearRetainingCapacity();
    try parseOut(c.pending(), &frames);
    try testing.expect(std.mem.indexOf(u8, frames.items[0].payload, "\x0b" ++ "grpc-status\x0212") != null);
}

test "large response waits for WINDOW_UPDATE and splits at the frame size" {
    const big = try testing.allocator.alloc(u8, 200_000);
    defer testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i);
    var echo: Echo = .{ .big = big };
    var c = try h2.Conn.init(testing.allocator, .{}, .{ .ctx = &echo, .call = Echo.call });
    defer c.deinit();
    try open(&c);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(testing.allocator);
    try requestHeaders(&hb, "/t/Big");
    try frame(&in, 1, 4, 1, hb.items);
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 0 });
    try c.feed(in.items);
    var total: usize = 0;
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(testing.allocator);
    try parseOut(c.pending(), &frames);
    for (frames.items) |f| if (f.t == 0) {
        try testing.expect(f.payload.len <= 16384);
        total += f.payload.len;
    };
    try testing.expectEqual(@as(usize, 65535), total); // default windows
    c.consumed(c.pending().len);
    // open both windows
    in.clearRetainingCapacity();
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, &inc, 1 << 20, .big);
    try frame(&in, 8, 0, 0, &inc);
    try frame(&in, 8, 0, 1, &inc);
    try c.feed(in.items);
    frames.clearRetainingCapacity();
    try parseOut(c.pending(), &frames);
    var last_end = false;
    for (frames.items) |f| {
        if (f.t == 0) total += f.payload.len;
        if (f.t == 1 and f.flags & 1 != 0) last_end = true;
    }
    try testing.expectEqual(@as(usize, 200_005), total);
    try testing.expect(last_end);
}

test "random bytes never crash or leak" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const r = prng.random();
    var echo: Echo = .{};
    for (0..200) |_| {
        var c = try h2.Conn.init(testing.allocator, .{}, .{ .ctx = &echo, .call = Echo.call });
        defer c.deinit();
        var buf: [300]u8 = undefined;
        if (r.boolean()) {
            @memcpy(buf[0..h2.conn.preface.len], h2.conn.preface);
            r.bytes(buf[h2.conn.preface.len..]);
        } else r.bytes(&buf);
        var pos: usize = 0;
        while (pos < buf.len) {
            const n = @min(buf.len - pos, r.intRangeAtMost(usize, 1, 40));
            c.feed(buf[pos..][0..n]) catch break;
            pos += n;
        }
    }
}

test "real sockets: serveStream answers a framed client on loopback" {
    const io = testing.io;
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    var echo: Echo = .{};
    const t = try std.Thread.spawn(.{}, struct {
        fn run(i: std.Io, s: *std.Io.net.Server, e: *Echo) void {
            const st = s.accept(i) catch return;
            h2.serveStream(testing.allocator, i, st, .{}, .{ .ctx = e, .call = Echo.call });
        }
    }.run, .{ io, &server, &echo });
    defer t.join();

    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const stream = try caddr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [512]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(testing.allocator);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(testing.allocator);
    try in.appendSlice(testing.allocator, h2.conn.preface);
    try frame(&in, 4, 0, 0, &.{});
    try requestHeaders(&hb, "/t/Echo");
    try frame(&in, 1, 4, 1, hb.items);
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
    try w.interface.writeAll(in.items);
    try w.interface.flush();
    // read until the stream's trailers (END_STREAM headers frame) arrive
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var rbuf: [4096]u8 = undefined;
    var saw_data = false;
    var done = false;
    while (!done) {
        var iov = [_][]u8{&rbuf};
        const n = try stream.read(io, &iov);
        if (n == 0) break;
        try got.appendSlice(testing.allocator, rbuf[0..n]);
        var frames: std.ArrayList(Out) = .empty;
        defer frames.deinit(testing.allocator);
        var pos: usize = 0;
        while (pos + 9 <= got.items.len) {
            const len = (@as(usize, got.items[pos]) << 16) | (@as(usize, got.items[pos + 1]) << 8) | got.items[pos + 2];
            if (pos + 9 + len > got.items.len) break;
            const ty = got.items[pos + 3];
            const fl = got.items[pos + 4];
            if (ty == 0) saw_data = std.mem.eql(u8, got.items[pos + 9 ..][0..len], &.{ 0, 0, 0, 0, 2, 'h', 'i' });
            if (ty == 1 and fl & 1 != 0) done = true;
            pos += 9 + len;
        }
    }
    try testing.expect(saw_data and done);
    stream.shutdown(io, .both) catch {};
}

// Manual interop: ZUI_H2_INTEROP_PORT=18080 ./zig build test -Dlane=serve, then in another shell
//   printf '\0\0\0\0\3abc' | curl --http2-prior-knowledge -sv -H 'content-type: application/grpc' -H 'te: trailers' --data-binary @- http://127.0.0.1:18080/t/Echo
// (see src/serve/h2/interop.sh). Serves exactly one connection.
test "interop server (manual)" {
    const port_s = std.c.getenv("ZUI_H2_INTEROP_PORT") orelse return error.SkipZigTest;
    const port = try std.fmt.parseInt(u16, std.mem.span(port_s), 10);
    const io = testing.io;
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var echo: Echo = .{};
    const st = try server.accept(io);
    h2.serveStream(testing.allocator, io, st, .{}, .{ .ctx = &echo, .call = Echo.call });
}

test "refused stream still updates the HPACK table; peer HEADER_TABLE_SIZE does not raise ours" {
    var echo: Echo = .{};
    var c = try h2.Conn.init(testing.allocator, .{ .max_streams = 1 }, .{ .ctx = &echo, .call = Echo.call });
    defer c.deinit();
    try open(&c);
    const gpa = testing.allocator;
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);

    // SETTINGS HEADER_TABLE_SIZE = 1 GiB from the peer must not lift our decoder's 4096 limit.
    try frame(&in, 4, 0, 0, &.{ 0, 1, 0x40, 0, 0, 0 });
    // Stream 1 stays open (no END_STREAM), so stream 3 is refused at max_streams = 1.
    try requestHeaders(&hb, "/t/Echo");
    try frame(&in, 1, 4, 1, hb.items);
    // Stream 3: refused, but its block inserts ":path: /t/Echo" into the dynamic table (index 62).
    hb.clearRetainingCapacity();
    try hb.appendSlice(gpa, &.{ 0x83, 0x86, 0x44, 7 });
    try hb.appendSlice(gpa, "/t/Echo");
    try frame(&in, 1, 4 | 1, 3, hb.items);
    // Finish stream 1, then stream 5 names its path only through dynamic index 62 (0xbe).
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 1, 'x' });
    try c.feed(in.items);
    c.consumed(c.pending().len);
    in.clearRetainingCapacity();
    try frame(&in, 1, 4, 5, &.{ 0x83, 0x86, 0xbe });
    try frame(&in, 0, 1, 5, &.{ 0, 0, 0, 0, 2, 'o', 'k' });
    try c.feed(in.items);
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(gpa);
    try parseOut(c.pending(), &frames);
    var echoed = false;
    for (frames.items) |f| {
        try testing.expect(f.t != 7); // no GOAWAY
        if (f.t == 0 and f.sid == 5) {
            try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 2, 'o', 'k' }, f.payload);
            echoed = true;
        }
    }
    try testing.expect(echoed);
    c.consumed(c.pending().len);

    // A dynamic table size update above 4096 is now a COMPRESSION_ERROR (GOAWAY).
    in.clearRetainingCapacity();
    try frame(&in, 1, 4 | 1, 7, &.{ 0x3f, 0xe2, 0x1f, 0x83 }); // size update to 4097
    c.feed(in.items) catch {};
    frames.clearRetainingCapacity();
    try parseOut(c.pending(), &frames);
    var goaway = false;
    for (frames.items) |f| if (f.t == 7) {
        goaway = true;
    };
    try testing.expect(goaway);
}

test "structured frame fuzz: random frame sequences never crash, leak, or grow without bound" {
    const gpa = testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x7a6f6e65);
    const rnd = prng.random();
    var echo: Echo = .{};
    for (0..400) |_| {
        var c = try h2.Conn.init(gpa, .{ .max_streams = 4 }, .{ .ctx = &echo, .call = Echo.call });
        defer c.deinit();
        try open(&c);
        var in: std.ArrayList(u8) = .empty;
        defer in.deinit(gpa);
        for (0..rnd.intRangeAtMost(usize, 1, 24)) |_| {
            const sid: u32 = switch (rnd.intRangeAtMost(u8, 0, 4)) {
                0 => 0,
                1 => 1,
                2 => 3,
                3 => rnd.int(u32) & 0x7fffffff,
                else => 2 * rnd.intRangeAtMost(u32, 0, 6) + 1,
            };
            var payload: [64]u8 = undefined;
            const n = rnd.intRangeAtMost(usize, 0, payload.len);
            rnd.bytes(payload[0..n]);
            switch (rnd.intRangeAtMost(u8, 0, 6)) {
                0 => { // HEADERS with a valid request block, random flags
                    var hb: std.ArrayList(u8) = .empty;
                    defer hb.deinit(gpa);
                    try requestHeaders(&hb, "/t/Echo");
                    try frame(&in, 1, rnd.int(u8) & 0x2d, sid, hb.items);
                },
                1 => try frame(&in, 9, rnd.int(u8), sid, payload[0..n]), // CONTINUATION, often orphaned
                2 => try frame(&in, 8, 0, sid, &.{ 0x7f, 0xff, 0xff, 0xff }), // WINDOW_UPDATE to the maximum
                3 => try frame(&in, 4, 0, 0, payload[0 .. n / 6 * 6]), // SETTINGS with random ids/values
                4 => try frame(&in, 0, rnd.int(u8) & 9, sid, payload[0..n]), // DATA
                5 => try frame(&in, 3, 0, sid, payload[0..@min(n, 4)]), // RST_STREAM
                else => try frame(&in, rnd.int(u8), rnd.int(u8), sid, payload[0..n]),
            }
        }
        c.feed(in.items) catch {};
        // the output queue stays bounded by a small multiple of the input
        try testing.expect(c.pending().len < 1 << 20);
    }
}
