//! Transport limits at sui-node 1.83.1's values (docs/FULLNODE-PARITY.md task 9) and the request
//! observer (obs.zig): behaviour at each limit.
//!   - 200 concurrent streams: advertised in SETTINGS, stream 201 refused (RST_STREAM REFUSED_STREAM);
//!   - 4 MiB request message: one byte over answers trailers-only OUT_OF_RANGE with tonic 0.14.6's
//!     text (`decode.rs`), as soon as the body passes the limit;
//!   - 60 s server timeout (or a shorter grpc-timeout): a unary call still running on a worker is
//!     answered DEADLINE_EXCEEDED "Timeout expired" at the deadline, trailers-only, as sui-http's
//!     GrpcTimeout; the connection stays usable and the late result is dropped. A call whose
//!     deadline passes while it waits for a worker, or whose stream is gone, is not run at all.
//!   - send bound (`max_out_bytes`, deepwave's own): output queued for the socket stops at the bound,
//!     the stream keeps the rest and stays open, and a peer that stops reading is not read from
//!     until it takes what it is owed;
//!   - rapid reset: the h2 crate's default (20 streams opened and reset before the server took
//!     them up) and deepwave's bound on cancelled calls still on workers both end the connection with
//!     GOAWAY(ENHANCE_YOUR_CALM) `too_many_resets`; a client that cancels calls is not affected;
//!   - no write waits for the peer under the connection lock: a peer that reads nothing holds no
//!     worker (they queue behind that lock), its replies wait in the connection.
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
    /// The reply of `/t.S/Big`.
    big: []const u8 = "",
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
        if (std.mem.eql(u8, req.path, "/t.S/Big")) {
            rs.message(self.big) catch return .internal;
            return .ok;
        }
        if (std.mem.eql(u8, req.path, "/t.S/Owned")) {
            // a status message: the response owns a copy until `release`
            rs.setMessage(&FreeSpy.needle);
            return .not_found;
        }
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
    const Req = struct { path: []const u8, timeout: ?[]const u8 };
    fn run(gpa: std.mem.Allocator, port: u16, reqs: []const Req, done: *std.ArrayList(Done)) !void {
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

/// SETTINGS_INITIAL_WINDOW_SIZE and a connection WINDOW_UPDATE that open both send windows to
/// 2^31-1: a peer that lets the server send everything at once.
fn hugeWindows(out: *std.ArrayList(u8)) !void {
    try frame(out, 4, 0, 0, &.{ 0, 4, 0x7f, 0xff, 0xff, 0xff });
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, &inc, 0x7fffffff - 65535, .big);
    try frame(out, 8, 0, 0, &inc);
}

/// Reads h2 frames from `fd` until `want` streams ended with trailers; every one must carry
/// grpc-status 0. Returns how many ended and the DATA bytes received.
fn readReplies(fd: std.c.fd_t, want: u32) !struct { ok: u32, data_bytes: u64 } {
    const gpa = testing.allocator;
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    const rbuf = try gpa.alloc(u8, 256 << 10);
    defer gpa.free(rbuf);
    var ok: u32 = 0;
    var data_bytes: u64 = 0;
    while (ok < want) {
        if (!(try h2.sock.waitReadable(fd, 10_000))) return error.Timeout;
        const n = try h2.sock.read(fd, rbuf);
        if (n == 0) break;
        try got.appendSlice(gpa, rbuf[0..n]);
        var pos: usize = 0;
        while (pos + 9 <= got.items.len) {
            const len = (@as(usize, got.items[pos]) << 16) | (@as(usize, got.items[pos + 1]) << 8) | got.items[pos + 2];
            if (pos + 9 + len > got.items.len) break;
            const ty = got.items[pos + 3];
            const fl = got.items[pos + 4];
            if (ty == 0) data_bytes += len;
            if (ty == 1 and fl & 1 != 0) {
                try testing.expect(std.mem.indexOf(u8, got.items[pos + 9 ..][0..len], "\x0bgrpc-status\x010") != null);
                ok += 1;
            }
            pos += 9 + len;
        }
        const rest = got.items.len - pos;
        std.mem.copyForwards(u8, got.items[0..rest], got.items[pos..]);
        got.shrinkRetainingCapacity(rest);
    }
    return .{ .ok = ok, .data_bytes = data_bytes };
}

test "limits: queued output stops at the send bound; the stream stays open and the rest follows as the socket drains" {
    const gpa = testing.allocator;
    const big = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i *% 31 +% (i >> 8));
    var svc: Svc = .{ .big = big };
    const bound: usize = 64 << 10;
    var c = try h2.Conn.init(gpa, .{ .max_out_bytes = bound }, svc.handler());
    defer c.deinit();
    try openConn(&c);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    try hugeWindows(&in);
    try c.feed(in.items);
    c.consumed(c.pending().len);
    in.clearRetainingCapacity();
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try requestHeaders(&hb, "/t.S/Big", null);
    try frame(&in, 1, 4, 1, hb.items);
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 0 });
    try c.feed(in.items);
    // One frame may pass the bound, plus the response HEADERS and the two WINDOW_UPDATEs.
    const slack = 16384 + 9 + 1024;
    try testing.expect(c.pending().len >= bound);
    try testing.expect(c.pending().len <= bound + slack);
    try testing.expect(c.outFull());
    try testing.expectEqual(@as(usize, 1), c.openStreams()); // not dropped: its bytes are still its own
    // The socket takes 10,000 bytes at a time.
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    var rounds: usize = 0;
    while (c.pending().len > 0) : (rounds += 1) {
        const p = c.pending();
        const k = @min(p.len, 10_000);
        try got.appendSlice(gpa, p[0..k]);
        c.consumed(k);
        try testing.expect(c.pending().len <= bound + slack);
        // the sent prefix does not pile up in front of the backlog
        try testing.expect(c.out.items.len <= 4 * bound);
    }
    try testing.expect(rounds > 100);
    try testing.expect(c.out_refilled);
    try testing.expectEqual(@as(usize, 0), c.openStreams());
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(gpa);
    parseOut(got.items, &frames);
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var ended = false;
    for (frames.items) |f| {
        if (f.sid != 1) continue;
        if (f.t == 0) {
            try testing.expect(!ended);
            // every DATA frame but the last is full: the bound does not change frame sizes
            if (body.items.len + f.payload.len < 5 + big.len) try testing.expectEqual(@as(usize, 16384), f.payload.len);
            try body.appendSlice(gpa, f.payload);
        } else if (f.t == 1 and f.flags & 1 != 0) {
            try testing.expect(std.mem.indexOf(u8, f.payload, "\x0bgrpc-status\x010") != null);
            ended = true;
        }
    }
    try testing.expect(ended);
    try testing.expectEqual(5 + big.len, body.items.len);
    try testing.expectEqual(@as(u32, @intCast(big.len)), std.mem.readInt(u32, body.items[1..5], .big));
    try testing.expectEqualSlices(u8, big, body.items[5..]);
}

test "limits: a peer that stops reading is not read from; its calls go on when it reads again" {
    const gpa = testing.allocator;
    const io = testing.io;
    const big = try gpa.alloc(u8, 256 << 10);
    defer gpa.free(big);
    @memset(big, 'z');
    var svc: Svc = .{ .big = big };
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    // Handlers run on the connection thread, so nothing but the bound holds the reads back.
    const opts: h2.ServerOptions = .{ .inline_unary = true, .h2 = .{ .max_out_bytes = 64 << 10 } };
    const t = try std.Thread.spawn(.{}, struct {
        fn run(i: std.Io, s: *std.Io.net.Server, o: h2.ServerOptions, h: h2.Handler) void {
            const st = s.accept(i) catch return;
            h2.server.serveStreamOpts(testing.allocator, i, st, o, h);
        }
    }.run, .{ io, &server, opts, svc.handler() });
    defer t.join();

    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const stream = try caddr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const fd = stream.socket.handle;
    // 150 calls, 256 KiB each way back (38 MiB), sent at once by a peer with 2^31-1 windows that
    // reads nothing. Each request carries 8 KiB, so the server needs many reads to see them all.
    const calls: u32 = 150;
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    try in.appendSlice(gpa, h2.conn.preface);
    try frame(&in, 4, 0, 0, &.{});
    try hugeWindows(&in);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try requestHeaders(&hb, "/t.S/Big", null);
    var req_body: [5 + 8187]u8 = @splat(0);
    std.mem.writeInt(u32, req_body[1..5], 8187, .big);
    for (0..calls) |i| {
        const sid: u32 = @intCast(1 + 2 * i);
        try frame(&in, 1, 4, sid, hb.items);
        try frame(&in, 0, 1, sid, &req_body);
    }
    // The requests are written on a thread: the write blocks while the server does not read.
    const wt = try std.Thread.spawn(.{}, struct {
        fn run(f: std.c.fd_t, bytes: []const u8) void {
            h2.sock.rawWriteAll(f, bytes) catch {};
        }
    }.run, .{ fd, in.items });
    defer wt.join();

    // The handler count stops moving well short of 150: the server filled the socket, then its
    // send bound, and stopped reading. Without the bound it ran all 150 and queued 38 MiB.
    var last: u32 = 0;
    var still_ms: u32 = 0;
    while (still_ms < 500) {
        h2.sock.sleepMs(10);
        const now = svc.calls.load(.monotonic);
        if (now != last or now == 0) {
            last = now;
            still_ms = 0;
        } else still_ms += 10;
    }
    try testing.expect(last < 100);

    // The peer reads again: every call is answered in full.
    const got = try readReplies(fd, calls);
    const ok = got.ok;
    const data_bytes = got.data_bytes;
    try testing.expectEqual(calls, ok);
    try testing.expectEqual(@as(u64, calls) * (5 + big.len), data_bytes);
    try testing.expectEqual(calls, svc.calls.load(.monotonic));
    stream.shutdown(io, .both) catch {};
}

test "limits: a peer that reads nothing holds no worker; its replies wait in the connection" {
    const gpa = testing.allocator;
    const io = testing.io;
    const big = try gpa.alloc(u8, 256 << 10);
    defer gpa.free(big);
    @memset(big, 'w');
    var svc: Svc = .{ .big = big, .sleep_ms = 1200 };
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    // The runtime as the node runs it: unary calls on the worker pool.
    const t = try std.Thread.spawn(.{}, struct {
        fn run(i: std.Io, s: *std.Io.net.Server, h: h2.Handler) void {
            const st = s.accept(i) catch return;
            h2.server.serveStreamOpts(testing.allocator, i, st, .{}, h);
        }
    }.run, .{ io, &server, svc.handler() });
    defer t.join();

    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const stream = try caddr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const fd = stream.socket.handle;
    // 40 calls answered with 256 KiB each (10 MiB, far more than the socket holds) and one that
    // runs for 1.2 s, from a peer with 2^31-1 windows that reads nothing. While the slow call
    // runs the connection thread goes through its timeout check on every turn, which used to
    // write the backlog with a blocking write under the connection lock: the workers finishing
    // the other calls, and then the slow one, sat behind that lock for as long as the peer read
    // nothing (5 s send timeouts, 24 of them).
    const calls: u32 = 41;
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    try in.appendSlice(gpa, h2.conn.preface);
    try frame(&in, 4, 0, 0, &.{});
    try hugeWindows(&in);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    for (0..calls) |i| {
        hb.clearRetainingCapacity();
        try requestHeaders(&hb, if (i == 0) "/t.S/Slow" else "/t.S/Big", null);
        const sid: u32 = @intCast(1 + 2 * i);
        try frame(&in, 1, 4, sid, hb.items);
        try frame(&in, 0, 1, sid, &.{ 0, 0, 0, 0, 0 });
    }
    try h2.sock.rawWriteAll(fd, in.items);
    const t0 = h2.meta.monoNs();
    // Every handler returns and every worker is free again soon after the slow call ends.
    while (h2.meta.monoNs() - t0 < 4000 * std.time.ns_per_ms) {
        if (svc.calls.load(.monotonic) == calls and h2.server.stats.jobs.load(.acquire) == 0) break;
        h2.sock.sleepMs(10);
    }
    try testing.expectEqual(calls, svc.calls.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), h2.server.stats.jobs.load(.acquire));
    // The peer reads: every reply is whole.
    const got = try readReplies(fd, calls);
    try testing.expectEqual(calls, got.ok);
    try testing.expectEqual(@as(u64, calls - 1) * (5 + big.len) + 5, got.data_bytes);
    stream.shutdown(io, .both) catch {};
}

/// The GOAWAY in `buf`, if any: its error code and debug data.
fn goawayOf(buf: []const u8) ?struct { code: u32, debug: []const u8 } {
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(testing.allocator);
    parseOut(buf, &frames);
    for (frames.items) |f| if (f.t == 7) return .{ .code = std.mem.readInt(u32, f.payload[4..8], .big), .debug = f.payload[8..] };
    return null;
}

test "rapid reset: 20 streams opened and reset in one pass are served, one more is GOAWAY ENHANCE_YOUR_CALM (h2's default)" {
    const gpa = testing.allocator;
    var svc: Svc = .{};
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try requestHeaders(&hb, "/t.S/Echo", null);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    {
        var c = try h2.Conn.init(gpa, .{}, svc.handler());
        defer c.deinit();
        try openConn(&c);
        // Three passes of 20 open-and-reset pairs: the count is per pass, as h2's is per accept.
        var sid: u32 = 1;
        for (0..3) |_| {
            in.clearRetainingCapacity();
            for (0..20) |_| {
                try frame(&in, 1, 4, sid, hb.items);
                try frame(&in, 3, 0, sid, &.{ 0, 0, 0, 8 });
                sid += 2;
            }
            try c.feed(in.items);
            try testing.expect(goawayOf(c.pending()) == null);
            c.consumed(c.pending().len);
        }
        try testing.expectEqual(@as(u64, 60), c.rst_frames);
        // A reset of a stream opened in an earlier pass (a client cancelling a call) is not one
        // of them, however many arrive together.
        in.clearRetainingCapacity();
        for (0..40) |_| {
            try frame(&in, 1, 4, sid, hb.items);
            sid += 2;
        }
        try c.feed(in.items);
        in.clearRetainingCapacity();
        var back = sid - 80;
        while (back < sid) : (back += 2) try frame(&in, 3, 0, back, &.{ 0, 0, 0, 8 });
        try c.feed(in.items);
        try testing.expect(goawayOf(c.pending()) == null);
        try testing.expectEqual(@as(usize, 0), c.openStreams());
    }
    var c = try h2.Conn.init(gpa, .{}, svc.handler());
    defer c.deinit();
    try openConn(&c);
    c.consumed(c.pending().len);
    in.clearRetainingCapacity();
    var sid: u32 = 1;
    for (0..21) |_| {
        try frame(&in, 1, 4, sid, hb.items);
        try frame(&in, 3, 0, sid, &.{ 0, 0, 0, 8 });
        sid += 2;
    }
    try testing.expectError(error.ConnectionError, c.feed(in.items));
    const ga = goawayOf(c.pending()).?;
    try testing.expectEqual(@as(u32, 11), ga.code); // ENHANCE_YOUR_CALM
    try testing.expectEqualStrings("too_many_resets", ga.debug);
    try testing.expect(c.calmed);
}

/// An offload that takes every job and runs none: the calls stay "on a worker" until the test
/// completes them.
const Parked = struct {
    jobs: std.ArrayList(*h2.conn.Job) = .empty,
    fn submit(ctx: *anyopaque, job: *h2.conn.Job) bool {
        const p: *Parked = @ptrCast(@alignCast(ctx));
        p.jobs.append(testing.allocator, job) catch return false;
        return true;
    }
    fn deinit(p: *Parked) void {
        for (p.jobs.items) |j| j.destroy(testing.allocator);
        p.jobs.deinit(testing.allocator);
    }
    /// The worker of job `i` returns: its (late) answer for a stream that may be gone.
    fn finish(p: *Parked, c: *h2.Conn, i: usize) !bool {
        return c.complete(p.jobs.items[i].stream_id, &.{ 0, 0, 0, 0, 0 }, 1, .ok, "", "");
    }
};

test "rapid reset: cancelled calls still on workers are bounded; a call that returns frees its place" {
    const gpa = testing.allocator;
    var svc: Svc = .{};
    var parked: Parked = .{};
    defer parked.deinit();
    // `--h2-max-cancelled`: 4096 unless set, so a timeout storm on a stalled node (several
    // rounds of 200 calls cancelled and retried while the first are still running) keeps its
    // connection.
    try testing.expectEqual(@as(u32, 4096), (h2.conn.Options{}).max_reset_running);
    var c = try h2.Conn.init(gpa, .{ .max_reset_running = 8 }, svc.handler());
    defer c.deinit();
    c.offload = .{ .ctx = &parked, .submit = Parked.submit };
    try openConn(&c);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try requestHeaders(&hb, "/t.S/Echo", null);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    var sid: u32 = 1;
    // One call per pass, cancelled in the next (so h2's per-pass rule never applies): a peer
    // that cancels each call as soon as a worker has it. The stream is free again at once, the
    // worker is not.
    const Step = struct {
        fn callAndCancel(conn: *h2.Conn, buf: *std.ArrayList(u8), headers: []const u8, id: u32, overflow: bool) !void {
            buf.clearRetainingCapacity();
            try frame(buf, 1, 4, id, headers);
            try frame(buf, 0, 1, id, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
            try conn.feed(buf.items);
            buf.clearRetainingCapacity();
            if (overflow) {
                // the other way to free a stream whose call is running: make the server reset
                // it (a WINDOW_UPDATE that overflows the stream's window)
                try frame(buf, 8, 0, id, &.{ 0x7f, 0xff, 0xff, 0xff });
            } else try frame(buf, 3, 0, id, &.{ 0, 0, 0, 8 });
            try conn.feed(buf.items);
        }
    };
    for (0..8) |i| {
        try Step.callAndCancel(&c, &in, hb.items, sid, i % 2 == 1);
        sid += 2;
    }
    try testing.expectEqual(@as(usize, 0), c.openStreams());
    try testing.expectEqual(@as(usize, 8), c.resetRunning());
    try testing.expect(goawayOf(c.pending()) == null);
    // Four workers return: their answers are dropped and four more cancelled calls fit.
    for (0..4) |i| try testing.expect(!(try parked.finish(&c, i)));
    try testing.expectEqual(@as(usize, 4), c.resetRunning());
    for (0..4) |_| {
        try Step.callAndCancel(&c, &in, hb.items, sid, false);
        sid += 2;
    }
    try testing.expect(goawayOf(c.pending()) == null);
    // A call that is answered is not counted at all.
    in.clearRetainingCapacity();
    try frame(&in, 1, 4, sid, hb.items);
    try frame(&in, 0, 1, sid, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
    try c.feed(in.items);
    try testing.expect(try parked.finish(&c, parked.jobs.items.len - 1));
    try testing.expectEqual(@as(usize, 8), c.resetRunning());
    sid += 2;
    c.consumed(c.pending().len);
    // The ninth cancelled call still on a worker closes the connection.
    try testing.expectError(error.ConnectionError, Step.callAndCancel(&c, &in, hb.items, sid, false));
    const ga = goawayOf(c.pending()).?;
    try testing.expectEqual(@as(u32, 11), ga.code);
    try testing.expectEqualStrings("too_many_resets", ga.debug);
}

test "deadlines: a job is dropped, not run, once its deadline passed or its stream is gone" {
    const gpa = testing.allocator;
    var svc: Svc = .{};
    var parked: Parked = .{};
    defer parked.deinit();
    var c = try h2.Conn.init(gpa, .{ .default_timeout_ns = 50 * std.time.ns_per_ms }, svc.handler());
    defer c.deinit();
    c.offload = .{ .ctx = &parked, .submit = Parked.submit };
    try openConn(&c);
    c.consumed(c.pending().len);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try requestHeaders(&hb, "/t.S/Echo", null);
    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    for ([_]u32{ 1, 3, 5 }) |sid| {
        try frame(&in, 1, 4, sid, hb.items);
        try frame(&in, 0, 1, sid, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
    }
    try c.feed(in.items);
    c.consumed(c.pending().len);
    try testing.expectEqual(@as(usize, 3), parked.jobs.items.len);
    const j1 = parked.jobs.items[0];
    const j3 = parked.jobs.items[1];
    const j5 = parked.jobs.items[2];
    const dl = j1.deadline_ns.?;
    // in time and wanted: run
    try testing.expectEqual(@as(?h2.Status, null), j1.dropped(dl - 1));
    // the deadline passed in the queue: answered as `expireJobs` answers, not run
    try testing.expectEqual(@as(?h2.Status, .deadline_exceeded), j1.dropped(dl));
    // stream 3 is reset by the peer: its job is cancelled
    in.clearRetainingCapacity();
    try frame(&in, 3, 0, 3, &.{ 0, 0, 0, 8 });
    try c.feed(in.items);
    try testing.expectEqual(@as(?h2.Status, .cancelled), j3.dropped(dl - 1));
    try testing.expectEqual(@as(?h2.Status, null), j5.dropped(dl - 1));
    // stream 5 is answered at its deadline by the connection: its job is cancelled too
    try c.expireJobs(j5.deadline_ns.?);
    try testing.expectEqual(@as(?h2.Status, .cancelled), j5.dropped(dl - 1));
    var frames: std.ArrayList(Out) = .empty;
    defer frames.deinit(gpa);
    parseOut(c.pending(), &frames);
    // (stream 1 expired with it: both get the trailers-only DEADLINE_EXCEEDED)
    var expired: u32 = 0;
    var by_conn: []const u8 = "";
    for (frames.items) |f| if (f.t == 1 and f.flags & 1 != 0) {
        try testing.expect(std.mem.indexOf(u8, f.payload, "\x0bgrpc-status\x014") != null);
        try testing.expect(std.mem.indexOf(u8, f.payload, "Timeout%20expired") != null);
        expired += 1;
        by_conn = f.payload;
    };
    try testing.expectEqual(@as(u32, 2), expired);
    // The worker's own answer for a job it dropped at its deadline is the same reply: a second
    // connection where the worker gets there before `expireJobs`.
    var parked2: Parked = .{};
    defer parked2.deinit();
    var c2 = try h2.Conn.init(gpa, .{ .default_timeout_ns = 50 * std.time.ns_per_ms }, svc.handler());
    defer c2.deinit();
    c2.offload = .{ .ctx = &parked2, .submit = Parked.submit };
    try openConn(&c2);
    c2.consumed(c2.pending().len);
    in.clearRetainingCapacity();
    try frame(&in, 1, 4, 1, hb.items);
    try frame(&in, 0, 1, 1, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
    try c2.feed(in.items);
    c2.consumed(c2.pending().len);
    try testing.expect(try c2.complete(1, "", 0, .deadline_exceeded, "Timeout expired", ""));
    frames.clearRetainingCapacity();
    parseOut(c2.pending(), &frames);
    var by_worker: []const u8 = "";
    for (frames.items) |f| if (f.t == 1 and f.flags & 1 != 0) {
        by_worker = f.payload;
    };
    // identical but for the `date` and `server-timing` values (compare up to the status text)
    const upto = std.mem.indexOf(u8, by_conn, "Timeout%20expired").? + "Timeout%20expired".len;
    try testing.expectEqualSlices(u8, by_conn[0..upto], by_worker[0..upto]);
    try testing.expectEqual(by_conn.len, by_worker.len);
}

test "deadlines: calls that expire in the queue are answered at the deadline and never run" {
    const gpa = testing.allocator;
    const io = testing.io;
    var svc: Svc = .{ .sleep_ms = 400 };
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    // 300 calls of 400 ms with a 100 ms grpc-timeout on one connection: more than the pool has
    // workers (256 at most), so the rest wait in its queue past their deadline.
    const calls = 300;
    const opts: h2.ServerOptions = .{ .h2 = .{ .max_streams = calls } };
    const dropped0 = h2.server.stats.jobs_dropped.load(.monotonic);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(i: std.Io, s: *std.Io.net.Server, o: h2.ServerOptions, h: h2.Handler) void {
            const st = s.accept(i) catch return;
            h2.server.serveStreamOpts(testing.allocator, i, st, o, h);
        }
    }.run, .{ io, &server, opts, svc.handler() });
    var done: std.ArrayList(Client.Done) = .empty;
    defer {
        for (done.items) |d| gpa.free(d.payload);
        done.deinit(gpa);
    }
    var reqs: [calls]Client.Req = undefined;
    for (&reqs) |*r| r.* = .{ .path = "/t.S/Slow", .timeout = "100m" };
    try Client.run(gpa, port, &reqs, &done);
    // The connection ends once the workers are done with its calls.
    t.join();
    try testing.expectEqual(@as(usize, calls), done.items.len);
    for (done.items) |d| {
        try testing.expect(std.mem.indexOf(u8, d.payload, "\x0bgrpc-status\x014") != null);
        try testing.expect(std.mem.indexOf(u8, d.payload, "Timeout%20expired") != null);
        try testing.expect(d.ms >= 90);
    }
    // Only the calls a worker took before the deadline ran; the others were dropped at dequeue.
    // Before, every one of the 300 handlers ran, long after its caller had its answer.
    const ran = svc.calls.load(.monotonic);
    const dropped = h2.server.stats.jobs_dropped.load(.monotonic) - dropped0;
    try testing.expect(ran < calls);
    try testing.expectEqual(@as(u64, calls), ran + dropped);
}

/// An allocator that notes how many calls were on the worker pool when the response's copy of
/// `needle` was freed. The copy is told by its length (the bytes are already scrubbed when the
/// allocator sees the free), which nothing else the connection allocates has.
const FreeSpy = struct {
    child: std.mem.Allocator,
    jobs_at_free: std.atomic.Value(u32) = .init(std.math.maxInt(u32)),
    const needle: [3001]u8 = @splat('m');
    const A = std.mem.Alignment;
    fn allocator(s: *FreeSpy) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: A, ra: usize) ?[*]u8 {
        const s: *FreeSpy = @ptrCast(@alignCast(ctx));
        return s.child.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, mem: []u8, a: A, new_len: usize, ra: usize) bool {
        const s: *FreeSpy = @ptrCast(@alignCast(ctx));
        return s.child.rawResize(mem, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, mem: []u8, a: A, new_len: usize, ra: usize) ?[*]u8 {
        const s: *FreeSpy = @ptrCast(@alignCast(ctx));
        return s.child.rawRemap(mem, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, mem: []u8, a: A, ra: usize) void {
        const s: *FreeSpy = @ptrCast(@alignCast(ctx));
        if (mem.len == needle.len) s.jobs_at_free.store(h2.server.stats.jobs.load(.acquire), .release);
        s.child.rawFree(mem, a, ra);
    }
};

test "a worker frees what its response owns before the call stops counting as in flight" {
    const gpa = testing.allocator;
    const io = testing.io;
    var svc: Svc = .{};
    var spy: FreeSpy = .{ .child = gpa };
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    const t = try std.Thread.spawn(.{}, struct {
        fn run(i: std.Io, s: *std.Io.net.Server, h: h2.Handler, a: std.mem.Allocator) void {
            const st = s.accept(i) catch return;
            h2.server.serveStreamOpts(a, i, st, .{}, h);
        }
    }.run, .{ io, &server, svc.handler(), spy.allocator() });
    var done: std.ArrayList(Client.Done) = .empty;
    defer {
        for (done.items) |d| gpa.free(d.payload);
        done.deinit(gpa);
    }
    try Client.run(gpa, port, &.{.{ .path = "/t.S/Owned", .timeout = null }}, &done);
    t.join();
    try testing.expectEqual(@as(usize, 1), done.items.len);
    try testing.expect(std.mem.indexOf(u8, done.items[0].payload, "\x0bgrpc-status\x015") != null);
    // The response's memory came from the server's allocator. It was freed after the call had
    // left `stats.jobs` and the connection's in-flight count (0 here): a drained server could
    // still have a worker about to free into an allocator its owner was taking down.
    try testing.expectEqual(@as(u32, 1), spy.jobs_at_free.load(.acquire));
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
