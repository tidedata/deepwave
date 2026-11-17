//! Threads started per call on the gRPC port: none once the server has run a while. A
//! connection's thread is a kept one (core/threads.zig), so a client that opens a connection
//! per call (HTTP/1.1, a health check) no longer starts and ends a thread each time; unary calls
//! on one h2c connection run on the fixed pool (pool.zig).
const std = @import("std");
const testing = std.testing;
const server = @import("server.zig");
const hpack = @import("hpack.zig");
const tcache = @import("core").threads;
const h2 = struct {
    const conn = @import("conn.zig");
    const Request = conn.Request;
    const ResponseStream = conn.ResponseStream;
    const Handler = conn.Handler;
    const Status = conn.Status;
    const meta = @import("meta.zig");
    const sock = @import("sock.zig");
};

const Echo = struct {
    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        if (!std.mem.eql(u8, req.path, "/t.S/Echo")) return .unimplemented;
        rs.message("ok") catch return .internal;
        return .ok;
    }
    fn known(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t.S/");
    }
    fn compress(_: *anyopaque, _: []const u8) bool {
        return false;
    }
    fn info(_: *anyopaque, out: *h2.meta.Info) void {
        out.* = .{ .chain_id = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S", .chain = "mainnet", .tip = .{ .epoch = 1, .height = 1, .timestamp_ms = 1 }, .lowest = 0, .server = "zui" };
    }
    var dummy: u8 = 0;
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call, .known = known, .compress = compress, .info = info };
};

/// One gRPC-web call on a connection of its own, closed after the answer.
fn webCall(io: std.Io, port: u16) !void {
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const c = try caddr.connect(io, .{ .mode = .stream });
    defer c.close(io);
    var wbuf: [256]u8 = undefined;
    var w = c.writer(io, &wbuf);
    try w.interface.writeAll("POST /t.S/Echo HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\nconnection: close\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00");
    try w.interface.flush();
    var got: [4096]u8 = undefined;
    var n: usize = 0;
    while (std.mem.indexOf(u8, got[0..n], "grpc-status:") == null) {
        var iov = [_][]u8{got[n..]};
        const r = try c.read(io, &iov);
        if (r == 0) return error.TestUnexpectedResult;
        n += r;
    }
    try testing.expect(std.mem.indexOf(u8, got[0..n], "grpc-status:0") != null);
}

/// Waits until no connection is served and the kept threads that were parked are again.
fn settle(parked: u64) void {
    var k: usize = 0;
    while (k < 2000 and (server.stats.conns.load(.acquire) != 0 or tcache.stats.parked.load(.acquire) < parked)) : (k += 1) h2.sock.sleepMs(1);
}

fn frame(out: *std.ArrayList(u8), t: u8, flags: u8, sid: u32, payload: []const u8) !void {
    const gpa = testing.allocator;
    try out.appendSlice(gpa, &.{ @intCast(payload.len >> 16), @intCast((payload.len >> 8) & 0xff), @intCast(payload.len & 0xff), t, flags });
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, sid, .big);
    try out.appendSlice(gpa, &s);
    try out.appendSlice(gpa, payload);
}

/// `n` unary calls on the h2c connection `c` (streams from `sid`), all sent, then every
/// answer's trailers read.
fn h2Batch(io: std.Io, c: anytype, sid: *u32, n: usize, rest: *std.ArrayList(u8)) !void {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try hb.appendSlice(gpa, &.{ 0x83, 0x86 }); // :method POST, :scheme http
    try hpack.encodeLiteral(&hb, gpa, ":path", "/t.S/Echo");
    try hpack.encodeLiteral(&hb, gpa, ":authority", "localhost");
    try hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    try hpack.encodeLiteral(&hb, gpa, "te", "trailers");
    for (0..n) |_| {
        try frame(&out, 1, 4, sid.*, hb.items);
        try frame(&out, 0, 1, sid.*, &.{ 0, 0, 0, 0, 2, 'h', 'i' });
        sid.* += 2;
    }
    var wbuf: [4096]u8 = undefined;
    var w = c.writer(io, &wbuf);
    try w.interface.writeAll(out.items);
    try w.interface.flush();
    var ended: usize = 0;
    var rbuf: [16384]u8 = undefined;
    while (ended < n) {
        var iov = [_][]u8{&rbuf};
        const r = try c.read(io, &iov);
        if (r == 0) return error.TestUnexpectedResult;
        try rest.appendSlice(gpa, rbuf[0..r]);
        var pos: usize = 0;
        while (pos + 9 <= rest.items.len) {
            const len = (@as(usize, rest.items[pos]) << 16) | (@as(usize, rest.items[pos + 1]) << 8) | rest.items[pos + 2];
            if (pos + 9 + len > rest.items.len) break;
            // a HEADERS frame that ends its stream: the call's trailers
            if (rest.items[pos + 3] == 1 and rest.items[pos + 4] & 1 != 0) ended += 1;
            pos += 9 + len;
        }
        std.mem.copyForwards(u8, rest.items[0 .. rest.items.len - pos], rest.items[pos..]);
        rest.shrinkRetainingCapacity(rest.items.len - pos);
    }
}

test "gRPC port: no thread started per call, on a connection per call (HTTP/1.1) or many calls on one (h2c)" {
    const io = testing.io;
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .reuse_address = true });
    const port = srv.socket.address.getPort();
    var stop: std.atomic.Value(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, st: *std.atomic.Value(bool)) void {
            server.serveBlocking(testing.allocator, testing.io, s, .{}, Echo.handler, st) catch {};
        }
    }.run, .{ &srv, &stop });
    defer {
        stop.store(true, .release);
        var caddr = std.Io.net.IpAddress.parseIp4("127.0.0.1", port) catch unreachable;
        if (caddr.connect(io, .{ .mode = .stream })) |x| x.close(io) else |_| {}
        t.join();
        srv.deinit(io);
        _ = server.waitDrained(3 * std.time.ns_per_s);
    }

    // a connection per call: warm, then 1,000
    for (0..20) |_| {
        try webCall(io, port);
        settle(0);
    }
    const parked = tcache.stats.parked.load(.acquire);
    const kept0 = tcache.stats.started.load(.monotonic);
    const seen0 = tcache.threadsStarted();
    for (0..1000) |_| {
        try webCall(io, port);
        settle(parked);
    }
    const kept1 = tcache.stats.started.load(.monotonic) - kept0;
    std.debug.print("gRPC, a connection per call: threads started per 1,000 calls: {d} (kept-thread cache grew by {d})\n", .{ if (seen0) |s| tcache.threadsStarted().? - s else kept1, kept1 });
    try testing.expectEqual(@as(u64, 0), kept1);
    if (seen0) |s| try testing.expectEqual(s, tcache.threadsStarted().?);

    // many calls on one h2c connection: warm (the unary pool starts), then 1,000
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const c = try caddr.connect(io, .{ .mode = .stream });
    defer c.close(io);
    {
        var pre: std.ArrayList(u8) = .empty;
        defer pre.deinit(testing.allocator);
        try pre.appendSlice(testing.allocator, h2.conn.preface);
        try frame(&pre, 4, 0, 0, &.{});
        var wbuf: [256]u8 = undefined;
        var w = c.writer(io, &wbuf);
        try w.interface.writeAll(pre.items);
        try w.interface.flush();
    }
    var rest: std.ArrayList(u8) = .empty;
    defer rest.deinit(testing.allocator);
    var sid: u32 = 1;
    try h2Batch(io, c, &sid, 50, &rest);
    const seen1 = tcache.threadsStarted();
    const threads1 = tcache.processThreads();
    for (0..20) |_| try h2Batch(io, c, &sid, 50, &rest);
    if (seen1) |s| {
        std.debug.print("gRPC, 1,000 unary calls on one h2c connection: threads started: {d}\n", .{tcache.threadsStarted().? - s});
        try testing.expectEqual(s, tcache.threadsStarted().?);
    }
    if (threads1) |n| try testing.expectEqual(n, tcache.processThreads().?);
}
