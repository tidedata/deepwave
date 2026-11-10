//! Graceful stop over real sockets: a call in flight when the server is told to stop still gets
//! its whole answer, new connections are refused, and `waitDrained` returns once every
//! connection thread is gone (deepwave's SIGTERM path, FULLNODE-PARITY section 10).
const std = @import("std");
const testing = std.testing;
const server = @import("server.zig");
// The pieces, not root.zig: this file also runs alone (`zig test src/serve/h2/test_drain.zig`).
const h2 = struct {
    const conn = @import("conn.zig");
    const Request = conn.Request;
    const ResponseStream = conn.ResponseStream;
    const Handler = conn.Handler;
    const Status = conn.Status;
    const meta = @import("meta.zig");
    const sock = @import("sock.zig");
};

const Slow = struct {
    var entered: std.atomic.Value(bool) = .init(false);
    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        if (!std.mem.eql(u8, req.path, "/t.S/Slow")) return .unimplemented;
        entered.store(true, .release);
        h2.sock.sleepMs(400);
        rs.message("done") catch return .internal;
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

test "graceful stop: the call in flight is answered in full, then the server drains" {
    const io = testing.io;
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .reuse_address = true });
    const port = srv.socket.address.getPort();
    var stop: std.atomic.Value(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, st: *std.atomic.Value(bool)) void {
            server.serveBlocking(testing.allocator, testing.io, s, .{ .stop_grace_ns = 5 * std.time.ns_per_s }, Slow.handler, st) catch {};
        }
    }.run, .{ &srv, &stop });

    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const c = try caddr.connect(io, .{ .mode = .stream });
    defer c.close(io);
    var wbuf: [256]u8 = undefined;
    var w = c.writer(io, &wbuf);
    try w.interface.writeAll("POST /t.S/Slow HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00");
    try w.interface.flush();
    while (!Slow.entered.load(.acquire)) h2.sock.sleepMs(1);

    // SIGTERM: stop accepting (wake the accept loop as deepwave does), then drain.
    stop.store(true, .release);
    if (caddr.connect(io, .{ .mode = .stream })) |x| x.close(io) else |_| {}
    t.join();
    srv.deinit(io);
    try testing.expect(server.stats.conns.load(.acquire) >= 1); // the slow call is still running

    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(testing.allocator);
    var rbuf: [4096]u8 = undefined;
    while (true) {
        var iov = [_][]u8{&rbuf};
        const n = c.read(io, &iov) catch break;
        if (n == 0) break;
        try got.appendSlice(testing.allocator, rbuf[0..n]);
    }
    try testing.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, got.items, "done") != null);
    try testing.expect(std.mem.indexOf(u8, got.items, "grpc-status:0") != null);
    try testing.expect(server.waitDrained(3 * std.time.ns_per_s));
    try testing.expectEqual(@as(u32, 0), server.stats.conns.load(.acquire));
}
