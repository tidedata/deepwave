//! Review fixes that need sockets: the gRPC client against scripted h2
//! peers, the reconnecting upstream, and ExecuteTransaction off the h2 connection thread.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const serve = @import("serve");
const h2 = serve.h2;
const grpc = @import("grpc_client.zig");
const Upstream = @import("upstream.zig").Upstream;

const io = testing.io;
const gpa = std.heap.smp_allocator; // connection reader threads may outlive a test

fn frame(out: *std.ArrayList(u8), ty: u8, flags: u8, sid: u32, payload: []const u8) !void {
    var h: [9]u8 = undefined;
    std.mem.writeInt(u24, h[0..3], @intCast(payload.len), .big);
    h[3] = ty;
    h[4] = flags;
    std.mem.writeInt(u32, h[5..9], sid, .big);
    try out.appendSlice(gpa, &h);
    try out.appendSlice(gpa, payload);
}

/// A scripted h2c peer: accepts one connection, reads until the client's first HEADERS frame (or
/// just the preface when `wait_headers` is false), writes `script`, then holds the socket open
/// until `close` is set (or closes at once when `close_after` is true).
const Peer = struct {
    server: Io.net.Server = undefined,
    port: u16 = 0,
    script: []const u8 = "",
    wait_headers: bool = true,
    close_after: bool = false,
    /// Never answer anything (not even read): a black hole after the TCP accept.
    silent: bool = false,
    close: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    fn start(p: *Peer) !void {
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        p.server = try addr.listen(io, .{ .reuse_address = true });
        p.port = p.server.socket.address.getPort();
        p.thread = try std.Thread.spawn(.{}, run, .{p});
    }

    fn stop(p: *Peer) void {
        p.close.store(true, .release);
        if (p.thread) |t| t.join();
        p.server.deinit(io);
    }

    fn run(p: *Peer) void {
        const st = p.server.accept(io) catch return;
        defer st.close(io);
        if (!p.silent) {
            var got: std.ArrayList(u8) = .empty;
            defer got.deinit(gpa);
            var rbuf: [4096]u8 = undefined;
            outer: while (true) {
                var iov = [_][]u8{&rbuf};
                const n = st.read(io, &iov) catch return;
                if (n == 0) return;
                got.appendSlice(gpa, rbuf[0..n]) catch return;
                if (got.items.len < 24) continue;
                if (!p.wait_headers) break;
                var pos: usize = 24;
                while (pos + 9 <= got.items.len) {
                    const len = std.mem.readInt(u24, got.items[pos..][0..3], .big);
                    if (got.items[pos + 3] == 1) break :outer;
                    pos += 9 + len;
                }
            }
            var wbuf: [4096]u8 = undefined;
            var w = st.writer(io, &wbuf);
            w.interface.writeAll(p.script) catch return;
            w.interface.flush() catch return;
            if (p.close_after) return;
        }
        while (!p.close.load(.acquire)) Io.sleep(io, .fromMilliseconds(5), .awake) catch return;
        st.shutdown(io, .both) catch {};
    }
};

fn settingsFrame(out: *std.ArrayList(u8), key: u16, val: u32) !void {
    var s: [6]u8 = undefined;
    std.mem.writeInt(u16, s[0..2], key, .big);
    std.mem.writeInt(u32, s[2..6], val, .big);
    try frame(out, 4, 0, 0, &s);
}

/// HEADERS :status 200 + content-type for stream 1.
fn responseHeaders(out: *std.ArrayList(u8), end_stream: bool) !void {
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try hb.append(gpa, 0x88);
    try h2.hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    try frame(out, 1, 4 | @as(u8, if (end_stream) 1 else 0), 1, hb.items);
}

fn trailersOk(out: *std.ArrayList(u8)) !void {
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try h2.hpack.encodeLiteral(&hb, gpa, "grpc-status", "0");
    try frame(out, 1, 4 | 1, 1, hb.items);
}

fn waitDead(c: *grpc.Conn, ms: u32) !void {
    var i: u32 = 0;
    while (!c.isDead() and i < ms) : (i += 1) try Io.sleep(io, .fromMilliseconds(1), .awake);
    try testing.expect(c.isDead());
}

fn plainConn(port: u16) !*grpc.Conn {
    return grpc.Conn.open(gpa, io, .{ .host = "127.0.0.1", .port = port, .security = .plain });
}

test "a dead connection has no writer left (no write through the reader's freed frame)" {
    var peer: Peer = .{ .wait_headers = false, .close_after = true };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    try waitDead(c, 5000);
    c.mu.lockUncancelable(io);
    const w = c.writer;
    const sw = c.sock_writer;
    c.mu.unlock(io);
    try testing.expect(w == null and sw == null);
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 2000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
}

test "SETTINGS_MAX_FRAME_SIZE 0 ends the connection instead of spinning" {
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try settingsFrame(&script, 5, 0);
    var peer: Peer = .{ .script = script.items };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 5000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expectEqualStrings("transport error: h2 protocol error", r.status.message);
    try testing.expect(!grpc.settingValid(5, 0) and !grpc.settingValid(5, 16_777_216) and grpc.settingValid(5, 16_384));
    try testing.expect(!grpc.settingValid(4, 0x8000_0000) and grpc.settingValid(4, 0x7fff_ffff));
}

test "a response over the size cap fails that call with RESOURCE_EXHAUSTED" {
    const saved = grpc.max_response_bytes;
    grpc.max_response_bytes = 64;
    defer grpc.max_response_bytes = saved;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try responseHeaders(&script, false);
    const big = @as([100]u8, @splat(0));
    try frame(&script, 0, 0, 1, &big);
    try trailersOk(&script);
    var peer: Peer = .{ .script = script.items };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 5000);
    try testing.expectEqual(@as(u8, 8), r.status.code);
    try testing.expect(!c.isDead()); // the connection keeps serving
}

test "an endless header block ends the connection" {
    const saved = grpc.max_header_block;
    grpc.max_header_block = 16;
    defer grpc.max_header_block = saved;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try frame(&script, 1, 0, 1, &@as([12]u8, @splat(0x40))); // no END_HEADERS
    try frame(&script, 9, 0, 1, &@as([12]u8, @splat(0x40)));
    var peer: Peer = .{ .script = script.items };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 5000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expectEqualStrings("transport error: header block too large", r.status.message);
}

test "a gRPC length prefix near 4 GiB is a truncated message, not an overflow" {
    const huge = [_]u8{ 0, 0xff, 0xff, 0xff, 0xff, 1, 2, 3 };
    try testing.expectEqual(@as(u8, 13), grpc.decodeUnary(&huge).status.code);
    const fffffffb = [_]u8{ 0, 0xff, 0xff, 0xff, 0xfb, 1 };
    try testing.expectEqual(@as(u8, 13), grpc.decodeUnary(&fffffffb).status.code);
    const trailing = [_]u8{ 0, 0, 0, 0, 1, 7, 9 };
    try testing.expectEqualStrings("protocol error: trailing bytes after the response message", grpc.decodeUnary(&trailing).status.message);
    const ok = [_]u8{ 0, 0, 0, 0, 2, 7, 9 };
    try testing.expectEqualSlices(u8, &.{ 7, 9 }, grpc.decodeUnary(&ok).ok);
    // and over a socket
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try responseHeaders(&script, false);
    try frame(&script, 0, 0, 1, &huge);
    try trailersOk(&script);
    var peer: Peer = .{ .script = script.items };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 5000);
    try testing.expectEqualStrings("protocol error: truncated response message", r.status.message);
}

test "keepalive: a peer that stops answering PINGs fails the open calls" {
    const saved = .{ grpc.keepalive_busy_ns, grpc.keepalive_timeout_ns, grpc.watchdog.period_ns };
    grpc.keepalive_busy_ns = 50 * std.time.ns_per_ms;
    grpc.keepalive_timeout_ns = 200 * std.time.ns_per_ms;
    grpc.watchdog.period_ns = 20 * std.time.ns_per_ms;
    defer {
        grpc.keepalive_busy_ns = saved[0];
        grpc.keepalive_timeout_ns = saved[1];
        grpc.watchdog.period_ns = saved[2];
    }
    var peer: Peer = .{ .script = "" }; // reads the request, then says nothing
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 10_000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expectEqualStrings("transport error: keepalive timeout", r.status.message);
}

test "connect deadline: a TLS peer that never answers the handshake" {
    const saved = .{ grpc.connect_timeout_ns, grpc.watchdog.period_ns };
    grpc.connect_timeout_ns = 200 * std.time.ns_per_ms;
    grpc.watchdog.period_ns = 20 * std.time.ns_per_ms;
    defer {
        grpc.connect_timeout_ns = saved[0];
        grpc.watchdog.period_ns = saved[1];
    }
    var peer: Peer = .{ .silent = true };
    try peer.start();
    defer peer.stop();
    const c = try grpc.Conn.open(gpa, io, .{ .host = "127.0.0.1", .port = peer.port, .security = .{ .pinned = @splat(1) } });
    defer c.release();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 10_000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expectEqualStrings("transport error: connect timeout", r.status.message);
}

test "the upstream reconnects after its connection died" {
    const u = try Upstream.init(gpa, io, .{ .host = "127.0.0.1", .port = 1, .security = .plain });
    defer u.deinit();
    u.cooldown_ns = 0;
    const c1 = u.acquire().?;
    try waitDead(c1, 5000);
    const c2 = u.acquire().?;
    try testing.expect(c1 != c2);
    try testing.expect(u.reconnects.load(.monotonic) >= 1);
    c1.unref(); // still valid: the caller's reference outlived the replacement
    c2.unref();
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try u.call(a.allocator(), "/x/Y", "", 2000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expect(u.isLocal());
}

/// ExecuteTransaction takes `slow_ms`; every other method answers at once.
const SlowExec = struct {
    slow_ms: u64,
    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const self: *SlowExec = @ptrCast(@alignCast(ctx));
        if (std.mem.startsWith(u8, req.path, "/sui.rpc.v2.TransactionExecutionService/")) {
            Io.sleep(io, .fromMilliseconds(@intCast(self.slow_ms)), .awake) catch {};
            rs.message("executed") catch return .internal;
            return .ok;
        }
        rs.setMessage("fast error");
        return .not_found;
    }
};

test "a slow ExecuteTransaction does not hold up the other streams of its connection" {
    var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const port = server.socket.address.getPort();
    var slow: SlowExec = .{ .slow_ms = 1500 };
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *Io.net.Server, e: *SlowExec) void {
            const st = s.accept(io) catch return;
            h2.serveStream(testing.allocator, io, st, .{}, .{ .ctx = e, .call = SlowExec.call });
        }
    }.run, .{ &server, &slow });
    defer t.join();
    const c = try plainConn(port);
    defer c.release();
    // the slow execute first, on the same connection
    const W = struct {
        done: std.atomic.Value(bool) = .init(false),
        ok: std.atomic.Value(bool) = .init(false),
        fn sink(ctx: *anyopaque, _: u64, r: grpc.Result) void {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            if (r == .ok and std.mem.eql(u8, r.ok, "executed")) w.ok.store(true, .release);
            w.done.store(true, .release);
        }
    };
    var w: W = .{};
    var slot: u32 = 0;
    c.start(&slot, "/sui.rpc.v2.TransactionExecutionService/ExecuteTransaction", "tx", .{ .ctx = &w, .done = W.sink }, 1, null);
    try Io.sleep(io, .fromMilliseconds(100), .awake);
    // a read on the same connection answers while the execute is still running
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const t0 = Io.Clock.awake.now(io).nanoseconds;
    const r = try grpc.callBlocking(a.allocator(), c, "/sui.rpc.v2.LedgerService/GetObject", "", 5000);
    const ms = @divTrunc(Io.Clock.awake.now(io).nanoseconds - t0, std.time.ns_per_ms);
    try testing.expectEqual(@as(u8, 5), r.status.code);
    try testing.expectEqualStrings("fast error", r.status.message);
    try testing.expect(ms < 1000);
    try testing.expect(!w.done.load(.acquire));
    var i: u32 = 0;
    while (!w.done.load(.acquire) and i < 5000) : (i += 1) try Io.sleep(io, .fromMilliseconds(1), .awake);
    try testing.expect(w.ok.load(.acquire));
    c.mu.lockUncancelable(io);
    if (c.stream) |s| s.shutdown(io, .both) catch {};
    c.mu.unlock(io);
}
