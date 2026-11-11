//! Review fixes that need sockets: the gRPC client against scripted h2
//! peers, the reconnecting upstream, and ExecuteTransaction off the h2 connection thread.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const serve = @import("serve");
const h2 = serve.h2;
const grpc = @import("grpc_client.zig");
const Upstream = @import("upstream.zig").Upstream;
const validators = @import("validators.zig");
const cm = @import("../driver/root.zig").committee;

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

/// How long a fake peer's thread waits in poll before it looks at its stop flag again.
const peer_poll_ms = 10;
/// A test thread still running this long after it should have ended is reported, not joined.
const join_limit_ms = 20_000;

/// Waits until `fd` is readable (a connection to accept, bytes, the other side's close); false
/// once `stop` is set. A fake peer only accepts and reads after this, so it never sits in
/// accept(2) or recvmsg(2) for a client that does not come or does not speak: nothing would
/// wake it there, and the test's join of the thread would wait forever.
fn readable(fd: std.posix.socket_t, stop: *const std.atomic.Value(bool)) bool {
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    while (!stop.load(.acquire)) {
        fds[0].revents = 0;
        switch (std.posix.errno(std.posix.system.poll(&fds, 1, peer_poll_ms))) {
            .SUCCESS => if (fds[0].revents != 0) return true,
            .INTR => {},
            else => return false,
        }
    }
    return false;
}

/// Joins a test thread once it has set `exited` (its last act). One that has not within
/// `join_limit_ms` would make the join, and with it the whole test run, wait forever: that is a
/// panic naming the thread instead, so the test fails and the process ends.
fn joinBounded(t: std.Thread, exited: *const std.atomic.Value(bool), what: []const u8) void {
    const t0 = Io.Clock.awake.now(io).nanoseconds;
    while (!exited.load(.acquire)) {
        if (Io.Clock.awake.now(io).nanoseconds - t0 > @as(i96, join_limit_ms) * std.time.ns_per_ms)
            std.debug.panic("fixes_test: the {s} thread did not end within {d} s", .{ what, join_limit_ms / 1000 });
        Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    }
    t.join();
}

/// A scripted h2c peer: accepts one connection, reads until the client's first HEADERS frame (or
/// just the preface when `wait_headers` is false), writes `script`, then holds the socket open
/// until `close` is set (or closes at once when `close_after` is true). Its thread ends within
/// `peer_poll_ms` of `stop`, whatever the client did or did not do.
const Peer = struct {
    server: Io.net.Server = undefined,
    port: u16 = 0,
    script: []const u8 = "",
    wait_headers: bool = true,
    /// With `wait_headers`: the script goes out once this many HEADERS frames have come.
    headers_wanted: u32 = 1,
    close_after: bool = false,
    /// Never answer anything (not even read): a black hole after the TCP accept.
    silent: bool = false,
    /// After the script keep reading, a trickle: 16 KiB every 5 ms.
    trickle: bool = false,
    close: std.atomic.Value(bool) = .init(false),
    exited: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    fn start(p: *Peer) !void {
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        p.server = try addr.listen(io, .{ .reuse_address = true });
        p.port = p.server.socket.address.getPort();
        p.thread = try std.Thread.spawn(.{}, run, .{p});
    }

    fn stop(p: *Peer) void {
        p.close.store(true, .release);
        if (p.thread) |t| joinBounded(t, &p.exited, "fake peer");
        p.server.deinit(io);
    }

    fn run(p: *Peer) void {
        defer p.exited.store(true, .release);
        if (!readable(p.server.socket.handle, &p.close)) return;
        const st = p.server.accept(io) catch return;
        defer st.close(io);
        if (!p.silent) {
            var got: std.ArrayList(u8) = .empty;
            defer got.deinit(gpa);
            var rbuf: [4096]u8 = undefined;
            outer: while (true) {
                var iov = [_][]u8{&rbuf};
                if (!readable(st.socket.handle, &p.close)) return;
                const n = st.read(io, &iov) catch return;
                if (n == 0) return;
                got.appendSlice(gpa, rbuf[0..n]) catch return;
                if (got.items.len < 24) continue;
                if (!p.wait_headers) break;
                var pos: usize = 24;
                var seen: u32 = 0;
                while (pos + 9 <= got.items.len) {
                    const len = std.mem.readInt(u24, got.items[pos..][0..3], .big);
                    if (got.items[pos + 3] == 1) {
                        seen += 1;
                        if (seen >= p.headers_wanted) break :outer;
                    }
                    pos += 9 + len;
                }
            }
            var wbuf: [4096]u8 = undefined;
            var w = st.writer(io, &wbuf);
            w.interface.writeAll(p.script) catch return;
            w.interface.flush() catch return;
            if (p.close_after) return;
        }
        var sink: [16 << 10]u8 = undefined;
        while (!p.close.load(.acquire)) {
            Io.sleep(io, .fromMilliseconds(5), .awake) catch return;
            if (!p.trickle) continue;
            var iov = [_][]u8{&sink};
            if (!readable(st.socket.handle, &p.close)) break;
            if ((st.read(io, &iov) catch return) == 0) return;
        }
        st.shutdown(io, .both) catch {};
    }
};

test "a fake peer stops when no client reaches it, and when its client says nothing" {
    // nobody connects: the thread must not sit in accept (before, `stop` joined it forever)
    var alone: Peer = .{};
    try alone.start();
    alone.stop();
    // a client connects and sends nothing: the thread must not sit in read
    var mute: Peer = .{};
    try mute.start();
    const to = try Io.net.IpAddress.parseIp4("127.0.0.1", mute.port);
    const st = try to.connect(io, .{ .mode = .stream });
    defer st.close(io);
    try Io.sleep(io, .fromMilliseconds(50), .awake); // the peer has accepted and waits for bytes
    mute.stop();
    try testing.expect(alone.exited.load(.acquire) and mute.exited.load(.acquire));
}

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

/// A whole answer on stream `sid`: HEADERS, one gRPC message, trailers with grpc-status 0.
fn responseOk(out: *std.ArrayList(u8), sid: u32, msg: []const u8) !void {
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try hb.append(gpa, 0x88);
    try h2.hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    try frame(out, 1, 4, sid, hb.items);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    try data.appendSlice(gpa, &.{ 0, 0, 0, 0, @intCast(msg.len) });
    try data.appendSlice(gpa, msg);
    try frame(out, 0, 0, sid, data.items);
    hb.clearRetainingCapacity();
    try h2.hpack.encodeLiteral(&hb, gpa, "grpc-status", "0");
    try frame(out, 1, 4 | 1, sid, hb.items);
}

/// GOAWAY(NO_ERROR) naming `last` as the last stream the peer answers.
fn goawayFrame(out: *std.ArrayList(u8), last: u32) !void {
    var b: [8]u8 = @splat(0);
    std.mem.writeInt(u32, b[0..4], last, .big);
    try frame(out, 7, 0, 0, &b);
}

/// The answers of a few calls, by tag: 0xff until answered, then the status code (0: a message).
const Answers = struct {
    codes: [4]std.atomic.Value(u32) = @splat(.init(0xff)),
    count: std.atomic.Value(u32) = .init(0),
    text: [4][64]u8 = undefined,
    len: [4]usize = @splat(0),

    fn sink(ctx: *anyopaque, tag: u64, r: grpc.Result) void {
        const a: *Answers = @ptrCast(@alignCast(ctx));
        const t: []const u8 = switch (r) {
            .ok => |b| b,
            .status => |st| st.message,
        };
        a.len[tag] = @min(t.len, 64);
        @memcpy(a.text[tag][0..a.len[tag]], t[0..a.len[tag]]);
        a.codes[tag].store(if (r == .status) r.status.code else 0, .release);
        _ = a.count.fetchAdd(1, .release);
    }

    fn textOf(a: *const Answers, tag: usize) []const u8 {
        return a.text[tag][0..a.len[tag]];
    }

    fn waitCount(a: *const Answers, n: u32, ms: u32) !void {
        var i: u32 = 0;
        while (a.count.load(.acquire) < n and i < ms) : (i += 1) try Io.sleep(io, .fromMilliseconds(1), .awake);
        try testing.expect(a.count.load(.acquire) >= n);
    }
};

/// An h2c peer that allows `limit` concurrent streams and answers each request `delay_ms`
/// after its last byte; it records how many streams the client had open at once. Its thread
/// waits in poll with the stop flag, like `Peer`.
const LimitPeer = struct {
    server: Io.net.Server = undefined,
    port: u16 = 0,
    limit: u32,
    delay_ms: i96 = 30,
    max_open: std.atomic.Value(u32) = .init(0),
    close: std.atomic.Value(bool) = .init(false),
    exited: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,

    const Due = struct { sid: u32, at: i96 };

    fn start(p: *LimitPeer) !void {
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        p.server = try addr.listen(io, .{ .reuse_address = true });
        p.port = p.server.socket.address.getPort();
        p.thread = try std.Thread.spawn(.{}, run, .{p});
    }

    fn stop(p: *LimitPeer) void {
        p.close.store(true, .release);
        if (p.thread) |t| joinBounded(t, &p.exited, "limit peer");
        p.server.deinit(io);
    }

    fn run(p: *LimitPeer) void {
        defer p.exited.store(true, .release);
        if (!readable(p.server.socket.handle, &p.close)) return;
        const st = p.server.accept(io) catch return;
        defer st.close(io);
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(gpa);
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var due: std.ArrayList(Due) = .empty;
        defer due.deinit(gpa);
        var wbuf: [4096]u8 = undefined;
        var w = st.writer(io, &wbuf);
        var rbuf: [4096]u8 = undefined;
        var pos: usize = 24; // frames are parsed from here, after the preface
        var greeted = false;
        var open: u32 = 0;
        var fds = [_]std.posix.pollfd{.{ .fd = st.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        while (!p.close.load(.acquire)) {
            fds[0].revents = 0;
            if (std.posix.errno(std.posix.system.poll(&fds, 1, 5)) == .SUCCESS and fds[0].revents != 0) {
                var iov = [_][]u8{&rbuf};
                const n = st.read(io, &iov) catch return;
                if (n == 0) return;
                got.appendSlice(gpa, rbuf[0..n]) catch return;
            }
            if (got.items.len < 24) continue;
            out.clearRetainingCapacity();
            if (!greeted) {
                settingsFrame(&out, 3, p.limit) catch return; // MAX_CONCURRENT_STREAMS
                greeted = true;
            }
            const now = Io.Clock.awake.now(io).nanoseconds;
            while (pos + 9 <= got.items.len) {
                const len = std.mem.readInt(u24, got.items[pos..][0..3], .big);
                if (pos + 9 + len > got.items.len) break;
                const ty = got.items[pos + 3];
                const fl = got.items[pos + 4];
                const sid = std.mem.readInt(u32, got.items[pos + 5 ..][0..4], .big) & 0x7fff_ffff;
                if (ty == 1) {
                    open += 1;
                    if (open > p.max_open.load(.monotonic)) p.max_open.store(open, .release);
                }
                // the request is complete: its answer is due
                if ((ty == 0 or ty == 1) and fl & 1 != 0) due.append(gpa, .{ .sid = sid, .at = now + p.delay_ms * std.time.ns_per_ms }) catch return;
                pos += 9 + len;
            }
            var k: usize = 0;
            while (k < due.items.len) {
                if (due.items[k].at > now) {
                    k += 1;
                    continue;
                }
                responseOk(&out, due.items[k].sid, "ok") catch return;
                open -= 1;
                _ = due.orderedRemove(k);
            }
            if (out.items.len == 0) continue;
            w.interface.writeAll(out.items) catch return;
            w.interface.flush() catch return;
        }
    }
};

test "the peer's limit of concurrent streams is kept: further calls wait and are started in order" {
    var peer: LimitPeer = .{ .limit = 1 };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer releaseAndJoin(c);
    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        c.mu.lockUncancelable(io);
        const known = c.peer_max_streams == 1;
        c.mu.unlock(io);
        if (known) break;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    var ans: Answers = .{};
    var slots: [4]u32 = @splat(0);
    for (&slots, 0..) |*slot, k| c.start(slot, "/x/Y", "body", .{ .ctx = &ans, .done = Answers.sink }, k, null);
    try ans.waitCount(4, 5000);
    for (0..4) |k| {
        try testing.expectEqual(@as(u32, 0), ans.codes[k].load(.acquire));
        try testing.expectEqualStrings("ok", ans.textOf(k));
    }
    // each stream id belongs to the call started in that order
    try testing.expectEqualSlices(u32, &.{ 1, 3, 5, 7 }, &slots);
    try testing.expectEqual(@as(u32, 1), peer.max_open.load(.acquire));
    try testing.expect(!c.isDead());
}

test "the response bytes a connection holds for its open calls together are capped" {
    const saved = grpc.max_conn_response_bytes;
    grpc.max_conn_response_bytes = 100;
    defer grpc.max_conn_response_bytes = saved;
    // two calls open; the peer sends 80 bytes of answer on each and ends neither: the second
    // 80 would make 160. Then the first call's answer ends.
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try hb.append(gpa, 0x88);
    try h2.hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    var msg: [80]u8 = @splat('m');
    @memcpy(msg[0..5], &[_]u8{ 0, 0, 0, 0, 75 }); // one gRPC message of 75 bytes
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try frame(&script, 1, 4, 1, hb.items);
    try frame(&script, 0, 0, 1, &msg);
    try frame(&script, 1, 4, 3, hb.items);
    try frame(&script, 0, 0, 3, &msg);
    hb.clearRetainingCapacity();
    try h2.hpack.encodeLiteral(&hb, gpa, "grpc-status", "0");
    try frame(&script, 1, 4 | 1, 1, hb.items);
    var peer: Peer = .{ .script = script.items, .headers_wanted = 2 };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer releaseAndJoin(c);
    var ans: Answers = .{};
    var slots: [2]u32 = @splat(0);
    const sink: grpc.Sink = .{ .ctx = &ans, .done = Answers.sink };
    c.start(&slots[0], "/x/Y", "one", sink, 0, null); // stream 1
    c.start(&slots[1], "/x/Y", "two", sink, 1, null); // stream 3
    try ans.waitCount(2, 5000);
    // the call that went past the connection's limit fails alone
    try testing.expectEqual(@as(u32, 8), ans.codes[1].load(.acquire));
    try testing.expectEqualStrings("response buffers of the connection are full", ans.textOf(1));
    try testing.expectEqual(@as(u32, 0), ans.codes[0].load(.acquire));
    try testing.expect(!c.isDead());
    // and a finished call gives its bytes back
    c.mu.lockUncancelable(io);
    const held = c.buffered;
    c.mu.unlock(io);
    try testing.expectEqual(@as(usize, 0), held);
}

const goaway_text = "transport error: connection closed by peer (GOAWAY)";

test "GOAWAY: the calls it covers finish, the others and new ones are answered UNAVAILABLE" {
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try goawayFrame(&script, 1); // stream 1 will be answered, stream 3 will not
    try responseOk(&script, 1, "ok");
    var peer: Peer = .{ .script = script.items, .headers_wanted = 2 };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer releaseAndJoin(c);
    var ans: Answers = .{};
    var slots: [3]u32 = @splat(0);
    const sink: grpc.Sink = .{ .ctx = &ans, .done = Answers.sink };
    c.start(&slots[0], "/x/Y", "one", sink, 0, null); // stream 1
    c.start(&slots[1], "/x/Y", "two", sink, 1, null); // stream 3
    try ans.waitCount(2, 5000);
    try testing.expectEqual(@as(u32, 0), ans.codes[0].load(.acquire));
    try testing.expectEqualStrings("ok", ans.textOf(0));
    try testing.expectEqual(@as(u32, 14), ans.codes[1].load(.acquire));
    try testing.expectEqualStrings(goaway_text, ans.textOf(1));
    try testing.expect(c.isDraining());
    // a call started after the GOAWAY is answered at once, whether the connection has ended
    // (its last call is done) or not yet
    c.start(&slots[2], "/x/Y", "three", sink, 2, null);
    try testing.expectEqual(@as(u32, 14), ans.codes[2].load(.acquire));
    try testing.expectEqualStrings(goaway_text, ans.textOf(2));
    try waitDead(c, 5000); // it ends by itself with its last call
}

test "GOAWAY: the pool opens the next connection at once and the open call keeps the old one" {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const members = try arena_state.allocator().alloc(cm.Member, 1);
    members[0] = .{ .name = @splat(7), .stake = 10_000 };
    members[0].network_address = "/ip4/127.0.0.1/tcp/1/http";
    members[0].network_key = @splat(0);
    const committee = try cm.Committee.init(arena_state.allocator(), 1, members);
    var pool = try validators.Pool.init(gpa, io, &committee);
    defer pool.deinit();

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try goawayFrame(&script, 1); // and no answer: the call stays open
    var peer: Peer = .{ .script = script.items };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    c.retain(); // ours, past the pool's
    defer {
        waitReaderGone(c) catch {};
        c.unref();
    }
    pool.conns[0] = c;
    var ans: Answers = .{};
    var slot: u32 = 0;
    c.start(&slot, "/x/Y", "one", .{ .ctx = &ans, .done = Answers.sink }, 0, null);
    var i: u32 = 0;
    while (!c.isDraining() and !c.isDead() and i < 5000) : (i += 1) try Io.sleep(io, .fromMilliseconds(1), .awake);
    try testing.expect(c.isDraining() and !c.isDead());
    // no cooldown for a connection the peer closes in an orderly way
    const next = pool.get(0).?;
    defer {
        waitReaderGone(next) catch {};
        next.unref();
    }
    try testing.expect(next != c);
    // the old connection is still there for its open call
    try testing.expect(!c.isDead());
    try testing.expectEqual(@as(u32, 0), ans.count.load(.acquire));
    // and ends once that call is gone
    c.cancel(&slot, 0);
    try waitDead(c, 5000);
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

/// A validator that opens its flow-control windows wide; the `Peer` never reads after its script,
/// so every request byte from then on stays in the kernel's buffers.
fn openWindows(out: *std.ArrayList(u8)) !void {
    try settingsFrame(out, 4, 0x7fff_ffff);
    var wu: [4]u8 = undefined;
    std.mem.writeInt(u32, &wu, 0x7fff_ffff - 65_535, .big);
    try frame(out, 8, 0, 0, &wu);
}

fn waitWindowsOpen(c: *grpc.Conn) !void {
    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        c.mu.lockUncancelable(io);
        const open = c.conn_send_window > 65_535;
        c.mu.unlock(io);
        if (open) return;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

/// Starts calls of `body_len` on a connection until it is dead (a peer that reads would take
/// them all).
const Flood = struct {
    c: *grpc.Conn,
    body_len: usize = 1 << 20,
    slots: [64]u32 = @splat(0),
    started: std.atomic.Value(u32) = .init(0),
    answered: std.atomic.Value(u32) = .init(0),
    unavailable: std.atomic.Value(u32) = .init(0),
    finished: std.atomic.Value(bool) = .init(false),

    fn sink(ctx: *anyopaque, _: u64, r: grpc.Result) void {
        const f: *Flood = @ptrCast(@alignCast(ctx));
        if (r == .status and r.status.code == 14) _ = f.unavailable.fetchAdd(1, .monotonic);
        _ = f.answered.fetchAdd(1, .release);
    }

    fn run(f: *Flood) void {
        defer f.finished.store(true, .release);
        const body = gpa.alloc(u8, f.body_len) catch return;
        defer gpa.free(body);
        @memset(body, 0xab);
        for (&f.slots) |*slot| {
            if (f.c.isDead()) return;
            _ = f.started.fetchAdd(1, .release);
            f.c.start(slot, "/x/Y", body, .{ .ctx = f, .done = sink }, 0, null);
        }
    }

    /// Waits until a `start` has made no progress for 100 ms: its write is stuck.
    fn waitStuck(f: *Flood) !void {
        var last: u32 = 0;
        var still: u32 = 0;
        var i: u32 = 0;
        while (i < 10_000 and !f.finished.load(.acquire)) : (i += 1) {
            const n = f.started.load(.acquire);
            still = if (n == last and n != 0) still + 1 else 0;
            last = n;
            if (still >= 100) return;
            try Io.sleep(io, .fromMilliseconds(1), .awake);
        }
    }

    fn waitFinished(f: *Flood, ms: u32) !bool {
        var i: u32 = 0;
        while (!f.finished.load(.acquire) and i < ms) : (i += 1) try Io.sleep(io, .fromMilliseconds(1), .awake);
        return f.finished.load(.acquire);
    }
};

test "a validator that stops reading fails its calls within the send timeout" {
    const saved = grpc.send_timeout_ns;
    grpc.send_timeout_ns = 500 * std.time.ns_per_ms;
    defer grpc.send_timeout_ns = saved;
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try openWindows(&script);
    var stalled: Peer = .{ .script = script.items, .wait_headers = false };
    try stalled.start();
    var stalled_up = true;
    defer if (stalled_up) stalled.stop();
    // a second validator, which answers
    var reply: std.ArrayList(u8) = .empty;
    defer reply.deinit(gpa);
    try responseHeaders(&reply, false);
    try frame(&reply, 0, 0, 1, &[_]u8{ 0, 0, 0, 0, 2, 'o', 'k' });
    try trailersOk(&reply);
    var healthy: Peer = .{ .script = reply.items };
    try healthy.start();
    defer healthy.stop();
    const c = try plainConn(stalled.port);
    defer c.release();
    const c2 = try plainConn(healthy.port);
    defer c2.release();
    try waitWindowsOpen(c);

    var flood: Flood = .{ .c = c };
    const th = try std.Thread.spawn(.{}, Flood.run, .{&flood});
    try flood.waitStuck();
    // the other validator's connection answers while this one is stuck
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c2, "/x/Y", "body", 5000);
    try testing.expectEqualStrings("ok", r.ok);
    // the stuck write gives up at the send timeout; without one it sits in sendmsg until the
    // peer goes away (stopping the peer lets such a writer return, so the thread always joins)
    const in_time = try flood.waitFinished(5000);
    stalled.stop();
    stalled_up = false;
    joinBounded(th, &flood.finished, "flood");
    try testing.expect(in_time);
    try testing.expect(c.isDead());
    // every call was answered UNAVAILABLE, the one whose write was stuck included
    const n = flood.started.load(.acquire);
    try testing.expect(n >= 1);
    try testing.expectEqual(n, flood.answered.load(.acquire));
    try testing.expectEqual(n, flood.unavailable.load(.acquire));
    const r2 = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 2000);
    try testing.expectEqual(@as(u8, 14), r2.status.code);
}

test "a validator that reads a trickle holds a connection's lock no longer than the section timeout" {
    const saved = .{ grpc.send_timeout_ns, grpc.send_section_timeout_ns };
    // every write gets some bytes through well inside the first; only the second can end it
    grpc.send_timeout_ns = 30 * std.time.ns_per_s;
    grpc.send_section_timeout_ns = 500 * std.time.ns_per_ms;
    defer {
        grpc.send_timeout_ns = saved[0];
        grpc.send_section_timeout_ns = saved[1];
    }
    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(gpa);
    try openWindows(&script);
    var peer: Peer = .{ .script = script.items, .wait_headers = false, .trickle = true };
    try peer.start();
    var peer_up = true;
    defer if (peer_up) peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    try waitWindowsOpen(c);
    // one call of 48 MiB: at 3 MiB/s its one `start` would hold the lock for many seconds
    var flood: Flood = .{ .c = c, .body_len = 48 << 20 };
    const th = try std.Thread.spawn(.{}, Flood.run, .{&flood});
    const in_time = try flood.waitFinished(5000);
    peer.stop();
    peer_up = false;
    joinBounded(th, &flood.finished, "flood");
    try testing.expect(in_time);
    try testing.expect(c.isDead());
    try testing.expectEqual(@as(u32, 1), flood.started.load(.acquire));
    try testing.expectEqual(@as(u32, 1), flood.unavailable.load(.acquire));
}

/// A socket option of a connection, read once it is ready.
fn sockOption(c: *grpc.Conn, level: i32, name: u32) !u32 {
    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        {
            c.mu.lockUncancelable(io);
            defer c.mu.unlock(io);
            if (c.state == .dead) return error.Dead;
            if (c.state == .ready) {
                var v: c_int = 0;
                var len: std.posix.socklen_t = @sizeOf(c_int);
                if (std.posix.errno(std.posix.system.getsockopt(c.stream.?.socket.handle, level, name, std.mem.asBytes(&v), &len)) != .SUCCESS) return error.GetSockOpt;
                return @intCast(v);
            }
        }
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

test "a connection has TCP_NODELAY set" {
    var peer: Peer = .{ .script = "", .wait_headers = false };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    try testing.expect(try sockOption(c, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY) != 0);
}

test "a connection carries the kernel bound on unacknowledged data" {
    var peer: Peer = .{ .script = "", .wait_headers = false };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer c.release();
    switch (@import("builtin").os.tag) {
        .linux => try testing.expectEqual(grpc.tcp_user_timeout_ms, try sockOption(c, std.posix.IPPROTO.TCP, std.posix.TCP.USER_TIMEOUT)),
        .macos => try testing.expectEqual(grpc.tcp_user_timeout_ms / 1000, try sockOption(c, std.posix.IPPROTO.TCP, std.posix.TCP.RXT_CONNDROPTIME)),
        else => {},
    }
}

test "a write that fails while the waiting calls are started answers each of them once" {
    const saved = grpc.send_timeout_ns;
    grpc.send_timeout_ns = 200 * std.time.ns_per_ms;
    defer grpc.send_timeout_ns = saved;
    // The peer accepts and never reads. Two calls wait for the connection, each with an 8 MiB
    // path (headers are outside flow control): starting the first one fills the socket.
    var peer: Peer = .{ .silent = true };
    try peer.start();
    defer peer.stop();
    const path = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(path);
    @memset(path, 'p');
    path[0] = '/';
    const W = struct {
        answers: [2]std.atomic.Value(u32) = @splat(.init(0)),
        unavailable: std.atomic.Value(u32) = .init(0),
        fn sink(ctx: *anyopaque, tag: u64, r: grpc.Result) void {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            if (r == .status and r.status.code == 14) _ = w.unavailable.fetchAdd(1, .monotonic);
            _ = w.answers[tag].fetchAdd(1, .release);
        }
    };
    var w: W = .{};
    var slots: [2]u32 = @splat(0);
    // The calls are put in the queue under the lock while the connection is still connecting
    // (`start` after the unlock could find it ready and not queue at all); a connection that
    // got ready first is dropped and the next one tried.
    var conn: ?*grpc.Conn = null;
    var tries: u32 = 0;
    while (conn == null and tries < 50) : (tries += 1) {
        const c = try plainConn(peer.port);
        c.mu.lockUncancelable(io);
        const connecting = c.state == .connecting;
        if (connecting) for (0..2) |k| {
            try c.queued.append(gpa, .{ .id_slot = &slots[k], .path = try gpa.dupe(u8, path), .body = try gpa.dupe(u8, ""), .sink = .{ .ctx = &w, .done = W.sink }, .tag = k, .opts = .{} });
        };
        c.mu.unlock(io);
        if (connecting) conn = c else releaseAndJoin(c);
    }
    const c = conn orelse return error.SkipZigTest;
    defer releaseAndJoin(c);
    try waitDead(c, 5000);
    try waitReaderGone(c);
    try testing.expectEqual(@as(u32, 1), w.answers[0].load(.acquire));
    try testing.expectEqual(@as(u32, 1), w.answers[1].load(.acquire));
    try testing.expectEqual(@as(u32, 2), w.unavailable.load(.acquire));
}

test "calls started before a connection is ready are held up to a byte limit" {
    const saved = grpc.max_queued_bytes;
    grpc.max_queued_bytes = 16;
    defer grpc.max_queued_bytes = saved;
    var peer: Peer = .{ .silent = true }; // the TLS handshake never ends: the connection stays connecting
    try peer.start();
    defer peer.stop();
    const c = try grpc.Conn.open(gpa, io, .{ .host = "127.0.0.1", .port = peer.port, .security = .{ .pinned = @splat(1) } });
    defer releaseAndJoin(c);
    const W = struct {
        codes: [4]std.atomic.Value(u32) = @splat(.init(0xff)),
        fn sink(ctx: *anyopaque, tag: u64, r: grpc.Result) void {
            const w: *@This() = @ptrCast(@alignCast(ctx));
            w.codes[tag].store(if (r == .status) r.status.code else 0, .release);
        }
    };
    var w: W = .{};
    var slots: [4]u32 = @splat(0);
    const sink: grpc.Sink = .{ .ctx = &w, .done = W.sink };
    c.start(&slots[0], "/x/Y", "12345678", sink, 0, null); // 12 bytes: held
    c.start(&slots[1], "/x/Y", "12345678", sink, 1, null); // 24 in all: over the limit
    try testing.expectEqual(@as(u32, 0xff), w.codes[0].load(.acquire));
    try testing.expectEqual(@as(u32, 14), w.codes[1].load(.acquire));
    c.start(&slots[2], "/x/Y", "", sink, 2, null); // 16: held
    try testing.expectEqual(@as(u32, 0xff), w.codes[2].load(.acquire));
    // a cancelled call gives its bytes back
    c.cancel(&slots[0], 0);
    c.start(&slots[3], "/x/Y", "12345678", sink, 3, null);
    try testing.expectEqual(@as(u32, 0xff), w.codes[3].load(.acquire));
    c.cancel(&slots[2], 2);
    c.cancel(&slots[3], 3);
}

fn waitReaderGone(c: *grpc.Conn) !void {
    var i: u32 = 0;
    while (i < 5000) : (i += 1) {
        c.mu.lockUncancelable(io);
        const gone = c.reader_done;
        c.mu.unlock(io);
        if (gone) return;
        try Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    return error.Timeout;
}

/// Releases a connection and waits for its reader thread. A test that ends while a reader is
/// still connecting leaves it inside `testing.io`, which the test runner tears down after every
/// test (the process then aborts now and then).
fn releaseAndJoin(c: *grpc.Conn) void {
    c.retain();
    c.release();
    waitReaderGone(c) catch {};
    c.unref();
}

fn waitFlag(flag: *const std.atomic.Value(bool), ms: u32) bool {
    var i: u32 = 0;
    while (!flag.load(.acquire) and i < ms) : (i += 1) Io.sleep(io, .fromMilliseconds(1), .awake) catch {};
    return flag.load(.acquire);
}

test "opening a connection never waits behind another connection's lock" {
    var peer: Peer = .{ .silent = true };
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    defer releaseAndJoin(c);
    const T = struct {
        port: u16,
        opened: ?*grpc.Conn = null,
        done: std.atomic.Value(bool) = .init(false),
        fn run(t: *@This()) void {
            // the watchdog's pass comes to the locked connection, then a new one registers
            grpc.watchdog.sweep(io, @intCast(Io.Clock.awake.now(io).nanoseconds));
            t.opened = plainConn(t.port) catch null;
            t.done.store(true, .release);
        }
    };
    var t: T = .{ .port = peer.port };
    // a writer stuck on this connection's socket holds its lock like this
    c.mu.lockUncancelable(io);
    const th = try std.Thread.spawn(.{}, T.run, .{&t});
    const in_time = waitFlag(&t.done, 2000);
    c.mu.unlock(io);
    joinBounded(th, &t.done, "sweep and open");
    if (t.opened) |o| releaseAndJoin(o);
    try testing.expect(in_time);
    try testing.expect(t.opened != null);
}

test "the upstream replaces a dead connection without waiting for its lock" {
    const u = try Upstream.init(gpa, io, .{ .host = "127.0.0.1", .port = 1, .security = .plain });
    defer u.deinit();
    u.cooldown_ns = 0;
    const c1 = u.acquire().?;
    defer c1.unref();
    try waitDead(c1, 5000);
    const T = struct {
        u: *Upstream,
        got: ?*grpc.Conn = null,
        done: std.atomic.Value(bool) = .init(false),
        fn run(t: *@This()) void {
            t.got = t.u.acquire();
            t.done.store(true, .release);
        }
    };
    var t: T = .{ .u = u };
    c1.mu.lockUncancelable(io);
    const th = try std.Thread.spawn(.{}, T.run, .{&t});
    const in_time = waitFlag(&t.done, 2000);
    c1.mu.unlock(io);
    joinBounded(th, &t.done, "upstream acquire");
    // both readers end by themselves (nobody listens on the port); see `releaseAndJoin`
    defer if (t.got) |c| {
        waitReaderGone(c) catch {};
        c.unref();
    };
    waitReaderGone(c1) catch {};
    try testing.expect(in_time);
    try testing.expect(t.got != null and t.got.? != c1);
}

/// A port where a TCP connect gets no answer: a listener nobody accepts on, its backlog full
/// (the kernel then drops the SYNs of further connects).
const BlackHole = struct {
    server: Io.net.Server,
    port: u16,
    fill: [8]?std.posix.socket_t = @splat(null),

    fn open() !BlackHole {
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        var b: BlackHole = .{ .server = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 1 }), .port = 0 };
        b.port = b.server.socket.address.getPort();
        const to = try Io.net.IpAddress.parseIp4("127.0.0.1", b.port);
        for (&b.fill) |*f| f.* = grpc.startConnect(&to) catch null;
        try Io.sleep(io, .fromMilliseconds(100), .awake);
        return b;
    }

    fn close(b: *BlackHole) void {
        for (b.fill) |f| if (f) |fd| {
            _ = std.posix.system.close(fd);
        };
        b.server.deinit(io);
    }
};

test "a connect that gets no answer ends at the connect deadline, its reader thread with it" {
    const saved = grpc.connect_timeout_ns;
    grpc.connect_timeout_ns = 300 * std.time.ns_per_ms;
    grpc.watchdog.paused = true; // the connection keeps the deadline itself
    defer {
        grpc.connect_timeout_ns = saved;
        grpc.watchdog.paused = false;
    }
    var hole = try BlackHole.open();
    var hole_open = true;
    defer if (hole_open) hole.close();
    const c = try plainConn(hole.port);
    defer releaseAndJoin(c);
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 3000);
    const reader_gone = if (waitReaderGone(c)) true else |_| false;
    // closing the listener refuses what is still connecting: a reader that sat in connect(2)
    // with no deadline returns now, and the test can end
    hole.close();
    hole_open = false;
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expectEqualStrings("transport error: connect timeout", r.status.message);
    try testing.expect(reader_gone);
}

test "a TLS handshake that gets no answer ends at the connect deadline without the watchdog" {
    const saved = grpc.connect_timeout_ns;
    grpc.connect_timeout_ns = 300 * std.time.ns_per_ms;
    grpc.watchdog.paused = true;
    defer {
        grpc.connect_timeout_ns = saved;
        grpc.watchdog.paused = false;
    }
    var peer: Peer = .{ .silent = true };
    try peer.start();
    defer peer.stop();
    const c = try grpc.Conn.open(gpa, io, .{ .host = "127.0.0.1", .port = peer.port, .security = .{ .pinned = @splat(1) } });
    defer releaseAndJoin(c);
    var a = std.heap.ArenaAllocator.init(gpa);
    defer a.deinit();
    const r = try grpc.callBlocking(a.allocator(), c, "/x/Y", "body", 3000);
    try testing.expectEqual(@as(u8, 14), r.status.code);
    try testing.expectEqualStrings("transport error: connect timeout", r.status.message);
}

test "a validator whose connections get ready and then drop is redialled with backoff" {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const members = try arena_state.allocator().alloc(cm.Member, 1);
    members[0] = .{ .name = @splat(7), .stake = 10_000 };
    members[0].network_address = "/ip4/127.0.0.1/tcp/1/http"; // nobody listens: the pool's own redials never get ready
    members[0].network_key = @splat(0);
    const committee = try cm.Committee.init(arena_state.allocator(), 1, members);
    var pool = try validators.Pool.init(gpa, io, &committee);
    defer pool.deinit();

    // the wait doubles per failure up to the cap, spread over its last quarter from the first
    // failure on; no failure: the plain cooldown
    const base = pool.reconnect_cooldown;
    const cap = pool.max_reconnect_cooldown;
    try testing.expectEqual(base, pool.cooldown(0, 0, 12345));
    var f: u8 = 1;
    while (f < 12) : (f += 1) {
        const full = @min(base << @intCast(@min(f, 8)), cap);
        const d = pool.cooldown(0, f, 12345);
        try testing.expect(d >= full - full / 4 and d <= full);
        try testing.expectEqual(d, pool.cooldown(0, f, 12345)); // one value per wait
    }
    var differs = false;
    for (1..16) |i| differs = differs or pool.cooldown(@intCast(i), 3, 12345) != pool.cooldown(0, 3, 12345);
    try testing.expect(differs); // members that dropped together are not redialled together
    // the streak: over once a connection held for `stable_ns`
    try testing.expectEqual(@as(u8, 4), pool.streakAfter(3, false, 0));
    try testing.expectEqual(@as(u8, 4), pool.streakAfter(3, true, pool.stable_ns - 1));
    try testing.expectEqual(@as(u8, 0), pool.streakAfter(3, true, pool.stable_ns));

    // and in the pool: a connection that got ready and dropped within milliseconds counts
    var peer: Peer = .{ .wait_headers = false, .close_after = true }; // takes the preface, closes
    try peer.start();
    defer peer.stop();
    const c = try plainConn(peer.port);
    c.retain(); // ours, past the pool's release
    defer {
        waitReaderGone(c) catch {};
        c.unref();
    }
    pool.conns[0] = c;
    try waitDead(c, 5000);
    try testing.expect(c.wasReady());
    pool.reconnect_cooldown = 0; // redial at once
    const next = pool.get(0).?;
    defer {
        waitReaderGone(next) catch {};
        next.unref();
    }
    try testing.expect(next != c);
    try testing.expectEqual(@as(u8, 1), pool.connect_fails[0]);
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
    var srv_stop: std.atomic.Value(bool) = .init(false);
    var srv_exited: std.atomic.Value(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *Io.net.Server, e: *SlowExec, stop: *const std.atomic.Value(bool), exited: *std.atomic.Value(bool)) void {
            defer exited.store(true, .release);
            if (!readable(s.socket.handle, stop)) return; // no client came (the test failed first)
            const st = s.accept(io) catch return;
            h2.serveStream(testing.allocator, io, st, .{}, .{ .ctx = e, .call = SlowExec.call });
        }
    }.run, .{ &server, &slow, &srv_stop, &srv_exited });
    defer joinBounded(t, &srv_exited, "h2 server");
    defer srv_stop.store(true, .release);
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
