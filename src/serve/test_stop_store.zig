//! A graceful stop of the RPC server over a real store, as deepwave's SIGTERM does it
//! (node.zig `drainRpc`: `h2.server.drainThenForce`, then the store close).
//!
//! Three clients are connected when the stop comes: a slow unary call that holds a snapshot of
//! the store across its work, a server stream to a client that stopped reading (the server's
//! thread is blocked in a send), and an idle keep-alive connection. The stop must answer the
//! slow call in full, end the two connections that are not in a call, be rid of every server
//! thread, and only then close the store. The store's use-after-release guard is on
//! (store/guard.zig; every mapping the close releases becomes inaccessible), so a handler that
//! read the store after the close would fault at the read and take the test with it. The
//! reopened store must be the one a clean close leaves.
//!
//! Before `forceClose` existed the stream's connection outlived the drain (its thread sat in
//! the send for up to two minutes), the node took that as "connections still open", flushed the
//! store without closing it, and the next start checked every page of the live table.
const std = @import("std");
const testing = std.testing;
const Atomic = std.atomic.Value;
const store = @import("store");
const h2 = @import("h2/root.zig");

const io = testing.io;
const ms = std.time.ns_per_ms;

const Bed = struct {
    var st: *store.Store = undefined;
    /// Set right before the store is closed: a read begun after it is counted, not made.
    var closed: Atomic(bool) = .init(false);
    var late: Atomic(u32) = .init(0);
    var slow_in: Atomic(bool) = .init(false);
    var slow_out: Atomic(bool) = .init(false);
    var stream_msgs: Atomic(u32) = .init(0);
    var pings: Atomic(u32) = .init(0);
    var dummy: u8 = 0;
    var big: [64 << 10]u8 = @splat('s');
    const id: [32]u8 = @splat(7);

    fn sum(bytes: []const u8) u64 {
        var s: u64 = 0;
        for (bytes) |b| s += b;
        return s;
    }

    /// One read of the store as a handler makes it: a snapshot, the object's bytes through the
    /// mapping, the snapshot released.
    fn read() u64 {
        if (closed.load(.acquire)) {
            _ = late.fetchAdd(1, .monotonic);
            return 0;
        }
        var snap = st.snapshot();
        defer snap.release();
        const o = snap.liveObject(&id) orelse return 0;
        return sum(o.bytes);
    }

    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        if (std.mem.eql(u8, req.path, "/t.S/Slow")) {
            // holds its snapshot across the work, and reads through it at the end
            var snap = st.snapshot();
            defer snap.release();
            const o = snap.liveObject(&id) orelse return .internal;
            slow_in.store(true, .release);
            h2.sock.sleepMs(250);
            if (sum(o.bytes) == 0) return .internal;
            rs.message("done") catch return .internal;
            slow_out.store(true, .release);
            return .ok;
        }
        if (std.mem.eql(u8, req.path, "/t.S/Ping")) {
            _ = read();
            rs.message("pong") catch return .internal;
            _ = pings.fetchAdd(1, .monotonic);
            return .ok;
        }
        if (std.mem.eql(u8, req.path, "/t.S/Stream")) {
            if (!h2.attach(req.stream_id, .{ .ctx = &dummy, .run = run, .wake = wake })) return .unimplemented;
            return .deferred;
        }
        return .unimplemented;
    }

    /// A subscription that never ends by itself: a read of the store, then a message, for ever.
    fn run(_: *anyopaque, link: *h2.Link) void {
        while (true) {
            _ = read();
            link.send(&big) catch return;
            _ = stream_msgs.fetchAdd(1, .monotonic);
        }
    }
    fn wake(_: *anyopaque) void {}
    fn known(_: *anyopaque, path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/t.S/");
    }
    fn compress(_: *anyopaque, _: []const u8) bool {
        return false;
    }
    fn info(_: *anyopaque, out: *h2.meta.Info) void {
        out.* = .{ .chain_id = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S", .chain = "mainnet", .tip = .{ .epoch = 1, .height = 1, .timestamp_ms = 1 }, .lowest = 0, .server = "zui" };
    }
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call, .known = known, .compress = compress, .info = info };
};

fn post(c: std.Io.net.Stream, comptime path: []const u8) !void {
    var wbuf: [256]u8 = undefined;
    var w = c.writer(io, &wbuf);
    try w.interface.writeAll("POST " ++ path ++ " HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00");
    try w.interface.flush();
}

/// Reads until `want` has been seen (or the peer closes, or 10 s pass); what was read.
fn readUntil(c: std.Io.net.Stream, got: *std.ArrayList(u8), want: ?[]const u8) !void {
    var rbuf: [4096]u8 = undefined;
    const t0 = h2.meta.monoNs();
    while (h2.meta.monoNs() - t0 < 10_000 * ms) {
        if (want) |w| if (std.mem.indexOf(u8, got.items, w) != null) return;
        if (!(h2.sock.waitReadableRaw(c.socket.handle, 100) catch return)) continue;
        var iov = [_][]u8{&rbuf};
        const n = c.read(io, &iov) catch return;
        if (n == 0) return;
        try got.appendSlice(testing.allocator, rbuf[0..n]);
    }
}

fn until(comptime cond: fn () bool, limit_ms: u64) bool {
    const t0 = h2.meta.monoNs();
    while (!cond()) {
        if (h2.meta.monoNs() - t0 > limit_ms * ms) return false;
        h2.sock.sleepMs(1);
    }
    return true;
}

test "graceful stop over a store: a slow call, a stream to a client that stopped reading and an idle keep-alive connection are all gone before the store closes; no handler reads it afterwards and the reopen is the clean one" {
    const gpa = testing.allocator;
    // nothing of an earlier test's server is left
    try testing.expect(h2.server.waitDrained(5 * std.time.ns_per_s));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const plen = try tmp.dir.realPath(io, &pb);
    var cfg: store.Config = .{ .max_live_objects = 1 << 12, .max_object_versions = 1 << 12, .max_transactions = 1 << 12, .max_checkpoints = 1 << 12 };
    cfg.dir = pb[0..plen];
    const h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    var store_closed = false;
    // last of all: the store goes only when no server thread is left (below)
    defer if (!store_closed) {
        h.store.deinit();
        h.io.deinit();
    };
    try testing.expect(h.store.uafGuard());
    {
        const b = try h.store.begin(1, 1);
        try b.checkpoint("summary-1", "");
        const payload: [8 << 10]u8 = @splat(0x5a);
        const digest: [32]u8 = @splat(1);
        try b.putObject(&Bed.id, 1, &digest, &payload);
        try h.store.commit(b);
    }
    Bed.st = h.store;
    inline for (.{ &Bed.closed, &Bed.slow_in, &Bed.slow_out }) |f| f.store(false, .release);
    inline for (.{ &Bed.late, &Bed.stream_msgs, &Bed.pings }) |f| f.store(0, .release);

    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .reuse_address = true });
    const port = srv.socket.address.getPort();
    var stop: Atomic(bool) = .init(false);
    var srv_open = true;
    defer if (srv_open) srv.deinit(io);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, flag: *Atomic(bool)) void {
            // the h2 grace: calls in flight get 300 ms
            h2.server.serveBlocking(testing.allocator, testing.io, s, .{ .stop_grace_ns = 300 * ms }, Bed.handler, flag) catch {};
        }
    }.run, .{ &srv, &stop });
    var joined = false;
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    // on any way out: the accept loop ends, and every server thread is gone before the store is
    // (the clients below are closed first, which ends whatever a failed stop left)
    defer {
        stop.store(true, .release);
        if (!joined) {
            if (caddr.connect(io, .{ .mode = .stream })) |x| x.close(io) else |_| {}
            t.join();
        }
        _ = h2.server.forceClose();
        _ = h2.server.waitDrained(20 * std.time.ns_per_s);
    }

    // the three clients
    const slow = try caddr.connect(io, .{ .mode = .stream });
    defer slow.close(io);
    const stream = try caddr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const idle = try caddr.connect(io, .{ .mode = .stream });
    defer idle.close(io);
    try post(idle, "/t.S/Ping");
    var idle_got: std.ArrayList(u8) = .empty;
    defer idle_got.deinit(gpa);
    try readUntil(idle, &idle_got, "grpc-status:0");
    try testing.expect(std.mem.indexOf(u8, idle_got.items, "pong") != null);
    try post(stream, "/t.S/Stream"); // and never a read: the server's sends back up
    try testing.expect(until(struct {
        fn c() bool {
            return Bed.stream_msgs.load(.acquire) > 0;
        }
    }.c, 10_000));
    // blocked: no message has gone out for 300 ms
    var last = Bed.stream_msgs.load(.acquire);
    var quiet: u32 = 0;
    while (quiet < 300) : (quiet += 10) {
        h2.sock.sleepMs(10);
        const now = Bed.stream_msgs.load(.acquire);
        if (now != last) {
            last = now;
            quiet = 0;
        }
    }
    try post(slow, "/t.S/Slow");
    try testing.expect(until(struct {
        fn c() bool {
            return Bed.slow_in.load(.acquire);
        }
    }.c, 10_000));
    try testing.expectEqual(@as(u32, 3), h2.server.stats.conns.load(.acquire));

    // SIGTERM: stop accepting, then the drain (the grace and a poll tick), then the forced
    // close of what is left, with a second for its threads
    stop.store(true, .release);
    if (caddr.connect(io, .{ .mode = .stream })) |x| x.close(io) else |_| {}
    t.join();
    joined = true;
    srv.deinit(io);
    srv_open = false;
    const d = h2.server.drainThenForce(1_500 * ms, 2_000 * ms, null);

    // the call in flight was answered in full
    var slow_got: std.ArrayList(u8) = .empty;
    defer slow_got.deinit(gpa);
    try readUntil(slow, &slow_got, null);
    try testing.expect(Bed.slow_out.load(.acquire));
    try testing.expect(std.mem.indexOf(u8, slow_got.items, "done") != null);
    try testing.expect(std.mem.indexOf(u8, slow_got.items, "grpc-status:0") != null);
    // every server thread is gone: the stream's connection was ended by the server
    try testing.expect(d.drained);
    try testing.expect(d.forced >= 1);
    try testing.expectEqual(@as(u32, 0), h2.server.stats.conns.load(.acquire));
    try testing.expectEqual(@as(u32, 0), h2.server.stats.jobs.load(.acquire));
    try testing.expectEqual(@as(u32, 0), h2.server.stats.pumps.load(.acquire));
    // inside the bound: the drain, plus scheduling time for the forced threads
    try testing.expect(d.waited_ns < 2_500 * ms);

    // the store closes; with the guard on, a read through a mapping from here on would fault
    Bed.closed.store(true, .release);
    store_closed = true;
    {
        defer h.io.deinit();
        try h.store.close();
    }
    h2.sock.sleepMs(200);
    try testing.expectEqual(@as(u32, 0), Bed.late.load(.acquire));

    // the next start: a clean close, no page check of the live table, nothing replayed
    const r = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer {
        r.store.deinit();
        r.io.deinit();
    }
    try testing.expect(r.store.stats.open_clean);
    try testing.expectEqual(@as(u64, 0), r.store.stats.replayed_groups);
    try testing.expectEqual(@as(?u64, 1), r.store.committed());
}

test "forceClose: an idle connection blocked in its poll and one that sent half a request end at once; a server with no connection has nothing to end" {
    try testing.expect(h2.server.waitDrained(5 * std.time.ns_per_s));
    try testing.expectEqual(@as(u32, 0), h2.server.forceClose());
    var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    var srv = try addr.listen(io, .{ .reuse_address = true });
    const port = srv.socket.address.getPort();
    var stop: Atomic(bool) = .init(false);
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server, flag: *Atomic(bool)) void {
            h2.server.serveBlocking(testing.allocator, testing.io, s, .{}, Bed.handler, flag) catch {};
        }
    }.run, .{ &srv, &stop });
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    // on any way out: the accept loop is joined and no connection thread is left
    defer {
        stop.store(true, .release);
        if (caddr.connect(io, .{ .mode = .stream })) |x| x.close(io) else |_| {}
        t.join();
        srv.deinit(io);
        _ = h2.server.waitDrained(20 * std.time.ns_per_s);
    }
    const a = try caddr.connect(io, .{ .mode = .stream });
    defer a.close(io);
    const b = try caddr.connect(io, .{ .mode = .stream });
    defer b.close(io);
    var wbuf: [64]u8 = undefined;
    var w = b.writer(io, &wbuf);
    try w.interface.writeAll("POST /t.S/Ping HTTP/1.1\r\nhost: x\r\ncontent-le");
    try w.interface.flush();
    try testing.expect(until(struct {
        fn c() bool {
            return h2.server.liveCount() == 2;
        }
    }.c, 10_000));
    try testing.expectEqual(@as(u32, 2), h2.server.stats.conns.load(.acquire));
    // no stop flag at all: only the forced close ends them (their idle timeout is 30 s)
    const t0 = h2.meta.monoNs();
    try testing.expectEqual(@as(u32, 2), h2.server.forceClose());
    try testing.expect(h2.server.waitDrained(2 * std.time.ns_per_s));
    try testing.expect(h2.meta.monoNs() - t0 < 1_000 * ms);
}
