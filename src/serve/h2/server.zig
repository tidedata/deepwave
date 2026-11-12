//! The :9000 connection runtime, shaped like sui-node 1.83.1 (sui-http over hyper's auto
//! builder): one port for h2c (prior knowledge) and HTTP/1.1, told apart by the first 24 bytes
//! (the HTTP/2 client preface), thread per connection.
//! - h2c: `Conn` under a per-connection lock; deferred server streams (`pump.attach`) run on
//!   their own threads and write through `Link`; finished pump threads are reaped as the
//!   connection runs, the rest are joined when it ends. Max connection age 4 h, then GOAWAY and
//!   a 10 min grace. Keepalive PINGs are off by default (as in sui-node).
//! - HTTP/1.1: `web.serve` (gRPC-web binary and text, `GET /health`, CORS, 30 s idle close).
//! - Live connection and stream counts are in `stats` (leak checks, metrics).
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const conn_mod = @import("conn.zig");
const Conn = conn_mod.Conn;
const Handler = conn_mod.Handler;
const web = @import("web.zig");
const sock = @import("sock.zig");
const meta = @import("meta.zig");
const pump = @import("pump.zig");
const pool_mod = @import("pool.zig");
const ns_per_s = std.time.ns_per_s;
/// A peer that takes no bytes of a pending reply for this long is dropped (sock.writeAll's limit).
const write_stall_ns: u64 = sock.write_stall_limit * 5 * ns_per_s;

pub const Options = struct {
    h2: conn_mod.Options = .{},
    web: web.Options = .{},
    /// Connections served at once; one more is closed at accept.
    max_connections: u32 = 16384,
    /// sui-http max_connection_age (h2: GOAWAY, then `age_grace_ns`; HTTP/1.1: close after the
    /// response in flight).
    max_age_ns: ?u64 = 4 * 3600 * ns_per_s,
    age_grace_ns: u64 = 10 * 60 * ns_per_s,
    /// h2 keepalive PING interval (null: none, as sui-node) and how long an ack may take.
    keepalive_ns: ?u64 = null,
    keepalive_timeout_ns: u64 = 20 * ns_per_s,
    /// Zero-downtime upgrade (node/handoff.zig): the listener is shared with a successor process.
    /// The accept loop then never blocks in accept(): it polls the listener with a short timeout
    /// and checks `stop` first, so after the stop it takes no connection that belongs to the
    /// successor (and needs no wake-up connection), and a connection accepted in the race with
    /// the stop is served (the drain sends it GOAWAY), not reset.
    poll_accept: bool = false,
    /// Grace for open h2 streams after the server is told to stop.
    stop_grace_ns: u64 = 2 * ns_per_s,
    /// Stack of connection threads (HTTP/1.1 runs handlers on them; rendering a checkpoint
    /// needs a few hundred KiB) and of the h2 worker threads.
    stack_size: usize = 8 << 20,
    /// Stack of pump threads (server streams over h2c).
    pump_stack_size: usize = 2 << 20,
    /// Pump threads running at once, process-wide; a server stream past it ends with
    /// RESOURCE_EXHAUSTED (each pump is an OS thread).
    max_pumps: u32 = 2048,
    /// h2c unary calls run on a fixed worker pool (0: 4 per usable CPU, 16 to 256), not on the
    /// connection thread, so the streams of one connection are served concurrently as tonic
    /// serves them. `inline_unary` keeps them on the connection thread (tests, tools).
    workers: u32 = 0,
    inline_unary: bool = false,
    /// TLS (`--serve-tls`): each accepted connection gets a session from this before the sniff.
    tls: ?sock.Acceptor = null,
};

pub const Stats = struct {
    accepted: Atomic(u64) = .init(0),
    refused: Atomic(u64) = .init(0),
    conns: Atomic(u32) = .init(0),
    h2_conns: Atomic(u32) = .init(0),
    h1_conns: Atomic(u32) = .init(0),
    pumps: Atomic(u32) = .init(0),
    /// Server streams refused at `max_pumps` or for want of a thread.
    pumps_refused: Atomic(u64) = .init(0),
    /// accept() errors survived (per-connection network errors, fd exhaustion).
    accept_errors: Atomic(u64) = .init(0),
    /// h2c unary calls in flight on the worker pool.
    jobs: Atomic(u32) = .init(0),
    /// RST_STREAM frames received, and connections closed with GOAWAY(ENHANCE_YOUR_CALM) for
    /// resetting streams past the limits (conn.zig `max_pending_resets`, `max_reset_running`).
    rst_frames: Atomic(u64) = .init(0),
    reset_closes: Atomic(u64) = .init(0),
    /// Calls a worker took and did not run: the deadline had passed while they waited in the
    /// queue, or nobody was left to answer (stream reset, connection closed).
    jobs_dropped: Atomic(u64) = .init(0),
};

pub var stats: Stats = .{};

/// Accepts connections until `stop` is set (checked between accepts; closing the listener
/// unblocks `accept`) and serves each on its own thread.
pub fn serveBlocking(gpa: std.mem.Allocator, io: Io, server: *Io.net.Server, opts: Options, handler: Handler, stop: *Atomic(bool)) !void {
    while (!stop.load(.acquire)) {
        if (opts.poll_accept) {
            const ready = sock.waitReadableRaw(server.socket.handle, 100) catch false;
            if (!ready) continue;
            if (stop.load(.acquire)) return;
        }
        const stream = server.accept(io) catch |e| {
            const ms = acceptBackoffMs(e) orelse return;
            _ = stats.accept_errors.fetchAdd(1, .monotonic);
            if (stop.load(.acquire)) return;
            sock.sleepMs(ms);
            continue;
        };
        const fd = stream.socket.handle;
        if (stop.load(.acquire) and !opts.poll_accept) {
            sock.close(fd);
            return;
        }
        _ = stats.accepted.fetchAdd(1, .monotonic);
        if (stats.conns.load(.monotonic) >= opts.max_connections) {
            _ = stats.refused.fetchAdd(1, .monotonic);
            sock.close(fd);
            continue;
        }
        spawnConn(gpa, io, fd, opts, handler, stop);
    }
}

/// Graceful stop (deepwave SIGTERM): true once every connection thread has returned, i.e. every
/// in-flight unary call answered, every server stream ended and every socket closed, or false at
/// `timeout_ns`. Call after setting the `stop` flag `serveBlocking` watches: h2 connections send
/// GOAWAY and keep serving their open streams for `Options.stop_grace_ns`, HTTP/1.1 connections
/// close after the response in flight.
pub fn waitDrained(timeout_ns: u64) bool {
    const t0 = meta.monoNs();
    while (true) {
        if (stats.conns.load(.acquire) == 0 and stats.jobs.load(.acquire) == 0 and stats.pumps.load(.acquire) == 0) return true;
        if (meta.monoNs() -| t0 >= timeout_ns) return false;
        sock.sleepMs(5);
    }
}

/// What an accept error means for the accept loop: null stops it (the listener is gone or the
/// task is canceled), otherwise the back-off before the next accept. Everything but a gone
/// listener is about one connection (accept(2): ECONNABORTED, and on Linux the pending network
/// errors of the new socket, EPROTO, ENETDOWN, EHOSTUNREACH, ENETUNREACH, ETIMEDOUT, EPERM,
/// EOPNOTSUPP, "should be treated like EAGAIN") or a passing shortage of descriptors or memory,
/// so the loop keeps accepting, as hyper/sui-http do.
pub fn acceptBackoffMs(e: Io.net.Server.AcceptError) ?u64 {
    return switch (e) {
        error.SocketNotListening, error.Canceled => null,
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => 50,
        error.ConnectionAborted, error.WouldBlock => 0,
        error.NetworkDown, error.BlockedByFirewall, error.ProtocolFailure, error.Unexpected => 5,
    };
}

test "accept errors: only a gone listener stops the loop" {
    try std.testing.expectEqual(@as(?u64, null), acceptBackoffMs(error.SocketNotListening));
    try std.testing.expectEqual(@as(?u64, null), acceptBackoffMs(error.Canceled));
    inline for (.{ error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources }) |e| {
        try std.testing.expectEqual(@as(?u64, 50), acceptBackoffMs(e));
    }
    inline for (.{ error.ConnectionAborted, error.NetworkDown, error.BlockedByFirewall, error.ProtocolFailure, error.Unexpected, error.WouldBlock }) |e| {
        try std.testing.expect(acceptBackoffMs(e) != null);
    }
}

/// Every connection being served, so a stop can end the ones that do not end by themselves
/// (`forceClose`). A node lives on its connection thread's stack for the length of `serveFd`.
const Live = struct {
    fd: std.c.fd_t,
    prev: ?*Live = null,
    next: ?*Live = null,
};
var live_lock: Atomic(bool) = .init(false);
var live_head: ?*Live = null;

fn liveLock() void {
    while (live_lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}

fn liveAdd(n: *Live) void {
    liveLock();
    defer live_lock.store(false, .release);
    n.next = live_head;
    if (live_head) |h| h.prev = n;
    live_head = n;
}

fn liveRemove(n: *Live) void {
    liveLock();
    defer live_lock.store(false, .release);
    if (n.prev) |p| p.next = n.next else live_head = n.next;
    if (n.next) |x| x.prev = n.prev;
}

/// Connections on the list now (each joins it when its thread starts serving it).
pub fn liveCount() u32 {
    liveLock();
    defer live_lock.store(false, .release);
    var n: u32 = 0;
    var it = live_head;
    while (it) |l| : (it = l.next) n += 1;
    return n;
}

/// Ends every connection still open: shuts its socket down both ways, so whatever its thread
/// is blocked in (the poll of an idle connection, a read of half a TLS record, a send to a peer
/// that does not read, the wait for a peer to take the last bytes) returns at once and the
/// thread leaves through its normal close. For the end of a graceful stop, after the drain:
/// until this existed a connection that did not end by itself kept its thread (and the store
/// under it) for up to two minutes, and the node could not close its store. Returns how many
/// connections it ended. A call still running in a handler is not interrupted: its connection
/// waits for it (`waitDrained` says when).
pub fn forceClose() u32 {
    liveLock();
    defer live_lock.store(false, .release);
    var n: u32 = 0;
    var it = live_head;
    // Under the lock a connection takes to leave the list before it closes its descriptor: a
    // number on the list is never one the kernel has since given to someone else.
    while (it) |l| : (it = l.next) {
        sock.shutdown(l.fd);
        n += 1;
    }
    return n;
}

pub const Drained = struct {
    /// Every connection thread, worker call and pump is gone: nothing of the server can touch
    /// what the handlers read.
    drained: bool,
    /// Connections `forceClose` ended (0: all ended by themselves within the drain).
    forced: u32 = 0,
    waited_ns: u64 = 0,
};

/// The end of a graceful stop, after the `stop` flag is set and the accept loops are woken:
/// waits up to `drain_ns` for the connections to end by themselves (h2: GOAWAY, open streams
/// served for `Options.stop_grace_ns`; HTTP/1.1: the response in flight), or until `cut` says
/// to stop waiting (a second signal). Whatever is left is then ended (`forceClose`) and its
/// threads are given `force_ns` to leave. `drained` false after that means a handler is still
/// running a call: the caller must not free what handlers use.
pub fn drainThenForce(drain_ns: u64, force_ns: u64, cut: ?*const fn () bool) Drained {
    const t0 = meta.monoNs();
    while (!waitDrained(20 * std.time.ns_per_ms)) {
        if (meta.monoNs() -| t0 >= drain_ns) break;
        if (cut) |c| if (c()) break;
    } else return .{ .drained = true, .waited_ns = meta.monoNs() -| t0 };
    const forced = forceClose();
    const ok = waitDrained(force_ns);
    return .{ .drained = ok, .forced = forced, .waited_ns = meta.monoNs() -| t0 };
}

fn spawnConn(gpa: std.mem.Allocator, io: Io, fd: std.c.fd_t, opts: Options, handler: Handler, stop: *const Atomic(bool)) void {
    _ = stats.conns.fetchAdd(1, .monotonic);
    const t = std.Thread.spawn(.{ .stack_size = opts.stack_size }, connMain, .{ gpa, io, fd, opts, handler, stop }) catch {
        _ = stats.conns.fetchSub(1, .monotonic);
        sock.close(fd);
        return;
    };
    t.detach();
}

fn connMain(gpa: std.mem.Allocator, io: Io, fd: std.c.fd_t, opts: Options, handler: Handler, stop: *const Atomic(bool)) void {
    defer _ = stats.conns.fetchSub(1, .monotonic);
    serveFd(gpa, io, fd, opts, handler, stop);
}

/// Serves one accepted connection (sniff, then h2c or HTTP/1.1) and closes `fd`.
pub fn serveFd(gpa: std.mem.Allocator, io: Io, fd: std.c.fd_t, opts: Options, handler: Handler, stop: *const Atomic(bool)) void {
    var live: Live = .{ .fd = fd };
    liveAdd(&live);
    // Off the list first, then closed (see `forceClose`).
    defer {
        liveRemove(&live);
        sock.close(fd);
    }
    sock.tune(fd);
    if (opts.tls) |t| {
        const sess = t.accept(t.ctx, fd) orelse return;
        if (!sock.attach(fd, sess)) return sess.vt.deinit(sess.ctx);
    }
    const t0 = meta.monoNs();
    const preface = conn_mod.preface;
    var first: [preface.len]u8 = undefined;
    var n: usize = 0;
    while (n < first.len) {
        if (stop.load(.acquire)) return;
        const ready = sock.waitReadable(fd, 1000) catch return;
        if (!ready) {
            if (meta.monoNs() -| t0 >= opts.web.idle_ns) return;
            continue;
        }
        const r = sock.read(fd, first[n..]) catch return;
        if (r == 0) return;
        n += r;
        if (!std.mem.startsWith(u8, preface, first[0..n])) break;
    }
    const ctl: web.Control = .{ .stop = stop, .close_after_ns = if (opts.max_age_ns) |a| t0 +| a else null };
    if (n == preface.len and std.mem.eql(u8, &first, preface)) {
        _ = stats.h2_conns.fetchAdd(1, .monotonic);
        defer _ = stats.h2_conns.fetchSub(1, .monotonic);
        serveH2(gpa, io, fd, first[0..n], opts, handler, stop, t0);
    } else {
        _ = stats.h1_conns.fetchAdd(1, .monotonic);
        defer _ = stats.h1_conns.fetchSub(1, .monotonic);
        // gRPC-web: the same caller facts as h2 (`conn.Request.peer`)
        var wopts = opts.web;
        sock.peerText(fd, &wopts.peer);
        web.serve(gpa, fd, first[0..n], wopts, handler, ctl);
    }
}

// ---------------------------------------------------------------- h2c

/// Test hook (fault injection, 0 in production): how long a pump thread stalls right after
/// `pump.done` ran, so a late `wake` has a wide window to land in (test_transport.zig's
/// ListPump stress test).
pub var test_stall_after_done_ms: Atomic(u32) = .init(0);

fn stallAfterDone() void {
    const ms = test_stall_after_done_ms.load(.monotonic);
    if (ms != 0) sock.sleepMs(ms);
}

const Attached = struct {
    pump: pump.Pump,
    link: pump.Link,
    thread: ?std.Thread = null,
    done: Atomic(bool) = .init(false),
    /// `pump.done` was called (exactly once: after `run`, or in place of `run`).
    released: bool = false,

    fn release(a: *Attached) void {
        if (a.released) return;
        a.released = true;
        if (a.pump.done) |d| d(a.pump.ctx);
    }
};

const H2 = struct {
    gpa: std.mem.Allocator,
    io: Io,
    fd: std.c.fd_t,
    opts: Options,
    handler: Handler,
    conn: Conn,
    mu: Io.Mutex = .init,
    closed: Atomic(bool) = .init(false),
    /// Unary calls of this connection running on the worker pool; the connection is freed
    /// only once they all returned.
    inflight: Atomic(u32) = .init(0),
    /// Pumps attached and not started yet (their HEADERS are out); started by `startFresh`.
    fresh: std.ArrayList(*Attached) = .empty,
    /// Wakes the connection thread when a worker leaves bytes it could not write (the socket
    /// was full): the connection thread then waits for POLLOUT instead of finding the backlog at
    /// its next read or poll timeout (that was up to 20 ms of added latency per backlogged reply).
    wake: ?sock.Wake = null,
    /// Running or finished pump threads; touched under `mu`.
    pumps: std.ArrayList(*Attached) = .empty,

    /// Writes what the socket takes now; the rest stays queued for the connection thread.
    /// Returns the bytes written. Caller holds `mu`, and nothing ever waits for the peer under
    /// `mu`: workers finishing calls of this connection queue behind it, and the pools are
    /// process-wide, so a few slow readers could otherwise park a whole worker class.
    fn drainSome(h: *H2) usize {
        var total: usize = 0;
        while (h.conn.pending().len > 0) {
            const p = h.conn.pending();
            const n = sock.writeSome(h.fd, p) catch {
                h.closed.store(true, .release);
                return total;
            };
            if (n == 0) return total;
            h.conn.consumed(n);
            total += n;
        }
        // records a TLS session sealed and the socket did not take yet
        if (sock.unsent(h.fd) > 0) _ = sock.writeSome(h.fd, "") catch h.closed.store(true, .release);
        return total;
    }

    /// Bytes are still owed to the peer: queued on the connection or held by a TLS session.
    /// Caller holds `mu`.
    fn owes(h: *H2) bool {
        return h.conn.pending().len > 0 or sock.unsent(h.fd) > 0;
    }

    /// `drainSome` from a thread other than the connection's (a worker, a pump): what the
    /// socket does not take is left to the connection thread, woken to wait for POLLOUT. A
    /// refill at the send bound may have unblocked a pump, which that thread wakes too.
    /// Caller holds `mu`.
    fn kick(h: *H2) void {
        _ = h.drainSome();
        if (h.owes() or h.conn.out_refilled) if (h.wake) |k| k.signal();
    }

    /// The last bytes of a connection that closes in an orderly way (a GOAWAY, the final
    /// trailers): written as the socket takes them, waiting for it outside `mu`, until nothing
    /// is left, the peer takes nothing for `write_stall_ns`, or the socket fails. Connection
    /// thread only; `mu` not held.
    fn lingerOut(h: *H2) void {
        var since = meta.monoNs();
        while (!h.closed.load(.acquire)) {
            h.lock();
            const wrote = h.drainSome();
            const left = h.owes();
            h.unlock();
            if (!left) return;
            const now = meta.monoNs();
            if (wrote > 0) since = now else if (now -| since >= write_stall_ns) return;
            const rdy = sock.waitConn(h.fd, false, true, null, 1000) catch return;
            if (rdy.readable and !rdy.writable) return; // hung up
        }
    }

    fn lock(h: *H2) void {
        h.mu.lockUncancelable(h.io);
    }
    fn unlock(h: *H2) void {
        h.mu.unlock(h.io);
    }

    fn attachFn(ctx: *anyopaque, stream_id: u32, p: pump.Pump) bool {
        const h: *H2 = @ptrCast(@alignCast(ctx));
        return h.attachLocked(stream_id, p);
    }

    /// Queues a pump for `stream_id` and sends the stream's HEADERS. Caller holds `mu`.
    fn attachLocked(h: *H2, stream_id: u32, p: pump.Pump) bool {
        const a = h.gpa.create(Attached) catch return false;
        a.* = .{ .pump = p, .link = .{ .impl = h, .vt = &link_vt, .stream_id = stream_id } };
        h.fresh.append(h.gpa, a) catch {
            h.gpa.destroy(a);
            return false;
        };
        // Response HEADERS go out now; a failure here surfaces on the pump's first send.
        h.conn.open(stream_id) catch {};
        return true;
    }

    fn linkSend(impl: *anyopaque, sid: u32, payload: []const u8) error{Closed}!void {
        const h: *H2 = @ptrCast(@alignCast(impl));
        if (h.closed.load(.acquire)) return error.Closed;
        h.lock();
        defer h.unlock();
        h.conn.push(sid, payload) catch return error.Closed;
        // The pump does not wait for the peer here (it holds `mu`); it waits on `blocked`, which
        // stays true while the stream's bytes are held back by a window or by the send bound.
        h.kick();
        if (h.closed.load(.acquire)) return error.Closed;
    }
    fn linkFinish(impl: *anyopaque, sid: u32, status: conn_mod.Status, text: []const u8, details: []const u8) void {
        const h: *H2 = @ptrCast(@alignCast(impl));
        if (h.closed.load(.acquire)) return;
        h.lock();
        defer h.unlock();
        h.conn.finishDetails(sid, status, text, details) catch return;
        h.kick();
    }
    fn linkBlocked(impl: *anyopaque, sid: u32) ?bool {
        const h: *H2 = @ptrCast(@alignCast(impl));
        if (h.closed.load(.acquire)) return null;
        h.lock();
        defer h.unlock();
        const n = h.conn.unsent(sid) orelse return null;
        return n > 0;
    }
    const link_vt: pump.Link.VTable = .{ .send = linkSend, .finish = linkFinish, .blocked = linkBlocked };

    fn pumpMain(a: *Attached) void {
        defer _ = stats.pumps.fetchSub(1, .monotonic);
        a.pump.run(a.pump.ctx, &a.link);
        // `wakeAll` reads `done` and calls `wake` under `mu`. Marking the pump done under the same
        // lock before `pump.done` (which may free the context: ListPump does) leaves no wake in
        // flight and none to come. Releasing first and marking after let a wake land on freed
        // memory (ListPump.wakeFn SIGSEGV under List* replay with cancels and deadlines).
        const h: *H2 = @ptrCast(@alignCast(a.link.impl));
        h.lock();
        a.done.store(true, .release);
        h.unlock();
        a.release();
        stallAfterDone();
    }

    /// Ends a stream whose pump cannot start and releases the pump. Caller holds `mu`.
    fn refuse(h: *H2, a: *Attached, text: []const u8) void {
        _ = stats.pumps_refused.fetchAdd(1, .monotonic);
        h.conn.finish(a.link.stream_id, .resource_exhausted, text) catch {};
        a.release();
    }

    /// Starts the pumps attached since the last call. Caller holds `mu`.
    fn startFresh(h: *H2) void {
        for (h.fresh.items) |a| {
            h.pumps.append(h.gpa, a) catch {
                // cannot track it: end the stream instead of leaking a thread
                h.refuse(a, "too many streams");
                h.gpa.destroy(a);
                continue;
            };
            // a process-wide reservation, given back when the pump returns
            if (stats.pumps.fetchAdd(1, .monotonic) >= h.opts.max_pumps) {
                _ = stats.pumps.fetchSub(1, .monotonic);
                a.done.store(true, .release);
                h.refuse(a, "too many server streams");
                continue;
            }
            a.thread = std.Thread.spawn(.{ .stack_size = h.opts.pump_stack_size }, pumpMain, .{a}) catch blk: {
                _ = stats.pumps.fetchSub(1, .monotonic);
                a.done.store(true, .release);
                h.refuse(a, "cannot start the stream");
                break :blk null;
            };
        }
        h.fresh.clearRetainingCapacity();
    }

    /// Joins pump threads that returned. Connection thread only.
    fn reap(h: *H2) void {
        var done: std.ArrayList(*Attached) = .empty;
        defer done.deinit(h.gpa);
        h.lock();
        var i: usize = 0;
        while (i < h.pumps.items.len) {
            const a = h.pumps.items[i];
            if (a.done.load(.acquire) and (done.append(h.gpa, a) catch null) != null) {
                _ = h.pumps.swapRemove(i);
            } else i += 1;
        }
        h.unlock();
        for (done.items) |a| {
            if (a.thread) |t| t.join();
            a.release();
            h.gpa.destroy(a);
        }
    }

    fn wakeAll(h: *H2) void {
        h.lock();
        defer h.unlock();
        for (h.pumps.items) |a| if (!a.done.load(.acquire)) a.pump.wake(a.pump.ctx);
    }

    /// Feeds received bytes with this connection as the pump runtime. Returns false when the
    /// connection must close.
    fn feed(h: *H2, bytes: []const u8) bool {
        h.lock();
        defer h.unlock();
        const prev = pump.current;
        pump.current = .{ .ctx = h, .attach = attachFn };
        const rst0 = h.conn.rst_frames;
        const calmed0 = h.conn.calmed;
        const r = h.conn.feed(bytes);
        pump.current = prev;
        if (h.conn.rst_frames != rst0) _ = stats.rst_frames.fetchAdd(h.conn.rst_frames - rst0, .monotonic);
        if (h.conn.calmed and !calmed0) _ = stats.reset_closes.fetchAdd(1, .monotonic);
        // Never block under the lock: what the socket does not take now goes out on POLLOUT.
        _ = h.drainSome();
        // the connection thread wakes its pumps after every read
        h.conn.out_refilled = false;
        h.startFresh();
        if (h.closed.load(.acquire)) return false;
        // (the GOAWAY of a connection error goes out before the close: `lingerOut`)
        if (r) |_| {} else |_| return false;
        return !h.conn.wantsClose();
    }

    /// Queues something on the connection (GOAWAY, PING, expired calls) and writes what the
    /// socket takes now; the loop sends the rest on POLLOUT. False when the connection must
    /// close (the caller lingers on what is left).
    fn control(h: *H2, comptime f: anytype, args: anytype) bool {
        h.lock();
        defer h.unlock();
        @call(.auto, f, .{&h.conn} ++ args) catch return false;
        _ = h.drainSome();
        if (h.closed.load(.acquire)) return false;
        return !h.conn.wantsClose();
    }

    // ---- unary calls on the worker pool ----

    const Work = struct {
        task: pool_mod.Task = .{ .run = runWork },
        h: *H2,
        job: *conn_mod.Job,
    };

    fn submitFn(ctx: *anyopaque, job: *conn_mod.Job) bool {
        const h: *H2 = @ptrCast(@alignCast(ctx));
        const p = pool_mod.getClass(h.io, .{ .workers = h.opts.workers, .stack_size = h.opts.stack_size }, pool_mod.classOf(job.path)) orelse return false;
        const w = h.gpa.create(Work) catch return false;
        w.* = .{ .h = h, .job = job };
        _ = h.inflight.fetchAdd(1, .acq_rel);
        _ = stats.jobs.fetchAdd(1, .monotonic);
        if (!p.submit(&w.task)) {
            _ = stats.jobs.fetchSub(1, .monotonic);
            _ = h.inflight.fetchSub(1, .acq_rel);
            h.gpa.destroy(w);
            return false;
        }
        return true;
    }

    /// Framed messages a worker's handler writes, sent with `Conn.complete`.
    const Buffered = struct {
        gpa: std.mem.Allocator,
        h: *H2,
        out: std.ArrayList(u8) = .empty,
        messages: u32 = 0,
        fn write(impl: *anyopaque, hdr: *const [5]u8, payload: []const u8) anyerror!void {
            const b: *Buffered = @ptrCast(@alignCast(impl));
            try b.out.appendSlice(b.gpa, hdr);
            try b.out.appendSlice(b.gpa, payload);
            b.messages += 1;
        }
        fn cancelled(impl: *anyopaque) bool {
            const b: *Buffered = @ptrCast(@alignCast(impl));
            return b.h.closed.load(.acquire);
        }
        const vt: conn_mod.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };

    /// A handler attaching a pump on a worker: kept until the call returns.
    const WorkAttach = struct {
        pump: ?pump.Pump = null,
        fn attach(ctx: *anyopaque, _: u32, p: pump.Pump) bool {
            const wa: *WorkAttach = @ptrCast(@alignCast(ctx));
            if (wa.pump != null) return false;
            wa.pump = p;
            return true;
        }
    };

    fn runWork(t: *pool_mod.Task) void {
        const w: *Work = @fieldParentPtr("task", t);
        const h = w.h;
        const gpa = h.gpa;
        const job = w.job;
        gpa.destroy(w);
        var buf: Buffered = .{ .gpa = gpa, .h = h };
        defer buf.out.deinit(gpa);
        var rs: conn_mod.ResponseStream = .{ .gpa = gpa, .impl = &buf, .vt = &Buffered.vt, .encoding = job.encoding, .deadline_ns = job.deadline_ns };
        defer rs.release();
        var wa: WorkAttach = .{};
        const req = job.request();
        // A call nobody waits for is not run: its deadline passed while it sat in the queue (it
        // is answered "Timeout expired", by this worker or by `expireJobs`, whichever is first),
        // its stream was reset, or the connection is gone. Under overload the queue used to hold
        // calls until the 60 s deadline answered them and then ran every one of them anyway.
        const drop: ?conn_mod.Status = if (h.closed.load(.acquire)) .cancelled else job.dropped(meta.monoNs());
        var status: conn_mod.Status = undefined;
        if (drop) |why| {
            _ = stats.jobs_dropped.fetchAdd(1, .monotonic);
            status = if (why == .deadline_exceeded) rs.deadlineExceeded() else why;
        } else {
            const prev = pump.current;
            pump.current = .{ .ctx = &wa, .attach = WorkAttach.attach };
            status = h.handler.call(h.handler.ctx, &req, &rs);
            pump.current = prev;
        }
        if (status == .deferred and wa.pump == null) status = .unimplemented;
        {
            h.lock();
            defer h.unlock();
            // (`jobEnded`: the stream forgets the job before it is freed below)
            if (rs.retry_after_ms) |ms| h.conn.retryAfter(job.stream_id, ms);
            const alive = if (h.closed.load(.acquire)) blk: {
                h.conn.jobEnded(job.stream_id);
                break :blk false;
            } else (h.conn.complete(job.stream_id, buf.out.items, buf.messages, status, rs.msg, rs.details_bin) catch false);
            if (wa.pump) |p| {
                if (alive and status == .deferred and h.attachLocked(job.stream_id, p)) {
                    h.startFresh();
                } else if (p.done) |d| d(p.ctx); // never started
            }
            h.kick();
        }
        job.destroy(gpa);
        // What the response still holds goes back now: the reference on a cached frame (`hold`),
        // its owned strings, the buffer. Once the counts below drop, the connection is freed and
        // whoever waited for the server to drain (`waitDrained`, a test, a runner) may take the
        // service, its cache and the allocator down; left to the `defer`s above, the hold was
        // dropped after that.
        rs.release();
        buf.out.clearAndFree(gpa);
        _ = stats.jobs.fetchSub(1, .monotonic);
        // last touch of `h`: the connection may be freed right after
        _ = h.inflight.fetchSub(1, .acq_rel);
    }
};

fn serveH2(gpa: std.mem.Allocator, io: Io, fd: std.c.fd_t, first: []const u8, opts: Options, handler: Handler, stop: *const Atomic(bool), t0: u64) void {
    const h = gpa.create(H2) catch return;
    h.* = .{ .gpa = gpa, .io = io, .fd = fd, .opts = opts, .handler = handler, .conn = Conn.init(gpa, opts.h2, handler) catch {
        gpa.destroy(h);
        return;
    } };
    sock.peerText(fd, &h.conn.peer);
    if (!opts.inline_unary) h.conn.offload = .{ .ctx = h, .submit = H2.submitFn };
    h.wake = sock.Wake.open();
    defer {
        h.closed.store(true, .release);
        // No pump or worker waits in a socket write (they write with `kick`); the shutdown ends
        // the connection for the peer, and `wakeAll` ends the pumps' waits.
        sock.shutdown(fd);
        h.wakeAll();
        // workers finish their call (handlers are finite) and touch `h` one last time
        while (h.inflight.load(.acquire) != 0) sock.sleepMs(1);
        h.lock();
        var pumps = h.pumps;
        h.pumps = .empty;
        h.unlock();
        for (pumps.items) |a| {
            if (a.thread) |t| t.join();
            a.release();
            gpa.destroy(a);
        }
        pumps.deinit(gpa);
        for (h.fresh.items) |a| {
            a.release();
            gpa.destroy(a);
        }
        h.fresh.deinit(gpa);
        h.conn.deinit();
        if (h.wake) |k| k.close();
        gpa.destroy(h);
    }
    if (!h.feed(first)) return h.lingerOut();
    var stall_since: ?u64 = null;
    var rbuf: [16384]u8 = undefined;
    var drain_deadline: ?u64 = null;
    var next_ping: ?u64 = if (opts.keepalive_ns) |k| t0 +| k else null;
    var ping_deadline: ?u64 = null;
    var ping_seq: u64 = 0;
    while (true) {
        // Bytes the socket did not take (a worker's reply, a big frame) are written here as soon
        // as it is writable; a peer that takes nothing for `write_stall_ns` is dropped.
        h.lock();
        const wrote = h.drainSome();
        const backlog = h.owes();
        const pumps_live = h.pumps.items.len > 0;
        // At the send bound (conn.zig `max_out_bytes`) nothing more is read from the peer: its
        // requests wait in the socket (TCP pushes back) until it takes some of what it is owed.
        const over = h.conn.outFull();
        const refilled = h.conn.out_refilled;
        h.conn.out_refilled = false;
        h.unlock();
        if (h.closed.load(.acquire)) return;
        // stream bytes held back at the bound moved on: a pump waiting on `blocked` may go on
        if (refilled) h.wakeAll();
        if (!backlog or wrote > 0) {
            stall_since = null;
        } else if (stall_since) |s0| {
            if (meta.monoNs() -| s0 >= write_stall_ns) return;
        } else stall_since = meta.monoNs();
        // With a wake fd, workers and pumps signal their backlog; without one, poll often while
        // they run.
        var timeout: i32 = if (h.wake != null or (h.inflight.load(.acquire) == 0 and !pumps_live)) 1000 else 20;
        // A call on a worker is answered DEADLINE_EXCEEDED at its deadline, not at the next wake.
        if (h.inflight.load(.acquire) > 0) if (h.conn.next_job_deadline) |d| {
            const left_ms = (d -| meta.monoNs()) / std.time.ns_per_ms + 1;
            timeout = @intCast(@min(@as(u64, @intCast(timeout)), left_ms));
        };
        const rdy = sock.waitConn(fd, !over, backlog, h.wake, timeout) catch return;
        if (rdy.woken) h.wake.?.clear();
        const now = meta.monoNs();
        if (rdy.readable) {
            const n = sock.read(fd, &rbuf) catch return;
            if (n == 0) return;
            const keep = h.feed(rbuf[0..n]);
            h.reap();
            h.wakeAll();
            if (!keep) return h.lingerOut();
        } else {
            h.reap();
            h.lock();
            const done = h.conn.wantsClose();
            h.unlock();
            if (done) return h.lingerOut();
        }
        // server timeout (sui-http GrpcTimeout) for unary calls running on workers
        if (h.inflight.load(.acquire) > 0) {
            if (!h.control(Conn.expireJobs, .{now})) return h.lingerOut();
        }
        // graceful close: server stop, then max connection age
        if (drain_deadline == null) {
            if (stop.load(.acquire)) {
                if (!h.control(Conn.drain, .{})) return h.lingerOut();
                drain_deadline = now +| opts.stop_grace_ns;
            } else if (opts.max_age_ns) |age| if (now -| t0 >= age) {
                if (!h.control(Conn.drain, .{})) return h.lingerOut();
                drain_deadline = now +| opts.age_grace_ns;
            };
        } else if (now >= drain_deadline.?) return;
        // keepalive
        if (ping_deadline) |d| {
            h.lock();
            const acked = h.conn.ping_acked;
            h.unlock();
            if (acked) {
                ping_deadline = null;
            } else if (now >= d) return;
        }
        if (next_ping) |np| if (now >= np) {
            ping_seq += 1;
            if (!h.control(Conn.ping, .{ping_seq})) return h.lingerOut();
            ping_deadline = now +| opts.keepalive_timeout_ns;
            next_ping = now +| opts.keepalive_ns.?;
        };
    }
}

/// `serveStream` with the full runtime options (tests: `max_pumps`, `inline_unary`).
pub fn serveStreamOpts(gpa: std.mem.Allocator, io: Io, stream: Io.net.Stream, opts: Options, handler: Handler) void {
    const never: Atomic(bool) = .init(false);
    serveFd(gpa, io, stream.socket.handle, opts, handler, &never);
}

/// Serves one accepted `Io.net.Stream` (tools and tests): sniff, then h2c or HTTP/1.1.
pub fn serveStream(gpa: std.mem.Allocator, io: Io, stream: Io.net.Stream, opts: conn_mod.Options, handler: Handler) void {
    const never: Atomic(bool) = .init(false);
    serveFd(gpa, io, stream.socket.handle, .{ .h2 = opts }, handler, &never);
}
