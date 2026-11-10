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
    /// h2c unary calls run on a fixed worker pool (0: 4 per CPU, 16 to 256), not on the
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
    defer sock.close(fd);
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
        web.serve(gpa, fd, first[0..n], opts.web, handler, ctl);
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

    /// Writes everything the connection has queued. Caller holds `mu`.
    fn drain(h: *H2) !void {
        while (h.conn.pending().len > 0) {
            const p = h.conn.pending();
            try sock.writeAll(h.fd, p);
            h.conn.consumed(p.len);
        }
    }

    /// Writes what the socket takes now; the rest stays queued for the connection thread
    /// (workers must not wait on a slow reader). Returns the bytes written. Caller holds `mu`.
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
        return total;
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
        h.drain() catch {
            h.closed.store(true, .release);
            return error.Closed;
        };
    }
    fn linkFinish(impl: *anyopaque, sid: u32, status: conn_mod.Status, text: []const u8, details: []const u8) void {
        const h: *H2 = @ptrCast(@alignCast(impl));
        if (h.closed.load(.acquire)) return;
        h.lock();
        defer h.unlock();
        h.conn.finishDetails(sid, status, text, details) catch return;
        h.drain() catch h.closed.store(true, .release);
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
        const r = h.conn.feed(bytes);
        pump.current = prev;
        // Never block under the lock: what the socket does not take now goes out on POLLOUT.
        _ = h.drainSome();
        h.startFresh();
        if (h.closed.load(.acquire)) return false;
        if (r) |_| {} else |_| {
            h.drain() catch {}; // the GOAWAY goes out before the close
            return false;
        }
        if (h.conn.wantsClose()) {
            h.drain() catch {};
            return false;
        }
        return true;
    }

    /// Queues something on the connection (GOAWAY, PING) and writes it. False when the
    /// connection must close.
    fn control(h: *H2, comptime f: anytype, args: anytype) bool {
        h.lock();
        defer h.unlock();
        @call(.auto, f, .{&h.conn} ++ args) catch return false;
        h.drain() catch return false;
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
        const prev = pump.current;
        pump.current = .{ .ctx = &wa, .attach = WorkAttach.attach };
        var status = h.handler.call(h.handler.ctx, &req, &rs);
        pump.current = prev;
        if (status == .deferred and wa.pump == null) status = .unimplemented;
        {
            h.lock();
            defer h.unlock();
            const alive = !h.closed.load(.acquire) and (h.conn.complete(job.stream_id, buf.out.items, buf.messages, status, rs.msg, rs.details_bin) catch false);
            if (wa.pump) |p| {
                if (alive and status == .deferred and h.attachLocked(job.stream_id, p)) {
                    h.startFresh();
                } else if (p.done) |d| d(p.ctx); // never started
            }
            _ = h.drainSome();
            if (h.conn.pending().len > 0) if (h.wake) |k| k.signal();
        }
        job.destroy(gpa);
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
    if (!opts.inline_unary) h.conn.offload = .{ .ctx = h, .submit = H2.submitFn };
    h.wake = sock.Wake.open();
    defer {
        h.closed.store(true, .release);
        // A pump or worker blocked in a socket write returns once the socket is shut down.
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
    if (!h.feed(first)) return;
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
        const backlog = h.conn.pending().len > 0;
        h.unlock();
        if (h.closed.load(.acquire)) return;
        if (!backlog or wrote > 0) {
            stall_since = null;
        } else if (stall_since) |s0| {
            if (meta.monoNs() -| s0 >= write_stall_ns) return;
        } else stall_since = meta.monoNs();
        // With a wake fd, workers signal their backlog; without one, poll often while they run.
        var timeout: i32 = if (h.wake != null or h.inflight.load(.acquire) == 0) 1000 else 20;
        // A call on a worker is answered DEADLINE_EXCEEDED at its deadline, not at the next wake.
        if (h.inflight.load(.acquire) > 0) if (h.conn.next_job_deadline) |d| {
            const left_ms = (d -| meta.monoNs()) / std.time.ns_per_ms + 1;
            timeout = @intCast(@min(@as(u64, @intCast(timeout)), left_ms));
        };
        const rdy = sock.waitConn(fd, backlog, h.wake, timeout) catch return;
        if (rdy.woken) h.wake.?.clear();
        const now = meta.monoNs();
        if (rdy.readable) {
            const n = sock.read(fd, &rbuf) catch return;
            if (n == 0) return;
            const keep = h.feed(rbuf[0..n]);
            h.reap();
            h.wakeAll();
            if (!keep) return;
        } else {
            h.reap();
            h.lock();
            const done = h.conn.wantsClose();
            h.unlock();
            if (done) return;
        }
        // server timeout (sui-http GrpcTimeout) for unary calls running on workers
        if (h.inflight.load(.acquire) > 0) {
            if (!h.control(Conn.expireJobs, .{now})) return;
        }
        // graceful close: server stop, then max connection age
        if (drain_deadline == null) {
            if (stop.load(.acquire)) {
                if (!h.control(Conn.drain, .{})) return;
                drain_deadline = now +| opts.stop_grace_ns;
            } else if (opts.max_age_ns) |age| if (now -| t0 >= age) {
                if (!h.control(Conn.drain, .{})) return;
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
            if (!h.control(Conn.ping, .{ping_seq})) return;
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
