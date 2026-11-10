//! Time limits and TLS clock refresh for the node's HTTP clients (stream.zig, http.zig).
//!
//! std.http in zig 0.17.1 has no read timeout, and its connect timeout is not wired (Client.zig
//! `connectTcpOptions` ignores `timeout`; Io.Threaded `netConnectIpPosix` panics on one). A
//! connection whose peer vanished without a FIN or RST (a network blip longer than the front end's
//! idle cut) then blocks a reader forever, and a thread that joins it hangs with it.
//!
//! `timed` runs one blocking step (connect + TLS handshake + request, one stream frame, one GET) on
//! an Io worker thread and waits at most `timeout_ms` for it, or until a stop flag turns true. On
//! expiry it cancels the step: Io.Threaded interrupts the blocked syscall (connect, recvmsg, send)
//! with SIG.IO and the step returns `error.Canceled` through its own error paths, which close the
//! connection. So every network wait in the node is bounded, and shutdown never waits on a socket.
//!
//! `Client` wraps std.http.Client for one thread at a time and keeps its TLS clock fresh:
//! std.http.Client reads the time once (`client.now`, at the first HTTPS request) and checks every
//! later certificate against that instant, so a certificate issued after the process started
//! (`not_before` > `now`: CertificateNotYetValid) fails every new connection until a restart, and
//! an expired one is still accepted. `prepare` clears `now` every `refresh_ms` (the next request
//! rereads the clock and rescans the CA bundle), `noteError` clears it after a TLS failure.
const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Atomic = std.atomic.Value;

pub const TimedError = error{ Timeout, Stopped };

fn ReturnOf(comptime f: type) type {
    return @typeInfo(f).@"fn".return_type.?;
}

/// `func`'s error union with `TimedError` added.
pub fn Timed(comptime F: type) type {
    const eu = @typeInfo(ReturnOf(F)).error_union;
    return (eu.error_set || TimedError)!eu.payload;
}

/// The socket a step is blocked on, so an expired wait can wake it without relying on the
/// step's cancelation alone. Io.Threaded delivers a cancel request to the next cancelation point
/// only, and std swallows one in places (HostName.connect's `connect_many.cancel(io) catch {}`):
/// a request that lands there leaves the step to block in its next read with no further signal
/// (seen in the unit tests: a GET stopped at once hung in receiveHead). So the step registers its
/// connection's socket (`arm`) as soon as it exists, and the waiter, on expiry, marks the abort
/// and shuts the socket down (`fire`): a blocked read or write then returns at once. Whichever
/// of `arm` and `fire` comes second sees the other. The spin lock keeps `fire` from shutting
/// down a descriptor the step has closed and the kernel reused.
pub const Abort = struct {
    aborted: Atomic(bool) = .init(false),
    fd: ?std.posix.socket_t = null,
    lock: Atomic(bool) = .init(false),

    fn acquire(a: *Abort) void {
        while (a.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    fn release(a: *Abort) void {
        a.lock.store(false, .release);
    }

    /// Step side, right after the connection exists: registers its socket, or fails with
    /// `error.Canceled` when the wait already ended.
    pub fn arm(a: *Abort, fd: std.posix.socket_t) error{Canceled}!void {
        a.acquire();
        a.fd = fd;
        a.release();
        if (a.aborted.load(.seq_cst)) {
            a.disarm();
            return error.Canceled;
        }
    }

    /// Step side, before the socket is closed or handed back to a pool.
    pub fn disarm(a: *Abort) void {
        a.acquire();
        a.fd = null;
        a.release();
    }

    /// Waiter side: the wait expired.
    pub fn fire(a: *Abort) void {
        a.aborted.store(true, .seq_cst);
        a.acquire();
        defer a.release();
        if (a.fd) |fd| shutdownSocket(fd);
    }

    /// For the next step (no step may be running).
    pub fn reset(a: *Abort) void {
        a.aborted.store(false, .seq_cst);
        a.fd = null;
    }
};

/// The socket under a std.http connection.
pub fn socketOf(conn: *std.http.Client.Connection) std.posix.socket_t {
    return conn.stream_reader.stream.socket.handle;
}

fn shutdownSocket(fd: std.posix.socket_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.shutdown(fd, std.os.linux.SHUT.RDWR);
    } else {
        _ = std.c.shutdown(fd, std.c.SHUT.RDWR);
    }
}

fn timer(io: Io, ms: u64, stop: ?*const Atomic(bool)) void {
    var left = ms;
    while (left > 0) {
        if (stop) |s| if (s.load(.acquire)) return;
        const d = @min(left, 100);
        io.sleep(.fromMilliseconds(@intCast(d)), .awake) catch return; // canceled: the step finished
        left -= d;
    }
}

/// Runs `func(args)` on an Io worker thread and waits for it at most `timeout_ms`, or until
/// `stop.*` is true (checked every 100 ms). On expiry `abort` fires (when the step registered its
/// socket there, a blocked read returns at once) and the step is canceled; this returns
/// `error.Timeout` (`error.Stopped` when `stop` ended it) once the step has unwound; a step that
/// finished in the same instant keeps its result (so nothing it returned leaks). Without a free
/// unit of concurrency it runs `func` inline, unbounded, as before.
///
/// The caller must not touch what `args` point to until this returns (the step owns them).
pub fn timed(io: Io, timeout_ms: u64, stop: ?*const Atomic(bool), abort: ?*Abort, comptime func: anytype, args: std.meta.ArgsTuple(@TypeOf(func))) Timed(@TypeOf(func)) {
    const R = ReturnOf(@TypeOf(func));
    const U = union(enum) { done: R, timer: void };
    var buf: [2]U = undefined;
    var sel: Io.Select(U) = .init(io, &buf);
    sel.concurrent(.done, func, args) catch return @call(.auto, func, args);
    sel.concurrent(.timer, timer, .{ io, timeout_ms, stop }) catch {
        // No unit of concurrency left for the timer: wait for the step without a limit.
        while (true) {
            const u = sel.await() catch continue;
            switch (u) {
                .done => |r| return r,
                .timer => {},
            }
        }
    };
    if (sel.await()) |u| switch (u) {
        .done => |r| {
            sel.cancelDiscard(); // the timer
            return r;
        },
        .timer => {},
    } else |_| {}
    // Expired or stopping: wake the step's socket, cancel the step (interrupts its blocking
    // syscall) and wait for it.
    if (abort) |a| a.fire();
    var late: ?R = null;
    while (sel.cancel()) |u| switch (u) {
        .done => |r| late = r,
        .timer => {},
    };
    if (late) |r| if (r) |v| return v else |_| {};
    if (stop) |s| if (s.load(.acquire)) return error.Stopped;
    return error.Timeout;
}

/// A std.http.Client used by one thread at a time (a stream worker, or one slot of the bucket
/// client pool), with a TLS clock that does not freeze.
pub const Client = struct {
    http: std.http.Client,
    /// Wall clock ms when `http.now` was last cleared or first set (0: never).
    clock_ms: u64 = 0,
    /// TLS clock refreshes per client (diagnostics).
    refreshes: u64 = 0,
    /// Wall clock ms when the last request on this client ended (`done`; 0: never, or a user
    /// that does not call `done`, so its pool is never aged).
    last_ms: u64 = 0,
    /// Idle keep-alive connections are dropped before a request that comes this long after the
    /// last one: servers close idle connections (Google's front end, S3) and std.http hands a
    /// closed one back from its pool; a write to it fails and std returns it to the pool again
    /// (see `dropPool`). Below every server keep-alive we use; 0: never.
    idle_ms: u64 = default_idle_ms,
    /// Pool drops (idle age or a failed request), diagnostics.
    drops: u64 = 0,

    pub const default_idle_ms: u64 = 30_000;

    /// How long one TLS clock (and CA bundle) is used: certificates are checked against a time at
    /// most this old. A rescan reads the system CA bundle (a few ms).
    pub const refresh_ms: u64 = 10 * 60_000;

    pub fn init(gpa: std.mem.Allocator, io: Io) Client {
        return .{ .http = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(c: *Client) void {
        c.http.deinit();
    }

    /// Call before each request, with the wall clock in ms. Clears a TLS clock older than
    /// `refresh_ms`, so the request rereads it. Safe only while no request on this client runs on
    /// another thread (std reads `now` without a lock in the handshake).
    pub fn prepare(c: *Client, now_ms: u64) void {
        if (c.idle_ms != 0 and c.last_ms != 0 and now_ms -| c.last_ms >= c.idle_ms) c.dropPool();
        if (c.http.now == null or c.clock_ms == 0) {
            c.clock_ms = now_ms;
            return;
        }
        if (now_ms -| c.clock_ms >= refresh_ms) c.reset(now_ms);
    }

    /// Call with any request error: a TLS failure (std folds certificate errors into
    /// TlsInitializationFailed) clears the clock and CA bundle, so a certificate rotated after
    /// the last scan is checked against the current time on the next attempt.
    pub fn noteError(c: *Client, err: anyerror, now_ms: u64) void {
        switch (err) {
            error.TlsInitializationFailed, error.CertificateBundleLoadFailure => c.reset(now_ms),
            else => {},
        }
    }

    /// Call when a request ends (ok or not), with the wall clock in ms: starts the idle age.
    pub fn done(c: *Client, now_ms: u64) void {
        c.last_ms = now_ms;
    }

    /// Closes every idle pooled connection (the next request connects afresh).
    pub fn dropPool(c: *Client) void {
        dropIdle(&c.http);
        c.drops += 1;
    }

    fn reset(c: *Client, now_ms: u64) void {
        c.http.now = null;
        c.clock_ms = now_ms;
        c.refreshes += 1;
    }
};

/// Closes `c`'s idle pooled connections and keeps its pool size. std.http (0.17.1) returns a
/// connection whose request failed in `sendBodiless` (error.WriteFailed: the server closed it
/// while it sat in the pool) to the pool as reusable: `Request.deinit` marks a connection closing
/// only when the response was being read. `findConnection` takes the newest free connection, so
/// every retry on that client got the same dead socket and failed the same way (the train/4
/// rehearsal: WriteFailed for minutes after a 107-minute restore). Call it before a retry.
pub fn dropIdle(c: *std.http.Client) void {
    const pool = &c.connection_pool;
    const keep = pool.free_size;
    pool.resize(c.io, 0) catch return;
    pool.resize(c.io, keep) catch {};
}

pub fn wallMs() u64 {
    var ts: std.posix.timespec = undefined;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    } else {
        _ = std.c.clock_gettime(.REALTIME, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

/// A local TCP server for the tests: accepts connections and answers each with `reply` (null:
/// reads the request and then sends nothing, a peer that went silent), counting accepts.
pub const TestServer = struct {
    io: Io,
    server: Io.net.Server,
    port: u16,
    reply: ?[]const u8,
    /// Keep the connection open after the reply (a stream head, then silence).
    hold: bool = false,
    accepts: Atomic(u32) = .init(0),
    stopping: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Connections a silent server holds open (closed at `stop`).
    held: [64]?Io.net.Stream = @splat(null),
    /// Keep-alive mode (`startKeepAlive`): answer every request on a connection with `reply` and
    /// reset the connection once it has been idle this long, as a server's keep-alive cut does.
    idle_close_ms: u32 = 0,
    /// Keep-alive mode: requests answered, and idle connections reset.
    requests: Atomic(u32) = .init(0),
    resets: Atomic(u32) = .init(0),

    pub fn start(t: *TestServer, io: Io, reply: ?[]const u8) !void {
        return t.startOpts(io, reply, false);
    }

    pub fn startOpts(t: *TestServer, io: Io, reply: ?[]const u8, hold: bool) !void {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        t.* = .{ .io = io, .server = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .reply = reply, .hold = hold };
        t.port = t.server.socket.address.getPort();
        t.thread = try std.Thread.spawn(.{}, loop, .{t});
    }

    /// Keep-alive server: one connection at a time, each request answered with `reply` (which
    /// must not say `connection: close`), the connection reset (SO_LINGER 0) after
    /// `idle_close_ms` without a request.
    pub fn startKeepAlive(t: *TestServer, io: Io, reply: []const u8, idle_close_ms: u32) !void {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        t.* = .{ .io = io, .server = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .reply = reply, .idle_close_ms = idle_close_ms };
        t.port = t.server.socket.address.getPort();
        t.thread = try std.Thread.spawn(.{}, loop, .{t});
    }

    fn serveKeepAlive(t: *TestServer, s: Io.net.Stream, reply: []const u8) void {
        defer s.close(t.io);
        while (!t.stopping.load(.acquire)) {
            var pfd = [_]std.posix.pollfd{.{ .fd = s.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
            const r = std.posix.poll(&pfd, @intCast(t.idle_close_ms)) catch return;
            if (t.stopping.load(.acquire)) return;
            if (r == 0) {
                const lg: extern struct { onoff: c_int, linger: c_int } = .{ .onoff = 1, .linger = 0 };
                std.posix.setsockopt(s.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&lg)) catch {};
                _ = t.resets.fetchAdd(1, .acq_rel);
                return;
            }
            if (!readRequest(t.io, s)) return;
            _ = t.requests.fetchAdd(1, .acq_rel);
            var wbuf: [256]u8 = undefined;
            var w = s.writer(t.io, &wbuf);
            w.interface.writeAll(reply) catch return;
            w.interface.flush() catch return;
        }
    }

    fn loop(t: *TestServer) void {
        while (true) {
            const s = t.server.accept(t.io) catch return;
            if (t.stopping.load(.acquire)) {
                s.close(t.io);
                return;
            }
            const n = t.accepts.fetchAdd(1, .acq_rel);
            if (t.idle_close_ms != 0) {
                t.serveKeepAlive(s, t.reply.?);
            } else if (t.reply) |r| {
                _ = readRequest(t.io, s);
                var wbuf: [256]u8 = undefined;
                var w = s.writer(t.io, &wbuf);
                w.interface.writeAll(r) catch {};
                w.interface.flush() catch {};
                if (t.hold and n < t.held.len) t.held[n] = s else s.close(t.io);
            } else if (n < t.held.len) {
                t.held[n] = s;
            } else s.close(t.io);
        }
    }

    /// Reads one request (head, then a content-length body) so closing after the reply sends a
    /// FIN, not an RST over unread bytes.
    /// True when a whole request was read (false: the peer closed or the read failed).
    fn readRequest(io: Io, s: Io.net.Stream) bool {
        var rbuf: [8192]u8 = undefined;
        var have: usize = 0;
        while (have < rbuf.len) {
            var iov = [_][]u8{rbuf[have..]};
            const k = s.read(io, &iov) catch return false;
            if (k == 0) return false;
            have += k;
            const end = std.mem.indexOf(u8, rbuf[0..have], "\r\n\r\n") orelse continue;
            var want: usize = end + 4;
            var it = std.mem.splitSequence(u8, rbuf[0..end], "\r\n");
            while (it.next()) |line| {
                const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                if (std.ascii.eqlIgnoreCase(line[0..colon], "content-length"))
                    want += std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch 0;
            }
            if (have >= want) return true;
        }
        return false;
    }

    pub fn url(t: *const TestServer, buf: []u8) []const u8 {
        return std.fmt.bufPrint(buf, "http://127.0.0.1:{d}", .{t.port}) catch unreachable;
    }

    pub fn stop(t: *TestServer) void {
        t.stopping.store(true, .release);
        // Wake the accept with a connection of our own.
        const addr = Io.net.IpAddress.parse("127.0.0.1", t.port) catch unreachable;
        if (addr.connect(t.io, .{ .mode = .stream })) |s| s.close(t.io) else |_| {}
        if (t.thread) |th| th.join();
        for (&t.held) |*h| if (h.*) |s| {
            s.close(t.io);
            h.* = null;
        };
        t.server.deinit(t.io);
    }
};

fn sleepy(io: Io, ms: u64) error{Canceled}!u64 {
    try io.sleep(.fromMilliseconds(@intCast(ms)), .awake);
    return ms;
}

test "timed: returns the step's result, or Timeout after the limit" {
    const io = std.testing.io;
    try std.testing.expectEqual(@as(u64, 5), try timed(io, 2000, null, null, sleepy, .{ io, 5 }));
    const t0 = wallMs();
    try std.testing.expectError(error.Timeout, timed(io, 150, null, null, sleepy, .{ io, 60_000 }));
    try std.testing.expect(wallMs() - t0 < 2000);
    var stop: Atomic(bool) = .init(true);
    try std.testing.expectError(error.Stopped, timed(io, 60_000, &stop, null, sleepy, .{ io, 60_000 }));
}

fn readOne(io: Io, s: Io.net.Stream) !usize {
    var buf: [16]u8 = undefined;
    var iov = [_][]u8{&buf};
    return s.read(io, &iov);
}

test "timed: a read from a peer that never sends is interrupted" {
    const io = std.testing.io;
    var srv: TestServer = undefined;
    try srv.start(io, null);
    defer srv.stop();
    const addr = try Io.net.IpAddress.parse("127.0.0.1", srv.port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    const t0 = wallMs();
    try std.testing.expectError(error.Timeout, timed(io, 200, null, null, readOne, .{ io, s }));
    try std.testing.expect(wallMs() - t0 < 3000);
}

test "Client: the TLS clock is refreshed when stale and after a TLS failure" {
    var c = Client.init(std.testing.allocator, std.testing.io);
    defer c.deinit();
    // A clock frozen at an old instant (what std does at the first request).
    c.http.now = .{ .nanoseconds = 1_600_000_000 * std.time.ns_per_s };
    c.prepare(1_000_000);
    try std.testing.expect(c.http.now != null); // first sight: start the age
    c.prepare(1_000_000 + Client.refresh_ms - 1);
    try std.testing.expect(c.http.now != null);
    c.prepare(1_000_000 + Client.refresh_ms);
    try std.testing.expect(c.http.now == null); // the next request rereads the time
    try std.testing.expectEqual(@as(u64, 1), c.refreshes);
    c.http.now = .{ .nanoseconds = 1_600_000_000 * std.time.ns_per_s };
    c.noteError(error.ConnectionResetByPeer, 2_000_000);
    try std.testing.expect(c.http.now != null);
    c.noteError(error.TlsInitializationFailed, 2_000_000);
    try std.testing.expect(c.http.now == null);
}

fn readArmed(io: Io, s: Io.net.Stream, a: *Abort) !usize {
    try a.arm(s.socket.handle);
    defer a.disarm();
    // Protected from cancelation, as if a cancel request had been swallowed: only `fire` can
    // wake this read.
    const old = io.swapCancelProtection(.blocked);
    defer _ = io.swapCancelProtection(old);
    var buf: [16]u8 = undefined;
    var iov = [_][]u8{&buf};
    const n = s.read(io, &iov) catch |e| switch (e) {
        error.Canceled => unreachable,
        else => return e,
    };
    if (n == 0) return error.EndOfStream;
    return n;
}

test "Abort: an expired wait wakes a read the cancel cannot reach" {
    const io = std.testing.io;
    var srv: TestServer = undefined;
    try srv.start(io, null);
    defer srv.stop();
    const addr = try Io.net.IpAddress.parse("127.0.0.1", srv.port);
    const s = try addr.connect(io, .{ .mode = .stream });
    defer s.close(io);
    var a: Abort = .{};
    const t0 = wallMs();
    try std.testing.expectError(error.Timeout, timed(io, 200, null, &a, readArmed, .{ io, s, &a }));
    try std.testing.expect(wallMs() - t0 < 3000);
    // Armed after the wait ended: refused at once.
    var b: Abort = .{};
    b.fire();
    try std.testing.expectError(error.Canceled, b.arm(s.socket.handle));
    try std.testing.expect(b.fd == null);
}
