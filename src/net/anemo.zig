//! anemo client peer: connects over QUIC (conn.zig) to a sui-node anemo endpoint, performs the
//! anemo handshake (the server opens a unidirectional stream with the 8-byte version frame) and
//! sends RPCs on bidirectional streams (wire.zig). Blocking driver over `std.Io.net.Socket`.
//!
//! Requests the remote sends on our connection are answered by `Options.handler` when one is set
//! (a state-sync follower serves what it holds), else 404 (an empty 200 for pushes).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const conn_mod = @import("conn.zig");
const wire = @import("wire.zig");
/// sui-node's `sui_{inbound,outbound}_*` families (lane ops-metrics hooks).
const p2pm = @import("core").p2p_metrics;
const udpio = @import("udpio.zig");
const push_checkpoint_summary_route = "/sui.StateSync/PushCheckpointSummary";

pub const PeerId = [32]u8;

const use_kqueue = switch (@import("builtin").os.tag) {
    .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => true,
    else => false,
};

/// Readiness wait on one socket. kqueue keeps one registration for the life of the peer;
/// `poll(2)` on macOS builds and tears down a kqueue on every call, which showed up as tens of
/// microseconds per request.
const Waiter = struct {
    kq: if (use_kqueue) i32 else void = if (use_kqueue) -1 else {},

    fn init(fd: std.posix.fd_t) !Waiter {
        var w: Waiter = .{};
        if (use_kqueue) {
            const rc = std.posix.system.kqueue();
            if (std.posix.errno(rc) != .SUCCESS) return error.SystemResources;
            w.kq = @intCast(rc);
            const change = [1]std.posix.Kevent{.{ .ident = @intCast(fd), .filter = std.c.EVFILT.READ, .flags = std.c.EV.ADD, .fflags = 0, .data = 0, .udata = 0 }};
            var none: [0]std.posix.Kevent = .{};
            const r = std.posix.system.kevent(w.kq, &change, 1, &none, 0, null);
            if (std.posix.errno(r) != .SUCCESS) return error.SystemResources;
        }
        return w;
    }

    fn deinit(w: *Waiter) void {
        if (use_kqueue) _ = std.posix.system.close(w.kq);
    }

    /// True when a datagram is readable within `timeout_ns` (0 = check only). `spin_us` busy-waits
    /// first (trades CPU for wake-up latency).
    fn wait(w: *Waiter, fd: std.posix.fd_t, timeout_ns: u64, spin_us: u32) !bool {
        if (use_kqueue) {
            var ev: [1]std.posix.Kevent = undefined;
            var none: [0]std.posix.Kevent = .{};
            var ts: std.posix.timespec = .{ .sec = 0, .nsec = 0 };
            if (spin_us != 0 and timeout_ns != 0) {
                var spins: u32 = 0;
                while (spins < spin_us * 4) : (spins += 1) {
                    const r = std.posix.system.kevent(w.kq, &none, 0, &ev, 1, &ts);
                    if (std.posix.errno(r) != .SUCCESS) return error.WaitFailed;
                    if (r > 0) return true;
                }
            }
            ts = .{ .sec = @intCast(timeout_ns / std.time.ns_per_s), .nsec = @intCast(timeout_ns % std.time.ns_per_s) };
            while (true) {
                const r = std.posix.system.kevent(w.kq, &none, 0, &ev, 1, &ts);
                switch (std.posix.errno(r)) {
                    .SUCCESS => return r > 0,
                    .INTR => continue,
                    else => return error.WaitFailed,
                }
            }
        } else {
            var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
            const ms: i32 = @intCast(@min((timeout_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms, 1000));
            const n = try std.posix.poll(&fds, ms);
            if (n == 0) return false;
            if (fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.NVAL) != 0) return error.WaitFailed;
            return true;
        }
    }
};

pub const Error = error{
    HandshakeTimeout,
    RequestTimeout,
    ConnectionClosed,
    BadAnemoHandshake,
    StreamReset,
    ResponseTooLarge,
    Protocol,
    /// `Options.cancel` was set: the caller is shutting down.
    Cancelled,
} || conn_mod.Error || wire.Error || Io.net.Socket.SendError || Allocator.Error;

pub const Options = struct {
    server_name: []const u8,
    /// Verify the server's certificate key equals this PeerId (anemo `connect_with_peer_id`).
    expected: ?PeerId = null,
    /// Network key seed; random per connection when null.
    identity_seed: ?[32]u8 = null,
    handshake_timeout_ms: u64 = 5_000,
    max_response_frame: usize = wire.sui_max_response_frame,
    /// Test only: drop this percentage of datagrams in each direction (deterministic PRNG).
    sim_drop_pct: u8 = 0,
    sim_seed: u64 = 1,
    /// Spin on the socket for this long before blocking in poll: trades CPU for wake-up latency.
    busy_poll_us: u32 = 0,
    /// Answers requests the remote sends us (null: 404, or an empty 200 for pushes).
    handler: ?Handler = null,
    /// Checked at every step (at most 20 ms apart in a request, 50 ms in the handshake): once
    /// true, the call returns error.Cancelled and `deinit` closes the connection gracefully.
    cancel: ?*const std.atomic.Value(bool) = null,
    /// Filled when `connect` fails: why (net/peer_diag classes).
    diag: ?*ConnectDiag = null,
};

/// Why a connect failed, as far as the client can tell.
pub const ConnectDiag = struct {
    pub const Class = enum {
        /// Not a single datagram came back (no route, firewall, nothing listening: UDP gives no
        /// error on an unconnected socket).
        silent,
        /// The peer answered, but the handshake did not finish in time.
        stalled,
        /// The peer closed the connection (CONNECTION_CLOSE): `code`, `reason`.
        peer_closed,
        /// We closed it: TLS failure, wrong peer id, protocol error (`code`, `reason`).
        local_closed,
        /// Handshake done but no anemo version frame, or a wrong one.
        anemo,
        /// Local socket error.
        socket,
        cancelled,
    };
    class: Class = .silent,
    code: u64 = 0,
    app: bool = false,
    reason_buf: [64]u8 = undefined,
    reason_len: u8 = 0,
    /// Datagrams received before the failure.
    received: u64 = 0,
    elapsed_ms: u64 = 0,

    pub fn reason(d: *const ConnectDiag) []const u8 {
        return d.reason_buf[0..d.reason_len];
    }
};

/// Batched socket I/O state of one client peer, allocated once (no allocation per datagram).
const IoBufs = struct {
    sock: udpio.Sock,
    tx: udpio.TxBatch = .{},
    rx: udpio.RxBatch = .{},
};

/// Server side of an outbound connection: anemo peers send requests on the connection we opened
/// (sui-node's state sync pushes summaries and asks for availability; discovery asks for peers).
pub const Handler = struct {
    ctx: *anyopaque,
    /// `body` is the request body as sent (snappy-framed BCS). Returns the status and response
    /// body (allocated in `arena`).
    serve: *const fn (ctx: *anyopaque, arena: Allocator, from: *const PeerId, route: []const u8, body: []const u8) Reply,
};

pub const Reply = struct { status: wire.Status, body: []const u8 = "" };

pub const Response = struct {
    status: wire.Status,
    headers: []const wire.Header,
    body: []const u8,
};

pub const Peer = struct {
    gpa: Allocator,
    io: Io,
    sock: Io.net.Socket,
    remote: Io.net.IpAddress,
    conn: *conn_mod.Connection,
    bufs: *IoBufs,
    opts: Options,
    /// Server's PeerId, proven by its certificate during the handshake.
    peer_id: PeerId = undefined,
    hello_stream: ?u64 = null,
    hello_done: bool = false,
    rtt_samples: u64 = 0,
    sim: std.Random.DefaultPrng = std.Random.DefaultPrng.init(1),
    waiter: Waiter = .{},
    inbound: std.ArrayList(u64) = .empty,
    answered: std.ArrayList(u64) = .empty,

    fn nowNs(p: *const Peer) u64 {
        return @intCast(Io.Clock.awake.now(p.io).toNanoseconds());
    }

    pub fn connect(gpa: Allocator, io: Io, remote: Io.net.IpAddress, opts: Options) Error!*Peer {
        const p = try gpa.create(Peer);
        errdefer gpa.destroy(p);
        // A loopback peer is reached from a loopback-bound socket: avoids a per-datagram source
        // address and route selection in the kernel (about 20 us per sendmsg on macOS).
        var bind_addr: Io.net.IpAddress = switch (remote) {
            .ip4 => |a4| if (a4.bytes[0] == 127) .{ .ip4 = Io.net.Ip4Address.loopback(0) } else .{ .ip4 = Io.net.Ip4Address.unspecified(0) },
            .ip6 => .{ .ip6 = Io.net.Ip6Address.unspecified(0) },
        };
        const sock = Io.net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram }) catch return error.ConnectionClosed;
        errdefer sock.close(io);
        // Large socket buffers (best effort, like sui-node's 20 MiB): a state-sync response arrives
        // as a burst, and a full buffer means loss and a congestion window cut.
        const rcvbuf: c_int = 8 << 20;
        const sndbuf: c_int = 2 << 20;
        std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&rcvbuf)) catch {};
        std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&sndbuf)) catch {};
        var seed: [64]u8 = undefined;
        io.random(&seed);
        var ident: [32]u8 = undefined;
        if (opts.identity_seed) |s| ident = s else io.random(&ident);
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
        const bufs = try gpa.create(IoBufs);
        errdefer gpa.destroy(bufs);
        bufs.* = .{ .sock = udpio.Sock.init(sock.handle) };
        p.* = .{ .gpa = gpa, .io = io, .sock = sock, .remote = remote, .conn = undefined, .bufs = bufs, .opts = opts };
        p.sim = std.Random.DefaultPrng.init(opts.sim_seed);
        p.waiter = Waiter.init(sock.handle) catch return error.ConnectionClosed;
        errdefer p.waiter.deinit();
        p.conn = try conn_mod.Connection.init(gpa, .{
            .server_name = opts.server_name,
            .identity_seed = ident,
            .expected_peer = opts.expected,
            .seed = seed,
            .now_unix = now_unix,
        }, p.nowNs());
        errdefer p.conn.deinit();
        const t0 = p.nowNs();
        p.waitHandshake() catch |e| {
            if (opts.diag) |d| p.diagnose(d, e, t0);
            return e;
        };
        return p;
    }

    pub fn deinit(p: *Peer) void {
        if (!p.conn.isClosed()) {
            p.conn.closeApp(0);
            p.flush() catch {};
        }
        p.conn.deinit();
        p.waiter.deinit();
        p.inbound.deinit(p.gpa);
        p.answered.deinit(p.gpa);
        p.sock.close(p.io);
        p.gpa.destroy(p.bufs);
        p.gpa.destroy(p);
    }

    fn diagnose(p: *Peer, d: *ConnectDiag, e: Error, t0: u64) void {
        d.* = .{ .received = p.bufs.sock.stats.received, .elapsed_ms = (p.nowNs() -| t0) / std.time.ns_per_ms };
        if (p.conn.close) |ci| {
            d.class = if (ci.remote) .peer_closed else .local_closed;
            d.code = ci.code;
            d.app = ci.app;
            const n = @min(ci.reason.len, d.reason_buf.len);
            @memcpy(d.reason_buf[0..n], ci.reason[0..n]);
            d.reason_len = @intCast(n);
            return;
        }
        d.class = switch (e) {
            error.Cancelled => .cancelled,
            error.BadAnemoHandshake => .anemo,
            error.HandshakeTimeout => if (d.received == 0) .silent else .stalled,
            error.ConnectionClosed => if (d.received == 0) .socket else .local_closed,
            else => .local_closed,
        };
        const n = @min(@errorName(e).len, d.reason_buf.len);
        @memcpy(d.reason_buf[0..n], @errorName(e)[0..n]);
        d.reason_len = @intCast(n);
    }

    fn cancelled(p: *const Peer) bool {
        return if (p.opts.cancel) |c| c.load(.acquire) else false;
    }

    /// Sends what the connection has queued: datagrams are written in place into one batch and
    /// leave in one syscall per batch (sendmmsg plus UDP GSO on Linux, sendmsg_x on macOS).
    fn flush(p: *Peer) Error!void {
        const b = &p.bufs.tx;
        const now = p.nowNs();
        while (true) {
            if (b.full()) b.flush(&p.bufs.sock);
            const slot = b.slot();
            const n = p.conn.pollTransmit(now, slot[0..@min(slot.len, conn_mod.max_datagram)]) orelse break;
            if (p.opts.sim_drop_pct != 0 and p.sim.random().uintLessThan(u8, 100) < p.opts.sim_drop_pct) continue;
            b.commit(n, &p.remote);
        }
        b.flush(&p.bufs.sock);
    }

    /// Runs the connection for at most `max_wait_ns`, or until the next timer, whichever is
    /// first: send, receive what is queued, fire due timers.
    fn step(p: *Peer, max_wait_ns: u64) Error!void {
        if (p.cancelled()) return error.Cancelled;
        try p.flush();
        var now = p.nowNs();
        var wait = max_wait_ns;
        if (p.conn.nextTimeout()) |t| wait = @min(wait, t -| now);
        wait = @max(wait, 1000);
        // Wait for the socket (kqueue on BSD and macOS, poll elsewhere), then drain what is queued;
        // receive never blocks after a positive wait. Avoids the Io batch machinery on the hot path.
        var wait_ns: u64 = wait;
        while (true) {
            const ready = p.waiter.wait(p.sock.handle, wait_ns, p.opts.busy_poll_us) catch return error.ConnectionClosed;
            if (!ready) break;
            wait_ns = 0;
            // Drain up to a batch per syscall (recvmmsg / recvmsg_x), never blocking here.
            const rx = &p.bufs.rx;
            const got = rx.recv(&p.bufs.sock, false);
            if (got == 0) break;
            now = p.nowNs();
            for (0..got) |k| {
                if (!p.remote.eql(&rx.from(k))) continue;
                if (p.opts.sim_drop_pct != 0 and p.sim.random().uintLessThan(u8, 100) < p.opts.sim_drop_pct) continue;
                p.conn.handleDatagram(now, rx.data(k));
            }
            if (got < udpio.max_batch) break;
        }
        now = p.nowNs();
        if (p.conn.nextTimeout()) |t| if (now >= t) p.conn.onTimeout(now);
        try p.serviceInbound();
        try p.flush();
    }

    fn waitHandshake(p: *Peer) Error!void {
        const deadline = p.nowNs() + p.opts.handshake_timeout_ms * std.time.ns_per_ms;
        while (true) {
            if (p.conn.isClosed()) return error.ConnectionClosed;
            if (p.conn.isEstablished()) {
                if (p.hello_stream == null) p.hello_stream = p.conn.acceptUni();
                if (p.hello_stream) |id| {
                    const s = p.conn.stream(id).?;
                    const data = s.recv.contiguous();
                    if (data.len >= 8) {
                        wire.checkVersionFrame(data[0..8]) catch return error.BadAnemoHandshake;
                        p.peer_id = p.conn.peerId().?;
                        s.recv.consume(8);
                        p.conn.streamFree(id);
                        p.hello_done = true;
                        return;
                    }
                }
            }
            if (p.nowNs() >= deadline) return error.HandshakeTimeout;
            try p.step(50 * std.time.ns_per_ms);
        }
    }

    /// Answers requests the remote sends us: this peer serves nothing.
    fn serviceInbound(p: *Peer) Error!void {
        // peer-initiated unidirectional streams (other than the hello) are drained and dropped
        if (p.hello_done) while (p.conn.acceptUni()) |id| p.conn.streamFree(id);
        while (p.conn.acceptBidi()) |id| try p.pendingInbound(id);
        var i: usize = 0;
        while (i < p.inbound.items.len) {
            const id = p.inbound.items[i];
            const s = p.conn.stream(id) orelse {
                _ = p.inbound.orderedRemove(i);
                continue;
            };
            var arena_state = std.heap.ArenaAllocator.init(p.gpa);
            defer arena_state.deinit();
            const a = arena_state.allocator();
            const parsed = wire.parseRequest(a, s.recv.contiguous(), wire.sui_max_request_frame) catch {
                p.conn.streamFree(id);
                _ = p.inbound.orderedRemove(i);
                continue;
            };
            if (parsed) |req| {
                const call = p2pm.inbound.begin(req.route, req.body.len);
                const reply: Reply = if (p.opts.handler) |h|
                    h.serve(h.ctx, a, &p.peer_id, req.route, req.body)
                else
                    .{ .status = if (std.mem.eql(u8, req.route, push_checkpoint_summary_route)) .success else .not_found };
                p2pm.inbound.end(call, @intFromEnum(reply.status), reply.body.len);
                const resp = try wire.encodeResponse(a, reply.status, &.{}, reply.body);
                try p.conn.streamWrite(id, resp, true);
                _ = p.inbound.orderedRemove(i);
                p.answered.append(p.gpa, id) catch {};
                continue;
            }
            i += 1;
        }
        // free answered streams once their send side is done
        var j: usize = 0;
        while (j < p.answered.items.len) {
            const id = p.answered.items[j];
            const s = p.conn.stream(id);
            if (s == null or (s.?.fin_sent and s.?.retx.items.len == 0 and s.?.recv.complete())) {
                p.conn.streamFree(id);
                _ = p.answered.orderedRemove(j);
            } else j += 1;
        }
    }

    fn pendingInbound(p: *Peer, id: u64) Error!void {
        try p.inbound.append(p.gpa, id);
    }

    /// Sends one RPC and waits for the response. Body bytes are copied into `arena`.
    pub fn request(p: *Peer, arena: Allocator, route: []const u8, headers: []const wire.Header, body: []const u8, timeout_ms: u64) Error!Response {
        const call = p2pm.outbound.begin(route, body.len);
        const r = p.requestInner(arena, route, headers, body, timeout_ms) catch |e| {
            p2pm.outbound.fail(call);
            return e;
        };
        p2pm.outbound.end(call, @intFromEnum(r.status), r.body.len);
        return r;
    }

    fn requestInner(p: *Peer, arena: Allocator, route: []const u8, headers: []const wire.Header, body: []const u8, timeout_ms: u64) Error!Response {
        const id = try p.conn.openBidi();
        // On every error path (timeout, reset, malformed response) the stream is released; late
        // frames for it are then ignored by the connection.
        errdefer p.conn.streamFree(id);
        const bytes = try wire.encodeRequest(arena, route, headers, body);
        try p.conn.streamWrite(id, bytes, true);
        const deadline = p.nowNs() + timeout_ms * std.time.ns_per_ms;
        while (true) {
            if (p.conn.isClosed()) return error.ConnectionClosed;
            const s = p.conn.stream(id).?;
            if (s.reset != null) return error.StreamReset;
            const parsed = try wire.parseResponse(arena, s.recv.contiguous(), p.opts.max_response_frame);
            if (parsed) |r| {
                const out: Response = .{
                    .status = r.status,
                    .headers = try dupHeaders(arena, r.headers),
                    .body = try arena.dupe(u8, r.body),
                };
                p.conn.streamFree(id);
                return out;
            }
            if (p.nowNs() >= deadline) return error.RequestTimeout;
            try p.step(@min(deadline -| p.nowNs(), 20 * std.time.ns_per_ms));
        }
    }

    /// Services the connection (timers, inbound requests) for `ms` milliseconds.
    pub fn pump(p: *Peer, ms: u64) Error!void {
        const deadline = p.nowNs() + ms * std.time.ns_per_ms;
        while (p.nowNs() < deadline) try p.step(@min(deadline -| p.nowNs(), 20 * std.time.ns_per_ms));
    }

    pub fn close(p: *Peer) void {
        p.conn.closeApp(0);
        p.flush() catch {};
    }
};

fn dupHeaders(a: Allocator, hs: []const wire.Header) Allocator.Error![]const wire.Header {
    const out = try a.alloc(wire.Header, hs.len);
    for (hs, out) |h, *o| o.* = .{ .name = try a.dupe(u8, h.name), .value = try a.dupe(u8, h.value) };
    return out;
}
