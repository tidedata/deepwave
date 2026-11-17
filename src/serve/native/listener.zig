//! zui/1 listener (NATIVE-PROTOCOL.md sections 1 to 3): one UDP socket, one I/O thread that owns
//! every QUIC connection (net/conn.zig server role, demultiplexed by our connection id, the same
//! shape as net/server.zig's anemo listener). ALPN picks the stack: `zui/1` streams carry the
//! protocol directly; `h3` connections run the HTTP/3 + WebTransport session (h3.zig) and the
//! protocol rides WT streams. The I/O thread does socket work, the QUIC connections and the
//! streams, and never reads the store: a store read can wait on a page fault, and while the I/O
//! thread waits no datagram is read, no ACK processed and nothing sent, for every connection.
//! Requests are answered on worker pools (jobs.zig: reads, slow methods, the edge feed), and
//! subscriptions' frames are produced on workers (subjobs.zig) while the data stream's backlog
//! is small; the I/O thread writes the finished bytes to their streams.
const std = @import("std");
const tcache = @import("core").threads;
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const net = @import("net");
const udpio = net.udpio;
const conn_mod = net.conn;
const store = @import("store");
const proto = @import("proto.zig");
const h3 = @import("h3.zig");
const dispatch = @import("dispatch.zig");
const sub = @import("sub.zig");
const cert_mod = @import("cert.zig");
const certs_mod = @import("certs.zig");
const jobs_mod = @import("jobs.zig");
const fairq = @import("fairq.zig");
const gate_mod = @import("gate.zig");
const subjobs = @import("subjobs.zig");

pub const alpns = [_][]const u8{ proto.alpn, "h3" };

pub const Options = struct {
    listen: Io.net.IpAddress,
    /// Ed25519 identity for raw zui/1 (self-signed cert, pinned by public key).
    identity_seed: [32]u8,
    /// P-256 certificate for WebTransport (h3): one fixed certificate (tests), or
    /// `certs`, which rotates it (certs.zig) and wins when both are set. With `--native-cert`,
    /// `certs` holds the operator's chain instead, presented under both ALPNs (a zui/1 client
    /// that pins the identity key still gets the identity certificate: net/tls13_server.zig).
    cert: ?*const cert_mod.Cert = null,
    certs: ?*certs_mod.Certs = null,
    max_connections: u32 = 1000,
    /// After a pass that moved datagrams, poll the socket without blocking for up to this long
    /// before sleeping in the kernel (busy-poll: a request that follows within the window skips
    /// the thread wakeup). 0 disables. Env ZUI_NATIVE_SPIN_US overrides.
    spin_us: u32 = 0,
    max_streams: u32 = 128,
    max_subscriptions: u32 = 16,
    idle_timeout_ms: u64 = 30_000,
    /// Unsent bytes a subscription data stream may hold before production pauses.
    sub_backlog: u64 = 512 << 10,
    /// Worker threads for dry_run and submit_transaction.
    slow_workers: usize = 4,
    /// Worker threads and queue depth (queued plus running) for edge feed assembly: their own
    /// pool, so dry_run and submit_transaction never wait behind feeds. The queue is divided
    /// between the clients with feed requests in flight (fairq.zig, `feedClient`): each has a
    /// share of `feed_queue` over their number, never under `feed_min_share`, and may use what
    /// the others leave. One client alone has all of it.
    feed_workers: usize = 4,
    feed_queue: usize = 64,
    feed_min_share: usize = 2,
    /// Worker threads and queue depth for every other request (reads: objects, transactions,
    /// checkpoints, index queries, hello), divided between clients like the feed queue.
    read_workers: usize = 4,
    read_queue: usize = 1024,
    read_min_share: usize = 8,
    /// Worker threads that produce subscription frames (subjobs.zig).
    sub_workers: usize = 2,
    /// Run on each slow worker before it exits (the simulate engine's thread caches).
    slow_worker_exit: ?*const fn () void = null,
    /// Half-open connections above which a new client must come back with a Retry token
    /// (stateless address validation, net/retry.zig; 0: always).
    retry_threshold: usize = 64,
    /// A connection that has not finished its handshake this long after its first Initial is
    /// dropped (instead of holding a slot for the 30 s idle timeout).
    handshake_timeout_ms: u64 = 5_000,
    /// Sender-side QUIC switches for every connection of this listener (zui/1 and
    /// WebTransport), all off by default: see `net.conn.Config`. Env overrides (1 or 0):
    /// ZUI_NATIVE_PACING, ZUI_NATIVE_HYSTART, ZUI_NATIVE_CUBIC, ZUI_NATIVE_PMTUD,
    /// ZUI_NATIVE_IW_MTU, ZUI_NATIVE_BBR.
    pacing: bool = false,
    hystart: bool = false,
    cubic: bool = false,
    pmtud: bool = false,
    iw_mtu: bool = false,
    /// BBR instead of NewReno or CUBIC (it paces by itself): see `net.conn.Config.bbr`.
    bbr: bool = false,
    /// WebTransport cold connect: the HTTP/3 control stream (SETTINGS) and the two QPACK
    /// streams are sent right behind the server's handshake flight ("0.5-RTT",
    /// `net.conn.Config.early_send`) instead of after the client's Finished has arrived. A
    /// browser may not send its CONNECT before it has the SETTINGS, so this takes one round
    /// trip off the first response of every new WebTransport session. Nothing else is sent
    /// early and nothing is read early. Off by default; env override ZUI_NATIVE_EARLY_SETTINGS.
    early_settings: bool = false,
    /// Access gate (`--gate`, docs/GATE.md): asked before every request. Null: no gate code runs.
    gate: ?gate_mod.Hook = null,
};

fn envSwitch(name: [*:0]const u8, default: bool) bool {
    const v = std.c.getenv(name) orelse return default;
    return v[0] == '1';
}

/// The largest UDP payload an Ethernet path carries to `a`: 1472 over IPv4 (also an
/// IPv4-mapped address on a dual-stack socket), 1452 over IPv6.
fn pathCeiling(a: *const Io.net.IpAddress) u16 {
    return switch (a.*) {
        .ip4 => 1472,
        .ip6 => |v| if (std.mem.eql(u8, v.bytes[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) 1472 else 1452,
    };
}

/// A live subscription sends a Heartbeat after this long without a match (spec 5.1).
pub const heartbeat_ms = 5000;

pub const Stats = struct {
    accepted: Atomic(u64) = .init(0),
    active: Atomic(u64) = .init(0),
    requests: Atomic(u64) = .init(0),
    bad_requests: Atomic(u64) = .init(0),
    sub_frames: Atomic(u64) = .init(0),
    bytes_in: Atomic(u64) = .init(0),
    bytes_out: Atomic(u64) = .init(0),
    /// Retry packets sent, and Initials whose Retry token checked out.
    retries: Atomic(u64) = .init(0),
    retried_ok: Atomic(u64) = .init(0),
    /// Datagrams sent and the send syscalls that carried them (udpio batches: sendmsg_x on
    /// macOS, sendmmsg with UDP GSO on Linux). Their ratio is the send batching achieved.
    datagrams_out: Atomic(u64) = .init(0),
    send_calls: Atomic(u64) = .init(0),
    /// Passes of the I/O loop, the passes that polled the socket without blocking (a timer was
    /// due in under 1 ms, or the burst cap left datagrams unsent), and the I/O thread's CPU
    /// time, sampled every 64 passes.
    io_passes: Atomic(u64) = .init(0),
    io_polls: Atomic(u64) = .init(0),
    io_cpu_ns: Atomic(u64) = .init(0),
    /// Wall time the I/O thread spent in passes (from its receive returning to the pass's end),
    /// and its major page faults (Linux; sampled every 64 passes). Faults here mean something
    /// on the I/O thread read cold memory: the stall that holds every connection.
    io_busy_ns: Atomic(u64) = .init(0),
    io_major_faults: Atomic(u64) = .init(0),
};

fn threadMajorFaults() u64 {
    if (comptime @import("builtin").os.tag != .linux) return 0;
    var ru: std.os.linux.rusage = undefined;
    if (std.os.linux.getrusage(1, &ru) != 0) return 0; // RUSAGE_THREAD
    return @intCast(@max(ru.majflt, 0));
}

/// Congestion state of the listener's connections (zui/1 and WebTransport), sampled by the I/O
/// thread every 64 passes. Gauges are the connections open at the sample; the counters add
/// those of closed connections, so they only rise. Rendered as `zui_native_cc_*`.
pub const CcStats = struct {
    /// Connections in the sample, the largest congestion window among them (bytes) and the
    /// largest smoothed round-trip time (ms).
    conns: Atomic(u64) = .init(0),
    cwnd_max: Atomic(u64) = .init(0),
    srtt_max_ms: Atomic(u64) = .init(0),
    /// Connections whose smoothed round-trip time is at most each bound (ms), cumulative.
    srtt_le: [srtt_bounds.len]Atomic(u64) = @splat(.init(0)),
    /// ACKs that acknowledged data; those that found the sender application-limited (the
    /// window did not grow on them); those after which `max_cwnd` held the window down.
    acks: Atomic(u64) = .init(0),
    acks_app_limited: Atomic(u64) = .init(0),
    cwnd_capped: Atomic(u64) = .init(0),
    /// I/O thread only: what closed connections counted.
    closed: [3]u64 = @splat(0),

    pub const srtt_bounds = [_]u64{ 50, 100, 250, 500, 1000, 2000 };

    fn sample(s: *CcStats, slots: *const std.AutoHashMapUnmanaged(u64, *Slot)) void {
        var n: u64 = 0;
        var cwnd: u64 = 0;
        var srtt: u64 = 0;
        var le: [srtt_bounds.len]u64 = @splat(0);
        var tot = s.closed;
        var it = slots.valueIterator();
        while (it.next()) |sp| {
            const c = sp.*.conn;
            tot[0] += c.acks;
            tot[1] += c.acks_app_limited;
            tot[2] += c.cwnd_capped;
            if (sp.*.kind == .pending or !c.isEstablished()) continue;
            n += 1;
            cwnd = @max(cwnd, c.cwnd);
            const r = c.srtt / std.time.ns_per_ms;
            srtt = @max(srtt, r);
            for (srtt_bounds, 0..) |b, i| {
                if (r <= b) le[i] += 1;
            }
        }
        s.conns.store(n, .monotonic);
        s.cwnd_max.store(cwnd, .monotonic);
        s.srtt_max_ms.store(srtt, .monotonic);
        for (&s.srtt_le, le) |*a, v| a.store(v, .monotonic);
        s.acks.store(tot[0], .monotonic);
        s.acks_app_limited.store(tot[1], .monotonic);
        s.cwnd_capped.store(tot[2], .monotonic);
    }

    fn noteClosed(s: *CcStats, c: *const conn_mod.Connection) void {
        s.closed[0] += c.acks;
        s.closed[1] += c.acks_app_limited;
        s.closed[2] += c.cwnd_capped;
    }

    pub fn render(s: *const CcStats, w: *std.Io.Writer) !void {
        try w.print("# HELP zui_native_cc_connections established zui/1 and WebTransport connections at the last sample\n# TYPE zui_native_cc_connections gauge\nzui_native_cc_connections {d}\n", .{s.conns.load(.monotonic)});
        try w.print("# HELP zui_native_cc_cwnd_max_bytes largest congestion window among them\n# TYPE zui_native_cc_cwnd_max_bytes gauge\nzui_native_cc_cwnd_max_bytes {d}\n", .{s.cwnd_max.load(.monotonic)});
        try w.print("# HELP zui_native_cc_srtt_max_ms largest smoothed round-trip time among them\n# TYPE zui_native_cc_srtt_max_ms gauge\nzui_native_cc_srtt_max_ms {d}\n", .{s.srtt_max_ms.load(.monotonic)});
        try w.writeAll("# HELP zui_native_cc_srtt_ms connections whose smoothed round-trip time is at most le ms\n# TYPE zui_native_cc_srtt_ms gauge\n");
        for (srtt_bounds, 0..) |b, i| try w.print("zui_native_cc_srtt_ms{{le=\"{d}\"}} {d}\n", .{ b, s.srtt_le[i].load(.monotonic) });
        try w.print("zui_native_cc_srtt_ms{{le=\"+Inf\"}} {d}\n", .{s.conns.load(.monotonic)});
        try w.print("# HELP zui_native_cc_acks ACKs that acknowledged data\n# TYPE zui_native_cc_acks counter\nzui_native_cc_acks {d}\n", .{s.acks.load(.monotonic)});
        try w.print("# HELP zui_native_cc_acks_app_limited of those, ACKs that found the sender application-limited (no window growth)\n# TYPE zui_native_cc_acks_app_limited counter\nzui_native_cc_acks_app_limited {d}\n", .{s.acks_app_limited.load(.monotonic)});
        try w.print("# HELP zui_native_cc_cwnd_capped ACKs after which the window was held at the hard bound\n# TYPE zui_native_cc_cwnd_capped counter\nzui_native_cc_cwnd_capped {d}\n", .{s.cwnd_capped.load(.monotonic)});
    }
};

fn threadCpuNs() u64 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(.THREAD_CPUTIME_ID, &ts) != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const Kind = enum { pending, zui, h3 };

const ReqStream = struct {
    buf: std.ArrayList(u8) = .empty,
    fin: bool = false,
    done: bool = false,
    /// pair_relay stream (method 0x30): frames after the PairAck are piped to the other role.
    relay: ?RelayRef = null,
    /// subscribe control stream (0x20): the sub id while it lives; later bytes are credit.
    sub: ?u64 = null,
    /// Request bytes at the front of `buf` already parsed (subscribe: header and body).
    consumed: usize = 0,
    /// A slow method runs on a worker; the response comes back through `Listener.jobs`.
    queued: bool = false,
    /// Access gate: the admitted request's ticket until it is settled, and when the request
    /// began to wait for its key's lookup (ms; 0: not waiting).
    gate: ?gate_mod.Ticket = null,
    gate_wait_ms: u64 = 0,
};

const RelayRef = struct { channel: [32]u8, role: u1 };

/// docs/NATIVE-WALLET-CONNECT.md 6: one channel per pairing, a stream per role, blind DATA piping.
pub const relay_max_frame = 65536;
pub const relay_buf_frames = 64;
pub const relay_buf_bytes = 256 << 10;
pub const relay_ttl_default_s = 24 * 3600;
pub const relay_ttl_max_s = 7 * 24 * 3600;
pub const relay_idle_ms = 10 * 60 * 1000;
pub const relay_per_conn = 4;
const RELAY_DATA = 0x01;
const RELAY_PEER_UP = 0x02;
const RELAY_PEER_DOWN = 0x03;
const RELAY_END = 0x04;

const StreamRef = struct { key: u64, stream: u64 };

const Channel = struct {
    claims: [2]?[32]u8 = .{ null, null },
    streams: [2]?StreamRef = .{ null, null },
    /// Frames waiting for role r (sent by the other role while r was away).
    bufs: [2]std.ArrayList([]u8) = .{ .empty, .empty },
    buf_bytes: [2]usize = .{ 0, 0 },
    expires_ms: u64,
    idle_since_ms: u64,

    fn deinit(ch: *Channel, gpa: Allocator) void {
        for (&ch.bufs) |*b| {
            for (b.items) |f| gpa.free(f);
            b.deinit(gpa);
        }
    }
};

const Sub = struct {
    id: u64,
    req: sub.Req,
    ctrl: u64,
    data: u64,
    cursor: u64,
    live: bool = false,
    /// Credit (spec 5.2): enforced once the client wrote any; `granted` = max_lag + credits.
    credit_on: bool = false,
    granted: u64 = 0,
    delivered: u64 = 0,
    last_match_ms: u64 = 0,
    /// Access gate: the subscription's ticket (its stream slot) until it ends.
    gate: ?gate_mod.Ticket = null,
    /// A worker is producing its next frames (subjobs.zig): one at a time, in order.
    busy: bool = false,
    /// Access gate: frames delivered since the gate was last told.
    gate_frames: u64 = 0,
};

const CIo = struct {
    c: *conn_mod.Connection,
    pub fn openUni(self: CIo) !u64 {
        return self.c.openUni();
    }
    pub fn write(self: CIo, id: u64, b: []const u8, fin: bool) !void {
        try self.c.streamWrite(id, b, fin);
    }
};

const Slot = struct {
    conn: *conn_mod.Connection,
    addr: Io.net.IpAddress,
    key: u64,
    odcid: [20]u8 = undefined,
    odcid_len: u8 = 0,
    kind: Kind = .pending,
    /// The `Options.certs` certificate this connection's handshake uses (held until freed).
    ident: ?*certs_mod.Entry = null,
    h3s: ?h3.ServerSession = null,
    session: ?u64 = null,
    principal: ?dispatch.Principal = null,
    /// h3: peer streams fed to the session (stream id -> fin delivered).
    h3_streams: std.AutoArrayHashMapUnmanaged(u64, bool) = .empty,
    reqs: std.AutoArrayHashMapUnmanaged(u64, ReqStream) = .empty,
    /// Streams whose response is queued; freed once fully sent.
    answered: std.ArrayList(u64) = .empty,
    subs: std.ArrayList(Sub) = .empty,
    /// Access gate: the connection's key (its hello or CONNECT token; owned).
    gate_key: []u8 = &.{},
};

pub const Listener = struct {
    gpa: Allocator,
    io: Io,
    opts: Options,
    disp: *dispatch.Dispatcher,
    stats: Stats = .{},
    sock: Io.net.Socket,
    stop_flag: Atomic(bool) = .init(false),
    io_thread: ?std.Thread = null,
    watchdog_thread: ?std.Thread = null,
    slots: std.AutoHashMapUnmanaged(u64, *Slot) = .empty,
    next_sub: u64 = 1,
    keys: sub.KeyCache,
    channels: std.AutoHashMapUnmanaged([32]u8, *Channel) = .empty,
    /// Batched socket I/O (sendmsg_x/recvmsg_x, sendmmsg/recvmmsg + GSO), owned by the I/O thread.
    us: udpio.Sock = undefined,
    tx: *udpio.TxBatch = undefined,
    rx: *udpio.RxBatch = undefined,
    /// Per-request scratch, reset (capacity kept) for each request instead of a fresh arena.
    req_arena: std.heap.ArenaAllocator = undefined,
    jobs: ?*jobs_mod.Jobs = null,
    feed_jobs: ?*jobs_mod.Jobs = null,
    read_jobs: ?*jobs_mod.Jobs = null,
    /// The read queue now, and what it refused (`zui_native_read_queue_*`).
    read_stats: fairq.Stats = .{},
    sub_jobs: ?*subjobs.Pool = null,
    sub_stats: subjobs.Stats = .{},
    /// The longest I/O pass in the last 10 to 20 s (ns), for `zui_native_io_stall_max_ms`.
    io_stall_max_ns: Atomic(u64) = .init(0),
    /// The feed queue now, and what it refused (`zui_native_feed_queue_*`).
    feed_stats: fairq.Stats = .{},
    /// Congestion windows and round-trip times of the connections (`zui_native_cc_*`).
    cc_stats: CcStats = .{},
    /// I/O thread only: Retry tokens, and connections whose handshake is not finished.
    guard: net.retry.Guard = undefined,
    half_open: usize = 0,
    /// Access gate: a request waits for its key's lookup, so the next pass comes soon.
    gate_waiting: bool = false,

    pub fn start(gpa: Allocator, io: Io, opts: Options, disp: *dispatch.Dispatcher) !*Listener {
        const l = try gpa.create(Listener);
        errdefer gpa.destroy(l);
        const sock = try Io.net.IpAddress.bind(&opts.listen, io, .{ .mode = .dgram });
        errdefer sock.close(io);
        const bufsz: c_int = 8 << 20;
        std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&bufsz)) catch {};
        std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&bufsz)) catch {};
        const tx = try gpa.create(udpio.TxBatch);
        errdefer gpa.destroy(tx);
        const rx = try gpa.create(udpio.RxBatch);
        errdefer gpa.destroy(rx);
        // Field defaults, not just `n`: `off[0]` must be 0 (gpa.create leaves it undefined, and
        // `slot()` indexed the buffer with 0xaaaaaaaa in safe builds: panic on the first send).
        tx.* = .{};
        rx.* = .{};
        var o = opts;
        if (std.c.getenv("ZUI_NATIVE_SPIN_US")) |v| o.spin_us = std.fmt.parseInt(u32, std.mem.span(v), 10) catch o.spin_us;
        o.pacing = envSwitch("ZUI_NATIVE_PACING", o.pacing);
        o.hystart = envSwitch("ZUI_NATIVE_HYSTART", o.hystart);
        o.cubic = envSwitch("ZUI_NATIVE_CUBIC", o.cubic);
        o.pmtud = envSwitch("ZUI_NATIVE_PMTUD", o.pmtud);
        o.iw_mtu = envSwitch("ZUI_NATIVE_IW_MTU", o.iw_mtu);
        o.bbr = envSwitch("ZUI_NATIVE_BBR", o.bbr);
        o.early_settings = envSwitch("ZUI_NATIVE_EARLY_SETTINGS", o.early_settings);
        if (o.pacing or o.hystart or o.cubic or o.pmtud or o.iw_mtu or o.bbr or o.early_settings)
            std.log.info("native: QUIC sender switches: pacing={} hystart={} cubic={} pmtud={} iw_mtu={} bbr={} early_settings={}", .{ o.pacing, o.hystart, o.cubic, o.pmtud, o.iw_mtu, o.bbr, o.early_settings });
        l.* = .{ .gpa = gpa, .io = io, .opts = o, .disp = disp, .sock = sock, .keys = .init(gpa, io), .us = .init(sock.handle), .tx = tx, .rx = rx, .req_arena = .init(gpa) };
        var gk: [32]u8 = undefined;
        io.random(&gk);
        l.guard = net.retry.Guard.init(gk);
        // the pools the watchdog looks at exist from the start, every worker running: a fixed
        // set of threads, none started per request or per subscription batch
        (l.readJobs() orelse return error.OutOfMemory).startWorkers();
        (l.subJobs() orelse return error.OutOfMemory).startWorkers();
        l.io_thread = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, ioLoop, .{l});
        l.watchdog_thread = std.Thread.spawn(.{}, watchdog, .{l}) catch null;
        return l;
    }

    pub fn address(l: *const Listener) Io.net.IpAddress {
        return l.sock.address;
    }

    pub fn stop(l: *Listener) void {
        l.stop_flag.store(true, .release);
        if (l.io_thread) |t| t.join();
        if (l.watchdog_thread) |t| t.join();
        l.closeAll();
        if (l.jobs) |j| {
            j.deinit();
            l.gpa.destroy(j);
        }
        if (l.feed_jobs) |j| {
            j.deinit();
            l.gpa.destroy(j);
        }
        if (l.read_jobs) |j| {
            j.deinit();
            l.gpa.destroy(j);
        }
        if (l.sub_jobs) |p| {
            p.deinit();
            l.gpa.destroy(p);
        }
        var it = l.slots.valueIterator();
        while (it.next()) |sp| l.freeSlot(sp.*);
        l.slots.deinit(l.gpa);
        var ci = l.channels.valueIterator();
        while (ci.next()) |c| {
            c.*.deinit(l.gpa);
            l.gpa.destroy(c.*);
        }
        l.channels.deinit(l.gpa);
        l.keys.deinit();
        l.gpa.destroy(l.tx);
        l.req_arena.deinit();
        l.gpa.destroy(l.rx);
        l.sock.close(l.io);
        l.gpa.destroy(l);
    }

    /// Tells every client the listener is going away (CONNECTION_CLOSE: zui/1 `shutdown`,
    /// H3_NO_ERROR under h3), so an edge fails over at once instead of waiting out its request
    /// timeout. Sent twice: the connection is freed right after, nothing would repeat a lost one.
    fn closeAll(l: *Listener) void {
        const now = l.nowNs();
        var it = l.slots.valueIterator();
        while (it.next()) |sp| {
            const s = sp.*;
            const c = s.conn;
            if (c.isClosed()) continue;
            c.closeApp(if (s.kind == .h3) 0x100 else @intFromEnum(proto.Code.shutdown));
            var d: [udpio.max_dgram]u8 = undefined;
            var k: usize = 0;
            while (k < 4) : (k += 1) {
                const n = c.pollTransmit(now, &d) orelse break;
                for (0..2) |_| {
                    if (l.tx.full()) l.tx.flush(&l.us);
                    @memcpy(l.tx.slot()[0..n], d[0..n]);
                    l.tx.commit(n, &s.addr);
                }
            }
        }
        l.tx.flush(&l.us);
    }

    fn nowNs(l: *const Listener) u64 {
        return @intCast(Io.Clock.awake.now(l.io).toNanoseconds());
    }

    fn freeSlot(l: *Listener, s: *Slot) void {
        const c = s.conn;
        // `path MTU` is the size at the end; a connection whose client went away ends in probe
        // timeouts, so the highest size it validated and the fallbacks to 1200 are named too.
        if (c.pkts_lost != 0 or c.ptos != 0)
            std.log.info("native: connection done, {d} packets sent, {d} lost, {d} PTOs, path MTU {d} (highest {d}, {d} fallbacks), srtt {d} ms, cwnd {d}, min rtt {d} ms, app-limited acks {d} of {d}", .{ c.pkts_sent, c.pkts_lost, c.ptos, c.mtu, c.mtu_peak, c.pmtu_black_holes, c.srtt / std.time.ns_per_ms, c.cwnd, if (c.rtt_initialized) c.min_rtt / std.time.ns_per_ms else 0, c.acks_app_limited, c.acks });
        l.cc_stats.noteClosed(c);
        s.conn.deinit();
        if (s.ident) |e| l.opts.certs.?.release(e);
        if (s.h3s) |*h| h.deinit();
        s.h3_streams.deinit(l.gpa);
        for (s.reqs.values()) |*r| {
            l.gateSettle(r, ""); // admitted and never answered: counted, not charged
            r.buf.deinit(l.gpa);
        }
        s.reqs.deinit(l.gpa);
        s.answered.deinit(l.gpa);
        for (s.subs.items) |*sb| {
            l.gateSubClosed(sb);
            sub.deinit(l.gpa, &sb.req);
        }
        s.subs.deinit(l.gpa);
        l.gpa.free(s.gate_key);
        l.gpa.destroy(s);
    }

    /// Logs a stall where it happens: the I/O thread in one pass for 2 s or more, or the read or
    /// subscription workers with work in flight and none of it finishing for 5 s. Looks every
    /// 250 ms; says each stall once (and again every 10 s while it lasts) with how long so far.
    fn watchdog(l: *Listener) void {
        const ms = std.time.ns_per_ms;
        var last_pass: u64 = l.stats.io_passes.load(.monotonic);
        var pass_at = l.nowNs();
        var said_io: u64 = 0;
        var reads_done: u64 = 0;
        var reads_at = pass_at;
        var said_reads: u64 = 0;
        var subs_done: u64 = 0;
        var subs_at = pass_at;
        var said_subs: u64 = 0;
        while (!l.stop_flag.load(.acquire)) {
            l.io.sleep(.fromMilliseconds(250), .awake) catch {};
            const now = l.nowNs();
            const tip = l.disp.svc.store.committed() orelse 0;
            const pass = l.stats.io_passes.load(.monotonic);
            if (pass != last_pass) {
                last_pass = pass;
                pass_at = now;
            } else if (now - pass_at >= 2000 * ms and now - said_io >= 10_000 * ms) {
                said_io = now;
                std.log.warn("native: stall: the I/O thread has been in one pass for {d} ms (store tip {d})", .{ (now - pass_at) / ms, tip });
            }
            if (l.read_jobs) |j| {
                const done = j.finished.load(.monotonic);
                const inflight = j.inflightNow();
                if (done != reads_done or inflight == 0) {
                    reads_done = done;
                    reads_at = now;
                } else if (now - reads_at >= 5000 * ms and now - said_reads >= 10_000 * ms) {
                    said_reads = now;
                    std.log.warn("native: stall: {d} read requests in flight and none finished for {d} ms (store tip {d})", .{ inflight, (now - reads_at) / ms, tip });
                }
            }
            if (l.sub_jobs) |p| {
                const done = l.sub_stats.works.load(.monotonic);
                const busy = p.busyNow();
                if (done != subs_done or busy == 0) {
                    subs_done = done;
                    subs_at = now;
                } else if (now - subs_at >= 5000 * ms and now - said_subs >= 10_000 * ms) {
                    said_subs = now;
                    std.log.warn("native: stall: {d} subscription batches queued or running and none finished for {d} ms (store tip {d})", .{ busy, (now - subs_at) / ms, tip });
                }
            }
        }
    }

    /// One pass: block in one batched receive until a datagram or the next timer (SO_RCVTIMEO;
    /// a timer under 10 ms away is waited for with ppoll on Linux, `udpio.Sock.waitShort`),
    /// drain the socket in batches, run every connection, then send everything queued
    /// with one batched send per 32 datagrams. An idle request/response round trip is one
    /// receive and one send syscall.
    fn ioLoop(l: *Listener) void {
        // macOS: ZUI_NATIVE_QOS=1 runs the I/O thread at QOS_CLASS_USER_INTERACTIVE (P cores).
        if (comptime @import("builtin").os.tag.isDarwin()) if (std.c.getenv("ZUI_NATIVE_QOS") != null) {
            const f = @extern(*const fn (c_uint, c_int) callconv(.c) c_int, .{ .name = "pthread_set_qos_class_self_np" });
            _ = f(0x21, 0);
        };
        var more = false; // a connection still had datagrams to send at the burst cap
        var last_busy: u64 = 0;
        // the longest pass in this window and the one before (`io_stall_max_ns`)
        var stall_cur: u64 = 0;
        var stall_prev: u64 = 0;
        var window_start: u64 = l.nowNs();
        const spin_ns: u64 = @as(u64, l.opts.spin_us) * std.time.ns_per_us;
        while (!l.stop_flag.load(.acquire)) {
            var now = l.nowNs();
            var wait_ns: u64 = 50 * std.time.ns_per_ms;
            var any_sub = false;
            var it = l.slots.valueIterator();
            while (it.next()) |sp| {
                if (sp.*.conn.nextTimeout()) |t| wait_ns = @min(wait_ns, t -| now);
                if (sp.*.subs.items.len > 0) any_sub = true;
            }
            if (any_sub) wait_ns = @min(wait_ns, 5 * std.time.ns_per_ms);
            if (l.gate_waiting) {
                wait_ns = @min(wait_ns, 5 * std.time.ns_per_ms);
                l.gate_waiting = false;
            }
            const spinning = spin_ns != 0 and now -| last_busy < spin_ns;
            const block = !more and !spinning and wait_ns >= std.time.ns_per_ms;
            const pass = l.stats.io_passes.fetchAdd(1, .monotonic);
            if (!block) _ = l.stats.io_polls.fetchAdd(1, .monotonic);
            if (pass % 64 == 0) {
                l.stats.io_cpu_ns.store(threadCpuNs(), .monotonic);
                l.stats.io_major_faults.store(threadMajorFaults(), .monotonic);
                l.cc_stats.sample(&l.slots);
            }
            var n = l.rx.recvWait(&l.us, if (block) wait_ns else 0);
            const pass_start = l.nowNs();
            defer {
                const end = l.nowNs();
                const dt = end -| pass_start;
                _ = l.stats.io_busy_ns.fetchAdd(dt, .monotonic);
                stall_cur = @max(stall_cur, dt);
                if (end -| window_start >= 10 * std.time.ns_per_s) {
                    stall_prev = stall_cur;
                    stall_cur = 0;
                    window_start = end;
                }
                l.io_stall_max_ns.store(@max(stall_cur, stall_prev), .monotonic);
            }
            if (n > 0) last_busy = now;
            if (n == 0 and spinning and !more) {
                std.atomic.spinLoopHint();
                continue;
            }
            var rounds: usize = 0;
            while (n > 0) {
                for (0..n) |i| {
                    const d = l.rx.data(i);
                    _ = l.stats.bytes_in.fetchAdd(d.len, .monotonic);
                    l.onDatagram(l.rx.from(i), d);
                }
                rounds += 1;
                if (n < udpio.max_batch or rounds >= 128) break;
                n = l.rx.recv(&l.us, false);
            }
            now = l.nowNs();
            const tip = l.disp.svc.store.committed();
            var dead: std.ArrayList(u64) = .empty;
            defer dead.deinit(l.gpa);
            more = false;
            var it2 = l.slots.valueIterator();
            while (it2.next()) |sp| {
                const s = sp.*;
                if (s.conn.nextTimeout()) |t| if (now >= t) s.conn.onTimeout(now);
                l.service(s, tip);
                if (l.flush(s, now)) more = true;
                if (s.conn.isClosed()) dead.append(l.gpa, s.key) catch {};
            }
            l.tx.flush(&l.us);
            l.stats.datagrams_out.store(l.us.stats.sent, .monotonic);
            l.stats.send_calls.store(l.us.stats.send_calls, .monotonic);
            for (dead.items) |k| if (l.slots.fetchRemove(k)) |kv| {
                _ = l.stats.active.fetchSub(1, .monotonic);
                if (kv.value.kind == .pending) l.half_open -|= 1;
                for (kv.value.reqs.keys(), kv.value.reqs.values()) |id, *r| if (r.relay) |rr| l.relayDetach(k, id, rr);
                if (l.feed_jobs) |j| j.cancel(k); // its queued feed requests give their places back
                if (l.read_jobs) |j| j.cancel(k);
                l.freeSlot(kv.value);
            };
            l.relaySweep();
        }
    }

    fn findOdcid(l: *Listener, dcid: []const u8) ?*Slot {
        var it = l.slots.valueIterator();
        while (it.next()) |sp| {
            const s = sp.*;
            if (s.odcid_len == dcid.len and std.mem.eql(u8, s.odcid[0..s.odcid_len], dcid)) return s;
        }
        return null;
    }

    fn onDatagram(l: *Listener, from: Io.net.IpAddress, d: []u8) void {
        if (d.len < 1 + conn_mod.cid_len) return;
        const now = l.nowNs();
        if (d[0] & 0x80 == 0) {
            const s = l.slots.get(std.mem.readInt(u64, d[1..][0..8], .little)) orelse return;
            s.conn.handleDatagram(now, d);
            return;
        }
        if (d.len < 7) return;
        const version = std.mem.readInt(u32, d[1..5], .big);
        const dl = d[5];
        if (dl > 20 or d.len < 6 + dl + 1) return;
        const dcid = d[6..][0..dl];
        const sl = d[6 + dl];
        if (sl > 20 or d.len < 7 + dl + sl) return;
        const scid = d[7 + dl ..][0..sl];
        if (dl == conn_mod.cid_len) if (l.slots.get(std.mem.readInt(u64, dcid[0..8], .little))) |s| {
            s.conn.handleDatagram(now, d);
            return;
        };
        if (l.findOdcid(dcid)) |s| {
            s.conn.handleDatagram(now, d);
            return;
        }
        if (version != 1) return;
        const ty = (d[0] >> 4) & 3;
        if (ty != 0 or d.len < 1200 or dl < 8) return;
        // Under a handshake flood a client first proves it receives at its address (a Retry and
        // its token); nothing is kept until it does.
        var ab: [19]u8 = undefined;
        const abytes = net.retry.addrBytes(&from, &ab);
        const tok = net.retry.initialToken(d) orelse return;
        const now_s: u32 = @truncate(@as(u64, @intCast(@divTrunc(Io.Clock.real.now(l.io).toNanoseconds(), std.time.ns_per_s))));
        var orig_buf: [20]u8 = undefined;
        var orig: ?[]const u8 = null;
        if (tok.len > 0) if (l.guard.check(tok, abytes, now_s)) |o| {
            @memcpy(orig_buf[0..o.len], o);
            orig = orig_buf[0..o.len];
        };
        if (orig == null and l.half_open >= l.opts.retry_threshold) {
            var tb: [net.retry.max_token]u8 = undefined;
            const t = l.guard.token(&tb, abytes, now_s, dcid);
            var nscid: [conn_mod.cid_len]u8 = undefined;
            l.io.random(&nscid);
            if (l.tx.full()) l.tx.flush(&l.us);
            const n = net.retry.writeRetry(l.tx.slot(), version, scid, &nscid, t, dcid, @truncate(nscid[0]));
            l.tx.commit(n, &from);
            _ = l.stats.retries.fetchAdd(1, .monotonic);
            return;
        }
        if (l.slots.count() >= l.opts.max_connections) return;
        var seed: [64]u8 = undefined;
        l.io.random(&seed);
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(l.io).toNanoseconds(), std.time.ns_per_s));
        // the certificate of this moment: a rotation changes what later handshakes get
        const ident: ?*certs_mod.Entry = if (l.opts.certs) |cs| cs.acquire() else null;
        const h3_cert: ?*const cert_mod.Cert = if (ident) |e| &e.cert else l.opts.cert;
        const c = conn_mod.Connection.initServer(l.gpa, .{
            .server_name = "zui",
            .identity_seed = l.opts.identity_seed,
            .seed = seed,
            .now_unix = now_unix,
            .max_streams_bidi = l.opts.max_streams,
            .max_streams_uni = 16,
            .max_data = 16 << 20,
            .max_stream_data = 1 << 20,
            .idle_timeout_ms = l.opts.idle_timeout_ms,
            .keep_alive_ms = 0,
            .alpn = &alpns,
            .client_auth = false,
            .alt = if (h3_cert) |ct| .{ .alpn_index = 1, .cert_der = ct.bytes(), .key = ct.key } else null,
            .chain = if (ident) |e| e.chainPtr() else null,
            .max_datagram_frame_size = 65535,
            .pmtu_max = if (l.opts.pmtud) pathCeiling(&from) else 1452,
            .handshake_timeout_ms = l.opts.handshake_timeout_ms,
            .pacing = l.opts.pacing,
            .hystart = l.opts.hystart,
            .cubic = l.opts.cubic,
            .pmtud = l.opts.pmtud,
            .iw_mtu = l.opts.iw_mtu,
            .bbr = l.opts.bbr,
            .early_send = l.opts.early_settings,
        }, now, dcid, scid) catch {
            if (ident) |e| l.opts.certs.?.release(e);
            return;
        };
        if (orig) |o| {
            c.markRetried(o, dcid);
            _ = l.stats.retried_ok.fetchAdd(1, .monotonic);
        }
        const s = l.gpa.create(Slot) catch {
            c.deinit();
            if (ident) |e| l.opts.certs.?.release(e);
            return;
        };
        s.* = .{ .conn = c, .addr = from, .key = std.mem.readInt(u64, &c.scid, .little), .ident = ident };
        s.odcid_len = dl;
        @memcpy(s.odcid[0..dl], dcid);
        l.slots.put(l.gpa, s.key, s) catch {
            l.freeSlot(s);
            return;
        };
        _ = l.stats.accepted.fetchAdd(1, .monotonic);
        _ = l.stats.active.fetchAdd(1, .monotonic);
        l.half_open += 1;
        c.handleDatagram(now, d);
    }

    /// Datagrams one connection may queue per loop pass, so a bulk sender (a checkpoint replay)
    /// shares the socket with request/response connections; cwnd bounds it as well.
    const burst = 64;

    /// Builds the connection's datagrams in place in the shared TxBatch (sent when it fills and
    /// at the end of the pass). Returns true when the burst cap left datagrams unsent.
    fn flush(l: *Listener, s: *Slot, now: u64) bool {
        var k: usize = 0;
        while (k < burst) : (k += 1) {
            if (l.tx.full()) l.tx.flush(&l.us);
            const n = s.conn.pollTransmit(now, l.tx.slot()) orelse return false;
            l.tx.commit(n, &s.addr);
            _ = l.stats.bytes_out.fetchAdd(n, .monotonic);
        }
        return true;
    }

    fn service(l: *Listener, s: *Slot, tip: ?u64) void {
        const c = s.conn;
        const cio: CIo = .{ .c = c };
        if (!c.isEstablished()) {
            // `early_settings`: an HTTP/3 client gets the control and QPACK streams with the
            // handshake flight. The slot stays `.pending` until the handshake is done.
            if (c.canSendEarly() and s.h3s == null and c.alpnIndex() == 1) {
                s.h3s = h3.ServerSession.init(l.gpa);
                s.h3s.?.start(cio) catch return c.closeApp(0x101);
            }
            return;
        }
        if (s.kind == .pending) {
            l.half_open -|= 1;
            s.kind = if (c.alpnIndex() == 1) .h3 else .zui;
            if (s.kind == .h3 and s.h3s == null) {
                s.h3s = h3.ServerSession.init(l.gpa);
                s.h3s.?.start(cio) catch return c.closeApp(0x101);
            }
        }
        switch (s.kind) {
            .zui => {
                while (c.acceptUni()) |id| c.streamFree(id);
                while (c.acceptBidi()) |id| s.reqs.put(l.gpa, id, .{}) catch {};
                for (s.reqs.keys(), s.reqs.values()) |id, *r| {
                    const st = c.stream(id) orelse {
                        if (r.relay) |rr| l.relayDetach(s.key, id, rr);
                        r.relay = null;
                        r.done = true;
                        continue;
                    };
                    if (st.reset != null) {
                        // the client cancelled (spec 3.1): stop and free the stream
                        l.cancelReq(s, id, r);
                        continue;
                    }
                    const data = st.recv.contiguous();
                    if (data.len > 0) {
                        r.buf.appendSlice(l.gpa, data) catch {};
                        st.recv.consume(data.len);
                    }
                    if (st.recv.complete()) r.fin = true;
                }
            },
            .h3 => l.serviceH3(s, cio),
            .pending => unreachable,
        }
        // slow methods finished on a worker
        if (l.jobs) |j| j.collect(s.key, JobCtx{ .l = l, .s = s }, jobDone, &l.slots);
        if (l.feed_jobs) |j| j.collect(s.key, JobCtx{ .l = l, .s = s }, jobDone, &l.slots);
        if (l.read_jobs) |j| j.collect(s.key, JobCtx{ .l = l, .s = s }, jobDone, &l.slots);
        if (l.sub_jobs) |p| p.collect(s.key, JobCtx{ .l = l, .s = s }, subWorkDone, &l.slots);
        // requests
        var i: usize = 0;
        while (i < s.reqs.count()) {
            const id = s.reqs.keys()[i];
            const r = &s.reqs.values()[i];
            if (r.relay != null) l.relayPump(s, id, r) else if (r.sub) |sid| l.creditPump(s, r, sid) else if (!r.done) l.tryRequest(s, id, r, tip);
            if (r.done and r.relay == null and r.sub == null and !r.queued) {
                r.buf.deinit(l.gpa);
                s.reqs.swapRemoveAt(i);
                continue;
            }
            i += 1;
        }
        // finished responses
        i = 0;
        while (i < s.answered.items.len) {
            const id = s.answered.items[i];
            if (c.stream(id) == null) {
                _ = s.answered.swapRemove(i);
                continue;
            }
            // Every packet of the response acknowledged, not just sent (conn.streamSettled). Freed
            // on "all sent", a packet lost afterwards could not be resent (its stream was gone)
            // and the client waited out its 20 s request timeout: the edge catch-up stall.
            if (c.streamSettled(id)) {
                c.streamFree(id);
                _ = s.answered.swapRemove(i);
                continue;
            }
            i += 1;
        }
        l.pumpSubs(s, tip);
    }

    fn serviceH3(l: *Listener, s: *Slot, cio: CIo) void {
        const c = s.conn;
        const hs = &s.h3s.?;
        while (c.acceptUni()) |id| s.h3_streams.put(l.gpa, id, false) catch {};
        while (c.acceptBidi()) |id| s.h3_streams.put(l.gpa, id, false) catch {};
        var i: usize = 0;
        while (i < s.h3_streams.count()) {
            const id = s.h3_streams.keys()[i];
            const fin_done = &s.h3_streams.values()[i];
            const st = c.stream(id) orelse {
                s.h3_streams.swapRemoveAt(i);
                continue;
            };
            if (st.reset != null) {
                const unwritten = st.send_off == 0 and st.send_buf.items.len == 0 and !st.fin_queued;
                if (s.reqs.getPtr(id)) |r| {
                    l.cancelReq(s, id, r);
                } else if (unwritten) {
                    // an HTTP/3 request or a client uni stream reset before any answer
                    c.streamAbort(id, h3_request_cancelled);
                }
                if (hs.onReset(cio, id)) |dv| l.deliver(s, dv);
                s.h3_streams.swapRemoveAt(i);
                continue;
            }
            const data = st.recv.contiguous();
            const fin = st.recv.fin_at != null and st.recv.base + data.len >= st.recv.fin_at.?;
            if (data.len > 0 or (fin and !fin_done.*)) {
                const n = data.len;
                const dv = hs.onStream(cio, id, data, fin) catch {
                    c.closeApp(hs.err_code);
                    return;
                };
                // deliver first: wt_data.bytes may point into the receive buffer `consume` moves
                if (dv) |d| l.deliver(s, d);
                if (c.stream(id)) |st2| if (n > 0) st2.recv.consume(n);
                if (fin) fin_done.* = true;
                // The session is done with the stream (answered 400/404/405/429, a finished
                // client uni stream, a stream of a stale session) and no zui/1 request owns it.
                if (!hs.streams.contains(id) and !s.reqs.contains(id)) if (c.stream(id)) |st2| {
                    if (st2.fin_queued) {
                        s.answered.append(l.gpa, id) catch {};
                    } else if (id & 2 != 0) {
                        c.streamFree(id); // uni: nothing to send
                    } else {
                        c.streamAbort(id, h3_request_cancelled);
                    }
                    s.h3_streams.swapRemoveAt(i);
                    continue;
                };
            }
            i += 1;
        }
    }

    /// H3_REQUEST_CANCELLED (RFC 9114 section 8.1).
    const h3_request_cancelled: u64 = 0x10c;

    /// The client reset request stream `id`: detach a relay, drop a request in progress (a
    /// worker's answer finds the stream gone), and free the stream with STOP_SENDING/RESET_STREAM
    /// as needed. A subscription's control stream is left to `pumpSubs`, which ends it.
    fn cancelReq(l: *Listener, s: *Slot, id: u64, r: *ReqStream) void {
        if (r.relay) |rr| l.relayDetach(s.key, id, rr);
        r.relay = null;
        if (r.sub != null) return;
        r.done = true;
        s.conn.streamAbort(id, l.cancelCode(s));
    }

    /// The zui/1 code 0 as a stream error: itself on raw QUIC, its WebTransport code under h3.
    fn cancelCode(l: *const Listener, s: *const Slot) u64 {
        _ = l;
        return if (s.kind == .h3) h3.wtErrorCode(0) else 0;
    }

    fn deliver(l: *Listener, s: *Slot, dv: h3.Delivery) void {
        switch (dv) {
            .session_open => |o| {
                s.session = o.stream;
                if (o.token) |t| if (l.disp.hooks.auth) |au| {
                    s.principal = au.check(au.ctx, t);
                };
                if (l.opts.gate != null) if (o.token) |t| l.gateSetKey(s, t);
            },
            .session_closed => s.conn.closeApp(0),
            .wt_data => |d| {
                if (!d.bidi) return; // zui/1 defines no client uni streams
                const gop = s.reqs.getOrPut(l.gpa, d.stream) catch return;
                if (!gop.found_existing) gop.value_ptr.* = .{};
                gop.value_ptr.buf.appendSlice(l.gpa, d.bytes) catch {};
                if (d.fin) gop.value_ptr.fin = true;
            },
        }
    }

    const JobCtx = struct { l: *Listener, s: *Slot };
    fn jobDone(ctx: JobCtx, id: u64, bytes: []const u8) void {
        if (ctx.s.reqs.getPtr(id)) |r| {
            r.queued = false;
            ctx.l.gateSettle(r, bytes);
        }
        if (ctx.s.conn.stream(id) == null) return; // the client reset it
        ctx.l.respond(ctx.s, id, bytes);
    }

    fn wakeSelf(ctx: *anyopaque) void {
        const l: *Listener = @ptrCast(@alignCast(ctx));
        var to = l.sock.address;
        switch (to) {
            .ip4 => |*a| if (std.mem.eql(u8, &a.bytes, &.{ 0, 0, 0, 0 })) {
                a.bytes = .{ 127, 0, 0, 1 };
            },
            .ip6 => |*a| if (std.mem.allEqual(u8, &a.bytes, 0)) {
                a.bytes[15] = 1;
            },
        }
        // a 1-byte datagram: onDatagram drops it, poll returns
        l.sock.send(l.io, &to, &.{0}) catch {};
    }

    fn slowJobs(l: *Listener) ?*jobs_mod.Jobs {
        if (l.jobs) |j| return j;
        const j = l.gpa.create(jobs_mod.Jobs) catch return null;
        j.* = .{ .gpa = l.gpa, .io = l.io, .disp = l.disp, .wake = .{ .ctx = l, .call = wakeSelf }, .workers = l.opts.slow_workers, .on_exit = l.opts.slow_worker_exit };
        l.jobs = j;
        return j;
    }

    fn feedJobs(l: *Listener) ?*jobs_mod.Jobs {
        if (l.feed_jobs) |j| return j;
        const j = l.gpa.create(jobs_mod.Jobs) catch return null;
        j.* = .{ .gpa = l.gpa, .io = l.io, .disp = l.disp, .wake = .{ .ctx = l, .call = wakeSelf }, .workers = l.opts.feed_workers, .max_inflight = l.opts.feed_queue, .on_exit = l.opts.slow_worker_exit };
        // the queue is divided between clients (`feedClient`)
        j.shares = .{ .cap = l.opts.feed_queue, .workers = l.opts.feed_workers, .min_share = l.opts.feed_min_share };
        j.share_stats = &l.feed_stats;
        j.evict_message = feed_refused;
        l.feed_jobs = j;
        return j;
    }

    fn readJobs(l: *Listener) ?*jobs_mod.Jobs {
        if (l.read_jobs) |j| return j;
        const j = l.gpa.create(jobs_mod.Jobs) catch return null;
        const workers = @max(l.opts.read_workers, 1);
        j.* = .{ .gpa = l.gpa, .io = l.io, .disp = l.disp, .wake = .{ .ctx = l, .call = wakeSelf }, .workers = workers, .max_inflight = l.opts.read_queue, .may_block = false };
        j.shares = .{ .cap = l.opts.read_queue, .workers = workers, .min_share = l.opts.read_min_share };
        j.share_stats = &l.read_stats;
        j.evict_message = read_refused;
        l.read_jobs = j;
        return j;
    }

    const read_refused = "too many requests in flight";

    fn subJobs(l: *Listener) ?*subjobs.Pool {
        if (l.sub_jobs) |p| return p;
        const p = l.gpa.create(subjobs.Pool) catch return null;
        p.* = .{ .gpa = l.gpa, .io = l.io, .disp = l.disp, .keys = &l.keys, .wake = .{ .ctx = l, .call = wakeSelf }, .workers = @max(l.opts.sub_workers, 1), .stats = &l.sub_stats };
        l.sub_jobs = p;
        return p;
    }

    /// The message of RATE_LIMITED on a feed request (an edge halves its requests in flight).
    const feed_refused = "too many feed requests in flight";

    /// Who a feed request is accounted to in the feed queue's shares. The API key the
    /// connection authenticated with (hello or the WebTransport session token), when it has
    /// one. Else the peer's address without the port: the listener asks for no client
    /// certificate and an edge sends no token, so an edge is known by its address only, and its
    /// connections (four with the edge profile, each from its own port) are one client with
    /// one share. IPv4 is the whole address (also IPv4-mapped on a dual-stack socket); IPv6 is
    /// the /64, which one host holds whole.
    pub fn feedClient(principal: ?dispatch.Principal, addr: *const Io.net.IpAddress) fairq.Key {
        if (principal) |p| return (@as(fairq.Key, 1) << 64) | p.id;
        switch (addr.*) {
            .ip4 => |a| return (@as(fairq.Key, 4) << 64) | std.mem.readInt(u32, &a.bytes, .big),
            .ip6 => |a| {
                if (std.mem.eql(u8, a.bytes[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff }))
                    return (@as(fairq.Key, 4) << 64) | std.mem.readInt(u32, a.bytes[12..16], .big);
                return (@as(fairq.Key, 6) << 64) | std.mem.readInt(u64, a.bytes[0..8], .big);
            },
        }
    }

    /// Credit varints written on a subscription's control stream after the SubscribeReq.
    fn creditPump(l: *Listener, s: *Slot, r: *ReqStream, sid: u64) void {
        const sb = for (s.subs.items) |*x| {
            if (x.id == sid) break x;
        } else {
            r.sub = null;
            r.done = true;
            return;
        };
        var p: usize = r.consumed;
        while (p < r.buf.items.len) {
            var q = p;
            const v = proto.getVarint(r.buf.items, &q) orelse break;
            p = q;
            if (!sb.credit_on) {
                sb.credit_on = true;
                sb.granted = sb.req.max_lag;
            }
            sb.granted +|= v;
        }
        if (p > 0) {
            const rest = r.buf.items.len - p;
            std.mem.copyForwards(u8, r.buf.items[0..rest], r.buf.items[p..]);
            r.buf.shrinkRetainingCapacity(rest);
            r.consumed = 0;
        }
        _ = l;
    }

    /// The control stream of sub `ctrl` no longer carries credit (the sub ended).
    fn subGone(s: *Slot, ctrl: u64) void {
        if (s.reqs.getPtr(ctrl)) |r| {
            r.sub = null;
            r.done = true;
        }
    }

    fn respond(l: *Listener, s: *Slot, id: u64, bytes: []const u8) void {
        s.conn.streamWrite(id, bytes, true) catch return;
        s.answered.append(l.gpa, id) catch {};
    }

    fn tryRequest(l: *Listener, s: *Slot, id: u64, r: *ReqStream, tip: ?u64) void {
        const max: usize = proto.max_submit_bytes;
        defer _ = l.req_arena.reset(.{ .retain_with_limit = 1 << 20 });
        const a = l.req_arena.allocator();
        var out: std.ArrayList(u8) = .empty;
        if (r.buf.items.len > max) {
            proto.errorResponse(&out, a, .too_large, "request too large", "") catch return;
            l.respond(s, id, out.items);
            r.done = true;
            return;
        }
        const req = proto.parseRequest(r.buf.items) orelse {
            if (r.fin) {
                _ = l.stats.bad_requests.fetchAdd(1, .monotonic);
                proto.errorResponse(&out, a, .bad_request, "request header", "") catch return;
                l.respond(s, id, out.items);
                r.done = true;
            }
            return;
        };
        if (req.method == .pair_relay) {
            if (req.body.len < 69) {
                if (r.fin) {
                    proto.errorResponse(&out, a, .bad_request, "short PairReq", "") catch return;
                    l.respond(s, id, out.items);
                    r.done = true;
                }
                return;
            }
            if (l.opts.gate != null) {
                if (!l.gateAdmit(s, id, r, req, a)) return;
                // a relay is one call: counted when it attaches
                l.gateSettle(r, &.{0});
            }
            l.relayAttach(s, id, r, req, a);
            return;
        }
        if (req.method == .subscribe) {
            // complete once the SubscribeReq decodes (the client may keep its side open for credit)
            var sr = sub.parse(req.body) catch |e| {
                if (e == error.Malformed and !r.fin) return;
                proto.errorResponse(&out, a, if (e == error.Unimplemented) .unimplemented else .bad_request, @errorName(e), "") catch return;
                l.respond(s, id, out.items);
                r.done = true;
                return;
            };
            if (l.opts.gate != null and r.gate == null and !l.gateAdmit(s, id, r, req, a)) return;
            r.done = true;
            if (req.flags & ~(proto.flag_verify | proto.flag_zstd_ok) != 0) {
                l.gateSubFailed(r);
                proto.errorResponse(&out, a, .bad_request, "unknown flags", "") catch return;
                return l.respond(s, id, out.items);
            }
            sr.verify = req.flags & proto.flag_verify != 0;
            sub.own(l.gpa, &sr) catch {
                l.gateSubFailed(r);
                proto.errorResponse(&out, a, .bad_request, "filter", "") catch return;
                return l.respond(s, id, out.items);
            };
            const sid = l.startSub(s, id, sr, tip, a) orelse {
                l.gateSubFailed(r);
                var tmp = sr;
                sub.deinit(l.gpa, &tmp);
                return;
            };
            if (r.gate) |t| {
                // the subscription holds the ticket (its stream slot) from here on
                l.gateSettle(r, &.{0});
                s.subs.items[s.subs.items.len - 1].gate = t;
            }
            r.sub = sid;
            r.consumed = (r.buf.items.len - req.body.len) + (sub.bodyLen(req.body) catch req.body.len);
            l.creditPump(s, r, sid);
            return;
        }
        if (!r.fin) return;
        if (l.opts.gate != null and r.gate == null and !l.gateAdmit(s, id, r, req, a)) return;
        r.done = true;
        _ = l.stats.requests.fetchAdd(1, .monotonic);
        if (dispatch.slowMethod(req.method) or l.disp.offThread(req)) {
            const j = l.slowJobs();
            if (j != null and j.?.push(s.key, id, s.principal, r.buf.items)) {
                r.queued = true;
                return;
            }
            l.gateSettle(r, &.{6});
            proto.errorResponse(&out, a, .rate_limited, "too many executions in flight", &.{ 0, 0, 0, 0 }) catch return;
            return l.respond(s, id, out.items);
        }
        if (dispatch.feedMethod(req.method)) {
            const j = l.feedJobs();
            if (j != null and j.?.pushFor(feedClient(s.principal, &s.addr), s.key, id, s.principal, r.buf.items)) {
                r.queued = true;
                return;
            }
            l.gateSettle(r, &.{6});
            proto.errorResponse(&out, a, .rate_limited, feed_refused, &.{ 0, 0, 0, 0 }) catch return;
            return l.respond(s, id, out.items);
        }
        // a token in hello replaces the connection's principal when it is accepted (spec 6)
        if (req.method == .hello) if (dispatch.helloToken(req.body)) |t| if (l.disp.hooks.auth) |au| if (au.check(au.ctx, t)) |p| {
            s.principal = p;
        };
        // every answer reads the store: on a worker (the module comment)
        const j = l.readJobs();
        if (j != null and j.?.pushFor(feedClient(s.principal, &s.addr), s.key, id, s.principal, r.buf.items)) {
            r.queued = true;
            return;
        }
        l.gateSettle(r, &.{6});
        proto.errorResponse(&out, a, .rate_limited, read_refused, &.{ 0, 0, 0, 0 }) catch return;
        return l.respond(s, id, out.items);
    }

    // ------------------------------------------------------------ access gate (Options.gate)

    fn gateSetKey(l: *Listener, s: *Slot, key: []const u8) void {
        const copy = l.gpa.dupe(u8, key[0..@min(key.len, 257)]) catch return;
        l.gpa.free(s.gate_key);
        s.gate_key = copy;
    }

    /// Puts a complete request to the gate. True: go on (a ticket is in `r.gate`, unless the
    /// request is a hello, which is never charged). False: the request was refused and
    /// answered, or its key is still being looked up and the next pass asks again.
    fn gateAdmit(l: *Listener, s: *Slot, id: u64, r: *ReqStream, req: proto.Request, a: Allocator) bool {
        const g = l.opts.gate.?;
        const now = l.nowMs();
        if (r.gate_wait_ms == 0) r.gate_wait_ms = now;
        const may_wait = now -| r.gate_wait_ms < gate_mod.wait_ms;
        var refusal: gate_mod.Refusal = undefined;
        if (req.method == .hello) {
            const token = dispatch.helloToken(req.body) orelse return true;
            switch (g.hello(g.ctx, token, s.addr, may_wait)) {
                .ok => {
                    l.gateSetKey(s, token);
                    return true;
                },
                .wait => {
                    l.gate_waiting = true;
                    return false;
                },
                .deny => |d| refusal = d,
            }
        } else switch (g.admit(g.ctx, s.gate_key, s.addr, req.method, req.body, may_wait)) {
            .allow => |t| {
                r.gate = t;
                return true;
            },
            .wait => {
                l.gate_waiting = true;
                return false;
            },
            .deny => |d| refusal = d,
        }
        var out: std.ArrayList(u8) = .empty;
        gate_mod.respond(&out, a, refusal) catch return false;
        l.respond(s, id, out.items);
        r.done = true;
        return false;
    }

    /// The request of `r` was answered with `response` (a zui/1 response: status byte first).
    fn gateSettle(l: *Listener, r: *ReqStream, response: []const u8) void {
        const t = r.gate orelse return;
        r.gate = null;
        if (l.opts.gate) |g| g.settle(g.ctx, &t, response.len > 0 and response[0] == 0);
    }

    /// A subscription that was admitted and then could not start.
    fn gateSubFailed(l: *Listener, r: *ReqStream) void {
        var t = r.gate orelse return;
        r.gate = null;
        const g = l.opts.gate orelse return;
        g.settle(g.ctx, &t, false);
        g.stream_close(g.ctx, &t);
    }

    fn gateSubClosed(l: *Listener, sb: *Sub) void {
        if (sb.gate) |*t| if (l.opts.gate) |g| g.stream_close(g.ctx, t);
        sb.gate = null;
    }

    fn startSub(l: *Listener, s: *Slot, ctrl: u64, sr: sub.Req, tip: ?u64, a: Allocator) ?u64 {
        var out: std.ArrayList(u8) = .empty;
        if (s.subs.items.len + relayCount(s) >= l.opts.max_subscriptions) {
            proto.errorResponse(&out, a, .rate_limited, "too many subscriptions", &.{ 0, 0, 0, 0 }) catch return null;
            l.respond(s, ctrl, out.items);
            return null;
        }
        var snap = l.disp.svc.store.snapshot();
        defer snap.release();
        const lowest = snap.lowestAvailable() orelse 0;
        const first = sr.start orelse (if (tip) |t| t + 1 else 0);
        if (first < lowest) {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, lowest, .little);
            proto.errorResponse(&out, a, .pruned, "start below the lowest available checkpoint", &b) catch return null;
            l.respond(s, ctrl, out.items);
            return null;
        }
        const c = s.conn;
        const data = (if (s.kind == .h3) s.h3s.?.openWtUni(CIo{ .c = c }, s.session orelse return null) else c.openUni()) catch {
            proto.errorResponse(&out, a, .rate_limited, "no stream credit", &.{ 0, 0, 0, 0 }) catch return null;
            l.respond(s, ctrl, out.items);
            return null;
        };
        const sid = l.next_sub;
        l.next_sub += 1;
        out.clearRetainingCapacity();
        proto.putVarint(&out, a, sid) catch return null;
        c.streamWrite(data, out.items, false) catch return null;
        out.clearRetainingCapacity();
        sub.ack(&out, a, sid, first, lowest) catch return null;
        c.streamWrite(ctrl, out.items, false) catch return null;
        s.subs.append(l.gpa, .{ .id = sid, .req = sr, .ctrl = ctrl, .data = data, .cursor = first, .last_match_ms = l.nowMs() }) catch return null;
        return sid;
    }

    fn endSub(l: *Listener, s: *Slot, i: usize, code: proto.Code, detail: u64) void {
        const sb = s.subs.items[i];
        const c = s.conn;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(l.gpa);
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(l.gpa);
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, detail, .little);
        proto.errorBody(&body, l.gpa, code, @tagName(code), &b) catch {};
        proto.frame(&out, l.gpa, .end, body.items) catch {};
        if (c.stream(sb.data) != null) {
            c.streamWrite(sb.data, out.items, true) catch {};
            s.answered.append(l.gpa, sb.data) catch {};
        }
        if (c.stream(sb.ctrl) != null) {
            c.streamWrite(sb.ctrl, "", true) catch {};
            s.answered.append(l.gpa, sb.ctrl) catch {};
        }
        subGone(s, sb.ctrl);
        l.gateSubClosed(&s.subs.items[i]);
        var rq = sb.req;
        sub.deinit(l.gpa, &rq);
        _ = s.subs.swapRemove(i);
    }

    // ------------------------------------------------------------ pair relay (0x30)

    fn relayCount(s: *const Slot) usize {
        var n: usize = 0;
        for (s.reqs.values()) |r| if (r.relay != null) {
            n += 1;
        };
        return n;
    }

    fn nowMs(l: *const Listener) u64 {
        return @intCast(@divTrunc(Io.Clock.real.now(l.io).toNanoseconds(), std.time.ns_per_ms));
    }

    fn relayFrame(l: *Listener, ref: StreamRef, ty: u64, payload: []const u8, fin: bool) void {
        const s = l.slots.get(ref.key) orelse return;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(l.gpa);
        proto.putVarint(&out, l.gpa, ty) catch return;
        proto.putVarint(&out, l.gpa, payload.len) catch return;
        out.appendSlice(l.gpa, payload) catch return;
        s.conn.streamWrite(ref.stream, out.items, fin) catch {};
    }

    /// END{code} on `ref`, FIN, and the stream leaves the relay (its slot is cleared by the caller).
    fn relayEnd(l: *Listener, ref: StreamRef, code: proto.Code, msg: []const u8) void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(l.gpa);
        proto.errorBody(&body, l.gpa, code, msg, "") catch {};
        l.relayFrame(ref, RELAY_END, body.items, true);
        const s = l.slots.get(ref.key) orelse return;
        if (s.reqs.getPtr(ref.stream)) |r| {
            r.relay = null;
            r.done = true;
        }
        s.answered.append(l.gpa, ref.stream) catch {};
    }

    fn relayAttach(l: *Listener, s: *Slot, id: u64, r: *ReqStream, req: proto.Request, a: Allocator) void {
        var out: std.ArrayList(u8) = .empty;
        const b = req.body;
        const role = b[0];
        const channel = b[1..33].*;
        const claim = b[33..65].*;
        const ttl = std.mem.readInt(u32, b[65..69], .little);
        const rest = b[69..];
        r.done = true;
        if (req.flags != 0 or role > 1) {
            proto.errorResponse(&out, a, .bad_request, "bad role or flags", "") catch return;
            return l.respond(s, id, out.items);
        }
        if (relayCount(s) >= relay_per_conn or s.subs.items.len + relayCount(s) >= l.opts.max_subscriptions) {
            proto.errorResponse(&out, a, .rate_limited, "too many relay channels", &.{ 0, 0, 0, 0 }) catch return;
            return l.respond(s, id, out.items);
        }
        l.relaySweep();
        const now = l.nowMs();
        const gop = l.channels.getOrPut(l.gpa, channel) catch return;
        if (!gop.found_existing) {
            const ch = l.gpa.create(Channel) catch {
                _ = l.channels.remove(channel);
                return;
            };
            const t: u64 = if (ttl == 0) relay_ttl_default_s else @min(ttl, relay_ttl_max_s);
            ch.* = .{ .expires_ms = now + t * 1000, .idle_since_ms = now };
            gop.value_ptr.* = ch;
        }
        const ch = gop.value_ptr.*;
        if (ch.claims[role]) |c| {
            if (!std.mem.eql(u8, &c, &claim)) {
                proto.errorResponse(&out, a, .permission_denied, "role claimed", "") catch return;
                return l.respond(s, id, out.items);
            }
        } else ch.claims[role] = claim;
        if (ch.streams[role]) |old| {
            ch.streams[role] = null;
            l.relayEnd(old, .unavailable, "superseded");
        }
        const me: StreamRef = .{ .key = s.key, .stream = id };
        ch.streams[role] = me;
        r.relay = .{ .channel = channel, .role = @intCast(role) };
        r.done = false;
        const peer = ch.streams[1 - role];
        proto.okHeader(&out, a, 0) catch return;
        const w: proto.W = .{ .gpa = a, .out = &out };
        w.int(u64, ch.expires_ms) catch return;
        w.u8_(if (peer != null) 1 else 0) catch return;
        s.conn.streamWrite(id, out.items, false) catch return;
        for (ch.bufs[role].items) |f| {
            l.relayFrame(me, RELAY_DATA, f, false);
            l.gpa.free(f);
        }
        ch.bufs[role].clearRetainingCapacity();
        ch.buf_bytes[role] = 0;
        if (peer) |p| l.relayFrame(p, RELAY_PEER_UP, "", false);
        // frames already behind the PairReq
        const keep = r.buf.items.len - rest.len;
        std.mem.copyForwards(u8, r.buf.items[0..rest.len], r.buf.items[keep..]);
        r.buf.shrinkRetainingCapacity(rest.len);
        l.relayPump(s, id, r);
    }

    fn relayPump(l: *Listener, s: *Slot, id: u64, r: *ReqStream) void {
        const rr = r.relay orelse return;
        const me: StreamRef = .{ .key = s.key, .stream = id };
        var p: usize = 0;
        defer {
            const rest = r.buf.items.len - p;
            std.mem.copyForwards(u8, r.buf.items[0..rest], r.buf.items[p..]);
            r.buf.shrinkRetainingCapacity(rest);
        }
        while (r.relay != null) {
            const ch = l.channels.get(rr.channel) orelse {
                l.relayEnd(me, .timeout, "channel expired");
                return;
            };
            var q = p;
            const ty = proto.getVarint(r.buf.items, &q) orelse break;
            const n = proto.getVarint(r.buf.items, &q) orelse break;
            if (ty != RELAY_DATA or n == 0 or n > relay_max_frame) {
                ch.streams[rr.role] = null;
                l.relayEnd(me, if (ty != RELAY_DATA) .bad_request else .too_large, "bad relay frame");
                l.peerDown(ch, rr.role);
                return;
            }
            if (r.buf.items.len - q < n) break;
            const payload = r.buf.items[q..][0..@intCast(n)];
            p = q + @as(usize, @intCast(n));
            const other: u1 = 1 - rr.role;
            if (ch.streams[other]) |peer| {
                l.relayFrame(peer, RELAY_DATA, payload, false);
            } else {
                if (ch.bufs[other].items.len >= relay_buf_frames or ch.buf_bytes[other] + payload.len > relay_buf_bytes) {
                    ch.streams[rr.role] = null;
                    l.relayEnd(me, .too_large, "peer buffer full");
                    return;
                }
                const copy = l.gpa.dupe(u8, payload) catch return;
                ch.bufs[other].append(l.gpa, copy) catch {
                    l.gpa.free(copy);
                    return;
                };
                ch.buf_bytes[other] += copy.len;
            }
        }
        if (r.fin and r.relay != null) {
            l.relayDetach(s.key, id, rr);
            r.relay = null;
            r.done = true;
            s.conn.streamWrite(id, "", true) catch {};
            s.answered.append(l.gpa, id) catch {};
        }
    }

    fn peerDown(l: *Listener, ch: *Channel, gone: u1) void {
        ch.idle_since_ms = l.nowMs();
        if (ch.streams[1 - gone]) |p| l.relayFrame(p, RELAY_PEER_DOWN, "", false);
    }

    /// The stream holding (channel, role) ended (FIN, reset, connection loss): clear the slot,
    /// PEER_DOWN to the other side. Buffers stay until expiry.
    fn relayDetach(l: *Listener, key: u64, id: u64, rr: RelayRef) void {
        const ch = l.channels.get(rr.channel) orelse return;
        const cur = ch.streams[rr.role] orelse return;
        if (cur.key != key or cur.stream != id) return;
        ch.streams[rr.role] = null;
        l.peerDown(ch, rr.role);
    }

    fn relaySweep(l: *Listener) void {
        if (l.channels.count() == 0) return;
        const now = l.nowMs();
        var drop: std.ArrayList([32]u8) = .empty;
        defer drop.deinit(l.gpa);
        var it = l.channels.iterator();
        while (it.next()) |e| {
            const ch = e.value_ptr.*;
            if (now >= ch.expires_ms) {
                for (&ch.streams) |*sr| if (sr.*) |ref| {
                    sr.* = null;
                    l.relayEnd(ref, .timeout, "channel expired");
                };
                drop.append(l.gpa, e.key_ptr.*) catch {};
            } else if (ch.streams[0] == null and ch.streams[1] == null and now - ch.idle_since_ms > relay_idle_ms) {
                drop.append(l.gpa, e.key_ptr.*) catch {};
            }
        }
        for (drop.items) |k| if (l.channels.fetchRemove(k)) |kv| {
            kv.value.deinit(l.gpa);
            l.gpa.destroy(kv.value);
        };
    }

    /// Runs every subscription of `s`: ends the ones the client cancelled or that lag, queues
    /// the production of the next frames (subjobs.zig) for the ones with credit and room, and
    /// sends heartbeats. No store read here: the frames come back through `subWorkDone`.
    fn pumpSubs(l: *Listener, s: *Slot, tip_opt: ?u64) void {
        if (s.subs.items.len == 0) return;
        const c = s.conn;
        var i: usize = 0;
        while (i < s.subs.items.len) {
            const sb = &s.subs.items[i];
            const ds = c.stream(sb.data);
            const cs = c.stream(sb.ctrl);
            if (ds == null or ds.?.stopped_by_peer != null or cs == null or cs.?.reset != null) {
                // the client ended it (spec 3.2): free both streams and their credit
                const code = l.cancelCode(s);
                c.streamAbort(sb.data, code);
                c.streamAbort(sb.ctrl, code);
                subGone(s, sb.ctrl);
                l.gateSubClosed(sb);
                sub.deinit(l.gpa, &sb.req);
                _ = s.subs.swapRemove(i);
                continue;
            }
            // (cancels are handled before the store has a checkpoint too)
            const tip = tip_opt orelse {
                i += 1;
                continue;
            };
            if (sb.cursor > tip) sb.live = true;
            if (sb.live and tip >= sb.cursor and tip - sb.cursor > sb.req.max_lag) {
                l.endSub(s, i, .lagged, sb.cursor -| 1);
                continue;
            }
            if (!sb.busy and sb.cursor <= tip) {
                const unsent = c.streamUnsent(sb.data);
                const credit: u64 = if (sb.credit_on) sb.granted -| sb.delivered else std.math.maxInt(u64);
                const max_cps = @min(@as(u64, 64), credit);
                if (unsent < l.opts.sub_backlog and max_cps > 0) if (l.subJobs()) |p| {
                    if (p.push(s.key, sb.id, &sb.req, sb.cursor, tip, max_cps, l.opts.sub_backlog - unsent)) sb.busy = true;
                };
            }
            if (l.opts.gate) |g| if (sb.gate) |*t| {
                // counts the frames and asks whether the caller may keep the stream
                const frames = sb.gate_frames;
                sb.gate_frames = 0;
                if (g.stream_frames(g.ctx, t, s.gate_key, @intCast(frames))) |refusal| {
                    l.endSub(s, i, refusal.code, sb.cursor -| 1);
                    continue;
                }
            };
            // a heartbeat only between checkpoints: never while frames up to the tip are coming
            if (sb.live and !sb.busy and sb.cursor > tip and sb.req.filter != .checkpoints) {
                const now = l.nowMs();
                if (now -| sb.last_match_ms >= heartbeat_ms) {
                    var hb: [8]u8 = undefined;
                    std.mem.writeInt(u64, &hb, tip, .little);
                    var out: std.ArrayList(u8) = .empty;
                    defer out.deinit(l.gpa);
                    proto.frame(&out, l.gpa, .heartbeat, &hb) catch {};
                    c.streamWrite(sb.data, out.items, false) catch {};
                    sb.last_match_ms = now;
                }
            }
            if (ds.?.send_buf.items.len > 4 * l.opts.sub_backlog) c.streamTrim(sb.data);
            i += 1;
        }
    }

    /// A worker's frames for a subscription (subjobs.zig): written to its data stream in one
    /// piece, the cursor moved past them; a checkpoint whose frames could not be built ends it.
    fn subWorkDone(ctx: JobCtx, w: *subjobs.Work) void {
        const l = ctx.l;
        const s = ctx.s;
        const i = for (s.subs.items, 0..) |*x, k| {
            if (x.id == w.sub_id) break k;
        } else return; // the subscription ended meanwhile
        const sb = &s.subs.items[i];
        sb.busy = false;
        if (w.start != sb.cursor) return;
        if (w.out.items.len > 0) s.conn.streamWrite(sb.data, w.out.items, false) catch return;
        _ = l.stats.sub_frames.fetchAdd(w.produced, .monotonic);
        sb.cursor += w.produced;
        sb.delivered += w.produced;
        sb.gate_frames += w.produced;
        if (w.matched) sb.last_match_ms = l.nowMs();
        if (w.failed) |e| {
            // A checkpoint whose frames cannot be built (say its input objects are not held)
            // would stall the stream forever: end it, naming the last checkpoint delivered.
            std.log.warn("zui/1 subscription: checkpoint {d}: {s}; ending it (UNAVAILABLE)", .{ sb.cursor, @errorName(e) });
            l.endSub(s, i, .unavailable, sb.cursor -| 1);
        }
    }

    /// The I/O thread's health and the work it hands to workers (`zui_native_*`, node metrics).
    pub fn renderWork(l: *Listener, w: *std.Io.Writer) !void {
        try w.print("# TYPE zui_native_io_stall_max_ms gauge\nzui_native_io_stall_max_ms {d}\n", .{l.io_stall_max_ns.load(.monotonic) / std.time.ns_per_ms});
        try l.read_stats.render(w, "zui_native_read");
        const ks = &l.keys.stats;
        try w.print("# TYPE zui_native_prestate_hits counter\nzui_native_prestate_hits {d}\n", .{ks.hits.load(.monotonic)});
        try w.print("# TYPE zui_native_prestate_coalesced counter\nzui_native_prestate_coalesced {d}\n", .{ks.coalesced.load(.monotonic)});
        try w.print("# TYPE zui_native_prestate_misses counter\nzui_native_prestate_misses {d}\n", .{ks.misses.load(.monotonic)});
        try w.print("# TYPE zui_native_prestate_compute_ns counter\nzui_native_prestate_compute_ns {d}\n", .{ks.compute_ns.load(.monotonic)});
        try w.print("# TYPE zui_native_prestate_compute_max_ms gauge\nzui_native_prestate_compute_max_ms {d}\n", .{ks.compute_max_ns.load(.monotonic) / std.time.ns_per_ms});
        const ps = &l.sub_stats;
        try w.print("# TYPE zui_native_sub_work_queue_depth gauge\nzui_native_sub_work_queue_depth {d}\n", .{ps.queued.load(.monotonic)});
        try w.print("# TYPE zui_native_sub_works counter\nzui_native_sub_works {d}\n", .{ps.works.load(.monotonic)});
        try w.print("# TYPE zui_native_sub_work_ns counter\nzui_native_sub_work_ns {d}\n", .{ps.produce_ns.load(.monotonic)});
        try w.print("# TYPE zui_native_sub_work_max_ms gauge\nzui_native_sub_work_max_ms {d}\n", .{ps.produce_max_ns.load(.monotonic) / std.time.ns_per_ms});
        // process-wide: kept threads (core/threads.zig) and every thread of the process; a
        // started count that keeps climbing is a thread per task somewhere
        const ts = &tcache.stats;
        try w.print("# TYPE zui_kept_threads gauge\nzui_kept_threads {d}\n", .{ts.threads.load(.monotonic)});
        try w.print("# TYPE zui_kept_threads_parked gauge\nzui_kept_threads_parked {d}\n", .{ts.parked.load(.monotonic)});
        try w.print("# TYPE zui_kept_threads_started counter\nzui_kept_threads_started {d}\n", .{ts.started.load(.monotonic)});
        try w.print("# TYPE zui_kept_threads_reused counter\nzui_kept_threads_reused {d}\n", .{ts.reused.load(.monotonic)});
        if (tcache.processThreads()) |n| try w.print("# TYPE zui_process_threads gauge\nzui_process_threads {d}\n", .{n});
    }
};

const ListenerTestClient = struct {
    io: Io,
    sock: Io.net.Socket,
    us: udpio.Sock,
    to: Io.net.IpAddress,
    c: *conn_mod.Connection,
    tx: udpio.TxBatch = .{},
    rx: udpio.RxBatch = .{},

    fn pump(t: *ListenerTestClient) void {
        var now: u64 = @intCast(Io.Clock.awake.now(t.io).toNanoseconds());
        while (t.c.pollTransmit(now, t.tx.slot())) |n| {
            t.tx.commit(n, &t.to);
            if (t.tx.full()) t.tx.flush(&t.us);
        }
        t.tx.flush(&t.us);
        t.us.setWait(5 * std.time.ns_per_ms);
        const n = t.rx.recv(&t.us, true);
        now = @intCast(Io.Clock.awake.now(t.io).toNanoseconds());
        for (0..n) |i| t.c.handleDatagram(now, t.rx.data(i));
        if (t.c.nextTimeout()) |d| if (now >= d) t.c.onTimeout(now);
    }
};

test "zui/1 listener: cancelled requests give their stream back, and stop sends CONNECTION_CLOSE" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 11, .max_transactions = 1 << 10, .max_checkpoints = 16, .max_batch_bytes = 16 << 20, .max_batch_objects = 1 << 10, .max_segments = 16, .segment_reserve = 4 << 20, .seed = 5 };
    const sim = try store.SimIo.init(gpa, 11, .{}, 32 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var svc: @import("serve").service.Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    var disp: dispatch.Dispatcher = .{ .svc = &svc };
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const cert = cert_mod.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui");
    const id_seed: [32]u8 = @splat(9);
    const l = try Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = &cert, .max_streams = 8 }, &disp);
    var stopped = false;
    defer if (!stopped) l.stop();

    var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    const sock = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
    defer sock.close(io);
    var seed: [64]u8 = @splat(2);
    const now0: u64 = @intCast(Io.Clock.awake.now(io).toNanoseconds());
    const c = try conn_mod.Connection.init(gpa, .{
        .server_name = "zui",
        .identity_seed = @splat(4),
        .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
        .seed = seed,
        .now_unix = 1_800_000_000,
        .alpn = &.{proto.alpn},
        .max_streams_uni = 16,
        .max_streams_bidi = 64,
        .keep_alive_ms = 0,
    }, now0);
    defer c.deinit();
    seed[0] = 1;
    var cl: ListenerTestClient = .{ .io = io, .sock = sock, .us = .init(sock.handle), .to = l.address(), .c = c };
    var rounds: usize = 0;
    while (!c.isEstablished()) : (rounds += 1) {
        if (rounds > 1000 or c.isClosed()) return error.TestUnexpectedResult;
        cl.pump();
    }
    // 40 requests cut off mid-header (a 2-byte method varint, one byte of it) and cancelled, with
    // 8 streams of credit: each must come back
    for (0..40) |_| {
        rounds = 0;
        const id = while (true) : (rounds += 1) {
            if (c.openBidi()) |id| break id else |_| {}
            if (rounds > 2000) return error.TestUnexpectedResult;
            cl.pump();
        };
        try c.streamWrite(id, &.{0x40}, false);
        for (0..3) |_| cl.pump();
        c.streamAbort(id, 0);
        cl.pump();
    }
    // and a whole request is still answered
    rounds = 0;
    const id = while (true) : (rounds += 1) {
        if (c.openBidi()) |id| break id else |_| {}
        if (rounds > 2000) return error.TestUnexpectedResult;
        cl.pump();
    };
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    try proto.encodeRequest(&req, gpa, .hello, 0, "");
    try c.streamWrite(id, req.items, true);
    rounds = 0;
    while (!(c.stream(id).?.recv.complete())) : (rounds += 1) {
        if (rounds > 2000) return error.TestUnexpectedResult;
        cl.pump();
    }
    try std.testing.expect(c.stream(id).?.recv.contiguous().len > 0);
    c.streamFree(id);
    // every datagram left through the batched send path, and it is counted
    const calls = l.stats.send_calls.load(.monotonic);
    try std.testing.expect(calls > 0 and l.stats.datagrams_out.load(.monotonic) >= calls);
    // stop: the client hears CONNECTION_CLOSE (zui/1 `shutdown`) instead of timing out
    l.stop();
    stopped = true;
    rounds = 0;
    while (!c.isClosed() and rounds < 200) : (rounds += 1) cl.pump();
    const cc = c.close orelse return error.TestUnexpectedResult;
    try std.testing.expect(cc.remote);
    try std.testing.expectEqual(@as(u64, @intFromEnum(proto.Code.shutdown)), cc.code);
}

/// A link for the pacing bench, applied by the client to what it receives: a rate, a tail-drop
/// queue and a one-way delay (rate 0: plain loopback).
const BenchLink = struct { name: []const u8, mbit: u64 = 0, delay_ms: u64 = 0, queue_ms: u64 = 50 };

const BenchRun = struct { bytes: u64, wall_ns: u64, cpu_ns: u64, passes: u64, polls: u64, dropped: u64 };

/// One bulk download through a real listener over loopback: `streams` requests for a 1 MiB
/// dictionary at a time until `total` bytes have arrived. The client thread spins (its CPU is
/// not what is measured) and plays the link. Returns the I/O thread's CPU time over the transfer.
fn paceBench(gpa: Allocator, io: Io, disp: *dispatch.Dispatcher, cert: *const cert_mod.Cert, dict_id: u32, opts: struct { pacing: bool = false, cubic: bool = false, bbr: bool = false }, link: BenchLink, total: u64) !BenchRun {
    const id_seed: [32]u8 = @splat(9);
    const l = try Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = cert, .max_streams = 64, .pacing = opts.pacing, .cubic = opts.cubic, .bbr = opts.bbr }, disp);
    defer l.stop();
    var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    const sock = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
    defer sock.close(io);
    const bufsz: c_int = 8 << 20;
    std.posix.setsockopt(sock.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&bufsz)) catch {};
    const seed: [64]u8 = @splat(2);
    const clock = struct {
        fn now(i: Io) u64 {
            return @intCast(Io.Clock.awake.now(i).toNanoseconds());
        }
    };
    const c = try conn_mod.Connection.init(gpa, .{
        .server_name = "zui",
        .identity_seed = @splat(4),
        .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
        .seed = seed,
        .now_unix = 1_800_000_000,
        .alpn = &.{proto.alpn},
        .keep_alive_ms = 0,
        .pmtu_max = 1452,
    }, clock.now(io));
    defer c.deinit();
    const us: *udpio.Sock = try gpa.create(udpio.Sock);
    defer gpa.destroy(us);
    us.* = .init(sock.handle);
    const tx = try gpa.create(udpio.TxBatch);
    defer gpa.destroy(tx);
    tx.* = .{};
    const rx = try gpa.create(udpio.RxBatch);
    defer gpa.destroy(rx);
    rx.* = .{};
    const to = l.address();
    // the link: datagrams wait here until their delivery time
    const Held = struct { at: u64, len: u16, data: [1500]u8 };
    var fifo: std.ArrayList(Held) = .empty;
    defer fifo.deinit(gpa);
    var head: usize = 0;
    var free_at: u64 = 0;
    const rate: u64 = link.mbit * 125_000;
    const queue_bytes: u64 = rate * link.queue_ms / 1000;
    var dropped: u64 = 0;

    const streams = 16;
    var open: [streams]?u64 = @splat(null);
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    try proto.encodeRequest(&req, gpa, .get_dictionary, 0, std.mem.asBytes(&std.mem.nativeToLittle(u32, dict_id)));
    var got: u64 = 0;
    var asked: u64 = 0;
    var start: ?u64 = null;
    var cpu0: u64 = 0;
    var passes0: u64 = 0;
    var polls0: u64 = 0;
    const deadline = clock.now(io) + 90 * std.time.ns_per_s;
    var res: BenchRun = undefined;
    while (true) {
        var now = clock.now(io);
        if (now > deadline or c.isClosed()) return error.TestUnexpectedResult;
        var busy = false;
        while (true) {
            const n = rx.recv(us, false);
            if (n == 0) break;
            busy = true;
            now = clock.now(io);
            for (0..n) |i| {
                const d = rx.data(i);
                if (rate == 0) {
                    c.handleDatagram(now, d);
                    continue;
                }
                const backlog = (free_at -| now) * rate / std.time.ns_per_s;
                if (backlog + d.len > queue_bytes or d.len > 1500) {
                    dropped += 1;
                    continue;
                }
                free_at = @max(now, free_at) + d.len * std.time.ns_per_s / rate;
                var h: Held = .{ .at = free_at + link.delay_ms * std.time.ns_per_ms, .len = @intCast(d.len), .data = undefined };
                @memcpy(h.data[0..d.len], d);
                try fifo.append(gpa, h);
            }
            if (n < udpio.max_batch) break;
        }
        while (head < fifo.items.len and fifo.items[head].at <= now) : (head += 1) {
            const h = &fifo.items[head];
            c.handleDatagram(now, h.data[0..h.len]);
            busy = true;
        }
        if (head > 0 and head == fifo.items.len) {
            fifo.clearRetainingCapacity();
            head = 0;
        } else if (head >= 1024) {
            const rest = fifo.items.len - head;
            std.mem.copyForwards(Held, fifo.items[0..rest], fifo.items[head..]);
            fifo.shrinkRetainingCapacity(rest);
            head = 0;
        }
        if (c.nextTimeout()) |t| if (now >= t) c.onTimeout(now);
        if (c.isEstablished()) {
            if (start == null) {
                start = now;
                cpu0 = l.stats.io_cpu_ns.load(.monotonic);
                passes0 = l.stats.io_passes.load(.monotonic);
                polls0 = l.stats.io_polls.load(.monotonic);
            }
            for (&open) |*slot| {
                if (slot.*) |id| {
                    const st = c.stream(id) orelse return error.TestUnexpectedResult;
                    const data = st.recv.contiguous();
                    if (data.len > 0) {
                        got += data.len;
                        st.recv.consume(data.len);
                    }
                    if (st.recv.complete()) {
                        c.streamFree(id);
                        slot.* = null;
                    }
                }
                if (slot.* == null and asked < total) {
                    const id = c.openBidi() catch continue;
                    try c.streamWrite(id, req.items, true);
                    slot.* = id;
                    asked += 1 << 20;
                }
            }
            var live = false;
            for (open) |o| if (o != null) {
                live = true;
            };
            if (!live and asked >= total) {
                res = .{
                    .bytes = got,
                    .wall_ns = now - start.?,
                    .cpu_ns = l.stats.io_cpu_ns.load(.monotonic) - cpu0,
                    .passes = l.stats.io_passes.load(.monotonic) - passes0,
                    .polls = l.stats.io_polls.load(.monotonic) - polls0,
                    .dropped = dropped,
                };
                break;
            }
        }
        while (c.pollTransmit(now, tx.slot())) |n| {
            tx.commit(n, &to);
            if (tx.full()) tx.flush(us);
            busy = true;
        }
        tx.flush(us);
        if (!busy) std.atomic.spinLoopHint();
    }
    return res;
}

test "native listener: I/O thread CPU during a bulk send, unpaced, paced and BBR (ZUI_NATIVE_PACE_BENCH=1)" {
    if (std.c.getenv("ZUI_NATIVE_PACE_BENCH") == null) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 11, .max_transactions = 1 << 10, .max_checkpoints = 16, .max_batch_bytes = 16 << 20, .max_batch_objects = 1 << 10, .max_segments = 16, .segment_reserve = 4 << 20, .seed = 5 };
    const sim = try store.SimIo.init(gpa, 11, .{}, 32 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var svc: @import("serve").service.Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    // the bulk: a 1 MiB dictionary, served whole by get_dictionary
    const dicts_mod = @import("dicts.zig");
    var ds = dicts_mod.Dicts.init(gpa);
    defer ds.deinit();
    {
        const content = try gpa.alloc(u8, 1 << 20);
        defer gpa.free(content);
        var prng = std.Random.DefaultPrng.init(3);
        prng.random().bytes(content);
        ds.owned[0] = try @TypeOf(ds.owned[0]).init(gpa, content, 3);
        ds.built[0] = true;
        ds.slots[0].store(&ds.owned[0], .release);
    }
    var disp: dispatch.Dispatcher = .{ .svc = &svc, .dicts = &ds };
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const cert = cert_mod.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui");
    const links = [_]BenchLink{
        .{ .name = "loopback" },
        .{ .name = "100Mbit 20ms", .mbit = 100, .delay_ms = 20 },
        .{ .name = "20Mbit 50ms", .mbit = 20, .delay_ms = 50 },
    };
    const modes = [_]struct { name: []const u8, pacing: bool = false, cubic: bool = false, bbr: bool = false }{
        .{ .name = "default" },
        .{ .name = "pacing", .pacing = true },
        .{ .name = "pacing+cubic", .pacing = true, .cubic = true },
        .{ .name = "bbr", .bbr = true },
    };
    std.debug.print("\npacing bench: bulk download from the native listener over loopback; CPU of its I/O thread\n{s:<14} {s:<13} {s:>6} {s:>7} {s:>8} {s:>9} {s:>7} {s:>10} {s:>10} {s:>10} {s:>7}\n", .{ "link", "sender", "MiB", "wall s", "Mbit/s", "cpu ms", "cpu %", "ms/MiB", "passes/s", "polls/s", "drops" });
    for (links) |link| {
        const mib: u64 = if (link.mbit == 0) 256 else if (link.mbit >= 100) 48 else 16;
        for (modes) |m| {
            const r = try paceBench(gpa, io, &disp, &cert, ds.owned[0].id, .{ .pacing = m.pacing, .cubic = m.cubic, .bbr = m.bbr }, link, mib << 20);
            const wall = @as(f64, @floatFromInt(r.wall_ns)) / 1e9;
            const cpu = @as(f64, @floatFromInt(r.cpu_ns)) / 1e6;
            std.debug.print("{s:<14} {s:<13} {d:>6} {d:>7.2} {d:>8.1} {d:>9.1} {d:>7.1} {d:>10.2} {d:>10.0} {d:>10.0} {d:>7}\n", .{
                link.name,                                 m.name,                                   r.bytes >> 20,
                wall,                                      @as(f64, @floatFromInt(r.bytes)) * 8 / 1e6 / wall, cpu,
                cpu / 10 / wall,                           cpu / @as(f64, @floatFromInt(r.bytes >> 20)), @as(f64, @floatFromInt(r.passes)) / wall,
                @as(f64, @floatFromInt(r.polls)) / wall, r.dropped,
            });
            try std.testing.expect(r.bytes >= mib << 20);
        }
    }
}

test "native listener: the path MTU ceiling follows the address family; switches default off" {
    const v4: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(1) };
    try std.testing.expectEqual(@as(u16, 1472), pathCeiling(&v4));
    var v6: Io.net.IpAddress = .{ .ip6 = .{ .port = 1, .bytes = @splat(0) } };
    v6.ip6.bytes[15] = 1;
    try std.testing.expectEqual(@as(u16, 1452), pathCeiling(&v6));
    // an IPv4 client on a dual-stack socket
    v6.ip6.bytes[10] = 0xff;
    v6.ip6.bytes[11] = 0xff;
    try std.testing.expectEqual(@as(u16, 1472), pathCeiling(&v6));
    const o: Options = .{ .listen = v4, .identity_seed = @splat(0), .cert = undefined };
    try std.testing.expect(!o.pacing and !o.hystart and !o.cubic and !o.pmtud and !o.iw_mtu and !o.bbr and !o.early_settings);
    const d: conn_mod.Config = .{ .server_name = "", .identity_seed = @splat(0), .seed = @splat(0), .now_unix = 0 };
    try std.testing.expect(!d.pacing and !d.hystart and !d.cubic and !d.pmtud and !d.iw_mtu and !d.bbr and !d.early_send);
    try std.testing.expect(!envSwitch("ZUI_NATIVE_NO_SUCH_SWITCH", false) and envSwitch("ZUI_NATIVE_NO_SUCH_SWITCH", true));
}
