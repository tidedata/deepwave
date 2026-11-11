//! Lossy-link bench: a real client and a real server `Connection` over a simulated link, in
//! virtual time. The link has a round-trip time, a random loss rate, a bandwidth and a tail-drop
//! queue at the bottleneck, so congestion control, pacing, loss recovery and packet size can be
//! compared on the same inputs. Nothing here touches a socket or the wall clock: a run is a pure
//! function of (link, workload, seed, server config), and `Result.fingerprint` hashes every
//! datagram and its send time, so "the old path did not change" is one integer comparison.
//!
//! The workload is what a browser does against the node over zui/1 or WebTransport:
//!   1. connect (TLS 1.3 handshake),
//!   2. one bulk response of `bulk_bytes` (a checkpoint replay),
//!   3. `requests` request/response pairs, three small reads (256 B to 4 KiB, get_object) to
//!      one checkpoint-sized response (87 KB),
//!   4. `tail_reqs` two-datagram responses whose last datagram the link drops (a tail loss; no
//!      random loss in this phase, so the figure is the recovery mechanism alone).
//!
//! `ZUI_NET_BENCH=1 ./zig build test -Dlane=net` prints the table for the four reference links
//! (ZUI_NET_BENCH_MIB, ZUI_NET_BENCH_REQS, ZUI_NET_BENCH_SEEDS override 8, 200 and 20).
//! `ZUI_NET_BENCH_LONG=1` adds the long-haul bulk profile (`long_haul`: one 200 MB transfer,
//! ZUI_NET_BENCH_LONG_MB and ZUI_NET_BENCH_LONG_SEEDS override 200 and 3).
const std = @import("std");
const Allocator = std.mem.Allocator;
const conn = @import("conn.zig");
const Connection = conn.Connection;
const Ed25519 = std.crypto.sign.Ed25519;
const ms = std.time.ns_per_ms;
const sec = std.time.ns_per_s;

pub const Link = struct {
    name: []const u8,
    rtt_ms: u32,
    /// Random loss in each direction, in units of 0.1 percent.
    loss_pm: u32,
    mbit: u32,
    /// Tail-drop queue at the bottleneck, as milliseconds of the link rate.
    queue_ms: u32 = 50,
    /// UDP payloads above this vanish (the path MTU; 1472 is IPv4 over Ethernet).
    path_mtu: u16 = 1472,
    /// From this virtual time on the path MTU is `path_mtu_late` (a route change; 0: never).
    mtu_change_at_ms: u64 = 0,
    path_mtu_late: u16 = 1472,
};

/// The four reference links: (RTT, loss, bandwidth), 50 ms tail-drop queue each.
pub const links = [_]Link{
    .{ .name = "20ms 0% 100Mbit", .rtt_ms = 20, .loss_pm = 0, .mbit = 100 },
    .{ .name = "50ms 1% 50Mbit", .rtt_ms = 50, .loss_pm = 10, .mbit = 50 },
    .{ .name = "150ms 1% 20Mbit", .rtt_ms = 150, .loss_pm = 10, .mbit = 20 },
    .{ .name = "250ms 2% 10Mbit", .rtt_ms = 250, .loss_pm = 20, .mbit = 10 },
};

/// The long-haul bulk profile, shaped like a core feeding an edge across an ocean: a fast link,
/// a long round trip and a little random loss. Not one of the four reference links.
pub const long_haul: Link = .{ .name = "250ms 0.5% 100Mbit", .rtt_ms = 250, .loss_pm = 5, .mbit = 100 };

/// A response larger than `Work.feed_from` is written to the stream as the sender drains it
/// (at most `feed_backlog` unsent at a time), the way the listener feeds a subscription, instead
/// of being copied whole into the send buffer.
const feed_backlog = 1 << 20;
const feed_chunk = 256 << 10;

pub const Work = struct {
    seed: u64 = 1,
    bulk_bytes: usize = 8 << 20,
    requests: usize = 200,
    /// Not 0: every response of phase 3 has this size.
    req_fixed: usize = 0,
    tail_reqs: usize = 20,
    /// Two datagrams, so the whole response leaves in one flight even at the minimum window.
    tail_resp: usize = 2000,
    feed_from: usize = 16 << 20,
    /// What stands between the handshake and the first request.
    setup: Setup = .none,
};

/// `.none`: zui/1 over raw QUIC, the first request leaves with the client's Finished.
/// `.webtransport`: the browser's sequence. The client may not send its extended CONNECT before
/// it has read the server's HTTP/3 SETTINGS (RFC 9220 section 3), and may not open a
/// WebTransport stream before the CONNECT is answered, so the server speaks first (one
/// unidirectional stream, `settings_len` bytes, sent when the connection is established or, with
/// `Config.early_send`, right behind the handshake flight), then one small request and response
/// (the CONNECT and its 200), then the first real request.
pub const Setup = enum { none, webtransport };
const settings_len = 40;
const connect_resp_len = 60;

/// Changes the server's `Config` (the sender under test). The client is the browser's stand-in
/// and always runs the defaults.
pub const Tune = *const fn (*conn.Config) void;

pub const Result = struct {
    connect_ns: u64 = 0,
    /// Handshake start to the first byte of the first response.
    ttfb_ns: u64 = 0,
    bulk_ns: u64 = 0,
    bulk_bytes: u64 = 0,
    /// Tail-loss recovery: mean latency of the requests whose last response datagram was dropped.
    tail_ns: u64 = 0,
    /// Server (sender) counters.
    pkts: u64 = 0,
    lost: u64 = 0,
    ptos: u64 = 0,
    /// STREAM frames the server sent again.
    retx: u64 = 0,
    /// STREAM frames that reached the client carrying no byte it did not already hold.
    spurious: u64 = 0,
    drops_random: u64 = 0,
    drops_queue: u64 = 0,
    drops_mtu: u64 = 0,
    /// Server datagrams of the bulk phase (packets per transfer) and its final datagram size.
    bulk_pkts: u64 = 0,
    mtu: usize = 0,
    /// Server datagrams during the second half of phase 3, the requests in it, and the
    /// server's datagram size at the end of the run.
    late_pkts: u64 = 0,
    late_reqs: u64 = 0,
    mtu_end: usize = 0,
    /// The server when phase 4 began: PTO count, datagram size, smoothed RTT and RTT variance.
    tail_ptos_from: u64 = 0,
    tail_mtu: usize = 0,
    tail_srtt: u64 = 0,
    tail_rttvar: u64 = 0,
    /// Most datagrams the server handed to the link at one instant, once established.
    max_burst: u64 = 0,
    /// Times the server fell back to 1200-byte datagrams (path MTU black hole).
    black_holes: u64 = 0,
    end_ns: u64 = 0,
    fingerprint: u64 = 0,

    pub fn goodputMbit(r: *const Result) f64 {
        if (r.bulk_ns == 0) return 0;
        return @as(f64, @floatFromInt(r.bulk_bytes)) * 8.0 * 1000.0 / @as(f64, @floatFromInt(r.bulk_ns));
    }
};

const Pkt = struct { t: u64, len: u16, drop: bool, data: [1500]u8 };

/// One direction of the link: packets in delivery order.
const Fifo = struct {
    q: std.ArrayList(Pkt) = .empty,
    head: usize = 0,
    /// When the bottleneck has serialised everything it holds.
    free_at: u64 = 0,

    fn peek(f: *Fifo) ?*Pkt {
        return if (f.head < f.q.items.len) &f.q.items[f.head] else null;
    }

    fn pop(f: *Fifo) void {
        f.head += 1;
        if (f.head == f.q.items.len) {
            f.q.clearRetainingCapacity();
            f.head = 0;
        } else if (f.head >= 512 and f.head * 2 >= f.q.items.len) {
            const rest = f.q.items.len - f.head;
            std.mem.copyForwards(Pkt, f.q.items[0..rest], f.q.items[f.head..]);
            f.q.shrinkRetainingCapacity(rest);
            f.head = 0;
        }
    }
};

const Phase = enum { handshake, settings, connect, bulk, reqs, tail, done };

fn fill(out: []u8, off: usize, seed: u32) void {
    for (out, off..) |*b, j| b.* = @truncate((j *% 131) ^ seed);
}

/// Runs the workload once. `lat` receives the latency of every request of phase 3 (ns).
pub fn run(gpa: Allocator, link: Link, work: Work, tune: ?Tune, lat: ?*std.ArrayList(u64)) !Result {
    var prng = std.Random.DefaultPrng.init(work.seed);
    const rnd = prng.random();
    const server_seed: [32]u8 = @splat(9);
    const skey = (try Ed25519.KeyPair.generateDeterministic(server_seed)).public_key.toBytes();
    var cseed: [64]u8 = undefined;
    rnd.bytes(&cseed);
    var sseed: [64]u8 = undefined;
    rnd.bytes(&sseed);
    const t0: u64 = 1_000_000_000;
    var now: u64 = t0;
    // The browser's stand-in: Chrome-sized receive windows (6 MiB per stream, 15 MiB in all).
    const client = try Connection.init(gpa, .{ .server_name = "zui", .identity_seed = @splat(4), .expected_peer = skey, .seed = cseed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .max_streams_uni = 16, .max_streams_bidi = 64, .max_data = 15 << 20, .max_stream_data = 6 << 20, .keep_alive_ms = 3_000, .pmtu_max = 1452 }, now);
    defer client.deinit();
    var server: ?*Connection = null;
    defer if (server) |s| s.deinit();
    // The zui/1 and WebTransport listener's connection settings (listener.zig onDatagram).
    var scfg: conn.Config = .{ .server_name = "zui", .identity_seed = server_seed, .seed = sseed, .now_unix = 1_800_000_000, .max_streams_bidi = 128, .max_streams_uni = 16, .max_data = 16 << 20, .max_stream_data = 1 << 20, .idle_timeout_ms = 30_000, .keep_alive_ms = 0, .alpn = &.{"zui/1"}, .client_auth = false, .pmtu_max = 1452 };
    if (tune) |f| f(&scfg);

    var fifo: [2]Fifo = .{ .{}, .{} }; // 0: to the client, 1: to the server
    defer for (&fifo) |*f| f.q.deinit(gpa);
    const rate: u64 = @as(u64, link.mbit) * 125_000; // bytes per second
    const queue_bytes: u64 = rate * link.queue_ms / 1000;
    const delay: u64 = @as(u64, link.rtt_ms) * ms / 2;
    var res: Result = .{};
    var fp = std.hash.Wyhash.init(0);

    // server application
    var reqs: std.ArrayList(u64) = .empty;
    defer reqs.deinit(gpa);
    var answered: std.ArrayList(u64) = .empty;
    defer answered.deinit(gpa);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);
    // a large response still being written (`Work.feed_from`)
    var feed: ?struct { id: u64, off: usize, len: usize, seed: u32 } = null;
    var spoke = false; // the server's SETTINGS stand-in is written (`Setup.webtransport`)
    // client application
    var phase: Phase = .handshake;
    var cur: ?u64 = null;
    var cur_len: usize = 0;
    var cur_seed: u32 = 0;
    var got: usize = 0;
    var started: u64 = 0;
    var n_done: usize = 0;
    var tail_sum: u64 = 0;
    var loss_on = true;
    var bulk_pkts_from: u64 = 0;
    var late_from: ?u64 = null;
    var ctl_stream: ?u64 = null;

    var out: [1500]u8 = undefined;
    var iter: u64 = 0;
    while (phase != .done) : (iter += 1) {
        if (iter > 200_000_000 or now - t0 > 7200 * sec) return error.SimRunaway;
        // deliveries
        for (&fifo, 0..) |*f, dir| while (f.peek()) |p| {
            if (p.t > now) break;
            if (!p.drop) {
                const d = p.data[0..p.len];
                if (dir == 0) client.handleDatagram(now, d) else {
                    if (server == null) {
                        const dl = d[5];
                        const sl = d[6 + dl];
                        server = try Connection.initServer(gpa, scfg, now, d[6..][0..dl], d[7 + dl ..][0..sl]);
                    }
                    server.?.handleDatagram(now, d);
                }
            }
            f.pop();
        };
        for (0..2) |side| {
            const is_server = side == 1;
            const c = if (is_server) server orelse continue else client;
            if (c.nextTimeout()) |t| if (now >= t) c.onTimeout(now);
            if (c.isClosed()) return error.SimClosed;
            var answered_now = false;
            if (is_server and work.setup == .webtransport and !spoke and (c.isEstablished() or c.canSendEarly())) {
                const ctl = try c.openUni();
                const settings: [settings_len]u8 = @splat(0x53);
                try c.streamWrite(ctl, &settings, false);
                spoke = true;
            }
            if (is_server and c.isEstablished()) {
                while (c.acceptBidi()) |id| try reqs.append(gpa, id);
                var k: usize = 0;
                while (k < reqs.items.len) {
                    const id = reqs.items[k];
                    const s = c.stream(id) orelse {
                        _ = reqs.swapRemove(k);
                        continue;
                    };
                    if (!s.recv.complete()) {
                        k += 1;
                        continue;
                    }
                    const rq = s.recv.contiguous();
                    if (rq.len != 8) return error.SimCorrupt;
                    const len = std.mem.readInt(u32, rq[0..4], .little);
                    const seed = std.mem.readInt(u32, rq[4..8], .little);
                    s.recv.consume(8);
                    if (len > work.feed_from) {
                        if (feed != null) return error.SimCorrupt; // one large response at a time
                        feed = .{ .id = id, .off = 0, .len = len, .seed = seed };
                        _ = reqs.swapRemove(k);
                        continue;
                    }
                    try payload.resize(gpa, len);
                    fill(payload.items, 0, seed);
                    try c.streamWrite(id, payload.items, true);
                    try answered.append(gpa, id);
                    answered_now = true;
                    _ = reqs.swapRemove(k);
                }
                if (feed) |*fd| {
                    while (fd.off < fd.len and c.streamUnsent(fd.id) < feed_backlog) {
                        const n = @min(feed_chunk, fd.len - fd.off);
                        try payload.resize(gpa, n);
                        fill(payload.items, fd.off, fd.seed);
                        try c.streamWrite(fd.id, payload.items, fd.off + n == fd.len);
                        fd.off += n;
                    }
                    if (fd.off == fd.len) {
                        try answered.append(gpa, fd.id);
                        feed = null;
                    }
                }
                k = 0;
                while (k < answered.items.len) {
                    const id = answered.items[k];
                    if (c.stream(id) == null or c.streamSettled(id)) {
                        c.streamFree(id);
                        _ = answered.swapRemove(k);
                        continue;
                    }
                    k += 1;
                }
            }
            if (!is_server and c.isEstablished()) {
                const first: Phase = if (work.bulk_bytes > 0) .bulk else if (work.requests > 0) .reqs else if (work.tail_reqs > 0) .tail else .done;
                if (phase == .handshake) {
                    res.connect_ns = now - t0;
                    phase = if (work.setup == .webtransport) .settings else first;
                    if (server) |sv| bulk_pkts_from = sv.pkts_sent;
                }
                if (phase == .settings) {
                    // the server's control stream, whole
                    while (c.acceptUni()) |id| {
                        ctl_stream = id;
                    }
                    if (ctl_stream) |id| if (c.stream(id)) |st| {
                        if (st.recv.contiguous().len >= settings_len) phase = .connect;
                    };
                }
                if (cur) |id| {
                    const s = c.stream(id) orelse return error.SimStreamGone;
                    const data = s.recv.contiguous();
                    if (data.len > 0) {
                        if (res.ttfb_ns == 0 and phase != .connect) res.ttfb_ns = now - t0;
                        for (data, got..) |b, j| if (b != @as(u8, @truncate((j *% 131) ^ cur_seed))) return error.SimCorrupt;
                        got += data.len;
                        s.recv.consume(data.len);
                    }
                    if (s.recv.complete()) {
                        if (got != cur_len) return error.SimCorrupt;
                        c.streamFree(id);
                        cur = null;
                        const took = now - started;
                        switch (phase) {
                            .connect => {
                                phase = first;
                                if (server) |sv| bulk_pkts_from = sv.pkts_sent;
                            },
                            .bulk => {
                                res.bulk_ns = took;
                                res.bulk_bytes = cur_len;
                                if (server) |sv| {
                                    res.bulk_pkts = sv.pkts_sent - bulk_pkts_from;
                                    res.mtu = sv.mtu;
                                }
                                phase = .reqs;
                                n_done = 0;
                            },
                            .reqs => {
                                if (lat) |l| try l.append(gpa, took);
                                n_done += 1;
                                if (server) |sv| {
                                    if (late_from == null and n_done >= work.requests / 2) late_from = sv.pkts_sent;
                                    if (n_done == work.requests) {
                                        res.late_pkts = sv.pkts_sent - late_from.?;
                                        res.late_reqs = work.requests - work.requests / 2;
                                    }
                                }
                            },
                            .tail => {
                                tail_sum += took;
                                n_done += 1;
                            },
                            else => unreachable,
                        }
                        if (phase == .reqs and n_done >= work.requests) {
                            phase = .tail;
                            n_done = 0;
                            if (server) |sv| {
                                res.tail_ptos_from = sv.ptos;
                                res.tail_mtu = sv.mtu;
                                res.tail_srtt = sv.srtt;
                                res.tail_rttvar = sv.rttvar;
                            }
                        }
                        if (phase == .tail and n_done >= work.tail_reqs) phase = .done;
                    }
                }
                if (cur == null and phase != .done and phase != .handshake and phase != .settings) {
                    const id = try c.openBidi();
                    cur_len = switch (phase) {
                        .connect => connect_resp_len,
                        .bulk => work.bulk_bytes,
                        .reqs => if (work.req_fixed != 0) work.req_fixed else if (n_done % 4 == 3) 87_000 else 256 + rnd.uintLessThan(usize, 4096 - 256),
                        else => work.tail_resp,
                    };
                    loss_on = phase != .tail;
                    cur_seed = rnd.int(u32);
                    var rq: [8]u8 = undefined;
                    std.mem.writeInt(u32, rq[0..4], @intCast(cur_len), .little);
                    std.mem.writeInt(u32, rq[4..8], cur_seed, .little);
                    try c.streamWrite(id, &rq, true);
                    cur = id;
                    got = 0;
                    started = now;
                }
            }
            // transmit: through the bottleneck queue, then the propagation delay, then the loss
            const f = &fifo[1 - side];
            var sent_any = false;
            var burst: u64 = 0;
            defer if (is_server and phase != .handshake) {
                res.max_burst = @max(res.max_burst, burst);
            };
            while (c.pollTransmit(now, &out)) |n| {
                burst += 1;
                fp.update(std.mem.asBytes(&now));
                fp.update(out[0..n]);
                const path_mtu = if (link.mtu_change_at_ms != 0 and now - t0 >= link.mtu_change_at_ms * ms) link.path_mtu_late else link.path_mtu;
                if (n > path_mtu) {
                    res.drops_mtu += 1;
                    continue;
                }
                const backlog = (f.free_at -| now) * rate / sec;
                if (backlog + n > queue_bytes) {
                    res.drops_queue += 1;
                    continue;
                }
                const depart = @max(now, f.free_at) + n * sec / rate;
                f.free_at = depart;
                const lost = loss_on and link.loss_pm != 0 and rnd.uintLessThan(u32, 1000) < link.loss_pm;
                if (lost) res.drops_random += 1;
                var p: Pkt = .{ .t = depart + delay, .len = @intCast(n), .drop = lost, .data = undefined };
                @memcpy(p.data[0..n], out[0..n]);
                try f.q.append(gpa, p);
                sent_any = true;
            }
            // phase 4: the link drops the last datagram of the response
            if (is_server and answered_now and phase == .tail and sent_any) f.q.items[f.q.items.len - 1].drop = true;
        }
        // next event: a delivery or a timer
        var next: u64 = std.math.maxInt(u64);
        for (&fifo) |*f| if (f.peek()) |p| {
            next = @min(next, p.t);
        };
        if (client.nextTimeout()) |t| next = @min(next, t);
        if (server) |s| if (s.nextTimeout()) |t| {
            next = @min(next, t);
        };
        now = if (next > now) next else now + 10_000;
    }
    if (server) |sv| {
        res.pkts = sv.pkts_sent;
        res.lost = sv.pkts_lost;
        res.ptos = sv.ptos;
        res.retx = sv.stream_retx;
        res.black_holes = sv.pmtu_black_holes;
        res.mtu_end = sv.mtu;
        if (res.mtu == 0) res.mtu = sv.mtu;
    }
    res.spurious = client.dup_frames;
    if (work.tail_reqs > 0) res.tail_ns = tail_sum / work.tail_reqs;
    res.end_ns = now - t0;
    fp.update(std.mem.asBytes(&now));
    res.fingerprint = fp.final();
    return res;
}

/// A server configuration under test: a name for the table and what it changes.
pub const Variant = struct { name: []const u8, tune: ?Tune = null };

fn tunePacing(c: *conn.Config) void {
    c.pacing = true;
}
fn tuneHystart(c: *conn.Config) void {
    c.hystart = true;
}
fn tunePacingHystart(c: *conn.Config) void {
    c.pacing = true;
    c.hystart = true;
}
fn tuneCubic(c: *conn.Config) void {
    c.cubic = true;
}
fn tunePacingCubic(c: *conn.Config) void {
    c.pacing = true;
    c.cubic = true;
}
/// The search with the IPv4 ceiling (the reference links carry 1472 bytes).
fn tunePmtud(c: *conn.Config) void {
    c.pmtud = true;
    c.pmtu_max = 1472;
}
fn tuneIwMtu(c: *conn.Config) void {
    c.iw_mtu = true;
}
fn tuneEarlySend(c: *conn.Config) void {
    c.early_send = true;
}
fn tuneAllReno(c: *conn.Config) void {
    tunePacingHystart(c);
    tunePmtud(c);
    c.iw_mtu = true;
}
fn tuneAllCubic(c: *conn.Config) void {
    tuneAllReno(c);
    c.cubic = true;
}

pub const variants = [_]Variant{
    .{ .name = "default" },
    .{ .name = "pacing", .tune = tunePacing },
    .{ .name = "hystart", .tune = tuneHystart },
    .{ .name = "pacing+hystart", .tune = tunePacingHystart },
    .{ .name = "cubic", .tune = tuneCubic },
    .{ .name = "pacing+cubic", .tune = tunePacingCubic },
    .{ .name = "pmtud", .tune = tunePmtud },
    .{ .name = "iw_mtu", .tune = tuneIwMtu },
    .{ .name = "all, newreno", .tune = tuneAllReno },
    .{ .name = "all, cubic", .tune = tuneAllCubic },
};

fn envInt(name: [*:0]const u8, default: u64) u64 {
    const v = std.c.getenv(name) orelse return default;
    return std.fmt.parseInt(u64, std.mem.span(v), 10) catch default;
}

fn pct(sorted: []const u64, p: usize) u64 {
    if (sorted.len == 0) return 0;
    return sorted[@min(sorted.len - 1, sorted.len * p / 100)];
}

fn fms(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / @as(f64, ms);
}

/// The bench table: every variant on every reference link, averaged over `seeds` runs.
pub fn table(gpa: Allocator, ls: []const Link, vs: []const Variant, work: Work, seeds: u64) !void {
    const mib = work.bulk_bytes % (1 << 20) == 0;
    std.debug.print("\nlinkbench: {d} {s} bulk, {d} requests, {d} tail losses, {d} seeds (virtual time; server is the sender under test)\n", .{ if (mib) work.bulk_bytes >> 20 else work.bulk_bytes / 1_000_000, if (mib) "MiB" else "MB", work.requests, work.tail_reqs, seeds });
    std.debug.print("{s:<18} {s:<14} {s:>8} {s:>8} {s:>8} {s:>8} {s:>9} {s:>8} {s:>7} {s:>6} {s:>6} {s:>6} {s:>5} {s:>5}\n", .{ "link", "variant", "Mbit/s", "conn ms", "ttfb ms", "p50 ms", "p99 ms", "tail ms", "pkts", "lost", "retx", "spur", "ptos", "mtu" });
    for (ls) |link| for (vs) |v| {
        var lat: std.ArrayList(u64) = .empty;
        defer lat.deinit(gpa);
        var sum: Result = .{};
        var mbit: f64 = 0;
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            var w = work;
            w.seed = seed;
            const r = try run(gpa, link, w, v.tune, &lat);
            mbit += r.goodputMbit();
            sum.connect_ns += r.connect_ns;
            sum.ttfb_ns += r.ttfb_ns;
            sum.tail_ns += r.tail_ns;
            sum.pkts += r.pkts;
            sum.lost += r.lost;
            sum.retx += r.retx;
            sum.spurious += r.spurious;
            sum.ptos += r.ptos;
            sum.mtu = r.mtu;
            sum.black_holes += r.black_holes;
            sum.tail_ptos_from += r.ptos - r.tail_ptos_from;
            sum.tail_mtu += r.tail_mtu;
            sum.tail_srtt += r.tail_srtt;
            sum.tail_rttvar += r.tail_rttvar;
        }
        std.mem.sort(u64, lat.items, {}, std.sort.asc(u64));
        const n: f64 = @floatFromInt(seeds);
        std.debug.print("{s:<18} {s:<14} {d:>8.2} {d:>8.1} {d:>8.1} {d:>8.1} {d:>9.1} {d:>8.1} {d:>7} {d:>6} {d:>6} {d:>6} {d:>5} {d:>5}\n", .{
            link.name,               v.name,                  mbit / n,             fms(sum.connect_ns) / n, fms(sum.ttfb_ns) / n,
            fms(pct(lat.items, 50)), fms(pct(lat.items, 99)), fms(sum.tail_ns) / n, sum.pkts / seeds,        sum.lost / seeds,
            sum.retx / seeds,        sum.spurious / seeds,    sum.ptos / seeds,     sum.mtu,
        });
        if (std.c.getenv("ZUI_NET_BENCH_DIAG") != null)
            std.debug.print("    diag: phase 4 PTOs {d:.1} of {d}, at its start mtu {d} srtt {d:.1} ms rttvar {d:.2} ms; black holes in {d} seeds: {d}\n", .{
                @as(f64, @floatFromInt(sum.tail_ptos_from)) / n, work.tail_reqs,           sum.tail_mtu / seeds,
                fms(sum.tail_srtt) / n,                          fms(sum.tail_rttvar) / n, seeds,
                sum.black_holes,
            });
    };
}

/// Fingerprints of the default sender (every switch off) on the four reference links, for the
/// small workload of the test below. A sender-side change that is meant to be off by default
/// must leave these alone: they cover every datagram of both directions and when it was sent.
/// They move only when the default sender itself is changed on purpose (re-pin then, and say so).
const pinned = [links.len]u64{ 0x160f4051a22423c0, 0x74135bff816414ea, 0xbd68a2dc86f92d47, 0x69884442ea3c69ca };

test "linkbench: the workload completes on every reference link; the default sender is pinned" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 256 << 10, .requests = 12, .tail_reqs = 3, .tail_resp = 4000 };
    var moved = false;
    for (links, pinned) |link, want| {
        const a = try run(gpa, link, work, null, null);
        const b = try run(gpa, link, work, null, null);
        try std.testing.expectEqual(a.fingerprint, b.fingerprint);
        if (a.fingerprint != want) {
            std.debug.print("linkbench: default sender on {s}: fingerprint 0x{x}, pinned 0x{x}\n", .{ link.name, a.fingerprint, want });
            moved = true;
        }
        try std.testing.expectEqual(@as(u64, 256 << 10), a.bulk_bytes);
        // the handshake is one round trip, the first byte two (plus serialisation)
        try std.testing.expect(a.connect_ns >= @as(u64, link.rtt_ms) * ms);
        try std.testing.expect(a.ttfb_ns >= 2 * @as(u64, link.rtt_ms) * ms);
        // goodput can never exceed the link
        try std.testing.expect(a.goodputMbit() <= @as(f64, @floatFromInt(link.mbit)));
        // a dropped tail costs a probe timeout, not the idle timeout
        try std.testing.expect(a.tail_ns < 8 * @as(u64, link.rtt_ms) * ms + 200 * ms);
        if (link.loss_pm == 0) try std.testing.expectEqual(@as(u64, 0), a.drops_random);
    }
    try std.testing.expect(!moved);
}

test "linkbench: cold connect is 2 round trips over raw QUIC, 4 for WebTransport, 3 with early_send" {
    const gpa = std.testing.allocator;
    // the two lossless shapes: 20 ms and a long 250 ms round trip
    const lossless = [_]Link{ links[0], .{ .name = "250ms 0% 100Mbit", .rtt_ms = 250, .loss_pm = 0, .mbit = 100 } };
    for (lossless) |link| {
        const rtt: u64 = @as(u64, link.rtt_ms) * ms;
        const slack = rtt / 4; // serialisation at the bottleneck and the 2 ms ACK delay
        const cases = [_]struct { setup: Setup, tune: ?Tune, rtts: u64 }{
            .{ .setup = .none, .tune = null, .rtts = 2 },
            .{ .setup = .none, .tune = tuneEarlySend, .rtts = 2 },
            .{ .setup = .webtransport, .tune = null, .rtts = 4 },
            .{ .setup = .webtransport, .tune = tuneEarlySend, .rtts = 3 },
        };
        for (cases) |cs| {
            const r = try run(gpa, link, .{ .bulk_bytes = 4096, .requests = 3, .tail_reqs = 0, .setup = cs.setup }, cs.tune, null);
            try std.testing.expectEqual(@as(u64, 4096), r.bulk_bytes);
            if (r.ttfb_ns < cs.rtts * rtt or r.ttfb_ns > cs.rtts * rtt + slack)
                std.debug.print("cold connect on {s}: {d:.1} ms, expected {d} round trips\n", .{ link.name, fms(r.ttfb_ns), cs.rtts });
            try std.testing.expect(r.ttfb_ns >= cs.rtts * rtt and r.ttfb_ns <= cs.rtts * rtt + slack);
            // the handshake itself is one round trip either way
            try std.testing.expect(r.connect_ns >= rtt and r.connect_ns <= rtt + slack);
        }
    }
    // with loss the sequence still completes on every reference link and the long haul
    for (links ++ [_]Link{long_haul}) |link| {
        const r = try run(gpa, link, .{ .seed = 3, .bulk_bytes = 64 << 10, .requests = 4, .tail_reqs = 2, .setup = .webtransport }, tuneEarlySend, null);
        try std.testing.expectEqual(@as(u64, 64 << 10), r.bulk_bytes);
    }
}

test "linkbench: a large response is fed to the stream as it drains and arrives whole" {
    const gpa = std.testing.allocator;
    // 3 MiB fed in 256 KiB pieces; every byte is checked against its offset on arrival
    // (error.SimCorrupt otherwise), and feeding changes nothing the link can see
    const fed: Work = .{ .bulk_bytes = (3 << 20) + 12_345, .requests = 2, .tail_reqs = 0, .feed_from = 256 << 10 };
    var whole = fed;
    whole.feed_from = 16 << 20;
    const a = try run(gpa, links[0], fed, null, null);
    const b = try run(gpa, links[0], whole, null, null);
    try std.testing.expectEqual(@as(u64, (3 << 20) + 12_345), a.bulk_bytes);
    try std.testing.expectEqual(b.bulk_bytes, a.bulk_bytes);
    try std.testing.expectEqual(b.fingerprint, a.fingerprint);
    // and on the long-haul profile's link
    const c = try run(gpa, long_haul, .{ .bulk_bytes = 1 << 20, .requests = 0, .tail_reqs = 0, .feed_from = 256 << 10 }, null, null);
    try std.testing.expectEqual(@as(u64, 1 << 20), c.bulk_bytes);
}

test "linkbench: pacing bounds the burst a response leaves in, and the workload still completes" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 256 << 10, .requests = 12, .tail_reqs = 3 };
    const old = try run(gpa, links[0], work, null, null);
    const new = try run(gpa, links[0], work, tunePacing, null);
    // unpaced, an 87 KB response leaves as one burst of about 60 datagrams
    try std.testing.expect(old.max_burst >= 55);
    // paced: the bucket (2 ms of the window, 10 to 64 datagrams)
    try std.testing.expect(new.max_burst <= 64 and new.max_burst < old.max_burst);
    for (links) |link| {
        const r = try run(gpa, link, work, tunePacing, null);
        try std.testing.expectEqual(@as(u64, 256 << 10), r.bulk_bytes);
        try std.testing.expect(r.max_burst <= 64);
    }
}

test "linkbench: HyStart++ leaves slow start before the bottleneck queue overflows" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 4 << 20, .requests = 0, .tail_reqs = 0 };
    const old = try run(gpa, links[0], work, null, null);
    const new = try run(gpa, links[0], work, tuneHystart, null);
    // the old slow start doubles the window until the queue drops a burst
    try std.testing.expect(old.drops_queue > 50 and old.lost > 50);
    // with HyStart++ the window stops doubling when the queue starts to build
    if (new.drops_queue * 3 > old.drops_queue or new.bulk_ns > old.bulk_ns)
        std.debug.print("hystart: old {d} drops {d} ms, new {d} drops {d} ms\n", .{ old.drops_queue, old.bulk_ns / ms, new.drops_queue, new.bulk_ns / ms });
    try std.testing.expect(new.drops_queue * 3 <= old.drops_queue);
    try std.testing.expect(new.lost * 3 <= old.lost);
    try std.testing.expect(new.bulk_ns <= old.bulk_ns);
}

test "linkbench: CUBIC completes the workload on every reference link" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 256 << 10, .requests = 12, .tail_reqs = 3 };
    for (links) |link| {
        const r = try run(gpa, link, work, tuneAllCubic, null);
        try std.testing.expectEqual(@as(u64, 256 << 10), r.bulk_bytes);
        try std.testing.expect(r.goodputMbit() <= @as(f64, @floatFromInt(link.mbit)));
    }
}

test "linkbench: the path MTU search finds a path below 1452, and the IPv4 ceiling above it" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 256 << 10, .requests = 40, .req_fixed = 87_079, .tail_reqs = 0 };
    // a tunnel: 1400 bytes pass. The single probe of 1452 fails and the old sender stays at 1200.
    var link = links[0];
    link.path_mtu = 1400;
    link.path_mtu_late = 1400;
    const old = try run(gpa, link, work, null, null);
    const new = try run(gpa, link, work, tunePmtud, null);
    try std.testing.expectEqual(@as(usize, 1200), old.mtu_end);
    try std.testing.expect(new.mtu_end > 1400 - 24 and new.mtu_end <= 1400);
    // the same checkpoints in fewer datagrams
    try std.testing.expect(new.late_pkts * 10 < old.late_pkts * 9);
    try std.testing.expectEqual(@as(u64, 0), new.black_holes);
    // Ethernet over IPv4: 1472 instead of 1452
    const v4 = try run(gpa, links[0], work, tunePmtud, null);
    try std.testing.expectEqual(@as(usize, 1472), v4.mtu_end);
    try std.testing.expectEqual(@as(u64, 0), v4.black_holes);
}

test "linkbench: a route change to a smaller MTU stalls the old sender; the search falls back to 1200" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 2 << 20, .requests = 4, .tail_reqs = 0 };
    var link: Link = .{ .name = "50ms 0% 50Mbit", .rtt_ms = 50, .loss_pm = 0, .mbit = 50 };
    link.mtu_change_at_ms = 400;
    link.path_mtu_late = 1300;
    // the validated 1452 is trusted for ever: every full datagram and every probe vanishes
    try std.testing.expectError(error.SimRunaway, run(gpa, link, work, null, null));
    const new = try run(gpa, link, work, tunePmtud, null);
    try std.testing.expectEqual(@as(u64, 2 << 20), new.bulk_bytes);
    try std.testing.expectEqual(@as(u64, 1), new.black_holes);
    try std.testing.expectEqual(@as(usize, 1200), new.mtu);
    try std.testing.expect(new.bulk_ns < 6 * sec);
}

/// Cold connect: the time from the client's first packet to the first byte of the first
/// response (a 4 KiB read), in milliseconds and in round trips of the link, for zui/1 over raw
/// QUIC and for the WebTransport sequence without and with `Config.early_send`. The mean over
/// `seeds` runs and the fastest run (no packet of the exchange lost).
pub fn coldTable(gpa: Allocator, ls: []const Link, seeds: u64) !void {
    std.debug.print("\ncold connect: first packet to first response byte, {d} seeds (virtual time)\n{s:<18} {s:<28} {s:>9} {s:>7} {s:>9} {s:>7}\n", .{ seeds, "link", "client", "mean ms", "RTTs", "best ms", "RTTs" });
    const rows = [_]struct { name: []const u8, setup: Setup, tune: ?Tune }{
        .{ .name = "zui/1 raw QUIC", .setup = .none, .tune = null },
        .{ .name = "WebTransport", .setup = .webtransport, .tune = null },
        .{ .name = "WebTransport, early_send", .setup = .webtransport, .tune = tuneEarlySend },
    };
    for (ls) |link| for (rows) |row| {
        var sum: u64 = 0;
        var best: u64 = std.math.maxInt(u64);
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            const r = try run(gpa, link, .{ .seed = seed, .bulk_bytes = 4096, .requests = 0, .tail_reqs = 0, .setup = row.setup }, row.tune, null);
            sum += r.ttfb_ns;
            best = @min(best, r.ttfb_ns);
        }
        const mean = fms(sum) / @as(f64, @floatFromInt(seeds));
        const rtt: f64 = @floatFromInt(link.rtt_ms);
        std.debug.print("{s:<18} {s:<28} {d:>9.1} {d:>7.2} {d:>9.1} {d:>7.2}\n", .{ link.name, row.name, mean, mean / rtt, fms(best), fms(best) / rtt });
    };
}

/// Datagrams per 87,079-byte checkpoint (a typical checkpoint on the wire), counted over the second half
/// of 200 such responses on the lossless reference link, after the path MTU has settled.
fn packetsPerCheckpoint(gpa: Allocator) !void {
    std.debug.print("\npackets per 87,079-byte checkpoint response (20ms 0% 100Mbit, datagram size after @)\n{s:<28} {s:>14} {s:>14}\n", .{ "path (UDP payload)", "default", "pmtud" });
    const paths = [_]struct { name: []const u8, mtu: u16 }{
        .{ .name = "1472 (Ethernet, IPv4)", .mtu = 1472 },
        .{ .name = "1452 (Ethernet, IPv6)", .mtu = 1452 },
        .{ .name = "1464 (PPPoE, IPv4)", .mtu = 1464 },
        .{ .name = "1392 (WireGuard, IPv4)", .mtu = 1392 },
        .{ .name = "1232 (IPv6 minimum MTU)", .mtu = 1232 },
    };
    for (paths) |pth| {
        var link = links[0];
        link.path_mtu = pth.mtu;
        link.path_mtu_late = pth.mtu;
        const work: Work = .{ .bulk_bytes = 1 << 20, .requests = 200, .req_fixed = 87_079, .tail_reqs = 0 };
        var per: [2]f64 = undefined;
        var mtus: [2]usize = undefined;
        for ([_]?Tune{ null, tunePmtud }, 0..) |t, i| {
            const r = try run(gpa, link, work, t, null);
            per[i] = @as(f64, @floatFromInt(r.late_pkts)) / @as(f64, @floatFromInt(r.late_reqs));
            mtus[i] = r.mtu_end;
        }
        std.debug.print("{s:<28} {d:>7.1} @{d:<5} {d:>7.1} @{d:<5}\n", .{ pth.name, per[0], mtus[0], per[1], mtus[1] });
    }
}

test "linkbench: table (ZUI_NET_BENCH=1)" {
    if (std.c.getenv("ZUI_NET_BENCH") == null) return error.SkipZigTest;
    const work: Work = .{ .bulk_bytes = @intCast(envInt("ZUI_NET_BENCH_MIB", 8) << 20), .requests = @intCast(envInt("ZUI_NET_BENCH_REQS", 200)) };
    const seeds = envInt("ZUI_NET_BENCH_SEEDS", 20);
    try table(std.testing.allocator, &links, &variants, work, seeds);
    // not one of the four: a bottleneck with a shallow queue (10 ms), where a burst is lost
    std.debug.print("\nextra link, shallow queue (10 ms instead of 50 ms)", .{});
    try table(std.testing.allocator, &.{.{ .name = "50ms 0% 20Mbit q10", .rtt_ms = 50, .loss_pm = 0, .mbit = 20, .queue_ms = 10 }}, &variants, work, seeds);
    try packetsPerCheckpoint(std.testing.allocator);
    try coldTable(std.testing.allocator, &(links ++ [_]Link{long_haul}), seeds);
    if (std.c.getenv("ZUI_NET_BENCH_LONG") != null) {
        std.debug.print("\nlong-haul bulk profile", .{});
        const long: Work = .{ .bulk_bytes = @intCast(envInt("ZUI_NET_BENCH_LONG_MB", 200) * 1_000_000), .requests = 0, .tail_reqs = 0 };
        try table(std.testing.allocator, &.{long_haul}, &variants, long, envInt("ZUI_NET_BENCH_LONG_SEEDS", 3));
    }
}
