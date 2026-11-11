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
//! ZUI_NET_BENCH_LONG_MB and ZUI_NET_BENCH_LONG_SEEDS override 200 and 3), with the browser's
//! receive windows and with the edge client's.
//!
//! Three more tables follow, for judging a sender on more than goodput:
//!   fairness      two flows of different senders start together on 20 Mbit, 50 ms and a queue
//!                 of one BDP (`flows`): each flow's rate and share over the second half,
//!   deep buffer   one flow on the same link with a queue of 10 BDPs: goodput, the time packets
//!                 wait in the queue (p50, p99) and loss,
//!   small         200 responses of 87 KB in sequence on a fresh connection, on each lossy link:
//!                 p50 and p99 completion time.
//! ZUI_NET_BENCH_FLOW_S, ZUI_NET_BENCH_FLOW_SEEDS and ZUI_NET_BENCH_SMALL_SEEDS override 60, 3 and 5.
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
    /// The client's receive windows: a browser's (6 MiB per stream, 15 MiB in all), or the
    /// edge client's (src/edge/client.zig runs the `conn.Config` defaults: 128 MiB per stream,
    /// 256 MiB in all). A sender that holds a bandwidth-delay product of several megabytes in
    /// flight is held by the browser's windows, not by the path.
    edge_windows: bool = false,
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
    const client = try Connection.init(gpa, .{ .server_name = "zui", .identity_seed = @splat(4), .expected_peer = skey, .seed = cseed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .max_streams_uni = 16, .max_streams_bidi = 64, .max_data = if (work.edge_windows) 256 << 20 else 15 << 20, .max_stream_data = if (work.edge_windows) 128 << 20 else 6 << 20, .keep_alive_ms = 3_000, .pmtu_max = 1452 }, now);
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

/// Several bulk flows through one bottleneck, each with its own sender configuration: who gets
/// what share of the link, how long packets wait in its queue, and what is lost.
pub const max_flows = 4;

pub const FlowsResult = struct {
    n: usize = 0,
    duration_ns: u64 = 0,
    /// Stream bytes each client received, over the whole run and over its second half.
    bytes: [max_flows]u64 = @splat(0),
    late_bytes: [max_flows]u64 = @splat(0),
    /// Each server's datagrams, the ones it declared lost, and the ones the queue dropped.
    pkts: [max_flows]u64 = @splat(0),
    lost: [max_flows]u64 = @splat(0),
    drops: [max_flows]u64 = @splat(0),
    /// Time a datagram toward the clients waited in the bottleneck queue before the link
    /// began to send it, over the second half of the run.
    delay_p50_ns: u64 = 0,
    delay_p99_ns: u64 = 0,
    fingerprint: u64 = 0,

    pub fn mbit(r: *const FlowsResult, i: usize) f64 {
        return @as(f64, @floatFromInt(r.bytes[i])) * 8.0 * 1000.0 / @as(f64, @floatFromInt(r.duration_ns));
    }
    /// Over the second half, once the flows have settled.
    pub fn lateMbit(r: *const FlowsResult, i: usize) f64 {
        return @as(f64, @floatFromInt(r.late_bytes[i])) * 8.0 * 1000.0 / @as(f64, @floatFromInt(r.duration_ns / 2));
    }
    pub fn lateShare(r: *const FlowsResult, i: usize) f64 {
        var sum: u64 = 0;
        for (r.late_bytes[0..r.n]) |b| sum += b;
        return if (sum == 0) 0 else @as(f64, @floatFromInt(r.late_bytes[i])) / @as(f64, @floatFromInt(sum));
    }
};

const FlowPkt = struct { t: u64, len: u16, flow: u8, drop: bool, data: [1500]u8 };

/// `tunes.len` flows start together and each downloads one endless response for `duration_ms`
/// of virtual time over `link`, whose queue and rate they share in both directions. Flow i's
/// server runs `tunes[i]`; the clients run the browser's defaults, as in `run`.
pub fn flows(gpa: Allocator, link: Link, tunes: []const ?Tune, duration_ms: u64, seed: u64) !FlowsResult {
    std.debug.assert(tunes.len >= 1 and tunes.len <= max_flows);
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const server_seed: [32]u8 = @splat(9);
    const skey = (try Ed25519.KeyPair.generateDeterministic(server_seed)).public_key.toBytes();
    const t0: u64 = 1_000_000_000;
    var now: u64 = t0;
    const duration: u64 = duration_ms * ms;
    var clients: [max_flows]*Connection = undefined;
    var servers: [max_flows]?*Connection = @splat(null);
    var scfgs: [max_flows]conn.Config = undefined;
    var made: usize = 0;
    defer for (clients[0..made]) |c| c.deinit();
    defer for (servers) |s| if (s) |sv| sv.deinit();
    for (tunes, 0..) |tune, i| {
        var cseed: [64]u8 = undefined;
        rnd.bytes(&cseed);
        var sseed: [64]u8 = undefined;
        rnd.bytes(&sseed);
        clients[i] = try Connection.init(gpa, .{ .server_name = "zui", .identity_seed = @splat(4), .expected_peer = skey, .seed = cseed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .max_streams_uni = 16, .max_streams_bidi = 64, .max_data = 15 << 20, .max_stream_data = 6 << 20, .keep_alive_ms = 3_000, .pmtu_max = 1452 }, now);
        made = i + 1;
        scfgs[i] = .{ .server_name = "zui", .identity_seed = server_seed, .seed = sseed, .now_unix = 1_800_000_000, .max_streams_bidi = 128, .max_streams_uni = 16, .max_data = 16 << 20, .max_stream_data = 1 << 20, .idle_timeout_ms = 30_000, .keep_alive_ms = 0, .alpn = &.{"zui/1"}, .client_auth = false, .pmtu_max = 1452 };
        if (tune) |f| f(&scfgs[i]);
    }
    var fifo: [2]std.ArrayList(FlowPkt) = .{ .empty, .empty }; // 0: to the clients, 1: to the servers
    defer for (&fifo) |*f| f.deinit(gpa);
    var head: [2]usize = .{ 0, 0 };
    var free_at: [2]u64 = .{ 0, 0 };
    const rate: u64 = @as(u64, link.mbit) * 125_000;
    const queue_bytes: u64 = rate * link.queue_ms / 1000;
    const delay: u64 = @as(u64, link.rtt_ms) * ms / 2;
    var waits: std.ArrayList(u32) = .empty; // microseconds
    defer waits.deinit(gpa);
    var res: FlowsResult = .{ .n = tunes.len, .duration_ns = duration };
    var fp = std.hash.Wyhash.init(0);
    var cstream: [max_flows]?u64 = @splat(null);
    var sstream: [max_flows]?u64 = @splat(null);
    var written: [max_flows]u64 = @splat(0);
    const chunk: [64 << 10]u8 = @splat(0x5a);
    var out: [1500]u8 = undefined;
    var iter: u64 = 0;
    while (now - t0 < duration) : (iter += 1) {
        if (iter > 400_000_000) return error.SimRunaway;
        for (&fifo, 0..) |*f, dir| {
            while (head[dir] < f.items.len) {
                const p = &f.items[head[dir]];
                if (p.t > now) break;
                if (!p.drop) {
                    const d = p.data[0..p.len];
                    if (dir == 0) clients[p.flow].handleDatagram(now, d) else {
                        if (servers[p.flow] == null) {
                            const dl = d[5];
                            const sl = d[6 + dl];
                            servers[p.flow] = try Connection.initServer(gpa, scfgs[p.flow], now, d[6..][0..dl], d[7 + dl ..][0..sl]);
                        }
                        servers[p.flow].?.handleDatagram(now, d);
                    }
                }
                head[dir] += 1;
            }
            if (head[dir] == f.items.len) {
                f.clearRetainingCapacity();
                head[dir] = 0;
            } else if (head[dir] >= 512 and head[dir] * 2 >= f.items.len) {
                const rest = f.items.len - head[dir];
                std.mem.copyForwards(FlowPkt, f.items[0..rest], f.items[head[dir]..]);
                f.shrinkRetainingCapacity(rest);
                head[dir] = 0;
            }
        }
        for (0..tunes.len) |i| for (0..2) |side| {
            const is_server = side == 1;
            const c = if (is_server) servers[i] orelse continue else clients[i];
            if (c.nextTimeout()) |t| if (now >= t) c.onTimeout(now);
            if (c.isClosed()) return error.SimClosed;
            if (is_server and c.isEstablished()) {
                if (sstream[i] == null) if (c.acceptBidi()) |id| {
                    sstream[i] = id;
                };
                if (sstream[i]) |id| {
                    while (c.streamUnsent(id) < feed_backlog) {
                        try c.streamWrite(id, &chunk, false);
                        written[i] += chunk.len;
                        // keep the long-lived stream's buffer bounded, as the listener does
                        if (written[i] % (4 << 20) == 0) c.streamTrim(id);
                    }
                }
            }
            if (!is_server and c.isEstablished()) {
                if (cstream[i] == null) {
                    const id = try c.openBidi();
                    try c.streamWrite(id, "bulkbulk", true);
                    cstream[i] = id;
                }
                const st = c.stream(cstream[i].?) orelse return error.SimStreamGone;
                const n = st.recv.contiguous().len;
                if (n > 0) {
                    res.bytes[i] += n;
                    if (now - t0 >= duration / 2) res.late_bytes[i] += n;
                    st.recv.consume(n);
                }
            }
            const dir: usize = 1 - side;
            while (c.pollTransmit(now, &out)) |n| {
                fp.update(std.mem.asBytes(&now));
                fp.update(out[0..n]);
                if (n > link.path_mtu) continue;
                const wait = free_at[dir] -| now;
                if (wait * rate / sec + n > queue_bytes) {
                    if (is_server) res.drops[i] += 1;
                    continue;
                }
                if (is_server and now - t0 >= duration / 2) try waits.append(gpa, @intCast(@min(wait / 1000, std.math.maxInt(u32))));
                const depart = @max(now, free_at[dir]) + n * sec / rate;
                free_at[dir] = depart;
                const lost = link.loss_pm != 0 and rnd.uintLessThan(u32, 1000) < link.loss_pm;
                var p: FlowPkt = .{ .t = depart + delay, .len = @intCast(n), .flow = @intCast(i), .drop = lost, .data = undefined };
                @memcpy(p.data[0..n], out[0..n]);
                try fifo[dir].append(gpa, p);
            }
        };
        var next: u64 = std.math.maxInt(u64);
        for (&fifo, 0..) |*f, dir| if (head[dir] < f.items.len) {
            next = @min(next, f.items[head[dir]].t);
        };
        for (0..tunes.len) |i| {
            if (clients[i].nextTimeout()) |t| next = @min(next, t);
            if (servers[i]) |sv| if (sv.nextTimeout()) |t| {
                next = @min(next, t);
            };
        }
        now = if (next > now) next else now + 10_000;
    }
    for (0..tunes.len) |i| if (servers[i]) |sv| {
        res.pkts[i] = sv.pkts_sent;
        res.lost[i] = sv.pkts_lost;
    };
    std.mem.sort(u32, waits.items, {}, std.sort.asc(u32));
    if (waits.items.len > 0) {
        res.delay_p50_ns = @as(u64, waits.items[waits.items.len / 2]) * 1000;
        res.delay_p99_ns = @as(u64, waits.items[@min(waits.items.len - 1, waits.items.len * 99 / 100)]) * 1000;
    }
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
fn tuneBbr(c: *conn.Config) void {
    c.bbr = true;
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
    .{ .name = "bbr", .tune = tuneBbr },
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
/// Re-pinned once since: a range acknowledged through a probe timeout's copy is no longer sent
/// again when its first packet is declared lost (before: 0x160f4051a22423c0, 0x74135bff816414ea,
/// 0xbd68a2dc86f92d47, 0x69884442ea3c69ca). Every link moved, the lossless one included: phase 4
/// drops the last datagram of each response, and each of those probe timeouts was followed by
/// one such retransmission.
const pinned = [links.len]u64{ 0xc29f6c2809741bf0, 0x1244562c33bb631a, 0x37062a96f9b0a27c, 0x8ef1bb1b2685d425 };

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
    // paced: the bucket (a run of 2 ms of the window, 10 to 64 datagrams, or 1.25 ms of the rate)
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

test "linkbench: BBR completes the workload on every reference link; random loss does not cap its rate" {
    const gpa = std.testing.allocator;
    const work: Work = .{ .bulk_bytes = 256 << 10, .requests = 12, .tail_reqs = 3 };
    for (links) |link| {
        const r = try run(gpa, link, work, tuneBbr, null);
        try std.testing.expectEqual(@as(u64, 256 << 10), r.bulk_bytes);
        try std.testing.expect(r.goodputMbit() <= @as(f64, @floatFromInt(link.mbit)));
        // paced: no burst beyond two send quanta (64 KB each at most)
        try std.testing.expect(r.max_burst <= 2 * 64);
    }
    // 16 MB over the long haul (250 ms, 0.5 percent loss, 100 Mbit): CUBIC is held near
    // 1 Mbit/s by the loss; BBR's model is not
    const long: Work = .{ .bulk_bytes = 16_000_000, .requests = 0, .tail_reqs = 0 };
    const cubic = try run(gpa, long_haul, long, tuneCubic, null);
    const bbr = try run(gpa, long_haul, long, tuneBbr, null);
    if (bbr.goodputMbit() < 10 * cubic.goodputMbit() or bbr.goodputMbit() < 20)
        std.debug.print("long haul: cubic {d:.2} Mbit/s, bbr {d:.2} Mbit/s\n", .{ cubic.goodputMbit(), bbr.goodputMbit() });
    try std.testing.expect(cubic.goodputMbit() < 3);
    try std.testing.expect(bbr.goodputMbit() >= 20);
    try std.testing.expect(bbr.goodputMbit() >= 10 * cubic.goodputMbit());
    // the price is the startup overshoot into a queue of a fifth of the BDP: it loses more
    // than the link's 0.5 percent, but far from a window's worth per round
    try std.testing.expect(bbr.drops_queue > 0 and bbr.lost * 4 < bbr.pkts);
    // with the edge client's receive windows (the browser's 6 MiB per stream is about one BDP
    // here and holds the sender back) it is faster still
    var long_edge = long;
    long_edge.edge_windows = true;
    const edge = try run(gpa, long_haul, long_edge, tuneBbr, null);
    try std.testing.expect(edge.goodputMbit() >= bbr.goodputMbit());
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

test "linkbench flows: flows share one bottleneck and repeat; BBR keeps a deep queue short and leaves CUBIC a share" {
    const gpa = std.testing.allocator;
    const a = try flows(gpa, shared_link, &.{ null, null }, 8_000, 1);
    const b = try flows(gpa, shared_link, &.{ null, null }, 8_000, 1);
    try std.testing.expectEqual(a.fingerprint, b.fingerprint);
    try std.testing.expect(a.bytes[0] > 0 and a.bytes[1] > 0);
    // together they cannot exceed the link, and neither starves
    try std.testing.expect(a.mbit(0) + a.mbit(1) <= 20.0 and a.mbit(0) + a.mbit(1) >= 16.0);
    try std.testing.expect(a.mbit(0) >= 4.0 and a.mbit(1) >= 4.0);
    // a deep queue (10 BDPs, 500 ms): a loss-based sender fills it, BBR does not
    const cubic = try flows(gpa, deep_link, &.{tuneCubic}, 20_000, 1);
    const bbr = try flows(gpa, deep_link, &.{tuneBbr}, 20_000, 1);
    try std.testing.expect(cubic.delay_p50_ns > 200 * ms);
    try std.testing.expect(bbr.delay_p99_ns < 100 * ms);
    try std.testing.expectEqual(@as(u64, 0), bbr.drops[0]);
    try std.testing.expect(bbr.mbit(0) >= 0.95 * cubic.mbit(0));
    // BBR next to CUBIC on a queue of one BDP: BBR takes the larger share, CUBIC is not starved
    const mix = try flows(gpa, shared_link, &.{ tuneBbr, tuneCubic }, 20_000, 1);
    try std.testing.expect(mix.lateShare(1) >= 0.15 and mix.lateShare(0) >= 0.15);
    try std.testing.expect(mix.lateMbit(0) + mix.lateMbit(1) >= 17.0);
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

/// Fairness: flows of different senders start together on one bottleneck with a queue of one
/// bandwidth-delay product. Each flow's rate and share over the second half of the run.
pub fn fairTable(gpa: Allocator, link: Link, duration_ms: u64, seeds: u64) !void {
    std.debug.print("\nfairness: flows sharing {s} for {d} s, {d} seeds; rate and share over the second half (virtual time)\n{s:<22} {s:>10} {s:>7} {s:>10} {s:>7} {s:>8} {s:>9} {s:>9} {s:>8} {s:>8}\n", .{ link.name, duration_ms / 1000, seeds, "flows", "A Mbit/s", "A %", "B Mbit/s", "B %", "sum", "q p50 ms", "q p99 ms", "A lost%", "B lost%" });
    const rows = [_]struct { name: []const u8, a: ?Tune, b: ?Tune }{
        .{ .name = "bbr vs cubic", .a = tuneBbr, .b = tuneCubic },
        .{ .name = "bbr vs newreno", .a = tuneBbr, .b = null },
        .{ .name = "cubic vs cubic", .a = tuneCubic, .b = tuneCubic },
        .{ .name = "bbr vs bbr", .a = tuneBbr, .b = tuneBbr },
        .{ .name = "cubic vs newreno", .a = tuneCubic, .b = null },
    };
    for (rows) |row| {
        var rate: [2]f64 = .{ 0, 0 };
        var share: [2]f64 = .{ 0, 0 };
        var lostp: [2]f64 = .{ 0, 0 };
        var p50: f64 = 0;
        var p99: f64 = 0;
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            const r = try flows(gpa, link, &.{ row.a, row.b }, duration_ms, seed);
            for (0..2) |i| {
                rate[i] += r.lateMbit(i);
                share[i] += r.lateShare(i);
                lostp[i] += 100.0 * @as(f64, @floatFromInt(r.lost[i])) / @as(f64, @floatFromInt(@max(r.pkts[i], 1)));
            }
            p50 += fms(r.delay_p50_ns);
            p99 += fms(r.delay_p99_ns);
        }
        const n: f64 = @floatFromInt(seeds);
        std.debug.print("{s:<22} {d:>10.2} {d:>7.1} {d:>10.2} {d:>7.1} {d:>8.2} {d:>9.1} {d:>9.1} {d:>8.2} {d:>8.2}\n", .{ row.name, rate[0] / n, 100 * share[0] / n, rate[1] / n, 100 * share[1] / n, (rate[0] + rate[1]) / n, p50 / n, p99 / n, lostp[0] / n, lostp[1] / n });
    }
}

/// One bulk flow on a bottleneck with a deep queue (bufferbloat): goodput, how long packets
/// sit in the queue, and loss.
pub fn deepTable(gpa: Allocator, link: Link, duration_ms: u64, seeds: u64) !void {
    std.debug.print("\ndeep buffer: one flow on {s} for {d} s, {d} seeds (virtual time; queue delay over the second half)\n{s:<16} {s:>9} {s:>10} {s:>10} {s:>10} {s:>8} {s:>8}\n", .{ link.name, duration_ms / 1000, seeds, "sender", "Mbit/s", "late Mbit", "q p50 ms", "q p99 ms", "lost %", "drops" });
    const rows = [_]Variant{ variants[0], variants[4], variants[5], .{ .name = "bbr", .tune = tuneBbr } };
    for (rows) |row| {
        var rate: f64 = 0;
        var late: f64 = 0;
        var lostp: f64 = 0;
        var p50: f64 = 0;
        var p99: f64 = 0;
        var drops: u64 = 0;
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            const r = try flows(gpa, link, &.{row.tune}, duration_ms, seed);
            rate += r.mbit(0);
            late += r.lateMbit(0);
            lostp += 100.0 * @as(f64, @floatFromInt(r.lost[0])) / @as(f64, @floatFromInt(@max(r.pkts[0], 1)));
            p50 += fms(r.delay_p50_ns);
            p99 += fms(r.delay_p99_ns);
            drops += r.drops[0];
        }
        const n: f64 = @floatFromInt(seeds);
        std.debug.print("{s:<16} {d:>9.2} {d:>10.2} {d:>10.1} {d:>10.1} {d:>8.2} {d:>8}\n", .{ row.name, rate / n, late / n, p50 / n, p99 / n, lostp / n, drops / seeds });
    }
}

/// Small responses: `requests` responses of 87 KB (one checkpoint), one after the other on a
/// fresh connection, on each lossy link. Completion time of each (request sent to last byte).
pub fn smallTable(gpa: Allocator, ls: []const Link, requests: usize, seeds: u64) !void {
    std.debug.print("\nsmall responses: {d} x 87 KB in sequence on a fresh connection, {d} seeds (virtual time)\n{s:<18} {s:<14} {s:>9} {s:>9} {s:>9} {s:>8} {s:>7} {s:>7} {s:>6}\n", .{ requests, seeds, "link", "variant", "p50 ms", "p99 ms", "mean ms", "p50 RTT", "lost", "retx", "ptos" });
    const rows = [_]Variant{ variants[0], variants[4], variants[5], .{ .name = "bbr", .tune = tuneBbr } };
    for (ls) |link| for (rows) |row| {
        var lat: std.ArrayList(u64) = .empty;
        defer lat.deinit(gpa);
        var lost: u64 = 0;
        var retx: u64 = 0;
        var ptos: u64 = 0;
        var seed: u64 = 1;
        while (seed <= seeds) : (seed += 1) {
            const r = try run(gpa, link, .{ .seed = seed, .bulk_bytes = 0, .requests = requests, .req_fixed = 87_000, .tail_reqs = 0 }, row.tune, &lat);
            lost += r.lost;
            retx += r.retx;
            ptos += r.ptos;
        }
        var sum: u64 = 0;
        for (lat.items) |x| sum += x;
        std.mem.sort(u64, lat.items, {}, std.sort.asc(u64));
        const p50 = fms(pct(lat.items, 50));
        std.debug.print("{s:<18} {s:<14} {d:>9.1} {d:>9.1} {d:>9.1} {d:>8.2} {d:>7} {d:>7} {d:>6}\n", .{ link.name, row.name, p50, fms(pct(lat.items, 99)), fms(sum / @max(lat.items.len, 1)), p50 / @as(f64, @floatFromInt(link.rtt_ms)), lost / seeds, retx / seeds, ptos / seeds });
    };
}

/// The fairness and deep-buffer link: 20 Mbit, a 50 ms round trip (a BDP of 125,000 bytes),
/// with a queue of 1 BDP (50 ms of the rate) or 10.
pub const shared_link: Link = .{ .name = "20Mbit 50ms q1BDP", .rtt_ms = 50, .loss_pm = 0, .mbit = 20, .queue_ms = 50 };
pub const deep_link: Link = .{ .name = "20Mbit 50ms q10BDP", .rtt_ms = 50, .loss_pm = 0, .mbit = 20, .queue_ms = 500 };

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
        std.debug.print("\nlong-haul bulk profile, edge client windows (128 MiB per stream)", .{});
        var long_edge = long;
        long_edge.edge_windows = true;
        try table(std.testing.allocator, &.{long_haul}, &.{ variants[0], variants[4], variants[10] }, long_edge, envInt("ZUI_NET_BENCH_LONG_SEEDS", 3));
    }
    const flow_s = envInt("ZUI_NET_BENCH_FLOW_S", 60);
    const flow_seeds = envInt("ZUI_NET_BENCH_FLOW_SEEDS", 3);
    try fairTable(std.testing.allocator, shared_link, flow_s * 1000, flow_seeds);
    try deepTable(std.testing.allocator, deep_link, flow_s * 1000, flow_seeds);
    try smallTable(std.testing.allocator, &(links[1..].* ++ [_]Link{long_haul}), 200, envInt("ZUI_NET_BENCH_SMALL_SEEDS", 5));
}
