//! QUIC v1 connection (RFC 9000, 9001, 9002) as a sans-I/O state machine: feed datagrams and the
//! clock in, read datagrams and a deadline out. One connection, client role (`init`, TLS from
//! tls13.zig) or server role (`initServer`, TLS from tls13_server.zig, used by server.zig's
//! listener), packet protection from qcrypto.zig. Scope: what an anemo client needs (streams,
//! flow control, loss recovery, NewReno, key update, Retry, close), not a general QUIC library.
//!
//! Times are monotonic nanoseconds supplied by the caller. Hot paths (datagram in, datagram out)
//! allocate only when stream buffers grow.
const std = @import("std");
const Allocator = std.mem.Allocator;
const qc = @import("qcrypto.zig");
const tls = @import("tls13.zig");
const tls_srv = @import("tls13_server.zig");
const x509 = @import("x509.zig");
const buf = @import("buf.zig");
const cong = @import("cc.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub const max_datagram = 1200; // datagram size before path MTU validation (and every Initial)
/// Largest datagram any path may validate (we advertise max_udp_payload_size 1500).
pub const max_mtu = 1500;
/// Delayed-ACK bound for 1-RTT packets (we advertise the default max_ack_delay of 25 ms).
const ack_delay_ns = 2 * std.time.ns_per_ms;
pub const cid_len = 8;
/// Out-of-order CRYPTO bytes we buffer per space before CRYPTO_BUFFER_EXCEEDED.
const max_crypto_buffer = 1 << 20;
/// Peer connection ids we keep (we advertise active_connection_id_limit = 4).
const max_peer_cids = 8;
const ms = std.time.ns_per_ms;
const us = std.time.ns_per_us;
/// Path MTU search (`Config.pmtud`): it stops when the largest size that passed and the
/// smallest that failed are closer than this; a finished search runs again after
/// `pmtu_raise_ns` (RFC 8899 PMTU_RAISE_TIMER), and after a black hole once `pmtu_cooldown_ns`
/// has passed.
const pmtu_step = 24;
const pmtu_raise_ns = 600 * std.time.ns_per_s;
const pmtu_cooldown_ns = 60 * std.time.ns_per_s;

pub var trace: bool = false;
fn tr(comptime fmt: []const u8, args: anytype) void {
    if (!trace) return;
    var us_now: u64 = 0;
    if (@import("builtin").link_libc) {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
        us_now = @as(u64, @intCast(ts.sec)) * 1_000_000 + @as(u64, @intCast(ts.nsec)) / 1000;
    }
    std.debug.print("[quic {d}] " ++ fmt ++ "\n", .{us_now % 100_000_000} ++ args);
}

pub const Space = enum(u2) { initial = 0, handshake = 1, app = 2 };

pub const Config = struct {
    server_name: []const u8,
    /// Ed25519 network key seed: the anemo PeerId is its public key.
    identity_seed: [32]u8,
    expected_peer: ?[32]u8 = null,
    /// Client role: check the server's certificate as `tls13.Trust` says (a P-256 certificate
    /// pinned by hash, as browsers do) instead of as an identity certificate.
    trust: ?tls.Trust = null,
    /// 64 bytes of fresh randomness: connection ids, TLS random, x25519 secret, cert serial.
    seed: [64]u8,
    now_unix: i64,
    // Flow control we advertise. Defaults suit large state-sync responses.
    max_data: u64 = 256 << 20,
    max_stream_data: u64 = 128 << 20,
    max_streams_uni: u64 = 16,
    max_streams_bidi: u64 = 16,
    idle_timeout_ms: u64 = 30_000,
    /// Send a PING after this much silence (0 = off). sui-node idles out at 10 s.
    keep_alive_ms: u64 = 3_000,
    // Server role only (zui/1 and WebTransport listeners; anemo leaves the defaults).
    /// ALPN protocols the server accepts (tls13_server.Config.alpn).
    alpn: []const []const u8 = &.{},
    /// Request a client certificate (anemo mutual auth).
    client_auth: bool = true,
    /// Serve a P-256 certificate when the client picks `alpn[alt.alpn_index]` (tls13_server.Alt).
    alt: ?tls_srv.Alt = null,
    /// Serve this loaded chain and key instead (tls13_server.Config.chain: to everyone but a
    /// client that asks for the identity certificate).
    chain: ?*const tls_srv.Identity = null,
    /// RFC 9221 max_datagram_frame_size we advertise (0: not sent). Received DATAGRAM frames are
    /// dropped (WebTransport needs the parameter; zui/1 reserves datagrams).
    max_datagram_frame_size: u64 = 0,
    /// Path MTU probing target (RFC 9000 section 14.3, DPLPMTUD): once the handshake is confirmed
    /// one PING+PADDING datagram of this size is sent; its ACK raises the datagram size from
    /// 1200. 0: no probing (anemo keeps 1200). 1452 fits IPv6 over a 1500-byte Ethernet MTU.
    pmtu_max: u16 = 0,
    /// 1-RTT packets sealed under one key before we update the keys ourselves (RFC 9001 6.6:
    /// AES-128-GCM must not seal more than 2^23 packets under one key). quinn rotates on its own
    /// side; a zui-to-zui link needs this one. Tests and the interop suite set it low.
    key_update_pkts: u64 = 1 << 22,
    /// A connection still handshaking this long after it was created is dropped silently (0:
    /// only the idle timeout). Listeners set it so half-open connections cannot hold a slot for
    /// a whole idle timeout.
    handshake_timeout_ms: u64 = 0,
    // Sender-side switches (src/net/cc.zig). All off by default: the sender is then exactly the
    // unpaced NewReno of this file. None changes a byte on the wire, only when datagrams leave.
    /// Pacing (RFC 9002 section 7.7): sends are spread over the round trip at 1.25 times the
    /// window per smoothed RTT (2 times in slow start) in runs of at most 64 datagrams, instead
    /// of a whole window in one burst. `nextTimeout` then also reports when the next run is due.
    pacing: bool = false,
    /// HyStart++ (RFC 9406): the first slow start ends when the round-trip time of a round
    /// rises by an eighth (4 to 16 ms) over the round before, instead of when the bottleneck
    /// queue overflows and a burst of packets is lost.
    hystart: bool = false,
    /// CUBIC (RFC 9438) instead of NewReno: the window is cut to 0.7 (not 0.5) on a loss and
    /// regrows along the cubic function, never slower than Reno would; one reduction per round
    /// trip, tracked by send time as RFC 9002 section 7.3.2 describes. NewReno stays the default.
    /// CUBIC brings HyStart++ with it (RFC 9438 section 4.10): cutting to 0.7 after a slow
    /// start that overshot leaves the window above the path and loses a second burst.
    cubic: bool = false,
    /// Path MTU search (RFC 8899 DPLPMTUD, RFC 9000 section 14.3) instead of the single probe
    /// of `pmtu_max`: when the largest size does not pass, smaller ones are tried (1452, then
    /// by halving) until the path's size is known to within 24 bytes, so a path below 1500
    /// (PPPoE, a tunnel) still gets more than 1200. The search runs again every 10 minutes.
    /// And the validated size is no longer trusted for ever: when full-size packets keep being
    /// lost while smaller ones pass, or two probe timeouts in a row go unanswered, the
    /// connection falls back to 1200 (a black hole after a route change) and searches again a
    /// minute later. `pmtu_max` is the ceiling (1472 fits IPv4 over Ethernet, 1452 IPv6).
    pmtud: bool = false,
    /// The initial congestion window follows the datagram size (RFC 9002 section 7.2: 10
    /// datagrams, at most 14,720 bytes, at least 2 datagrams; recalculated when the size
    /// changes). At 1200 bytes that is the 12,000 every connection starts with, switch or not.
    /// With the switch on, a datagram size raised before the first slow start has ended adds
    /// the difference to the window (1452: 14,520, so 2,520 more; 1472: 14,720).
    iw_mtu: bool = false,
    /// Server only. The 1-RTT send keys are installed when the server's Finished is written
    /// (not when the client's arrives), so the application may open streams and write right
    /// behind the handshake flight (`canSendEarly`): "0.5-RTT data", RFC 9001 sections 4.1.1 and
    /// 5.7, RFC 8446 section 4.4.4. It reaches the client with the handshake instead of a
    /// round trip later. Nothing is read early: the receive keys still wait for the client's
    /// Finished, and the 3x anti-amplification limit covers these packets like any other. The
    /// data goes to a client that has not proven it holds its key, so a listener that
    /// authenticates clients must only send what any client may see (HTTP/3 SETTINGS).
    early_send: bool = false,
};

/// RFC 9002 section 7.2.
fn initialWindow(mtu: u64) u64 {
    return @min(10 * mtu, @max(2 * mtu, 14_720));
}

pub const Error = error{ OutOfMemory, ConnectionClosed, StreamLimit, InvalidStream, FlowControl };

pub const CloseInfo = struct { code: u64, app: bool, remote: bool, reason: []const u8 };

// ------------------------------------------------------------------ varint

pub fn varintLen(v: u64) usize {
    return if (v < 1 << 6) 1 else if (v < 1 << 14) 2 else if (v < 1 << 30) 4 else 8;
}

pub fn putVarint(out: []u8, p: *usize, v: u64) void {
    switch (varintLen(v)) {
        1 => out[p.*] = @intCast(v),
        2 => std.mem.writeInt(u16, out[p.*..][0..2], @as(u16, @intCast(v)) | 0x4000, .big),
        4 => std.mem.writeInt(u32, out[p.*..][0..4], @as(u32, @intCast(v)) | 0x8000_0000, .big),
        else => std.mem.writeInt(u64, out[p.*..][0..8], v | 0xC000_0000_0000_0000, .big),
    }
    p.* += varintLen(v);
}

pub fn getVarint(b: []const u8, p: *usize) ?u64 {
    if (p.* >= b.len) return null;
    const first = b[p.*];
    const n: usize = @as(usize, 1) << @intCast(first >> 6);
    if (b.len - p.* < n) return null;
    var v: u64 = first & 0x3f;
    for (b[p.* + 1 ..][0 .. n - 1]) |x| v = (v << 8) | x;
    p.* += n;
    return v;
}

// ------------------------------------------------------------------ records

const FrameRec = union(enum) {
    crypto: struct { off: u64, len: u32 },
    stream: struct { id: u64, off: u64, len: u32, fin: bool },
    max_data,
    max_stream_data: u64,
    max_streams_uni,
    max_streams_bidi,
    retire_cid: u64,
    handshake_done,
    /// PMTU probe of this datagram size (not retransmitted; loss is no congestion signal).
    pmtu: u16,
    reset_stream: Ctl.Reset,
    stop_sending: Ctl.Stop,
};

/// RESET_STREAM and STOP_SENDING waiting to be sent (or resent after a loss). Kept on the
/// connection, not the stream: a reset must reach the peer after the stream is gone.
const Ctl = union(enum) {
    reset: Reset,
    stop: Stop,
    const Reset = struct { id: u64, code: u64, final: u64 };
    const Stop = struct { id: u64, code: u64 };
};
/// Streams the application freed while the peer may still send on them or a packet of ours is
/// unacknowledged (`streamFree`). Past this many the oldest is dropped outright.
const max_detached = 1024;
const max_recs = 6;

const Sent = struct {
    pn: u64,
    time: u64,
    size: u16,
    ack_eliciting: bool,
    in_flight: bool,
    nrec: u8 = 0,
    recs: [max_recs]FrameRec = undefined,
};

const SpaceState = struct {
    /// Packets in flight, ascending pn, live from `sent_head` (acked and lost packets leave from
    /// the front by moving the head, so an ACK costs O(packets it covers), not O(in flight)).
    sent_head: usize = 0,
    send: ?qc.PacketKeys = null,
    recv: ?qc.PacketKeys = null,
    next_pn: u64 = 0,
    recv_set: buf.PnSet = .{},
    largest_recv_time: u64 = 0,
    ack_needed: bool = false,
    ack_now: bool = false,
    unacked_eliciting: u32 = 0,
    ack_deadline: ?u64 = null,
    crypto_out: std.ArrayList(u8) = .empty,
    crypto_sent: u64 = 0,
    crypto_retx: std.ArrayList(buf.Range) = .empty,
    crypto_in: buf.RecvBuf = .{},
    sent: std.ArrayList(Sent) = .empty,
    largest_acked: ?u64 = null,
    loss_time: ?u64 = null,
    time_last_ack_eliciting: u64 = 0,
    probe: u8 = 0,
    ack_eliciting_in_flight: u32 = 0,
    discarded: bool = false,

    fn live(s: *const SpaceState) []Sent {
        return s.sent.items[s.sent_head..];
    }

    /// Index (in `live()`) of the first packet with pn > `pn`.
    fn upper(s: *const SpaceState, pn: u64) usize {
        const l = s.live();
        var lo: usize = 0;
        var hi: usize = l.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (l[mid].pn <= pn) lo = mid + 1 else hi = mid;
        }
        return lo;
    }

    /// Drops `n` packets from the front of `live()`; compacts once the dead prefix is large.
    fn dropFront(s: *SpaceState, n: usize) void {
        s.sent_head += n;
        if (s.sent_head == s.sent.items.len) {
            s.sent.clearRetainingCapacity();
            s.sent_head = 0;
        } else if (s.sent_head >= 256 and s.sent_head * 2 >= s.sent.items.len) {
            const rest = s.sent.items.len - s.sent_head;
            std.mem.copyForwards(Sent, s.sent.items[0..rest], s.sent.items[s.sent_head..]);
            s.sent.shrinkRetainingCapacity(rest);
            s.sent_head = 0;
        }
    }

    fn clearSent(s: *SpaceState) void {
        s.sent.clearRetainingCapacity();
        s.sent_head = 0;
    }

    fn deinit(s: *SpaceState, gpa: Allocator) void {
        s.crypto_out.deinit(gpa);
        s.crypto_retx.deinit(gpa);
        s.crypto_in.deinit(gpa);
        s.sent.deinit(gpa);
    }
};

pub const Stream = struct {
    id: u64,
    // send side
    send_buf: std.ArrayList(u8) = .empty,
    /// Stream offset of send_buf[0] (bytes below it were acknowledged and trimmed, `streamTrim`).
    send_base: u64 = 0,
    send_off: u64 = 0, // next new byte
    fin_queued: bool = false,
    fin_sent: bool = false,
    retx: std.ArrayList(buf.Range) = .empty,
    peer_max: u64 = 0,
    /// STREAM frames of this stream in packets not yet acknowledged or declared lost. A stream
    /// whose bytes are all sent is not finished until this is 0 (`streamSettled`): a lost packet
    /// requeues its range on the stream, so a freed stream's lost data could never be resent.
    inflight: u32 = 0,
    // receive side
    recv: buf.RecvBuf = .{},
    recv_limit: u64 = 0,
    reset: ?u64 = null,
    stopped_by_peer: ?u64 = null,
    /// Highest offset counted toward the connection's received bytes (`recv_data`).
    counted: u64 = 0,
    /// Offset up to which this stream's bytes were returned to the connection window (consumed
    /// by the application, or discarded).
    credited: u64 = 0,
    /// On the connection's `recv_watch` list (window credit is checked from `recv.base`).
    watched: bool = false,
    /// Freed by the application but kept: late bytes are counted and dropped, unacknowledged
    /// data stays retransmittable, until both directions are finished (`reapDetached`).
    detached: bool = false,
    /// Our send side was reset (RESET_STREAM queued): nothing more is sent or resent.
    send_reset: bool = false,

    fn deinit(s: *Stream, gpa: Allocator) void {
        s.send_buf.deinit(gpa);
        s.retx.deinit(gpa);
        s.recv.deinit(gpa);
    }

    fn hasPending(s: *const Stream) bool {
        if (s.send_reset) return false;
        if (s.retx.items.len > 0) return true;
        if (s.send_off < s.send_base + s.send_buf.items.len) return true;
        return s.fin_queued and !s.fin_sent;
    }
};

const PeerParams = struct {
    idle_timeout_ms: u64 = 0,
    max_udp_payload: u64 = 65527,
    max_data: u64 = 0,
    max_stream_data_bidi_local: u64 = 0,
    max_stream_data_bidi_remote: u64 = 0,
    max_stream_data_uni: u64 = 0,
    max_streams_bidi: u64 = 0,
    max_streams_uni: u64 = 0,
    ack_delay_exponent: u6 = 3,
    max_ack_delay_ms: u64 = 25,
};

pub const State = enum { handshaking, established, closing, draining, closed };

pub const Connection = struct {
    gpa: Allocator,
    cfg: Config,
    prng: std.Random.DefaultCsprng,
    tls: tls.Client,
    cert: [x509.max_cert_len]u8 = undefined,
    cert_len: usize = 0,
    local_tp: [256]u8 = undefined,
    local_tp_len: usize = 0,

    state: State = .handshaking,
    scid: [cid_len]u8,
    dcid: [20]u8 = undefined,
    dcid_len: u8 = cid_len,
    odcid: [cid_len]u8,
    retry_token: std.ArrayList(u8) = .empty,
    retry_scid: ?[20]u8 = null,
    retry_scid_len: u8 = 0,
    got_server_packet: bool = false,
    spaces: [3]SpaceState = .{ .{}, .{}, .{} },
    initial_keys_secret_dcid: [20]u8 = undefined,
    initial_keys_dcid_len: u8 = cid_len,

    app_recv_next: ?qc.PacketKeys = null,
    send_phase: bool = false,
    recv_phase: bool = false,
    /// 1-RTT packets sealed under the current send keys, the first packet number sent under them,
    /// and whether the peer has acknowledged one of those (required before the next update).
    phase_pkts: u64 = 0,
    phase_first_pn: u64 = 0,
    phase_acked: bool = false,
    /// Key updates we initiated, and 1-RTT packets that failed authentication (integrity limit).
    key_updates: u64 = 0,
    auth_failures: u64 = 0,
    handshake_confirmed: bool = false,
    /// Validated datagram size on the current path (`max_datagram` until a probe is acked).
    mtu: usize = max_datagram,
    pmtu_inflight: bool = false,
    pmtu_tries: u8 = 0,
    /// Path MTU search (`cfg.pmtud`): the size being probed (0: none chosen yet), the smallest
    /// size known not to pass (0: none), and when a finished search starts again (0: running).
    pmtu_probe: u16 = 0,
    pmtu_fail: u16 = 0,
    pmtu_search_at: u64 = 0,
    /// Black-hole detection: loss events in a row that took full-size packets while no
    /// full-size packet was acknowledged; set by a loss pass that lost one.
    big_loss: u8 = 0,
    big_lost_pass: bool = false,
    pmtu_black_holes: u64 = 0,
    /// Freed streams kept with their buffer capacity for reuse (warm streams: a request stream
    /// costs no allocation once the connection has served a few).
    stream_pool: std.ArrayList(*Stream) = .empty,
    /// Counters for benches and logs: packets sent, declared lost, PTO expiries.
    pkts_sent: u64 = 0,
    pkts_lost: u64 = 0,
    ptos: u64 = 0,
    /// STREAM frames sent again (after a loss, or by a PTO probe), and STREAM frames received
    /// that carried nothing new (the peer's spurious retransmissions).
    stream_retx: u64 = 0,
    dup_frames: u64 = 0,

    peer: PeerParams = .{},
    peer_tp_checked: bool = false,

    // server role (initServer)
    srv: ?*tls_srv.Server = null,
    /// The client's first destination connection id (its Initial keys and our
    /// original_destination_connection_id transport parameter).
    srv_odcid: [20]u8 = undefined,
    srv_odcid_len: u8 = 0,
    /// The source connection id of the Retry we sent (retry_source_connection_id), if any.
    srv_retry_scid: [20]u8 = undefined,
    srv_retry_scid_len: u8 = 0,
    hs_deadline: u64 = 0,
    need_handshake_done: bool = false,
    /// Anti-amplification (RFC 9000 section 8.1): before the client's address is validated (its
    /// first Handshake packet) a server sends at most 3x the bytes it received.
    addr_validated: bool = true,
    amp_recv: u64 = 0,
    amp_sent: u64 = 0,

    // flow control (connection level)
    send_max_data: u64 = 0,
    sent_data: u64 = 0,
    recv_max_data: u64,
    recv_data: u64 = 0,
    /// Bytes returned to the connection window: consumed by the application from a stream,
    /// discarded when it freed one, or dropped on a reset or freed stream. MAX_DATA follows
    /// this, not `recv_data`: credit given on receipt let a peer send without bound while the
    /// application read nothing, and data it never read held credit for ever.
    recv_consumed: u64 = 0,
    /// Streams with receive data whose window credit may be due (scanned by `creditScan`).
    recv_watch: std.ArrayList(*Stream) = .empty,
    credit_due: bool = true,
    detached: std.ArrayList(u64) = .empty,
    ctl: std.ArrayList(Ctl) = .empty,
    need_max_data: bool = false,
    need_max_streams_uni: bool = false,
    need_max_streams_bidi: bool = false,
    streams_uni_limit: u64,
    streams_bidi_limit: u64,
    streams_uni_seen: u64 = 0,
    streams_bidi_seen: u64 = 0,

    streams: std.AutoArrayHashMapUnmanaged(u64, *Stream) = .empty,
    next_bidi: u64 = 0,
    /// Next unidirectional stream id we open (client 2, server 3; step 4).
    next_uni: u64 = 2,
    incoming_uni: std.ArrayList(u64) = .empty,
    incoming_bidi: std.ArrayList(u64) = .empty,
    pending_msd: std.ArrayList(u64) = .empty, // stream ids needing MAX_STREAM_DATA
    pending_retire: std.ArrayList(u64) = .empty,
    path_responses: std.ArrayList([8]u8) = .empty,
    peer_cids: std.ArrayList(PeerCid) = .empty,
    dcid_seq: u64 = 0,

    // recovery
    rtt_initialized: bool = false,
    latest_rtt: u64 = 0,
    min_rtt: u64 = std.math.maxInt(u64),
    srtt: u64 = 333 * ms,
    rttvar: u64 = 333 * ms / 2,
    pto_count: u32 = 0,
    bytes_in_flight: u64 = 0,
    cwnd: u64 = initialWindow(max_datagram),
    ssthresh: u64 = std.math.maxInt(u64),
    recovery_start: ?u64 = null,
    timer: ?u64 = null,
    pacer: cong.Pacer = .{},
    hystart: cong.HyStart = .{},
    cubic: cong.Cubic = .{},
    /// The last transmit round ended because the window was full (not because the application
    /// had nothing more): only then does CUBIC grow the window (RFC 9438 section 5.8).
    cwnd_limited: bool = false,
    /// Set by a transmit round that the pacer held back: when the next run may leave.
    pace_at: ?u64 = null,

    // timing
    last_recv: u64 = 0,
    last_send: u64 = 0,
    idle_ns: u64 = 0,
    close: ?CloseInfo = null,
    close_pending: bool = false,
    close_sent: bool = false,
    close_deadline: u64 = 0,
    close_reason_buf: [64]u8 = undefined,

    const PeerCid = struct { seq: u64, len: u8, cid: [20]u8, token: [16]u8 };
    /// What an ACK frame told the congestion controller: its space and largest acknowledged
    /// packet number, and the round-trip sample it produced, if any.
    const AckInfo = struct { space: Space, largest: u64, rtt: ?u64, newest_sent: u64 };

    pub fn init(gpa: Allocator, cfg: Config, now: u64) Error!*Connection {
        const c = try gpa.create(Connection);
        errdefer gpa.destroy(c);
        var prng = std.Random.DefaultCsprng.init(cfg.seed[0..32].*);
        var scid: [cid_len]u8 = undefined;
        var odcid: [cid_len]u8 = undefined;
        var tls_random: [32]u8 = undefined;
        var xsec: [32]u8 = undefined;
        var serial: [20]u8 = undefined;
        prng.random().bytes(&scid);
        prng.random().bytes(&odcid);
        prng.random().bytes(&tls_random);
        prng.random().bytes(&xsec);
        prng.random().bytes(&serial);
        const kp = Ed25519.KeyPair.generateDeterministic(cfg.identity_seed) catch return error.OutOfMemory;
        c.* = .{
            .gpa = gpa,
            .cfg = cfg,
            .prng = prng,
            .tls = undefined,
            .scid = scid,
            .odcid = odcid,
            .recv_max_data = cfg.max_data,
            .streams_uni_limit = cfg.max_streams_uni,
            .streams_bidi_limit = cfg.max_streams_bidi,
            .idle_ns = cfg.idle_timeout_ms * ms,
            .last_recv = now,
            .last_send = now,
        };
        @memcpy(c.dcid[0..cid_len], &odcid);
        c.cert_len = x509.generateSelfSigned(&c.cert, kp, serial, cfg.server_name);
        c.encodeLocalParams();
        if (cfg.handshake_timeout_ms != 0) c.hs_deadline = now + cfg.handshake_timeout_ms * ms;
        c.tls = tls.Client.init(.{
            .server_name = cfg.server_name,
            .local_tp = c.local_tp[0..c.local_tp_len],
            .identity = kp,
            .cert_der = c.cert[0..c.cert_len],
            .expected_peer = cfg.expected_peer,
            .trust = cfg.trust,
            .now_unix = cfg.now_unix,
            .random = tls_random,
            .x25519_secret = xsec,
            .alpn = if (cfg.alpn.len > 0) cfg.alpn[0] else "",
        });
        c.installInitialKeys(&odcid);
        c.tls.start(gpa) catch |e| return mapTls(e);
        try c.drainTls();
        return c;
    }

    /// Server role: a connection for the client whose first Initial packet carried destination
    /// connection id `odcid` and source connection id `client_scid`. Feed that datagram to
    /// `handleDatagram` next. `cfg.expected_peer` is ignored (any client key is accepted; the
    /// caller reads `peerId` after the handshake).
    pub fn initServer(gpa: Allocator, cfg: Config, now: u64, odcid: []const u8, client_scid: []const u8) Error!*Connection {
        if (odcid.len < 8 or odcid.len > 20 or client_scid.len > 20) return error.ConnectionClosed;
        const c = try gpa.create(Connection);
        errdefer gpa.destroy(c);
        var prng = std.Random.DefaultCsprng.init(cfg.seed[0..32].*);
        var scid: [cid_len]u8 = undefined;
        var tls_random: [32]u8 = undefined;
        var xsec: [32]u8 = undefined;
        var serial: [20]u8 = undefined;
        prng.random().bytes(&scid);
        prng.random().bytes(&tls_random);
        prng.random().bytes(&xsec);
        prng.random().bytes(&serial);
        const kp = Ed25519.KeyPair.generateDeterministic(cfg.identity_seed) catch return error.OutOfMemory;
        c.* = .{
            .gpa = gpa,
            .cfg = cfg,
            .prng = prng,
            .tls = undefined,
            .scid = scid,
            .odcid = undefined,
            .recv_max_data = cfg.max_data,
            .streams_uni_limit = cfg.max_streams_uni,
            .streams_bidi_limit = cfg.max_streams_bidi,
            .idle_ns = cfg.idle_timeout_ms * ms,
            .last_recv = now,
            .last_send = now,
            .got_server_packet = true, // the peer's connection id is known; no Retry to us
            .next_bidi = 1,
            .next_uni = 3,
            .addr_validated = false,
        };
        c.tls = tls.Client.init(.{ .server_name = cfg.server_name, .local_tp = "", .identity = kp, .cert_der = "", .now_unix = cfg.now_unix, .random = tls_random, .x25519_secret = xsec });
        c.srv_odcid_len = @intCast(odcid.len);
        @memcpy(c.srv_odcid[0..odcid.len], odcid);
        c.dcid_len = @intCast(client_scid.len);
        @memcpy(c.dcid[0..client_scid.len], client_scid);
        c.cert_len = x509.generateSelfSigned(&c.cert, kp, serial, cfg.server_name);
        c.encodeLocalParams();
        if (cfg.handshake_timeout_ms != 0) c.hs_deadline = now + cfg.handshake_timeout_ms * ms;
        const st = try gpa.create(tls_srv.Server);
        st.* = tls_srv.Server.init(.{
            .server_name = cfg.server_name,
            .local_tp = c.local_tp[0..c.local_tp_len],
            .identity = kp,
            .cert_der = c.cert[0..c.cert_len],
            .alpn = cfg.alpn,
            .client_auth = cfg.client_auth,
            .alt = cfg.alt,
            .chain = cfg.chain,
            .now_unix = cfg.now_unix,
            .random = tls_random,
            .x25519_secret = xsec,
        });
        c.srv = st;
        const k = qc.initialKeys(odcid);
        c.spaces[0].send = k.server;
        c.spaces[0].recv = k.client;
        return c;
    }

    /// Server role, right after `initServer`: the client came back with a valid Retry token. Its
    /// Initial keys and `initServer`'s odcid are the Retry's source connection id; the transport
    /// parameters name the client's first destination id (from the token) and the Retry's id
    /// (RFC 9000 section 7.3), and the address counts as validated (no amplification limit).
    pub fn markRetried(c: *Connection, original_dcid: []const u8, retry_scid: []const u8) void {
        std.debug.assert(original_dcid.len <= 20 and retry_scid.len <= 20);
        @memcpy(c.srv_odcid[0..original_dcid.len], original_dcid);
        c.srv_odcid_len = @intCast(original_dcid.len);
        @memcpy(c.srv_retry_scid[0..retry_scid.len], retry_scid);
        c.srv_retry_scid_len = @intCast(retry_scid.len);
        c.encodeLocalParams();
        if (c.srv) |st| st.cfg.local_tp = c.local_tp[0..c.local_tp_len];
        c.addr_validated = true;
    }

    /// Server role: index into `cfg.alpn` of the negotiated protocol.
    pub fn alpnIndex(c: *const Connection) ?u8 {
        return if (c.srv) |s| s.alpn else null;
    }

    pub fn isServer(c: *const Connection) bool {
        return c.srv != null;
    }

    /// True for a stream id the peer opens (client: odd ids; server: even ids).
    fn peerInitiated(c: *const Connection, id: u64) bool {
        return ((id & 1) == 1) != (c.srv != null);
    }

    pub fn deinit(c: *Connection) void {
        const gpa = c.gpa;
        c.tls.deinit(gpa);
        if (c.srv) |st| {
            st.deinit(gpa);
            gpa.destroy(st);
        }
        for (&c.spaces) |*s| s.deinit(gpa);
        for (c.streams.values()) |s| {
            s.deinit(gpa);
            gpa.destroy(s);
        }
        c.streams.deinit(gpa);
        c.recv_watch.deinit(gpa);
        c.detached.deinit(gpa);
        c.ctl.deinit(gpa);
        for (c.stream_pool.items) |s| {
            s.deinit(gpa);
            gpa.destroy(s);
        }
        c.stream_pool.deinit(gpa);
        c.incoming_uni.deinit(gpa);
        c.incoming_bidi.deinit(gpa);
        c.pending_msd.deinit(gpa);
        c.pending_retire.deinit(gpa);
        c.path_responses.deinit(gpa);
        c.peer_cids.deinit(gpa);
        c.retry_token.deinit(gpa);
        gpa.destroy(c);
    }

    fn mapTls(e: tls.Error) Error {
        return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.ConnectionClosed,
        };
    }

    fn encodeLocalParams(c: *Connection) void {
        var p: usize = 0;
        const o = &c.local_tp;
        const put = struct {
            fn f(out: *[256]u8, pos: *usize, id: u64, v: u64) void {
                putVarint(out, pos, id);
                putVarint(out, pos, varintLen(v));
                putVarint(out, pos, v);
            }
        }.f;
        put(o, &p, 0x01, c.cfg.idle_timeout_ms);
        put(o, &p, 0x03, 1500);
        put(o, &p, 0x04, c.cfg.max_data);
        put(o, &p, 0x05, c.cfg.max_stream_data);
        put(o, &p, 0x06, c.cfg.max_stream_data);
        put(o, &p, 0x07, c.cfg.max_stream_data);
        put(o, &p, 0x08, c.cfg.max_streams_bidi);
        put(o, &p, 0x09, c.cfg.max_streams_uni);
        put(o, &p, 0x0e, 4);
        if (c.cfg.max_datagram_frame_size != 0) put(o, &p, 0x20, c.cfg.max_datagram_frame_size);
        if (c.srv_odcid_len != 0) {
            putVarint(o, &p, 0x00);
            putVarint(o, &p, c.srv_odcid_len);
            @memcpy(o[p..][0..c.srv_odcid_len], c.srv_odcid[0..c.srv_odcid_len]);
            p += c.srv_odcid_len;
        }
        if (c.srv_retry_scid_len != 0) {
            putVarint(o, &p, 0x10);
            putVarint(o, &p, c.srv_retry_scid_len);
            @memcpy(o[p..][0..c.srv_retry_scid_len], c.srv_retry_scid[0..c.srv_retry_scid_len]);
            p += c.srv_retry_scid_len;
        }
        putVarint(o, &p, 0x0f);
        putVarint(o, &p, cid_len);
        @memcpy(o[p..][0..cid_len], &c.scid);
        p += cid_len;
        c.local_tp_len = p;
    }

    fn installInitialKeys(c: *Connection, dcid: []const u8) void {
        const k = qc.initialKeys(dcid);
        c.spaces[0].send = k.client;
        c.spaces[0].recv = k.server;
    }

    fn drainTls(c: *Connection) Error!void {
        if (c.srv) |st| return c.drainTlsServer(st);
        inline for ([_]tls.Level{ .initial, .handshake, .app }, 0..) |lv, i| {
            const out = c.tls.takeOutput(lv);
            if (out.len > 0) {
                try c.spaces[i].crypto_out.appendSlice(c.gpa, out);
                c.tls.clearOutput(lv);
            }
        }
        // Install keys the handshake produced.
        if (c.tls.c_hs != null and c.spaces[1].send == null) {
            c.spaces[1].send = qc.PacketKeys.fromSecret(c.tls.c_hs.?);
            c.spaces[1].recv = qc.PacketKeys.fromSecret(c.tls.s_hs.?);
        }
        if (c.tls.complete and c.spaces[2].send == null) {
            c.spaces[2].send = qc.PacketKeys.fromSecret(c.tls.c_ap.?);
            c.spaces[2].recv = qc.PacketKeys.fromSecret(c.tls.s_ap.?);
            try c.checkPeerParams();
            c.state = .established;
        }
    }

    fn drainTlsServer(c: *Connection, st: *tls_srv.Server) Error!void {
        inline for ([_]tls.Level{ .initial, .handshake, .app }, 0..) |lv, i| {
            const out = st.takeOutput(lv);
            if (out.len > 0) {
                try c.spaces[i].crypto_out.appendSlice(c.gpa, out);
                st.clearOutput(lv);
            }
        }
        if (st.s_hs != null and c.spaces[1].send == null and !c.spaces[1].discarded) {
            c.spaces[1].send = qc.PacketKeys.fromSecret(st.s_hs.?);
            c.spaces[1].recv = qc.PacketKeys.fromSecret(st.c_hs.?);
        }
        if (c.cfg.early_send and !st.complete and st.s_ap != null and c.spaces[2].send == null) {
            // the flight through Finished is written: the server may send 1-RTT data now
            c.spaces[2].send = qc.PacketKeys.fromSecret(st.s_ap.?);
            try c.checkPeerParams();
        }
        if (st.complete and c.spaces[2].recv == null) {
            if (c.spaces[2].send == null) {
                c.spaces[2].send = qc.PacketKeys.fromSecret(st.s_ap.?);
                try c.checkPeerParams();
            }
            c.spaces[2].recv = qc.PacketKeys.fromSecret(st.c_ap.?);
            c.state = .established;
            // The server's handshake is confirmed once complete (RFC 9001 section 4.1.2): tell the
            // client with HANDSHAKE_DONE and drop the Handshake keys.
            c.handshake_confirmed = true;
            c.need_handshake_done = true;
            c.discardSpace(.handshake);
        }
    }

    // ------------------------------------------------------------ transport parameters

    fn checkPeerParams(c: *Connection) Error!void {
        const tp = if (c.srv) |st| st.peerTransportParams() else c.tls.peerTransportParams();
        var p: usize = 0;
        var got_odcid = false;
        var got_iscid = false;
        var got_retry = false;
        while (p < tp.len) {
            const id = getVarint(tp, &p) orelse return c.fail(0x8, "bad transport parameters");
            const len = getVarint(tp, &p) orelse return c.fail(0x8, "bad transport parameters");
            if (len > tp.len - p) return c.fail(0x8, "bad transport parameters");
            const v = tp[p..][0..@intCast(len)];
            p += @intCast(len);
            var q: usize = 0;
            const num = if (id <= 0x0b and id != 0 and id != 2) (getVarint(v, &q) orelse return c.fail(0x8, "bad transport parameter")) else 0;
            switch (id) {
                0x00 => {
                    if (c.srv != null) return c.fail(0x8, "client sent original_destination_connection_id");
                    got_odcid = std.mem.eql(u8, v, &c.odcid);
                },
                0x01 => c.peer.idle_timeout_ms = num,
                0x03 => {
                    if (num < 1200) return c.fail(0x8, "max_udp_payload_size");
                    c.peer.max_udp_payload = num;
                },
                0x04 => c.peer.max_data = num,
                0x05 => c.peer.max_stream_data_bidi_local = num,
                0x06 => c.peer.max_stream_data_bidi_remote = num,
                0x07 => c.peer.max_stream_data_uni = num,
                0x08 => c.peer.max_streams_bidi = num,
                0x09 => c.peer.max_streams_uni = num,
                0x0a => {
                    if (num > 20) return c.fail(0x8, "ack_delay_exponent");
                    c.peer.ack_delay_exponent = @intCast(num);
                },
                0x0b => {
                    if (num >= 1 << 14) return c.fail(0x8, "max_ack_delay");
                    c.peer.max_ack_delay_ms = num;
                },
                0x0f => {
                    got_iscid = c.dcid_len == v.len and std.mem.eql(u8, v, c.dcid[0..c.dcid_len]);
                },
                0x10 => {
                    if (c.srv != null) return c.fail(0x8, "client sent retry_source_connection_id");
                    got_retry = c.retry_scid != null and v.len == c.retry_scid_len and std.mem.eql(u8, v, c.retry_scid.?[0..v.len]);
                },
                else => {},
            }
        }
        if (c.srv != null) got_odcid = true;
        if (!got_odcid or !got_iscid) return c.fail(0x8, "connection id transport parameters mismatch");
        if (c.retry_scid != null and !got_retry) return c.fail(0x8, "retry_source_connection_id mismatch");
        c.send_max_data = c.peer.max_data;
        if (c.peer.idle_timeout_ms != 0) {
            const peer_ns = c.peer.idle_timeout_ms *| ms;
            if (c.idle_ns == 0 or peer_ns < c.idle_ns) c.idle_ns = peer_ns;
        }
        c.peer_tp_checked = true;
    }

    fn fail(c: *Connection, code: u64, reason: []const u8) Error {
        tr("FAIL code=0x{x} {s}", .{ code, reason });
        c.startClose(code, false, reason);
        return error.ConnectionClosed;
    }

    fn startClose(c: *Connection, code: u64, app: bool, reason: []const u8) void {
        if (c.state == .closing or c.state == .draining or c.state == .closed) return;
        const n = @min(reason.len, c.close_reason_buf.len);
        @memcpy(c.close_reason_buf[0..n], reason[0..n]);
        c.close = .{ .code = code, .app = app, .remote = false, .reason = c.close_reason_buf[0..n] };
        c.state = .closing;
        c.close_pending = true;
    }

    /// Application close: sends CONNECTION_CLOSE (application error) once.
    pub fn closeApp(c: *Connection, code: u64) void {
        c.startClose(code, true, "");
    }

    pub fn isEstablished(c: *const Connection) bool {
        return c.state == .established;
    }
    /// A server with `cfg.early_send` between writing its Finished and reading the client's:
    /// streams of ours can be opened and written, nothing can be read yet.
    pub fn canSendEarly(c: *const Connection) bool {
        return c.srv != null and c.state == .handshaking and c.spaces[2].send != null;
    }
    pub fn isClosed(c: *const Connection) bool {
        return c.state == .closed or c.state == .draining or (c.state == .closing and c.close_sent);
    }
    pub fn peerId(c: *const Connection) ?[32]u8 {
        if (c.srv) |st| return st.peer_id;
        return c.tls.peer_id;
    }

    // ------------------------------------------------------------ receive

    /// Processes one UDP datagram (decrypted in place). Never fails: bad packets are dropped; a
    /// protocol violation closes the connection (see `close`).
    pub fn handleDatagram(c: *Connection, now: u64, dgram: []u8) void {
        if (c.state == .closed or c.state == .draining) return;
        tr("rx datagram {d} bytes", .{dgram.len});
        var pos: usize = 0;
        var any = false;
        while (pos < dgram.len) {
            const n = c.handlePacket(now, dgram[pos..]) catch |e| switch (e) {
                error.Drop => {
                    tr("  packet dropped", .{});
                    break;
                },
                else => return,
            };
            any = true;
            pos += n;
        }
        if (any) c.last_recv = now;
        if (!c.addr_validated) c.amp_recv += dgram.len;
        c.updateTimer(now);
    }

    const PktError = error{Drop} || Error;

    fn expandPn(largest: ?u64, truncated: u64, nbits: u6) u64 {
        const expected: u64 = if (largest) |l| l + 1 else 0;
        const win: u64 = @as(u64, 1) << nbits;
        const hwin = win / 2;
        const mask = win - 1;
        const candidate = (expected & ~mask) | truncated;
        if (candidate + hwin <= expected and candidate < (@as(u64, 1) << 62) - win) return candidate + win;
        if (candidate > expected + hwin and candidate >= win) return candidate - win;
        return candidate;
    }

    /// Handles the first packet of `d`; returns bytes consumed (the whole datagram for short headers).
    fn handlePacket(c: *Connection, now: u64, d: []u8) PktError!usize {
        if (d.len < 1) return error.Drop;
        const b0 = d[0];
        var space: Space = .app;
        var pn_off: usize = undefined;
        var pkt_len: usize = d.len;
        if (b0 & 0x80 != 0) {
            // long header
            if (d.len < 7) return error.Drop;
            const version = std.mem.readInt(u32, d[1..5], .big);
            var p: usize = 5;
            const dl = d[p];
            p += 1;
            if (dl > 20 or d.len < p + dl + 1) return error.Drop;
            const dcid = d[p..][0..dl];
            p += dl;
            const sl = d[p];
            p += 1;
            if (sl > 20 or d.len < p + sl) return error.Drop;
            const scid = d[p..][0..sl];
            p += sl;
            if (version == 0) {
                return c.fail(0x0a, "version negotiation: peer does not speak QUIC v1");
            }
            if (version != 1) return error.Drop;
            if (!std.mem.eql(u8, dcid, &c.scid) and !(c.srv_odcid_len != 0 and std.mem.eql(u8, dcid, c.srv_odcid[0..c.srv_odcid_len])) and
                !(c.srv_retry_scid_len != 0 and std.mem.eql(u8, dcid, c.srv_retry_scid[0..c.srv_retry_scid_len]))) return error.Drop;
            const ty = (b0 >> 4) & 3;
            if (ty == 3) {
                try c.handleRetry(d, p, scid);
                return d.len;
            }
            if (ty == 1) return error.Drop; // 0-RTT never accepted by a client
            space = if (ty == 0) .initial else .handshake;
            if (ty == 0) {
                const tl = getVarint(d, &p) orelse return error.Drop;
                if (tl > d.len - p) return error.Drop;
                p += @intCast(tl); // server Initial carries no token
            }
            const len = getVarint(d, &p) orelse return error.Drop;
            if (len > d.len - p) return error.Drop;
            pn_off = p;
            pkt_len = p + @as(usize, @intCast(len));
            const sp = &c.spaces[@intFromEnum(space)];
            const keys = sp.recv orelse return error.Drop;
            _ = try c.decryptAndProcess(now, d[0..pkt_len], pn_off, space, keys);
            return pkt_len;
        }
        // short header
        if (d.len < 1 + cid_len + 4 + 16) return error.Drop;
        if (!std.mem.eql(u8, d[1..][0..cid_len], &c.scid)) return error.Drop;
        pn_off = 1 + cid_len;
        const sp = &c.spaces[2];
        const keys = sp.recv orelse return error.Drop;
        _ = try c.decryptAndProcess(now, d, pn_off, .app, keys);
        return d.len;
    }

    fn decryptAndProcess(c: *Connection, now: u64, pkt: []u8, pn_off: usize, space: Space, keys: qc.PacketKeys) PktError!usize {
        if (pkt.len < pn_off + 4 + 16) return error.Drop;
        const sp = &c.spaces[@intFromEnum(space)];
        const mask = qc.hpMaskK(&keys, pkt[pn_off + 4 ..][0..16]);
        var first = pkt[0];
        const was_long = first & 0x80 != 0;
        qc.maskFirstByte(&first, mask);
        pkt[0] = first;
        const pn_len: usize = (first & 3) + 1;
        qc.maskPn(pkt, pn_off, pn_len, mask);
        if (!was_long and first & 0x40 == 0) return error.Drop; // fixed bit
        if (was_long and first & 0x0c != 0) return error.Drop; // reserved bits (checked after auth in spec; drop is fine)
        if (!was_long and first & 0x18 != 0) return error.Drop;
        var trunc: u64 = 0;
        for (pkt[pn_off..][0..pn_len]) |b| trunc = (trunc << 8) | b;
        const pn = expandPn(sp.recv_set.largest(), trunc, @intCast(pn_len * 8));
        var use_keys = keys;
        var rotated = false;
        if (space == .app) {
            const phase = first & 0x04 != 0;
            if (phase != c.recv_phase) {
                if (c.app_recv_next == null) c.app_recv_next = keys.nextGeneration();
                use_keys = c.app_recv_next.?;
                rotated = true;
            }
        }
        const hdr_len = pn_off + pn_len;
        const plain_len = qc.open(&use_keys, pn, pkt, hdr_len) catch {
            tr("  decrypt failed space={s} pn={d}", .{ @tagName(space), pn });
            if (space == .app) {
                // AES-128-GCM integrity limit (RFC 9001 section 6.6): 2^52 forgeries
                c.auth_failures += 1;
                if (c.auth_failures >= 1 << 52) return c.fail(0x0f, "AEAD integrity limit");
            }
            return error.Drop;
        };
        tr("  rx {s} pn={d} len={d}", .{ @tagName(space), pn, plain_len });
        if (rotated) {
            c.spaces[2].recv = use_keys;
            c.app_recv_next = null;
            c.recv_phase = !c.recv_phase;
            if (c.send_phase != c.recv_phase) {
                // the peer updated: follow it
                c.spaces[2].send = c.spaces[2].send.?.nextGeneration();
                c.send_phase = c.recv_phase;
                c.newSendPhase();
            }
        }
        if (sp.recv_set.contains(pn)) return error.Drop; // duplicate
        // Packet authenticated. The first server Initial fixes our destination connection id.
        if (space == .initial and !c.got_server_packet) {
            var p: usize = 5;
            p += 1 + pkt[5]; // skip dcid
            const sl = pkt[p];
            p += 1;
            c.dcid_len = sl;
            @memcpy(c.dcid[0..sl], pkt[p..][0..sl]);
            c.got_server_packet = true;
        }
        const payload = pkt[hdr_len..][0..plain_len];
        const eliciting = try c.processFrames(now, space, payload);
        const prev_largest = sp.recv_set.largest();
        sp.recv_set.insert(pn);
        sp.largest_recv_time = now;
        // A packet that is not the next in sequence (reordering, or a gap such as quinn's
        // deliberately skipped packet numbers) is acked without delay, once.
        const out_of_order = if (prev_largest) |l| pn != l + 1 else pn != 0;
        if (eliciting) {
            sp.ack_needed = true;
            sp.unacked_eliciting += 1;
            // Handshake spaces ack at once; 1-RTT acks every second packet, on reordering, or
            // after `ack_delay` (RFC 9000 section 13.2.1), so request/response traffic piggybacks.
            if (space != .app or sp.unacked_eliciting >= 2 or out_of_order or c.state != .established) {
                sp.ack_now = true;
            } else if (sp.ack_deadline == null) sp.ack_deadline = now + ack_delay_ns;
        }
        if (space == .handshake and c.spaces[0].recv != null) c.discardSpace(.initial); // client: server's first Handshake proves key possession; server: the client's (RFC 9001 4.9.1)
        if (space == .handshake) c.addr_validated = true;
        return pkt.len;
    }

    fn handleRetry(c: *Connection, d: []u8, p: usize, scid: []const u8) PktError!void {
        if (c.got_server_packet or c.retry_scid != null) return error.Drop;
        if (d.len < p + 16) return error.Drop;
        const body = d[0 .. d.len - 16];
        if (body.len > qc.max_retry_len) return error.Drop;
        if (body.len == p) return error.Drop; // a Retry without a token is discarded (RFC 9000 17.2.5.2)
        const want = qc.retryTag(&c.odcid, body);
        if (!std.crypto.timing_safe.eql([16]u8, want, d[d.len - 16 ..][0..16].*)) return error.Drop;
        const token = d[p .. d.len - 16];
        c.retry_token.clearRetainingCapacity();
        c.retry_token.appendSlice(c.gpa, token) catch return error.OutOfMemory;
        c.dcid_len = @intCast(scid.len);
        @memcpy(c.dcid[0..scid.len], scid);
        c.retry_scid = c.dcid;
        c.retry_scid_len = @intCast(scid.len);
        c.installInitialKeys(scid);
        // resend the ClientHello from offset 0 in a fresh Initial packet
        const sp = &c.spaces[0];
        for (sp.live()) |s| if (s.in_flight) {
            c.bytes_in_flight -|= s.size;
        };
        sp.clearSent();
        sp.ack_eliciting_in_flight = 0;
        sp.crypto_sent = 0;
        sp.crypto_retx.clearRetainingCapacity();
        sp.probe = 0;
    }

    // ------------------------------------------------------------ frames in

    /// Returns true if the packet is ack-eliciting.
    fn processFrames(c: *Connection, now: u64, space: Space, pl: []const u8) PktError!bool {
        var p: usize = 0;
        var eliciting = false;
        while (p < pl.len) {
            const ty = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
            if (ty != 0) tr("    frame 0x{x}", .{ty});
            // Initial and Handshake packets carry only PADDING, PING, ACK, CRYPTO and
            // CONNECTION_CLOSE (transport) (RFC 9000 section 12.4, table 3).
            if (space != .app) switch (ty) {
                0x00, 0x01, 0x02, 0x03, 0x06, 0x1c => {},
                else => return c.fail(0x0a, "frame not permitted in this packet type"),
            };
            switch (ty) {
                0x00 => {}, // PADDING
                0x01 => eliciting = true, // PING
                0x02, 0x03 => try c.onAck(now, space, pl, &p, ty == 0x03),
                0x04 => { // RESET_STREAM
                    const id = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const code = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const final = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                    if (!c.peerInitiated(id) and (id & 2) != 0) return c.fail(0x05, "RESET_STREAM on our send-only stream");
                    if (c.streamFor(id, true)) |s| try c.onResetStream(s, code, final);
                },
                0x05 => { // STOP_SENDING
                    const id = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const code = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                    if (c.peerInitiated(id) and (id & 2) != 0) return c.fail(0x05, "STOP_SENDING on a receive-only stream");
                    if (c.streams.get(id)) |s| try c.onStopSending(s, code);
                },
                0x06 => { // CRYPTO
                    const off = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const len = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (len > pl.len - p) return c.fail(0x07, "frame encoding");
                    eliciting = true;
                    try c.onCrypto(space, off, pl[p..][0..@intCast(len)]);
                    p += @intCast(len);
                },
                0x07 => { // NEW_TOKEN
                    const len = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (len > pl.len - p) return c.fail(0x07, "frame encoding");
                    p += @intCast(len);
                    eliciting = true;
                },
                0x08...0x0f => {
                    eliciting = true;
                    try c.onStream(pl, &p, ty);
                },
                0x10 => {
                    const v = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    c.send_max_data = @max(c.send_max_data, v);
                    eliciting = true;
                },
                0x11 => {
                    const id = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const v = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (c.streams.get(id)) |s| s.peer_max = @max(s.peer_max, v);
                    eliciting = true;
                },
                0x12, 0x13 => {
                    const v = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (ty == 0x12) c.peer.max_streams_bidi = @max(c.peer.max_streams_bidi, v) else c.peer.max_streams_uni = @max(c.peer.max_streams_uni, v);
                    eliciting = true;
                },
                0x14 => {
                    _ = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                },
                0x15 => {
                    _ = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    _ = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                },
                0x16, 0x17 => {
                    _ = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                },
                0x18 => { // NEW_CONNECTION_ID
                    const seq = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const retire_prior = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (p >= pl.len) return c.fail(0x07, "frame encoding");
                    const l = pl[p];
                    p += 1;
                    if (l < 1 or l > 20 or pl.len - p < l + 16) return c.fail(0x07, "frame encoding");
                    var e: PeerCid = .{ .seq = seq, .len = l, .cid = undefined, .token = undefined };
                    @memcpy(e.cid[0..l], pl[p..][0..l]);
                    p += l;
                    @memcpy(&e.token, pl[p..][0..16]);
                    p += 16;
                    eliciting = true;
                    if (retire_prior > seq) return c.fail(0x07, "retire_prior_to above sequence number");
                    try c.onNewCid(e, retire_prior);
                },
                0x19 => { // RETIRE_CONNECTION_ID (we issue only our initial cid)
                    _ = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                },
                0x1a => { // PATH_CHALLENGE
                    if (pl.len - p < 8) return c.fail(0x07, "frame encoding");
                    c.path_responses.append(c.gpa, pl[p..][0..8].*) catch return error.OutOfMemory;
                    p += 8;
                    eliciting = true;
                },
                0x1b => {
                    if (pl.len - p < 8) return c.fail(0x07, "frame encoding");
                    p += 8;
                    eliciting = true;
                },
                0x1c, 0x1d => {
                    const code = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (ty == 0x1c) _ = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const rl = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    if (rl > pl.len - p) return c.fail(0x07, "frame encoding");
                    const n: usize = @min(@as(usize, @intCast(rl)), c.close_reason_buf.len);
                    @memcpy(c.close_reason_buf[0..n], pl[p..][0..n]);
                    p += @intCast(rl);
                    if (c.state != .closing and c.state != .draining and c.state != .closed) {
                        c.close = .{ .code = code, .app = ty == 0x1d, .remote = true, .reason = c.close_reason_buf[0..n] };
                    }
                    c.state = .draining;
                    return false;
                },
                0x1e => { // HANDSHAKE_DONE
                    if (space != .app) return c.fail(0x0a, "HANDSHAKE_DONE outside 1-RTT");
                    if (c.srv != null) return c.fail(0x0a, "HANDSHAKE_DONE from a client");
                    eliciting = true;
                    c.handshake_confirmed = true;
                    c.discardSpace(.handshake);
                },
                0x30, 0x31 => { // DATAGRAM (RFC 9221): accepted when we advertised it, then dropped
                    if (c.cfg.max_datagram_frame_size == 0 or space != .app) return c.fail(0x0a, "unexpected DATAGRAM");
                    if (ty == 0x31) {
                        const dl = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                        if (dl > pl.len - p) return c.fail(0x07, "frame encoding");
                        p += @intCast(dl);
                    } else p = pl.len;
                    eliciting = true;
                },
                else => return c.fail(0x07, "unknown frame type"),
            }
        }
        return eliciting;
    }

    /// Stores a NEW_CONNECTION_ID, retires every stored id below `retire_prior`, and bounds the
    /// set (we advertise active_connection_id_limit 4; a peer past it is in error).
    fn onNewCid(c: *Connection, e: PeerCid, retire_prior: u64) Error!void {
        for (c.peer_cids.items) |k| if (k.seq == e.seq) return; // retransmission
        if (e.seq < retire_prior) {
            // already retired by the peer's own frame: retire it at once
            try c.pending_retire.append(c.gpa, e.seq);
        } else try c.peer_cids.append(c.gpa, e);
        try c.onRetirePrior(retire_prior);
        var i: usize = 0;
        while (i < c.peer_cids.items.len) {
            const k = c.peer_cids.items[i];
            if (k.seq < retire_prior and k.seq != c.dcid_seq) {
                try c.pending_retire.append(c.gpa, k.seq);
                _ = c.peer_cids.swapRemove(i);
            } else i += 1;
        }
        if (c.peer_cids.items.len > max_peer_cids) {
            for (c.peer_cids.items, 0..) |k, j| if (k.seq == e.seq and k.seq != c.dcid_seq) {
                _ = c.peer_cids.swapRemove(j);
                break;
            };
            return c.fail(0x09, "connection id limit");
        }
    }

    fn onRetirePrior(c: *Connection, retire_prior: u64) Error!void {
        if (c.dcid_seq >= retire_prior) return;
        // pick a replacement with seq >= retire_prior
        for (c.peer_cids.items) |e| {
            if (e.seq >= retire_prior) {
                try c.pending_retire.append(c.gpa, c.dcid_seq);
                c.dcid_seq = e.seq;
                c.dcid_len = e.len;
                @memcpy(c.dcid[0..e.len], e.cid[0..e.len]);
                return;
            }
        }
    }

    fn onCrypto(c: *Connection, space: Space, off: u64, data: []const u8) Error!void {
        const sp = &c.spaces[@intFromEnum(space)];
        if (off + data.len > sp.crypto_in.base + max_crypto_buffer) return c.fail(0x0d, "crypto buffer exceeded");
        sp.crypto_in.insert(c.gpa, off, data) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Fragmented => return c.fail(0x0d, "crypto buffer exceeded"),
        };
        const ready = sp.crypto_in.contiguous();
        if (ready.len > 0) {
            const lv: tls.Level = @enumFromInt(@intFromEnum(space));
            (if (c.srv) |st| st.feed(c.gpa, lv, ready) else c.tls.feed(c.gpa, lv, ready)) catch |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                return c.fail(0x100 + 0x28, @errorName(e)); // CRYPTO_ERROR | handshake_failure
            };
            sp.crypto_in.consume(ready.len);
            try c.drainTls();
        }
    }

    /// True for a stream that existed and has been freed: late frames for it (a retransmission,
    /// a FIN that trails the data the application already consumed) are ignored.
    fn streamClosed(c: *const Connection, id: u64) bool {
        if (c.streams.contains(id)) return false;
        const index = id >> 2;
        if (c.peerInitiated(id)) return index < (if ((id & 2) != 0) c.streams_uni_seen else c.streams_bidi_seen);
        if ((id & 2) != 0) return id < c.next_uni; // unidirectional streams we opened
        return id < c.next_bidi; // bidirectional streams we opened
    }

    fn streamFor(c: *Connection, id: u64, create_remote: bool) ?*Stream {
        if (c.streams.get(id)) |s| return s;
        if (!create_remote) return null;
        if (!c.peerInitiated(id)) return null; // data for a stream of ours we never opened
        const uni = (id & 2) != 0;
        const index = id >> 2;
        const seen = if (uni) &c.streams_uni_seen else &c.streams_bidi_seen;
        if (index < seen.*) return null; // opened before and freed since
        if (index >= (if (uni) c.streams_uni_limit else c.streams_bidi_limit)) return null;
        // Opening stream n opens every lower stream of the same type (RFC 9000 section 3.2).
        while (seen.* <= index) {
            const sid = (seen.* << 2) | (id & 3);
            const s = c.newStream(sid) catch return null;
            s.recv_limit = c.cfg.max_stream_data;
            if (!uni) s.peer_max = c.peer.max_stream_data_bidi_local;
            c.streams.put(c.gpa, sid, s) catch {
                c.recycle(s);
                return null;
            };
            seen.* += 1;
            (if (uni) &c.incoming_uni else &c.incoming_bidi).append(c.gpa, sid) catch return null;
        }
        return c.streams.get(id);
    }

    fn onStream(c: *Connection, pl: []const u8, p: *usize, ty: u64) PktError!void {
        const id = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
        const has_off = ty & 4 != 0;
        const has_len = ty & 2 != 0;
        const fin = ty & 1 != 0;
        const off = if (has_off) (getVarint(pl, p) orelse return c.fail(0x07, "frame encoding")) else 0;
        const len: usize = if (has_len) blk: {
            const l = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
            if (l > pl.len - p.*) return c.fail(0x07, "frame encoding");
            break :blk @intCast(l);
        } else pl.len - p.*;
        const data = pl[p.*..][0..len];
        p.* += len;
        tr("    stream id={d} off={d} len={d} fin={}", .{ id, off, len, fin });
        const s = c.streamFor(id, true) orelse {
            if (c.streamClosed(id)) return;
            if (!c.peerInitiated(id)) return c.fail(0x05, "stream we never opened"); // STREAM_STATE_ERROR
            if ((id & 2) != 0 and (id & 1) == @intFromBool(c.srv != null)) return c.fail(0x05, "data on our send-only stream");
            return c.fail(0x04, "stream limit"); // STREAM_LIMIT_ERROR
        };
        if (!c.peerInitiated(id) and (id & 2) != 0) return c.fail(0x05, "data on our send-only stream");
        const end = off + len;
        // The window moves only as the application consumes (`creditScan`), so this bounds what
        // one stream can make us hold.
        if (end > s.recv_limit) return c.fail(0x03, "stream flow control");
        if (s.recv.fin_at) |f| if (end > f or (fin and end != f)) return c.fail(0x06, "final size");
        if (fin and end < s.counted) return c.fail(0x06, "final size");
        if (end > s.counted) {
            c.recv_data += end - s.counted;
            s.counted = end;
            if (c.recv_data > c.recv_max_data) return c.fail(0x03, "connection flow control");
        }
        if (fin) s.recv.fin_at = end;
        if (s.detached or s.reset != null) {
            // nobody reads it: the bytes go straight back to the connection window
            c.creditDiscard(s);
            return;
        }
        const dups = s.recv.dups;
        s.recv.insert(c.gpa, off, data) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Fragmented => return c.fail(0x0a, "stream data too fragmented"),
        };
        c.dup_frames += s.recv.dups - dups;
        if (!s.watched) {
            c.recv_watch.append(c.gpa, s) catch return error.OutOfMemory;
            s.watched = true;
        }
        c.credit_due = true;
    }

    /// Everything counted on `s` so far is returned to the connection window (the application
    /// will not read it: the stream was freed or reset).
    fn creditDiscard(c: *Connection, s: *Stream) void {
        if (s.counted > s.credited) {
            c.recv_consumed += s.counted - s.credited;
            s.credited = s.counted;
        }
        c.credit_due = true;
    }

    fn onResetStream(c: *Connection, s: *Stream, code: u64, final: u64) PktError!void {
        if (s.reset != null) return;
        if (final > s.recv_limit) return c.fail(0x03, "stream flow control");
        if (final < s.counted) return c.fail(0x06, "final size");
        if (s.recv.fin_at) |f| if (final != f) return c.fail(0x06, "final size");
        c.recv_data += final - s.counted;
        s.counted = final;
        if (c.recv_data > c.recv_max_data) return c.fail(0x03, "connection flow control");
        s.reset = code;
        s.recv.fin_at = final;
        c.creditDiscard(s);
    }

    /// RFC 9000 section 3.5: a STOP_SENDING is answered with a RESET_STREAM (the peer's code),
    /// and nothing more of the stream is sent. The stream is then settled for the application.
    fn onStopSending(c: *Connection, s: *Stream, code: u64) PktError!void {
        if (s.stopped_by_peer == null) s.stopped_by_peer = code;
        if (s.send_reset or c.sendSettled(s)) return;
        c.resetSend(s, code) catch return error.OutOfMemory;
    }

    fn sendSettled(c: *const Connection, s: *const Stream) bool {
        _ = c;
        return s.send_reset or (s.fin_sent and s.retx.items.len == 0 and s.send_off == s.send_base + s.send_buf.items.len and s.inflight == 0);
    }

    /// Queues RESET_STREAM for our send side and drops what was waiting to be sent.
    fn resetSend(c: *Connection, s: *Stream, code: u64) Allocator.Error!void {
        try c.ctl.append(c.gpa, .{ .reset = .{ .id = s.id, .code = code, .final = s.send_off } });
        s.send_reset = true;
        s.retx.clearRetainingCapacity();
        s.send_buf.clearRetainingCapacity();
        s.send_base = s.send_off;
        s.fin_queued = true;
        s.fin_sent = true;
    }

    /// Returns consumed bytes to the stream and connection windows (MAX_STREAM_DATA once half a
    /// stream window was consumed, MAX_DATA once half the connection window was), and frees
    /// detached streams that are finished. Runs at the start of a transmit round.
    fn creditScan(c: *Connection) void {
        c.credit_due = false;
        var i: usize = 0;
        while (i < c.recv_watch.items.len) {
            const s = c.recv_watch.items[i];
            if (s.recv.base > s.credited) {
                c.recv_consumed += s.recv.base - s.credited;
                s.credited = s.recv.base;
            }
            const finished = s.reset != null or s.recv.fin_at != null;
            if (!finished and s.recv_limit - s.recv.base < c.cfg.max_stream_data / 2) {
                s.recv_limit = s.recv.base + c.cfg.max_stream_data;
                c.pending_msd.append(c.gpa, s.id) catch return c.internalError();
            }
            if (s.reset != null or (s.recv.fin_at != null and s.recv.base >= s.recv.fin_at.?)) {
                s.watched = false;
                _ = c.recv_watch.swapRemove(i);
                continue;
            }
            i += 1;
        }
        if (c.recv_max_data - c.recv_consumed < c.cfg.max_data / 2) {
            c.recv_max_data = c.recv_consumed + c.cfg.max_data;
            c.need_max_data = true;
        }
        c.reapDetached();
    }

    /// An allocation failure where carrying on would leave a hole (a packet sent but not
    /// recorded, a retransmission or window update dropped): close the connection instead.
    /// Out of memory where state would otherwise be lost silently (a retransmission, a sent
    /// packet's record, a control frame): close the connection (INTERNAL_ERROR) rather than let
    /// data be lost unseen and the peer wait for it.
    fn internalError(c: *Connection) void {
        c.startClose(0x01, false, "out of memory");
    }

    // ------------------------------------------------------------ ACK processing and recovery

    fn onAck(c: *Connection, now: u64, space: Space, pl: []const u8, p: *usize, ecn: bool) PktError!void {
        const largest = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
        const delay_raw = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
        const range_count = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
        const first_range = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
        const sp = &c.spaces[@intFromEnum(space)];
        if (largest >= sp.next_pn) return c.fail(0x0a, "ACK for unsent packet");
        if (first_range > largest) return c.fail(0x07, "frame encoding");
        var hi = largest;
        var lo = largest - first_range;
        var newly_largest_eliciting_time: ?u64 = null;
        var newly_acked_any = false;
        var acked_bytes: u64 = 0;
        var newest_sent: u64 = 0;
        var big_acked = false;
        // Ranges arrive in descending order; keep the first `max_ranges` (later ones are acked
        // again by the peer's next ACK) and validate them all.
        const max_ranges = 64;
        var ranges: [max_ranges][2]u64 = undefined;
        var nr: usize = 0;
        var i: u64 = 0;
        while (true) {
            if (nr < max_ranges) {
                ranges[nr] = .{ lo, hi };
                nr += 1;
            }
            if (i == range_count) break;
            const gap = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
            const rl = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
            if (gap + 2 > lo) return c.fail(0x07, "frame encoding");
            hi = lo - gap - 2;
            if (rl > hi) return c.fail(0x07, "frame encoding");
            lo = hi - rl;
            i += 1;
        }
        {
            // Walk the in-flight packets with pn <= largest from the top down, keeping the
            // unacked ones packed against the top; the acked ones leave from the front.
            const live = sp.live();
            const ub = sp.upper(largest);
            var w: usize = ub;
            var ri: usize = 0;
            var k: usize = ub;
            while (k > 0) {
                k -= 1;
                const s = live[k];
                while (ri < nr and s.pn < ranges[ri][0]) ri += 1;
                const acked = ri < nr and s.pn <= ranges[ri][1];
                if (!acked) {
                    w -= 1;
                    live[w] = s;
                    continue;
                }
                newly_acked_any = true;
                newest_sent = @max(newest_sent, s.time);
                if (s.size > max_datagram) big_acked = true;
                for (s.recs[0..s.nrec]) |r| switch (r) {
                    .pmtu => |m| {
                        if (c.cfg.iw_mtu and m > c.mtu and c.ssthresh == std.math.maxInt(u64))
                            c.cwnd += initialWindow(m) - initialWindow(c.mtu);
                        c.mtu = @max(c.mtu, m);
                        c.pmtu_inflight = false;
                        if (m == c.pmtu_probe) c.pmtu_probe = 0; // passed: the search moves up
                    },
                    .stream => |sr| if (c.streams.get(sr.id)) |st| {
                        st.inflight -|= 1;
                        if (st.detached) c.credit_due = true;
                    },
                    else => {},
                };
                if (s.pn == largest and s.ack_eliciting) newly_largest_eliciting_time = s.time;
                if (s.in_flight) {
                    c.bytes_in_flight -|= s.size;
                    acked_bytes += s.size;
                }
                if (s.ack_eliciting and s.in_flight) sp.ack_eliciting_in_flight -|= 1;
            }
            sp.dropFront(w);
        }
        if (ecn) {
            _ = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
            _ = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
            _ = getVarint(pl, p) orelse return c.fail(0x07, "frame encoding");
        }
        if (sp.largest_acked == null or largest > sp.largest_acked.?) sp.largest_acked = largest;
        if (space == .app and newly_acked_any and largest >= c.phase_first_pn) c.phase_acked = true;
        if (newly_largest_eliciting_time) |t| {
            c.latest_rtt = now -| t;
            var ack_delay: u64 = 0;
            if (space == .app) {
                const e = c.peer.ack_delay_exponent;
                const scaled = if (delay_raw > @as(u64, std.math.maxInt(u64)) >> e) std.math.maxInt(u64) else delay_raw << e;
                ack_delay = scaled *| us;
                if (c.handshake_confirmed) ack_delay = @min(ack_delay, c.peer.max_ack_delay_ms * ms);
            }
            c.updateRtt(ack_delay);
        }
        if (newly_acked_any) {
            c.pto_count = 0;
            c.onAckedBytes(now, acked_bytes, .{ .space = space, .largest = largest, .rtt = if (newly_largest_eliciting_time != null) c.latest_rtt else null, .newest_sent = newest_sent });
        }
        c.detectLoss(now, space);
        if (c.cfg.pmtud and space == .app) c.blackHoleCheck(now, big_acked);
        c.updateTimer(now);
    }

    fn updateRtt(c: *Connection, ack_delay: u64) void {
        c.min_rtt = @min(c.min_rtt, c.latest_rtt);
        if (!c.rtt_initialized) {
            c.srtt = c.latest_rtt;
            c.rttvar = c.latest_rtt / 2;
            c.rtt_initialized = true;
            return;
        }
        var adjusted = c.latest_rtt;
        if (adjusted >= c.min_rtt +| ack_delay) adjusted -= ack_delay;
        const diff = if (c.srtt > adjusted) c.srtt - adjusted else adjusted - c.srtt;
        c.rttvar = (3 * c.rttvar + diff) / 4;
        c.srtt = (7 * c.srtt + adjusted) / 8;
    }

    fn onAckedBytes(c: *Connection, now: u64, bytes: u64, a: AckInfo) void {
        if (c.cfg.cubic) {
            // in recovery until a packet sent after the reduction is acknowledged
            if (c.cubic.inRecovery(a.newest_sent)) return;
        } else if (c.recovery_start != null) return; // simplified: no growth while in recovery
        if (c.cwnd < c.ssthresh) {
            // HyStart++ runs in the first slow start only (RFC 9406 section 4.3), on the
            // application space's packet numbers.
            if ((c.cfg.hystart or c.cfg.cubic) and c.ssthresh == std.math.maxInt(u64) and a.space == .app) {
                const step = c.hystart.onAck(a.largest, c.spaces[2].next_pn, a.rtt);
                // an unpaced sender adds at most 8 datagrams per ACK (section 4.3, L)
                const n = if (c.cfg.pacing) bytes else @min(bytes, cong.HyStart.l_unpaced * c.mtu);
                c.cwnd += n / step.divisor;
                if (step.exit) c.ssthresh = c.cwnd;
                return;
            }
            c.cwnd += bytes;
        } else if (c.cfg.cubic) {
            c.cubic.onAck(now, bytes, &c.cwnd, c.mtu, c.srtt, c.cwnd_limited);
        } else {
            c.cwnd += c.mtu * bytes / c.cwnd;
        }
    }

    fn onLostPacket(c: *Connection, now: u64, s: Sent, space: Space) void {
        c.pkts_lost += 1;
        if (s.in_flight) c.bytes_in_flight -|= s.size;
        // requeue payload
        for (s.recs[0..s.nrec]) |r| switch (r) {
            .crypto => |cr| c.spaces[@intFromEnum(space)].crypto_retx.append(c.gpa, .{ .start = cr.off, .end = cr.off + cr.len }) catch c.internalError(),
            .stream => |sr| if (c.streams.get(sr.id)) |st| {
                st.inflight -|= 1;
                if (!st.send_reset) {
                    st.retx.append(c.gpa, .{ .start = sr.off, .end = sr.off + sr.len }) catch c.internalError();
                    if (sr.fin) st.fin_sent = false;
                }
            },
            .reset_stream => |rs| c.ctl.append(c.gpa, .{ .reset = rs }) catch c.internalError(),
            .stop_sending => |ss| if (c.streams.get(ss.id)) |st| {
                // only while the peer may still send
                if (st.reset == null and !(st.recv.fin_at != null and st.counted >= st.recv.fin_at.?))
                    c.ctl.append(c.gpa, .{ .stop = ss }) catch c.internalError();
            },
            .max_data => c.need_max_data = true,
            .max_stream_data => |id| c.pending_msd.append(c.gpa, id) catch c.internalError(),
            .max_streams_uni => c.need_max_streams_uni = true,
            .max_streams_bidi => c.need_max_streams_bidi = true,
            .retire_cid => |seq| c.pending_retire.append(c.gpa, seq) catch c.internalError(),
            .handshake_done => c.need_handshake_done = true,
            .pmtu => |m| {
                c.pmtu_inflight = false;
                if (!c.cfg.pmtud) {
                    c.pmtu_tries += 1;
                } else if (m == c.pmtu_probe) {
                    c.pmtu_tries += 1;
                    if (c.pmtu_tries >= 3) {
                        // three probes of this size lost: it does not pass
                        c.pmtu_fail = m;
                        c.pmtu_probe = 0;
                        c.pmtu_tries = 0;
                    }
                }
                return; // a lost probe says nothing about congestion (RFC 9000 section 14.4)
            },
        };
        if (s.size > max_datagram) c.big_lost_pass = true;
        // congestion event
        if (c.cfg.cubic) {
            _ = c.cubic.onCongestion(now, s.time, &c.cwnd, &c.ssthresh, c.mtu);
        } else if (c.recovery_start == null or s.time > c.recovery_start.?) {
            c.recovery_start = now;
            c.cwnd = @max(c.cwnd / 2, 2 * c.mtu);
            c.ssthresh = c.cwnd;
        }
    }

    fn detectLoss(c: *Connection, now: u64, space: Space) void {
        const sp = &c.spaces[@intFromEnum(space)];
        sp.loss_time = null;
        c.big_lost_pass = false;
        const largest_acked = sp.largest_acked orelse return;
        const base = @max(c.latest_rtt, c.srtt);
        const loss_delay = @max(base + base / 8, 1 * ms);
        const lost_send_time = now -| loss_delay;
        // Only packets at or below the largest acked can be lost; they sit at the front.
        const ub = sp.upper(largest_acked);
        var lost_buf: [64]Sent = undefined;
        var nlost: usize = 0;
        {
            const live = sp.live();
            var w: usize = ub;
            var k: usize = ub;
            while (k > 0) {
                k -= 1;
                const s = live[k];
                if (nlost < lost_buf.len and (s.time <= lost_send_time or largest_acked >= s.pn + 3)) {
                    if (s.ack_eliciting and s.in_flight) sp.ack_eliciting_in_flight -|= 1;
                    lost_buf[nlost] = s;
                    nlost += 1;
                } else {
                    if (s.time > lost_send_time and largest_acked < s.pn + 3) {
                        const t = s.time + loss_delay;
                        sp.loss_time = if (sp.loss_time) |lt| @min(lt, t) else t;
                    } else if (sp.loss_time == null) sp.loss_time = now; // more lost than fit: next timer pass
                    w -= 1;
                    live[w] = s;
                }
            }
            sp.dropFront(w);
        }
        // Oldest first, as the per-packet removal did.
        var j = nlost;
        while (j > 0) {
            j -= 1;
            c.onLostPacket(now, lost_buf[j], space);
        }
        if (c.recovery_start) |rs| {
            // leave recovery once a packet sent after it is acked or lost-free; approximate by time
            if (now > rs + c.srtt * 2) c.recovery_start = null;
        }
    }

    /// After a loss pass of the application space (path MTU search on). A loss event that took
    /// full-size packets while this ACK brought none back is suspicious; three in a row with no
    /// full-size packet acknowledged in between mean the path stopped carrying them.
    fn blackHoleCheck(c: *Connection, now: u64, big_acked: bool) void {
        if (big_acked) {
            c.big_loss = 0;
            return;
        }
        if (!c.big_lost_pass or c.mtu <= max_datagram) return;
        c.big_loss += 1;
        if (c.big_loss >= 3) c.pmtuBlackHole(now);
    }

    /// The path no longer carries the validated size: back to 1200 (what is lost is resent in
    /// packets of that size, since retransmission works on stream ranges), search again later.
    fn pmtuBlackHole(c: *Connection, now: u64) void {
        tr("pmtu black hole: {d} -> {d}", .{ c.mtu, max_datagram });
        c.mtu = max_datagram;
        c.pmtu_black_holes += 1;
        c.big_loss = 0;
        c.pmtu_probe = 0;
        c.pmtu_fail = 0;
        c.pmtu_tries = 0;
        c.pmtu_search_at = now + pmtu_cooldown_ns;
    }

    fn ptoDuration(c: *const Connection, space: Space) u64 {
        var d = c.srtt + @max(4 * c.rttvar, 1 * ms);
        if (space == .app) d += c.peer.max_ack_delay_ms * ms;
        return d << @intCast(@min(c.pto_count, 16));
    }

    fn discardSpace(c: *Connection, space: Space) void {
        const sp = &c.spaces[@intFromEnum(space)];
        if (sp.discarded) return;
        sp.discarded = true;
        for (sp.live()) |s| if (s.in_flight) {
            c.bytes_in_flight -|= s.size;
        };
        sp.clearSent();
        sp.send = null;
        sp.recv = null;
        sp.loss_time = null;
        sp.ack_needed = false;
        sp.ack_now = false;
        sp.ack_deadline = null;
        sp.ack_eliciting_in_flight = 0;
        sp.probe = 0;
        sp.crypto_retx.clearRetainingCapacity();
        c.pto_count = 0;
    }

    /// Next time `onTimeout` should be called (null: nothing pending).
    pub fn nextTimeout(c: *const Connection) ?u64 {
        var best: ?u64 = c.timer;
        if (c.pace_at) |t| best = if (best) |b| @min(b, t) else t;
        if (c.spaces[2].ack_needed) if (c.spaces[2].ack_deadline) |t| {
            best = if (best) |b| @min(b, t) else t;
        };
        if (c.state == .handshaking and c.hs_deadline != 0) best = if (best) |b| @min(b, c.hs_deadline) else c.hs_deadline;
        if (c.state == .established or c.state == .handshaking) {
            if (c.idle_ns != 0) {
                const t = c.last_recv + c.idle_ns;
                best = if (best) |b| @min(b, t) else t;
            }
            if (c.cfg.keep_alive_ms != 0 and c.state == .established) {
                const t = @max(c.last_send, c.last_recv) + c.cfg.keep_alive_ms * ms;
                best = if (best) |b| @min(b, t) else t;
            }
        }
        if (c.state == .closing or c.state == .draining) {
            best = if (best) |b| @min(b, c.close_deadline) else c.close_deadline;
        }
        return best;
    }

    fn updateTimer(c: *Connection, now: u64) void {
        var earliest_loss: ?u64 = null;
        for (c.spaces) |s| if (s.loss_time) |t| {
            earliest_loss = if (earliest_loss) |e| @min(e, t) else t;
        };
        if (earliest_loss) |t| {
            c.timer = t;
            return;
        }
        var in_flight: u32 = 0;
        for (c.spaces) |s| in_flight += s.ack_eliciting_in_flight;
        if (in_flight == 0) {
            if (c.handshake_confirmed or c.state != .handshaking) {
                c.timer = null;
                return;
            }
            // client: keep probing while the handshake is unconfirmed (a server waits)
            if (c.srv != null) {
                c.timer = null;
                return;
            }
            const sp: Space = if (c.spaces[1].send != null) .handshake else .initial;
            c.timer = now + c.ptoDuration(sp);
            return;
        }
        var best: ?u64 = null;
        for (c.spaces, 0..) |s, i| {
            if (s.ack_eliciting_in_flight == 0) continue;
            if (i == 2 and !c.handshake_confirmed and c.state == .handshaking) continue;
            const t = s.time_last_ack_eliciting + c.ptoDuration(@enumFromInt(i));
            best = if (best) |b| @min(b, t) else t;
        }
        c.timer = best;
    }

    pub fn onTimeout(c: *Connection, now: u64) void {
        if (c.state == .closing or c.state == .draining) {
            if (now >= c.close_deadline) c.state = .closed;
            return;
        }
        if (c.idle_ns != 0 and now >= c.last_recv + c.idle_ns) {
            c.close = .{ .code = 0, .app = false, .remote = false, .reason = "idle timeout" };
            c.state = .closed;
            return;
        }
        if (c.state == .handshaking and c.hs_deadline != 0 and now >= c.hs_deadline) {
            c.close = .{ .code = 0, .app = false, .remote = false, .reason = "handshake timeout" };
            c.state = .closed;
            return;
        }
        if (c.timer) |t| if (now >= t) {
            var earliest_loss: ?u64 = null;
            var loss_space: Space = .initial;
            for (c.spaces, 0..) |s, i| if (s.loss_time) |lt| {
                if (earliest_loss == null or lt < earliest_loss.?) {
                    earliest_loss = lt;
                    loss_space = @enumFromInt(i);
                }
            };
            if (earliest_loss != null) {
                c.detectLoss(now, loss_space);
                if (c.cfg.pmtud and loss_space == .app) c.blackHoleCheck(now, false);
            } else {
                // PTO
                var space: Space = .initial;
                var best: ?u64 = null;
                for (c.spaces, 0..) |s, i| {
                    if (s.discarded or s.send == null) continue;
                    // no probe of 1-RTT data before the handshake is done (RFC 9002 section
                    // 6.2.1); the space only has keys this early with `cfg.early_send`
                    if (i == 2 and c.state == .handshaking) continue;
                    if (s.ack_eliciting_in_flight == 0 and !(c.state == .handshaking and !c.handshake_confirmed)) continue;
                    const tt = s.time_last_ack_eliciting + c.ptoDuration(@enumFromInt(i));
                    if (best == null or tt < best.?) {
                        best = tt;
                        space = @enumFromInt(i);
                    }
                }
                c.pto_count += 1;
                c.ptos += 1;
                // two probe timeouts in a row with nothing acknowledged, at a raised datagram
                // size: the probes themselves may be what the path drops
                if (c.cfg.pmtud and space == .app and c.pto_count >= 2 and c.mtu > max_datagram) c.pmtuBlackHole(now);
                const sp = &c.spaces[@intFromEnum(space)];
                sp.probe = 2;
                if (space != .app) {
                    // retransmit unacked handshake data
                    for (sp.live()) |s| for (s.recs[0..s.nrec]) |r| switch (r) {
                        .crypto => |cr| sp.crypto_retx.append(c.gpa, .{ .start = cr.off, .end = cr.off + cr.len }) catch c.internalError(),
                        else => {},
                    };
                } else c.probeData();
            }
            c.updateTimer(now);
        };
    }

    /// RFC 9002 section 6.2.4: a PTO probe carries data. Without new data to send, the stream
    /// data of the oldest packets in flight (one per probe) is queued again, so the probe repairs
    /// a tail loss at once instead of a PING that only asks for the ACK that then declares the
    /// loss, a round trip later. The originals stay in flight; whichever copy arrives first wins.
    fn probeData(c: *Connection) void {
        for (c.streams.values()) |st| if (st.hasPending() and st.stopped_by_peer == null) return;
        const sp = &c.spaces[2];
        var probes: usize = 0;
        for (sp.live()) |pk| {
            if (probes >= 2) break;
            if (!pk.ack_eliciting) continue;
            var any = false;
            for (pk.recs[0..pk.nrec]) |r| switch (r) {
                .stream => |sr| if (c.streams.get(sr.id)) |st| {
                    if (st.send_reset or sr.off < st.send_base or (sr.len == 0 and !sr.fin)) continue;
                    st.retx.append(c.gpa, .{ .start = sr.off, .end = sr.off + sr.len }) catch return c.internalError();
                    if (sr.fin) st.fin_sent = false;
                    any = true;
                },
                else => {},
            };
            if (any) probes += 1;
        }
    }

    // ------------------------------------------------------------ transmit

    const Plan = struct {
        space: Space,
        /// Frame bytes: a scratch buffer, or (1-RTT only, nothing coalesced) the datagram itself
        /// right after the short header, so writePacket seals in place without a copy.
        frames: []u8,
        len: usize = 0,
        eliciting: bool = false,
        recs: [max_recs]FrameRec = undefined,
        nrec: u8 = 0,

        fn addRec(p: *Plan, r: FrameRec) bool {
            if (p.nrec >= max_recs) return false;
            p.recs[p.nrec] = r;
            p.nrec += 1;
            return true;
        }
    };

    fn headerOverhead(c: *const Connection, space: Space) usize {
        return switch (space) {
            .app => 1 + c.dcid_len + 4,
            .initial => 1 + 4 + 1 + c.dcid_len + 1 + cid_len + varintLen(c.retry_token.items.len) + c.retry_token.items.len + 2 + 4,
            .handshake => 1 + 4 + 1 + c.dcid_len + 1 + cid_len + 2 + 4,
        };
    }

    /// Writes the next datagram into `out` (at least `max_datagram` bytes; datagrams grow to the
    /// validated path MTU when `out` has room). Returns its length, or null when there is nothing
    /// to send.
    pub fn pollTransmit(c: *Connection, now: u64, out: []u8) ?usize {
        std.debug.assert(out.len >= max_datagram);
        if (c.state == .closed or c.state == .draining) return null;
        if (c.state == .closing) {
            if (!c.close_pending) return null;
            return c.buildClose(now, out);
        }
        if (c.credit_due) {
            c.creditScan();
            if (c.state == .closing) return c.buildClose(now, out);
        }
        c.pace_at = null;
        if (!c.addr_validated and c.amp_sent + max_datagram > 3 * c.amp_recv) return null;
        if (c.pmtuProbeDue(now, out.len)) return c.buildProbe(now, out);
        const mtu = @min(c.mtu, out.len, max_mtu);
        var scratch: [3][max_mtu]u8 = undefined;
        var plans: [3]Plan = undefined;
        var np: usize = 0;
        var used: usize = 0;
        var has_initial = false;
        // Only 1-RTT keys left: the single packet's frames go straight into `out`.
        const direct = c.spaces[0].send == null and c.spaces[1].send == null;
        const spaces = [_]Space{ .initial, .handshake, .app };
        for (spaces, 0..) |sp_id, si| {
            const sp = &c.spaces[@intFromEnum(sp_id)];
            if (sp.send == null) continue;
            const overhead = c.headerOverhead(sp_id) + 16;
            if (used + overhead + 4 >= mtu) break;
            const budget = mtu - used - overhead;
            var plan: Plan = .{ .space = sp_id, .frames = if (direct) out[overhead - 16 ..][0..budget] else scratch[si][0..budget] };
            c.fillPlan(now, &plan, budget);
            if (plan.len == 0) continue;
            plans[np] = plan;
            np += 1;
            used += overhead + plan.len;
            if (sp_id == .initial) has_initial = true;
        }
        if (np == 0) {
            // the round is over: the application may consume before the next one
            c.credit_due = true;
            return null;
        }
        // Pad datagrams carrying Initial packets to 1200 bytes (RFC 9000 section 14.1).
        if (has_initial and used < max_datagram) {
            const last = &plans[np - 1];
            const pad = max_datagram - used;
            @memset(last.frames[last.len..][0..pad], 0);
            last.len += pad;
            used += pad;
        }
        var pos: usize = 0;
        for (plans[0..np]) |*plan| {
            tr("tx {s} len={d} eliciting={}", .{ @tagName(plan.space), plan.len, plan.eliciting });
            pos += c.writePacket(now, plan, out[pos..]);
        }
        c.last_send = now;
        if (!c.addr_validated) c.amp_sent += pos;
        c.updateTimer(now);
        return pos;
    }

    fn pmtuProbeDue(c: *Connection, now: u64, out_len: usize) bool {
        if (c.cfg.pmtud) return c.pmtuSearchDue(now, out_len);
        const target = c.cfg.pmtu_max;
        return target > c.mtu and out_len >= target and target <= max_mtu and c.handshake_confirmed and
            !c.pmtu_inflight and c.pmtu_tries < 3 and c.peer.max_udp_payload >= target and
            c.spaces[2].send != null and c.state == .established;
    }

    /// Path MTU search: true when a probe of `pmtu_probe` bytes should leave now. Picks the
    /// next size when the last one was settled, and ends the search when no size is left.
    fn pmtuSearchDue(c: *Connection, now: u64, out_len: usize) bool {
        if (c.pmtu_inflight or !c.handshake_confirmed or c.spaces[2].send == null or c.state != .established) return false;
        if (c.pmtu_search_at != 0) {
            if (now < c.pmtu_search_at) return false;
            // again from the top: the path may carry more than it did
            c.pmtu_search_at = 0;
            c.pmtu_fail = 0;
            c.pmtu_probe = 0;
        }
        if (c.pmtu_probe == 0) {
            const ceiling: u64 = @min(@as(u64, c.cfg.pmtu_max), max_mtu, out_len, c.peer.max_udp_payload);
            const hi: u64 = if (c.pmtu_fail != 0) @min(ceiling, c.pmtu_fail - 1) else ceiling;
            if (hi < c.mtu + pmtu_step) {
                c.pmtu_search_at = now + pmtu_raise_ns;
                return false;
            }
            // First the ceiling itself (most paths carry it). When that failed, the size of
            // IPv6 over Ethernet, then halfway between what passed and what failed.
            const next: u64 = if (c.pmtu_fail == 0) hi else if (c.pmtu_fail > 1452 and c.mtu < 1452) 1452 else (c.mtu + hi + 1) / 2;
            c.pmtu_probe = @intCast(next);
            c.pmtu_tries = 0;
        }
        return c.pmtu_probe <= out_len;
    }

    /// PING + PADDING filling exactly the probe size (`cfg.pmtu_max`, or the search's choice).
    fn buildProbe(c: *Connection, now: u64, out: []u8) usize {
        const target: usize = if (c.cfg.pmtud) c.pmtu_probe else c.cfg.pmtu_max;
        const overhead = c.headerOverhead(.app) + 16;
        var plan: Plan = .{ .space = .app, .frames = out[overhead - 16 ..][0 .. target - overhead] };
        plan.frames[0] = 0x01;
        @memset(plan.frames[1..], 0);
        plan.len = plan.frames.len;
        plan.eliciting = true;
        _ = plan.addRec(.{ .pmtu = @intCast(target) });
        c.pmtu_inflight = true;
        const n = c.writePacket(now, &plan, out);
        c.last_send = now;
        c.updateTimer(now);
        return n;
    }

    fn fillPlan(c: *Connection, now: u64, plan: *Plan, budget: usize) void {
        const sp = &c.spaces[@intFromEnum(plan.space)];
        var p: usize = 0;
        const f = plan.frames;
        const lim = @min(budget, f.len);
        // ACK
        var ack_len: usize = 0;
        if (sp.ack_needed and sp.recv_set.n > 0) ack_len = encodeAck(sp, now, f[p..lim]);
        p += ack_len;
        var can_send = c.bytes_in_flight < c.cwnd or sp.probe > 0;
        if (c.cfg.pacing and can_send and sp.probe == 0 and plan.space == .app and c.rtt_initialized) {
            // Probes and ACKs are never paced; the handshake flights fit the first bucket.
            const slow_start = c.cwnd < c.ssthresh;
            if (c.pacer.delay(now, c.srtt, c.cwnd, c.mtu, c.cwnd - c.bytes_in_flight, if (slow_start) 2 else 5, if (slow_start) 1 else 4)) |at| {
                can_send = false;
                c.pace_at = at;
            }
        }
        if (can_send) {
            // CRYPTO: retransmissions first, then new bytes
            while (p + 16 < lim) {
                var start: u64 = undefined;
                var end: u64 = undefined;
                var from_retx = false;
                if (sp.crypto_retx.items.len > 0) {
                    const r = sp.crypto_retx.items[0];
                    start = r.start;
                    end = r.end;
                    from_retx = true;
                } else if (sp.crypto_sent < sp.crypto_out.items.len) {
                    start = sp.crypto_sent;
                    end = sp.crypto_out.items.len;
                } else break;
                if (!from_retx) {} // new data
                const room = lim - p - 1 - varintLen(start) - 4; // type + off + len(2..4)
                if (room < 1) break;
                const take: usize = @intCast(@min(end - start, @as(u64, @min(room, 1100))));
                if (!plan.addRec(.{ .crypto = .{ .off = start, .len = @intCast(take) } })) break;
                f[p] = 0x06;
                p += 1;
                putVarint(f, &p, start);
                // length: always 2-byte varint to keep layout predictable
                std.mem.writeInt(u16, f[p..][0..2], @as(u16, @intCast(take)) | 0x4000, .big);
                p += 2;
                @memcpy(f[p..][0..take], sp.crypto_out.items[@intCast(start)..][0..take]);
                p += take;
                plan.eliciting = true;
                if (from_retx) {
                    if (@as(u64, take) == end - start) {
                        _ = sp.crypto_retx.orderedRemove(0);
                    } else sp.crypto_retx.items[0].start += take;
                } else sp.crypto_sent += take;
            }
        }
        if (plan.space == .app) {
            if (c.state == .established or c.spaces[2].send != null) {
                p = c.fillApp(plan, p, lim, can_send);
            }
            if (c.cfg.cubic) {
                if (c.bytes_in_flight >= c.cwnd) {
                    c.cwnd_limited = true;
                } else if (!plan.eliciting and c.pace_at == null) c.cwnd_limited = false;
            }
        }
        // PING for probes
        if (sp.probe > 0 and !plan.eliciting and p + 1 <= lim) {
            f[p] = 0x01;
            p += 1;
            plan.eliciting = true;
        }
        if (plan.eliciting and sp.probe > 0) sp.probe -= 1;
        // A key update waits for the peer to acknowledge a packet of the current phase. A side that
        // only sends ACKs (a client downloading) never gets one: when the next update is near and
        // nothing ack-eliciting is in flight, one PING per key phase asks for it.
        if (!plan.eliciting and plan.space == .app and c.handshake_confirmed and !c.phase_acked and
            sp.ack_eliciting_in_flight == 0 and c.phase_pkts + 1 >= c.cfg.key_update_pkts and p + 1 <= lim)
        {
            f[p] = 0x01;
            p += 1;
            plan.eliciting = true;
        }
        // keep-alive
        if (!plan.eliciting and plan.space == .app and c.state == .established and c.cfg.keep_alive_ms != 0 and p + 1 <= lim) {
            if (now >= @max(c.last_send, c.last_recv) + c.cfg.keep_alive_ms * ms) {
                f[p] = 0x01;
                p += 1;
                plan.eliciting = true;
            }
        }
        plan.len = p;
        if (ack_len > 0) {
            const due = sp.ack_now or (sp.ack_deadline != null and now >= sp.ack_deadline.?);
            if (!plan.eliciting and p == ack_len and !due) {
                plan.len = 0; // nothing but a not-yet-due ACK: stay quiet, keep the state
                return;
            }
            sp.ack_needed = false;
            sp.ack_now = false;
            sp.unacked_eliciting = 0;
            sp.ack_deadline = null;
        }
    }

    fn fillApp(c: *Connection, plan: *Plan, p_in: usize, lim: usize, can_send: bool) usize {
        var p = p_in;
        const f = plan.frames;
        // PATH_RESPONSE
        while (c.path_responses.items.len > 0 and p + 9 <= lim) {
            const r = c.path_responses.orderedRemove(0);
            f[p] = 0x1b;
            @memcpy(f[p + 1 ..][0..8], &r);
            p += 9;
            plan.eliciting = true;
        }
        if (c.need_handshake_done and p + 1 <= lim and plan.addRec(.handshake_done)) {
            f[p] = 0x1e;
            p += 1;
            c.need_handshake_done = false;
            plan.eliciting = true;
        }
        // RETIRE_CONNECTION_ID
        while (c.pending_retire.items.len > 0 and p + 9 <= lim) {
            const seq = c.pending_retire.orderedRemove(0);
            if (!plan.addRec(.{ .retire_cid = seq })) {
                c.pending_retire.insert(c.gpa, 0, seq) catch c.internalError();
                break;
            }
            f[p] = 0x19;
            p += 1;
            putVarint(f, &p, seq);
            plan.eliciting = true;
        }
        if (c.need_max_data and p + 9 <= lim and plan.addRec(.max_data)) {
            f[p] = 0x10;
            p += 1;
            putVarint(f, &p, c.recv_max_data);
            c.need_max_data = false;
            plan.eliciting = true;
        }
        while (c.ctl.items.len > 0 and p + 25 <= lim) {
            const e = c.ctl.items[0];
            if (!plan.addRec(switch (e) {
                .reset => |r| .{ .reset_stream = r },
                .stop => |t| .{ .stop_sending = t },
            })) break;
            _ = c.ctl.orderedRemove(0);
            switch (e) {
                .reset => |r| {
                    f[p] = 0x04;
                    p += 1;
                    putVarint(f, &p, r.id);
                    putVarint(f, &p, r.code);
                    putVarint(f, &p, r.final);
                },
                .stop => |t| {
                    f[p] = 0x05;
                    p += 1;
                    putVarint(f, &p, t.id);
                    putVarint(f, &p, t.code);
                },
            }
            plan.eliciting = true;
        }
        while (c.pending_msd.items.len > 0 and p + 17 <= lim) {
            const id = c.pending_msd.orderedRemove(0);
            const s = c.streams.get(id) orelse continue;
            if (s.detached or s.reset != null) continue;
            if (!plan.addRec(.{ .max_stream_data = id })) {
                c.pending_msd.insert(c.gpa, 0, id) catch c.internalError();
                break;
            }
            f[p] = 0x11;
            p += 1;
            putVarint(f, &p, id);
            putVarint(f, &p, s.recv_limit);
            plan.eliciting = true;
        }
        if (c.need_max_streams_uni and p + 9 <= lim and plan.addRec(.max_streams_uni)) {
            f[p] = 0x13;
            p += 1;
            putVarint(f, &p, c.streams_uni_limit);
            c.need_max_streams_uni = false;
            plan.eliciting = true;
        }
        if (c.need_max_streams_bidi and p + 9 <= lim and plan.addRec(.max_streams_bidi)) {
            f[p] = 0x12;
            p += 1;
            putVarint(f, &p, c.streams_bidi_limit);
            c.need_max_streams_bidi = false;
            plan.eliciting = true;
        }
        if (!can_send) return p;
        // STREAM data
        for (c.streams.values()) |s| {
            if (p + 24 >= lim) break;
            if (!s.hasPending()) continue;
            if (s.stopped_by_peer != null) continue;
            p = c.fillStream(plan, p, lim, s);
        }
        return p;
    }

    fn fillStream(c: *Connection, plan: *Plan, p_in: usize, lim: usize, s: *Stream) usize {
        var p = p_in;
        const f = plan.frames;
        while (p + 24 < lim and s.hasPending()) {
            var start: u64 = undefined;
            var end: u64 = undefined;
            var is_new = false;
            if (s.retx.items.len > 0) {
                start = s.retx.items[0].start;
                end = s.retx.items[0].end;
            } else {
                start = s.send_off;
                end = s.send_base + s.send_buf.items.len;
                is_new = true;
                // flow control for new data
                const stream_room = s.peer_max -| start;
                const conn_room = c.send_max_data -| c.sent_data;
                end = @min(end, start + @min(stream_room, conn_room));
            }
            const room = lim - p - 1 - varintLen(s.id) - 8 - 4;
            const take: usize = @intCast(@min(end - start, @as(u64, room)));
            const at_end = start + take == s.send_base + s.send_buf.items.len;
            const send_fin = s.fin_queued and at_end and (!s.fin_sent or !is_new);
            if (take == 0 and !send_fin) break;
            if (!plan.addRec(.{ .stream = .{ .id = s.id, .off = start, .len = @intCast(take), .fin = send_fin } })) break;
            s.inflight += 1;
            f[p] = 0x08 | 0x04 | 0x02 | @as(u8, if (send_fin) 1 else 0);
            p += 1;
            putVarint(f, &p, s.id);
            putVarint(f, &p, start);
            putVarint(f, &p, take);
            @memcpy(f[p..][0..take], s.send_buf.items[@intCast(start - s.send_base)..][0..take]);
            p += take;
            plan.eliciting = true;
            if (is_new) {
                s.send_off += take;
                c.sent_data += take;
            } else {
                c.stream_retx += 1;
                if (@as(u64, take) == end - start) {
                    _ = s.retx.orderedRemove(0);
                } else s.retx.items[0].start += take;
            }
            if (send_fin) s.fin_sent = true;
            if (take == 0) break;
        }
        return p;
    }

    fn encodeAck(sp: *const SpaceState, now: u64, out: []u8) usize {
        const set = &sp.recv_set;
        // worst case size: 1 + 8 + 8 + 8 + 8 + 16 * ranges
        if (out.len < 40 + 16 * set.n) {
            if (out.len < 40) return 0;
        }
        var p: usize = 0;
        out[p] = 0x02;
        p += 1;
        const largest = set.r[0].end - 1;
        putVarint(out, &p, largest);
        const delay_us = (now -| sp.largest_recv_time) / us;
        putVarint(out, &p, delay_us >> 3);
        // ranges that fit
        var count: usize = set.n;
        while (count > 1 and 40 + 16 * (count - 1) > out.len) count -= 1;
        putVarint(out, &p, count - 1);
        putVarint(out, &p, set.r[0].end - set.r[0].start - 1);
        var prev_start = set.r[0].start;
        for (set.r[1..count]) |r| {
            putVarint(out, &p, prev_start - r.end - 1); // gap (smallest unacked - 1 encoded)
            putVarint(out, &p, r.end - r.start - 1);
            prev_start = r.start;
        }
        return p;
    }

    /// Starts a key update of our own (RFC 9001 section 6.1) once `key_update_pkts` packets were
    /// sealed under the current keys: only with the handshake confirmed, no update in progress
    /// (our phase is the peer's) and a packet of the current phase acknowledged. If the peer
    /// never lets us update, the connection closes before the confidentiality limit.
    fn maybeUpdateKeys(c: *Connection) void {
        c.phase_pkts += 1;
        if (c.phase_pkts <= c.cfg.key_update_pkts) return;
        if (c.handshake_confirmed and c.send_phase == c.recv_phase and c.phase_acked) {
            c.spaces[2].send = c.spaces[2].send.?.nextGeneration();
            c.send_phase = !c.send_phase;
            c.key_updates += 1;
            c.newSendPhase();
            c.phase_pkts = 1;
            tr("key update (ours) phase={}", .{c.send_phase});
        } else if (c.phase_pkts >= 1 << 23) {
            c.startClose(0x0f, false, "AEAD confidentiality limit"); // AEAD_LIMIT_REACHED
        }
    }

    fn newSendPhase(c: *Connection) void {
        c.phase_pkts = 0;
        c.phase_first_pn = c.spaces[2].next_pn;
        c.phase_acked = false;
    }

    /// Serialises one packet; returns bytes written.
    fn writePacket(c: *Connection, now: u64, plan: *Plan, out: []u8) usize {
        const sp = &c.spaces[@intFromEnum(plan.space)];
        if (plan.space == .app) c.maybeUpdateKeys();
        const keys = sp.send.?;
        const pn = sp.next_pn;
        sp.next_pn += 1;
        c.pkts_sent += 1;
        var p: usize = 0;
        var len_pos: usize = 0;
        // 4-byte packet numbers always
        const payload_len = plan.len;
        // Header protection needs >= 4 bytes after pn_off for the sample: payload + tag >= 16 holds.
        var min_payload = payload_len;
        if (min_payload < 4) min_payload = 4; // plan.len >= 1 always; pad tiny packets
        if (plan.space == .app) {
            out[p] = 0x40 | 0x03 | (if (c.send_phase) @as(u8, 0x04) else 0);
            p += 1;
            @memcpy(out[p..][0..c.dcid_len], c.dcid[0..c.dcid_len]);
            p += c.dcid_len;
        } else {
            const ty: u8 = if (plan.space == .initial) 0 else 2;
            out[p] = 0xc0 | (ty << 4) | 0x03;
            p += 1;
            std.mem.writeInt(u32, out[p..][0..4], 1, .big);
            p += 4;
            out[p] = c.dcid_len;
            p += 1;
            @memcpy(out[p..][0..c.dcid_len], c.dcid[0..c.dcid_len]);
            p += c.dcid_len;
            out[p] = cid_len;
            p += 1;
            @memcpy(out[p..][0..cid_len], &c.scid);
            p += cid_len;
            if (plan.space == .initial) {
                putVarint(out, &p, c.retry_token.items.len);
                @memcpy(out[p..][0..c.retry_token.items.len], c.retry_token.items);
                p += c.retry_token.items.len;
            }
            len_pos = p;
            p += 2; // 2-byte length
        }
        const pn_off = p;
        std.mem.writeInt(u32, out[p..][0..4], @truncate(pn), .big);
        p += 4;
        const hdr_len = p;
        if (plan.frames.ptr != out[p..].ptr) @memcpy(out[p..][0..payload_len], plan.frames[0..payload_len]);
        if (min_payload > payload_len) {
            @memset(out[p + payload_len ..][0 .. min_payload - payload_len], 0);
        }
        const pl = min_payload;
        if (plan.space != .app) {
            const l: u16 = @intCast(4 + pl + 16);
            std.mem.writeInt(u16, out[len_pos..][0..2], l | 0x4000, .big);
        }
        qc.seal(&keys, pn, out, hdr_len, pl);
        const total = hdr_len + pl + 16;
        // header protection
        const mask = qc.hpMaskK(&keys, out[pn_off + 4 ..][0..16]);
        qc.maskFirstByte(&out[0], mask);
        qc.maskPn(out, pn_off, 4, mask);
        // record
        var rec: Sent = .{ .pn = pn, .time = now, .size = @intCast(total), .ack_eliciting = plan.eliciting, .in_flight = plan.eliciting or plan.len > 0 and false };
        rec.in_flight = plan.eliciting;
        rec.nrec = plan.nrec;
        if (plan.nrec > 0) @memcpy(rec.recs[0..plan.nrec], plan.recs[0..plan.nrec]);
        if (plan.eliciting) {
            sp.sent.append(c.gpa, rec) catch c.internalError();
            sp.time_last_ack_eliciting = now;
            sp.ack_eliciting_in_flight += 1;
            c.bytes_in_flight += total;
            if (c.cfg.pacing) c.pacer.onSend(total);
        }
        // Initial keys are dropped as soon as the first Handshake packet is sent (client).
        if (plan.space == .handshake and c.srv == null) c.discardSpace(.initial);
        return total;
    }

    fn buildClose(c: *Connection, now: u64, out: []u8) ?usize {
        // Send CONNECTION_CLOSE in the highest space with keys.
        const order = [_]Space{ .app, .handshake, .initial };
        for (order) |sid| {
            const sp = &c.spaces[@intFromEnum(sid)];
            if (sp.send == null) continue;
            // early 1-RTT send keys (`cfg.early_send`): until the handshake is done the peer may
            // not be able to read a 1-RTT packet, so the close goes in a Handshake packet
            if (sid == .app and sp.recv == null) continue;
            var close_buf: [max_datagram]u8 = undefined;
            var plan: Plan = .{ .space = sid, .frames = &close_buf };
            const info = c.close.?;
            var p: usize = 0;
            plan.frames[p] = if (info.app and sid == .app) 0x1d else 0x1c;
            p += 1;
            const code = if (info.app and sid != .app) 0x0c else info.code; // APPLICATION_ERROR in non-1-RTT spaces
            putVarint(plan.frames, &p, code);
            if (plan.frames[0] == 0x1c) putVarint(plan.frames, &p, 0);
            const reason: []const u8 = if (sid == .app) info.reason else "";
            putVarint(plan.frames, &p, reason.len);
            @memcpy(plan.frames[p..][0..reason.len], reason);
            p += reason.len;
            plan.len = p;
            if (sid == .initial and p < 1100) {
                @memset(plan.frames[p..][0 .. 1100 - p], 0);
                plan.len = 1100;
            }
            const n = c.writePacket(now, &plan, out);
            c.close_pending = false;
            c.close_sent = true;
            c.close_deadline = now + 3 * c.ptoDuration(.app) / 1;
            return n;
        }
        c.close_pending = false;
        c.close_sent = true;
        c.state = .closed;
        return null;
    }

    // ------------------------------------------------------------ streams (application API)

    /// Opens the next client-initiated bidirectional stream.
    pub fn openBidi(c: *Connection) Error!u64 {
        if (c.next_bidi / 4 >= c.peer.max_streams_bidi) return error.StreamLimit;
        const id = c.next_bidi;
        c.next_bidi += 4;
        const s = try c.newStream(id);
        errdefer c.recycle(s);
        s.recv_limit = c.cfg.max_stream_data;
        s.peer_max = c.peer.max_stream_data_bidi_remote;
        try c.streams.put(c.gpa, id, s);
        return id;
    }

    /// Opens the next unidirectional stream of ours (send only).
    pub fn openUni(c: *Connection) Error!u64 {
        if (c.next_uni / 4 >= c.peer.max_streams_uni) return error.StreamLimit;
        const id = c.next_uni;
        c.next_uni += 4;
        const s = try c.newStream(id);
        errdefer c.recycle(s);
        s.peer_max = c.peer.max_stream_data_uni;
        s.recv.fin_at = 0; // nothing to receive
        try c.streams.put(c.gpa, id, s);
        return id;
    }

    /// A fresh stream, from the warm pool when one is there (its buffers keep their capacity).
    fn newStream(c: *Connection, id: u64) Error!*Stream {
        if (c.stream_pool.pop()) |s| {
            var send_buf = s.send_buf;
            var retx = s.retx;
            var data = s.recv.data;
            s.recv.discard(c.gpa);
            var ooo = s.recv.ooo;
            send_buf.clearRetainingCapacity();
            retx.clearRetainingCapacity();
            data.clearRetainingCapacity();
            ooo.clearRetainingCapacity();
            s.* = .{ .id = id, .send_buf = send_buf, .retx = retx };
            s.recv.data = data;
            s.recv.ooo = ooo;
            return s;
        }
        const s = try c.gpa.create(Stream);
        s.* = .{ .id = id };
        return s;
    }

    /// Keeps a freed stream for reuse (bounded pool; big buffers go back to the allocator).
    fn recycle(c: *Connection, s: *Stream) void {
        s.recv.discard(c.gpa); // out-of-order chunks are not kept warm
        const big = s.send_buf.capacity > 64 << 10 or s.recv.data.capacity > 64 << 10;
        if (!big and c.stream_pool.items.len < 64) {
            if (c.stream_pool.append(c.gpa, s)) |_| return else |_| {}
        }
        s.deinit(c.gpa);
        c.gpa.destroy(s);
    }

    /// The application's view of a stream: null once it was freed (a detached stream is only
    /// the connection's).
    pub fn stream(c: *Connection, id: u64) ?*Stream {
        const s = c.streams.get(id) orelse return null;
        return if (s.detached) null else s;
    }

    /// Appends `data` to the stream's send buffer (copied) and optionally finishes the stream.
    pub fn streamWrite(c: *Connection, id: u64, data: []const u8, fin: bool) Error!void {
        const s = c.stream(id) orelse return error.InvalidStream;
        if (s.send_reset) return error.InvalidStream;
        try s.send_buf.appendSlice(c.gpa, data);
        if (fin) s.fin_queued = true;
    }

    /// Bytes written to the stream that have not been sent yet (a long-lived stream's backlog).
    pub fn streamUnsent(c: *Connection, id: u64) u64 {
        const s = c.stream(id) orelse return 0;
        return s.send_base + s.send_buf.items.len - s.send_off;
    }

    /// Drops the stream's sent bytes that no packet in flight or pending retransmission still
    /// needs, so a long-lived send stream (a subscription) keeps a bounded buffer. Cheap enough
    /// to call when the buffer passes a threshold (scans the 1-RTT sent list once).
    pub fn streamTrim(c: *Connection, id: u64) void {
        const s = c.stream(id) orelse return;
        var keep: u64 = s.send_off;
        for (s.retx.items) |r| keep = @min(keep, r.start);
        for (c.spaces[2].live()) |e| for (e.recs[0..e.nrec]) |r| switch (r) {
            .stream => |sr| if (sr.id == id) {
                keep = @min(keep, sr.off);
            },
            else => {},
        };
        if (keep <= s.send_base) return;
        const n: usize = @intCast(keep - s.send_base);
        const rest = s.send_buf.items.len - n;
        std.mem.copyForwards(u8, s.send_buf.items[0..rest], s.send_buf.items[n..]);
        s.send_buf.shrinkRetainingCapacity(rest);
        s.send_base = keep;
    }

    /// The stream's send side is finished and nothing of it can be needed again: FIN and every
    /// byte sent, nothing queued for retransmission, and every packet that carried any of it
    /// acknowledged (or declared lost and its range requeued, which makes `retx` non-empty).
    /// Only then may a server `streamFree` an answered stream: freeing on "all sent" dropped the
    /// ranges of packets lost afterwards, and the client waited out its request timeout.
    /// A stream the peer stopped (STOP_SENDING, answered with RESET_STREAM) is settled too.
    pub fn streamSettled(c: *Connection, id: u64) bool {
        const s = c.stream(id) orelse return true;
        return c.sendSettled(s);
    }

    /// Next peer-initiated unidirectional stream id, if any.
    pub fn acceptUni(c: *Connection) ?u64 {
        if (c.incoming_uni.items.len == 0) return null;
        return c.incoming_uni.orderedRemove(0);
    }
    pub fn acceptBidi(c: *Connection) ?u64 {
        if (c.incoming_bidi.items.len == 0) return null;
        return c.incoming_bidi.orderedRemove(0);
    }

    /// The application is done with the stream; the peer gets a new stream slot at once. What
    /// is unfinished is finished properly (RFC 9000 section 3): data written but not yet sent is
    /// abandoned with RESET_STREAM; data sent but unacknowledged stays retransmittable; bytes the
    /// peer still sends are counted and dropped, so they keep returning connection credit. The
    /// stream object goes when both directions are done (`reapDetached`).
    pub fn streamFree(c: *Connection, id: u64) void {
        c.release(id, null);
    }

    /// Abandons the stream (a timed-out or cancelled request, a request refused unread): as
    /// `streamFree`, and the peer is asked to stop sending (STOP_SENDING) and our unfinished send
    /// side is reset, both with application error `code`.
    pub fn streamAbort(c: *Connection, id: u64, code: u64) void {
        c.release(id, code);
    }

    fn hasSend(c: *const Connection, id: u64) bool {
        return (id & 2) == 0 or !c.peerInitiated(id);
    }

    fn recvDone(c: *const Connection, s: *const Stream) bool {
        if ((s.id & 2) != 0 and !c.peerInitiated(s.id)) return true; // our send-only stream
        if (s.reset != null) return true;
        const f = s.recv.fin_at orelse return false;
        return s.counted >= f;
    }

    fn release(c: *Connection, id: u64, abort: ?u64) void {
        const s = c.stream(id) orelse return;
        if (s.watched) {
            for (c.recv_watch.items, 0..) |w, i| if (w == s) {
                _ = c.recv_watch.swapRemove(i);
                break;
            };
            s.watched = false;
        }
        if (s.recv.base > s.credited) {
            // consumed since the last scan
            c.recv_consumed += s.recv.base - s.credited;
            s.credited = s.recv.base;
        }
        c.creditDiscard(s);
        s.recv.discard(c.gpa);
        const recv_done = c.recvDone(s);
        if (c.hasSend(id) and !c.sendSettled(s)) {
            // written but not all sent (or no FIN): the peer would wait for the rest for ever
            const all_sent = s.fin_sent and s.retx.items.len == 0 and s.send_off == s.send_base + s.send_buf.items.len;
            if (abort != null or !all_sent) c.resetSend(s, abort orelse 0) catch return c.internalError();
        }
        if (abort) |code| if (!recv_done) {
            c.ctl.append(c.gpa, .{ .stop = .{ .id = id, .code = code } }) catch return c.internalError();
        };
        s.detached = true;
        c.creditStreamSlot(id);
        if (recv_done and (!c.hasSend(id) or c.sendSettled(s))) return c.dropStream(id);
        c.detached.append(c.gpa, id) catch return c.internalError();
        if (c.detached.items.len > max_detached) {
            const old = c.detached.orderedRemove(0);
            c.dropStream(old);
        }
    }

    fn dropStream(c: *Connection, id: u64) void {
        const kv = c.streams.fetchSwapRemove(id) orelse return;
        c.recycle(kv.value);
    }

    /// Frees detached streams whose both directions are finished.
    fn reapDetached(c: *Connection) void {
        var i: usize = 0;
        while (i < c.detached.items.len) {
            const id = c.detached.items[i];
            const s = c.streams.get(id) orelse {
                _ = c.detached.swapRemove(i);
                continue;
            };
            if (c.recvDone(s) and (!c.hasSend(id) or c.sendSettled(s))) {
                c.dropStream(id);
                _ = c.detached.swapRemove(i);
                continue;
            }
            i += 1;
        }
    }

    fn creditStreamSlot(c: *Connection, id: u64) void {
        if (c.peerInitiated(id)) {
            if ((id & 2) != 0) {
                c.streams_uni_limit += 1;
                c.need_max_streams_uni = true;
            } else {
                c.streams_bidi_limit += 1;
                c.need_max_streams_bidi = true;
            }
        }
    }
};

test "varint round trip" {
    var b: [8]u8 = undefined;
    for ([_]u64{ 0, 63, 64, 16383, 16384, 1 << 30, (1 << 62) - 1 }) |v| {
        var p: usize = 0;
        putVarint(&b, &p, v);
        var q: usize = 0;
        try std.testing.expectEqual(v, getVarint(&b, &q).?);
        try std.testing.expectEqual(p, q);
    }
}

test "packet number expansion (RFC 9000 A.3)" {
    try std.testing.expectEqual(@as(u64, 0xa82f9b32), Connection.expandPn(0xa82f30ea, 0x9b32, 16));
}

fn testConn(gpa: Allocator) !*Connection {
    var seed: [64]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @truncate(i *% 13 +% 5);
    return Connection.init(gpa, .{ .server_name = "sui-test", .identity_seed = @as([32]u8, @splat(3)), .seed = seed, .now_unix = 1_800_000_000 }, 0);
}

test "frame parser survives random payloads" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xf00d);
    const r = prng.random();
    var payload: [300]u8 = undefined;
    var iter: usize = 0;
    while (iter < 3000) : (iter += 1) {
        const c = try testConn(gpa);
        defer c.deinit();
        const n = r.uintLessThan(usize, payload.len);
        r.bytes(payload[0..n]);
        // bias the first byte towards real frame types
        if (n > 0 and iter % 2 == 0) payload[0] = r.uintLessThan(u8, 0x20);
        _ = c.processFrames(1000, .app, payload[0..n]) catch {};
        // a connection that survived must still produce well-formed output
        var out: [max_datagram]u8 = undefined;
        _ = c.pollTransmit(2000, &out);
    }
}

test "datagram parser survives random and mutated datagrams" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0xbeef);
    const r = prng.random();
    const c = try testConn(gpa);
    defer c.deinit();
    var first: [max_datagram]u8 = undefined;
    const fl = c.pollTransmit(0, &first).?;
    try std.testing.expectEqual(@as(usize, max_datagram), fl);
    var d: [1500]u8 = undefined;
    var iter: usize = 0;
    while (iter < 20000) : (iter += 1) {
        var n: usize = undefined;
        if (iter % 2 == 0) {
            n = r.uintLessThan(usize, d.len);
            r.bytes(d[0..n]);
            if (n > 0) d[0] |= 0x80 * @as(u8, @intFromBool(iter % 4 == 0));
        } else {
            @memcpy(d[0..fl], &first); // a real Initial (client keys), mutated
            n = fl;
            for (0..1 + r.uintLessThan(usize, 4)) |_| d[r.uintLessThan(usize, n)] ^= @as(u8, 1) << r.int(u3);
        }
        c.handleDatagram(1000 + iter, d[0..n]);
    }
}

test "ack encoding round trip through the ack parser" {
    const gpa = std.testing.allocator;
    const c = try testConn(gpa);
    defer c.deinit();
    const sp = &c.spaces[2];
    for ([_]u64{ 0, 1, 2, 5, 6, 9, 10, 11, 20 }) |pn| sp.recv_set.insert(pn);
    sp.largest_recv_time = 100;
    var abuf: [200]u8 = undefined;
    const n = Connection.encodeAck(sp, 100, &abuf);
    try std.testing.expect(n > 0);
    // Parse it as an ACK for packets we "sent": make 21 sent packets known.
    c.spaces[2].next_pn = 30;
    for (0..21) |i| try c.spaces[2].sent.append(gpa, .{ .pn = i, .time = 0, .size = 100, .ack_eliciting = true, .in_flight = true });
    c.spaces[2].ack_eliciting_in_flight = 21;
    c.bytes_in_flight = 2100;
    var p: usize = 1;
    try c.onAck(1000, .app, abuf[0..n], &p, false);
    try std.testing.expectEqual(n, p);
    // acked: 0,1,2,5,6,9,10,11,20 -> the others remain (some possibly declared lost by the threshold rule)
    var left: usize = 0;
    for (c.spaces[2].live()) |s| {
        try std.testing.expect(s.pn != 0 and s.pn != 20 and s.pn != 11);
        left += 1;
    }
    try std.testing.expect(left <= 12);
}

/// Builds a 1-RTT packet as a peer would: for protocol tests of the state machine.
fn craftShort(keys: *const qc.PacketKeys, dcid: []const u8, pn: u64, phase: bool, payload: []const u8, out: []u8) usize {
    var p: usize = 0;
    out[p] = 0x40 | 0x03 | (if (phase) @as(u8, 4) else 0);
    p += 1;
    @memcpy(out[p..][0..dcid.len], dcid);
    p += dcid.len;
    const pn_off = p;
    std.mem.writeInt(u32, out[p..][0..4], @truncate(pn), .big);
    p += 4;
    @memcpy(out[p..][0..payload.len], payload);
    var plen = payload.len;
    while (plen < 4) : (plen += 1) out[p + plen] = 0; // PADDING
    qc.seal(keys, pn, out, p, plen);
    const total = p + plen + 16;
    const mask = qc.hpMaskK(keys, out[pn_off + 4 ..][0..16]);
    qc.maskFirstByte(&out[0], mask);
    qc.maskPn(out, pn_off, 4, mask);
    return total;
}

/// Opens a datagram this connection produced (client keys), returning plaintext frames.
fn openOurs(keys: *const qc.PacketKeys, pkt: []u8, phase_out: *bool, pn_out: *u64) ![]u8 {
    const pn_off = 1 + cid_len;
    const mask = qc.hpMaskK(keys, pkt[pn_off + 4 ..][0..16]);
    var first = pkt[0];
    qc.maskFirstByte(&first, mask);
    phase_out.* = first & 4 != 0;
    qc.maskPn(pkt, pn_off, 4, mask);
    const pn: u64 = std.mem.readInt(u32, pkt[pn_off..][0..4], .big);
    pn_out.* = pn;
    pkt[0] = first;
    const n = try qc.open(keys, pn, pkt, pn_off + 4);
    return pkt[pn_off + 4 ..][0..n];
}

test "1-RTT key update initiated by the peer rotates both directions" {
    const gpa = std.testing.allocator;
    const c = try testConn(gpa);
    defer c.deinit();
    const our_secret: qc.Secret = @splat(0x11);
    const their_secret: qc.Secret = @splat(0x22);
    c.spaces[2].send = qc.PacketKeys.fromSecret(our_secret);
    c.spaces[2].recv = qc.PacketKeys.fromSecret(their_secret);
    c.discardSpace(.initial); // as after a real handshake: only 1-RTT packets from here on
    c.state = .established;
    c.handshake_confirmed = true;
    c.peer.max_streams_bidi = 8;
    c.peer.max_stream_data_bidi_remote = 1 << 20;
    c.send_max_data = 1 << 20;
    c.peer.max_data = 1 << 20;
    var theirs = qc.PacketKeys.fromSecret(their_secret);
    var pkt: [200]u8 = undefined;
    // packet 0, phase 0: PING
    var n = craftShort(&theirs, &c.scid, 0, false, &.{0x01}, &pkt);
    c.handleDatagram(1000, pkt[0..n]);
    try std.testing.expect(c.spaces[2].recv_set.contains(0));
    try std.testing.expect(!c.recv_phase);
    // the peer updates: packet 1 in phase 1 under the next generation of keys
    theirs = theirs.nextGeneration();
    n = craftShort(&theirs, &c.scid, 1, true, &.{0x01}, &pkt);
    c.handleDatagram(2000, pkt[0..n]);
    try std.testing.expect(c.spaces[2].recv_set.contains(1));
    try std.testing.expect(c.recv_phase and c.send_phase);
    // we answer in the new phase with next-generation send keys
    var out: [max_datagram]u8 = undefined;
    const m = c.pollTransmit(3000, &out).?;
    var ours = qc.PacketKeys.fromSecret(our_secret).nextGeneration();
    var phase: bool = undefined;
    var pn: u64 = undefined;
    const frames = try openOurs(&ours, out[0..m], &phase, &pn);
    try std.testing.expect(phase);
    try std.testing.expectEqual(@as(u8, 0x02), frames[0]); // ACK
    // a stale packet in the old phase after the update is dropped (keys are gone), not a crash
    var old = qc.PacketKeys.fromSecret(their_secret);
    n = craftShort(&old, &c.scid, 2, false, &.{0x01}, &pkt);
    c.handleDatagram(4000, pkt[0..n]);
    try std.testing.expect(!c.spaces[2].recv_set.contains(2));
}

test "1-RTT key update initiated by us, after an ACK in the current phase, and followed by the peer" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.key_update_pkts = 4;
    const id = try c.openBidi();
    var ours = [_]qc.PacketKeys{qc.PacketKeys.fromSecret(@splat(0x11))};
    var theirs = qc.PacketKeys.fromSecret(@splat(0x22));
    var their_phase = false;
    var their_pn: u64 = 0;
    var gen: usize = 0; // our send generation
    var updates_seen: usize = 0;
    var pkt: [200]u8 = undefined;
    var out: [max_datagram]u8 = undefined;
    for (0..60) |round| {
        try c.streamWrite(id, "0123456789", false);
        const m = c.pollTransmit(1000 + round * 1000, &out).?;
        // our packet opens under generation `gen` with phase gen % 2, or under the next one
        var phase: bool = undefined;
        var pn: u64 = undefined;
        const copy = out;
        if (openOurs(&ours[0], out[0..m], &phase, &pn)) |_| {
            try std.testing.expectEqual(gen % 2 == 1, phase);
        } else |_| {
            out = copy;
            const next = ours[0].nextGeneration();
            _ = try openOurs(&next, out[0..m], &phase, &pn);
            ours[0] = next;
            gen += 1;
            updates_seen += 1;
            try std.testing.expectEqual(gen % 2 == 1, phase);
        }
        // the peer acks everything; when it sees our new phase it updates too (as quinn does)
        if (phase != their_phase) {
            theirs = theirs.nextGeneration();
            their_phase = phase;
        }
        var a: [32]u8 = undefined;
        const al = ackFrame(&a, pn, pn);
        const n = craftShort(&theirs, &c.scid, their_pn, their_phase, a[0..al], &pkt);
        their_pn += 1;
        c.handleDatagram(1500 + round * 1000, pkt[0..n]);
        try std.testing.expect(c.state == .established);
    }
    // 60 packets at 4 per key, each update waiting for the peer's ACK: about one per 5 packets
    try std.testing.expect(updates_seen >= 8);
    try std.testing.expectEqual(@as(u64, updates_seen), c.key_updates);
}

test "a PTO probe retransmits the tail's stream data, not a bare PING (RFC 9002 6.2.4)" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.keep_alive_ms = 0;
    const id = try c.openBidi();
    try c.streamWrite(id, "the last request of a burst", true);
    var out: [max_datagram]u8 = undefined;
    _ = c.pollTransmit(1000, &out).?; // lost
    try std.testing.expect(c.pollTransmit(1000, &out) == null);
    const t = c.nextTimeout().?;
    c.onTimeout(t);
    const m = c.pollTransmit(t, &out).?;
    var keys = qc.PacketKeys.fromSecret(@splat(0x11));
    var phase: bool = undefined;
    var pn: u64 = undefined;
    const pl = try openOurs(&keys, out[0..m], &phase, &pn);
    try std.testing.expectEqual(@as(u64, 1), pn);
    // a STREAM frame with offset 0, the data and FIN
    var p: usize = 0;
    while (p < pl.len and pl[p] == 0) p += 1;
    try std.testing.expect(pl[p] & 0xf8 == 0x08 and pl[p] & 0x01 == 1);
    try std.testing.expect(std.mem.indexOf(u8, pl, "the last request of a burst") != null);
    try std.testing.expectEqual(@as(u64, 1), c.ptos);
}

test "out of memory for a sent packet's record closes the connection instead of losing the data" {
    var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const c = try testEstablished(fa.allocator());
    defer c.deinit();
    const id = try c.openBidi();
    try c.streamWrite(id, "data that must not be lost", true);
    fa.fail_index = fa.alloc_index; // every allocation from here on fails
    var out: [max_datagram]u8 = undefined;
    var now: u64 = 1000;
    for (0..4) |_| {
        while (c.pollTransmit(now, &out)) |_| {}
        now += 1000;
    }
    const cc = c.close orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0x01), cc.code);
}

test "a side that only sends ACKs still updates its keys (a PING asks for the phase ACK)" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.key_update_pkts = 8;
    c.cfg.keep_alive_ms = 0;
    var ours = qc.PacketKeys.fromSecret(@splat(0x11));
    var theirs = qc.PacketKeys.fromSecret(@splat(0x22));
    var their_phase = false;
    var their_pn: u64 = 0;
    var pkt: [200]u8 = undefined;
    var out: [max_datagram]u8 = undefined;
    var now: u64 = 1000;
    var ack_due = false; // the peer acks only when we sent something ack-eliciting (as quinn)
    var our_largest: u64 = 0;
    var pings: usize = 0;
    for (0..200) |_| {
        // the peer sends data-like (ack-eliciting) packets, two per round
        for (0..2) |_| {
            var pl: [40]u8 = undefined;
            var q: usize = 0;
            if (ack_due) {
                q = ackFrame(&pl, our_largest, our_largest);
                ack_due = false;
            }
            pl[q] = 0x01;
            q += 1;
            const n = craftShort(&theirs, &c.scid, their_pn, their_phase, pl[0..q], &pkt);
            their_pn += 1;
            c.handleDatagram(now, pkt[0..n]);
        }
        now += 50 * ms;
        while (c.pollTransmit(now, &out)) |m| {
            var phase: bool = undefined;
            var pn: u64 = undefined;
            const copy = out;
            const pl = openOurs(&ours, out[0..m], &phase, &pn) catch blk: {
                out = copy;
                const next = ours.nextGeneration();
                const r = try openOurs(&next, out[0..m], &phase, &pn);
                ours = next;
                break :blk r;
            };
            if (phase != their_phase) {
                theirs = theirs.nextGeneration();
                their_phase = phase;
            }
            our_largest = pn;
            // skip a leading ACK frame; anything else but PADDING is ack-eliciting
            var p: usize = 0;
            if (pl[0] == 0x02) {
                p = 1;
                for (0..4) |_| _ = getVarint(pl, &p).?;
            }
            for (pl[p..]) |b| if (b == 0x01) {
                ack_due = true;
                pings += 1;
                break;
            };
        }
        try std.testing.expect(c.state == .established);
    }
    // about 200 ACK packets at 8 per key, with a round trip of waiting for the phase ACK each
    try std.testing.expect(c.key_updates >= 10);
    try std.testing.expect(pings <= c.key_updates + 2);
}

test "no key update of ours before the peer acknowledged the current phase" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.key_update_pkts = 2;
    c.phase_acked = false;
    const id = try c.openBidi();
    var out: [max_datagram]u8 = undefined;
    for (0..10) |round| {
        try c.streamWrite(id, "x", false);
        _ = c.pollTransmit(1000 + round, &out);
    }
    try std.testing.expectEqual(@as(u64, 0), c.key_updates);
    try std.testing.expect(!c.send_phase);
}

test "stream data round trip through the state machine, with loss and retransmission" {
    const gpa = std.testing.allocator;
    const c = try testConn(gpa);
    defer c.deinit();
    const our_secret: qc.Secret = @splat(0x11);
    const their_secret: qc.Secret = @splat(0x22);
    c.spaces[2].send = qc.PacketKeys.fromSecret(our_secret);
    c.spaces[2].recv = qc.PacketKeys.fromSecret(their_secret);
    c.discardSpace(.initial); // as after a real handshake: only 1-RTT packets from here on
    c.state = .established;
    c.handshake_confirmed = true;
    c.peer.max_streams_bidi = 8;
    c.peer.max_stream_data_bidi_remote = 1 << 20;
    c.send_max_data = 1 << 20;
    const id = try c.openBidi();
    const data = try gpa.alloc(u8, 5000);
    defer gpa.free(data);
    for (data, 0..) |*b, i| b.* = @truncate(i *% 7);
    try c.streamWrite(id, data, true);
    // collect every datagram we send, never acknowledge the first one (lost), ack the rest
    var theirs = qc.PacketKeys.fromSecret(their_secret);
    var ours = qc.PacketKeys.fromSecret(our_secret);
    var got: [6000]u8 = undefined;
    var have: [6000]bool = @splat(false);
    var out: [max_datagram]u8 = undefined;
    var now: u64 = 1_000_000;
    var sent: usize = 0;
    var first_lost = true;
    var their_pn: u64 = 0;
    var fin_seen = false;
    while (sent < 50) : (sent += 1) {
        const m = c.pollTransmit(now, &out) orelse {
            // nothing to send: fire timers so the lost packet is retransmitted
            if (c.nextTimeout()) |t| now = @max(now, t) else break;
            c.onTimeout(now);
            continue;
        };
        var phase: bool = undefined;
        var pn: u64 = undefined;
        const frames = try openOurs(&ours, out[0..m], &phase, &pn);
        var ack_needed = false;
        var p: usize = 0;
        while (p < frames.len) {
            const ty = getVarint(frames, &p).?;
            if (ty == 0 or ty == 1) {
                if (ty == 1) ack_needed = true;
                continue;
            }
            if (ty == 2) { // skip our own ACK frame fields
                var k: usize = 0;
                while (k < 3) : (k += 1) _ = getVarint(frames, &p).?;
                _ = getVarint(frames, &p).?;
                continue;
            }
            try std.testing.expect(ty & 0xf8 == 0x08);
            ack_needed = true;
            _ = getVarint(frames, &p).?; // id
            const off = if (ty & 4 != 0) getVarint(frames, &p).? else 0;
            const len = getVarint(frames, &p).?;
            if (!(first_lost and pn == 0)) {
                @memcpy(got[@intCast(off)..][0..@intCast(len)], frames[p..][0..@intCast(len)]);
                for (0..@intCast(len)) |i| have[@as(usize, @intCast(off)) + i] = true;
                if (ty & 1 != 0) fin_seen = true;
            }
            p += @intCast(len);
        }
        if (first_lost and pn == 0) {
            first_lost = false;
            now += 1_000_000;
            continue; // dropped on the wire
        }
        if (ack_needed) {
            // ack pn in a server packet: ACK frame [pn, pn]
            var ack: [16]u8 = undefined;
            var q: usize = 0;
            ack[q] = 0x02;
            q += 1;
            putVarint(&ack, &q, pn);
            putVarint(&ack, &q, 0);
            putVarint(&ack, &q, 0);
            putVarint(&ack, &q, 0);
            var d: [100]u8 = undefined;
            const dn = craftShort(&theirs, &c.scid, their_pn, false, ack[0..q], &d);
            their_pn += 1;
            now += 50_000;
            c.handleDatagram(now, d[0..dn]);
        }
        now += 1_000;
    }
    try std.testing.expect(fin_seen);
    for (0..data.len) |i| try std.testing.expect(have[i]);
    try std.testing.expectEqualSlices(u8, data, got[0..data.len]);
}

/// An established 1-RTT connection with fixed keys, for protocol tests.
fn testEstablished(gpa: Allocator) !*Connection {
    const c = try testConn(gpa);
    c.spaces[2].send = qc.PacketKeys.fromSecret(@splat(0x11));
    c.spaces[2].recv = qc.PacketKeys.fromSecret(@splat(0x22));
    c.discardSpace(.initial);
    c.discardSpace(.handshake);
    c.state = .established;
    c.handshake_confirmed = true;
    c.peer.max_streams_bidi = 8;
    c.peer.max_stream_data_bidi_remote = 1 << 20;
    c.send_max_data = 1 << 20;
    c.peer.max_data = 1 << 20;
    return c;
}

test "hostile ACK delay does not overflow" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.peer.ack_delay_exponent = 20;
    const id = try c.openBidi();
    try c.streamWrite(id, "x", true);
    var out: [max_datagram]u8 = undefined;
    _ = c.pollTransmit(1_000_000, &out).?;
    var theirs = qc.PacketKeys.fromSecret(@splat(0x22));
    var ack: [32]u8 = undefined;
    var q: usize = 0;
    ack[q] = 0x02;
    q += 1;
    putVarint(&ack, &q, 0); // largest
    putVarint(&ack, &q, (1 << 62) - 1); // ack delay
    putVarint(&ack, &q, 0);
    putVarint(&ack, &q, 0);
    var d: [100]u8 = undefined;
    const dn = craftShort(&theirs, &c.scid, 0, false, ack[0..q], &d);
    c.handleDatagram(2_000_000, d[0..dn]);
    try std.testing.expect(c.state == .established);
}

fn sendTheirs(c: *Connection, pn: u64, frames: []const u8, now: u64) void {
    var theirs = qc.PacketKeys.fromSecret(@splat(0x22));
    var d: [1400]u8 = undefined;
    const dn = craftShort(&theirs, &c.scid, pn, false, frames, &d);
    c.handleDatagram(now, d[0..dn]);
}

test "late frames for freed streams are ignored, not a connection error" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    const id = try c.openBidi();
    // response data, consumed and freed by the application before the FIN arrives
    sendTheirs(c, 0, &.{ 0x0e, @intCast(id), 0x00, 0x02, 'o', 'k' }, 1000);
    try std.testing.expectEqualStrings("ok", c.stream(id).?.recv.contiguous());
    c.streamFree(id);
    sendTheirs(c, 1, &.{ 0x0f, @intCast(id), 0x02, 0x00 }, 2000); // FIN alone
    sendTheirs(c, 2, &.{ 0x0e, @intCast(id), 0x00, 0x02, 'o', 'k' }, 3000); // retransmission
    try std.testing.expect(c.state == .established);
    try std.testing.expect(c.stream(id) == null);
    // a server uni stream freed after use is not re-opened by its retransmitted data
    sendTheirs(c, 3, &.{ 0x0e, 0x03, 0x00, 0x01, 'v' }, 4000);
    try std.testing.expectEqual(@as(?u64, 3), c.acceptUni());
    c.streamFree(3);
    sendTheirs(c, 4, &.{ 0x0f, 0x03, 0x00, 0x01, 'v' }, 5000);
    try std.testing.expect(c.acceptUni() == null and c.stream(3) == null);
    // opening server uni stream 11 implicitly opens 7 (RFC 9000 section 3.2)
    sendTheirs(c, 5, &.{ 0x0e, 0x0b, 0x00, 0x01, 'z' }, 6000);
    try std.testing.expectEqual(@as(?u64, 7), c.acceptUni());
    try std.testing.expectEqual(@as(?u64, 11), c.acceptUni());
    // data on a client stream we never opened is STREAM_STATE_ERROR
    sendTheirs(c, 6, &.{ 0x0e, 0x40, 0x40, 0x00, 0x01, 'x' }, 7000);
    try std.testing.expect(c.state == .closing);
    try std.testing.expectEqual(@as(u64, 0x05), c.close.?.code);
}

fn testEstablishedWindows(gpa: Allocator, msd: u64, md: u64) !*Connection {
    const c = try testEstablished(gpa);
    c.cfg.max_stream_data = msd;
    c.cfg.max_data = md;
    c.recv_max_data = md;
    return c;
}

fn streamFrame(out: []u8, id: u64, off: u64, data: []const u8, fin: bool) usize {
    var q: usize = 0;
    out[q] = 0x0e | @as(u8, @intFromBool(fin));
    q += 1;
    putVarint(out, &q, id);
    putVarint(out, &q, off);
    putVarint(out, &q, data.len);
    @memcpy(out[q..][0..data.len], data);
    return q + data.len;
}

/// Sends what `c` has queued and returns the decrypted frames of every packet, concatenated.
fn ourFrames(c: *Connection, now: u64, out: *std.ArrayList(u8), gpa: Allocator) !void {
    const keys = qc.PacketKeys.fromSecret(@splat(0x11));
    var d: [max_mtu]u8 = undefined;
    while (c.pollTransmit(now, &d)) |n| {
        var phase: bool = undefined;
        var pn: u64 = undefined;
        const f = try openOurs(&keys, d[0..n], &phase, &pn);
        try out.appendSlice(gpa, f);
    }
}

test "receive windows move with what the application consumes, not with what arrives" {
    const gpa = std.testing.allocator;
    var f: [1400]u8 = undefined;
    const fill: [1000]u8 = @splat('a');
    {
        // one byte at the end of the stream window is held as one byte; one past it is refused
        const c = try testEstablished(gpa);
        defer c.deinit();
        const lim = c.cfg.max_stream_data;
        sendTheirs(c, 0, f[0..streamFrame(&f, 1, lim - 1, "x", false)], 1000);
        try std.testing.expect(c.state == .established);
        try std.testing.expectEqual(@as(usize, 1), c.stream(1).?.recv.held());
        sendTheirs(c, 1, f[0..streamFrame(&f, 5, lim, "x", false)], 1100);
        try std.testing.expectEqual(@as(u64, 0x03), c.close.?.code);
    }
    {
        const c = try testEstablishedWindows(gpa, 4000, 8000);
        defer c.deinit();
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var pn: u64 = 0;
        for (0..3) |k| {
            sendTheirs(c, pn, f[0..streamFrame(&f, 1, k * 1000, &fill, false)], 1000 + pn);
            pn += 1;
        }
        try ourFrames(c, 2000, &out, gpa);
        // 3000 of 4000 received, nothing consumed: no MAX_STREAM_DATA, no MAX_DATA
        const st = c.stream(1).?;
        try std.testing.expectEqual(@as(u64, 4000), st.recv_limit);
        try std.testing.expectEqual(@as(u64, 8000), c.recv_max_data);
        // the 4001st byte is a flow control error even though 3000 sit unread
        // (checked on a copy of the limit below); consume 2500: the stream window moves
        st.recv.consume(2500);
        out.clearRetainingCapacity();
        try ourFrames(c, 3000, &out, gpa);
        try std.testing.expectEqual(@as(u64, 6500), c.stream(1).?.recv_limit);
        try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x11, 0x01, 0x59, 0x64 }) != null); // MAX_STREAM_DATA 1 6500
        // freeing a stream returns everything it held to the connection window
        sendTheirs(c, pn, f[0..streamFrame(&f, 5, 0, &fill, false)], 4000);
        pn += 1;
        sendTheirs(c, pn, f[0..streamFrame(&f, 5, 1000, &fill, false)], 4100);
        pn += 1;
        c.streamFree(5);
        out.clearRetainingCapacity();
        try ourFrames(c, 5000, &out, gpa);
        try std.testing.expectEqual(@as(u64, 5000), c.recv_data);
        try std.testing.expectEqual(@as(u64, 4500), c.recv_consumed);
        try std.testing.expectEqual(@as(u64, 4500 + 8000), c.recv_max_data);
        try std.testing.expect(c.state == .established);
    }
}

test "an abandoned stream asks the peer to stop, counts its late bytes and is reaped on its reset" {
    const gpa = std.testing.allocator;
    var f: [1400]u8 = undefined;
    const fill: [1000]u8 = @splat('b');
    const c = try testEstablishedWindows(gpa, 4000, 8000);
    defer c.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const id = try c.openBidi();
    try c.streamWrite(id, "request", true);
    try ourFrames(c, 1000, &out, gpa);
    sendTheirs(c, 0, f[0..streamFrame(&f, id, 0, &fill, false)], 1100);
    // the request times out part-way through the response
    c.streamAbort(id, 7);
    try std.testing.expect(c.stream(id) == null);
    out.clearRetainingCapacity();
    try ourFrames(c, 1200, &out, gpa);
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x05, @intCast(id), 0x07 }) != null); // STOP_SENDING
    // and our unacknowledged request is reset rather than kept for retransmission (final size 7)
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x04, @intCast(id), 0x07, 0x07 }) != null);
    // bytes in flight from the peer keep arriving: counted and given back at once
    sendTheirs(c, 1, f[0..streamFrame(&f, id, 1000, &fill, false)], 1300);
    sendTheirs(c, 2, f[0..streamFrame(&f, id, 2000, &fill, false)], 1400);
    try std.testing.expectEqual(@as(u64, 3000), c.recv_data);
    try std.testing.expectEqual(c.recv_data, c.recv_consumed);
    // the peer answers STOP_SENDING with RESET_STREAM (final size 3500)
    sendTheirs(c, 3, &.{ 0x04, @intCast(id), 0x07, 0x4d, 0xac }, 1500);
    try std.testing.expectEqual(@as(u64, 3500), c.recv_data);
    try std.testing.expectEqual(c.recv_data, c.recv_consumed);
    // both directions are done and the stream goes
    out.clearRetainingCapacity();
    try ourFrames(c, 1700, &out, gpa);
    try std.testing.expect(c.streams.get(id) == null);
    try std.testing.expectEqual(@as(usize, 0), c.detached.items.len);
    try std.testing.expect(c.state == .established);
    // a long-lived connection keeps its window: 20 more abandoned windows flow through
    var pn: u64 = 5;
    c.peer.max_streams_bidi = 100;
    for (0..20) |_| {
        const sid = try c.openBidi();
        try c.streamWrite(sid, "r", true);
        for (0..4) |k| {
            sendTheirs(c, pn, f[0..streamFrame(&f, sid, k * 1000, &fill, false)], 2000 + pn);
            pn += 1;
        }
        c.streamAbort(sid, 7);
        try ourFrames(c, 2000 + pn, &out, gpa);
        var rf: [32]u8 = undefined;
        var q: usize = 0;
        rf[q] = 0x04;
        q += 1;
        for ([_]u64{ sid, 7, 4000 }) |v| putVarint(&rf, &q, v);
        sendTheirs(c, pn, rf[0..q], 2000 + pn);
        pn += 1;
        try ourFrames(c, 2000 + pn, &out, gpa);
        if (c.state != .established) std.debug.print("closed: {s}\n", .{c.close.?.reason});
        try std.testing.expect(c.state == .established);
    }
    try std.testing.expectEqual(@as(usize, 0), c.detached.items.len);
    try std.testing.expectEqual(c.recv_data, c.recv_consumed);
}

test "STOP_SENDING from the peer is answered with RESET_STREAM and settles the stream" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const id = try c.openBidi();
    const big: [5000]u8 = @splat('c');
    try c.streamWrite(id, &big, false);
    c.peer.max_stream_data_bidi_remote = 1000;
    c.stream(id).?.peer_max = 1000; // most of it waits on the peer's window
    try ourFrames(c, 1000, &out, gpa);
    try std.testing.expect(!c.streamSettled(id));
    sendTheirs(c, 0, &.{ 0x05, @intCast(id), 0x09 }, 1100);
    try std.testing.expect(c.streamSettled(id));
    try std.testing.expectEqual(@as(u64, 0), c.streamUnsent(id));
    out.clearRetainingCapacity();
    try ourFrames(c, 1200, &out, gpa);
    // RESET_STREAM id, the peer's code, final size = what was sent (1000)
    try std.testing.expect(std.mem.indexOf(u8, out.items, &.{ 0x04, @intCast(id), 0x09, 0x43, 0xe8 }) != null);
    // a lost RESET_STREAM is sent again, even once the stream is gone
    c.streamFree(id);
    const live = c.spaces[2].live();
    const last = live[live.len - 1];
    c.onLostPacket(1300, last, .app);
    try std.testing.expect(c.ctl.items.len == 1 and c.ctl.items[0] == .reset);
    try std.testing.expect(c.streams.get(id) == null or c.streams.get(id).?.detached);
}

test "a freed stream whose answer is unacknowledged is still retransmitted, then reaped" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const id = try c.openBidi();
    try c.streamWrite(id, "question", true);
    try ourFrames(c, 1000, &out, gpa);
    var f: [64]u8 = undefined;
    sendTheirs(c, 0, f[0..streamFrame(&f, id, 0, "answer", true)], 1100);
    c.streamFree(id);
    try std.testing.expect(c.stream(id) == null);
    try std.testing.expect(c.streams.get(id) != null); // lingering for retransmission
    const sp = &c.spaces[2];
    const lost = sp.live()[0];
    sp.dropFront(1);
    c.onLostPacket(1200, lost, .app);
    out.clearRetainingCapacity();
    try ourFrames(c, 1300, &out, gpa);
    try std.testing.expect(std.mem.indexOf(u8, out.items, "question") != null);
    var a: [32]u8 = undefined;
    sendTheirs(c, 1, a[0..ackFrame(&a, sp.next_pn - 1, 0)], 1400);
    out.clearRetainingCapacity();
    try ourFrames(c, 1500, &out, gpa);
    try std.testing.expect(c.streams.get(id) == null);
}

test "frames not permitted in Initial or Handshake packets close the connection" {
    const gpa = std.testing.allocator;
    const c = try testConn(gpa);
    defer c.deinit();
    // STREAM in an Initial packet (Initial keys are public to anyone on the path)
    _ = c.processFrames(1000, .initial, &.{ 0x0b, 0x03, 0x01, 'x' }) catch {};
    try std.testing.expect(c.state == .closing);
    try std.testing.expectEqual(@as(u64, 0x0a), c.close.?.code);
    try std.testing.expect(c.stream(3) == null);
}

test "hostile peer input is bounded: crypto offset, connection ids, transport parameters, retry size" {
    const gpa = std.testing.allocator;
    {
        const c = try testConn(gpa);
        defer c.deinit();
        var f: [32]u8 = undefined;
        var q: usize = 0;
        f[q] = 0x06;
        q += 1;
        putVarint(&f, &q, 1 << 40); // CRYPTO far beyond any handshake flight
        putVarint(&f, &q, 1);
        f[q] = 0;
        q += 1;
        _ = c.processFrames(1000, .initial, f[0..q]) catch {};
        try std.testing.expectEqual(@as(u64, 0x0d), c.close.?.code);
    }
    {
        const c = try testEstablished(gpa);
        defer c.deinit();
        var pn: u64 = 0;
        var seq: u64 = 1;
        while (seq < 40 and c.state == .established) : (seq += 1) {
            var f: [64]u8 = undefined;
            var q: usize = 0;
            f[q] = 0x18;
            q += 1;
            putVarint(&f, &q, seq);
            putVarint(&f, &q, 0);
            f[q] = 8;
            q += 1;
            @memset(f[q..][0 .. 8 + 16], @truncate(seq));
            q += 8 + 16;
            sendTheirs(c, pn, f[0..q], 1000 + pn);
            pn += 1;
        }
        try std.testing.expect(c.peer_cids.items.len <= max_peer_cids);
        try std.testing.expectEqual(@as(u64, 0x09), c.close.?.code);
    }
    {
        const c = try testConn(gpa);
        defer c.deinit();
        var tp: [64]u8 = undefined;
        var q: usize = 0;
        for ([_][2]u64{ .{ 0x01, (1 << 62) - 1 }, .{ 0x0b, 1 << 14 } }) |kv| {
            putVarint(&tp, &q, kv[0]);
            putVarint(&tp, &q, varintLen(kv[1]));
            putVarint(&tp, &q, kv[1]);
        }
        @memcpy(c.tls.peer_tp[0..q], tp[0..q]);
        c.tls.peer_tp_len = q;
        try std.testing.expectError(error.ConnectionClosed, c.checkPeerParams());
        try std.testing.expectEqual(@as(u64, 0x08), c.close.?.code);
    }
    {
        // an oversized Retry for our connection id is dropped before the integrity check
        const c = try testConn(gpa);
        defer c.deinit();
        var d: [4000]u8 = @splat(0x41);
        d[0] = 0xf0;
        std.mem.writeInt(u32, d[1..5], 1, .big);
        d[5] = cid_len;
        @memcpy(d[6..][0..cid_len], &c.scid);
        d[6 + cid_len] = 4;
        c.handleDatagram(1000, &d);
        try std.testing.expect(c.retry_scid == null and c.state == .handshaking);
    }
}

test "a QUIC Initial whose ClientHello has an overflowing extension length closes the connection, no panic" {
    const gpa = std.testing.allocator;
    var seed: [64]u8 = @splat(4);
    for (tls_srv.hostile_hello_lengths) |h| {
        const client = try Connection.init(gpa, .{ .server_name = "zui", .identity_seed = @as([32]u8, @splat(3)), .seed = seed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"} }, 0);
        defer client.deinit();
        // rewrite one length inside the ClientHello before it is packetised and sealed
        const ch = client.spaces[0].crypto_out.items;
        tls_srv.pokeLength(ch, tls_srv.helloExtOffset(ch, h.et).?, h.v, h.w);
        var d: [max_datagram]u8 = undefined;
        const n = client.pollTransmit(0, &d).?;
        const dl = d[5];
        const dcid = d[6..][0..dl];
        const sl = d[6 + dl];
        const scid = d[7 + dl ..][0..sl];
        seed[0] +%= 1;
        const server = try Connection.initServer(gpa, .{ .server_name = "zui", .identity_seed = @as([32]u8, @splat(5)), .seed = seed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .client_auth = false }, 0, dcid, scid);
        defer server.deinit();
        server.handleDatagram(1000, d[0..n]);
        try std.testing.expect(server.state == .closing);
        try std.testing.expectEqual(@as(u64, 0x100 + 0x28), server.close.?.code);
        // the server says so in an Initial CONNECTION_CLOSE and is then done
        var o: [max_datagram]u8 = undefined;
        try std.testing.expect(server.pollTransmit(2000, &o) != null);
        try std.testing.expect(server.isClosed());
    }
}

test "early_send: 1-RTT data rides behind the server's handshake flight; nothing is read early; a close stays in the Handshake space" {
    const gpa = std.testing.allocator;
    var seed: [64]u8 = @splat(4);
    const server_seed: [32]u8 = @splat(5);
    const skey = (try Ed25519.KeyPair.generateDeterministic(server_seed)).public_key.toBytes();
    for ([_]bool{ false, true }) |early| {
        const client = try Connection.init(gpa, .{ .server_name = "zui", .identity_seed = @as([32]u8, @splat(3)), .expected_peer = skey, .seed = seed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .max_streams_uni = 4 }, 0);
        defer client.deinit();
        var d: [max_datagram]u8 = undefined;
        const n = client.pollTransmit(0, &d).?;
        const dl = d[5];
        const dcid = d[6..][0..dl];
        const sl = d[6 + dl];
        const scid = d[7 + dl ..][0..sl];
        seed[0] +%= 1;
        const server = try Connection.initServer(gpa, .{ .server_name = "zui", .identity_seed = server_seed, .seed = seed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .client_auth = false, .early_send = early }, 0, dcid, scid);
        defer server.deinit();
        seed[0] +%= 1;
        server.handleDatagram(1000, d[0..n]);
        // the flight through Finished is written, the client's Finished is a round trip away
        try std.testing.expect(!server.isEstablished());
        try std.testing.expectEqual(early, server.canSendEarly());
        try std.testing.expectEqual(early, server.spaces[2].send != null);
        try std.testing.expect(server.spaces[2].recv == null);
        var o: [max_mtu]u8 = undefined;
        if (!early) {
            // the old path: the flight alone; the client is established and has no stream
            while (server.pollTransmit(2000, &o)) |m| client.handleDatagram(3000, o[0..m]);
            try std.testing.expect(client.isEstablished());
            try std.testing.expect(client.acceptUni() == null);
            continue;
        }
        const id = try server.openUni();
        try server.streamWrite(id, "settings", false);
        // the handshake flight and the stream data arrive without one more packet from the
        // client, inside the 3x anti-amplification budget of its one Initial
        var sent: usize = 0;
        while (server.pollTransmit(2000, &o)) |m| {
            sent += m;
            client.handleDatagram(3000, o[0..m]);
        }
        try std.testing.expect(sent <= 3 * n);
        try std.testing.expect(client.isEstablished());
        const got = client.acceptUni().?;
        try std.testing.expectEqualStrings("settings", client.stream(got).?.recv.contiguous());
        try std.testing.expect(!server.isEstablished());
        // a close before the handshake is done goes in a long-header packet, which a client
        // without 1-RTT keys can still read
        server.closeApp(0x101);
        const m = server.pollTransmit(4000, &o).?;
        try std.testing.expect(o[0] & 0x80 != 0);
        try std.testing.expect(m >= 20);
        // and the client's Finished still completes a server that was not closed: covered by
        // the linkbench cold-connect test, which runs whole workloads with the switch on
    }
}

fn ackFrame(out: []u8, largest: u64, first_range: u64) usize {
    var q: usize = 0;
    out[q] = 0x02;
    q += 1;
    putVarint(out, &q, largest);
    putVarint(out, &q, 0);
    putVarint(out, &q, 0);
    putVarint(out, &q, first_range);
    return q;
}

test "PMTU probe: one PING+PADDING datagram of pmtu_max, its ACK raises the datagram size" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.pmtu_max = 1452;
    var out: [max_mtu]u8 = undefined;
    // a small buffer never carries a probe
    var small: [max_datagram]u8 = undefined;
    try std.testing.expect(c.pollTransmit(1_000_000, &small) == null);
    const n = c.pollTransmit(1_000_000, &out).?;
    try std.testing.expectEqual(@as(usize, 1452), n);
    try std.testing.expect(c.pmtu_inflight);
    try std.testing.expectEqual(@as(usize, max_datagram), c.mtu);
    // stream data still goes out at 1200 while the probe is in flight
    const id = try c.openBidi();
    const big: [4000]u8 = @splat(7);
    try c.streamWrite(id, &big, true);
    const n1 = c.pollTransmit(1_000_001, &out).?;
    try std.testing.expect(n1 > 1180 and n1 <= max_datagram);
    var ack: [32]u8 = undefined;
    sendTheirs(c, 0, ack[0..ackFrame(&ack, 0, 0)], 2_000_000);
    try std.testing.expectEqual(@as(usize, 1452), c.mtu);
    try std.testing.expect(!c.pmtu_inflight);
    const n2 = c.pollTransmit(2_000_001, &out).?;
    try std.testing.expect(n2 > 1430 and n2 <= 1452);
}

test "initial window: 10 datagrams capped at 14,720 bytes; the switch adds the difference when the size is raised" {
    try std.testing.expectEqual(@as(u64, 12_000), initialWindow(1200));
    try std.testing.expectEqual(@as(u64, 14_520), initialWindow(1452));
    try std.testing.expectEqual(@as(u64, 14_720), initialWindow(1472));
    try std.testing.expectEqual(@as(u64, 14_720), initialWindow(1500));
    try std.testing.expectEqual(@as(u64, 18_000), initialWindow(9000));
    const gpa = std.testing.allocator;
    var grown: [3]u64 = undefined;
    // off; on; on, but after a loss has ended slow start
    for ([_]bool{ false, true, true }, [_]bool{ false, false, true }, 0..) |on, after_loss, k| {
        const c = try testEstablished(gpa);
        defer c.deinit();
        c.cfg.iw_mtu = on;
        c.cfg.pmtu_max = 1452;
        try std.testing.expectEqual(initialWindow(max_datagram), c.cwnd);
        if (after_loss) c.ssthresh = c.cwnd;
        var out: [max_mtu]u8 = undefined;
        try std.testing.expectEqual(@as(?usize, 1452), c.pollTransmit(1_000_000, &out));
        const before = c.cwnd;
        var ack: [32]u8 = undefined;
        sendTheirs(c, 0, ack[0..ackFrame(&ack, 0, 0)], 2_000_000);
        try std.testing.expectEqual(@as(usize, 1452), c.mtu);
        grown[k] = c.cwnd - before;
    }
    // the probe's own acknowledgement grows the window as any packet's does; the switch adds
    // 14,520 - 12,000 on top, and only while the first slow start lasts
    try std.testing.expectEqual(grown[0] + 2_520, grown[1]);
    try std.testing.expect(grown[2] <= grown[0]);
}

test "pacing: a window leaves in bucket-sized runs spread over the round trip (RFC 9002 7.7)" {
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |paced| {
        const c = try testEstablished(gpa);
        defer c.deinit();
        c.cfg.pacing = paced;
        // a measured 40 ms round trip and a 100-datagram window in congestion avoidance
        c.rtt_initialized = true;
        c.srtt = 40 * ms;
        c.latest_rtt = 40 * ms;
        c.min_rtt = 40 * ms;
        c.rttvar = 1 * ms;
        c.cwnd = 100 * max_datagram;
        c.ssthresh = c.cwnd;
        const id = try c.openBidi();
        const chunk: [64 << 10]u8 = @splat(1);
        for (0..4) |_| try c.streamWrite(id, &chunk, false);
        var out: [max_mtu]u8 = undefined;
        const t0: u64 = 1_000_000;
        var now = t0;
        var first: u64 = 0;
        while (c.pollTransmit(now, &out)) |_| first += 1;
        if (!paced) {
            // the switch is off: the whole window in one burst, as before
            try std.testing.expect(first >= 100);
            try std.testing.expectEqual(@as(?u64, null), c.pace_at);
            continue;
        }
        // the bucket: 2 ms of 100 datagrams per 40 ms is 5, so the floor of 10 datagrams
        try std.testing.expectEqual(@as(u64, 10), first);
        // the next run is due when the bucket is full again: 10 datagrams at 1.25 windows per
        // round trip is 3.2 ms
        const due = c.nextTimeout().?;
        try std.testing.expect(due > now + 3 * ms and due <= now + 3200 * us);
        // one round trip without an ACK: runs of a bucket, the window and no more
        var total = first;
        var max_run = first;
        var runs: u64 = 1;
        while (c.nextTimeout()) |at| {
            if (at > t0 + 40 * ms) break;
            now = at;
            c.onTimeout(now);
            var run: u64 = 0;
            while (c.pollTransmit(now, &out)) |_| run += 1;
            total += run;
            max_run = @max(max_run, run);
            if (run > 0) runs += 1;
        }
        try std.testing.expect(max_run <= 11);
        try std.testing.expect(runs >= 9);
        try std.testing.expect(total >= 100 and total <= 102);
        try std.testing.expect(c.bytes_in_flight >= c.cwnd);
        // the window is full: nothing is pending for the pacer, only the probe timer
        try std.testing.expectEqual(@as(?u64, null), c.pace_at);
        // a probe timeout is not paced
        const pto = c.nextTimeout().?;
        c.onTimeout(pto);
        try std.testing.expect(c.pollTransmit(pto, &out) != null);
    }
}

test "cubic switch: a loss cuts the window to 0.7, once per round trip; off, NewReno halves" {
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |cubic| {
        const c = try testEstablished(gpa);
        defer c.deinit();
        c.cfg.cubic = cubic;
        c.cwnd = 100 * max_datagram;
        c.ssthresh = c.cwnd; // congestion avoidance
        const id = try c.openBidi();
        const chunk: [32 << 10]u8 = @splat(1);
        try c.streamWrite(id, &chunk, false);
        var out: [max_mtu]u8 = undefined;
        for (0..10) |_| _ = c.pollTransmit(1_000_000, &out).?;
        // the peer has 4..8: packets 0..3 are lost (three later packets acknowledged)
        var ack: [32]u8 = undefined;
        sendTheirs(c, 0, ack[0..ackFrame(&ack, 8, 4)], 2_000_000);
        try std.testing.expectEqual(@as(u64, 4), c.pkts_lost);
        const reduced = c.cwnd;
        if (cubic) {
            try std.testing.expectEqual(@as(u64, 70 * max_datagram), reduced);
            try std.testing.expectEqual(reduced, c.ssthresh);
        } else {
            // the old path: half (of a window the ACK had grown by a fraction of a datagram)
            try std.testing.expect(reduced >= 50 * max_datagram and reduced < 50 * max_datagram + 100);
        }
        // packet 9 (sent before the reduction) is lost as well: no second reduction
        for (0..3) |_| _ = c.pollTransmit(2_000_001, &out).?;
        sendTheirs(c, 1, ack[0..ackFrame(&ack, 12, 2)], 2_000_002);
        try std.testing.expectEqual(@as(u64, 5), c.pkts_lost);
        try std.testing.expectEqual(reduced, c.cwnd);
    }
}

test "path MTU search: a failed ceiling is followed by 1452 and halving; a black hole falls back to 1200" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.pmtud = true;
    c.cfg.pmtu_max = 1472;
    c.cfg.keep_alive_ms = 0;
    var out: [max_mtu]u8 = undefined;
    var ack: [32]u8 = undefined;
    var now: u64 = 1_000_000;
    var their_pn: u64 = 0;
    // A path that carries 1400 bytes. Each probe is followed by three small packets; the peer
    // acknowledges those, and the probe too when it fits.
    const path: usize = 1400;
    var sizes: [16]usize = undefined;
    var n_sizes: usize = 0;
    const id = try c.openBidi();
    var guard: usize = 0;
    while (c.pmtu_search_at == 0 and guard < 64) : (guard += 1) {
        const n = c.pollTransmit(now, &out) orelse break;
        try std.testing.expect(n > c.mtu); // a probe
        const probe_pn = c.spaces[2].next_pn - 1;
        if (n_sizes == 0 or sizes[n_sizes - 1] != n) {
            sizes[n_sizes] = n;
            n_sizes += 1;
        }
        for (0..3) |_| {
            try c.streamWrite(id, "x", false);
            const m = c.pollTransmit(now, &out).?;
            try std.testing.expect(m < 100);
        }
        now += 1_000_000;
        // ack the three small packets, and the probe with them when the path carried it
        const fits = n <= path;
        sendTheirs(c, their_pn, ack[0..ackFrame(&ack, probe_pn + 3, if (fits) 3 else 2)], now);
        their_pn += 1;
        now += 1_000_000;
    }
    try std.testing.expect(c.pmtu_search_at != 0);
    // 1472 three times, 1452 three times, then halving between 1200 and 1451
    try std.testing.expectEqualSlices(usize, &.{ 1472, 1452, 1326, 1389, 1420, 1404 }, sizes[0..n_sizes]);
    try std.testing.expectEqual(@as(usize, 1389), c.mtu);
    try std.testing.expect(path - c.mtu < pmtu_step);
    // nothing more is probed until the raise timer
    try std.testing.expect(c.pollTransmit(now, &out) == null);
    try std.testing.expectEqual(@as(u64, 0), c.pmtu_black_holes);

    // The route changes: full-size packets vanish, small ones still pass. Three loss events
    // without a full-size packet acknowledged and the connection is back at 1200.
    const big: [1380]u8 = @splat(7);
    for (0..3) |_| {
        c.cwnd = 1 << 20; // the losses below halve it; this test is not about the window
        try c.streamWrite(id, &big, false);
        const n = c.pollTransmit(now, &out).?;
        try std.testing.expect(n > max_datagram);
        const big_pn = c.spaces[2].next_pn - 1;
        for (0..3) |_| {
            try c.streamWrite(id, "y", false);
            _ = c.pollTransmit(now, &out).?;
        }
        now += 1_000_000;
        try std.testing.expectEqual(@as(usize, 1389), c.mtu);
        sendTheirs(c, their_pn, ack[0..ackFrame(&ack, big_pn + 3, 2)], now);
        their_pn += 1;
        // the lost range is resent at once; drain it so the next round starts clean
        while (c.pollTransmit(now, &out)) |_| {}
        now += 1_000_000;
    }
    try std.testing.expectEqual(@as(usize, max_datagram), c.mtu);
    try std.testing.expectEqual(@as(u64, 1), c.pmtu_black_holes);
    // the search starts again after the cooldown, not before
    try std.testing.expect(c.pmtu_search_at > now);
    // (the black hole was seen one step of this test's clock ago)
    try std.testing.expectEqual(now - 1_000_000 + pmtu_cooldown_ns, c.pmtu_search_at);
    now = c.pmtu_search_at - 1;
    while (c.pollTransmit(now, &out)) |n| try std.testing.expect(n <= max_datagram);
    // then from the ceiling again
    now += 1;
    try std.testing.expectEqual(@as(?usize, 1472), c.pollTransmit(now, &out));
}

test "path MTU search: two probe timeouts in a row at a raised size fall back to 1200; off, the size stays" {
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |search| {
        const c = try testEstablished(gpa);
        defer c.deinit();
        c.cfg.pmtud = search;
        c.cfg.keep_alive_ms = 0;
        c.mtu = 1452; // validated earlier on this connection
        const id = try c.openBidi();
        const big: [1400]u8 = @splat(3);
        try c.streamWrite(id, &big, false);
        var out: [max_mtu]u8 = undefined;
        var now: u64 = 1_000_000;
        try std.testing.expect(c.pollTransmit(now, &out).? > max_datagram);
        // nothing comes back, not even for the first probe timeout's probes
        for (0..2) |k| {
            try std.testing.expectEqual(@as(usize, 1452), c.mtu);
            now = c.nextTimeout().?;
            c.onTimeout(now);
            try std.testing.expectEqual(@as(u32, @intCast(k + 1)), c.pto_count);
            while (c.pollTransmit(now, &out)) |_| {}
        }
        try std.testing.expectEqual(@as(usize, if (search) max_datagram else 1452), c.mtu);
        try std.testing.expectEqual(@as(u64, if (search) 1 else 0), c.pmtu_black_holes);
        if (search) try std.testing.expectEqual(now + pmtu_cooldown_ns, c.pmtu_search_at);
    }
}

test "path MTU search off: one probe of pmtu_max, three tries, then 1200 for good (the old path)" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cfg.pmtu_max = 1452;
    c.cfg.keep_alive_ms = 0;
    var out: [max_mtu]u8 = undefined;
    var ack: [32]u8 = undefined;
    var now: u64 = 1_000_000;
    const id = try c.openBidi();
    for (0..3) |k| {
        const n = c.pollTransmit(now, &out).?;
        try std.testing.expectEqual(@as(usize, 1452), n);
        const probe_pn = c.spaces[2].next_pn - 1;
        for (0..3) |_| {
            try c.streamWrite(id, "x", false);
            _ = c.pollTransmit(now, &out).?;
        }
        now += 1_000_000;
        sendTheirs(c, k, ack[0..ackFrame(&ack, probe_pn + 3, 2)], now);
        now += 1_000_000;
    }
    try std.testing.expect(c.pollTransmit(now, &out) == null);
    try std.testing.expectEqual(@as(usize, max_datagram), c.mtu);
    try std.testing.expectEqual(@as(u8, 3), c.pmtu_tries);
}

test "ACK of a long in-flight run removes exactly the acked packets" {
    const gpa = std.testing.allocator;
    const c = try testEstablished(gpa);
    defer c.deinit();
    c.cwnd = 1 << 30;
    c.peer.max_stream_data_bidi_remote = 1 << 30;
    c.send_max_data = 1 << 30;
    const id = try c.openBidi();
    const chunk: [64 << 10]u8 = @splat(1);
    for (0..16) |_| try c.streamWrite(id, &chunk, false);
    var out: [max_mtu]u8 = undefined;
    var sent: u64 = 0;
    while (c.pollTransmit(1_000_000, &out)) |_| sent += 1;
    try std.testing.expect(sent > 800);
    try std.testing.expectEqual(sent, c.spaces[2].live().len);
    // ack [0, 499]: 500 leave from the front, the rest stay in order
    var ack: [32]u8 = undefined;
    sendTheirs(c, 0, ack[0..ackFrame(&ack, 499, 499)], 1_000_100);
    const live = c.spaces[2].live();
    try std.testing.expectEqual(sent - 500, live.len);
    for (live, 0..) |s, i| try std.testing.expectEqual(500 + i, s.pn);
    // ack the rest
    sendTheirs(c, 1, ack[0..ackFrame(&ack, sent - 1, sent - 501)], 1_000_200);
    try std.testing.expectEqual(@as(usize, 0), c.spaces[2].live().len);
    try std.testing.expectEqual(@as(u64, 0), c.bytes_in_flight);
}

// ------------------------------------------------------------------ request/response simulation

/// A zui/1-shaped exchange between a real client and a real server Connection over a simulated
/// link that drops, delays and reorders datagrams, and receivers that stall (a CPU-starved
/// process) with a bounded receive queue (the socket buffer). The client sends one request per
/// bidirectional stream and waits for the whole response; the server frees an answered stream
/// as the zui/1 listener does (`streamSettled`). Returns the slowest request in ns, or
/// error.Stalled when a request takes longer than `stall_ns` (the edge client's request timeout).
const SimOpts = struct {
    seed: u64,
    requests: usize = 120,
    drop_pct: u32 = 2,
    /// Percent of passes after which an endpoint sleeps up to `starve_ns` (CPU starvation).
    starve_pct: u32 = 5,
    starve_ns: u64 = 40 * std.time.ns_per_ms,
    /// Datagrams a receiver holds before the link drops more (SO_RCVBUF).
    rx_cap: usize = 160,
    max_resp: usize = 300 << 10,
    stall_ns: u64 = 20 * std.time.ns_per_s,
};

const SimStats = struct { slowest_ns: u64 = 0, dropped: u64 = 0, server_lost: u64 = 0, server_ptos: u64 = 0 };

fn simRequests(gpa: Allocator, o: SimOpts) !SimStats {
    var prng = std.Random.DefaultPrng.init(o.seed);
    const rnd = prng.random();
    const server_seed: [32]u8 = @splat(9);
    const skey = (try Ed25519.KeyPair.generateDeterministic(server_seed)).public_key.toBytes();
    var cseed: [64]u8 = undefined;
    rnd.bytes(&cseed);
    var now: u64 = 1_000_000_000;
    const client = try Connection.init(gpa, .{ .server_name = "zui", .identity_seed = @splat(4), .expected_peer = skey, .seed = cseed, .now_unix = 1_800_000_000, .alpn = &.{"zui/1"}, .max_streams_uni = 16, .max_streams_bidi = 64, .keep_alive_ms = 3_000, .pmtu_max = 1452 }, now);
    defer client.deinit();
    var server: ?*Connection = null;
    defer if (server) |s| s.deinit();

    const Pkt = struct { t: u64, to_server: bool, len: u16, data: [1500]u8 };
    var link: std.ArrayList(Pkt) = .empty;
    defer link.deinit(gpa);
    var rxq: [2]std.ArrayList(Pkt) = .{ .empty, .empty }; // 0 client, 1 server
    defer for (&rxq) |*q| q.deinit(gpa);
    var wake: [2]u64 = .{ 0, 0 };
    var st: SimStats = .{};

    // server application state
    var reqs: std.ArrayList(u64) = .empty;
    defer reqs.deinit(gpa);
    var answered: std.ArrayList(u64) = .empty;
    defer answered.deinit(gpa);
    var reqbuf: std.AutoHashMapUnmanaged(u64, std.ArrayList(u8)) = .empty;
    defer {
        var it = reqbuf.valueIterator();
        while (it.next()) |v| v.deinit(gpa);
        reqbuf.deinit(gpa);
    }
    // client application state
    var done: usize = 0;
    var cur: ?u64 = null;
    var cur_len: usize = 0;
    var cur_seed: u32 = 0;
    var started: u64 = 0;
    var resp: std.ArrayList(u8) = .empty;
    defer resp.deinit(gpa);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(gpa);

    var out: [1500]u8 = undefined;
    var iter: u64 = 0;
    while (done < o.requests) : (iter += 1) {
        if (iter > 50_000_000) return error.SimRunaway;
        // the link delivers what is due into the receivers' queues (a full queue drops)
        var i: usize = 0;
        while (i < link.items.len) {
            if (link.items[i].t > now) {
                i += 1;
                continue;
            }
            const p = link.swapRemove(i);
            const q = &rxq[@intFromBool(p.to_server)];
            if (q.items.len >= o.rx_cap) st.dropped += 1 else try q.append(gpa, p);
        }
        for (0..2) |side| {
            if (now < wake[side]) continue;
            const is_server = side == 1;
            for (rxq[side].items) |*p| {
                const d = p.data[0..p.len];
                if (is_server) {
                    if (server == null) {
                        // an Initial: create the server connection as the zui/1 listener does
                        const dl = d[5];
                        const dcid = d[6..][0..dl];
                        const sl = d[6 + dl];
                        const scid = d[7 + dl ..][0..sl];
                        var sseed: [64]u8 = undefined;
                        rnd.bytes(&sseed);
                        server = try Connection.initServer(gpa, .{ .server_name = "zui", .identity_seed = server_seed, .seed = sseed, .now_unix = 1_800_000_000, .max_streams_bidi = 128, .max_streams_uni = 16, .max_data = 16 << 20, .max_stream_data = 1 << 20, .idle_timeout_ms = 30_000, .keep_alive_ms = 0, .alpn = &.{"zui/1"}, .client_auth = false, .pmtu_max = 1452 }, now, dcid, scid);
                    }
                    server.?.handleDatagram(now, d);
                } else client.handleDatagram(now, d);
            }
            rxq[side].clearRetainingCapacity();
            const c = if (is_server) server orelse continue else client;
            if (c.nextTimeout()) |t| if (now >= t) c.onTimeout(now);
            if (c.isClosed()) return error.SimClosed;
            if (is_server and c.isEstablished()) {
                // the listener's deepwave branch: read requests, answer them, free settled streams
                while (c.acceptBidi()) |id| try reqs.append(gpa, id);
                var k: usize = 0;
                while (k < reqs.items.len) {
                    const id = reqs.items[k];
                    const s = c.stream(id) orelse {
                        _ = reqs.swapRemove(k);
                        continue;
                    };
                    const gop = try reqbuf.getOrPut(gpa, id);
                    if (!gop.found_existing) gop.value_ptr.* = .empty;
                    const data = s.recv.contiguous();
                    try gop.value_ptr.appendSlice(gpa, data);
                    s.recv.consume(data.len);
                    if (!s.recv.complete()) {
                        k += 1;
                        continue;
                    }
                    const rq = gop.value_ptr.items;
                    try std.testing.expectEqual(@as(usize, 8), rq.len);
                    const len = std.mem.readInt(u32, rq[0..4], .little);
                    const seed = std.mem.readInt(u32, rq[4..8], .little);
                    payload.clearRetainingCapacity();
                    try payload.resize(gpa, len);
                    for (payload.items, 0..) |*b, j| b.* = @truncate((j *% 131) ^ seed);
                    try c.streamWrite(id, payload.items, true);
                    try answered.append(gpa, id);
                    gop.value_ptr.deinit(gpa);
                    _ = reqbuf.remove(id);
                    _ = reqs.swapRemove(k);
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
                if (cur == null) {
                    const id = try c.openBidi();
                    cur_len = 1 + rnd.uintLessThan(usize, o.max_resp);
                    cur_seed = rnd.int(u32);
                    var rq: [8]u8 = undefined;
                    std.mem.writeInt(u32, rq[0..4], @intCast(cur_len), .little);
                    std.mem.writeInt(u32, rq[4..8], cur_seed, .little);
                    try c.streamWrite(id, &rq, true);
                    cur = id;
                    started = now;
                    resp.clearRetainingCapacity();
                }
                const id = cur.?;
                const s = c.stream(id) orelse return error.SimStreamGone;
                const data = s.recv.contiguous();
                try resp.appendSlice(gpa, data);
                s.recv.consume(data.len);
                if (s.recv.complete()) {
                    try std.testing.expectEqual(cur_len, resp.items.len);
                    for (resp.items, 0..) |b, j| if (b != @as(u8, @truncate((j *% 131) ^ cur_seed))) return error.SimCorrupt;
                    c.streamFree(id);
                    st.slowest_ns = @max(st.slowest_ns, now - started);
                    cur = null;
                    done += 1;
                } else if (now - started > o.stall_ns) {
                    st.slowest_ns = now - started;
                    if (server) |sv| {
                        st.server_lost = sv.pkts_lost;
                        st.server_ptos = sv.ptos;
                    }
                    std.debug.print("sim seed {d}: request {d} stalled {d} ms (got {d} of {d} bytes, server lost {d}, ptos {d})\n", .{ o.seed, done, st.slowest_ns / ms, resp.items.len, cur_len, st.server_lost, st.server_ptos });
                    return error.Stalled;
                }
            }
            // send everything; the link drops some and delays the rest by 0.1 to 3 ms (reorders)
            while (c.pollTransmit(now, &out)) |n| {
                if (rnd.uintLessThan(u32, 100) < o.drop_pct) {
                    st.dropped += 1;
                    continue;
                }
                var p: Pkt = .{ .t = now + 100_000 + rnd.uintLessThan(u64, 3 * ms), .to_server = !is_server, .len = @intCast(n), .data = undefined };
                @memcpy(p.data[0..n], out[0..n]);
                try link.append(gpa, p);
            }
            if (rnd.uintLessThan(u32, 100) < o.starve_pct) wake[side] = now + rnd.uintLessThan(u64, o.starve_ns);
        }
        // next event: a delivery, a timer or a wake-up, at least 20 us on
        var next: u64 = now + 5 * ms;
        for (link.items) |p| next = @min(next, p.t);
        if (client.nextTimeout()) |t| next = @min(next, t);
        if (server) |s| if (s.nextTimeout()) |t| {
            next = @min(next, t);
        };
        for (wake) |w| if (w > now) {
            next = @min(next, w);
        };
        if (rxq[0].items.len > 0 or rxq[1].items.len > 0) next = @min(next, @max(wake[0], wake[1]));
        now = @max(now + 20_000, next);
    }
    if (server) |sv| {
        st.server_lost = sv.pkts_lost;
        st.server_ptos = sv.ptos;
    }
    return st;
}

test "zui/1 requests over a lossy, reordering link with starved receivers all complete (edge 20 s stall)" {
    const gpa = std.testing.allocator;
    // ZUI_NET_SIM_SEEDS=N sweeps N seeds (default 12), ZUI_NET_SIM_DROP=pct the loss rate (2)
    const n: u64 = if (std.c.getenv("ZUI_NET_SIM_SEEDS")) |v| std.fmt.parseInt(u64, std.mem.span(v), 10) catch 12 else 12;
    const drop: u32 = if (std.c.getenv("ZUI_NET_SIM_DROP")) |v| std.fmt.parseInt(u32, std.mem.span(v), 10) catch 2 else 2;
    var worst: u64 = 0;
    var lost: u64 = 0;
    var seed: u64 = 1;
    while (seed <= n) : (seed += 1) {
        const st = try simRequests(gpa, .{ .seed = seed, .drop_pct = drop });
        // a lost tail costs a few PTOs at most, never the client's 20 s request timeout
        try std.testing.expect(st.slowest_ns < 5 * std.time.ns_per_s);
        worst = @max(worst, st.slowest_ns);
        lost += st.server_lost;
    }
    if (std.c.getenv("ZUI_NET_SIM_SEEDS") != null)
        std.debug.print("zui/1 sim: {d} seeds at {d}% drop, slowest request {d} ms, server packets lost {d}\n", .{ n, drop, worst / ms, lost });
}
