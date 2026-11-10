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
    /// RFC 9221 max_datagram_frame_size we advertise (0: not sent). Received DATAGRAM frames are
    /// dropped (WebTransport needs the parameter; zui/1 reserves datagrams).
    max_datagram_frame_size: u64 = 0,
    /// Path MTU probing target (RFC 9000 section 14.3, DPLPMTUD): once the handshake is confirmed
    /// one PING+PADDING datagram of this size is sent; its ACK raises the datagram size from
    /// 1200. 0: no probing (anemo keeps 1200). 1452 fits IPv6 over a 1500-byte Ethernet MTU.
    pmtu_max: u16 = 0,
};

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
};
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
    // receive side
    recv: buf.RecvBuf = .{},
    recv_limit: u64 = 0,
    reset: ?u64 = null,
    stopped_by_peer: ?u64 = null,

    fn deinit(s: *Stream, gpa: Allocator) void {
        s.send_buf.deinit(gpa);
        s.retx.deinit(gpa);
        s.recv.deinit(gpa);
    }

    fn hasPending(s: *const Stream) bool {
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
    handshake_confirmed: bool = false,
    /// Validated datagram size on the current path (`max_datagram` until a probe is acked).
    mtu: usize = max_datagram,
    pmtu_inflight: bool = false,
    pmtu_tries: u8 = 0,
    /// Freed streams kept with their buffer capacity for reuse (warm streams: a request stream
    /// costs no allocation once the connection has served a few).
    stream_pool: std.ArrayList(*Stream) = .empty,
    /// Counters for benches and logs: packets sent, declared lost, PTO expiries.
    pkts_sent: u64 = 0,
    pkts_lost: u64 = 0,
    ptos: u64 = 0,

    peer: PeerParams = .{},
    peer_tp_checked: bool = false,

    // server role (initServer)
    srv: ?*tls_srv.Server = null,
    /// The client's first destination connection id (its Initial keys and our
    /// original_destination_connection_id transport parameter).
    srv_odcid: [20]u8 = undefined,
    srv_odcid_len: u8 = 0,
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
    cwnd: u64 = 12_000,
    ssthresh: u64 = std.math.maxInt(u64),
    recovery_start: ?u64 = null,
    timer: ?u64 = null,

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
        c.tls = tls.Client.init(.{
            .server_name = cfg.server_name,
            .local_tp = c.local_tp[0..c.local_tp_len],
            .identity = kp,
            .cert_der = c.cert[0..c.cert_len],
            .expected_peer = cfg.expected_peer,
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
        const st = try gpa.create(tls_srv.Server);
        st.* = tls_srv.Server.init(.{
            .server_name = cfg.server_name,
            .local_tp = c.local_tp[0..c.local_tp_len],
            .identity = kp,
            .cert_der = c.cert[0..c.cert_len],
            .alpn = cfg.alpn,
            .client_auth = cfg.client_auth,
            .alt = cfg.alt,
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
        if (st.complete and c.spaces[2].send == null) {
            c.spaces[2].send = qc.PacketKeys.fromSecret(st.s_ap.?);
            c.spaces[2].recv = qc.PacketKeys.fromSecret(st.c_ap.?);
            try c.checkPeerParams();
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
            if (!std.mem.eql(u8, dcid, &c.scid) and !(c.srv_odcid_len != 0 and std.mem.eql(u8, dcid, c.srv_odcid[0..c.srv_odcid_len]))) return error.Drop;
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
            return error.Drop;
        };
        tr("  rx {s} pn={d} len={d}", .{ @tagName(space), pn, plain_len });
        if (rotated) {
            c.spaces[2].recv = use_keys;
            c.app_recv_next = null;
            c.recv_phase = !c.recv_phase;
            if (c.send_phase != c.recv_phase) {
                c.spaces[2].send = c.spaces[2].send.?.nextGeneration();
                c.send_phase = c.recv_phase;
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
                    if (c.streamFor(id, true)) |s| {
                        s.reset = code;
                        s.recv.fin_at = final;
                    }
                },
                0x05 => { // STOP_SENDING
                    const id = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    const code = getVarint(pl, &p) orelse return c.fail(0x07, "frame encoding");
                    eliciting = true;
                    if (c.streams.get(id)) |s| s.stopped_by_peer = code;
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
        try sp.crypto_in.insert(c.gpa, off, data);
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
        const end = off + len;
        if (end > s.recv_limit) return c.fail(0x03, "stream flow control");
        const before = s.recv.highest();
        s.recv.insert(c.gpa, off, data) catch return error.OutOfMemory;
        const after = s.recv.highest();
        if (after > before) {
            c.recv_data += after - before;
            if (c.recv_data > c.recv_max_data) return c.fail(0x03, "connection flow control");
        }
        if (fin) s.recv.fin_at = end;
        // window updates: raise when more than half consumed
        if (s.recv.highest() > s.recv_limit - c.cfg.max_stream_data / 2) {
            s.recv_limit = s.recv.highest() + c.cfg.max_stream_data;
            c.pending_msd.append(c.gpa, id) catch return error.OutOfMemory;
        }
        if (c.recv_data > c.recv_max_data - c.cfg.max_data / 2) {
            c.recv_max_data = c.recv_data + c.cfg.max_data;
            c.need_max_data = true;
        }
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
                for (s.recs[0..s.nrec]) |r| if (r == .pmtu) {
                    c.mtu = @max(c.mtu, r.pmtu);
                    c.pmtu_inflight = false;
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
            c.onAckedBytes(now, acked_bytes);
        }
        c.detectLoss(now, space);
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

    fn onAckedBytes(c: *Connection, now: u64, bytes: u64) void {
        _ = now;
        if (c.recovery_start != null) return; // simplified: no growth while in recovery
        if (c.cwnd < c.ssthresh) {
            c.cwnd += bytes;
        } else {
            c.cwnd += c.mtu * bytes / c.cwnd;
        }
    }

    fn onLostPacket(c: *Connection, now: u64, s: Sent, space: Space) void {
        c.pkts_lost += 1;
        if (s.in_flight) c.bytes_in_flight -|= s.size;
        // requeue payload
        for (s.recs[0..s.nrec]) |r| switch (r) {
            .crypto => |cr| c.spaces[@intFromEnum(space)].crypto_retx.append(c.gpa, .{ .start = cr.off, .end = cr.off + cr.len }) catch {},
            .stream => |sr| if (c.streams.get(sr.id)) |st| {
                st.retx.append(c.gpa, .{ .start = sr.off, .end = sr.off + sr.len }) catch {};
                if (sr.fin) st.fin_sent = false;
            },
            .max_data => c.need_max_data = true,
            .max_stream_data => |id| c.pending_msd.append(c.gpa, id) catch {},
            .max_streams_uni => c.need_max_streams_uni = true,
            .max_streams_bidi => c.need_max_streams_bidi = true,
            .retire_cid => |seq| c.pending_retire.append(c.gpa, seq) catch {},
            .handshake_done => c.need_handshake_done = true,
            .pmtu => {
                c.pmtu_inflight = false;
                c.pmtu_tries += 1;
                return; // a lost probe says nothing about congestion (RFC 9000 section 14.4)
            },
        };
        // congestion event
        if (c.recovery_start == null or s.time > c.recovery_start.?) {
            c.recovery_start = now;
            c.cwnd = @max(c.cwnd / 2, 2 * c.mtu);
            c.ssthresh = c.cwnd;
        }
    }

    fn detectLoss(c: *Connection, now: u64, space: Space) void {
        const sp = &c.spaces[@intFromEnum(space)];
        sp.loss_time = null;
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
        if (c.spaces[2].ack_needed) if (c.spaces[2].ack_deadline) |t| {
            best = if (best) |b| @min(b, t) else t;
        };
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
            } else {
                // PTO
                var space: Space = .initial;
                var best: ?u64 = null;
                for (c.spaces, 0..) |s, i| {
                    if (s.discarded or s.send == null) continue;
                    if (s.ack_eliciting_in_flight == 0 and !(c.state == .handshaking and !c.handshake_confirmed)) continue;
                    const tt = s.time_last_ack_eliciting + c.ptoDuration(@enumFromInt(i));
                    if (best == null or tt < best.?) {
                        best = tt;
                        space = @enumFromInt(i);
                    }
                }
                c.pto_count += 1;
                c.ptos += 1;
                const sp = &c.spaces[@intFromEnum(space)];
                sp.probe = 2;
                if (space != .app) {
                    // retransmit unacked handshake data
                    for (sp.live()) |s| for (s.recs[0..s.nrec]) |r| switch (r) {
                        .crypto => |cr| sp.crypto_retx.append(c.gpa, .{ .start = cr.off, .end = cr.off + cr.len }) catch {},
                        else => {},
                    };
                }
            }
            c.updateTimer(now);
        };
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
        if (!c.addr_validated and c.amp_sent + max_datagram > 3 * c.amp_recv) return null;
        if (c.pmtuProbeDue(out.len)) return c.buildProbe(now, out);
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
        if (np == 0) return null;
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

    fn pmtuProbeDue(c: *const Connection, out_len: usize) bool {
        const target = c.cfg.pmtu_max;
        return target > c.mtu and out_len >= target and target <= max_mtu and c.handshake_confirmed and
            !c.pmtu_inflight and c.pmtu_tries < 3 and c.peer.max_udp_payload >= target and
            c.spaces[2].send != null and c.state == .established;
    }

    /// PING + PADDING filling exactly `cfg.pmtu_max` bytes.
    fn buildProbe(c: *Connection, now: u64, out: []u8) usize {
        const target: usize = c.cfg.pmtu_max;
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
        const can_send = c.bytes_in_flight < c.cwnd or sp.probe > 0;
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
        }
        // PING for probes
        if (sp.probe > 0 and !plan.eliciting and p + 1 <= lim) {
            f[p] = 0x01;
            p += 1;
            plan.eliciting = true;
        }
        if (plan.eliciting and sp.probe > 0) sp.probe -= 1;
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
                c.pending_retire.insert(c.gpa, 0, seq) catch {};
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
        while (c.pending_msd.items.len > 0 and p + 17 <= lim) {
            const id = c.pending_msd.orderedRemove(0);
            const s = c.streams.get(id) orelse continue;
            if (!plan.addRec(.{ .max_stream_data = id })) {
                c.pending_msd.insert(c.gpa, 0, id) catch {};
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
            } else if (@as(u64, take) == end - start) {
                _ = s.retx.orderedRemove(0);
            } else s.retx.items[0].start += take;
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

    /// Serialises one packet; returns bytes written.
    fn writePacket(c: *Connection, now: u64, plan: *Plan, out: []u8) usize {
        const sp = &c.spaces[@intFromEnum(plan.space)];
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
            sp.sent.append(c.gpa, rec) catch {};
            sp.time_last_ack_eliciting = now;
            sp.ack_eliciting_in_flight += 1;
            c.bytes_in_flight += total;
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
            var ranges = s.recv.ranges;
            send_buf.clearRetainingCapacity();
            retx.clearRetainingCapacity();
            data.clearRetainingCapacity();
            ranges.clearRetainingCapacity();
            s.* = .{ .id = id, .send_buf = send_buf, .retx = retx };
            s.recv.data = data;
            s.recv.ranges = ranges;
            return s;
        }
        const s = try c.gpa.create(Stream);
        s.* = .{ .id = id };
        return s;
    }

    /// Keeps a freed stream for reuse (bounded pool; big buffers go back to the allocator).
    fn recycle(c: *Connection, s: *Stream) void {
        const big = s.send_buf.capacity > 64 << 10 or s.recv.data.capacity > 64 << 10;
        if (!big and c.stream_pool.items.len < 64) {
            if (c.stream_pool.append(c.gpa, s)) |_| return else |_| {}
        }
        s.deinit(c.gpa);
        c.gpa.destroy(s);
    }

    pub fn stream(c: *Connection, id: u64) ?*Stream {
        return c.streams.get(id);
    }

    /// Appends `data` to the stream's send buffer (copied) and optionally finishes the stream.
    pub fn streamWrite(c: *Connection, id: u64, data: []const u8, fin: bool) Error!void {
        const s = c.streams.get(id) orelse return error.InvalidStream;
        try s.send_buf.appendSlice(c.gpa, data);
        if (fin) s.fin_queued = true;
    }

    /// Bytes written to the stream that have not been sent yet (a long-lived stream's backlog).
    pub fn streamUnsent(c: *Connection, id: u64) u64 {
        const s = c.streams.get(id) orelse return 0;
        return s.send_base + s.send_buf.items.len - s.send_off;
    }

    /// Drops the stream's sent bytes that no packet in flight or pending retransmission still
    /// needs, so a long-lived send stream (a subscription) keeps a bounded buffer. Cheap enough
    /// to call when the buffer passes a threshold (scans the 1-RTT sent list once).
    pub fn streamTrim(c: *Connection, id: u64) void {
        const s = c.streams.get(id) orelse return;
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

    /// Next peer-initiated unidirectional stream id, if any.
    pub fn acceptUni(c: *Connection) ?u64 {
        if (c.incoming_uni.items.len == 0) return null;
        return c.incoming_uni.orderedRemove(0);
    }
    pub fn acceptBidi(c: *Connection) ?u64 {
        if (c.incoming_bidi.items.len == 0) return null;
        return c.incoming_bidi.orderedRemove(0);
    }

    /// Releases a finished stream and credits the peer with a new stream slot.
    pub fn streamFree(c: *Connection, id: u64) void {
        const kv = c.streams.fetchSwapRemove(id) orelse return;
        c.recycle(kv.value);
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
