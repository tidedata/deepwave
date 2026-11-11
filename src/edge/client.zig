//! zui/1 client over raw QUIC (ALPN `zui/1`, server pinned by its Ed25519 key) and the core pool an
//! edge node follows (docs/EDGE.md section 4).
//!
//! `Conn` is one connection: single threaded, one request per bidirectional stream, answers
//! read to the end. `Pool` keeps up to `max_conns` of them to a list of cores (or other edges),
//! all in one process-wide failover order: a connection that fails is dropped and the request is
//! retried on the next core, so one dead or slow box costs a timeout, not a stall. Nothing a core
//! says is trusted: the pool only moves bytes, the follower verifies them (docs/EDGE.md section 5).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const net = @import("net");
const native = @import("native");
const edgewire = @import("edgewire");
const proto = native.proto;
const conn_mod = net.conn;
const dict = edgewire.dict;
const feed = edgewire.feed;

pub const Error = error{
    HandshakeFailed,
    Timeout,
    StreamGone,
    Closed,
    BadResponse,
    BadSpec,
    /// The server answered with an error status.
    Server,
    /// The server has no edge feed (hello feature bit 13 clear).
    NoEdgeFeed,
    WrongChain,
    BadData,
    NoCores,
    TooLarge,
    /// Below the server's retention (PRUNED): it will never hold it.
    Pruned,
} || Allocator.Error;

pub const feature_edge_feed: u64 = 1 << 32;
/// One response (a checkpoint feed, or a dictionary) never needs more; a core cannot make an edge
/// buffer more than this per request.
const response_max: usize = 96 << 20;

/// A core: where it listens and its zui/1 key (Ed25519, what the node prints as `zui/1 key`).
pub const Spec = struct {
    addr: Io.net.IpAddress,
    key: [32]u8,
};

/// `ADDR:PORT/KEYHEX[,ADDR:PORT/KEYHEX...]` (IP literals; IPv6 as `[::1]:4433`).
pub fn parseSpecs(gpa: Allocator, text: []const u8) Error![]Spec {
    var out: std.ArrayList(Spec) = .empty;
    errdefer out.deinit(gpa);
    var it = std.mem.splitScalar(u8, text, ',');
    while (it.next()) |part| {
        const t = std.mem.trim(u8, part, " \t");
        if (t.len == 0) continue;
        const slash = std.mem.indexOfScalar(u8, t, '/') orelse return error.BadSpec;
        const hostport = t[0..slash];
        const colon = std.mem.lastIndexOfScalar(u8, hostport, ':') orelse return error.BadSpec;
        var host = hostport[0..colon];
        if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host = host[1 .. host.len - 1];
        const port = std.fmt.parseInt(u16, hostport[colon + 1 ..], 10) catch return error.BadSpec;
        const addr = Io.net.IpAddress.parse(host, port) catch return error.BadSpec;
        var key: [32]u8 = undefined;
        const kh = t[slash + 1 ..];
        if (kh.len != 64) return error.BadSpec;
        _ = std.fmt.hexToBytes(&key, kh) catch return error.BadSpec;
        try out.append(gpa, .{ .addr = addr, .key = key });
    }
    if (out.items.len == 0) return error.BadSpec;
    return out.toOwnedSlice(gpa);
}

fn nowNs(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).toNanoseconds());
}

/// What a hello told us.
pub const Hello = struct {
    chain_id: [32]u8,
    lowest: u64,
    highest: u64,
    epoch: u64,
    features: u64,
    /// The dictionary the server advertises (kind 1), if any.
    dict_id: u32 = 0,
    dict_sha256: [32]u8 = @splat(0),
    dict_size: u32 = 0,
};

/// One zui/1 connection. Not thread safe.
pub const Conn = struct {
    gpa: Allocator,
    io: Io,
    sock: Io.net.Socket,
    addr: Io.net.IpAddress,
    c: *conn_mod.Connection,
    us: net.udpio.Sock,
    tx: net.udpio.TxBatch = .{},
    rx: net.udpio.RxBatch = .{},
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    hello: Hello = undefined,
    request_timeout_ms: u64 = 20_000,
    /// A request whose response makes no progress (no new byte) for this long fails with
    /// `Timeout`. 0: off (only `request_timeout_ms` bounds a request).
    stall_ms: u64 = 0,
    /// Monotonic ns: a request that has no response byte by then fails with `Timeout` (the
    /// caller's deadline for an answer to start; a response under way is left to `stall_ms`).
    first_byte_by: u64 = std.math.maxInt(u64),
    /// When the last request last received a response byte (monotonic ns; 0: it never did).
    last_progress: u64 = 0,
    /// The owner's stop flag (the pool's, the prober's): once it is set, a request in progress
    /// fails with `Closed` at its next turn (one pump, 5 ms) instead of at a timeout. A stop
    /// never waits on the network.
    stop: ?*const Atomic(bool) = null,
    /// When the last `requestMany` got its first response byte (monotonic ns; 0: it never did).
    first_byte_ns: u64 = 0,

    pub fn connect(gpa: Allocator, io: Io, spec: Spec, connect_timeout_ms: u64) Error!*Conn {
        return connectStop(gpa, io, spec, connect_timeout_ms, null);
    }

    /// `connect` that gives up (`Closed`) once `stop` is set; the connection keeps the flag.
    pub fn connectStop(gpa: Allocator, io: Io, spec: Spec, connect_timeout_ms: u64, stop: ?*const Atomic(bool)) Error!*Conn {
        const cl = try gpa.create(Conn);
        errdefer gpa.destroy(cl);
        var any: Io.net.IpAddress = switch (spec.addr) {
            .ip4 => .{ .ip4 = Io.net.Ip4Address.unspecified(0) },
            .ip6 => .{ .ip6 = Io.net.Ip6Address.unspecified(0) },
        };
        const sock = Io.net.IpAddress.bind(&any, io, .{ .mode = .dgram }) catch return error.HandshakeFailed;
        errdefer sock.close(io);
        var seed: [64]u8 = undefined;
        io.random(&seed);
        var idseed: [32]u8 = undefined;
        io.random(&idseed);
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
        const c = conn_mod.Connection.init(gpa, .{
            .server_name = "zui",
            .identity_seed = idseed,
            .expected_peer = spec.key,
            .seed = seed,
            .now_unix = now_unix,
            .alpn = &.{proto.alpn},
            .max_streams_uni = 16,
            .max_streams_bidi = 64,
            .keep_alive_ms = 3_000,
            .pmtu_max = 1452,
        }, nowNs(io)) catch return error.HandshakeFailed;
        cl.* = .{ .gpa = gpa, .io = io, .sock = sock, .addr = spec.addr, .c = c, .us = .init(sock.handle), .stop = stop };
        errdefer c.deinit();
        const deadline = nowNs(io) + connect_timeout_ms * std.time.ns_per_ms;
        while (!c.isEstablished()) {
            if (cl.stopped()) return error.Closed;
            if (c.isClosed() or nowNs(io) > deadline) return error.HandshakeFailed;
            try cl.pump(10);
        }
        return cl;
    }

    fn stopped(cl: *const Conn) bool {
        return if (cl.stop) |s| s.load(.acquire) else false;
    }

    pub fn close(cl: *Conn) void {
        cl.c.closeApp(0);
        cl.send(nowNs(cl.io));
        cl.c.deinit();
        cl.sock.close(cl.io);
        cl.gpa.destroy(cl);
    }

    pub fn alive(cl: *const Conn) bool {
        return !cl.c.isClosed();
    }

    /// The server closed this connection saying it is shutting down (the listener's stop sends
    /// CONNECTION_CLOSE with zui/1 `shutdown`): it is going away, not slow.
    pub fn peerShutdown(cl: *const Conn) bool {
        const ci = cl.c.close orelse return false;
        return ci.remote and ci.app and ci.code == @intFromEnum(proto.Code.shutdown);
    }

    fn send(cl: *Conn, now: u64) void {
        while (true) {
            if (cl.tx.full()) cl.tx.flush(&cl.us);
            const n = cl.c.pollTransmit(now, cl.tx.slot()) orelse break;
            cl.tx.commit(n, &cl.addr);
            cl.bytes_out += n;
        }
        cl.tx.flush(&cl.us);
    }

    /// Sends what is queued, then one batched receive that blocks up to `wait_ms` (or the next timer).
    fn pump(cl: *Conn, wait_ms: i32) Error!void {
        var now = nowNs(cl.io);
        cl.send(now);
        var wait: u64 = @as(u64, @intCast(wait_ms)) * std.time.ns_per_ms;
        if (cl.c.nextTimeout()) |t| wait = @min(wait, t -| now);
        const block = wait >= std.time.ns_per_ms;
        if (block) cl.us.setWait(wait);
        var n = cl.rx.recv(&cl.us, block);
        while (n > 0) {
            now = nowNs(cl.io);
            for (0..n) |i| {
                const d = cl.rx.data(i);
                cl.bytes_in += d.len;
                cl.c.handleDatagram(now, d);
            }
            if (n < net.udpio.max_batch) break;
            n = cl.rx.recv(&cl.us, false);
        }
        now = nowNs(cl.io);
        if (cl.c.nextTimeout()) |t| if (now >= t) cl.c.onTimeout(now);
        cl.send(now);
    }

    /// One request; the whole response (status byte, flags varint, body), owned by `a`.
    pub fn request(cl: *Conn, a: Allocator, m: proto.Method, flags: u64, body: []const u8) Error![]u8 {
        const id = cl.c.openBidi() catch return error.Closed;
        defer cl.c.streamFree(id);
        var req: std.ArrayList(u8) = .empty;
        try proto.encodeRequest(&req, a, m, flags, body);
        cl.c.streamWrite(id, req.items, true) catch return error.Closed;
        var resp: std.ArrayList(u8) = .empty;
        const start = nowNs(cl.io);
        const deadline = start + cl.request_timeout_ms * std.time.ns_per_ms;
        var progress = start;
        cl.last_progress = 0;
        while (true) {
            const st = cl.c.stream(id) orelse return error.StreamGone;
            const d = st.recv.contiguous();
            if (d.len > 0) {
                if (resp.items.len + d.len > response_max) return error.TooLarge;
                try resp.appendSlice(a, d);
                st.recv.consume(d.len);
                progress = nowNs(cl.io);
                cl.last_progress = progress;
            }
            if (st.recv.complete()) break;
            if (cl.c.isClosed() or cl.stopped()) return error.Closed;
            const now = nowNs(cl.io);
            if (now > deadline) return error.Timeout;
            if (cl.stall_ms != 0 and now -| progress > cl.stall_ms * std.time.ns_per_ms) return error.Timeout;
            if (resp.items.len == 0 and now > cl.first_byte_by) return error.Timeout;
            try cl.pump(5);
        }
        return resp.items;
    }

    /// One request of a pipelined call (`requestMany`).
    pub const Piped = struct {
        /// The encoded request (`proto.encodeRequest`).
        req: []const u8,
        id: u64 = 0,
        /// The whole response (status byte, flags varint, body), owned by the call's allocator.
        resp: std.ArrayList(u8) = .empty,
        done: bool = false,
    };

    /// Sends every request of `ps`, each on its own stream, then reads every response to the
    /// end: the round trip is paid once for all of them. The timeouts are `request`'s, with
    /// progress counted over the whole call (a byte on any stream). An error leaves the
    /// connection with responses half read: the caller closes it.
    pub fn requestMany(cl: *Conn, a: Allocator, ps: []Piped) Error!void {
        var opened: usize = 0;
        defer for (ps[0..opened]) |*p| cl.c.streamFree(p.id);
        for (ps) |*p| {
            p.id = cl.c.openBidi() catch return error.Closed;
            opened += 1;
            cl.c.streamWrite(p.id, p.req, true) catch return error.Closed;
        }
        const start = nowNs(cl.io);
        const deadline = start + cl.request_timeout_ms * std.time.ns_per_ms;
        var progress = start;
        cl.last_progress = 0;
        cl.first_byte_ns = 0;
        var left = ps.len;
        while (left > 0) {
            for (ps) |*p| {
                if (p.done) continue;
                const st = cl.c.stream(p.id) orelse return error.StreamGone;
                const d = st.recv.contiguous();
                if (d.len > 0) {
                    if (p.resp.items.len + d.len > response_max) return error.TooLarge;
                    try p.resp.appendSlice(a, d);
                    st.recv.consume(d.len);
                    progress = nowNs(cl.io);
                    cl.last_progress = progress;
                    if (cl.first_byte_ns == 0) cl.first_byte_ns = progress;
                }
                if (st.recv.complete()) {
                    p.done = true;
                    left -= 1;
                }
            }
            if (left == 0) break;
            if (cl.c.isClosed() or cl.stopped()) return error.Closed;
            const now = nowNs(cl.io);
            if (now > deadline) return error.Timeout;
            if (cl.stall_ms != 0 and now -| progress > cl.stall_ms * std.time.ns_per_ms) return error.Timeout;
            if (cl.first_byte_ns == 0 and now > cl.first_byte_by) return error.Timeout;
            try cl.pump(5);
        }
    }

    /// Sends hello and records what it says.
    pub fn doHello(cl: *Conn, a: Allocator) Error!void {
        var b: std.ArrayList(u8) = .empty;
        const w: proto.W = .{ .gpa = a, .out = &b };
        try w.str("zui-edge/0.1");
        try w.int(u16, proto.minor);
        try w.u8_(0);
        const resp = try cl.request(a, .hello, 0, b.items);
        const r = proto.parseResponse(resp) orelse return error.BadResponse;
        if (r.status != 0) return error.Server;
        var rd: proto.R = .{ .b = r.body };
        const bad = error.BadResponse;
        _ = rd.str() catch return bad;
        _ = rd.int(u16) catch return bad;
        var h: Hello = undefined;
        h.chain_id = (rd.fixed(32) catch return bad).*;
        h.lowest = rd.int(u64) catch return bad;
        h.highest = rd.int(u64) catch return bad;
        h.epoch = rd.int(u64) catch return bad;
        h.features = rd.int(u64) catch return bad;
        _ = rd.int(u32) catch return bad;
        _ = rd.int(u32) catch return bad;
        _ = rd.int(u32) catch return bad;
        _ = rd.int(u32) catch return bad;
        _ = rd.int(u64) catch return bad;
        const nd = rd.uleb() catch return bad;
        h.dict_id = 0;
        h.dict_sha256 = @splat(0);
        h.dict_size = 0;
        for (0..@as(usize, @intCast(@min(nd, 16)))) |_| {
            const id = rd.int(u32) catch return bad;
            const kind = rd.u8_() catch return bad;
            const sha = (rd.fixed(32) catch return bad).*;
            const size = rd.int(u32) catch return bad;
            if (kind == 1 and h.dict_id == 0) {
                h.dict_id = id;
                h.dict_sha256 = sha;
                h.dict_size = size;
            }
        }
        cl.hello = h;
    }

    /// The dictionary `id` from the server (checked against `sha256`), as a ready dictionary.
    pub fn fetchDictionary(cl: *Conn, a: Allocator, gpa: Allocator, id: u32, sha256: [32]u8) Error!dict.Dictionary {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, id, .little);
        const resp = try cl.request(a, .get_dictionary, 0, &b);
        const r = proto.parseResponse(resp) orelse return error.BadResponse;
        if (r.status != 0) return error.Server;
        var rd: proto.R = .{ .b = r.body };
        const content = rd.bytes() catch return error.BadResponse;
        rd.done() catch return error.BadResponse;
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(content, &h, .{});
        if (!std.mem.eql(u8, &h, &sha256)) return error.BadData;
        const d = dict.Dictionary.init(gpa, content, 3) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadData,
        };
        if (d.id != id) {
            var dd = d;
            dd.deinit(gpa);
            return error.BadData;
        }
        return d;
    }

    /// Highest committed checkpoint and whether `seq` is held, by `get_checkpoint` with no parts
    /// (the summary only: a few hundred bytes).
    pub fn hasCheckpoint(cl: *Conn, a: Allocator, seq: u64) Error!bool {
        var b: std.ArrayList(u8) = .empty;
        const w: proto.W = .{ .gpa = a, .out = &b };
        try w.uleb(1);
        try w.int(u64, seq);
        try w.u8_(0);
        const resp = try cl.request(a, .get_checkpoint, 0, b.items);
        const r = proto.parseResponse(resp) orelse return error.BadResponse;
        // below the server's retention: not held (a source answer, not a server failure)
        if (r.status == @intFromEnum(proto.Code.pruned)) return false;
        if (r.status != 0) return error.Server;
        if (r.body.len < 1) return error.BadResponse;
        return r.body[0] == 1;
    }

    /// The feed of `seq`: null when the server does not hold it yet. Frames are decoded with
    /// `dicts` (a dictionary the server named in hello).
    pub fn getFeed(cl: *Conn, a: Allocator, seq: u64, want: ?*const dict.Dictionary, zstd_ok: bool) Error!?[]u8 {
        var b: [12]u8 = undefined;
        std.mem.writeInt(u64, b[0..8], seq, .little);
        std.mem.writeInt(u32, b[8..12], if (want) |d| d.id else 0, .little);
        const resp = try cl.request(a, .get_checkpoint_feed, if (zstd_ok) proto.flag_zstd_ok else 0, &b);
        const r = proto.parseResponse(resp) orelse return error.BadResponse;
        if (r.status == @intFromEnum(proto.Code.pruned)) return error.Pruned;
        if (r.status != 0) return error.Server;
        var rd: proto.R = .{ .b = r.body };
        if (!(rd.option() catch return error.BadResponse)) return null;
        const body = rd.bytes() catch return error.BadResponse;
        rd.done() catch return error.BadResponse;
        // With flag_zstd_ok the body is a dict.zig frame. The header carries no ZSTD flag for it
        // (spec 2.2: the feed is self-framed); cores before that set it, which changes nothing here.
        if (!zstd_ok) return @constCast(body);
        return dict.decompress(a, want, body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TooLarge => return error.TooLarge,
            else => return error.BadData,
        };
    }
};

pub const Result = enum { ok, missing };

/// What a failed `fetchBlobBy` can tell its caller beyond the error.
pub const Fail = struct {
    /// When the failed feed request last received a response byte (monotonic ns; 0: it never
    /// did, or no request was sent). A response that was under way means the core answered
    /// until then.
    progress_ns: u64 = 0,
};

pub const Stats = struct {
    requests: Atomic(u64) = .init(0),
    failovers: Atomic(u64) = .init(0),
    wire_bytes: Atomic(u64) = .init(0),
    raw_bytes: Atomic(u64) = .init(0),
    blob_bytes: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
};

/// The cores an edge follows and a few connections to them. Thread safe: every fetching thread
/// takes a free slot for the length of one request.
pub const Pool = struct {
    gpa: Allocator,
    io: Io,
    specs: []Spec,
    /// All cores must serve this chain (digest of checkpoint 0); null: unchecked.
    chain_id: ?[32]u8 = null,
    slots: []Slot,
    /// Index into `specs` the next new connection tries first (moves on after a failure).
    pref: Atomic(u32) = .init(0),
    stats: Stats = .{},
    /// Highest checkpoint a core actually served (a feed that decoded for that sequence number).
    /// Hello heights are claims and never land here; see `hints`.
    highest_seen: Atomic(u64) = .init(0),
    /// Per core: the highest checkpoint its last hello claimed. Only a hint for whether asking
    /// another core after a "not yet" is worth a connection; never evidence a checkpoint exists.
    hints: []Atomic(u64),
    /// Last time a "not yet" made a fetcher try the other cores without a hint pointing at one.
    last_sweep_ns: Atomic(u64) = .init(0),
    last_pruned_log_ns: Atomic(u64) = .init(0),
    /// Which core served each recent checkpoint (`blame`).
    served: [served_n]Served = @splat(.{}),
    /// Cores excluded for one checkpoint after its feed failed verification.
    excl_seq: Atomic(u64) = .init(std.math.maxInt(u64)),
    excl_mask: Atomic(u64) = .init(0),
    dicts_mu: std.atomic.Mutex = .unlocked,
    dicts: std.ArrayList(*dict.Dictionary) = .empty,
    use_zstd: bool = true,
    connect_timeout_ms: u64 = 5_000,
    /// `Conn.stall_ms` of every connection the pool opens (0: off). Set before the first request.
    stall_ms: u64 = 0,
    /// Monotonic ns at which a core last closed a connection saying it is shutting down (0:
    /// never). A caller with a fallback takes it as "that core is going away now".
    shutdown_ns: Atomic(u64) = .init(0),
    /// The last checkpoint every core answered PRUNED for (below each one's retention: no core
    /// will ever hold it).
    pruned_seq: Atomic(u64) = .init(std.math.maxInt(u64)),
    /// Bumped by `retire`: a connection opened under an older value is closed at its next use.
    gen: Atomic(u32) = .init(0),
    /// Set by `stop` (the node is shutting down): every call in progress and every later one
    /// fails with `Closed` within a few milliseconds.
    stopping: Atomic(bool) = .init(false),

    /// No deadline: the pool's own timeouts bound a call.
    pub const no_deadline: u64 = std.math.maxInt(u64);

    const served_n = 64;
    const Served = struct {
        seq: Atomic(u64) = .init(std.math.maxInt(u64)),
        core: Atomic(u32) = .init(0),
    };

    const Slot = struct {
        busy: Atomic(bool) = .init(false),
        /// Index into `specs` of the core `conn` talks to.
        idx: u32 = 0,
        conn: ?*Conn = null,
        dict: ?*const dict.Dictionary = null,
        /// `Pool.gen` when `conn` was opened.
        gen: u32 = 0,
    };

    pub fn init(gpa: Allocator, io: Io, specs: []const Spec, max_conns: u32) Allocator.Error!*Pool {
        const p = try gpa.create(Pool);
        errdefer gpa.destroy(p);
        const own = try gpa.dupe(Spec, specs);
        errdefer gpa.free(own);
        const slots = try gpa.alloc(Slot, @max(max_conns, 1));
        errdefer gpa.free(slots);
        for (slots) |*s| s.* = .{};
        const hints = try gpa.alloc(Atomic(u64), own.len);
        for (hints) |*h| h.* = .init(0);
        p.* = .{ .gpa = gpa, .io = io, .specs = own, .slots = slots, .hints = hints };
        return p;
    }

    pub fn deinit(p: *Pool) void {
        for (p.slots) |*s| if (s.conn) |c| c.close();
        for (p.dicts.items) |d| {
            d.deinit(p.gpa);
            p.gpa.destroy(d);
        }
        p.dicts.deinit(p.gpa);
        p.gpa.free(p.slots);
        p.gpa.free(p.hints);
        p.gpa.free(p.specs);
        p.gpa.destroy(p);
    }

    /// Ends every call on the pool, in progress or not yet made: a connect, a request waiting
    /// for its response and a thread waiting for a free connection all return `Closed` at their
    /// next turn (10 ms at most). Until this existed a stop waited for whatever the network did:
    /// a fetcher inside a request to a core that had gone silent held the node's shutdown for
    /// the fallback's grace (3 s), or with no fallback for the connect and request timeouts
    /// (5 s and 20 s per core), past the node's stop deadline. Connections are closed by `deinit`.
    pub fn stop(p: *Pool) void {
        p.stopping.store(true, .release);
    }

    fn stopped(p: *const Pool) bool {
        return p.stopping.load(.acquire);
    }

    fn acquire(p: *Pool) Error!*Slot {
        while (true) {
            if (p.stopped()) return error.Closed;
            for (p.slots) |*s| if (s.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return s;
            p.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    fn release(s: *Slot) void {
        s.busy.store(false, .release);
    }

    fn noteHighest(p: *Pool, seq: u64) void {
        var cur = p.highest_seen.load(.monotonic);
        while (seq > cur) cur = p.highest_seen.cmpxchgWeak(cur, seq, .monotonic, .monotonic) orelse return;
    }

    fn findDict(p: *Pool, id: u32) ?*const dict.Dictionary {
        while (!p.dicts_mu.tryLock()) std.atomic.spinLoopHint();
        defer p.dicts_mu.unlock();
        for (p.dicts.items) |d| if (d.id == id) return d;
        return null;
    }

    fn keepDict(p: *Pool, d: dict.Dictionary) Allocator.Error!*const dict.Dictionary {
        while (!p.dicts_mu.tryLock()) std.atomic.spinLoopHint();
        defer p.dicts_mu.unlock();
        for (p.dicts.items) |x| if (x.id == d.id) {
            var dd = d;
            dd.deinit(p.gpa);
            return x;
        };
        const box = try p.gpa.create(dict.Dictionary);
        errdefer p.gpa.destroy(box);
        box.* = d;
        try p.dicts.append(p.gpa, box);
        return box;
    }

    /// Opens a connection for `s` to the first core that answers (starting at `pref`), checks it.
    /// With a deadline `by` (monotonic ns), the time left is shared by the cores still to try, so
    /// one silent core cannot use up the whole budget.
    fn open(p: *Pool, a: Allocator, s: *Slot, excl: u64, by: u64) Error!void {
        var last: Error = error.NoCores;
        const n = p.specs.len;
        const start = p.pref.load(.monotonic);
        for (0..n) |k| {
            const i = (start + k) % n;
            if (i < 64 and excl >> @intCast(i) & 1 == 1) continue;
            if (p.stopped()) return error.Closed;
            var budget_ms = p.connect_timeout_ms;
            if (by != no_deadline) {
                const now = nowNs(p.io);
                if (now >= by) return if (last == error.NoCores) error.Timeout else last;
                budget_ms = @min(budget_ms, @max(1, (by - now) / std.time.ns_per_ms / (n - k)));
            }
            const c = Conn.connectStop(p.gpa, p.io, p.specs[i], budget_ms, &p.stopping) catch |e| {
                last = e;
                continue;
            };
            c.stall_ms = p.stall_ms;
            c.first_byte_by = by;
            ok: {
                c.doHello(a) catch |e| {
                    if (c.peerShutdown()) p.shutdown_ns.store(nowNs(p.io), .monotonic);
                    last = e;
                    break :ok;
                };
                if (c.hello.features & feature_edge_feed == 0) {
                    last = error.NoEdgeFeed;
                    break :ok;
                }
                if (p.chain_id) |want| if (!std.mem.eql(u8, &want, &c.hello.chain_id)) {
                    last = error.WrongChain;
                    break :ok;
                };
                p.hints[i].store(c.hello.highest, .monotonic);
                s.idx = @intCast(i);
                s.dict = null;
                if (p.use_zstd and c.hello.dict_id != 0) {
                    s.dict = p.findDict(c.hello.dict_id) orelse blk: {
                        const d = c.fetchDictionary(a, p.gpa, c.hello.dict_id, c.hello.dict_sha256) catch |e| {
                            // a failed dictionary costs only the compression gain
                            if (!p.stopped()) std.log.warn("edge: dictionary {x} from core {d}: {s}", .{ c.hello.dict_id, i, @errorName(e) });
                            break :blk null;
                        };
                        break :blk try p.keepDict(d);
                    };
                }
                c.first_byte_by = no_deadline;
                s.conn = c;
                s.gen = p.gen.load(.acquire);
                p.pref.store(@intCast(i), .monotonic);
                return;
            }
            c.close();
        }
        return last;
    }

    /// Every connection open now is closed at its next use, without a word about how it ended.
    /// For a caller that stopped using the pool for a while (an edge on its fallback): what
    /// those connections saw meanwhile (a shutdown notice of a core since restarted, a core that
    /// went silent) says nothing about the cores now.
    pub fn retire(p: *Pool) void {
        _ = p.gen.fetchAdd(1, .acq_rel);
    }

    /// Closes the connection of `s` if it is retired or dead. True when it was dead because its
    /// core said it is shutting down (noted in `shutdown_ns`).
    fn reap(p: *Pool, s: *Slot) bool {
        const c = s.conn orelse return false;
        if (s.gen != p.gen.load(.acquire)) {
            c.close();
            s.conn = null;
            return false;
        }
        if (c.alive()) return false;
        const going = c.peerShutdown();
        if (going) p.shutdown_ns.store(nowNs(p.io), .monotonic);
        c.close();
        s.conn = null;
        return going;
    }

    /// With a deadline and one core, a shutdown notice ends the call: there is nothing to
    /// reconnect to, and the caller has somewhere else to go.
    fn gone(p: *const Pool, going: bool, by: u64) bool {
        return going and by != no_deadline and p.specs.len == 1;
    }

    /// A core pruned `seq`: logged at most every 10 s (the follower polls a missing checkpoint).
    fn warnPruned(p: *Pool, seq: u64, core: u32) void {
        const now = nowNs(p.io);
        const last = p.last_pruned_log_ns.load(.monotonic);
        if (last != 0 and now -| last < 10 * std.time.ns_per_s) return;
        if (p.last_pruned_log_ns.cmpxchgStrong(last, now, .monotonic, .monotonic) != null) return;
        std.log.warn("edge: core {d} has pruned checkpoint {d} (below its retention): not held", .{ core, seq });
    }

    fn drop(p: *Pool, s: *Slot) void {
        if (s.conn) |c| c.close();
        s.conn = null;
        _ = p.stats.failovers.fetchAdd(1, .monotonic);
        _ = p.pref.fetchAdd(1, .monotonic);
    }

    /// Bitmask of cores not to ask for `seq` (they served a feed that failed verification).
    fn exclFor(p: *Pool, seq: u64) u64 {
        if (p.excl_seq.load(.acquire) != seq) return 0;
        return p.excl_mask.load(.acquire);
    }

    /// The feed of `seq` failed the follower's checks: whichever core served it is not asked for
    /// that checkpoint again. True when another core is left to try (the caller then fetches it
    /// again); false when none is (or the serving core is unknown), so the failure stands.
    pub fn blame(p: *Pool, seq: u64) bool {
        const e = &p.served[seq % served_n];
        if (e.seq.load(.acquire) != seq) return false;
        const core = e.core.load(.monotonic);
        if (core >= 64) return false;
        if (p.excl_seq.load(.acquire) != seq) {
            p.excl_mask.store(0, .release);
            p.excl_seq.store(seq, .release);
        }
        const mask = p.excl_mask.fetchOr(@as(u64, 1) << @intCast(core), .acq_rel) | (@as(u64, 1) << @intCast(core));
        _ = p.stats.failovers.fetchAdd(1, .monotonic);
        var left: usize = 0;
        for (0..@min(p.specs.len, 64)) |i| {
            if (mask >> @intCast(i) & 1 == 0) left += 1;
        }
        return left > 0 and p.specs.len <= 64;
    }

    /// After a core answered "not yet": is it worth asking the others? Yes when one of them last
    /// said it holds `seq`; otherwise once per two seconds (a lagging or stuck core must not stall
    /// the edge, and a tip wait must not cost a handshake per poll).
    fn tryOthers(p: *Pool, seq: u64, mine: u32) bool {
        if (p.specs.len < 2) return false;
        for (p.hints, 0..) |*h, i| if (i != mine and h.load(.monotonic) >= seq) return true;
        const now = nowNs(p.io);
        const last = p.last_sweep_ns.load(.monotonic);
        if (now -| last < 2 * std.time.ns_per_s) return false;
        return p.last_sweep_ns.cmpxchgStrong(last, now, .monotonic, .monotonic) == null;
    }

    /// Fetches checkpoint `seq` and appends its blob (`0x01 ++ BCS(CheckpointData)`, input objects
    /// empty) to `out` (cleared first). `.missing`: no core holds it yet. `a` is scratch.
    pub fn fetchBlob(p: *Pool, a: Allocator, seq: u64, out: *std.ArrayList(u8)) Error!Result {
        return p.fetchBlobBy(a, seq, out, no_deadline, null);
    }

    /// `fetchBlob` that gives up at `by` (monotonic ns; `no_deadline`: never): connects share the
    /// time left, a request with no response byte by then fails, and no new try starts after it.
    /// A response under way is not cut at `by` (see `stall_ms`).
    pub fn fetchBlobBy(p: *Pool, a: Allocator, seq: u64, out: *std.ArrayList(u8), by: u64, fail: ?*Fail) Error!Result {
        const s = try p.acquire();
        defer release(s);
        var last: Error = error.NoCores;
        var missing: usize = 0;
        var pruned: usize = 0;
        // one try per core, plus one for a connection that had gone stale
        for (0..p.specs.len + 1) |k| {
            if (p.stopped()) return error.Closed;
            if (k > 0 and by != no_deadline and nowNs(p.io) >= by) break;
            const excl = p.exclFor(seq);
            if (s.conn != null and s.idx < 64 and excl >> @intCast(s.idx) & 1 == 1) {
                // this connection's core served a bad feed for `seq`: not asked again for it
                s.conn.?.close();
                s.conn = null;
                _ = p.pref.fetchAdd(1, .monotonic);
            }
            if (p.gone(p.reap(s), by)) return error.Closed;
            if (s.conn == null) {
                p.open(a, s, excl, by) catch |e| {
                    last = e;
                    continue;
                };
            }
            const c = s.conn.?;
            _ = p.stats.requests.fetchAdd(1, .monotonic);
            const before = c.bytes_in;
            const t_req = nowNs(p.io);
            c.first_byte_by = by;
            defer if (s.conn == c) {
                c.first_byte_by = no_deadline;
            };
            const got = c.getFeed(a, seq, s.dict, p.use_zstd) catch |e| if (e == error.Pruned) {
                // the core's answer, not a bad link: no failover counted; another core may hold it
                missing += 1;
                pruned += 1;
                p.warnPruned(seq, s.idx);
                if (pruned >= p.specs.len) p.pruned_seq.store(seq, .monotonic);
                if (missing >= p.specs.len) return .missing;
                last = error.NoCores;
                c.close();
                s.conn = null;
                _ = p.pref.fetchAdd(1, .monotonic);
                continue;
            } else {
                // the pool was stopped under the request: not the core's failure, nothing to say
                if (p.stopped()) return error.Closed;
                last = e;
                _ = p.stats.errors.fetchAdd(1, .monotonic);
                // was silent: a 20 s request timeout looked like an idle edge
                std.log.warn("edge: core {d} feed {d}: {s} after {d} ms ({d} bytes in); reconnecting", .{ s.idx, seq, @errorName(e), (nowNs(p.io) - t_req) / std.time.ns_per_ms, c.bytes_in - before });
                const going = c.peerShutdown();
                if (going) p.shutdown_ns.store(nowNs(p.io), .monotonic);
                if (fail) |f| f.progress_ns = c.last_progress;
                // a server error (unavailable) is that core's answer; others are a bad link
                p.drop(s);
                if (p.gone(going, by)) return e;
                continue;
            };
            const raw = got orelse {
                // "not yet" from this core: another may hold it
                missing += 1;
                if (missing >= p.specs.len or !p.tryOthers(seq, s.idx)) return .missing;
                last = error.NoCores;
                c.close();
                s.conn = null;
                _ = p.pref.fetchAdd(1, .monotonic);
                continue;
            };
            _ = p.stats.wire_bytes.fetchAdd(c.bytes_in - before, .monotonic);
            _ = p.stats.raw_bytes.fetchAdd(raw.len, .monotonic);
            // A feed that does not decode, or names another checkpoint, is that core's fault: the
            // next core gets the request.
            var f = feed.decode(a, raw) catch {
                last = error.BadData;
                p.drop(s);
                continue;
            };
            defer f.deinit(a);
            if (f.seq != seq) {
                last = error.BadData;
                p.drop(s);
                continue;
            }
            out.clearRetainingCapacity();
            feed.toBlob(out, p.gpa, &f) catch return error.OutOfMemory;
            _ = p.stats.blob_bytes.fetchAdd(out.items.len, .monotonic);
            const e = &p.served[seq % served_n];
            e.core.store(s.idx, .monotonic);
            e.seq.store(seq, .release);
            p.noteHighest(seq);
            return .ok;
        }
        if (missing > 0 and last == error.NoCores) return .missing;
        return last;
    }

    /// How one checkpoint of a `fetchBlobs` call came out.
    pub const BatchItem = enum(u8) {
        /// Its blob went to the sink.
        ok,
        /// The core does not hold it yet.
        missing,
        /// Anything else (pruned, a server error, a feed that does not decode): for `fetchBlob`.
        failed,
    };

    /// What a `fetchBlobs` call measured.
    pub const CallTimes = struct {
        /// From the requests' send to the first response byte, and to the last.
        first_byte_ns: u64 = 0,
        total_ns: u64 = 0,
        /// The core refused a request of the call (rate limited: its feed queue is full).
        limited: bool = false,
    };

    /// Where `fetchBlobs` puts the blobs: called once per checkpoint that came back whole, in
    /// order, with bytes that are valid during the call.
    pub const Sink = struct {
        ctx: *anyopaque,
        put: *const fn (ctx: *anyopaque, seq: u64, blob: []const u8) void,
    };

    /// Fetches the checkpoints `first .. first + results.len` as one pipelined call on one
    /// connection: every request is sent before the first response is read, so the round trip
    /// is paid once (an edge far from its core is bound by round trips, not by bytes). The
    /// fast path of a catch-up only: one try on the connection in use, no failover and no
    /// verdict about the core. Whatever did not come out `ok`, and the whole call when it
    /// fails, is for `fetchBlobBy` to ask again, with its rules. `out` is scratch for one blob.
    pub fn fetchBlobs(p: *Pool, a: Allocator, first: u64, results: []BatchItem, out: *std.ArrayList(u8), sink: Sink, by: u64, times: *CallTimes) Error!void {
        @memset(results, .failed);
        times.* = .{};
        const s = try p.acquire();
        defer release(s);
        if (p.stopped()) return error.Closed;
        // a core excluded for one of these checkpoints: the single path knows what to do
        const xs = p.excl_seq.load(.acquire);
        if (xs >= first and xs - first < results.len) return error.NoCores;
        if (p.gone(p.reap(s), by)) return error.Closed;
        if (s.conn == null) try p.open(a, s, 0, by);
        const c = s.conn.?;
        const ps = try a.alloc(Conn.Piped, results.len);
        for (ps, 0..) |*q, k| {
            var b: [12]u8 = undefined;
            std.mem.writeInt(u64, b[0..8], first + k, .little);
            std.mem.writeInt(u32, b[8..12], if (s.dict) |d| d.id else 0, .little);
            var req: std.ArrayList(u8) = .empty;
            try proto.encodeRequest(&req, a, .get_checkpoint_feed, if (p.use_zstd) proto.flag_zstd_ok else 0, &b);
            q.* = .{ .req = req.items };
        }
        _ = p.stats.requests.fetchAdd(results.len, .monotonic);
        const before = c.bytes_in;
        const t0 = nowNs(p.io);
        c.first_byte_by = by;
        c.requestMany(a, ps) catch |e| {
            // responses half read: the connection is of no more use
            if (c.peerShutdown()) p.shutdown_ns.store(nowNs(p.io), .monotonic);
            c.close();
            s.conn = null;
            if (p.stopped()) return error.Closed;
            _ = p.stats.errors.fetchAdd(1, .monotonic);
            return e;
        };
        c.first_byte_by = no_deadline;
        const t1 = nowNs(p.io);
        times.first_byte_ns = c.first_byte_ns -| t0;
        times.total_ns = t1 - t0;
        _ = p.stats.wire_bytes.fetchAdd(c.bytes_in - before, .monotonic);
        for (ps, results, 0..) |*q, *res, k| {
            const seq = first + k;
            const r = proto.parseResponse(q.resp.items) orelse continue;
            if (r.status == @intFromEnum(proto.Code.rate_limited)) times.limited = true;
            if (r.status != 0) continue;
            var rd: proto.R = .{ .b = r.body };
            if (!(rd.option() catch continue)) {
                res.* = .missing;
                continue;
            }
            const body = rd.bytes() catch continue;
            rd.done() catch continue;
            const raw: []const u8 = if (!p.use_zstd) body else dict.decompress(a, s.dict, body) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => continue,
            };
            _ = p.stats.raw_bytes.fetchAdd(raw.len, .monotonic);
            var f = feed.decode(a, raw) catch continue;
            defer f.deinit(a);
            if (f.seq != seq) continue;
            out.clearRetainingCapacity();
            feed.toBlob(out, p.gpa, &f) catch return error.OutOfMemory;
            _ = p.stats.blob_bytes.fetchAdd(out.items.len, .monotonic);
            const e = &p.served[seq % served_n];
            e.core.store(s.idx, .monotonic);
            e.seq.store(seq, .release);
            p.noteHighest(seq);
            res.* = .ok;
            sink.put(sink.ctx, seq, out.items);
        }
    }

    /// How one checkpoint of a `fetchSummaries` call came out.
    pub const Summary = union(enum) {
        /// The core's BCS CertifiedCheckpointSummary, as it stores it (owned by the call's
        /// allocator). Not checked here: the caller verifies it like any other.
        cert: []const u8,
        /// The core does not hold the checkpoint yet.
        missing,
        /// Below the core's retention; its lowest held checkpoint.
        pruned: u64,
        /// The core refused the request (rate limited).
        refused,
        /// The core answered an error.
        failed,
        /// An answer that does not parse, or names another checkpoint.
        bad,
    };

    /// Body of `get_checkpoint` by sequence number with no parts: the smallest request zui/1
    /// has for a certified summary (10 bytes; the answer is the sequence number, the stored
    /// CertifiedCheckpointSummary and two empty fields).
    pub fn summaryRequest(seq: u64) [10]u8 {
        var b: [10]u8 = undefined;
        b[0] = 1; // by sequence number
        std.mem.writeInt(u64, b[1..9], seq, .little);
        b[9] = 0; // no contents, no transactions
        return b;
    }

    /// The answer to `summaryRequest(seq)`.
    pub fn parseSummary(resp: []const u8, seq: u64) Summary {
        const r = proto.parseResponse(resp) orelse return .bad;
        if (r.status == @intFromEnum(proto.Code.rate_limited)) return .refused;
        if (r.status == @intFromEnum(proto.Code.pruned)) {
            // ErrorBody: code u32, message, detail (the lowest held checkpoint, u64)
            var rd: proto.R = .{ .b = r.body };
            _ = rd.int(u32) catch return .bad;
            _ = rd.str() catch return .bad;
            const detail = rd.bytes() catch return .bad;
            if (detail.len != 8) return .bad;
            return .{ .pruned = std.mem.readInt(u64, detail[0..8], .little) };
        }
        if (r.status != 0) return .failed;
        var rd: proto.R = .{ .b = r.body };
        switch (rd.u8_() catch return .bad) {
            0 => return .missing,
            1 => {},
            else => return .bad,
        }
        if ((rd.int(u64) catch return .bad) != seq) return .bad;
        const cert = rd.bytes() catch return .bad;
        if (cert.len == 0) return .bad;
        return .{ .cert = cert };
    }

    /// The certified summaries of `seqs` from the core in use, as one pipelined call (every
    /// request sent before the first response is read: one round trip for all of them). For an
    /// edge that replaces certificates it did not take from a core (certs.zig, docs/EDGE.md
    /// section 13). The lowest priority call on the pool: it takes a connection only when one
    /// is free (false: none was, nothing was asked) and never waits in front of a fetch thread;
    /// one try on that connection, no failover, no verdict about the core. `get_checkpoint` is
    /// answered on the core's listener thread from its store: it does not pass the feed queue.
    pub fn fetchSummaries(p: *Pool, a: Allocator, seqs: []const u64, out: []Summary, by: u64) Error!bool {
        std.debug.assert(seqs.len == out.len);
        @memset(out, .failed);
        if (p.stopped()) return error.Closed;
        const s = for (p.slots) |*x| {
            if (x.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) break x;
        } else return false;
        defer release(s);
        if (p.gone(p.reap(s), by)) return error.Closed;
        if (s.conn == null) try p.open(a, s, 0, by);
        const c = s.conn.?;
        const ps = try a.alloc(Conn.Piped, seqs.len);
        for (ps, seqs) |*q, seq| {
            var req: std.ArrayList(u8) = .empty;
            try proto.encodeRequest(&req, a, .get_checkpoint, 0, &summaryRequest(seq));
            q.* = .{ .req = req.items };
        }
        c.first_byte_by = by;
        c.requestMany(a, ps) catch |e| {
            // responses half read: the connection is of no more use
            if (c.peerShutdown()) p.shutdown_ns.store(nowNs(p.io), .monotonic);
            c.close();
            s.conn = null;
            if (p.stopped()) return error.Closed;
            return e;
        };
        c.first_byte_by = no_deadline;
        for (ps, out, seqs) |*q, *res, seq| res.* = parseSummary(q.resp.items, seq);
        return true;
    }

    /// Passes one zui/1 request to a core and returns its whole response (status byte, flags,
    /// body; owned by `a`): for an edge whose own answer would hand out a quorum certificate
    /// that is not the core's (docs/EDGE.md section 13). A client's request, so it waits for a
    /// connection like a fetch; one try per core. `flags` without `flag_zstd_ok`: the core's
    /// dictionaries are not the edge's, and the edge compresses for its own client.
    pub fn forward(p: *Pool, a: Allocator, m: proto.Method, flags: u64, body: []const u8, by: u64) Error![]u8 {
        const s = try p.acquire();
        defer release(s);
        var last: Error = error.NoCores;
        for (0..p.specs.len + 1) |k| {
            if (p.stopped()) return error.Closed;
            if (k > 0 and by != no_deadline and nowNs(p.io) >= by) break;
            if (p.gone(p.reap(s), by)) return error.Closed;
            if (s.conn == null) {
                p.open(a, s, 0, by) catch |e| {
                    last = e;
                    continue;
                };
            }
            const c = s.conn.?;
            c.first_byte_by = by;
            defer if (s.conn == c) {
                c.first_byte_by = no_deadline;
            };
            return c.request(a, m, flags, body) catch |e| {
                if (p.stopped()) return error.Closed;
                last = e;
                const going = c.peerShutdown();
                if (going) p.shutdown_ns.store(nowNs(p.io), .monotonic);
                p.drop(s);
                if (p.gone(going, by)) return e;
                continue;
            };
        }
        return last;
    }

    /// Does any core hold `seq`? One small request (the summary only), unless a feed of `seq` or
    /// a later one was already served. A core's own claim of how high it is never answers this.
    /// The lowest checkpoint the core in use holds (its hello), opening a connection if none is.
    /// The tip search starts here: a floor from a stale epochs index lies below a core's
    /// retention, and a core holds nothing below its lowest.
    pub fn lowestHeld(p: *Pool, a: Allocator) Error!u64 {
        return p.lowestHeldBy(a, no_deadline);
    }

    /// `lowestHeld` that gives up at `by` (see `fetchBlobBy`).
    pub fn lowestHeldBy(p: *Pool, a: Allocator, by: u64) Error!u64 {
        const s = try p.acquire();
        defer release(s);
        if (p.gone(p.reap(s), by)) return error.Closed;
        if (s.conn == null) try p.open(a, s, 0, by);
        return s.conn.?.hello.lowest;
    }

    pub fn exists(p: *Pool, a: Allocator, seq: u64) Error!bool {
        return p.existsBy(a, seq, no_deadline);
    }

    /// `exists` that gives up at `by` (see `fetchBlobBy`).
    pub fn existsBy(p: *Pool, a: Allocator, seq: u64, by: u64) Error!bool {
        if (p.highest_seen.load(.monotonic) >= seq) return true;
        const s = try p.acquire();
        defer release(s);
        var last: Error = error.NoCores;
        for (0..p.specs.len + 1) |k| {
            if (p.stopped()) return error.Closed;
            if (k > 0 and by != no_deadline and nowNs(p.io) >= by) break;
            if (p.gone(p.reap(s), by)) return error.Closed;
            if (s.conn == null) {
                p.open(a, s, 0, by) catch |e| {
                    last = e;
                    continue;
                };
            }
            const c = s.conn.?;
            c.first_byte_by = by;
            defer if (s.conn == c) {
                c.first_byte_by = no_deadline;
            };
            return c.hasCheckpoint(a, seq) catch |e| {
                if (p.stopped()) return error.Closed;
                last = e;
                std.log.warn("edge: core {d} checkpoint {d} probe: {s}; reconnecting", .{ s.idx, seq, @errorName(e) });
                const going = c.peerShutdown();
                if (going) p.shutdown_ns.store(nowNs(p.io), .monotonic);
                p.drop(s);
                if (p.gone(going, by)) return e;
                continue;
            };
        }
        return last;
    }
};

/// A core that never answers: a bound UDP socket nobody reads (a dead box, a cut link).
const SilentCore = struct {
    sock: Io.net.Socket,

    fn open() !SilentCore {
        var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        return .{ .sock = try Io.net.IpAddress.bind(&lo, std.testing.io, .{ .mode = .dgram }) };
    }

    fn close(s: *SilentCore) void {
        s.sock.close(std.testing.io);
    }

    fn spec(s: *const SilentCore) Spec {
        return .{ .addr = .{ .ip4 = Io.net.Ip4Address.loopback(s.sock.address.getPort()) }, .key = @splat(7) };
    }
};

/// One pool call on its own thread, with when it returned and what.
const StopCall = struct {
    pool: *Pool,
    kind: enum { fetch, exists, lowest },
    result: ?Error = null,
    ok: bool = false,
    done_ns: Atomic(u64) = .init(0),
    thread: ?std.Thread = null,

    fn start(c: *StopCall) !void {
        c.thread = try std.Thread.spawn(.{}, run, .{c});
    }

    fn run(c: *StopCall) void {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(std.testing.allocator);
        const r: Error!void = switch (c.kind) {
            .fetch => if (c.pool.fetchBlob(arena.allocator(), 5, &out)) |_| {} else |e| e,
            .exists => if (c.pool.exists(arena.allocator(), 5)) |_| {} else |e| e,
            .lowest => if (c.pool.lowestHeld(arena.allocator())) |_| {} else |e| e,
        };
        if (r) |_| {
            c.ok = true;
        } else |e| c.result = e;
        c.done_ns.store(nowNs(std.testing.io), .release);
    }

    /// Joins (the call is bounded by the pool's own timeouts whatever happens) and returns how
    /// long after `t_stop` it ended, in ms.
    fn join(c: *StopCall, t_stop: u64) u64 {
        if (c.thread) |t| t.join();
        c.thread = null;
        return (c.done_ns.load(.acquire) -| t_stop) / std.time.ns_per_ms;
    }
};

test "edge pool: stop ends a connect to a core that never answers, a thread waiting for a free connection and every later call, at once and not at the timeouts" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var core = try SilentCore.open();
    defer core.close();
    const specs = [_]Spec{core.spec()};
    // One connection: the first call holds it (in its connect), the others wait for it.
    const p = try Pool.init(gpa, io, &specs, 1);
    defer p.deinit();
    // The test's bound if the stop did nothing: every call ends by itself after this.
    p.connect_timeout_ms = 4_000;
    var calls = [_]StopCall{ .{ .pool = p, .kind = .fetch }, .{ .pool = p, .kind = .exists }, .{ .pool = p, .kind = .lowest } };
    var started: usize = 0;
    var took: [calls.len]u64 = undefined;
    {
        // every thread is joined before anything is asserted (each ends by itself at the latest
        // after the pool's own timeouts)
        var t_stop: u64 = 0;
        defer for (calls[0..started], took[0..started]) |*c, *ms| {
            ms.* = c.join(t_stop);
        };
        for (&calls) |*c| {
            try c.start();
            started += 1;
        }
        // All three are inside the pool: one connecting, two waiting for the slot.
        io.sleep(.fromMilliseconds(150), .awake) catch {};
        t_stop = nowNs(io);
        p.stop();
    }
    for (&calls, took) |*c, ms| {
        try std.testing.expect(!c.ok);
        try std.testing.expectEqual(@as(?Error, error.Closed), c.result);
        try std.testing.expect(ms < 500);
    }
    // A call made after the stop does not touch the network.
    var late: StopCall = .{ .pool = p, .kind = .fetch };
    const t1 = nowNs(io);
    try late.start();
    try std.testing.expect(late.join(t1) < 500);
    try std.testing.expectEqual(@as(?Error, error.Closed), late.result);
    try std.testing.expectEqual(@as(u64, 0), p.stats.requests.load(.monotonic));
}

test "edge client: a connect with a stop flag ends when the flag is set" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var core = try SilentCore.open();
    defer core.close();
    const T = struct {
        spec: Spec,
        stop: Atomic(bool) = .init(false),
        err: ?Error = null,
        done_ns: Atomic(u64) = .init(0),
        fn run(t: *@This()) void {
            if (Conn.connectStop(std.testing.allocator, std.testing.io, t.spec, 4_000, &t.stop)) |c| c.close() else |e| t.err = e;
            t.done_ns.store(nowNs(std.testing.io), .release);
        }
    };
    var t: T = .{ .spec = core.spec() };
    const th = try std.Thread.spawn(.{}, T.run, .{&t});
    io.sleep(.fromMilliseconds(100), .awake) catch {};
    try std.testing.expectEqual(@as(u64, 0), t.done_ns.load(.acquire));
    const t_stop = nowNs(io);
    t.stop.store(true, .release);
    th.join();
    try std.testing.expectEqual(@as(?Error, error.Closed), t.err);
    try std.testing.expect((t.done_ns.load(.acquire) -| t_stop) / std.time.ns_per_ms < 500);
    // without a flag the same connect ends at its own timeout
    const t0 = nowNs(io);
    try std.testing.expectError(error.HandshakeFailed, Conn.connect(gpa, io, core.spec(), 200));
    try std.testing.expect((nowNs(io) - t0) / std.time.ns_per_ms >= 150);
}

test "parseSpecs" {
    const gpa = std.testing.allocator;
    const key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const s = try parseSpecs(gpa, "127.0.0.1:4433/" ++ key ++ ", [::1]:9/" ++ key);
    defer gpa.free(s);
    try std.testing.expectEqual(@as(usize, 2), s.len);
    try std.testing.expectEqual(@as(u8, 0x00), s[0].key[0]);
    try std.testing.expectEqual(@as(u8, 0xff), s[1].key[31]);
    try std.testing.expectEqual(@as(u16, 4433), s[0].addr.getPort());
    try std.testing.expectError(error.BadSpec, parseSpecs(gpa, "127.0.0.1:4433"));
    try std.testing.expectError(error.BadSpec, parseSpecs(gpa, "127.0.0.1:4433/abcd"));
    try std.testing.expectError(error.BadSpec, parseSpecs(gpa, "nothost:1/" ++ key));
    try std.testing.expectError(error.BadSpec, parseSpecs(gpa, ""));
}
