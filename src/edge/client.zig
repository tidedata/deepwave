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

    pub fn connect(gpa: Allocator, io: Io, spec: Spec, connect_timeout_ms: u64) Error!*Conn {
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
        cl.* = .{ .gpa = gpa, .io = io, .sock = sock, .addr = spec.addr, .c = c, .us = .init(sock.handle) };
        errdefer c.deinit();
        const deadline = nowNs(io) + connect_timeout_ms * std.time.ns_per_ms;
        while (!c.isEstablished()) {
            if (c.isClosed() or nowNs(io) > deadline) return error.HandshakeFailed;
            try cl.pump(10);
        }
        return cl;
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
        const deadline = nowNs(cl.io) + cl.request_timeout_ms * std.time.ns_per_ms;
        while (true) {
            const st = cl.c.stream(id) orelse return error.StreamGone;
            const d = st.recv.contiguous();
            if (d.len > 0) {
                if (resp.items.len + d.len > response_max) return error.TooLarge;
                try resp.appendSlice(a, d);
                st.recv.consume(d.len);
            }
            if (st.recv.complete()) break;
            if (cl.c.isClosed()) return error.Closed;
            if (nowNs(cl.io) > deadline) return error.Timeout;
            try cl.pump(5);
        }
        return resp.items;
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

    fn acquire(p: *Pool) *Slot {
        while (true) {
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
    fn open(p: *Pool, a: Allocator, s: *Slot, excl: u64) Error!void {
        var last: Error = error.NoCores;
        const n = p.specs.len;
        const start = p.pref.load(.monotonic);
        for (0..n) |k| {
            const i = (start + k) % n;
            if (i < 64 and excl >> @intCast(i) & 1 == 1) continue;
            const c = Conn.connect(p.gpa, p.io, p.specs[i], p.connect_timeout_ms) catch |e| {
                last = e;
                continue;
            };
            ok: {
                c.doHello(a) catch |e| {
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
                            std.log.warn("edge: dictionary {x} from core {d}: {s}", .{ c.hello.dict_id, i, @errorName(e) });
                            break :blk null;
                        };
                        break :blk try p.keepDict(d);
                    };
                }
                s.conn = c;
                p.pref.store(@intCast(i), .monotonic);
                return;
            }
            c.close();
        }
        return last;
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
        const s = p.acquire();
        defer release(s);
        var last: Error = error.NoCores;
        var missing: usize = 0;
        // one try per core, plus one for a connection that had gone stale
        for (0..p.specs.len + 1) |_| {
            const excl = p.exclFor(seq);
            if (s.conn != null and s.idx < 64 and excl >> @intCast(s.idx) & 1 == 1) {
                // this connection's core served a bad feed for `seq`: not asked again for it
                s.conn.?.close();
                s.conn = null;
                _ = p.pref.fetchAdd(1, .monotonic);
            }
            if (s.conn == null or !s.conn.?.alive()) {
                if (s.conn) |c| c.close();
                s.conn = null;
                p.open(a, s, excl) catch |e| {
                    last = e;
                    continue;
                };
            }
            const c = s.conn.?;
            _ = p.stats.requests.fetchAdd(1, .monotonic);
            const before = c.bytes_in;
            const t_req = nowNs(p.io);
            const got = c.getFeed(a, seq, s.dict, p.use_zstd) catch |e| if (e == error.Pruned) {
                // the core's answer, not a bad link: no failover counted; another core may hold it
                missing += 1;
                p.warnPruned(seq, s.idx);
                if (missing >= p.specs.len) return .missing;
                last = error.NoCores;
                c.close();
                s.conn = null;
                _ = p.pref.fetchAdd(1, .monotonic);
                continue;
            } else {
                last = e;
                _ = p.stats.errors.fetchAdd(1, .monotonic);
                // was silent: a 20 s request timeout looked like an idle edge
                std.log.warn("edge: core {d} feed {d}: {s} after {d} ms ({d} bytes in); reconnecting", .{ s.idx, seq, @errorName(e), (nowNs(p.io) - t_req) / std.time.ns_per_ms, c.bytes_in - before });
                // a server error (unavailable) is that core's answer; others are a bad link
                p.drop(s);
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

    /// Does any core hold `seq`? One small request (the summary only), unless a feed of `seq` or
    /// a later one was already served. A core's own claim of how high it is never answers this.
    /// The lowest checkpoint the core in use holds (its hello), opening a connection if none is.
    /// The tip search starts here: a floor from a stale epochs index lies below a core's
    /// retention, and a core holds nothing below its lowest.
    pub fn lowestHeld(p: *Pool, a: Allocator) Error!u64 {
        const s = p.acquire();
        defer release(s);
        if (s.conn == null or !s.conn.?.alive()) {
            if (s.conn) |c| c.close();
            s.conn = null;
            try p.open(a, s, 0);
        }
        return s.conn.?.hello.lowest;
    }

    pub fn exists(p: *Pool, a: Allocator, seq: u64) Error!bool {
        if (p.highest_seen.load(.monotonic) >= seq) return true;
        const s = p.acquire();
        defer release(s);
        var last: Error = error.NoCores;
        for (0..p.specs.len + 1) |_| {
            if (s.conn == null or !s.conn.?.alive()) {
                if (s.conn) |c| c.close();
                s.conn = null;
                p.open(a, s, 0) catch |e| {
                    last = e;
                    continue;
                };
            }
            return s.conn.?.hasCheckpoint(a, seq) catch |e| {
                last = e;
                std.log.warn("edge: core {d} checkpoint {d} probe: {s}; reconnecting", .{ s.idx, seq, @errorName(e) });
                p.drop(s);
                continue;
            };
        }
        return last;
    }
};

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
