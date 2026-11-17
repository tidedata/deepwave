//! The validator's `sui.StateSync` and `sui.Discovery` services on its anemo endpoint (run/p2p.zig),
//! wire-identical to sui-node 1.83.1 (`sui-network/src/state_sync/server.rs`,
//! `discovery/server.rs`), served from the validator's own stores: certified summaries from the
//! checkpoint store, contents as built, each transaction's data and effects from the exec store.
//! The same module is the client a lagging seat catches up with (run/catchup.zig), against
//! sui-node and deepwave peers alike.
//!
//! StateSync routes (request and response: BCS in a snappy frame, `BcsSnappyCodec`):
//! - PushCheckpointSummary(CertifiedCheckpointSummary) -> (): the pusher's height is noted
//!   (the catch-up client reads it); nothing is stored, as a validator whose consensus runs
//!   certifies its own.
//! - GetCheckpointSummary(Latest | ByDigest | BySequenceNumber) -> Option<Certified...>: Latest is
//!   the highest certified checkpoint (sui-node: highest synced; a deepwave seat certifies only what
//!   it built or applied whole).
//! - GetCheckpointAvailability(()) -> { highest_synced_checkpoint, lowest_available_checkpoint }:
//!   lowest is 0 (nothing is pruned: `get_highest_pruned_checkpoint_seq_number` None).
//! - GetCheckpointContents(digest) -> Option<FullCheckpointContents> (V2 contents as `into_v1`),
//!   GetCheckpointContentsV2(digest) -> Option<VersionedFullCheckpointContents>,
//!   GetCheckpointContentsDigests(seq) -> Option<CheckpointContents>,
//!   GetCheckpointTransactions{seq, start, end} -> Option<Vec<ExecutionData>> (16 MiB budget, at
//!   least one; an empty or out-of-range span is 400). Only certified checkpoints whose built
//!   digest is the certified one are served. A full contents answer above 128 MiB serialized is
//!   500 (the client pages, `full_contents_size_error`).
//! - Request bodies above 256 KiB get an empty 200 (`SizeLimitLayer`, max_checkpoint_summary_size).
//!
//! `ExecutionData.transaction` is the `Transaction` (`SenderSignedData`: one
//! `SenderSignedTransaction { IntentMessage { Intent(0,0,0), TransactionData }, tx_signatures }`)
//! with the signatures the contents recorded for it (consensus carried them; the checkpoint
//! builder stored them in that order).
//!
//! Discovery: GetKnownPeersV2(()) / GetKnownPeersV3(own info) -> our signed NodeInfo (V3:
//! VersionedNodeInfo::V2) and the public peers whose infos we hold (node/p2p_serve.zig PeerBook).
//!
//! Pushes and peer heights (sui-node `notify_peers_of_checkpoint`, `get_latest_from_peer`): each
//! newly certified checkpoint is pushed to every connected peer on the same chain (genesis
//! checkpoint digest checked once per peer) whose known height is below it; peers are asked
//! for their availability every `poll_ms`.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Ed25519 = std.crypto.sign.Ed25519;
const bcs = @import("bcs");
const types = @import("types");
const net = @import("net");
const node = @import("node");
const anemo = net.anemo;
const wire = net.wire;
const ss = net.state_sync;
const discovery = net.discovery;
const snappy = net.snappy;
const p2p_serve = node.p2p_serve;
const p2p_mod = @import("p2p.zig");
const ckpt_store = @import("ckpt_store.zig");
const exec_store = @import("exec_store.zig");

const log = std.log.scoped(.state_sync);
const Id = [32]u8;

/// sui-node StateSyncConfig defaults.
pub const max_request_size: usize = 256 * 1024;
pub const max_full_contents: usize = 128 << 20;
pub const transactions_budget: usize = 16 << 20;
/// `interval_period_ms` of the state sync event loop (peers asked for their latest).
pub const poll_ms: u64 = 5_000;
/// `timeout_ms` of state sync requests.
pub const request_timeout_ms: u64 = 10_000;
/// Availability and genesis probes (a peer that is not up must not hold a starting seat for long).
pub const probe_timeout_ms: u64 = 3_000;

const content_type = wire.Header{ .name = "content-type", .value = "bcs" };
const reply_headers = [_]wire.Header{content_type};
const request_headers = [_]wire.Header{ content_type, .{ .name = wire.timeout_header, .value = "10000000000" } };

pub const Options = struct {
    p2p: *p2p_mod.P2p,
    ckpt: *ckpt_store.CkptStore,
    exec: *exec_store.ExecStore,
    /// Digest of the genesis checkpoint summary (ChainIdentifier).
    genesis_digest: Id,
    /// Ed25519 seed of the network key (signs our NodeInfo).
    network_seed: *const [32]u8,
    /// Our advertised p2p address (Multiaddr string, the genesis `p2p_address`).
    external: []const u8,
    /// Push certified checkpoints and poll peers (off in unit tests that drive it by hand).
    background: bool = true,
};

pub const Stats = struct {
    served: Atomic(u64) = .init(0),
    found: Atomic(u64) = .init(0),
    pushes_in: Atomic(u64) = .init(0),
    pushes_out: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
};

const PeerInfo = struct {
    /// null until its genesis summary was asked for.
    same_chain: ?bool = null,
    height: u64 = 0,
};

pub const Service = struct {
    gpa: Allocator,
    io: Io,
    opts: Options,
    key: Ed25519.KeyPair,
    external: []u8,
    book: p2p_serve.PeerBook,
    mu: Io.Mutex = .init,
    peers: std.AutoHashMapUnmanaged(Id, PeerInfo) = .empty,
    own_mu: Io.Mutex = .init,
    own_ts: u64 = 0,
    own_v1: []u8 = &.{},
    own_v2: []u8 = &.{},
    pushed_through: u64 = 0,
    stats: Stats = .{},
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,

    pub fn start(gpa: Allocator, io: Io, opts: Options) !*Service {
        const s = try gpa.create(Service);
        errdefer gpa.destroy(s);
        const key = try Ed25519.KeyPair.generateDeterministic(opts.network_seed.*);
        const ext = try gpa.dupe(u8, opts.external);
        errdefer gpa.free(ext);
        s.* = .{ .gpa = gpa, .io = io, .opts = opts, .key = key, .external = ext, .book = .{ .gpa = gpa, .io = io, .our_id = key.public_key.toBytes() } };
        s.opts.network_seed = undefined;
        s.pushed_through = opts.ckpt.highestCertified() orelse 0;
        if (opts.background) s.thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, loop, .{s});
        opts.p2p.setService(.state_sync, .{ .ctx = @ptrCast(s), .serve = serveStateSync });
        opts.p2p.setService(.discovery, .{ .ctx = @ptrCast(s), .serve = serveDiscovery });
        return s;
    }

    pub fn stop(s: *Service) void {
        s.opts.p2p.clearService(.state_sync);
        s.opts.p2p.clearService(.discovery);
        s.stop_flag.store(true, .release);
        if (s.thread) |t| t.join();
        s.peers.deinit(s.gpa);
        s.book.deinit();
        s.gpa.free(s.own_v1);
        s.gpa.free(s.own_v2);
        s.gpa.free(s.external);
        std.crypto.secureZero(u8, &s.key.secret_key.bytes);
        s.gpa.destroy(s);
    }

    fn nowMs(s: *const Service) u64 {
        return @intCast(@divTrunc(Io.Clock.real.now(s.io).toNanoseconds(), std.time.ns_per_ms));
    }

    // ------------------------------------------------------------------ server

    fn serveStateSync(ctx: *anyopaque, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const s: *Service = @ptrCast(@alignCast(ctx));
        _ = s.stats.served.fetchAdd(1, .monotonic);
        if (body.len > max_request_size) return .{ .status = .success };
        const reply = s.answer(a, from, route, body) catch |e| switch (e) {
            error.OutOfMemory, error.Internal, error.TooLarge => anemo.Reply{ .status = .internal_server_error },
            error.NotFound => anemo.Reply{ .status = .not_found },
            else => anemo.Reply{ .status = .bad_request },
        };
        if (reply.status != .success) _ = s.stats.errors.fetchAdd(1, .monotonic);
        return reply;
    }

    const AnswerError = error{ OutOfMemory, Internal, TooLarge, NotFound, BadRequest } || ss.DecodeError || bcs.Error;

    fn ok(a: Allocator, raw: []const u8) Allocator.Error!anemo.Reply {
        return .{ .status = .success, .body = try snappy.compressFrame(a, raw), .headers = &reply_headers };
    }

    fn decodeRequest(a: Allocator, body: []const u8) ss.DecodeError![]u8 {
        return snappy.decompressFrame(a, body, 4 << 20);
    }

    fn answer(s: *Service, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) AnswerError!anemo.Reply {
        const R = ss.Route;
        const eq = std.mem.eql;
        if (eq(u8, route, R.push_checkpoint_summary)) {
            const cert = try decodeRequest(a, body);
            s.onPush(from, cert);
            return ok(a, &.{});
        }
        if (eq(u8, route, R.get_checkpoint_summary)) {
            const id = try p2p_serve.parseSummaryRequest(try decodeRequest(a, body));
            const seq: ?u64 = switch (id) {
                .latest => s.opts.ckpt.highestCertified(),
                .seq => |q| q,
                .digest => |d| s.opts.ckpt.seqByDigest(&d),
            };
            const cert: ?[]const u8 = if (seq) |q| try s.opts.ckpt.certifiedCopy(a, q) else null;
            if (cert != null) _ = s.stats.found.fetchAdd(1, .monotonic);
            return ok(a, try p2p_serve.option(a, cert));
        }
        if (eq(u8, route, R.get_checkpoint_availability)) {
            const hi = s.opts.ckpt.highestCertified() orelse return error.Internal;
            const cert = (try s.opts.ckpt.certifiedCopy(a, hi)) orelse return error.Internal;
            const b = try a.alloc(u8, cert.len + 8);
            @memcpy(b[0..cert.len], cert);
            std.mem.writeInt(u64, b[cert.len..][0..8], 0, .little);
            return ok(a, b);
        }
        if (eq(u8, route, R.get_checkpoint_contents) or eq(u8, route, R.get_checkpoint_contents_v2)) {
            const req = try decodeRequest(a, body);
            if (req.len != 33 or req[0] != 32) return error.BadRequest;
            const seq = s.opts.ckpt.seqByContents(req[1..33]);
            const full: ?[]const u8 = if (seq) |q| try s.fullContents(a, q, eq(u8, route, R.get_checkpoint_contents)) else null;
            if (full) |f| {
                if (f.len > max_full_contents) return error.TooLarge;
                _ = s.stats.found.fetchAdd(1, .monotonic);
            }
            return ok(a, try p2p_serve.option(a, full));
        }
        if (eq(u8, route, R.get_checkpoint_contents_digests)) {
            const req = try decodeRequest(a, body);
            if (req.len != 8) return error.BadRequest;
            const seq = std.mem.readInt(u64, req[0..8], .little);
            const contents = try s.servedContents(a, seq);
            return ok(a, try p2p_serve.option(a, contents));
        }
        if (eq(u8, route, R.get_checkpoint_transactions)) {
            const req = try decodeRequest(a, body);
            if (req.len != 24) return error.BadRequest;
            const seq = std.mem.readInt(u64, req[0..8], .little);
            const first = std.mem.readInt(u64, req[8..16], .little);
            const end = std.mem.readInt(u64, req[16..24], .little);
            const contents = (try s.servedContents(a, seq)) orelse return ok(a, &.{0});
            const out = try s.transactionsPage(a, contents, first, end);
            return ok(a, out orelse &.{0});
        }
        return error.NotFound;
    }

    /// The contents of certified checkpoint `seq` when this seat built the certified checkpoint
    /// (the genesis checkpoint's contents are not kept: a peer has them from the genesis blob).
    fn servedContents(s: *Service, a: Allocator, seq: u64) Allocator.Error!?[]const u8 {
        const hi = s.opts.ckpt.highestCertified() orelse return null;
        if (seq > hi) return null;
        const st = s.opts.ckpt.store();
        const cert_d = st.certifiedDigest(seq) orelse return null;
        const built_d = st.locallyComputedDigest(seq) orelse return null;
        if (!std.mem.eql(u8, &cert_d, &built_d)) return null;
        return st.builtContents(a, seq) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }

    /// `VersionedFullCheckpointContents` (or `FullCheckpointContents` when `v1`) of checkpoint
    /// `seq`; null when it is not served or a transaction is not in the exec store.
    pub fn fullContents(s: *Service, a: Allocator, seq: u64, v1: bool) Allocator.Error!?[]const u8 {
        const contents = (try s.servedContents(a, seq)) orelse return null;
        return buildFull(a, s.opts.exec, contents, v1) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }

    fn transactionsPage(s: *Service, a: Allocator, contents: []const u8, first: u64, end: u64) AnswerError!?[]const u8 {
        const lay = parseContents(a, contents) catch return null;
        if (first >= end or end > lay.items.len) return error.BadRequest;
        var body: std.ArrayList(u8) = .empty;
        var size: usize = 0;
        var count: usize = 0;
        for (lay.items[@intCast(first)..@intCast(end)]) |*it| {
            const item = (try executionData(a, s.opts.exec, it, lay.v2)) orelse return null;
            if (count > 0 and size + item.len > transactions_budget) break;
            size += item.len;
            count += 1;
            try body.appendSlice(a, item);
        }
        var out: std.ArrayList(u8) = .empty;
        try out.append(a, 1);
        try putUleb(&out, a, count);
        try out.appendSlice(a, body.items);
        return out.items;
    }

    fn onPush(s: *Service, from: *const anemo.PeerId, cert: []const u8) void {
        _ = s.stats.pushes_in.fetchAdd(1, .monotonic);
        const seq = certSeq(cert) orelse return;
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const gop = s.peers.getOrPut(s.gpa, from.*) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        // sui-node `update_peer_height`: the claimed height even before the chain check
        gop.value_ptr.height = @max(gop.value_ptr.height, seq);
    }

    // ------------------------------------------------------------------ discovery

    fn serveDiscovery(ctx: *anyopaque, a: Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        const s: *Service = @ptrCast(@alignCast(ctx));
        const v3 = std.mem.eql(u8, route, ss.Route.get_known_peers_v3);
        if (!v3 and !std.mem.eql(u8, route, ss.Route.get_known_peers_v2)) return .{ .status = .not_found };
        const now = s.nowMs();
        if (v3) {
            const req = decodeRequest(a, body) catch return .{ .status = .bad_request };
            const info = discovery.decodeSignedInfo(a, req, true) catch return .{ .status = .bad_request };
            _ = s.book.add(&info, true, now);
        }
        var out: std.ArrayList(u8) = .empty;
        const own = s.ownInfo(a, v3, now) catch return .{ .status = .internal_server_error };
        out.appendSlice(a, own) catch return .{ .status = .internal_server_error };
        s.book.appendShared(a, &out, v3, s.book.isTrusted(from), now, s.opts.p2p.inbound(a)) catch return .{ .status = .internal_server_error };
        return ok(a, out.items) catch .{ .status = .internal_server_error };
    }

    pub fn ownInfo(s: *Service, a: Allocator, versioned: bool, now: u64) ![]const u8 {
        s.own_mu.lockUncancelable(s.io);
        defer s.own_mu.unlock(s.io);
        if (s.own_v1.len == 0 or now -| s.own_ts >= 5_000) {
            const addrs: []const []const u8 = &.{s.external};
            const v1b = try p2p_serve.signedNodeInfo(s.gpa, &s.key, addrs, now, .public, false);
            errdefer s.gpa.free(v1b);
            const v2b = try p2p_serve.signedNodeInfo(s.gpa, &s.key, addrs, now, .public, true);
            s.gpa.free(s.own_v1);
            s.gpa.free(s.own_v2);
            s.own_v1 = v1b;
            s.own_v2 = v2b;
            s.own_ts = now;
        }
        return a.dupe(u8, if (versioned) s.own_v2 else s.own_v1);
    }

    // ------------------------------------------------------------------ client

    /// One state sync call to committee peer `i`: the response's raw BCS (snappy undone), null
    /// when the peer is unreachable or did not answer 200.
    pub fn call(s: *Service, a: Allocator, i: usize, route: []const u8, body: []const u8, timeout_ms: u64) ?[]const u8 {
        const r = s.opts.p2p.call(a, i, route, &request_headers, body, timeout_ms) orelse return null;
        if (r.status != .success) {
            log.debug("peer {d} {s}: status {d}", .{ i, route, @intFromEnum(r.status) });
            return null;
        }
        return ss.decodeBody(a, r.body) catch null;
    }

    /// `GetCheckpointSummary(BySequenceNumber(seq))` from peer `i`.
    pub fn summary(s: *Service, a: Allocator, i: usize, seq: u64) ?[]const u8 {
        return s.summaryWithin(a, i, seq, request_timeout_ms);
    }

    fn summaryWithin(s: *Service, a: Allocator, i: usize, seq: u64, timeout_ms: u64) ?[]const u8 {
        const body = ss.encodeSummaryRequest(a, .{ .seq = seq }) catch return null;
        const raw = s.call(a, i, ss.Route.get_checkpoint_summary, body, timeout_ms) orelse return null;
        return ss.optionPayload(raw) catch null;
    }

    /// `GetCheckpointContentsV2(digest)` from peer `i`: the raw `VersionedFullCheckpointContents`.
    pub fn contentsV2(s: *Service, a: Allocator, i: usize, digest: Id) ?[]const u8 {
        const body = ss.encodeDigestRequest(a, digest) catch return null;
        const raw = s.call(a, i, ss.Route.get_checkpoint_contents_v2, body, request_timeout_ms) orelse return null;
        return ss.optionPayload(raw) catch null;
    }

    pub const Latest = struct { seq: u64, cert: []const u8 };

    /// Peer `i`'s highest synced checkpoint (`query_peer_for_latest_info`), after checking once
    /// that it is on our chain (`get_latest_from_peer`). Records its height.
    pub fn latest(s: *Service, a: Allocator, i: usize) ?Latest {
        if (s.opts.p2p.isSelf(i)) return null;
        const id = s.opts.p2p.peerId(i).*;
        if (!s.checkChain(a, i, &id)) return null;
        const raw = s.call(a, i, ss.Route.get_checkpoint_availability, ss.encodeUnitRequest(), probe_timeout_ms) orelse return null;
        const av = ss.splitAvailability(raw) catch return null;
        const seq = certSeq(av.highest_synced_summary) orelse return null;
        s.noteHeight(&id, seq);
        return .{ .seq = seq, .cert = av.highest_synced_summary };
    }

    fn checkChain(s: *Service, a: Allocator, i: usize, id: *const Id) bool {
        s.mu.lockUncancelable(s.io);
        const known = if (s.peers.get(id.*)) |p| p.same_chain else null;
        s.mu.unlock(s.io);
        if (known) |k| return k;
        const g = s.summaryWithin(a, i, 0, probe_timeout_ms) orelse return false;
        const same = std.mem.eql(u8, &(certDigest(a, g) orelse return false), &s.opts.genesis_digest);
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const gop = s.peers.getOrPut(s.gpa, id.*) catch return same;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.same_chain = same;
        if (!same) log.warn("peer {d} is not on our chain (genesis differs)", .{i});
        return same;
    }

    fn noteHeight(s: *Service, id: *const Id, seq: u64) void {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const gop = s.peers.getOrPut(s.gpa, id.*) catch return;
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.height = @max(gop.value_ptr.height, seq);
    }

    /// The highest checkpoint committee peer `i` claimed (0: unknown or not on our chain).
    pub fn heightOf(s: *Service, i: usize) u64 {
        const id = s.opts.p2p.peerId(i).*;
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        const p = s.peers.get(id) orelse return 0;
        return if (p.same_chain orelse false) p.height else 0;
    }

    /// The highest checkpoint any peer on our chain claimed (pushes and polls).
    pub fn peersHighest(s: *Service) u64 {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        var hi: u64 = 0;
        var it = s.peers.valueIterator();
        while (it.next()) |p| if (p.same_chain orelse true) {
            hi = @max(hi, p.height);
        };
        return hi;
    }

    // ------------------------------------------------------------------ pushes and polls

    fn loop(s: *Service) void {
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        var last_poll: u64 = 0;
        while (!s.stop_flag.load(.acquire)) {
            Io.sleep(s.io, .fromMilliseconds(200), .awake) catch {};
            _ = arena.reset(.retain_capacity);
            const a = arena.allocator();
            s.pushNew(a);
            const now = s.nowMs();
            if (now -| last_poll >= poll_ms) {
                last_poll = now;
                for (0..s.opts.p2p.peerCount()) |i| {
                    if (s.stop_flag.load(.acquire)) return;
                    _ = s.latest(a, i);
                }
            }
        }
    }

    /// `notify_peers_of_checkpoint` for checkpoints certified since the last pass (the newest
    /// few: a peer that learns the tip syncs the rest).
    fn pushNew(s: *Service, a: Allocator) void {
        const hi = s.opts.ckpt.highestCertified() orelse return;
        if (hi <= s.pushed_through) return;
        const from = @max(s.pushed_through + 1, hi -| 3);
        s.pushed_through = hi;
        var seq = from;
        while (seq <= hi) : (seq += 1) {
            const cert = (s.opts.ckpt.certifiedCopy(a, seq) catch return) orelse continue;
            const body = snappy.compressFrame(a, cert) catch return;
            for (0..s.opts.p2p.peerCount()) |i| {
                if (s.opts.p2p.isSelf(i)) continue;
                const id = s.opts.p2p.peerId(i).*;
                s.mu.lockUncancelable(s.io);
                const info = s.peers.get(id) orelse PeerInfo{};
                s.mu.unlock(s.io);
                if (!(info.same_chain orelse false) or info.height >= seq) continue;
                const r = s.opts.p2p.call(a, i, ss.Route.push_checkpoint_summary, &request_headers, body, request_timeout_ms) orelse continue;
                if (r.status == .success) _ = s.stats.pushes_out.fetchAdd(1, .monotonic);
            }
        }
    }
};

// ---------------------------------------------------------------------------------------------
// codec helpers

fn putUleb(out: *std.ArrayList(u8), a: Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(a, b);
        try out.append(a, b | 0x80);
    }
}

/// Sequence number of BCS `CertifiedCheckpointSummary` bytes (epoch u64, then sequence u64).
pub fn certSeq(cert: []const u8) ?u64 {
    if (cert.len < 16) return null;
    return std.mem.readInt(u64, cert[8..16], .little);
}

/// The summary digest of BCS `CertifiedCheckpointSummary` bytes.
pub fn certDigest(a: Allocator, cert: []const u8) ?Id {
    const C = types.hand.Envelope(types.CheckpointSummary, types.AuthorityQuorumSignInfo);
    const c = bcs.decode(C, a, cert) catch return null;
    const sb = bcs.encodeAlloc(types.CheckpointSummary, a, &c.data) catch return null;
    return types.digest.checkpointSummaryDigest(sb);
}

/// One transaction of a `CheckpointContents`: its digests and its signatures' raw BCS (V1: a
/// `Vec<GenericSignature>`; V2: a `Vec<(GenericSignature, Option<SequenceNumber>)>`).
pub const Item = struct { tx: Id, effects: Id, sigs: []const u8 };
pub const Layout = struct { v2: bool, items: []Item };

pub fn parseContents(a: Allocator, contents: []const u8) !Layout {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    if (tag > 1) return error.Malformed;
    const n = try r.length();
    if (n > contents.len) return error.Malformed;
    const items = try a.alloc(Item, n);
    for (items) |*it| {
        const d = try r.bytes(66);
        if (d[0] != 32 or d[33] != 32) return error.Malformed;
        it.* = .{ .tx = d[1..33].*, .effects = d[34..66].*, .sigs = &.{} };
        if (tag == 1) it.sigs = try sigSpan(&r, contents, true);
    }
    if (tag == 0) {
        if (try r.length() != n) return error.Malformed;
        for (items) |*it| it.sigs = try sigSpan(&r, contents, false);
    }
    if (r.remaining() != 0) return error.TrailingBytes;
    return .{ .v2 = tag == 1, .items = items };
}

fn sigSpan(r: *bcs.Reader, raw: []const u8, with_versions: bool) ![]const u8 {
    const a = r.pos();
    const k = try r.length();
    for (0..k) |_| {
        _ = try r.bytes(try r.length());
        if (with_versions) switch (try r.int(u8)) {
            0 => {},
            1 => _ = try r.int(u64),
            else => return error.Malformed,
        };
    }
    return raw[a..r.pos()];
}

/// A V2 signature list without the alias versions (`into_v1`): a `Vec<GenericSignature>`.
fn plainSigs(a: Allocator, span: []const u8, with_versions: bool) ![]const u8 {
    if (!with_versions) return span;
    var r = bcs.Reader.init(span);
    var out: std.ArrayList(u8) = .empty;
    const k = try r.length();
    try putUleb(&out, a, k);
    for (0..k) |_| {
        const s0 = r.pos();
        _ = try r.bytes(try r.length());
        try out.appendSlice(a, span[s0..r.pos()]);
        if (try r.int(u8) == 1) _ = try r.int(u64);
    }
    return out.items;
}

/// BCS `Transaction` (`SenderSignedData` with one `SenderSignedTransaction`, intent
/// TransactionData/V0/Sui) of `td` signed with `sigs` (a `Vec<GenericSignature>`).
pub fn transactionBytes(a: Allocator, td: []const u8, sigs: []const u8) ![]const u8 {
    const out = try a.alloc(u8, 4 + td.len + sigs.len);
    out[0] = 1;
    @memset(out[1..4], 0);
    @memcpy(out[4..][0..td.len], td);
    @memcpy(out[4 + td.len ..], sigs);
    return out;
}

/// `ExecutionData { transaction, effects }` of one contents item; null when the transaction
/// is not executed here or its effects digest differs.
fn executionData(a: Allocator, ex: *exec_store.ExecStore, it: *const Item, v2: bool) !?[]const u8 {
    const x = ex.executed(&it.tx) orelse return null;
    if (!std.mem.eql(u8, &x.effects_digest, &it.effects)) return null;
    const tx = try transactionBytes(a, x.td_bcs, try plainSigs(a, it.sigs, v2));
    const out = try a.alloc(u8, tx.len + x.effects_bcs.len);
    @memcpy(out[0..tx.len], tx);
    @memcpy(out[tx.len..], x.effects_bcs);
    return out;
}

/// `VersionedFullCheckpointContents` of `contents` (or the V1 `FullCheckpointContents`).
pub fn buildFull(a: Allocator, ex: *exec_store.ExecStore, contents: []const u8, v1: bool) !?[]const u8 {
    const lay = try parseContents(a, contents);
    var out: std.ArrayList(u8) = .empty;
    if (!v1) try out.append(a, @intFromBool(lay.v2));
    try putUleb(&out, a, lay.items.len);
    for (lay.items) |*it| {
        const ed = (try executionData(a, ex, it, lay.v2)) orelse return null;
        try out.appendSlice(a, ed);
    }
    try putUleb(&out, a, lay.items.len);
    for (lay.items) |it| try out.appendSlice(a, if (v1) try plainSigs(a, it.sigs, lay.v2) else it.sigs);
    return out.items;
}

// ---------------------------------------------------------------------------------------------
// tests

const testing = std.testing;

fn testTx(a: Allocator, td: []const u8) !struct { digest: Id, effects: []const u8 } {
    const digest = types.digest.transactionDataDigest(td);
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = .{ .computationCost = 1, .storageCost = 2, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = digest } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 3 },
        .changed_objects = &.{},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    return .{ .digest = digest, .effects = try bcs.encodeAlloc(types.TransactionEffects, a, &fx) };
}

test "state sync: full contents from the validator stores split back into the certified contents" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const io = testing.io;
    var ex = exec_store.ExecStore.openMem(testing.allocator, io);
    defer ex.close();

    // TransactionData bytes only need to skip as one in splitFull: use a real empty-ish one
    const td_v: types.TransactionData = .{ .V1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = &.{}, .commands = &.{} } },
        .sender = .{ .@"0" = @splat(7) },
        .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = @splat(7) }, .price = 1000, .budget = 5000 },
        .expiration = .None,
    } };
    const td = try bcs.encodeAlloc(types.TransactionData, a, &td_v);
    var td2_v = td_v;
    td2_v.V1.gas_data.price = 1001;
    const td2 = try bcs.encodeAlloc(types.TransactionData, a, &td2_v);
    const t1 = try testTx(a, td);
    const t2 = try testTx(a, td2);
    try ex.commitTx(&.{ .digest = t1.digest, .td_bcs = td, .effects_bcs = t1.effects, .written = &.{} });
    try ex.commitTx(&.{ .digest = t2.digest, .td_bcs = td2, .effects_bcs = t2.effects, .written = &.{} });

    const ed = [_]types.ExecutionDigests{
        .{ .transaction = .{ .@"0" = .{ .@"0" = t1.digest } }, .effects = .{ .@"0" = .{ .@"0" = types.digest.effectsDigest(t1.effects) } } },
        .{ .transaction = .{ .@"0" = .{ .@"0" = t2.digest } }, .effects = .{ .@"0" = .{ .@"0" = types.digest.effectsDigest(t2.effects) } } },
    };
    const sig_a: types.hand.GenericSignature = .{ .@"0" = &([_]u8{0} ++ @as([96]u8, @splat(0xaa))) };
    const sig_b: types.hand.GenericSignature = .{ .@"0" = &([_]u8{0} ++ @as([96]u8, @splat(0xbb))) };
    const sigs = [_][]const types.hand.GenericSignature{ &.{sig_a}, &.{ sig_a, sig_b } };
    const c1: types.CheckpointContents = .{ .V1 = .{ .transactions = &ed, .user_signatures = &sigs } };
    const c1b = try bcs.encodeAlloc(types.CheckpointContents, a, &c1);
    // V1 contents: both routes, and splitFull (the fullnode client) rebuilds the same contents
    for ([_]bool{ false, true }) |v1| {
        const full = (try buildFull(a, &ex, c1b, v1)).?;
        const tagged = if (v1) try std.mem.concat(a, u8, &.{ &.{0}, full }) else full;
        const back = try node.p2p_exec.splitFull(a, tagged);
        try testing.expectEqualSlices(u8, c1b, back.contents);
        try testing.expectEqual(@as(usize, 2), back.txs.len);
        try testing.expectEqualSlices(u8, t2.effects, back.txs[1].effects);
        try testing.expectEqualSlices(u8, td2, try node.p2p_exec.txDataOf(back.txs[1].tx));
        // the transaction decodes as sui-types' Transaction
        _ = try bcs.decode(types.hand.Envelope(types.SenderSignedData, types.EmptySignInfo), a, back.txs[1].tx);
    }
    // V2 contents (alias versions): V2 route round trips, V1 route drops the versions
    const tc = [_]types.CheckpointTransactionContents{
        .{ .digest = ed[0], .user_signatures = &.{.{ sig_a, null }} },
        .{ .digest = ed[1], .user_signatures = &.{ .{ sig_a, .{ .@"0" = 9 } }, .{ sig_b, null } } },
    };
    const c2: types.CheckpointContents = .{ .V2 = .{ .transactions = &tc } };
    const c2b = try bcs.encodeAlloc(types.CheckpointContents, a, &c2);
    const full2 = (try buildFull(a, &ex, c2b, false)).?;
    const back2 = try node.p2p_exec.splitFull(a, full2);
    try testing.expectEqualSlices(u8, c2b, back2.contents);
    const full2v1 = (try buildFull(a, &ex, c2b, true)).?;
    const fc = try bcs.decode(types.FullCheckpointContents, a, full2v1);
    try testing.expectEqual(@as(usize, 2), fc.user_signatures[1].len);
    // a transaction not executed here: nothing is served
    var ex2 = exec_store.ExecStore.openMem(testing.allocator, io);
    defer ex2.close();
    try testing.expect((try buildFull(a, &ex2, c1b, false)) == null);
    // GetCheckpointTransactions pages are ExecutionData
    const lay = try parseContents(a, c1b);
    try testing.expect(!lay.v2);
    try testing.expectEqualSlices(u8, &t2.digest, &lay.items[1].tx);
}
