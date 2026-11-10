//! p2p state-sync follower: deepwave joins mainnet as an ordinary full-node peer over anemo (QUIC),
//! the way sui-node 1.83.1's state sync does, and races the other sources (bucket, stream).
//!
//!   peers --PushCheckpointSummary / GetCheckpointAvailability--> certified summaries
//!         --GetCheckpointContentsV2--> transactions + certified effects
//!   exec thread: checkpoint S once S-1 is committed: chain link and contents digest checked,
//!         every transaction executed locally (p2p_exec.zig), effects bytes equal to the
//!         certified ones, events digest equal; then the blob goes to the spool through the
//!         fetcher's claim (first verified copy wins). The follower verifies it like any source
//!         (BLS certificate against the committee, all digests, output objects against effects).
//!   Anything deepwave cannot execute, or a result that differs, leaves the checkpoint to the bucket
//!   and stream (counted as a fallback). Nothing unverified is ever committed.
//!
//! Being a peer. sui-node pushes a new checkpoint only to peers on the same chain (it asks
//! `GetCheckpointSummary(0)`) whose reported height is below it (`GetCheckpointAvailability`).
//! So deepwave answers both, plus `GetCheckpointSummary` by number and Latest, the contents of recent
//! checkpoints it holds (`GetCheckpointContents[V2]`) and discovery's `GetKnownPeersV2/V3` (its
//! own signed info, not dialable, no peers to share). Everything else is 404.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const store = @import("store");
const net = @import("net");
const source = @import("source.zig");
/// sui-node's quinn peer families (lane ops-metrics hooks, core/p2p_metrics.zig).
const p2pm = @import("core").p2p_metrics;
const px = @import("p2p_exec.zig");
const only_mod = @import("p2p_only.zig");
const Atomic = std.atomic.Value;

const anemo = net.anemo;
const ss = net.state_sync;
const discovery = net.discovery;
const peer_score = net.peer_score;
const Ed25519 = std.crypto.sign.Ed25519;

/// `dns`: a seed given by host name (`/dns/...` or `host:port`), resolved again at every dial as
/// sui-node does; `addr` then holds the last resolved address.
pub const PeerSpec = struct { addr: Io.net.IpAddress, id: ?[32]u8 = null, dns: ?net.peer_addr.Dns = null };


pub const Hooks = struct {
    ctx: *anyopaque,
    /// Protocol version, reference gas price and start of `epoch` (null: not known yet).
    params: *const fn (ctx: *anyopaque, epoch: u64) ?px.Params,
};

pub const Stats = struct {
    connects: Atomic(u64) = .init(0),
    connect_errors: Atomic(u64) = .init(0),
    /// Failed connects by why (anemo.ConnectDiag): no datagram back; closed after the handshake
    /// (connection limit) or stalled; another key at the address; local socket or DNS error.
    connect_silent: Atomic(u64) = .init(0),
    connect_refused: Atomic(u64) = .init(0),
    connect_wrong_peer: Atomic(u64) = .init(0),
    connect_local: Atomic(u64) = .init(0),
    /// Distinct peers that accepted at least one connection.
    peers_ever: Atomic(u64) = .init(0),
    peers_up: Atomic(u64) = .init(0),
    peers_max: Atomic(u64) = .init(0),
    /// GetKnownPeersV2 asked (every `query_ms` from one connected peer, as sui-node's tick).
    discovery_queries: Atomic(u64) = .init(0),
    /// Why rotating-slot sessions ended: dropped as failing, connection closed (peer or idle),
    /// a request timed out, anything else (stop included).
    sessions_dropped: Atomic(u64) = .init(0),
    sessions_closed: Atomic(u64) = .init(0),
    sessions_timeout: Atomic(u64) = .init(0),
    sessions_other: Atomic(u64) = .init(0),
    sessions_logged: Atomic(u64) = .init(0),
    sessions_replaced: Atomic(u64) = .init(0),
    pushes: Atomic(u64) = .init(0),
    polls: Atomic(u64) = .init(0),
    /// Checkpoints whose certified summary p2p saw (first sighting).
    summaries: Atomic(u64) = .init(0),
    /// First sighting came from a push (else from an availability poll).
    first_by_push: Atomic(u64) = .init(0),
    contents: Atomic(u64) = .init(0),
    contents_errors: Atomic(u64) = .init(0),
    contents_bytes: Atomic(u64) = .init(0),
    /// Checkpoints built and verified (effects equal) by local execution.
    built: Atomic(u64) = .init(0),
    /// Built and written to the spool first.
    delivered: Atomic(u64) = .init(0),
    /// Built, but another source had already claimed it.
    lost_race: Atomic(u64) = .init(0),
    /// Not built: a transaction deepwave cannot execute or whose result differs (the checkpoint comes
    /// from the bucket or the stream).
    fallbacks: Atomic(u64) = .init(0),
    /// The summary or contents arrived after another source had the checkpoint.
    late: Atomic(u64) = .init(0),
    rejected_link: Atomic(u64) = .init(0),
    txs: Atomic(u64) = .init(0),
    exec_ns: Atomic(u64) = .init(0),
    served: Atomic(u64) = .init(0),
    served_contents: Atomic(u64) = .init(0),
    /// Summary seen to blob in the spool (ms, summed over delivered), and summary first seen
    /// relative to the checkpoint timestamp.
    build_ms_sum: Atomic(u64) = .init(0),
    seen_ms_sum: Atomic(u64) = .init(0),
    /// Contents in hand relative to the checkpoint timestamp (ms, summed over fetched contents).
    contents_ms_sum: Atomic(u64) = .init(0),
    /// Blob in the spool relative to the checkpoint timestamp (ms, summed over delivered).
    spool_ms_sum: Atomic(u64) = .init(0),
    /// Contents requests started (more than one per checkpoint when peers race), and contents
    /// that arrived after another peer's copy had won.
    fetches: Atomic(u64) = .init(0),
    race_lost: Atomic(u64) = .init(0),
    /// Contents whose rebuilt digest differed from the summary's (dropped at the peer thread).
    contents_bad: Atomic(u64) = .init(0),
    /// Checkpoints built on the previous checkpoint's writes before it was committed.
    pipelined: Atomic(u64) = .init(0),
    /// Summaries asked for by number: peers push only their newest checkpoint, so one certified
    /// together with the next can go unseen (it then came from the stream, late).
    gap_requests: Atomic(u64) = .init(0),
    gap_filled: Atomic(u64) = .init(0),
    /// Checkpoints run again in order after the level-parallel run differed (p2p_exec.Pool).
    reruns: Atomic(u64) = .init(0),
    /// Summaries (push or poll) for a checkpoint already seen: handled without a decode.
    push_dups: Atomic(u64) = .init(0),
    /// Availability poll ticks skipped: the peer pushed recently, or it is outside the active
    /// set (polled every `idle_poll_ms` only).
    polls_skipped: Atomic(u64) = .init(0),
    /// Checkpoints whose contents were not fetched while builds kept falling back (a store
    /// without live objects cannot build): see `pause_after`.
    contents_paused: Atomic(u64) = .init(0),
    /// Changes of the active set (the peers contents are fetched from).
    elections: Atomic(u64) = .init(0),
    /// Discovered candidates at a seed's address (never dialled by a slot; held instead).
    slot_seed_skips: Atomic(u64) = .init(0),
    /// PushCheckpointSummary sent to a connected peer whose height is below a checkpoint we
    /// applied (sui-node `notify_peers_of_checkpoint`), and pushes that failed.
    pushes_sent: Atomic(u64) = .init(0),
    push_errors: Atomic(u64) = .init(0),
    /// Paged contents downloads (GetCheckpointContentsDigests + GetCheckpointTransactions, after
    /// a full-contents request failed): started, pages received, failed.
    paged: Atomic(u64) = .init(0),
    paged_pages: Atomic(u64) = .init(0),
    paged_failed: Atomic(u64) = .init(0),
    /// Discovery answers dropped as stale and candidates culled after a day (sui-node's 1-day
    /// NodeInfo freshness).
    discovery_stale: Atomic(u64) = .init(0),
    discovery_culled: Atomic(u64) = .init(0),
    /// GetKnownPeersV3 queries (`use-get-known-peers-v3`).
    discovery_v3: Atomic(u64) = .init(0),
};

pub const Outcome = enum(u8) { none, delivered, lost, fallback, late, paused };

/// Push lag of a peer with no push yet (`P2p.push_lag_ms`).
pub const no_lag: u32 = std.math.maxInt(u32);

/// What `elect` knows about one peer slot.
pub const ElectInfo = struct {
    up: bool = false,
    /// Not off-chain and not failing.
    ok: bool = true,
    /// Smoothed delay of its pushes behind the first sighting (ms; `no_lag`: none yet).
    lag_ms: u32 = no_lag,
    /// Smoothed availability round trip (us; max: not measured).
    rtt_us: u64 = std.math.maxInt(u64),
};

/// The active set: the `cap` connected, healthy peers whose pushes arrive soonest behind the first
/// sighting (peers without a push yet after them, by RTT, unmeasured last). A member of `prev`
/// keeps its place against a challenger less than `hysteresis_ms` faster, so the set does not
/// flap on noise. Bit j: peer j. 0 with `cap` 0 or no peer up (the caller then treats every peer
/// as active).
pub fn elect(infos: []const ElectInfo, cap: usize, prev: u64) u64 {
    const hysteresis_ms = 25;
    if (cap == 0) return 0;
    var idx: [max_peers]u8 = undefined;
    var keys: [max_peers]u64 = undefined;
    var n: usize = 0;
    for (infos[0..@min(infos.len, max_peers)], 0..) |inf, j| {
        if (!inf.up or !inf.ok) continue;
        const incumbent = prev & (@as(u64, 1) << @intCast(j)) != 0;
        const key: u64 = if (inf.lag_ms != no_lag)
            (@as(u64, if (incumbent) inf.lag_ms -| hysteresis_ms else inf.lag_ms))
        else if (inf.rtt_us != std.math.maxInt(u64))
            (@as(u64, 1) << 48) | @min(inf.rtt_us, (@as(u64, 1) << 48) - 1)
        else
            (@as(u64, 2) << 48) | @as(u64, j);
        // insertion sort: at most 64 entries, once a second
        var k = n;
        while (k > 0 and keys[k - 1] > key) : (k -= 1) {
            keys[k] = keys[k - 1];
            idx[k] = idx[k - 1];
        }
        keys[k] = key;
        idx[k] = @intCast(j);
        n += 1;
    }
    var m: u64 = 0;
    for (idx[0..@min(n, cap)]) |j| m |= @as(u64, 1) << @intCast(j);
    return m;
}

/// Whether a session polls its peer's availability now. Every peer is polled at least every
/// `idle_ms` (RTT, height, the failing-peer tick). An active peer is polled every `poll_ms`,
/// except while it pushes: a push carries the same certified summary, so a poll within
/// `skip_ms` of the peer's last push would only repeat it (about 19 polls per checkpoint with
/// 40 peers before this).
pub fn pollDue(now: u64, last_poll: u64, last_push: u64, active: bool, poll_ms: u64, skip_ms: u64, idle_ms: u64) bool {
    const since = now -| last_poll;
    if (since >= idle_ms) return true;
    if (!active or since < poll_ms) return false;
    return last_push == 0 or now -| last_push >= skip_ms;
}

pub const ring = 512;
/// Seeds plus discovered peers (one thread each; the fetch masks are 64 bits).
const max_peers = 64;

pub const Slot = struct {
    seq: u64 = std.math.maxInt(u64),
    cert: []u8 = &.{},
    content_digest: [32]u8 = undefined,
    timestamp_ms: u64 = 0,
    seen_ms: u64 = 0,
    state: enum { none, fetching, ready, failed } = .none,
    tries: u8 = 0,
    full: []u8 = &.{},
    done: bool = false,
    /// Peers with a contents request in flight for it (bit i: peer i), how many, and when the
    /// first one started.
    fetch_mask: u64 = 0,
    inflight: u8 = 0,
    fetch_ms: u64 = 0,
    // Per-checkpoint timeline (`--p2p-trace`), wall clock ms.
    seen_peer: u8 = 0,
    pushed: bool = false,
    racers: u8 = 0,
    contents_ms: u64 = 0,
    contents_peer: u8 = 0,
    exec0_ms: u64 = 0,
    exec1_ms: u64 = 0,
    spool_ms: u64 = 0,
    ntx: u32 = 0,
    parent: bool = false,
    outcome: Outcome = .none,
    /// Execute in order (no level-parallel run): a p2p-only retry (p2p_only.zig).
    serial: bool = false,
    /// Most transactions per GetCheckpointTransactions page: halved after a page fails, so the
    /// next peer asks for smaller pages (sui-node `PaginatedProgress.max_items`).
    page_max: u64 = std.math.maxInt(u64),
    /// In the tile pipeline (p2p_tiles.zig) and not finished: not queued again (lock held).
    queued: bool = false,
    /// The exec thread is building it outside the lock (`execLoop`): `cert` and `full` are in
    /// use, so the slot is not reused for a later sequence number until the build returns.
    building: bool = false,
};

/// A built checkpoint's writes, kept until it is committed so the next one can run on them.
pub const Parent = struct { seq: u64, digest: [32]u8, layer: px.Layer };

pub const P2p = struct {
    gpa: std.mem.Allocator,
    io: Io,
    st: *store.Store,
    fetcher: *source.Fetcher,
    /// Seeds (`--p2p`).
    peers: []const PeerSpec,
    /// Seeds, then peers learned from them (GetKnownPeersV2): `n_peers` are live.
    specs: []PeerSpec = &.{},
    n_peers: Atomic(usize) = .init(0),
    /// Connection slots for discovered peers (net/peer_pool.zig rotates candidates through them).
    discover: u8 = 32,
    discovered: Atomic(bool) = .init(false),
    /// Every peer learned from discovery, with its dial backoff.
    cands: net.peer_pool.Pool = undefined,
    /// Its backoffs (`discovery.peer-failure-cooldown-ms` sets the silent and wrong-key ones).
    pool_cfg: net.peer_pool.Config = .{},
    /// sui-node's discovery tick: one connected peer is asked for its known peers this often.
    query_ms: u64 = 5_000,
    next_query_ms: Atomic(u64) = .init(0),
    /// Handshake timeout for discovered peers (seeds: 10 s). A good peer answers in about 1 s
    /// even across oceans; most bad ones never answer at all.
    dial_timeout_ms: u64 = 4_000,
    key: Ed25519.KeyPair,
    hooks: Hooks,
    poll_ms: u32 = 500,
    /// Peers asked for a checkpoint's contents at once (the lowest-RTT peers that have it). One:
    /// a second copy of the same contents only after `hedge_ms` without an answer (two at once
    /// doubled the contents traffic and decode for a 30 ms p50 gain).
    race: u8 = 1,
    /// Active set size (`--p2p-push-peers`, 0: every connected peer): contents are fetched and
    /// availability polled every `poll_ms` only from these peers, the ones whose pushes arrive
    /// first (`elect`, every second). Every connected peer still pushes to us (sui-node pushes
    /// each new checkpoint to every peer below it) and every push counts as a sighting, but a
    /// push for a checkpoint already seen costs no decode. The others are polled every
    /// `idle_poll_ms` and take a fetch only when no active peer has the checkpoint or it has had
    /// no answer for `stuck_ms`.
    push_peers: u8 = 8,
    /// An active peer that pushed within this long is not polled (`pollDue`).
    poll_skip_ms: u64 = 3_000,
    /// Poll interval of peers outside the active set, and the longest gap for any peer.
    idle_poll_ms: u64 = 10_000,
    /// A checkpoint seen this long ago whose contents are not in hand: any peer may fetch it.
    stuck_ms: u64 = 500,
    /// After this many builds in a row fell back (none built), contents are fetched only for one
    /// checkpoint in `probe_every` until one builds again: a store without live objects (verify
    /// only, started from the tip) cannot build any, and fetching each checkpoint's contents was
    /// most of the p2p contents traffic there. Never in p2p-only mode. 0: off.
    pause_after: u32 = 32,
    probe_every: u64 = 16,
    fallback_streak: Atomic(u32) = .init(0),
    /// Bit j: peer j is in the active set (0: not elected yet, every peer counts as active).
    active: Atomic(u64) = .init(0),
    /// Exec thread only: when the active set is next elected.
    next_elect_ms: u64 = 0,
    /// Per peer: wall clock ms of its last push, and the smoothed lag of its pushes behind the
    /// first sighting of the same checkpoint (ms, `no_lag`: none yet).
    last_push_ms: []Atomic(u64) = &.{},
    push_lag_ms: []Atomic(u32) = &.{},
    /// A further peer joins a fetch with no answer after this long (or takes an unstarted one
    /// that the top peers have not picked up).
    hedge_ms: u64 = 120,
    wait_ms: u64 = 15,
    /// One log line per applied checkpoint with its p2p timeline.
    trace: bool = false,
    /// Threads executing a checkpoint's independent transactions (1: in order).
    exec_threads: u8 = 4,
    pool: px.Pool = undefined,
    stats: Stats = .{},
    /// `--tiles`: the checkpoint tip path runs as a pipeline of pinned tiles on shared-memory
    /// rings (p2p_tiles.zig) instead of the exec thread. Off: the path above, unchanged.
    tiles: bool = false,
    /// Cores for the tiles (`--tile-cpus`), in pipeline order; fewer than tiles: the rest float.
    tile_cpus: []const u16 = &.{},
    /// Tiles spin on their rings without ever sleeping (`--tile-spin`).
    tile_spin: bool = false,
    pipeline: ?*@import("p2p_tiles.zig").Pipeline = null,
    /// Bumped whenever a slot may have become ready to build (contents arrived, a build ended):
    /// the ingest tile takes the lock only when it moved (or every millisecond).
    ready_gen: Atomic(u64) = .init(0),
    stopping: Atomic(bool) = .init(false),
    threads: std.ArrayList(std.Thread) = .empty,
    lock: Io.Mutex = .init,
    slots: []Slot = &.{},
    heights: []Atomic(u64) = &.{},
    /// Smoothed round trip of the availability poll per peer (us; max: not measured yet).
    rtt_us: []Atomic(u64) = &.{},
    up: []Atomic(bool) = &.{},
    /// Exec thread only.
    parent: ?Parent = null,
    /// Sequence number whose summary was asked for by number, by `seq % ring` (lock held).
    gap_req: []u64 = &.{},
    genesis: ?[]u8 = null,
    /// The network followed: TLS server name and the genesis digest peers must serve.
    net: *const @import("network.zig").Params = &@import("network.zig").mainnet,
    pkg_src: px.PackageSource = undefined,
    exec_stats: px.Stats = .{},
    /// Fallback reasons (first few, for the log).
    reasons: [16]?[]const u8 = @splat(null),
    reason_counts: [16]u64 = @splat(0),
    /// The last fallback's reason (exec thread only).
    last_reason: []const u8 = "",
    /// sui-node state-sync peer scoring, balancer order, failing-peer drop and cooldown, pruning
    /// (net/peer_score.zig). Seeds are its configured (trusted) peers.
    scores: peer_score.Table = .{},
    /// `pinned-checkpoints`: a summary at a pinned sequence number must have the pinned digest.
    pinned: peer_score.Pinned = .{},
    /// No other source (p2p_only.zig): fallbacks are retried here, never left to the bucket.
    p2p_only: bool = false,
    only: only_mod.State = .{},
    /// Serves peers' requests on our outbound connections when set (p2p_serve.Server); else `answer`.
    server: ?anemo.Handler = null,
    /// Discovered peers' signed infos go here when set (p2p_serve.PeerBook, served to others).
    book: ?*@import("p2p_serve.zig").PeerBook = null,
    /// The node's server: our signed info for GetKnownPeersV3.
    srv: ?*@import("p2p_serve.zig").Server = null,
    /// sui-node's `is_trusted_peer` set (seeds with an id, `allowlisted-peers`): their Private
    /// and Trusted infos are dialable.
    trusted: []const [32]u8 = &.{},
    /// `state-sync.use-get-checkpoint-contents-v2` (default true; false: the V1 route).
    contents_v2: bool = true,
    /// `discovery.use-get-known-peers-v3` (default false): ask GetKnownPeersV3 with our info.
    known_peers_v3: bool = false,
    /// Highest checkpoint the node applied (any source): pushed to connected peers below it.
    synced: Atomic(u64) = .init(0),
    /// Per peer: the highest checkpoint we pushed to it.
    pushed_to: []Atomic(u64) = &.{},

    pub fn init(p: *P2p) !void {
        p.slots = try p.gpa.alloc(Slot, ring);
        p.gap_req = try p.gpa.alloc(u64, ring);
        @memset(p.gap_req, std.math.maxInt(u64));
        for (p.slots) |*s| s.* = .{};
        if (p.peers.len > max_peers) return error.TooManyPeers;
        p.specs = try p.gpa.alloc(PeerSpec, max_peers);
        @memcpy(p.specs[0..p.peers.len], p.peers);
        p.n_peers.store(p.peers.len, .release);
        for (0..p.peers.len) |i| p.scores.trusted[i] = true;
        p.heights = try p.gpa.alloc(Atomic(u64), max_peers);
        for (p.heights) |*h| h.* = .init(0);
        p.rtt_us = try p.gpa.alloc(Atomic(u64), max_peers);
        for (p.rtt_us) |*r| r.* = .init(std.math.maxInt(u64));
        p.up = try p.gpa.alloc(Atomic(bool), max_peers);
        for (p.up) |*u| u.* = .init(false);
        p.last_push_ms = try p.gpa.alloc(Atomic(u64), max_peers);
        for (p.last_push_ms) |*x| x.* = .init(0);
        p.push_lag_ms = try p.gpa.alloc(Atomic(u32), max_peers);
        for (p.push_lag_ms) |*x| x.* = .init(no_lag);
        p.pushed_to = try p.gpa.alloc(Atomic(u64), max_peers);
        for (p.pushed_to) |*x| x.* = .init(0);
        p.cands = .{ .gpa = p.gpa, .own_id = p.key.public_key.toBytes(), .trusted = p.trusted, .cfg = p.pool_cfg };
        for (p.peers) |sp| if (sp.id) |id| p.cands.hold(&id);
        // sui-node labels seed peers given with a peer id (`known_peers`)
        for (p.peers) |sp| if (sp.id) |id| p2pm.quinn.addKnown(&id, "seed_peer");
        p.pkg_src = .{ .keep = .init(p.gpa) };
        p.pkg_src.bind();
        p.pool = .{ .gpa = p.gpa, .io = p.io };
        try p.pool.start(p.exec_threads);
    }

    pub fn start(p: *P2p) !void {
        try p.init();
        // Named threads: the live run's sampler adds up p2p CPU from /proc/PID/task/*/stat.
        for (0..p.peers.len) |i| {
            const t = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, peerLoop, .{ p, i });
            t.setName(p.io, "p2p-peer") catch {};
            try p.threads.append(p.gpa, t);
        }
        if (p.discover == 0) p.discovered.store(true, .release);
        const slots = @min(p.discover, max_peers - p.peers.len);
        for (p.peers.len..p.peers.len + slots) |i| {
            p.specs[i] = .{ .addr = .{ .ip4 = Io.net.Ip4Address.unspecified(0) } };
            const t = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, slotLoop, .{ p, i });
            t.setName(p.io, "p2p-peer") catch {};
            try p.threads.append(p.gpa, t);
        }
        p.n_peers.store(p.peers.len + slots, .release);
        if (p.tiles) {
            p.pipeline = try @import("p2p_tiles.zig").Pipeline.create(p);
            try p.pipeline.?.start();
        } else try p.threads.append(p.gpa, try std.Thread.spawn(.{ .stack_size = 64 << 20 }, execLoop, .{p}));
    }

    pub fn stop(p: *P2p) void {
        p.lock.lockUncancelable(p.io);
        p.stopping.store(true, .release);
        p.lock.unlock(p.io);
        if (p.pipeline) |pl| {
            pl.stop();
            pl.destroy();
            p.pipeline = null;
        }
        for (p.threads.items) |t| t.join();
        p.threads.deinit(p.gpa);
        for (p.slots) |*s| {
            p.gpa.free(s.cert);
            p.gpa.free(s.full);
        }
        p.gpa.free(p.slots);
        p.gpa.free(p.gap_req);
        p.gpa.free(p.heights);
        p.gpa.free(p.rtt_us);
        p.gpa.free(p.specs);
        p.gpa.free(p.up);
        p.gpa.free(p.last_push_ms);
        p.gpa.free(p.push_lag_ms);
        p.gpa.free(p.pushed_to);
        if (p.genesis) |g| p.gpa.free(g);
        p.cands.deinit();
        p.pkg_src.deinit();
        p.pool.stop();
    }

    /// Sleeps up to `ms`, waking within 50 ms of `stop`.
    fn sleepMs(p: *P2p, ms: u64) void {
        var left = ms;
        while (left > 0 and !p.stopping.load(.acquire)) {
            const step = @min(left, 50);
            p.io.sleep(.fromMilliseconds(@intCast(step)), .awake) catch {};
            left -= step;
        }
    }

    /// Counts a failed connect by class and maps it to the pool's backoff class.
    fn noteConnectFail(p: *P2p, d: *const anemo.ConnectDiag) net.peer_pool.Outcome {
        _ = p.stats.connect_errors.fetchAdd(1, .monotonic);
        const o: net.peer_pool.Outcome = switch (d.class) {
            .silent => .silent,
            .stalled, .peer_closed, .anemo => .refused,
            .local_closed => if (std.mem.eql(u8, d.reason(), "PeerIdMismatch")) .wrong_peer else .refused,
            .socket, .cancelled => .local,
        };
        _ = switch (o) {
            .silent => p.stats.connect_silent.fetchAdd(1, .monotonic),
            .refused => p.stats.connect_refused.fetchAdd(1, .monotonic),
            .wrong_peer => p.stats.connect_wrong_peer.fetchAdd(1, .monotonic),
            .local, .ended => p.stats.connect_local.fetchAdd(1, .monotonic),
        };
        return o;
    }

    fn connectOpts(p: *P2p, i: usize, id: ?[32]u8, timeout_ms: u64, diag: *anemo.ConnectDiag) anemo.Options {
        return .{
            .server_name = p.net.p2p_server_name,
            .expected = id,
            .identity_seed = p.key.secret_key.seed(),
            .handshake_timeout_ms = timeout_ms,
            .handler = p.server orelse .{ .ctx = @ptrCast(&handler_ctxs[i]), .serve = serveRequest },
            .cancel = &p.stopping,
            .diag = diag,
        };
    }

    fn peerUp(p: *P2p, i: usize) void {
        _ = p.stats.connects.fetchAdd(1, .monotonic);
        const up = p.stats.peers_up.fetchAdd(1, .monotonic) + 1;
        var m = p.stats.peers_max.load(.monotonic);
        while (up > m) m = p.stats.peers_max.cmpxchgWeak(m, up, .monotonic, .monotonic) orelse break;
        p.up[i].store(true, .monotonic);
    }

    fn peerDown(p: *P2p, i: usize) void {
        p.up[i].store(false, .monotonic);
        p.scores.lostPeer(i);
        _ = p.stats.peers_up.fetchSub(1, .monotonic);
    }

    /// Why a session ended, as far as QUIC knows: who closed, the code and reason, the state.
    /// The first 40 and then every 100th (`sessions_logged`).
    fn logSessionEnd(p: *P2p, i: usize, peer: *anemo.Peer, why: ?anyerror, ms: u64) void {
        const n = p.stats.sessions_logged.fetchAdd(1, .monotonic);
        if (n >= 40 and n % 100 != 0) return;
        const c = peer.conn;
        if (c.close) |ci| {
            std.log.info("p2p: slot {d} peer {x} session ended after {d} ms ({s}): closed by {s}, code 0x{x}{s}, reason '{s}', state {s}", .{ i, peer.peer_id[0..4], ms, if (why) |e| @errorName(e) else "-", if (ci.remote) "peer" else "us", ci.code, if (ci.app) " (app)" else "", ci.reason, @tagName(c.state) });
        } else {
            std.log.info("p2p: slot {d} session ended after {d} ms ({s}): no CONNECTION_CLOSE, state {s}", .{ i, ms, if (why) |e| @errorName(e) else "-", @tagName(c.state) });
        }
    }

    /// A rotating slot: takes the next due candidate from discovery, dials each of its
    /// addresses (IP and /dns, as sui-node's try_to_connect_to_peer), runs the session, and gives
    /// the candidate back with the outcome (net/peer_pool.zig decides when it is tried again).
    fn slotLoop(p: *P2p, i: usize) void {
        handler_ctxs[i] = .{ .p = p, .peer = i };
        while (!p.stopping.load(.acquire)) {
            var c: net.peer_pool.Candidate = undefined;
            if (!p.cands.take(source.wallMs(), &c)) {
                p.sleepMs(250);
                continue;
            }
            var outcome: net.peer_pool.Outcome = .local;
            var connected = false;
            for (0..c.n_addrs) |k| {
                if (p.stopping.load(.acquire)) break;
                const ip: Io.net.IpAddress = switch (discovery.parseAddress(c.addr(k)) orelse continue) {
                    .ip4_or_6 => |ip| ip,
                    .dns => |h| net.peer_addr.resolve(p.io, .{ .dns = .{ .name = h.host, .port = h.port } }) catch {
                        _ = p.stats.connect_errors.fetchAdd(1, .monotonic);
                        _ = p.stats.connect_local.fetchAdd(1, .monotonic);
                        continue;
                    },
                };
                // A seed's address under another listing (a seed given without its PeerId, not
                // connected yet, so not held): its own thread dials it; a slot dialling it too
                // would make anemo close one of the two connections. Held from now on.
                if (p.isSeedAddr(&ip)) {
                    p.cands.hold(&c.id);
                    _ = p.stats.slot_seed_skips.fetchAdd(1, .monotonic);
                    break;
                }
                p.scores.resetPeer(i);
                p.heights[i].store(0, .monotonic);
                p.rtt_us[i].store(std.math.maxInt(u64), .monotonic);
                p.last_push_ms[i].store(0, .monotonic);
                p.push_lag_ms[i].store(no_lag, .monotonic);
                p.pushed_to[i].store(0, .monotonic);
                p.dropActive(i);
                p.specs[i] = .{ .addr = ip, .id = c.id };
                var diag: anemo.ConnectDiag = .{};
                const peer = anemo.Peer.connect(p.gpa, p.io, ip, p.connectOpts(i, c.id, p.dial_timeout_ms, &diag)) catch {
                    if (p.stopping.load(.acquire)) break;
                    outcome = p.noteConnectFail(&diag);
                    continue;
                };
                connected = true;
                if (c.oks == 0) _ = p.stats.peers_ever.fetchAdd(1, .monotonic);
                p.peerUp(i);
                var why: ?anyerror = null;
                const s0 = source.wallMs();
                p.session(peer, i) catch |e| {
                    why = e;
                };
                p.logSessionEnd(i, peer, why, source.wallMs() -| s0);
                _ = (if (why == null) &p.stats.sessions_other else switch (why.?) {
                    error.PeerDropped => &p.stats.sessions_dropped,
                    error.ConnectionClosed => &p.stats.sessions_closed,
                    error.RequestTimeout => &p.stats.sessions_timeout,
                    else => &p.stats.sessions_other,
                }).fetchAdd(1, .monotonic);
                // A peer reported failing (sui-node's state-sync report) gets sui-node's
                // treatment, a cooldown, not a reconnect 2 s later: that loop was 4,742 connects
                // to 46 peers in a 30 min run.
                // Closed by the peer with app code 0 within seconds of the handshake is anemo
                // replacing this connection with another from our PeerId (a seed thread or our
                // listener's inbound session holds the same peer): redialling 2 s later just
                // kicks the other one, so it waits as long as a refusal.
                const replaced = why != null and why.? == error.ConnectionClosed and source.wallMs() -| s0 < 10_000 and
                    if (peer.conn.close) |ci| ci.remote and ci.app and ci.code == 0 else false;
                if (replaced) _ = p.stats.sessions_replaced.fetchAdd(1, .monotonic);
                outcome = if (p.scores.isOffChain(i)) .wrong_peer else if (replaced or (why != null and why.? == error.PeerDropped)) .refused else .ended;
                p.peerDown(i);
                peer.deinit();
                break;
            }
            p.specs[i].id = null;
            p.cands.release(&c.id, outcome, connected, source.wallMs());
        }
    }

    /// `ip` is a configured seed's address as given (`--p2p`). A seed given by /dns name is not
    /// matched here (its parsed address is a placeholder); it is held once it connects.
    fn isSeedAddr(p: *const P2p, ip: *const Io.net.IpAddress) bool {
        for (p.peers) |*sp| if (sp.dns == null and sp.addr.eql(ip)) return true;
        return false;
    }

    // ------------------------------------------------------------ active set

    /// Peer `i` fetches contents and polls at the full rate (see `push_peers`).
    pub fn isActive(p: *const P2p, i: usize) bool {
        if (p.push_peers == 0) return true;
        const m = p.active.load(.monotonic);
        return m == 0 or (i < 64 and m & (@as(u64, 1) << @intCast(i)) != 0);
    }

    /// A slot that now holds another peer leaves the active set until the next election.
    fn dropActive(p: *P2p, i: usize) void {
        if (i >= 64) return;
        _ = p.active.fetchAnd(~(@as(u64, 1) << @intCast(i)), .monotonic);
    }

    /// Some connected active peer has reported `seq` (lock not needed: atomics only).
    fn activeHas(p: *const P2p, seq: u64) bool {
        const m = p.active.load(.monotonic);
        if (p.push_peers == 0 or m == 0) return true;
        var bits = m;
        while (bits != 0) : (bits &= bits - 1) {
            const j = @ctz(bits);
            if (j < p.up.len and p.up[j].load(.monotonic) and p.heights[j].load(.monotonic) >= seq) return true;
        }
        return false;
    }

    /// Exec thread: elects the active set once a second.
    pub fn maybeElect(p: *P2p, now_ms: u64) void {
        if (p.push_peers == 0 or now_ms < p.next_elect_ms) return;
        p.next_elect_ms = now_ms + 1000;
        const n = @min(p.n_peers.load(.acquire), max_peers);
        var infos: [max_peers]ElectInfo = undefined;
        const ns = source.nowNs();
        for (0..n) |j| infos[j] = .{
            .up = p.up[j].load(.monotonic),
            .ok = !p.scores.isOffChain(j) and !p.scores.isFailing(j, ns),
            .lag_ms = p.push_lag_ms[j].load(.monotonic),
            .rtt_us = p.rtt_us[j].load(.monotonic),
        };
        const old = p.active.load(.monotonic);
        const m = elect(infos[0..n], p.push_peers, old);
        if (m != old) {
            p.active.store(m, .monotonic);
            _ = p.stats.elections.fetchAdd(1, .monotonic);
        }
    }

    /// One push from `peer` arrived `lag_ms` after the checkpoint's first sighting (0: it was
    /// the first). Smoothed 1/8, capped at 5 s.
    fn notePushLag(p: *P2p, peer: usize, lag_ms: u64) void {
        if (peer >= p.push_lag_ms.len) return;
        const lag: u32 = @intCast(@min(lag_ms, 5_000));
        const old = p.push_lag_ms[peer].load(.monotonic);
        p.push_lag_ms[peer].store(if (old == no_lag) lag else @intCast((@as(u64, old) * 7 + lag) / 8), .monotonic);
    }

    /// Contents fetches are paused (builds keep falling back; see `pause_after`).
    pub fn contentsPaused(p: *const P2p) bool {
        return !p.p2p_only and p.pause_after != 0 and p.fallback_streak.load(.monotonic) >= p.pause_after;
    }

    fn noteReason(p: *P2p, why: []const u8) void {
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        for (&p.reasons, &p.reason_counts) |*r, *c| {
            if (r.*) |have| {
                if (std.mem.eql(u8, have, why)) {
                    c.* += 1;
                    return;
                }
            } else {
                r.* = p.gpa.dupe(u8, why) catch return;
                c.* = 1;
                std.log.info("p2p: fallback: {s}", .{why});
                return;
            }
        }
    }

    // ------------------------------------------------------------ summaries

    /// Records a certified summary from a peer (push or availability). Untrusted until the exec
    /// thread checks the chain link and the follower the certificate. With 40 peers about 38
    /// pushes arrive per checkpoint, all but the first for a checkpoint already seen: those only
    /// move the peer's height, push time and push lag, with no decode.
    fn onSummary(p: *P2p, peer: usize, cert: []const u8, pushed: bool) void {
        if (cert.len < 57 + 8) return;
        const seq = std.mem.readInt(u64, cert[8..16], .little);
        const now = source.wallMs();
        if (peer < p.heights.len) {
            var h = p.heights[peer].load(.monotonic);
            while (seq > h) h = p.heights[peer].cmpxchgWeak(h, seq, .monotonic, .monotonic) orelse break;
            if (pushed) p.last_push_ms[peer].store(now, .monotonic);
        }
        const lo = p.fetcher.applied_next.load(.acquire);
        if (seq < lo or seq >= lo + ring) return;
        if (cert[24] != 32) return;
        // A pinned sequence number is checked on every copy (a peer on another chain is found
        // whichever copy came first); nothing else needs the summary decoded twice.
        if (p.pinned.items.len > 0 and p.pinned.check(seq, &@as([32]u8, @splat(0))) != .not_pinned) {
            var pr = bcs.Reader.init(cert);
            bcs.skip(types.CheckpointSummary, &pr) catch return;
            const d = hash.blake2b256(&.{ "CheckpointSummary::", cert[0..pr.pos()] });
            if (p.pinned.check(seq, &d) == .mismatch) {
                _ = p.scores.stats.pinned_rejects.fetchAdd(1, .monotonic);
                std.log.warn("p2p: peer {d} served checkpoint {d} with a digest other than the pinned one; treated as another chain", .{ peer, seq });
                p.scores.markOffChain(peer);
                return;
            }
        }
        if (p.seenAlready(peer, seq, pushed, now)) return;
        var r = bcs.Reader.init(cert);
        bcs.skip(types.CheckpointSummary, &r) catch return;
        const ts_at = blk: {
            // timestamp_ms follows epoch_rolling_gas_cost_summary; decode the summary for it
            var a = std.heap.ArenaAllocator.init(p.gpa);
            defer a.deinit();
            const s = bcs.decode(types.CheckpointSummary, a.allocator(), cert[0..r.pos()]) catch return;
            break :blk s.timestamp_ms;
        };
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        p.fetcher.noteSeen(seq, if (pushed) .push else .poll);
        const slot = &p.slots[seq % ring];
        if (slot.seq == seq) {
            // another peer's copy got here while this one decoded
            _ = p.stats.push_dups.fetchAdd(1, .monotonic);
            if (pushed) p.notePushLag(peer, now -| slot.seen_ms);
            return;
        }
        // S + ring maps to S's slot. Once S is applied from another source, a summary for S + ring
        // is in range while S may still be building here (execLoop or the tile pipeline read
        // `cert` and `full` outside the lock): freeing them under the builder was a use after
        // free. Leave the slot; S + ring is asked for again once the slot is free.
        if (slot.building or slot.queued) return;
        p.gpa.free(slot.cert);
        p.gpa.free(slot.full);
        slot.* = .{ .seq = seq, .cert = p.gpa.dupe(u8, cert) catch return, .content_digest = cert[25..57].*, .timestamp_ms = ts_at, .seen_ms = now, .seen_peer = @intCast(@min(peer, 255)), .pushed = pushed };
        _ = p.stats.summaries.fetchAdd(1, .monotonic);
        if (pushed) {
            _ = p.stats.first_by_push.fetchAdd(1, .monotonic);
            p.notePushLag(peer, 0);
        }
        _ = p.stats.seen_ms_sum.fetchAdd(slot.seen_ms -| ts_at, .monotonic);
    }

    /// The summary of `seq` is in its slot already: notes the sighting (and the push lag) and
    /// returns true.
    fn seenAlready(p: *P2p, peer: usize, seq: u64, pushed: bool, now: u64) bool {
        p.lock.lockUncancelable(p.io);
        const slot = &p.slots[seq % ring];
        const have = slot.seq == seq;
        const first_ms = slot.seen_ms;
        p.lock.unlock(p.io);
        if (!have) return false;
        p.fetcher.noteSeen(seq, if (pushed) .push else .poll);
        _ = p.stats.push_dups.fetchAdd(1, .monotonic);
        if (pushed) p.notePushLag(peer, now -| first_ms);
        return true;
    }

    /// A summary pushed by `from` (p2p_serve.Server, inbound or outbound connection): counted
    /// against the peer's slot when it is one of ours.
    pub fn onPush(p: *P2p, from: *const [32]u8, cert: []const u8) void {
        if (p.slots.len == 0) return; // not started
        _ = p.stats.pushes.fetchAdd(1, .monotonic);
        const n = p.n_peers.load(.acquire);
        const i = for (p.specs[0..n], 0..) |sp, j| {
            if (sp.id) |id| if (std.mem.eql(u8, &id, from)) break j;
        } else max_peers;
        p.onSummary(i, cert, true);
    }

    const Job = struct { seq: u64, digest: [32]u8 };

    /// `peer`'s place in sui-node's PeerBalancer order for `seq` (net/peer_score.zig: peers with
    /// a throughput by throughput, others by RTT, 10% exploration, failing peers last) among the
    /// connected peers that have it (lock held).
    fn rank(p: *P2p, peer: usize, seq: u64) usize {
        const View = struct {
            p: *P2p,
            pub fn count(v: @This()) usize {
                return v.p.n_peers.load(.acquire);
            }
            pub fn info(v: @This(), j: usize) peer_score.PeerInfo {
                const us = v.p.rtt_us[j].load(.monotonic);
                // Only the active set competes for a fetch (outside it: `pickWork`'s fallback).
                return .{ .connected = v.p.up[j].load(.monotonic) and v.p.isActive(j), .height = v.p.heights[j].load(.monotonic), .rtt_ns = if (us == std.math.maxInt(u64)) us else us * 1000 };
            }
        };
        return p.scores.rank(peer, seq, source.nowNs(), View{ .p = p });
    }

    /// A checkpoint whose contents this peer should fetch now. Contents are requested as soon as
    /// the summary is seen (the certificate is checked later, by the follower). The `race`
    /// lowest-RTT peers that have the checkpoint ask at once and the first answer wins; any other
    /// peer joins only when the top peers have not started within `wait_ms`, or a fetch has had
    /// no answer for `hedge_ms` (a slow or stuck peer).
    /// Only active peers (`push_peers`) take fetches, unless no active peer has the checkpoint or
    /// it has waited `stuck_ms` since it was seen. One request per checkpoint is in flight
    /// (`race` 1) until the hedge: a contents digest is never fetched from several peers at once
    /// for nothing.
    fn pickWork(p: *P2p, peer: usize) ?Job {
        const lo = p.fetcher.applied_next.load(.acquire);
        const h = p.heights[peer].load(.monotonic);
        const bit = @as(u64, 1) << @intCast(peer % 64);
        const now = source.wallMs();
        const act = p.isActive(peer);
        const paused = p.contentsPaused();
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        var seq = lo;
        while (seq < lo + 8 and seq <= h) : (seq += 1) {
            const slot = &p.slots[seq % ring];
            if (slot.seq != seq or slot.done or slot.fetch_mask & bit != 0) continue;
            if (paused and slot.state == .none and seq % @max(p.probe_every, 1) != 0) {
                // Builds keep falling back: leave it to the other sources (no contents fetch).
                slot.done = true;
                slot.outcome = .paused;
                _ = p.stats.contents_paused.fetchAdd(1, .monotonic);
                continue;
            }
            if (!act and now -| slot.seen_ms < p.stuck_ms and p.activeHas(seq)) continue;
            switch (slot.state) {
                .ready, .failed => continue,
                .none => if (p.rank(peer, seq) >= p.race and now -| slot.seen_ms < p.wait_ms) continue,
                .fetching => {
                    if (slot.inflight >= p.race + 1) continue;
                    const top = slot.inflight < p.race and p.rank(peer, seq) < p.race;
                    if (!top and now -| slot.fetch_ms < p.hedge_ms) continue;
                },
            }
            if (!p.fetcher.wants(seq)) {
                slot.done = true;
                slot.outcome = .late;
                _ = p.stats.late.fetchAdd(1, .monotonic);
                continue;
            }
            if (slot.state == .none) slot.fetch_ms = now;
            slot.state = .fetching;
            slot.inflight += 1;
            slot.racers +|= 1;
            slot.fetch_mask |= bit;
            _ = p.stats.fetches.fetchAdd(1, .monotonic);
            return .{ .seq = seq, .digest = slot.content_digest };
        }
        return null;
    }

    /// A checkpoint below this peer's height whose summary p2p has not seen (pushes carry only a
    /// peer's newest checkpoint): ask this peer for it by number, once.
    fn pickGap(p: *P2p, peer: usize) ?u64 {
        const lo = p.fetcher.applied_next.load(.acquire);
        const h = p.heights[peer].load(.monotonic);
        const act = p.isActive(peer);
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        var seq = lo;
        while (seq < lo + 8 and seq < h) : (seq += 1) {
            if (p.slots[seq % ring].seq == seq or p.gap_req[seq % ring] == seq) continue;
            // An active peer that has it asks (one request per gap across all peers).
            if (!act and p.activeHas(seq + 1)) continue;
            if (!p.fetcher.wants(seq)) continue;
            p.gap_req[seq % ring] = seq;
            return seq;
        }
        return null;
    }

    fn finishFetch(p: *P2p, seq: u64, peer: usize, full: ?[]u8) void {
        p.lock.lockUncancelable(p.io);
        defer p.lock.unlock(p.io);
        const slot = &p.slots[seq % ring];
        if (slot.seq != seq) {
            if (full) |f| p.gpa.free(f);
            return;
        }
        slot.fetch_mask &= ~(@as(u64, 1) << @intCast(peer % 64));
        slot.inflight -|= 1;
        if (full) |f| {
            if (slot.state == .ready or slot.done) {
                p.gpa.free(f);
                _ = p.stats.race_lost.fetchAdd(1, .monotonic);
                return;
            }
            p.fetcher.noteSeen(seq, .p2p_contents);
            slot.full = f;
            slot.state = .ready;
            slot.contents_ms = source.wallMs();
            slot.contents_peer = @intCast(@min(peer, 255));
            _ = p.ready_gen.fetchAdd(1, .release);
            _ = p.stats.contents_ms_sum.fetchAdd(slot.contents_ms -| slot.timestamp_ms, .monotonic);
        } else if (slot.state == .fetching and slot.inflight == 0) {
            slot.tries += 1;
            slot.state = if (slot.tries >= 3) .failed else .none;
        }
    }

    /// Called by the node for every applied checkpoint (any source): with `trace`, one log line
    /// of the checkpoint's p2p timeline, in ms after the checkpoint timestamp.
    pub fn noteApplied(p: *P2p, seq: u64, ts_ms: u64) void {
        var cur = p.synced.load(.monotonic);
        while (seq > cur) cur = p.synced.cmpxchgWeak(cur, seq, .release, .monotonic) orelse break;
        if (!p.trace) return;
        const now = source.wallMs();
        p.lock.lockUncancelable(p.io);
        const slot = p.slots[seq % ring];
        p.lock.unlock(p.io);
        const rel = struct {
            fn f(t: u64, base: u64) i64 {
                return if (t == 0) -1 else @as(i64, @intCast(t)) - @as(i64, @intCast(base));
            }
        }.f;
        if (slot.seq != seq) {
            std.log.info("p2p trace {d} applied {d} unseen", .{ seq, rel(now, ts_ms) });
            return;
        }
        std.log.info("p2p trace {d} applied {d} seen {d} peer {d} {s} contents {d} peer {d} racers {d} exec {d} {d} spool {d} txs {d} parent {d} {s}", .{
            seq,                       rel(now, ts_ms),                rel(slot.seen_ms, ts_ms), slot.seen_peer, if (slot.pushed) "push" else "poll",
            rel(slot.contents_ms, ts_ms), slot.contents_peer,           slot.racers,              rel(slot.exec0_ms, ts_ms), rel(slot.exec1_ms, ts_ms),
            rel(slot.spool_ms, ts_ms), slot.ntx,                       @intFromBool(slot.parent), @tagName(slot.outcome),
        });
    }

    // ------------------------------------------------------------ peer threads

    fn peerLoop(p: *P2p, i: usize) void {
        var backoff: u64 = 500;
        handler_ctxs[i] = .{ .p = p, .peer = i };
        while (!p.stopping.load(.acquire)) {
            // Off-chain peers never; cooled-down peers only to reach the connection target.
            if (p.scores.isOffChain(i)) return;
            if (!p.scores.mayDial(i, source.nowNs(), p.stats.peers_up.load(.monotonic))) {
                p.sleepMs(1000);
                continue;
            }
            var spec = p.specs[i];
            var ovr_name: [net.peer_pool.max_addr_len]u8 = undefined;
            if (spec.id) |*id| _ = seedOverride(id, &ovr_name, &spec);
            if (spec.dns) |d| {
                spec.addr = net.peer_addr.resolve(p.io, .{ .dns = d }) catch |e| {
                    std.log.warn("p2p: peer {d}: cannot resolve {s}: {s}", .{ i, d.name, @errorName(e) });
                    p.sleepMs(backoff);
                    backoff = @min(backoff * 2, 30_000);
                    continue;
                };
                p.specs[i].addr = spec.addr;
            }
            var diag: anemo.ConnectDiag = .{};
            const peer = anemo.Peer.connect(p.gpa, p.io, spec.addr, p.connectOpts(i, spec.id, 10_000, &diag)) catch {
                if (p.stopping.load(.acquire)) return;
                _ = p.noteConnectFail(&diag);
                if (backoff == 500) std.log.info("p2p: seed {d} {f}: connect failed: {s} (code 0x{x}, {d} datagrams back) {s}", .{ i, spec.addr, @tagName(diag.class), diag.code, diag.received, diag.reason() });
                if (p.scores.noteConnect(i, false)) {
                    std.log.info("p2p: peer {d} pruned (never connected, {d} failed connects)", .{ i, p.scores.cfg.prune_after_failed_connects });
                    return;
                }
                p.sleepMs(backoff);
                backoff = @min(backoff * 2, 30_000);
                continue;
            };
            backoff = 500;
            // A seed given without its id: now known, and never dialled a second time by a slot.
            p.cands.hold(&peer.peer_id);
            if (!p.scores.ever_connected[i]) _ = p.stats.peers_ever.fetchAdd(1, .monotonic);
            _ = p.scores.noteConnect(i, true);
            p.peerUp(i);
            p2pm.quinn.connected(&peer.peer_id);
            var reason: p2pm.DisconnectReason = .ConnectionClosed;
            p.session(peer, i) catch |e| {
                if (e == error.PeerDropped) {
                    reason = .LocallyClosed;
                    std.log.info("p2p: peer {d} disconnected (failing for {d} s, or off-chain); cooldown {d} s", .{ i, p.scores.cfg.disconnect_threshold_ns / std.time.ns_per_s, p.scores.cfg.cooldown_ns / std.time.ns_per_s });
                } else if (e == error.RequestTimeout) reason = .TimedOut;
            };
            if (p.stopping.load(.acquire)) reason = .LocallyClosed;
            p2pm.quinn.disconnected(&peer.peer_id, reason);
            p.peerDown(i);
            peer.deinit();
        }
    }

    /// A seed's admin address override (`POST /update-endpoint`, net.peer_pool.admin_overrides):
    /// its first dialable address replaces the configured one in `spec`.
    fn seedOverride(id: *const [32]u8, name_buf: *[net.peer_pool.max_addr_len]u8, spec: *PeerSpec) bool {
        var e: net.peer_pool.Overrides.Entry = undefined;
        if (net.peer_pool.admin_overrides.count() == 0 or !net.peer_pool.admin_overrides.get(id, &e)) return false;
        for (0..e.n_addrs) |k| switch (discovery.parseAddress(e.addr(k)) orelse continue) {
            .ip4_or_6 => |ip| {
                spec.addr = ip;
                spec.dns = null;
                return true;
            },
            .dns => |h| {
                @memcpy(name_buf[0..h.host.len], h.host);
                spec.dns = .{ .name = name_buf[0..h.host.len], .port = h.port };
                return true;
            },
        };
        return false;
    }

    fn session(p: *P2p, peer: *anemo.Peer, i: usize) !void {
        var arena_state = std.heap.ArenaAllocator.init(p.gpa);
        defer arena_state.deinit();
        if (p.genesis == null) {
            _ = arena_state.reset(.retain_capacity);
            if (try ss.getCheckpointSummary(peer, arena_state.allocator(), .{ .seq = 0 })) |g| {
                var r = bcs.Reader.init(g);
                try bcs.skip(types.CheckpointSummary, &r);
                const d = hash.blake2b256(&.{ "CheckpointSummary::", g[0..r.pos()] });
                if (std.mem.eql(u8, &d, &p.net.chain_id)) {
                    p.lock.lockUncancelable(p.io);
                    if (p.genesis == null) p.genesis = try p.gpa.dupe(u8, g);
                    p.lock.unlock(p.io);
                } else std.log.warn("p2p: peer {d} serves a genesis summary of another chain", .{i});
            }
        }
        var next_poll: u64 = 0;
        var last_poll: u64 = 0;
        var next_stats_ms: u64 = 0;
        while (!p.stopping.load(.acquire)) {
            if (p.scores.takeDrop(i)) return error.PeerDropped;
            // `update_quinn_metrics_for_peer` (sui-node: every 5 s; known peers only)
            const now_s = source.wallMs();
            if (now_s >= next_stats_ms) {
                next_stats_ms = now_s + 5000;
                const c = peer.conn;
                p2pm.quinn.peerStats(&peer.peer_id, c.srtt / std.time.ns_per_ms, c.pkts_lost, c.pkts_sent, c.cwnd);
            }
            // sui-node's discovery tick: every `query_ms`, one connected peer (whichever session
            // gets here first) is asked for its known peers.
            if (p.discover > 0) {
                const now_q = source.wallMs();
                const due = p.next_query_ms.load(.monotonic);
                if (now_q >= due and p.next_query_ms.cmpxchgStrong(due, now_q + p.query_ms, .monotonic, .monotonic) == null) {
                    _ = arena_state.reset(.retain_capacity);
                    p.discoverFrom(peer, arena_state.allocator()) catch |e| {
                        if (e == error.Cancelled) return e;
                        std.log.warn("p2p: discovery from peer {d}: {s}", .{ i, @errorName(e) });
                        if (e == error.ConnectionClosed) return e;
                    };
                }
            }
            if (p.pushDue(i)) |seq| {
                _ = arena_state.reset(.retain_capacity);
                p.pushTo(peer, arena_state.allocator(), i, seq) catch |e| if (e == error.ConnectionClosed or e == error.Cancelled) return e;
                continue;
            }
            if (p.pickWork(i)) |job| {
                _ = arena_state.reset(.retain_capacity);
                const a = arena_state.allocator();
                const c0 = source.nowNs();
                const full_try = if (p.contents_v2) ss.getCheckpointContentsV2(peer, a, job.digest) else ss.getCheckpointContentsV1(peer, a, job.digest);
                // The V1 route answers `FullCheckpointContents` (no version tag); paged results
                // are already versioned.
                var untagged = !p.contents_v2;
                const got = full_try catch |e| paged: {
                    if (e == error.ConnectionClosed or e == error.Cancelled) {
                        p.scores.recordFailure(i, source.nowNs());
                        _ = p.stats.contents_errors.fetchAdd(1, .monotonic);
                        p.finishFetch(job.seq, i, null);
                        return e;
                    }
                    // sui-node: a peer that has the checkpoint but failed to deliver full contents
                    // (too large for one response, or too slow) is asked for them in pages.
                    p.scores.recordFailure(i, source.nowNs());
                    _ = p.stats.paged.fetchAdd(1, .monotonic);
                    _ = arena_state.reset(.retain_capacity);
                    const pa = arena_state.allocator();
                    const out = p.fetchPaged(peer, pa, i, job.seq, &job.digest) catch |pe| {
                        _ = p.stats.paged_failed.fetchAdd(1, .monotonic);
                        _ = p.stats.contents_errors.fetchAdd(1, .monotonic);
                        p.finishFetch(job.seq, i, null);
                        if (pe == error.ConnectionClosed or pe == error.Cancelled) return pe;
                        continue;
                    };
                    untagged = false;
                    break :paged out;
                };
                if (got) |raw0| {
                    const raw = if (!untagged) raw0 else blk: {
                        const t = a.alloc(u8, raw0.len + 1) catch {
                            p.finishFetch(job.seq, i, null);
                            continue;
                        };
                        t[0] = 0;
                        @memcpy(t[1..], raw0);
                        break :blk t;
                    };
                    _ = p.stats.contents.fetchAdd(1, .monotonic);
                    _ = p.stats.contents_bytes.fetchAdd(raw.len, .monotonic);
                    // Contents that do not hash to the summary's digest never win the race.
                    const ok = blk: {
                        if (raw.len == 0 or raw[0] > 1) break :blk false;
                        const fc = px.splitFull(a, raw) catch break :blk false;
                        const cd = hash.blake2b256(&.{ "CheckpointContents::", fc.contents });
                        break :blk std.mem.eql(u8, &cd, &job.digest);
                    };
                    if (!ok) _ = p.stats.contents_bad.fetchAdd(1, .monotonic);
                    // sui: a success only when the contents verify; bad contents are not scored.
                    if (ok) p.scores.recordSuccess(i, raw.len, source.nowNs() - c0, source.nowNs());
                    p.finishFetch(job.seq, i, if (ok) p.gpa.dupe(u8, raw) catch null else null);
                } else {
                    p.scores.recordFailure(i, source.nowNs());
                    _ = p.stats.contents_errors.fetchAdd(1, .monotonic);
                    p.finishFetch(job.seq, i, null);
                }
                continue;
            }
            if (p.pickGap(i)) |seq| {
                _ = arena_state.reset(.retain_capacity);
                _ = p.stats.gap_requests.fetchAdd(1, .monotonic);
                const g0 = source.nowNs();
                const got = ss.getCheckpointSummary(peer, arena_state.allocator(), .{ .seq = seq }) catch |e| {
                    p.scores.recordFailure(i, source.nowNs());
                    p.lock.lockUncancelable(p.io);
                    p.gap_req[seq % ring] = std.math.maxInt(u64);
                    p.lock.unlock(p.io);
                    if (e == error.ConnectionClosed) return e;
                    continue;
                };
                if (got) |cert| {
                    p.scores.recordSuccess(i, cert.len, source.nowNs() - g0, source.nowNs());
                    _ = p.stats.gap_filled.fetchAdd(1, .monotonic);
                    p.onSummary(i, cert, false);
                } else p.scores.recordFailure(i, source.nowNs());
                continue;
            }
            const now = source.wallMs();
            const act = p.isActive(i);
            if (now >= next_poll) {
                next_poll = now + p.poll_ms;
                if (!pollDue(now, last_poll, p.last_push_ms[i].load(.monotonic), act, p.poll_ms, p.poll_skip_ms, p.idle_poll_ms)) {
                    _ = p.stats.polls_skipped.fetchAdd(1, .monotonic);
                    continue;
                }
                last_poll = now;
                _ = arena_state.reset(.retain_capacity);
                const t0 = source.nowNs();
                const av = ss.getCheckpointAvailability(peer, arena_state.allocator()) catch |e| {
                    p.scores.recordFailure(i, source.nowNs());
                    return e;
                };
                const us = (source.nowNs() - t0) / std.time.ns_per_us;
                p.scores.recordSuccess(i, av.highest_synced_summary.len, source.nowNs() - t0, source.nowNs());
                // sui's state-sync tick: report (drop and cool down) a peer failing for 30 s.
                if (p.scores.maybeReportFailing(source.nowNs(), p.stats.peers_up.load(.monotonic))) |d|
                    std.log.warn("p2p: peer {d} failing for {d} s: disconnecting", .{ d, p.scores.cfg.disconnect_threshold_ns / std.time.ns_per_s });
                const old = p.rtt_us[i].load(.monotonic);
                p.rtt_us[i].store(if (old == std.math.maxInt(u64)) us else (old * 7 + us) / 8, .monotonic);
                _ = p.stats.polls.fetchAdd(1, .monotonic);
                p.onSummary(i, av.highest_synced_summary, false);
                continue;
            }
            // Pushes are answered inside the pump as they arrive either way; the wait only bounds
            // how soon this thread looks for new work, which a peer outside the active set takes
            // only after `stuck_ms`.
            try peer.pump(if (act) 2 else 20);
        }
    }

    /// The checkpoint to push to peer `i` now, if any: the newest one the node applied, when the
    /// peer's reported height is below it and it has not had it from us (sui-node pushes each
    /// synced checkpoint to every connected same-chain peer whose height is lower). A peer whose
    /// height we do not know yet (no availability answer) gets nothing.
    fn pushDue(p: *P2p, i: usize) ?u64 {
        const seq = p.synced.load(.acquire);
        if (seq == 0) return null;
        const h = p.heights[i].load(.monotonic);
        if (h == 0 or h >= seq) return null;
        if (p.pushed_to[i].load(.monotonic) >= seq) return null;
        if (p.scores.isOffChain(i)) return null;
        return seq;
    }

    fn pushTo(p: *P2p, peer: *anemo.Peer, a: std.mem.Allocator, i: usize, seq: u64) !void {
        p.pushed_to[i].store(seq, .monotonic);
        const cert = blk: {
            var snap = p.st.snapshot();
            defer snap.release();
            const rec = snap.checkpoint(seq) orelse return;
            break :blk try a.dupe(u8, rec.summary_cert);
        };
        ss.pushCheckpointSummary(peer, a, cert) catch |e| {
            _ = p.stats.push_errors.fetchAdd(1, .monotonic);
            return e;
        };
        _ = p.stats.pushes_sent.fetchAdd(1, .monotonic);
    }

    /// sui-node's paged contents download from one peer (`get_paginated_checkpoint_contents_from_peer`):
    /// GetCheckpointContentsDigests(seq), checked against the summary's contents digest, then
    /// GetCheckpointTransactions pages, each transaction checked against its digests. The result
    /// is the `VersionedFullCheckpointContents` a full-contents answer would have been, so the
    /// build path is the same. A failed page halves the page size for the next attempt.
    fn fetchPaged(p: *P2p, peer: *anemo.Peer, a: std.mem.Allocator, i: usize, seq: u64, content_digest: *const [32]u8) ![]const u8 {
        const contents = (try ss.getCheckpointContentsDigests(peer, a, seq)) orelse return error.NotFound;
        if (!std.mem.eql(u8, &hash.blake2b256(&.{ "CheckpointContents::", contents }), content_digest)) return error.ContentsMismatch;
        const lay = try contentsLayout(a, contents);
        const n: u64 = lay.digests.len;
        var items: std.ArrayList(u8) = .empty;
        var next: u64 = 0;
        var last_len: ?u64 = null;
        while (next < n) {
            if (p.stopping.load(.acquire)) return error.Cancelled;
            const max = blk: {
                p.lock.lockUncancelable(p.io);
                defer p.lock.unlock(p.io);
                const slot = &p.slots[seq % ring];
                break :blk if (slot.seq == seq) slot.page_max else std.math.maxInt(u64);
            };
            const end = @min(next +| max, n);
            const requested = end - next;
            const page = ss.getCheckpointTransactions(peer, a, .{ .sequence_number = seq, .start = next, .end = end }) catch |e| {
                // A page too large to arrive in time: the next peer asks for half as many.
                p.lock.lockUncancelable(p.io);
                const slot = &p.slots[seq % ring];
                if (slot.seq == seq) slot.page_max = @max(@min(last_len orelse requested, requested) / 2, 1);
                p.lock.unlock(p.io);
                return e;
            } orelse return error.NotFound;
            _ = p.stats.paged_pages.fetchAdd(1, .monotonic);
            var r = bcs.Reader.init(page);
            const k = try r.length();
            if (k == 0 or k > n - next) return error.BadPage;
            for (0..k) |j| {
                const t0 = r.pos();
                try bcs.skip(types.SenderSignedData, &r);
                const t1 = r.pos();
                try bcs.skip(types.TransactionEffects, &r);
                const want = &lay.digests[@intCast(next + j)];
                const td = try px.txDataOf(page[t0..t1]);
                if (want[0] != 32 or want[33] != 32) return error.BadPage;
                if (!std.mem.eql(u8, &hash.blake2b256(&.{ "TransactionData::", td }), want[1..33])) return error.BadPage;
                if (!std.mem.eql(u8, &hash.blake2b256(&.{ "TransactionEffects::", page[t1..r.pos()] }), want[34..66])) return error.BadPage;
                try items.appendSlice(a, page[t0..r.pos()]);
            }
            if (r.remaining() != 0) return error.BadPage;
            next += k;
            last_len = k;
        }
        _ = i;
        return assembleFull(a, contents, &lay, items.items);
    }

    /// Adds a connected peer's known peers (signed infos that verify) to the dial pool and to
    /// the book served to others. The rotating slots (`slotLoop`) dial them.
    fn discoverFrom(p: *P2p, peer: *anemo.Peer, a: std.mem.Allocator) !void {
        _ = p.stats.discovery_queries.fetchAdd(1, .monotonic);
        const now = source.wallMs();
        // sui-node's tick also culls infos older than a day.
        const culled = p.cands.cull(now);
        if (culled > 0) _ = p.stats.discovery_culled.fetchAdd(culled, .monotonic);
        // sui-node asks GetKnownPeersV2 always and, with `use-get-known-peers-v3`, V3 as well
        // (V3 answers fill the versioned book, which the peer cache is written from).
        const kp = try discovery.getKnownPeersV2(peer, a);
        if (p.book) |b| _ = b.addKnownPeers(&kp, false, now);
        var added: usize = 0;
        const stale0 = p.cands.stats.stale;
        if (kp.own.verify()) added += @intFromBool(p.cands.addFresh(&kp.own, now));
        for (kp.peers[0..@min(kp.peers.len, 200)]) |*info| {
            if (!info.verify()) continue;
            added += @intFromBool(p.cands.addFresh(info, now));
        }
        if (p.known_peers_v3) if (p.srv) |srv| v3: {
            _ = p.stats.discovery_v3.fetchAdd(1, .monotonic);
            const own = srv.ownInfo(a, true, now) catch break :v3;
            const kp3 = discovery.getKnownPeersV3(peer, a, own) catch |e| {
                if (e == error.ConnectionClosed) return e;
                break :v3;
            };
            if (p.book) |b| _ = b.addKnownPeers(&kp3, true, now);
            if (kp3.own.verify()) added += @intFromBool(p.cands.addFresh(&kp3.own, now));
            for (kp3.peers[0..@min(kp3.peers.len, 200)]) |*info| {
                if (!info.verify()) continue;
                added += @intFromBool(p.cands.addFresh(info, now));
            }
        };
        if (p.cands.stats.stale > stale0) _ = p.stats.discovery_stale.fetchAdd(p.cands.stats.stale - stale0, .monotonic);
        if (added > 0 or !p.discovered.load(.monotonic))
            std.log.info("p2p: discovery: {d} known peers, {d} new ({d} candidates, {d} connected)", .{ kp.peers.len, added, p.cands.count(), p.stats.peers_up.load(.monotonic) });
        p.discovered.store(true, .release);
    }

    // ------------------------------------------------------------ execution

    fn execLoop(p: *P2p) void {
        // Two arenas: checkpoint S's writes (its arena) stay alive while S+1 builds on them.
        var arenas: [2]std.heap.ArenaAllocator = .{ .init(p.gpa), .init(p.gpa) };
        defer for (&arenas) |*x| x.deinit();
        while (!p.stopping.load(.acquire)) {
            if (p.p2p_only) only_mod.tick(p);
            p.maybeElect(source.wallMs());
            const lo = p.fetcher.applied_next.load(.acquire);
            // The next checkpoint to build: the follower's next, or the one after it once that is
            // built (or left to another source) and not yet committed.
            var seq = lo;
            const ready = blk: {
                p.lock.lockUncancelable(p.io);
                defer p.lock.unlock(p.io);
                const s0 = &p.slots[lo % ring];
                if (s0.seq == lo and s0.done) seq = lo + 1;
                const slot = &p.slots[seq % ring];
                const go = slot.seq == seq and slot.state == .ready and !slot.done;
                if (go) slot.building = true;
                break :blk go;
            };
            if (!ready) {
                p.io.sleep(.fromMicroseconds(300), .awake) catch {};
                continue;
            }
            const ar = &arenas[seq % 2];
            if (p.parent) |par| if (par.seq % 2 == seq % 2) {
                p.parent = null;
            };
            _ = ar.reset(.retain_capacity);
            const fb0 = p.stats.fallbacks.load(.monotonic);
            const retry = p.buildOne(ar.allocator(), seq);
            {
                p.lock.lockUncancelable(p.io);
                defer p.lock.unlock(p.io);
                p.slots[seq % ring].building = false;
            }
            if (retry) {
                p.io.sleep(.fromMicroseconds(200), .awake) catch {};
                continue;
            }
            if (p.p2p_only) {
                // Nothing else delivers it: retry here (p2p_only.zig), never leave it.
                if (p.stats.fallbacks.load(.monotonic) != fb0) {
                    only_mod.onFallback(p, seq, p.last_reason);
                    continue;
                }
                if (p.slots[seq % ring].outcome == .delivered) only_mod.onDelivered(p, seq);
            }
            p.lock.lockUncancelable(p.io);
            const slot = &p.slots[seq % ring];
            if (slot.seq == seq) {
                slot.done = true;
                p.gpa.free(slot.full);
                slot.full = &.{};
            }
            p.lock.unlock(p.io);
        }
    }

    /// Builds checkpoint `seq` (its slot is this thread's while ready and not done). True: the
    /// store does not show S-1 yet (and S-1's writes are not in hand), try again.
    fn buildOne(p: *P2p, a: std.mem.Allocator, seq: u64) bool {
        p.buildInner(a, seq) catch |e| switch (e) {
            error.Retry => return true,
        };
        return false;
    }

    fn buildInner(p: *P2p, a: std.mem.Allocator, seq: u64) error{Retry}!void {
        const slot = &p.slots[seq % ring];
        if (!p.fetcher.wants(seq)) {
            slot.outcome = .late;
            _ = p.stats.late.fetchAdd(1, .monotonic);
            return;
        }
        const t0 = source.nowNs();
        var snap = p.st.snapshot();
        defer snap.release();
        const hi = snap.highestCommitted() orelse return error.Retry;
        // The pre-state: the store at S-1, or the store at S-2 plus S-1's writes (built here, every
        // effects equal to the certified ones, not yet committed).
        var parent: ?*const px.Layer = null;
        var prev_digest: [32]u8 = undefined;
        if (hi + 1 == seq) {
            const prev = snap.checkpoint(seq - 1) orelse return p.fallback("previous checkpoint not stored");
            var pr = bcs.Reader.init(prev.summary_cert);
            bcs.skip(types.CheckpointSummary, &pr) catch return p.fallback("stored summary does not parse");
            prev_digest = hash.blake2b256(&.{ "CheckpointSummary::", prev.summary_cert[0..pr.pos()] });
        } else if (hi + 2 == seq and p.parent != null and p.parent.?.seq + 1 == seq) {
            parent = &p.parent.?.layer;
            prev_digest = p.parent.?.digest;
        } else return error.Retry;
        const cert = slot.cert;
        var r = bcs.Reader.init(cert);
        bcs.skip(types.CheckpointSummary, &r) catch return p.fallback("summary does not parse");
        const summary = bcs.decode(types.CheckpointSummary, a, cert[0..r.pos()]) catch return p.fallback("summary does not parse");
        // Chain link: the previous digest must name S-1 (committed, or built here).
        const link = summary.previous_digest orelse return p.fallback("no previous digest");
        if (!std.mem.eql(u8, &link.@"0".@"0", &prev_digest)) {
            _ = p.stats.rejected_link.fetchAdd(1, .monotonic);
            return p.fallback("chain link differs");
        }
        const full_raw = slot.full;
        if (full_raw.len == 0 or full_raw[0] > 1) return p.fallback("contents do not parse");
        const fc = px.splitFull(a, full_raw) catch return p.fallback("contents do not parse");
        const cd = hash.blake2b256(&.{ "CheckpointContents::", fc.contents });
        if (!std.mem.eql(u8, &cd, &summary.content_digest.@"0".@"0")) return p.fallback("contents digest differs");
        // Next epoch's parameters are known once S-1 (the end of epoch) is committed.
        const params = p.hooks.params(p.hooks.ctx, summary.epoch) orelse
            if (parent != null) return error.Retry else return p.fallback("epoch parameters unknown");
        slot.exec0_ms = source.wallMs();
        slot.parent = parent != null;
        slot.ntx = @intCast(fc.txs.len);
        const res = px.run(p.gpa, a, &snap, &p.pkg_src, params, summary.epoch, cert, fc.contents, fc.txs, &p.exec_stats, parent, if (slot.serial) null else &p.pool) catch |e| return p.fallback(@errorName(e));
        p.stats.reruns.store(p.pool.reruns.load(.monotonic), .monotonic);
        slot.exec1_ms = source.wallMs();
        _ = p.stats.exec_ns.fetchAdd(source.nowNs() - t0, .monotonic);
        _ = p.stats.txs.fetchAdd(fc.txs.len, .monotonic);
        switch (res) {
            .fallback => |why| {
                slot.outcome = .fallback;
                return p.fallback(why);
            },
            .ok => |o| {
                _ = p.stats.built.fetchAdd(1, .monotonic);
                if (p.fallback_streak.swap(0, .monotonic) >= p.pause_after and p.pause_after != 0 and !p.p2p_only)
                    std.log.info("p2p: checkpoint {d} built; contents fetched for every checkpoint again", .{seq});
                if (parent != null) _ = p.stats.pipelined.fetchAdd(1, .monotonic);
                p.parent = .{ .seq = seq, .digest = hash.blake2b256(&.{ "CheckpointSummary::", cert[0..r.pos()] }), .layer = o.layer };
                if (!p.fetcher.markDone(seq)) {
                    slot.outcome = .lost;
                    _ = p.stats.lost_race.fetchAdd(1, .monotonic);
                    return;
                }
                p.fetcher.writeSpoolBuilt(seq, o.blob, o.aux) catch {
                    p.fetcher.unmarkDone(seq);
                    slot.outcome = .fallback;
                    return p.fallback("spool write");
                };
                p.fetcher.noteArrival(seq);
                p.fetcher.noteSeen(seq, .p2p_built);
                p.fetcher.delivered(seq);
                slot.spool_ms = source.wallMs();
                slot.outcome = .delivered;
                _ = p.stats.delivered.fetchAdd(1, .monotonic);
                _ = p.stats.build_ms_sum.fetchAdd(slot.spool_ms -| slot.seen_ms, .monotonic);
                _ = p.stats.spool_ms_sum.fetchAdd(slot.spool_ms -| slot.timestamp_ms, .monotonic);
            },
        }
    }

    pub fn fallback(p: *P2p, why: []const u8) void {
        p.last_reason = why;
        _ = p.stats.fallbacks.fetchAdd(1, .monotonic);
        p.noteReason(why);
        const streak = p.fallback_streak.fetchAdd(1, .monotonic) + 1;
        if (streak == p.pause_after and !p.p2p_only)
            std.log.info("p2p: {d} builds in a row fell back (last: {s}; a store without live objects cannot build): contents fetched for 1 checkpoint in {d} until one builds", .{ streak, why, p.probe_every });
    }

    // ------------------------------------------------------------ serving peers

    const HandlerCtx = struct { p: ?*P2p = null, peer: usize = 0 };
    var handler_ctxs: [64]HandlerCtx = @splat(.{});

    fn serveRequest(ctx: *anyopaque, a: std.mem.Allocator, from: *const anemo.PeerId, route: []const u8, body: []const u8) anemo.Reply {
        _ = from;
        const hc: *HandlerCtx = @ptrCast(@alignCast(ctx));
        const p = hc.p orelse return .{ .status = .not_found };
        _ = p.stats.served.fetchAdd(1, .monotonic);
        return p.answer(a, hc.peer, route, body) catch .{ .status = .internal_server_error };
    }

    fn some(a: std.mem.Allocator, payload: ?[]const u8) ![]const u8 {
        const v = payload orelse return net.snappy.compressFrame(a, &.{0});
        const b = try a.alloc(u8, v.len + 1);
        b[0] = 1;
        @memcpy(b[1..], v);
        return net.snappy.compressFrame(a, b);
    }

    fn answer(p: *P2p, a: std.mem.Allocator, peer: usize, route: []const u8, body: []const u8) !anemo.Reply {
        const R = ss.Route;
        if (std.mem.eql(u8, route, R.push_checkpoint_summary)) {
            _ = p.stats.pushes.fetchAdd(1, .monotonic);
            const cert = try ss.decodeBody(a, body);
            p.onSummary(peer, cert, true);
            return .{ .status = .success, .body = try net.snappy.compressFrame(a, &.{}) };
        }
        if (std.mem.eql(u8, route, R.get_checkpoint_availability)) {
            var snap = p.st.snapshot();
            defer snap.release();
            const tip = snap.highestCommitted() orelse return .{ .status = .not_found };
            const rec = snap.checkpoint(tip) orelse return .{ .status = .not_found };
            const b = try a.alloc(u8, rec.summary_cert.len + 8);
            @memcpy(b[0..rec.summary_cert.len], rec.summary_cert);
            std.mem.writeInt(u64, b[rec.summary_cert.len..][0..8], tip -| (ring - 1), .little);
            return .{ .status = .success, .body = try net.snappy.compressFrame(a, b) };
        }
        if (std.mem.eql(u8, route, R.get_checkpoint_summary)) {
            const req = try ss.decodeBody(a, body);
            if (req.len == 0) return .{ .status = .bad_request };
            var snap = p.st.snapshot();
            defer snap.release();
            const seq: ?u64 = switch (req[0]) {
                0 => snap.highestCommitted(),
                2 => if (req.len == 9) std.mem.readInt(u64, req[1..9], .little) else return .{ .status = .bad_request },
                else => null,
            };
            const s = seq orelse return .{ .status = .success, .body = try some(a, null) };
            if (s == 0) return .{ .status = .success, .body = try some(a, p.genesis) };
            const rec = snap.checkpoint(s) orelse return .{ .status = .success, .body = try some(a, null) };
            return .{ .status = .success, .body = try some(a, try a.dupe(u8, rec.summary_cert)) };
        }
        if (std.mem.eql(u8, route, R.get_checkpoint_contents_v2) or std.mem.eql(u8, route, R.get_checkpoint_contents)) {
            const req = try ss.decodeBody(a, body);
            if (req.len != 33 or req[0] != 32) return .{ .status = .bad_request };
            const seq = blk: {
                p.lock.lockUncancelable(p.io);
                defer p.lock.unlock(p.io);
                for (p.slots) |*s| if (s.seq != std.math.maxInt(u64) and std.mem.eql(u8, &s.content_digest, req[1..33])) break :blk s.seq;
                break :blk null;
            } orelse return .{ .status = .success, .body = try some(a, null) };
            var snap = p.st.snapshot();
            defer snap.release();
            const rec = snap.checkpoint(seq) orelse return .{ .status = .success, .body = try some(a, null) };
            const full = (try fullFromStore(a, &snap, rec.contents)) orelse return .{ .status = .success, .body = try some(a, null) };
            // V1 route: only V1 contents (FullCheckpointContents has no V2 form).
            if (std.mem.eql(u8, route, R.get_checkpoint_contents)) {
                if (full[0] != 0) return .{ .status = .success, .body = try some(a, null) };
                _ = p.stats.served_contents.fetchAdd(1, .monotonic);
                return .{ .status = .success, .body = try some(a, full[1..]) };
            }
            _ = p.stats.served_contents.fetchAdd(1, .monotonic);
            return .{ .status = .success, .body = try some(a, full) };
        }
        if (std.mem.eql(u8, route, R.get_known_peers_v2) or std.mem.eql(u8, route, R.get_known_peers_v3)) {
            const v3 = std.mem.eql(u8, route, R.get_known_peers_v3);
            var info: std.ArrayList(u8) = .empty;
            if (v3) try info.append(a, 0); // VersionedNodeInfo::V1
            try info.appendSlice(a, &p.key.public_key.toBytes());
            try info.append(a, 0); // no dialable address
            var ts: [8]u8 = undefined;
            std.mem.writeInt(u64, &ts, source.wallMs(), .little);
            try info.appendSlice(a, &ts);
            try info.append(a, 1); // AccessType::Private: do not share us
            const sig = try p.key.sign(info.items, null);
            try info.appendSlice(a, &sig.toBytes());
            try info.append(a, 0); // known_peers: empty
            return .{ .status = .success, .body = try net.snappy.compressFrame(a, info.items) };
        }
        return .{ .status = .not_found };
    }
};

/// Where a `CheckpointContents` (V1 or V2) keeps its digests and signatures.
pub const ContentsLayout = struct {
    tag: u8,
    digests: []const [66]u8,
    /// V1: the `user_signatures` vector (everything after the digests). V2: each transaction's
    /// signature list.
    v1_sigs: []const u8 = &.{},
    v2_sigs: []const []const u8 = &.{},
};

pub fn contentsLayout(a: std.mem.Allocator, contents: []const u8) !ContentsLayout {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    if (tag > 1) return error.Malformed;
    const n = try r.length();
    if (n > contents.len / 66) return error.Malformed;
    const ds = try a.alloc([66]u8, n);
    if (tag == 0) {
        for (ds) |*d| d.* = (try r.bytes(66))[0..66].*;
        return .{ .tag = 0, .digests = ds, .v1_sigs = contents[r.pos()..] };
    }
    const sigs = try a.alloc([]const u8, n);
    for (ds, sigs) |*d, *sg| {
        d.* = (try r.bytes(66))[0..66].*;
        const s0 = r.pos();
        const k = try r.length();
        for (0..k) |_| {
            _ = try r.bytes(try r.length());
            switch (try r.int(u8)) {
                0 => {},
                1 => _ = try r.int(u64),
                else => return error.Malformed,
            }
        }
        sg.* = contents[s0..r.pos()];
    }
    if (r.remaining() != 0) return error.TrailingBytes;
    return .{ .tag = 1, .digests = ds, .v2_sigs = sigs };
}

/// `VersionedFullCheckpointContents` from a checkpoint's `CheckpointContents` and its
/// transactions in order (`items`: each `ExecutionData` = transaction ++ effects): the bytes a
/// GetCheckpointContentsV2 answer carries (p2p_serve.fullFromStore builds the same from the store).
pub fn assembleFull(a: std.mem.Allocator, contents: []const u8, lay: *const ContentsLayout, items: []const u8) ![]const u8 {
    _ = contents;
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, lay.tag);
    try putUleb(&out, a, lay.digests.len);
    try out.appendSlice(a, items);
    if (lay.tag == 0) {
        try out.appendSlice(a, lay.v1_sigs);
    } else {
        try putUleb(&out, a, lay.v2_sigs.len);
        for (lay.v2_sigs) |sg| try out.appendSlice(a, sg);
    }
    return out.items;
}

/// `VersionedFullCheckpointContents` of a stored checkpoint from its `CheckpointContents` and the
/// stored transactions. Null when a transaction is missing.
fn fullFromStore(a: std.mem.Allocator, snap: *const store.Snapshot, contents: []const u8) !?[]const u8 {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    if (tag > 1) return null;
    const n = try r.length();
    if (n > contents.len) return null;
    var txs: std.ArrayList(u8) = .empty;
    var sigs: std.ArrayList(u8) = .empty;
    try putUleb(&txs, a, n);
    try putUleb(&sigs, a, n);
    for (0..n) |_| {
        const d = try r.bytes(66);
        if (d[0] != 32) return null;
        const t = snap.transaction(d[1..33]) orelse return null;
        try txs.appendSlice(a, t.tx);
        try txs.appendSlice(a, t.effects);
        if (tag == 1) {
            const s0 = r.pos();
            const k = try r.length();
            for (0..k) |_| {
                _ = try r.bytes(try r.length());
                if (try r.int(u8) == 1) _ = try r.int(u64);
            }
            try sigs.appendSlice(a, contents[s0..r.pos()]);
        }
    }
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, @intCast(tag));
    try out.appendSlice(a, txs.items);
    if (tag == 0) {
        try out.appendSlice(a, contents[r.pos()..]); // user_signatures as stored
    } else try out.appendSlice(a, sigs.items);
    return out.items;
}

fn putUleb(out: *std.ArrayList(u8), a: std.mem.Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) return out.append(a, b);
        try out.append(a, b | 0x80);
    }
}

/// `ADDR@peerid_hex` (peer id optional), comma separated. ADDR: `ip:port`, `[v6]:port`,
/// `host:port`, or a multiaddr `/ip4|ip6|dns|dns4|dns6/HOST/udp/PORT` (sui-node's seed-peers).
pub fn parsePeers(a: std.mem.Allocator, text: []const u8) ![]PeerSpec {
    return parsePeersIo(a, null, text);
}

/// `parsePeers`, and with `io` a host name (fullnode.yaml's `/dns/HOST/udp/PORT` seeds) is
/// resolved, IPv4 first. A seed whose name does not resolve is skipped with a warning (sui-node
/// skips unreachable seeds too); without `io` a name is `BadPeer`.
pub fn parsePeersIo(a: std.mem.Allocator, io: ?Io, text: []const u8) ![]PeerSpec {
    _ = io; // host names are resolved at every dial (peer_addr.resolve), as sui-node does
    var list: std.ArrayList(PeerSpec) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, ',');
    while (it.next()) |item0| {
        const item = std.mem.trim(u8, item0, " ");
        var addr_text = item;
        var id: ?[32]u8 = null;
        if (std.mem.indexOfScalar(u8, item, '@')) |at| {
            addr_text = item[0..at];
            var b: [32]u8 = undefined;
            _ = std.fmt.hexToBytes(&b, item[at + 1 ..]) catch return error.BadPeer;
            id = b;
        }
        const pa = net.peer_addr.parse(a, addr_text) catch return error.BadPeer;
        switch (pa) {
            .ip => |ip| try list.append(a, .{ .addr = ip, .id = id }),
            // resolved at dial time; the placeholder is never dialled
            .dns => |d| try list.append(a, .{ .addr = .{ .ip4 = Io.net.Ip4Address.unspecified(d.port) }, .id = id, .dns = d }),
        }
    }
    if (list.items.len > 64) return error.TooManyPeers;
    return list.items;
}

/// `peer-address-overrides` (sui-node: AddressSource::Config, above discovered and seed
/// addresses; the peer is then kept connected like a seed): a seed with the same id takes the
/// override's first address, any other overridden peer is added as a seed. Further addresses of
/// an override are not used (a deepwave seed has one address).
pub fn applyOverrides(a: std.mem.Allocator, io: ?Io, peers: []const PeerSpec, overrides: []const @import("p2p_config.zig").Override) ![]PeerSpec {
    _ = io;
    var list: std.ArrayList(PeerSpec) = .empty;
    try list.appendSlice(a, peers);
    for (overrides) |o| {
        const pa = net.peer_addr.parse(a, o.addresses[0]) catch continue;
        const spec: PeerSpec = switch (pa) {
            .ip => |ip| .{ .addr = ip, .id = o.id },
            .dns => |d| .{ .addr = .{ .ip4 = Io.net.Ip4Address.unspecified(d.port) }, .id = o.id, .dns = d },
        };
        const at = for (list.items, 0..) |sp, j| {
            if (sp.id) |id| if (std.mem.eql(u8, &id, &o.id)) break j;
        } else null;
        if (at) |j| list.items[j] = spec else try list.append(a, spec);
    }
    if (list.items.len > 64) return error.TooManyPeers;
    return list.items;
}

/// The first address `host` resolves to, IPv4 preferred.
fn resolve(io: Io, host: []const u8, port: u16) !Io.net.IpAddress {
    const name = Io.net.HostName.init(host) catch return error.BadPeer;
    var buf: [32]Io.net.HostName.LookupResult = undefined;
    var q: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    // Does not block with a queue of 16 or more; closes `q` before it returns.
    try name.lookup(io, &q, .{ .port = port });
    var v6: ?Io.net.IpAddress = null;
    while (q.getOne(io)) |r| switch (r) {
        .address => |ad| switch (ad) {
            .ip4 => return ad,
            .ip6 => if (v6 == null) {
                v6 = ad;
            },
        },
        .canonical_name => {},
    } else |_| {}
    return v6 orelse error.UnknownHostName;
}

/// The network key: 32 raw bytes or 64 hex characters (the Ed25519 seed).
pub fn loadKey(io: Io, path: []const u8) !Ed25519.KeyPair {
    var buf: [256]u8 = undefined;
    const f = try Io.Dir.cwd().openFile(io, path, .{});
    defer f.close(io);
    const n = try f.readPositionalAll(io, &buf, 0);
    var seed: [32]u8 = undefined;
    const text = std.mem.trim(u8, buf[0..n], " \n\r\t");
    if (n == 32) seed = buf[0..32].* else if (text.len == 64) {
        _ = try std.fmt.hexToBytes(&seed, text);
    } else return error.BadKey;
    return Ed25519.KeyPair.generateDeterministic(seed);
}

test "peer list parsing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ps = try parsePeers(arena.allocator(), "104.207.128.152:8084@c7bf6cb93ca8fdda655c47ebb85ace28e6931464564332bf63e27e90199c50ee, 127.0.0.1:9");
    try std.testing.expectEqual(@as(usize, 2), ps.len);
    try std.testing.expectEqual(@as(u8, 0xc7), ps[0].id.?[0]);
    try std.testing.expect(ps[1].id == null);
    const ds = try parsePeers(arena.allocator(), "/dns/ewr-00.mainnet.sui.io/udp/8084@c7bf6cb93ca8fdda655c47ebb85ace28e6931464564332bf63e27e90199c50ee,/ip4/1.2.3.4/udp/8084,mel-00.mainnet.sui.io:8084");
    try std.testing.expectEqual(@as(usize, 3), ds.len);
    try std.testing.expectEqualStrings("ewr-00.mainnet.sui.io", ds[0].dns.?.name);
    try std.testing.expect(ds[1].dns == null);
    try std.testing.expectEqual(@as(u16, 8084), ds[2].dns.?.port);
}

test "p2p: active set election (push lag first, then RTT, hysteresis, cap, down and failing peers out)" {
    const t = std.testing;
    var infos: [6]ElectInfo = .{
        .{ .up = true, .lag_ms = 40 },
        .{ .up = true, .lag_ms = 5 },
        .{ .up = false, .lag_ms = 0 }, // down
        .{ .up = true, .rtt_us = 30_000 }, // no push yet: after every pusher
        .{ .up = true, .ok = false, .lag_ms = 0 }, // failing or off-chain
        .{ .up = true }, // nothing measured: last
    };
    try t.expectEqual(@as(u64, 0b000011), elect(&infos, 2, 0));
    try t.expectEqual(@as(u64, 0b001011), elect(&infos, 3, 0));
    try t.expectEqual(@as(u64, 0b101011), elect(&infos, 8, 0));
    try t.expectEqual(@as(u64, 0), elect(&infos, 0, 0));
    // an incumbent at 40 ms keeps its place against a newcomer at 20 ms (inside 25 ms) ...
    infos[3].lag_ms = 20;
    try t.expectEqual(@as(u64, 0b000011), elect(&infos, 2, 0b000011));
    // ... not against one at 10 ms
    infos[3].lag_ms = 10;
    try t.expectEqual(@as(u64, 0b001010), elect(&infos, 2, 0b000011));
    // nobody up: 0 (every peer then counts as active)
    for (&infos) |*x| x.up = false;
    try t.expectEqual(@as(u64, 0), elect(&infos, 4, 0b11));
}

test "p2p: availability polls skipped while a peer pushes" {
    const t = std.testing;
    const poll = 500;
    const skip = 3_000;
    const idle = 10_000;
    // first poll of a session: always
    try t.expect(pollDue(100_000, 0, 0, true, poll, skip, idle));
    try t.expect(pollDue(100_000, 0, 0, false, poll, skip, idle));
    // active, never pushed: every poll_ms
    try t.expect(!pollDue(100_400, 100_000, 0, true, poll, skip, idle));
    try t.expect(pollDue(100_500, 100_000, 0, true, poll, skip, idle));
    // active and pushed 1 s ago: skipped until the idle refresh
    try t.expect(!pollDue(100_500, 100_000, 99_500, true, poll, skip, idle));
    try t.expect(!pollDue(109_000, 100_000, 108_000, true, poll, skip, idle));
    try t.expect(pollDue(110_000, 100_000, 109_900, true, poll, skip, idle));
    // active, last push 3 s ago: polled again
    try t.expect(pollDue(103_000, 100_000, 100_000, true, poll, skip, idle));
    // outside the active set: every idle_ms only
    try t.expect(!pollDue(105_000, 100_000, 0, false, poll, skip, idle));
    try t.expect(pollDue(110_000, 100_000, 0, false, poll, skip, idle));
}

/// A P2p with no network and no store (as p2p_only.zig's test): slots, heights and the fetcher's
/// spool only.
pub const TestRig = struct {
    tmp: std.testing.TmpDir,
    applied_next: Atomic(u64),
    f: *source.Fetcher,
    p: P2p,

    pub fn init(r: *TestRig, lo: u64) !void {
        const gpa = std.testing.allocator;
        const io = std.testing.io;
        r.tmp = std.testing.tmpDir(.{});
        r.applied_next = .init(lo);
        r.f = try gpa.create(source.Fetcher);
        r.f.* = .{ .gpa = gpa, .io = io, .source = undefined, .spool = r.tmp.dir, .next = .init(lo), .applied_next = &r.applied_next, .window = 64, .poll_ms = 25, .to = std.math.maxInt(u64) };
        try r.f.start(0);
        r.p = .{ .gpa = gpa, .io = io, .st = undefined, .fetcher = r.f, .peers = &.{}, .key = undefined, .hooks = .{ .ctx = undefined, .params = undefined }, .exec_threads = 1 };
        try r.p.init();
    }

    pub fn deinit(r: *TestRig) void {
        for (&r.p.reasons) |*x| {
            if (x.*) |why| r.p.gpa.free(why);
            x.* = null;
        }
        r.p.stop();
        r.f.stop();
        std.testing.allocator.destroy(r.f);
        r.tmp.cleanup();
    }

    /// Checkpoint `seq`'s summary seen `ago_ms` ago, contents not fetched.
    pub fn seen(r: *TestRig, seq: u64, ago_ms: u64) !void {
        const slot = &r.p.slots[seq % ring];
        r.p.gpa.free(slot.cert);
        r.p.gpa.free(slot.full);
        slot.* = .{ .seq = seq, .cert = try r.p.gpa.dupe(u8, "cert"), .content_digest = @splat(7), .seen_ms = source.wallMs() - ago_ms };
    }

    fn peerAt(r: *TestRig, i: usize, height: u64) void {
        r.p.up[i].store(true, .monotonic);
        r.p.heights[i].store(height, .monotonic);
        if (r.p.n_peers.load(.monotonic) <= i) r.p.n_peers.store(i + 1, .monotonic);
    }
};

test "p2p: a summary already seen is handled without a decode (height, push time and lag only)" {
    const t = std.testing;
    var r: TestRig = undefined;
    try r.init(100);
    defer r.deinit();
    const p = &r.p;
    try r.seen(100, 40);
    // Not a parseable summary: only the bytes the fast path reads (seq, digest length) are real.
    var cert: [96]u8 = @splat(0xff);
    std.mem.writeInt(u64, cert[8..16], 100, .little);
    cert[24] = 32;
    p.onSummary(3, &cert, true);
    try t.expectEqual(@as(u64, 1), p.stats.push_dups.load(.monotonic));
    try t.expectEqual(@as(u64, 100), p.heights[3].load(.monotonic));
    try t.expect(p.last_push_ms[3].load(.monotonic) != 0);
    const lag = p.push_lag_ms[3].load(.monotonic);
    try t.expect(lag >= 40 and lag < 5_000);
    try t.expect(p.fetcher.seenMs(100, .push) != null);
    // the slot is untouched (still the first copy)
    try t.expectEqualStrings("cert", p.slots[100 % ring].cert);
    // a poll copy: counted, no push time
    p.onSummary(4, &cert, false);
    try t.expectEqual(@as(u64, 2), p.stats.push_dups.load(.monotonic));
    try t.expectEqual(@as(u64, 0), p.last_push_ms[4].load(.monotonic));
    try t.expectEqual(no_lag, p.push_lag_ms[4].load(.monotonic));
    // a later checkpoint not seen yet goes to the decode (which rejects these bytes): no slot
    std.mem.writeInt(u64, cert[8..16], 101, .little);
    p.onSummary(3, &cert, true);
    try t.expect(p.slots[101 % ring].seq != 101);
    try t.expectEqual(@as(u64, 2), p.stats.push_dups.load(.monotonic));
}

test "p2p: a summary for S + ring leaves S's slot alone while S is building (no use after free)" {
    const t = std.testing;
    var r: TestRig = undefined;
    try r.init(100);
    defer r.deinit();
    const p = &r.p;
    const gpa = t.allocator;
    const S: u64 = 100;
    try r.seen(S, 0);
    const slot = &p.slots[S % ring];
    slot.full = try gpa.dupe(u8, "full");
    slot.state = .ready;
    slot.building = true;
    const cert0 = slot.cert.ptr;
    const full0 = slot.full.ptr;
    // S applied from another source meanwhile: S + ring is in range
    r.applied_next.store(S + 1, .release);
    const summary: types.CheckpointSummary = .{
        .epoch = 1,
        .sequence_number = S + ring,
        .network_total_transactions = 5,
        .content_digest = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .previous_digest = null,
        .epoch_rolling_gas_cost_summary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .timestamp_ms = 1,
        .checkpoint_commitments = &.{},
        .end_of_epoch_data = null,
        .version_specific_data = &.{},
    };
    const enc = try bcs.encodeAlloc(types.CheckpointSummary, gpa, &summary);
    defer gpa.free(enc);
    const cert = try std.mem.concat(gpa, u8, &.{ enc, &@as([96]u8, @splat(0)) });
    defer gpa.free(cert);
    p.onSummary(3, cert, true);
    try t.expectEqual(S, slot.seq);
    try t.expect(slot.cert.ptr == cert0 and slot.full.ptr == full0);
    // once the build is over the slot is free for it
    slot.building = false;
    p.onSummary(3, cert, true);
    try t.expectEqual(S + ring, slot.seq);
}

test "p2p: contents fetched from the active set only, one request per checkpoint until the hedge" {
    const t = std.testing;
    var r: TestRig = undefined;
    try r.init(100);
    defer r.deinit();
    const p = &r.p;
    r.peerAt(0, 100);
    r.peerAt(1, 100);
    r.peerAt(2, 100);
    p.active.store(0b001, .monotonic); // peer 0 elected
    try r.seen(100, 0);
    // peer 1 (outside the set) leaves it to peer 0
    try t.expect(p.pickWork(1) == null);
    const job = p.pickWork(0) orelse return error.TestExpectedJob;
    try t.expectEqual(@as(u64, 100), job.seq);
    // in flight on peer 0: nobody else asks before the hedge (race 1)
    try t.expect(p.pickWork(0) == null);
    try t.expect(p.pickWork(2) == null);
    try t.expectEqual(@as(u64, 1), p.stats.fetches.load(.monotonic));
    // no answer for hedge_ms and seen stuck_ms ago: one more peer joins, then no third
    const slot = &p.slots[100 % ring];
    slot.fetch_ms -= p.hedge_ms;
    slot.seen_ms -= p.stuck_ms;
    try t.expect(p.pickWork(1) != null);
    try t.expect(p.pickWork(2) == null);
    try t.expectEqual(@as(u8, 2), slot.inflight);
}

test "p2p: a peer outside the active set fetches when no active peer has the checkpoint" {
    const t = std.testing;
    var r: TestRig = undefined;
    try r.init(100);
    defer r.deinit();
    const p = &r.p;
    r.peerAt(0, 99); // active, behind
    r.peerAt(1, 100);
    p.active.store(0b01, .monotonic);
    try r.seen(100, 100); // older than wait_ms
    try t.expect(p.pickWork(0) == null); // does not have it
    const job = p.pickWork(1) orelse return error.TestExpectedJob;
    try t.expectEqual(@as(u64, 100), job.seq);
    // with push_peers 0 every connected peer is active
    p.push_peers = 0;
    try t.expect(p.isActive(5));
}

test "p2p: contents paused after a run of fallbacks, one probe in probe_every, resumed by a build" {
    const t = std.testing;
    var r: TestRig = undefined;
    try r.init(96);
    defer r.deinit();
    const p = &r.p;
    r.peerAt(0, 200);
    p.pause_after = 3;
    p.probe_every = 16;
    for (0..3) |_| p.fallback("input object not in the store");
    // reasons live until exit in the node; the test frees them
    defer {
        for (&p.reasons) |*x| {
            if (x.*) |why| p.gpa.free(why);
            x.* = null;
        }
    }
    try t.expectEqual(@as(u32, 3), p.fallback_streak.load(.monotonic));
    try t.expect(p.contentsPaused());
    try r.seen(97, 100);
    try r.seen(96, 100); // 96 % 16 == 0: the probe
    const job = p.pickWork(0) orelse return error.TestExpectedJob;
    try t.expectEqual(@as(u64, 96), job.seq);
    try t.expect(p.pickWork(0) == null); // 97 is left to the other sources
    try t.expect(p.slots[97 % ring].done and p.slots[97 % ring].outcome == .paused);
    try t.expectEqual(@as(u64, 1), p.stats.contents_paused.load(.monotonic));
    // p2p-only never pauses (nothing else would deliver it)
    p.p2p_only = true;
    try t.expect(!p.contentsPaused());
    p.p2p_only = false;
    p.fallback_streak.store(0, .monotonic);
    try t.expect(!p.contentsPaused());
}

test "p2p: the first complete source takes the checkpoint; the stream finds it claimed and does not wait" {
    const t = std.testing;
    var r: TestRig = undefined;
    try r.init(100);
    defer r.deinit();
    const f = r.f;
    // p2p built 100 first (buildInner: markDone, then the spool)
    try t.expect(f.wants(100));
    try t.expect(f.markDone(100));
    try f.writeSpool(100, "blob", "");
    f.delivered(100);
    // the stream's copy arrives later: not wanted, and its claim fails (stream.zig handle)
    try t.expect(!f.wants(100));
    try t.expect(!f.markDone(100));
    // the follower reads the spool file as soon as it is renamed in (nothing waits for a source)
    const got = try r.tmp.dir.readFileAlloc(std.testing.io, "100.chk", t.allocator, .limited(64));
    defer t.allocator.free(got);
    try t.expectEqualStrings("blob", got);
    // and the other way round: a checkpoint the stream claimed first is late for p2p
    try t.expect(f.markDone(101));
    try t.expect(!f.wants(101));
}
