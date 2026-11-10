//! Catching up, at mainnet-v1.83.1. Owner lane: val-consensus-net.
//! - `Subscriber` (`subscriber.rs`): one SubscribeBlocks stream per peer, resubscribing with
//!   backoff from the highest round accepted from that peer.
//! - `Synchronizer` (`synchronizer.rs`): fetches missing ancestors the core reports (live sync,
//!   from the block's sender), the periodic sync of what stays missing (every 200 ms, from the
//!   authors and random peers, at most 2 peers per block), and `sync_last_known_own_block` at
//!   start: no proposal until the highest own round known to f+1 stake of peers is known.
//! - `CommitSyncer` (`commit_syncer.rs`): when the local commit index lags the quorum's, fetches
//!   commit ranges in parallel (`commit_sync_parallel_fetches`, `commit_sync_batches_ahead`),
//!   verifies each range is chained and certified by 2f+1 votes in the returned blocks, and feeds
//!   them to the core as certified commits.
//! - `RoundProber` (`round_prober.rs`): GetLatestRounds to every peer each
//!   `round_prober_interval_ms`, for propagation delay and ancestor selection.
//! Each runs on its own threads; they stop when `Shared.stopping` is set.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const consensus = @import("consensus");
const types = consensus.types;
const shared_mod = @import("shared.zig");
const Shared = shared_mod.Shared;
const peers_mod = @import("peers.zig");
const bc = @import("broadcast.zig");
const mon = @import("mon.zig");
const rounds_mod = @import("rounds.zig");
const hash = @import("hash");

const log = std.log.scoped(.consensus_sync);

pub const Error = error{ Shutdown, OutOfMemory };

fn sleepMs(ms: u64) void {
    shared_mod.sleepMs(ms);
}

/// Sleeps `ms` in slices against the monotonic clock (slices oversleep, so counting them would
/// drift: 250 slices of a 5 s prober interval came to about 6 s), returning early (true) when
/// the node is stopping.
fn sleepOrStop(s: *const Shared, ms: u64) bool {
    return sleepUntilOrStop(s, mon.monoNs(s.io) +| ms * std.time.ns_per_ms);
}

fn sleepUntilOrStop(s: *const Shared, until_ns: u64) bool {
    while (!s.isStopping()) {
        const now = mon.monoNs(s.io);
        if (now >= until_ns) return false;
        sleepMs(@min(20, (until_ns - now + std.time.ns_per_ms - 1) / std.time.ns_per_ms));
    }
    return true;
}

// ================================================================ Subscriber

/// `mysten_common::backoff::ExponentialBackoff`: the next delay is the current one times 1.2,
/// capped at `max`, plus a jitter below `initial`. `next` returns the current delay.
pub const Backoff = struct {
    initial_ns: u64,
    next_ns: u64,
    max_ns: u64,
    max_jitter_ns: u64,

    pub fn init(initial_ns: u64, max_ns: u64) Backoff {
        return .{ .initial_ns = initial_ns, .next_ns = initial_ns, .max_ns = max_ns, .max_jitter_ns = initial_ns };
    }

    pub fn reset(b: *Backoff) void {
        b.next_ns = b.initial_ns;
    }

    pub fn next(b: *Backoff, rand: std.Random) u64 {
        const current = b.next_ns;
        const jitter = if (b.max_jitter_ns == 0) 0 else rand.uintLessThan(u64, b.max_jitter_ns);
        b.next_ns = @min(current *| 6 / 5, b.max_ns) +| jitter;
        return current;
    }
};

pub const Subscriber = struct {
    shared: *Shared,
    threads: []?std.Thread,

    /// subscriber.rs: IMMEDIATE_RETRIES, then ExponentialBackoff::new(100 ms, 10 s).
    const immediate_retries: u32 = 3;
    const backoff_initial_ns: u64 = 100 * std.time.ns_per_ms;
    const backoff_max_ns: u64 = 10 * std.time.ns_per_s;

    /// Starts one stream thread per peer (never ourselves).
    pub fn start(s: *Shared) !*Subscriber {
        const gpa = s.gpa;
        const sub = try gpa.create(Subscriber);
        sub.* = .{ .shared = s, .threads = try gpa.alloc(?std.Thread, s.context.committee.size()) };
        @memset(sub.threads, null);
        for (0..sub.threads.len) |i| {
            if (s.context.own_index != null and s.context.own_index.? == i) continue;
            sub.threads[i] = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, run, .{ s, @as(types.AuthorityIndex, @intCast(i)) });
        }
        return sub;
    }

    pub fn stop(sub: *Subscriber) void {
        for (sub.threads) |t| if (t) |th| th.join();
        sub.shared.gpa.free(sub.threads);
        sub.shared.gpa.destroy(sub);
    }

    /// The retry state of `subscription_loop`: `retries` counts attempts since the last block;
    /// past IMMEDIATE_RETRIES each attempt waits for the backoff. A received block resets both,
    /// and the end of a stream counts as one more retry (Rust bumps it there and at the top).
    pub const Retry = struct {
        retries: u32 = 0,
        backoff: Backoff = Backoff.init(backoff_initial_ns, backoff_max_ns),

        /// Delay before the next attempt (0 = at once); counts the attempt.
        pub fn beforeAttempt(r: *Retry, rand: std.Random) u64 {
            const delay = if (r.retries > immediate_retries) r.backoff.next(rand) else 0;
            r.retries +|= 1;
            return delay;
        }

        pub fn onBlock(r: *Retry) void {
            r.retries = 0;
            r.backoff.reset();
        }

        pub fn onStreamEnd(r: *Retry) void {
            r.retries +|= 1;
        }
    };

    fn run(s: *Shared, peer: types.AuthorityIndex) void {
        var seed: [8]u8 = undefined;
        s.io.random(&seed);
        var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little));
        var retry: Retry = .{};
        while (!s.isStopping()) {
            const delay_ns = retry.beforeAttempt(prng.random());
            if (delay_ns > 0 and sleepOrStop(s, (delay_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms)) return;
            // subscriber.rs: the highest round accepted from the peer, floored at the GC round.
            const last_received = @max(s.published.accepted[peer].load(.acquire), s.published.gc_round.load(.acquire));
            const st = s.peers.subscribe(peer, last_received) catch continue;
            streamBlocks(s, peer, st, &retry);
            st.cancel();
            st.release();
            retry.onStreamEnd();
        }
    }

    /// subscriber.rs SUBSCRIPTION_TIMEOUT: a stream that delivers nothing this long is dropped
    /// and resubscribed, even when the peer still answers keepalives.
    const subscription_timeout_ns: u64 = 30 * std.time.ns_per_s;

    /// Reads blocks until the stream ends. Every block received resets the retry state, valid
    /// or not, as in Rust.
    fn streamBlocks(s: *Shared, peer: types.AuthorityIndex, st: *@import("grpc.zig").Stream, retry: *Retry) void {
        var last_progress_ns = mon.monoNs(s.io);
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        while (!s.isStopping()) {
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            const m = (st.recv(arena, 1 * std.time.ns_per_s) catch |e| switch (e) {
                error.DeadlineExceeded => {
                    if (mon.monoNs(s.io) -| last_progress_ns >= subscription_timeout_ns) {
                        log.info("subscription to peer {d} made no progress for 30 s", .{peer});
                        return;
                    }
                    continue;
                },
                else => return,
            }) orelse return;
            last_progress_ns = mon.monoNs(s.io);
            // A message tonic cannot decode ends the stream (Status from the stream).
            const resp = @import("proto.zig").decode(@import("proto.zig").SubscribeBlocksResponse, arena, m) catch return;
            retry.onBlock();
            var excluded: std.ArrayList(types.BlockRef) = .empty;
            // parse_excluded_ancestors: the list is cut to 2n entries before it is decoded; a
            // malformed entry rejects this block only, the stream goes on.
            const ex_limit = s.context.committee.size() * 2;
            var bad_ref = false;
            for (resp.excluded_ancestors[0..@min(resp.excluded_ancestors.len, ex_limit)]) |raw| {
                const r = bc.decodeRef(raw) orelse {
                    bad_ref = true;
                    break;
                };
                excluded.append(arena, r) catch return;
            }
            if (bad_ref) {
                _ = s.stats.blocks_invalid.fetchAdd(1, .monotonic);
                continue;
            }
            // Blocks on a subscription must be authored by the peer itself.
            _ = s.submitBlocks(peer, &.{resp.block}, excluded.items, true) catch |e| switch (e) {
                error.Shutdown => return,
                else => continue,
            };
        }
    }
};

test "ExponentialBackoff as mysten_common (100 ms, 10 s): factor 1.2, jitter below the initial delay" {
    var prng = std.Random.DefaultPrng.init(1);
    // backoff.rs test_exponential_backoff_default bounds for (50 ms, 10 s).
    var b = Backoff.init(50 * std.time.ns_per_ms, 10 * std.time.ns_per_s);
    const d0 = b.next(prng.random());
    const d1 = b.next(prng.random());
    try std.testing.expect(d0 >= 50 * std.time.ns_per_ms and d0 <= 100 * std.time.ns_per_ms);
    try std.testing.expect(d1 >= 60 * std.time.ns_per_ms and d1 <= 170 * std.time.ns_per_ms);
    // No jitter: exact 1.2 steps, capped at max.
    b = Backoff.init(100 * std.time.ns_per_ms, 10 * std.time.ns_per_s);
    b.max_jitter_ns = 0;
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), b.next(prng.random()));
    try std.testing.expectEqual(@as(u64, 120 * std.time.ns_per_ms), b.next(prng.random()));
    try std.testing.expectEqual(@as(u64, 144 * std.time.ns_per_ms), b.next(prng.random()));
    for (0..40) |_| _ = b.next(prng.random());
    try std.testing.expectEqual(@as(u64, 10 * std.time.ns_per_s), b.next(prng.random()));
}

test "subscriber retry schedule as subscription_loop" {
    var prng = std.Random.DefaultPrng.init(2);
    const rnd = prng.random();
    var r: Subscriber.Retry = .{};
    // First attempt and three immediate retries, then backoff from 100 ms.
    for (0..4) |_| try std.testing.expectEqual(@as(u64, 0), r.beforeAttempt(rnd));
    const d = r.beforeAttempt(rnd);
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), d);
    try std.testing.expect(r.beforeAttempt(rnd) >= 120 * std.time.ns_per_ms);
    // A block resets; the end of that stream counts once more, so 3 immediate attempts follow.
    r.onBlock();
    r.onStreamEnd();
    for (0..3) |_| try std.testing.expectEqual(@as(u64, 0), r.beforeAttempt(rnd));
    try std.testing.expectEqual(@as(u64, 100 * std.time.ns_per_ms), r.beforeAttempt(rnd));
}

// ================================================================ Synchronizer

/// Blocks being fetched, and from which peers (at most MAX_AUTHORITIES_TO_FETCH_PER_BLOCK each).
const InflightBlocks = struct {
    mu: mon.Monitor,
    map: std.AutoHashMapUnmanaged(types.BlockRef, [2]?types.AuthorityIndex) = .empty,
    gpa: Allocator,

    const max_peers_per_block = 2;

    fn init(gpa: Allocator, io: std.Io) InflightBlocks {
        return .{ .mu = mon.Monitor.init(io), .gpa = gpa };
    }
    fn deinit(m: *InflightBlocks) void {
        m.map.deinit(m.gpa);
    }

    /// Locks the refs not already inflight from `peer` or from 2 peers; returns them in `out`.
    fn lock(m: *InflightBlocks, refs: []const types.BlockRef, peer: types.AuthorityIndex, out: *std.ArrayList(types.BlockRef), arena: Allocator) Allocator.Error!void {
        m.mu.lock();
        defer m.mu.unlock();
        for (refs) |r| {
            const e = try m.map.getOrPut(m.gpa, r);
            if (!e.found_existing) e.value_ptr.* = .{ null, null };
            var peers = e.value_ptr;
            if (peers[0] == peer or peers[1] == peer) continue;
            if (peers[0] == null) peers[0] = peer else if (peers[1] == null) peers[1] = peer else continue;
            try out.append(arena, r);
        }
    }

    fn unlock(m: *InflightBlocks, refs: []const types.BlockRef, peer: types.AuthorityIndex) void {
        m.mu.lock();
        defer m.mu.unlock();
        for (refs) |r| {
            if (m.map.getPtr(r)) |p| {
                if (p[0] == peer) p[0] = null;
                if (p[1] == peer) p[1] = null;
                if (p[0] == null and p[1] == null) _ = m.map.remove(r);
            }
        }
    }
};

const FetchJob = struct {
    peer: types.AuthorityIndex,
    refs: []types.BlockRef, // gpa-owned
};

/// One periodic-sync request (`fetch_blocks_from_peers`): its locked refs, its peer, and the
/// blocks it brought back.
const PeriodicReq = struct {
    sy: *Synchronizer,
    run: *PeriodicRun,
    arena: std.heap.ArenaAllocator,
    refs: []types.BlockRef,
    peer: types.AuthorityIndex,
    result: ?[]const []const u8 = null,
    thread: ?std.Thread = null,
};

const PeriodicRun = struct {
    mu: mon.Monitor,
    after: []const types.Round,
    deadline_ns: u64,
    peers: []const types.AuthorityIndex,
    next_peer: usize,
    last_finished_ok: bool = false,

    fn nextPeer(r: *PeriodicRun) ?types.AuthorityIndex {
        r.mu.lock();
        defer r.mu.unlock();
        if (r.next_peer >= r.peers.len) return null;
        r.next_peer += 1;
        return r.peers[r.next_peer - 1];
    }
};

/// synchronizer.rs at mainnet-v1.83.1.
/// - Live sync (`fetch_blocks_from_peer`): per peer at most FETCH_BLOCKS_CONCURRENCY requests in
///   flight and as many queued, more are dropped; each request asks the sender for the missing
///   refs with `fetch_missing_ancestors`, and a failed attempt waits out the 2 s request timeout
///   before retrying, 3 attempts in all.
/// - Periodic sync (`start_fetch_missing_blocks_task`, every 200 ms, one run at a time): the
///   missing blocks are grouped by author, the groups spread over at most 3 random peers, up to
///   `max_blocks_per_fetch` refs per request without missing ancestors; a failed request moves
///   to the next random peer; everything stops at 4 s. During commit-sync failover, missing
///   blocks above `fetch_after_rounds` are left to it and, with none left, one random peer is
///   asked with `fetch_after_rounds` only.
/// - Every response is cut to `max_blocks_per_sync` blocks before it is verified.
pub const Synchronizer = struct {
    shared: *Shared,
    inflight: InflightBlocks,
    jobs: mon.Queue(FetchJob),
    jobs_storage: []FetchJob,
    workers: []std.Thread,
    scheduler: ?std.Thread = null,
    /// live requests per peer: queued + running, and running
    load_mu: mon.Monitor,
    queued: []u32,
    running: []u32,
    prng: std.Random.DefaultPrng,
    gate: PeriodicGate = .{},

    const fetch_blocks_concurrency: u32 = 5;
    const fetch_request_timeout_ns: u64 = 2 * std.time.ns_per_s;
    const fetch_from_peers_timeout_ns: u64 = 4 * std.time.ns_per_s;
    const max_periodic_sync_peers: usize = 3;
    /// fetch_blocks_from_peer MAX_RETRIES: attempts are counted from 1, so 3 attempts in all.
    const max_retries: u32 = 3;
    const periodic_interval_ms: u64 = 200;
    const commit_progress_timeout_ns: u64 = 10 * std.time.ns_per_s;
    const worker_count = 16;

    pub fn start(s: *Shared) !*Synchronizer {
        const gpa = s.gpa;
        const n = s.context.committee.size();
        const sy = try gpa.create(Synchronizer);
        // Every peer can hold 2 * FETCH_BLOCKS_CONCURRENCY live requests (channel + in flight).
        const storage = try gpa.alloc(FetchJob, n * 2 * fetch_blocks_concurrency + 1);
        var seed: [8]u8 = undefined;
        s.io.random(&seed);
        sy.* = .{
            .shared = s,
            .inflight = InflightBlocks.init(gpa, s.io),
            .jobs = mon.Queue(FetchJob).init(s.io, storage),
            .jobs_storage = storage,
            .workers = try gpa.alloc(std.Thread, worker_count),
            .load_mu = mon.Monitor.init(s.io),
            .queued = try gpa.alloc(u32, n),
            .running = try gpa.alloc(u32, n),
            .prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little)),
            .gate = .{ .last_commit_change_ns = mon.monoNs(s.io) },
        };
        @memset(sy.queued, 0);
        @memset(sy.running, 0);
        for (sy.workers) |*w| w.* = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, worker, .{sy});
        if (n > 1) sy.scheduler = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, schedulerLoop, .{sy});
        return sy;
    }

    pub fn stop(sy: *Synchronizer) void {
        sy.jobs.close();
        if (sy.scheduler) |t| t.join();
        for (sy.workers) |w| w.join();
        const gpa = sy.shared.gpa;
        while (sy.jobs.pop(0)) |j| gpa.free(j.refs);
        sy.inflight.deinit();
        gpa.free(sy.workers);
        gpa.free(sy.jobs_storage);
        gpa.free(sy.queued);
        gpa.free(sy.running);
        gpa.destroy(sy);
    }

    /// Live sync: the core found these ancestors missing after a block from `peer`. At most
    /// `max_blocks_per_sync` are taken; blocks already being fetched are skipped; when the peer
    /// already has 2 * FETCH_BLOCKS_CONCURRENCY requests the request is dropped (the periodic
    /// sync picks the blocks up).
    pub fn fetchMissing(sy: *Synchronizer, refs: []const types.BlockRef, peer: types.AuthorityIndex) void {
        const s = sy.shared;
        if (refs.len == 0 or s.context.committee.size() <= 1) return;
        if (s.context.own_index != null and s.context.own_index.? == peer) return;
        if (peer >= sy.queued.len) return;
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const take = refs[0..@min(refs.len, s.context.parameters.max_blocks_per_sync)];
        var locked: std.ArrayList(types.BlockRef) = .empty;
        sy.inflight.lock(take, peer, &locked, arena) catch return;
        if (locked.items.len == 0) return;
        sy.load_mu.lock();
        const full = sy.queued[peer] >= 2 * fetch_blocks_concurrency;
        if (!full) sy.queued[peer] += 1;
        sy.load_mu.unlock();
        if (full) {
            sy.inflight.unlock(locked.items, peer);
            return;
        }
        const owned = s.gpa.dupe(types.BlockRef, locked.items) catch {
            sy.release(peer, false);
            sy.inflight.unlock(locked.items, peer);
            return;
        };
        if (!sy.jobs.push(.{ .peer = peer, .refs = owned })) {
            sy.release(peer, false);
            sy.inflight.unlock(owned, peer);
            s.gpa.free(owned);
        }
    }

    fn release(sy: *Synchronizer, peer: types.AuthorityIndex, was_running: bool) void {
        sy.load_mu.lock();
        defer sy.load_mu.unlock();
        sy.queued[peer] -= 1;
        if (was_running) sy.running[peer] -= 1;
    }

    fn worker(sy: *Synchronizer) void {
        const s = sy.shared;
        while (!s.isStopping()) {
            const job = sy.jobs.pop(200 * std.time.ns_per_ms) orelse continue;
            sy.load_mu.lock();
            const busy = sy.running[job.peer] >= fetch_blocks_concurrency;
            if (!busy) sy.running[job.peer] += 1;
            sy.load_mu.unlock();
            if (busy) {
                // The peer has FETCH_BLOCKS_CONCURRENCY requests in flight: back in the queue.
                if (!sy.jobs.push(job)) {
                    sy.release(job.peer, false);
                    sy.inflight.unlock(job.refs, job.peer);
                    s.gpa.free(job.refs);
                } else sleepMs(2);
                continue;
            }
            sy.runJob(job);
            sy.release(job.peer, true);
            sy.inflight.unlock(job.refs, job.peer);
            s.gpa.free(job.refs);
        }
    }

    /// `get_fetch_after_rounds`: per authority the round of its last cached block, floored at
    /// the GC round.
    fn afterRounds(s: *Shared, arena: Allocator) Allocator.Error![]types.Round {
        const out = try arena.alloc(types.Round, s.context.committee.size());
        const gc = s.published.gc_round.load(.acquire);
        for (out, 0..) |*r, i| r.* = @max(s.published.accepted[i].load(.acquire), gc);
        return out;
    }

    /// `process_fetched_blocks`: at most `max_blocks_per_sync` of the returned blocks are used.
    fn processFetched(s: *Shared, peer: types.AuthorityIndex, blocks: []const []const u8) void {
        if (blocks.len == 0) return;
        const take = blocks[0..@min(blocks.len, s.context.parameters.max_blocks_per_sync)];
        const accepted = s.submitBlocks(peer, take, &.{}, false) catch 0;
        _ = s.stats.blocks_fetched.fetchAdd(accepted, .monotonic);
    }

    fn runJob(sy: *Synchronizer, job: FetchJob) void {
        const s = sy.shared;
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const after = afterRounds(s, arena) catch return;
        var retries: u32 = 1;
        while (!s.isStopping()) {
            const start_ns = mon.monoNs(s.io);
            const blocks = s.peers.fetchBlocks(arena, job.peer, job.refs, after, true, fetch_request_timeout_ns) catch {
                // fetch_blocks_request: wait out the request timeout before a retry.
                if (sleepUntilOrStop(s, start_ns + fetch_request_timeout_ns)) return;
                retries += 1;
                if (retries > max_retries) return;
                continue;
            };
            processFetched(s, job.peer, blocks);
            return;
        }
    }

    // ------------------------------------------------------------ periodic sync

    /// `should_run_periodic_sync`.
    fn shouldRunPeriodic(sy: *Synchronizer) bool {
        const s = sy.shared;
        const quorum = s.commit_votes.quorumCommitIndex(&s.context.committee);
        const local = s.published.commit_index.load(.acquire);
        return sy.gate.decide(s.context.parameters.commit_sync_batch_size, local, quorum, mon.monoNs(s.io));
    }

    fn schedulerLoop(sy: *Synchronizer) void {
        const s = sy.shared;
        while (!sleepOrStop(s, periodic_interval_ms)) {
            sy.periodicOnce() catch {};
        }
    }

    /// `start_fetch_missing_blocks_task`, run to completion (Rust starts a run only when the
    /// previous one finished).
    fn periodicOnce(sy: *Synchronizer) !void {
        const s = sy.shared;
        if (!sy.shouldRunPeriodic()) return;
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var missing = std.ArrayList(types.BlockRef).fromOwnedSlice(try s.copyMissing(arena));
        const after = try afterRounds(s, arena);
        if (sy.gate.commit_sync_failover) {
            // Blocks above fetch_after_rounds come with a fetch_after_rounds request.
            var k: usize = 0;
            for (missing.items) |r| {
                if (r.author < after.len and r.round <= after[r.author]) {
                    missing.items[k] = r;
                    k += 1;
                }
            }
            missing.shrinkRetainingCapacity(k);
        } else if (missing.items.len == 0) return;

        const n = s.context.committee.size();
        const own = s.context.own_index orelse n;
        var peers: std.ArrayList(types.AuthorityIndex) = .empty;
        for (0..n) |i| if (i != own) try peers.append(arena, @intCast(i));
        if (peers.items.len == 0) return;
        const rnd = sy.prng.random();
        rnd.shuffle(types.AuthorityIndex, peers.items);

        if (missing.items.len == 0) {
            // fetch_blocks_with_fetch_after_rounds: one random peer, no refs, no retry.
            const peer = peers.items[0];
            const blocks = s.peers.fetchBlocks(arena, peer, &.{}, after, false, fetch_request_timeout_ns) catch return;
            processFetched(s, peer, blocks);
            return;
        }
        try sy.fetchFromPeers(arena, missing.items, after, peers.items, rnd);
    }

    /// `fetch_blocks_from_peers`.
    fn fetchFromPeers(sy: *Synchronizer, arena: Allocator, missing_in: []types.BlockRef, after: []const types.Round, peers: []const types.AuthorityIndex, rnd: std.Random) !void {
        const s = sy.shared;
        const p = s.context.parameters;
        const n = s.context.committee.size();
        // BTreeSet order (round, author, digest), lowest first.
        std.mem.sort(types.BlockRef, missing_in, {}, struct {
            fn lt(_: void, a: types.BlockRef, b: types.BlockRef) bool {
                return a.order(b) == .lt;
            }
        }.lt);
        const missing = missing_in[0..@min(missing_in.len, 2 * max_periodic_sync_peers * p.max_blocks_per_fetch)];
        // Group by author.
        const by_author = try arena.alloc(std.ArrayList(types.BlockRef), n);
        for (by_author) |*l| l.* = .empty;
        for (missing) |r| if (r.author < n) try by_author[r.author].append(arena, r);
        var groups: std.ArrayList([]const types.BlockRef) = .empty;
        for (by_author) |l| if (l.items.len > 0) try groups.append(arena, l.items);
        if (groups.items.len == 0) return;
        const per_peer = std.math.divCeil(usize, groups.items.len, @min(peers.len, max_periodic_sync_peers)) catch unreachable;
        rnd.shuffle([]const types.BlockRef, groups.items);

        var run: PeriodicRun = .{
            .mu = mon.Monitor.init(s.io),
            .after = after,
            .deadline_ns = mon.monoNs(s.io) + fetch_from_peers_timeout_ns,
            .peers = peers,
            .next_peer = 0,
        };
        var reqs: std.ArrayList(*PeriodicReq) = .empty;
        defer for (reqs.items) |r| {
            r.arena.deinit();
            s.gpa.destroy(r);
        };
        var off: usize = 0;
        while (off < groups.items.len) : (off += per_peer) {
            const peer = run.nextPeer() orelse break;
            // The refs of these authorities, lowest first, at most max_blocks_per_fetch.
            var refs: std.ArrayList(types.BlockRef) = .empty;
            for (groups.items[off..@min(groups.items.len, off + per_peer)]) |g| try refs.appendSlice(arena, g);
            std.mem.sort(types.BlockRef, refs.items, {}, struct {
                fn lt(_: void, a: types.BlockRef, b: types.BlockRef) bool {
                    return a.order(b) == .lt;
                }
            }.lt);
            const want = refs.items[0..@min(refs.items.len, p.max_blocks_per_fetch)];
            const req = try s.gpa.create(PeriodicReq);
            req.* = .{ .sy = sy, .run = &run, .arena = std.heap.ArenaAllocator.init(s.gpa), .refs = &.{}, .peer = peer };
            reqs.append(arena, req) catch |e| {
                req.arena.deinit();
                s.gpa.destroy(req);
                return e;
            };
            var locked: std.ArrayList(types.BlockRef) = .empty;
            try sy.inflight.lock(want, peer, &locked, req.arena.allocator());
            if (locked.items.len == 0) continue; // nothing to lock from this peer: skip it
            req.refs = locked.items;
            req.thread = std.Thread.spawn(.{ .stack_size = 8 << 20 }, periodicReqMain, .{req}) catch blk: {
                sy.inflight.unlock(req.refs, req.peer);
                req.refs = &.{};
                break :blk null;
            };
        }
        var any = false;
        for (reqs.items) |r| if (r.thread) |t| {
            t.join();
            any = true;
        };
        if (!any) return;
        // The run ends early only when the last request to finish brought blocks; otherwise
        // Rust waits for FETCH_FROM_PEERS_TIMEOUT.
        if (!run.last_finished_ok) _ = sleepUntilOrStop(s, run.deadline_ns);
        for (reqs.items) |r| {
            if (r.result) |blocks| processFetched(s, r.peer, blocks);
            if (r.refs.len > 0) sy.inflight.unlock(r.refs, r.peer);
        }
    }

    fn periodicReqMain(req: *PeriodicReq) void {
        const sy = req.sy;
        const s = sy.shared;
        const run = req.run;
        const arena = req.arena.allocator();
        var ok = false;
        defer {
            run.mu.lock();
            run.last_finished_ok = ok;
            run.mu.unlock();
        }
        while (!s.isStopping()) {
            const start_ns = mon.monoNs(s.io);
            if (start_ns >= run.deadline_ns) break;
            const t = @min(fetch_request_timeout_ns, run.deadline_ns - start_ns);
            if (s.peers.fetchBlocks(arena, req.peer, req.refs, run.after, false, t)) |blocks| {
                req.result = blocks;
                ok = true;
                return;
            } else |_| {}
            if (sleepUntilOrStop(s, @min(start_ns + fetch_request_timeout_ns, run.deadline_ns))) break;
            if (mon.monoNs(s.io) >= run.deadline_ns) break;
            // Retry from the next random peer, if the blocks can be locked for it.
            const next = run.nextPeer() orelse break;
            sy.inflight.unlock(req.refs, req.peer);
            var locked: std.ArrayList(types.BlockRef) = .empty;
            sy.inflight.lock(req.refs, next, &locked, arena) catch {
                req.refs = &.{};
                return;
            };
            req.refs = locked.items;
            req.peer = next;
            if (req.refs.len == 0) return;
        }
    }
};

/// `should_run_periodic_sync`: while commits lag, periodic sync pauses for the commit syncer;
/// after COMMIT_PROGRESS_TIMEOUT without progress it runs as the commit-sync failover until one
/// commit batch was gained.
const PeriodicGate = struct {
    last_changed_commit_index: u32 = 0,
    last_commit_change_ns: u64 = 0,
    commit_sync_failover: bool = false,

    fn decide(g: *PeriodicGate, batch: u32, local: u32, quorum: u32, now: u64) bool {
        if (!rounds_mod.isCommitLagging(batch, local, quorum)) {
            g.last_changed_commit_index = local;
            g.last_commit_change_ns = now;
            g.commit_sync_failover = false;
            return true;
        }
        if (g.commit_sync_failover) {
            if (local < g.last_changed_commit_index +| batch) return true;
            g.last_changed_commit_index = local;
            g.last_commit_change_ns = now;
            g.commit_sync_failover = false;
            return false;
        }
        if (local == g.last_changed_commit_index) {
            if (now -| g.last_commit_change_ns >= Synchronizer.commit_progress_timeout_ns) {
                g.commit_sync_failover = true;
                return true;
            }
        } else {
            g.last_changed_commit_index = local;
            g.last_commit_change_ns = now;
        }
        return false;
    }
};

test "periodic sync gate as should_run_periodic_sync" {
    const s_ns = std.time.ns_per_s;
    var g: PeriodicGate = .{};
    // Not lagging: run.
    try std.testing.expect(g.decide(100, 50, 60, 0));
    // Lagging (quorum far ahead): skip while the commit index moves.
    try std.testing.expect(!g.decide(100, 50, 1000, 1 * s_ns));
    try std.testing.expect(!g.decide(100, 70, 1000, 2 * s_ns));
    // No progress for 10 s: failover, run.
    try std.testing.expect(!g.decide(100, 70, 1000, 11 * s_ns));
    try std.testing.expect(g.decide(100, 70, 1000, 12 * s_ns));
    try std.testing.expect(g.commit_sync_failover);
    // Failover holds until a full batch was gained.
    try std.testing.expect(g.decide(100, 169, 1000, 13 * s_ns));
    try std.testing.expect(!g.decide(100, 170, 1000, 14 * s_ns));
    try std.testing.expect(!g.commit_sync_failover);
}

// ================================================================ own block sync

/// One pass of `sync_last_known_own_block` (synchronizer.rs): all peers are asked in parallel,
/// each retrying after 1 s on a transport error, until the pass deadline.
const OwnPass = struct {
    s: *Shared,
    own: types.AuthorityIndex,
    deadline_ns: u64,
    mu: mon.Monitor,
    total_stake: u64 = 0,
    highest: types.Round = 0,

    const fetch_timeout_ns: u64 = 2 * std.time.ns_per_s;
    const retry_delay_ms: u64 = 1000;

    fn peerMain(p: *OwnPass, peer: types.AuthorityIndex) void {
        const s = p.s;
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        var delay_ms: u64 = 0;
        while (!s.isStopping()) {
            const now = mon.monoNs(s.io);
            if (now >= p.deadline_ns) return;
            if (delay_ms > 0) {
                if (sleepOrStop(s, @min(delay_ms, (p.deadline_ns - now) / std.time.ns_per_ms + 1))) return;
            }
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();
            const blocks = s.peers.fetchLatestBlocks(arena, peer, &.{p.own}, fetch_timeout_ns) catch {
                delay_ms = retry_delay_ms;
                continue;
            };
            var max_round: types.Round = 0;
            for (blocks) |raw| {
                const v = s.verifyBlock(arena, raw, peer, false) catch return; // invalid result: not counted
                if (v.block.block.inner.author() != p.own) return;
                max_round = @max(max_round, v.block.block.inner.round());
            }
            p.mu.lock();
            p.total_stake += s.context.committee.stake(peer);
            p.highest = @max(p.highest, max_round);
            p.mu.unlock();
            return;
        }
    }
};

/// `sync_last_known_own_block`: asks every peer for our latest block until peers holding at
/// least validity-threshold stake answered; returns the highest own round seen. Blocks of
/// returned results are verified and must be authored by us. Null when stopping. Callers run it
/// only on the first boot (`boot_counter == 0`) with a non-zero timeout, like Rust.
pub fn syncLastKnownOwnBlock(s: *Shared) ?types.Round {
    const ctx = s.context;
    const own = ctx.own_index orelse return 0;
    const n = ctx.committee.size();
    if (n <= 1) return 0;
    var retry_delay_ms: u64 = 500;
    while (!s.isStopping()) {
        var pass: OwnPass = .{
            .s = s,
            .own = own,
            .deadline_ns = mon.monoNs(s.io) +| ctx.parameters.sync_last_known_own_block_timeout_ns,
            .mu = mon.Monitor.init(s.io),
        };
        var threads: [shared_mod.max_peers]?std.Thread = @splat(null);
        for (0..n) |i| {
            if (i == own) continue;
            threads[i] = std.Thread.spawn(.{ .stack_size = 8 << 20 }, OwnPass.peerMain, .{ &pass, @as(types.AuthorityIndex, @intCast(i)) }) catch null;
        }
        for (threads[0..n]) |t| if (t) |th| th.join();
        if (ctx.committee.reachedValidity(pass.total_stake)) return pass.highest;
        log.warn("own-block sync: stake {d} did not reach the validity threshold, retrying", .{pass.total_stake});
        if (sleepOrStop(s, retry_delay_ms)) return null;
        retry_delay_ms = @min(retry_delay_ms * 3 / 2, 4000);
    }
    return null;
}

// ================================================================ CommitSyncer

pub const CommitSyncer = struct {
    shared: *Shared,
    thread: ?std.Thread = null,
    mu: mon.Monitor,
    /// pending ranges (inclusive start,end), ordered; fetched results; completed fetch results
    pending: std.ArrayList(Range) = .empty,
    fetched: std.ArrayList(Fetched) = .empty,
    done: std.ArrayList(Done) = .empty,
    inflight: usize = 0,
    highest_scheduled: u32 = 0,
    synced_commit_index: u32 = 0,

    const Range = struct { start: u32, end: u32 };
    const Fetched = struct { range: Range, batch: *shared_mod.CommitBatch };
    const Done = struct { target_end: u32, batch: *shared_mod.CommitBatch, first: u32, last: u32 };

    pub fn start(s: *Shared) !*CommitSyncer {
        const cs = try s.gpa.create(CommitSyncer);
        cs.* = .{ .shared = s, .mu = mon.Monitor.init(s.io) };
        cs.thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, loop, .{cs});
        return cs;
    }

    pub fn stop(cs: *CommitSyncer) void {
        if (cs.thread) |t| t.join();
        // wait for fetch threads
        while (true) {
            cs.mu.lock();
            const n = cs.inflight;
            cs.mu.unlock();
            if (n == 0) break;
            sleepMs(5);
        }
        const gpa = cs.shared.gpa;
        for (cs.fetched.items) |f| f.batch.destroy();
        for (cs.done.items) |d| d.batch.destroy();
        cs.pending.deinit(gpa);
        cs.fetched.deinit(gpa);
        cs.done.deinit(gpa);
        gpa.destroy(cs);
    }

    fn unhandledThreshold(s: *Shared) u32 {
        return s.context.parameters.commit_sync_batch_size * @as(u32, @intCast(s.context.parameters.commit_sync_batches_ahead));
    }

    fn loop(cs: *CommitSyncer) void {
        const s = cs.shared;
        var last_schedule_ns: u64 = 0;
        while (!sleepOrStop(s, 100)) {
            const now = mon.monoNs(s.io);
            if (now -| last_schedule_ns >= 2 * std.time.ns_per_s) {
                last_schedule_ns = now;
                cs.trySchedule();
            }
            cs.handleResults();
            cs.tryStartFetches();
        }
    }

    fn trySchedule(cs: *CommitSyncer) void {
        const s = cs.shared;
        const p = s.context.parameters;
        const quorum = s.commit_votes.quorumCommitIndex(&s.context.committee);
        const local = s.published.commit_index.load(.acquire);
        const handled = s.handled_commit.load(.acquire);
        cs.mu.lock();
        defer cs.mu.unlock();
        cs.synced_commit_index = @max(cs.synced_commit_index, local);
        const after = @max(cs.synced_commit_index, cs.highest_scheduled);
        var prev_end = after;
        while (prev_end <= quorum) : (prev_end += p.commit_sync_batch_size) {
            const range_start = prev_end + 1;
            const range_end = prev_end + p.commit_sync_batch_size;
            // Only full batches; block broadcast and the synchronizer finish the tail.
            if (quorum < range_end) break;
            // Pause while the consensus handler is behind.
            if (handled + unhandledThreshold(s) < range_end) break;
            cs.insertPending(.{ .start = range_start, .end = range_end }) catch return;
            cs.highest_scheduled = range_end;
        }
    }

    fn insertPending(cs: *CommitSyncer, r: Range) !void {
        const gpa = cs.shared.gpa;
        var i: usize = 0;
        while (i < cs.pending.items.len and cs.pending.items[i].start < r.start) i += 1;
        if (i < cs.pending.items.len and cs.pending.items[i].start == r.start and cs.pending.items[i].end == r.end) return;
        try cs.pending.insert(gpa, i, r);
    }

    fn tryStartFetches(cs: *CommitSyncer) void {
        const s = cs.shared;
        const p = s.context.parameters;
        const known_peers = s.context.committee.size() -| 1;
        cs.mu.lock();
        defer cs.mu.unlock();
        const target = @max(1, @min(@min(p.commit_sync_parallel_fetches, known_peers * 2 / 3), p.commit_sync_batches_ahead -| cs.fetched.items.len));
        while (cs.inflight < target and cs.pending.items.len > 0) {
            const r = cs.pending.orderedRemove(0);
            cs.inflight += 1;
            const t = std.Thread.spawn(.{ .stack_size = 8 << 20 }, fetchTask, .{ cs, r }) catch {
                cs.inflight -= 1;
                cs.insertPending(r) catch {};
                return;
            };
            t.detach();
        }
    }

    fn fetchTask(cs: *CommitSyncer, range: Range) void {
        const s = cs.shared;
        defer {
            cs.mu.lock();
            cs.inflight -= 1;
            cs.mu.unlock();
        }
        const base = s.context.parameters.commit_sync_request_timeout_ns;
        var mult: u64 = 0;
        var seed: [8]u8 = undefined;
        s.io.random(&seed);
        var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little));
        while (!s.isStopping()) {
            mult = @min(mult + 1, 12);
            const request_timeout = base * mult;
            // peers in random order, at most 24
            const n = s.context.committee.size();
            const own = s.context.own_index orelse n;
            var order: [shared_mod.max_peers]u32 = undefined;
            var cnt: usize = 0;
            for (0..n) |i| if (i != own and cnt < order.len) {
                order[cnt] = @intCast(i);
                cnt += 1;
            };
            prng.random().shuffle(u32, order[0..cnt]);
            for (order[0..@min(cnt, 24)]) |peer| {
                if (s.isStopping()) return;
                const batch = fetchOnce(s, peer, range, request_timeout) catch |e| {
                    log.debug("commit fetch {d}..{d} from {d}: {s}", .{ range.start, range.end, peer, @errorName(e) });
                    continue;
                };
                const cb: *shared_mod.CommitBatch = batch.batch;
                cs.mu.lock();
                cs.done.append(s.gpa, .{ .target_end = range.end, .batch = cb, .first = batch.first, .last = batch.last }) catch {
                    cb.destroy();
                };
                cs.mu.unlock();
                return;
            }
            if (sleepOrStop(s, base / std.time.ns_per_ms)) return;
        }
    }

    const FetchError = error{ Peer, BadCommits, NotEnoughVotes, BadBlocks, OutOfMemory, Shutdown };

    /// `fetch_once`: probe, fetch commits, verify chain and certification, fetch and check blocks.
    fn fetchOnce(s: *Shared, peer: types.AuthorityIndex, range: Range, timeout_ns: u64) FetchError!struct { batch: *shared_mod.CommitBatch, first: u32, last: u32 } {
        const ctx = s.context;
        const batch = shared_mod.CommitBatch.create(s.gpa) catch return error.OutOfMemory;
        errdefer batch.destroy();
        const arena = batch.arena.allocator();
        var scratch_state = std.heap.ArenaAllocator.init(s.gpa);
        defer scratch_state.deinit();
        const scratch = scratch_state.allocator();

        s.peers.probe(scratch, peer, ctx.parameters.commit_sync_probe_timeout_ns) catch return error.Peer;
        const resp = s.peers.fetchCommits(scratch, peer, range.start, range.end, timeout_ns) catch return error.Peer;

        // Parse and chain-check the commits (Rust verify_commits).
        var commits: std.ArrayList(types.TrustedCommit) = .empty;
        for (resp.commits) |raw| {
            const bytes = arena.dupe(u8, raw) catch return error.OutOfMemory;
            const c = bcs.decode(types.Commit, arena, bytes) catch return error.BadCommits;
            const digest = hash.blake2b256(&.{bytes});
            if (commits.items.len == 0) {
                if (c.index() != range.start) return error.BadCommits;
            } else {
                const prev = commits.items[commits.items.len - 1];
                if (c.index() != prev.commit.index() + 1 or !std.mem.eql(u8, &c.V1.previous_digest, &prev.digest)) return error.BadCommits;
            }
            if (c.index() > range.end) break;
            commits.append(arena, .{ .commit = c, .serialized = bytes, .digest = digest }) catch return error.OutOfMemory;
        }
        if (commits.items.len == 0) return error.BadCommits;
        const end_commit = commits.items[commits.items.len - 1];
        const end_ref = end_commit.reference();

        // Certifying blocks: fully verified; their commit votes for the end commit must reach a quorum.
        var agg: consensus.committee.StakeAggregator(consensus.committee.max_committee_size) = .{};
        var out_blocks: std.ArrayList(types.VerifiedBlock) = .empty;
        var rejects: std.ArrayList([]const types.TransactionIndex) = .empty;
        for (resp.certifier_blocks) |raw| {
            const v = s.verifyBlock(arena, raw, peer, false) catch return error.BadBlocks;
            for (v.block.block.inner.commitVotes()) |vote| {
                if (vote.index == end_ref.index and std.mem.eql(u8, &vote.digest, &end_ref.digest)) _ = agg.add(v.block.block.inner.author(), &ctx.committee, ctx.committee.quorum_threshold);
            }
            out_blocks.append(arena, v.block) catch return error.OutOfMemory;
            rejects.append(arena, v.rejects) catch return error.OutOfMemory;
        }
        if (!ctx.committee.reachedQuorum(agg.stake)) return error.NotEnoughVotes;

        // Blocks of the commits, in chunks, each checked against its requested ref by digest.
        var want: std.ArrayList(types.BlockRef) = .empty;
        for (commits.items) |c| want.appendSlice(scratch, c.commit.V1.blocks) catch return error.OutOfMemory;
        std.mem.sort(types.BlockRef, want.items, {}, struct {
            fn lt(_: void, a: types.BlockRef, b: types.BlockRef) bool {
                return a.order(b) == .lt;
            }
        }.lt);
        var off: usize = 0;
        while (off < want.items.len) : (off += ctx.parameters.max_blocks_per_fetch) {
            if (s.isStopping()) return error.Shutdown;
            const chunk = want.items[off..@min(want.items.len, off + ctx.parameters.max_blocks_per_fetch)];
            const got = s.peers.fetchBlocks(scratch, peer, chunk, &.{}, false, timeout_ns) catch return error.Peer;
            if (got.len != chunk.len) return error.BadBlocks;
            for (chunk, got) |req, raw| {
                const vb = shared_mod.decodeTrusted(arena, raw) catch return error.BadBlocks;
                const got_ref = vb.reference();
                if (!got_ref.eql(req)) return error.BadBlocks;
                out_blocks.append(arena, vb) catch return error.OutOfMemory;
            }
        }
        // Record votes and rounds from everything fetched.
        for (out_blocks.items) |b| {
            s.commit_votes.observeBlock(b.block.inner.author(), b.block.inner.commitVotes());
            s.rounds.updateFromVerifiedBlock(b.block.inner.author(), b.block.inner.round(), b.block.inner.ancestors(), &.{});
        }
        batch.commits = commits.items;
        batch.blocks = out_blocks.items;
        batch.certifier_rejects = rejects.items;
        return .{ .batch = batch, .first = commits.items[0].commit.index(), .last = end_commit.commit.index() };
    }

    /// Takes finished fetches, re-queues the unfetched tail of partial results, and sends ranges
    /// to the core in order, without gaps after what is already synced.
    fn handleResults(cs: *CommitSyncer) void {
        const s = cs.shared;
        const gpa = s.gpa;
        cs.mu.lock();
        const local = s.published.commit_index.load(.acquire);
        cs.synced_commit_index = @max(cs.synced_commit_index, local);
        while (cs.done.items.len > 0) {
            const d = cs.done.orderedRemove(0);
            if (d.last < d.target_end) cs.insertPending(.{ .start = d.last + 1, .end = d.target_end }) catch {};
            if (cs.synced_commit_index < d.last) {
                const range: Range = .{ .start = d.first, .end = d.last };
                var i: usize = 0;
                while (i < cs.fetched.items.len and cs.fetched.items[i].range.start < range.start) i += 1;
                cs.fetched.insert(gpa, i, .{ .range = range, .batch = d.batch }) catch d.batch.destroy();
            } else d.batch.destroy();
        }
        while (cs.fetched.items.len > 0) {
            const f = cs.fetched.items[0];
            if (f.range.start > cs.synced_commit_index + 1) break; // gap: wait for the earlier range
            _ = cs.fetched.orderedRemove(0);
            if (f.range.end <= cs.synced_commit_index) {
                f.batch.destroy();
                continue;
            }
            cs.synced_commit_index = @max(cs.synced_commit_index, f.range.end);
            cs.mu.unlock();
            // Blocking here slows the syncer when the core is busy.
            if (s.pushCore(.{ .commits = f.batch })) {
                _ = s.stats.commit_batches_synced.fetchAdd(1, .monotonic);
            } else f.batch.destroy();
            cs.mu.lock();
        }
        cs.mu.unlock();
    }
};

// ================================================================ RoundProber

pub const RoundProber = struct {
    shared: *Shared,
    thread: ?std.Thread = null,

    pub fn start(s: *Shared) !*RoundProber {
        const p = try s.gpa.create(RoundProber);
        p.* = .{ .shared = s };
        if (s.context.committee.size() > 1) p.thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, loop, .{p});
        return p;
    }

    pub fn stop(p: *RoundProber) void {
        if (p.thread) |t| t.join();
        p.shared.gpa.destroy(p);
    }

    /// round_prober.rs: a tokio interval (first tick at once, then every
    /// `round_prober_interval_ms` from the previous tick, not from the end of the probe).
    fn loop(p: *RoundProber) void {
        const s = p.shared;
        const period_ns = s.context.parameters.round_prober_interval_ms * std.time.ns_per_ms;
        var next_ns = mon.monoNs(s.io);
        while (!sleepUntilOrStop(s, next_ns)) {
            const tick_ns = mon.monoNs(s.io);
            _ = probe(s);
            // MissedTickBehavior::Delay: a late tick shifts the schedule instead of bursting.
            next_ns = @max(next_ns + period_ns, tick_ns);
        }
    }

    const Probe = struct {
        s: *Shared,
        next: std.atomic.Value(u32) = .init(0),
        timeout_ns: u64,
        mu: mon.Monitor,
        received: [][]u32,
        accepted: [][]u32,
    };

    /// One probe of every peer (parallel); updates the round tracker and returns the propagation
    /// delay of our own blocks, which is also sent to the core.
    pub fn probe(s: *Shared) types.Round {
        const ctx = s.context;
        const n = ctx.committee.size();
        const own = ctx.own_index orelse return 0;
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        var pr: Probe = .{ .s = s, .timeout_ns = ctx.parameters.round_prober_request_timeout_ms * std.time.ns_per_ms, .mu = mon.Monitor.init(s.io), .received = arena.alloc([]u32, n) catch return 0, .accepted = arena.alloc([]u32, n) catch return 0 };
        for (0..n) |i| {
            pr.received[i] = &.{};
            pr.accepted[i] = &.{};
        }
        const workers = @min(n, 16);
        var threads: [16]?std.Thread = @splat(null);
        for (0..workers) |i| threads[i] = std.Thread.spawn(.{ .stack_size = 4 << 20 }, probeWorker, .{ &pr, arena }) catch null;
        for (&threads) |*t| if (t.*) |th| th.join();
        // Failed peers count as zeros.
        s.rounds.resetProbe();
        for (0..n) |i| {
            if (i == own) continue;
            s.rounds.updateFromProbe(@intCast(i), if (pr.received[i].len == n) pr.received[i] else null, if (pr.accepted[i].len == n) pr.accepted[i] else null);
        }
        var local_accepted: [shared_mod.max_peers]types.Round = undefined;
        for (0..n) |i| local_accepted[i] = s.published.accepted[i].load(.acquire);
        const last_proposed = s.published.last_proposed.load(.acquire);
        s.rounds.setLocalAccepted(local_accepted[0..n], last_proposed);
        const delay = s.rounds.propagationDelay(&ctx.committee, last_proposed);
        _ = s.core_q.push(.{ .propagation_delay = delay });
        return delay;
    }

    fn probeWorker(pr: *Probe, arena: Allocator) void {
        const s = pr.s;
        const n = s.context.committee.size();
        const own = s.context.own_index orelse return;
        while (true) {
            const i = pr.next.fetchAdd(1, .monotonic);
            if (i >= n) return;
            if (i == own or s.isStopping()) continue;
            var local_state = std.heap.ArenaAllocator.init(s.gpa);
            defer local_state.deinit();
            const r = s.peers.getLatestRounds(local_state.allocator(), i, pr.timeout_ns) catch continue;
            pr.mu.lock();
            defer pr.mu.unlock();
            pr.received[i] = arena.dupe(u32, r.received) catch &.{};
            pr.accepted[i] = arena.dupe(u32, r.accepted) catch &.{};
        }
    }
};

// ================================================================ tests over loopback gRPC

/// A peer that serves FetchBlocks from a fixed block set and records every request; `fail`
/// makes it answer UNAVAILABLE.
const SyncTestPeer = struct {
    gpa: Allocator,
    mu: mon.Monitor,
    blocks: []const []const u8,
    refs: []const types.BlockRef,
    fail: bool = false,
    reqs: std.ArrayList(Req) = .empty,
    /// FetchCommits answer
    commits: []const []const u8 = &.{},
    certifiers: []const []const u8 = &.{},

    const Req = struct { refs: []types.BlockRef, after: []u32, missing: bool, at_ns: u64 };

    fn serve(ctx: *anyopaque, st: *@import("grpc.zig").Stream) void {
        const p: *SyncTestPeer = @ptrCast(@alignCast(ctx));
        const proto = @import("proto.zig");
        var arena_state = std.heap.ArenaAllocator.init(p.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const m = st.method() orelse return st.finish(.unimplemented, "");
        const raw = (st.recv(arena, 5 * std.time.ns_per_s) catch null) orelse return st.finish(.internal, "");
        switch (m) {
            .FetchBlocks => {},
            .GetLatestRounds => {
                const z = [_]u32{ 0, 0, 0, 0 };
                const msg = proto.encode(proto.GetLatestRoundsResponse, arena, &.{ .highest_received = &z, .highest_accepted = &z }) catch return st.finish(.internal, "");
                st.send(msg) catch return;
                return st.finish(.ok, "");
            },
            .FetchCommits => {
                const msg = proto.encode(proto.FetchCommitsResponse, arena, &.{ .commits = p.commits, .certifier_blocks = p.certifiers }) catch return st.finish(.internal, "");
                st.send(msg) catch return;
                return st.finish(.ok, "");
            },
            else => return st.finish(.unimplemented, ""),
        }
        const req = proto.decode(proto.FetchBlocksRequest, arena, raw) catch return st.finish(.internal, "");
        var out: std.ArrayList([]const u8) = .empty;
        {
            p.mu.lock();
            defer p.mu.unlock();
            const refs = p.gpa.alloc(types.BlockRef, req.block_refs.len) catch return st.finish(.internal, "");
            for (req.block_refs, 0..) |b, i| refs[i] = bc.decodeRef(b).?;
            p.reqs.append(p.gpa, .{ .refs = refs, .after = p.gpa.dupe(u32, req.fetch_after_rounds) catch unreachable, .missing = req.fetch_missing_ancestors, .at_ns = mon.monoNs(std.testing.io) }) catch unreachable;
            if (p.fail) return st.finish(.unavailable, "down");
            for (refs) |r| for (p.refs, p.blocks) |have, bytes| if (have.eql(r)) out.append(arena, bytes) catch unreachable;
        }
        const msg = proto.encode(proto.FetchBlocksResponse, arena, &.{ .blocks = out.items }) catch return st.finish(.internal, "");
        st.send(msg) catch return;
        st.finish(.ok, "");
    }

    fn count(p: *SyncTestPeer) usize {
        p.mu.lock();
        defer p.mu.unlock();
        return p.reqs.items.len;
    }

    fn deinit(p: *SyncTestPeer) void {
        for (p.reqs.items) |r| {
            p.gpa.free(r.refs);
            p.gpa.free(r.after);
        }
        p.reqs.deinit(p.gpa);
    }
};

fn acceptAll(_: *anyopaque, arena: Allocator, serialized: []const u8, out: *types.VerifiedBlock, _: []types.TransactionIndex, reject_count: *usize) consensus.errors.Error!consensus.errors.BlockVerdict {
    out.* = shared_mod.decodeTrusted(arena, serialized) catch return error.SerializationFailure;
    reject_count.* = 0;
    return .ok;
}

test "synchronizer over loopback: live retries and periodic fan-out as synchronizer.rs" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const grpc = @import("grpc.zig");
    const tls = @import("tls.zig");
    const testkit = @import("testkit.zig");
    const tc = try testkit.TestCommittee.init(gpa, io, 4, 11, 0, 3);
    defer tc.deinit();
    var rc: testkit.RealClock = .{ .io = io };
    const ctx = testkit.makeContext(tc, 0, rc.clock());

    // Rounds 1..3 of authors 1..3.
    var bytes: std.ArrayList([]const u8) = .empty;
    var refs: std.ArrayList(types.BlockRef) = .empty;
    defer {
        for (bytes.items) |b| gpa.free(b);
        bytes.deinit(gpa);
        refs.deinit(gpa);
    }
    for (1..4) |r| for (1..4) |a| {
        const b = try testkit.buildBlock(gpa, .{ .epoch = 3, .round = @intCast(r), .author = @intCast(a) });
        try bytes.append(gpa, b.bytes);
        try refs.append(gpa, b.ref);
    };
    const refOf = struct {
        fn f(all: []const types.BlockRef, round: u32, author: u32) types.BlockRef {
            for (all) |r| if (r.round == round and r.author == author) return r;
            unreachable;
        }
    }.f;

    // Servers for authorities 1..3 on their committee ports; 2 is down.
    var name_buf: [40]u8 = undefined;
    const name = try tls.serverName(&name_buf, 3);
    const Keys = struct {
        keys: [4][32]u8,
        fn lookup(c: *anyopaque, key: *const [32]u8) ?u32 {
            const self: *@This() = @ptrCast(@alignCast(c));
            for (self.keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
            return null;
        }
    };
    var keys: Keys = .{ .keys = undefined };
    for (0..4) |i| keys.keys[i] = tc.authorities[i].network_key;
    var ids: [4]tls.Identity = undefined;
    var tps: [4]SyncTestPeer = undefined;
    var srvs: [4]?*grpc.Server = @splat(null);
    defer for (1..4) |i| {
        if (srvs[i]) |sv| sv.stop();
        tps[i].deinit();
    };
    for (1..4) |i| {
        ids[i] = try tls.Identity.init(&tc.network_seeds[i], name);
        tps[i] = .{ .gpa = gpa, .mu = mon.Monitor.init(io), .blocks = bytes.items, .refs = refs.items, .fail = i == 2 };
        srvs[i] = try grpc.Server.start(gpa, io, .{ .listen_port = tc.ports[i], .server_name = name, .identity = &ids[i], .check = .{ .ctx = &keys, .lookup = Keys.lookup }, .handler = .{ .ctx = &tps[i], .serve = SyncTestPeer.serve } });
    }

    const peers = try peers_mod.Peers.init(gpa, io, &ctx, &tc.network_seeds[0], .{});
    defer peers.deinit();
    const s = try Shared.init(gpa, io, &ctx, peers, undefined);
    defer s.deinit();
    var hook_ctx: u8 = 0;
    s.verifier_hook = .{ .ctx = &hook_ctx, .verify = acceptAll };
    s.published.publish(&.{ 0, 2, 0, 0 }, 0, 0);
    s.published.gc_round.store(1, .release);
    const want_after = [_]u32{ 1, 2, 1, 1 };

    const sy = try Synchronizer.start(s);
    defer {
        s.stopping.store(true, .release);
        sy.stop();
    }
    var got: std.AutoHashMapUnmanaged(types.BlockRef, void) = .empty;
    defer got.deinit(gpa);
    const drain = struct {
        fn f(sh: *Shared, g: *std.AutoHashMapUnmanaged(types.BlockRef, void), a: Allocator, wait_ns: u64) !void {
            while (sh.core_q.pop(wait_ns)) |ev| {
                defer Shared.freeEvent(ev);
                if (ev == .blocks) for (ev.blocks.blocks) |b| try g.put(a, b.reference(), {});
            }
        }
    }.f;

    // Live sync from a healthy sender: one request with missing ancestors and fetch_after_rounds.
    sy.fetchMissing(&.{refOf(refs.items, 3, 1)}, 1);
    // Live sync from a sender that is down: 3 attempts, each after the 2 s request timeout.
    sy.fetchMissing(&.{refOf(refs.items, 3, 2)}, 2);
    try drain(s, &got, gpa, 7 * std.time.ns_per_s);
    try std.testing.expect(got.contains(refOf(refs.items, 3, 1)));
    try std.testing.expectEqual(@as(usize, 1), tps[1].count());
    try std.testing.expect(tps[1].reqs.items[0].missing);
    try std.testing.expectEqualSlices(u32, &want_after, tps[1].reqs.items[0].after);
    try std.testing.expectEqual(@as(usize, 3), tps[2].count());
    for (tps[2].reqs.items[1..], tps[2].reqs.items[0..2]) |b, a| try std.testing.expect(b.at_ns - a.at_ns >= 1900 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), sy.inflight.map.count());

    // Periodic: blocks of authors 1 and 3 (rounds 2 and 3); two author groups go to two random
    // peers, a failed one moves to the remaining peer.
    for (1..4) |i| tps[i].deinit();
    for (1..4) |i| tps[i].reqs = .empty;
    got.clearRetainingCapacity();
    var missing = [_]types.BlockRef{ refOf(refs.items, 3, 3), refOf(refs.items, 2, 1), refOf(refs.items, 3, 1), refOf(refs.items, 2, 3) };
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const order = [_]types.AuthorityIndex{ 2, 1, 3 }; // the down peer first
    var prng = std.Random.DefaultPrng.init(5);
    try sy.fetchFromPeers(arena_state.allocator(), &missing, &want_after, &order, prng.random());
    try drain(s, &got, gpa, 200 * std.time.ns_per_ms);
    for (missing) |r| try std.testing.expect(got.contains(r));
    try std.testing.expectEqual(@as(usize, 1), tps[2].count());
    // One request per peer, each for one author's blocks, lowest round first, no ancestors.
    for ([_]usize{ 1, 2, 3 }) |i| {
        for (tps[i].reqs.items) |rq| {
            try std.testing.expect(!rq.missing);
            try std.testing.expectEqualSlices(u32, &want_after, rq.after);
            try std.testing.expectEqual(@as(usize, 2), rq.refs.len);
            try std.testing.expectEqual(rq.refs[0].author, rq.refs[1].author);
            try std.testing.expect(rq.refs[0].round < rq.refs[1].round);
        }
    }
    try std.testing.expectEqual(@as(usize, 3), tps[1].count() + tps[2].count() + tps[3].count());
    try std.testing.expectEqual(@as(u32, 0), sy.inflight.map.count());
}

/// Votes to reject transaction 7 of every block.
fn rejectSeven(_: *anyopaque, arena: Allocator, serialized: []const u8, out: *types.VerifiedBlock, reject_votes: []types.TransactionIndex, reject_count: *usize) consensus.errors.Error!consensus.errors.BlockVerdict {
    out.* = shared_mod.decodeTrusted(arena, serialized) catch return error.SerializationFailure;
    reject_votes[0] = 7;
    reject_count.* = 1;
    return .ok;
}

test "commit sync keeps our reject votes on the certifying blocks (commit_syncer.rs verify_and_vote)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const grpc = @import("grpc.zig");
    const tls = @import("tls.zig");
    const testkit = @import("testkit.zig");
    const tc = try testkit.TestCommittee.init(gpa, io, 4, 12, 0, 3);
    defer tc.deinit();
    var rc: testkit.RealClock = .{ .io = io };
    const ctx = testkit.makeContext(tc, 0, rc.clock());

    // Commit 1 = the round-1 block of author 1; round-2 blocks of authors 1..3 vote for it.
    const leader = try testkit.buildBlock(gpa, .{ .epoch = 3, .round = 1, .author = 1 });
    defer gpa.free(leader.bytes);
    const c1 = try testkit.buildCommit(gpa, 1, @splat(0), leader.ref, &.{leader.ref});
    defer gpa.free(c1.bytes);
    var certs: [3][]const u8 = undefined;
    for (0..3) |i| certs[i] = (try testkit.buildBlock(gpa, .{ .epoch = 3, .round = 2, .author = @intCast(i + 1), .ancestors = &.{leader.ref}, .commit_votes = &.{.{ .index = 1, .digest = c1.digest }} })).bytes;
    defer for (certs) |c| gpa.free(c);

    var name_buf: [40]u8 = undefined;
    const name = try tls.serverName(&name_buf, 3);
    const Keys = struct {
        keys: [4][32]u8,
        fn lookup(c: *anyopaque, key: *const [32]u8) ?u32 {
            const self: *@This() = @ptrCast(@alignCast(c));
            for (self.keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
            return null;
        }
    };
    var keys: Keys = .{ .keys = undefined };
    for (0..4) |i| keys.keys[i] = tc.authorities[i].network_key;
    const id1 = try tls.Identity.init(&tc.network_seeds[1], name);
    var tp: SyncTestPeer = .{ .gpa = gpa, .mu = mon.Monitor.init(io), .blocks = &.{leader.bytes}, .refs = &.{leader.ref}, .commits = &.{c1.bytes}, .certifiers = &certs };
    defer tp.deinit();
    const srv = try grpc.Server.start(gpa, io, .{ .listen_port = tc.ports[1], .server_name = name, .identity = &id1, .check = .{ .ctx = &keys, .lookup = Keys.lookup }, .handler = .{ .ctx = &tp, .serve = SyncTestPeer.serve } });
    defer srv.stop();

    const peers = try peers_mod.Peers.init(gpa, io, &ctx, &tc.network_seeds[0], .{});
    defer peers.deinit();
    const s = try Shared.init(gpa, io, &ctx, peers, undefined);
    defer s.deinit();
    var hook_ctx: u8 = 0;
    s.verifier_hook = .{ .ctx = &hook_ctx, .verify = rejectSeven };

    const r = try CommitSyncer.fetchOnce(s, 1, .{ .start = 1, .end = 1 }, 5 * std.time.ns_per_s);
    defer r.batch.destroy();
    try std.testing.expectEqual(@as(u32, 1), r.last);
    // Certifying blocks first, each with its reject votes; then the commit's block.
    try std.testing.expectEqual(@as(usize, 4), r.batch.blocks.len);
    try std.testing.expectEqual(@as(usize, 3), r.batch.certifier_rejects.len);
    for (r.batch.certifier_rejects) |rej| try std.testing.expectEqualSlices(types.TransactionIndex, &.{7}, rej);
    try std.testing.expect(r.batch.blocks[3].reference().eql(leader.ref));
}
