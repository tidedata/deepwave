//! consensus_core::authority_service::AuthorityService and `block_sync_service.rs` at
//! mainnet-v1.83.1: the server side of ConsensusService. Owner lane: val-consensus-net. Each
//! handler gets the caller's AuthorityIndex from the TLS session (never from the message).
//!
//! - SubscribeBlocks: streams our own proposed blocks after `last_received_round` (all cached
//!   ones, or the last proposed block when none), then live ones from the broadcast ring, one per
//!   `min_round_delay / 2` (tonic `throttle`).
//! - FetchBlocks: the three request shapes of `block_sync_service::fetch_blocks` (live sync,
//!   periodic sync, commit sync) with Rust's validation and limits.
//! - FetchCommits: commits in range (at most commit_sync_batch_size) and the blocks certifying
//!   the last commit that reached a quorum of votes.
//! - FetchLatestBlocks: the latest block per asked authority (own-block recovery for peers).
//! - GetLatestRounds: highest received and accepted round per authority.
//! - SendBlock (tests only in Rust): a pushed block goes to the ingress like a stream block.
//!
//! The handlers read the consensus store (which the core thread keeps flushed after every step)
//! and a published snapshot of rounds; they never touch DagState, which only the core thread owns.
const std = @import("std");
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const Store = consensus.store.Store;
const grpc = @import("grpc.zig");
const proto = @import("proto.zig");
const bc = @import("broadcast.zig");
const mon = @import("mon.zig");
const rounds_mod = @import("rounds.zig");

pub const Error = error{ InvalidArgument, Shutdown, Unavailable, OutOfMemory, StoreFailure, RequestMissing, RequestMalformed };

/// Where blocks pushed by peers go (the verify tiles).
pub const Ingress = struct {
    ctx: *anyopaque,
    /// Takes a copy of `serialized`; false when the queue is full (the block is dropped).
    submit: *const fn (ctx: *anyopaque, peer: types.AuthorityIndex, serialized: []const u8, excluded: []const types.BlockRef) bool,
};

/// Round snapshot the core thread publishes after each step; handlers read it lock-free.
pub const Published = struct {
    gpa: Allocator,
    accepted: []std.atomic.Value(u32),
    last_proposed: std.atomic.Value(u32) = .init(0),
    commit_index: std.atomic.Value(u32) = .init(0),
    /// DagState's GC round (published by the core thread when the driver reports it).
    gc_round: std.atomic.Value(u32) = .init(0),

    pub fn init(gpa: Allocator, n: usize) Allocator.Error!Published {
        const a = try gpa.alloc(std.atomic.Value(u32), n);
        for (a) |*x| x.* = .init(0);
        return .{ .gpa = gpa, .accepted = a };
    }
    pub fn deinit(p: *Published) void {
        p.gpa.free(p.accepted);
    }
    pub fn publish(p: *Published, accepted: []const types.Round, last_proposed: types.Round, commit_index: types.CommitIndex) void {
        for (accepted, 0..) |r, i| if (i < p.accepted.len) p.accepted[i].store(r, .release);
        p.last_proposed.store(last_proposed, .release);
        p.commit_index.store(commit_index, .release);
    }
};

/// Counters for health and the localnet report.
pub const Stats = struct {
    blocks_streamed: std.atomic.Value(u64) = .init(0),
    blocks_received: std.atomic.Value(u64) = .init(0),
    blocks_invalid: std.atomic.Value(u64) = .init(0),
    /// Blocks stamped further ahead than max_forward_time_drift (Rust only records a metric).
    forward_drift_blocks: std.atomic.Value(u64) = .init(0),
    /// Streamed / SendBlock blocks dropped because we lag the quorum's commits (BlockRejected).
    blocks_rejected_lagging: std.atomic.Value(u64) = .init(0),
    blocks_dropped_full: std.atomic.Value(u64) = .init(0),
    fetch_blocks_served: std.atomic.Value(u64) = .init(0),
    fetch_commits_served: std.atomic.Value(u64) = .init(0),
    subscriptions: std.atomic.Value(u32) = .init(0),
    commit_batches_synced: std.atomic.Value(u64) = .init(0),
    blocks_fetched: std.atomic.Value(u64) = .init(0),
};

pub const Handlers = struct {
    gpa: Allocator,
    context: *const consensus.Context,
    store: Store,
    broadcaster: *bc.Broadcaster,
    rounds: *rounds_mod.RoundTracker,
    published: *Published,
    ingress: Ingress,
    stats: *Stats,
    prng: std.Random.DefaultPrng,
    prng_mu: mon.Monitor,
    stopping: *const std.atomic.Value(bool),
    /// Reads blocks deep-copied into the caller's arena under the store lock (and from disk once
    /// evicted). Without it, blocks read through `store` are copied after the read.
    read_copy: ?ReadCopy = null,

    pub const ReadCopy = struct {
        ctx: *anyopaque,
        read: *const fn (ctx: *anyopaque, arena: Allocator, refs: []const types.BlockRef, out: []?types.VerifiedBlock) consensus.errors.Error!void,
    };

    pub fn init(gpa: Allocator, io: std.Io, context: *const consensus.Context, store: Store, broadcaster: *bc.Broadcaster, rounds: *rounds_mod.RoundTracker, published: *Published, ingress: Ingress, stats: *Stats, stopping: *const std.atomic.Value(bool)) Handlers {
        var seed: [8]u8 = undefined;
        io.random(&seed);
        return .{
            .gpa = gpa,
            .context = context,
            .store = store,
            .broadcaster = broadcaster,
            .rounds = rounds,
            .published = published,
            .ingress = ingress,
            .stats = stats,
            .prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little)),
            .prng_mu = mon.Monitor.init(io),
            .stopping = stopping,
        };
    }

    pub fn grpcHandler(h: *Handlers) grpc.Handler {
        return .{ .ctx = h, .serve = serveStream };
    }

    fn random(h: *Handlers, bound: usize) usize {
        h.prng_mu.lock();
        defer h.prng_mu.unlock();
        return h.prng.random().uintLessThan(usize, bound);
    }

    // ------------------------------------------------------------ store reads

    fn readBlocks(h: *Handlers, arena: Allocator, refs: []const types.BlockRef) Error![]types.VerifiedBlock {
        const out = try arena.alloc(?types.VerifiedBlock, refs.len);
        if (h.read_copy) |rc| {
            rc.read(rc.ctx, arena, refs, out) catch return error.StoreFailure;
        } else {
            h.store.vtable.read_blocks(h.store.ctx, refs, out) catch return error.StoreFailure;
            for (out) |*o| if (o.*) |*b| {
                o.* = consensus.digest.cloneVerified(arena, b) catch return error.StoreFailure;
            };
        }
        var n: usize = 0;
        const res = try arena.alloc(types.VerifiedBlock, refs.len);
        for (out) |o| if (o) |b| {
            res[n] = b;
            n += 1;
        };
        return res[0..n];
    }

    // ------------------------------------------------------------ handlers

    /// `block_sync_service::fetch_blocks`. Returns the serialized blocks in request order, then
    /// ancestors / additional blocks.
    pub fn fetchBlocks(h: *Handlers, arena: Allocator, req_refs: []const types.BlockRef, fetch_after_rounds: []const types.Round, fetch_missing_ancestors: bool) Error![]const []const u8 {
        const ctx = h.context;
        if (req_refs.len == 0 and (fetch_missing_ancestors or fetch_after_rounds.len == 0)) return error.InvalidArgument;
        if (fetch_missing_ancestors and fetch_after_rounds.len == 0) return error.InvalidArgument;
        if (fetch_after_rounds.len != 0 and fetch_after_rounds.len != ctx.committee.size()) return error.InvalidArgument;
        const max_blocks: usize = if (fetch_after_rounds.len != 0 and req_refs.len != 0) ctx.parameters.max_blocks_per_sync else ctx.parameters.max_blocks_per_fetch;
        const refs = if (req_refs.len > max_blocks) req_refs[0..max_blocks] else req_refs;
        for (refs) |r| {
            if (!ctx.committee.isValidIndex(r.author)) return error.InvalidArgument;
            if (r.round == types.GENESIS_ROUND) return error.InvalidArgument;
        }
        var blocks: std.ArrayList(types.VerifiedBlock) = .empty;
        try blocks.appendSlice(arena, try h.readBlocks(arena, refs));

        if (blocks.items.len < max_blocks and fetch_after_rounds.len != 0) {
            if (fetch_missing_ancestors) {
                // Unique missing ancestors of the requested blocks, a random subset when too many.
                var missing: std.ArrayList(types.BlockRef) = .empty;
                for (blocks.items) |b| for (b.block.inner.ancestors()) |a| {
                    if (a.author < fetch_after_rounds.len and fetch_after_rounds[a.author] < a.round) try missing.append(arena, a);
                };
                std.mem.sort(types.BlockRef, missing.items, {}, struct {
                    fn lt(_: void, a: types.BlockRef, b: types.BlockRef) bool {
                        return a.order(b) == .lt;
                    }
                }.lt);
                var uniq: usize = 0;
                for (missing.items) |m| {
                    if (uniq == 0 or !missing.items[uniq - 1].eql(m)) {
                        missing.items[uniq] = m;
                        uniq += 1;
                    }
                }
                const want = @min(max_blocks - blocks.items.len, uniq);
                // partial Fisher-Yates
                for (0..want) |i| {
                    const j = i + h.random(uniq - i);
                    std.mem.swap(types.BlockRef, &missing.items[i], &missing.items[j]);
                }
                if (want > 0) try blocks.appendSlice(arena, try h.readBlocks(arena, missing.items[0..want]));
            } else {
                // Additional blocks depth-first from the requested block authorities, across
                // authorities in ascending round order.
                const Lim = struct { start: types.Round, authority: types.AuthorityIndex, limit: types.Round };
                var heap: std.ArrayList(Lim) = .empty;
                var limits = std.AutoArrayHashMapUnmanaged(types.AuthorityIndex, types.Round).empty;
                if (refs.len == 0) {
                    for (0..ctx.committee.size()) |i| try limits.put(arena, @intCast(i), h.published.accepted[i].load(.acquire));
                } else {
                    for (refs) |r| {
                        const e = try limits.getOrPut(arena, r.author);
                        e.value_ptr.* = if (e.found_existing) @min(e.value_ptr.*, r.round) else r.round;
                    }
                }
                var it = limits.iterator();
                while (it.next()) |kv| {
                    const start = fetch_after_rounds[kv.key_ptr.*] +| 1;
                    if (start < kv.value_ptr.*) try heap.append(arena, .{ .start = start, .authority = kv.key_ptr.*, .limit = kv.value_ptr.* });
                }
                while (heap.items.len > 0 and blocks.items.len < max_blocks) {
                    var mi: usize = 0;
                    for (heap.items, 0..) |e, i| {
                        const m = heap.items[mi];
                        if (e.start < m.start or (e.start == m.start and e.authority < m.authority)) mi = i;
                    }
                    const e = heap.swapRemove(mi);
                    const got = h.store.vtable.scan_blocks_by_author(h.store.ctx, arena, e.authority, e.start, e.limit, 1) catch return error.StoreFailure;
                    if (got.len > 0) {
                        const b = got[0];
                        try blocks.append(arena, b);
                        const next_start = b.block.inner.round() + 1;
                        if (next_start < e.limit) try heap.append(arena, .{ .start = next_start, .authority = e.authority, .limit = e.limit });
                    }
                }
            }
        }
        const out = try arena.alloc([]const u8, blocks.items.len);
        for (blocks.items, 0..) |b, i| out[i] = b.serialized;
        _ = h.stats.fetch_blocks_served.fetchAdd(1, .monotonic);
        return out;
    }

    pub const CommitsResult = struct { commits: []const []const u8, certifier_blocks: []const []const u8 };

    /// `fetch_commits`: commits in `range` (inclusive end), capped at the batch size, with the
    /// blocks certifying the last commit that has a quorum of votes.
    pub fn fetchCommits(h: *Handlers, arena: Allocator, start: types.CommitIndex, end_inclusive: types.CommitIndex) Error!CommitsResult {
        const ctx = h.context;
        const cap = start +| ctx.parameters.commit_sync_batch_size -| 1;
        const inclusive_end = @min(end_inclusive, cap);
        if (inclusive_end < start) return .{ .commits = &.{}, .certifier_blocks = &.{} };
        var commits = std.ArrayList(types.TrustedCommit).fromOwnedSlice(h.store.vtable.scan_commits(h.store.ctx, arena, types.CommitRange.inclusive(start, inclusive_end)) catch return error.StoreFailure);
        var certifier_refs: []const types.BlockRef = &.{};
        while (commits.items.len > 0) {
            const last = commits.items[commits.items.len - 1];
            const votes = h.store.vtable.read_commit_votes(h.store.ctx, arena, last.commit.index()) catch return error.StoreFailure;
            var agg: consensus.committee.StakeAggregator(consensus.committee.max_committee_size) = .{};
            for (votes) |v| _ = agg.add(v.author, &ctx.committee, ctx.committee.quorum_threshold);
            if (ctx.committee.reachedQuorum(agg.stake)) {
                certifier_refs = votes;
                break;
            }
            _ = commits.pop();
        }
        const blocks = try h.readBlocks(arena, certifier_refs);
        const cs = try arena.alloc([]const u8, commits.items.len);
        for (commits.items, 0..) |c, i| cs[i] = c.serialized;
        const bs = try arena.alloc([]const u8, blocks.len);
        for (blocks, 0..) |b, i| bs[i] = b.serialized;
        _ = h.stats.fetch_commits_served.fetchAdd(1, .monotonic);
        return .{ .commits = cs, .certifier_blocks = bs };
    }

    /// `fetch_latest_blocks`: the latest block of each asked authority, genesis omitted.
    pub fn fetchLatestBlocks(h: *Handlers, arena: Allocator, authorities: []const u32) Error![]const []const u8 {
        const ctx = h.context;
        if (authorities.len > ctx.committee.size()) return error.InvalidArgument;
        for (authorities) |a| if (!ctx.committee.isValidIndex(a)) return error.InvalidArgument;
        var out: std.ArrayList([]const u8) = .empty;
        for (authorities) |a| {
            const last = h.store.vtable.scan_last_blocks_by_author(h.store.ctx, arena, a, 1, null) catch return error.StoreFailure;
            if (last.len > 0 and last[last.len - 1].block.inner.round() != types.GENESIS_ROUND) try out.append(arena, last[last.len - 1].serialized);
        }
        return out.items;
    }

    // ------------------------------------------------------------ gRPC dispatch

    fn decodeRefs(arena: Allocator, raw: []const []const u8) Error![]types.BlockRef {
        var out: std.ArrayList(types.BlockRef) = .empty;
        // Rust skips refs that do not decode.
        for (raw) |r| if (bc.decodeRef(r)) |ref| try out.append(arena, ref);
        return out.items;
    }

    fn sendChunks(st: *grpc.Stream, arena: Allocator, comptime T: type, blocks: []const []const u8) Error!void {
        var ends: [4096]usize = undefined;
        const n = proto.chunkBlocks(blocks, proto.max_fetch_response_bytes, &ends) orelse return error.InvalidArgument;
        var start: usize = 0;
        for (ends[0..n]) |end| {
            const msg = try proto.encode(T, arena, &.{ .blocks = blocks[start..end] });
            st.send(msg) catch return error.Unavailable;
            start = end;
        }
    }

    /// The gRPC status Rust answers with (tonic_network.rs `TonicServiceProxy` at 1.83.1):
    /// - a request that does not decode is INTERNAL (tonic-prost `from_decode_error`), and so is
    ///   a unary or server-streaming call without its message (tonic "Missing request message.");
    ///   SubscribeBlocks answers both itself with INVALID_ARGUMENT ("Missing request",
    ///   "Request error");
    /// - handler (AuthorityService / BlockSyncService) errors are INVALID_ARGUMENT for SendBlock
    ///   and INTERNAL for every other method, including FetchLatestBlocks' invalid authority index;
    /// - a service that is shutting down is UNAVAILABLE.
    pub fn statusOf(m: proto.Method, e: Error) grpc.Status {
        return switch (e) {
            error.Shutdown, error.Unavailable => .unavailable,
            error.RequestMissing, error.RequestMalformed => if (m == .SubscribeBlocks) .invalid_argument else .internal,
            else => if (m == .SendBlock) .invalid_argument else .internal,
        };
    }

    fn serveStream(ctx: *anyopaque, st: *grpc.Stream) void {
        const h: *Handlers = @ptrCast(@alignCast(ctx));
        var arena_state = std.heap.ArenaAllocator.init(h.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const m = st.method() orelse return st.finish(.unimplemented, "unknown method");
        const peer = st.peer();
        h.dispatch(arena, st, m, peer) catch |e| return st.finish(statusOf(m, e), @errorName(e));
        st.finish(.ok, "");
    }

    fn dispatch(h: *Handlers, arena: Allocator, st: *grpc.Stream, m: proto.Method, peer: types.AuthorityIndex) Error!void {
        const req_bytes = (st.recv(arena, 10 * std.time.ns_per_s) catch return error.RequestMissing) orelse return error.RequestMissing;
        switch (m) {
            .SendBlock => {
                const req = proto.decode(proto.SendBlockRequest, arena, req_bytes) catch return error.RequestMalformed;
                if (!h.ingress.submit(h.ingress.ctx, peer, req.block, &.{})) _ = h.stats.blocks_dropped_full.fetchAdd(1, .monotonic);
                st.send("") catch return error.Unavailable;
            },
            .SubscribeBlocks => {
                const req = proto.decode(proto.SubscribeBlocksRequest, arena, req_bytes) catch return error.RequestMalformed;
                try h.subscribe(st, peer, req.last_received_round);
            },
            .FetchBlocks => {
                const req = proto.decode(proto.FetchBlocksRequest, arena, req_bytes) catch return error.RequestMalformed;
                const refs = try decodeRefs(arena, req.block_refs);
                const blocks = try h.fetchBlocks(arena, refs, req.fetch_after_rounds, req.fetch_missing_ancestors);
                try sendChunks(st, arena, proto.FetchBlocksResponse, blocks);
            },
            .FetchCommits => {
                const req = proto.decode(proto.FetchCommitsRequest, arena, req_bytes) catch return error.RequestMalformed;
                const r = try h.fetchCommits(arena, req.start, req.end);
                const msg = try proto.encode(proto.FetchCommitsResponse, arena, &.{ .commits = r.commits, .certifier_blocks = r.certifier_blocks });
                st.send(msg) catch return error.Unavailable;
            },
            .FetchLatestBlocks => {
                const req = proto.decode(proto.FetchLatestBlocksRequest, arena, req_bytes) catch return error.RequestMalformed;
                const blocks = try h.fetchLatestBlocks(arena, req.authorities);
                try sendChunks(st, arena, proto.FetchLatestBlocksResponse, blocks);
            },
            .GetLatestRounds => {
                const n = h.context.committee.size();
                const received = try arena.alloc(u32, n);
                h.rounds.localHighestReceived(received);
                const accepted = try arena.alloc(u32, n);
                for (accepted, 0..) |*a, i| a.* = h.published.accepted[i].load(.acquire);
                const msg = try proto.encode(proto.GetLatestRoundsResponse, arena, &.{ .highest_received = received, .highest_accepted = accepted });
                st.send(msg) catch return error.Unavailable;
            },
        }
    }

    fn sendBlock(h: *Handlers, st: *grpc.Stream, arena: Allocator, block: []const u8, excluded: []const types.BlockRef) Error!void {
        const ex = try arena.alloc([]const u8, excluded.len);
        for (excluded, 0..) |r, i| {
            const e = bc.encodeRef(r);
            ex[i] = try arena.dupe(u8, &e);
        }
        const msg = try proto.encode(proto.SubscribeBlocksResponse, arena, &.{ .block = block, .excluded_ancestors = ex });
        st.send(msg) catch return error.Unavailable;
        _ = h.stats.blocks_streamed.fetchAdd(1, .monotonic);
    }

    /// `handle_subscribe_blocks`: subscribe first (cursor at the tail), then replay past own
    /// blocks, then follow the ring. Duplicates between replay and ring are fine.
    fn subscribe(h: *Handlers, st: *grpc.Stream, peer: types.AuthorityIndex, last_received: types.Round) Error!void {
        _ = peer;
        const ctx = h.context;
        const own = ctx.own_index orelse return error.Unavailable;
        _ = h.stats.subscriptions.fetchAdd(1, .monotonic);
        defer _ = h.stats.subscriptions.fetchSub(1, .monotonic);
        var cursor = h.broadcaster.tail();
        var arena_state = std.heap.ArenaAllocator.init(h.gpa);
        defer arena_state.deinit();
        const throttle_ns = ctx.parameters.min_round_delay_ns / 2;
        {
            const arena = arena_state.allocator();
            // Rust serves `get_cached_blocks(own, last_received + 1)`: only the DagState's cache
            // window of our most recent rounds, never older blocks the peer may have missed. The
            // cache holds rounds above `DagState::eviction_round` = min(gc_round, last_round -
            // cached_rounds), so a stalled GC keeps (and replays) more than cached_rounds.
            const window_floor = cacheWindowFloor(h.published.last_proposed.load(.acquire), h.published.gc_round.load(.acquire), ctx.parameters.dag_state_cached_rounds);
            const start = @max(last_received +| 1, window_floor);
            var past = h.store.vtable.scan_blocks_by_author(h.store.ctx, arena, own, start, std.math.maxInt(types.Round), std.math.maxInt(usize)) catch return error.StoreFailure;
            if (past.len == 0) {
                const last = h.store.vtable.scan_last_blocks_by_author(h.store.ctx, arena, own, 1, null) catch return error.StoreFailure;
                if (last.len > 0 and last[last.len - 1].block.inner.round() > types.GENESIS_ROUND) past = last[last.len - 1 ..];
            }
            for (past) |b| {
                try h.sendBlock(st, arena, b.serialized, &.{});
                sleepNs(throttle_ns);
            }
        }
        _ = arena_state.reset(.retain_capacity);
        while (!h.stopping.load(.acquire) and !st.closed()) {
            const arena = arena_state.allocator();
            const item = h.broadcaster.next(arena, &cursor, 200 * std.time.ns_per_ms) catch return error.OutOfMemory;
            if (item) |it| {
                try h.sendBlock(st, arena, it.block, it.excluded);
                sleepNs(throttle_ns);
            }
            _ = arena_state.reset(.retain_capacity);
        }
    }
};

/// Lowest round DagState still caches for an authority whose last block is `last_round`:
/// `eviction_round(last_round, gc_round, cached_rounds) + 1` (dag_state.rs).
pub fn cacheWindowFloor(last_round: types.Round, gc_round: types.Round, cached_rounds: u32) types.Round {
    return @min(gc_round, last_round -| cached_rounds) + 1;
}

fn sleepNs(ns: u64) void {
    if (ns == 0) return;
    const sock = @import("serve").h2.sock;
    sock.sleepMs(@max(1, ns / std.time.ns_per_ms));
}

// ---------------------------------------------------------------- tests

const testkit = @import("testkit.zig");
const tls = @import("tls.zig");

const Sink = struct {
    count: std.atomic.Value(u32) = .init(0),
    fn submit(ctx: *anyopaque, peer: types.AuthorityIndex, serialized: []const u8, excluded: []const types.BlockRef) bool {
        _ = .{ peer, serialized, excluded };
        const s: *Sink = @ptrCast(@alignCast(ctx));
        _ = s.count.fetchAdd(1, .monotonic);
        return true;
    }
};

test "service over loopback gRPC: fetch blocks (all shapes), commits, latest, rounds, subscribe" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const tc = try testkit.TestCommittee.init(gpa, io, 4, 7, 0, 5);
    defer tc.deinit();
    var rc: testkit.RealClock = .{ .io = io };
    var ctx = testkit.makeContext(tc, 0, rc.clock());
    ctx.parameters.min_round_delay_ns = 2 * std.time.ns_per_ms;

    // 3 rounds of 4 authorities, each block pointing at the previous round's blocks.
    var fs = testkit.FakeStore.init(gpa, io);
    defer fs.deinit();
    var refs: [4][4]types.BlockRef = undefined; // [round][author], round 0 = genesis stand-ins
    for (0..4) |a| refs[0][a] = .{ .round = 0, .author = @intCast(a), .digest = @splat(0) };
    var keep: std.ArrayList([]u8) = .empty;
    defer {
        for (keep.items) |k| gpa.free(k);
        keep.deinit(gpa);
    }
    for (1..4) |r| for (0..4) |a| {
        const b = try testkit.buildBlock(gpa, .{ .round = @intCast(r), .author = @intCast(a), .ancestors = &refs[r - 1] });
        try keep.append(gpa, b.bytes);
        try fs.addBlock(b.bytes, b.ref);
        refs[r][a] = b.ref;
    };
    // commits 1 and 2: commit 1 certified by votes of 3 authorities' round-3 blocks, commit 2 by 2
    const c1 = try testkit.buildCommit(gpa, 1, @splat(0), refs[1][0], &.{refs[1][0]});
    const c2 = try testkit.buildCommit(gpa, 2, c1.digest, refs[2][0], &.{refs[2][0]});
    defer gpa.free(c1.bytes);
    defer gpa.free(c2.bytes);
    try fs.addCommit(1, c1.digest, c1.bytes, &.{ refs[3][0], refs[3][1], refs[3][2] });
    try fs.addCommit(2, c2.digest, c2.bytes, &.{ refs[3][0], refs[3][1] });

    var bcast = try bc.Broadcaster.init(gpa, io, 16);
    defer bcast.deinit();
    var rt = try rounds_mod.RoundTracker.init(gpa, io, &ctx.committee, 0);
    defer rt.deinit();
    var published = try Published.init(gpa, 4);
    defer published.deinit();
    published.publish(&.{ 3, 3, 3, 3 }, 3, 2);
    var sink: Sink = .{};
    var stats: Stats = .{};
    var stopping: std.atomic.Value(bool) = .init(false);
    var h = Handlers.init(gpa, io, &ctx, fs.store(), &bcast, &rt, &published, .{ .ctx = &sink, .submit = Sink.submit }, &stats, &stopping);

    var name_buf: [40]u8 = undefined;
    const name = try tls.serverName(&name_buf, 5);
    const id0 = try tls.Identity.init(&tc.network_seeds[0], name);
    const id1 = try tls.Identity.init(&tc.network_seeds[1], name);
    const Peers = struct {
        keys: [4][32]u8,
        fn lookup(c: *anyopaque, key: *const [32]u8) ?u32 {
            const self: *@This() = @ptrCast(@alignCast(c));
            for (self.keys, 0..) |k, i| if (std.mem.eql(u8, &k, key)) return @intCast(i);
            return null;
        }
    };
    var peers: Peers = .{ .keys = undefined };
    for (0..4) |i| peers.keys[i] = tc.authorities[i].network_key;
    const srv = try grpc.Server.start(gpa, io, .{ .server_name = name, .identity = &id0, .check = .{ .ctx = &peers, .lookup = Peers.lookup }, .handler = h.grpcHandler() });
    defer {
        stopping.store(true, .release);
        srv.stop();
    }
    const pub0 = id0.publicKey();
    const ch = try grpc.Channel.create(gpa, io, .{}, .{ .host = "127.0.0.1", .port = srv.port }, name, &id1, &pub0);
    defer ch.destroy();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const T = 5 * std.time.ns_per_s;

    // GetLatestRounds
    {
        const resp = try ch.unary(arena, .GetLatestRounds, "", T);
        const r = try proto.decode(proto.GetLatestRoundsResponse, arena, resp);
        try std.testing.expectEqual(@as(usize, 4), r.highest_received.len);
        try std.testing.expectEqualSlices(u32, &.{ 3, 3, 3, 3 }, r.highest_accepted);
    }
    // FetchBlocks: commit-sync shape (refs only)
    {
        var rr: [3][]const u8 = undefined;
        var bufs: [3][40]u8 = undefined;
        for (0..3) |i| {
            bufs[i] = bc.encodeRef(refs[2][i]);
            rr[i] = &bufs[i];
        }
        const req = try proto.encode(proto.FetchBlocksRequest, arena, &.{ .block_refs = &rr, .fetch_after_rounds = &.{}, .fetch_missing_ancestors = false });
        const st = try ch.startCall(.FetchBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        var total: usize = 0;
        while (try st.recv(arena, 0)) |m| {
            const fb = try proto.decode(proto.FetchBlocksResponse, arena, m);
            total += fb.blocks.len;
        }
        try std.testing.expectEqual(@as(usize, 3), total);
    }
    // FetchBlocks: live sync with missing ancestors (round 3 block of author 0 asks for its round 2 ancestors)
    {
        const rb = bc.encodeRef(refs[3][0]);
        const req = try proto.encode(proto.FetchBlocksRequest, arena, &.{ .block_refs = &.{&rb}, .fetch_after_rounds = &.{ 1, 1, 1, 1 }, .fetch_missing_ancestors = true });
        const st = try ch.startCall(.FetchBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        var total: usize = 0;
        while (try st.recv(arena, 0)) |m| total += (try proto.decode(proto.FetchBlocksResponse, arena, m)).blocks.len;
        try std.testing.expectEqual(@as(usize, 1 + 4), total); // the block plus its four round 2 ancestors
    }
    // FetchBlocks: periodic shape (no refs, fetch_after_rounds): ascending blocks after the given rounds
    {
        const req = try proto.encode(proto.FetchBlocksRequest, arena, &.{ .block_refs = &.{}, .fetch_after_rounds = &.{ 0, 2, 3, 3 }, .fetch_missing_ancestors = false });
        const st = try ch.startCall(.FetchBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        var total: usize = 0;
        while (try st.recv(arena, 0)) |m| total += (try proto.decode(proto.FetchBlocksResponse, arena, m)).blocks.len;
        // Rust scans [fetch_after + 1, last accepted round) per authority: author 0 yields rounds 1 and 2.
        try std.testing.expectEqual(@as(usize, 2), total);
    }
    // invalid shape is refused
    {
        const req = try proto.encode(proto.FetchBlocksRequest, arena, &.{ .block_refs = &.{}, .fetch_after_rounds = &.{}, .fetch_missing_ancestors = false });
        const st = try ch.startCall(.FetchBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        try std.testing.expectError(error.Status, st.recv(arena, 0));
        try std.testing.expectEqual(grpc.Status.internal, st.grpcStatus()); // AuthorityService: INTERNAL
    }
    // FetchCommits: both commits are asked; commit 2 has only 2 votes so it is dropped
    {
        const req = try proto.encode(proto.FetchCommitsRequest, arena, &.{ .start = 1, .end = 2 });
        const resp = try ch.unary(arena, .FetchCommits, req, T);
        const r = try proto.decode(proto.FetchCommitsResponse, arena, resp);
        try std.testing.expectEqual(@as(usize, 1), r.commits.len);
        try std.testing.expectEqualSlices(u8, c1.bytes, r.commits[0]);
        try std.testing.expectEqual(@as(usize, 3), r.certifier_blocks.len);
    }
    // FetchLatestBlocks
    {
        const req = try proto.encode(proto.FetchLatestBlocksRequest, arena, &.{ .authorities = &.{ 0, 2 } });
        const st = try ch.startCall(.FetchLatestBlocks, T);
        defer st.release();
        try st.send(req);
        try st.closeSend();
        var total: usize = 0;
        while (try st.recv(arena, 0)) |m| total += (try proto.decode(proto.FetchLatestBlocksResponse, arena, m)).blocks.len;
        try std.testing.expectEqual(@as(usize, 2), total);
    }
    // SubscribeBlocks: replays our own blocks after round 1 (rounds 2 and 3), then a live one
    {
        const st = try ch.startCall(.SubscribeBlocks, 0);
        defer st.release();
        try st.send(try proto.encode(proto.SubscribeBlocksRequest, arena, &.{ .last_received_round = 1 }));
        for ([_]types.Round{ 2, 3 }) |round| {
            const m = (try st.recv(arena, T)).?;
            const sb = try proto.decode(proto.SubscribeBlocksResponse, arena, m);
            const vb = try testkit.decodeBlock(arena, sb.block);
            try std.testing.expectEqual(round, vb.block.inner.round());
            try std.testing.expectEqual(@as(types.AuthorityIndex, 0), vb.block.inner.author());
        }
        const live = try testkit.buildBlock(gpa, .{ .round = 4, .author = 0, .ancestors = &refs[3] });
        defer gpa.free(live.bytes);
        try bcast.append(live.bytes, &.{refs[3][3]});
        const m = (try st.recv(arena, T)).?;
        const sb = try proto.decode(proto.SubscribeBlocksResponse, arena, m);
        try std.testing.expectEqualSlices(u8, live.bytes, sb.block);
        try std.testing.expectEqual(@as(usize, 1), sb.excluded_ancestors.len);
        try std.testing.expect(bc.decodeRef(sb.excluded_ancestors[0]).?.eql(refs[3][3]));
        st.cancel();
    }
    // SendBlock goes to the ingress
    {
        const req = try proto.encode(proto.SendBlockRequest, arena, &.{ .block = "x" });
        _ = try ch.unary(arena, .SendBlock, req, T);
        try std.testing.expectEqual(@as(u32, 1), sink.count.load(.monotonic));
    }
}

test "gRPC status per method matches TonicServiceProxy" {
    // tonic-prost decode errors and missing unary messages: INTERNAL; SubscribeBlocks' own checks: INVALID_ARGUMENT.
    try std.testing.expectEqual(grpc.Status.internal, Handlers.statusOf(.FetchBlocks, error.RequestMalformed));
    try std.testing.expectEqual(grpc.Status.internal, Handlers.statusOf(.GetLatestRounds, error.RequestMissing));
    try std.testing.expectEqual(grpc.Status.invalid_argument, Handlers.statusOf(.SubscribeBlocks, error.RequestMissing));
    try std.testing.expectEqual(grpc.Status.invalid_argument, Handlers.statusOf(.SubscribeBlocks, error.RequestMalformed));
    // handler errors: INVALID_ARGUMENT for SendBlock, INTERNAL elsewhere.
    try std.testing.expectEqual(grpc.Status.invalid_argument, Handlers.statusOf(.SendBlock, error.InvalidArgument));
    inline for (.{ .FetchBlocks, .FetchCommits, .FetchLatestBlocks, .GetLatestRounds, .SubscribeBlocks }) |m| {
        try std.testing.expectEqual(grpc.Status.internal, Handlers.statusOf(m, error.InvalidArgument));
        try std.testing.expectEqual(grpc.Status.internal, Handlers.statusOf(m, error.StoreFailure));
        try std.testing.expectEqual(grpc.Status.unavailable, Handlers.statusOf(m, error.Shutdown));
    }
}

test "SubscribeBlocks replay floor is DagState's cache window" {
    // eviction_round = min(gc_round, last_round - cached_rounds); cached rounds are above it.
    try std.testing.expectEqual(@as(types.Round, 501), cacheWindowFloor(1000, 900, 500));
    try std.testing.expectEqual(@as(types.Round, 301), cacheWindowFloor(1000, 300, 500)); // stalled GC keeps more
    try std.testing.expectEqual(@as(types.Round, 1), cacheWindowFloor(10, 0, 500));
    try std.testing.expectEqual(@as(types.Round, 1), cacheWindowFloor(0, 0, 500));
}
