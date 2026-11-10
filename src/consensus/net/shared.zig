//! State shared by the threads of one ConsensusAuthority: the context, peers, round tracking,
//! the published round snapshot, the broadcast ring, the queue into the core thread, and the
//! block verification entry point every ingress path uses (subscriber streams, synchronizer
//! fetches, commit syncer, SendBlock). Owner lane: val-consensus-net.
//!
//! Verification runs on the calling thread (one subscriber thread per peer, fetch workers), so
//! signature checks parallelize across peers without a separate pool; the core thread only ever
//! sees verified blocks (docs/VALIDATOR-DESIGN.md 7).
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const hash = @import("hash");
const consensus = @import("consensus");
const types = consensus.types;
const mon = @import("mon.zig");
const peers_mod = @import("peers.zig");
const rounds_mod = @import("rounds.zig");
const service = @import("service.zig");
const bc = @import("broadcast.zig");
const log = std.log.scoped(.consensus_verify);

pub const Error = error{ InvalidBlock, Shutdown, OutOfMemory };

/// Upper bound for fixed-size per-authority scratch arrays (consensus.committee.max_committee_size).
pub const max_peers = consensus.committee.max_committee_size;

/// Verified blocks of one ingress call, owned by their arena. The core thread frees the batch
/// after processing it.
pub const BlockBatch = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    /// The peer the blocks came from (missing ancestors are fetched from it first).
    peer: types.AuthorityIndex,
    blocks: []types.VerifiedBlock = &.{},
    /// Our own fast-path reject votes per block (parallel to `blocks`).
    rejects: []const []const types.TransactionIndex = &.{},
    /// Ancestors the sender excluded from the (single) streamed block.
    excluded: []const types.BlockRef = &.{},

    pub fn create(gpa: Allocator, peer: types.AuthorityIndex) Allocator.Error!*BlockBatch {
        const b = try gpa.create(BlockBatch);
        b.* = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa), .peer = peer };
        return b;
    }
    pub fn destroy(b: *BlockBatch) void {
        const gpa = b.gpa;
        b.arena.deinit();
        gpa.destroy(b);
    }
};

/// Commits (chained, certified by a quorum) with their blocks and the certifying blocks.
pub const CommitBatch = struct {
    gpa: Allocator,
    arena: std.heap.ArenaAllocator,
    commits: []types.TrustedCommit = &.{},
    blocks: []types.VerifiedBlock = &.{},
    /// Our reject votes on the certifying blocks, which come first in `blocks`
    /// (commit_syncer.rs feeds them to the TransactionVoteTracker).
    certifier_rejects: []const []const types.TransactionIndex = &.{},

    pub fn create(gpa: Allocator) Allocator.Error!*CommitBatch {
        const b = try gpa.create(CommitBatch);
        b.* = .{ .gpa = gpa, .arena = std.heap.ArenaAllocator.init(gpa) };
        return b;
    }
    pub fn destroy(b: *CommitBatch) void {
        const gpa = b.gpa;
        b.arena.deinit();
        gpa.destroy(b);
    }
};

pub const CoreEvent = union(enum) {
    blocks: *BlockBatch,
    commits: *CommitBatch,
    /// The transaction source has new transactions.
    new_txs,
    propagation_delay: types.Round,
    /// Result of the own-block sync: highest own round known to a validity quorum of peers.
    last_known_round: types.Round,
    stop,
};

/// Replaces `SignedBlockVerifier` (tests drive the network without the consensus lane's verifier).
pub const VerifierHook = struct {
    ctx: *anyopaque,
    verify: *const fn (ctx: *anyopaque, arena: Allocator, serialized: []const u8, out: *types.VerifiedBlock, reject_votes: []types.TransactionIndex, reject_count: *usize) consensus.errors.Error!consensus.errors.BlockVerdict,
};

/// Receives the excluded ancestors a peer's block carried (already validated) so the owner can
/// ask the synchronizer for the ones it does not have, from that peer.
pub const ExcludedHook = struct {
    ctx: *anyopaque,
    check: *const fn (ctx: *anyopaque, refs: []const types.BlockRef, peer: types.AuthorityIndex) void,
};

pub const Shared = struct {
    verifier_hook: ?VerifierHook = null,
    gpa: Allocator,
    io: Io,
    context: *const consensus.Context,
    verifier: consensus.verifier.SignedBlockVerifier,
    peers: *peers_mod.Peers,
    rounds: rounds_mod.RoundTracker,
    commit_votes: rounds_mod.CommitVoteMonitor,
    published: service.Published,
    broadcaster: bc.Broadcaster,
    stats: service.Stats = .{},
    stopping: std.atomic.Value(bool) = .init(false),
    core_q: mon.Queue(CoreEvent),
    core_q_storage: []CoreEvent,
    /// Missing block refs the core reported (the synchronizer's periodic work list).
    missing_mu: mon.Monitor,
    missing: std.ArrayList(types.BlockRef) = .empty,
    /// Highest commit index the consumer finished (CommitSink.processed_through), refreshed by the core thread.
    handled_commit: std.atomic.Value(u32) = .init(0),
    /// Once true the core may propose (own-block sync done, or single node).
    may_propose: std.atomic.Value(bool) = .init(false),
    /// Called for the excluded ancestors of a streamed or SendBlock block (`check_block_refs`).
    excluded_hook: ?ExcludedHook = null,

    pub const core_queue_len = 4096;
    pub const max_missing = 4096;

    pub fn init(gpa: Allocator, io: Io, context: *const consensus.Context, peers: *peers_mod.Peers, verifier: consensus.verifier.SignedBlockVerifier) !*Shared {
        const s = try gpa.create(Shared);
        errdefer gpa.destroy(s);
        const own = context.own_index orelse 0;
        const n = context.committee.size();
        const storage = try gpa.alloc(CoreEvent, core_queue_len);
        errdefer gpa.free(storage);
        var rt = try rounds_mod.RoundTracker.init(gpa, io, &context.committee, own);
        errdefer rt.deinit();
        var cvm = try rounds_mod.CommitVoteMonitor.init(gpa, io, n);
        errdefer cvm.deinit();
        var pub_ = try service.Published.init(gpa, n);
        errdefer pub_.deinit();
        s.* = .{
            .gpa = gpa,
            .io = io,
            .context = context,
            .verifier = verifier,
            .peers = peers,
            .rounds = rt,
            .commit_votes = cvm,
            .published = pub_,
            .broadcaster = try bc.Broadcaster.init(gpa, io, 1024),
            .core_q = mon.Queue(CoreEvent).init(io, storage),
            .core_q_storage = storage,
            .missing_mu = mon.Monitor.init(io),
        };
        return s;
    }

    pub fn deinit(s: *Shared) void {
        // Free batches still queued.
        while (s.core_q.pop(0)) |ev| freeEvent(ev);
        s.core_q.close();
        s.broadcaster.deinit();
        s.published.deinit();
        s.commit_votes.deinit();
        s.rounds.deinit();
        s.missing.deinit(s.gpa);
        s.gpa.free(s.core_q_storage);
        s.gpa.destroy(s);
    }

    pub fn freeEvent(ev: CoreEvent) void {
        switch (ev) {
            .blocks => |b| b.destroy(),
            .commits => |c| c.destroy(),
            else => {},
        }
    }

    pub fn isStopping(s: *const Shared) bool {
        return s.stopping.load(.acquire);
    }

    /// Queues an event for the core thread, waiting while it is full. False when stopping: the
    /// event was NOT taken and the caller still owns (and frees) its batch.
    pub fn pushCore(s: *Shared, ev: CoreEvent) bool {
        while (!s.isStopping()) {
            if (s.core_q.push(ev)) return true;
            sleepMs(1);
        }
        return false;
    }

    pub fn nowMs(s: *const Shared) u64 {
        return s.context.clock.nowMs();
    }

    // ------------------------------------------------------------ verification

    pub const Verified = struct { block: types.VerifiedBlock, rejects: []const types.TransactionIndex };

    /// Decodes and verifies one peer block into `arena` (BlockVerifier, in Rust's order). As in
    /// mainnet-v1.83.1 (`authority_service.rs`, `commit_syncer.rs`) a timestamp ahead of our clock
    /// is only measured (`Stats.forward_drift_blocks`), never rejected or waited for.
    pub fn verifyBlock(s: *Shared, arena: Allocator, serialized: []const u8, from: types.AuthorityIndex, require_author: bool) Error!Verified {
        const copy = arena.dupe(u8, serialized) catch return error.OutOfMemory;
        const cap: usize = @intCast(@min(s.context.protocol_config.max_num_transactions_in_block, 1 << 16));
        const votes = arena.alloc(types.TransactionIndex, cap) catch return error.OutOfMemory;
        var vb: types.VerifiedBlock = undefined;
        var nrej: usize = 0;
        const verified = if (s.verifier_hook) |h| h.verify(h.ctx, arena, copy, &vb, votes, &nrej) else s.verifier.verifyAndVote(arena, copy, &vb, votes, &nrej);
        const verdict = verified catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Shutdown => return error.Shutdown,
            else => {
                if (s.stats.blocks_invalid.fetchAdd(1, .monotonic) < 64) log.warn("block from peer {d} not decodable/verifiable: {s} ({d} bytes)", .{ from, @errorName(e), serialized.len });
                return error.InvalidBlock;
            },
        };
        switch (verdict) {
            .ok => {},
            .reject => |why| {
                if (s.stats.blocks_invalid.fetchAdd(1, .monotonic) < 64) log.warn("block from peer {d} rejected: {any}", .{ from, why });
                return error.InvalidBlock;
            },
        }
        if (require_author and vb.block.inner.author() != from) {
            if (s.stats.blocks_invalid.fetchAdd(1, .monotonic) < 64) log.warn("block from peer {d} has author {d}", .{ from, vb.block.inner.author() });
            return error.InvalidBlock;
        }
        const now = s.nowMs();
        const ts = vb.block.inner.timestampMs();
        if (ts > now and (ts - now) *| std.time.ns_per_ms > s.context.parameters.max_forward_time_drift_ns) {
            _ = s.stats.forward_drift_blocks.fetchAdd(1, .monotonic);
        }
        _ = s.stats.blocks_received.fetchAdd(1, .monotonic);
        return .{ .block = vb, .rejects = votes[0..nrej] };
    }

    /// Verifies and submits blocks to the core thread as one batch. Invalid blocks are dropped
    /// (counted); returns how many were submitted. With `require_author` (subscriber streams and
    /// SendBlock) `excluded` is the sender's excluded-ancestor list, handled as Rust's
    /// `parse_excluded_ancestors` does (truncated to 2n, an invalid author or a round not below
    /// the block's rejects the block), and the block is dropped while we lag the quorum's commits.
    pub fn submitBlocks(s: *Shared, from: types.AuthorityIndex, serialized: []const []const u8, excluded: []const types.BlockRef, require_author: bool) Error!usize {
        if (serialized.len == 0) return 0;
        const batch = BlockBatch.create(s.gpa, from) catch return error.OutOfMemory;
        errdefer batch.destroy();
        const arena = batch.arena.allocator();
        var blocks: std.ArrayList(types.VerifiedBlock) = .empty;
        var rejects: std.ArrayList([]const types.TransactionIndex) = .empty;
        const n_auth = s.context.committee.size();
        const ex_all = if (require_author) excluded[0..@min(excluded.len, n_auth * 2)] else excluded;
        var ex_used: []const types.BlockRef = &.{};
        for (serialized) |raw| {
            const v = s.verifyBlock(arena, raw, from, require_author) catch |e| switch (e) {
                error.InvalidBlock => continue,
                else => return e,
            };
            const vb = v.block;
            const round = vb.block.inner.round();
            if (require_author) {
                var ok = true;
                for (ex_all) |r| {
                    if (r.author >= n_auth or r.round >= round) {
                        ok = false;
                        break;
                    }
                }
                if (!ok) {
                    _ = s.stats.blocks_invalid.fetchAdd(1, .monotonic);
                    continue;
                }
            }
            s.commit_votes.observeBlock(vb.block.inner.author(), vb.block.inner.commitVotes());
            s.rounds.updateFromVerifiedBlock(vb.block.inner.author(), round, vb.block.inner.ancestors(), ex_all);
            if (require_author) {
                // While far behind the quorum's commits, streamed blocks would only pile up as
                // suspended blocks; commit sync brings the node up instead.
                const quorum = s.commit_votes.quorumCommitIndex(&s.context.committee);
                if (rounds_mod.isCommitLagging(s.context.parameters.commit_sync_batch_size, s.published.commit_index.load(.acquire), quorum)) {
                    _ = s.stats.blocks_rejected_lagging.fetchAdd(1, .monotonic);
                    continue;
                }
                ex_used = ex_all;
            }
            blocks.append(arena, vb) catch return error.OutOfMemory;
            rejects.append(arena, v.rejects) catch return error.OutOfMemory;
        }
        if (blocks.items.len == 0) {
            batch.destroy();
            return 0;
        }
        batch.blocks = blocks.items;
        batch.rejects = rejects.items;
        batch.excluded = arena.dupe(types.BlockRef, ex_used) catch return error.OutOfMemory;
        const n = blocks.items.len;
        if (require_author and ex_used.len > 0) {
            if (s.excluded_hook) |h| h.check(h.ctx, ex_used, from);
        }
        if (!s.pushCore(.{ .blocks = batch })) return error.Shutdown;
        return n;
    }

    // ------------------------------------------------------------ missing blocks

    pub fn setMissing(s: *Shared, refs: []const types.BlockRef) void {
        s.missing_mu.lock();
        defer s.missing_mu.unlock();
        s.missing.clearRetainingCapacity();
        s.missing.appendSlice(s.gpa, refs[0..@min(refs.len, max_missing)]) catch {};
    }

    pub fn copyMissing(s: *Shared, arena: Allocator) Allocator.Error![]types.BlockRef {
        s.missing_mu.lock();
        defer s.missing_mu.unlock();
        return arena.dupe(types.BlockRef, s.missing.items);
    }
};

pub fn sleepMs(ms: u64) void {
    @import("serve").h2.sock.sleepMs(@max(1, ms));
}

pub fn blockDigest(serialized: []const u8) types.BlockDigest {
    return hash.blake2b256(&.{serialized});
}

/// Decodes serialized SignedBlock bytes without verifying (for blocks already bound to a
/// certified commit by their digest).
pub fn decodeTrusted(arena: Allocator, serialized: []const u8) !types.VerifiedBlock {
    const copy = try arena.dupe(u8, serialized);
    const sb = try bcs.decode(types.SignedBlock, arena, copy);
    return .{ .block = sb, .serialized = copy, .digest = blockDigest(copy) };
}
