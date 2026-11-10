//! consensus_core::transaction_vote_tracker at mainnet-v1.83.1: the reject votes carried in blocks
//! (block V2 `transaction_votes`), accumulated per (block, transaction index) with stake, plus our
//! own reject votes for the blocks we accepted. Owner lane: val-consensus-core.
//! Reject votes are explicit; every other transaction of a voted-on block receives an implicit accept.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const iface = @import("iface.zig");
const committee_mod = @import("committee.zig");
const dag_mod = @import("dag_state.zig");
const store_mod = @import("store.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;
const Agg = committee_mod.StakeAggregator(committee_mod.max_committee_size);

pub const RejectVote = struct { index: types.TransactionIndex, stake: types.Stake };
pub const VotedBlock = struct { block: *const types.VerifiedBlock, own_rejects: []const types.TransactionIndex };

const RejectAgg = struct { index: types.TransactionIndex, agg: Agg = .{} };

const VoteInfo = struct {
    /// The block itself was voted on (added through `addVotedBlock`).
    voted: bool = false,
    own_rejects: []types.TransactionIndex = &.{},
    rejects: std.ArrayList(RejectAgg) = .empty,

    fn deinit(self: *VoteInfo, gpa: Allocator) void {
        gpa.free(self.own_rejects);
        self.rejects.deinit(gpa);
    }
};

fn refCmp(ctx: types.BlockRef, item: types.BlockRef) std.math.Order {
    return ctx.order(item);
}

pub const TransactionVoteTracker = struct {
    gpa: Allocator,
    context: *const Context,
    dag: *dag_mod.DagState,
    tx_verifier: iface.TransactionVerifier,
    votes: std.HashMapUnmanaged(types.BlockRef, *VoteInfo, store_mod.RefContext, 80) = .empty,
    order: std.ArrayList(types.BlockRef) = .empty,
    gc_round: types.Round = types.GENESIS_ROUND,

    pub fn init(gpa: Allocator, context: *const Context, dag: *dag_mod.DagState, tx_verifier: iface.TransactionVerifier) TransactionVoteTracker {
        return .{ .gpa = gpa, .context = context, .dag = dag, .tx_verifier = tx_verifier };
    }

    pub fn deinit(self: *TransactionVoteTracker) void {
        var it = self.votes.valueIterator();
        while (it.next()) |p| {
            p.*.deinit(self.gpa);
            self.gpa.destroy(p.*);
        }
        self.votes.deinit(self.gpa);
        self.order.deinit(self.gpa);
    }

    fn entry(self: *TransactionVoteTracker, ref: types.BlockRef) Allocator.Error!*VoteInfo {
        if (self.votes.get(ref)) |v| return v;
        const v = try self.gpa.create(VoteInfo);
        errdefer self.gpa.destroy(v);
        v.* = .{};
        try self.votes.put(self.gpa, ref, v);
        errdefer _ = self.votes.remove(ref);
        try dag_mod.refSetInsert(self.gpa, &self.order, ref);
        return v;
    }

    /// `add_voted_block`: ignores blocks at or below the GC round and blocks already added. Records
    /// our own reject votes for the block and every reject vote the block casts on earlier blocks.
    pub fn addVotedBlock(self: *TransactionVoteTracker, voted: *const types.VerifiedBlock, own_rejects: []const types.TransactionIndex) err.Error!void {
        const ref = voted.reference();
        if (ref.round <= self.gc_round) return;
        const info = self.entry(ref) catch return error.OutOfMemory;
        if (info.voted) return;
        info.voted = true;
        info.own_rejects = self.gpa.dupe(types.TransactionIndex, own_rejects) catch return error.OutOfMemory;

        const c = &self.context.committee;
        for (voted.block.inner.transactionVotes()) |bv| {
            if (bv.block_ref.round <= self.gc_round) continue;
            const target = self.entry(bv.block_ref) catch return error.OutOfMemory;
            for (bv.rejects) |idx| {
                const pos = std.sort.lowerBound(RejectAgg, target.rejects.items, idx, struct {
                    fn cmp(ctx: types.TransactionIndex, item: RejectAgg) std.math.Order {
                        return std.math.order(ctx, item.index);
                    }
                }.cmp);
                if (pos >= target.rejects.items.len or target.rejects.items[pos].index != idx) {
                    target.rejects.insert(self.gpa, pos, .{ .index = idx }) catch return error.OutOfMemory;
                }
                _ = target.rejects.items[pos].agg.add(voted.block.inner.author(), c, c.quorum_threshold);
            }
        }
    }

    pub fn addVotedBlocks(self: *TransactionVoteTracker, blocks: []const VotedBlock) err.Error!void {
        for (blocks) |b| try self.addVotedBlock(b.block, b.own_rejects);
    }

    /// `recover_and_vote_on_blocks`: votes (through the TransactionVerifier) on blocks above the GC
    /// round that no own proposal has included yet, then records them.
    pub fn recoverAndVoteOnBlocks(self: *TransactionVoteTracker, arena: Allocator, blocks: []const types.VerifiedBlock) err.Error!void {
        const gc = self.dag.gcRound();
        for (blocks) |*b| {
            const ref = b.reference();
            const should_vote = ref.round > gc and !(try self.dag.hasBeenIncluded(ref));
            var rejects: []types.TransactionIndex = &.{};
            if (should_vote) {
                const txs = b.block.inner.transactions();
                const buf = arena.alloc(types.TransactionIndex, txs.len) catch return error.OutOfMemory;
                const n = self.tx_verifier.verifyAndVoteBatch(ref, txs, buf) catch return error.Invariant;
                rejects = buf[0..n];
            }
            try self.addVotedBlock(b, rejects);
        }
    }

    /// `recover_blocks_after_round`: scans every authority's stored blocks after `after_round`.
    pub fn recoverBlocksAfterRound(self: *TransactionVoteTracker, arena: Allocator, after_round: types.Round) err.Error!void {
        if (!self.context.protocol_config.transaction_voting_enabled) return;
        for (0..self.context.committee.size()) |a| {
            const blocks = try self.dag.store.scanBlocksByAuthor(arena, @intCast(a), after_round + 1, std.math.maxInt(types.Round), std.math.maxInt(usize));
            try self.recoverAndVoteOnBlocks(arena, blocks);
        }
    }

    /// `get_own_votes`: our reject votes for each of `refs` above the GC round that has any.
    pub fn getOwnVotes(self: *const TransactionVoteTracker, arena: Allocator, refs: []const types.BlockRef) err.Error![]types.BlockTransactionVotes {
        var out: std.ArrayList(types.BlockTransactionVotes) = .empty;
        for (refs) |r| {
            if (r.round <= self.gc_round) continue;
            const info = self.votes.get(r) orelse return error.MissingBlock;
            if (info.own_rejects.len == 0) continue;
            out.append(arena, .{ .block_ref = r, .rejects = arena.dupe(types.TransactionIndex, info.own_rejects) catch return error.OutOfMemory }) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// `get_reject_votes`: (index, accumulated reject stake) of the block, ascending index; null if
    /// the block has no vote info (not tracked or collected).
    pub fn getRejectVotes(self: *const TransactionVoteTracker, arena: Allocator, ref: types.BlockRef) err.Error!?[]RejectVote {
        const info = self.votes.get(ref) orelse return null;
        const out = arena.alloc(RejectVote, info.rejects.items.len) catch return error.OutOfMemory;
        for (out, info.rejects.items) |*o, r| o.* = .{ .index = r.index, .stake = r.agg.stake };
        return out;
    }

    /// `run_gc`.
    pub fn runGc(self: *TransactionVoteTracker, gc_round: types.Round) err.Error!void {
        if (gc_round > self.dag.gcRound()) return error.Invariant;
        self.gc_round = gc_round;
        var cut: usize = 0;
        while (cut < self.order.items.len and self.order.items[cut].round <= gc_round) : (cut += 1) {
            if (self.votes.fetchRemove(self.order.items[cut])) |kv| {
                kv.value.deinit(self.gpa);
                self.gpa.destroy(kv.value);
            }
        }
        if (cut > 0) {
            std.mem.copyForwards(types.BlockRef, self.order.items, self.order.items[cut..]);
            self.order.shrinkRetainingCapacity(self.order.items.len - cut);
        }
    }
};
