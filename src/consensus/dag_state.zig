//! consensus_core::dag_state::DagState at mainnet-v1.83.1: the in-memory DAG window (recent
//! blocks per authority, cached rounds, GC round), commit state, commit votes, scoring sub-dags,
//! and the buffered writes flushed to the Store in one batch. Owner lane: val-consensus-core.
//! Single-threaded: only the core thread touches it (Rust wraps it in a RwLock; deepwave publishes
//! read-only snapshots for the network tiles, docs/VALIDATOR-DESIGN.md 7).
//!
//! Memory: every cached block lives in its own arena (a copy of the serialized bytes, decoded).
//! Pointers returned by the getters stay valid until the block is evicted by `flush` (after it
//! is older than both the GC round and `dag_state_cached_rounds`). V3 consensus is not implemented:
//! `init` refuses `enable_v3`.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types.zig");
const err = @import("error.zig");
const digest_mod = @import("digest.zig");
const Context = @import("context.zig").Context;
const store_mod = @import("store.zig");
const scoring = @import("leader_scoring.zig");
const ThresholdClock = @import("threshold_clock.zig").ThresholdClock;

const Allocator = std.mem.Allocator;
const RefContext = store_mod.RefContext;

pub const BlockInfo = struct {
    arena: std.heap.ArenaAllocator,
    block: types.VerifiedBlock,
    committed: bool = false,
    /// Hard linked into one of our own proposals (`link_causal_history`).
    included: bool = false,
};

fn refCmp(ctx: types.BlockRef, item: types.BlockRef) std.math.Order {
    return ctx.order(item);
}

/// Inserts into a sorted unique list of refs.
pub fn refSetInsert(gpa: Allocator, list: *std.ArrayList(types.BlockRef), r: types.BlockRef) Allocator.Error!void {
    const pos = std.sort.lowerBound(types.BlockRef, list.items, r, refCmp);
    if (pos < list.items.len and list.items[pos].eql(r)) return;
    try list.insert(gpa, pos, r);
}

pub const DagState = struct {
    gpa: Allocator,
    context: *const Context,
    store: store_mod.Store,

    genesis_arena: std.heap.ArenaAllocator,
    genesis: []types.VerifiedBlock,

    /// Recent blocks by ref and the sorted order of the same refs (BTreeMap range queries).
    recent: std.HashMapUnmanaged(types.BlockRef, *BlockInfo, RefContext, 80) = .empty,
    order: std.ArrayList(types.BlockRef) = .empty,
    refs_by_author: []std.ArrayList(types.BlockRef),
    evicted_rounds: []types.Round,
    highest_accepted_round: types.Round = 0,
    threshold_clock: ThresholdClock,

    last_commit_arena: std.heap.ArenaAllocator,
    last_commit: ?types.TrustedCommit = null,
    last_committed_rounds: []types.Round,
    scoring_subdag: scoring.ScoringSubdag,
    pending_commit_votes: std.ArrayList(types.CommitVote) = .empty,

    write_arena: std.heap.ArenaAllocator,
    blocks_to_write: std.ArrayList(*const types.VerifiedBlock) = .empty,
    commits_to_write: std.ArrayList(types.TrustedCommit) = .empty,
    commit_info_to_write: std.ArrayList(store_mod.CommitInfoEntry) = .empty,
    finalized_to_write: std.ArrayList(store_mod.FinalizedEntry) = .empty,

    cached_rounds: types.Round,

    pub fn init(gpa: Allocator, context: *const Context, store: store_mod.Store) err.Error!*DagState {
        if (context.protocol_config.enable_v3) return error.Unsupported;
        const n = context.committee.size();
        const self = gpa.create(DagState) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);
        self.* = .{
            .gpa = gpa,
            .context = context,
            .store = store,
            .genesis_arena = std.heap.ArenaAllocator.init(gpa),
            .genesis = &.{},
            .refs_by_author = gpa.alloc(std.ArrayList(types.BlockRef), n) catch return error.OutOfMemory,
            .evicted_rounds = gpa.alloc(types.Round, n) catch return error.OutOfMemory,
            .threshold_clock = ThresholdClock.init(&context.committee, 1, context.clock.monoNs()),
            .last_commit_arena = std.heap.ArenaAllocator.init(gpa),
            .last_committed_rounds = gpa.alloc(types.Round, n) catch return error.OutOfMemory,
            .scoring_subdag = scoring.ScoringSubdag.init(gpa, &context.committee),
            .write_arena = std.heap.ArenaAllocator.init(gpa),
            .cached_rounds = context.parameters.dag_state_cached_rounds,
        };
        for (self.refs_by_author) |*l| l.* = .empty;
        @memset(self.evicted_rounds, 0);
        @memset(self.last_committed_rounds, 0);
        self.genesis = try digest_mod.genesisBlocks(self.genesis_arena.allocator(), &context.committee, context.epoch_start_timestamp_ms, &context.protocol_config);
        try self.recover();
        return self;
    }

    pub fn deinit(self: *DagState) void {
        const gpa = self.gpa;
        var it = self.recent.valueIterator();
        while (it.next()) |p| {
            p.*.arena.deinit();
            gpa.destroy(p.*);
        }
        self.recent.deinit(gpa);
        self.order.deinit(gpa);
        for (self.refs_by_author) |*l| l.deinit(gpa);
        gpa.free(self.refs_by_author);
        gpa.free(self.evicted_rounds);
        gpa.free(self.last_committed_rounds);
        self.scoring_subdag.deinit();
        self.pending_commit_votes.deinit(gpa);
        self.blocks_to_write.deinit(gpa);
        self.commits_to_write.deinit(gpa);
        self.commit_info_to_write.deinit(gpa);
        self.finalized_to_write.deinit(gpa);
        self.genesis_arena.deinit();
        self.last_commit_arena.deinit();
        self.write_arena.deinit();
        gpa.destroy(self);
    }

    // ------------------------------------------------------------ recovery (DagState::new)

    fn recover(self: *DagState) err.Error!void {
        var tmp = std.heap.ArenaAllocator.init(self.gpa);
        defer tmp.deinit();
        const ta = tmp.allocator();
        const ctx = self.context;
        const n = ctx.committee.size();

        if (try self.store.readLastCommit()) |lc| try self.setLastCommit(lc);

        var recovery_start: types.CommitIndex = 1;
        if (try self.store.readLastCommitInfo()) |e| {
            @memcpy(self.last_committed_rounds, e.info.committed_rounds[0..n]);
            recovery_start = e.ref.index + 1;
        }

        if (self.last_commit) |lc| {
            const commits = try self.store.scanCommits(ta, types.CommitRange.inclusive(recovery_start, lc.commit.index()));
            for (commits) |c| {
                for (c.commit.V1.blocks) |br| {
                    self.last_committed_rounds[br.author] = @max(self.last_committed_rounds[br.author], br.round);
                }
                const sub = try loadCommittedSubdag(ta, self.store, c);
                self.scoring_subdag.addSubdag(&sub) catch |e| return switch (e) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.Invariant,
                };
            }
        }

        // Recover cached blocks per authority from their eviction round.
        var recovered: std.ArrayList(types.VerifiedBlock) = .empty;
        for (0..n) |a| {
            const author: types.AuthorityIndex = @intCast(a);
            const last = try self.store.scanLastBlocksByAuthor(ta, author, 1, null);
            const last_round: types.Round = if (last.len > 0) last[last.len - 1].block.inner.round() else 0;
            const ev = evictionRound(last_round, self.gcRound(), self.cached_rounds);
            const blocks = try self.store.scanBlocksByAuthor(ta, author, ev + 1, std.math.maxInt(types.Round), std.math.maxInt(usize));
            recovered.appendSlice(ta, blocks) catch return error.OutOfMemory;
            self.evicted_rounds[a] = ev;
        }
        std.mem.sort(types.VerifiedBlock, recovered.items, {}, struct {
            fn lt(_: void, x: types.VerifiedBlock, y: types.VerifiedBlock) bool {
                return x.reference().order(y.reference()) == .lt;
            }
        }.lt);
        for (recovered.items) |*b| _ = try self.insertCached(b);

        // Block commit statuses from the last commits backwards until the leader round <= gc round.
        if (self.last_commit) |lc| {
            var index = lc.commit.index();
            const gc = self.gcRound();
            while (index > 0) : (index -= 1) {
                const commits = try self.store.scanCommits(ta, types.CommitRange.inclusive(index, index));
                if (commits.len == 0) break;
                const c = commits[0];
                if (gc > 0 and c.commit.leader().round <= gc) break;
                for (c.commit.V1.blocks) |br| {
                    if (br.round <= gc) continue;
                    const info = self.recent.get(br) orelse return error.Invariant;
                    info.committed = true;
                }
            }
        }

        // Hard linked statuses for our own proposed blocks within the GC window.
        if (ctx.own_index) |own| {
            const proposed = try self.store.scanBlocksByAuthor(ta, own, self.gcRound() + 1, std.math.maxInt(types.Round), std.math.maxInt(usize));
            for (proposed) |b| _ = try self.linkCausalHistory(ta, b.reference());
        }
    }

    // ------------------------------------------------------------ blocks

    fn insertCached(self: *DagState, vb: *const types.VerifiedBlock) err.Error!*BlockInfo {
        const ref = vb.reference();
        if (self.recent.get(ref)) |existing| return existing;
        const info = self.gpa.create(BlockInfo) catch return error.OutOfMemory;
        errdefer self.gpa.destroy(info);
        info.* = .{ .arena = std.heap.ArenaAllocator.init(self.gpa), .block = undefined };
        errdefer info.arena.deinit();
        info.block = try digest_mod.cloneVerified(info.arena.allocator(), vb);
        self.recent.put(self.gpa, ref, info) catch return error.OutOfMemory;
        errdefer _ = self.recent.remove(ref);
        try refSetInsert(self.gpa, &self.order, ref);
        try refSetInsert(self.gpa, &self.refs_by_author[ref.author], ref);
        _ = self.threshold_clock.addBlock(ref, self.context.clock.monoNs());
        self.highest_accepted_round = @max(self.highest_accepted_round, ref.round);
        return info;
    }

    /// Accepts a block into the DAG and queues it for the next flush (`accept_block`). Genesis
    /// blocks are never accepted; a second block in our own slot is an invariant violation.
    pub fn acceptBlock(self: *DagState, block: *const types.VerifiedBlock) err.Error!void {
        const ref = block.reference();
        if (ref.round == 0) return error.Invariant;
        if (self.recent.contains(ref)) return;
        if (self.context.own_index) |own| {
            if (ref.author == own and !self.context.parameters.skip_equivocation_validation) {
                var scratch = std.heap.ArenaAllocator.init(self.gpa);
                defer scratch.deinit();
                const existing = try self.getUncommittedBlocksAtSlot(scratch.allocator(), .{ .round = ref.round, .authority = ref.author });
                if (existing.len != 0) return error.Invariant;
            }
        }
        const info = try self.insertCached(block);
        self.blocks_to_write.append(self.gpa, &info.block) catch return error.OutOfMemory;
    }

    pub fn acceptBlocks(self: *DagState, blocks: []const types.VerifiedBlock) err.Error!void {
        for (blocks) |*b| try self.acceptBlock(b);
    }

    /// Cache or genesis lookup. Null when the block is not in memory.
    pub fn getBlock(self: *const DagState, ref: types.BlockRef) ?*const types.VerifiedBlock {
        if (ref.round == 0) {
            for (self.genesis) |*g| if (g.reference().eql(ref)) return g;
            return null;
        }
        if (self.recent.get(ref)) |info| return &info.block;
        return null;
    }

    /// Like `getBlock`, falling back to the store (the result is then valid for the store's life).
    pub fn getBlockOrStore(self: *const DagState, ref: types.BlockRef) err.Error!?types.VerifiedBlock {
        if (self.getBlock(ref)) |b| return b.*;
        var out = [1]?types.VerifiedBlock{null};
        try self.store.readBlocks(&.{ref}, &out);
        return out[0];
    }

    pub fn containsBlock(self: *const DagState, ref: types.BlockRef) err.Error!bool {
        if (self.getBlock(ref) != null) return true;
        var out = [1]bool{false};
        try self.store.containsBlocks(&.{ref}, &out);
        return out[0];
    }

    fn lowerBoundRef(self: *const DagState, r: types.BlockRef) usize {
        return std.sort.lowerBound(types.BlockRef, self.order.items, r, refCmp);
    }

    /// `get_uncommitted_blocks_at_slot`: all cached blocks at (round, authority), in ref order.
    pub fn getUncommittedBlocksAtSlot(self: *const DagState, arena: Allocator, slot: types.Slot) err.Error![]*const types.VerifiedBlock {
        var out: std.ArrayList(*const types.VerifiedBlock) = .empty;
        var i = self.lowerBoundRef(.{ .round = slot.round, .author = slot.authority, .digest = types.block_digest_min });
        while (i < self.order.items.len) : (i += 1) {
            const r = self.order.items[i];
            if (r.round != slot.round or r.author != slot.authority) break;
            out.append(arena, &self.recent.get(r).?.block) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// `get_uncommitted_blocks_at_round`: all cached blocks of `round`. Rust panics for a round
    /// at or below the last commit round; that is `error.Invariant` here.
    pub fn getUncommittedBlocksAtRound(self: *const DagState, arena: Allocator, round: types.Round) err.Error![]*const types.VerifiedBlock {
        if (round <= self.lastCommitRound()) return error.Invariant;
        var out: std.ArrayList(*const types.VerifiedBlock) = .empty;
        var i = self.lowerBoundRef(.{ .round = round, .author = 0, .digest = types.block_digest_min });
        while (i < self.order.items.len) : (i += 1) {
            const r = self.order.items[i];
            if (r.round != round) break;
            out.append(arena, &self.recent.get(r).?.block) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// `ancestors_at_round`: the blocks at `earlier_round` or later reachable... exactly Rust's
    /// frontier walk: start from the ancestors of `later`, repeatedly expand the highest-ref entry
    /// while its round is above `earlier_round`, then return the entries with round >= earlier_round.
    pub fn ancestorsAtRound(self: *const DagState, arena: Allocator, later: *const types.VerifiedBlock, earlier_round: types.Round) err.Error![]*const types.VerifiedBlock {
        var linked: std.ArrayList(types.BlockRef) = .empty;
        for (later.block.inner.ancestors()) |a| refSetInsert(arena, &linked, a) catch return error.OutOfMemory;
        while (linked.items.len > 0) {
            const last = linked.items[linked.items.len - 1];
            if (last.round <= earlier_round) break;
            _ = linked.pop();
            const b = self.getBlock(last) orelse return error.MissingBlock;
            for (b.block.inner.ancestors()) |a| refSetInsert(arena, &linked, a) catch return error.OutOfMemory;
        }
        var out: std.ArrayList(*const types.VerifiedBlock) = .empty;
        var i = std.sort.lowerBound(types.BlockRef, linked.items, types.BlockRef{ .round = earlier_round, .author = 0, .digest = types.block_digest_min }, refCmp);
        while (i < linked.items.len) : (i += 1) {
            out.append(arena, self.getBlock(linked.items[i]) orelse return error.MissingBlock) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// `get_last_block_for_authority`: highest cached block, else genesis.
    pub fn getLastBlockForAuthority(self: *const DagState, author: types.AuthorityIndex) *const types.VerifiedBlock {
        const l = self.refs_by_author[author].items;
        if (l.len > 0) return &self.recent.get(l[l.len - 1]).?.block;
        return &self.genesis[author];
    }
    pub fn getLastProposedBlock(self: *const DagState) ?*const types.VerifiedBlock {
        const own = self.context.own_index orelse return null;
        return self.getLastBlockForAuthority(own);
    }

    /// Cached blocks of `author` with round >= start, ascending.
    pub fn getCachedBlocks(self: *const DagState, arena: Allocator, author: types.AuthorityIndex, start: types.Round) err.Error![]*const types.VerifiedBlock {
        var out: std.ArrayList(*const types.VerifiedBlock) = .empty;
        for (self.refs_by_author[author].items) |r| {
            if (r.round < start) continue;
            out.append(arena, &self.recent.get(r).?.block) catch return error.OutOfMemory;
        }
        return out.items;
    }

    /// `get_last_cached_block_per_authority`: for every authority its highest cached block with
    /// round < `end_round` (genesis if none) and the other blocks it has at that same round
    /// (equivocations). `end_round` must be above the genesis round and above the eviction round.
    pub const LastBlock = struct { block: *const types.VerifiedBlock, equivocating: []const types.BlockRef };
    pub fn getLastCachedBlockPerAuthority(self: *const DagState, arena: Allocator, end_round: types.Round) err.Error![]LastBlock {
        if (end_round == types.GENESIS_ROUND) return error.Invariant;
        const out = arena.alloc(LastBlock, self.genesis.len) catch return error.OutOfMemory;
        for (out, self.genesis) |*o, *g| o.* = .{ .block = g, .equivocating = &.{} };
        if (end_round == types.GENESIS_ROUND + 1) return out;
        for (self.refs_by_author, 0..) |list, a| {
            if (end_round -| 1 <= self.evicted_rounds[a]) return error.Invariant;
            var eq: std.ArrayList(types.BlockRef) = .empty;
            var last_round: types.Round = 0;
            var i = list.items.len;
            while (i > 0) {
                i -= 1;
                const r = list.items[i];
                if (r.round >= end_round) continue;
                if (r.round <= self.evicted_rounds[a]) break;
                if (last_round == 0) {
                    last_round = r.round;
                    out[a].block = &self.recent.get(r).?.block;
                    continue;
                }
                if (r.round < last_round) break;
                eq.append(arena, r) catch return error.OutOfMemory;
            }
            out[a].equivocating = eq.items;
        }
        return out;
    }

    /// `contains_cached_block_at_slot` (genesis slots are always present).
    pub fn containsCachedBlockAtSlot(self: *const DagState, slot: types.Slot) err.Error!bool {
        if (slot.round == types.GENESIS_ROUND) return true;
        if (slot.round <= self.evicted_rounds[slot.authority]) return error.Invariant;
        for (self.refs_by_author[slot.authority].items) |r| {
            if (r.round == slot.round) return true;
        }
        return false;
    }

    /// `recover_commits_to_write`: commits already in the store are re-queued by commit recovery.
    pub fn recoverCommitsToWrite(self: *DagState, commits: []const types.TrustedCommit) err.Error!void {
        for (commits) |c| self.commits_to_write.append(self.gpa, try cloneCommit(self.write_arena.allocator(), c)) catch return error.OutOfMemory;
    }

    pub fn setCommitted(self: *DagState, ref: types.BlockRef) err.Error!bool {
        const info = self.recent.get(ref) orelse return error.MissingBlock;
        if (info.committed) return false;
        info.committed = true;
        return true;
    }
    /// Valid only for blocks above the GC round that are cached.
    pub fn isCommitted(self: *const DagState, ref: types.BlockRef) err.Error!bool {
        const info = self.recent.get(ref) orelse return error.MissingBlock;
        return info.committed;
    }

    /// `link_causal_history`: marks the root and every ancestor above the GC round as included in
    /// an own proposal; returns the newly linked refs (BFS order) from `arena`.
    pub fn linkCausalHistory(self: *DagState, arena: Allocator, root: types.BlockRef) err.Error![]types.BlockRef {
        const gc = self.gcRound();
        var linked: std.ArrayList(types.BlockRef) = .empty;
        var targets: std.ArrayList(types.BlockRef) = .empty;
        targets.append(arena, root) catch return error.OutOfMemory;
        var head: usize = 0;
        while (head < targets.items.len) {
            const r = targets.items[head];
            head += 1;
            if (r.round <= gc) continue;
            const info = self.recent.get(r) orelse return error.MissingBlock;
            if (info.included) continue;
            linked.append(arena, r) catch return error.OutOfMemory;
            info.included = true;
            targets.appendSlice(arena, info.block.block.inner.ancestors()) catch return error.OutOfMemory;
        }
        return linked.items;
    }
    pub fn hasBeenIncluded(self: *const DagState, ref: types.BlockRef) err.Error!bool {
        const info = self.recent.get(ref) orelse return error.MissingBlock;
        return info.included;
    }

    // ------------------------------------------------------------ clock and rounds

    pub fn thresholdClockRound(self: *const DagState) types.Round {
        return self.threshold_clock.getRound();
    }
    pub fn thresholdClockQuorumTsNs(self: *const DagState) u64 {
        return self.threshold_clock.quorum_ts_ns;
    }
    pub fn highestAcceptedRound(self: *const DagState) types.Round {
        return self.highest_accepted_round;
    }
    pub fn gcRound(self: *const DagState) types.Round {
        return self.calculateGcRound(self.lastCommitRound());
    }
    pub fn calculateGcRound(self: *const DagState, commit_round: types.Round) types.Round {
        return commit_round -| self.context.protocol_config.gc_depth;
    }

    // ------------------------------------------------------------ commits

    pub fn lastCommitIndex(self: *const DagState) types.CommitIndex {
        return if (self.last_commit) |c| c.commit.index() else 0;
    }
    pub fn lastCommitDigest(self: *const DagState) types.CommitDigest {
        return if (self.last_commit) |c| c.digest else types.block_digest_min;
    }
    pub fn lastCommitTimestampMs(self: *const DagState) types.BlockTimestampMs {
        return if (self.last_commit) |c| c.commit.V1.timestamp_ms else 0;
    }
    /// The leader slot of the last commit, or the first genesis block's slot.
    pub fn lastCommitLeader(self: *const DagState) types.Slot {
        if (self.last_commit) |c| return .{ .round = c.commit.V1.leader.round, .authority = c.commit.V1.leader.author };
        const g = self.genesis[0].reference();
        return .{ .round = g.round, .authority = g.author };
    }
    pub fn lastCommitRound(self: *const DagState) types.Round {
        return if (self.last_commit) |c| c.commit.V1.leader.round else 0;
    }
    pub fn lastCommittedRounds(self: *const DagState) []const types.Round {
        return self.last_committed_rounds;
    }

    fn setLastCommit(self: *DagState, c: types.TrustedCommit) err.Error!void {
        self.last_commit_arena.deinit();
        self.last_commit_arena = std.heap.ArenaAllocator.init(self.gpa);
        self.last_commit = try cloneCommit(self.last_commit_arena.allocator(), c);
    }

    /// Records a new commit (`add_commit`): checks index continuity and timestamp monotonicity,
    /// updates last committed rounds, queues a commit vote and the commit for the next flush.
    /// A stale index is ignored (Rust logs an error and returns).
    pub fn addCommit(self: *DagState, commit: types.TrustedCommit) err.Error!void {
        const idx = commit.commit.index();
        if (self.last_commit) |lc| {
            if (idx <= lc.commit.index()) return;
            if (idx != lc.commit.index() + 1) return error.Invariant;
            if (commit.commit.V1.timestamp_ms < lc.commit.V1.timestamp_ms) return error.Invariant;
        } else if (idx != 1) return error.Invariant;

        try self.setLastCommit(commit);
        for (commit.commit.V1.blocks) |br| {
            self.last_committed_rounds[br.author] = @max(self.last_committed_rounds[br.author], br.round);
        }
        self.pending_commit_votes.append(self.gpa, commit.reference()) catch return error.OutOfMemory;
        self.commits_to_write.append(self.gpa, try cloneCommit(self.write_arena.allocator(), commit)) catch return error.OutOfMemory;
    }

    /// `add_commit_info`: stores CommitInfo{last committed rounds, scores} for the last commit.
    /// The scoring sub-dag must have been cleared first.
    pub fn addCommitInfo(self: *DagState, scores: types.ReputationScores) err.Error!void {
        if (!self.scoring_subdag.isEmpty()) return error.Invariant;
        const lc = self.last_commit orelse return error.Invariant;
        const a = self.write_arena.allocator();
        const info: types.CommitInfo = .{
            .committed_rounds = a.dupe(types.Round, self.last_committed_rounds) catch return error.OutOfMemory,
            .reputation_scores = .{
                .scores_per_authority = a.dupe(u64, scores.scores_per_authority) catch return error.OutOfMemory,
                .commit_range = scores.commit_range,
            },
        };
        self.commit_info_to_write.append(self.gpa, .{ .ref = lc.reference(), .info = info }) catch return error.OutOfMemory;
    }

    pub fn addFinalizedCommit(self: *DagState, commit_ref: types.CommitRef, rejected: []const types.RejectedInBlock) err.Error!void {
        const a = self.write_arena.allocator();
        const rej = a.alloc(types.RejectedInBlock, rejected.len) catch return error.OutOfMemory;
        for (rej, rejected) |*o, i| o.* = .{ .block = i.block, .indices = a.dupe(types.TransactionIndex, i.indices) catch return error.OutOfMemory };
        self.finalized_to_write.append(self.gpa, .{ .ref = commit_ref, .rejected = rej }) catch return error.OutOfMemory;
    }

    /// Takes up to `out.len` pending commit votes for the next proposal, oldest first.
    pub fn takeCommitVotes(self: *DagState, out: []types.CommitVote) usize {
        const n = @min(out.len, self.pending_commit_votes.items.len);
        @memcpy(out[0..n], self.pending_commit_votes.items[0..n]);
        std.mem.copyForwards(types.CommitVote, self.pending_commit_votes.items, self.pending_commit_votes.items[n..]);
        self.pending_commit_votes.shrinkRetainingCapacity(self.pending_commit_votes.items.len - n);
        return n;
    }

    // ------------------------------------------------------------ scoring sub-dags

    pub fn addScoringSubdag(self: *DagState, sub_dag: *const types.CommittedSubDag) err.Error!void {
        self.scoring_subdag.addSubdag(sub_dag) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Invariant,
        };
    }
    pub fn clearScoringSubdag(self: *DagState) void {
        self.scoring_subdag.clear();
    }
    pub fn scoringSubdagsCount(self: *const DagState) usize {
        return self.scoring_subdag.scoredSubdagsCount();
    }
    pub fn calculateScoringSubdagScores(self: *const DagState, gpa: Allocator) err.Error!types.ReputationScores {
        return self.scoring_subdag.calculateScores(gpa) catch |e| switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.EmptyRange => error.Invariant,
        };
    }
    /// Last commit index of the scoring range (inclusive).
    pub fn scoringSubdagCommitRange(self: *const DagState) err.Error!types.CommitIndex {
        const r = self.scoring_subdag.commit_range orelse return error.Invariant;
        return r.last();
    }

    // ------------------------------------------------------------ flush

    pub fn evictionRound(last_round: types.Round, gc_round: types.Round, cached_rounds: types.Round) types.Round {
        return @min(gc_round, last_round -| cached_rounds);
    }

    /// Writes buffered blocks, commits, commit info and finalized commits as one batch, then evicts
    /// cached blocks that are below both the GC round and the per-authority cached window.
    pub fn flush(self: *DagState) err.Error!void {
        if (self.blocks_to_write.items.len == 0 and self.commits_to_write.items.len == 0 and
            self.commit_info_to_write.items.len == 0 and self.finalized_to_write.items.len == 0) return;

        var blocks: std.ArrayList(types.VerifiedBlock) = .empty;
        defer blocks.deinit(self.gpa);
        for (self.blocks_to_write.items) |b| blocks.append(self.gpa, b.*) catch return error.OutOfMemory;
        const batch: store_mod.WriteBatch = .{
            .blocks = blocks.items,
            .commits = self.commits_to_write.items,
            .commit_info = self.commit_info_to_write.items,
            .finalized_commits = self.finalized_to_write.items,
        };
        try self.store.write(&batch);
        self.blocks_to_write.clearRetainingCapacity();
        self.commits_to_write.clearRetainingCapacity();
        self.commit_info_to_write.clearRetainingCapacity();
        self.finalized_to_write.clearRetainingCapacity();
        _ = self.write_arena.reset(.retain_capacity);

        const gc = self.gcRound();
        var removed: usize = 0;
        var max_cut_round: types.Round = 0;
        for (self.refs_by_author, 0..) |*list, a| {
            const last_round: types.Round = if (list.items.len > 0) list.items[list.items.len - 1].round else 0;
            const ev = evictionRound(last_round, gc, self.cached_rounds);
            var cut: usize = 0;
            while (cut < list.items.len and list.items[cut].round <= ev) : (cut += 1) {
                if (self.recent.fetchRemove(list.items[cut])) |kv| {
                    kv.value.arena.deinit();
                    self.gpa.destroy(kv.value);
                    removed += 1;
                }
                max_cut_round = @max(max_cut_round, list.items[cut].round);
            }
            if (cut > 0) {
                std.mem.copyForwards(types.BlockRef, list.items, list.items[cut..]);
                list.shrinkRetainingCapacity(list.items.len - cut);
            }
            self.evicted_rounds[a] = ev;
        }
        // `order` is sorted by round first and every evicted ref has a round <= max_cut_round, so
        // only that prefix can hold dropped refs; nothing evicted, nothing to compact.
        if (removed == 0) return;
        var end: usize = 0;
        while (end < self.order.items.len and self.order.items[end].round <= max_cut_round) : (end += 1) {}
        var w: usize = 0;
        for (self.order.items[0..end]) |r| {
            if (self.recent.contains(r)) {
                self.order.items[w] = r;
                w += 1;
            }
        }
        if (w != end) {
            const tail = self.order.items.len - end;
            std.mem.copyForwards(types.BlockRef, self.order.items[w .. w + tail], self.order.items[end..]);
            self.order.shrinkRetainingCapacity(w + tail);
        }
    }
};

/// Deep copy of a TrustedCommit into `arena`.
pub fn cloneCommit(arena: Allocator, c: types.TrustedCommit) err.Error!types.TrustedCommit {
    const ser = arena.dupe(u8, c.serialized) catch return error.OutOfMemory;
    const dec = bcs.decode(types.Commit, arena, ser) catch return error.SerializationFailure;
    return .{ .commit = dec, .serialized = ser, .digest = c.digest };
}

/// `load_committed_subdag_from_store`: rebuilds the CommittedSubDag of a stored commit.
pub fn loadCommittedSubdag(arena: Allocator, store: store_mod.Store, commit: types.TrustedCommit) err.Error!types.CommittedSubDag {
    const refs = commit.commit.V1.blocks;
    const opts = arena.alloc(?types.VerifiedBlock, refs.len) catch return error.OutOfMemory;
    try store.readBlocks(refs, opts);
    const blocks = arena.alloc(types.VerifiedBlock, refs.len) catch return error.OutOfMemory;
    for (opts, blocks) |o, *b| b.* = o orelse return error.MissingBlock;
    var sub: types.CommittedSubDag = .{
        .leader = commit.commit.V1.leader,
        .blocks = blocks,
        .timestamp_ms = commit.commit.V1.timestamp_ms,
        .commit_ref = commit.reference(),
        .decided_with_local_blocks = true,
        .recovered_rejected_transactions = false,
        .rejected_transactions_by_block = &.{},
    };
    var found_leader = false;
    for (blocks) |b| {
        if (b.reference().eql(sub.leader)) found_leader = true;
    }
    if (!found_leader) return error.Invariant;
    if (try store.readRejectedTransactions(commit.reference())) |rej| {
        sub.decided_with_local_blocks = true;
        sub.recovered_rejected_transactions = true;
        sub.rejected_transactions_by_block = rej;
    } else {
        sub.decided_with_local_blocks = false;
    }
    return sub;
}
