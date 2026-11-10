//! consensus_core::commit_finalizer::CommitFinalizer at mainnet-v1.83.1: a commit's transactions
//! become final when each is either certified (2f+1 accept votes, direct from the committed blocks'
//! vote tracker or indirect through descendants in later commits) or rejected (2f+1 reject votes, or
//! still pending `INDIRECT_REJECT_DEPTH` rounds after the leader). It records
//! `rejected_transactions_by_block` for the consensus handler. Owner lane: val-consensus-core.
//!
//! Synchronous version of Rust's finalizer task: `process` takes one committed sub-dag and returns
//! the commits that are finalized now, in commit order (Rust runs the indirect pass on blocking
//! tasks; the result is the same). The finalizer copies each sub-dag into its own arena; a
//! finalized commit hands that arena (and so the sub-dag memory) over to the caller.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const committee_mod = @import("committee.zig");
const dag_mod = @import("dag_state.zig");
const digest_mod = @import("digest.zig");
const tracker_mod = @import("transaction_vote_tracker.zig");
const store_mod = @import("store.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;
const Agg = committee_mod.StakeAggregator(committee_mod.max_committee_size);
pub const TransactionVoteTracker = tracker_mod.TransactionVoteTracker;

pub const INDIRECT_REJECT_DEPTH: types.Round = 3;

/// A finalized commit. `arena` owns all the memory of `sub_dag`; the caller frees it with `deinit`.
pub const Finalized = struct {
    arena: std.heap.ArenaAllocator,
    sub_dag: types.CommittedSubDag,
    already_finalized: bool,

    pub fn deinit(self: *Finalized) void {
        self.arena.deinit();
    }
};

fn refCmp(ctx: types.BlockRef, item: types.BlockRef) std.math.Order {
    return ctx.order(item);
}
fn idxCmp(ctx: types.TransactionIndex, item: types.TransactionIndex) std.math.Order {
    return std.math.order(ctx, item);
}
fn idxInsert(gpa: Allocator, l: *std.ArrayList(types.TransactionIndex), v: types.TransactionIndex) Allocator.Error!void {
    const pos = std.sort.lowerBound(types.TransactionIndex, l.items, v, idxCmp);
    if (pos < l.items.len and l.items[pos] == v) return;
    try l.insert(gpa, pos, v);
}
fn idxRemove(l: *std.ArrayList(types.TransactionIndex), v: types.TransactionIndex) void {
    const pos = std.sort.lowerBound(types.TransactionIndex, l.items, v, idxCmp);
    if (pos < l.items.len and l.items[pos] == v) _ = l.orderedRemove(pos);
}
fn idxContains(l: []const types.TransactionIndex, v: types.TransactionIndex) bool {
    const pos = std.sort.lowerBound(types.TransactionIndex, l, v, idxCmp);
    return pos < l.len and l[pos] == v;
}

/// BTreeMap<BlockRef, BTreeSet<TransactionIndex>>: sorted entries, sets of indices.
const TxSets = struct {
    const E = struct { ref: types.BlockRef, idx: std.ArrayList(types.TransactionIndex) = .empty };
    entries: std.ArrayList(E) = .empty,

    fn deinit(self: *TxSets, gpa: Allocator) void {
        for (self.entries.items) |*e| e.idx.deinit(gpa);
        self.entries.deinit(gpa);
    }
    fn pos(self: *const TxSets, ref: types.BlockRef) usize {
        return std.sort.lowerBound(E, self.entries.items, ref, struct {
            fn c(ctx: types.BlockRef, item: E) std.math.Order {
                return ctx.order(item.ref);
            }
        }.c);
    }
    fn getOrPut(self: *TxSets, gpa: Allocator, ref: types.BlockRef) Allocator.Error!*E {
        const p = self.pos(ref);
        if (p < self.entries.items.len and self.entries.items[p].ref.eql(ref)) return &self.entries.items[p];
        try self.entries.insert(gpa, p, .{ .ref = ref });
        return &self.entries.items[p];
    }
    fn find(self: *TxSets, ref: types.BlockRef) ?*E {
        const p = self.pos(ref);
        if (p < self.entries.items.len and self.entries.items[p].ref.eql(ref)) return &self.entries.items[p];
        return null;
    }
    fn isEmpty(self: *const TxSets) bool {
        return self.entries.items.len == 0;
    }
    /// `remove_pending_transactions`: removes the indices, and the entry when it becomes empty.
    fn removeIdxs(self: *TxSets, gpa: Allocator, ref: types.BlockRef, idxs: []const types.TransactionIndex) void {
        const p = self.pos(ref);
        if (p >= self.entries.items.len or !self.entries.items[p].ref.eql(ref)) return;
        for (idxs) |i| idxRemove(&self.entries.items[p].idx, i);
        if (self.entries.items[p].idx.items.len == 0) {
            var e = self.entries.orderedRemove(p);
            e.idx.deinit(gpa);
        }
    }
};

const PendingBlock = struct { ref: types.BlockRef, num_transactions: usize };

const CommitState = struct {
    arena: std.heap.ArenaAllocator,
    commit: types.CommittedSubDag,
    already_finalized: bool,
    pending_blocks: std.ArrayList(PendingBlock) = .empty,
    pending_transactions: TxSets = .{},
    rejected_transactions: TxSets = .{},

    fn deinit(self: *CommitState, gpa: Allocator) void {
        self.pending_blocks.deinit(gpa);
        self.pending_transactions.deinit(gpa);
        self.rejected_transactions.deinit(gpa);
        self.arena.deinit();
    }
};

const BlockState = struct {
    block: *const types.VerifiedBlock,
    children: std.ArrayList(types.BlockRef) = .empty,
    /// target block -> its rejected indices, from this block's `transaction_votes`.
    reject_votes: []const types.BlockTransactionVotes,
    origin_descendants: std.ArrayList(types.BlockRef) = .empty,
    commit_index: types.CommitIndex,
};

pub const CommitFinalizer = struct {
    gpa: Allocator,
    context: *const Context,
    dag: *dag_mod.DagState,
    votes: *TransactionVoteTracker,

    last_processed_commit: ?types.CommitIndex = null,
    pending_commits: std.ArrayList(*CommitState) = .empty,
    blocks: std.HashMapUnmanaged(types.BlockRef, *BlockState, store_mod.RefContext, 80) = .empty,

    pub fn init(gpa: Allocator, context: *const Context, dag: *dag_mod.DagState, votes: *TransactionVoteTracker) CommitFinalizer {
        return .{ .gpa = gpa, .context = context, .dag = dag, .votes = votes };
    }

    pub fn deinit(self: *CommitFinalizer) void {
        for (self.pending_commits.items) |c| {
            c.deinit(self.gpa);
            self.gpa.destroy(c);
        }
        self.pending_commits.deinit(self.gpa);
        var it = self.blocks.valueIterator();
        while (it.next()) |b| self.freeBlockState(b.*);
        self.blocks.deinit(self.gpa);
    }

    fn freeBlockState(self: *CommitFinalizer, b: *BlockState) void {
        b.children.deinit(self.gpa);
        b.origin_descendants.deinit(self.gpa);
        self.gpa.destroy(b);
    }

    pub fn isEmpty(self: *const CommitFinalizer) bool {
        return self.pending_commits.items.len == 0 and self.blocks.count() == 0;
    }

    /// The finalizer task's loop body: finalizes `sub_dag` (or passes it through when voting is off
    /// or its rejects were recovered), updates the vote tracker's GC round, records finalized commits
    /// in the DagState and flushes it. Returns the finalized commits in commit order.
    pub fn process(self: *CommitFinalizer, out: Allocator, sub_dag: *const types.CommittedSubDag) err.Error![]Finalized {
        const already = !self.context.protocol_config.transaction_voting_enabled or sub_dag.recovered_rejected_transactions;
        var finalized: []Finalized = undefined;
        if (!already) {
            finalized = try self.processCommit(out, sub_dag);
        } else {
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            errdefer arena.deinit();
            const copy = try copySubDag(arena.allocator(), sub_dag);
            const one = out.alloc(Finalized, 1) catch return error.OutOfMemory;
            one[0] = .{ .arena = arena, .sub_dag = copy, .already_finalized = true };
            finalized = one;
        }
        if (finalized.len > 0) {
            const last_round = finalized[finalized.len - 1].sub_dag.leader.round;
            try self.votes.runGc(self.dag.calculateGcRound(last_round));
            for (finalized) |f| {
                if (!f.already_finalized) try self.dag.addFinalizedCommit(f.sub_dag.commit_ref, f.sub_dag.rejected_transactions_by_block);
            }
            try self.dag.flush();
        }
        return finalized;
    }

    /// `process_commit`: queues the commit, direct-finalizes what can be, then indirect-finalizes
    /// the first pending commit while possible. Commits must arrive in index order.
    pub fn processCommit(self: *CommitFinalizer, out: Allocator, sub_dag: *const types.CommittedSubDag) err.Error![]Finalized {
        if (self.last_processed_commit) |l| {
            if (l + 1 != sub_dag.commit_ref.index) return error.Invariant;
        }
        self.last_processed_commit = sub_dag.commit_ref.index;

        _ = try self.queueCommit(sub_dag);

        var finalized: std.ArrayList(Finalized) = .empty;
        // Arenas already handed to `finalized` are ours until the caller gets the list.
        errdefer for (finalized.items) |*f| f.deinit();

        var i: usize = 0;
        while (i < self.pending_commits.items.len) : (i += 1) {
            const st = self.pending_commits.items[i];
            if (st.pending_blocks.items.len == 0) continue;
            if (!st.commit.decided_with_local_blocks) {
                const last = self.pending_commits.items[self.pending_commits.items.len - 1];
                if (st.commit.leader.round + types.MINIMUM_WAVE_LENGTH > last.commit.leader.round) break;
            }
            try self.tryDirectFinalizeCommit(out, i);
        }
        try self.popFinalizedCommits(out, &finalized);

        if (self.pending_commits.items.len > 0) {
            try self.linkBlocksInLastCommit();
            try self.appendOriginDescendantsFromLastCommit();
            while (self.pending_commits.items.len > 1) {
                if (self.pending_commits.items[0].pending_blocks.items.len != 0) break;
                try self.tryIndirectFinalizeFirstCommit(out);
                const before = finalized.items.len;
                try self.popFinalizedCommits(out, &finalized);
                if (finalized.items.len == before) break;
            }
        }
        return finalized.items;
    }

    /// Builds the CommitState and appends it to `pending_commits`. Cleanup on failure is scoped to
    /// the setup; once appended, `CommitFinalizer.deinit` owns it.
    fn queueCommit(self: *CommitFinalizer, sub_dag: *const types.CommittedSubDag) err.Error!*CommitState {
        const cs = self.gpa.create(CommitState) catch return error.OutOfMemory;
        cs.* = .{ .arena = std.heap.ArenaAllocator.init(self.gpa), .commit = undefined, .already_finalized = false };
        errdefer {
            cs.deinit(self.gpa);
            self.gpa.destroy(cs);
        }
        cs.commit = try copySubDag(cs.arena.allocator(), sub_dag);
        if (cs.commit.blocks.len == 0) return error.Invariant;
        for (cs.commit.blocks) |b| {
            try insertPendingBlock(self.gpa, &cs.pending_blocks, b.reference(), b.block.inner.transactions().len);
        }
        self.pending_commits.append(self.gpa, cs) catch return error.OutOfMemory;
        return cs;
    }

    fn insertPendingBlock(gpa: Allocator, l: *std.ArrayList(PendingBlock), ref: types.BlockRef, n: usize) err.Error!void {
        const pos = std.sort.lowerBound(PendingBlock, l.items, ref, struct {
            fn c(ctx: types.BlockRef, item: PendingBlock) std.math.Order {
                return ctx.order(item.ref);
            }
        }.c);
        if (pos < l.items.len and l.items[pos].ref.eql(ref)) return;
        l.insert(gpa, pos, .{ .ref = ref, .num_transactions = n }) catch return error.OutOfMemory;
    }

    fn tryDirectFinalizeCommit(self: *CommitFinalizer, scratch: Allocator, index: usize) err.Error!void {
        const st = self.pending_commits.items[index];
        const vote_gc_round = self.dag.calculateGcRound(st.commit.leader.round + INDIRECT_REJECT_DEPTH);
        if (st.pending_blocks.items.len == 0) return error.Invariant;
        const pending = st.pending_blocks;
        st.pending_blocks = .empty;
        defer {
            var p = pending;
            p.deinit(self.gpa);
        }
        const quorum = self.context.committee.quorum_threshold;

        for (pending.items) |pb| {
            if (pb.ref.round <= vote_gc_round and pb.num_transactions > 0) {
                const e = st.pending_transactions.getOrPut(self.gpa, pb.ref) catch return error.OutOfMemory;
                var k: usize = 0;
                while (k < pb.num_transactions) : (k += 1) idxInsert(self.gpa, &e.idx, @intCast(k)) catch return error.OutOfMemory;
                continue;
            }
            const reject_votes = (try self.votes.getRejectVotes(scratch, pb.ref)) orelse return error.MissingBlock;
            for (reject_votes) |rv| {
                if (rv.stake < quorum) {
                    const e = st.pending_transactions.getOrPut(self.gpa, pb.ref) catch return error.OutOfMemory;
                    idxInsert(self.gpa, &e.idx, rv.index) catch return error.OutOfMemory;
                } else {
                    const e = st.rejected_transactions.getOrPut(self.gpa, pb.ref) catch return error.OutOfMemory;
                    idxInsert(self.gpa, &e.idx, rv.index) catch return error.OutOfMemory;
                }
            }
        }
    }

    fn linkBlocksInLastCommit(self: *CommitFinalizer) err.Error!void {
        const st = self.pending_commits.items[self.pending_commits.items.len - 1];
        const sorted = st.arena.allocator().dupe(types.VerifiedBlock, st.commit.blocks) catch return error.OutOfMemory;
        std.sort.block(types.VerifiedBlock, sorted, {}, struct {
            fn lt(_: void, a: types.VerifiedBlock, b: types.VerifiedBlock) bool {
                return a.block.inner.round() < b.block.inner.round();
            }
        }.lt);
        for (sorted) |*b| {
            const ref = b.reference();
            for (b.block.inner.ancestors()) |anc| {
                if (self.blocks.get(anc)) |ab| dag_mod.refSetInsert(self.gpa, &ab.children, ref) catch return error.OutOfMemory;
            }
            if (!self.blocks.contains(ref)) {
                const rv = try normalizeVotes(st.arena.allocator(), b.block.inner.transactionVotes());
                const bs = self.gpa.create(BlockState) catch return error.OutOfMemory;
                errdefer self.gpa.destroy(bs);
                bs.* = .{ .block = b, .reject_votes = rv, .commit_index = st.commit.commit_ref.index };
                self.blocks.put(self.gpa, ref, bs) catch return error.OutOfMemory;
            }
        }
    }

    /// BlockState::new: BTreeMap<BlockRef, BTreeSet<TransactionIndex>> from the raw votes. A later
    /// entry for the same target replaces an earlier one; indices are a set whatever their order.
    /// V2 blocks are not checked for ordering or uniqueness by the verifier, so this must not assume it.
    fn normalizeVotes(a: Allocator, raw: []const types.BlockTransactionVotes) err.Error![]const types.BlockTransactionVotes {
        var table: std.ArrayList(types.BlockTransactionVotes) = .empty;
        for (raw) |tv| {
            const idxs = a.dupe(types.TransactionIndex, tv.rejects) catch return error.OutOfMemory;
            std.sort.block(types.TransactionIndex, idxs, {}, std.sort.asc(types.TransactionIndex));
            var w: usize = 0;
            for (idxs) |x| {
                if (w > 0 and idxs[w - 1] == x) continue;
                idxs[w] = x;
                w += 1;
            }
            const entry: types.BlockTransactionVotes = .{ .block_ref = tv.block_ref, .rejects = idxs[0..w] };
            const p = std.sort.lowerBound(types.BlockTransactionVotes, table.items, tv.block_ref, voteCmp);
            if (p < table.items.len and table.items[p].block_ref.eql(tv.block_ref)) {
                table.items[p] = entry;
            } else {
                table.insert(a, p, entry) catch return error.OutOfMemory;
            }
        }
        return table.items;
    }

    fn voteCmp(ctx: types.BlockRef, item: types.BlockTransactionVotes) std.math.Order {
        return ctx.order(item.block_ref);
    }

    fn appendOriginDescendantsFromLastCommit(self: *CommitFinalizer) err.Error!void {
        const st = self.pending_commits.items[self.pending_commits.items.len - 1];
        const sorted = st.arena.allocator().dupe(types.VerifiedBlock, st.commit.blocks) catch return error.OutOfMemory;
        std.sort.block(types.VerifiedBlock, sorted, {}, struct {
            fn lt(_: void, a: types.VerifiedBlock, b: types.VerifiedBlock) bool {
                return a.block.inner.round() < b.block.inner.round();
            }
        }.lt);
        for (sorted) |*b| {
            const ref = b.reference();
            const own = self.blocks.get(ref) orelse return error.Invariant;
            const anc = own.block.block.inner.ancestors();
            if (anc.len == 0) return error.Invariant;
            var origin = anc[0];
            while (origin.author == ref.author) {
                const ob = self.blocks.get(origin) orelse break;
                ob.origin_descendants.append(self.gpa, ref) catch return error.OutOfMemory;
                const oa = ob.block.block.inner.ancestors();
                if (oa.len == 0) return error.Invariant;
                origin = oa[0];
            }
        }
    }

    fn tryIndirectFinalizeFirstCommit(self: *CommitFinalizer, scratch: Allocator) err.Error!void {
        if (self.pending_commits.items.len == 0 or self.pending_commits.items[0].pending_blocks.items.len != 0) return error.Invariant;
        try self.checkPendingTransactionsInFirstCommit(scratch);
        try self.tryIndirectFinalizePendingTransactionsInFirstCommit(scratch);
        self.tryIndirectRejectPendingTransactionsInFirstCommit();
    }

    fn checkPendingTransactionsInFirstCommit(self: *CommitFinalizer, scratch: Allocator) err.Error!void {
        const st = self.pending_commits.items[0];
        const quorum = self.context.committee.quorum_threshold;
        const Rej = struct { ref: types.BlockRef, idxs: []types.TransactionIndex };
        var all: std.ArrayList(Rej) = .empty;
        for (st.pending_transactions.entries.items) |e| {
            const rv = (try self.votes.getRejectVotes(scratch, e.ref)) orelse return error.MissingBlock;
            var rejected: std.ArrayList(types.TransactionIndex) = .empty;
            for (e.idx.items) |idx| {
                var stake: types.Stake = 0;
                for (rv) |r| if (r.index == idx) {
                    stake = r.stake;
                    break;
                };
                if (stake < quorum) continue;
                rejected.append(scratch, idx) catch return error.OutOfMemory;
            }
            if (rejected.items.len > 0) all.append(scratch, .{ .ref = e.ref, .idxs = rejected.items }) catch return error.OutOfMemory;
        }
        for (all.items) |r| {
            st.pending_transactions.removeIdxs(self.gpa, r.ref, r.idxs);
            const e = st.rejected_transactions.getOrPut(self.gpa, r.ref) catch return error.OutOfMemory;
            for (r.idxs) |i| idxInsert(self.gpa, &e.idx, i) catch return error.OutOfMemory;
        }
    }

    fn tryIndirectFinalizePendingTransactionsInFirstCommit(self: *CommitFinalizer, scratch: Allocator) err.Error!void {
        const st = self.pending_commits.items[0];
        // (commit index, gc round of that commit's leader round) for every pending commit.
        const GcRound = struct { index: types.CommitIndex, gc: types.Round };
        const gc_rounds = scratch.alloc(GcRound, self.pending_commits.items.len) catch return error.OutOfMemory;
        for (gc_rounds, self.pending_commits.items) |*g, c| g.* = .{ .index = c.commit.commit_ref.index, .gc = self.dag.calculateGcRound(c.commit.leader.round) };

        const Fin = struct { ref: types.BlockRef, idxs: []types.TransactionIndex };
        var all: std.ArrayList(Fin) = .empty;
        for (st.pending_transactions.entries.items) |e| {
            const fin = try self.finalizeInBlock(scratch, gc_rounds, e.ref, e.idx.items);
            if (fin.len > 0) all.append(scratch, .{ .ref = e.ref, .idxs = fin }) catch return error.OutOfMemory;
        }
        for (all.items) |f| st.pending_transactions.removeIdxs(self.gpa, f.ref, f.idxs);
    }

    fn tryIndirectRejectPendingTransactionsInFirstCommit(self: *CommitFinalizer) void {
        const st = self.pending_commits.items[0];
        const last = self.pending_commits.items[self.pending_commits.items.len - 1];
        if (st.commit.leader.round + INDIRECT_REJECT_DEPTH > last.commit.leader.round) return;
        var pend = st.pending_transactions;
        st.pending_transactions = .{};
        defer pend.deinit(self.gpa);
        for (pend.entries.items) |e| {
            const r = st.rejected_transactions.getOrPut(self.gpa, e.ref) catch return;
            for (e.idx.items) |i| idxInsert(self.gpa, &r.idx, i) catch return;
        }
    }

    fn gcedVotes(gc_rounds: anytype, pending_block_round: types.Round, pending_commit_index: types.CommitIndex, current_commit_index: types.CommitIndex) err.Error!bool {
        if (pending_commit_index > current_commit_index) return error.Invariant;
        if (pending_commit_index == current_commit_index) return false;
        const k = current_commit_index - 1 - pending_commit_index;
        if (k >= gc_rounds.len) return error.Invariant;
        const g = gc_rounds[k];
        if (g.index != current_commit_index - 1) return error.Invariant;
        return pending_block_round <= g.gc;
    }

    /// `try_indirect_finalize_pending_transactions_in_block`: walks the descendants of the pending
    /// block in ref order; a transaction is finalized once descendants of 2f+1 stake (one per
    /// authority and origin chain) did not reject it.
    fn finalizeInBlock(self: *CommitFinalizer, scratch: Allocator, gc_rounds: anytype, pending_ref: types.BlockRef, pending: []const types.TransactionIndex) err.Error![]types.TransactionIndex {
        if (pending.len == 0) return &.{};
        const Acc = struct { idx: types.TransactionIndex, agg: Agg = .{} };
        const accs = scratch.alloc(Acc, pending.len) catch return error.OutOfMemory;
        for (accs, pending) |*a, p| a.* = .{ .idx = p };
        var n_acc: usize = accs.len;
        var finalized: std.ArrayList(types.TransactionIndex) = .empty;

        const pbs = self.blocks.get(pending_ref) orelse return error.MissingBlock;
        const pending_commit_index = pbs.commit_index;
        const Q = std.PriorityQueue(types.BlockRef, void, struct {
            fn lt(_: void, a: types.BlockRef, b: types.BlockRef) std.math.Order {
                return a.order(b);
            }
        }.lt);
        var to_visit: Q = Q.initContext({});
        for (pbs.children.items) |c| to_visit.push(scratch, c) catch return error.OutOfMemory;
        var visited: std.ArrayList(types.BlockRef) = .empty;
        var ignored: std.ArrayList(types.BlockRef) = .empty;
        const committee = &self.context.committee;

        while (to_visit.pop()) |cur_ref| {
            const vpos = std.sort.lowerBound(types.BlockRef, visited.items, cur_ref, refCmp);
            if (vpos < visited.items.len and visited.items[vpos].eql(cur_ref)) continue;
            visited.insert(scratch, vpos, cur_ref) catch return error.OutOfMemory;

            const cur = self.blocks.get(cur_ref) orelse return error.MissingBlock;
            const votes_gced = try gcedVotes(gc_rounds, pending_ref.round, pending_commit_index, cur.commit_index);
            const ipos = std.sort.lowerBound(types.BlockRef, ignored.items, cur_ref, refCmp);
            const already_ignored = ipos < ignored.items.len and ignored.items[ipos].eql(cur_ref);
            if (!already_ignored) {
                ignored.insert(scratch, ipos, cur_ref) catch return error.OutOfMemory;
                for (cur.origin_descendants.items) |od| dag_mod.refSetInsert(scratch, &ignored, od) catch return error.OutOfMemory;
                if (votes_gced) continue;

                // Reject votes of `cur` on the pending block.
                var cur_rejects: []const types.TransactionIndex = &.{};
                {
                    const vp = std.sort.lowerBound(types.BlockTransactionVotes, cur.reject_votes, pending_ref, voteCmp);
                    if (vp < cur.reject_votes.len and cur.reject_votes[vp].block_ref.eql(pending_ref)) cur_rejects = cur.reject_votes[vp].rejects;
                }
                var k: usize = 0;
                while (k < n_acc) {
                    const a = &accs[k];
                    if (idxContains(cur_rejects, a.idx)) {
                        k += 1;
                        continue;
                    }
                    if (!a.agg.add(cur_ref.author, committee, committee.quorum_threshold)) {
                        k += 1;
                        continue;
                    }
                    finalized.append(scratch, a.idx) catch return error.OutOfMemory;
                    accs[k] = accs[n_acc - 1];
                    n_acc -= 1;
                }
                if (n_acc == 0) break;
            }
            for (cur.children.items) |c| {
                const cp = std.sort.lowerBound(types.BlockRef, visited.items, c, refCmp);
                if (cp < visited.items.len and visited.items[cp].eql(c)) continue;
                to_visit.push(scratch, c) catch return error.OutOfMemory;
            }
        }
        return finalized.items;
    }

    fn popFinalizedCommits(self: *CommitFinalizer, out: Allocator, finalized: *std.ArrayList(Finalized)) err.Error!void {
        while (self.pending_commits.items.len > 0) {
            const st = self.pending_commits.items[0];
            if (st.pending_blocks.items.len != 0 or !st.pending_transactions.isEmpty()) break;

            // Rejected transactions by block, sorted by block ref (a BTreeMap in Rust).
            const a = st.arena.allocator();
            const rej = a.alloc(types.RejectedInBlock, st.rejected_transactions.entries.items.len) catch return error.OutOfMemory;
            for (rej, st.rejected_transactions.entries.items) |*o, e| {
                o.* = .{ .block = e.ref, .indices = a.dupe(types.TransactionIndex, e.idx.items) catch return error.OutOfMemory };
            }
            var commit = st.commit;
            commit.rejected_transactions_by_block = rej;
            finalized.ensureUnusedCapacity(out, 1) catch return error.OutOfMemory;
            _ = self.pending_commits.orderedRemove(0);

            for (commit.blocks) |b| {
                if (self.blocks.fetchRemove(b.reference())) |kv| self.freeBlockState(kv.value);
            }
            // Transfer the arena to the caller.
            const arena = st.arena;
            st.pending_blocks.deinit(self.gpa);
            st.pending_transactions.deinit(self.gpa);
            st.rejected_transactions.deinit(self.gpa);
            self.gpa.destroy(st);
            finalized.appendAssumeCapacity(.{ .arena = arena, .sub_dag = commit, .already_finalized = false });
        }
    }
};

/// Deep copy of a sub-dag into `arena`.
pub fn copySubDag(arena: Allocator, s: *const types.CommittedSubDag) err.Error!types.CommittedSubDag {
    const blocks = arena.alloc(types.VerifiedBlock, s.blocks.len) catch return error.OutOfMemory;
    for (blocks, s.blocks) |*o, *b| o.* = try digest_mod.cloneVerified(arena, b);
    const rej = arena.alloc(types.RejectedInBlock, s.rejected_transactions_by_block.len) catch return error.OutOfMemory;
    for (rej, s.rejected_transactions_by_block) |*o, r| o.* = .{ .block = r.block, .indices = arena.dupe(types.TransactionIndex, r.indices) catch return error.OutOfMemory };
    var c = s.*;
    c.blocks = blocks;
    c.rejected_transactions_by_block = rej;
    return c;
}

// ---------------------------------------------------------------- tests (ported from commit_finalizer.rs)

const test_dag = @import("test_dag.zig");
const verifier_mod = @import("verifier.zig");

const tx_data: [16]u8 = @splat(1);

const TestEnv = struct {
    f: *test_dag.Fixture,
    noop: verifier_mod.NoopTransactionVerifier = .{},
    tracker: TransactionVoteTracker,
    fin: CommitFinalizer,
    lin: @import("linearizer.zig").Linearizer,

    fn init(gpa: Allocator) !*TestEnv {
        var stakes = test_dag.Fixture.equalStakes(4);
        const self = try gpa.create(TestEnv);
        self.f = try test_dag.Fixture.init(gpa, .{ .stakes = &stakes, .protocol = .{ .gc_depth = 5, .transaction_voting_enabled = true, .num_leaders_per_round = 1, .bad_nodes_stake_threshold = 30 }, .parameters = .{ .skip_equivocation_validation = true } });
        self.noop = .{};
        self.tracker = TransactionVoteTracker.init(gpa, self.f.context, self.f.dag, self.noop.verifier());
        self.fin = CommitFinalizer.init(gpa, self.f.context, self.f.dag, &self.tracker);
        self.lin = self.f.linearizer();
        return self;
    }
    fn deinit(self: *TestEnv, gpa: Allocator) void {
        self.fin.deinit();
        self.tracker.deinit();
        self.f.deinit();
        gpa.destroy(self);
    }

    /// `create_block`: own authority first among ancestors, `n` transactions of 16 bytes.
    fn createBlock(self: *TestEnv, round: types.Round, author: types.AuthorityIndex, ancestors: []const types.BlockRef, n: usize, votes: []const types.BlockTransactionVotes) !types.VerifiedBlock {
        const a = self.f.arena();
        const anc = try a.dupe(types.BlockRef, ancestors);
        const i = for (anc, 0..) |r, k| {
            if (r.author == author) break k;
        } else return error.NoSelfAncestor;
        const first = anc[i];
        std.mem.copyBackwards(types.BlockRef, anc[1 .. i + 1], anc[0..i]);
        anc[0] = first;
        const txs = try a.alloc(types.Transaction, n);
        for (txs) |*t| t.* = .{ .data = &tx_data };
        const block: types.Block = .{ .V2 = .{ .epoch = 0, .round = round, .author = author, .timestamp_ms = round * 1000 + author, .ancestors = anc, .transactions = txs, .transaction_votes = try a.dupe(types.BlockTransactionVotes, votes), .commit_votes = &.{}, .misbehavior_reports = &.{} } };
        return digest_mod.verifiedForTest(a, block);
    }

    fn addBlocks(self: *TestEnv, blocks: []const types.VerifiedBlock) !void {
        for (blocks) |*b| {
            try self.tracker.addVotedBlock(b, &.{});
            try self.f.dag.acceptBlock(b);
        }
    }
    fn refs(self: *TestEnv, blocks: []const types.VerifiedBlock) ![]types.BlockRef {
        const out = try self.f.arena().alloc(types.BlockRef, blocks.len);
        for (out, blocks) |*o, b| o.* = b.reference();
        return out;
    }
};

test "V2 vote normalization: last duplicate target wins, rejects are a set" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const x: types.BlockRef = .{ .round = 1, .author = 2, .digest = @splat(3) };
    const y: types.BlockRef = .{ .round = 1, .author = 1, .digest = @splat(3) };
    const raw = [_]types.BlockTransactionVotes{
        .{ .block_ref = x, .rejects = &.{1} },
        .{ .block_ref = y, .rejects = &.{ 5, 1, 5 } },
        .{ .block_ref = x, .rejects = &.{} },
    };
    const t = try CommitFinalizer.normalizeVotes(arena.allocator(), &raw);
    try std.testing.expectEqual(@as(usize, 2), t.len);
    try std.testing.expect(t[0].block_ref.eql(y)); // sorted by block ref
    try std.testing.expectEqualSlices(types.TransactionIndex, &.{ 1, 5 }, t[0].rejects);
    try std.testing.expect(t[1].block_ref.eql(x));
    try std.testing.expectEqual(@as(usize, 0), t[1].rejects.len); // last entry wins: no reject
}

test "direct finalize with no reject votes" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    const a = env.f.arena();

    var prev: []const types.BlockRef = env.f.genesisRefs();
    var round2_leader: ?types.VerifiedBlock = null;
    for (1..5) |r| {
        const blocks = try a.alloc(types.VerifiedBlock, 4);
        for (blocks, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), prev, 10, &.{});
        try env.addBlocks(blocks);
        if (r == 2) round2_leader = blocks[1];
        prev = try env.refs(blocks);
    }
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const leader = env.f.dag.getBlock(round2_leader.?.reference()).?;
    const subs = try env.lin.handleCommit(scratch.allocator(), &.{leader});
    try std.testing.expectEqual(@as(usize, 1), subs.len);
    const out = try env.fin.processCommit(scratch.allocator(), &subs[0]);
    try std.testing.expectEqual(@as(usize, 1), out.len);
    try std.testing.expectEqual(subs[0].commit_ref.index, out[0].sub_dag.commit_ref.index);
    try std.testing.expectEqual(@as(usize, 0), out[0].sub_dag.rejected_transactions_by_block.len);
    for (out) |*o| @constCast(o).deinit();
    try std.testing.expect(env.fin.isEmpty());
}

test "direct finalize with reject votes" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    const a = env.f.arena();

    const r1 = try a.alloc(types.VerifiedBlock, 4);
    for (r1, 0..) |*b, au| b.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, &.{});
    // Our own reject votes (txns 0 and 3) for authority 3's block.
    for (r1) |*b| {
        const rej: []const types.TransactionIndex = if (b.block.inner.author() == 3) &.{ 0, 3 } else &.{};
        try env.tracker.addVotedBlock(b, rej);
        try env.f.dag.acceptBlock(b);
    }
    const rejected_block = r1[3].reference();
    const reject_vote: types.BlockTransactionVotes = .{ .block_ref = rejected_block, .rejects = &.{ 0, 3 } };
    const r1_refs = try env.refs(r1);

    const r2 = [_]types.VerifiedBlock{
        try env.createBlock(2, 0, r1_refs, 10, &.{reject_vote}),
        try env.createBlock(2, 1, r1_refs[0..3], 10, &.{}),
        try env.createBlock(2, 2, r1_refs[0..3], 10, &.{}),
    };
    try env.addBlocks(&r2);
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const leader = env.f.dag.getBlock(r2[0].reference()).?;
    const subs = try env.lin.handleCommit(scratch.allocator(), &.{leader});
    try std.testing.expectEqual(@as(usize, 5), subs[0].blocks.len);

    const r2_refs = try env.refs(&r2);
    const self_anc = try a.dupe(types.BlockRef, &.{rejected_block});
    const r3_anc3 = try std.mem.concat(a, types.BlockRef, &.{ self_anc, r2_refs });
    const r3 = [_]types.VerifiedBlock{
        try env.createBlock(3, 0, r2_refs, 0, &.{}),
        try env.createBlock(3, 1, r2_refs, 0, &.{reject_vote}),
        try env.createBlock(3, 2, r2_refs, 0, &.{reject_vote}),
        try env.createBlock(3, 3, r3_anc3, 0, &.{reject_vote}),
    };
    try env.addBlocks(&r3);
    const r3_refs = try env.refs(&r3);
    var r4: [4]types.VerifiedBlock = undefined;
    for (&r4, 0..) |*b, au| b.* = try env.createBlock(4, @intCast(au), r3_refs, 0, &.{});
    try env.addBlocks(&r4);

    const out = try env.fin.processCommit(scratch.allocator(), &subs[0]);
    try std.testing.expectEqual(@as(usize, 1), out.len);
    const rej = out[0].sub_dag.rejected_transactions_by_block;
    try std.testing.expectEqual(@as(usize, 1), rej.len);
    try std.testing.expect(rej[0].block.eql(rejected_block));
    try std.testing.expectEqualSlices(types.TransactionIndex, &.{ 0, 3 }, rej[0].indices);
    for (out) |*o| @constCast(o).deinit();
    try std.testing.expect(env.fin.isEmpty());
}

test "indirect finalize: late reject quorum, indirect reject, indirect finalize" {
    const gpa = std.testing.allocator;
    const env = try TestEnv.init(gpa);
    defer env.deinit(gpa);
    const a = env.f.arena();

    const r1 = try a.alloc(types.VerifiedBlock, 4);
    for (r1, 0..) |*b, au| b.* = try env.createBlock(1, @intCast(au), env.f.genesisRefs(), 10, &.{});
    for (r1) |*b| {
        const rej: []const types.TransactionIndex = if (b.block.inner.author() == 3) &.{ 0, 3 } else &.{};
        try env.tracker.addVotedBlock(b, rej);
        try env.f.dag.acceptBlock(b);
    }
    const target = r1[3].reference();
    const r1_refs = try env.refs(r1);

    const r2 = [_]types.VerifiedBlock{
        try env.createBlock(2, 0, r1_refs, 10, &.{.{ .block_ref = target, .rejects = &.{ 1, 4 } }}),
        try env.createBlock(2, 1, r1_refs[0..3], 10, &.{}),
        try env.createBlock(2, 2, r1_refs[0..3], 10, &.{}),
    };
    try env.addBlocks(&r2);
    var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
    try leaders.append(a, env.f.dag.getBlock(r2[0].reference()).?);

    const r2_refs = try env.refs(&r2);
    const r3_anc3 = try std.mem.concat(a, types.BlockRef, &.{ &[_]types.BlockRef{target}, r2_refs });
    const r3 = [_]types.VerifiedBlock{
        try env.createBlock(3, 0, r2_refs, 0, &.{}),
        try env.createBlock(3, 1, r2_refs, 0, &.{.{ .block_ref = target, .rejects = &.{ 1, 4, 7 } }}),
        try env.createBlock(3, 3, r3_anc3, 0, &.{}),
    };
    try env.addBlocks(&r3);
    try leaders.append(a, env.f.dag.getBlock(r3[2].reference()).?);

    const r3_refs = try env.refs(&r3);
    const r4_anc2 = try std.mem.concat(a, types.BlockRef, &.{ &[_]types.BlockRef{r2[2].reference()}, r3_refs });
    const r4 = [_]types.VerifiedBlock{
        try env.createBlock(4, 0, r3_refs, 0, &.{}),
        try env.createBlock(4, 1, r3_refs, 0, &.{}),
        try env.createBlock(4, 2, r4_anc2, 0, &.{.{ .block_ref = target, .rejects = &.{1} }}),
        try env.createBlock(4, 3, r3_refs, 0, &.{}),
    };
    try env.addBlocks(&r4);
    try leaders.append(a, env.f.dag.getBlock(r4[1].reference()).?);

    var last: []const types.BlockRef = try env.refs(&r4);
    for (5..6) |r| {
        const bl = try a.alloc(types.VerifiedBlock, 4);
        for (bl, 0..) |*b, au| b.* = try env.createBlock(@intCast(r), @intCast(au), last, 0, &.{});
        try env.addBlocks(bl);
        try leaders.append(a, env.f.dag.getBlock(bl[0].reference()).?);
        last = try env.refs(bl);
    }
    try std.testing.expectEqual(@as(usize, 4), leaders.items.len);

    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const subs = try env.lin.handleCommit(scratch.allocator(), leaders.items);
    for (subs[0..3]) |*s| {
        const out = try env.fin.processCommit(scratch.allocator(), s);
        try std.testing.expectEqual(@as(usize, 0), out.len);
    }
    const out = try env.fin.processCommit(scratch.allocator(), &subs[3]);
    try std.testing.expectEqual(@as(usize, 4), out.len);
    const rej = out[0].sub_dag.rejected_transactions_by_block;
    try std.testing.expectEqual(@as(usize, 1), rej.len);
    try std.testing.expect(rej[0].block.eql(target));
    try std.testing.expectEqualSlices(types.TransactionIndex, &.{ 1, 4 }, rej[0].indices);
    for (out[1..]) |o| try std.testing.expectEqual(@as(usize, 0), o.sub_dag.rejected_transactions_by_block.len);
    for (out) |*o| @constCast(o).deinit();
    try std.testing.expect(env.fin.isEmpty());
}
