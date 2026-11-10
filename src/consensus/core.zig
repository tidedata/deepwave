//! consensus_core::core::Core at mainnet-v1.83.1 (v2 path: `enable_v3` off) with the
//! ValidatorProposer (`proposer.rs`) and the CommitObserver (`commit_observer.rs`) folded in, as a
//! sans-I/O state machine. Owner lane: val-consensus-core. The network lane's core thread
//! (net/core_thread.zig) is the only caller: it feeds verified blocks, certified commits and timer
//! ticks, and carries out the `Output` (broadcast, fetch, emit committed sub-dags). Nothing here does
//! I/O, takes locks, reads clocks directly or spawns threads, so the whole core runs under the
//! deterministic simulator (seeded DAG tests) and against recorded traffic.
//!
//! Equivocation safety: a block is proposed only through `iface.BlockSigner`, which persists the
//! round before returning a signature. On startup the network lane runs `sync_last_known_own_block`
//! (highest own round known to peers) before `setLastKnownProposedRound` lets the core propose
//! (Rust: `Core::set_last_known_proposed_round`); `Deps.sync_last_known_own_block = false` skips that
//! wait (single-node tests, a fresh authority that never signed).
//!
//! Not implemented: smart ancestor selection with
//! excluded low-propagation peers (all peers stay `include`, which only costs efficiency), V3
//! consensus, the notify-committed hook to the transaction pool.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const iface = @import("iface.zig");
const digest_mod = @import("digest.zig");
const committee_mod = @import("committee.zig");
const dag_mod = @import("dag_state.zig");
const Context = @import("context.zig").Context;
const DagState = dag_mod.DagState;
const BlockManager = @import("block_manager.zig").BlockManager;
const LeaderSchedule = @import("leader_schedule.zig").LeaderSchedule;
const UniversalCommitter = @import("committer.zig").UniversalCommitter;
const Linearizer = @import("linearizer.zig").Linearizer;
const commit_finalizer = @import("commit_finalizer.zig");
const CommitFinalizer = commit_finalizer.CommitFinalizer;
const TransactionVoteTracker = @import("transaction_vote_tracker.zig").TransactionVoteTracker;

const Allocator = std.mem.Allocator;
const Agg = committee_mod.StakeAggregator(committee_mod.max_committee_size);

/// MAX_COMMIT_VOTES_PER_BLOCK (proposer.rs).
pub const max_commit_votes_per_block = 100;

/// What the core asks its driver to do after calls. Lists live in the call arenas.
pub const Output = struct {
    /// Our newly proposed (or re-emitted after recovery) blocks, to stream to subscribers
    /// (SubscribeBlocks), in order. `signals.new_block`.
    proposed: std.ArrayList(types.ExtendedBlock) = .empty,
    /// Blocks newly accepted into the DAG (peers' and ours). `signals.new_accepted_block`.
    accepted: std.ArrayList(types.VerifiedBlock) = .empty,
    /// Missing ancestors for the synchronizer to fetch (sorted unique per call).
    missing: []const types.BlockRef = &.{},
    /// Finalized sub-dags in commit index order, for the CommitSink. Each owns its memory: the
    /// driver calls `deinit` on it after use.
    committed: std.ArrayList(commit_finalizer.Finalized) = .empty,
    /// The threshold clock round advanced to this (once per call). `signals.new_round`.
    new_round: ?types.Round = null,
    /// Off by default. When set, every sub-dag the Linearizer produces is also appended to
    /// `linearized` before the CommitFinalizer sees it (the CommitObserver's input in Rust): the
    /// replay conformance suite compares these with Rust's per-step commits, since finalization may
    /// hold commits with transactions for later rounds.
    record_linearized: bool = false,
    linearized: std.ArrayList(types.CommittedSubDag) = .empty,
};

/// Peer-derived inputs the core cannot compute itself.
pub const Signals = struct {
    /// Rounds a quorum of peers lags behind our last proposal (round prober): stops proposing when it
    /// exceeds `propagation_delay_stop_proposal_threshold`.
    propagation_delay: types.Round = 0,
};

/// Rust try_commit: the locally linearized commit must equal the certified one (index and digest);
/// a mismatch means our DAG, timestamp or commit chain differs from what a quorum certified.
pub fn checkCertifiedRef(certified: types.CommitRef, local: types.CommitRef) err.Error!void {
    if (certified.index != local.index or !std.mem.eql(u8, &certified.digest, &local.digest)) return error.Invariant;
}

test "certified commit ref mismatch is an invariant failure" {
    const a: types.CommitRef = .{ .index = 7, .digest = @splat(1) };
    try checkCertifiedRef(a, a);
    var bad_digest = a;
    bad_digest.digest[31] ^= 1;
    try std.testing.expectError(error.Invariant, checkCertifiedRef(a, bad_digest));
    try std.testing.expectError(error.Invariant, checkCertifiedRef(a, .{ .index = 8, .digest = a.digest }));
}

pub const Core = struct {
    gpa: Allocator,
    context: *const Context,
    dag: *DagState,
    schedule: *LeaderSchedule,
    tracker: *TransactionVoteTracker,
    finalizer: *CommitFinalizer,
    block_manager: BlockManager,
    committer: UniversalCommitter,
    linearizer: Linearizer,
    signer: ?iface.BlockSigner,
    tx_source: ?iface.TransactionSource,

    last_signaled_round: types.Round,
    last_decided_leader: types.Slot,
    last_included_ancestors: []?types.BlockRef,
    /// Null until the last proposed round is known (no proposals before).
    last_known_proposed_round: ?types.Round,
    propagation_delay: types.Round = 0,

    pub const Deps = struct {
        context: *const Context,
        dag: *DagState,
        schedule: *LeaderSchedule,
        tracker: *TransactionVoteTracker,
        finalizer: *CommitFinalizer,
        /// Null for an observer (no proposals).
        signer: ?iface.BlockSigner = null,
        tx_source: ?iface.TransactionSource = null,
        sync_last_known_own_block: bool = true,
        /// Commits up to this index were already processed by the consumer (CommitSink
        /// `processed_through`); later stored commits are replayed through the finalizer.
        replay_after_commit_index: types.CommitIndex = 0,
    };

    /// `Core::new_validator`/`new_observer` + `recover`: replays unsent commits, rebuilds the vote
    /// tracker, then commits locally and proposes if possible.
    pub fn recover(gpa: Allocator, arena: Allocator, deps: Deps, out: *Output) err.Error!Core {
        const ctx = deps.context;
        if (ctx.protocol_config.enable_v3) return error.Unsupported;
        if (ctx.own_index != null and (deps.signer == null)) return error.Invariant;
        const n = ctx.committee.size();
        const last_included = gpa.alloc(?types.BlockRef, n) catch return error.OutOfMemory;
        errdefer gpa.free(last_included);
        @memset(last_included, null);

        var core: Core = .{
            .gpa = gpa,
            .context = ctx,
            .dag = deps.dag,
            .schedule = deps.schedule,
            .tracker = deps.tracker,
            .finalizer = deps.finalizer,
            .block_manager = BlockManager.init(gpa, ctx, deps.dag),
            .committer = try UniversalCommitter.fromProtocol(ctx, deps.dag, deps.schedule),
            .linearizer = .{ .context = ctx, .dag = deps.dag },
            .signer = deps.signer,
            .tx_source = deps.tx_source,
            .last_signaled_round = 0,
            .last_decided_leader = deps.dag.lastCommitLeader(),
            .last_included_ancestors = last_included,
            .last_known_proposed_round = if (deps.sync_last_known_own_block) null else 0,
        };
        errdefer core.block_manager.deinit();

        if (ctx.own_index != null) {
            const last = deps.dag.getLastProposedBlock().?;
            core.last_signaled_round = last.block.inner.round();
            for (last.block.inner.ancestors()) |a| core.last_included_ancestors[a.author] = a;
        } else {
            core.last_signaled_round = deps.dag.thresholdClockRound();
        }

        try core.recoverCommits(arena, deps.replay_after_commit_index, out);
        try deps.tracker.recoverBlocksAfterRound(arena, deps.dag.gcRound());

        _ = try core.tryCommit(arena, &.{}, out);
        if (ctx.own_index != null) {
            if (!(try core.tryPropose(arena, true, out))) {
                const last = deps.dag.getLastProposedBlock().?;
                out.proposed.append(arena, .{ .block = last.*, .excluded_ancestors = &.{} }) catch return error.OutOfMemory;
            }
        }
        core.trySignalNewRound(out);
        return core;
    }

    pub fn deinit(self: *Core) void {
        self.block_manager.deinit();
        self.gpa.free(self.last_included_ancestors);
    }

    // ------------------------------------------------------------ inputs

    /// `add_blocks`: verified peer blocks in. The driver must have registered each block with the
    /// `TransactionVoteTracker` (`addVotedBlock`, with the block's reject votes) first, as
    /// authority_service.rs does after verification; proposing needs the own votes. Accepts what it can, then tries to commit, propose and
    /// advance the round. Missing ancestors are reported in `out.missing`.
    pub fn addBlocks(self: *Core, arena: Allocator, blocks: []const types.VerifiedBlock, out: *Output) err.Error!void {
        const r = try self.block_manager.tryAcceptBlocks(arena, blocks);
        out.missing = r.missing;
        try appendAccepted(arena, out, r.accepted);
        if (r.accepted.len > 0) {
            _ = try self.tryCommit(arena, &.{}, out);
            _ = try self.tryPropose(arena, false, out);
            self.trySignalNewRound(out);
        }
    }

    /// `add_certified_commits`: commits fetched by the CommitSyncer with their blocks, plus the
    /// vote blocks that certify the tip. Commits must be sorted and start at last commit index + 1
    /// (older ones are skipped).
    pub fn addCertifiedCommits(self: *Core, arena: Allocator, commits: []const types.CertifiedCommit, votes: []const types.VerifiedBlock, out: *Output) err.Error!void {
        const last = self.dag.lastCommitIndex();
        var fresh: std.ArrayList(types.CertifiedCommit) = .empty;
        for (commits) |c| {
            if (c.commit.commit.index() > last) fresh.append(arena, c) catch return error.OutOfMemory;
        }
        if (fresh.items.len > 0 and fresh.items[0].commit.commit.index() != last + 1) return error.CommitIndexGap;

        const r = try self.block_manager.tryAcceptBlocks(arena, votes);
        out.missing = r.missing;
        try appendAccepted(arena, out, r.accepted);

        _ = try self.tryCommit(arena, fresh.items, out);
        _ = try self.tryPropose(arena, false, out);
        self.trySignalNewRound(out);
    }

    /// `check_block_refs`: which of `refs` the DAG still lacks (the synchronizer's periodic check).
    pub fn checkBlockRefs(self: *Core, arena: Allocator, refs: []const types.BlockRef) err.Error![]const types.BlockRef {
        return self.block_manager.tryFindBlocks(arena, refs);
    }

    /// `new_block(round, force)`: leader timeout (force) or new transactions. Proposes only if
    /// `round` is above our last proposed round.
    pub fn newBlock(self: *Core, arena: Allocator, round: types.Round, force: bool, out: *Output) err.Error!void {
        if (self.lastProposedRound()) |last| {
            if (last < round) {
                _ = try self.tryPropose(arena, force, out);
                self.trySignalNewRound(out);
            }
        }
    }

    pub fn setSignals(self: *Core, signals: Signals) void {
        self.propagation_delay = signals.propagation_delay;
    }

    /// `set_last_known_proposed_round`: after own-block sync, enables proposing above `round`.
    /// Setting it twice is a bug (Rust panics).
    pub fn setLastKnownProposedRound(self: *Core, round: types.Round) err.Error!void {
        if (self.last_known_proposed_round != null) return error.Invariant;
        self.last_known_proposed_round = round;
    }

    pub fn missingBlocks(self: *const Core) []const types.BlockRef {
        return self.block_manager.missingBlocks();
    }

    pub fn lastProposedRound(self: *const Core) ?types.Round {
        const b = self.dag.getLastProposedBlock() orelse return null;
        return b.block.inner.round();
    }

    /// Deep copies (arena) so the driver can read accepted blocks after later flushes evict them.
    fn appendAccepted(arena: Allocator, out: *Output, blocks: []const types.VerifiedBlock) err.Error!void {
        for (blocks) |*b| {
            const c = try digest_mod.cloneVerified(arena, b);
            out.accepted.append(arena, c) catch return error.OutOfMemory;
        }
    }

    fn trySignalNewRound(self: *Core, out: *Output) void {
        const r = self.dag.thresholdClockRound();
        if (r <= self.last_signaled_round) return;
        out.new_round = r;
        self.last_signaled_round = r;
    }

    // ------------------------------------------------------------ commit path

    /// `try_commit` (v2). Returns the number of sub-dags committed.
    fn tryCommit(self: *Core, arena: Allocator, certified_in: []const types.CertifiedCommit, out: *Output) err.Error!usize {
        var certified = certified_in;
        var total: usize = 0;
        while (true) {
            var until = try self.schedule.commitsUntilLeaderScheduleUpdate(self.dag);
            if (until == 0) {
                try self.schedule.updateLeaderScheduleV2(self.dag);
                until = try self.schedule.commitsUntilLeaderScheduleUpdate(self.dag);
            }
            if (until == 0) return error.Invariant;

            // try_select_certified_leaders
            var taken: []const types.CertifiedCommit = &.{};
            if (certified.len > 0) {
                const k = @min(certified.len, until);
                taken = certified[0..k];
                certified = certified[k..];
            }

            var decided: []const types.DecidedLeader = undefined;
            var local = true;
            if (taken.len == 0) {
                const d = try self.committer.tryDecide(arena, self.last_decided_leader);
                decided = if (d.len >= until) d[0..until] else d;
            } else {
                const ds = arena.alloc(types.DecidedLeader, taken.len) catch return error.OutOfMemory;
                for (ds, taken) |*o, c| {
                    if (c.blocks.len == 0) return error.Invariant;
                    const leader = &c.blocks[c.blocks.len - 1];
                    if (!leader.reference().eql(c.commit.commit.leader())) return error.Invariant;
                    o.* = .{ .commit = .{ .block = leader, .direct = false } };
                }
                decided = ds;
                local = false;
            }
            if (decided.len == 0) break;

            const last = decided[decided.len - 1];
            self.last_decided_leader = switch (last) {
                .commit => |c| .{ .round = c.block.block.inner.round(), .authority = c.block.block.inner.author() },
                .skip => |s| s,
            };

            var leaders: std.ArrayList(*const types.VerifiedBlock) = .empty;
            for (decided) |d| switch (d) {
                .commit => |c| leaders.append(arena, c.block) catch return error.OutOfMemory,
                .skip => {},
            };
            if (leaders.items.len == 0) break;

            if (local) {
                total += try self.handleCommittedLeaders(arena, leaders.items, true, null, out);
            } else {
                for (leaders.items, taken) |leader, c| {
                    try self.acceptCommittedBlocks(arena, c.blocks, out);
                    total += try self.handleCommittedLeaders(arena, &.{leader}, false, c.commit.reference(), out);
                }
            }
            // Rust emits no new_accepted_block for GC-unsuspended blocks.
            _ = try self.block_manager.tryUnsuspendBlocksForLatestGcRound(arena);
        }
        return total;
    }

    /// Hands the finalized commits to the driver's list. Each owns memory (an arena, and a hold
    /// on every block it shares with the DAG window) that the driver frees through that list: if
    /// the list cannot take them, they are freed here, since nobody else knows them.
    fn appendCommitted(arena: Allocator, out: *Output, fin: []commit_finalizer.Finalized) err.Error!void {
        out.committed.appendSlice(arena, fin) catch {
            for (fin) |*f| f.deinit();
            return error.OutOfMemory;
        };
    }

    fn acceptCommittedBlocks(self: *Core, arena: Allocator, blocks: []const types.VerifiedBlock, out: *Output) err.Error!void {
        const acc = try self.block_manager.tryAcceptCommittedBlocks(arena, blocks);
        try appendAccepted(arena, out, acc);
    }

    /// `CommitObserver::handle_committed_leaders`: linearize, mark local/certified, finalize
    /// (fast path), record scoring sub-dags.
    fn handleCommittedLeaders(self: *Core, arena: Allocator, leaders: []const *const types.VerifiedBlock, local: bool, expected: ?types.CommitRef, out: *Output) err.Error!usize {
        const subs = try self.linearizer.handleCommit(arena, leaders);
        if (out.record_linearized) out.linearized.appendSlice(arena, subs) catch return error.OutOfMemory;
        for (subs) |*s| {
            // Rust try_commit: assert_eq!(certified commit_ref, sub_dag.commit_ref).
            if (expected) |e| try checkCertifiedRef(e, s.commit_ref);
            s.decided_with_local_blocks = local;
            const fin = try self.finalizer.process(arena, s);
            try appendCommitted(arena, out, fin);
        }
        for (subs) |*s| try self.dag.addScoringSubdag(s);
        return subs.len;
    }

    /// `CommitObserver::recover_and_send_commits` (FromWatermark replay): stored commits after
    /// `replay_after` go through the finalizer again; commits without stored rejects are voted on
    /// and finalized, commits with them pass through.
    fn recoverCommits(self: *Core, arena: Allocator, replay_after: types.CommitIndex, out: *Output) err.Error!void {
        const store = self.dag.store;
        const last = (try store.readLastCommit()) orelse return;
        const last_index = last.commit.index();
        if (last_index == replay_after) return;
        if (last_index < replay_after) return error.Invariant;

        var seen_unfinalized = false;
        var index = replay_after + 1;
        while (index <= last_index) : (index += 1) {
            const commits = try store.scanCommits(arena, types.CommitRange.inclusive(index, index));
            if (commits.len != 1) return error.StoreCorrupt;
            try self.dag.recoverCommitsToWrite(commits);
            const sub = try dag_mod.loadCommittedSubdag(arena, store, commits[0]);
            if (!sub.recovered_rejected_transactions and !seen_unfinalized) seen_unfinalized = true;
            if (seen_unfinalized) {
                if (sub.recovered_rejected_transactions) return error.Invariant;
                try self.tracker.recoverAndVoteOnBlocks(arena, sub.blocks);
            }
            const fin = try self.finalizer.process(arena, &sub);
            try appendCommitted(arena, out, fin);
        }
    }

    // ------------------------------------------------------------ proposer

    pub fn shouldPropose(self: *const Core) bool {
        if (self.propagation_delay > self.context.parameters.propagation_delay_stop_proposal_threshold) return false;
        const known = self.last_known_proposed_round orelse return false;
        if (self.dag.thresholdClockRound() <= known) return false;
        return true;
    }

    /// `Core::try_propose`: one proposal if allowed; returns whether a block was created.
    pub fn tryPropose(self: *Core, arena: Allocator, force: bool, out: *Output) err.Error!bool {
        const eb = (try self.tryNewBlock(arena, force)) orelse return false;
        out.proposed.append(arena, eb) catch return error.OutOfMemory;
        try appendAccepted(arena, out, &.{eb.block});
        _ = try self.tryCommit(arena, &.{}, out);
        return true;
    }

    /// `ValidatorProposer::try_new_block`.
    fn tryNewBlock(self: *Core, arena: Allocator, force: bool) err.Error!?types.ExtendedBlock {
        const ctx = self.context;
        const signer = self.signer orelse return null;
        const own = ctx.own_index orelse return null;
        if (!self.shouldPropose()) return null;

        const dag = self.dag;
        const clock_round = dag.thresholdClockRound();
        const last_proposed = dag.getLastProposedBlock().?;
        if (clock_round <= last_proposed.block.inner.round()) return null;

        const quorum_round = clock_round -| 1;
        var leader_buf: [16]types.AuthorityIndex = undefined;
        const n_leaders = try self.committer.getLeaders(quorum_round, &leader_buf);

        const now_ms = ctx.clock.nowMs();
        if (!force) {
            for (leader_buf[0..n_leaders]) |a| {
                if (!try dag.containsCachedBlockAtSlot(.{ .round = quorum_round, .authority = a })) return null;
            }
            const since_ms = now_ms -| last_proposed.block.inner.timestampMs();
            if (@as(u128, since_ms) * std.time.ns_per_ms < ctx.parameters.min_round_delay_ns) return null;
        }

        // Ancestors: our last block first, then each peer's latest block above what we already
        // included (all peers `include`; no smart exclusion).
        const committee = &ctx.committee;
        const last_per = try dag.getLastCachedBlockPerAuthority(arena, clock_round);
        var excluded: std.ArrayList(types.BlockRef) = .empty;
        var ancestors: std.ArrayList(*const types.VerifiedBlock) = .empty;
        ancestors.append(arena, last_proposed) catch return error.OutOfMemory;
        for (last_per) |lp| {
            const a = lp.block.block.inner.author();
            if (a == own) continue;
            if (self.last_included_ancestors[a]) |lr| {
                if (lr.round >= lp.block.block.inner.round()) continue;
            }
            for (lp.equivocating) |e| try dag_mod.refSetInsert(arena, &excluded, e);
            ancestors.append(arena, lp.block) catch return error.OutOfMemory;
        }
        var parent_quorum: Agg = .{};
        for (ancestors.items) |b| {
            if (b.block.inner.round() == quorum_round) _ = parent_quorum.add(b.block.inner.author(), committee, committee.quorum_threshold);
        }
        if (!committee.reachedQuorum(parent_quorum.stake)) {
            if (!force) return null; // smart select: wait for more parents
            return error.Invariant; // Rust asserts: DagState and Core disagree
        }

        const excluded_limit = committee.size() * 2;
        const excluded_refs = if (excluded.items.len > excluded_limit) excluded.items[0..excluded_limit] else excluded.items;
        const anc_refs = arena.alloc(types.BlockRef, ancestors.items.len) catch return error.OutOfMemory;
        for (anc_refs, ancestors.items) |*o, b| {
            o.* = b.reference();
            self.last_included_ancestors[b.block.inner.author()] = o.*;
        }

        // Transactions.
        const pc = &ctx.protocol_config;
        var txs: []types.Transaction = &.{};
        if (self.tx_source) |src| {
            const buf = arena.alloc(types.Transaction, @intCast(pc.max_num_transactions_in_block)) catch return error.OutOfMemory;
            const k = src.next(buf, pc.max_transactions_in_block_bytes);
            txs = buf[0..k];
        }

        const votes_buf = arena.alloc(types.CommitVote, max_commit_votes_per_block) catch return error.OutOfMemory;
        const nv = dag.takeCommitVotes(votes_buf);
        const commit_votes = votes_buf[0..nv];

        var tx_votes: []const types.BlockTransactionVotes = &.{};
        if (pc.transaction_voting_enabled) {
            const cutoff = dag.gcRound();
            var targets: std.ArrayList(types.BlockRef) = .empty;
            for (anc_refs) |ar| {
                const linked = try dag.linkCausalHistory(arena, ar);
                for (linked) |l| if (l.round > cutoff) targets.append(arena, l) catch return error.OutOfMemory;
            }
            tx_votes = try self.tracker.getOwnVotes(arena, targets.items);
        }

        const block: types.Block = if (pc.transaction_voting_enabled)
            .{ .V2 = .{ .epoch = committee.epoch, .round = clock_round, .author = own, .timestamp_ms = now_ms, .ancestors = anc_refs, .transactions = txs, .transaction_votes = tx_votes, .commit_votes = commit_votes, .misbehavior_reports = &.{} } }
        else
            .{ .V1 = .{ .epoch = committee.epoch, .round = clock_round, .author = own, .timestamp_ms = now_ms, .ancestors = anc_refs, .transactions = txs, .commit_votes = commit_votes, .misbehavior_reports = &.{} } };

        const pending = try digest_mod.PendingBlock.init(arena, self.gpa, block);
        const signature = signer.signBlock(committee.epoch, clock_round, &pending.message) catch return error.SignRefused;
        const vb = try pending.seal(arena, &signature);

        try dag.acceptBlock(&vb);
        const in_dag = dag.getBlock(vb.reference()).?;
        if (pc.transaction_voting_enabled) {
            try self.tracker.addVotedBlock(in_dag, &.{});
            _ = try dag.linkCausalHistory(arena, vb.reference());
        }
        try dag.flush();
        if (self.tx_source) |src| src.ack(vb.reference());

        return .{ .block = in_dag.*, .excluded_ancestors = arena.dupe(types.BlockRef, excluded_refs) catch return error.OutOfMemory };
    }
};
