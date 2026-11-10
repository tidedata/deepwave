//! The Mysticeti commit rule at mainnet-v1.83.1: consensus_core::universal_committer and
//! base_committer (direct decision: 2f+1 certificates for the leader in the decision round;
//! indirect decision through an anchor at least one wave later; skip on 2f+1 blames). Wave length 3,
//! pipelined, `mysticeti_num_leaders_per_round` leaders per round (1 on mainnet 141). Owner lane:
//! val-consensus-core. FlexCommitter (`flex_committer.rs`) is V3-only and off on mainnet.
//!
//! Every function is idempotent and allocation-free apart from the caller's `arena` for the
//! decision's temporary lists. Rust panics (an impossible second certified leader, a missing block
//! above the GC round) are `error.Invariant` / `error.MissingBlock`: the caller stops consensus.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const committee_mod = @import("committee.zig");
const dag_mod = @import("dag_state.zig");
const store_mod = @import("store.zig");
const Context = @import("context.zig").Context;
const LeaderSchedule = @import("leader_schedule.zig").LeaderSchedule;

const Allocator = std.mem.Allocator;
const Agg = committee_mod.StakeAggregator(committee_mod.max_committee_size);
const Block = *const types.VerifiedBlock;
const VoteCache = std.HashMapUnmanaged(types.BlockRef, bool, store_mod.RefContext, 80);

pub const WaveNumber = u32;

/// consensus_core::commit::LeaderStatus.
pub const LeaderStatus = union(enum) {
    commit: Block,
    skip: types.Slot,
    undecided: types.Slot,

    pub fn round(s: LeaderStatus) types.Round {
        return switch (s) {
            .commit => |b| b.block.inner.round(),
            .skip, .undecided => |slot| slot.round,
        };
    }
    pub fn isDecided(s: LeaderStatus) bool {
        return s != .undecided;
    }
};

pub const Decision = enum { direct, indirect, certified };

pub const BaseCommitterOptions = struct {
    wave_length: u32 = types.MINIMUM_WAVE_LENGTH,
    leader_offset: u32 = 0,
    round_offset: u32 = 0,
};

pub const BaseCommitter = struct {
    context: *const Context,
    dag: *const dag_mod.DagState,
    schedule: *const LeaderSchedule,
    options: BaseCommitterOptions = .{},

    pub fn leaderRound(self: *const BaseCommitter, wave: WaveNumber) types.Round {
        return wave * self.options.wave_length + self.options.round_offset;
    }
    pub fn decisionRound(self: *const BaseCommitter, wave: WaveNumber) types.Round {
        const l = self.options.wave_length;
        return wave * l + l - 1 + self.options.round_offset;
    }
    pub fn waveNumber(self: *const BaseCommitter, round: types.Round) WaveNumber {
        return (round -| self.options.round_offset) / self.options.wave_length;
    }

    /// `elect_leader`: the leader slot of `round` for this committer, or null if `round` is not a
    /// leader round of its pipeline stage.
    pub fn electLeader(self: *const BaseCommitter, round: types.Round) err.Error!?types.Slot {
        const wave = self.waveNumber(round);
        if (self.leaderRound(wave) != round) return null;
        return .{ .round = round, .authority = try self.schedule.electLeader(round, self.options.leader_offset) };
    }

    /// `try_direct_decide`.
    pub fn tryDirectDecide(self: *const BaseCommitter, arena: Allocator, leader: types.Slot) err.Error!LeaderStatus {
        const voting_round = leader.round + 1;
        if (try self.enoughLeaderBlame(arena, voting_round, leader.authority)) return .{ .skip = leader };

        const wave = self.waveNumber(leader.round);
        const decision_round = self.decisionRound(wave);
        const leader_blocks = try self.dag.getUncommittedBlocksAtSlot(arena, leader);
        var found: ?Block = null;
        for (leader_blocks) |lb| {
            if (try self.enoughLeaderSupport(arena, decision_round, lb)) {
                if (found != null) return error.Invariant; // two supported candidates in one slot
                found = lb;
            }
        }
        if (found) |b| return .{ .commit = b };
        return .{ .undecided = leader };
    }

    /// `try_indirect_decide`. `leaders` are the already decided statuses of higher rounds, lowest
    /// round first (the committer's deque from the front).
    pub fn tryIndirectDecide(self: *const BaseCommitter, arena: Allocator, leader_slot: types.Slot, leaders: []const LeaderStatus) err.Error!LeaderStatus {
        for (leaders) |anchor| {
            if (leader_slot.round + self.options.wave_length > anchor.round()) continue;
            switch (anchor) {
                .commit => |a| return self.decideLeaderFromAnchor(arena, a, leader_slot),
                .skip => {},
                .undecided => break,
            }
        }
        return .{ .undecided = leader_slot };
    }

    /// `find_supported_block`: the block at `leader_slot` that `from` supports (reaches first in
    /// ancestor order), if any.
    fn findSupportedBlock(self: *const BaseCommitter, leader_slot: types.Slot, from: Block) err.Error!?types.BlockRef {
        if (from.block.inner.round() < leader_slot.round) return null;
        for (from.block.inner.ancestors()) |anc| {
            if (anc.round == leader_slot.round and anc.author == leader_slot.authority) return anc;
            if (anc.round <= leader_slot.round) continue;
            const b = self.dag.getBlock(anc) orelse return error.MissingBlock;
            if (try self.findSupportedBlock(leader_slot, b)) |s| return s;
        }
        return null;
    }

    fn isVote(self: *const BaseCommitter, potential_vote: Block, leader_block: Block) err.Error!bool {
        const r = leader_block.reference();
        const s = (try self.findSupportedBlock(.{ .round = r.round, .authority = r.author }, potential_vote)) orelse return false;
        return s.eql(r);
    }

    /// `is_certificate`: `potential_certificate` references a quorum of votes for `leader_block`.
    /// `all_votes` caches per-ancestor vote results for the same leader block.
    fn isCertificate(self: *const BaseCommitter, arena: Allocator, potential_certificate: Block, leader_block: Block, all_votes: *VoteCache) err.Error!bool {
        const gc = self.dag.gcRound();
        var agg: Agg = .{};
        const committee = &self.context.committee;
        for (potential_certificate.block.inner.ancestors()) |reference| {
            const is_vote = if (all_votes.get(reference)) |v| v else blk: {
                const v = if (self.dag.getBlock(reference)) |pv|
                    try self.isVote(pv, leader_block)
                else if (reference.round <= gc) false else return error.MissingBlock;
                all_votes.put(arena, reference, v) catch return error.OutOfMemory;
                break :blk v;
            };
            if (is_vote) {
                if (agg.add(reference.author, committee, committee.quorum_threshold)) return true;
            }
        }
        return false;
    }

    /// `decide_leader_from_anchor`.
    fn decideLeaderFromAnchor(self: *const BaseCommitter, arena: Allocator, anchor: Block, leader_slot: types.Slot) err.Error!LeaderStatus {
        const leader_blocks = try self.dag.getUncommittedBlocksAtSlot(arena, leader_slot);
        const wave = self.waveNumber(leader_slot.round);
        const decision_round = self.decisionRound(wave);
        const potential = try self.dag.ancestorsAtRound(arena, anchor, decision_round);
        var certified: ?Block = null;
        for (leader_blocks) |lb| {
            var votes: VoteCache = .empty;
            var any = false;
            for (potential) |pc| {
                if (try self.isCertificate(arena, pc, lb, &votes)) {
                    any = true;
                    break;
                }
            }
            if (any) {
                if (certified != null) return error.Invariant;
                certified = lb;
            }
        }
        if (certified) |b| return .{ .commit = b };
        return .{ .skip = leader_slot };
    }

    /// `enough_leader_blame`: 2f+1 stake of blocks at the voting round that do not reference the leader.
    fn enoughLeaderBlame(self: *const BaseCommitter, arena: Allocator, voting_round: types.Round, leader: types.AuthorityIndex) err.Error!bool {
        const voting_blocks = try self.dag.getUncommittedBlocksAtRound(arena, voting_round);
        const committee = &self.context.committee;
        var agg: Agg = .{};
        for (voting_blocks) |vb| {
            const blame = for (vb.block.inner.ancestors()) |a| {
                if (a.author == leader) break false;
            } else true;
            if (blame and agg.add(vb.block.inner.author(), committee, committee.quorum_threshold)) return true;
        }
        return false;
    }

    /// `enough_leader_support`: 2f+1 stake of decision-round blocks that certify the leader block.
    fn enoughLeaderSupport(self: *const BaseCommitter, arena: Allocator, decision_round: types.Round, leader_block: Block) err.Error!bool {
        const decision_blocks = try self.dag.getUncommittedBlocksAtRound(arena, decision_round);
        const committee = &self.context.committee;
        var total: u64 = 0;
        for (decision_blocks) |b| total += committee.stake(b.block.inner.author());
        if (!committee.reachedQuorum(total)) return false;

        var agg: Agg = .{};
        var votes: VoteCache = .empty;
        for (decision_blocks) |db| {
            if (try self.isCertificate(arena, db, leader_block, &votes) and agg.add(db.block.inner.author(), committee, committee.quorum_threshold)) return true;
        }
        return false;
    }
};

/// Maximum committers: wave length 3 x leaders per round. Fixed capacity, no allocation.
pub const max_committers = 3 * 16;

pub const UniversalCommitter = struct {
    context: *const Context,
    dag: *const dag_mod.DagState,
    schedule: *const LeaderSchedule,
    committers: [max_committers]BaseCommitter = undefined,
    n_committers: usize = 0,

    /// `UniversalCommitterBuilder::new(...).with_number_of_leaders(n).with_pipeline(pipeline).build()`.
    /// Core builds it with the protocol's `num_leaders_per_round` (default 1) and pipelining on.
    pub fn init(context: *const Context, dag: *const dag_mod.DagState, schedule: *const LeaderSchedule, number_of_leaders: usize, pipeline: bool) err.Error!UniversalCommitter {
        const wave_length: u32 = types.MINIMUM_WAVE_LENGTH;
        const stages: u32 = if (pipeline) wave_length else 1;
        if (number_of_leaders == 0 or number_of_leaders > 16) return error.Unsupported;
        var u: UniversalCommitter = .{ .context = context, .dag = dag, .schedule = schedule };
        var round_offset: u32 = 0;
        while (round_offset < stages) : (round_offset += 1) {
            var leader_offset: u32 = 0;
            while (leader_offset < number_of_leaders) : (leader_offset += 1) {
                u.committers[u.n_committers] = .{
                    .context = context,
                    .dag = dag,
                    .schedule = schedule,
                    .options = .{ .wave_length = wave_length, .round_offset = round_offset, .leader_offset = leader_offset },
                };
                u.n_committers += 1;
            }
        }
        return u;
    }

    pub fn fromProtocol(context: *const Context, dag: *const dag_mod.DagState, schedule: *const LeaderSchedule) err.Error!UniversalCommitter {
        return init(context, dag, schedule, context.protocol_config.num_leaders_per_round orelse 1, true);
    }

    /// `try_decide`: decides every leader slot after `last_decided` that can be decided now, as the
    /// longest decided prefix in slot order. The result (and everything it points to) lives in
    /// `arena` or the DAG; pointers stay valid until the next DAG flush.
    pub fn tryDecide(self: *const UniversalCommitter, arena: Allocator, last_decided: types.Slot) err.Error![]types.DecidedLeader {
        const highest = self.dag.highestAcceptedRound();
        const last_round: types.Round = if (self.context.protocol_config.num_leaders_per_round) |n|
            (if (n == 1) last_decided.round + 1 else last_decided.round)
        else
            last_decided.round;

        // Pushed in descending round order; the Rust deque is read front to back = reverse.
        const Entry = struct { status: LeaderStatus, decision: Decision };
        var pushed: std.ArrayList(Entry) = .empty;
        var statuses: std.ArrayList(LeaderStatus) = .empty; // mirrors `pushed` for the anchor scan

        const top = highest -| 2;
        if (last_round <= top) {
            var round = top;
            outer: while (true) : (round -= 1) {
                var ci = self.n_committers;
                while (ci > 0) {
                    ci -= 1;
                    const committer = &self.committers[ci];
                    const slot = (try committer.electLeader(round)) orelse continue;
                    if (slot.round == last_decided.round and slot.authority == last_decided.authority) break :outer;

                    var status = try committer.tryDirectDecide(arena, slot);
                    var decision: Decision = .direct;
                    if (!status.isDecided()) {
                        // Anchors: pushed statuses from the front (lowest round) upward.
                        const anchors = try arena.alloc(LeaderStatus, statuses.items.len);
                        for (anchors, 0..) |*a, k| a.* = statuses.items[statuses.items.len - 1 - k];
                        status = try committer.tryIndirectDecide(arena, slot, anchors);
                        decision = .indirect;
                    }
                    pushed.append(arena, .{ .status = status, .decision = decision }) catch return error.OutOfMemory;
                    statuses.append(arena, status) catch return error.OutOfMemory;
                }
                if (round == last_round) break;
            }
        }

        var decided: std.ArrayList(types.DecidedLeader) = .empty;
        var k = pushed.items.len;
        while (k > 0) {
            k -= 1;
            const e = pushed.items[k];
            if (e.status.round() == types.GENESIS_ROUND) continue;
            switch (e.status) {
                .commit => |b| decided.append(arena, .{ .commit = .{ .block = b, .direct = e.decision == .direct } }) catch return error.OutOfMemory,
                .skip => |s| decided.append(arena, .{ .skip = s }) catch return error.OutOfMemory,
                .undecided => break,
            }
        }
        return decided.items;
    }

    /// `get_leaders`: leader authorities of `round` across committers (empty if not a leader round).
    pub fn getLeaders(self: *const UniversalCommitter, round: types.Round, out: []types.AuthorityIndex) err.Error!usize {
        var n: usize = 0;
        for (self.committers[0..self.n_committers]) |*c| {
            const slot = (try c.electLeader(round)) orelse continue;
            if (n >= out.len) return error.Invariant;
            out[n] = slot.authority;
            n += 1;
        }
        return n;
    }
};
