//! Leader election at mainnet-v1.83.1: consensus_core::leader_schedule::LeaderSchedule (stake
//! weighted election seeded by the round, then swapped through the LeaderSwapTable built from
//! reputation scores every `num_commits_per_schedule` (300) commits) and the distributed vote
//! scoring of leader_scoring.rs. The random draws reproduce rand 0.8.5 `StdRng` (ChaCha12) bit for
//! bit (rand.zig). V3 (`leader_schedule_v3.rs`) is behind `enable_v3` and off on mainnet; deepwave
//! refuses it. Owner lane: val-consensus-core.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const rand = @import("rand.zig");
const Context = @import("context.zig").Context;
const committee_mod = @import("committee.zig");
const dag_mod = @import("dag_state.zig");
const scoring = @import("leader_scoring.zig");

const Allocator = std.mem.Allocator;

pub const LeaderSwapTable = struct {
    /// The f (by `consensus_bad_nodes_stake_threshold`) best scoring authorities, used in place of
    /// bad nodes. Iteration order of the sorted score list.
    good_nodes: []const types.AuthorityIndex = &.{},
    /// The worst scoring authorities, ascending authority index (a BTreeMap in Rust).
    bad_nodes: []const types.AuthorityIndex = &.{},
    reputation_scores: types.ReputationScores = .{ .scores_per_authority = &.{}, .commit_range = .{ .start = 0, .end_exclusive = 0 } },

    pub fn deinit(self: *LeaderSwapTable, gpa: Allocator) void {
        gpa.free(self.good_nodes);
        gpa.free(self.bad_nodes);
        gpa.free(self.reputation_scores.scores_per_authority);
        self.* = .{};
    }

    /// `LeaderSwapTable::new`. `reputation_scores` is copied. Errors: threshold outside [0, 33] or a
    /// score vector of the wrong length are `error.Invariant` (Rust asserts).
    pub fn init(gpa: Allocator, committee: *const committee_mod.Committee, swap_stake_threshold: u64, commit_index: types.CommitIndex, scores: types.ReputationScores) err.Error!LeaderSwapTable {
        if (swap_stake_threshold > 33) return error.Invariant;
        if (scores.scores_per_authority.len == 0) return .{};
        if (scores.scores_per_authority.len != committee.size()) return error.Invariant;

        var seed: [32]u8 = @splat(0);
        std.mem.writeInt(u32, seed[28..32], commit_index, .little);
        var rng = rand.ChaCha12.fromSeed(seed);

        const by_score = scoring.authoritiesByScore(gpa, scores.scores_per_authority) catch return error.OutOfMemory;
        defer gpa.free(by_score);
        rng.shuffle(scoring.ScoredAuthority, by_score);
        // sort_by_key(Reverse(score)) is stable.
        std.sort.block(scoring.ScoredAuthority, by_score, {}, struct {
            fn lt(_: void, a: scoring.ScoredAuthority, b: scoring.ScoredAuthority) bool {
                return a.score > b.score;
            }
        }.lt);

        const good = firstNodes(gpa, committee, by_score, false, swap_stake_threshold) catch return error.OutOfMemory;
        errdefer gpa.free(good);
        const bad = firstNodes(gpa, committee, by_score, true, swap_stake_threshold) catch return error.OutOfMemory;
        errdefer gpa.free(bad);
        std.mem.sort(types.AuthorityIndex, bad, {}, std.sort.asc(types.AuthorityIndex));
        const owned = gpa.dupe(u64, scores.scores_per_authority) catch return error.OutOfMemory;
        return .{
            .good_nodes = good,
            .bad_nodes = bad,
            .reputation_scores = .{ .scores_per_authority = owned, .commit_range = scores.commit_range },
        };
    }

    /// `retrieve_first_nodes`.
    fn firstNodes(gpa: Allocator, committee: *const committee_mod.Committee, sorted: []const scoring.ScoredAuthority, reverse: bool, threshold: u64) Allocator.Error![]types.AuthorityIndex {
        var out: std.ArrayList(types.AuthorityIndex) = .empty;
        errdefer out.deinit(gpa);
        var stake: u64 = 0;
        const cutoff = @as(u128, threshold) * committee.total_stake / 100;
        var k: usize = 0;
        while (k < sorted.len) : (k += 1) {
            const e = if (reverse) sorted[sorted.len - 1 - k] else sorted[k];
            stake += committee.stake(e.authority);
            if (stake > cutoff) break;
            try out.append(gpa, e.authority);
        }
        return out.toOwnedSlice(gpa);
    }

    pub fn isBad(self: *const LeaderSwapTable, a: types.AuthorityIndex) bool {
        return std.mem.indexOfScalar(types.AuthorityIndex, self.bad_nodes, a) != null;
    }

    /// `swap`: the good node replacing a bad leader for (round, offset), or null.
    pub fn swap(self: *const LeaderSwapTable, leader: types.AuthorityIndex, leader_round: types.Round, leader_offset: u32) err.Error!?types.AuthorityIndex {
        if (!self.isBad(leader)) return null;
        if (leader_offset != 0) return error.Invariant; // multi-leader swap is not implemented in Rust either
        if (self.good_nodes.len == 0) return error.Invariant;
        var seed: [32]u8 = @splat(0);
        std.mem.writeInt(u32, seed[24..28], leader_round, .little);
        std.mem.writeInt(u32, seed[28..32], leader_offset, .little);
        var rng = rand.ChaCha12.fromSeed(seed);
        return self.good_nodes[rng.genRangeU32(@intCast(self.good_nodes.len))];
    }
};

pub const ElectionMode = enum {
    /// Mainnet: stake weighted pseudo random choice seeded by the round.
    stake_based,
    /// Rust's `cfg(test)` election, (round + offset) % n: for vectors captured from Rust unit
    /// tests and the committer tests only. Never used by a validator.
    round_robin_test,
};

pub const LeaderSchedule = struct {
    gpa: Allocator,
    context: *const Context,
    num_commits_per_schedule: u64 = 300,
    swap_table: LeaderSwapTable = .{},
    mode: ElectionMode = .stake_based,

    pub fn init(gpa: Allocator, context: *const Context, table: LeaderSwapTable) LeaderSchedule {
        return .{ .gpa = gpa, .context = context, .swap_table = table };
    }
    pub fn deinit(self: *LeaderSchedule) void {
        self.swap_table.deinit(self.gpa);
    }

    /// `from_store`: the swap table of the last stored CommitInfo, if any.
    pub fn fromStore(gpa: Allocator, context: *const Context, dag: *const dag_mod.DagState) err.Error!LeaderSchedule {
        var table: LeaderSwapTable = .{};
        if (try dag.store.readLastCommitInfo()) |e| {
            table = try LeaderSwapTable.init(gpa, &context.committee, context.protocol_config.bad_nodes_stake_threshold, e.ref.index, e.info.reputation_scores);
        }
        return init(gpa, context, table);
    }

    pub fn commitsUntilLeaderScheduleUpdate(self: *const LeaderSchedule, dag: *const dag_mod.DagState) err.Error!usize {
        const count: u64 = dag.scoringSubdagsCount();
        if (count > self.num_commits_per_schedule) return error.Invariant;
        return @intCast(self.num_commits_per_schedule - count);
    }

    /// `update_leader_schedule_v2`: scores the collected sub-dags, stores CommitInfo, installs a new
    /// swap table.
    pub fn updateLeaderScheduleV2(self: *LeaderSchedule, dag: *dag_mod.DagState) err.Error!void {
        const scores = try dag.calculateScoringSubdagScores(self.gpa);
        defer self.gpa.free(scores.scores_per_authority);
        const last_commit_index = try dag.scoringSubdagCommitRange();
        dag.clearScoringSubdag();
        try dag.addCommitInfo(scores);
        var table = try LeaderSwapTable.init(self.gpa, &self.context.committee, self.context.protocol_config.bad_nodes_stake_threshold, last_commit_index, scores);
        errdefer table.deinit(self.gpa);
        try self.updateLeaderSwapTable(table);
    }

    /// `update_leader_swap_table`: the new range must directly follow the old one and have the
    /// same size (unless the old one is the default).
    pub fn updateLeaderSwapTable(self: *LeaderSchedule, table: LeaderSwapTable) err.Error!void {
        const old = self.swap_table.reputation_scores.commit_range;
        const new = table.reputation_scores.commit_range;
        if (old.start != 0 or old.end_exclusive != 0) {
            if (old.end_exclusive != new.start or old.size() != new.size()) return error.Invariant;
        }
        self.swap_table.deinit(self.gpa);
        self.swap_table = table;
    }

    pub fn electLeader(self: *const LeaderSchedule, round: types.Round, leader_offset: u32) err.Error!types.AuthorityIndex {
        const leader: types.AuthorityIndex = switch (self.mode) {
            .round_robin_test => @intCast((@as(u64, round) + leader_offset) % self.context.committee.size()),
            .stake_based => try self.electLeaderStakeBased(round, leader_offset),
        };
        return (try self.swap_table.swap(leader, round, leader_offset)) orelse leader;
    }

    /// `elect_leader_stake_based`: `choose_multiple_weighted(rng, n, stake as f32).skip(offset).next()`
    /// with `StdRng::from_seed(round as u32 LE in the last 4 bytes)`.
    pub fn electLeaderStakeBased(self: *const LeaderSchedule, round: types.Round, offset: u32) err.Error!types.AuthorityIndex {
        const c = &self.context.committee;
        if (offset >= c.size()) return error.Invariant;
        var seed: [32]u8 = @splat(0);
        std.mem.writeInt(u32, seed[28..32], round, .little);
        var rng = rand.ChaCha12.fromSeed(seed);
        if (c.size() > rand.max_weighted) return error.Unsupported;
        var weights: [rand.max_weighted]f64 = undefined;
        for (c.authorities, 0..) |a, i| {
            const f: f32 = @floatFromInt(a.stake);
            weights[i] = f;
        }
        const idx = rand.chooseWeighted(&rng, weights[0..c.size()], offset) orelse return error.Invariant;
        return @intCast(idx);
    }
};

fn testContext(buf: []committee_mod.Authority, n: usize) Context {
    for (buf[0..n]) |*a| a.* = .{ .stake = 1, .address = "", .hostname = "", .authority_name = "", .protocol_key = @splat(0), .network_key = @splat(0) };
    return .{
        .epoch_start_timestamp_ms = 0,
        .own_index = 0,
        .committee = committee_mod.Committee.init(0, buf[0..n]) catch unreachable,
        .parameters = .{},
        .protocol_config = .{ .gc_depth = 60, .bad_nodes_stake_threshold = 30, .transaction_voting_enabled = true, .num_leaders_per_round = 1 },
        .clock = undefined,
    };
}

test "elect_leader_stake_based equals the rust test values (4 equal stakes)" {
    var buf: [4]committee_mod.Authority = undefined;
    const ctx = testContext(&buf, 4);
    const ls = LeaderSchedule.init(std.testing.allocator, &ctx, .{});
    try std.testing.expectEqual(@as(types.AuthorityIndex, 1), try ls.electLeaderStakeBased(0, 0));
    try std.testing.expectEqual(@as(types.AuthorityIndex, 1), try ls.electLeaderStakeBased(1, 0));
    try std.testing.expectEqual(@as(types.AuthorityIndex, 3), try ls.electLeaderStakeBased(5, 0));
    try std.testing.expect((try ls.electLeaderStakeBased(1, 1)) != (try ls.electLeaderStakeBased(1, 2)));
}

test "leader swap table and swap equal the rust tests" {
    var buf: [4]committee_mod.Authority = undefined;
    const ctx = testContext(&buf, 4);
    const scores: types.ReputationScores = .{ .scores_per_authority = &.{ 0, 1, 2, 3 }, .commit_range = types.CommitRange.inclusive(0, 10) };
    var t = try LeaderSwapTable.init(std.testing.allocator, &ctx.committee, 33, 0, scores);
    defer t.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), t.good_nodes.len);
    try std.testing.expectEqual(@as(types.AuthorityIndex, 3), t.good_nodes[0]);
    try std.testing.expectEqual(@as(usize, 1), t.bad_nodes.len);
    try std.testing.expect(t.isBad(0));
    try std.testing.expectEqual(@as(?types.AuthorityIndex, 3), try t.swap(0, 1, 0));
    try std.testing.expectEqual(@as(?types.AuthorityIndex, null), try t.swap(1, 1, 0));
    try std.testing.expectError(error.Invariant, LeaderSwapTable.init(std.testing.allocator, &ctx.committee, 34, 0, scores));
}
