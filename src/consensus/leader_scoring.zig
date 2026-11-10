//! consensus_core::leader_scoring at mainnet-v1.83.1: ReputationScores helpers and ScoringSubdag
//! (distributed vote scoring: each vote for a committed leader scores the stake of every block of
//! the sub-dags that included the vote). Owner lane: val-consensus-core.
const std = @import("std");
const types = @import("types.zig");
const committee_mod = @import("committee.zig");
const store_mod = @import("store.zig");

pub const Agg = committee_mod.StakeAggregator(committee_mod.max_committee_size);

/// `ReputationScores::authorities_by_score`: (authority index, score) in index order.
pub fn authoritiesByScore(gpa: std.mem.Allocator, scores: []const u64) std.mem.Allocator.Error![]ScoredAuthority {
    const out = try gpa.alloc(ScoredAuthority, scores.len);
    for (out, scores, 0..) |*o, s, i| o.* = .{ .authority = @intCast(i), .score = s };
    return out;
}
pub const ScoredAuthority = struct { authority: types.AuthorityIndex, score: u64 };

pub const ScoringSubdag = struct {
    gpa: std.mem.Allocator,
    committee: *const committee_mod.Committee,
    /// Commit range scored so far (inclusive start, exclusive end on the wire); null when empty.
    commit_range: ?types.CommitRange = null,
    leaders: std.HashMapUnmanaged(types.BlockRef, void, store_mod.RefContext, 80) = .empty,
    votes: std.HashMapUnmanaged(types.BlockRef, Agg, store_mod.RefContext, 80) = .empty,

    pub fn init(gpa: std.mem.Allocator, committee: *const committee_mod.Committee) ScoringSubdag {
        return .{ .gpa = gpa, .committee = committee };
    }
    pub fn deinit(self: *ScoringSubdag) void {
        self.leaders.deinit(self.gpa);
        self.votes.deinit(self.gpa);
    }

    /// `add_subdags` for one sub-dag. Errors only on allocation failure or on the "duplicate vote"
    /// invariant Rust asserts (a block voting twice), reported as `error.DuplicateVote`.
    pub fn addSubdag(self: *ScoringSubdag, sub_dag: *const types.CommittedSubDag) error{ OutOfMemory, DuplicateVote, NonContiguousRange }!void {
        const idx = sub_dag.commit_ref.index;
        if (self.commit_range) |*r| {
            // CommitRange::extend_to asserts the end only grows.
            if (r.end_exclusive > idx +| 1) return error.NonContiguousRange;
            r.end_exclusive = idx +| 1;
        } else {
            self.commit_range = types.CommitRange.inclusive(idx, idx);
        }
        try self.leaders.put(self.gpa, sub_dag.leader, {});
        for (sub_dag.blocks) |*block| {
            const b = &block.block.inner;
            const round = b.round();
            for (b.ancestors()) |anc| {
                if (anc.round != round -| 1) continue;
                if (self.leaders.contains(anc)) {
                    const ref = block.reference();
                    const gop = try self.votes.getOrPut(self.gpa, ref);
                    if (gop.found_existing) return error.DuplicateVote;
                    gop.value_ptr.* = .{};
                }
                if (self.votes.getPtr(anc)) |agg| {
                    _ = agg.add(b.author(), self.committee, self.committee.quorum_threshold);
                }
            }
        }
    }

    /// `calculate_distributed_vote_scores`: scores per authority (caller frees), range.
    pub fn calculateScores(self: *const ScoringSubdag, gpa: std.mem.Allocator) error{ OutOfMemory, EmptyRange }!types.ReputationScores {
        const range = self.commit_range orelse return error.EmptyRange;
        const scores = try gpa.alloc(u64, self.committee.size());
        @memset(scores, 0);
        var it = self.votes.iterator();
        while (it.next()) |e| {
            if (e.key_ptr.author < scores.len) scores[e.key_ptr.author] += e.value_ptr.stake;
        }
        return .{ .scores_per_authority = scores, .commit_range = range };
    }

    pub fn scoredSubdagsCount(self: *const ScoringSubdag) usize {
        return if (self.commit_range) |r| r.size() else 0;
    }
    pub fn isEmpty(self: *const ScoringSubdag) bool {
        return self.leaders.count() == 0 and self.votes.count() == 0 and self.commit_range == null;
    }
    pub fn clear(self: *ScoringSubdag) void {
        self.leaders.clearRetainingCapacity();
        self.votes.clearRetainingCapacity();
        self.commit_range = null;
    }
};
