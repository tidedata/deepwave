//! consensus_core::threshold_clock::ThresholdClock: the round advances when blocks from a
//! quorum of stake at the current round are accepted. Owner lane: val-consensus-core.
const std = @import("std");
const types = @import("types.zig");
const committee_mod = @import("committee.zig");

pub const ThresholdClock = struct {
    committee: *const committee_mod.Committee,
    round: types.Round = 1,
    aggregator: committee_mod.StakeAggregator(committee_mod.max_committee_size) = .{},
    /// Monotonic time the current round was reached (for min_round_delay and the tracer).
    quorum_ts_ns: u64 = 0,

    pub fn init(committee: *const committee_mod.Committee, round: types.Round, now_ns: u64) ThresholdClock {
        return .{ .committee = committee, .round = round, .quorum_ts_ns = now_ns };
    }

    /// Adds an accepted block; returns true if the round advanced (`add_block`).
    pub fn addBlock(self: *ThresholdClock, block: types.BlockRef, now_ns: u64) bool {
        const q = self.committee.quorum_threshold;
        switch (std.math.order(block.round, self.round)) {
            .lt => return false,
            .eq => {
                if (self.aggregator.add(block.author, self.committee, q)) {
                    self.aggregator.clear();
                    self.round = block.round + 1;
                    self.quorum_ts_ns = now_ns;
                    return true;
                }
                return false;
            },
            .gt => {
                self.aggregator.clear();
                if (self.aggregator.add(block.author, self.committee, q)) {
                    self.round = block.round + 1;
                } else {
                    self.round = block.round;
                }
                self.quorum_ts_ns = now_ns;
                return true;
            },
        }
    }

    pub fn getRound(self: *const ThresholdClock) types.Round {
        return self.round;
    }
};

fn testCommittee(n: usize, buf: []committee_mod.Authority) committee_mod.Committee {
    for (buf[0..n]) |*a| a.* = .{ .stake = 1, .address = "", .hostname = "", .authority_name = "", .protocol_key = @splat(0), .network_key = @splat(0) };
    return committee_mod.Committee.init(0, buf[0..n]) catch unreachable;
}

test "threshold clock advances on a quorum (threshold_clock.rs tests)" {
    var buf: [4]committee_mod.Authority = undefined;
    const c = testCommittee(4, &buf);
    var clock = ThresholdClock.init(&c, 0, 0);
    const d: types.BlockDigest = @splat(0);
    try std.testing.expect(!clock.addBlock(.{ .round = 0, .author = 0, .digest = d }, 1));
    try std.testing.expect(!clock.addBlock(.{ .round = 0, .author = 1, .digest = d }, 1));
    try std.testing.expect(clock.addBlock(.{ .round = 0, .author = 2, .digest = d }, 1));
    try std.testing.expectEqual(@as(types.Round, 1), clock.getRound());
    // A block of a later round jumps the clock.
    try std.testing.expect(clock.addBlock(.{ .round = 5, .author = 3, .digest = d }, 2));
    try std.testing.expectEqual(@as(types.Round, 5), clock.getRound());
    try std.testing.expect(!clock.addBlock(.{ .round = 4, .author = 0, .digest = d }, 3));
}
