//! `transaction_deferral.rs` (mainnet-v1.83.1): the key a deferred transaction is stored under,
//! its ordering, and the deferral limit. Keys order as Rust's derived `Ord`: every Randomness key
//! sorts before every ConsensusRound key; ConsensusRound sorts by (future_round,
//! deferred_from_round).
const std = @import("std");

pub const Round = u64;

pub const DeferralKey = union(enum) {
    /// Deferred until new randomness is available (DKG delay or skipped commits).
    randomness: struct { deferred_from_round: Round },
    /// Deferred to `future_round`, from `deferred_from_round`.
    consensus_round: struct { future_round: Round, deferred_from_round: Round },

    pub fn newForRandomness(deferred_from_round: Round) DeferralKey {
        return .{ .randomness = .{ .deferred_from_round = deferred_from_round } };
    }
    pub fn newForConsensusRound(future_round: Round, deferred_from_round: Round) DeferralKey {
        return .{ .consensus_round = .{ .future_round = future_round, .deferred_from_round = deferred_from_round } };
    }
    pub fn deferredFromRound(k: DeferralKey) Round {
        return switch (k) {
            .randomness => |r| r.deferred_from_round,
            .consensus_round => |c| c.deferred_from_round,
        };
    }
    pub fn order(a: DeferralKey, b: DeferralKey) std.math.Order {
        const ta = std.meta.activeTag(a);
        const tb = std.meta.activeTag(b);
        if (ta != tb) return std.math.order(@intFromEnum(ta), @intFromEnum(tb));
        return switch (a) {
            .randomness => |x| std.math.order(x.deferred_from_round, b.randomness.deferred_from_round),
            .consensus_round => |x| blk: {
                const y = b.consensus_round;
                const o = std.math.order(x.future_round, y.future_round);
                if (o != .eq) break :blk o;
                break :blk std.math.order(x.deferred_from_round, y.deferred_from_round);
            },
        };
    }
    pub fn lessThan(_: void, a: DeferralKey, b: DeferralKey) bool {
        return order(a, b) == .lt;
    }
    pub fn eql(a: DeferralKey, b: DeferralKey) bool {
        return order(a, b) == .eq;
    }
    /// True for keys loaded by `range_for_up_to_consensus_round(round)`:
    /// ConsensusRound with future_round <= round.
    pub fn dueByRound(k: DeferralKey, round: Round) bool {
        return switch (k) {
            .consensus_round => |c| c.future_round <= round,
            .randomness => false,
        };
    }
};

pub const Reason = union(enum) {
    randomness_not_ready,
    /// The congested object ids.
    shared_object_congestion: []const [32]u8,
};

/// `transaction_deferral_within_limit`.
pub fn withinLimit(key: DeferralKey, max_deferral_rounds: u64) bool {
    switch (key) {
        .consensus_round => |c| return (c.future_round -% c.deferred_from_round) <= max_deferral_rounds,
        .randomness => return true,
    }
}

test "key order" {
    const a = DeferralKey.newForRandomness(100);
    const b = DeferralKey.newForConsensusRound(1, 0);
    const c = DeferralKey.newForConsensusRound(1, 5);
    const d = DeferralKey.newForConsensusRound(2, 0);
    try std.testing.expect(DeferralKey.lessThan({}, a, b));
    try std.testing.expect(DeferralKey.lessThan({}, b, c));
    try std.testing.expect(DeferralKey.lessThan({}, c, d));
    try std.testing.expect(c.dueByRound(1) and !d.dueByRound(1) and !a.dueByRound(1000));
    try std.testing.expect(withinLimit(b, 1));
    try std.testing.expect(!withinLimit(DeferralKey.newForConsensusRound(12, 1), 10));
    try std.testing.expect(withinLimit(a, 0));
}
