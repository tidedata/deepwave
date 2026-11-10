//! consensus_config::Committee at mainnet-v1.83.1 (`consensus/config/src/committee.rs`): stake,
//! thresholds and the per-authority keys consensus needs. Owner lane: val-consensus-core.
//!
//! The thresholds are computed exactly as `Committee::new` does (`new_v3` is test-only at 1.83.1
//! and not used on mainnet): f = (total - 1) / 3, quorum = total - f, validity = f + 1,
//! certification = quorum. This file is complete; the lane adds only what the core needs.
const std = @import("std");
const types = @import("types.zig");

pub const Stake = types.Stake;
pub const Epoch = types.Epoch;
pub const AuthorityIndex = types.AuthorityIndex;

/// consensus_config::Authority. `authority_name` is the Sui AuthorityName (the 96-byte BLS
/// protocol public key) the Sui side maps this index to; `protocol_key` signs blocks (Ed25519,
/// Sui's "worker"/protocol key for consensus); `network_key` is the TLS identity (Ed25519).
pub const Authority = struct {
    stake: Stake,
    /// Multiaddr text, e.g. "/ip4/127.0.0.1/udp/8081" (consensus maps udp to a TCP port).
    address: []const u8,
    hostname: []const u8,
    authority_name: []const u8,
    protocol_key: [32]u8,
    network_key: [32]u8,
};

pub const Error = error{ EmptyCommittee, ZeroStake, TooManyAuthorities, StakeOverflow };

pub const Committee = struct {
    epoch: Epoch,
    authorities: []const Authority,
    total_stake: Stake,
    quorum_threshold: Stake,
    certification_threshold: Stake,
    validity_threshold: Stake,

    /// `Committee::new`. Rust asserts (panics) on an empty committee or zero stake; deepwave returns
    /// an error instead. `authorities` is borrowed.
    pub fn init(epoch: Epoch, authorities: []const Authority) Error!Committee {
        if (authorities.len == 0) return error.EmptyCommittee;
        if (authorities.len >= std.math.maxInt(u32)) return error.TooManyAuthorities;
        var total: Stake = 0;
        for (authorities) |a| total = std.math.add(Stake, total, a.stake) catch return error.StakeOverflow;
        if (total == 0) return error.ZeroStake;
        const f = (total - 1) / 3;
        const quorum = total - f;
        return .{
            .epoch = epoch,
            .authorities = authorities,
            .total_stake = total,
            .quorum_threshold = quorum,
            .certification_threshold = quorum,
            .validity_threshold = f + 1,
        };
    }

    pub fn size(c: *const Committee) usize {
        return c.authorities.len;
    }
    pub fn isValidIndex(c: *const Committee, i: AuthorityIndex) bool {
        return i < c.authorities.len;
    }
    pub fn stake(c: *const Committee, i: AuthorityIndex) Stake {
        return c.authorities[i].stake;
    }
    pub fn reachedQuorum(c: *const Committee, s: Stake) bool {
        return s >= c.quorum_threshold;
    }
    pub fn reachedValidity(c: *const Committee, s: Stake) bool {
        return s >= c.validity_threshold;
    }
};

/// consensus_core::stake_aggregator::StakeAggregator<QuorumThreshold|ValidityThreshold>: adds
/// each authority's stake once. Fixed capacity: a bitset over authority indices.
pub fn StakeAggregator(comptime max_authorities: usize) type {
    return struct {
        const Self = @This();
        votes: std.StaticBitSet(max_authorities) = .empty,
        stake: Stake = 0,

        /// Returns true if the threshold is reached after adding `who`.
        pub fn add(self: *Self, who: AuthorityIndex, committee: *const Committee, threshold: Stake) bool {
            if (who < max_authorities and !self.votes.isSet(who)) {
                self.votes.set(who);
                self.stake += committee.stake(who);
            }
            return self.stake >= threshold;
        }
        pub fn clear(self: *Self) void {
            self.* = .{};
        }
    };
}

/// Upper bound on committee size for fixed-capacity structures (mainnet: about 120).
pub const max_committee_size = 512;

test "thresholds equal Committee::new" {
    var auths: [4]Authority = undefined;
    for (&auths) |*a| a.* = .{ .stake = 1, .address = "", .hostname = "", .authority_name = "", .protocol_key = @splat(0), .network_key = @splat(0) };
    const c = try Committee.init(0, &auths);
    try std.testing.expectEqual(@as(Stake, 3), c.quorum_threshold);
    try std.testing.expectEqual(@as(Stake, 2), c.validity_threshold);
    // Mainnet-like: total 10_000 voting power.
    auths[0].stake = 9_997;
    const m = try Committee.init(1, &auths);
    try std.testing.expectEqual(@as(Stake, 6_667), m.quorum_threshold);
    try std.testing.expectEqual(@as(Stake, 3_334), m.validity_threshold);
    var agg: StakeAggregator(max_committee_size) = .{};
    try std.testing.expect(!agg.add(1, &c, c.quorum_threshold));
    try std.testing.expect(!agg.add(1, &c, c.quorum_threshold));
    try std.testing.expect(!agg.add(2, &c, c.quorum_threshold));
    try std.testing.expect(agg.add(3, &c, c.quorum_threshold));
}
