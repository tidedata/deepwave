//! Validator committees: the BLS keys and stakes of one epoch, and the transition from an
//! end-of-epoch checkpoint to the next epoch's committee.
const std = @import("std");
const bls = @import("bls");
const types = @import("types");

pub const total_voting_power: u64 = 10_000;
pub const quorum_threshold: u64 = 6_667;

pub const Committee = struct {
    epoch: u64,
    /// Committee index order: the order signer bitmaps index (sorted by key bytes).
    keys: []const [96]u8,
    stakes: []const u64,
    total_stake: u64,
    prepared: bls.PreparedCommittee,

    pub const Error = error{ EmptyCommittee, UnsortedCommittee, BadStake } || bls.PreparedCommittee.InitError;

    /// Memory (keys, stakes, decoded points, pairing lines) comes from `arena` and lives as long as it.
    pub fn init(arena: std.mem.Allocator, epoch: u64, keys: []const [96]u8, stakes: []const u64) Error!Committee {
        if (keys.len == 0 or keys.len != stakes.len) return error.EmptyCommittee;
        // sui-types `Committee::new`: some stake is non-zero and the total is exactly
        // TOTAL_VOTING_POWER (it asserts both). A zero-stake member is allowed; it can never
        // count as a signer (`weight`).
        var total: u64 = 0;
        for (stakes, 0..) |s, i| {
            total = std.math.add(u64, total, s) catch return error.BadStake;
            if (i > 0 and std.mem.order(u8, &keys[i - 1], &keys[i]) != .lt) return error.UnsortedCommittee;
        }
        if (total != total_voting_power) return error.BadStake;
        const k = try arena.dupe([96]u8, keys);
        const st = try arena.dupe(u64, stakes);
        return .{ .epoch = epoch, .keys = k, .stakes = st, .total_stake = total, .prepared = try bls.PreparedCommittee.init(arena, k) };
    }

    /// The committee of `eoe_summary.epoch + 1`, from the end-of-epoch data of that epoch's last checkpoint.
    pub fn fromEndOfEpoch(arena: std.mem.Allocator, epoch: u64, eoe: types.EndOfEpochData) Error!Committee {
        const n = eoe.nextEpochCommittee.len;
        const keys = try arena.alloc([96]u8, n);
        const stakes = try arena.alloc(u64, n);
        for (eoe.nextEpochCommittee, keys, stakes) |m, *k, *s| {
            k.* = m[0].@"0";
            s.* = m[1];
        }
        return init(arena, epoch, keys, stakes);
    }

    pub fn quorum(c: *const Committee) u64 {
        _ = c;
        return quorum_threshold;
    }

    /// Stake of the listed committee indexes (no duplicates), or null when one is not a member
    /// or has no voting power (both are SuiError::UnknownSigner in `verify_secure`).
    pub fn weight(c: *const Committee, signers: []const u32) ?u64 {
        var w: u64 = 0;
        for (signers) |s| {
            if (s >= c.stakes.len or c.stakes[s] == 0) return null;
            w += c.stakes[s];
        }
        return w;
    }
};

/// A committee from one JSON line `{"epoch":E,"keys":["hex96",...],"stakes":[...]}` (the format of
/// the bls lane's `vectors/bls-cert/<epoch>.jsonl` first line and of `zui-sync-truth`). The keys
/// must already be sorted.
pub fn fromJsonLine(arena: std.mem.Allocator, line: []const u8) !Committee {
    const V = struct { epoch: u64, keys: []const []const u8, stakes: []const u64 };
    const v = try std.json.parseFromSliceLeaky(V, arena, line, .{ .ignore_unknown_fields = true });
    const keys = try arena.alloc([96]u8, v.keys.len);
    for (v.keys, keys) |hex, *k| {
        if (hex.len != 192) return error.BadKey;
        _ = try std.fmt.hexToBytes(k, hex);
    }
    return Committee.init(arena, v.epoch, keys, v.stakes);
}
