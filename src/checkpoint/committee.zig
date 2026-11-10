//! Committees: construction (sui-types `Committee::new`), the epoch 0 committee from the genesis
//! blob, and the next committee from an end-of-epoch checkpoint summary.
//!
//! `Committee::new` panics on a bad input (empty, all-zero stakes, total stake other than
//! 10,000, an undecodable key); here each is an error value so a caller can refuse the input.
const std = @import("std");
const bls = @import("bls");
const summary_mod = @import("summary.zig");

pub const total_voting_power: u64 = 10_000;
pub const quorum_threshold: u64 = 6_667;
pub const validity_threshold: u64 = 3_334;

pub const Member = struct {
    /// The validator's BLS12-381 min-sig public key (compressed G2), also its AuthorityName.
    name: [96]u8,
    stake: u64,
};

pub const Error = error{ EmptyCommittee, ZeroStake, BadTotalStake, BadKey } || std.mem.Allocator.Error;

pub const Committee = struct {
    epoch: u64,
    /// Sorted by `name` (byte order): the index a signer bitmap refers to.
    members: []const Member,
    total_stake: u64,
    quorum_threshold: u64,
    validity_threshold: u64,
    /// Keys decoded once, plus the sum and the G2 generator lines (crypto-bls).
    prepared: bls.PreparedCommittee,

    /// `Committee::new`: sorts by name, the last listed stake wins for a repeated name, then
    /// asserts in Rust's order: non-empty, some stake, total exactly 10,000 (summed with
    /// wrapping, as the release build does), every key decodes.
    /// Memory comes from `arena` and lives as long as it.
    pub fn init(arena: std.mem.Allocator, epoch: u64, rights: []const Member) Error!Committee {
        if (rights.len == 0) return error.EmptyCommittee;
        const sorted = try arena.dupe(Member, rights);
        std.sort.pdq(Member, sorted, {}, struct {
            fn lt(_: void, a: Member, b: Member) bool {
                return std.mem.order(u8, &a.name, &b.name) == .lt;
            }
        }.lt);
        // pdq is not stable: restore "last listed wins" for repeated names by re-resolving them
        // against the input order
        var n: usize = 0;
        var i: usize = 0;
        while (i < sorted.len) {
            var j = i + 1;
            while (j < sorted.len and std.mem.eql(u8, &sorted[j].name, &sorted[i].name)) j += 1;
            var m = sorted[i];
            if (j - i > 1) {
                var k = rights.len;
                while (k > 0) {
                    k -= 1;
                    if (std.mem.eql(u8, &rights[k].name, &m.name)) {
                        m.stake = rights[k].stake;
                        break;
                    }
                }
            }
            sorted[n] = m;
            n += 1;
            i = j;
        }
        const members = sorted[0..n];
        var any = false;
        var total: u64 = 0;
        for (members) |m| {
            if (m.stake != 0) any = true;
            // sui-node is built without overflow checks: Rust's `.sum()` wraps, so a total of
            // 10,000 mod 2^64 passes `Committee::new` (suite case synth/stake-wrap)
            total +%= m.stake;
        }
        if (!any) return error.ZeroStake;
        if (total != total_voting_power) return error.BadTotalStake;
        const keys = try arena.alloc([96]u8, n);
        for (members, keys) |m, *k| k.* = m.name;
        const prepared = bls.PreparedCommittee.init(arena, keys) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.BadKey,
        };
        return .{
            .epoch = epoch,
            .members = members,
            .total_stake = total_voting_power,
            .quorum_threshold = quorum_threshold,
            .validity_threshold = validity_threshold,
            .prepared = prepared,
        };
    }

    pub fn stakeByIndex(c: *const Committee, i: u32) ?u64 {
        if (i >= c.members.len) return null;
        return c.members[i].stake;
    }
};

/// The committee of epoch `eoe.epoch + 1` from an end-of-epoch checkpoint summary
/// (`EndOfEpochData::next_epoch_committee`). `error.NotEndOfEpoch` when the summary has none.
pub fn nextCommittee(arena: std.mem.Allocator, summary: summary_mod.Summary) (Error || error{NotEndOfEpoch})!Committee {
    const eoe = summary.next_committee orelse return error.NotEndOfEpoch;
    const rights = try arena.alloc(Member, eoe.count);
    for (rights, 0..) |*m, i| m.* = .{ .name = eoe.key(i).*, .stake = eoe.stake(i) };
    return Committee.init(arena, summary.epoch + 1, rights);
}

test "Committee::new rules" {
    const bls_ = @import("bls");
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var keys: [3][96]u8 = undefined;
    for (&keys, 0..) |*k, i| {
        var b: [32]u8 = @splat(0);
        b[31] = @intCast(i + 1);
        b[0] = 0x21;
        k.* = bls_.sig.SecretKey.fromBytes(&b).?.publicKey().toBytes();
    }
    const m = [_]Member{ .{ .name = keys[0], .stake = 5000 }, .{ .name = keys[1], .stake = 3000 }, .{ .name = keys[2], .stake = 2000 } };
    const c = try Committee.init(a, 9, &m);
    try std.testing.expectEqual(@as(usize, 3), c.members.len);
    try std.testing.expectEqual(@as(u64, 6667), c.quorum_threshold);
    try std.testing.expectEqual(@as(u64, 3334), c.validity_threshold);
    for (c.members[1..], 1..) |x, i| try std.testing.expect(std.mem.order(u8, &c.members[i - 1].name, &x.name) == .lt);
    // a repeated name: the last listed stake wins
    const dup = [_]Member{ m[0], .{ .name = keys[0], .stake = 1 }, m[1], .{ .name = keys[0], .stake = 5000 }, m[2] };
    try std.testing.expectEqual(@as(usize, 3), (try Committee.init(a, 9, &dup)).members.len);
    try std.testing.expectError(error.EmptyCommittee, Committee.init(a, 9, &.{}));
    const zero = [_]Member{ .{ .name = keys[0], .stake = 0 }, .{ .name = keys[1], .stake = 0 } };
    try std.testing.expectError(error.ZeroStake, Committee.init(a, 9, &zero));
    const low = [_]Member{ .{ .name = keys[0], .stake = 9999 } };
    try std.testing.expectError(error.BadTotalStake, Committee.init(a, 9, &low));
    const bad = [_]Member{ .{ .name = keys[0], .stake = 5000 }, .{ .name = @splat(0xff), .stake = 5000 } };
    try std.testing.expectError(error.BadKey, Committee.init(a, 9, &bad));
}
