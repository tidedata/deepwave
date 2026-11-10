//! The committee the driver submits to, as plain data, and sui-core's `StatusAggregator`.
//!
//! sui-types `Committee` keeps members sorted by `AuthorityName` (a BTreeMap); a member's
//! committee index is its position in that order. Voting power is normalized to
//! `TOTAL_VOTING_POWER` (10,000) with the fixed thresholds `QUORUM_THRESHOLD` (6,667, 2f+1) and
//! `VALIDITY_THRESHOLD` (3,334, f+1); `Committee::new` asserts the total, so does `init`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const se = @import("sui_error.zig");

pub const AuthorityName = types.AuthorityPublicKeyBytes;
pub const total_voting_power: u64 = 10_000;
pub const quorum_threshold: u64 = 6_667;
pub const validity_threshold: u64 = 3_334;

pub const Member = struct {
    /// BLS12-381 protocol public key bytes (96).
    name: [96]u8,
    stake: u64,
    /// Network address (multiaddr text, e.g. `/dns/x/tcp/8080/http`); the transport's business.
    network_address: []const u8 = "",
    /// `AuthorityAggregator::get_display_name`: the on-chain validator name when known; the
    /// allowed/blocked lists match on it. Null = the concise name `k#xxxxxxxx..`.
    display_name: ?[]const u8 = null,
    /// Ed25519 network public key: the validator gRPC TLS certificate key (sui-tls pinning).
    network_key: [32]u8 = @splat(0),
};

pub const Committee = struct {
    epoch: u64,
    /// Sorted by name; index = committee index (`AuthorityIndex`).
    members: []const Member,
    /// Concise names, one per member, for display-name fallbacks.
    concise: []const [12]u8,

    pub const Error = error{ InvalidCommittee, OutOfMemory };

    /// Copies and sorts `members` (any order). The stakes must add up to 10,000 and names be
    /// distinct, as `Committee::new` requires.
    pub fn init(arena: Allocator, epoch: u64, members: []const Member) Error!Committee {
        if (members.len == 0) return error.InvalidCommittee;
        const ms = try arena.dupe(Member, members);
        std.mem.sort(Member, ms, {}, struct {
            fn lt(_: void, a: Member, b: Member) bool {
                return std.mem.order(u8, &a.name, &b.name) == .lt;
            }
        }.lt);
        var total: u64 = 0;
        for (ms, 0..) |m, i| {
            if (i > 0 and std.mem.eql(u8, &ms[i - 1].name, &m.name)) return error.InvalidCommittee;
            total += m.stake;
        }
        if (total != total_voting_power) return error.InvalidCommittee;
        const concise = try arena.alloc([12]u8, ms.len);
        for (ms, concise) |m, *c| {
            const digits = "0123456789abcdef";
            c[0] = 'k';
            c[1] = '#';
            for (m.name[0..4], 0..) |b, j| {
                c[2 + 2 * j] = digits[b >> 4];
                c[3 + 2 * j] = digits[b & 15];
            }
            c[10] = '.';
            c[11] = '.';
        }
        return .{ .epoch = epoch, .members = ms, .concise = concise };
    }

    pub fn size(c: *const Committee) u32 {
        return @intCast(c.members.len);
    }

    pub fn stake(c: *const Committee, i: u32) u64 {
        return c.members[i].stake;
    }

    pub fn indexOf(c: *const Committee, name: *const [96]u8) ?u32 {
        for (c.members, 0..) |m, i| if (std.mem.eql(u8, &m.name, name)) return @intCast(i);
        return null;
    }

    pub fn displayName(c: *const Committee, i: u32) []const u8 {
        return c.members[i].display_name orelse &c.concise[i];
    }
};

/// sui-core `StatusAggregator<T>`: the latest status per authority plus the total stake of the
/// authorities that reported one (a second report replaces the status, not the stake).
pub fn StatusAggregator(comptime T: type) type {
    return struct {
        const Self = @This();
        committee: *const Committee,
        total_votes: u64 = 0,
        statuses: []?T,

        pub fn init(arena: Allocator, committee: *const Committee) Allocator.Error!Self {
            const s = try arena.alloc(?T, committee.members.len);
            @memset(s, null);
            return .{ .committee = committee, .statuses = s };
        }

        /// True when the authority reported for the first time.
        pub fn insert(self: *Self, i: u32, status: T) bool {
            const first = self.statuses[i] == null;
            self.statuses[i] = status;
            if (first) self.total_votes += self.committee.stake(i);
            return first;
        }

        pub fn reachedValidityThreshold(self: *const Self) bool {
            return self.total_votes >= validity_threshold;
        }

        pub fn reachedQuorumThreshold(self: *const Self) bool {
            return self.total_votes >= quorum_threshold;
        }
    };
}

const testing = std.testing;

test "committee sorts by name and checks the total" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var a: Member = .{ .name = @splat(2), .stake = 5000 };
    var b: Member = .{ .name = @splat(1), .stake = 5000, .display_name = "val-b" };
    const c = try Committee.init(arena, 3, &.{ a, b });
    try testing.expectEqual(@as(u8, 1), c.members[0].name[0]);
    try testing.expectEqualStrings("val-b", c.displayName(0));
    try testing.expectEqualStrings("k#02020202..", c.displayName(1));
    a.stake = 1;
    try testing.expectError(error.InvalidCommittee, Committee.init(arena, 3, &.{ a, b }));
    b.name = a.name;
    a.stake = 5000;
    try testing.expectError(error.InvalidCommittee, Committee.init(arena, 3, &.{ a, b }));
    var agg = try StatusAggregator(u8).init(arena, &c);
    try testing.expect(agg.insert(0, 1));
    try testing.expect(!agg.insert(0, 2));
    try testing.expectEqual(@as(u64, 5000), agg.total_votes);
    try testing.expect(agg.reachedValidityThreshold() and !agg.reachedQuorumThreshold());
    _ = se;
}
