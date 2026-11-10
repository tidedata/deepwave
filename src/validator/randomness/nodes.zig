//! fastcrypto-tbls `nodes`: the DKG participants (party id = committee index, ECIES public key,
//! weight) and the share id layout (share ids 1..=total_weight are dealt to nodes in party order,
//! a node gets a contiguous range of `weight` ids). `newReduced` is `Nodes::new_reduced`, which
//! Sui 1.83.1 uses (`random_beacon_reduction_allowed_delta` / `_lower_bound`).
const std = @import("std");
const group = @import("group.zig");
const G2P = group.G2P;

pub const PartyId = u16;
pub const max_nodes = 1000;

pub const Node = struct { id: PartyId, pk: G2P, weight: u16 };

pub const Error = error{InvalidInput} || std.mem.Allocator.Error;

pub const ShareRange = struct {
    /// First share id (1-based); the node owns first .. first + count - 1.
    first: u16,
    count: u16,

    pub fn contains(r: ShareRange, id: u16) bool {
        return id >= r.first and id - r.first < r.count;
    }
};

pub const Nodes = struct {
    nodes: []const Node,
    total_weight: u16,
    /// starts[i] = sum of weights of nodes before i (share ids of node i start at starts[i] + 1).
    starts: []const u16,

    /// `Nodes::new`: ids must be 0..n-1 in order after sorting, total weight in 1..=u16::MAX.
    pub fn init(arena: std.mem.Allocator, input: []const Node) Error!Nodes {
        if (input.len == 0 or input.len > max_nodes) return error.InvalidInput;
        const nodes = try arena.dupe(Node, input);
        std.mem.sort(Node, nodes, {}, struct {
            fn lt(_: void, a: Node, b: Node) bool {
                return a.id < b.id;
            }
        }.lt);
        var total: u32 = 0;
        const starts = try arena.alloc(u16, nodes.len);
        for (nodes, 0..) |n, i| {
            if (n.id != i) return error.InvalidInput;
            starts[i] = @intCast(@min(total, std.math.maxInt(u16)));
            total += n.weight;
        }
        if (total == 0 or total > std.math.maxInt(u16)) return error.InvalidInput;
        return .{ .nodes = nodes, .total_weight = @intCast(total), .starts = starts };
    }

    pub fn numNodes(self: *const Nodes) usize {
        return self.nodes.len;
    }

    pub fn isValidId(self: *const Nodes, id: PartyId) bool {
        return id < self.nodes.len;
    }

    pub fn nodeOf(self: *const Nodes, id: PartyId) Error!*const Node {
        if (!self.isValidId(id)) return error.InvalidInput;
        return &self.nodes[id];
    }

    pub fn weightOf(self: *const Nodes, id: PartyId) Error!u16 {
        return (try self.nodeOf(id)).weight;
    }

    /// `share_ids_of`: the contiguous range of share ids of a party.
    pub fn shareRange(self: *const Nodes, id: PartyId) Error!ShareRange {
        const n = try self.nodeOf(id);
        return .{ .first = self.starts[id] + 1, .count = n.weight };
    }

    /// `share_id_to_node`: the party owning a share id (1..=total_weight).
    pub fn partyOfShare(self: *const Nodes, share_id: u16) Error!PartyId {
        if (share_id == 0 or share_id > self.total_weight) return error.InvalidInput;
        // last node with start < share_id and non-zero weight
        var lo: usize = 0;
        var hi: usize = self.nodes.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (@as(u32, self.starts[mid]) + self.nodes[mid].weight < share_id) lo = mid + 1 else hi = mid;
        }
        return @intCast(lo);
    }

    /// `Nodes::new_reduced`: divide all weights by the largest d in 2..=40 whose rounding loss
    /// stays within `allowed_delta`, keeping the total at or above `total_weight_lower_bound`.
    /// Returns the reduced nodes and the new threshold ceil(t / d).
    pub fn newReduced(
        arena: std.mem.Allocator,
        input: []const Node,
        t: u16,
        allowed_delta: u16,
        total_weight_lower_bound: u16,
    ) Error!struct { nodes: Nodes, t: u16 } {
        const n = try init(arena, input);
        if (total_weight_lower_bound > n.total_weight or total_weight_lower_bound == 0) return error.InvalidInput;
        var max_d: u16 = 1;
        var d: u16 = 2;
        while (d <= 40) : (d += 1) {
            var new_total: u32 = 0;
            var delta: u32 = 0;
            for (n.nodes) |nd| {
                new_total += nd.weight / d;
                delta += nd.weight % d;
            }
            if (new_total < total_weight_lower_bound) break;
            if (delta <= allowed_delta) max_d = d;
        }
        const reduced = try arena.alloc(Node, n.nodes.len);
        for (n.nodes, reduced) |nd, *r| r.* = .{ .id = nd.id, .pk = nd.pk, .weight = nd.weight / max_d };
        // the reduced total can be zero only if every weight rounds to zero: init rejects it
        const out = try init(arena, reduced);
        return .{ .nodes = out, .t = (t + max_d - 1) / max_d };
    }
};

test "share layout" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const g = group.g2Generator();
    const nodes = try Nodes.init(a, &.{
        .{ .id = 0, .pk = g, .weight = 2 },
        .{ .id = 1, .pk = g, .weight = 0 },
        .{ .id = 2, .pk = g, .weight = 3 },
    });
    try std.testing.expectEqual(@as(u16, 5), nodes.total_weight);
    const r2 = try nodes.shareRange(2);
    try std.testing.expectEqual(@as(u16, 3), r2.first);
    try std.testing.expectEqual(@as(u16, 3), r2.count);
    try std.testing.expectEqual(@as(PartyId, 0), try nodes.partyOfShare(2));
    try std.testing.expectEqual(@as(PartyId, 2), try nodes.partyOfShare(3));
    try std.testing.expectEqual(@as(PartyId, 2), try nodes.partyOfShare(5));
}

test "new reduced keeps a total above the bound" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const g = group.g2Generator();
    var in: [10]Node = undefined;
    for (&in, 0..) |*n, i| n.* = .{ .id = @intCast(i), .pk = g, .weight = 1000 };
    const r = try Nodes.newReduced(a, &in, 3334, 800, 500);
    try std.testing.expect(r.nodes.total_weight >= 500);
    try std.testing.expect(r.nodes.total_weight < 10000);
}
