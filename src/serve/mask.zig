//! FieldMaskTree exactly as `sui-rpc` 's `field/field_mask_tree.rs` (the type sui-rpc-api reads
//! `read_mask` through): same path validity rules, same add_field_path pruning, same
//! `contains` and `subtree` semantics (a leaf matches everything below it; the subtree of a
//! leaf is a wildcard). A `Tree` is built once per request into an arena; `Mask` is a cheap
//! (tree, node) handle that renderers pass down.
const std = @import("std");
const Allocator = std.mem.Allocator;

const no_node: u32 = std.math.maxInt(u32);

const Node = struct {
    name: []const u8,
    first_child: u32 = no_node,
    next_sibling: u32 = no_node,
    /// One bit per entry of `known` for the children of this node: a lookup with a literal
    /// field name is a single AND, no string compares.
    bits: u128 = 0,
};

/// Field names the renderers look up with literals. Order is irrelevant; at most 128.
const known = [_][]const u8{
    "auxiliary_data_digest", "balance",                  "balance_changes",     "bcs",                         "changed_objects",
    "checkpoint",            "commitments",              "content_digest",      "contents",                    "dependencies",
    "digest",                "effects",                  "end_of_epoch_data",   "epoch",                       "epoch_rolling_gas_cost_summary",
    "event_type",            "events",                   "events_digest",       "expiration",                  "gas_object",
    "gas_payment",           "gas_used",                 "has_public_transfer", "kind",                        "lamport_version",
    "module",                "multisig",                 "object_type",         "objects",                     "owner",
    "package",               "package_id",               "passkey",             "previous_digest",             "previous_transaction",
    "scheme",                "sender",                   "sequence_number",     "signature",                   "signatures",
    "simple",                "status",                   "storage_rebate",      "summary",                     "timestamp",
    "total_network_transactions", "transaction",         "transaction_digest",  "transactions",                "unchanged_consensus_objects",
    "unchanged_loaded_runtime_objects", "version",       "version_specific_data", "zklogin",
};

fn knownBit(comptime name: []const u8) ?u128 {
    inline for (known, 0..) |k, i| if (comptime std.mem.eql(u8, k, name)) return @as(u128, 1) << i;
    return null;
}

fn bitOf(name: []const u8) u128 {
    for (known, 0..) |k, i| if (std.mem.eql(u8, k, name)) return @as(u128, 1) << @intCast(i);
    return 0;
}

pub const Tree = struct {
    wildcard: bool = false,
    /// nodes[0] is the root.
    nodes: std.ArrayList(Node) = .empty,

    pub fn init(gpa: Allocator) Allocator.Error!Tree {
        var t: Tree = .{};
        try t.nodes.append(gpa, .{ .name = "" });
        return t;
    }

    pub fn deinit(t: *Tree, gpa: Allocator) void {
        t.nodes.deinit(gpa);
    }

    /// `FieldMaskUtil::from_str` followed by `FieldMaskTree::from`: comma separated paths,
    /// empty paths dropped. `s` must outlive the tree (node names borrow from it).
    pub fn parse(gpa: Allocator, s: []const u8) Allocator.Error!Tree {
        var t = try init(gpa);
        errdefer t.deinit(gpa);
        var it = std.mem.splitScalar(u8, s, ',');
        while (it.next()) |p| try t.addPath(gpa, p);
        return t;
    }

    /// `FieldMaskTree::from_field_mask`: every path of a request's `read_mask.paths`.
    pub fn fromPaths(gpa: Allocator, paths: []const []const u8) Allocator.Error!Tree {
        var t = try init(gpa);
        errdefer t.deinit(gpa);
        for (paths) |p| try t.addPath(gpa, p);
        return t;
    }

    fn childOf(t: *const Tree, node: u32, name: []const u8) u32 {
        var c = t.nodes.items[node].first_child;
        while (c != no_node) : (c = t.nodes.items[c].next_sibling) {
            if (std.mem.eql(u8, t.nodes.items[c].name, name)) return c;
        }
        return no_node;
    }

    /// `FieldMaskTree::add_field_path`. Invalid paths and paths below an existing leaf are
    /// ignored; a path that is an ancestor of existing nodes replaces them.
    pub fn addPath(t: *Tree, gpa: Allocator, path: []const u8) Allocator.Error!void {
        if (t.wildcard or !isValidPath(path)) return;
        if (std.mem.eql(u8, path, "*")) {
            t.wildcard = true;
            t.nodes.items[0].first_child = no_node;
            t.nodes.items[0].bits = 0;
            return;
        }
        var node: u32 = 0;
        var created = false;
        var it = std.mem.splitScalar(u8, path, '.');
        while (it.next()) |comp| {
            if (!created and node != 0 and t.nodes.items[node].first_child == no_node) return;
            const c = t.childOf(node, comp);
            if (c != no_node) {
                node = c;
            } else {
                created = true;
                const idx: u32 = @intCast(t.nodes.items.len);
                // BTreeMap order: children are kept sorted by name (only matters for to_paths).
                try t.nodes.append(gpa, .{ .name = comp });
                t.link(node, idx);
                node = idx;
            }
        }
        t.nodes.items[node].first_child = no_node;
        t.nodes.items[node].bits = 0;
    }

    fn link(t: *Tree, parent: u32, idx: u32) void {
        const name = t.nodes.items[idx].name;
        var prev: u32 = no_node;
        var c = t.nodes.items[parent].first_child;
        while (c != no_node and std.mem.lessThan(u8, t.nodes.items[c].name, name)) {
            prev = c;
            c = t.nodes.items[c].next_sibling;
        }
        t.nodes.items[parent].bits |= bitOf(name);
        t.nodes.items[idx].next_sibling = c;
        if (prev == no_node) t.nodes.items[parent].first_child = idx else t.nodes.items[prev].next_sibling = idx;
    }

    pub fn mask(t: *const Tree) Mask {
        return .{ .tree = t, .node = 0, .wild = t.wildcard };
    }
};

/// A position inside a Tree. `wild` is the Rust `wildcard` flag of the (sub)tree.
pub const Mask = struct {
    tree: *const Tree,
    node: u32,
    wild: bool,

    /// `FieldMaskTree::contains` for a (possibly dotted) path. Literal single field names, the
    /// renderers' case, are one bit test.
    pub inline fn contains(m: Mask, comptime path: []const u8) bool {
        if (comptime knownBit(path)) |bit| return m.wild or (m.tree.nodes.items[m.node].bits & bit) != 0;
        return m.containsDyn(path);
    }

    pub fn containsDyn(m: Mask, path: []const u8) bool {
        if (path.len == 0) return false;
        if (m.wild) return true;
        var node = m.node;
        var it = std.mem.splitScalar(u8, path, '.');
        while (it.next()) |comp| {
            if (node != m.node and m.tree.nodes.items[node].first_child == no_node) return true;
            const c = m.tree.childOf(node, comp);
            if (c == no_node) return false;
            node = c;
        }
        return true;
    }

    /// `FieldMaskTree::subtree`: null when the path is not in the mask.
    pub inline fn subtree(m: Mask, comptime path: []const u8) ?Mask {
        if (comptime knownBit(path)) |bit| {
            if (m.wild) return m;
            if ((m.tree.nodes.items[m.node].bits & bit) == 0) return null;
        }
        return m.subtreeDyn(path);
    }

    pub fn subtreeDyn(m: Mask, path: []const u8) ?Mask {
        if (path.len == 0) return null;
        if (m.wild) return m;
        var node = m.node;
        var it = std.mem.splitScalar(u8, path, '.');
        while (it.next()) |comp| {
            const c = m.tree.childOf(node, comp);
            if (c == no_node) return null;
            node = c;
        }
        if (node == m.node) return null;
        return .{ .tree = m.tree, .node = node, .wild = m.tree.nodes.items[node].first_child == no_node };
    }

    /// True when nothing is selected (an empty, non-wildcard mask).
    pub fn isEmpty(m: Mask) bool {
        return !m.wild and m.tree.nodes.items[m.node].first_child == no_node;
    }
};

pub fn isValidPath(path: []const u8) bool {
    if (std.mem.eql(u8, path, "*")) return true;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |c| if (!isValidComponent(c)) return false;
    return true;
}

fn isValidComponent(c: []const u8) bool {
    if (c.len == 0 or std.mem.eql(u8, c, "_")) return false;
    if (!(std.ascii.isAlphabetic(c[0]) or c[0] == '_')) return false;
    for (c[1..]) |b| if (!(std.ascii.isAlphanumeric(b) or b == '_')) return false;
    return true;
}

const testing = std.testing;

test "contains and subtree follow FieldMaskTree" {
    var t = try Tree.parse(testing.allocator, "summary.bcs,signature,transactions.effects.bcs,,x..y");
    defer t.deinit(testing.allocator);
    const m = t.mask();
    try testing.expect(m.contains("signature"));
    try testing.expect(m.contains("summary"));
    try testing.expect(m.contains("summary.bcs"));
    try testing.expect(!m.contains("summary.digest"));
    try testing.expect(!m.contains("contents"));
    try testing.expect(!m.contains("x"));
    const s = m.subtree("summary").?;
    try testing.expect(s.contains("bcs"));
    try testing.expect(!s.contains("epoch"));
    const sig = m.subtree("signature").?;
    try testing.expect(sig.wild and sig.contains("epoch"));
    try testing.expect(m.subtree("transactions").?.subtree("effects").?.contains("bcs"));
    try testing.expect(m.subtree("nope") == null);
}

test "ancestor replaces, descendant of a leaf is ignored, wildcard" {
    var t = try Tree.parse(testing.allocator, "a.b.c,a.b,a.b.d,e,e.f");
    defer t.deinit(testing.allocator);
    const m = t.mask();
    try testing.expect(m.contains("a.b.c") and m.contains("a.b.d") and m.contains("e.f"));
    try testing.expect(m.subtree("a").?.subtree("b").?.wild);
    var w = try Tree.parse(testing.allocator, "a,*,b");
    defer w.deinit(testing.allocator);
    try testing.expect(w.mask().contains("anything") and w.mask().subtree("q").?.wild);
    var e = try Tree.parse(testing.allocator, "");
    defer e.deinit(testing.allocator);
    try testing.expect(e.mask().isEmpty());
}
