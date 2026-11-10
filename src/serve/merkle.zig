//! sui-sdk-types `merkle` (rev 8c356d6, crates/sui-sdk-types/src/merkle.rs): the Blake2b256 Merkle
//! tree a checkpoint's `CheckpointArtifacts` commit to (the OCS tree), its inclusion proofs and
//! its sorted-leaf non-inclusion proofs. Pure (std only), so `zig test src/serve/merkle.zig` runs it.
//!
//! - leaf hash: BLAKE2b-256(0x00 || leaf bytes); inner hash: BLAKE2b-256(0x01 || left || right),
//!   an empty node hashing as 32 zero bytes;
//! - build: the leaf hashes, then level by level, a level of odd size padded with one Empty node
//!   before pairing; the root is the last node (Empty for zero leaves);
//! - proof of leaf i: the sibling of i on each level, leaf side first (siblings that are padding
//!   are Empty, which the wire form keeps apart from a digest);
//! - non-inclusion of a target in sorted leaves: `position` = how many leaves sort <= target,
//!   with the leaves at position-1 and position (when they exist) and their proofs.
//!
//! An OCS leaf is BCS `(ObjectID, SequenceNumber, ObjectDigest)`: 32 id bytes, the version as u64
//! little endian, then the digest as a length-prefixed byte string (0x20 + 32 bytes): 73 bytes.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Blake2b256 = std.crypto.hash.blake2.Blake2b256;

pub const digest_len = 32;
pub const leaf_prefix: u8 = 0x00;
pub const inner_prefix: u8 = 0x01;
pub const empty_node: [digest_len]u8 = @splat(0);

pub const Node = union(enum) {
    empty,
    digest: [digest_len]u8,

    pub fn bytes(n: Node) [digest_len]u8 {
        return switch (n) {
            .empty => empty_node,
            .digest => |d| d,
        };
    }
};

pub fn leafHash(input: []const u8) Node {
    var h = Blake2b256.init(.{});
    h.update(&.{leaf_prefix});
    h.update(input);
    var out: [digest_len]u8 = undefined;
    h.final(&out);
    return .{ .digest = out };
}

pub fn innerHash(left: Node, right: Node) Node {
    var h = Blake2b256.init(.{});
    h.update(&.{inner_prefix});
    const l = left.bytes();
    const r = right.bytes();
    h.update(&l);
    h.update(&r);
    var out: [digest_len]u8 = undefined;
    h.final(&out);
    return .{ .digest = out };
}

/// Nodes of a tree of `n_leaves` leaves (merkle.rs `n_nodes`).
pub fn nNodes(n_leaves: usize) usize {
    var lvl = n_leaves;
    var tot: usize = 0;
    while (lvl > 1) {
        lvl += lvl % 2;
        tot += lvl;
        lvl /= 2;
    }
    return tot + lvl;
}

pub const Tree = struct {
    nodes: []Node,
    n_leaves: usize,

    /// `MerkleTree::build_from_leaf_hashes`. The tree owns `nodes` (free with `deinit`).
    pub fn fromLeafHashes(a: Allocator, leaf_hashes: []const Node) Allocator.Error!Tree {
        const nodes = try a.alloc(Node, nNodes(leaf_hashes.len));
        @memcpy(nodes[0..leaf_hashes.len], leaf_hashes);
        var len = leaf_hashes.len;
        var level_nodes = leaf_hashes.len;
        var prev: usize = 0;
        while (level_nodes > 1) {
            if (level_nodes % 2 == 1) {
                nodes[len] = .empty;
                len += 1;
                level_nodes += 1;
            }
            const next = prev + level_nodes;
            var i = prev;
            while (i < next) : (i += 2) {
                nodes[len] = innerHash(nodes[i], nodes[i + 1]);
                len += 1;
            }
            prev = next;
            level_nodes /= 2;
        }
        std.debug.assert(len == nodes.len);
        return .{ .nodes = nodes, .n_leaves = leaf_hashes.len };
    }

    /// `MerkleTree::build_from_serialized`: leaves given as their bytes.
    pub fn fromLeaves(a: Allocator, leaves: []const []const u8) Allocator.Error!Tree {
        const hashes = try a.alloc(Node, leaves.len);
        defer a.free(hashes);
        for (leaves, hashes) |l, *h| h.* = leafHash(l);
        return fromLeafHashes(a, hashes);
    }

    pub fn deinit(t: *Tree, a: Allocator) void {
        a.free(t.nodes);
        t.* = undefined;
    }

    pub fn root(t: *const Tree) Node {
        return if (t.nodes.len == 0) .empty else t.nodes[t.nodes.len - 1];
    }

    /// Length of every proof of this tree.
    pub fn depth(t: *const Tree) usize {
        var n = t.n_leaves;
        var d: usize = 0;
        while (n > 1) : (d += 1) n = (n + 1) / 2;
        return d;
    }

    /// `MerkleTree::get_proof`: the sibling path of leaf `index`, leaf side first, written to
    /// `out` (at least `depth()` long). Returns the used part; null when `index` is out of range
    /// (`MerkleError::InvalidInput`).
    pub fn proof(t: *const Tree, index: usize, out: []Node) ?[]Node {
        if (index >= t.n_leaves) return null;
        var n: usize = 0;
        var level_index = index;
        var n_level = t.n_leaves;
        var base: usize = 0;
        while (n_level > 1) {
            n_level += n_level % 2;
            const sibling = if (level_index % 2 == 0) base + level_index + 1 else base + level_index - 1;
            out[n] = t.nodes[sibling];
            n += 1;
            level_index /= 2;
            base += n_level;
            n_level /= 2;
        }
        return out[0..n];
    }
};

/// `MerkleProof::compute_root`: null when `leaf_index` does not fit the path's length.
pub fn computeRoot(path: []const Node, leaf: []const u8, leaf_index: usize) ?Node {
    if (path.len < @bitSizeOf(usize) and (leaf_index >> @intCast(path.len)) != 0) return null;
    var cur = leafHash(leaf);
    var idx = leaf_index;
    for (path) |sib| {
        cur = if (idx % 2 == 0) innerHash(cur, sib) else innerHash(sib, cur);
        idx /= 2;
    }
    return cur;
}

/// `MerkleProof::is_right_most`.
pub fn isRightMost(path: []const Node, leaf_index: usize) bool {
    var idx = leaf_index;
    for (path) |sib| {
        if (idx % 2 == 0 and !std.mem.eql(u8, &sib.bytes(), &empty_node)) return false;
        idx /= 2;
    }
    return true;
}

// ---- OCS leaves ----

/// An OCS leaf: the final (version, digest) of an object the checkpoint wrote.
pub const ObjRef = struct {
    id: [32]u8,
    version: u64,
    digest: [32]u8,

    pub const bcs_len = 32 + 8 + 1 + 32;

    /// BCS `(ObjectID, SequenceNumber, ObjectDigest)`.
    pub fn bcs(r: *const ObjRef) [bcs_len]u8 {
        var out: [bcs_len]u8 = undefined;
        @memcpy(out[0..32], &r.id);
        std.mem.writeInt(u64, out[32..40], r.version, .little);
        out[40] = 32;
        @memcpy(out[41..73], &r.digest);
        return out;
    }

    pub fn lessById(_: void, x: ObjRef, y: ObjRef) bool {
        return std.mem.order(u8, &x.id, &y.id) == .lt;
    }
};

/// sui-types `ObjectDigest::OBJECT_DIGEST_DELETED` / `_WRAPPED` / `_CANCELLED`.
pub const digest_deleted: [32]u8 = @splat(99);
pub const digest_wrapped: [32]u8 = @splat(88);
pub const digest_cancelled: [32]u8 = @splat(77);

/// `ObjectDigest::is_alive`.
pub fn isAlive(d: *const [32]u8) bool {
    return !std.mem.eql(u8, d, &digest_deleted) and !std.mem.eql(u8, d, &digest_wrapped);
}

/// The OCS tree over `leaves` (sorted by id): `MerkleTree::build_from_unserialized`.
pub fn ocsTree(a: Allocator, leaves: []const ObjRef) Allocator.Error!Tree {
    const hashes = try a.alloc(Node, leaves.len);
    defer a.free(hashes);
    for (leaves, hashes) |*l, *h| h.* = leafHash(&l.bcs());
    return Tree.fromLeafHashes(a, hashes);
}

pub const Search = union(enum) {
    /// The leaf with the id.
    found: usize,
    /// Not in the tree: the non-inclusion position (count of leaves with a smaller id).
    absent: usize,
};

/// `binary_search_by_key(&object_id, |r| r.0)` on leaves sorted by id; on a miss, the position
/// `compute_non_inclusion_proof` gives target `(id, 0, [0; 32])`: `partition_point(leaf <= target)`
/// is the count of leaves whose id is smaller (no leaf has the id, so the version and digest
/// never decide).
pub fn search(leaves: []const ObjRef, id: *const [32]u8) Search {
    var lo: usize = 0;
    var hi: usize = leaves.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        switch (std.mem.order(u8, &leaves[mid].id, id)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return .{ .found = mid },
        }
    }
    return .{ .absent = lo };
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn hex32(comptime s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn dg(comptime s: []const u8) Node {
    return .{ .digest = hex32(s) };
}

fn idOf(comptime short: []const u8) [32]u8 {
    var buf: [64]u8 = @splat('0');
    @memcpy(buf[64 - short.len ..], short);
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, &buf) catch unreachable;
    return out;
}

test "merkle: n_nodes formula (merkle.rs)" {
    const want = [_]usize{ 0, 1, 3, 7, 7, 13, 13, 15, 15, 23 };
    for (want, 0..) |w, n| try testing.expectEqual(w, nNodes(n));
}

test "merkle: empty tree root is the empty node; one leaf's root is its leaf hash" {
    var t0 = try Tree.fromLeaves(testing.allocator, &.{});
    defer t0.deinit(testing.allocator);
    try testing.expectEqual(Node.empty, t0.root());
    var t1 = try Tree.fromLeaves(testing.allocator, &.{"Test"});
    defer t1.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &leafHash("Test").bytes(), &t1.root().bytes());
    var buf: [1]Node = undefined;
    try testing.expectEqual(@as(usize, 0), t1.proof(0, &buf).?.len);
    // BLAKE2b-256(0x00 || "foo"), checked with python hashlib
    try testing.expectEqualSlices(u8, &hex32("d49d71d62803f5c6b8c9ae0f1029a4e351a51eff62646fa1ea74d6b7279a3e5e"), &leafHash("foo").bytes());
}

test "merkle: every proof round-trips, right-most detection, out of range" {
    const input = [_][]const u8{ "foo", "bar", "fizz", "baz", "buzz", "fizz", "foobar", "walrus", "fizz" };
    var buf: [16]Node = undefined;
    for (0..input.len + 1) |n| {
        var t = try Tree.fromLeaves(testing.allocator, input[0..n]);
        defer t.deinit(testing.allocator);
        for (input[0..n], 0..) |leaf, i| {
            const p = t.proof(i, &buf).?;
            try testing.expectEqual(t.depth(), p.len);
            try testing.expectEqualSlices(u8, &t.root().bytes(), &computeRoot(p, leaf, i).?.bytes());
            if (i + 1 < n) try testing.expect(!std.mem.eql(u8, &t.root().bytes(), &computeRoot(p, leaf, i + 1).?.bytes()));
            try testing.expectEqual(i == n - 1, isRightMost(p, i));
        }
        try testing.expect(t.proof(n, &buf) == null);
    }
}

test "merkle: OCS leaf BCS and a padded 3-leaf tree equal sui-node's checkpoint 1 root (rpc-surface proof captures)" {
    // localnet checkpoint 1's object states (proof/short-object-id, object-no-0x-prefix)
    const leaves = [_]ObjRef{
        .{ .id = idOf("6"), .version = 2, .digest = hex32("08d1e5672b09fc1bb7cc9ba473516e2be3f51309115c9d9e462dd139ca74fdee") },
        .{ .id = idOf("acc"), .version = 2, .digest = hex32("da6ce33921026be46136e69db1325a25f3bef21bf8de7fd987f8aa6da60c9066") },
        .{ .id = hex32("ea4eb77f2a5a8ba172de0c4d2c51be91686ec84fdccd9a9dadd3ba7674bac468"), .version = 2, .digest = hex32("466d901a54104880ad2139e9de818b3aa61ae3d771137c322c80624ef37f580e") },
    };
    var t = try ocsTree(testing.allocator, &leaves);
    defer t.deinit(testing.allocator);
    try testing.expectEqualSlices(u8, &hex32("4b37da323ac2c4f7fae8527620e4bb1e26781cd2eb2a000005dca306961d4ec5"), &t.root().bytes());
    var buf: [4]Node = undefined;
    // the right neighbour's proof in object-no-0x-prefix: [Empty, 2bce..]
    const p2 = t.proof(2, &buf).?;
    try testing.expectEqual(@as(usize, 2), p2.len);
    try testing.expectEqual(Node.empty, p2[0]);
    try testing.expectEqualSlices(u8, &hex32("2bce8d464df8d70c97d6296d2d521d03814efa22c26c2ab62a4255827d41357d"), &p2[1].bytes());
    try testing.expect(isRightMost(p2, 2));
    // short-object-id: the right neighbour 0x6 at index 0, path [aba7.., 414d..]
    const p0 = t.proof(0, &buf).?;
    try testing.expectEqualSlices(u8, &hex32("aba7f041a7ba9145d3cbe7689e485aebbf751d26a3382a4f61b9fd641887ae6d"), &p0[0].bytes());
    try testing.expectEqualSlices(u8, &hex32("414d93f03e9a698b210740d4b3f07ae41b9d8e11aa752a7993b6b04d3d86a22b"), &p0[1].bytes());
    // positions: 0x5 sorts first (short-object-id index 0), 0xe4b5.. between 0xacc and 0xea4e (2)
    try testing.expectEqual(Search{ .absent = 0 }, search(&leaves, &idOf("5")));
    try testing.expectEqual(Search{ .absent = 2 }, search(&leaves, &hex32("e4b533e84975e5f2a48ae1961e2606e81a57050fe738ca30ac77ed4d8b9b4f18")));
    try testing.expectEqual(Search{ .found = 1 }, search(&leaves, &idOf("acc")));
}

test "merkle: sui-node inclusion proofs verify (counter at cp148, deleted thing3 at cp160)" {
    // proof/counter-shared-touched-cp148: leaf index 8 of 10, padding siblings on two levels
    const counter: ObjRef = .{ .id = hex32("e4b533e84975e5f2a48ae1961e2606e81a57050fe738ca30ac77ed4d8b9b4f18"), .version = 3, .digest = hex32("4f020be0008d1fa1e3acf5adfa2da112b25cbbc185c7b0fba83826ceca2b614e") };
    const path = [_]Node{ dg("4b6f732d5fd2935eaa98ee7f06423fac1f586067d1cb8157b323a7674cf8e106"), .empty, .empty, dg("0ce665fb8f08118153acb78c7ffe4cbd16c6fc754426f1c90d6539e4fa2ff390") };
    try testing.expectEqualSlices(u8, &hex32("5aaeb2c3aa298dc398adf1a3f971fdf7ecc907da9ee70e6f9c7332b25bce3b1c"), &computeRoot(&path, &counter.bcs(), 8).?.bytes());
    try testing.expect(isRightMost(&path, 8) == false);
    // proof/thing3-created-deleted-touched-cp160: the deleted sentinel digest is the leaf's digest
    const thing3: ObjRef = .{ .id = hex32("8ae04fe791bd1e120b7031c41905cb5216888928c65d0f9533ad031cd677d27d"), .version = 9, .digest = digest_deleted };
    try testing.expect(!isAlive(&thing3.digest));
    try testing.expect(isAlive(&digest_cancelled));
    const path3 = [_]Node{ dg("4343edb5ff9fb7ee59e9a6e5f772b5cbecd044a8a1ab61d6c72e5768c56c92b6"), dg("0942ab4d68de55e891d0722147c1b081f8e5761b20cd2fa8b236534d850e9930") };
    try testing.expectEqualSlices(u8, &hex32("1643acb3ad2c92675d96083e4c8ef75494d45dc44c6de3dad1d67a34d4e5d89e"), &computeRoot(&path3, &thing3.bcs(), 3).?.bytes());
    try testing.expect(isRightMost(&path3, 3));
    // index past the path's reach
    try testing.expect(computeRoot(&path3, &thing3.bcs(), 4) == null);
}
