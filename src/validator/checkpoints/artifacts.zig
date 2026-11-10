//! CheckpointArtifacts (sui-types `messages_checkpoint.rs`, 1.83.1; protocol flag
//! `include_checkpoint_artifacts_digest_in_summary`): the digest of the post-checkpoint object
//! states committed in the summary's `checkpoint_commitments`.
//!
//!   object_states = BTreeMap<ObjectID, (SequenceNumber, ObjectDigest)> over every effects'
//!                   `written()`, a later write replacing an earlier one (its version must be
//!                   strictly greater, Rust asserts)
//!   artifact digest = root of fastcrypto's binary MerkleTree<Blake2b256> whose leaves are
//!                   BCS((id, version, digest)) in ObjectID order
//!   artifacts digest = Blake2b256(BCS(Vec<Digest>[artifact digests]))
const std = @import("std");
const hash = @import("hash");
const ev = @import("effects_view.zig");

pub const Error = error{ NonMonotonicObjectVersion, OutOfMemory } || ev.Error;

const leaf_prefix = [1]u8{0};
const inner_prefix = [1]u8{1};

/// fastcrypto `MerkleTree<Blake2b256>::build_from_serialized(leaves).root()`: leaf =
/// H(0x00 ++ data), inner = H(0x01 ++ left ++ right), an odd node on a level is paired with the
/// empty node (32 zero bytes), no leaves = the empty node.
pub fn merkleRoot(gpa: std.mem.Allocator, leaves: []const []const u8) Error![32]u8 {
    if (leaves.len == 0) return @splat(0);
    var level = try gpa.alloc([32]u8, leaves.len + 1);
    defer gpa.free(level);
    for (leaves, 0..) |l, i| level[i] = hash.blake2b256(&.{ &leaf_prefix, l });
    var n = leaves.len;
    while (n > 1) {
        if (n % 2 == 1) {
            level[n] = @splat(0);
            n += 1;
        }
        var i: usize = 0;
        while (i < n) : (i += 2) level[i / 2] = hash.blake2b256(&.{ &inner_prefix, &level[i], &level[i + 1] });
        n /= 2;
    }
    return level[0];
}

const State = struct { id: [32]u8, version: u64, digest: [32]u8, order: u32 };

fn stateLess(_: void, a: State, b: State) bool {
    const o = std.mem.order(u8, &a.id, &b.id);
    if (o != .eq) return o == .lt;
    return a.order < b.order;
}

/// The ObjectStates map over `effects` in checkpoint order, as sorted (id, version, digest).
pub fn objectStates(gpa: std.mem.Allocator, effects: []const ev.View) Error![]ev.ObjRef {
    var refs: std.ArrayList(ev.ObjRef) = .empty;
    defer refs.deinit(gpa);
    for (effects) |*e| try e.written(gpa, &refs);
    const st = try gpa.alloc(State, refs.items.len);
    defer gpa.free(st);
    for (refs.items, st, 0..) |r, *s, i| s.* = .{ .id = r.id, .version = r.version, .digest = r.digest, .order = @intCast(i) };
    std.mem.sort(State, st, {}, stateLess);
    var out: std.ArrayList(ev.ObjRef) = .empty;
    errdefer out.deinit(gpa);
    for (st, 0..) |s, i| {
        if (i + 1 < st.len and std.mem.eql(u8, &st[i + 1].id, &s.id)) {
            if (!(s.version < st[i + 1].version)) return error.NonMonotonicObjectVersion;
            continue;
        }
        try out.append(gpa, .{ .id = s.id, .version = s.version, .digest = s.digest });
    }
    return out.toOwnedSlice(gpa);
}

/// `CheckpointArtifact::ObjectStates` digest.
pub fn objectStatesDigest(gpa: std.mem.Allocator, states: []const ev.ObjRef) Error![32]u8 {
    // leaf = BCS((ObjectID, SequenceNumber, ObjectDigest)): 32 + 8 + (1 + 32) bytes
    const buf = try gpa.alloc([73]u8, states.len);
    defer gpa.free(buf);
    const leaves = try gpa.alloc([]const u8, states.len);
    defer gpa.free(leaves);
    for (states, buf, leaves) |s, *b, *l| {
        b[0..32].* = s.id;
        std.mem.writeInt(u64, b[32..40], s.version, .little);
        b[40] = 32;
        b[41..73].* = s.digest;
        l.* = b;
    }
    return merkleRoot(gpa, leaves);
}

/// `CheckpointArtifacts::from(&effects).digest()` (the single ObjectStates artifact).
pub fn artifactsDigest(gpa: std.mem.Allocator, effects: []const ev.View) Error![32]u8 {
    const states = try objectStates(gpa, effects);
    defer gpa.free(states);
    const root = try objectStatesDigest(gpa, states);
    // BCS(Vec<Digest>): one element = 0x01, then the Digest as bytes (0x20 ++ 32)
    var msg: [1 + 1 + 32]u8 = undefined;
    msg[0] = 1;
    msg[1] = 32;
    msg[2..34].* = root;
    return hash.blake2b256(&.{&msg});
}

test "merkle root shapes" {
    const a = std.testing.allocator;
    try std.testing.expectEqual(@as([32]u8, @splat(0)), try merkleRoot(a, &.{}));
    // one leaf: the leaf hash
    const l0 = hash.blake2b256(&.{ &leaf_prefix, "a" });
    try std.testing.expectEqual(l0, try merkleRoot(a, &.{"a"}));
    // two leaves
    const l1 = hash.blake2b256(&.{ &leaf_prefix, "b" });
    const r2 = hash.blake2b256(&.{ &inner_prefix, &l0, &l1 });
    try std.testing.expectEqual(r2, try merkleRoot(a, &.{ "a", "b" }));
    // three leaves: the third pairs with the empty node
    const l2 = hash.blake2b256(&.{ &leaf_prefix, "c" });
    const n01 = r2;
    const n23 = hash.blake2b256(&.{ &inner_prefix, &l2, &@as([32]u8, @splat(0)) });
    const r3 = hash.blake2b256(&.{ &inner_prefix, &n01, &n23 });
    try std.testing.expectEqual(r3, try merkleRoot(a, &.{ "a", "b", "c" }));
}
