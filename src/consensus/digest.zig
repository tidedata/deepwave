//! Block and commit encodings, digests and the block signing message, as `consensus/core/src/block.rs`
//! and `commit.rs` compute them at mainnet-v1.83.1. Owner lane: val-consensus-core.
//!
//! - InnerBlockDigest = Blake2b256(BCS(Block))               (what the author signs)
//! - signing message   = BCS(IntentMessage(Intent{scope 8, version 0, app 2}, InnerBlockDigest))
//!                     = [8, 0, 2] ++ InnerBlockDigest (35 bytes)
//! - BlockDigest       = Blake2b256(BCS(SignedBlock))         (the serialized bytes as received)
//! - CommitDigest      = Blake2b256(BCS(Commit))
//!
//! BCS of the declarations in types.zig equals serde's bytes (field and variant order is the
//! serde order, `[32]u8` digests are fixed arrays, `Bytes` are length-prefixed).
const std = @import("std");
const builtin = @import("builtin");
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types.zig");
const err = @import("error.zig");
const config = @import("config.zig");
const committee_mod = @import("committee.zig");

/// Intent bytes of IntentScope::ConsensusBlock, IntentVersion::V0, AppId::Consensus.
pub const consensus_block_intent = [3]u8{ 8, 0, 2 };
pub const signing_message_len = 3 + types.DIGEST_LENGTH;

pub fn blake2b(bytes: []const u8) [32]u8 {
    return hash.blake2b256(&.{bytes});
}

/// `compute_inner_block_digest`.
pub fn innerBlockDigest(gpa: std.mem.Allocator, block: *const types.Block) err.Error!types.BlockDigest {
    const bytes = bcs.encodeAlloc(types.Block, gpa, block) catch return error.OutOfMemory;
    defer gpa.free(bytes);
    return blake2b(bytes);
}

pub fn signingMessage(inner_digest: *const types.BlockDigest) [signing_message_len]u8 {
    var m: [signing_message_len]u8 = undefined;
    m[0..3].* = consensus_block_intent;
    m[3..].* = inner_digest.*;
    return m;
}

/// Digest of serialized SignedBlock bytes (VerifiedBlock::compute_digest).
pub fn blockDigest(serialized_signed_block: []const u8) types.BlockDigest {
    return blake2b(serialized_signed_block);
}

/// Digest of serialized Commit bytes (TrustedCommit::compute_digest).
pub fn commitDigest(serialized_commit: []const u8) types.CommitDigest {
    return blake2b(serialized_commit);
}

/// Message the author signs for `block`.
pub fn blockSigningMessage(gpa: std.mem.Allocator, block: *const types.Block) err.Error![signing_message_len]u8 {
    const d = try innerBlockDigest(gpa, block);
    return signingMessage(&d);
}

// ---------------------------------------------------------------- one-pass block digests
//
// BCS(SignedBlock) = BCS(Block) ++ ULEB128(signature length) ++ signature (serde: `inner`, then
// `signature: Bytes`), so the message of InnerBlockDigest is a prefix of the message of
// BlockDigest and Blake2b's chaining state after the prefix serves both: one pass over the
// serialized bytes, the state copied where the inner block ends. The digests are the ones
// `innerBlockDigest` and `blockDigest` give; only the work differs (no second pass, no re-encode
// of the inner block into a fresh buffer).

/// Runtime switch of the one-pass digests in `SignedBlockVerifier` and `PendingBlock`. Off by
/// default: the two-pass code runs. On with `setOnePass(true)` or ZUI_BLOCK_ONE_PASS=1 in the
/// environment (read once, at first use). 0 = not read yet, 1 = off, 2 = on.
var one_pass: std.atomic.Value(u8) = .init(0);

pub fn onePass() bool {
    const s = one_pass.load(.monotonic);
    if (s != 0) return s == 2;
    return onePassFromEnv();
}

fn onePassFromEnv() bool {
    @branchHint(.cold);
    const on = if (std.c.getenv("ZUI_BLOCK_ONE_PASS")) |v| std.mem.eql(u8, std.mem.span(v), "1") else false;
    // a `setOnePass` that ran meanwhile wins
    _ = one_pass.cmpxchgStrong(0, if (on) 2 else 1, .monotonic, .monotonic);
    return one_pass.load(.monotonic) == 2;
}

pub fn setOnePass(on: bool) void {
    one_pass.store(if (on) 2 else 1, .monotonic);
}

pub const BlockDigests = struct {
    /// Blake2b256(BCS(Block)): what the author signs (inside the intent message).
    inner: types.BlockDigest,
    /// Blake2b256(BCS(SignedBlock)): the digest of the BlockRef.
    block: types.BlockDigest,
};

/// Both digests from one Blake2b-256 pass over `serialized`, where `serialized[0..inner_len]`
/// is BCS(Block) (see `innerLen`).
pub fn blockDigestsAt(serialized: []const u8, inner_len: usize) BlockDigests {
    var h = hash.Blake2b256.init();
    h.update(serialized[0..inner_len]);
    // `final` pads and compresses the last block in place, so the inner digest comes from a copy
    // and `h` goes on with the signature field.
    var fork = h;
    var out: BlockDigests = undefined;
    fork.final(&out.inner);
    h.update(serialized[inner_len..]);
    h.final(&out.block);
    return out;
}

/// Where BCS(sb.inner) ends inside `serialized`, for an `sb` decoded from `serialized`; null
/// when that cannot be shown, and the caller then takes the two-pass code. Shown by:
///   - the signature is the last `signature.len` bytes of `serialized` (the decoder borrows it),
///   - the canonical encoding of the inner block has exactly the length left in front of the
///     signature's canonical length prefix.
/// The decoder follows bcs 0.1.6: every ULEB128 canonical, all input consumed, and a Block has no
/// bool, option or map, so the bytes it read for the inner block are the bytes the encoder
/// writes for it. A longer (non-canonical) form cannot pass the length comparison even if a
/// decoder accepted it.
pub fn innerLen(sb: *const types.SignedBlock, serialized: []const u8) ?usize {
    const sig = sb.signature;
    if (sig.len > bcs.max_sequence_length) return null;
    const tail = bcs.ulebLen(@intCast(sig.len)) + sig.len;
    if (serialized.len < tail) return null;
    if (@intFromPtr(sig.ptr) + sig.len != @intFromPtr(serialized.ptr) + serialized.len) return null;
    const inner_len = serialized.len - tail;
    if (bcs.encodedLen(types.Block, &sb.inner) != inner_len) return null;
    return inner_len;
}

/// Debug builds only: `prefix` (what the one-pass hash takes as the inner block) must be the
/// encoding `innerBlockDigest` hashes.
pub fn debugCheckInnerPrefix(gpa: std.mem.Allocator, block: *const types.Block, prefix: []const u8) void {
    if (builtin.mode != .debug) return;
    const bytes = bcs.encodeAlloc(types.Block, gpa, block) catch return;
    defer gpa.free(bytes);
    std.debug.assert(std.mem.eql(u8, bytes, prefix));
}

// ---------------------------------------------------------------- construction

/// BCS of a SignedBlock (`SignedBlock::serialize`), allocated from `gpa`.
pub fn serializeSignedBlock(gpa: std.mem.Allocator, sb: *const types.SignedBlock) err.Error![]u8 {
    return bcs.encodeAlloc(types.SignedBlock, gpa, sb) catch error.OutOfMemory;
}

/// Wraps already serialized bytes (which must be exactly BCS of `sb`) as a VerifiedBlock without
/// copying: `VerifiedBlock::new_verified`.
pub fn newVerified(sb: types.SignedBlock, serialized: []const u8) types.VerifiedBlock {
    return .{ .block = sb, .serialized = serialized, .digest = blockDigest(serialized) };
}

/// A block between "contents chosen" and "signed": `Core.tryNewBlock` and `SignedBlock::new`
/// followed by `serialize` and `VerifiedBlock::new_verified`. `init` gives the message to sign,
/// `seal` the VerifiedBlock. With `onePass()` the inner block is encoded once into the buffer
/// that becomes the serialized block and hashed once: the state after it gives the
/// InnerBlockDigest (a copy) and, continued over the signature field, the BlockDigest. Without
/// it the two-pass calls run exactly as before. Bytes and digests are the same either way.
pub const PendingBlock = struct {
    block: types.Block,
    /// What the author signs: the intent message of the InnerBlockDigest.
    message: [signing_message_len]u8,
    /// One pass: BCS(block) followed by room for the signature field, and the Blake2b state
    /// after BCS(block). Null: two passes.
    one: ?struct { buf: []u8, h: hash.Blake2b256 } = null,

    const signature_field_len = 1 + 64; // ULEB128(64) ++ signature

    /// `arena` holds the serialized block (one pass); `gpa` is the scratch of the two-pass
    /// inner digest.
    pub fn init(arena: std.mem.Allocator, gpa: std.mem.Allocator, block: types.Block) err.Error!PendingBlock {
        if (!onePass()) return .{ .block = block, .message = try blockSigningMessage(gpa, &block) };
        const inner_len = bcs.encodedLen(types.Block, &block);
        const buf = arena.alloc(u8, inner_len + signature_field_len) catch return error.OutOfMemory;
        var w = bcs.Writer.init(buf[0..inner_len]);
        bcs.encode(types.Block, &block, &w) catch unreachable;
        var h = hash.Blake2b256.init();
        h.update(buf[0..inner_len]);
        var fork = h;
        var inner: types.BlockDigest = undefined;
        fork.final(&inner);
        return .{ .block = block, .message = signingMessage(&inner), .one = .{ .buf = buf, .h = h } };
    }

    /// The signed block, serialized in `arena`, with its digest. `signature` is the author's
    /// signature of `message`.
    pub fn seal(p: *const PendingBlock, arena: std.mem.Allocator, signature: *const [64]u8) err.Error!types.VerifiedBlock {
        const one = p.one orelse {
            const sig_copy = arena.dupe(u8, signature) catch return error.OutOfMemory;
            const sb: types.SignedBlock = .{ .inner = p.block, .signature = sig_copy };
            const serialized = try serializeSignedBlock(arena, &sb);
            return newVerified(sb, serialized);
        };
        const buf = one.buf;
        const inner_len = buf.len - signature_field_len;
        buf[inner_len] = 64;
        buf[inner_len + 1 ..][0..64].* = signature.*;
        var h = one.h;
        h.update(buf[inner_len..]);
        var d: types.BlockDigest = undefined;
        h.final(&d);
        // the signature is the end of the serialized bytes, as in a decoded block
        return .{ .block = .{ .inner = p.block, .signature = buf[inner_len + 1 ..] }, .serialized = buf, .digest = d };
    }
};

/// Decodes `serialized` (BCS SignedBlock, must consume all bytes) into `arena`. The result
/// borrows `serialized` for byte fields. A malformed block is `error.SerializationFailure`.
pub fn decodeSignedBlock(arena: std.mem.Allocator, serialized: []const u8) err.Error!types.SignedBlock {
    return bcs.decode(types.SignedBlock, arena, serialized) catch |e| switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.SerializationFailure,
    };
}

/// Decode plus digest (`VerifiedBlock` fields without any verification).
pub fn decodeVerifiedUnchecked(arena: std.mem.Allocator, serialized: []const u8) err.Error!types.VerifiedBlock {
    return newVerified(try decodeSignedBlock(arena, serialized), serialized);
}

/// `VerifiedBlock::new_for_test`: empty signature, serialized in `arena`.
pub fn verifiedForTest(arena: std.mem.Allocator, block: types.Block) err.Error!types.VerifiedBlock {
    const sb: types.SignedBlock = .{ .inner = block, .signature = &.{} };
    const ser = try serializeSignedBlock(arena, &sb);
    return newVerified(sb, ser);
}

/// Deep copy of a VerifiedBlock into `arena` (serialized bytes duplicated and re-decoded), so the
/// copy outlives whatever owned the original.
pub fn cloneVerified(arena: std.mem.Allocator, vb: *const types.VerifiedBlock) err.Error!types.VerifiedBlock {
    const ser = arena.dupe(u8, vb.serialized) catch return error.OutOfMemory;
    // the digest is the original's: no second Blake2b-256 over the bytes
    return .{ .block = try decodeSignedBlock(arena, ser), .serialized = ser, .digest = vb.digest };
}

/// `Commit::serialize` + `TrustedCommit::new_trusted`.
pub fn newTrustedCommit(gpa: std.mem.Allocator, commit: types.Commit) err.Error!types.TrustedCommit {
    const ser = bcs.encodeAlloc(types.Commit, gpa, &commit) catch return error.OutOfMemory;
    return .{ .commit = commit, .serialized = ser, .digest = commitDigest(ser) };
}

/// `genesis_blocks`: one per authority, in authority index order, empty signature, round 0,
/// timestamp = epoch start. Block version follows the protocol config (V3 > V2 > V1).
pub fn genesisBlocks(arena: std.mem.Allocator, committee: *const committee_mod.Committee, epoch_start_timestamp_ms: u64, pc: *const config.ProtocolConfig) err.Error![]types.VerifiedBlock {
    const out = arena.alloc(types.VerifiedBlock, committee.size()) catch return error.OutOfMemory;
    for (out, 0..) |*slot, i| {
        const author: types.AuthorityIndex = @intCast(i);
        const block: types.Block = if (pc.enable_v3)
            .{ .V3 = .{ .epoch = committee.epoch, .round = 0, .author = author, .timestamp_ms = epoch_start_timestamp_ms, .ancestors = &.{}, .transactions = &.{}, .transaction_votes = &.{}, .transaction_votes_cutoff_round = 0, .commit_votes = &.{}, .misbehavior_reports = &.{} } }
        else if (pc.transaction_voting_enabled)
            .{ .V2 = .{ .epoch = committee.epoch, .round = 0, .author = author, .timestamp_ms = epoch_start_timestamp_ms, .ancestors = &.{}, .transactions = &.{}, .transaction_votes = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } }
        else
            .{ .V1 = .{ .epoch = committee.epoch, .round = 0, .author = author, .timestamp_ms = epoch_start_timestamp_ms, .ancestors = &.{}, .transactions = &.{}, .commit_votes = &.{}, .misbehavior_reports = &.{} } };
        slot.* = try verifiedForTest(arena, block);
    }
    return out;
}

test "signing message layout" {
    const d: types.BlockDigest = @splat(7);
    const m = signingMessage(&d);
    try std.testing.expectEqualSlices(u8, &.{ 8, 0, 2, 7 }, m[0..4]);
}

test "block BCS round trip, digest is blake2b of the serialized signed block" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const anc = [_]types.BlockRef{.{ .round = 1, .author = 2, .digest = @splat(9) }};
    const txs = [_]types.Transaction{.{ .data = "hello" }};
    const votes = [_]types.CommitVote{.{ .index = 4, .digest = @splat(1) }};
    const blk: types.Block = .{ .V2 = .{ .epoch = 3, .round = 2, .author = 1, .timestamp_ms = 1234, .ancestors = &anc, .transactions = &txs, .transaction_votes = &.{}, .commit_votes = &votes, .misbehavior_reports = &.{} } };
    const vb = try verifiedForTest(arena, blk);
    const back = try decodeVerifiedUnchecked(arena, vb.serialized);
    try std.testing.expectEqual(vb.digest, back.digest);
    try std.testing.expectEqual(@as(u64, 1234), back.block.inner.timestampMs());
    try std.testing.expectEqualStrings("hello", back.block.inner.transactions()[0].data);
    // Layout: variant tag 1 (V2), then epoch u64 LE.
    try std.testing.expectEqual(@as(u8, 1), vb.serialized[0]);
    try std.testing.expectEqual(@as(u8, 3), vb.serialized[1]);
    const c = try cloneVerified(arena, &vb);
    try std.testing.expectEqual(vb.digest, c.digest);
}
