//! Digests and intent messages exactly as Mysten computes them (sui-types crypto.rs `Signable`,
//! shared-crypto intent.rs).
const std = @import("std");
const core = @import("core");
const hand = @import("hand.zig");
const hash = @import("hash");
const Blake2b256 = hash.Blake2b256;

/// Sui digest of a BcsSignable value from its raw BCS bytes: Blake2b256(name ++ "::" ++ raw).
/// `type_name` is the serde name of the Rust type: "TransactionData", "TransactionEffects",
/// "TransactionEvents", "CheckpointSummary", "CheckpointContents", "SenderSignedData", "Object".
pub fn digestOf(comptime type_name: []const u8, raw: []const u8) core.Bytes32 {
    var h = Blake2b256.init();
    h.update(type_name ++ "::");
    h.update(raw);
    var out: core.Bytes32 = undefined;
    h.final(&out);
    return out;
}

/// `digestOf` over many values of one type at once, through the multi-buffer Blake2b kernel
/// (several messages per SIMD pass). `out[i] == digestOf(type_name, raws[i])`. No allocation.
pub fn digestOfMany(comptime type_name: []const u8, raws: []const []const u8, out: [][32]u8) void {
    std.debug.assert(out.len >= raws.len);
    const chunk = 64;
    const prefix: []const u8 = type_name ++ "::";
    var parts: [chunk][2][]const u8 = undefined;
    var inputs: [chunk][]const []const u8 = undefined;
    var i: usize = 0;
    while (i < raws.len) {
        const n = @min(chunk, raws.len - i);
        for (0..n) |k| {
            parts[k] = .{ prefix, raws[i + k] };
            inputs[k] = &parts[k];
        }
        hash.blake2b256Many(inputs[0..n], out[i..][0..n]);
        i += n;
    }
}

/// One message of `digestMixed`: `prefix` is `type_name ++ "::"` (see `prefixOf`).
pub const Item = struct { prefix: []const u8, raw: []const u8 };

pub fn prefixOf(comptime type_name: []const u8) []const u8 {
    return type_name ++ "::";
}

/// Digests of mixed-type values, all through one multi-buffer pass so short and long messages
/// keep every SIMD lane busy. `out[i] == Blake2b256(items[i].prefix ++ items[i].raw)`. The caller
/// supplies scratch (`parts.len`, `inputs.len` and `out.len` at least `items.len`).
pub fn digestMixed(items: []const Item, parts: [][2][]const u8, inputs: [][]const []const u8, out: [][32]u8) void {
    for (items, 0..) |it, k| {
        parts[k] = .{ it.prefix, it.raw };
        inputs[k] = &parts[k];
    }
    hash.blake2b256Many(inputs[0..items.len], out[0..items.len]);
}

pub fn transactionDataDigest(raw: []const u8) core.Bytes32 {
    return digestOf("TransactionData", raw);
}
pub fn effectsDigest(raw: []const u8) core.Bytes32 {
    return digestOf("TransactionEffects", raw);
}
pub fn eventsDigest(raw: []const u8) core.Bytes32 {
    return digestOf("TransactionEvents", raw);
}
pub fn checkpointSummaryDigest(raw: []const u8) core.Bytes32 {
    return digestOf("CheckpointSummary", raw);
}
pub fn checkpointContentsDigest(raw: []const u8) core.Bytes32 {
    return digestOf("CheckpointContents", raw);
}
/// Full-message digest of a SenderSignedData (what consensus dedups on); not the transaction
/// digest, which is `transactionDataDigest` over the TransactionData.
pub fn senderSignedDataDigest(raw: []const u8) core.Bytes32 {
    return digestOf("SenderSignedData", raw);
}
/// Digest of a GlobalStateHash (fastcrypto's EllipticCurveMultisetHash, 32 bytes on the wire);
/// the serde name Rust hashes under is the struct's, not the alias.
pub fn globalStateHashDigest(raw: []const u8) core.Bytes32 {
    return digestOf("EllipticCurveMultisetHash", raw);
}
/// Object digests use the serde name "Object".
pub fn objectDigest(raw: []const u8) core.Bytes32 {
    return digestOf("Object", raw);
}

/// Blake2b256(intent ++ raw_value): what a user signs for a transaction (scope 0) and what
/// authorities sign (the checkpoint adds the epoch, see `checkpointSigningDigest`).
pub fn intentMessageDigest(intent: hand.Intent, raw_value: []const u8) core.Bytes32 {
    var h = Blake2b256.init();
    h.update(&intent.bytes());
    h.update(raw_value);
    var out: core.Bytes32 = undefined;
    h.final(&out);
    return out;
}

/// Digest of the BLS-signed message of a checkpoint:
/// Blake2b256(BCS(IntentMessage(CheckpointSummary scope, summary)) ++ BCS(epoch)).
pub fn checkpointSigningDigest(raw_summary: []const u8, epoch: u64) core.Bytes32 {
    var h = Blake2b256.init();
    h.update(&hand.Intent.sui(.checkpoint_summary).bytes());
    h.update(raw_summary);
    var e: [8]u8 = undefined;
    std.mem.writeInt(u64, &e, epoch, .little);
    h.update(&e);
    var out: core.Bytes32 = undefined;
    h.final(&out);
    return out;
}

/// Signing digest of a transaction: Blake2b256(IntentMessage(TransactionData scope, data)).
pub fn transactionSigningDigest(raw_data: []const u8) core.Bytes32 {
    return intentMessageDigest(hand.Intent.sui(.transaction_data), raw_data);
}

test "digestOfMany equals digestOf for every count and size" {
    var bufs: [150][]u8 = undefined;
    var raws: [150][]const u8 = undefined;
    for (&bufs, 0..) |*b, i| {
        b.* = try std.testing.allocator.alloc(u8, (i * 37) % 700);
        for (b.*, 0..) |*c, j| c.* = @truncate(i *% 31 +% j *% 7);
        raws[i] = b.*;
    }
    defer for (bufs) |b| std.testing.allocator.free(b);
    for ([_]usize{ 0, 1, 2, 3, 5, 64, 65, 150 }) |n| {
        var out: [150][32]u8 = undefined;
        digestOfMany("Object", raws[0..n], out[0..n]);
        for (0..n) |i| try std.testing.expectEqual(digestOf("Object", raws[i]), out[i]);
    }
}
