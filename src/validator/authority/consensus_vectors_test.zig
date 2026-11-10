//! ConsensusTransaction wire parity with Mysten sui-types 1.83.1 (protocol 141). The vectors in
//! testdata/consensus_tx_vectors.txt come from a scratch Rust test over sui-types: every
//! ConsensusTransactionKind variant (indices 0..13), the transaction claims, and malformed
//! inputs a Byzantine proposer could send. For each one deepwave must decode exactly when Rust does
//! (a decode failure rejects the whole block in both), re-encode to the same bytes, and derive
//! the same ConsensusTransactionKey and digests.
//!
//! The deny-config share-limit cases rebuild the Rust ZUILIMIT inputs byte for byte (pinned by
//! SHA-256) and check the verdict Rust's `check_share_limits` gave on them.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const protocol = @import("protocol");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const env_mod = @import("env.zig");
const tx_validator = @import("tx_validator.zig");

const Allocator = std.mem.Allocator;
const vectors = @embedFile("testdata/consensus_tx_vectors.txt");

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn txDigest(a: Allocator, ssd: *const types.SenderSignedData) !types.TransactionDigest {
    const enc = try bcs.encodeAlloc(types.TransactionData, a, &ssd.@"0".element().intent_message.value);
    return .{ .@"0" = .{ .@"0" = hash.blake2b256(&.{ "TransactionData::", enc }) } };
}

fn ckptDigest(a: Allocator, s: *const types.CheckpointSummary) !types.CheckpointDigest {
    const enc = try bcs.encodeAlloc(types.CheckpointSummary, a, s);
    return .{ .@"0" = .{ .@"0" = hash.blake2b256(&.{ "CheckpointSummary::", enc }) } };
}

/// `ConsensusTransaction::key()` (null for RandomnessStateUpdate, which the generator skips).
fn rustKey(a: Allocator, k: *const messages.ConsensusTransactionKind) !?messages.ConsensusTransactionKey {
    return switch (k.*) {
        .CertifiedTransaction => |c| .{ .Certificate = try txDigest(a, &c.data) },
        .CheckpointSignature => |m| .{ .CheckpointSignature = .{ m.summary.auth_signature.authority, m.summary.data.sequence_number } },
        .EndOfPublish => |n| .{ .EndOfPublish = n },
        .CapabilityNotification => |c| .{ .CapabilityNotification = .{ c.authority, c.generation } },
        .NewJWKFetched => |j| .{ .NewJWKFetched = .{ j[0], j[1], j[2] } },
        .RandomnessStateUpdate => null,
        .RandomnessDkgMessage => |m| .{ .RandomnessDkgMessage = m[0] },
        .RandomnessDkgConfirmation => |m| .{ .RandomnessDkgConfirmation = m[0] },
        .CapabilityNotificationV2 => |c| .{ .CapabilityNotification = .{ c.authority, c.generation } },
        .UserTransaction => |t| .{ .Certificate = try txDigest(a, &t.data) },
        .ExecutionTimeObservation => |o| .{ .ExecutionTimeObservation = .{ o.authority, o.generation } },
        .CheckpointSignatureV2 => |m| .{ .CheckpointSignatureV2 = .{ m.summary.auth_signature.authority, m.summary.data.sequence_number, try ckptDigest(a, &m.summary.data) } },
        .UserTransactionV2 => |t| .{ .Certificate = try txDigest(a, &t.tx.data) },
        .UpdateTransactionDenyConfig => |m| switch (m) {
            .V1 => |v| .{ .UpdateTransactionDenyConfig = .{ v.authority, v.generation } },
        },
    };
}

/// The digest the generator printed as `extra`: the transaction or checkpoint digest.
fn extraDigest(a: Allocator, k: *const messages.ConsensusTransactionKind) !?[32]u8 {
    return switch (k.*) {
        .CertifiedTransaction => |c| (try txDigest(a, &c.data)).@"0".@"0",
        .UserTransaction => |t| (try txDigest(a, &t.data)).@"0".@"0",
        .UserTransactionV2 => |t| (try txDigest(a, &t.tx.data)).@"0".@"0",
        .CheckpointSignature, .CheckpointSignatureV2 => |m| (try ckptDigest(a, &m.summary.data)).@"0".@"0",
        else => null,
    };
}

const Tally = struct {
    seen_variant: [14]bool = @splat(false),
    ok: usize = 0,
    neg: usize = 0,
};

fn checkVector(a: Allocator, line: []const u8, tally: *Tally) !void {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    _ = f.next();
    _ = f.next();
    const ok = std.mem.eql(u8, f.next().?, "1");
    const input = try unhex(a, f.next().?);
    const re_hex = f.next().?;
    const key_hex = f.next().?;
    const extra_hex = f.next().?;

    const got = bcs.decode(messages.ConsensusTransaction, a, input);
    if (!ok) {
        try std.testing.expect(std.meta.isError(got));
        tally.neg += 1;
        return;
    }
    var t = try got;
    tally.seen_variant[@backingInt(t.kind)] = true;
    tally.ok += 1;
    // Rust decodes the deny lists into BTreeSets (sorted, deduplicated) and re-encodes those
    switch (t.kind) {
        .UpdateTransactionDenyConfig => |*m| switch (m.*) {
            .V1 => |*c| if (c.rules) |*r| {
                c.rules = try tx_validator.normalizedDenyRules(a, r);
            },
        },
        else => {},
    }
    const re = try bcs.encodeAlloc(messages.ConsensusTransaction, a, &t);
    try std.testing.expectEqualSlices(u8, try unhex(a, re_hex), re);
    if (!std.mem.eql(u8, key_hex, "-")) {
        const key = (try rustKey(a, &t.kind)).?;
        try std.testing.expectEqualSlices(u8, try unhex(a, key_hex), try bcs.encodeAlloc(messages.ConsensusTransactionKey, a, &key));
    }
    if (!std.mem.eql(u8, extra_hex, "-")) {
        const d = (try extraDigest(a, &t.kind)).?;
        try std.testing.expectEqualSlices(u8, try unhex(a, extra_hex), &d);
    }
}

test "ConsensusTransaction vectors from sui-types 1.83.1: decode, re-encode, key, digests" {
    var ar: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var tally: Tally = .{};
    var failed: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, vectors, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "ZUIVEC ")) continue;
        checkVector(a, line, &tally) catch |e| {
            var f = std.mem.tokenizeScalar(u8, line, ' ');
            _ = f.next();
            std.debug.print("vector {s}: {s}\n", .{ f.next().?, @errorName(e) });
            failed += 1;
        };
    }
    try std.testing.expectEqual(@as(usize, 0), failed);
    // every variant index 0..13 was covered, and the malformed set ran
    for (tally.seen_variant) |s| try std.testing.expect(s);
    try std.testing.expectEqual(@as(usize, 23), tally.ok);
    try std.testing.expectEqual(@as(usize, 14), tally.neg);
}

/// The Rust ZUILIMIT input: UpdateTransactionDenyConfig V1 { name, generation 17, rules: Some }
/// with `n_unique` object ids (big-endian index in the first 8 bytes) followed by the first
/// `n_dup` of them again, every other list empty and every flag false.
fn denyLimitInput(a: Allocator, name: []const u8, n_unique: usize, n_dup: usize) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    try w.appendSlice(a, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 13, 0 });
    try w.appendSlice(a, name);
    var g: [8]u8 = undefined;
    std.mem.writeInt(u64, &g, 17, .little);
    try w.appendSlice(a, &g);
    try w.append(a, 1);
    var x = n_unique + n_dup;
    while (true) {
        const byte: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            try w.append(a, byte);
            break;
        }
        try w.append(a, byte | 0x80);
    }
    for (0..n_unique + n_dup) |j| {
        const i = if (j < n_unique) j else j - n_unique;
        var id: [32]u8 = @splat(0);
        std.mem.writeInt(u64, id[0..8], i, .big);
        try w.appendSlice(a, &id);
    }
    try w.appendSlice(a, &@as([10]u8, @splat(0)));
    return w.items;
}

test "deny-config share limits count the deduplicated sets, as Rust BTreeSet decoding does" {
    const gpa = std.testing.allocator;
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();

    // the authority name (ULEB 96 + key) from the Rust EndOfPublish vector
    const eop_line = std.mem.indexOf(u8, vectors, "ZUIVEC eop 1 ").?;
    const eop_hex = vectors[eop_line + "ZUIVEC eop 1 ".len ..][0 .. (8 + 1 + 97) * 2];
    const name = (try unhex(a, eop_hex))[9..];

    const Case = struct { u: usize, d: usize, accept: bool, sha: []const u8 };
    const cases = [_]Case{
        .{ .u = 5000, .d = 0, .accept = true, .sha = "aafdccdc8d9bde0fa0488ecb2c11e12e5bc969e7c30a5e1c695aaddcda336e06" },
        .{ .u = 5001, .d = 0, .accept = false, .sha = "e897b1dbed421093a59a7645da40480eee2277d682f5bd4c4ad77f3d39427a73" },
        // duplicates beyond the cap are fine: Rust counts the set after dedup
        .{ .u = 4999, .d = 5, .accept = true, .sha = "91a27948c088e3e08a44cd5d125149aee3d75cfe5b4f08728456563fc2a192d9" },
        .{ .u = 5000, .d = 1, .accept = true, .sha = "c3e937d3d5719df1dc4a49886a9f688f7fd7267dc0586047e09aa0727a3c3224" },
    };

    const cfg = try protocol.get(141, .mainnet);
    var stakes: [4]u64 = .{ 2500, 2500, 2500, 2500 };
    var ctl = try env_mod.LocalEpochControl.init(gpa, &stakes);
    defer ctl.deinit();
    var reasons: tx_validator.ReasonCache = .{ .gpa = gpa };
    defer reasons.deinit();
    var v = tx_validator.TxValidator.init(gpa, env_mod.Params.fromProtocol(cfg, 1, 0, 1000), cfg, undefined, ctl.control(), &reasons);
    defer v.deinit();

    for (cases) |c| {
        const input = try denyLimitInput(a, name, c.u, c.d);
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(input, &sha, .{});
        try std.testing.expectEqualSlices(u8, try unhex(a, c.sha), &sha);
        const txs = [_]consensus.types.Transaction{.{ .data = input }};
        const got = v.verifyBatch(&txs, 0);
        if (c.accept) try got else try std.testing.expectError(error.InvalidTransaction, got);
    }
}
