//! ConsensusTransaction builders for the beacon (sui-types `messages_consensus.rs`):
//! `new_randomness_dkg_message` and `new_randomness_dkg_confirmation`. The tracking id is the
//! SipHash-1-3 (zero keys, std `DefaultHasher`) of the `Vec<u8>` payload as `Hash` feeds it: the
//! length as a native endian usize, then the bytes; little endian bytes of the result.
const std = @import("std");
const bcs = @import("bcs");
const messages = @import("../messages.zig");

pub const Error = error{OutOfMemory} || bcs.EncodeError;

pub fn trackingIdOfBytes(payload: []const u8) [8]u8 {
    const SipHash = std.crypto.auth.siphash.SipHash64(1, 3);
    const key: [16]u8 = @splat(0);
    var h = SipHash.init(&key);
    var l: [8]u8 = undefined;
    std.mem.writeInt(u64, &l, payload.len, .little);
    h.update(&l);
    h.update(payload);
    var out: [8]u8 = undefined;
    h.final(&out);
    return out;
}

fn name(bytes: *const [96]u8) messages.AuthorityName {
    return .{ .@"0" = bytes.* };
}

/// BCS(ConsensusTransaction::RandomnessDkgMessage(authority, versioned_message_bcs)).
pub fn dkgMessageTx(gpa: std.mem.Allocator, authority: *const [96]u8, versioned_message: []const u8) Error![]u8 {
    const tx: messages.ConsensusTransaction = .{
        .tracking_id = trackingIdOfBytes(versioned_message),
        .kind = .{ .RandomnessDkgMessage = .{ name(authority), versioned_message } },
    };
    return bcs.encodeAlloc(messages.ConsensusTransaction, gpa, &tx);
}

pub fn dkgConfirmationTx(gpa: std.mem.Allocator, authority: *const [96]u8, versioned_confirmation: []const u8) Error![]u8 {
    const tx: messages.ConsensusTransaction = .{
        .tracking_id = trackingIdOfBytes(versioned_confirmation),
        .kind = .{ .RandomnessDkgConfirmation = .{ name(authority), versioned_confirmation } },
    };
    return bcs.encodeAlloc(messages.ConsensusTransaction, gpa, &tx);
}

test "dkg transactions encode and decode" {
    const gpa = std.testing.allocator;
    const auth: [96]u8 = @splat(7);
    const payload = "versioned dkg bytes";
    const b = try dkgMessageTx(gpa, &auth, payload);
    defer gpa.free(b);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const tx = try bcs.decode(messages.ConsensusTransaction, arena.allocator(), b);
    try std.testing.expect(tx.kind == .RandomnessDkgMessage);
    try std.testing.expectEqualSlices(u8, payload, tx.kind.RandomnessDkgMessage[1]);
    try std.testing.expectEqualSlices(u8, &auth, &tx.kind.RandomnessDkgMessage[0].@"0");
    const c = try dkgConfirmationTx(gpa, &auth, payload);
    defer gpa.free(c);
    const txc = try bcs.decode(messages.ConsensusTransaction, arena.allocator(), c);
    try std.testing.expect(txc.kind == .RandomnessDkgConfirmation);
}
