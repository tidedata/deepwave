//! The RandomnessStateUpdate system transaction (sui-types `new_randomness_state_update`): what
//! the validator executes for every completed beacon round. `random_bytes` is BCS of the
//! round's full threshold signature (the 48 byte G1 element, serialized as a fixed array).
//!
//! `TransactionData::new_system_transaction`: sender 0x0, gas payment [(ZERO, 0, MIN)] owned by
//! 0x0, price 1 (GAS_PRICE_FOR_SYSTEM_TX), budget 0, no expiration.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");

pub const Error = error{OutOfMemory} || bcs.EncodeError;

/// The gas payment of every system transaction: [(ObjectID::ZERO, SequenceNumber(0), ObjectDigest::MIN)].
const zero_payment = [1]struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest }{.{
    std.mem.zeroes(types.ObjectID),
    .{ .@"0" = 0 },
    std.mem.zeroes(types.ObjectDigest),
}};

pub fn systemTransactionData(kind: types.TransactionKind) types.TransactionData {
    const sender = std.mem.zeroes(types.SuiAddress);
    return .{ .V1 = .{
        .kind = kind,
        .sender = sender,
        .gas_data = .{ .payment = &zero_payment, .owner = sender, .price = 1, .budget = 0 },
        .expiration = .None,
    } };
}

/// The kind: `TransactionKind::RandomnessStateUpdate`.
pub fn randomnessStateUpdate(
    epoch: u64,
    round: u64,
    random_bytes: []const u8,
    randomness_obj_initial_shared_version: u64,
) types.TransactionKind {
    return .{ .RandomnessStateUpdate = .{
        .epoch = epoch,
        .randomness_round = .{ .@"0" = round },
        .random_bytes = random_bytes,
        .randomness_obj_initial_shared_version = .{ .@"0" = randomness_obj_initial_shared_version },
    } };
}

pub const Built = struct {
    /// BCS(TransactionData)
    data: []u8,
    /// Blake2b256("TransactionData::" ++ data): the transaction digest.
    digest: [32]u8,

    pub fn deinit(b: *Built, gpa: std.mem.Allocator) void {
        gpa.free(b.data);
    }
};

pub fn build(gpa: std.mem.Allocator, epoch: u64, round: u64, signature_bcs: []const u8, initial_shared_version: u64) Error!Built {
    const td = systemTransactionData(randomnessStateUpdate(epoch, round, signature_bcs, initial_shared_version));
    const data = try bcs.encodeAlloc(types.TransactionData, gpa, &td);
    return .{ .data = data, .digest = types.digest.transactionDataDigest(data) };
}

test "randomness state update encodes and round trips" {
    const gpa = std.testing.allocator;
    const sig: [48]u8 = @splat(0x5a);
    var b = try build(gpa, 12, 345, &sig, 7);
    defer b.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const back = try bcs.decode(types.TransactionData, arena.allocator(), b.data);
    const k = back.V1.kind.RandomnessStateUpdate;
    try std.testing.expectEqual(@as(u64, 12), k.epoch);
    try std.testing.expectEqual(@as(u64, 345), k.randomness_round.@"0");
    try std.testing.expectEqualSlices(u8, &sig, k.random_bytes);
    try std.testing.expectEqual(@as(u64, 7), k.randomness_obj_initial_shared_version.@"0");
    try std.testing.expectEqual(@as(u64, 1), back.V1.gas_data.price);
    // same input, same digest
    var b2 = try build(gpa, 12, 345, &sig, 7);
    defer b2.deinit(gpa);
    try std.testing.expectEqualSlices(u8, &b.digest, &b2.digest);
}
