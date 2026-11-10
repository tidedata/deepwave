//! The JWK system transactions: AuthenticatorStateUpdate (scheduled by the consensus handler for
//! the JWKs that became active in the previous commit round), and the end of epoch
//! AuthenticatorStateCreate / AuthenticatorStateExpire (`create_authenticator_state_tx`).
//!
//! `authenticator_state_update_transaction`: the new JWKs are sorted by `ActiveJwk` order, the
//! transaction carries the CURRENT commit's round and the authenticator object's initial shared
//! version; a system transaction shape as in the randomness lane.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const aggregator = @import("aggregator.zig");

pub const Error = error{OutOfMemory} || bcs.EncodeError;

const zero_payment = [1]struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest }{.{
    std.mem.zeroes(types.ObjectID),
    .{ .@"0" = 0 },
    std.mem.zeroes(types.ObjectDigest),
}};

/// `TransactionData::new_system_transaction`: sender 0x0, gas [(ZERO, 0, MIN)], price 1, budget 0.
pub fn systemTransactionData(kind: types.TransactionKind) types.TransactionData {
    const sender = std.mem.zeroes(types.SuiAddress);
    return .{ .V1 = .{
        .kind = kind,
        .sender = sender,
        .gas_data = .{ .payment = &zero_payment, .owner = sender, .price = 1, .budget = 0 },
        .expiration = .None,
    } };
}

pub const Built = struct {
    data: []u8, // BCS(TransactionData)
    digest: [32]u8, // transaction digest
    pub fn deinit(b: *Built, gpa: std.mem.Allocator) void {
        gpa.free(b.data);
    }
};

fn finish(gpa: std.mem.Allocator, kind: types.TransactionKind) Error!Built {
    const td = systemTransactionData(kind);
    const data = try bcs.encodeAlloc(types.TransactionData, gpa, &td);
    return .{ .data = data, .digest = types.digest.transactionDataDigest(data) };
}

/// `new_authenticator_state_update`. `new_active_jwks` is sorted here (callers pass the raw list).
pub fn authenticatorStateUpdate(
    gpa: std.mem.Allocator,
    epoch: u64,
    round: u64,
    new_active_jwks: []const types.ActiveJwk,
    authenticator_obj_initial_shared_version: u64,
) Error!Built {
    const sorted = try gpa.dupe(types.ActiveJwk, new_active_jwks);
    defer gpa.free(sorted);
    std.mem.sort(types.ActiveJwk, sorted, {}, struct {
        fn less(_: void, a: types.ActiveJwk, b: types.ActiveJwk) bool {
            return aggregator.activeJwkOrder(a, b) == .lt;
        }
    }.less);
    return finish(gpa, .{ .AuthenticatorStateUpdate = .{
        .epoch = epoch,
        .round = round,
        .new_active_jwks = sorted,
        .authenticator_obj_initial_shared_version = .{ .@"0" = authenticator_obj_initial_shared_version },
    } });
}

/// The consensus handler step (`create_authenticator_state_update`): the transaction for the JWKs
/// that became active in `last_committed_round`, emitted in the commit with round `commit_round`.
/// Null when none did.
pub fn forCommit(
    gpa: std.mem.Allocator,
    agg: *aggregator.Aggregator,
    last_committed_round: u64,
    commit_round: u64,
    authenticator_obj_initial_shared_version: u64,
) !?Built {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const jwks = try agg.newJwks(arena.allocator(), last_committed_round);
    if (jwks.len == 0) return null;
    return try authenticatorStateUpdate(gpa, agg.epoch, commit_round, jwks, authenticator_obj_initial_shared_version);
}

/// EndOfEpochTransactionKind for the authenticator state at epoch change:
/// Create when the object does not exist yet, else Expire with
/// `min_epoch = (epoch + 1).saturating_sub(max_age_of_jwk_in_epochs)`; null when
/// `enable_jwk_consensus_updates` is off. (The epoch lane embeds this in the end of epoch tx.)
pub fn endOfEpochKind(
    enabled: bool,
    state_exists: bool,
    epoch: u64,
    max_age_of_jwk_in_epochs: u64,
    initial_shared_version: u64,
) ?types.EndOfEpochTransactionKind {
    if (!enabled) return null;
    if (!state_exists) return .AuthenticatorStateCreate;
    const next = epoch + 1;
    return .{ .AuthenticatorStateExpire = .{
        .min_epoch = next -| max_age_of_jwk_in_epochs,
        .authenticator_obj_initial_shared_version = .{ .@"0" = initial_shared_version },
    } };
}

test "authenticator state update sorts and round trips" {
    const gpa = std.testing.allocator;
    const a: types.ActiveJwk = .{ .jwk_id = .{ .iss = .{ .@"0" = "bb" }, .kid = .{ .@"0" = "x" } }, .jwk = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n" }, .alg = .{ .@"0" = "RS256" } }, .epoch = 3 };
    const b: types.ActiveJwk = .{ .jwk_id = .{ .iss = .{ .@"0" = "a" }, .kid = .{ .@"0" = "x" } }, .jwk = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = "n" }, .alg = .{ .@"0" = "RS256" } }, .epoch = 3 };
    var built = try authenticatorStateUpdate(gpa, 3, 99, &.{ a, b }, 11);
    defer built.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const back = try bcs.decode(types.TransactionData, arena.allocator(), built.data);
    const u = back.V1.kind.AuthenticatorStateUpdate;
    try std.testing.expectEqual(@as(u64, 99), u.round);
    try std.testing.expectEqualStrings("a", u.new_active_jwks[0].jwk_id.iss.@"0");
    try std.testing.expectEqual(@as(u64, 11), u.authenticator_obj_initial_shared_version.@"0");
}

test "end of epoch kinds" {
    try std.testing.expect(endOfEpochKind(false, true, 5, 1, 2) == null);
    try std.testing.expect(endOfEpochKind(true, false, 5, 1, 2).? == .AuthenticatorStateCreate);
    const k = endOfEpochKind(true, true, 5, 1, 2).?;
    try std.testing.expectEqual(@as(u64, 5), k.AuthenticatorStateExpire.min_epoch); // (5 + 1) - 1
    const z = endOfEpochKind(true, true, 0, 5, 2).?;
    try std.testing.expectEqual(@as(u64, 0), z.AuthenticatorStateExpire.min_epoch); // saturating
}
