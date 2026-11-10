//! A user transaction as the validator sees it after decoding a `UserTransactionV2`: the digest,
//! the owned input refs (what post-consensus locking locks), the shared inputs (what version
//! assignment and congestion control use) and the few scalar facts the handler needs.
//!
//! Truth (mainnet-v1.83.1): `transaction.rs` `TransactionData::input_objects`,
//! `shared_input_objects`, `uses_randomness`, `TransactionExpiration::{restricts_proposers,
//! is_allowed_proposer}`, `paid_proposer_count`; `consensus_handler.rs` `owned_object_refs_to_lock`.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const checks = @import("rpc_exec").checks;
const messages = @import("../messages.zig");

const Allocator = std.mem.Allocator;
pub const Id = [32]u8;

pub const ObjRef = struct {
    id: Id,
    version: u64,
    digest: Id,

    pub fn eql(a: ObjRef, b: ObjRef) bool {
        return a.version == b.version and std.mem.eql(u8, &a.id, &b.id) and std.mem.eql(u8, &a.digest, &b.digest);
    }
    pub fn lessThan(_: void, a: ObjRef, b: ObjRef) bool {
        const o = std.mem.order(u8, &a.id, &b.id);
        if (o != .eq) return o == .lt;
        if (a.version != b.version) return a.version < b.version;
        return std.mem.order(u8, &a.digest, &b.digest) == .lt;
    }
};

pub const Mutability = enum { immutable, mutable, non_exclusive_write };

pub const SharedInput = struct {
    id: Id,
    /// initial_shared_version
    isv: u64,
    mutability: Mutability,

    /// SharedObjectMutability::is_exclusive: only Mutable.
    pub fn exclusive(s: SharedInput) bool {
        return s.mutability == .mutable;
    }
};

pub const randomness_object_id: Id = blk: {
    var a: Id = @splat(0);
    a[31] = 8;
    break :blk a;
};

/// `MAX_UNPAID_ALLOWED_PROPOSERS`.
pub const max_unpaid_allowed_proposers: u64 = 3;

/// `paid_proposer_count(gas_price, reference_gas_price)`.
pub fn paidProposerCount(gas_price: u64, rgp: u64) u64 {
    return @max(max_unpaid_allowed_proposers, gas_price / @max(rgp, 1));
}

pub const ParseError = error{ Malformed, NotUserTransaction } || Allocator.Error;

pub const UserTx = struct {
    /// BCS(PlainTransactionWithClaims) exactly as sequenced (kept for deferral persistence).
    raw: []const u8,
    /// TransactionDigest: blake2b256("TransactionData::" ++ BCS(TransactionData)).
    digest: Id,
    tx: messages.PlainTransactionWithClaims,
    /// `InputObjectKind::ImmOrOwnedMoveObject` of `input_objects()`: owned PTB inputs then gas.
    owned: []const ObjRef,
    shared: []const SharedInput,
    /// Receiving objects (`receiving_objects()`).
    receiving: []const ObjRef,
    gas_price: u64,
    sender: Id,
    uses_randomness: bool,

    pub fn data(u: *const UserTx) *const types.TransactionDataV1 {
        return &u.tx.tx.data.@"0".element().intent_message.value.V1;
    }

    pub fn signatures(u: *const UserTx) []const types.GenericSignature {
        return u.tx.tx.data.@"0".element().tx_signatures;
    }

    /// `restricts_proposers(epoch)`: a Validity expiration whose allowed_proposers are for `epoch`.
    pub fn restrictsProposers(u: *const UserTx, epoch: u64) bool {
        return switch (u.data().expiration) {
            .Validity => |v| if (v.allowed_proposers) |ap| ap.epoch == epoch else false,
            else => false,
        };
    }

    /// `is_allowed_proposer(proposer, epoch)`: no restriction means everyone may propose.
    pub fn isAllowedProposer(u: *const UserTx, proposer: u32, epoch: u64) bool {
        return allowedProposer(u.data(), proposer, epoch);
    }

    /// The immutable input claim (`get_immutable_objects`): empty when absent.
    pub fn immutableClaims(u: *const UserTx) []const types.ObjectID {
        for (u.tx.claims) |c| switch (c) {
            .ImmutableInputObjects => |ids| return ids,
            else => {},
        };
        return &.{};
    }

    pub fn hasImmutableClaim(u: *const UserTx, id: *const Id) bool {
        for (u.immutableClaims()) |c| if (std.mem.eql(u8, &c.@"0".@"0", id)) return true;
        return false;
    }

    /// `owned_object_refs_to_lock`: ImmOrOwned inputs minus the claimed immutable ones.
    pub fn refsToLock(u: *const UserTx, arena: Allocator) Allocator.Error![]ObjRef {
        var out: std.ArrayList(ObjRef) = .empty;
        for (u.owned) |r| if (!u.hasImmutableClaim(&r.id)) try out.append(arena, r);
        return out.items;
    }

    /// `is_consensus_tx` approximation used for classification only: has shared inputs.
    pub fn hasSharedInputs(u: *const UserTx) bool {
        return u.shared.len != 0;
    }
};

/// `is_allowed_proposer` on the expiration alone.
pub fn allowedProposer(td: *const types.TransactionDataV1, proposer: u32, epoch: u64) bool {
    switch (td.expiration) {
        .Validity => |v| if (v.allowed_proposers) |ap| {
            if (ap.epoch != epoch) return true;
            for (ap.proposers) |p| {
                if (p >= proposer) return p == proposer;
            }
            return false;
        },
        else => {},
    }
    return true;
}

/// `TransactionData` digest from the decoded value.
pub fn transactionDigest(arena: Allocator, td: *const types.TransactionDataV1) Allocator.Error!Id {
    const all: types.TransactionData = .{ .V1 = td.* };
    const enc = try bcs.encodeAlloc(types.TransactionData, arena, &all);
    return hash.blake2b256(&.{ "TransactionData::", enc });
}

/// Decodes a sequenced `UserTransactionV2` payload. `raw` must outlive the result.
pub fn parse(arena: Allocator, raw: []const u8) ParseError!UserTx {
    const t = bcs.decode(messages.PlainTransactionWithClaims, arena, raw) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    return fromDecoded(arena, raw, t);
}

pub fn fromDecoded(arena: Allocator, raw: []const u8, t: messages.PlainTransactionWithClaims) ParseError!UserTx {
    return fromDecodedWhy(arena, raw, t, null);
}

/// Like `fromDecoded`; on `error.Malformed` from an input check, `why` (when given) receives the
/// `UserInputError` text Rust would record as the reject reason.
pub fn fromDecodedWhy(arena: Allocator, raw: []const u8, t: messages.PlainTransactionWithClaims, why: ?*[]const u8) ParseError!UserTx {
    var u: UserTx = .{
        .raw = raw,
        .digest = undefined,
        .tx = t,
        .owned = &.{},
        .shared = &.{},
        .receiving = &.{},
        .gas_price = 0,
        .sender = undefined,
        .uses_randomness = false,
    };
    const td = u.data();
    u.digest = try transactionDigest(arena, td);
    u.gas_price = td.gas_data.price;
    u.sender = td.sender.@"0";

    var kinds: std.ArrayList(checks.InputKind) = .empty;
    var recv: std.ArrayList(checks.Receiving) = .empty;
    if (try checks.inputKinds(arena, td, &kinds, &recv)) |f| {
        if (why) |w| w.* = f.message;
        return error.Malformed;
    }
    var owned: std.ArrayList(ObjRef) = .empty;
    var shared: std.ArrayList(SharedInput) = .empty;
    for (kinds.items) |k| switch (k) {
        .package => {},
        .owned => |o| try owned.append(arena, .{ .id = o.id, .version = o.version, .digest = o.digest }),
        .shared => |s| try shared.append(arena, .{ .id = s.id, .isv = s.isv, .mutability = switch (s.mutability) {
            .Immutable => .immutable,
            .Mutable => .mutable,
            .NonExclusiveWrite => .non_exclusive_write,
        } }),
    };
    u.owned = owned.items;
    u.shared = shared.items;
    var rcv: std.ArrayList(ObjRef) = .empty;
    for (recv.items) |r| try rcv.append(arena, .{ .id = r.id, .version = r.version, .digest = r.digest });
    u.receiving = rcv.items;
    for (u.shared) |s| if (std.mem.eql(u8, &s.id, &randomness_object_id)) {
        u.uses_randomness = true;
    };
    return u;
}

test "paid proposer count" {
    try std.testing.expectEqual(@as(u64, 3), paidProposerCount(1000, 1000));
    try std.testing.expectEqual(@as(u64, 7), paidProposerCount(7000, 1000));
    try std.testing.expectEqual(@as(u64, 3), paidProposerCount(1, 0));
}
