//! Consensus commit prologue transactions (all four kinds) on every execution version.
//!
//! `setup_consensus_commit` runs one system-mode MoveCall,
//! `0x2::clock::consensus_commit_prologue(&mut Clock, commit_timestamp_ms)`, which checks that
//! the sender is 0x0 and sets `clock.timestamp_ms`. The call is unmetered and cannot fail, so
//! its whole effect on state is the Clock (0x6) at the lamport version with the new timestamp,
//! storage rebate 0 (`track_storage_mutation` returns 0 when unmetered) and this transaction as
//! its previous transaction. This module writes that object and the effects directly; it is
//! the one framework function exec models natively until move_vm runs the framework. Its
//! scope ends where the Move function's effect stops being that store: a Clock with a
//! non-zero storage rebate (the unmetered rebate would then be conserved into 0x5) is reported
//! unsupported.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const bcs = @import("bcs");
const objects = @import("objects.zig");

const Allocator = std.mem.Allocator;

const coin_ptb = @import("coin_ptb.zig");
pub const Written = coin_ptb.Written;
pub const Output = coin_ptb.Output;
pub const Outcome = union(enum) { done: Output, unsupported: []const u8 };

const clock_id: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 6;
    break :blk a;
};
const zero32: [32]u8 = @splat(0);

pub fn timestampOf(kind: *const types.TransactionKind) ?u64 {
    return switch (kind.*) {
        .ConsensusCommitPrologue => |*c| c.commit_timestamp_ms,
        .ConsensusCommitPrologueV2 => |*c| c.commit_timestamp_ms,
        .ConsensusCommitPrologueV3 => |*c| c.commit_timestamp_ms,
        .ConsensusCommitPrologueV4 => |*c| c.commit_timestamp_ms,
        else => null,
    };
}

/// `inputs`: the transaction's input objects as its checkpoint carries them (the Clock at the
/// version consensus assigned).
pub fn execute(
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    tx_data_raw: []const u8,
    data: *const types.TransactionDataV1,
    inputs: []const []const u8,
) !Outcome {
    const ts = timestampOf(&data.kind) orelse return .{ .unsupported = "not a prologue" };
    var clock_raw: ?[]const u8 = null;
    for (inputs) |raw| {
        const v = objects.ObjectView.parse(raw) catch continue;
        if (std.mem.eql(u8, &v.id, &clock_id)) {
            if (clock_raw != null) return .{ .unsupported = "two Clock inputs" };
            clock_raw = raw;
        }
    }
    const raw = clock_raw orelse return .{ .unsupported = "Clock not among the checkpoint's inputs" };
    if (inputs.len != 1) return .{ .unsupported = "prologue with inputs besides the Clock" };
    const v = try objects.ObjectView.parse(raw);
    if (v.is_package or v.contents_len != 40) return .{ .unsupported = "Clock layout" };
    const owner = v.ownerBytes();
    if (owner.len != 9 or owner[0] != 2) return .{ .unsupported = "Clock not shared" };
    if (v.storageRebate() != 0) return .{ .unsupported = "Clock with a storage rebate (unmetered rebate conserved into 0x5)" };
    const isv = std.mem.readInt(u64, owner[1..9], .little);

    const tx_digest = types.digest.transactionDataDigest(tx_data_raw);
    const lamport = v.version + 1;

    // The new Clock: same header and owner, lamport version, new timestamp, this tx, rebate 0.
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(arena, raw[0..v.version_at]);
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, lamport, .little);
    try buf.appendSlice(arena, &v8);
    try buf.append(arena, 40);
    try buf.appendSlice(arena, &clock_id);
    std.mem.writeInt(u64, &v8, ts, .little);
    try buf.appendSlice(arena, &v8);
    try buf.appendSlice(arena, owner);
    try buf.append(arena, 32);
    try buf.appendSlice(arena, &tx_digest);
    try buf.appendSlice(arena, &@as([8]u8, @splat(0)));
    const out = buf.items;
    const old_digest = v.digest();
    const new_digest = types.digest.objectDigest(out);

    const prev = raw[v.prev_tx_at + 1 ..][0..32].*;
    const deps: []const types.TransactionDigest = if (cfg.feature_flags.disable_effects_tx_dependencies or std.mem.eql(u8, &prev, &zero32))
        &.{}
    else
        try arena.dupe(types.TransactionDigest, &.{.{ .@"0" = .{ .@"0" = prev } }});

    const shared_owner: types.Owner = .{ .Shared = .{ .initial_shared_version = .{ .@"0" = isv } } };
    const fx: types.TransactionEffects = if (cfg.feature_flags.enable_effects_v2) .{ .V2 = .{
        .status = .Success,
        .executed_epoch = epoch,
        .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = tx_digest } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = deps,
        .lamport_version = .{ .@"0" = lamport },
        .changed_objects = &.{.{ .{ .@"0" = .{ .@"0" = clock_id } }, .{
            .input_state = .{ .Exist = .{ .{ .{ .@"0" = v.version }, .{ .@"0" = .{ .@"0" = old_digest } } }, shared_owner } },
            .output_state = .{ .ObjectWrite = .{ .{ .@"0" = .{ .@"0" = new_digest } }, shared_owner } },
            .id_operation = .None,
        } }},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } } else .{ .V1 = .{
        .status = .Success,
        .executed_epoch = epoch,
        .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .modified_at_versions = &.{.{ .{ .@"0" = .{ .@"0" = clock_id } }, .{ .@"0" = v.version } }},
        .shared_objects = &.{.{ .{ .@"0" = .{ .@"0" = clock_id } }, .{ .@"0" = v.version }, .{ .@"0" = .{ .@"0" = old_digest } } }},
        .transaction_digest = .{ .@"0" = .{ .@"0" = tx_digest } },
        .created = &.{},
        .mutated = &.{.{ .{ .{ .@"0" = .{ .@"0" = clock_id } }, .{ .@"0" = lamport }, .{ .@"0" = .{ .@"0" = new_digest } } }, shared_owner }},
        .unwrapped = &.{},
        .deleted = &.{},
        .unwrapped_then_deleted = &.{},
        .wrapped = &.{},
        // No gas coin: (ObjectID::ZERO, 0, ObjectDigest::MIN) owned by 0x0.
        .gas_object = .{ .{ .{ .@"0" = .{ .@"0" = zero32 } }, .{ .@"0" = 0 }, .{ .@"0" = .{ .@"0" = zero32 } } }, .{ .AddressOwner = .{ .@"0" = zero32 } } },
        .events_digest = null,
        .dependencies = deps,
    } };
    const written = try arena.dupe(Written, &.{.{ .id = clock_id, .bytes = out }});
    return .{ .done = .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, arena, &fx), .written = written } };
}
