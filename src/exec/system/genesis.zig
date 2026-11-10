//! Genesis (`execution_loop` `TransactionKind::Genesis`, execution version 0, epoch 0): every
//! `GenesisObject::RawObject { data, owner }` is written as created with the transaction as its
//! previous transaction and no storage rebate. `update_object_version_and_prev_tx` then moves
//! every Move object to the lamport version (1: genesis has no inputs) and records it as the
//! initial version of a shared owner; packages keep their version. Unmetered, no SUI
//! conservation check, no 0x5 rebate. Effects V1 with everything in `created`, in id order.
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const store_mod = @import("store.zig");

const Allocator = std.mem.Allocator;

const zero32: [32]u8 = @splat(0);

pub fn execute(arena: Allocator, epoch: u64, tx_digest: *const [32]u8, g: *const types.GenesisTransaction, enable_effects_v2: bool) !store_mod.Output {
    if (epoch != 0) return error.InvariantViolation; // Rust panics
    if (enable_effects_v2) return error.Unsupported;
    const lamport: u64 = 1;
    // `written` is a BTreeMap: a repeated id keeps the last object.
    var by_id: std.AutoArrayHashMapUnmanaged([32]u8, []const u8) = .empty;
    for (g.objects) |*go| {
        const raw = go.RawObject;
        var data = raw.data;
        var owner = raw.owner;
        const id: [32]u8 = switch (data) {
            .Move => |*m| blk: {
                if (m.contents.len < 32) return error.InvariantViolation;
                m.version = .{ .@"0" = lamport };
                break :blk m.contents[0..32].*;
            },
            .Package => |*p| p.id.@"0".@"0",
        };
        switch (owner) {
            .Shared => |*sh| {
                if (sh.initial_shared_version.@"0" != 0) return error.InvariantViolation; // Rust asserts
                sh.initial_shared_version = .{ .@"0" = lamport };
            },
            else => {},
        }
        const obj: types.Object = .{ .data = data, .owner = owner, .previous_transaction = .{ .@"0" = .{ .@"0" = tx_digest.* } }, .storage_rebate = 0 };
        try by_id.put(arena, id, try bcs.encodeAlloc(types.Object, arena, &obj));
    }
    const ids = try arena.dupe([32]u8, by_id.keys());
    std.mem.sort([32]u8, ids, {}, struct {
        fn lt(_: void, x: [32]u8, y: [32]u8) bool {
            return std.mem.order(u8, &x, &y) == .lt;
        }
    }.lt);
    const RefOwner = @typeInfo(@FieldType(types.TransactionEffectsV1, "created")).pointer.child;
    const created = try arena.alloc(RefOwner, ids.len);
    const written = try arena.alloc(store_mod.Written, ids.len);
    for (ids, created, written) |id, *c, *w| {
        const bytes = by_id.get(id).?;
        const o = try bcs.decode(types.Object, arena, bytes);
        const version: u64 = switch (o.data) {
            .Move => |m| m.version.@"0",
            .Package => |p| p.version.@"0",
        };
        c.* = .{ .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = types.digest.objectDigest(bytes) } } }, o.owner };
        w.* = .{ .id = id, .bytes = bytes };
    }
    const fx: types.TransactionEffects = .{ .V1 = .{
        .status = .Success,
        .executed_epoch = 0,
        .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .modified_at_versions = &.{},
        .shared_objects = &.{},
        .transaction_digest = .{ .@"0" = .{ .@"0" = tx_digest.* } },
        .created = created,
        .mutated = &.{},
        .unwrapped = &.{},
        .deleted = &.{},
        .unwrapped_then_deleted = &.{},
        .wrapped = &.{},
        .gas_object = .{ .{ .{ .@"0" = .{ .@"0" = zero32 } }, .{ .@"0" = 0 }, .{ .@"0" = .{ .@"0" = zero32 } } }, .{ .AddressOwner = .{ .@"0" = zero32 } } },
        .events_digest = null,
        .dependencies = &.{},
    } };
    return .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, arena, &fx), .events = null, .written = written };
}
