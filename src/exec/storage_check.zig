//! Storage-gas diagnostic run inside `exec-replay` while transactions still wait on the Move VM.
//! For a metered transaction with V2 effects it replays exec's storage accounting
//! (`TemporaryStore::collect_storage_and_rebate` + `StorageGas` + `sender_rebate`) over the
//! objects the certified effects say were written and removed, and compares:
//!   - each written object's `storage_rebate` field with the storage cost exec assigns it,
//!   - the effects' storageCost, storageRebate and nonRefundableStorageFee.
//! This is not an exec-replay pass: the write set comes from the certified effects, not from
//! execution. It proves the storage half of the gas charger on every corpus transaction.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const objects = @import("objects.zig");
const gas = @import("gas.zig");

const Allocator = std.mem.Allocator;

pub const Result = union(enum) { ok, not_applicable, storage_oog, mismatch: []const u8 };

pub fn check(
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    blob: []const u8,
    idx: *const types.CheckpointIndex,
    tx: *const types.index.Tx,
    fx: *const types.TransactionEffects,
    metered: bool,
    gas_budget: u64,
) !Result {
    const v = switch (fx.*) {
        .V2 => |*v| v,
        .V1 => return .not_applicable,
    };
    // Unmetered transactions (system kinds) report a zero summary; their rebate is parked on 0x5.
    if (!metered) return .not_applicable;
    // Out of gas while charging storage: Rust drops the writes, charges the whole budget as
    // computation and resets storage (`handle_error` / legacy OOG retry). Not modeled here.
    if (v.status == .Failure and v.status.Failure.@"error" == .InsufficientGas and v.gas_used.storageCost == 0) return .storage_oog;
    // A failed transaction whose input-only storage still does not fit pays the whole budget as
    // computation with storage reset (`handle_error` fallback; legacy equivalent).
    if (v.status == .Failure and v.gas_used.storageCost == 0 and v.gas_used.computationCost == gas_budget) return .storage_oog;
    // Insufficient funds for an address-balance withdrawal short-circuits to a bump-only outcome
    // with a zero summary (execution_engine `Outcome::BumpOnly`). Not modeled here.
    if (v.status == .Failure and v.status.Failure.@"error" == .InsufficientFundsForWithdraw) return .storage_oog;

    const ins = idx.objs[tx.in_first..][0..tx.in_count];
    const outs = idx.objs[tx.out_first..][0..tx.out_count];
    const in_views = try arena.alloc(objects.ObjectView, ins.len);
    for (ins, in_views) |r, *iv| iv.* = try objects.ObjectView.parse(r.slice(blob));

    var storage: gas.StorageGas = .{
        .storage_gas_price = try cfg.get("storage_gas_price"),
        .storage_per_byte_cost = try cfg.get("obj_data_cost_refundable"),
    };
    const rate = try cfg.get("storage_rebate_rate");

    // Old rebate of a changed object: the input object at its input version.
    const Lookup = struct {
        fn oldRebate(views: []const objects.ObjectView, change: *const types.EffectsObjectChange, id: *const [32]u8) ?u64 {
            const e = switch (change.input_state) {
                .Exist => |e| e,
                .NotExist => return null,
            };
            for (views) |*iv| if (std.mem.eql(u8, &iv.id, id) and iv.version == e[0][0].@"0") return iv.storageRebate();
            return null;
        }
    };

    // Written objects (output objects), in effects order: storage cost per object.
    for (outs) |r| {
        const ov = try objects.ObjectView.parse(r.slice(blob));
        var change: ?*const types.EffectsObjectChange = null;
        for (v.changed_objects) |*c| if (std.mem.eql(u8, &c[0].@"0".@"0", &ov.id)) {
            change = &c[1];
            break;
        };
        const ch = change orelse return .{ .mismatch = try std.fmt.allocPrint(arena, "output {x} not in effects", .{&ov.id}) };
        const old = if (ch.input_state == .Exist)
            (Lookup.oldRebate(in_views, ch, &ov.id) orelse return .{ .mismatch = try std.fmt.allocPrint(arena, "input of {x} missing", .{&ov.id}) })
        else
            0;
        const size = try objects.sizeForGasMetering(arena, &ov);
        const cost = (try storage.trackMutation(arena, ov.id, size, old, false)) orelse return .{ .mismatch = "overflow" };
        if (cost != ov.storageRebate())
            return .{ .mismatch = try std.fmt.allocPrint(arena, "object {x} storage_rebate {d}, exec {d} (size {d})", .{ &ov.id, ov.storageRebate(), cost, size }) };
    }
    // Modified (input Exist) objects not written: deleted or wrapped, new size 0.
    for (v.changed_objects) |*c| {
        if (c[1].input_state != .Exist) continue;
        switch (c[1].output_state) {
            .NotExist => {},
            else => continue,
        }
        const old = Lookup.oldRebate(in_views, &c[1], &c[0].@"0".@"0") orelse return .{ .mismatch = try std.fmt.allocPrint(arena, "input of removed {x} missing", .{&c[0].@"0".@"0"}) };
        _ = (try storage.trackMutation(arena, c[0].@"0".@"0", 0, old, false)) orelse return .{ .mismatch = "overflow" };
    }
    const sender = gas.senderRebate(storage.total_storage_rebate, rate);
    const g = v.gas_used;
    if (g.storageCost != storage.total_storage_cost or g.storageRebate != sender or g.nonRefundableStorageFee != storage.total_storage_rebate - sender)
        return .{ .mismatch = try std.fmt.allocPrint(arena, "{s} computation {d} summary storage {d}/{d}/{d}, exec {d}/{d}/{d}", .{
            if (v.status == .Failure) @tagName(v.status.Failure.@"error") else "ok",
            v.gas_used.computationCost,
            g.storageCost,                          g.storageRebate, g.nonRefundableStorageFee,
            storage.total_storage_cost,             sender,          storage.total_storage_rebate - sender,
        }) };
    return .ok;
}
