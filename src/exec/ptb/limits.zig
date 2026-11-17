//! The post-execution effects checks of execution version 4 (`check_effects` in
//! sui-execution/latest/sui-adapter/src/execution_engine.rs): the estimated effects size
//! (`check_meter_limit`, EffectsTooLarge), the written objects size (`check_written_objects_limit`,
//! WrittenObjectsTooLarge) and the accumulator amounts (`check_accumulator_amounts_representable`,
//! CoinBalanceOverflow). Pure functions over counts and the accumulator events; root.zig gathers
//! the counts from its TemporaryStore model and orders the checks.
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const run = @import("run.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

// crates/sui-types/src/effects/mod.rs:39-61
const APPROX_SIZE_OF_OBJECT_REF: u64 = 80;
const APPROX_SIZE_OF_EXECUTION_STATUS: u64 = 120;
const APPROX_SIZE_OF_EPOCH_ID: u64 = 10;
const APPROX_SIZE_OF_GAS_COST_SUMMARY: u64 = 40;
const APPROX_SIZE_OF_OPT_TX_EVENTS_DIGEST: u64 = 40;
const APPROX_SIZE_OF_TX_DIGEST: u64 = 40;
const APPROX_SIZE_OF_OWNER: u64 = 48;
const APPROX_SIZE_OF_ACCUMULATOR_WRITE: u64 = 96;
const APPROX_SIZE_OF_ACCUMULATOR_EVENT_DIGEST: u64 = 48;
const APPROX_SIZE_OF_ID_ONLY_CHANGE: u64 = 40;
const APPROX_SIZE_OF_UNCHANGED_CONSENSUS_OBJECT: u64 = 80;

/// `TOTAL_SUPPLY_MIST` (sui-types gas_coin.rs): 10 billion SUI.
pub const total_supply_mist: u128 = 10_000_000_000 * 1_000_000_000;

/// The arguments of `estimate_effects_size_upperbound_v2`, as temporary_store.rs
/// `estimate_effects_size_upperbound` passes them.
pub const Counts = struct {
    /// `execution_results.written_objects.len()`
    writes: u64,
    /// `execution_results.modified_objects.len()`
    modifies: u64,
    /// `input_objects.len()` (passed as `num_deps`)
    inputs: u64,
    /// `count_id_only_changes`: created or deleted ids neither written nor modified
    id_only: u64 = 0,
    /// `count_unchanged_consensus_objects_upperbound`: read-only consensus inputs, stream-ended
    /// inputs, loaded per-epoch config objects, loaded system objects
    unchanged_consensus: u64 = 0,
    /// `estimate_accumulator_effects_size_upperbound` of the accumulator events
    accumulator: u64 = 0,
};

/// effects/mod.rs `estimate_effects_size_upperbound_v2`. Without `complete` (before protocol
/// 141, `complete_effects_size_estimate`) the id-only, unchanged consensus and accumulator terms
/// are left out.
pub fn estimateV2(c: Counts, complete: bool) u64 {
    const fixed = APPROX_SIZE_OF_EXECUTION_STATUS + APPROX_SIZE_OF_EPOCH_ID + APPROX_SIZE_OF_GAS_COST_SUMMARY + APPROX_SIZE_OF_OPT_TX_EVENTS_DIGEST;
    const change = 1_000 + (APPROX_SIZE_OF_OWNER + APPROX_SIZE_OF_OBJECT_REF) * c.writes + (APPROX_SIZE_OF_OWNER + APPROX_SIZE_OF_OBJECT_REF) * c.modifies;
    const deps = 1_000 + APPROX_SIZE_OF_TX_DIGEST * c.inputs;
    var size: u64 = fixed + change + deps;
    if (complete) {
        size +|= c.id_only *| APPROX_SIZE_OF_ID_ONLY_CHANGE;
        size +|= c.unchanged_consensus *| APPROX_SIZE_OF_UNCHANGED_CONSENSUS_OBJECT;
        size +|= c.accumulator;
    }
    return size;
}

/// effects/mod.rs `estimate_accumulator_effects_size_upperbound`: per accumulator object (first
/// event of each) `bcs::serialized_size(type) + APPROX_SIZE_OF_ACCUMULATOR_WRITE`, plus 48 per
/// event digest of every event.
pub fn accumulatorSize(arena: Allocator, events: []const run.AccWrite) !u64 {
    var seen: std.AutoHashMapUnmanaged(Id, void) = .empty;
    defer seen.deinit(arena);
    var size: u64 = 0;
    for (events) |*ev| {
        const gop = try seen.getOrPut(arena, ev.id);
        if (!gop.found_existing) size +|= @as(u64, (try bcs.encodeAlloc(types.TypeTag, arena, &ev.ty)).len) +| APPROX_SIZE_OF_ACCUMULATOR_WRITE;
        switch (ev.value) {
            .Integer, .IntegerTuple => {},
            .EventDigest => |d| size +|= @as(u64, d.len) *| APPROX_SIZE_OF_ACCUMULATOR_EVENT_DIGEST,
        }
    }
    return size;
}

/// sui-protocol-config `check_limit_by_meter!` for a metered transaction (hard limit = the
/// metered limit) or an unmetered one (soft = metered, hard = the system limit; a soft crossing
/// only warns). `check_limit_in_range`: `x >= hard` is a hard crossing. Returns the hard limit
/// crossed.
pub fn crossed(metered: bool, x: u64, metered_limit: u64, system_limit: u64) ?u64 {
    const hard = if (metered) metered_limit else system_limit;
    return if (x >= hard) hard else null;
}

/// `GasCoin::is_gas_balance_type`: `0x2::balance::Balance<0x2::sui::SUI>`.
fn isSuiBalance(ty: *const types.TypeTag) bool {
    const st = switch (ty.*) {
        .@"struct" => |s| s,
        else => return false,
    };
    if (!isFramework2(&st.address.@"0") or !std.mem.eql(u8, st.module.@"0", "balance") or !std.mem.eql(u8, st.name.@"0", "Balance") or st.type_args.len != 1) return false;
    const inner = switch (st.type_args[0]) {
        .@"struct" => |s| s,
        else => return false,
    };
    return isFramework2(&inner.address.@"0") and std.mem.eql(u8, inner.module.@"0", "sui") and std.mem.eql(u8, inner.name.@"0", "SUI") and inner.type_args.len == 0;
}

fn isFramework2(a: *const Id) bool {
    for (a[0..31]) |x| if (x != 0) return false;
    return a[31] == 2;
}

/// temporary_store.rs `check_accumulator_amounts_representable`: per accumulator object, the gross
/// Merge total and the gross Split total of the integer events stay within the total supply for
/// `Balance<SUI>` (u64::MAX for any other type), and the SUI Split total across all accumulator
/// objects within the supply. False is CoinBalanceOverflow.
pub fn amountsRepresentable(arena: Allocator, events: []const run.AccWrite) !bool {
    var merge: std.AutoHashMapUnmanaged(Id, u128) = .empty;
    defer merge.deinit(arena);
    var split: std.AutoHashMapUnmanaged(Id, u128) = .empty;
    defer split.deinit(arena);
    var sui_split: u128 = 0;
    for (events) |*ev| {
        const amount: u128 = switch (ev.value) {
            .Integer => |v| v,
            else => continue,
        };
        const is_sui = isSuiBalance(&ev.ty);
        const limit: u128 = if (is_sui) total_supply_mist else std.math.maxInt(u64);
        const gop = try (if (ev.op == .Merge) &merge else &split).getOrPut(arena, ev.id);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += amount;
        if (gop.value_ptr.* > limit) return false;
        if (is_sui and ev.op == .Split) {
            sui_split += amount;
            if (sui_split > total_supply_mist) return false;
        }
    }
    return true;
}

// Rust-computed numbers: `TransactionEffects::estimate_effects_size_upperbound_v2` and
// `check_accumulator_amounts_representable` evaluated by zui-truth-exec `limits-units`
// (tools/truth/exec/src/synth.rs `cmd_limits_units`) at mainnet-v1.83.1.
test "estimate_effects_size_upperbound_v2 matches Rust" {
    // (writes, modifies, inputs, id_only, unchanged, accumulator, complete) -> Rust
    const cases = [_]struct { Counts, bool, u64 }{
        .{ .{ .writes = 0, .modifies = 0, .inputs = 0 }, false, 2210 },
        .{ .{ .writes = 0, .modifies = 0, .inputs = 0 }, true, 2210 },
        .{ .{ .writes = 1, .modifies = 1, .inputs = 1 }, true, 2506 },
        .{ .{ .writes = 3, .modifies = 2, .inputs = 5, .id_only = 7, .unchanged_consensus = 2, .accumulator = 188 }, false, 3050 },
        .{ .{ .writes = 3, .modifies = 2, .inputs = 5, .id_only = 7, .unchanged_consensus = 2, .accumulator = 188 }, true, 3678 },
        .{ .{ .writes = 2048, .modifies = 2048, .inputs = 2048, .id_only = 2048, .unchanged_consensus = 1000, .accumulator = 1024 * 188 }, true, 962_850 },
    };
    for (cases) |c| try std.testing.expectEqual(c[2], estimateV2(c[0], c[1]));
}

test "check_limit_by_meter: the limit itself is a hard crossing" {
    try std.testing.expectEqual(@as(?u64, null), crossed(true, 524_287, 524_288, 8_388_608));
    try std.testing.expectEqual(@as(?u64, 524_288), crossed(true, 524_288, 524_288, 8_388_608));
    try std.testing.expectEqual(@as(?u64, null), crossed(false, 524_288, 524_288, 8_388_608));
    try std.testing.expectEqual(@as(?u64, 8_388_608), crossed(false, 8_388_608, 524_288, 8_388_608));
}

test "accumulator size: one write per object plus 48 per event digest" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var x: Id = @splat(0x11);
    const y: Id = @splat(0x22);
    const w1 = try run.balanceWrite(a, x, 5);
    const w2 = try run.balanceWrite(a, x, -3);
    x[0] = 0x33;
    const w3 = try run.balanceWrite(a, x, 7);
    // Balance<SUI> serializes to 92 bytes (Rust: bcs::serialized_size)
    try std.testing.expectEqual(@as(u64, 2 * (92 + 96)), try accumulatorSize(a, &.{ w1, w2, w3 }));
    const El = @typeInfo(@FieldType(types.AccumulatorValue, "EventDigest")).pointer.child;
    var digests = [_]El{ .{ 1, .{ .@"0" = @splat(0) } }, .{ 2, .{ .@"0" = @splat(1) } } };
    var ev = w1;
    ev.id = y;
    ev.value = .{ .EventDigest = &digests };
    try std.testing.expectEqual(@as(u64, 92 + 96 + 2 * 48), try accumulatorSize(a, &.{ev}));
}

test "check_accumulator_amounts_representable: SUI to the supply, other types to u64::MAX" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const x: Id = @splat(0x11);
    var at = try run.balanceWrite(a, x, 1);
    at.value = .{ .Integer = @intCast(total_supply_mist) };
    try std.testing.expect(try amountsRepresentable(a, &.{at}));
    var one = at;
    one.value = .{ .Integer = 1 };
    try std.testing.expect(!try amountsRepresentable(a, &.{ at, one }));
    // a merge and a split of the same object are totalled apart
    var sp = at;
    sp.op = .Split;
    try std.testing.expect(try amountsRepresentable(a, &.{ at, sp }));
    // the SUI split total across objects
    var sp2 = one;
    sp2.op = .Split;
    sp2.id = @splat(0x44);
    try std.testing.expect(!try amountsRepresentable(a, &.{ sp, sp2 }));
    // another type: u64::MAX
    var other = at;
    other.ty = .u64;
    other.value = .{ .Integer = std.math.maxInt(u64) };
    try std.testing.expect(try amountsRepresentable(a, &.{other}));
    try std.testing.expect(!try amountsRepresentable(a, &.{ other, blk: {
        var o = other;
        o.value = .{ .Integer = 1 };
        break :blk o;
    } }));
}
