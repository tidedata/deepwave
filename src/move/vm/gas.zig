//! Gas metering with exact `SuiGasMeter` semantics (sui-adapter-latest `gas_meter.rs` over
//! sui-types `gas_model::tables::GasStatus`), for every gas model version.
//!
//! Only the quantities Rust actually uses are computed: `GasStatus::charge` ignores the size
//! decrease, so callers pass only pushes, pops and the size increase. Sizes are abstract memory
//! sizes from `value.zig` with the size config of the gas model version (`SizeCfg`).
const std = @import("std");
const protocol = @import("protocol");
const move_format = @import("move_format");

const StatusCode = move_format.StatusCode;
const CostTable = protocol.gas.CostTable;

/// sui-types `tables.rs` constants.
pub const REFERENCE_SIZE: u64 = 8;
pub const STRUCT_SIZE: u64 = 2;
pub const VEC_SIZE: u64 = 8;
/// `Type::size()` of every primitive type (legacy base memory size).
pub const PRIM_TYPE_SIZE: u64 = 1;

/// `SizeConfig` for `ValueView::abstract_memory_size`.
pub const SizeCfg = struct {
    traverse_references: bool,
    include_vector_size: bool,
    /// `fine_grained_value_size` of the historical cuts (exec-history, CONTRACTS 6.6b): false at
    /// gas model 10 and below, where every primitive but an address counts LEGACY_CONST_SIZE (16).
    /// Latest (gas model 11 and later) is always fine grained.
    fine_grained: bool = true,
};

pub const ChargeError = error{Charge};

/// `GasStatus` plus the `SuiGasMeter` charge functions. On a failed charge the error status is
/// left in `err` and `error.Charge` is returned.
pub const Meter = struct {
    gas_model_version: u64,
    table: *const CostTable,
    gas_left: u64,
    gas_price: u64,
    initial_budget: u64,
    charge_enabled: bool = true,

    stack_height_high_water_mark: u64 = 0,
    stack_height_current: u64 = 0,
    stack_height_next_tier_start: ?u64,
    stack_height_current_tier_mult: u64,

    stack_size_high_water_mark: u64 = 0,
    stack_size_current: u64 = 0,
    stack_size_next_tier_start: ?u64,
    stack_size_current_tier_mult: u64,

    instructions_executed: u64 = 0,
    instructions_next_tier_start: ?u64,
    instructions_current_tier_mult: u64,

    num_native_calls: u64 = 0,
    err: StatusCode = .EXECUTED,

    /// Size configs of this gas model version (`size_config_for_gas_model_version`).
    plain: SizeCfg,
    traversal: SizeCfg,

    const INTERNAL_UNIT_MULTIPLIER: u64 = 1000;

    /// `GasStatus::new(cost_table_for_version(gm), budget, gas_price, gm)`.
    pub fn init(gas_model_version: u64, budget: u64, gas_price: u64) Meter {
        std.debug.assert(gas_price > 0);
        const table = protocol.gas.costTableForVersion(gas_model_version);
        const gas_left = (budget / gas_price) *% INTERNAL_UNIT_MULTIPLIER;
        const h = table.stackHeightTier(0);
        const s = table.stackSizeTier(0);
        const i = table.instructionTier(0);
        return .{
            .gas_model_version = gas_model_version,
            .table = table,
            .gas_left = gas_left,
            .gas_price = gas_price,
            .initial_budget = gas_left,
            .stack_height_current_tier_mult = h[0],
            .stack_height_next_tier_start = h[1],
            .stack_size_current_tier_mult = s[0],
            .stack_size_next_tier_start = s[1],
            .instructions_current_tier_mult = i[0],
            .instructions_next_tier_start = i[1],
            .plain = sizeConfig(gas_model_version, false),
            .traversal = sizeConfig(gas_model_version, true),
        };
    }

    /// `GasStatus::new_unmetered()`.
    pub fn unmetered() Meter {
        var m = init(11, 0, 1);
        m.table = &protocol.gas.zero_cost_schedule;
        m.charge_enabled = false;
        m.stack_height_current_tier_mult = 0;
        m.stack_size_current_tier_mult = 0;
        m.instructions_current_tier_mult = 0;
        m.stack_height_next_tier_start = null;
        m.stack_size_next_tier_start = null;
        m.instructions_next_tier_start = null;
        return m;
    }

    fn fail(m: *Meter, s: StatusCode) ChargeError {
        @branchHint(.cold);
        m.err = s;
        return error.Charge;
    }

    inline fn pushStack(m: *Meter, pushes: u64) ChargeError!void {
        const nh = std.math.add(u64, m.stack_height_current, pushes) catch return m.fail(.ARITHMETIC_OVERFLOW);
        if (nh > m.stack_height_high_water_mark) m.stack_height_high_water_mark = nh;
        m.stack_height_current = nh;
        if (m.stack_height_next_tier_start) |next| if (m.stack_height_current > next) m.heightTier();
    }

    fn heightTier(m: *Meter) void {
        @branchHint(.cold);
        const t = m.table.stackHeightTier(m.stack_height_current);
        m.stack_height_current_tier_mult = t[0];
        m.stack_height_next_tier_start = t[1];
    }

    fn instructionTier(m: *Meter) void {
        @branchHint(.cold);
        const t = m.table.instructionTier(m.instructions_executed);
        m.instructions_current_tier_mult = t[0];
        m.instructions_next_tier_start = t[1];
    }

    fn sizeTier(m: *Meter) void {
        @branchHint(.cold);
        const t = m.table.stackSizeTier(m.stack_size_current);
        m.stack_size_current_tier_mult = t[0];
        m.stack_size_next_tier_start = t[1];
    }

    inline fn popStack(m: *Meter, pops: u64) void {
        // Underflow saturates to 0 (legacy double-pop, or debug_fatal in release).
        m.stack_height_current = std.math.sub(u64, m.stack_height_current, pops) catch 0;
    }

    inline fn increaseInstructionCount(m: *Meter, amount: u64) ChargeError!void {
        m.instructions_executed = std.math.add(u64, m.instructions_executed, amount) catch return m.fail(.PC_OVERFLOW);
        if (m.instructions_next_tier_start) |next| if (m.instructions_executed > next) m.instructionTier();
    }

    inline fn increaseStackSize(m: *Meter, amount: u64) ChargeError!void {
        const ns = std.math.add(u64, m.stack_size_current, amount) catch return m.fail(.ARITHMETIC_OVERFLOW);
        if (ns > m.stack_size_high_water_mark) m.stack_size_high_water_mark = ns;
        m.stack_size_current = ns;
        if (m.stack_size_next_tier_start) |next| if (m.stack_size_current > next) m.sizeTier();
    }

    /// `GasStatus::charge(num_instructions, pushes, pops, incr_size, _decr_size)`.
    ///
    /// Fast path: computes every candidate counter and the cost from the current state without
    /// writing anything; only when nothing unusual happens (no overflow, no tier boundary
    /// crossed, metering on, enough gas, no pop below zero) does it commit, with the same
    /// values `chargeExact` writes. Anything else runs `chargeExact` from the untouched state.
    pub inline fn charge(m: *Meter, num_instructions: u64, pushes: u64, pops: u64, incr_size: u64) ChargeError!void {
        const max = std.math.maxInt(u64);
        const nh, const o1 = @addWithOverflow(m.stack_height_current, pushes);
        const ni, const o2 = @addWithOverflow(m.instructions_executed, num_instructions);
        const ns, const o3 = @addWithOverflow(m.stack_size_current, incr_size);
        const a, const o4 = @mulWithOverflow(m.instructions_current_tier_mult, num_instructions);
        const b, const o5 = @mulWithOverflow(m.stack_size_current_tier_mult, incr_size);
        const c, const o6 = @mulWithOverflow(m.stack_height_current_tier_mult, pushes);
        const cost = a +% b +% c;
        const unusual = (o1 | o2 | o3 | o4 | o5 | o6) != 0 or
            nh > (m.stack_height_next_tier_start orelse max) or
            ni > (m.instructions_next_tier_start orelse max) or
            ns > (m.stack_size_next_tier_start orelse max) or
            !m.charge_enabled or m.gas_left < cost or nh < pops;
        if (unusual) return m.chargeExact(num_instructions, pushes, pops, incr_size);
        m.stack_height_high_water_mark = @max(m.stack_height_high_water_mark, nh);
        m.instructions_executed = ni;
        m.stack_size_high_water_mark = @max(m.stack_size_high_water_mark, ns);
        m.stack_size_current = ns;
        m.gas_left -= cost;
        m.stack_height_current = nh - pops;
    }

    /// `GasStatus::charge` step by step (tier changes, overflow, out of gas, unmetered).
    fn chargeExact(m: *Meter, num_instructions: u64, pushes: u64, pops: u64, incr_size: u64) ChargeError!void {
        @branchHint(.cold);
        try m.pushStack(pushes);
        try m.increaseInstructionCount(num_instructions);
        try m.increaseStackSize(incr_size);
        const a = std.math.mul(u64, m.instructions_current_tier_mult, num_instructions) catch return m.fail(.ARITHMETIC_OVERFLOW);
        const b = std.math.mul(u64, m.stack_size_current_tier_mult, incr_size) catch return m.fail(.ARITHMETIC_OVERFLOW);
        const c = std.math.mul(u64, m.stack_height_current_tier_mult, pushes) catch return m.fail(.ARITHMETIC_OVERFLOW);
        // GasCost::total_internal: plain u64 additions (wrapping in a release build).
        try m.deductGas(a +% b +% c);
        m.popStack(pops);
    }

    /// `GasStatus::deduct_gas`.
    pub inline fn deductGas(m: *Meter, amount: u64) ChargeError!void {
        if (!m.charge_enabled) return;
        if (m.gas_left >= amount) {
            m.gas_left -= amount;
        } else {
            m.gas_left = 0;
            return m.fail(.OUT_OF_GAS);
        }
    }

    /// `GasStatus::gas_used_pre_gas_price`.
    pub fn gasUsedPreGasPrice(m: *const Meter) u64 {
        const used = if (m.initial_budget >= m.gas_left) m.initial_budget - m.gas_left else m.initial_budget;
        return used / INTERNAL_UNIT_MULTIPLIER;
    }

    /// `GasMeter::remaining_gas` of `SuiGasMeter`.
    pub fn remainingGas(m: *const Meter) u64 {
        if (!m.charge_enabled) return std.math.maxInt(u64);
        return m.gas_left;
    }

    /// `GasStatus::charge_bytes`.
    pub fn chargeBytes(m: *Meter, size: u64, cost_per_byte: u64) ChargeError!void {
        const cost = if (protocol.gas.chargeInputAsMemory(m.gas_model_version)) blk: {
            try m.increaseStackSize(size);
            break :blk m.stack_size_current_tier_mult *% size *% cost_per_byte;
        } else size *% cost_per_byte;
        try m.deductGas(cost);
    }

    // ---- SuiGasMeter: one function per GasMeter hook --------------------------------------

    pub const Simple = enum { Nop, Ret, BrTrue, BrFalse, Branch, LdU8, LdU16, LdU32, LdU64, LdU128, LdU256, LdTrue, LdFalse, FreezeRef, ImmBorrowLoc, MutBorrowLoc, ImmBorrowField, MutBorrowField, ImmBorrowFieldGeneric, MutBorrowFieldGeneric, CastU8, CastU16, CastU32, CastU64, CastU128, CastU256, Add, Sub, Mul, Mod, Div, BitOr, BitAnd, Xor, Shl, Shr, Or, And, Lt, Gt, Le, Ge, Not, Abort };

    /// (pops, pushes, incr) of `get_simple_instruction_stack_change`; every `Type::size()` is 1.
    pub fn simpleChange(i: Simple) struct { u64, u64, u64 } {
        return switch (i) {
            .Nop, .Ret, .Branch => .{ 0, 0, 0 },
            .BrTrue, .BrFalse => .{ 1, 0, 0 },
            .LdU8, .LdU16, .LdU32, .LdU64, .LdU128, .LdU256, .LdTrue, .LdFalse => .{ 0, 1, PRIM_TYPE_SIZE },
            .FreezeRef => .{ 1, 1, REFERENCE_SIZE },
            .ImmBorrowLoc, .MutBorrowLoc => .{ 0, 1, REFERENCE_SIZE },
            .ImmBorrowField, .MutBorrowField, .ImmBorrowFieldGeneric, .MutBorrowFieldGeneric => .{ 1, 1, REFERENCE_SIZE },
            .CastU8, .CastU16, .CastU32, .CastU64, .CastU128, .CastU256 => .{ 1, 1, PRIM_TYPE_SIZE },
            .Add, .Sub, .Mul, .Mod, .Div, .BitOr, .BitAnd, .Xor, .Shl, .Shr, .Or, .And, .Lt, .Gt, .Le, .Ge => .{ 2, 1, PRIM_TYPE_SIZE },
            .Not => .{ 1, 1, PRIM_TYPE_SIZE },
            .Abort => .{ 1, 0, 0 },
        };
    }

    pub inline fn chargeSimple(m: *Meter, comptime i: Simple) ChargeError!void {
        const c = comptime simpleChange(i);
        return m.charge(1, c[1], c[0], c[2]);
    }

    pub inline fn chargePop(m: *Meter) ChargeError!void {
        return m.charge(1, 0, 1, 0);
    }
    pub inline fn chargeLdConst(m: *Meter, size: u64) ChargeError!void {
        return m.charge(1, 1, 0, size);
    }
    pub inline fn chargeCopyLoc(m: *Meter, size: u64) ChargeError!void {
        return m.charge(1, 1, 0, size);
    }
    /// `size` is only used before gas model 11 (`reweight_move_loc`).
    pub inline fn chargeMoveLoc(m: *Meter, size: u64) ChargeError!void {
        return m.charge(1, 1, 0, if (m.gas_model_version > 10) REFERENCE_SIZE else size);
    }
    pub inline fn moveLocNeedsSize(m: *const Meter) bool {
        return m.gas_model_version <= 10;
    }
    pub inline fn chargeStoreLoc(m: *Meter) ChargeError!void {
        return m.charge(1, 0, 1, 0);
    }
    pub inline fn chargeCall(m: *Meter, n_args: u64) ChargeError!void {
        return m.charge(1, 0, n_args, 0);
    }
    pub inline fn chargePack(m: *Meter, n_fields: u64) ChargeError!void {
        return m.charge(1, 1, n_fields, STRUCT_SIZE);
    }
    pub inline fn chargeUnpack(m: *Meter, n_fields: u64) ChargeError!void {
        return m.charge(1, n_fields, 1, 0);
    }
    pub inline fn chargeVariantSwitch(m: *Meter) ChargeError!void {
        return m.charge(1, 0, 1, 0);
    }
    /// `size_plain` / `size_traversal`: abstract size of the referent under `plain` / `traversal`.
    pub inline fn chargeReadRef(m: *Meter, size_plain: u64, size_traversal: u64) ChargeError!void {
        const size = if (m.gas_model_version > 10) size_traversal else size_plain;
        return m.charge(1, 1, 1, size);
    }
    pub inline fn chargeWriteRef(m: *Meter, new_size: u64) ChargeError!void {
        const pushes: u64 = if (m.gas_model_version > 10) 0 else 1;
        return m.charge(1, pushes, 2, new_size);
    }
    /// Sizes under the `traversal` config.
    pub inline fn chargeEq(m: *Meter, lhs: u64, rhs: u64) ChargeError!void {
        const red = lhs +| rhs;
        return m.charge(1, 1, 2, PRIM_TYPE_SIZE +| red);
    }
    pub inline fn chargeNeq(m: *Meter, lhs: u64, rhs: u64) ChargeError!void {
        const red = lhs +| rhs;
        const incr = if (m.gas_model_version > 9) PRIM_TYPE_SIZE +| red else PRIM_TYPE_SIZE;
        return m.charge(1, 1, 2, incr);
    }
    pub inline fn chargeVecPack(m: *Meter, n: u64) ChargeError!void {
        return m.charge(1, 1, n, VEC_SIZE);
    }
    pub inline fn chargeVecLen(m: *Meter) ChargeError!void {
        return m.charge(1, 1, 1, PRIM_TYPE_SIZE);
    }
    pub inline fn chargeVecBorrow(m: *Meter) ChargeError!void {
        return m.charge(1, 1, 2, REFERENCE_SIZE);
    }
    pub inline fn chargeVecPushBack(m: *Meter) ChargeError!void {
        return m.charge(1, 0, 2, 0);
    }
    pub inline fn chargeVecPopBack(m: *Meter) ChargeError!void {
        return m.charge(1, 1, 1, 0);
    }
    pub inline fn chargeVecUnpack(m: *Meter, expect: u64) ChargeError!void {
        return m.charge(1, expect, 1, 0);
    }
    pub inline fn chargeVecSwap(m: *Meter) ChargeError!void {
        if (m.gas_model_version > 10) return m.charge(1, 0, 3, 0);
        return m.charge(1, 1, 1, 0);
    }

    /// `charge_native_function_before_execution` (the argument sizes only feed the unused
    /// size decrease).
    pub fn chargeNativeBefore(m: *Meter, n_args: u64) ChargeError!void {
        if (protocol.gas.legacyChargeNativePopsArgs(m.gas_model_version)) {
            return m.charge(1, 0, n_args, 0);
        }
        return m.charge(1, 0, 0, 0);
    }

    /// `charge_native_function(amount, ret_vals)`; `ret` is null when the native aborted.
    pub fn chargeNative(m: *Meter, amount: u64, ret: ?struct { n: u64, size: u64 }) ChargeError!void {
        const pushes: u64 = if (ret) |r| r.n else 0;
        const size: u64 = if (ret) |r| r.size else 0;
        m.num_native_calls +|= 1;
        if (protocol.gas.nativeFunctionThresholdExceeded(m.gas_model_version, m.num_native_calls)) {
            return m.charge(amount, pushes, 0, size);
        }
        try m.charge(0, pushes, 0, size);
        return m.deductGas(amount);
    }
};

/// `size_config_for_gas_model_version`.
pub fn sizeConfig(gm: u64, traverse: bool) SizeCfg {
    const fine = gm > 10; // enable_fine_grained_value_size
    if (protocol.gas.useLegacyAbstractSize(gm)) return .{ .traverse_references = false, .include_vector_size = false, .fine_grained = false };
    if (traverse) return .{ .traverse_references = gm > 9, .include_vector_size = true, .fine_grained = fine };
    return .{ .traverse_references = false, .include_vector_size = true, .fine_grained = fine };
}

test "simple charges" {
    var m = Meter.init(15, 1_000_000, 1);
    try m.chargeSimple(.LdU64);
    try m.chargeSimple(.Ret);
    try std.testing.expectEqual(@as(u64, 999_999_996), m.gas_left);
    try std.testing.expectEqual(@as(u64, 1), m.stack_height_current);
}

test "out of gas leaves counters as Rust does" {
    var m = Meter.init(15, 0, 1);
    try std.testing.expectError(error.Charge, m.chargeSimple(.Add));
    try std.testing.expectEqual(StatusCode.OUT_OF_GAS, m.err);
    try std.testing.expectEqual(@as(u64, 1), m.stack_height_current); // pushes applied, pops not
    try std.testing.expectEqual(@as(u64, 1), m.instructions_executed);
}

test "charge fast path equals chargeExact (tiers, out of gas, overflow, unmetered, pop underflow)" {
    var prng = std.Random.DefaultPrng.init(0x5a17_4e0f);
    const rnd = prng.random();
    const gms = [_]u64{ 1, 4, 5, 8, 10, 11, 12 };
    const big = [_]u64{ 0, 1, 2, 3, 7, 999, 1000, 1001, 4095, 4096, 4097, 1 << 20, (1 << 32) - 1, std.math.maxInt(u64) - 1, std.math.maxInt(u64) };
    var i: usize = 0;
    while (i < 200_000) : (i += 1) {
        const gm = gms[rnd.uintLessThan(usize, gms.len)];
        const budget = if (rnd.boolean()) rnd.int(u64) else rnd.uintLessThan(u64, 100_000);
        var a = if (rnd.uintLessThan(u8, 16) == 0) Meter.unmetered() else Meter.init(gm, budget, 1 + rnd.uintLessThan(u64, 1000));
        // a random reachable state: run some charges first through the exact path
        var warm = rnd.uintLessThan(u32, 8);
        while (warm > 0) : (warm -= 1) a.chargeExact(rnd.uintLessThan(u64, 3000), rnd.uintLessThan(u64, 3000), rnd.uintLessThan(u64, 3000), rnd.uintLessThan(u64, 5000)) catch {};
        // and sometimes counters placed right at or past a tier boundary, or near overflow
        if (rnd.boolean()) {
            if (a.stack_height_next_tier_start) |n| a.stack_height_current = n -| rnd.uintLessThan(u64, 3);
            if (a.instructions_next_tier_start) |n| a.instructions_executed = n -| rnd.uintLessThan(u64, 3);
            if (a.stack_size_next_tier_start) |n| a.stack_size_current = n -| rnd.uintLessThan(u64, 3);
        }
        if (rnd.uintLessThan(u8, 32) == 0) a.stack_height_current = std.math.maxInt(u64) - rnd.uintLessThan(u64, 3);
        if (rnd.uintLessThan(u8, 32) == 0) a.instructions_executed = std.math.maxInt(u64) - rnd.uintLessThan(u64, 3);
        if (rnd.uintLessThan(u8, 32) == 0) a.stack_size_current = std.math.maxInt(u64) - rnd.uintLessThan(u64, 3);
        if (rnd.uintLessThan(u8, 8) == 0) a.gas_left = rnd.uintLessThan(u64, 64);
        a.err = .EXECUTED;
        var b = a;
        const pick = struct {
            fn f(r: std.Random, edges: []const u64, small: u64) u64 {
                return if (r.uintLessThan(u8, 8) == 0) edges[r.uintLessThan(usize, edges.len)] else r.uintLessThan(u64, small);
            }
        }.f;
        const ni = pick(rnd, &big, 4);
        const pu = pick(rnd, &big, 8);
        const po = pick(rnd, &big, 8);
        const sz = pick(rnd, &big, 200);
        const ok_a = if (a.charge(ni, pu, po, sz)) |_| true else |_| false;
        const ok_b = if (b.chargeExact(ni, pu, po, sz)) |_| true else |_| false;
        try std.testing.expectEqual(ok_b, ok_a);
        try std.testing.expectEqual(b, a);
    }
}
