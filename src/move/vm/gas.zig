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

    /// The three next tier starts as plain integers (maxInt: the table has no further tier).
    /// A caller that charges in a loop keeps them in locals (`chargeL`), so a charge reads no
    /// optional; they are derived from the meter, never stored in it.
    pub const Limits = struct { h: u64, i: u64, s: u64 };

    pub inline fn limits(m: *const Meter) Limits {
        const max = std.math.maxInt(u64);
        return .{
            .h = m.stack_height_next_tier_start orelse max,
            .i = m.instructions_next_tier_start orelse max,
            .s = m.stack_size_next_tier_start orelse max,
        };
    }

    /// `GasStatus::charge(num_instructions, pushes, pops, incr_size, _decr_size)`.
    pub inline fn charge(m: *Meter, num_instructions: u64, pushes: u64, pops: u64, incr_size: u64) ChargeError!void {
        var l = m.limits();
        return m.chargeL(&l, num_instructions, pushes, pops, incr_size);
    }

    /// `charge` with the tier limits held by the caller: `l` must equal `m.limits()` on entry
    /// and does again on return (the only charges that move a tier start run `chargeExact`
    /// here, and the limits are read again after it). A caller that lets anything else charge
    /// the meter reads `m.limits()` again afterwards.
    ///
    /// Fast path: computes every candidate counter and the cost from the current state without
    /// writing anything; only when nothing unusual happens (no overflow, no tier boundary
    /// crossed, enough gas, no pop below zero) does it commit, with the same values
    /// `chargeExact` writes. Anything else runs `chargeExact` from the untouched state.
    /// An unmetered meter deducts nothing (`deduct_gas` returns early) and is otherwise
    /// charged like a metered one, so it takes the fast path too, with a cost of zero.
    pub inline fn chargeL(m: *Meter, l: *Limits, num_instructions: u64, pushes: u64, pops: u64, incr_size: u64) ChargeError!void {
        const nh, const o1 = @addWithOverflow(m.stack_height_current, pushes);
        const ni, const o2 = @addWithOverflow(m.instructions_executed, num_instructions);
        const ns, const o3 = @addWithOverflow(m.stack_size_current, incr_size);
        const a, const o4 = @mulWithOverflow(m.instructions_current_tier_mult, num_instructions);
        const b, const o5 = @mulWithOverflow(m.stack_size_current_tier_mult, incr_size);
        const c, const o6 = @mulWithOverflow(m.stack_height_current_tier_mult, pushes);
        const cost = if (m.charge_enabled) a +% b +% c else 0;
        const unusual = (o1 | o2 | o3 | o4 | o5 | o6) != 0 or
            nh > l.h or ni > l.i or ns > l.s or
            m.gas_left < cost or nh < pops;
        if (unusual) {
            const r = m.chargeExact(num_instructions, pushes, pops, incr_size);
            l.* = m.limits();
            return r;
        }
        m.stack_height_high_water_mark = @max(m.stack_height_high_water_mark, nh);
        m.instructions_executed = ni;
        m.stack_size_high_water_mark = @max(m.stack_size_high_water_mark, ns);
        m.stack_size_current = ns;
        m.gas_left -= cost;
        m.stack_height_current = nh - pops;
    }

    // ---- block charging (the interpreter's `block_gas` switch) ---------------------------------
    //
    // Between two tier starts every multiplier is constant, so `charge` is linear: n charges
    // that all take the fast path of `chargeL` leave the meter exactly where one charge of
    // their sums leaves it. `chargeBlock` makes that one charge when, and only when, every
    // one of the n would take the fast path; `uncharge` returns to the state after the first
    // k of them (every prefix of such a block takes the fast path too: counters only grow,
    // a prefix costs at most the whole, and a prefix's highest height is at most the block's).

    /// The sums of a run of charges of one instruction each, relative to the meter before the
    /// first: what the run adds, and what it needs of the stack height.
    pub const Block = struct {
        /// Charges in the run.
        n: u32 = 0,
        /// Sum of the size increases, sum of the pushes.
        size: u64 = 0,
        pushes: u64 = 0,
        /// Stack height after the run minus the height before it.
        net: i64 = 0,
        /// The highest height a charge reaches (height before the charge + its pushes) above
        /// the height before the run: what the height high-water mark and the height tier see.
        hmax: u64 = 0,
        /// The least height before the run for which no charge pops below zero.
        need: u64 = 0,

        pub fn add(b: *Block, pushes: u64, pops: u64, incr: u64) void {
            const reach = b.net + @as(i64, @intCast(pushes));
            if (reach > 0) b.hmax = @max(b.hmax, @as(u64, @intCast(reach)));
            const short = @as(i64, @intCast(pops)) - reach;
            if (short > 0) b.need = @max(b.need, @as(u64, @intCast(short)));
            b.net = reach - @as(i64, @intCast(pops));
            b.size += incr;
            b.pushes += pushes;
            b.n += 1;
        }
    };

    /// The meter before `chargeBlock` charged a block.
    pub const Mark = struct {
        instructions: u64,
        size: u64,
        size_hwm: u64,
        height: u64,
        height_hwm: u64,
        gas_left: u64,
    };

    /// Charges block `b` at once if each of its charges would take the fast path of `chargeL`
    /// from here (no counter passes its limit `l`, no pop below zero, enough gas for all of
    /// them, no overflow), and returns the meter's state before. Otherwise null, with the
    /// meter untouched: the caller charges the instructions one by one.
    pub fn chargeBlock(m: *Meter, l: Limits, b: *const Block) ?Mark {
        const ni, const o1 = @addWithOverflow(m.instructions_executed, @as(u64, b.n));
        const ns, const o2 = @addWithOverflow(m.stack_size_current, b.size);
        const top, const o3 = @addWithOverflow(m.stack_height_current, b.hmax);
        const ca, const o4 = @mulWithOverflow(m.instructions_current_tier_mult, @as(u64, b.n));
        const cb, const o5 = @mulWithOverflow(m.stack_size_current_tier_mult, b.size);
        const cc, const o6 = @mulWithOverflow(m.stack_height_current_tier_mult, b.pushes);
        const cab, const o7 = @addWithOverflow(ca, cb);
        const total, const o8 = @addWithOverflow(cab, cc);
        const cost = if (m.charge_enabled) total else 0;
        if ((o1 | o2 | o3 | o4 | o5 | o6 | o7 | o8) != 0 or
            ni > l.i or ns > l.s or top > l.h or
            m.stack_height_current < b.need or m.gas_left < cost) return null;
        const mark: Mark = .{
            .instructions = m.instructions_executed,
            .size = m.stack_size_current,
            .size_hwm = m.stack_size_high_water_mark,
            .height = m.stack_height_current,
            .height_hwm = m.stack_height_high_water_mark,
            .gas_left = m.gas_left,
        };
        m.instructions_executed = ni;
        m.stack_size_current = ns;
        m.stack_size_high_water_mark = @max(m.stack_size_high_water_mark, ns);
        m.stack_height_high_water_mark = @max(m.stack_height_high_water_mark, top);
        m.stack_height_current = heightPlus(m.stack_height_current, b.net);
        m.gas_left -= cost;
        return mark;
    }

    /// After `chargeBlock` returned `mark`: puts the meter where charging only the block's
    /// first `p.n` instructions one by one would have left it (`p`: their sums).
    pub fn uncharge(m: *Meter, mark: Mark, p: *const Block) void {
        m.instructions_executed = mark.instructions + p.n;
        m.stack_size_current = mark.size + p.size;
        // an empty prefix charged nothing; a charge moves each mark up to what it reaches
        m.stack_size_high_water_mark = if (p.n == 0) mark.size_hwm else @max(mark.size_hwm, mark.size + p.size);
        m.stack_height_high_water_mark = if (p.n == 0) mark.height_hwm else @max(mark.height_hwm, mark.height + p.hmax);
        m.stack_height_current = heightPlus(mark.height, p.net);
        const cost = m.instructions_current_tier_mult * p.n + m.stack_size_current_tier_mult * p.size + m.stack_height_current_tier_mult * p.pushes;
        m.gas_left = mark.gas_left - if (m.charge_enabled) cost else 0;
    }

    inline fn heightPlus(h: u64, d: i64) u64 {
        return if (d >= 0) h + @as(u64, @intCast(d)) else h - @as(u64, @intCast(-d));
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
    pub inline fn chargeSimpleL(m: *Meter, l: *Limits, comptime i: Simple) ChargeError!void {
        const c = comptime simpleChange(i);
        return m.chargeL(l, 1, c[1], c[0], c[2]);
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
        return m.charge(1, 1, 0, m.moveLocIncr(size));
    }
    /// The size increase `chargeMoveLoc` charges.
    pub inline fn moveLocIncr(m: *const Meter, size: u64) u64 {
        return if (m.gas_model_version > 10) REFERENCE_SIZE else size;
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
    /// The size config `chargeReadRef` takes the referent's size under, so a caller measures
    /// the referent once: `chargeReadRefSize(referentSize(r, m.readRefCfg()))`.
    pub inline fn readRefCfg(m: *const Meter) SizeCfg {
        return if (m.gas_model_version > 10) m.traversal else m.plain;
    }
    pub inline fn chargeReadRefSize(m: *Meter, size: u64) ChargeError!void {
        return m.charge(1, 1, 1, size);
    }
    pub inline fn chargeWriteRef(m: *Meter, new_size: u64) ChargeError!void {
        return m.charge(1, m.writeRefPushes(), 2, new_size);
    }
    pub inline fn writeRefPushes(m: *const Meter) u64 {
        return if (m.gas_model_version > 10) 0 else 1;
    }
    /// Sizes under the `traversal` config.
    pub inline fn chargeEq(m: *Meter, lhs: u64, rhs: u64) ChargeError!void {
        return m.charge(1, 1, 2, eqIncr(lhs, rhs));
    }
    pub inline fn chargeNeq(m: *Meter, lhs: u64, rhs: u64) ChargeError!void {
        return m.charge(1, 1, 2, m.neqIncr(lhs, rhs));
    }
    /// The size increases `chargeEq` and `chargeNeq` charge.
    pub inline fn eqIncr(lhs: u64, rhs: u64) u64 {
        return PRIM_TYPE_SIZE +| (lhs +| rhs);
    }
    pub inline fn neqIncr(m: *const Meter, lhs: u64, rhs: u64) u64 {
        const red = lhs +| rhs;
        return if (m.gas_model_version > 9) PRIM_TYPE_SIZE +| red else PRIM_TYPE_SIZE;
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
        const c = m.vecSwapChange();
        return m.charge(1, c[0], c[1], 0);
    }
    /// (pushes, pops) `chargeVecSwap` charges.
    pub inline fn vecSwapChange(m: *const Meter) struct { u64, u64 } {
        return if (m.gas_model_version > 10) .{ 0, 3 } else .{ 1, 1 };
    }

    // The interpreter loop's twins of the charges above: the same arguments through `chargeL`
    // (test "L twins charge what their plain functions charge").
    pub inline fn chargePopL(m: *Meter, l: *Limits) ChargeError!void {
        return m.chargeL(l, 1, 0, 1, 0);
    }
    pub inline fn chargeCopyLocL(m: *Meter, l: *Limits, size: u64) ChargeError!void {
        return m.chargeL(l, 1, 1, 0, size);
    }
    pub inline fn chargeMoveLocL(m: *Meter, l: *Limits, size: u64) ChargeError!void {
        return m.chargeL(l, 1, 1, 0, m.moveLocIncr(size));
    }
    pub inline fn chargeStoreLocL(m: *Meter, l: *Limits) ChargeError!void {
        return m.chargeL(l, 1, 0, 1, 0);
    }
    pub inline fn chargeCallL(m: *Meter, l: *Limits, n_args: u64) ChargeError!void {
        return m.chargeL(l, 1, 0, n_args, 0);
    }
    pub inline fn chargeReadRefSizeL(m: *Meter, l: *Limits, size: u64) ChargeError!void {
        return m.chargeL(l, 1, 1, 1, size);
    }
    pub inline fn chargeWriteRefL(m: *Meter, l: *Limits, new_size: u64) ChargeError!void {
        return m.chargeL(l, 1, m.writeRefPushes(), 2, new_size);
    }
    pub inline fn chargeEqL(m: *Meter, l: *Limits, lhs: u64, rhs: u64) ChargeError!void {
        return m.chargeL(l, 1, 1, 2, eqIncr(lhs, rhs));
    }
    pub inline fn chargeNeqL(m: *Meter, l: *Limits, lhs: u64, rhs: u64) ChargeError!void {
        return m.chargeL(l, 1, 1, 2, m.neqIncr(lhs, rhs));
    }
    pub inline fn chargeVecLenL(m: *Meter, l: *Limits) ChargeError!void {
        return m.chargeL(l, 1, 1, 1, PRIM_TYPE_SIZE);
    }
    pub inline fn chargeVecBorrowL(m: *Meter, l: *Limits) ChargeError!void {
        return m.chargeL(l, 1, 1, 2, REFERENCE_SIZE);
    }
    pub inline fn chargeVecPushBackL(m: *Meter, l: *Limits) ChargeError!void {
        return m.chargeL(l, 1, 0, 2, 0);
    }
    pub inline fn chargeVecPopBackL(m: *Meter, l: *Limits) ChargeError!void {
        return m.chargeL(l, 1, 1, 1, 0);
    }
    pub inline fn chargeVecSwapL(m: *Meter, l: *Limits) ChargeError!void {
        const c = m.vecSwapChange();
        return m.chargeL(l, 1, c[0], c[1], 0);
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

test "L twins charge what their plain functions charge" {
    var prng = std.Random.DefaultPrng.init(0x7717_0b5e);
    const rnd = prng.random();
    var round: usize = 0;
    while (round < 20_000) : (round += 1) {
        const gm = 1 + rnd.uintLessThan(u64, 12);
        var a = if (round % 11 == 0) Meter.unmetered() else Meter.init(gm, rnd.uintLessThan(u64, 100), 1);
        if (rnd.boolean()) {
            if (a.stack_height_next_tier_start) |n| a.stack_height_current = n -| rnd.uintLessThan(u64, 3);
            if (a.instructions_next_tier_start) |n| a.instructions_executed = n -| rnd.uintLessThan(u64, 3);
            if (a.stack_size_next_tier_start) |n| a.stack_size_current = n -| rnd.uintLessThan(u64, 60);
        }
        a.stack_height_current +|= rnd.uintLessThan(u64, 4);
        var b = a;
        var l = a.limits();
        const x = rnd.uintLessThan(u64, 70);
        const y = if (rnd.uintLessThan(u8, 8) == 0) std.math.maxInt(u64) - rnd.uintLessThan(u64, 3) else rnd.uintLessThan(u64, 70);
        const which = round % (14 + @typeInfo(Meter.Simple).@"enum".field_names.len);
        const ra: ChargeError!void, const rb: ChargeError!void = switch (which) {
            0 => .{ a.chargePop(), b.chargePopL(&l) },
            1 => .{ a.chargeCopyLoc(x), b.chargeCopyLocL(&l, x) },
            2 => .{ a.chargeMoveLoc(x), b.chargeMoveLocL(&l, x) },
            3 => .{ a.chargeStoreLoc(), b.chargeStoreLocL(&l) },
            4 => .{ a.chargeCall(x), b.chargeCallL(&l, x) },
            5 => .{ a.chargeReadRef(x, y), b.chargeReadRefSizeL(&l, if (b.gas_model_version > 10) y else x) },
            6 => .{ a.chargeWriteRef(x), b.chargeWriteRefL(&l, x) },
            7 => .{ a.chargeEq(x, y), b.chargeEqL(&l, x, y) },
            8 => .{ a.chargeNeq(x, y), b.chargeNeqL(&l, x, y) },
            9 => .{ a.chargeVecLen(), b.chargeVecLenL(&l) },
            10 => .{ a.chargeVecBorrow(), b.chargeVecBorrowL(&l) },
            11 => .{ a.chargeVecPushBack(), b.chargeVecPushBackL(&l) },
            12 => .{ a.chargeVecPopBack(), b.chargeVecPopBackL(&l) },
            13 => .{ a.chargeVecSwap(), b.chargeVecSwapL(&l) },
            else => blk: {
                inline for (@typeInfo(Meter.Simple).@"enum".field_names, 0..) |name, i| {
                    if (which - 14 == i) break :blk .{ a.chargeSimple(@field(Meter.Simple, name)), b.chargeSimpleL(&l, @field(Meter.Simple, name)) };
                }
                unreachable;
            },
        };
        try std.testing.expectEqual(ra, rb);
        try std.testing.expectEqual(a, b);
        try std.testing.expectEqual(b.limits(), l);
        // and the size config of a ReadRef is the one its charge reads
        try std.testing.expectEqual(if (a.gas_model_version > 10) a.traversal else a.plain, a.readRefCfg());
    }
}

test "chargeBlock equals its charges one by one, and uncharge equals every prefix" {
    var prng = std.Random.DefaultPrng.init(0xb10c_6a5);
    const rnd = prng.random();
    var committed: usize = 0;
    var refused: usize = 0;
    var round: usize = 0;
    while (round < 60_000) : (round += 1) {
        const gm = 1 + rnd.uintLessThan(u64, 12);
        var m0 = if (round % 13 == 0) Meter.unmetered() else Meter.init(gm, if (rnd.uintLessThan(u8, 4) == 0) rnd.uintLessThan(u64, 2) else 1_000_000, 1);
        if (round % 17 == 0) m0.charge_enabled = false;
        // a reachable state, often right under a tier start or with just about enough gas
        var warm = rnd.uintLessThan(u32, 4);
        while (warm > 0) : (warm -= 1) m0.chargeExact(rnd.uintLessThan(u64, 2000), rnd.uintLessThan(u64, 30), rnd.uintLessThan(u64, 30), rnd.uintLessThan(u64, 3000)) catch {};
        if (rnd.uintLessThan(u8, 4) != 0) {
            // most blocks start with values on the stack to pop
            m0.stack_height_current += 40 + rnd.uintLessThan(u64, 100);
            m0.stack_height_high_water_mark = @max(m0.stack_height_high_water_mark, m0.stack_height_current);
        }
        if (rnd.uintLessThan(u8, 3) == 0) {
            if (m0.stack_height_next_tier_start) |n| m0.stack_height_current = n -| rnd.uintLessThan(u64, 12);
            if (m0.instructions_next_tier_start) |n| m0.instructions_executed = n -| rnd.uintLessThan(u64, 24);
            if (m0.stack_size_next_tier_start) |n| m0.stack_size_current = n -| rnd.uintLessThan(u64, 200);
        }
        if (rnd.uintLessThan(u8, 4) == 0) m0.stack_height_current = rnd.uintLessThan(u64, 4);
        if (rnd.uintLessThan(u8, 4) == 0) m0.stack_height_high_water_mark = rnd.uintLessThan(u64, 2000); // also below the current height
        if (rnd.uintLessThan(u8, 4) == 0) m0.gas_left = rnd.uintLessThan(u64, 400);
        if (rnd.uintLessThan(u8, 64) == 0) m0.instructions_executed = std.math.maxInt(u64) - rnd.uintLessThan(u64, 20);
        if (rnd.uintLessThan(u8, 64) == 0) m0.stack_size_current = std.math.maxInt(u64) - rnd.uintLessThan(u64, 200);
        if (rnd.uintLessThan(u8, 64) == 0) m0.stack_height_current = std.math.maxInt(u64) - rnd.uintLessThan(u64, 4);
        m0.err = .EXECUTED;
        // a block of instruction-like charges, and its prefixes
        const n = 1 + rnd.uintLessThan(usize, 24);
        var ch: [24][3]u64 = undefined;
        var pre: [25]Meter.Block = undefined;
        var b: Meter.Block = .{};
        for (ch[0..n], 0..) |*c, i| {
            c.* = .{ rnd.uintLessThan(u64, 2), rnd.uintLessThan(u64, 4), ([_]u64{ 0, 0, 1, 1, 8, 8, 16, 32 })[rnd.uintLessThan(usize, 8)] };
            pre[i] = b;
            b.add(c[0], c[1], c[2]);
        }
        pre[n] = b;
        try std.testing.expectEqual(@as(u32, @intCast(n)), b.n);
        var blk = m0;
        const l = m0.limits();
        if (blk.chargeBlock(l, &b)) |mark| {
            committed += 1;
            // the reference: each charge through chargeExact, none fails, no tier moves
            var one = m0;
            for (ch[0..n], 0..) |c, i| {
                var back = blk;
                back.uncharge(mark, &pre[i]);
                try std.testing.expectEqual(one, back);
                try one.chargeExact(1, c[0], c[1], c[2]);
                try std.testing.expectEqual(l, one.limits());
            }
            try std.testing.expectEqual(one, blk);
            var back = blk;
            back.uncharge(mark, &pre[n]);
            try std.testing.expectEqual(one, back);
        } else {
            refused += 1;
            try std.testing.expectEqual(m0, blk);
            // refused for a reason: one of the charges does leave the fast path, or the meter
            // is at the far end of its range
            var one = m0;
            var unusual = false;
            for (ch[0..n]) |c| {
                const nh = one.stack_height_current +| c[0];
                const cost = if (one.charge_enabled) one.instructions_current_tier_mult +| one.stack_size_current_tier_mult *| c[2] +| one.stack_height_current_tier_mult *| c[0] else 0;
                if (nh > l.h or one.instructions_executed +| 1 > l.i or one.stack_size_current +| c[2] > l.s or one.gas_left < cost or nh < c[1]) unusual = true;
                one.chargeExact(1, c[0], c[1], c[2]) catch {
                    unusual = true;
                    break;
                };
            }
            const far = m0.instructions_executed > std.math.maxInt(u64) - 64 or m0.stack_size_current > std.math.maxInt(u64) - 1024 or m0.stack_height_current > std.math.maxInt(u64) - 64;
            try std.testing.expect(unusual or far);
        }
    }
    // both happen all the time
    if (committed < 8_000 or refused < 8_000) {
        std.debug.print("\nchargeBlock test: {d} blocks charged at once, {d} refused\n", .{ committed, refused });
        return error.TestUnexpectedResult;
    }
}

test "chargeL keeps its limits equal to the meter's across tier changes" {
    // A run of charges through `chargeL` with one `Limits` held outside the meter against the
    // same charges through `chargeExact`: same meter after every charge, and the held limits
    // are the meter's own after every charge, also when a charge fails.
    var prng = std.Random.DefaultPrng.init(0x71e5_11a1);
    const rnd = prng.random();
    var round: usize = 0;
    while (round < 2_000) : (round += 1) {
        const gm = 1 + rnd.uintLessThan(u64, 12);
        var a = if (round % 9 == 0) Meter.unmetered() else Meter.init(gm, rnd.uintLessThan(u64, 3_000_000), 1);
        if (round % 7 == 0) a.charge_enabled = false; // a metered table that deducts nothing
        if (rnd.boolean()) {
            if (a.stack_height_next_tier_start) |n| a.stack_height_current = n -| rnd.uintLessThan(u64, 40);
            if (a.instructions_next_tier_start) |n| a.instructions_executed = n -| rnd.uintLessThan(u64, 40);
            if (a.stack_size_next_tier_start) |n| a.stack_size_current = n -| rnd.uintLessThan(u64, 400);
        }
        var b = a;
        var l = a.limits();
        var k: usize = 0;
        while (k < 200) : (k += 1) {
            const pu = rnd.uintLessThan(u64, 3);
            const po = rnd.uintLessThan(u64, 4);
            const sz = if (rnd.uintLessThan(u8, 20) == 0) rnd.uintLessThan(u64, 200_000) else rnd.uintLessThan(u64, 40);
            const ok_a = if (a.chargeL(&l, 1, pu, po, sz)) |_| true else |_| false;
            const ok_b = if (b.chargeExact(1, pu, po, sz)) |_| true else |_| false;
            try std.testing.expectEqual(ok_b, ok_a);
            try std.testing.expectEqual(b, a);
            try std.testing.expectEqual(a.limits(), l);
        }
    }
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
        // metering off on a metered table: nothing is deducted, the counters and tiers move
        if (rnd.uintLessThan(u8, 16) == 0) a.charge_enabled = false;
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
