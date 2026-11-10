//! Gas status for transaction execution.
//!
//! - `MoveGasStatus`: sui-types `gas_model/tables.rs` `GasStatus`, the Move meter core (tiers of
//!   instruction count, stack height and stack size; internal gas = 1000 x gas units).
//! - `StorageGas`: `gas_model/gas_common.rs` per-object storage cost and rebate accumulator.
//! - `SuiGasStatus`: `gas_model/gas_v3.rs` (gas model 15 and later: half-digit rounding of
//!   computation, derived computation capped by the budget net of storage) and
//!   `gas_model/gas_v2.rs` (earlier models: bucketed or stepped computation).
//!
//! The Move VM charges through `MoveGasStatus` (`move_vm.GasMeter` wraps it once the move-vm
//! lane lands; until then exec owns this copy).
//!
//! Overflow semantics follow Mysten's release build exactly, with no undefined behaviour in any
//! Zig build mode:
//! - `gas_model/tables.rs` is plain Rust arithmetic, and sui-node's `[profile.release]` has no
//!   `overflow-checks`, so `to_internal_units`, `charge_bytes` and the instruction + memory +
//!   stack sum in `charge` wrap. Here they use wrapping operators (`*%`, `+%`).
//! - `gas.rs`, `gas_v2.rs` and `gas_v3.rs` are under `with_checked_arithmetic` (or use
//!   `checked_*().expect`): an overflow there panics the Rust node. Here it returns
//!   `error.ArithmeticPanic`, which no certified transaction can reach.
//! - `checked_*` that Rust maps to an error, and `saturating_*`, are mirrored as such.
const std = @import("std");
const protocol = @import("protocol");

const CostTable = protocol.gas.CostTable;

pub const OutOfGas = error{OutOfGas};

/// An arithmetic overflow at a site where Mysten's Rust panics (checked arithmetic or
/// `.expect`). A validator would abort; a certified transaction cannot reach it.
pub const Panic = error{ArithmeticPanic};

/// A protocol-visible execution failure from gas accounting (ExecutionErrorKind).
pub const GasError = enum { InsufficientGas, InvariantViolation };

pub const internal_unit_multiplier: u64 = 1000;

pub const MoveGasStatus = struct {
    gas_model_version: u64,
    cost_table: *const CostTable,
    gas_left: u64,
    gas_price: u64,
    initial_budget: u64,
    metering: bool,
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

    pub fn init(cost_table: *const CostTable, budget: u64, gas_price: u64, gas_model_version: u64) MoveGasStatus {
        std.debug.assert(gas_price > 0);
        const gas_left = toInternalUnits(budget / gas_price);
        const sh = cost_table.stackHeightTier(0);
        const ss = cost_table.stackSizeTier(0);
        const in = cost_table.instructionTier(0);
        return .{
            .gas_model_version = gas_model_version,
            .cost_table = cost_table,
            .gas_left = gas_left,
            .gas_price = gas_price,
            .initial_budget = gas_left,
            .metering = true,
            .stack_height_current_tier_mult = sh[0],
            .stack_height_next_tier_start = sh[1],
            .stack_size_current_tier_mult = ss[0],
            .stack_size_next_tier_start = ss[1],
            .instructions_current_tier_mult = in[0],
            .instructions_next_tier_start = in[1],
        };
    }

    /// tables.rs `to_internal_units`: `val * 1000`, wrapping in the release build.
    pub fn toInternalUnits(val: u64) u64 {
        return val *% internal_unit_multiplier;
    }

    pub fn initUnmetered() MoveGasStatus {
        return .{
            .gas_model_version = 11,
            .cost_table = &protocol.gas.zero_cost_schedule,
            .gas_left = 0,
            .gas_price = 1,
            .initial_budget = 0,
            .metering = false,
            .stack_height_current_tier_mult = 0,
            .stack_height_next_tier_start = null,
            .stack_size_current_tier_mult = 0,
            .stack_size_next_tier_start = null,
            .instructions_current_tier_mult = 0,
            .instructions_next_tier_start = null,
        };
    }

    pub fn pushStack(s: *MoveGasStatus, pushes: u64) error{ArithmeticOverflow}!void {
        const h = std.math.add(u64, s.stack_height_current, pushes) catch return error.ArithmeticOverflow;
        if (h > s.stack_height_high_water_mark) s.stack_height_high_water_mark = h;
        s.stack_height_current = h;
        if (s.stack_height_next_tier_start) |next| if (h > next) {
            const tr = s.cost_table.stackHeightTier(h);
            s.stack_height_current_tier_mult = tr[0];
            s.stack_height_next_tier_start = tr[1];
        };
    }

    pub fn popStack(s: *MoveGasStatus, pops: u64) void {
        s.stack_height_current = std.math.sub(u64, s.stack_height_current, pops) catch 0;
    }

    pub fn increaseInstructionCount(s: *MoveGasStatus, amount: u64) error{PcOverflow}!void {
        s.instructions_executed = std.math.add(u64, s.instructions_executed, amount) catch return error.PcOverflow;
        if (s.instructions_next_tier_start) |next| if (s.instructions_executed > next) {
            const tr = s.cost_table.instructionTier(s.instructions_executed);
            s.instructions_current_tier_mult = tr[0];
            s.instructions_next_tier_start = tr[1];
        };
    }

    pub fn increaseStackSize(s: *MoveGasStatus, amount: u64) error{ArithmeticOverflow}!void {
        const n = std.math.add(u64, s.stack_size_current, amount) catch return error.ArithmeticOverflow;
        if (n > s.stack_size_high_water_mark) s.stack_size_high_water_mark = n;
        s.stack_size_current = n;
        if (s.stack_size_next_tier_start) |next| if (n > next) {
            const tr = s.cost_table.stackSizeTier(n);
            s.stack_size_current_tier_mult = tr[0];
            s.stack_size_next_tier_start = tr[1];
        };
    }

    pub const ChargeError = error{ ArithmeticOverflow, PcOverflow, OutOfGas };

    pub fn charge(s: *MoveGasStatus, num_instructions: u64, pushes: u64, pops: u64, incr_size: u64, decr_size: u64) ChargeError!void {
        _ = decr_size;
        try s.pushStack(pushes);
        try s.increaseInstructionCount(num_instructions);
        try s.increaseStackSize(incr_size);
        const instr = std.math.mul(u64, s.instructions_current_tier_mult, num_instructions) catch return error.ArithmeticOverflow;
        const mem = std.math.mul(u64, s.stack_size_current_tier_mult, incr_size) catch return error.ArithmeticOverflow;
        const stack = std.math.mul(u64, s.stack_height_current_tier_mult, pushes) catch return error.ArithmeticOverflow;
        // units_types.rs `GasCost::total_internal`: plain u64 adds (wrap in release).
        try s.deductGas(instr +% mem +% stack);
        s.popStack(pops);
    }

    pub fn deductGas(s: *MoveGasStatus, amount: u64) OutOfGas!void {
        if (!s.metering) return;
        if (s.gas_left >= amount) {
            s.gas_left -= amount;
        } else {
            s.gas_left = 0;
            return error.OutOfGas;
        }
    }

    pub fn recordNativeCall(s: *MoveGasStatus) void {
        s.num_native_calls +|= 1;
    }

    pub fn remainingGas(s: *const MoveGasStatus) u64 {
        return s.gas_left / internal_unit_multiplier;
    }

    pub fn gasUsedPreGasPrice(s: *const MoveGasStatus) u64 {
        const used = if (s.initial_budget >= s.gas_left) s.initial_budget - s.gas_left else s.initial_budget;
        return used / internal_unit_multiplier;
    }

    pub fn chargeBytes(s: *MoveGasStatus, size: u64, cost_per_byte: u64) error{ ArithmeticOverflow, OutOfGas }!void {
        const cost = if (protocol.gas.chargeInputAsMemory(s.gas_model_version)) blk: {
            try s.increaseStackSize(size);
            break :blk s.stack_size_current_tier_mult *% size *% cost_per_byte;
        } else size *% cost_per_byte;
        try s.deductGas(cost);
    }
};

pub const PerObjectStorage = struct { id: [32]u8, storage_cost: u64, storage_rebate: u64, new_size: u64 };

pub const StorageGas = struct {
    per_object: std.ArrayList(PerObjectStorage) = .empty,
    total_storage_cost: u64 = 0,
    total_storage_rebate: u64 = 0,
    unmetered_storage_rebate: u64 = 0,
    storage_gas_price: u64,
    storage_per_byte_cost: u64,

    pub fn reset(s: *StorageGas) void {
        s.per_object.clearRetainingCapacity();
        s.total_storage_cost = 0;
        s.total_storage_rebate = 0;
        s.unmetered_storage_rebate = 0;
    }

    /// The new storage cost of the object, or null on overflow (Rust `None`).
    pub fn trackMutation(s: *StorageGas, arena: std.mem.Allocator, id: [32]u8, new_size: u64, storage_rebate: u64, unmetered: bool) !?u64 {
        if (unmetered) {
            s.unmetered_storage_rebate = std.math.add(u64, s.unmetered_storage_rebate, storage_rebate) catch return null;
            return 0;
        }
        const a = std.math.mul(u64, new_size, s.storage_per_byte_cost) catch return null;
        const cost = std.math.mul(u64, a, s.storage_gas_price) catch return null;
        s.total_storage_cost = std.math.add(u64, s.total_storage_cost, cost) catch return null;
        s.total_storage_rebate = std.math.add(u64, s.total_storage_rebate, storage_rebate) catch return null;
        try s.per_object.append(arena, .{ .id = id, .storage_cost = cost, .storage_rebate = storage_rebate, .new_size = new_size });
        return cost;
    }
};

/// gas_common.rs `sender_rebate`: storage_rebate * rate / 10000 rounded half up, saturating.
pub fn senderRebate(storage_rebate: u64, rate: u64) u64 {
    const basis: u128 = 10000;
    const r = (@as(u128, storage_rebate) *| @as(u128, rate)) +| basis / 2;
    return std.math.cast(u64, r / basis) orelse std.math.maxInt(u64);
}

/// gas_common.rs `package_read_internal_gas`: ceil(size * cost_per_kb / 1024), saturating.
pub fn packageReadInternalGas(size: u64, cost_per_kb: u64) u64 {
    const c = std.math.divCeil(u128, @as(u128, size) * cost_per_kb, 1024) catch unreachable;
    return std.math.cast(u64, c) orelse std.math.maxInt(u64);
}

pub const GasCostSummary = struct {
    computation_cost: u64 = 0,
    storage_cost: u64 = 0,
    storage_rebate: u64 = 0,
    non_refundable_storage_fee: u64 = 0,

    /// gas.rs `net_gas_usage` under `with_checked_arithmetic`:
    /// `(computation + storage) as i64 - storage_rebate as i64`. The add and the subtraction
    /// are checked (panic); the two `as i64` casts reinterpret the bits.
    pub fn netGasUsage(s: GasCostSummary) Panic!i64 {
        const used = std.math.add(u64, s.computation_cost, s.storage_cost) catch return error.ArithmeticPanic;
        const a: i64 = @bitCast(used);
        const b: i64 = @bitCast(s.storage_rebate);
        return std.math.sub(i64, a, b) catch error.ArithmeticPanic;
    }

    pub fn encode(s: GasCostSummary, out: *[32]u8) void {
        std.mem.writeInt(u64, out[0..8], s.computation_cost, .little);
        std.mem.writeInt(u64, out[8..16], s.storage_cost, .little);
        std.mem.writeInt(u64, out[16..24], s.storage_rebate, .little);
        std.mem.writeInt(u64, out[24..32], s.non_refundable_storage_fee, .little);
    }
};

const Rounding = union(enum) { bucketize: [8]protocol.gas.ComputationBucket, stepped: u64, keep_half_digits };

/// SuiGasStatus: V3 for gas model >= 15, V2 before (gas.rs dispatch).
pub const SuiGasStatus = struct {
    move: MoveGasStatus,
    v3: bool,
    gas_budget: u64,
    charge: bool,
    /// V3: effective (possibly capped) price; V2: the user price.
    effective_gas_price: u64,
    user_gas_price: u64,
    reference_gas_price: u64,
    rebate_rate: u64,
    storage: StorageGas,
    // cost table
    min_transaction_cost: u64,
    max_gas_budget: u64,
    package_publish_per_byte_cost: u64,
    object_read_per_byte_cost: u64,
    package_read_per_kb_cost: ?u64,
    max_gas_price_rgp_factor_for_aborted_transactions: ?u64,
    // V3
    force_computation_cost_to_budget: bool = false,
    // V2
    computation_cost: u64 = 0,
    rounding: Rounding,

    pub fn initWithBudget(cfg: *const protocol.ProtocolConfig, gas_budget: u64, gas_price: u64, reference_gas_price: u64) !SuiGasStatus {
        const gm = try cfg.get("gas_model_version");
        const v3 = protocol.gas.bumpOnlyEnabled(gm);
        const max_bucket = try cfg.get("max_gas_computation_bucket");
        // v3: checked_mul().expect; v2: checked arithmetic. Both panic.
        const max_computation_budget = std.math.mul(u64, max_bucket, gas_price) catch return error.ArithmeticPanic;
        const computation_budget = @min(gas_budget, max_computation_budget);
        const base = try cfg.get("base_tx_cost_fixed");
        const min_tx = if (v3 or txnBaseCostAsMultiplier(cfg))
            std.math.mul(u64, base, gas_price) catch return error.ArithmeticPanic
        else
            base;
        const table = protocol.gas.costTableForVersion(gm);
        const rounding: Rounding = if (cfg.feature_flags.gas_rounding_halve_digits)
            .keep_half_digits
        else if (cfg.getOpt("gas_rounding_step")) |step|
            // gas_v2.rs SuiGasStatus::new: `GasRoundingMode::Stepped(val.max(1))`.
            .{ .stepped = @max(step, 1) }
        else
            .{ .bucketize = protocol.gas.computationBucket(max_bucket) };
        return .{
            .move = MoveGasStatus.init(table, computation_budget, gas_price, gm),
            .v3 = v3,
            .gas_budget = gas_budget,
            .charge = true,
            .effective_gas_price = gas_price,
            .user_gas_price = gas_price,
            .reference_gas_price = reference_gas_price,
            .rebate_rate = try cfg.get("storage_rebate_rate"),
            .storage = .{ .storage_gas_price = try cfg.get("storage_gas_price"), .storage_per_byte_cost = try cfg.get("obj_data_cost_refundable") },
            .min_transaction_cost = min_tx,
            .max_gas_budget = try cfg.get("max_tx_gas"),
            .package_publish_per_byte_cost = try cfg.get("package_publish_cost_per_byte"),
            .object_read_per_byte_cost = try cfg.get("obj_access_cost_read_per_byte"),
            .package_read_per_kb_cost = if (v3) cfg.getOpt("obj_access_cost_read_per_package_kb") else null,
            .max_gas_price_rgp_factor_for_aborted_transactions = cfg.getOpt("max_gas_price_rgp_factor_for_aborted_transactions"),
            .rounding = rounding,
        };
    }

    pub fn initUnmetered(cfg: *const protocol.ProtocolConfig) !SuiGasStatus {
        const gm = try cfg.get("gas_model_version");
        return .{
            .move = MoveGasStatus.initUnmetered(),
            .v3 = protocol.gas.bumpOnlyEnabled(gm),
            .gas_budget = 0,
            .charge = false,
            .effective_gas_price = 0,
            .user_gas_price = 0,
            .reference_gas_price = 0,
            .rebate_rate = 0,
            .storage = .{ .storage_gas_price = 0, .storage_per_byte_cost = 0 },
            .min_transaction_cost = 0,
            .max_gas_budget = std.math.maxInt(u64),
            .package_publish_per_byte_cost = 0,
            .object_read_per_byte_cost = 0,
            .package_read_per_kb_cost = null,
            .max_gas_price_rgp_factor_for_aborted_transactions = null,
            .rounding = .{ .bucketize = protocol.gas.computationBucket(5_000_000) },
        };
    }

    fn txnBaseCostAsMultiplier(cfg: *const protocol.ProtocolConfig) bool {
        return cfg.feature_flags.txn_base_cost_as_multiplier;
    }

    pub fn isUnmetered(s: *const SuiGasStatus) bool {
        return !s.charge;
    }

    pub fn storageGasUnits(s: *const SuiGasStatus) u64 {
        return s.storage.total_storage_cost;
    }

    pub fn storageRebate(s: *const SuiGasStatus) u64 {
        return s.storage.total_storage_rebate;
    }

    pub fn gasUsed(s: *const SuiGasStatus) u64 {
        return s.move.gasUsedPreGasPrice();
    }

    fn uncappedComputationCost(s: *const SuiGasStatus) u64 {
        if (s.force_computation_cost_to_budget) return s.gas_budget;
        return protocol.gas.halfDigitsRounding(s.move.gasUsedPreGasPrice()) *| s.effective_gas_price;
    }

    fn derivedComputationCost(s: *const SuiGasStatus) u64 {
        const uncapped = s.uncappedComputationCost();
        const sender = senderRebate(s.storageRebate(), s.rebate_rate);
        const net_storage = s.storageGasUnits() -| sender;
        return @min(uncapped, s.gas_budget -| net_storage);
    }

    /// bucketize_computation(Some(aborted)).
    pub fn bucketizeComputation(s: *SuiGasStatus, aborted: bool) Panic!?GasError {
        if (s.v3) {
            s.effective_gas_price = if (s.max_gas_price_rgp_factor_for_aborted_transactions) |f| blk: {
                if (!aborted) break :blk s.user_gas_price;
                const cap = std.math.mul(u64, f, s.reference_gas_price) catch return .InvariantViolation;
                break :blk @min(s.user_gas_price, cap);
            } else s.user_gas_price;
            if (s.uncappedComputationCost() >= s.gas_budget) return .InsufficientGas;
            return null;
        }
        // gas_v2.rs is under with_checked_arithmetic: every overflow below panics.
        const used = s.move.gasUsedPreGasPrice();
        const price = if (s.max_gas_price_rgp_factor_for_aborted_transactions) |f|
            (if (aborted) @min(s.user_gas_price, try pmul(f, s.reference_gas_price)) else s.user_gas_price)
        else
            s.user_gas_price;
        const cost = switch (s.rounding) {
            .keep_half_digits => try pmul(protocol.gas.halfDigitsRounding(used), price),
            .stepped => |step| if (used > 0 and used % step == 0)
                try pmul(used, price)
            else
                try pmul(try pmul(try padd(used / step, 1), step), price),
            .bucketize => |*table| try pmul(protocol.gas.bucketCost(table, used), price),
        };
        if (s.gas_budget <= cost) {
            s.computation_cost = s.gas_budget;
            return .InsufficientGas;
        }
        s.computation_cost = cost;
        return null;
    }

    pub fn summary(s: *const SuiGasStatus) GasCostSummary {
        const rebate = s.storageRebate();
        const sender = senderRebate(rebate, s.rebate_rate);
        std.debug.assert(sender <= rebate);
        return .{
            .computation_cost = if (s.v3) s.derivedComputationCost() else s.computation_cost,
            .storage_cost = s.storageGasUnits(),
            .storage_rebate = sender,
            .non_refundable_storage_fee = rebate - sender,
        };
    }

    pub fn resetStorageCostAndRebate(s: *SuiGasStatus) void {
        s.storage.reset();
    }

    pub fn chargeStorageRead(s: *SuiGasStatus, size: u64) ?GasError {
        s.move.chargeBytes(size, s.object_read_per_byte_cost) catch return .InsufficientGas;
        return null;
    }

    /// V3 charges package inputs per KiB when configured; V2 (and V3 without it) per byte.
    pub fn chargePackageObjectRead(s: *SuiGasStatus, size: u64) ?GasError {
        if (s.v3) if (s.package_read_per_kb_cost) |kb| {
            s.move.deductGas(packageReadInternalGas(size, kb)) catch return .InsufficientGas;
            return null;
        };
        return s.chargeStorageRead(size);
    }

    pub fn chargePublishPackage(s: *SuiGasStatus, size: u64) ?GasError {
        s.move.chargeBytes(size, s.package_publish_per_byte_cost) catch return .InsufficientGas;
        return null;
    }

    pub fn trackStorageMutation(s: *SuiGasStatus, arena: std.mem.Allocator, id: [32]u8, new_size: u64, storage_rebate: u64) !?u64 {
        return s.storage.trackMutation(arena, id, new_size, storage_rebate, s.isUnmetered());
    }

    pub fn chargeStorageAndRebate(s: *SuiGasStatus) Panic!?GasError {
        const rebate = s.storage.total_storage_rebate;
        const cost = s.storage.total_storage_cost;
        const sender = senderRebate(rebate, s.rebate_rate);
        if (s.v3) {
            const net = cost -| sender;
            const left = s.gas_budget -| s.uncappedComputationCost();
            if (net > left) return .InsufficientGas;
            return null;
        }
        if (sender >= cost) return null;
        // Checked in Rust (panics); bucketize caps computation_cost at the budget.
        const left = std.math.sub(u64, s.gas_budget, s.computation_cost) catch return error.ArithmeticPanic;
        if (left < cost - sender) return .InsufficientGas;
        return null;
    }

    pub fn adjustComputationOnOutOfGas(s: *SuiGasStatus) void {
        s.storage.reset();
        if (s.v3) s.force_computation_cost_to_budget = true else s.computation_cost = s.gas_budget;
    }
};

fn pmul(a: u64, b: u64) Panic!u64 {
    return std.math.mul(u64, a, b) catch error.ArithmeticPanic;
}

fn padd(a: u64, b: u64) Panic!u64 {
    return std.math.add(u64, a, b) catch error.ArithmeticPanic;
}

const testing = std.testing;

test "half digits rounding (gas_common.rs test)" {
    const h = protocol.gas.halfDigitsRounding;
    try testing.expectEqual(@as(u64, 1000), h(0));
    try testing.expectEqual(@as(u64, 1000), h(999));
    try testing.expectEqual(@as(u64, 1010), h(1001));
    try testing.expectEqual(@as(u64, 2000), h(1999));
    try testing.expectEqual(@as(u64, 20_100), h(20_001));
    try testing.expectEqual(@as(u64, 30_000), h(29_999));
    try testing.expectEqual(@as(u64, 300_100), h(300_001));
}

test "sender rebate rounds half up" {
    try testing.expectEqual(@as(u64, 99), senderRebate(100, 9900));
    try testing.expectEqual(@as(u64, 1), senderRebate(1, 9900));
    try testing.expectEqual(@as(u64, 0), senderRebate(0, 9900));
    try testing.expectEqual(@as(u64, 1485), senderRebate(1500, 9900));
}

test "move gas status charge and tiers" {
    var s = MoveGasStatus.init(protocol.gas.costTableForVersion(15), 1_000_000, 1000, 15);
    try testing.expectEqual(@as(u64, 1000 * 1000), s.gas_left);
    try s.charge(1, 1, 0, 8, 0);
    try testing.expectEqual(@as(u64, 1), s.stack_height_current);
    try s.chargeBytes(100, 15);
    try testing.expectEqual(@as(u64, 1), s.gasUsedPreGasPrice());
}

test "release-build overflow semantics" {
    // tables.rs wraps (no overflow-checks in sui-node's release profile).
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)) *% 1000, MoveGasStatus.toInternalUnits(std.math.maxInt(u64)));
    // gas.rs net_gas_usage: checked add and sub panic, the casts reinterpret.
    try testing.expectError(error.ArithmeticPanic, (GasCostSummary{ .computation_cost = std.math.maxInt(u64), .storage_cost = 1 }).netGasUsage());
    try testing.expectEqual(@as(i64, -5), try (GasCostSummary{ .computation_cost = 10, .storage_cost = 5, .storage_rebate = 20 }).netGasUsage());
    try testing.expectEqual(@as(i64, -1), try (GasCostSummary{ .computation_cost = std.math.maxInt(u64) - 1, .storage_cost = 1 }).netGasUsage());
}
