//! Gas schedule tables of sui-types `gas_model` (tables.rs, gas_predicates.rs, gas_v2.rs bucket table,
//! gas_common.rs rounding). Values are copied from Rust and proven against it for every table and
//! every gas model version by suite `gas-tables`.
const std = @import("std");

pub const Tier = struct { start: u64, mult: u64 };

pub const CostTable = struct {
    instruction_tiers: []const Tier,
    stack_height_tiers: []const Tier,
    stack_size_tiers: []const Tier,

    pub const tier_default: u64 = 1; // INSTRUCTION/STACK_HEIGHT/STACK_SIZE_TIER_DEFAULT

    /// (multiplier, start of the next tier). Rust `CostTable::get_current_and_future_tier`:
    /// the largest tier start <= current, else the default; the next is the smallest start > current.
    pub fn tierAt(tiers: []const Tier, current: u64) struct { u64, ?u64 } {
        var mult: u64 = tier_default;
        var next: ?u64 = null;
        // tiers are sorted by start (BTreeMap order)
        for (tiers) |tr| {
            if (tr.start <= current) {
                mult = tr.mult;
            } else {
                next = tr.start;
                break;
            }
        }
        return .{ mult, next };
    }

    pub fn instructionTier(self: *const CostTable, instr_count: u64) struct { u64, ?u64 } {
        return tierAt(self.instruction_tiers, instr_count);
    }
    pub fn stackHeightTier(self: *const CostTable, h: u64) struct { u64, ?u64 } {
        return tierAt(self.stack_height_tiers, h);
    }
    pub fn stackSizeTier(self: *const CostTable, s: u64) struct { u64, ?u64 } {
        return tierAt(self.stack_size_tiers, s);
    }
};

fn t(comptime pairs: anytype) []const Tier {
    comptime {
        var out: [pairs.len]Tier = undefined;
        for (pairs, 0..) |p, i| out[i] = .{ .start = p[0], .mult = p[1] };
        const final = out;
        return &final;
    }
}

pub const zero_cost_schedule: CostTable = .{
    .instruction_tiers = t(.{.{ 0, 0 }}),
    .stack_size_tiers = t(.{.{ 0, 0 }}),
    .stack_height_tiers = t(.{.{ 0, 0 }}),
};

pub const unit_cost_schedule: CostTable = .{
    .instruction_tiers = t(.{.{ 0, 1 }}),
    .stack_size_tiers = t(.{.{ 0, 1 }}),
    .stack_height_tiers = t(.{.{ 0, 1 }}),
};

pub const initial_cost_schedule_v1: CostTable = .{
    .instruction_tiers = t(.{ .{ 0, 1 }, .{ 3000, 2 }, .{ 6000, 3 }, .{ 8000, 5 }, .{ 9000, 9 }, .{ 9500, 16 }, .{ 10000, 29 }, .{ 10500, 50 } }),
    .stack_height_tiers = t(.{ .{ 0, 1 }, .{ 400, 2 }, .{ 800, 3 }, .{ 1200, 5 }, .{ 1500, 9 }, .{ 1800, 16 }, .{ 2000, 29 }, .{ 2200, 50 } }),
    .stack_size_tiers = t(.{ .{ 0, 1 }, .{ 2000, 2 }, .{ 5000, 3 }, .{ 8000, 5 }, .{ 10000, 9 }, .{ 11000, 16 }, .{ 11500, 50 } }),
};

pub const initial_cost_schedule_v2: CostTable = .{
    .instruction_tiers = t(.{ .{ 0, 1 }, .{ 3000, 2 }, .{ 6000, 3 }, .{ 8000, 5 }, .{ 9000, 9 }, .{ 9500, 16 }, .{ 10000, 29 }, .{ 10500, 50 }, .{ 12000, 150 }, .{ 15000, 250 } }),
    .stack_height_tiers = t(.{ .{ 0, 1 }, .{ 400, 2 }, .{ 800, 3 }, .{ 1200, 5 }, .{ 1500, 9 }, .{ 1800, 16 }, .{ 2000, 29 }, .{ 2200, 50 }, .{ 3000, 150 }, .{ 5000, 250 } }),
    .stack_size_tiers = t(.{ .{ 0, 1 }, .{ 2000, 2 }, .{ 5000, 3 }, .{ 8000, 5 }, .{ 10000, 9 }, .{ 11000, 16 }, .{ 11500, 50 }, .{ 15000, 150 }, .{ 20000, 250 } }),
};

pub const initial_cost_schedule_v3: CostTable = .{
    .instruction_tiers = t(.{ .{ 0, 1 }, .{ 3000, 2 }, .{ 6000, 3 }, .{ 8000, 5 }, .{ 9000, 9 }, .{ 9500, 16 }, .{ 10000, 29 }, .{ 10500, 50 }, .{ 15000, 100 } }),
    .stack_height_tiers = t(.{ .{ 0, 1 }, .{ 400, 2 }, .{ 800, 3 }, .{ 1200, 5 }, .{ 1500, 9 }, .{ 1800, 16 }, .{ 2000, 29 }, .{ 2200, 50 }, .{ 5000, 100 } }),
    .stack_size_tiers = t(.{ .{ 0, 1 }, .{ 2000, 2 }, .{ 5000, 3 }, .{ 8000, 5 }, .{ 10000, 9 }, .{ 11000, 16 }, .{ 11500, 50 }, .{ 20000, 100 } }),
};

pub const initial_cost_schedule_v4: CostTable = .{
    .instruction_tiers = t(.{ .{ 0, 1 }, .{ 20_000, 2 }, .{ 50_000, 10 }, .{ 100_000, 50 }, .{ 200_000, 100 } }),
    .stack_height_tiers = t(.{ .{ 0, 1 }, .{ 1_000, 2 }, .{ 10_000, 10 } }),
    .stack_size_tiers = t(.{ .{ 0, 1 }, .{ 100_000, 2 }, .{ 500_000, 5 }, .{ 1_000_000, 100 } }),
};

pub const initial_cost_schedule_v5: CostTable = .{
    .instruction_tiers = t(.{ .{ 0, 1 }, .{ 20_000, 2 }, .{ 50_000, 10 }, .{ 100_000, 50 }, .{ 200_000, 100 }, .{ 10_000_000, 1000 } }),
    .stack_height_tiers = t(.{ .{ 0, 1 }, .{ 1_000, 2 }, .{ 10_000, 10 } }),
    .stack_size_tiers = t(.{ .{ 0, 1 }, .{ 100_000, 2 }, .{ 500_000, 5 }, .{ 1_000_000, 100 }, .{ 100_000_000, 1000 } }),
};

/// gas_predicates.rs `cost_table_for_version`.
pub fn costTableForVersion(gas_model: u64) *const CostTable {
    if (gas_model <= 3) return &initial_cost_schedule_v1;
    if (gas_model == 4) return &initial_cost_schedule_v2;
    if (gas_model == 5) return &initial_cost_schedule_v3;
    if (gas_model <= 7) return &initial_cost_schedule_v4;
    return &initial_cost_schedule_v5;
}

// ---- gas_predicates.rs (all keyed on gas_model_version) ----

pub fn dontChargeBudgetOnStorageOog(gm: u64) bool {
    return gm >= 4;
}
pub fn checkForGasPriceTooHigh(gm: u64) bool {
    return gm >= 4;
}
pub fn chargeInputAsMemory(gm: u64) bool {
    return gm == 4;
}
pub fn useLegacyAbstractSize(gm: u64) bool {
    return gm <= 7;
}
pub fn chargeUpgrades(gm: u64) bool {
    return gm >= 7;
}
pub fn legacyChargeNativePopsArgs(gm: u64) bool {
    return gm <= 13;
}
pub fn refreshGasPaymentLocation(gm: u64) bool {
    return gm >= 13;
}
pub fn bumpOnlyEnabled(gm: u64) bool {
    return gm >= 15;
}
/// Threshold after which native function calls contribute to the virtual instruction count.
pub const v2_native_function_call_threshold: u64 = 700;
pub fn nativeFunctionThresholdExceeded(gm: u64, num_native_calls: u64) bool {
    return gm > 8 and num_native_calls > v2_native_function_call_threshold;
}

// ---- gas_v2.rs computation buckets and gas_common.rs rounding ----

pub const ComputationBucket = struct { min: u64, max: u64, cost: u64 };

/// gas_v2.rs `computation_bucket(max_bucket_cost)`; requires max_bucket_cost >= 5_000_000.
pub fn computationBucket(max_bucket_cost: u64) [8]ComputationBucket {
    std.debug.assert(max_bucket_cost >= 5_000_000);
    const edges = [_]u64{ 0, 1_000, 5_000, 10_000, 20_000, 50_000, 200_000, 1_000_000, max_bucket_cost };
    var out: [8]ComputationBucket = undefined;
    for (0..8) |i| out[i] = .{ .min = edges[i], .max = edges[i + 1], .cost = edges[i + 1] };
    return out;
}

/// gas_v2.rs `get_bucket_cost`.
pub fn bucketCost(table: []const ComputationBucket, computation_cost: u64) u64 {
    for (table) |b| if (b.max >= computation_cost) return b.cost;
    if (table.len == 0) return 5_000_000;
    return table[table.len - 1].cost;
}

/// gas_common.rs `half_digits_rounding`.
pub fn halfDigitsRounding(n: u64) u64 {
    if (n < 1000) return 1000;
    const digits: u32 = std.math.log10_int(n);
    const drop = digits / 2;
    const base = std.math.pow(u64, 10, drop);
    // div_ceil then saturating_mul
    const dc = n / base + @intFromBool(n % base != 0);
    return std.math.mul(u64, dc, base) catch std.math.maxInt(u64);
}

test "half_digits_rounding (gas_common.rs test)" {
    const cases = [_][2]u64{
        .{ 0, 1000 },              .{ 1, 1000 },                .{ 999, 1000 },                .{ 1000, 1000 },
        .{ 1001, 1010 },           .{ 1050, 1050 },             .{ 1999, 2000 },               .{ 20_000, 20_000 },
        .{ 20_001, 20_100 },       .{ 20_500, 20_500 },         .{ 29_999, 30_000 },           .{ 300_000, 300_000 },
        .{ 300_001, 300_100 },     .{ 305_500, 305_500 },       .{ 305_501, 305_600 },         .{ 999_999, 1_000_000 },
        .{ 1_000_000, 1_000_000 }, .{ 1_000_001, 1_001_000 },   .{ 1_005_000, 1_005_000 },     .{ 1_005_001, 1_006_000 },
        .{ 1_999_999, 2_000_000 }, .{ 10_000_001, 10_001_000 }, .{ 100_000_001, 100_010_000 },
    };
    for (cases) |c| try std.testing.expectEqual(c[1], halfDigitsRounding(c[0]));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), halfDigitsRounding(std.math.maxInt(u64)));
}
