//! Hand-written value types of sui-protocol-config (lib.rs) that the generated ProtocolConfig
//! and FeatureFlags structs use. Variant order and names mirror the Rust enums.
const std = @import("std");

pub const Chain = enum { mainnet, testnet, unknown };

/// Ordering mechanism for transactions in one consensus output.
pub const ConsensusTransactionOrdering = enum { None, ByGasPrice };
pub const ConsensusChoice = enum { Narwhal, SwapEachEpoch, Mysticeti };
pub const ConsensusNetwork = enum { Anemo, Tonic };
/// move-binary-format `BinaryFormatLimitsProfile` (1.84): LEGACY reads type parameter indices up
/// to 65536 (then fails the u16 conversion), V1 up to 65535.
pub const BinaryFormatLimitsProfile = enum { LEGACY, V1 };

/// `ExecutionTimeEstimateParams`. Fields in `yaml_skip` are omitted from the snapshot when equal to
/// their default (`skip_serializing_if` in Rust).
pub const ExecutionTimeEstimateParams = struct {
    target_utilization: u64 = 0,
    allowed_txn_cost_overage_burst_limit_us: u64 = 0,
    randomness_scalar: u64 = 0,
    max_estimate_us: u64 = 0,
    stored_observations_num_included_checkpoints: u64 = 0,
    stored_observations_limit: u64 = 0,
    stake_weighted_median_threshold: u64 = 0,
    default_none_duration_for_new_keys: bool = false,
    observations_chunk_size: ?u64 = null,

    pub const yaml_skip = [_][]const u8{ "stake_weighted_median_threshold", "default_none_duration_for_new_keys", "observations_chunk_size" };
};

pub const PerObjectCongestionControlMode = union(enum) {
    None,
    TotalGasBudget,
    TotalTxCount,
    TotalGasBudgetWithCap,
    ExecutionTimeEstimate: ExecutionTimeEstimateParams,
};

pub const AliasedAddress = struct {
    original: [32]u8,
    aliased: [32]u8,
    allowed_tx_digests: []const [32]u8,
};

/// `(String, u64)`: a type tag and its allowed amount.
pub const GaslessToken = struct { []const u8, u64 };

pub const AddrPair = struct { k: [32]u8, v: [32]u8 };
pub const AddrMapEntry = struct { k: [32]u8, v: []const AddrPair };
/// `BTreeMap<AccountAddress, BTreeMap<AccountAddress, AccountAddress>>`, sorted by key bytes.
pub const Amendments = []const AddrMapEntry;

/// Decode a 64-digit hex literal at comptime.
pub fn h32(comptime s: []const u8) [32]u8 {
    comptime {
        @setEvalBranchQuota(100_000_000);
        if (s.len != 64) @compileError("h32 needs 64 hex digits");
        var out: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch @compileError("h32: bad hex");
        return out;
    }
}
