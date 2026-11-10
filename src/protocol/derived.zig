//! The hand-written, derived part of `impl ProtocolConfig` in sui-protocol-config/src/lib.rs:
//! getters with defaults and invariants, `verifier_config` and `binary_config`.
//!
//! Where Rust panics (a config value that does not exist at this version, or a failed `assert!`)
//! these return an error instead (CONTRACTS.md 2.2): `ProtocolConfigMissing` or `InvariantViolated`.
//! Suite `protocol-config-getters` proves every function here against Mysten's for every
//! (version, chain). The macro-generated plain getters (`max_tx_gas()`, `package_upgrades()`, ...)
//! are `cfg.get("name")` / `cfg.feature_flags.name`.
const std = @import("std");
const types = @import("types.zig");
const gen = @import("gen_types.zig");
const Cfg = gen.ProtocolConfig;

pub const Error = error{ ProtocolConfigMissing, InvariantViolated };

fn need(c: *const Cfg, comptime field: []const u8) error{ProtocolConfigMissing}!@typeInfo(@FieldType(Cfg, field)).optional.child {
    return @field(c, field) orelse error.ProtocolConfigMissing;
}

pub fn checkPackageUpgradesSupported(c: *const Cfg) bool {
    return c.feature_flags.package_upgrades;
}

pub fn zkloginSupportedProviders(c: *const Cfg) []const []const u8 {
    return c.feature_flags.zklogin_supported_providers;
}

/// 0 = v1 circuit only, 1 = v2 circuit with fallback to v1, 2 = v2 circuit only.
pub fn zkloginCircuitMode(c: *const Cfg) u64 {
    return c.feature_flags.zklogin_circuit_mode;
}

pub fn consensusTransactionOrdering(c: *const Cfg) types.ConsensusTransactionOrdering {
    return c.feature_flags.consensus_transaction_ordering;
}

pub fn enableJwkConsensusUpdates(c: *const Cfg) Error!bool {
    const ret = c.feature_flags.enable_jwk_consensus_updates;
    if (ret and !c.feature_flags.end_of_epoch_transaction_supported) return error.InvariantViolated;
    return ret;
}

pub fn staggeredSubmissionSignal(c: *const Cfg) Error!bool {
    const ret = c.feature_flags.staggered_submission_signal;
    if (ret and !c.feature_flags.allowed_proposers) return error.InvariantViolated;
    return ret;
}

pub fn endOfEpochTransactionSupported(c: *const Cfg) Error!bool {
    const ret = c.feature_flags.end_of_epoch_transaction_supported;
    if (!ret and c.feature_flags.enable_jwk_consensus_updates) return error.InvariantViolated;
    return ret;
}

pub fn dkgVersion(c: *const Cfg) u64 {
    return c.random_beacon_dkg_version orelse 1;
}

pub fn bridge(c: *const Cfg) Error!bool {
    const ret = c.feature_flags.bridge;
    if (ret and !c.feature_flags.end_of_epoch_transaction_supported) return error.InvariantViolated;
    return ret;
}

pub fn shouldTryToFinalizeBridgeCommittee(c: *const Cfg) Error!bool {
    if (!try bridge(c)) return false;
    return c.bridge_should_try_to_finalize_committee orelse true;
}

pub fn zkloginMaxEpochUpperBoundDelta(c: *const Cfg) ?u64 {
    return c.feature_flags.zklogin_max_epoch_upper_bound_delta;
}

pub fn enableAllowances(c: *const Cfg) bool {
    return c.feature_flags.enable_allowances and c.feature_flags.enable_accumulators;
}

pub fn enableCoinReservationObjRefs(c: *const Cfg) bool {
    return newVmEnabled(c) and c.feature_flags.enable_coin_reservation_obj_refs;
}

pub fn enableAuthenticatedEventStreams(c: *const Cfg) bool {
    return c.feature_flags.enable_authenticated_event_streams and c.feature_flags.enable_accumulators;
}

pub fn perObjectCongestionControlMode(c: *const Cfg) types.PerObjectCongestionControlMode {
    return c.feature_flags.per_object_congestion_control_mode;
}

pub fn consensusChoice(c: *const Cfg) types.ConsensusChoice {
    return c.feature_flags.consensus_choice;
}

pub fn consensusNetwork(c: *const Cfg) types.ConsensusNetwork {
    return c.feature_flags.consensus_network;
}

pub fn mysticetiNumLeadersPerRound(c: *const Cfg) ?usize {
    return c.feature_flags.mysticeti_num_leaders_per_round;
}

pub fn maxTransactionSizeBytes(c: *const Cfg) u64 {
    return c.consensus_max_transaction_size_bytes orelse 256 * 1024;
}

pub fn maxTransactionsInBlockBytes(c: *const Cfg) u64 {
    return c.consensus_max_transactions_in_block_bytes orelse 512 * 1024;
}

pub fn maxNumTransactionsInBlock(c: *const Cfg) u64 {
    return c.consensus_max_num_transactions_in_block orelse 512;
}

pub fn gcDepth(c: *const Cfg) u32 {
    return c.consensus_gc_depth orelse 0;
}

pub fn consensusLinearizeSubdagV2(c: *const Cfg) Error!bool {
    const res = c.feature_flags.consensus_linearize_subdag_v2;
    if (res and gcDepth(c) == 0) return error.InvariantViolated;
    return res;
}

pub fn consensusMedianBasedCommitTimestamp(c: *const Cfg) Error!bool {
    const res = c.feature_flags.consensus_median_based_commit_timestamp;
    if (res and gcDepth(c) == 0) return error.InvariantViolated;
    return res;
}

pub fn consensusCommitRateEstimationWindowSize(c: *const Cfg) u32 {
    return c.consensus_commit_rate_estimation_window_size orelse 0;
}

pub fn consensusNumRequestedPriorCommitsAtStartup(c: *const Cfg) Error!u32 {
    const window = consensusCommitRateEstimationWindowSize(c);
    if (window != 0 and !c.feature_flags.record_additional_state_digest_in_prologue) return error.InvariantViolated;
    return window;
}

pub fn addressAliases(c: *const Cfg) Error!bool {
    const a = c.feature_flags.address_aliases;
    if (a and !c.feature_flags.mysticeti_fastpath) return error.InvariantViolated;
    if (a and !c.feature_flags.disable_preconsensus_locking) return error.InvariantViolated;
    return a;
}

pub fn newVmEnabled(c: *const Cfg) bool {
    return if (c.execution_version) |v| v >= 4 else false;
}

pub fn gaslessAllowedTokenTypes(c: *const Cfg) []const types.GaslessToken {
    return c.gasless_allowed_token_types orelse &.{};
}

pub fn gaslessMaxUnusedInputs(c: *const Cfg) u64 {
    return c.gasless_max_unused_inputs orelse std.math.maxInt(u64);
}

pub fn gaslessMaxPureInputBytes(c: *const Cfg) u64 {
    return c.gasless_max_pure_input_bytes orelse std.math.maxInt(u64);
}

pub fn gaslessMaxTxSizeBytes(c: *const Cfg) u64 {
    return c.gasless_max_tx_size_bytes orelse std.math.maxInt(u64);
}

// ---- move-vm-config VerifierConfig, filled as ProtocolConfig::verifier_config does ----

pub const VerifierConfig = struct {
    max_loop_depth: ?usize,
    max_function_parameters: ?usize,
    max_generic_instantiation_length: ?usize,
    max_basic_blocks: ?usize,
    max_value_stack_size: usize,
    max_type_nodes: ?usize,
    max_push_size: ?usize,
    max_dependency_depth: ?usize,
    max_data_definitions: ?usize,
    max_fields_in_struct: ?usize,
    max_function_definitions: ?usize,
    max_constant_vector_len: ?u64,
    max_back_edges_per_function: ?usize,
    max_back_edges_per_module: ?usize,
    max_basic_blocks_in_script: ?usize,
    max_identifier_len: ?u64,
    disallow_self_identifier: bool,
    allow_receiving_object_id: bool,
    reject_mutable_random_on_entry_functions: bool,
    bytecode_version: u32,
    max_variants_in_enum: ?u64,
    additional_borrow_checks: bool,
    better_loader_errors: bool,
    private_generics_verifier_v2: bool,
    sanity_check_with_regex_reference_safety: ?u128,
    deprecate_global_storage_ops: bool,
    disable_entry_point_signature_check: bool,
    switch_to_regex_reference_safety: bool,
    framework_tx_context_mut_restrictions: bool,
    disallow_jump_orphans: bool,
    max_generic_instantiation_type_nodes_per_function: ?usize,
    max_generic_instantiation_type_nodes_per_module: ?usize,
    include_function_signatures_in_instantiation_limits: bool,
    disable_id_leak_verifier: bool,
};

pub const SigningLimits = struct { max_back_edges_per_function: usize, max_back_edges_per_module: usize, sanity_check_with_regex_reference_safety: usize };

/// Rust `verifier_config(signing_limits)`.
pub fn verifierConfig(c: *const Cfg, signing_limits: ?SigningLimits) error{ProtocolConfigMissing}!VerifierConfig {
    const f = &c.feature_flags;
    const signing = signing_limits != null;
    return .{
        .max_loop_depth = try need(c, "max_loop_depth"),
        .max_generic_instantiation_length = try need(c, "max_generic_instantiation_length"),
        .max_function_parameters = try need(c, "max_function_parameters"),
        .max_basic_blocks = try need(c, "max_basic_blocks"),
        .max_value_stack_size = try need(c, "max_value_stack_size"),
        .max_type_nodes = try need(c, "max_type_nodes"),
        .max_generic_instantiation_type_nodes_per_function = c.max_generic_instantiation_type_nodes_per_function,
        .max_generic_instantiation_type_nodes_per_module = c.max_generic_instantiation_type_nodes_per_module,
        .include_function_signatures_in_instantiation_limits = f.include_function_signatures_in_instantiation_limits,
        .max_push_size = try need(c, "max_push_size"),
        .max_dependency_depth = try need(c, "max_dependency_depth"),
        .max_fields_in_struct = try need(c, "max_fields_in_struct"),
        .max_function_definitions = try need(c, "max_function_definitions"),
        .max_data_definitions = try need(c, "max_struct_definitions"),
        .max_constant_vector_len = try need(c, "max_move_vector_len"),
        .max_back_edges_per_function = if (signing_limits) |s| s.max_back_edges_per_function else null,
        .max_back_edges_per_module = if (signing_limits) |s| s.max_back_edges_per_module else null,
        .max_basic_blocks_in_script = null,
        .max_identifier_len = c.max_move_identifier_len,
        .disallow_self_identifier = f.disallow_self_identifier,
        .allow_receiving_object_id = f.allow_receiving_object_id,
        .reject_mutable_random_on_entry_functions = f.reject_mutable_random_on_entry_functions,
        .bytecode_version = try need(c, "move_binary_format_version"),
        .max_variants_in_enum = c.max_move_enum_variants,
        .additional_borrow_checks = signing or f.additional_borrow_checks,
        .better_loader_errors = f.better_loader_errors,
        .private_generics_verifier_v2 = f.private_generics_verifier_v2,
        .sanity_check_with_regex_reference_safety = if (signing_limits) |s| s.sanity_check_with_regex_reference_safety else null,
        .deprecate_global_storage_ops = signing or f.deprecate_global_storage_ops,
        .disable_entry_point_signature_check = f.disable_entry_point_signature_check,
        .switch_to_regex_reference_safety = false,
        .framework_tx_context_mut_restrictions = f.framework_tx_context_mut_restrictions,
        .disallow_jump_orphans = f.disallow_jump_orphans,
        .disable_id_leak_verifier = f.disable_id_leak_verifier,
    };
}

// ---- move-binary-format BinaryConfig, filled as ProtocolConfig::binary_config does ----

pub const TableConfig = struct {
    module_handles: u16,
    datatype_handles: u16,
    function_handles: u16,
    function_instantiations: u16,
    signatures: u16,
    constant_pool: u16,
    identifiers: u16,
    address_identifiers: u16,
    struct_defs: u16,
    struct_def_instantiations: u16,
    function_defs: u16,
    field_handles: u16,
    field_instantiations: u16,
    friend_decls: u16,
    enum_defs: u16,
    enum_def_instantiations: u16,
    variant_handles: u16,
    variant_instantiation_handles: u16,
};

pub const BinaryConfig = struct {
    max_binary_format_version: u32,
    min_binary_format_version: u32,
    check_no_extraneous_bytes: bool,
    deprecate_global_storage_ops: bool,
    table_config: TableConfig,
    allow_unpublishable: bool = false,
    /// `binary_format_limits()`: the profile's `type_parameter_index_max` (the only limit LEGACY
    /// and V1 differ in).
    type_parameter_index_max: u64,
};

/// Rust `binary_config(override_deprecate_global_storage_ops_during_deserialization)`.
pub fn binaryConfig(c: *const Cfg, override_deprecate_global_storage_ops: ?bool) error{ProtocolConfigMissing}!BinaryConfig {
    const max: u16 = std.math.maxInt(u16);
    return .{
        .max_binary_format_version = try need(c, "move_binary_format_version"),
        .min_binary_format_version = c.min_move_binary_format_version orelse 1, // VERSION_1
        .check_no_extraneous_bytes = c.feature_flags.no_extraneous_module_bytes,
        .deprecate_global_storage_ops = override_deprecate_global_storage_ops orelse c.feature_flags.deprecate_global_storage_ops,
        .type_parameter_index_max = switch (c.binary_format_limits_profile orelse .LEGACY) {
            .LEGACY => 65536,
            .V1 => 65535,
        },
        .table_config = .{
            .module_handles = c.binary_module_handles orelse max,
            .datatype_handles = c.binary_struct_handles orelse max,
            .function_handles = c.binary_function_handles orelse max,
            .function_instantiations = c.binary_function_instantiations orelse max,
            .signatures = c.binary_signatures orelse max,
            .constant_pool = c.binary_constant_pool orelse max,
            .identifiers = c.binary_identifiers orelse max,
            .address_identifiers = c.binary_address_identifiers orelse max,
            .struct_defs = c.binary_struct_defs orelse max,
            .struct_def_instantiations = c.binary_struct_def_instantiations orelse max,
            .function_defs = c.binary_function_defs orelse max,
            .field_handles = c.binary_field_handles orelse max,
            .field_instantiations = c.binary_field_instantiations orelse max,
            .friend_decls = c.binary_friend_decls orelse max,
            .enum_defs = c.binary_enum_defs orelse max,
            .enum_def_instantiations = c.binary_enum_def_instantiations orelse max,
            .variant_handles = c.binary_variant_handles orelse max,
            .variant_instantiation_handles = c.binary_variant_instantiation_handles orelse max,
        },
    };
}

// ---- macro-generated lookups and the limit helper of sui-protocol-config ----

/// Byte offset of every `bool` field of `FeatureFlags`, by name. Rust `FeatureFlags::lookup_attr`
/// (from `ProtocolConfigFeatureFlagsGetters`) has one arm per `bool` field; other field types
/// (`u64`, enums, sets, options) have no arm.
const feature_offsets = blk: {
    @setEvalBranchQuota(100_000);
    const info = @typeInfo(gen.FeatureFlags).@"struct";
    var n: usize = 0;
    for (info.field_types) |FT| {
        if (FT == bool) n += 1;
    }
    var kvs: [n]struct { []const u8, usize } = undefined;
    var k: usize = 0;
    for (info.field_names, info.field_types) |name, FT| {
        if (FT != bool) continue;
        kvs[k] = .{ name, @offsetOf(gen.FeatureFlags, name) };
        k += 1;
    }
    break :blk std.StaticStringMap(usize).initComptime(kvs);
};

/// Number of feature flags `lookupFeature` knows (Rust `feature_map().len()`).
pub const feature_count: usize = feature_offsets.kvs.len;

/// Rust `ProtocolConfig::lookup_feature(name)`: the flag's value, or null when `name` is not a
/// `bool` feature flag. The Move native `protocol_config::is_feature_enabled` maps null to false.
pub fn lookupFeature(c: *const Cfg, name: []const u8) ?bool {
    const off = feature_offsets.get(name) orelse return null;
    const base: [*]const u8 = @ptrCast(&c.feature_flags);
    return @as(*const bool, @ptrCast(base + off)).*;
}

/// Rust `LimitThresholdCrossed`: which limit got crossed, with the value and the limit.
pub const LimitThresholdCrossed = union(enum) {
    None,
    Soft: struct { u128, u128 },
    Hard: struct { u128, u128 },
};

/// Rust `check_limit_in_range(x, soft_limit, hard_limit)`. `check_limit!` casts `x` to u64 first
/// (`$x as u64`, truncating); callers mirroring it pass `@as(u64, @truncate(x))`.
/// The comparison order matters: soft == hard gives `Hard`.
pub fn checkLimitInRange(x: u128, soft_limit: u128, hard_limit: u128) LimitThresholdCrossed {
    std.debug.assert(soft_limit <= hard_limit);
    if (x >= hard_limit) return .{ .Hard = .{ x, hard_limit } };
    if (x < soft_limit) return .None;
    return .{ .Soft = .{ x, soft_limit } };
}

test "lookupFeature covers exactly the bool flags" {
    var c: Cfg = .{};
    try std.testing.expectEqual(@as(?bool, false), lookupFeature(&c, "package_upgrades"));
    c.feature_flags.package_upgrades = true;
    try std.testing.expectEqual(@as(?bool, true), lookupFeature(&c, "package_upgrades"));
    try std.testing.expectEqual(@as(?bool, null), lookupFeature(&c, "zklogin_circuit_mode"));
    try std.testing.expectEqual(@as(?bool, null), lookupFeature(&c, "consensus_choice"));
    try std.testing.expectEqual(@as(?bool, null), lookupFeature(&c, "max_tx_size_bytes"));
    try std.testing.expectEqual(@as(?bool, null), lookupFeature(&c, ""));
    // Every bool field round-trips through the offset table.
    inline for (@typeInfo(gen.FeatureFlags).@"struct".field_names, @typeInfo(gen.FeatureFlags).@"struct".field_types) |n, FT| {
        if (FT == bool) {
            var d: Cfg = .{};
            @field(d.feature_flags, n) = true;
            try std.testing.expectEqual(@as(?bool, true), lookupFeature(&d, n));
        }
    }
}

test "check_limit (lib.rs limit_range_fn_test)" {
    const low: u128 = 100;
    const high: u128 = 10000;
    try std.testing.expectEqual(LimitThresholdCrossed.None, checkLimitInRange(1, low, high));
    try std.testing.expectEqual(LimitThresholdCrossed{ .Soft = .{ 255, 100 } }, checkLimitInRange(255, low, high));
    try std.testing.expectEqual(LimitThresholdCrossed{ .Hard = .{ 2550000, 10000 } }, checkLimitInRange(2550000, low, high));
    try std.testing.expectEqual(LimitThresholdCrossed{ .Hard = .{ 2550000, 10000 } }, checkLimitInRange(2550000, high, high));
    try std.testing.expectEqual(LimitThresholdCrossed.None, checkLimitInRange(1, high, high));
    try std.testing.expectEqual(LimitThresholdCrossed.None, checkLimitInRange(255, high, high));
    try std.testing.expectEqual(LimitThresholdCrossed{ .Hard = .{ 10000, 10000 } }, checkLimitInRange(10000, high, high));
}
