//! protocol: ProtocolConfig + FeatureFlags for versions 1..142 on every chain.
//! Owner lane: protocol-config. Interface: CONTRACTS.md. Only the protocol-config lane edits files in src/protocol/.
//!
//! The config of every (version, chain) is built at comptime from the generated per-version
//! deltas (gen_data.zig, derived from Mysten's real configs by src/protocol/gen/gen.zig) and lives
//! in read-only memory: `get` is one array indexing. Each chain has its own 141 entries because
//! `chain` is part of the config value.
const std = @import("std");

pub const types = @import("types.zig");
pub const gen_types = @import("gen_types.zig");
pub const gen_data = @import("gen_data.zig");
pub const yaml = @import("yaml.zig");
pub const gas = @import("gas.zig");
pub const derived = @import("derived.zig");
pub const conformance = @import("conformance.zig");

pub const Chain = types.Chain;
pub const FeatureFlags = gen_types.FeatureFlags;
pub const ProtocolConfig = gen_types.ProtocolConfig;
pub const ConsensusTransactionOrdering = types.ConsensusTransactionOrdering;
pub const ConsensusChoice = types.ConsensusChoice;
pub const ConsensusNetwork = types.ConsensusNetwork;
pub const PerObjectCongestionControlMode = types.PerObjectCongestionControlMode;
pub const ExecutionTimeEstimateParams = types.ExecutionTimeEstimateParams;
pub const AliasedAddress = types.AliasedAddress;
pub const Amendments = types.Amendments;

/// MIN_PROTOCOL_VERSION and MAX_PROTOCOL_VERSION of sui-protocol-config 1.84.0.
pub const min_protocol_version: u64 = 1;
pub const max_protocol_version: u64 = 142;

/// `FeatureFlags` and `ProtocolConfig` fields each Sui release added, keyed by that release's
/// max protocol version. A sui-node of an older release has no such field in any surface (its
/// GetEpoch `feature_flags`/`attributes`/`configs` lack it at every version), so a replay of that
/// node's answers renders as of its release (`fieldRelease`). Add a row per release.
pub const release_fields = [_]struct { max: u64, names: []const []const u8 }{
    // 1.84.0
    .{ .max = 142, .names = &.{ "binary_format_limits_profile", "check_groth16_pvk_length", "clock_borrow_cost_base", "object_is_shared_input_cost_base", "secp256r1_ecrecover_checks_x_below_p" } },
};

/// The max protocol version of the release that added field `name` (0: older than every row).
pub fn fieldRelease(comptime name: []const u8) u64 {
    @setEvalBranchQuota(100_000);
    for (release_fields) |r| for (r.names) |n| if (std.mem.eql(u8, n, name)) return r.max;
    return 0;
}

const n_versions = max_protocol_version - min_protocol_version + 1;

/// Cumulative unknown-chain configs, index v - 1.
const base_table: [n_versions]ProtocolConfig = blk: {
    @setEvalBranchQuota(10_000_000);
    var out: [n_versions]ProtocolConfig = undefined;
    var cur: ProtocolConfig = .{};
    for (0..n_versions) |i| {
        const v = i + 1;
        gen_data.applyBase(&cur, v);
        cur.version = v;
        out[i] = cur;
    }
    break :blk out;
};

/// Every config of one chain: the unknown-chain config of the same version, the chain's overrides
/// (gen_data.applyChain) and `chain` set, as `get_for_version` does (`ret.chain = chain`). The chain
/// is part of the value (execution reads `protocol_config.chain()`), so chains never share entries.
fn chainTable(comptime chain: Chain) [n_versions]ProtocolConfig {
    @setEvalBranchQuota(10_000_000);
    var out: [n_versions]ProtocolConfig = undefined;
    for (0..n_versions) |i| {
        var c = base_table[i];
        gen_data.applyChain(&c, chain, i + 1);
        c.chain = chain;
        out[i] = c;
    }
    return out;
}

const mainnet_table = chainTable(.mainnet);
const testnet_table = chainTable(.testnet);

/// Config in force at `version` on `chain`. Built at comptime; pointers live for the process.
/// Rust: `ProtocolConfig::get_for_version` (which panics outside 1..=141).
pub fn get(version: u64, chain: Chain) error{UnsupportedVersion}!*const ProtocolConfig {
    if (version < min_protocol_version or version > max_protocol_version) return error.UnsupportedVersion;
    const i: usize = @intCast(version - min_protocol_version);
    return switch (chain) {
        .unknown => &base_table[i],
        .mainnet => &mainnet_table[i],
        .testnet => &testnet_table[i],
    };
}

/// insta snapshot body, byte-identical to sui-protocol-config/src/snapshots/*.snap after the header
/// (and to what insta writes: one trailing newline).
pub fn renderSnapshot(cfg: *const ProtocolConfig, w: *std.Io.Writer) !void {
    var e: yaml.Emitter = .{ .w = w };
    try e.root(cfg.*);
    try w.writeAll("\n");
}

test {
    std.testing.refAllDecls(@This());
}

test "release_fields name real fields" {
    inline for (release_fields) |r| {
        try std.testing.expect(r.max <= max_protocol_version);
        for (r.names) |n| {
            var found = false;
            inline for (@typeInfo(FeatureFlags).@"struct".field_names) |f| found = found or std.mem.eql(u8, f, n);
            inline for (@typeInfo(ProtocolConfig).@"struct".field_names) |f| found = found or std.mem.eql(u8, f, n);
            try std.testing.expect(found);
        }
    }
    try std.testing.expectEqual(@as(u64, 142), comptime fieldRelease("clock_borrow_cost_base"));
    try std.testing.expectEqual(@as(u64, 0), comptime fieldRelease("max_move_object_size"));
}

test "range" {
    try std.testing.expectError(error.UnsupportedVersion, get(0, .mainnet));
    try std.testing.expectError(error.UnsupportedVersion, get(143, .mainnet));
    for (1..143) |v| for ([_]Chain{ .unknown, .mainnet, .testnet }) |ch| {
        const c = try get(v, ch);
        try std.testing.expectEqual(@as(u64, v), c.version);
        try std.testing.expectEqual(ch, c.chain);
    };
}

test "values and missing fields" {
    const v1 = try get(1, .unknown);
    try std.testing.expectEqual(@as(u64, 131072), try v1.get("max_tx_size_bytes"));
    try std.testing.expectEqual(@as(?u64, null), v1.getOpt("max_ptb_live_references"));
    try std.testing.expectError(error.ProtocolConfigMissing, v1.get("max_ptb_live_references"));
    const v141 = try get(141, .mainnet);
    try std.testing.expectEqual(@as(u64, 64), try v141.get("max_ptb_live_references"));
    try std.testing.expect(v141.feature_flags.enable_accumulators);
    try std.testing.expect(!v1.feature_flags.package_upgrades);
    try std.testing.expect(v141.feature_flags.per_object_congestion_control_mode == .ExecutionTimeEstimate);
    try std.testing.expectEqual(@as(u64, 50), v141.feature_flags.per_object_congestion_control_mode.ExecutionTimeEstimate.target_utilization);
}

test "mainnet differs from unknown only where Mysten says so" {
    // Amendments exist on mainnet and testnet only, and they differ.
    const m = try get(141, .mainnet);
    const t = try get(141, .testnet);
    const u = try get(141, .unknown);
    try std.testing.expect(m.include_special_package_amendments != null);
    try std.testing.expect(t.include_special_package_amendments != null);
    try std.testing.expect(u.include_special_package_amendments == null);
    try std.testing.expect(m.include_special_package_amendments.?.len != t.include_special_package_amendments.?.len);
}

test "render version 1" {
    var buf: [16384]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try renderSnapshot(try get(1, .unknown), &w);
    try std.testing.expect(std.mem.startsWith(u8, w.buffered(), "version: 1\nfeature_flags: {}\nmax_tx_size_bytes: 131072\nmax_input_objects: 2048\n"));
    try std.testing.expect(std.mem.endsWith(u8, w.buffered(), "\n"));
}

test "derived invariants (Rust asserts) are errors" {
    var c: ProtocolConfig = (try get(1, .unknown)).*;
    c.feature_flags.enable_jwk_consensus_updates = true;
    try std.testing.expectError(error.InvariantViolated, derived.enableJwkConsensusUpdates(&c));
    try std.testing.expectError(error.InvariantViolated, derived.endOfEpochTransactionSupported(&c));
    c.feature_flags.end_of_epoch_transaction_supported = true;
    try std.testing.expect(try derived.enableJwkConsensusUpdates(&c));
    c.feature_flags.consensus_linearize_subdag_v2 = true;
    try std.testing.expectError(error.InvariantViolated, derived.consensusLinearizeSubdagV2(&c));
    c.consensus_gc_depth = 3;
    try std.testing.expect(try derived.consensusLinearizeSubdagV2(&c));
    c.feature_flags.address_aliases = true;
    try std.testing.expectError(error.InvariantViolated, derived.addressAliases(&c));
    c.max_loop_depth = null;
    try std.testing.expectError(error.ProtocolConfigMissing, derived.verifierConfig(&c, null));
}

test "tiers" {
    const t = gas.initial_cost_schedule_v1;
    try std.testing.expectEqual(.{ @as(u64, 1), @as(?u64, 3000) }, t.instructionTier(0));
    try std.testing.expectEqual(.{ @as(u64, 2), @as(?u64, 6000) }, t.instructionTier(3000));
    try std.testing.expectEqual(.{ @as(u64, 50), @as(?u64, null) }, t.instructionTier(1 << 40));
    try std.testing.expectEqual(gas.initial_cost_schedule_v5.instruction_tiers.len, gas.costTableForVersion(8).instruction_tiers.len);
}
