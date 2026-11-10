//! End-of-epoch transaction construction at mainnet-v1.83.1: `AuthorityState::create_and_execute_advance_epoch_tx`
//! up to (not including) execution. The system transaction is an `EndOfEpochTransaction` of the kinds
//! below, in Rust's order, ending with `ChangeEpoch` (or a bare `ChangeEpoch` transaction when the
//! protocol config lacks `end_of_epoch_transaction_supported`).
//!
//!   AuthenticatorStateExpire | AuthenticatorStateCreate   (enable_jwk_consensus_updates)
//!   RandomnessStateCreate                                   (random_beacon, not yet created)
//!   BridgeStateCreate, BridgeCommitteeInit                  (bridge)
//!   DenyListStateCreate                                     (enable_coin_deny_list)
//!   StoreExecutionTimeObservations                          (ExecutionTimeEstimate congestion mode)
//!   AccumulatorRootCreate                                   (create_root_accumulator_object)
//!   CoinRegistryCreate, DisplayRegistryCreate               (enable_coin_registry, enable_display_registry)
//!   AddressAliasStateCreate                                 (address_aliases)
//!   ForwardingAddressRegistryCreate                         (create_forwarding_address_registry)
//!   WriteAccumulatorStorageCost                             (accumulators and the root exists)
//!   ChangeEpoch                                             (always last)
//!
//! What the full node cannot know is passed in `Facts` (which system objects exist: the epoch store's
//! `*_exists()` answers from the epoch start config and the object store) and `Inputs` (gas totals of
//! the epoch from the checkpoint builder, the chosen next protocol version and its system packages).
//! The transaction itself is a system transaction: sender 0x0, gas price 1, budget 0, one gas payment
//! (0x0, 0, MIN digest), signed with 97 zero bytes (`VerifiedTransaction::new_system_transaction`).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const reconfig = @import("reconfig.zig");

pub const Error = error{ SystemPackagesMissing, MissingExecutionTimeObservations, OutOfMemory, Encode };

/// Existence of the system objects the end-of-epoch kinds create, and the initial shared versions
/// of those that are used. All from the node's store and the epoch start config.
pub const Facts = struct {
    authenticator_state_exists: bool = false,
    authenticator_obj_initial_shared_version: ?u64 = null,
    randomness_state_exists: bool = false,
    bridge_exists: bool = false,
    bridge_committee_initiated: bool = false,
    bridge_obj_initial_shared_version: ?u64 = null,
    coin_deny_list_state_exists: bool = false,
    accumulator_root_exists: bool = false,
    coin_registry_exists: bool = false,
    display_registry_exists: bool = false,
    address_alias_state_exists: bool = false,
    forwarding_address_registry_exists: bool = false,
    /// `accumulator_metadata::get_accumulator_object_count`; null when unknown or the metadata is absent.
    accumulator_object_count: ?u64 = null,
    /// Chain identifier (genesis checkpoint digest) for BridgeStateCreate.
    chain_identifier: [32]u8 = @splat(0),
    /// StoreExecutionTimeObservations payload computed by the authority lane
    /// (`filter_and_sort_v1` over the end-of-epoch estimator state); required in ExecutionTimeEstimate mode.
    execution_time_observations: ?types.StoredExecutionTimeObservations = null,
};

/// GasCostSummary of the epoch (sum over its checkpoints).
pub const GasTotals = struct {
    computation_cost: u64,
    storage_cost: u64,
    storage_rebate: u64,
    non_refundable_storage_fee: u64,
};

pub const SystemPackage = struct {
    version: u64,
    modules: []const []const u8,
    deps: []const [32]u8,
};

/// `get_system_package_bytes`: the bytes of the upgraded system packages named by the winning
/// capability vote, from this binary's framework snapshot. Null when a package is not available
/// (the builder then reports `SystemPackagesMissing` and the validator waits for the certified
/// checkpoint from peers, as Rust does).
pub const PackageSource = struct {
    ctx: *anyopaque,
    lookup: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, refs: []const reconfig.ObjectRef) ?[]const SystemPackage,
};

pub const Inputs = struct {
    /// Epoch being closed.
    current_epoch: u64,
    epoch_start_timestamp_ms: u64,
    gas: GasTotals,
    chosen: reconfig.Chosen,
};

pub const Built = struct {
    kinds: []const types.EndOfEpochTransactionKind,
    kind: types.TransactionKind,
    /// BCS(TransactionData).
    data_bcs: []const u8,
    /// Transaction digest (`TransactionData::` salted Blake2b of data_bcs).
    digest: [32]u8,
    /// BCS(SenderSignedData) as stored in checkpoints and sent through the executor.
    sender_signed_bcs: []const u8,
};

const SysPkg = @typeInfo(@FieldType(types.ChangeEpoch, "system_packages")).pointer.child;

fn seq(v: u64) types.SequenceNumber {
    return .{ .@"0" = v };
}

/// The ordered kinds before ChangeEpoch (`create_and_execute_advance_epoch_tx`).
pub fn preludeKinds(arena: std.mem.Allocator, cfg: *const protocol.ProtocolConfig, current_epoch: u64, f: Facts) Error![]types.EndOfEpochTransactionKind {
    const ff = &cfg.feature_flags;
    var out: std.ArrayList(types.EndOfEpochTransactionKind) = .empty;
    if (ff.enable_jwk_consensus_updates) {
        if (f.authenticator_state_exists) {
            const next = current_epoch + 1;
            const min_epoch = next -| (cfg.max_age_of_jwk_in_epochs orelse 0);
            const v = f.authenticator_obj_initial_shared_version orelse return error.Encode;
            try out.append(arena, .{ .AuthenticatorStateExpire = .{ .min_epoch = min_epoch, .authenticator_obj_initial_shared_version = seq(v) } });
        } else try out.append(arena, .{ .AuthenticatorStateCreate = {} });
    }
    if (ff.random_beacon and !f.randomness_state_exists) try out.append(arena, .{ .RandomnessStateCreate = {} });
    if (ff.bridge) {
        if (!f.bridge_exists) try out.append(arena, .{ .BridgeStateCreate = .{ .@"0" = .{ .@"0" = .{ .@"0" = f.chain_identifier } } } });
        const finalize = cfg.bridge_should_try_to_finalize_committee orelse true;
        if (finalize and f.bridge_exists and !f.bridge_committee_initiated) {
            const v = f.bridge_obj_initial_shared_version orelse return error.Encode;
            try out.append(arena, .{ .BridgeCommitteeInit = seq(v) });
        }
    }
    if (ff.enable_coin_deny_list and !f.coin_deny_list_state_exists) try out.append(arena, .{ .DenyListStateCreate = {} });
    switch (ff.per_object_congestion_control_mode) {
        // Rust always emits the kind in this mode (the payload may be empty after
        // filter_and_sort_v1): a missing payload would fork the transaction digest.
        .ExecutionTimeEstimate => try out.append(arena, .{ .StoreExecutionTimeObservations = f.execution_time_observations orelse return error.MissingExecutionTimeObservations }),
        else => {},
    }
    if (ff.create_root_accumulator_object and !f.accumulator_root_exists) try out.append(arena, .{ .AccumulatorRootCreate = {} });
    if (ff.enable_coin_registry and !f.coin_registry_exists) try out.append(arena, .{ .CoinRegistryCreate = {} });
    if (ff.enable_display_registry and !f.display_registry_exists) try out.append(arena, .{ .DisplayRegistryCreate = {} });
    if (ff.address_aliases and !f.address_alias_state_exists) try out.append(arena, .{ .AddressAliasStateCreate = {} });
    if (ff.create_forwarding_address_registry and !f.forwarding_address_registry_exists) try out.append(arena, .{ .ForwardingAddressRegistryCreate = {} });
    if (f.accumulator_root_exists and ff.enable_accumulators) {
        if (f.accumulator_object_count) |count| {
            const unit = cfg.accumulator_object_storage_cost orelse 0;
            try out.append(arena, .{ .WriteAccumulatorStorageCost = .{ .storage_cost = count *| unit } });
        }
    }
    return out.items;
}

pub fn build(
    arena: std.mem.Allocator,
    cfg: *const protocol.ProtocolConfig,
    facts: Facts,
    in: Inputs,
    source: ?PackageSource,
) Error!Built {
    // system packages of the winning vote
    var pkgs: []const SysPkg = &.{};
    if (in.chosen.packages.len > 0) {
        const src = source orelse return error.SystemPackagesMissing;
        const found = src.lookup(src.ctx, arena, in.chosen.packages) orelse return error.SystemPackagesMissing;
        const list = try arena.alloc(SysPkg, found.len);
        for (found, list) |p, *o| {
            const deps = try arena.alloc(types.ObjectID, p.deps.len);
            for (p.deps, deps) |d, *od| od.* = .{ .@"0" = .{ .@"0" = d } };
            o.* = .{ seq(p.version), p.modules, deps };
        }
        pkgs = list;
    }
    const change: types.ChangeEpoch = .{
        .epoch = in.current_epoch + 1,
        .protocol_version = .{ .@"0" = in.chosen.protocol_version },
        .storage_charge = in.gas.storage_cost,
        .computation_charge = in.gas.computation_cost,
        .storage_rebate = in.gas.storage_rebate,
        .non_refundable_storage_fee = in.gas.non_refundable_storage_fee,
        .epoch_start_timestamp_ms = in.epoch_start_timestamp_ms,
        .system_packages = pkgs,
    };
    const supported = cfg.feature_flags.end_of_epoch_transaction_supported;
    var kinds: []const types.EndOfEpochTransactionKind = &.{};
    var kind: types.TransactionKind = undefined;
    if (supported) {
        const pre = try preludeKinds(arena, cfg, in.current_epoch, facts);
        const all = try arena.alloc(types.EndOfEpochTransactionKind, pre.len + 1);
        @memcpy(all[0..pre.len], pre);
        all[pre.len] = .{ .ChangeEpoch = change };
        kinds = all;
        kind = .{ .EndOfEpochTransaction = all };
    } else {
        kind = .{ .ChangeEpoch = change };
    }
    return finish(arena, kind, kinds);
}

/// Wraps a system `TransactionKind` the way `new_system_transaction` does and encodes it.
pub fn finish(arena: std.mem.Allocator, kind: types.TransactionKind, kinds: []const types.EndOfEpochTransactionKind) Error!Built {
    const zero_addr: types.SuiAddress = .{ .@"0" = @splat(0) };
    const payment = try arena.alloc(struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest }, 1);
    payment[0] = .{ .{ .@"0" = .{ .@"0" = @splat(0) } }, seq(0), .{ .@"0" = .{ .@"0" = @splat(0) } } };
    const data: types.TransactionData = .{ .V1 = .{
        .kind = kind,
        .sender = zero_addr,
        .gas_data = .{ .payment = payment, .owner = zero_addr, .price = 1, .budget = 0 },
        .expiration = .{ .None = {} },
    } };
    const data_bcs = bcs.encodeAlloc(types.TransactionData, arena, &data) catch return error.Encode;
    const zero_sig = try arena.alloc(u8, 97);
    @memset(zero_sig, 0);
    const sigs = try arena.alloc(types.GenericSignature, 1);
    sigs[0] = .{ .@"0" = zero_sig };
    const sst = try arena.alloc(types.SenderSignedTransaction, 1);
    sst[0] = .{ .intent_message = .{ .intent = types.hand.Intent.sui(.transaction_data), .value = data }, .tx_signatures = sigs };
    const ssd: types.SenderSignedData = .{ .@"0" = .{ .items = sst } };
    const ssd_bcs = bcs.encodeAlloc(types.SenderSignedData, arena, &ssd) catch return error.Encode;
    return .{
        .kinds = kinds,
        .kind = kind,
        .data_bcs = data_bcs,
        .digest = types.digest.transactionDataDigest(data_bcs),
        .sender_signed_bcs = ssd_bcs,
    };
}

// ------------------------------------------------------------------ tests

test "mainnet 141 builds the expected kinds and a decodable system transaction" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cfg = try protocol.get(141, .mainnet);
    // a mainnet-like state: everything exists except nothing new to create
    const facts: Facts = .{
        .authenticator_state_exists = true,
        .authenticator_obj_initial_shared_version = 7,
        .randomness_state_exists = true,
        .bridge_exists = true,
        .bridge_committee_initiated = true,
        .bridge_obj_initial_shared_version = 9,
        .coin_deny_list_state_exists = true,
        .accumulator_root_exists = true,
        .coin_registry_exists = true,
        .display_registry_exists = true,
        .address_alias_state_exists = true,
        .forwarding_address_registry_exists = true,
        .accumulator_object_count = 12,
        .execution_time_observations = .{ .V1 = &.{} },
    };
    const built = try build(arena, cfg, facts, .{
        .current_epoch = 800,
        .epoch_start_timestamp_ms = 1_700_000_000_000,
        .gas = .{ .computation_cost = 5, .storage_cost = 6, .storage_rebate = 7, .non_refundable_storage_fee = 8 },
        .chosen = .{ .protocol_version = 141, .packages = &.{} },
    }, null);
    try std.testing.expect(built.kinds.len >= 2);
    // AuthenticatorStateExpire first, ChangeEpoch last
    try std.testing.expect(built.kinds[0] == .AuthenticatorStateExpire);
    try std.testing.expectEqual(@as(u64, 800 + 1 - cfg.max_age_of_jwk_in_epochs.?), built.kinds[0].AuthenticatorStateExpire.min_epoch);
    const last = built.kinds[built.kinds.len - 1];
    try std.testing.expectEqual(@as(u64, 801), last.ChangeEpoch.epoch);
    try std.testing.expectEqual(@as(u64, 7), last.ChangeEpoch.storage_rebate);
    // the encoding decodes back as the same system transaction
    const back = try bcs.decode(types.TransactionData, arena, built.data_bcs);
    try std.testing.expect(back.V1.kind == .EndOfEpochTransaction);
    try std.testing.expectEqual(built.kinds.len, back.V1.kind.EndOfEpochTransaction.len);
    try std.testing.expectEqual(@as(u64, 1), back.V1.gas_data.price);
    const ssd = try bcs.decode(types.SenderSignedData, arena, built.sender_signed_bcs);
    try std.testing.expectEqual(@as(usize, 1), ssd.@"0".items.len);
    try std.testing.expectEqual(@as(usize, 97), ssd.@"0".items[0].tx_signatures[0].@"0".len);
}

test "a missing system package source is reported, not guessed" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cfg = try protocol.get(141, .mainnet);
    const refs = [_]reconfig.ObjectRef{.{ .{ .@"0" = .{ .@"0" = @splat(1) } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = @splat(2) } } }};
    try std.testing.expectError(error.SystemPackagesMissing, build(arena, cfg, .{ .execution_time_observations = .{ .V1 = &.{} } }, .{
        .current_epoch = 1,
        .epoch_start_timestamp_ms = 0,
        .gas = .{ .computation_cost = 0, .storage_cost = 0, .storage_rebate = 0, .non_refundable_storage_fee = 0 },
        .chosen = .{ .protocol_version = 142, .packages = &refs },
    }, null));
}

test "ExecutionTimeEstimate mode requires the observations payload" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cfg = try protocol.get(141, .mainnet);
    try std.testing.expectError(error.MissingExecutionTimeObservations, preludeKinds(arena, cfg, 5, .{}));
    const kinds = try preludeKinds(arena, cfg, 5, .{ .execution_time_observations = .{ .V1 = &.{} } });
    var seen = false;
    for (kinds) |k| {
        if (k == .StoreExecutionTimeObservations) seen = true;
    }
    try std.testing.expect(seen);
}

test "protocol without end of epoch transactions builds a bare ChangeEpoch" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const cfg = try protocol.get(5, .mainnet);
    const built = try build(arena, cfg, .{}, .{
        .current_epoch = 1,
        .epoch_start_timestamp_ms = 99,
        .gas = .{ .computation_cost = 1, .storage_cost = 2, .storage_rebate = 3, .non_refundable_storage_fee = 4 },
        .chosen = .{ .protocol_version = 5, .packages = &.{} },
    }, null);
    try std.testing.expect(built.kind == .ChangeEpoch);
    try std.testing.expectEqual(@as(usize, 0), built.kinds.len);
}
