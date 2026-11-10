//! The epoch 0 committee from `genesis.blob` (MystenLabs/sui-genesis, mainnet): the active
//! validators of the genesis system state, exactly what sui-types
//! `get_sui_system_state(..).get_current_epoch_committee()` reads.
//!
//! Layout walked here (sui-types 1.83.1): the blob is a BCS `Vec<u8>` holding the genesis
//! (certified checkpoint 0, its contents, the genesis transaction, effects, events, all objects).
//! Object 0x5 is the `SuiSystemStateWrapper` {id, version}; the system state itself is the
//! dynamic field `Field<u64, SuiSystemStateInnerV{1,2}>` named by the wrapper's version under
//! the wrapper's id. Both inner versions begin with the same fields up to the validator set.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const committee_mod = @import("committee.zig");
const Reader = bcs.Reader;

pub const Error = committee_mod.Error || bcs.Error || error{ NoSystemState, UnsupportedSystemState };

/// Dynamic field object id: Blake2b256(0xf0 ++ parent ++ len(key) as u64 ++ key ++ BCS(key type)).
fn dynamicFieldId(parent: *const [32]u8, key_u64: u64) [32]u8 {
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, key_u64, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &klen, &k, &[_]u8{2} });
}

fn skipVecBytes(r: *Reader) bcs.Error!void {
    const n = try r.length();
    _ = try r.bytes(n);
}
fn skipOptVecBytes(r: *Reader) bcs.Error!void {
    switch (try r.int(u8)) {
        0 => {},
        1 => try skipVecBytes(r),
        else => return error.InvalidEnumTag,
    }
}
fn skipOptU64(r: *Reader) bcs.Error!void {
    switch (try r.int(u8)) {
        0 => {},
        1 => _ = try r.bytes(8),
        else => return error.InvalidEnumTag,
    }
}

/// Reads (protocol_pubkey_bytes, voting_power) of each active validator.
fn readValidators(arena: std.mem.Allocator, contents: []const u8) Error![]committee_mod.Member {
    var r = Reader.init(contents);
    return readValidatorsAt(arena, &r);
}

/// `readValidators` over a reader, leaving it after `active_validators`.
fn readValidatorsAt(arena: std.mem.Allocator, rp: *Reader) Error![]committee_mod.Member {
    var r = rp.*;
    defer rp.* = r;
    _ = try r.bytes(32); // Field.id
    _ = try r.int(u64); // Field.name
    _ = try r.int(u64); // epoch
    _ = try r.int(u64); // protocol_version
    _ = try r.int(u64); // system_state_version
    _ = try r.int(u64); // validators.total_stake
    const n = try r.length();
    if (n > r.remaining()) return error.EndOfInput;
    const out = try arena.alloc(committee_mod.Member, n);
    for (out) |*m| {
        // ValidatorMetadataV1
        _ = try r.bytes(32); // sui_address
        const pk_len = try r.length();
        const pk = try r.bytes(pk_len);
        if (pk_len != 96) return error.BadKey;
        m.name = pk[0..96].*;
        try skipVecBytes(&r); // network_pubkey_bytes
        try skipVecBytes(&r); // worker_pubkey_bytes
        try skipVecBytes(&r); // proof_of_possession_bytes
        for (0..8) |_| try skipVecBytes(&r); // name .. worker_address (strings are length-prefixed bytes)
        for (0..4) |_| try skipOptVecBytes(&r); // next_epoch pubkeys and proof
        for (0..4) |_| try skipOptVecBytes(&r); // next_epoch addresses
        _ = try r.bytes(40); // extra_fields: Bag { id, size }
        m.stake = try r.int(u64); // voting_power
        _ = try r.bytes(32); // operation_cap_id
        _ = try r.int(u64); // gas_price
        // StakingPoolV1
        _ = try r.bytes(32); // id
        try skipOptU64(&r);
        try skipOptU64(&r);
        _ = try r.bytes(8 * 3); // sui_balance, rewards_pool, pool_token_balance
        _ = try r.bytes(40); // exchange_rates: Table { id, size }
        _ = try r.bytes(8 * 3); // pending_stake, pending_total_sui_withdraw, pending_pool_token_withdraw
        _ = try r.bytes(40); // extra_fields
        _ = try r.bytes(8 * 4); // commission_rate, next_epoch_stake, next_epoch_gas_price, next_epoch_commission_rate
        _ = try r.bytes(40); // extra_fields
    }
    return out;
}

/// exec-history: epoch 0's reference gas price and start time, from the genesis system state
/// (`SuiSystemStateInnerV1.reference_gas_price` and `epoch_start_timestamp_ms`). Execute mode
/// needs them for epoch 0, which has no end-of-epoch checkpoint before it.
pub const GenesisParams = struct { rgp: u64, start_ms: u64 };

pub fn genesisEpochParams(arena: std.mem.Allocator, blob: []const u8) Error!GenesisParams {
    const c = try systemStateContents(arena, blob);
    var r = Reader.init(c);
    _ = try readValidatorsAt(arena, &r);
    _ = try r.bytes(40); // pending_active_validators: TableVec { Table { id, size } }
    const nrem = try r.length();
    _ = try r.bytes(8 * nrem); // pending_removals
    _ = try r.bytes(40 * 3); // staking_pool_mappings, inactive_validators, validator_candidates
    const nrisk = try r.length();
    _ = try r.bytes(40 * nrisk); // at_risk_validators: VecMap<address, u64>
    _ = try r.bytes(40); // validators.extra_fields
    _ = try r.bytes(16); // storage_fund
    _ = try r.bytes(8 * 7 + 40); // parameters
    const rgp = try r.int(u64);
    const nrep = try r.length(); // validator_report_records: VecMap<address, VecSet<address>>
    for (0..nrep) |_| {
        _ = try r.bytes(32);
        const m = try r.length();
        _ = try r.bytes(32 * m);
    }
    _ = try r.bytes(8 * 4 + 2 + 40); // stake_subsidy
    _ = try r.int(u8); // safe_mode
    _ = try r.bytes(8 * 4); // safe_mode balances and fees
    const start_ms = try r.int(u64);
    return .{ .rgp = rgp, .start_ms = start_ms };
}

/// The genesis system state inner object's contents (`Field<u64, SuiSystemStateInnerV1>`).
fn systemStateContents(arena: std.mem.Allocator, blob: []const u8) Error![]const u8 {
    var outer = Reader.init(blob);
    const n = try outer.length();
    const inner = try outer.bytes(n);
    var r = Reader.init(inner);
    try bcs.skip(@FieldType(types.CheckpointData, "checkpoint_summary"), &r);
    try bcs.skip(types.CheckpointContents, &r);
    try bcs.skip(@FieldType(types.CheckpointTransaction, "transaction"), &r);
    try bcs.skip(types.TransactionEffects, &r);
    try bcs.skip(types.TransactionEvents, &r);
    const nobj = try r.length();
    if (nobj > r.remaining()) return error.EndOfInput;
    const ObjView = bcs.View(types.Object);
    var five: [32]u8 = @splat(0);
    five[31] = 5;
    const ranges = try arena.alloc([]const u8, nobj);
    var want: ?[32]u8 = null;
    for (ranges) |*rg| {
        const st = r.at;
        try bcs.skip(types.Object, &r);
        rg.* = inner[st..r.at];
        const mv = (ObjView{ .bytes = rg.* }).field("data").payload("Move") orelse continue;
        const c = mv.field("contents").raw();
        if (c.len >= 40 and std.mem.eql(u8, c[0..32], &five)) want = dynamicFieldId(&five, std.mem.readInt(u64, c[32..40], .little));
    }
    const w = want orelse return error.NoSystemState;
    for (ranges) |rg| {
        const mv = (ObjView{ .bytes = rg }).field("data").payload("Move") orelse continue;
        const c = mv.field("contents").raw();
        if (c.len >= 40 and std.mem.eql(u8, c[0..32], &w)) return c;
    }
    return error.NoSystemState;
}

/// `bytes` is the content of genesis.blob. Memory comes from `arena`.
pub fn genesisCommittee(arena: std.mem.Allocator, blob: []const u8) Error!committee_mod.Committee {
    var outer = Reader.init(blob);
    const n = try outer.length();
    const inner = try outer.bytes(n);
    try outer.finish();

    var r = Reader.init(inner);
    try bcs.skip(@FieldType(types.CheckpointData, "checkpoint_summary"), &r);
    try bcs.skip(types.CheckpointContents, &r);
    try bcs.skip(@FieldType(types.CheckpointTransaction, "transaction"), &r);
    try bcs.skip(types.TransactionEffects, &r);
    try bcs.skip(types.TransactionEvents, &r);
    const nobj = try r.length();
    if (nobj > r.remaining()) return error.EndOfInput;

    const ObjView = bcs.View(types.Object);
    // pass 1: the wrapper object (id 0x5) gives the system state version
    var wrapper_version: ?u64 = null;
    var wrapper_id: [32]u8 = undefined;
    var five: [32]u8 = @splat(0);
    five[31] = 5;
    var k: usize = 0;
    var ranges = try arena.alloc([]const u8, nobj);
    while (k < nobj) : (k += 1) {
        const s = r.at;
        try bcs.skip(types.Object, &r);
        ranges[k] = inner[s..r.at];
        const mv = (ObjView{ .bytes = ranges[k] }).field("data").payload("Move") orelse continue;
        const c = mv.field("contents").raw();
        if (c.len >= 40 and std.mem.eql(u8, c[0..32], &five)) {
            wrapper_id = c[0..32].*;
            wrapper_version = std.mem.readInt(u64, c[32..40], .little);
        }
    }
    try r.finish();
    const version = wrapper_version orelse return error.NoSystemState;
    if (version != 1 and version != 2) return error.UnsupportedSystemState;
    const want = dynamicFieldId(&wrapper_id, version);
    for (ranges) |rg| {
        const mv = (ObjView{ .bytes = rg }).field("data").payload("Move") orelse continue;
        const c = mv.field("contents").raw();
        if (c.len < 40 or !std.mem.eql(u8, c[0..32], &want)) continue;
        const members = try readValidators(arena, c);
        return committee_mod.Committee.init(arena, 0, members);
    }
    return error.NoSystemState;
}
