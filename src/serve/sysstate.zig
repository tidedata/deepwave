//! The Sui system state (`SuiSystemStateInnerV1`/`V2`, sui-types 1.83.1) read from BCS and written
//! as the `sui.rpc.v2.SystemState` message exactly as sui-types `rpc_proto_conversions.rs` builds it
//! (`impl From<SuiSystemStateInnerV{1,2}> for SystemState`) and prost encodes it: every `Some` field
//! is emitted (empty strings, empty bytes and zeros included), `None` only for the staking pool's
//! activation/deactivation epoch, the validators' `next_epoch_*` options and V1's `min_validator_count`;
//! addresses and ids as `0x` + 64 lowercase hex; `at_risk_validators` as a sorted map with prost's
//! default-value skipping. Also the epoch committee (`ValidatorCommittee`) the system state implies.
//!
//! Live layout: object 0x5 is the `SuiSystemStateWrapper { id, version }`; the state is the dynamic
//! field `Field<u64, SuiSystemStateInnerV{version}>` under 0x5 named by `version`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const hash = @import("hash");
const proto = @import("proto.zig");
const Reader = bcs.Reader;

pub const Error = bcs.Error || proto.Error || Allocator.Error || error{ UnsupportedSystemState, NoSystemState };

pub const system_state_id: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 5;
    break :blk a;
};

/// `derive_dynamic_field_id(parent, &TypeTag::U64, bcs(key))`.
pub fn u64FieldId(parent: *const [32]u8, key: u64) [32]u8 {
    var k: [8]u8 = undefined;
    std.mem.writeInt(u64, &k, key, .little);
    var klen: [8]u8 = undefined;
    std.mem.writeInt(u64, &klen, 8, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &klen, &k, &[_]u8{2} });
}

/// Move contents of a BCS `Object` holding a Move object (null for a package or bad bytes).
pub fn moveContents(object_bytes: []const u8) ?[]const u8 {
    const types = @import("types");
    const V = bcs.View(types.Object);
    const v = V.init(object_bytes) catch return null;
    const mv = v.field("data").payload("Move") orelse return null;
    return mv.field("contents").raw();
}

/// The wrapper's `version` (which inner struct the state uses) from the 0x5 object's contents.
pub fn wrapperVersion(wrapper_contents: []const u8) ?u64 {
    if (wrapper_contents.len < 40) return null;
    return std.mem.readInt(u64, wrapper_contents[32..40], .little);
}

/// Inner state bytes (from `epoch` on) of a `Field<u64, Inner>` object's contents.
pub fn innerOfField(field_contents: []const u8) ?[]const u8 {
    if (field_contents.len < 40) return null;
    return field_contents[40..];
}

/// A system state: its wrapper version (1 or 2) and the inner struct's BCS bytes.
pub const State = struct {
    version: u64,
    inner: []const u8,
};

/// What GetEpoch reads besides the full message (the fields the trait accessors return).
pub const Summary = struct {
    epoch: u64,
    protocol_version: u64,
    system_state_version: u64,
    reference_gas_price: u64,
    epoch_start_timestamp_ms: u64,
};

fn skipBytes(r: *Reader) bcs.Error!void {
    const n = try r.length();
    _ = try r.bytes(n);
}
fn readBytes(r: *Reader) bcs.Error![]const u8 {
    const n = try r.length();
    return r.bytes(n);
}
fn readOpt(r: *Reader) bcs.Error!?[]const u8 {
    return switch (try r.int(u8)) {
        0 => null,
        1 => try readBytes(r),
        else => error.InvalidEnumTag,
    };
}
fn readOptU64(r: *Reader) bcs.Error!?u64 {
    return switch (try r.int(u8)) {
        0 => null,
        1 => try r.int(u64),
        else => error.InvalidEnumTag,
    };
}
fn readAddr(r: *Reader) bcs.Error!*const [32]u8 {
    return (try r.bytes(32))[0..32];
}

/// `0x` + 64 lowercase hex (sui-types `SuiAddress`/`ObjectID` Display, `to_canonical_string(true)`).
pub fn hexAddr(buf: *[66]u8, a: *const [32]u8) []const u8 {
    buf[0] = '0';
    buf[1] = 'x';
    const digits = "0123456789abcdef";
    for (a, 0..) |b, i| {
        buf[2 + 2 * i] = digits[b >> 4];
        buf[3 + 2 * i] = digits[b & 15];
    }
    return buf;
}

fn writeAddr(w: *proto.Writer, field: u32, a: *const [32]u8) proto.Error!void {
    var b: [66]u8 = undefined;
    try w.string(field, hexAddr(&b, a));
}

/// `MoveTable { id, size }` from a Bag (`UID`), Table (`ObjectID`) or TableVec (`Table`): 40 bytes.
fn writeTable(w: *proto.Writer, field: u32, r: *Reader) Error!void {
    const id = try readAddr(r);
    const size = try r.int(u64);
    const m = try w.begin(field, 80);
    try writeAddr(w, 1, id);
    try w.uint(2, size);
    try w.end(m);
}

pub fn summary(s: State) Error!Summary {
    if (s.version != 1 and s.version != 2) return error.UnsupportedSystemState;
    var r = Reader.init(s.inner);
    var out: Summary = undefined;
    out.epoch = try r.int(u64);
    out.protocol_version = try r.int(u64);
    out.system_state_version = try r.int(u64);
    try skipValidatorSet(&r);
    _ = try r.bytes(16); // storage fund
    _ = try r.bytes(if (s.version == 2) 8 * 8 + 40 else 7 * 8 + 40); // parameters
    out.reference_gas_price = try r.int(u64);
    try skipReportRecords(&r);
    _ = try r.bytes(8 * 4 + 2 + 40); // stake subsidy
    _ = try r.boolean();
    _ = try r.bytes(8 * 4);
    out.epoch_start_timestamp_ms = try r.int(u64);
    return out;
}

/// Parameters and flags the validator lane reads at an epoch switch (val-epoch-api-keys): the
/// system parameters' `epoch_duration_ms` (their first field in V1 and V2) and `safe_mode`.
pub fn epochParams(s: State) Error!struct { epoch_duration_ms: u64, safe_mode: bool } {
    if (s.version != 1 and s.version != 2) return error.UnsupportedSystemState;
    var r = Reader.init(s.inner);
    _ = try r.int(u64); // epoch
    _ = try r.bytes(16); // protocol_version, system_state_version
    try skipValidatorSet(&r);
    _ = try r.bytes(16); // storage fund
    const duration = try r.int(u64);
    _ = try r.bytes(if (s.version == 2) 7 * 8 + 40 else 6 * 8 + 40); // rest of the parameters
    _ = try r.int(u64); // reference_gas_price
    try skipReportRecords(&r);
    _ = try r.bytes(8 * 4 + 2 + 40); // stake subsidy
    const safe_mode = try r.boolean();
    return .{ .epoch_duration_ms = duration, .safe_mode = safe_mode };
}

/// The system state's epoch and `storage_fund.total_object_storage_rebates` (the value of the
/// first Balance of `StorageFund`, right after the validator set in both inner versions): what
/// sui-node's SUI conservation check reads (`storage_fund_total_object_storage_rebates`).
pub fn storageFund(s: State) Error!struct { epoch: u64, total_object_storage_rebates: u64, non_refundable_balance: u64 } {
    if (s.version != 1 and s.version != 2) return error.UnsupportedSystemState;
    var r = Reader.init(s.inner);
    const epoch = try r.int(u64);
    _ = try r.bytes(16); // protocol_version, system_state_version
    try skipValidatorSet(&r);
    const rebates = try r.int(u64);
    const non_refundable = try r.int(u64);
    return .{ .epoch = epoch, .total_object_storage_rebates = rebates, .non_refundable_balance = non_refundable };
}

fn skipReportRecords(r: *Reader) bcs.Error!void {
    const n = try r.length();
    for (0..n) |_| {
        _ = try r.bytes(32);
        const k = try r.length();
        _ = try r.bytes(32 * k);
    }
}

fn skipValidatorSet(r: *Reader) bcs.Error!void {
    _ = try r.int(u64);
    const n = try r.length();
    for (0..n) |_| _ = try readValidator(r);
    _ = try r.bytes(40); // pending_active_validators
    const k = try r.length();
    _ = try r.bytes(8 * k);
    _ = try r.bytes(40 * 3);
    const m = try r.length();
    _ = try r.bytes(40 * m);
    _ = try r.bytes(40);
}

const Validator = struct {
    sui_address: *const [32]u8,
    protocol_pubkey: []const u8,
    network_pubkey: []const u8,
    worker_pubkey: []const u8,
    pop: []const u8,
    name: []const u8,
    description: []const u8,
    image_url: []const u8,
    project_url: []const u8,
    net_address: []const u8,
    p2p_address: []const u8,
    primary_address: []const u8,
    worker_address: []const u8,
    next: [8]?[]const u8,
    metadata_extra: [40]u8,
    voting_power: u64,
    operation_cap_id: *const [32]u8,
    gas_price: u64,
    pool_id: *const [32]u8,
    activation_epoch: ?u64,
    deactivation_epoch: ?u64,
    sui_balance: u64,
    rewards_pool: u64,
    pool_token_balance: u64,
    exchange_rates: [40]u8,
    pending_stake: u64,
    pending_total_sui_withdraw: u64,
    pending_pool_token_withdraw: u64,
    pool_extra: [40]u8,
    commission_rate: u64,
    next_epoch_stake: u64,
    next_epoch_gas_price: u64,
    next_epoch_commission_rate: u64,
    extra: [40]u8,
};

/// `ValidatorV1` (metadata, then the validator and its `StakingPoolV1`).
fn readValidator(r: *Reader) bcs.Error!Validator {
    var v: Validator = undefined;
    v.sui_address = try readAddr(r);
    v.protocol_pubkey = try readBytes(r);
    v.network_pubkey = try readBytes(r);
    v.worker_pubkey = try readBytes(r);
    v.pop = try readBytes(r);
    v.name = try readBytes(r);
    v.description = try readBytes(r);
    v.image_url = try readBytes(r);
    v.project_url = try readBytes(r);
    v.net_address = try readBytes(r);
    v.p2p_address = try readBytes(r);
    v.primary_address = try readBytes(r);
    v.worker_address = try readBytes(r);
    for (&v.next) |*o| o.* = try readOpt(r);
    v.metadata_extra = (try r.bytes(40))[0..40].*;
    v.voting_power = try r.int(u64);
    v.operation_cap_id = try readAddr(r);
    v.gas_price = try r.int(u64);
    v.pool_id = try readAddr(r);
    v.activation_epoch = try readOptU64(r);
    v.deactivation_epoch = try readOptU64(r);
    v.sui_balance = try r.int(u64);
    v.rewards_pool = try r.int(u64);
    v.pool_token_balance = try r.int(u64);
    v.exchange_rates = (try r.bytes(40))[0..40].*;
    v.pending_stake = try r.int(u64);
    v.pending_total_sui_withdraw = try r.int(u64);
    v.pending_pool_token_withdraw = try r.int(u64);
    v.pool_extra = (try r.bytes(40))[0..40].*;
    v.commission_rate = try r.int(u64);
    v.next_epoch_stake = try r.int(u64);
    v.next_epoch_gas_price = try r.int(u64);
    v.next_epoch_commission_rate = try r.int(u64);
    v.extra = (try r.bytes(40))[0..40].*;
    return v;
}

fn writeTable40(w: *proto.Writer, field: u32, b: *const [40]u8) Error!void {
    var r = Reader.init(b);
    try writeTable(w, field, &r);
}

fn writeValidator(w: *proto.Writer, v: *const Validator) Error!void {
    const m = try w.begin(2, 1024);
    try w.string(1, v.name);
    try writeAddr(w, 2, v.sui_address);
    try w.string(3, v.description);
    try w.string(4, v.image_url);
    try w.string(5, v.project_url);
    try w.bytes(7, v.protocol_pubkey);
    try w.bytes(8, v.pop);
    try w.bytes(10, v.network_pubkey);
    try w.bytes(12, v.worker_pubkey);
    try w.string(13, v.net_address);
    try w.string(14, v.p2p_address);
    try w.string(15, v.primary_address);
    try w.string(16, v.worker_address);
    // next_epoch_{protocol pk, pop, network pk, worker pk, net, p2p, primary, worker}
    const next_fields = [8]u32{ 18, 19, 21, 23, 24, 25, 26, 27 };
    for (v.next, next_fields) |o, f| if (o) |b| try w.bytes(f, b);
    try writeTable40(w, 28, &v.metadata_extra);
    try w.uint(29, v.voting_power);
    try writeAddr(w, 30, v.operation_cap_id);
    try w.uint(31, v.gas_price);
    {
        const p = try w.begin(32, 256);
        try writeAddr(w, 1, v.pool_id);
        if (v.activation_epoch) |e| try w.uint(2, e);
        if (v.deactivation_epoch) |e| try w.uint(3, e);
        try w.uint(4, v.sui_balance);
        try w.uint(5, v.rewards_pool);
        try w.uint(6, v.pool_token_balance);
        try writeTable40(w, 7, &v.exchange_rates);
        try w.uint(8, v.pending_stake);
        try w.uint(9, v.pending_total_sui_withdraw);
        try w.uint(10, v.pending_pool_token_withdraw);
        try writeTable40(w, 11, &v.pool_extra);
        try w.end(p);
    }
    try w.uint(33, v.commission_rate);
    try w.uint(34, v.next_epoch_stake);
    try w.uint(35, v.next_epoch_gas_price);
    try w.uint(36, v.next_epoch_commission_rate);
    try writeTable40(w, 37, &v.extra);
    try w.end(m);
}

const AtRisk = struct { addr: [66]u8, value: u64 };

/// The `SystemState` message body (no tag) of `s`. `arena` holds the sorted at-risk map.
pub fn writeSystemState(arena: Allocator, w: *proto.Writer, s: State) Error!void {
    if (s.version != 1 and s.version != 2) return error.UnsupportedSystemState;
    var r = Reader.init(s.inner);
    const epoch = try r.int(u64);
    const protocol_version = try r.int(u64);
    const system_state_version = try r.int(u64);
    try w.uint(1, system_state_version);
    try w.uint(2, epoch);
    try w.uint(3, protocol_version);
    {
        // ValidatorSetV1
        const vs = try w.begin(4, 64 * 1024);
        try w.uint(1, try r.int(u64)); // total_stake
        const n = try r.length();
        for (0..n) |_| {
            const v = try readValidator(&r);
            try writeValidator(w, &v);
        }
        try writeTable(w, 3, &r); // pending_active_validators: TableVec { contents: Table }
        const k = try r.length();
        if (k > r.remaining() / 8) return error.EndOfInput;
        const removals = try arena.alloc(u64, k);
        for (removals) |*x| x.* = try r.int(u64);
        try w.packedUints(4, removals);
        try writeTable(w, 5, &r);
        try writeTable(w, 6, &r);
        try writeTable(w, 7, &r);
        // at_risk_validators: VecMap<SuiAddress, u64> into a BTreeMap<String, u64>
        const m = try r.length();
        if (m > r.remaining() / 40) return error.EndOfInput;
        var risk = try arena.alloc(AtRisk, m);
        var nrisk: usize = 0;
        for (0..m) |_| {
            var e: AtRisk = undefined;
            _ = hexAddr(&e.addr, try readAddr(&r));
            e.value = try r.int(u64);
            // later duplicates replace earlier ones (BTreeMap::from_iter)
            var replaced = false;
            for (risk[0..nrisk]) |*o| if (std.mem.eql(u8, &o.addr, &e.addr)) {
                o.value = e.value;
                replaced = true;
            };
            if (!replaced) {
                risk[nrisk] = e;
                nrisk += 1;
            }
        }
        risk = risk[0..nrisk];
        std.mem.sort(AtRisk, risk, {}, struct {
            fn lt(_: void, a: AtRisk, b: AtRisk) bool {
                return std.mem.lessThan(u8, &a.addr, &b.addr);
            }
        }.lt);
        for (risk) |e| {
            const em = try w.begin(8, 80);
            try w.string(1, &e.addr);
            if (e.value != 0) try w.uint(2, e.value);
            try w.end(em);
        }
        try writeTable(w, 9, &r); // extra_fields
        try w.end(vs);
    }
    {
        const sf = try w.begin(5, 24);
        try w.uint(1, try r.int(u64));
        try w.uint(2, try r.int(u64));
        try w.end(sf);
    }
    {
        const p = try w.begin(6, 128);
        try w.uint(1, try r.int(u64)); // epoch_duration_ms
        try w.uint(2, try r.int(u64)); // stake_subsidy_start_epoch
        if (s.version == 2) try w.uint(3, try r.int(u64)); // min_validator_count
        for (4..9) |f| try w.uint(@intCast(f), try r.int(u64));
        try writeTable(w, 9, &r);
        try w.end(p);
    }
    try w.uint(7, try r.int(u64)); // reference_gas_price
    {
        const n = try r.length();
        for (0..n) |_| {
            const m = try w.begin(8, 256);
            try writeAddr(w, 1, try readAddr(&r));
            const k = try r.length();
            for (0..k) |_| try writeAddr(w, 2, try readAddr(&r));
            try w.end(m);
        }
    }
    {
        const m = try w.begin(9, 96);
        try w.uint(1, try r.int(u64)); // balance
        try w.uint(2, try r.int(u64)); // distribution_counter
        try w.uint(3, try r.int(u64)); // current_distribution_amount
        try w.uint(4, try r.int(u64)); // stake_subsidy_period_length
        try w.uint(5, try r.int(u16)); // stake_subsidy_decrease_rate
        try writeTable(w, 6, &r);
        try w.end(m);
    }
    try w.uint(10, @intFromBool(try r.boolean()));
    try w.uint(11, try r.int(u64));
    try w.uint(12, try r.int(u64));
    try w.uint(13, try r.int(u64));
    try w.uint(14, try r.int(u64));
    try w.uint(15, try r.int(u64));
    try writeTable(w, 16, &r);
    try r.finish();
}

pub const Member = struct { key: []const u8, weight: u64 };

/// `Committee` of the state's epoch: (protocol key, voting power) of every active validator,
/// sorted by key bytes (`Committee::new` keeps a BTreeMap).
pub fn committee(arena: Allocator, s: State) Error![]Member {
    if (s.version != 1 and s.version != 2) return error.UnsupportedSystemState;
    var r = Reader.init(s.inner);
    _ = try r.bytes(24);
    _ = try r.int(u64);
    const n = try r.length();
    if (n > r.remaining()) return error.EndOfInput;
    const out = try arena.alloc(Member, n);
    for (out) |*m| {
        const v = try readValidator(&r);
        m.* = .{ .key = v.protocol_pubkey, .weight = v.voting_power };
    }
    std.mem.sort(Member, out, {}, struct {
        fn lt(_: void, a: Member, b: Member) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    }.lt);
    return out;
}

/// `ValidatorCommittee { epoch = 1, members = 2 { public_key = 1, weight = 2 } }` body.
pub fn writeCommittee(w: *proto.Writer, epoch: u64, members: []const Member) proto.Error!void {
    try w.uint(1, epoch);
    for (members) |m| {
        const mm = try w.begin(2, m.key.len + 16);
        try w.bytes(1, m.key);
        try w.uint(2, m.weight);
        try w.end(mm);
    }
}

test "u64FieldId matches genesis walk" {
    // derive_dynamic_field_id(0x5, u64, 2) on mainnet: the inner system state object id
    const id = u64FieldId(&system_state_id, 2);
    var b: [66]u8 = undefined;
    try std.testing.expectEqualStrings("0x5b890eaf2abcfa2ab90b77b8e6f3d5d8609586c3e583baf3dccd5af17edf48d1", hexAddr(&b, &id));
}
