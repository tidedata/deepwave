//! `0x3::validator::validate_metadata_bcs(vector<u8>)` (sui-move-natives validator.rs over
//! sui-types `ValidatorMetadataV1::verify(metadata_v2 = true)`).
//!
//!   charge base, then per_byte * len
//!   bcs decode of ValidatorMetadataV1 fails   MALFORMED (VM error)
//!   verify fails                              abort <E_METADATA_*>, cost so far
//!   ok                                        no return values
const std = @import("std");
const bcs = @import("bcs");
const bls = @import("bls");
const sig = @import("sig");
const abi = @import("abi.zig");
const multiaddr = @import("multiaddr.zig");
const crypto = @import("crypto.zig");

const Ctx = abi.Ctx;
const Value = abi.Value;
const TyArg = abi.TyArg;
const Outcome = abi.Outcome;
const Error = abi.Error;
const Allocator = std.mem.Allocator;

pub const E_METADATA_INVALID_POP: u64 = 0;
pub const E_METADATA_INVALID_PUBKEY: u64 = 1;
pub const E_METADATA_INVALID_NET_PUBKEY: u64 = 2;
pub const E_METADATA_INVALID_WORKER_PUBKEY: u64 = 3;
pub const E_METADATA_INVALID_NET_ADDR: u64 = 4;
pub const E_METADATA_INVALID_P2P_ADDR: u64 = 5;
pub const E_METADATA_INVALID_PRIMARY_ADDR: u64 = 6;
pub const E_METADATA_INVALID_WORKER_ADDR: u64 = 7;

pub const Metadata = struct {
    sui_address: *const [32]u8,
    protocol_pubkey: []const u8,
    network_pubkey: []const u8,
    worker_pubkey: []const u8,
    pop: []const u8,
    net_address: []const u8,
    p2p_address: []const u8,
    primary_address: []const u8,
    worker_address: []const u8,
    next_protocol_pubkey: ?[]const u8,
    next_pop: ?[]const u8,
    next_network_pubkey: ?[]const u8,
    next_worker_pubkey: ?[]const u8,
    next_net_address: ?[]const u8,
    next_p2p_address: ?[]const u8,
    next_primary_address: ?[]const u8,
    next_worker_address: ?[]const u8,
};

fn vecU8(r: *bcs.Reader) bcs.Error![]const u8 {
    const n = try r.length();
    return r.bytes(n);
}

fn str(r: *bcs.Reader) bcs.Error![]const u8 {
    const s = try vecU8(r);
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    return s;
}

fn opt(r: *bcs.Reader, comptime f: fn (*bcs.Reader) bcs.Error![]const u8) bcs.Error!?[]const u8 {
    const t = try r.int(u8);
    return switch (t) {
        0 => null,
        1 => try f(r),
        else => error.InvalidValue,
    };
}

/// `bcs::from_bytes::<ValidatorMetadataV1>` (strict: whole input consumed).
pub fn decode(b: []const u8) bcs.Error!Metadata {
    var r = bcs.Reader.init(b);
    var m: Metadata = undefined;
    m.sui_address = (try r.bytes(32))[0..32];
    m.protocol_pubkey = try vecU8(&r);
    m.network_pubkey = try vecU8(&r);
    m.worker_pubkey = try vecU8(&r);
    m.pop = try vecU8(&r);
    _ = try str(&r); // name
    _ = try str(&r); // description
    _ = try str(&r); // image_url
    _ = try str(&r); // project_url
    m.net_address = try str(&r);
    m.p2p_address = try str(&r);
    m.primary_address = try str(&r);
    m.worker_address = try str(&r);
    m.next_protocol_pubkey = try opt(&r, vecU8);
    m.next_pop = try opt(&r, vecU8);
    m.next_network_pubkey = try opt(&r, vecU8);
    m.next_worker_pubkey = try opt(&r, vecU8);
    m.next_net_address = try opt(&r, str);
    m.next_p2p_address = try opt(&r, str);
    m.next_primary_address = try opt(&r, str);
    m.next_worker_address = try opt(&r, str);
    _ = try r.bytes(32); // extra_fields.id
    _ = try r.int(u64); // extra_fields.size
    try r.finish();
    return m;
}

/// `verify_proof_of_possession`: pk validated, then a min-sig BLS signature over
/// bcs(IntentMessage{ [5,0,0], pk_compressed ++ address }) ++ epoch 0.
fn popOk(pk: *const bls.PublicKey, s: *const bls.Signature, addr: *const [32]u8) bool {
    var msg: [3 + 2 + 128 + 8]u8 = undefined;
    msg[0..5].* = .{ 5, 0, 0, 0x80, 0x01 };
    msg[5..101].* = pk.toBytes();
    msg[101..133].* = addr.*;
    @memset(msg[133..], 0);
    return crypto.minSigVerifyValidated(pk, &msg, s);
}

/// `NetworkPublicKey::from_bytes` (ed25519-consensus `VerificationKey::try_from`).
fn edKey(b: []const u8) ?*const [32]u8 {
    if (b.len != 32) return null;
    const k = b[0..32];
    _ = sig.ed25519.decompress(k) orelse return null;
    return k;
}

fn addrOk(arena: Allocator, s: []const u8, anemo: bool) Error!bool {
    const p = (try multiaddr.parse(arena, s)) orelse return false;
    return !anemo or p.anemo();
}

/// `ValidatorMetadataV1::verify(true)`: null on success, else the abort code.
/// `metadata_v2`: the next-epoch key checks of `verify(metadata_v2)`; false only in execution
/// version 3 before `validator_metadata_verify_v2` (exec-history-vm), where only two equal next
/// keys are refused.
pub fn verify(arena: Allocator, m: *const Metadata, metadata_v2: bool) Error!?u64 {
    const pk = bls.PublicKey.decode(m.protocol_pubkey) orelse return E_METADATA_INVALID_PUBKEY;
    const pop = bls.Signature.decode(m.pop) orelse return E_METADATA_INVALID_POP;
    if (!popOk(&pk, &pop, m.sui_address)) return E_METADATA_INVALID_POP;

    const net = edKey(m.network_pubkey) orelse return E_METADATA_INVALID_NET_PUBKEY;
    const worker = edKey(m.worker_pubkey) orelse return E_METADATA_INVALID_WORKER_PUBKEY;
    if (std.mem.eql(u8, net, worker)) return E_METADATA_INVALID_WORKER_PUBKEY;

    if (!try addrOk(arena, m.net_address, false)) return E_METADATA_INVALID_NET_ADDR;
    if (!try addrOk(arena, m.p2p_address, true)) return E_METADATA_INVALID_P2P_ADDR;
    if (!try addrOk(arena, m.primary_address, true)) return E_METADATA_INVALID_PRIMARY_ADDR;
    if (!try addrOk(arena, m.worker_address, true)) return E_METADATA_INVALID_WORKER_ADDR;

    const next_pk: ?bls.PublicKey = if (m.next_protocol_pubkey) |b|
        bls.PublicKey.decode(b) orelse return E_METADATA_INVALID_PUBKEY
    else
        null;
    const next_pop: ?bls.Signature = if (m.next_pop) |b|
        bls.Signature.decode(b) orelse return E_METADATA_INVALID_POP
    else
        null;
    if (next_pk) |npk| {
        const np = next_pop orelse return E_METADATA_INVALID_POP;
        if (!popOk(&npk, &np, m.sui_address)) return E_METADATA_INVALID_POP;
    }

    const next_net: ?*const [32]u8 = if (m.next_network_pubkey) |b|
        edKey(b) orelse return E_METADATA_INVALID_NET_PUBKEY
    else
        null;
    const next_worker: ?*const [32]u8 = if (m.next_worker_pubkey) |b|
        edKey(b) orelse return E_METADATA_INVALID_WORKER_PUBKEY
    else
        null;
    if (!metadata_v2) {
        if (next_net != null and next_worker != null and std.mem.eql(u8, next_net.?, next_worker.?)) return E_METADATA_INVALID_WORKER_PUBKEY;
    } else if (next_net != null and next_worker != null) {
        if (std.mem.eql(u8, next_net.?, next_worker.?)) return E_METADATA_INVALID_WORKER_PUBKEY;
    } else if (next_net) |nn| {
        if (std.mem.eql(u8, nn, worker)) return E_METADATA_INVALID_NET_PUBKEY;
    } else if (next_worker) |nw| {
        if (std.mem.eql(u8, nw, net)) return E_METADATA_INVALID_WORKER_PUBKEY;
    }

    if (m.next_net_address) |s| if (!try addrOk(arena, s, false)) return E_METADATA_INVALID_NET_ADDR;
    if (m.next_p2p_address) |s| if (!try addrOk(arena, s, true)) return E_METADATA_INVALID_P2P_ADDR;
    if (m.next_primary_address) |s| if (!try addrOk(arena, s, true)) return E_METADATA_INVALID_PRIMARY_ADDR;
    if (m.next_worker_address) |s| if (!try addrOk(arena, s, true)) return E_METADATA_INVALID_WORKER_ADDR;
    return null;
}

pub fn validate_metadata_bcs(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("validator_validate_metadata_cost_base"))) return c.oog();
    const bytes = try abi.bytesOf(c.arena, args[0]);
    if (!c.charge(c.p("validator_validate_metadata_data_cost_per_byte") *| bytes.len)) return c.oog();
    const m = decode(bytes) catch return Ctx.err(.MALFORMED, null);
    const v2 = (c.cfg.execution_version orelse 0) != 3 or c.cfg.feature_flags.validator_metadata_verify_v2;
    if (try verify(c.arena, &m, v2)) |code| return c.abort(code);
    return c.ok0();
}
