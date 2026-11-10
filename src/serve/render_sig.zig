//! sui.rpc.v2 `UserSignature` rendering from the raw GenericSignature bytes (flag byte first),
//! byte-equal to `rpc_proto_conversions.rs` 1645-1982, including zkLogin authenticators and
//! public identifiers (through sui-sdk-types in Rust) and legacy multisig.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");

const Mask = mask.Mask;
pub const Error = proto.Error || bcs.DecodeError || std.mem.Allocator.Error || error{ InvalidValue, Unsupported };

fn bcsMsg(w: *proto.Writer, field: u32, name: []const u8, value: []const u8) proto.Error!void {
    const m = try w.begin(field, name.len + value.len + 8);
    try w.string(1, name);
    try w.bytes(2, value);
    try w.end(m);
}

/// SimpleSignature (scheme 1, signature 2, public_key 3) from flag ++ sig ++ pk bytes.
fn writeSimple(w: *proto.Writer, field: u32, b: []const u8) Error!void {
    const sig_len: usize = switch (b[0]) {
        0, 1, 2 => 64,
        7 => 3309,
        else => return error.InvalidValue,
    };
    const m = try w.begin(field, b.len + 12);
    try w.uint(1, b[0]);
    try w.bytes(2, b[1..][0..sig_len]);
    try w.bytes(3, b[1 + sig_len ..]);
    try w.end(m);
}

/// ZkLoginPublicIdentifier (sui-types bytes: iss_len ++ iss ++ 32-byte seed) through sui-sdk-types;
/// an invalid value renders as the empty message (`unwrap_or_default`).
fn writeZkPublicId(w: *proto.Writer, field: u32, bytes: []const u8) Error!void {
    const m = try w.begin(field, 300);
    parse: {
        if (bytes.len < 1) break :parse;
        const iss_len: usize = bytes[0];
        if (bytes.len < 1 + iss_len) break :parse;
        const iss = bytes[1..][0..iss_len];
        if (!std.unicode.utf8ValidateSlice(iss)) break :parse;
        const seed_bytes = bytes[1 + iss_len ..];
        if (seed_bytes.len != 32) break :parse;
        var seed: u256 = 0;
        for (seed_bytes) |b| seed = (seed << 8) | b;
        var buf: [80]u8 = undefined;
        const dec = std.fmt.bufPrint(&buf, "{d}", .{seed}) catch unreachable;
        try w.string(1, iss);
        try w.string(2, dec);
    }
    try w.end(m);
}

fn writePublicKey(w: *proto.Writer, field: u32, pk: types.PublicKey) Error!void {
    const m = try w.begin(field, 40);
    switch (pk) {
        .Ed25519 => |k| {
            try w.uint(1, 0);
            try w.bytes(2, &k);
        },
        .Secp256k1 => |k| {
            try w.uint(1, 1);
            try w.bytes(2, &k);
        },
        .Secp256r1 => |k| {
            try w.uint(1, 2);
            try w.bytes(2, &k);
        },
        .Passkey => |k| {
            try w.uint(1, 6);
            try w.bytes(2, &k);
        },
        .MLDSA65 => |k| {
            try w.uint(1, 7);
            try w.bytes(2, &k);
        },
        .ZkLogin => |z| {
            try w.uint(1, 5);
            try writeZkPublicId(w, 3, z.@"0");
        },
    }
    try w.end(m);
}

fn writeMemberSig(w: *proto.Writer, field: u32, s: types.CompressedSignature) Error!void {
    const m = try w.begin(field, 70);
    switch (s) {
        .Ed25519 => |b| {
            try w.uint(1, 0);
            try w.bytes(2, &b);
        },
        .Secp256k1 => |b| {
            try w.uint(1, 1);
            try w.bytes(2, &b);
        },
        .Secp256r1 => |b| {
            try w.uint(1, 2);
            try w.bytes(2, &b);
        },
        .ZkLogin => try w.uint(1, 5),
        .Passkey => try w.uint(1, 6),
        .MLDSA65 => |b| {
            try w.uint(1, 7);
            try w.bytes(2, &b);
        },
    }
    try w.end(m);
}

fn writeMultisig(w: *proto.Writer, field: u32, arena: std.mem.Allocator, inner: []const u8) Error!void {
    if (!types.hand.GenericSignature.multiSigOk(inner)) return writeLegacyMultisig(w, field, arena, inner);
    const ms = try bcs.decode(types.MultiSig, arena, inner);
    const m = try w.begin(field, 256);
    for (ms.sigs) |s| try writeMemberSig(w, 1, s);
    try w.uint(2, ms.bitmap);
    const c = try w.begin(4, 128);
    for (ms.multisig_pk.pk_map) |e| {
        const mm = try w.begin(1, 48);
        try writePublicKey(w, 1, e.@"0");
        try w.uint(2, e.@"1");
        try w.end(mm);
    }
    try w.uint(2, ms.multisig_pk.threshold);
    try w.end(c);
    try w.end(m);
}

fn writePasskey(w: *proto.Writer, field: u32, arena: std.mem.Allocator, inner: []const u8) Error!void {
    const p = try bcs.decode(types.hand.RawPasskeyAuthenticator, arena, inner);
    const m = try w.begin(field, inner.len + 16);
    try w.bytes(1, p.authenticator_data);
    try w.string(2, p.client_data_json.@"0");
    try writeSimple(w, 3, p.user_signature.@"0");
    try w.end(m);
}

/// UserSignature message (as field `field` of its parent) for mask `m`.
pub fn writeUserSignature(w: *proto.Writer, field: u32, arena: std.mem.Allocator, m: Mask, b: []const u8) Error!void {
    const mm = try w.begin(field, b.len + 40);
    if (m.contains("bcs")) try bcsMsg(w, 1, "UserSignatureBytes", b);
    const flag = b[0];
    if (m.contains("scheme")) try w.uint(2, flag);
    switch (flag) {
        0, 1, 2, 7 => if (m.contains("simple")) try writeSimple(w, 3, b),
        3 => if (m.contains("multisig")) try writeMultisig(w, 4, arena, b[1..]),
        5 => if (m.contains("zklogin")) try writeZkLogin(w, 5, arena, b[1..]),
        6 => if (m.contains("passkey")) try writePasskey(w, 6, arena, b[1..]),
        else => return error.InvalidValue,
    }
    try w.end(mm);
}

const Legacy = types.hand.MultiSigLegacyOf(types.CompressedSignature);

/// MultiSigLegacy -> MultisigAggregatedSignature (signatures, legacy_bitmap, committee).
fn writeLegacyMultisig(w: *proto.Writer, field: u32, arena: std.mem.Allocator, inner: []const u8) Error!void {
    const ms = try bcs.decode(Legacy, arena, inner);
    const m = try w.begin(field, 512);
    for (ms.sigs) |sg| try writeMemberSig(w, 1, sg);
    var tmp: [types.roaring.max_canonical]u8 = undefined;
    const bm = types.roaring.canonical(ms.bitmap.@"0", &tmp) catch return error.InvalidValue;
    try w.bytes(3, bm);
    const c = try w.begin(4, 256);
    for (ms.multisig_pk.pk_map) |e| {
        const mm = try w.begin(1, 64);
        var kbuf: [types.hand.Base64PublicKey.max_decoded]u8 = undefined;
        const key = types.hand.Base64PublicKey.decodeCanonical(e.@"0".@"0", &kbuf) orelse return error.InvalidValue;
        const km = try w.begin(1, 40);
        try w.uint(1, key[0]);
        try w.bytes(2, key[1..]);
        try w.end(km);
        try w.uint(2, e.@"1");
        try w.end(mm);
    }
    try w.uint(2, ms.multisig_pk.threshold);
    try w.end(c);
    try w.end(m);
}

// ---- zkLogin ----

const fr_modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// The canonical decimal of `dec mod p` (sui-types reduces the field element when it parses it).
fn canonDec(dec: []const u8, comptime modulus: []const u8, buf: *[80]u8) []const u8 {
    const p = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk std.fmt.parseInt(u256, modulus, 10) catch unreachable;
    };
    var acc: u256 = 0;
    for (dec) |c| {
        const t: u512 = @as(u512, acc) * 10 + (c - '0');
        acc = @intCast(t % p);
    }
    return std.fmt.bufPrint(buf, "{d}", .{acc}) catch unreachable;
}

/// `From<&sui_types::ZkLoginAuthenticator> for ZkLoginAuthenticator`. Rust first converts through
/// `sui_sdk_types::ZkLoginAuthenticator::try_from(value.clone())`, a BCS round trip whose
/// deserializer expects a length-prefixed byte string holding `flag ++ bcs(fields)`, while
/// sui-types serialises the bare struct. The round trip therefore fails for every real
/// authenticator and the `unwrap_or(message)` fallback is what the node sends: `inputs` with only
/// `address_seed`, `max_epoch` and the user signature.
fn writeZkLogin(w: *proto.Writer, field: u32, arena: std.mem.Allocator, inner: []const u8) Error!void {
    const z = try bcs.decode(types.hand.ZkLoginAuthenticator, arena, inner);
    const m = try w.begin(field, inner.len + 128);
    var buf: [80]u8 = undefined;
    const im = try w.begin(1, 100);
    try w.string(4, canonDec(z.inputs.addressSeed.@"0", fr_modulus, &buf));
    try w.end(im);
    try w.uint(2, z.maxEpoch);
    const sig = z.userSignature.@"0";
    if (sig.len == 0) return error.InvalidValue;
    try writeSimple(w, 3, sig);
    try w.end(m);
}
