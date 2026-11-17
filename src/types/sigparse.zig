//! The semantic checks `GenericSignature::from_bytes` (sui-types 1.83.1, fastcrypto da61cd4)
//! runs while decoding a signature, beyond the BCS shape. A failure rejects the signature at
//! decode time, so it rejects a consensus block that carries it (PARITY.md G20):
//!   - zkLogin: `ZkLoginInputs::init` (JWT header and iss claim parsing);
//!   - passkey: `TryFrom<RawPasskeyAuthenticator> for PasskeyAuthenticator`;
//!   - MultiSigLegacy base64 keys: point validity in the fastcrypto key parsers.
//! The parsers live here (types cannot import zk or sig); zk and sig re-export them.
const std = @import("std");
const bcs = @import("bcs");

pub const errors = @import("sigparse/errors.zig");
pub const b64 = @import("sigparse/b64.zig");
pub const jwt = @import("sigparse/jwt.zig");
pub const clientdata = @import("sigparse/clientdata.zig");

const Reader = bcs.Reader;
const ecc = std.crypto.ecc;

/// Scratch for the zkLogin checks: on the stack for every real header and claim, from the page
/// allocator only for oversized ones (the sizes are bounded by the message carrying them).
const stack_scratch = 4096;

/// `ZkLoginInputs::init` over the BCS of a `ZkLoginAuthenticator` (after the 0x05 flag) that
/// already parsed: `JWTHeader::new(header_base64)` (base64url unpadded, serde JSON with string
/// `alg` and `kid`, `alg == "RS256"`), then `decode_base64_url(iss_value, index_mod_4)` and
/// `verify_extended_claim(.., "iss")` (an object member list whose "iss" is a string).
pub fn zkLoginInitOk(inner: []const u8) bool {
    const hand = @import("hand.zig");
    var r = Reader.init(inner);
    bcs.skip(hand.ZkLoginProof, &r) catch return false;
    const iss = bcs.readStr(&r) catch return false;
    const idx = r.int(u8) catch return false;
    const header = bcs.readStr(&r) catch return false;
    const need = 3 * b64.decodedLen(header.len) + 3 * iss.len + 2;
    var stack: [stack_scratch]u8 = undefined;
    const heap = need > stack.len;
    const scratch = if (heap) std.heap.page_allocator.alloc(u8, need) catch return false else stack[0..need];
    defer if (heap) std.heap.page_allocator.free(scratch);
    return initOk(header, iss, idx, scratch);
}

fn initOk(header: []const u8, iss: []const u8, idx: u8, scratch: []u8) bool {
    var rest = scratch;
    const hdr = b64.decodeUrlUnpadded(header, rest) orelse return false;
    rest = rest[hdr.len..];
    const h = jwt.jwtHeader(hdr, rest[0 .. 2 * hdr.len]) catch return false;
    if (!std.mem.eql(u8, h.alg, "RS256")) return false;
    rest = rest[2 * hdr.len ..];
    var fail: errors.Fail = .none;
    const ext = b64.decodeBase64UrlBits(iss, idx, rest, &fail) orelse return false;
    rest = rest[ext.len..];
    // verify_extended_claim: ends in '}' or ',', and "{" ++ ext[..len-1] ++ "}" is a JSON
    // object whose "iss" member (last duplicate wins) is a string.
    if (ext.len == 0 or (ext[ext.len - 1] != '}' and ext[ext.len - 1] != ',')) return false;
    const text = rest[0 .. ext.len + 1];
    text[0] = '{';
    @memcpy(text[1..ext.len], ext[0 .. ext.len - 1]);
    text[ext.len] = '}';
    const v = jwt.claimValue(text, "iss", rest[ext.len + 1 ..]) catch return false;
    return v != null;
}

/// `PasskeyAuthenticator::try_from(RawPasskeyAuthenticator)` over the BCS after the 0x06 flag
/// (already parsed, so `user_signature` has a valid flag and length): client data JSON parses
/// as `CollectedClientData` with type "webauthn.get", its challenge is base64url (unpadded,
/// strict) of 32 bytes, and the user signature is Secp256r1 with a valid public key (SEC1
/// compressed or compact point) and r, s in [1, n).
pub fn passkeyOk(inner: []const u8) bool {
    var r = Reader.init(inner);
    _ = r.bytes(r.length() catch return false) catch return false;
    const cdj = bcs.readStr(&r) catch return false;
    const us = r.bytes(r.length() catch return false) catch return false;
    var cbuf: [64]u8 = undefined;
    const cd = clientdata.parse(cdj, &cbuf) orelse return false;
    if (cd.ty != .get) return false;
    if (cd.challenge_len > cbuf.len) return false;
    var ch: [48]u8 = undefined;
    const c = b64.decodeUrlUnpadded(cd.challenge, &ch) orelse return false;
    if (c.len != 32) return false;
    if (us.len != 1 + 64 + 33 or us[0] != 2) return false;
    if (!r1PointOk(us[65..98])) return false;
    const n = ecc.P256.scalar.field_order;
    const rr = std.mem.readInt(u256, us[1..33], .big);
    const ss = std.mem.readInt(u256, us[33..65], .big);
    return rr != 0 and ss != 0 and rr < n and ss < n;
}

/// Point validity of a legacy multisig key (flag ++ key bytes, already shape-checked by
/// `Base64PublicKey.decodeCanonical`), as fastcrypto's `from_bytes` checks it:
/// - Ed25519: ed25519-consensus `VerificationKey::try_from` = curve25519-dalek `decompress`
///   (non-canonical y accepted, x = 0 with the sign bit set accepted);
/// - Secp256k1: `secp256k1::PublicKey::from_slice` (coordinates < p, on the curve);
/// - Secp256r1 / passkey: p256 `VerifyingKey::from_sec1_bytes` (coordinates < p, on the curve).
/// Shapes the key parsers reject anyway (length, SEC1 tag) may return either answer.
pub fn keyPointOk(key: []const u8) bool {
    if (key.len < 2) return true;
    const k = key[1..];
    return switch (key[0]) {
        0 => k.len == 32 and edPointOk(k[0..32].*),
        1 => switch (k[0]) {
            2, 3 => if (ecc.Secp256k1.fromSec1(k)) |_| true else |_| false,
            4, 6, 7 => blk: {
                if (k.len != 65) break :blk false;
                var u: [65]u8 = k[0..65].*;
                u[0] = 4;
                break :blk if (ecc.Secp256k1.fromSec1(&u)) |_| true else |_| false;
            },
            else => false,
        },
        2, 6 => r1PointOk(k),
        else => true,
    };
}

fn r1PointOk(k: []const u8) bool {
    if (k.len == 33 and k[0] == 5) {
        // SEC1 compact: x alone, any root (p256 `decompact`)
        var c: [33]u8 = k[0..33].*;
        c[0] = 2;
        return if (ecc.P256.fromSec1(&c)) |_| true else |_| false;
    }
    return if (ecc.P256.fromSec1(k)) |_| true else |_| false;
}

fn edPointOk(b: [32]u8) bool {
    if (ecc.Edwards25519.fromBytes(b)) |_| return true else |_| {}
    // Zig rejects x = 0 with the sign bit set; dalek negates zero and accepts.
    var c = b;
    c[31] &= 0x7f;
    const p = ecc.Edwards25519.fromBytes(c) catch return false;
    return c[31] != b[31] and p.x.isZero();
}

test {
    _ = errors;
    _ = b64;
    _ = jwt;
    _ = clientdata;
}

test "zkLogin init, passkey and key point checks" {
    const t = std.testing;
    var buf: [512]u8 = undefined;
    const hdr = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImFiYyJ9"; // {"alg":"RS256","typ":"JWT","kid":"abc"}
    const claim = "ImlzcyI6Imh0dHBzOi8vYS5iYyIs"; // "iss":"https://a.bc",
    try t.expect(initOk(hdr, claim, 0, &buf));
    try t.expect(!initOk(hdr, claim, 3, &buf));
    try t.expect(!initOk("bm9wZQ", claim, 0, &buf)); // "nope"
    try t.expect(!initOk(hdr, "InN1YiI6Imh0dHBzOi8vYS5iYyIs", 0, &buf)); // "sub":...,
    // ed25519: (0, 1) with the sign bit is accepted by dalek; y = 2 is not on the curve
    var one: [32]u8 = @splat(0);
    one[0] = 1;
    try t.expect(edPointOk(one));
    one[31] = 0x80;
    try t.expect(edPointOk(one));
    var two: [32]u8 = @splat(0);
    two[0] = 2;
    try t.expect(!edPointOk(two));
    try t.expect(edPointOk(ecc.Edwards25519.basePoint.toBytes()));
    const g1 = ecc.P256.basePoint.toCompressedSec1();
    try t.expect(r1PointOk(&g1));
    var gc = g1;
    gc[0] = 5;
    try t.expect(r1PointOk(&gc));
    var over: [33]u8 = @splat(0xff);
    over[0] = 2;
    try t.expect(!r1PointOk(&over));
    try t.expect(!keyPointOk(&([_]u8{1} ++ over)));
}
