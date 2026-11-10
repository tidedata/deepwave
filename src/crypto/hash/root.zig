//! hash: Blake2b-256, SHA-256/384/512, SHA3-256/512, Keccak-256, HMAC, HKDF; SIMD multi-buffer.
//! Owner lane: crypto-hash. Interface: CONTRACTS.md 5.3. Only the crypto-hash lane edits files in src/crypto/hash/.
//!
//! Every hasher: `init() -> update(bytes) -> final(*[N]u8)` plus one-shot `hash(bytes, *[N]u8)`.
//! No function here allocates.
const std = @import("std");

pub const conformance = @import("conformance.zig");

pub const blake2b = @import("blake2b.zig");
pub const sha2 = @import("sha2.zig");
pub const keccak = @import("keccak.zig");
pub const hmac = @import("hmac.zig");

pub const Blake2b256 = blake2b.Blake2b256;
pub const Sha256 = sha2.Sha256;
pub const Sha384 = sha2.Sha384;
pub const Sha512 = sha2.Sha512;
pub const Sha3_256 = keccak.Sha3_256;
pub const Sha3_512 = keccak.Sha3_512;
pub const Keccak256 = keccak.Keccak256;

pub const blake2b256 = blake2b.blake2b256;
pub const blake2b256Many = blake2b.blake2b256Many;

/// fastcrypto `hmac_sha3_256` (key of any length).
pub fn hmacSha3_256(key: []const u8, msg: []const u8) [32]u8 {
    return hmac.Hmac(Sha3_256).mac(key, msg);
}

/// fastcrypto `hkdf_sha3_256`: extract with `salt` (may be empty), expand `out.len` bytes.
pub fn hkdfSha3_256(ikm: []const u8, salt: []const u8, info: []const u8, out: []u8) error{OutputTooLong}!void {
    const K = hmac.Hkdf(Sha3_256);
    const prk = K.extract(salt, ikm);
    try K.expand(&prk, info, out);
}

/// TLS 1.3 / QUIC (net lane).
pub fn hmacSha256(key: []const u8, msg: []const u8) [32]u8 {
    return hmac.Hmac(Sha256).mac(key, msg);
}
pub fn hkdfSha256Extract(salt: []const u8, ikm: []const u8) [32]u8 {
    return hmac.Hkdf(Sha256).extract(salt, ikm);
}
/// `out.len` is at most 255 * 32 by construction in TLS/QUIC; a longer request is a caller bug
/// and panics in every build mode (never undefined behaviour in ReleaseFast).
pub fn hkdfSha256Expand(prk: *const [32]u8, info: []const u8, out: []u8) void {
    hmac.Hkdf(Sha256).expand(prk, info, out) catch @panic("hkdfSha256Expand: output longer than 255 * 32 bytes");
}

test {
    std.testing.refAllDecls(@This());
}
