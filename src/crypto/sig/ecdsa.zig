//! ECDSA over secp256k1 and secp256r1 exactly as fastcrypto (da61cd4) accepts it.
//!
//! secp256k1 (libsecp256k1 0.27 through the `secp256k1` crate):
//!   - key: SEC1 33-byte compressed (02/03, x < p, on curve) or 65-byte (04, or hybrid 06/07
//!     whose tag parity matches y), x and y < p, on curve. Anything else: pk:InvalidInput.
//!   - signature: 64 bytes r || s (else sig:InputLengthWrong), r < n and s < n (else
//!     sig:InvalidInput). Zero r or s, high s (s > (n-1)/2), and a failed equation are all
//!     verify:InvalidSignature.
//!   - recovery: 65 bytes (else sig:InputLengthWrong), recovery id 0..3 and r, s < n (else
//!     sig:InvalidInput). High s is accepted. With id bit 1 the x coordinate is r + n, allowed
//!     only when r < p - n. Every failure after parsing is recover:GeneralOpaqueError.
//! secp256r1 (fastcrypto's own verify over p256 0.13 parsing):
//!   - key: SEC1 33-byte compressed (02/03), 33-byte compact (05: y is the smaller root), or
//!     65-byte uncompressed (04); never the identity.
//!   - signature: 64 bytes (else sig:InputLengthWrong), 1 <= r, s < n (else sig:InvalidInput).
//!     High s is verify:GeneralError, checked before the equation (verify:InvalidSignature).
//!   - recovery: id 0..3 (else sig:InvalidInput); with id bit 1 the x coordinate is
//!     (r + n) mod 2^256 (the wrapping add fastcrypto does), which must be < p and on the
//!     curve; a recovered identity is an error. Failures: recover:GeneralOpaqueError.
//! The message is hashed with SHA-256 or Keccak-256 and reduced mod n.
//!
//! Verification and recovery work on public data and are variable time.
const std = @import("std");
const hash = @import("hash");
const cpu = @import("core").cpu;
const verdict = @import("verdict.zig");
const k1 = @import("secp256k1.zig");
const r1 = @import("secp256r1.zig");
const Verdict = verdict.Verdict;

pub const HashKind = enum {
    sha256,
    keccak256,

    pub fn digest(h: HashKind, msg: []const u8) [32]u8 {
        var out: [32]u8 = undefined;
        switch (h) {
            .sha256 => hash.Sha256.hash(msg, &out),
            .keccak256 => hash.Keccak256.hash(msg, &out),
        }
        return out;
    }
};

pub const RecoverResult = union(enum) {
    ok: [33]u8,
    invalid: verdict.Reason,
};

const Kind = enum { k1, r1 };

fn Ecdsa(comptime kind: Kind) type {
    return struct {
        const C = switch (kind) {
            .k1 => std.crypto.ecc.Secp256k1,
            .r1 => std.crypto.ecc.P256,
        };
        const Fe = C.Fe;
        const Scalar = C.scalar.Scalar;
        const n: u256 = C.scalar.field_order;
        const p: u256 = Fe.field_order;
        const half_n: u256 = (n - 1) / 2;

        fn be(b: *const [32]u8) u256 {
            return std.mem.readInt(u256, b, .big);
        }

        fn toBe(x: u256) [32]u8 {
            var out: [32]u8 = undefined;
            std.mem.writeInt(u256, &out, x, .big);
            return out;
        }

        fn scalarOf(x: u256) Scalar {
            return Scalar.fromBytes(toBe(modN(x)), .big) catch unreachable;
        }

        /// A parsed public key (deepwave's own affine point).
        pub const Key = if (kind == .k1) k1.Affine else r1.Affine;

        fn parseR1(bytes: []const u8) ?r1.Affine {
            if (bytes.len == 33) {
                const tag = bytes[0];
                if (tag != 2 and tag != 3 and tag != 5) return null;
                const x = be(bytes[1..33]);
                if (x >= r1.p_int) return null;
                const pt = r1.Affine.fromX(r1.Fe.fromInt(x), tag == 3) orelse return null;
                if (tag == 5) {
                    // SEC1 "compact" form (sec1 0.7 Tag::Compact): y is the smaller of y, p - y
                    const y = pt.y.toInt();
                    if (y > r1.p_int - y) return pt.neg();
                }
                return pt;
            }
            if (bytes.len == 65) {
                if (bytes[0] != 4) return null;
                const x = be(bytes[1..33]);
                const y = be(bytes[33..65]);
                if (x >= r1.p_int or y >= r1.p_int) return null;
                const pt: r1.Affine = .{ .x = r1.Fe.fromInt(x), .y = r1.Fe.fromInt(y) };
                if (!pt.isOnCurve()) return null;
                return pt;
            }
            return null;
        }

        fn parseK1(bytes: []const u8) ?k1.Affine {
            if (bytes.len == 33) {
                if (bytes[0] != 2 and bytes[0] != 3) return null;
                const x = be(bytes[1..33]);
                if (x >= k1.p_int) return null;
                return k1.Affine.fromX(k1.Fe.fromInt(x), bytes[0] == 3);
            }
            if (bytes.len == 65) {
                const tag = bytes[0];
                if (tag != 4 and tag != 6 and tag != 7) return null;
                const x = be(bytes[1..33]);
                const y = be(bytes[33..65]);
                if (x >= k1.p_int or y >= k1.p_int) return null;
                if (tag != 4 and ((y & 1) == 1) != (tag == 7)) return null;
                const pt: k1.Affine = .{ .x = k1.Fe.fromInt(x), .y = k1.Fe.fromInt(y) };
                if (!pt.isOnCurve()) return null;
                return pt;
            }
            return null;
        }

        /// x mod n for any 256-bit x (n > 2^255, so one subtraction).
        inline fn modN(x: u256) u256 {
            return if (x >= n) x - n else x;
        }

        /// Public key parsing as the Rust library does it. Variable time.
        pub fn parsePublicKey(bytes: []const u8) ?Key {
            return if (kind == .k1) parseK1(bytes) else parseR1(bytes);
        }

        fn mulModN(a: u256, b: u256) u256 {
            return be(&scalarOf(a).mul(scalarOf(b)).toBytes(.big));
        }

        pub fn verify(pk: *const [33]u8, msg: []const u8, sig: *const [64]u8, h: HashKind) Verdict {
            return verifySlices(pk, msg, sig, h);
        }

        pub fn verifySlices(pk: []const u8, msg: []const u8, sig: []const u8, h: HashKind) Verdict {
            const d = h.digest(msg);
            return verifyDigestSlices(pk, &d, sig);
        }

        /// Verify over an already hashed message (the 32-byte digest reduced mod n).
        pub fn verifyDigest(pk: []const u8, d: *const [32]u8, sig: *const [64]u8) Verdict {
            return verifyDigestSlices(pk, d, sig);
        }

        pub fn verifyDigestSlices(pk: []const u8, d: *const [32]u8, sig: []const u8) Verdict {
            return cpu.call("ecdsa_" ++ @tagName(kind) ++ "_verify_slices", verifyDigestSlicesImpl, .{ pk, d, sig });
        }

        pub fn verifyDigestSlicesImpl(pk: []const u8, d: *const [32]u8, sig: []const u8) Verdict {
            const q = parsePublicKey(pk) orelse return .{ .invalid = .pk_invalid_input };
            return verifyDigestParsed(q, d, sig);
        }

        /// Verify with a key already parsed by `parsePublicKey`.
        pub fn verifyDigestParsed(q: Key, d: *const [32]u8, sig: []const u8) Verdict {
            return cpu.call("ecdsa_" ++ @tagName(kind) ++ "_verify", verifyDigestParsedImpl, .{ q, d, sig });
        }

        pub fn verifyDigestParsedImpl(q: Key, d: *const [32]u8, sig: []const u8) Verdict {
            if (sig.len != 64) return .{ .invalid = .sig_input_length_wrong };
            const r = be(sig[0..32]);
            const s = be(sig[32..64]);
            switch (kind) {
                .k1 => {
                    if (r >= n or s >= n) return .{ .invalid = .sig_invalid_input };
                    if (s > half_n or r == 0 or s == 0) return .{ .invalid = .verify_invalid_signature };
                },
                .r1 => {
                    if (r == 0 or s == 0 or r >= n or s >= n) return .{ .invalid = .sig_invalid_input };
                    if (s > half_n) return .{ .invalid = .verify_general_error };
                },
            }
            if (kind == .k1) {
                const z = modN(be(d));
                const s_inv = k1.invModN(s);
                const pt = k1.mulDoubleG(k1.mulModN(z, s_inv), q, k1.mulModN(r, s_inv));
                if (!k1.xModNEquals(pt, r)) return .{ .invalid = .verify_invalid_signature };
                return .valid;
            }
            const z = modN(be(d));
            const s_inv = r1.invModN(s);
            const pt = r1.mulDoubleG(mulModN(z, s_inv), q, mulModN(r, s_inv));
            if (!r1.xModNEquals(pt, r)) return .{ .invalid = .verify_invalid_signature };
            return .valid;
        }

        pub fn recover(msg: []const u8, sig: *const [65]u8, h: HashKind) ?[33]u8 {
            return switch (recoverSlices(msg, sig, h)) {
                .ok => |k| k,
                .invalid => null,
            };
        }

        pub fn recoverSlices(msg: []const u8, sig: []const u8, h: HashKind) RecoverResult {
            return recoverSlicesMode(msg, sig, h, false);
        }

        /// `strict` (secp256r1 only): fastcrypto 0a26327 `recover_with_hash`, where x = r + n
        /// must be below p without wrapping (SEC 1 4.1.6 step 1.3). Not strict: the pre-fix
        /// `recover_with_hash_legacy`, (r + n) mod 2^256. Sui picks by
        /// `secp256r1_ecrecover_checks_x_below_p` (protocol 142).
        pub fn recoverSlicesMode(msg: []const u8, sig: []const u8, h: HashKind, strict: bool) RecoverResult {
            return cpu.call("ecdsa_" ++ @tagName(kind) ++ "_recover", recoverSlicesModeImpl, .{ msg, sig, h, strict });
        }

        pub fn recoverSlicesModeImpl(msg: []const u8, sig: []const u8, h: HashKind, strict: bool) RecoverResult {
            if (sig.len != 65) return .{ .invalid = .sig_input_length_wrong };
            const rid = sig[64];
            if (rid > 3) return .{ .invalid = .sig_invalid_input };
            const r = be(sig[0..32]);
            const s = be(sig[32..64]);
            const opaque_err: RecoverResult = .{ .invalid = .recover_general_opaque_error };
            var x: u256 = undefined;
            switch (kind) {
                .k1 => {
                    if (r >= n or s >= n) return .{ .invalid = .sig_invalid_input };
                    if (r == 0 or s == 0) return opaque_err;
                    x = r;
                    if (rid & 2 != 0) {
                        if (r >= p - n) return opaque_err;
                        x = r + n;
                    }
                },
                .r1 => {
                    if (r == 0 or s == 0 or r >= n or s >= n) return .{ .invalid = .sig_invalid_input };
                    x = r;
                    if (rid & 2 != 0) {
                        const sum = @addWithOverflow(r, n);
                        if (strict and sum[1] != 0) return opaque_err;
                        x = sum[0];
                    }
                    if (x >= p) return opaque_err;
                },
            }
            if (kind == .k1) {
                const big_r = k1.Affine.fromX(k1.Fe.fromInt(x), rid & 1 != 0) orelse return opaque_err;
                const d = h.digest(msg);
                const z = modN(be(&d));
                const r_inv = k1.invModN(r);
                const ua = k1.subModN(0, k1.mulModN(z, r_inv));
                const ub = k1.mulModN(s, r_inv);
                const q = k1.mulDoubleG(ua, big_r, ub).toAffine() orelse return opaque_err;
                return .{ .ok = q.compressed() };
            }
            if (x >= r1.p_int) return opaque_err;
            const big_r = r1.Affine.fromX(r1.Fe.fromInt(x), rid & 1 != 0) orelse return opaque_err;
            const d = h.digest(msg);
            const z = modN(be(&d));
            const r_inv = r1.invModN(r);
            const ua = mulModN(z, r_inv);
            const ub = mulModN(s, r_inv);
            const q = r1.mulDoubleG(if (ua == 0) 0 else n - ua, big_r, ub).toAffine() orelse return opaque_err;
            return .{ .ok = q.compressed() };
        }
    };
}

pub const secp256k1 = Ecdsa(.k1);
pub const secp256r1 = Ecdsa(.r1);

test "secp256k1 and secp256r1 sign with std, verify here" {
    inline for (.{ .{ secp256k1, std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256 }, .{ secp256r1, std.crypto.sign.ecdsa.EcdsaP256Sha256 } }) |pair| {
        const Ours = pair[0];
        const Std = pair[1];
        const kp = try Std.KeyPair.generateDeterministic(@as([32]u8, @splat(9)));
        const msg = "zui";
        var sig = (try kp.sign(msg, null)).toBytes();
        // normalise to low s, as both Rust libraries require
        const n = Ours.n;
        var s = std.mem.readInt(u256, sig[32..64], .big);
        if (s > (n - 1) / 2) s = n - s;
        std.mem.writeInt(u256, sig[32..64], s, .big);
        const pk = kp.public_key.toCompressedSec1();
        try std.testing.expectEqual(Verdict.valid, Ours.verify(&pk, msg, &sig, .sha256));
        var bad = sig;
        bad[5] ^= 1;
        try std.testing.expect(Ours.verify(&pk, msg, &bad, .sha256) != .valid);
        // recovery finds the key for one of the ids
        var found = false;
        for (0..4) |rid| {
            var rs: [65]u8 = undefined;
            @memcpy(rs[0..64], &sig);
            rs[64] = @intCast(rid);
            if (Ours.recover(msg, &rs, .sha256)) |k| {
                if (std.mem.eql(u8, &k, &pk)) found = true;
            }
        }
        try std.testing.expect(found);
    }
}

test "secp256r1 recovery: r + n past 2^256 wraps (legacy) or fails (strict, protocol 142)" {
    const E = secp256r1;
    // r with r < n and r + n >= 2^256: the legacy x is (r + n) mod 2^256 = k, small.
    const wrap_at: u256 = 0 -% E.n; // 2^256 - n
    var found = false;
    var k: u256 = 1;
    while (k < 200) : (k += 1) {
        var sig: [65]u8 = undefined;
        std.mem.writeInt(u256, sig[0..32], wrap_at + k, .big);
        std.mem.writeInt(u256, sig[32..64], 7, .big);
        sig[64] = 2; // x reduced, y even
        const legacy = E.recoverSlicesMode("zui", &sig, .sha256, false);
        const strict = E.recoverSlicesMode("zui", &sig, .sha256, true);
        try std.testing.expect(strict == .invalid);
        try std.testing.expectEqual(@as(@TypeOf(strict.invalid), .recover_general_opaque_error), strict.invalid);
        if (legacy == .ok) found = true;
    }
    try std.testing.expect(found);
    // below the wrap point both modes agree
    var sig: [65]u8 = undefined;
    std.mem.writeInt(u256, sig[0..32], 12345, .big);
    std.mem.writeInt(u256, sig[32..64], 7, .big);
    sig[64] = 2;
    const a = E.recoverSlicesMode("zui", &sig, .sha256, false);
    const b = E.recoverSlicesMode("zui", &sig, .sha256, true);
    try std.testing.expectEqualDeep(a, b);
}
