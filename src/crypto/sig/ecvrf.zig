//! ECVRF over ristretto255 exactly as fastcrypto `vrf::ecvrf` (suite string "sui_vrf"), and the
//! byte-level checks of the `sui::ecvrf::ecvrf_verify` native (sui-move-natives crypto/ecvrf.rs).
//!
//! Wire forms (BCS, as the native parses them):
//!   public key  32 bytes: a canonical Ristretto encoding
//!   proof       80 bytes: gamma (Ristretto, 32) || c (16) || s (canonical scalar, 32)
//!   output      64 bytes: SHA-512("sui_vrf" || 0x03 || gamma || 0x00)
//!
//! `prove` is constant time in the secret key and nonce (mulCT / mulBaseCT, std scalar
//! arithmetic); `verify` works on public data and is variable time.
const std = @import("std");
const hash = @import("hash");
const ed = @import("ed25519.zig");
const rst = @import("ristretto255.zig");
const dit = @import("dit.zig");

const Ristretto = rst.Ristretto;
const Sha512 = hash.Sha512;
const scalar = std.crypto.ecc.Edwards25519.scalar;

const suite = "sui_vrf";
const dst = "ECVRF_ristretto255_XMD:SHA-512_R255MAP_RO_sui_vrf";

pub const proof_len = 80;

fn encodeToCurve(pk_bytes: *const [32]u8, alpha: []const u8) Ristretto {
    return Ristretto.hashWithDst(&.{ pk_bytes, alpha }, dst);
}

fn challenge(points: [5]*const [32]u8) [16]u8 {
    var h = Sha512.init();
    h.update(suite);
    h.update(&.{0x02});
    for (points) |p| h.update(p);
    h.update(&.{0x00});
    var d: [64]u8 = undefined;
    h.final(&d);
    return d[0..16].*;
}

fn challengeScalar(c: *const [16]u8) [32]u8 {
    var b: [32]u8 = @splat(0);
    @memcpy(b[0..16], c);
    return b; // < 2^128 < l: already reduced
}

/// The 64-byte VRF output of a proof (fastcrypto `ECVRFProof::to_hash`).
pub fn outputFromProof(proof: *const [proof_len]u8) [64]u8 {
    var h = Sha512.init();
    h.update(suite);
    h.update(&.{0x03});
    h.update(proof[0..32]);
    h.update(&.{0x00});
    var d: [64]u8 = undefined;
    h.final(&d);
    return d;
}

pub const KeyPair = struct {
    sk: [32]u8,
    pk: [32]u8,

    /// `sk` is the BCS ECVRFPrivateKey: a canonical scalar (< l). Null otherwise.
    pub fn fromSecret(sk: *const [32]u8) ?KeyPair {
        if (!ed.isCanonicalScalar(sk)) return null;
        const g = dit.Guard.enter();
        defer g.leave();
        return .{ .sk = sk.*, .pk = (Ristretto{ .p = ed.mulBaseCT(sk) }).encode() };
    }

    /// fastcrypto `ECVRFKeyPair::prove` (proof in its BCS form). Constant time.
    pub fn prove(kp: *const KeyPair, alpha: []const u8) [proof_len]u8 {
        const g = dit.Guard.enter();
        defer g.leave();
        const h = encodeToCurve(&kp.pk, alpha);
        const h_bytes = h.encode();
        const gamma = (Ristretto{ .p = ed.mulCT(h.p, &kp.sk) }).encode();
        // nonce: SHA-512(sk)[32..64] || h_string
        var hs: [64]u8 = undefined;
        Sha512.hash(&kp.sk, &hs);
        var n = Sha512.init();
        n.update(hs[32..64]);
        n.update(&h_bytes);
        var kd: [64]u8 = undefined;
        n.final(&kd);
        const k = scalar.reduce64(kd);
        const kb = (Ristretto{ .p = ed.mulBaseCT(&k) }).encode();
        const kh = (Ristretto{ .p = ed.mulCT(h.p, &k) }).encode();
        const c = challenge(.{ &kp.pk, &h_bytes, &gamma, &kb, &kh });
        const s = scalar.mulAdd(challengeScalar(&c), kp.sk, k);
        std.crypto.secureZero(u8, &hs);
        std.crypto.secureZero(u8, &kd);
        var out: [proof_len]u8 = undefined;
        out[0..32].* = gamma;
        out[32..48].* = c;
        out[48..80].* = s;
        return out;
    }

    /// fastcrypto `VRFKeyPair::output`: (output, proof).
    pub fn output(kp: *const KeyPair, alpha: []const u8) struct { [64]u8, [proof_len]u8 } {
        const pf = kp.prove(alpha);
        return .{ outputFromProof(&pf), pf };
    }
};

/// Result of the `sui::ecvrf::ecvrf_verify` native: an abort code for malformed inputs, else the
/// boolean it returns.
pub const NativeResult = enum {
    /// INVALID_ECVRF_HASH_LENGTH: hash is not 64 bytes
    err_hash,
    /// INVALID_ECVRF_PUBLIC_KEY: bcs::from_bytes::<ECVRFPublicKey> failed
    err_pk,
    /// INVALID_ECVRF_PROOF: bcs::from_bytes::<ECVRFProof> failed
    err_proof,
    valid,
    invalid,

    pub fn truthName(r: NativeResult) []const u8 {
        return switch (r) {
            .err_hash => "err:hash",
            .err_pk => "err:pk",
            .err_proof => "err:proof",
            .valid => "true",
            .invalid => "false",
        };
    }
};

/// fastcrypto `ECVRFProof::verify` on parsed inputs.
fn verifyParsed(pk_bytes: *const [32]u8, pk: Ristretto, alpha: []const u8, gamma: Ristretto, gamma_bytes: *const [32]u8, c: *const [16]u8, s: *const [32]u8) bool {
    if (pk.isIdentity()) return false; // InvalidInput
    const h = encodeToCurve(pk_bytes, alpha);
    const h_bytes = h.encode();
    const neg_c = scalar.neg(challengeScalar(c));
    const u = (Ristretto{ .p = ed.doubleMulVartime(s, ed.basepoint, &neg_c, pk.p) }).encode();
    const v = (Ristretto{ .p = ed.doubleMulVartime(s, h.p, &neg_c, gamma.p) }).encode();
    const c2 = challenge(.{ pk_bytes, &h_bytes, gamma_bytes, &u, &v });
    return std.mem.eql(u8, &c2, c);
}

/// The `sui::ecvrf::ecvrf_verify(hash, alpha_string, public_key, proof)` native, byte for byte.
pub fn verifyNative(hash_bytes: []const u8, alpha: []const u8, pk_bytes: []const u8, proof: []const u8) NativeResult {
    if (hash_bytes.len != 64) return .err_hash;
    if (pk_bytes.len != 32) return .err_pk;
    const pk = Ristretto.decode(pk_bytes[0..32]) orelse return .err_pk;
    if (proof.len != proof_len) return .err_proof;
    const gamma = Ristretto.decode(proof[0..32]) orelse return .err_proof;
    if (!ed.isCanonicalScalar(proof[48..80])) return .err_proof;
    if (!verifyParsed(pk_bytes[0..32], pk, alpha, gamma, proof[0..32], proof[32..48], proof[48..80])) return .invalid;
    if (!std.mem.eql(u8, &outputFromProof(proof[0..proof_len]), hash_bytes)) return .invalid;
    return .valid;
}

/// fastcrypto `VRFProof::verify` (no output check). `proof` in BCS form; malformed is false.
pub fn verify(pk_bytes: *const [32]u8, alpha: []const u8, proof: *const [proof_len]u8) bool {
    const pk = Ristretto.decode(pk_bytes) orelse return false;
    const gamma = Ristretto.decode(proof[0..32]) orelse return false;
    if (!ed.isCanonicalScalar(proof[48..80])) return false;
    return verifyParsed(pk_bytes, pk, alpha, gamma, proof[0..32], proof[32..48], proof[48..80]);
}

test "prove then verify, and a flipped proof fails" {
    var sk: [32]u8 = @splat(7);
    sk[31] = 1;
    const kp = KeyPair.fromSecret(&sk).?;
    const o = kp.output("zui");
    try std.testing.expectEqual(NativeResult.valid, verifyNative(&o[0], "zui", &kp.pk, &o[1]));
    var bad = o[1];
    bad[40] ^= 1;
    try std.testing.expectEqual(NativeResult.invalid, verifyNative(&o[0], "zui", &kp.pk, &bad));
    try std.testing.expectEqual(NativeResult.invalid, verifyNative(&o[0], "zuj", &kp.pk, &o[1]));
}

// dudect-style check (as for Ed25519 signing in ed25519.zig) on ECVRF prove: fixed secret key
// vs random secret keys, same alpha; Welch's t after a 90th-percentile crop must stay below 10.
test "dudect: ecvrf prove time does not depend on the secret key" {
    const builtin = @import("builtin");
    const io = std.testing.io;
    const n: usize = if (builtin.mode == .debug) 1000 else 200_000;
    const gpa = std.testing.allocator;
    const times = try gpa.alloc(u64, n);
    defer gpa.free(times);
    const class = try gpa.alloc(u1, n);
    defer gpa.free(class);
    var prng: std.Random.DefaultPrng = .init(0x7a75_692d_7672_6664);
    const rnd = prng.random();
    var fixed: [32]u8 = @splat(0x42);
    fixed[31] = 0x0a;
    var sink: u8 = 0;
    for (times, class) |*t, *c| {
        c.* = rnd.int(u1);
        var sk: [32]u8 = fixed;
        if (c.* == 1) {
            rnd.bytes(&sk);
            sk[31] &= 0x0f;
        }
        const kp = KeyPair.fromSecret(&sk).?;
        const t0 = std.Io.Timestamp.now(io, .awake);
        const pf = kp.prove("zui dudect alpha");
        const t1 = std.Io.Timestamp.now(io, .awake);
        sink ^= pf[0];
        t.* = @intCast(t0.durationTo(t1).nanoseconds);
    }
    std.mem.doNotOptimizeAway(sink);
    const sorted = try gpa.dupe(u64, times);
    defer gpa.free(sorted);
    std.mem.sort(u64, sorted, {}, std.sort.asc(u64));
    const cut = sorted[sorted.len * 9 / 10];
    var cnt: [2]f64 = .{ 0, 0 };
    var mean: [2]f64 = .{ 0, 0 };
    var m2: [2]f64 = .{ 0, 0 };
    for (times, class) |t, c| {
        if (t > cut) continue;
        const x: f64 = @floatFromInt(t);
        cnt[c] += 1;
        const d = x - mean[c];
        mean[c] += d / cnt[c];
        m2[c] += d * (x - mean[c]);
    }
    const t_stat = (mean[0] - mean[1]) / @sqrt(m2[0] / (cnt[0] - 1) / cnt[0] + m2[1] / (cnt[1] - 1) / cnt[1]);
    if (dudectVerbose() or @abs(t_stat) >= 10) std.debug.print("dudect ecvrf prove: n={d} t={d:.3} mean0={d:.0}ns mean1={d:.0}ns\n", .{ n, t_stat, mean[0], mean[1] });
    try std.testing.expect(@abs(t_stat) < 10);
}

/// ZUI_DUDECT=1 prints the t statistics (the build runner fails a test that writes to stderr).
fn dudectVerbose() bool {
    return std.testing.environ.containsUnempty(std.testing.allocator, "ZUI_DUDECT") catch false;
}
