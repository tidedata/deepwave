//! bls: BLS12-381: Fp..Fp12, G1/G2, pairing, hash-to-curve, min-sig signatures, aggregation, group ops.
//! Owner lane: crypto-bls. Interface: CONTRACTS.md. Only the crypto-bls lane edits files in src/crypto/bls/.
const std = @import("std");

pub const field = @import("field.zig");
pub const tower = @import("tower.zig");
pub const curve = @import("curve.zig");
pub const encoding = @import("encoding.zig");
pub const hash_to_curve = @import("hash_to_curve.zig");
pub const pairing = @import("pairing.zig");
pub const sig = @import("sig.zig");
pub const group_ops = @import("group_ops.zig");
const microbench = @import("microbench.zig");

// CONTRACTS.md 5.5 surface
pub const Fp = field.Fp;
pub const Fr = field.Fr;
pub const Fp2 = tower.Fp2;
pub const Fp6 = tower.Fp6;
pub const Fp12 = tower.Fp12;
pub const Gt = tower.Fp12;
pub const G1Affine = curve.G1.Affine;
pub const G1Projective = curve.G1.Point;
pub const G2Affine = curve.G2.Affine;
pub const G2Projective = curve.G2.Point;
pub const min_sig_dst = sig.min_sig_dst;
pub const PublicKey = sig.PublicKey;
pub const Signature = sig.Signature;
pub const SecretKey = sig.SecretKey;
pub const PreparedCommittee = sig.PreparedCommittee;
pub const CertVerdict = sig.CertVerdict;
pub const verify = sig.verify;
pub const aggregate = sig.aggregate;
pub const fastAggregateVerify = sig.fastAggregateVerify;
pub const aggregateVerify = sig.aggregateVerify;

pub fn hashToG1(msg: []const u8, dst: []const u8) G1Affine {
    return hash_to_curve.hashToG1(msg, dst).toAffine();
}

pub const PairingInput = struct { G1Affine, G2Affine };

/// prod e(P_i, Q_i) == 1 (one shared Miller loop, one final exponentiation).
pub fn pairingCheck(pairs: []const PairingInput) bool {
    return @import("core").cpu.call("bls_pairing_check", pairingCheckImpl, .{pairs});
}

/// prod e(P_i, Q_i) == want for at most `pairing.max_pairs` pairs (one shared Miller loop, one
/// final exponentiation).
pub fn pairingProductIs(pairs: []const PairingInput, want: *const Fp12) bool {
    return @import("core").cpu.call("bls_pairing_product_is", pairingProductIsImpl, .{ pairs, want });
}

pub fn pairingProductIsImpl(pairs: []const PairingInput, want: *const Fp12) bool {
    if (pairs.len > pairing.max_pairs) return false;
    var buf: [pairing.max_pairs]pairing.Pair = undefined;
    for (pairs, buf[0..pairs.len]) |pr, *b| b.* = .{ .p = pr[0], .q = pr[1] };
    return pairing.finalExp(pairing.millerLoop(buf[0..pairs.len], &.{})).eql(want.*);
}

pub fn pairingCheckImpl(pairs: []const PairingInput) bool {
    var f = Fp12.one;
    var buf: [pairing.max_pairs]pairing.Pair = undefined;
    var i: usize = 0;
    while (i < pairs.len) {
        const n = @min(pairing.max_pairs, pairs.len - i);
        for (0..n) |j| buf[j] = .{ .p = pairs[i + j][0], .q = pairs[i + j][1] };
        f = f.mul(pairing.millerLoop(buf[0..n], &.{}));
        i += n;
    }
    return pairing.finalExp(f).isOne();
}
pub const conformance = @import("conformance.zig");

test {
    std.testing.refAllDecls(@This());
    _ = microbench;
}
