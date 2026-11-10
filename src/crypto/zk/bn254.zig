//! BN254: fields, tower, groups, pairing (arkworks 0.4 compatible encodings and results).
pub const fp = @import("bn254/fp.zig");
pub const tower = @import("bn254/tower.zig");
pub const curve = @import("bn254/curve.zig");
pub const pairing_ = @import("bn254/pairing.zig");

pub const Fq = fp.Fq;
pub const Fr = fp.Fr;
pub const Fq2 = tower.Fq2;
pub const Fq6 = tower.Fq6;
pub const Fq12 = tower.Fq12;
pub const G1 = curve.G1;
pub const G2 = curve.G2;
pub const G1J = curve.G1J;
pub const G2J = curve.G2J;
pub const G2Prepared = pairing_.G2Prepared;
pub const multiMillerLoop = pairing_.multiMillerLoop;
pub const finalExponentiation = pairing_.finalExponentiation;
pub const pairing = pairing_.pairing;

/// Product of pairings equals one.
pub fn pairingCheck(pairs: []const pairing_.Pair) bool {
    const f = multiMillerLoop(pairs);
    const e = finalExponentiation(f) orelse return false;
    return e.isOne();
}

test {
    @import("std").testing.refAllDecls(@This());
    _ = fp;
    _ = tower;
    _ = curve;
    _ = pairing_;
}
