//! Optimal ate pairing on BN254, following arkworks 0.4 (`ark_ec::models::bn`) step for step:
//! the same NAF loop (6x+2), homogeneous-projective line coefficients for a D-type twist, the
//! two Frobenius additions, and the same final-exponentiation chain. Final exponentiation
//! output is therefore identical to arkworks' `Bn254::pairing(..).0` byte for byte, which is
//! what Groth16 `alpha_g1_beta_g2` compares against.
const std = @import("std");
const fp = @import("fp.zig");
const tower = @import("tower.zig");
const curve = @import("curve.zig");
const Fq = fp.Fq;
const Fq2 = tower.Fq2;
const Fq12 = tower.Fq12;
const G1 = curve.G1;
const G2 = curve.G2;

pub const x_param: u64 = 4965661367192848881;

/// arkworks `ATE_LOOP_COUNT` for BN254 (NAF of 6x+2, least significant digit first).
pub const ate_loop_count = [_]i2{
    0, 0, 0, 1, 0, 1, 0, -1, 0, 0, 1, -1, 0, 0, 1, 0, 0, 1, 1, 0, -1, 0, 0, 1, 0, -1, 0, 0, 0,
    0, 1, 1, 1, 0, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, -1, 0, 0, 0, 1, 1, 0,
    -1, 0, 0, 1, 0, 1, 1,
};

const nonzero_digits = blk: {
    var n: usize = 0;
    for (ate_loop_count[0 .. ate_loop_count.len - 1]) |d| {
        if (d != 0) n += 1;
    }
    break :blk n;
};

/// Number of line coefficients for one G2 point.
pub const coeff_count = (ate_loop_count.len - 1) + nonzero_digits + 2;

pub const EllCoeff = struct { c0: Fq2, c1: Fq2, c2: Fq2 };

/// arkworks `G2Prepared`: precomputed line coefficients (no allocation, fixed size).
pub const G2Prepared = struct {
    coeffs: [coeff_count]EllCoeff,
    infinity: bool,

    pub fn init(q: G2) G2Prepared {
        var out: G2Prepared = undefined;
        if (q.infinity) {
            out.infinity = true;
            return out;
        }
        out.infinity = false;
        const two_inv = comptime Fq.fromInt((fp.q_modulus + 1) / 2);
        var r: HomProjective = .{ .x = q.x, .y = q.y, .z = Fq2.one };
        const nq = q.neg();
        var n: usize = 0;
        var i: usize = ate_loop_count.len - 1;
        while (i > 0) {
            i -= 1;
            out.coeffs[n] = r.double(two_inv);
            n += 1;
            switch (ate_loop_count[i]) {
                1 => {
                    out.coeffs[n] = r.addMixed(q);
                    n += 1;
                },
                -1 => {
                    out.coeffs[n] = r.addMixed(nq);
                    n += 1;
                },
                else => {},
            }
        }
        const q1 = mulByChar(q);
        var q2 = mulByChar(q1);
        q2.y = q2.y.neg();
        out.coeffs[n] = r.addMixed(q1);
        n += 1;
        out.coeffs[n] = r.addMixed(q2);
        n += 1;
        std.debug.assert(n == coeff_count);
        return out;
    }
};

const twist_mul_by_q_x: Fq2 = .{
    .c0 = Fq.fromInt(21575463638280843010398324269430826099269044274347216827212613867836435027261),
    .c1 = Fq.fromInt(10307601595873709700152284273816112264069230130616436755625194854815875713954),
};
const twist_mul_by_q_y: Fq2 = .{
    .c0 = Fq.fromInt(2821565182194536844548159561693502659359617185244120367078079554186484126554),
    .c1 = Fq.fromInt(3505843767911556378687030309984248845540243509899259641013678093033130930403),
};

fn mulByChar(r: G2) G2 {
    return .{ .x = r.x.frob(1).mul(twist_mul_by_q_x), .y = r.y.frob(1).mul(twist_mul_by_q_y), .infinity = r.infinity };
}

const HomProjective = struct {
    x: Fq2,
    y: Fq2,
    z: Fq2,

    fn double(s: *HomProjective, two_inv: Fq) EllCoeff {
        const a = s.x.mul(s.y).mulFq(two_inv);
        const b = s.y.sq();
        const c = s.z.sq();
        const e = curve.g2_b.mul(c.dbl().add(c));
        const f = e.dbl().add(e);
        const g = b.add(f).mulFq(two_inv);
        const h = s.y.add(s.z).sq().sub(b.add(c));
        const i = e.sub(b);
        const j = s.x.sq();
        const e_sq = e.sq();
        s.x = a.mul(b.sub(f));
        s.y = g.sq().sub(e_sq.dbl().add(e_sq));
        s.z = b.mul(h);
        return .{ .c0 = h.neg(), .c1 = j.dbl().add(j), .c2 = i };
    }

    fn addMixed(s: *HomProjective, q: G2) EllCoeff {
        const theta = s.y.sub(q.y.mul(s.z));
        const lambda = s.x.sub(q.x.mul(s.z));
        const c = theta.sq();
        const d = lambda.sq();
        const e = lambda.mul(d);
        const f = s.z.mul(c);
        const g = s.x.mul(d);
        const h = e.add(f).sub(g.dbl());
        s.x = lambda.mul(h);
        s.y = theta.mul(g.sub(h)).sub(e.mul(s.y));
        s.z = s.z.mul(e);
        const j = theta.mul(q.x).sub(lambda.mul(q.y));
        return .{ .c0 = lambda, .c1 = theta.neg(), .c2 = j };
    }
};

inline fn ell(f: *Fq12, c: EllCoeff, p: G1) void {
    f.* = f.mulBy034(c.c0.mulFq(p.y), c.c1.mulFq(p.x), c.c2);
}

pub const Pair = struct { p: G1, q: *const G2Prepared };

/// Product of Miller loops (arkworks `multi_miller_loop`); pairs with an identity point are
/// skipped exactly as arkworks filters them.
pub fn multiMillerLoop(pairs: []const Pair) Fq12 {
    var buf: [8]Pair = undefined;
    var n: usize = 0;
    for (pairs) |pr| {
        if (pr.p.infinity or pr.q.infinity) continue;
        buf[n] = pr;
        n += 1;
    }
    const live = buf[0..n];
    var f = Fq12.one;
    var idx: usize = 0;
    var i: usize = ate_loop_count.len - 1;
    while (i >= 1) : (i -= 1) {
        if (i != ate_loop_count.len - 1) f = f.sq();
        for (live) |pr| ell(&f, pr.q.coeffs[idx], pr.p);
        idx += 1;
        const bit = ate_loop_count[i - 1];
        if (bit != 0) {
            for (live) |pr| ell(&f, pr.q.coeffs[idx], pr.p);
            idx += 1;
        }
    }
    for (live) |pr| ell(&f, pr.q.coeffs[idx], pr.p);
    idx += 1;
    for (live) |pr| ell(&f, pr.q.coeffs[idx], pr.p);
    return f;
}

/// f^x on the cyclotomic subgroup (x = BN parameter, positive).
fn cyclotomicExpX(f: Fq12) Fq12 {
    var r = Fq12.one;
    var started = false;
    var bit: u7 = 64;
    while (bit > 0) {
        bit -= 1;
        if (started) r = r.cyclotomicSq();
        if ((x_param >> @intCast(bit)) & 1 == 1) {
            r = if (started) r.mul(f) else f;
            started = true;
        }
    }
    return r;
}

fn expByNegX(f: Fq12) Fq12 {
    return cyclotomicExpX(f).conj();
}

/// arkworks `BnConfig::final_exponentiation`. Null when f is zero.
pub fn finalExponentiation(f: Fq12) ?Fq12 {
    if (f.isZero()) return null;
    const f1 = f.conj();
    var f2 = f.inverse();
    var r = f1.mul(f2);
    f2 = r;
    r = r.frob(2);
    r = r.mul(f2);

    const y0 = expByNegX(r);
    const y1 = y0.cyclotomicSq();
    const y2 = y1.cyclotomicSq();
    var y3 = y2.mul(y1);
    const y4 = expByNegX(y3);
    const y5 = y4.cyclotomicSq();
    var y6 = expByNegX(y5);
    y3 = y3.conj();
    y6 = y6.conj();
    const y7 = y6.mul(y4);
    var y8 = y7.mul(y3);
    const y9 = y8.mul(y1);
    const y10 = y8.mul(y4);
    const y11 = y10.mul(r);
    var y12 = y9;
    y12 = y12.frob(1);
    const y13 = y12.mul(y11);
    y8 = y8.frob(2);
    const y14 = y8.mul(y13);
    r = r.conj();
    var y15 = r.mul(y9);
    y15 = y15.frob(3);
    const y16 = y15.mul(y14);
    return y16;
}

pub fn pairing(p: G1, q: G2) Fq12 {
    const qp = G2Prepared.init(q);
    return finalExponentiation(multiMillerLoop(&.{.{ .p = p, .q = &qp }})).?;
}

test "bilinearity" {
    const g1 = curve.g1_generator;
    const g2 = curve.g2_generator;
    const e = pairing(g1, g2);
    try std.testing.expect(!e.isOne());
    const a = curve.G1J.mulLimbs(g1, &.{ 6, 0, 0, 0 }).toAffine();
    const b = curve.G2J.mulLimbs(g2, &.{ 7, 0, 0, 0 }).toAffine();
    const lhs = pairing(a, b);
    var rhs = Fq12.one;
    for (0..42) |_| rhs = rhs.mul(e);
    try std.testing.expect(lhs.eql(rhs));
    // e(a, b) * e(-a, b) == 1 via one multi-Miller loop
    const bp = G2Prepared.init(b);
    const f = multiMillerLoop(&.{ .{ .p = a, .q = &bp }, .{ .p = a.neg(), .q = &bp } });
    try std.testing.expect(finalExponentiation(f).?.isOne());
}
