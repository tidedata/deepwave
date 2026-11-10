//! The BLS12-381 extension tower, laid out as blst lays it out:
//!   Fp2  = Fp[u]  / (u^2 + 1)
//!   Fp6  = Fp2[v] / (v^3 - (u + 1))
//!   Fp12 = Fp6[w] / (w^2 - v)
//! Formulas follow blst's fp12_tower.c (non-x2 variants) so Miller-loop and final-exponentiation
//! intermediates are the same field elements blst computes. Constant time throughout, except
//! `Fp2.sqrt`'s final verification, which only reveals whether a square root exists.
const std = @import("std");
const field = @import("field.zig");
const consts = @import("consts.zig");
pub const Fp = field.Fp;

/// blst's lazy (x2) tower for Fp6/Fp12 products and the cyclotomic squaring. On AArch64 it is
/// 15% faster (Miller loop 206 -> 175 us, M5 Pro); on x86-64 with the mulx kernels it measured
/// no faster than the eager formulas (r7i, box 3), so x86-64 keeps those.
const lazy = @import("builtin").cpu.arch != .x86_64;

pub const Fp2 = struct {
    c0: Fp,
    c1: Fp,

    pub const zero: Fp2 = .{ .c0 = Fp.zero, .c1 = Fp.zero };
    pub const one: Fp2 = .{ .c0 = Fp.one, .c1 = Fp.zero };

    pub fn fromInts(comptime v: [2]u384) Fp2 {
        return .{ .c0 = Fp.fromInt(v[0]), .c1 = Fp.fromInt(v[1]) };
    }

    pub inline fn add(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }
    pub inline fn sub(a: Fp2, b: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }
    pub inline fn dbl(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.dbl(), .c1 = a.c1.dbl() };
    }
    pub inline fn neg(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }
    pub inline fn conj(a: Fp2) Fp2 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }
    pub inline fn mul3(a: Fp2) Fp2 {
        return a.dbl().add(a);
    }
    /// Karatsuba with lazy reduction: three double-width products, two Montgomery reductions.
    /// Results are fully reduced, so the value equals the eagerly reduced formula's.
    pub fn mul(a: Fp2, b: Fp2) Fp2 {
        const t0 = Fp.mulWide(a.c0.l, b.c0.l);
        const t1 = Fp.mulWide(a.c1.l, b.c1.l);
        const t2 = Fp.mulWide(Fp.addRaw(a.c0, a.c1), Fp.addRaw(b.c0, b.c1)); // < 4p^2
        return .{
            .c0 = Fp.redc(Fp.subWideModM2(t0, t1)),
            .c1 = Fp.redc(Fp.subWide(t2, Fp.addWide(t0, t1))), // a0 b1 + a1 b0 < 2p^2
        };
    }
    /// Unreduced product (blst mul_fp2x2): both halves in [0, p R).
    pub inline fn mulX2(a: Fp2, b: Fp2) Fp2x2 {
        const t0 = Fp.mulWide(a.c0.l, b.c0.l);
        const t1 = Fp.mulWide(a.c1.l, b.c1.l);
        const t2 = Fp.mulWide(Fp.addRaw(a.c0, a.c1), Fp.addRaw(b.c0, b.c1)); // < 4p^2
        return .{ .c0 = Fp.subWideModMR(t0, t1), .c1 = Fp.subWide(t2, Fp.addWide(t0, t1)) };
    }
    /// Unreduced square (blst sqr_fp2x2): (a0 + a1)(a0 - a1) and 2 a0 a1, both below 4p^2.
    pub inline fn sqrX2(a: Fp2) Fp2x2 {
        return .{
            .c0 = Fp.mulWide(Fp.addRaw(a.c0, a.c1), Fp.subRawPlusM(a.c0, a.c1)),
            .c1 = Fp.mulWide(Fp.addRaw(a.c0, a.c0), a.c1.l),
        };
    }
    pub fn sqr(a: Fp2) Fp2 {
        const t0 = a.c0.add(a.c1).mul(a.c0.sub(a.c1));
        const t1 = a.c0.mul(a.c1);
        return .{ .c0 = t0, .c1 = t1.dbl() };
    }
    pub inline fn mulFp(a: Fp2, b: Fp) Fp2 {
        return .{ .c0 = a.c0.mul(b), .c1 = a.c1.mul(b) };
    }
    /// a * (u + 1)
    pub inline fn mulByXi(a: Fp2) Fp2 {
        return .{ .c0 = a.c0.sub(a.c1), .c1 = a.c0.add(a.c1) };
    }
    pub inline fn isZero(a: Fp2) bool {
        return a.c0.isZero() and a.c1.isZero();
    }
    pub inline fn eql(a: Fp2, b: Fp2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub inline fn select(c: bool, b: Fp2, a: Fp2) Fp2 {
        return .{ .c0 = Fp.select(c, b.c0, a.c0), .c1 = Fp.select(c, b.c1, a.c1) };
    }
    pub inline fn condNeg(a: Fp2, c: bool) Fp2 {
        return select(c, a.neg(), a);
    }
    pub fn inv(a: Fp2) Fp2 {
        const t = a.c0.sqr().add(a.c1.sqr()).inv();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).neg() };
    }
    /// Variable-time inverse, public values only.
    pub fn invVartime(a: Fp2) Fp2 {
        const t = a.c0.sqr().add(a.c1.sqr()).invVartime();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).neg() };
    }
    pub inline fn frobenius(a: Fp2) Fp2 {
        return a.conj();
    }

    /// a^e for a public exponent given as limbs.
    pub fn powLimbs(a: Fp2, comptime e: anytype) Fp2 {
        const ex = e;
        var acc = one;
        var started = false;
        var limb: usize = ex.len;
        while (limb > 0) {
            limb -= 1;
            var bit: usize = 64;
            while (bit > 0) {
                bit -= 1;
                if (started) acc = acc.sqr();
                if ((ex[limb] >> @intCast(bit)) & 1 == 1) {
                    acc = if (started) acc.mul(a) else a;
                    started = true;
                }
            }
        }
        return acc;
    }

    const p_minus_3_div_4 = limbs6((consts.p - 3) / 4);
    const p_minus_1_div_2 = limbs6((consts.p - 1) / 2);

    const p_plus_1_div_4 = limbs6((consts.p + 1) / 4);
    const half_fp = Fp.fromInt((consts.p + 1) / 2);

    fn sqrtFp(x: Fp) ?Fp {
        const s = x.powLimbs(p_plus_1_div_4);
        return if (s.sqr().eql(x)) s else null;
    }

    /// A square root, or null. Public inputs only (decompression, hash-to-curve). Callers fix
    /// the sign themselves, so any root will do. Uses the norm: with alpha = sqrt(a0^2 + a1^2)
    /// and delta = (a0 +- alpha) / 2 a square, sqrt(a) = sqrt(delta) + a1 / (2 sqrt(delta)) u,
    /// where r = delta^((p-3)/4) gives both sqrt(delta) = delta r and 1 / sqrt(delta) = r.
    pub fn sqrt(a: Fp2) ?Fp2 {
        if (a.c1.isZero()) {
            if (sqrtFp(a.c0)) |s| return .{ .c0 = s, .c1 = Fp.zero };
            // -1 is not a square mod p, so -a0 is: sqrt(a0) = sqrt(-a0) u
            const s = sqrtFp(a.c0.neg()) orelse return null;
            return .{ .c0 = Fp.zero, .c1 = s };
        }
        // a is a square in Fp2 iff its norm is a square in Fp
        const alpha = sqrtFp(a.c0.sqr().add(a.c1.sqr())) orelse return null;
        const delta = a.c0.add(alpha).mul(half_fp);
        const r = delta.powLimbs(p_minus_3_div_4);
        // delta r^2 = 1 when delta is a square. Otherwise delta r^2 = -1 and the other
        // candidate delta' = (a0 - alpha) / 2 = -a1^2 / (4 delta) is the square, with
        // sqrt(delta') = -(a1 / 2) r and 1 / sqrt(delta') = 2 delta r / a1 (blst's
        // sqrt_align_fp2 idea): x = (a1 / 2) r - (delta r) u, no second exponentiation.
        return sqrtFinish(a, delta, r);
    }

    fn sqrtFinish(a: Fp2, delta: Fp, r: Fp) ?Fp2 {
        const dr = delta.mul(r);
        const a1r = a.c1.mul(half_fp).mul(r);
        const x: Fp2 = if (dr.mul(r).eql(Fp.one)) .{ .c0 = dr, .c1 = a1r } else .{ .c0 = a1r, .c1 = dr.neg() };
        if (x.sqr().eql(a)) return x;
        return sqrtGeneric(a);
    }

    /// `sqrt` of two elements at once: the same roots, with the two elements' Fp
    /// exponentiations interleaved (independent chains the CPU overlaps).
    pub fn sqrt2(a: Fp2, b: Fp2) [2]?Fp2 {
        if (a.c1.isZero() or b.c1.isZero()) return .{ a.sqrt(), b.sqrt() };
        const na = a.c0.sqr().add(a.c1.sqr());
        const nb = b.c0.sqr().add(b.c1.sqr());
        const al = Fp.powLimbs2(na, nb, p_plus_1_div_4);
        const ok_a = al[0].sqr().eql(na);
        const ok_b = al[1].sqr().eql(nb);
        const da = if (ok_a) a.c0.add(al[0]).mul(half_fp) else Fp.one;
        const db = if (ok_b) b.c0.add(al[1]).mul(half_fp) else Fp.one;
        const r = Fp.powLimbs2(da, db, p_minus_3_div_4);
        return .{
            if (ok_a) sqrtFinish(a, da, r[0]) else null,
            if (ok_b) sqrtFinish(b, db, r[1]) else null,
        };
    }

    /// A square root (Adj and Rodriguez-Henriquez, Algorithm 9, p = 3 mod 4), or null.
    pub fn sqrtGeneric(a: Fp2) ?Fp2 {
        const a1 = a.powLimbs(p_minus_3_div_4);
        const alpha = a1.sqr().mul(a);
        const x0 = a1.mul(a);
        const minus_one: Fp2 = .{ .c0 = Fp.one.neg(), .c1 = Fp.zero };
        const x = if (alpha.eql(minus_one))
            Fp2.mul(.{ .c0 = Fp.zero, .c1 = Fp.one }, x0)
        else
            alpha.add(one).powLimbs(p_minus_1_div_2).mul(x0);
        if (!x.sqr().eql(a)) return null;
        return x;
    }

    /// RFC 9380 sgn0 for m = 2.
    pub fn sgn0(a: Fp2) bool {
        const s0 = a.c0.sgn0();
        const z0 = a.c0.isZero();
        const s1 = a.c1.sgn0();
        return s0 or (z0 and s1);
    }

    /// The compressed-point sign of blst/ZCash: c1 != 0 ? c1 > (p-1)/2 : c0 > (p-1)/2.
    pub fn isLexLargest(a: Fp2) bool {
        return if (a.c1.isZero()) a.c0.isLexLargest() else a.c1.isLexLargest();
    }
};

/// An Fp2 element before Montgomery reduction (blst's vec768x): each half in [0, p R), held
/// modulo p R. `redc` gives the fully reduced Fp2.
pub const Fp2x2 = struct {
    c0: Fp.WideLimbs,
    c1: Fp.WideLimbs,

    pub inline fn add(a: Fp2x2, b: Fp2x2) Fp2x2 {
        return .{ .c0 = Fp.addWideModMR(a.c0, b.c0), .c1 = Fp.addWideModMR(a.c1, b.c1) };
    }
    pub inline fn sub(a: Fp2x2, b: Fp2x2) Fp2x2 {
        return .{ .c0 = Fp.subWideModMR(a.c0, b.c0), .c1 = Fp.subWideModMR(a.c1, b.c1) };
    }
    /// a * (u + 1)
    pub inline fn mulByXi(a: Fp2x2) Fp2x2 {
        return .{ .c0 = Fp.subWideModMR(a.c0, a.c1), .c1 = Fp.addWideModMR(a.c0, a.c1) };
    }
    pub inline fn redc(a: Fp2x2) Fp2 {
        return .{ .c0 = Fp.redc(a.c0), .c1 = Fp.redc(a.c1) };
    }
};

const Fp6x2 = [3]Fp2x2;

inline fn redc6(a: Fp6x2) Fp6 {
    return .{ .c0 = a[0].redc(), .c1 = a[1].redc(), .c2 = a[2].redc() };
}
inline fn add6x2(a: Fp6x2, b: Fp6x2) Fp6x2 {
    return .{ a[0].add(b[0]), a[1].add(b[1]), a[2].add(b[2]) };
}
inline fn sub6x2(a: Fp6x2, b: Fp6x2) Fp6x2 {
    return .{ a[0].sub(b[0]), a[1].sub(b[1]), a[2].sub(b[2]) };
}

/// blst mul_fp6x2: Karatsuba over Fp2 with every product left unreduced.
fn mul6x2(a: Fp6, b: Fp6) Fp6x2 {
    const t0 = a.c0.mulX2(b.c0);
    const t1 = a.c1.mulX2(b.c1);
    const t2 = a.c2.mulX2(b.c2);
    var r0 = a.c1.add(a.c2).mulX2(b.c1.add(b.c2)).sub(t1).sub(t2);
    r0 = r0.mulByXi().add(t0);
    const r1 = a.c0.add(a.c1).mulX2(b.c0.add(b.c1)).sub(t0).sub(t1).add(t2.mulByXi());
    const r2 = a.c0.add(a.c2).mulX2(b.c0.add(b.c2)).sub(t0).sub(t2).add(t1);
    return .{ r0, r1, r2 };
}

/// blst mul_by_xy0_fp6x2: a * (b0 + b1 v), unreduced.
fn mulBy01x2(a: Fp6, b0: Fp2, b1: Fp2) Fp6x2 {
    const t0 = a.c0.mulX2(b0);
    const t1 = a.c1.mulX2(b1);
    const r0 = a.c2.mulX2(b1).mulByXi().add(t0);
    const r1 = a.c0.add(a.c1).mulX2(b0.add(b1)).sub(t0).sub(t1);
    const r2 = a.c2.mulX2(b0).add(t1);
    return .{ r0, r1, r2 };
}

/// blst mul_by_0y0_fp6x2: a * (b v), unreduced.
fn mulBy1x2(a: Fp6, b: Fp2) Fp6x2 {
    return .{ a.c2.mulX2(b).mulByXi(), a.c0.mulX2(b), a.c1.mulX2(b) };
}

fn limbs6(comptime x: u384) [6]u64 {
    var out: [6]u64 = undefined;
    for (0..6) |i| out[i] = @truncate(x >> @intCast(64 * i));
    return out;
}

pub const Fp6 = struct {
    c0: Fp2,
    c1: Fp2,
    c2: Fp2,

    pub const zero: Fp6 = .{ .c0 = Fp2.zero, .c1 = Fp2.zero, .c2 = Fp2.zero };
    pub const one: Fp6 = .{ .c0 = Fp2.one, .c1 = Fp2.zero, .c2 = Fp2.zero };

    pub inline fn add(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }
    pub inline fn sub(a: Fp6, b: Fp6) Fp6 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }
    pub inline fn neg(a: Fp6) Fp6 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg(), .c2 = a.c2.neg() };
    }
    pub inline fn isZero(a: Fp6) bool {
        return a.c0.isZero() and a.c1.isZero() and a.c2.isZero();
    }
    pub inline fn eql(a: Fp6, b: Fp6) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1) and a.c2.eql(b.c2);
    }
    /// a * v
    pub inline fn mulByV(a: Fp6) Fp6 {
        return .{ .c0 = a.c2.mulByXi(), .c1 = a.c0, .c2 = a.c1 };
    }

    /// Lazy reduction (blst mul_fp6): 18 wide products, 6 Montgomery reductions.
    pub fn mul(a: Fp6, b: Fp6) Fp6 {
        if (lazy) return redc6(mul6x2(a, b));
        const t0 = a.c0.mul(b.c0);
        const t1 = a.c1.mul(b.c1);
        const t2 = a.c2.mul(b.c2);
        const t3 = a.c1.add(a.c2).mul(b.c1.add(b.c2)).sub(t1).sub(t2).mulByXi();
        const r1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(t0).sub(t1).add(t2.mulByXi());
        const r2 = a.c0.add(a.c2).mul(b.c0.add(b.c2)).sub(t0).sub(t2).add(t1);
        return .{ .c0 = t3.add(t0), .c1 = r1, .c2 = r2 };
    }

    pub fn sqr(a: Fp6) Fp6 {
        const s0 = a.c0.sqr();
        const m01 = a.c0.mul(a.c1).dbl();
        const m12 = a.c1.mul(a.c2).dbl();
        const s2 = a.c2.sqr();
        const r2 = a.c2.add(a.c1).add(a.c0).sqr().sub(s0).sub(s2).sub(m01).sub(m12);
        return .{ .c0 = m12.mulByXi().add(s0), .c1 = s2.mulByXi().add(m01), .c2 = r2 };
    }

    /// a * (b0 + b1 v)
    pub fn mulBy01(a: Fp6, b0: Fp2, b1: Fp2) Fp6 {
        if (lazy) return redc6(mulBy01x2(a, b0, b1));
        const t0 = a.c0.mul(b0);
        const t1 = a.c1.mul(b1);
        const t3 = a.c2.mul(b1).mulByXi();
        const r1 = a.c0.add(a.c1).mul(b0.add(b1)).sub(t0).sub(t1);
        const r2 = a.c2.mul(b0).add(t1);
        return .{ .c0 = t3.add(t0), .c1 = r1, .c2 = r2 };
    }

    /// a * (b v)
    pub fn mulBy1(a: Fp6, b: Fp2) Fp6 {
        if (lazy) return redc6(mulBy1x2(a, b));
        const t = a.c2.mul(b);
        return .{ .c0 = t.mulByXi(), .c1 = a.c0.mul(b), .c2 = a.c1.mul(b) };
    }

    pub fn inv(a: Fp6) Fp6 {
        return a.invImpl(false);
    }
    /// Variable-time inverse, public values only.
    pub fn invVartime(a: Fp6) Fp6 {
        return a.invImpl(true);
    }
    fn invImpl(a: Fp6, comptime vartime: bool) Fp6 {
        const c0 = a.c0.sqr().sub(a.c1.mul(a.c2).mulByXi());
        const c1 = a.c2.sqr().mulByXi().sub(a.c0.mul(a.c1));
        const c2 = a.c1.sqr().sub(a.c0.mul(a.c2));
        const n = c1.mul(a.c2).add(c2.mul(a.c1)).mulByXi().add(c0.mul(a.c0));
        const t = if (vartime) n.invVartime() else n.inv();
        return .{ .c0 = c0.mul(t), .c1 = c1.mul(t), .c2 = c2.mul(t) };
    }

    const c1_frob = [3]Fp2{ Fp2.fromInts(consts.frob6_c1[0]), Fp2.fromInts(consts.frob6_c1[1]), Fp2.fromInts(consts.frob6_c1[2]) };
    const c2_frob = [3]Fp{ Fp.fromInt(consts.frob6_c2[0]), Fp.fromInt(consts.frob6_c2[1]), Fp.fromInt(consts.frob6_c2[2]) };

    /// a^(p^n), n in 1..3.
    pub fn frobenius(a: Fp6, comptime n: usize) Fp6 {
        const f = struct {
            fn f2(x: Fp2) Fp2 {
                return if (n & 1 == 1) x.conj() else x;
            }
        };
        return .{
            .c0 = f.f2(a.c0),
            .c1 = f.f2(a.c1).mul(c1_frob[n - 1]),
            .c2 = f.f2(a.c2).mulFp(c2_frob[n - 1]),
        };
    }
};

pub const Fp12 = struct {
    c0: Fp6,
    c1: Fp6,

    pub const one: Fp12 = .{ .c0 = Fp6.one, .c1 = Fp6.zero };

    pub inline fn conj(a: Fp12) Fp12 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }
    pub fn eql(a: Fp12, b: Fp12) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub fn isOne(a: Fp12) bool {
        return a.eql(one);
    }

    /// Lazy reduction (blst mul_fp12): 54 wide products, 12 Montgomery reductions.
    pub fn mul(a: Fp12, b: Fp12) Fp12 {
        if (!lazy) {
            const e0 = a.c0.mul(b.c0);
            const e1 = a.c1.mul(b.c1);
            const s1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(e0).sub(e1);
            return .{ .c0 = e0.add(e1.mulByV()), .c1 = s1 };
        }
        const t0 = mul6x2(a.c0, b.c0);
        const t1 = mul6x2(a.c1, b.c1);
        const r1 = sub6x2(sub6x2(mul6x2(a.c0.add(a.c1), b.c0.add(b.c1)), t0), t1);
        // a0 b0 + a1 b1 v
        const r0: Fp6x2 = .{ t0[0].add(t1[2].mulByXi()), t0[1].add(t1[0]), t0[2].add(t1[1]) };
        return .{ .c0 = redc6(r0), .c1 = redc6(r1) };
    }

    pub fn sqr(a: Fp12) Fp12 {
        const t0 = a.c0.add(a.c1).mul(a.c0.add(a.c1.mulByV()));
        const t1 = a.c0.mul(a.c1);
        return .{ .c0 = t0.sub(t1).sub(t1.mulByV()), .c1 = t1.add(t1) };
    }

    /// a * line, line = (l0 + l1 v) + (l2 v) w  (blst's "xy00z0").
    /// Lazy reduction (blst mul_by_xy00z0_fp12): 12 Montgomery reductions.
    pub fn mulByLine(a: Fp12, l0: Fp2, l1: Fp2, l2: Fp2) Fp12 {
        if (!lazy) {
            const e0 = a.c0.mulBy01(l0, l1);
            const e1 = a.c1.mulBy1(l2);
            const s1 = a.c0.add(a.c1).mulBy01(l0, l1.add(l2)).sub(e0).sub(e1);
            return .{ .c0 = e0.add(e1.mulByV()), .c1 = s1 };
        }
        const t0 = mulBy01x2(a.c0, l0, l1);
        const t1 = mulBy1x2(a.c1, l2);
        const r1 = sub6x2(sub6x2(mulBy01x2(a.c0.add(a.c1), l0, l1.add(l2)), t0), t1);
        const r0: Fp6x2 = .{ t0[0].add(t1[2].mulByXi()), t0[1].add(t1[0]), t0[2].add(t1[1]) };
        return .{ .c0 = redc6(r0), .c1 = redc6(r1) };
    }

    pub fn inv(a: Fp12) Fp12 {
        const t = a.c0.sqr().sub(a.c1.sqr().mulByV()).inv();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).neg() };
    }
    /// Variable-time inverse, public values only.
    pub fn invVartime(a: Fp12) Fp12 {
        const t = a.c0.sqr().sub(a.c1.sqr().mulByV()).invVartime();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).neg() };
    }

    const w_frob = [3]Fp2{ Fp2.fromInts(consts.frob12_c1[0]), Fp2.fromInts(consts.frob12_c1[1]), Fp2.fromInts(consts.frob12_c1[2]) };

    /// a^(p^n), n in 1..3.
    pub fn frobenius(a: Fp12, comptime n: usize) Fp12 {
        const c1 = a.c1.frobenius(n);
        const w = w_frob[n - 1];
        return .{ .c0 = a.c0.frobenius(n), .c1 = .{ .c0 = c1.c0.mul(w), .c1 = c1.c1.mul(w), .c2 = c1.c2.mul(w) } };
    }

    /// blst sqr_fp4: three unreduced Fp2 squares, two reductions per output.
    fn sqrFp4(a0: Fp2, a1: Fp2) [2]Fp2 {
        if (!lazy) {
            const e0 = a0.sqr();
            const e1 = a1.sqr();
            return .{ e1.mulByXi().add(e0), a0.add(a1).sqr().sub(e0).sub(e1) };
        }
        const t0 = a0.sqrX2();
        const t1 = a1.sqrX2();
        return .{ t1.mulByXi().add(t0).redc(), a0.add(a1).sqrX2().sub(t0).sub(t1).redc() };
    }

    /// Granger-Scott squaring, valid in the cyclotomic subgroup (after the easy part).
    pub fn cyclotomicSqr(a: Fp12) Fp12 {
        const t0 = sqrFp4(a.c0.c0, a.c1.c1);
        const t1 = sqrFp4(a.c1.c0, a.c0.c2);
        const t2 = sqrFp4(a.c0.c1, a.c1.c2);
        var r: Fp12 = undefined;
        r.c0.c0 = t0[0].sub(a.c0.c0).dbl().add(t0[0]);
        r.c0.c1 = t1[0].sub(a.c0.c1).dbl().add(t1[0]);
        r.c0.c2 = t2[0].sub(a.c0.c2).dbl().add(t2[0]);
        const t21 = t2[1].mulByXi();
        r.c1.c0 = t21.add(a.c1.c0).dbl().add(t21);
        r.c1.c1 = t0[1].add(a.c1.c1).dbl().add(t0[1]);
        r.c1.c2 = t1[1].add(a.c1.c2).dbl().add(t1[1]);
        return r;
    }

    /// 576-byte big-endian serialization in fastcrypto's GTElement order:
    /// for i in 0..3 (Fp2 index in Fp6), j in 0..2 (Fp6 index), k in 0..2 (Fp index).
    pub fn toBytes(a: Fp12) [576]u8 {
        var out: [576]u8 = undefined;
        var off: usize = 0;
        for (0..3) |i| for (0..2) |j| for (0..2) |k| {
            const x = a.coeff(j, i, k);
            out[off..][0..48].* = x.toBytesBE();
            off += 48;
        };
        return out;
    }

    /// Inverse of `toBytes`; null when a coordinate is not below p.
    pub fn fromBytes(b: *const [576]u8) ?Fp12 {
        var r: Fp12 = undefined;
        var off: usize = 0;
        for (0..3) |i| for (0..2) |j| for (0..2) |k| {
            const x = Fp.fromBytesBE(b[off..][0..48]) orelse return null;
            r.coeffPtr(j, i, k).* = x;
            off += 48;
        };
        return r;
    }

    fn coeff(a: *const Fp12, j: usize, i: usize, k: usize) Fp {
        const f6 = if (j == 0) &a.c0 else &a.c1;
        const f2 = switch (i) {
            0 => &f6.c0,
            1 => &f6.c1,
            else => &f6.c2,
        };
        return if (k == 0) f2.c0 else f2.c1;
    }

    fn coeffPtr(a: *Fp12, j: usize, i: usize, k: usize) *Fp {
        const f6 = if (j == 0) &a.c0 else &a.c1;
        const f2 = switch (i) {
            0 => &f6.c0,
            1 => &f6.c1,
            else => &f6.c2,
        };
        return if (k == 0) &f2.c0 else &f2.c1;
    }
};

fn pow12(a: Fp12, e: [6]u64) Fp12 {
    var acc = Fp12.one;
    var i: usize = 384;
    while (i > 0) {
        i -= 1;
        acc = acc.sqr();
        if ((e[i / 64] >> @intCast(i % 64)) & 1 == 1) acc = acc.mul(a);
    }
    return acc;
}

test "tower identities" {
    var prng = std.Random.DefaultPrng.init(7);
    const rnd = prng.random();
    const R = struct {
        fn fp(r: std.Random) Fp {
            var b: [48]u8 = undefined;
            r.bytes(&b);
            return Fp.fromBytesBEReduce(&b);
        }
        fn fp2(r: std.Random) Fp2 {
            return .{ .c0 = fp(r), .c1 = fp(r) };
        }
        fn fp6(r: std.Random) Fp6 {
            return .{ .c0 = fp2(r), .c1 = fp2(r), .c2 = fp2(r) };
        }
        fn fp12(r: std.Random) Fp12 {
            return .{ .c0 = fp6(r), .c1 = fp6(r) };
        }
    };
    for (0..20) |_| {
        const a = R.fp2(rnd);
        const b = R.fp2(rnd);
        try std.testing.expect(a.mul(b).eql(b.mul(a)));
        try std.testing.expect(a.sqr().eql(a.mul(a)));
        try std.testing.expect(a.mul(a.inv()).eql(Fp2.one));
        const s = a.sqr().sqrt().?;
        try std.testing.expect(s.sqr().eql(a.sqr()));
        const x = R.fp6(rnd);
        const y = R.fp6(rnd);
        try std.testing.expect(x.sqr().eql(x.mul(x)));
        try std.testing.expect(x.mul(x.inv()).eql(Fp6.one));
        try std.testing.expect(x.mulBy01(a, b).eql(x.mul(.{ .c0 = a, .c1 = b, .c2 = Fp2.zero })));
        try std.testing.expect(x.mulBy1(a).eql(x.mul(.{ .c0 = Fp2.zero, .c1 = a, .c2 = Fp2.zero })));
        try std.testing.expect(x.mulByV().eql(x.mul(.{ .c0 = Fp2.zero, .c1 = Fp2.one, .c2 = Fp2.zero })));
        _ = y;
        const f = R.fp12(rnd);
        const g = R.fp12(rnd);
        try std.testing.expect(f.sqr().eql(f.mul(f)));
        try std.testing.expect(f.mul(f.inv()).isOne());
        const c = R.fp2(rnd);
        const line: Fp12 = .{ .c0 = .{ .c0 = a, .c1 = b, .c2 = Fp2.zero }, .c1 = .{ .c0 = Fp2.zero, .c1 = c, .c2 = Fp2.zero } };
        try std.testing.expect(f.mulByLine(a, b, c).eql(f.mul(line)));
        // Frobenius: f^p directly, then compositions
        try std.testing.expect(f.frobenius(1).eql(pow12(f, Fp.P)));
        try std.testing.expect(f.mul(g).frobenius(1).eql(f.frobenius(1).mul(g.frobenius(1))));
        try std.testing.expect(f.frobenius(1).frobenius(2).eql(f.frobenius(3)));
        try std.testing.expect(f.frobenius(1).frobenius(1).eql(f.frobenius(2)));
        // cyclotomic squaring on an element of the cyclotomic subgroup: f^((p^6-1)(p^2+1))
        var cyc = f.conj().mul(f.inv());
        cyc = cyc.frobenius(2).mul(cyc);
        try std.testing.expect(cyc.cyclotomicSqr().eql(cyc.sqr()));
        try std.testing.expect(Fp12.fromBytes(&f.toBytes()).?.eql(f));
    }
}

test "fp2 sqrt: norm method agrees with the generic algorithm" {
    var prng = std.Random.DefaultPrng.init(7);
    var squares: usize = 0;
    for (0..300) |i| {
        var b: [48]u8 = undefined;
        prng.random().bytes(&b);
        const c0 = Fp.fromBytesBEReduce(&b);
        prng.random().bytes(&b);
        const c1 = if (i % 10 == 0) Fp.zero else Fp.fromBytesBEReduce(&b);
        const a: Fp2 = .{ .c0 = c0, .c1 = c1 };
        const fast = a.sqrt();
        const slow = a.sqrtGeneric();
        try std.testing.expectEqual(slow == null, fast == null);
        if (fast) |x| {
            try std.testing.expect(x.sqr().eql(a));
            squares += 1;
        }
        const sq = a.sqr();
        const r = sq.sqrt().?;
        try std.testing.expect(r.eql(a) or r.eql(a.neg()));
        // pairs: same roots (or both null) as one at a time, squares and non-squares mixed
        const both = Fp2.sqrt2(a, sq);
        try std.testing.expectEqual(fast == null, both[0] == null);
        if (fast) |x| try std.testing.expect(both[0].?.eql(x));
        try std.testing.expect(both[1].?.eql(r));
        const swapped = Fp2.sqrt2(sq, a);
        try std.testing.expect(swapped[0].?.eql(r));
        try std.testing.expectEqual(fast == null, swapped[1] == null);
    }
    try std.testing.expect(squares > 100 and squares < 200);
}
