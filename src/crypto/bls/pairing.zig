//! Optimal ate pairing on BLS12-381, the same Miller loop and final exponentiation as blst
//! 0.3.16 (pairing.c): Jacobian G2 accumulator, line functions from eprint 2010/354 with the
//! common factors moved into (-2 Px, 2 Py), loop over |z| = 0xd201000000010000, conjugation
//! for z < 0, and blst's (zkcrypto-derived) hard part. Because every step is the same, the
//! Miller-loop products and the final-exponentiated values are the same Fp12 elements blst
//! computes, also for inputs outside the prime-order subgroups.
//!
//! Multi-pairings share one accumulator: one Fp12 squaring per loop bit for all pairs, and
//! pairs whose G2 point is fixed (the generator in signature verification) use precomputed
//! lines.
const std = @import("std");
const curve = @import("curve.zig");
const tower = @import("tower.zig");
const Fp = curve.Fp;
const Fp2 = curve.Fp2;
const Fp6 = tower.Fp6;
const Fp12 = tower.Fp12;
const G1 = curve.G1;
const G2 = curve.G2;

pub const Line = [3]Fp2;
pub const n_lines = 68;

/// The loop's addition schedule: after the first doubling, (add, then `k` doublings) for each k.
const schedule = [_]usize{ 2, 3, 9, 32, 16 };

/// blst line_dbl: doubles T in place and returns the (unscaled) tangent line.
fn lineDbl(t: *G2.Point) Line {
    const A = t.x.sqr();
    var B = t.y.sqr();
    const ZZ = t.z.sqr();
    const C = B.sqr();
    const D = t.x.add(B).sqr().sub(A).sub(C).dbl();
    const E = A.mul3();
    const F = E.sqr();
    var l0 = E.add(t.x);
    const x3 = F.sub(D).sub(D);
    const z3 = t.y.add(t.z).sqr().sub(B).sub(ZZ);
    const y3 = E.mul(D.sub(x3)).sub(C.dbl().dbl().dbl());
    l0 = l0.sqr().sub(A).sub(F);
    B = B.dbl().dbl();
    l0 = l0.sub(B);
    const l1 = E.mul(ZZ);
    const l2 = z3.mul(ZZ);
    t.* = .{ .x = x3, .y = y3, .z = z3 };
    return .{ l0, l1, l2 };
}

/// blst line_add: T += Q (Q affine) and returns the chord line.
fn lineAdd(t: *G2.Point, q: G2.Affine) Line {
    const z1z1 = t.z.sqr();
    const u_2 = q.x.mul(z1z1);
    const s2 = q.y.mul(t.z).mul(z1z1);
    const h = u_2.sub(t.x);
    const hh = h.sqr();
    const i = hh.dbl().dbl();
    var j = h.mul(i);
    const r = s2.sub(t.y).dbl();
    const v = t.x.mul(i);
    const x3 = r.sqr().sub(j).sub(v).sub(v);
    j = j.mul(t.y);
    const y3 = v.sub(x3).mul(r).sub(j).sub(j);
    const z3 = t.z.add(h).sqr().sub(z1z1).sub(hh);
    const l0 = r.mul(q.x).sub(q.y.mul(z3)).dbl();
    t.* = .{ .x = x3, .y = y3, .z = z3 };
    return .{ l0, r, z3 };
}

/// G1 point with blst's common factors: (-2 Px, 2 Py).
pub const Px2 = struct {
    x: Fp,
    y: Fp,
    pub fn init(p: G1.Affine) Px2 {
        return .{ .x = p.x.dbl().neg(), .y = p.y.dbl() };
    }
};

inline fn mulLine(f: Fp12, l: Line, p: Px2) Fp12 {
    return f.mulByLine(l[0], l[1].mulFp(p.x), l[2].mulFp(p.y));
}

/// The 68 lines of the Miller loop for a fixed G2 point (blst precompute_lines).
pub fn precomputeLines(q: G2.Affine, out: *[n_lines]Line) void {
    var t: G2.Point = .{ .x = q.x, .y = q.y, .z = Fp2.one };
    var k: usize = 0;
    out[k] = lineDbl(&t);
    k += 1;
    for (schedule) |n| {
        out[k] = lineAdd(&t, q);
        k += 1;
        for (0..n) |_| {
            out[k] = lineDbl(&t);
            k += 1;
        }
    }
    std.debug.assert(k == n_lines);
}

pub const Pair = struct { p: G1.Affine, q: G2.Affine };
pub const PrePair = struct { p: G1.Affine, lines: *const [n_lines]Line };

pub const max_pairs = 16;

/// prod_i f_{|z|,Q_i}(P_i), conjugated, over `pairs` (computed lines) and `pre` (precomputed
/// lines). Pairs with an infinite point contribute 1 (as blst's single-pair special case and
/// fastcrypto's multi-pairing filter do). Returns 1 when nothing remains.
pub fn millerLoop(pairs: []const Pair, pre: []const PrePair) Fp12 {
    std.debug.assert(pairs.len <= max_pairs and pre.len <= max_pairs);
    var ts: [max_pairs]G2.Point = undefined;
    var qs: [max_pairs]G2.Affine = undefined;
    var ps: [max_pairs]Px2 = undefined;
    var n: usize = 0;
    for (pairs) |pr| {
        if (pr.p.isInfinity() or pr.q.isInfinity()) continue;
        ts[n] = .{ .x = pr.q.x, .y = pr.q.y, .z = Fp2.one };
        qs[n] = pr.q;
        ps[n] = Px2.init(pr.p);
        n += 1;
    }
    var pls: [max_pairs]*const [n_lines]Line = undefined;
    var pps: [max_pairs]Px2 = undefined;
    var m: usize = 0;
    for (pre) |pr| {
        if (pr.p.isInfinity()) continue;
        pls[m] = pr.lines;
        pps[m] = Px2.init(pr.p);
        m += 1;
    }
    if (n + m == 0) return Fp12.one;

    // first doubling: f = product of the first lines (f = 1^2 * line)
    var f = Fp12.one;
    var first = true;
    var li: usize = 0;
    for (0..n) |i| {
        const l = lineDbl(&ts[i]);
        f = if (first) lineToFp12(l, ps[i]) else mulLine(f, l, ps[i]);
        first = false;
    }
    for (0..m) |i| {
        const l = pls[i][li];
        f = if (first) lineToFp12(l, pps[i]) else mulLine(f, l, pps[i]);
        first = false;
    }
    li += 1;
    for (schedule) |k| {
        for (0..n) |i| f = mulLine(f, lineAdd(&ts[i], qs[i]), ps[i]);
        for (0..m) |i| f = mulLine(f, pls[i][li], pps[i]);
        li += 1;
        for (0..k) |_| {
            f = f.sqr();
            for (0..n) |i| f = mulLine(f, lineDbl(&ts[i]), ps[i]);
            for (0..m) |i| f = mulLine(f, pls[i][li], pps[i]);
            li += 1;
        }
    }
    return f.conj();
}

fn lineToFp12(l: Line, p: Px2) Fp12 {
    return .{
        .c0 = .{ .c0 = l[0], .c1 = l[1].mulFp(p.x), .c2 = Fp2.zero },
        .c1 = .{ .c0 = Fp2.zero, .c1 = l[2].mulFp(p.y), .c2 = Fp2.zero },
    };
}

fn mulNSqr(ret: Fp12, a: Fp12, n: usize) Fp12 {
    var r = ret.mul(a);
    for (0..n) |_| r = r.cyclotomicSqr();
    return r;
}

fn raiseToZDivBy2(a: Fp12) Fp12 {
    var r = a.cyclotomicSqr(); // 0x2
    r = mulNSqr(r, a, 2); // ..0xc
    r = mulNSqr(r, a, 3); // ..0x68
    r = mulNSqr(r, a, 9); // ..0xd200
    r = mulNSqr(r, a, 32); // ..0xd20100000000
    r = mulNSqr(r, a, 15); // ..0x6900800000008000
    return r.conj(); // z < 0
}

fn raiseToZ(a: Fp12) Fp12 {
    return raiseToZDivBy2(a).cyclotomicSqr();
}

/// blst final_exp (adapted from zkcrypto/pairing). Variable time: pairings here only ever see
/// public points.
pub fn finalExp(f: Fp12) Fp12 {
    var y1 = f.conj();
    var y2 = f.invVartime(); // public data only
    var ret = y1.mul(y2);
    y2 = ret.frobenius(2);
    ret = ret.mul(y2);

    const y0 = ret.cyclotomicSqr();
    y1 = raiseToZ(y0);
    y2 = raiseToZDivBy2(y1);
    var y3 = ret.conj();
    y1 = y1.mul(y3);
    y1 = y1.conj();
    y1 = y1.mul(y2);
    y2 = raiseToZ(y1);
    y3 = raiseToZ(y2);
    y1 = y1.conj();
    y3 = y3.mul(y1);
    y1 = y1.conj();
    y1 = y1.frobenius(3);
    y2 = y2.frobenius(2);
    y1 = y1.mul(y2);
    y2 = raiseToZ(y3);
    y2 = y2.mul(y0);
    y2 = y2.mul(ret);
    y1 = y1.mul(y2);
    y2 = y3.frobenius(1);
    return y1.mul(y2);
}

/// e(P, Q) as blst_miller_loop + blst_final_exp compute it.
pub fn pairing(p: G1.Affine, q: G2.Affine) Fp12 {
    return finalExp(millerLoop(&.{.{ .p = p, .q = q }}, &.{}));
}

test "pairing bilinearity and generator order" {
    const g1 = curve.g1_generator;
    const g2 = curve.g2_generator;
    const e = pairing(g1, g2);
    try std.testing.expect(!e.isOne());
    // e(2P, Q) = e(P, 2Q) = e(P, Q)^2
    const p2 = g1.toJacobian().dbl().toAffine();
    const q2 = g2.toJacobian().dbl().toAffine();
    try std.testing.expect(pairing(p2, g2).eql(e.sqr()));
    try std.testing.expect(pairing(g1, q2).eql(e.sqr()));
    // e(P, Q) * e(-P, Q) = 1 through the shared multi-pairing
    const f = millerLoop(&.{ .{ .p = g1, .q = g2 }, .{ .p = g1.neg(), .q = g2 } }, &.{});
    try std.testing.expect(finalExp(f).isOne());
    // precomputed lines give the same Miller value
    var lines: [n_lines]Line = undefined;
    precomputeLines(g2, &lines);
    const a = millerLoop(&.{.{ .p = p2, .q = g2 }}, &.{});
    const b = millerLoop(&.{}, &.{.{ .p = p2, .lines = &lines }});
    try std.testing.expect(a.eql(b));
}
