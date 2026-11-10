//! G1 (over Fp) and G2 (over Fp2) of BLS12-381: y^2 = x^3 + 4 and y^2 = x^3 + 4(1 + u).
//!
//! Points are Jacobian (X, Y, Z) with x = X/Z^2, y = Y/Z^3; Z = 0 is the point at infinity,
//! as in blst. Affine points use (0, 0) for infinity, again as blst does, so the byte formats
//! and edge cases line up with blst one to one.
//!
//! Two addition flavours:
//!   - `add`/`addAffine`: branching, for public data (verification, aggregation, hashing).
//!   - `addCt`: constant time (computes add and double and selects), for secret scalars.
const std = @import("std");
const field = @import("field.zig");
const tower = @import("tower.zig");
const consts = @import("consts.zig");
pub const Fp = field.Fp;
pub const Fp2 = tower.Fp2;
pub const Fr = field.Fr;

/// |z| for the BLS parameter z = -0xd201000000010000.
pub const z_abs: u64 = 0xd201000000010000;

pub fn Curve(comptime F: type, comptime b_coeff: F) type {
    return struct {
        pub const Field = F;
        pub const b = b_coeff;

        pub const Affine = struct {
            x: F,
            y: F,

            pub const infinity: Affine = .{ .x = F.zero, .y = F.zero };

            pub fn isInfinity(a: Affine) bool {
                return a.x.isZero() and a.y.isZero();
            }
            pub fn onCurve(a: Affine) bool {
                return a.y.sqr().eql(a.x.sqr().mul(a.x).add(b));
            }
            pub fn neg(a: Affine) Affine {
                return .{ .x = a.x, .y = a.y.neg() };
            }
            pub fn toJacobian(a: Affine) Point {
                // blst FROM_AFFINE: Z = is_zero(x, y) ? 0 : 1
                return .{ .x = a.x, .y = a.y, .z = F.select(a.isInfinity(), F.zero, F.one) };
            }
            pub fn eql(a: Affine, o: Affine) bool {
                return a.x.eql(o.x) and a.y.eql(o.y);
            }
        };

        pub const Point = struct {
            x: F,
            y: F,
            z: F,

            pub const infinity: Point = .{ .x = F.zero, .y = F.one, .z = F.zero };

            pub inline fn isInfinity(p: Point) bool {
                return p.z.isZero();
            }

            pub fn neg(p: Point) Point {
                return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
            }

            pub fn condNeg(p: Point, c: bool) Point {
                return .{ .x = p.x, .y = p.y.condNeg(c), .z = p.z };
            }

            /// dbl-2009-l (a = 0). Infinity maps to infinity (Z3 = 2*Y*Z = 0).
            pub fn dbl(p: Point) Point {
                const A = p.x.sqr();
                const B = p.y.sqr();
                const C = B.sqr();
                const D = p.x.add(B).sqr().sub(A).sub(C).dbl();
                const E = A.mul3();
                const Fv = E.sqr();
                const x3 = Fv.sub(D.dbl());
                const y3 = E.mul(D.sub(x3)).sub(C.dbl().dbl().dbl());
                const z3 = p.y.mul(p.z).dbl();
                return .{ .x = x3, .y = y3, .z = z3 };
            }

            /// add-2007-bl, general Jacobian addition; handles infinity and doubling by branching.
            pub fn add(p: Point, q: Point) Point {
                if (p.isInfinity()) return q;
                if (q.isInfinity()) return p;
                const z1z1 = p.z.sqr();
                const z2z2 = q.z.sqr();
                const u_1 = p.x.mul(z2z2);
                const u_2 = q.x.mul(z1z1);
                const s1 = p.y.mul(q.z).mul(z2z2);
                const s2 = q.y.mul(p.z).mul(z1z1);
                const h = u_2.sub(u_1);
                const r0 = s2.sub(s1);
                if (h.isZero()) {
                    if (r0.isZero()) return p.dbl();
                    return infinity;
                }
                const i = h.dbl().sqr();
                const j = h.mul(i);
                const r = r0.dbl();
                const v = u_1.mul(i);
                const x3 = r.sqr().sub(j).sub(v.dbl());
                const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
                const z3 = p.z.add(q.z).sqr().sub(z1z1).sub(z2z2).mul(h);
                return .{ .x = x3, .y = y3, .z = z3 };
            }

            /// madd-2007-bl: p + q with q affine; branching (public data).
            pub fn addAffine(p: Point, q: Affine) Point {
                if (q.isInfinity()) return p;
                if (p.isInfinity()) return q.toJacobian();
                const z1z1 = p.z.sqr();
                const u_2 = q.x.mul(z1z1);
                const s2 = q.y.mul(p.z).mul(z1z1);
                const h = u_2.sub(p.x);
                const r0 = s2.sub(p.y);
                if (h.isZero()) {
                    if (r0.isZero()) return p.dbl();
                    return infinity;
                }
                const hh = h.sqr();
                const i = hh.dbl().dbl();
                const j = h.mul(i);
                const r = r0.dbl();
                const v = p.x.mul(i);
                const x3 = r.sqr().sub(j).sub(v.dbl());
                const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).dbl());
                const z3 = p.z.add(h).sqr().sub(z1z1).sub(hh);
                return .{ .x = x3, .y = y3, .z = z3 };
            }

            /// Constant-time p + q for any p, q (infinity, equal, opposite): both the addition
            /// and the doubling are computed and the right one is selected.
            pub fn addCt(p: Point, q: Point) Point {
                const z1z1 = p.z.sqr();
                const z2z2 = q.z.sqr();
                const u_1 = p.x.mul(z2z2);
                const u_2 = q.x.mul(z1z1);
                const s1 = p.y.mul(q.z).mul(z2z2);
                const s2 = q.y.mul(p.z).mul(z1z1);
                const h = u_2.sub(u_1);
                const r0 = s2.sub(s1);
                const i = h.dbl().sqr();
                const j = h.mul(i);
                const r = r0.dbl();
                const v = u_1.mul(i);
                const x3 = r.sqr().sub(j).sub(v.dbl());
                const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
                const z3 = p.z.add(q.z).sqr().sub(z1z1).sub(z2z2).mul(h);
                var out: Point = .{ .x = x3, .y = y3, .z = z3 };
                const d = p.dbl();
                const p_inf = p.isInfinity();
                const q_inf = q.isInfinity();
                // bitwise, not `and`: no short-circuit branch on secret-derived values
                const same = (@intFromBool(h.isZero()) & @intFromBool(r0.isZero()) &
                    ~@intFromBool(p_inf) & ~@intFromBool(q_inf)) == 1;
                out = select(same, d, out);
                out = select(q_inf, p, out);
                out = select(p_inf, q, out);
                return out;
            }

            pub fn select(c: bool, a: Point, o: Point) Point {
                return .{ .x = F.select(c, a.x, o.x), .y = F.select(c, a.y, o.y), .z = F.select(c, a.z, o.z) };
            }

            /// blst POINT_IS_EQUAL: X1 Z2^2 == X2 Z1^2, Y1 Z2^3 == Y2 Z1^3, same infinity status.
            pub fn eql(p: Point, q: Point) bool {
                const z1z1 = p.z.sqr();
                const z2z2 = q.z.sqr();
                const same = p.x.mul(z2z2).eql(q.x.mul(z1z1)) and
                    p.y.mul(q.z).mul(z2z2).eql(q.y.mul(p.z).mul(z1z1));
                return same and (p.isInfinity() == q.isInfinity());
            }

            /// Affine form of a public point (variable-time inversion).
            pub fn toAffine(p: Point) Affine {
                if (p.isInfinity()) return Affine.infinity;
                const zi = p.z.invVartime();
                const zi2 = zi.sqr();
                return .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2).mul(zi) };
            }

            /// Constant-time affine conversion (infinity -> (0, 0)).
            pub fn toAffineCt(p: Point) Affine {
                const zi = p.z.inv(); // 0 -> 0
                const zi2 = zi.sqr();
                return .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2).mul(zi) };
            }

            /// [|z|]p by blst's add-then-double chain for 0xd201000000010000 (public data).
            pub fn timesMinusZ(p: Point) Point {
                var out = p.dbl(); // 0x2
                out = addNDbl(out, p, 2); // ..0xc
                out = addNDbl(out, p, 3); // ..0x68
                out = addNDbl(out, p, 9); // ..0xd200
                out = addNDbl(out, p, 32); // ..0xd20100000000
                out = addNDbl(out, p, 16); // ..0xd201000000010000
                return out;
            }

            fn addNDbl(acc: Point, p: Point, n: usize) Point {
                var out = acc.add(p);
                for (0..n) |_| out = out.dbl();
                return out;
            }

            /// Variable-time [k]p for a public little-endian scalar of `nbits` bits.
            pub fn mulVartime(p: Point, k: []const u8, nbits: usize) Point {
                var acc = infinity;
                var i: usize = nbits;
                while (i > 0) {
                    i -= 1;
                    acc = acc.dbl();
                    if ((k[i / 8] >> @intCast(i % 8)) & 1 == 1) acc = acc.add(p);
                }
                return acc;
            }

            /// Constant-time [k]p for a secret 32-byte little-endian scalar: fixed 4-bit
            /// windows, table scanned in full for every lookup, complete additions.
            pub fn mulCt(p: Point, k: *const [32]u8) Point {
                var table: [16]Point = undefined;
                table[0] = infinity;
                table[1] = p;
                for (2..16) |i| table[i] = table[i - 1].addCt(p);
                var acc = infinity;
                var i: usize = 64;
                while (i > 0) {
                    i -= 1;
                    acc = acc.dbl().dbl().dbl().dbl();
                    const w: u8 = (k[i / 2] >> @intCast(4 * (i % 2))) & 0xf;
                    var sel = infinity;
                    for (table, 0..) |t, j| sel = select(j == w, t, sel);
                    acc = acc.addCt(sel);
                }
                return acc;
            }
        };
    };
}

pub const G1 = Curve(Fp, Fp.fromInt(4));
pub const G2 = Curve(Fp2, Fp2.fromInts(.{ 4, 4 }));

pub const g1_generator: G1.Affine = .{ .x = Fp.fromInt(consts.g1_x), .y = Fp.fromInt(consts.g1_y) };
pub const g2_generator: G2.Affine = .{ .x = Fp2.fromInts(consts.g2_x), .y = Fp2.fromInts(consts.g2_y) };

const beta = Fp.fromInt(consts.beta);
const psi_x = Fp2.fromInts(consts.psi_x);
const psi_y = Fp2.fromInts(consts.psi_y);

/// sigma(x, y) = (beta x, y), on Jacobian coordinates as blst does it (Z *= beta).
pub fn sigma(p: G1.Point) G1.Point {
    return .{ .x = p.x, .y = p.y, .z = p.z.mul(beta) };
}

/// psi = untwist-Frobenius-twist endomorphism on G2 (blst e2.c `psi`).
pub fn psi(p: G2.Point) G2.Point {
    return .{ .x = p.x.conj().mul(psi_x), .y = p.y.conj().mul(psi_y), .z = p.z.conj() };
}

/// G1 subgroup membership (Scott, eprint 2021/1130, as in blst): sigma^2(P) == [-z^2]P.
/// Equivalent to [r]P == O for every point on the curve.
pub fn g1InGroup(p: G1.Point) bool {
    const t0 = p.timesMinusZ();
    const t1 = t0.timesMinusZ().neg(); // [-z^2]P
    const s = sigma(sigma(p));
    return s.eql(t1);
}

/// G2 subgroup membership (Scott, as in blst): psi(P) == [z]P.
pub fn g2InGroup(p: G2.Point) bool {
    const t0 = psi(p);
    const t1 = p.timesMinusZ().neg(); // [z]P
    return t0.eql(t1);
}

pub fn g1AffineInGroup(a: G1.Affine) bool {
    return g1InGroup(a.toJacobian());
}

pub fn g2AffineInGroup(a: G2.Affine) bool {
    return g2InGroup(a.toJacobian());
}

/// Batch affine conversion (Montgomery's trick, one inversion), public data.
pub fn batchToAffine(comptime C: type, points: []const C.Point, out: []C.Affine, scratch: []C.Field) void {
    std.debug.assert(out.len == points.len and scratch.len >= points.len);
    var acc = C.Field.one;
    for (points, 0..) |p, i| {
        scratch[i] = acc;
        if (!p.isInfinity()) acc = acc.mul(p.z);
    }
    var inv = acc.invVartime();
    var i = points.len;
    while (i > 0) {
        i -= 1;
        const p = points[i];
        if (p.isInfinity()) {
            out[i] = C.Affine.infinity;
            continue;
        }
        const zi = inv.mul(scratch[i]);
        inv = inv.mul(p.z);
        const zi2 = zi.sqr();
        out[i] = .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2).mul(zi) };
    }
}

test "generators, subgroup checks, endomorphisms" {
    try std.testing.expect(g1_generator.onCurve());
    try std.testing.expect(g2_generator.onCurve());
    const g1 = g1_generator.toJacobian();
    const g2 = g2_generator.toJacobian();
    try std.testing.expect(g1InGroup(g1));
    try std.testing.expect(g2InGroup(g2));
    try std.testing.expect(g1InGroup(G1.Point.infinity));
    try std.testing.expect(g2InGroup(G2.Point.infinity));
    // [r]G = O
    var rb: [32]u8 = undefined;
    std.mem.writeInt(u256, &rb, consts.r, .little);
    try std.testing.expect(g1.mulVartime(&rb, 255).isInfinity());
    try std.testing.expect(g2.mulVartime(&rb, 255).isInfinity());
    // addition laws
    const g1x2 = g1.add(g1);
    try std.testing.expect(g1x2.eql(g1.dbl()));
    try std.testing.expect(g1x2.eql(g1.addAffine(g1_generator)));
    try std.testing.expect(g1.add(g1.neg()).isInfinity());
    const g1x3 = g1x2.add(g1);
    try std.testing.expect(g1x3.eql(g1.addCt(g1x2)));
    try std.testing.expect(g1.addCt(g1).eql(g1x2));
    try std.testing.expect(g1.addCt(G1.Point.infinity).eql(g1));
    try std.testing.expect(G1.Point.infinity.addCt(g1).eql(g1));
    try std.testing.expect(g1.addCt(g1.neg()).isInfinity());
    try std.testing.expect(g1x3.toAffine().onCurve());
    // mulCt agrees with mulVartime
    var k: [32]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    prng.random().bytes(&k);
    k[31] &= 0x3f;
    try std.testing.expect(g1.mulCt(&k).eql(g1.mulVartime(&k, 256)));
    try std.testing.expect(g2.mulCt(&k).eql(g2.mulVartime(&k, 256)));
    // a point on the curve but outside G1: x = 0 (y = 2)
    const t: G1.Affine = .{ .x = Fp.zero, .y = Fp.fromInt(2) };
    try std.testing.expect(t.onCurve());
    try std.testing.expect(!g1AffineInGroup(t));
    // sigma acts as [lambda] on G1: sigma(G) is in G1 and on the curve
    try std.testing.expect(sigma(g1).toAffine().onCurve());
    try std.testing.expect(psi(g2).toAffine().onCurve());
    // batch affine
    var pts = [_]G1.Point{ g1, G1.Point.infinity, g1x2, g1x3 };
    var aff: [4]G1.Affine = undefined;
    var scr: [4]Fp = undefined;
    batchToAffine(G1, &pts, &aff, &scr);
    for (pts, aff) |pp, a| try std.testing.expect(pp.toAffine().eql(a));
}
