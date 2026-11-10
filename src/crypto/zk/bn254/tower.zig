//! BN254 extension tower, identical in representation to arkworks `ark_bn254`:
//!   Fq2  = Fq[u] / (u^2 + 1)
//!   Fq6  = Fq2[v] / (v^3 - (9 + u))
//!   Fq12 = Fq6[w] / (w^2 - v)
//! so serialized bytes (c0 before c1, Fq6 as c0, c1, c2) match arkworks' canonical encoding.
const std = @import("std");
const fp = @import("fp.zig");
const Fq = fp.Fq;

pub const Fq2 = struct {
    c0: Fq,
    c1: Fq,

    pub const zero: Fq2 = .{ .c0 = Fq.zero, .c1 = Fq.zero };
    pub const one: Fq2 = .{ .c0 = Fq.one, .c1 = Fq.zero };

    pub fn init(comptime a: comptime_int, comptime b: comptime_int) Fq2 {
        return .{ .c0 = Fq.fromInt(a), .c1 = Fq.fromInt(b) };
    }

    pub fn isZero(a: Fq2) bool {
        return a.c0.isZero() and a.c1.isZero();
    }
    pub fn eql(a: Fq2, b: Fq2) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub fn add(a: Fq2, b: Fq2) Fq2 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1) };
    }
    pub fn sub(a: Fq2, b: Fq2) Fq2 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1) };
    }
    pub fn dbl(a: Fq2) Fq2 {
        return .{ .c0 = a.c0.dbl(), .c1 = a.c1.dbl() };
    }
    pub fn neg(a: Fq2) Fq2 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg() };
    }
    pub fn conj(a: Fq2) Fq2 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }
    pub fn mul(a: Fq2, b: Fq2) Fq2 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        const s = a.c0.add(a.c1).mul(b.c0.add(b.c1));
        return .{ .c0 = v0.sub(v1), .c1 = s.sub(v0).sub(v1) };
    }
    pub fn sq(a: Fq2) Fq2 {
        const t = a.c0.mul(a.c1);
        return .{ .c0 = a.c0.add(a.c1).mul(a.c0.sub(a.c1)), .c1 = t.dbl() };
    }
    pub fn mulFq(a: Fq2, s: Fq) Fq2 {
        return .{ .c0 = a.c0.mul(s), .c1 = a.c1.mul(s) };
    }
    /// Multiply by the Fq6 non-residue xi = 9 + u.
    pub fn mulXi(a: Fq2) Fq2 {
        // (a0 + a1 u)(9 + u) = (9 a0 - a1) + (a0 + 9 a1) u
        const a0_8 = a.c0.dbl().dbl().dbl();
        const a1_8 = a.c1.dbl().dbl().dbl();
        return .{ .c0 = a0_8.add(a.c0).sub(a.c1), .c1 = a1_8.add(a.c1).add(a.c0) };
    }
    pub fn inverse(a: Fq2) Fq2 {
        const t = a.c0.sq().add(a.c1.sq()).inverse();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).neg() };
    }
    /// Frobenius: a^(p^k) = conj^k.
    pub fn frob(a: Fq2, k: usize) Fq2 {
        return if (k % 2 == 1) a.conj() else a;
    }
    pub fn pow(a: Fq2, comptime e: comptime_int) Fq2 {
        const el = comptime fp.limbsOf(e);
        var r = one;
        var i: usize = 4;
        while (i > 0) {
            i -= 1;
            var bit: u7 = 64;
            while (bit > 0) {
                bit -= 1;
                r = r.sq();
                if ((el[i] >> @intCast(bit)) & 1 == 1) r = r.mul(a);
            }
        }
        return r;
    }
    /// A square root (any one; callers pick by `cmp`), or null when `a` is not a square.
    pub fn sqrt(a: Fq2) ?Fq2 {
        if (a.isZero()) return zero;
        if (a.c1.isZero()) {
            if (a.c0.sqrt()) |s| return .{ .c0 = s, .c1 = Fq.zero };
            // a0 not a square in Fq: sqrt(a0) = sqrt(-a0) * u since u^2 = -1.
            if (a.c0.neg().sqrt()) |s| return .{ .c0 = Fq.zero, .c1 = s };
            return null;
        }
        // Norm method: alpha = a0^2 + a1^2 must be a square in Fq.
        const alpha = a.c0.sq().add(a.c1.sq());
        const gamma = alpha.sqrt() orelse return null;
        const two_inv = comptime Fq.fromInt((fp.q_modulus + 1) / 2);
        var delta = a.c0.add(gamma).mul(two_inv);
        var x0 = delta.sqrt();
        if (x0 == null) {
            delta = a.c0.sub(gamma).mul(two_inv);
            x0 = delta.sqrt();
        }
        const s0 = x0 orelse return null;
        const s1 = a.c1.mul(s0.dbl().inverse());
        const r: Fq2 = .{ .c0 = s0, .c1 = s1 };
        if (!r.sq().eql(a)) return null;
        return r;
    }
    /// arkworks `Ord` for quadratic extensions: compare c1 first, then c0.
    pub fn cmp(a: Fq2, b: Fq2) std.math.Order {
        const o = a.c1.cmp(b.c1);
        if (o != .eq) return o;
        return a.c0.cmp(b.c0);
    }
    pub fn isLexSmallest(a: Fq2) bool {
        return a.cmp(a.neg()) != .gt;
    }
};

fn q2(comptime a: comptime_int, comptime b: comptime_int) Fq2 {
    return Fq2.init(a, b);
}

/// FROBENIUS_COEFF_FP6_C1[k] = xi^((p^k - 1)/3), from ark-bn254 0.4 fq6.rs.
const frob6_c1 = [6]Fq2{
    q2(1, 0),
    q2(21575463638280843010398324269430826099269044274347216827212613867836435027261, 10307601595873709700152284273816112264069230130616436755625194854815875713954),
    q2(21888242871839275220042445260109153167277707414472061641714758635765020556616, 0),
    q2(3772000881919853776433695186713858239009073593817195771773381919316419345261, 2236595495967245188281701248203181795121068902605861227855261137820944008926),
    q2(2203960485148121921418603742825762020974279258880205651966, 0),
    q2(18429021223477853657660792034369865839114504446431234726392080002137598044644, 9344045779998320333812420223237981029506012124075525679208581902008406485703),
};
/// FROBENIUS_COEFF_FP6_C2[k] = xi^((2p^k - 2)/3).
const frob6_c2 = [6]Fq2{
    q2(1, 0),
    q2(2581911344467009335267311115468803099551665605076196740867805258568234346338, 19937756971775647987995932169929341994314640652964949448313374472400716661030),
    q2(2203960485148121921418603742825762020974279258880205651966, 0),
    q2(5324479202449903542726783395506214481928257762400643279780343368557297135718, 16208900380737693084919495127334387981393726419856888799917914180988844123039),
    q2(21888242871839275220042445260109153167277707414472061641714758635765020556616, 0),
    q2(13981852324922362344252311234282257507216387789820983642040889267519694726527, 7629828391165209371577384193250820201684255241773809077146787135900891633097),
};
/// FROBENIUS_COEFF_FP12_C1[k] = xi^((p^k - 1)/6).
const frob12_c1 = [12]Fq2{
    q2(1, 0),
    q2(8376118865763821496583973867626364092589906065868298776909617916018768340080, 16469823323077808223889137241176536799009286646108169935659301613961712198316),
    q2(21888242871839275220042445260109153167277707414472061641714758635765020556617, 0),
    q2(11697423496358154304825782922584725312912383441159505038794027105778954184319, 303847389135065887422783454877609941456349188919719272345083954437860409601),
    q2(21888242871839275220042445260109153167277707414472061641714758635765020556616, 0),
    q2(3321304630594332808241809054958361220322477375291206261884409189760185844239, 5722266937896532885780051958958348231143373700109372999374820235121374419868),
    q2(-1, 0),
    q2(13512124006075453725662431877630910996106405091429524885779419978626457868503, 5418419548761466998357268504080738289687024511189653727029736280683514010267),
    q2(2203960485148121921418603742825762020974279258880205651966, 0),
    q2(10190819375481120917420622822672549775783927716138318623895010788866272024264, 21584395482704209334823622290379665147239961968378104390343953940207365798982),
    q2(2203960485148121921418603742825762020974279258880205651967, 0),
    q2(18566938241244942414004596690298913868373833782006617400804628704885040364344, 16165975933942742336466353786298926857552937457188450663314217659523851788715),
};

pub const Fq6 = struct {
    c0: Fq2,
    c1: Fq2,
    c2: Fq2,

    pub const zero: Fq6 = .{ .c0 = Fq2.zero, .c1 = Fq2.zero, .c2 = Fq2.zero };
    pub const one: Fq6 = .{ .c0 = Fq2.one, .c1 = Fq2.zero, .c2 = Fq2.zero };

    pub fn isZero(a: Fq6) bool {
        return a.c0.isZero() and a.c1.isZero() and a.c2.isZero();
    }
    pub fn eql(a: Fq6, b: Fq6) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1) and a.c2.eql(b.c2);
    }
    pub fn add(a: Fq6, b: Fq6) Fq6 {
        return .{ .c0 = a.c0.add(b.c0), .c1 = a.c1.add(b.c1), .c2 = a.c2.add(b.c2) };
    }
    pub fn sub(a: Fq6, b: Fq6) Fq6 {
        return .{ .c0 = a.c0.sub(b.c0), .c1 = a.c1.sub(b.c1), .c2 = a.c2.sub(b.c2) };
    }
    pub fn dbl(a: Fq6) Fq6 {
        return .{ .c0 = a.c0.dbl(), .c1 = a.c1.dbl(), .c2 = a.c2.dbl() };
    }
    pub fn neg(a: Fq6) Fq6 {
        return .{ .c0 = a.c0.neg(), .c1 = a.c1.neg(), .c2 = a.c2.neg() };
    }
    /// Multiply by v: (c0, c1, c2) -> (xi c2, c0, c1).
    pub fn mulV(a: Fq6) Fq6 {
        return .{ .c0 = a.c2.mulXi(), .c1 = a.c0, .c2 = a.c1 };
    }
    pub fn mulFq2(a: Fq6, s: Fq2) Fq6 {
        return .{ .c0 = a.c0.mul(s), .c1 = a.c1.mul(s), .c2 = a.c2.mul(s) };
    }
    pub fn mul(a: Fq6, b: Fq6) Fq6 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        const v2 = a.c2.mul(b.c2);
        const c0 = a.c1.add(a.c2).mul(b.c1.add(b.c2)).sub(v1).sub(v2).mulXi().add(v0);
        const c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(v0).sub(v1).add(v2.mulXi());
        const c2 = a.c0.add(a.c2).mul(b.c0.add(b.c2)).sub(v0).sub(v2).add(v1);
        return .{ .c0 = c0, .c1 = c1, .c2 = c2 };
    }
    /// Chung-Hasan SQR2.
    pub fn sq(a: Fq6) Fq6 {
        const s0 = a.c0.sq();
        const ab = a.c0.mul(a.c1);
        const s1 = ab.dbl();
        const s2 = a.c0.sub(a.c1).add(a.c2).sq();
        const bc = a.c1.mul(a.c2);
        const s3 = bc.dbl();
        const s4 = a.c2.sq();
        return .{
            .c0 = s3.mulXi().add(s0),
            .c1 = s4.mulXi().add(s1),
            .c2 = s1.add(s2).add(s3).sub(s0).sub(s4),
        };
    }
    /// a * (b0 + b1 v).
    pub fn mulBy01(a: Fq6, b0: Fq2, b1: Fq2) Fq6 {
        const aa = a.c0.mul(b0);
        const bb = a.c1.mul(b1);
        const c0 = a.c2.mul(b1).mulXi().add(aa);
        const c1 = a.c0.add(a.c1).mul(b0.add(b1)).sub(aa).sub(bb);
        const c2 = a.c2.mul(b0).add(bb);
        return .{ .c0 = c0, .c1 = c1, .c2 = c2 };
    }
    /// a * (b1 v).
    pub fn mulBy1(a: Fq6, b1: Fq2) Fq6 {
        return .{ .c0 = a.c2.mul(b1).mulXi(), .c1 = a.c0.mul(b1), .c2 = a.c1.mul(b1) };
    }
    pub fn inverse(a: Fq6) Fq6 {
        const t0 = a.c0.sq().sub(a.c1.mul(a.c2).mulXi());
        const t1 = a.c2.sq().mulXi().sub(a.c0.mul(a.c1));
        const t2 = a.c1.sq().sub(a.c0.mul(a.c2));
        const d = a.c2.mul(t1).add(a.c1.mul(t2)).mulXi().add(a.c0.mul(t0)).inverse();
        return .{ .c0 = t0.mul(d), .c1 = t1.mul(d), .c2 = t2.mul(d) };
    }
    pub fn frob(a: Fq6, k: usize) Fq6 {
        return .{
            .c0 = a.c0.frob(k),
            .c1 = a.c1.frob(k).mul(frob6_c1[k % 6]),
            .c2 = a.c2.frob(k).mul(frob6_c2[k % 6]),
        };
    }
};

pub const Fq12 = struct {
    c0: Fq6,
    c1: Fq6,

    pub const one: Fq12 = .{ .c0 = Fq6.one, .c1 = Fq6.zero };

    pub fn isZero(a: Fq12) bool {
        return a.c0.isZero() and a.c1.isZero();
    }
    pub fn eql(a: Fq12, b: Fq12) bool {
        return a.c0.eql(b.c0) and a.c1.eql(b.c1);
    }
    pub fn isOne(a: Fq12) bool {
        return a.eql(one);
    }
    pub fn mul(a: Fq12, b: Fq12) Fq12 {
        const v0 = a.c0.mul(b.c0);
        const v1 = a.c1.mul(b.c1);
        const c1 = a.c0.add(a.c1).mul(b.c0.add(b.c1)).sub(v0).sub(v1);
        return .{ .c0 = v0.add(v1.mulV()), .c1 = c1 };
    }
    pub fn sq(a: Fq12) Fq12 {
        const ab = a.c0.mul(a.c1);
        const c0 = a.c0.add(a.c1).mul(a.c0.add(a.c1.mulV())).sub(ab).sub(ab.mulV());
        return .{ .c0 = c0, .c1 = ab.dbl() };
    }
    /// Conjugation: the inverse on the cyclotomic subgroup.
    pub fn conj(a: Fq12) Fq12 {
        return .{ .c0 = a.c0, .c1 = a.c1.neg() };
    }
    pub fn inverse(a: Fq12) Fq12 {
        const t = a.c0.sq().sub(a.c1.sq().mulV()).inverse();
        return .{ .c0 = a.c0.mul(t), .c1 = a.c1.mul(t).neg() };
    }
    pub fn frob(a: Fq12, k: usize) Fq12 {
        const c1 = a.c1.frob(k);
        const s = frob12_c1[k % 12];
        return .{ .c0 = a.c0.frob(k), .c1 = .{ .c0 = c1.c0.mul(s), .c1 = c1.c1.mul(s), .c2 = c1.c2.mul(s) } };
    }
    /// a * (c0 + (c3 + c4 v) w): the sparse line of a D-type twist (arkworks `mul_by_034`).
    pub fn mulBy034(a: Fq12, c0: Fq2, c3: Fq2, c4: Fq2) Fq12 {
        const x = a.c0.mulFq2(c0);
        const y = a.c1.mulBy01(c3, c4);
        const e = a.c0.add(a.c1).mulBy01(c0.add(c3), c4);
        return .{ .c0 = x.add(y.mulV()), .c1 = e.sub(x).sub(y) };
    }
    /// Granger-Scott squaring, valid for elements of the cyclotomic subgroup.
    pub fn cyclotomicSq(a: Fq12) Fq12 {
        // Fq4 view: (z0, z4), (z3, z2), (z1, z5) following arkworks' cyclotomic_square.
        const z0 = a.c0.c0;
        const z4 = a.c0.c1;
        const z3 = a.c0.c2;
        const z2 = a.c1.c0;
        const z1 = a.c1.c1;
        const z5 = a.c1.c2;
        // (t0, t1) = (z0 + z1 w)^2 in Fq4 = Fq2[s]/(s^2 - xi)
        var tmp = z0.mul(z1);
        const t0 = z0.add(z1).mul(z0.add(z1.mulXi())).sub(tmp).sub(tmp.mulXi());
        const t1 = tmp.dbl();
        tmp = z2.mul(z3);
        const t2 = z2.add(z3).mul(z2.add(z3.mulXi())).sub(tmp).sub(tmp.mulXi());
        const t3 = tmp.dbl();
        tmp = z4.mul(z5);
        const t4 = z4.add(z5).mul(z4.add(z5.mulXi())).sub(tmp).sub(tmp.mulXi());
        const t5 = tmp.dbl();
        // z0 = 3 t0 - 2 z0, z1 = 3 t1 + 2 z1, ...
        const r0 = t0.sub(z0).dbl().add(t0);
        const r1 = t1.add(z1).dbl().add(t1);
        const t5x = t5.mulXi();
        const r2 = t5x.add(z2).dbl().add(t5x);
        const r3 = t4.sub(z3).dbl().add(t4);
        const r4 = t2.sub(z4).dbl().add(t2);
        const r5 = t3.add(z5).dbl().add(t3);
        return .{ .c0 = .{ .c0 = r0, .c1 = r4, .c2 = r3 }, .c1 = .{ .c0 = r2, .c1 = r1, .c2 = r5 } };
    }

    /// 384 bytes: arkworks compressed (= uncompressed) serialization, each Fq little-endian.
    pub fn toBytes(a: Fq12) [384]u8 {
        var out: [384]u8 = undefined;
        const parts = [12]Fq{ a.c0.c0.c0, a.c0.c0.c1, a.c0.c1.c0, a.c0.c1.c1, a.c0.c2.c0, a.c0.c2.c1, a.c1.c0.c0, a.c1.c0.c1, a.c1.c1.c0, a.c1.c1.c1, a.c1.c2.c0, a.c1.c2.c1 };
        for (parts, 0..) |x, i| out[i * 32 ..][0..32].* = x.toBytesLe();
        return out;
    }
    pub fn fromBytes(b: *const [384]u8) ?Fq12 {
        var v: [12]Fq = undefined;
        for (0..12) |i| v[i] = Fq.fromBytesLeCanonical(b[i * 32 ..][0..32]) orelse return null;
        return .{
            .c0 = .{ .c0 = .{ .c0 = v[0], .c1 = v[1] }, .c1 = .{ .c0 = v[2], .c1 = v[3] }, .c2 = .{ .c0 = v[4], .c1 = v[5] } },
            .c1 = .{ .c0 = .{ .c0 = v[6], .c1 = v[7] }, .c1 = .{ .c0 = v[8], .c1 = v[9] }, .c2 = .{ .c0 = v[10], .c1 = v[11] } },
        };
    }
};

test "tower identities" {
    const a: Fq2 = .{ .c0 = Fq.fromInt(3), .c1 = Fq.fromInt(11) };
    try std.testing.expect(a.mul(a.inverse()).eql(Fq2.one));
    try std.testing.expect(a.sq().eql(a.mul(a)));
    const s = a.sq().sqrt().?;
    try std.testing.expect(s.sq().eql(a.sq()));
    // Frobenius: a^p
    try std.testing.expect(a.pow(fp.q_modulus).eql(a.frob(1)));
    const b6: Fq6 = .{ .c0 = a, .c1 = a.sq(), .c2 = a.add(Fq2.one) };
    try std.testing.expect(b6.sq().eql(b6.mul(b6)));
    try std.testing.expect(b6.mul(b6.inverse()).eql(Fq6.one));
    const f: Fq12 = .{ .c0 = b6, .c1 = b6.mulV() };
    try std.testing.expect(f.sq().eql(f.mul(f)));
    try std.testing.expect(f.mul(f.inverse()).eql(Fq12.one));
    // frob(1) applied 12 times is the identity; frob(2) == frob(1)^2
    var g = f;
    for (0..12) |_| g = g.frob(1);
    try std.testing.expect(g.eql(f));
    try std.testing.expect(f.frob(1).frob(1).eql(f.frob(2)));
    try std.testing.expect(f.frob(1).frob(2).eql(f.frob(3)));
    // sparse multiply equals full multiply
    const c0: Fq2 = .{ .c0 = Fq.fromInt(5), .c1 = Fq.fromInt(6) };
    const c3: Fq2 = .{ .c0 = Fq.fromInt(7), .c1 = Fq.fromInt(8) };
    const c4: Fq2 = .{ .c0 = Fq.fromInt(9), .c1 = Fq.fromInt(10) };
    const sp: Fq12 = .{ .c0 = .{ .c0 = c0, .c1 = Fq2.zero, .c2 = Fq2.zero }, .c1 = .{ .c0 = c3, .c1 = c4, .c2 = Fq2.zero } };
    try std.testing.expect(f.mulBy034(c0, c3, c4).eql(f.mul(sp)));
    // cyclotomic square on a cyclotomic element: f^((p^6-1)(p^2+1))
    var c = f.conj().mul(f.inverse());
    c = c.frob(2).mul(c);
    try std.testing.expect(c.cyclotomicSq().eql(c.sq()));
}
