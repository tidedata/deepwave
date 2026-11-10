//! BN254 groups G1 (over Fq, y^2 = x^3 + 3) and G2 (over Fq2, the D-type sextic twist
//! y^2 = x^3 + 3/(9+u)), with arkworks 0.4 compressed encodings and validity rules.
const std = @import("std");
const fp = @import("fp.zig");
const tower = @import("tower.zig");
const Fq = fp.Fq;
const Fr = fp.Fr;
const Fq2 = tower.Fq2;

pub fn Affine(comptime F: type, comptime b: F) type {
    return struct {
        x: F,
        y: F,
        infinity: bool,

        const Self = @This();
        pub const Base = F;
        pub const coeff_b = b;
        pub const identity: Self = .{ .x = F.zero, .y = F.one, .infinity = true };

        pub fn isOnCurve(p: Self) bool {
            if (p.infinity) return true;
            return p.y.sq().eql(p.x.sq().mul(p.x).add(b));
        }

        pub fn neg(p: Self) Self {
            if (p.infinity) return p;
            return .{ .x = p.x, .y = p.y.neg(), .infinity = false };
        }

        pub fn eql(p: Self, q: Self) bool {
            if (p.infinity or q.infinity) return p.infinity == q.infinity;
            return p.x.eql(q.x) and p.y.eql(q.y);
        }

        pub fn toJacobian(p: Self) Jacobian(F, b) {
            if (p.infinity) return Jacobian(F, b).identity;
            return .{ .x = p.x, .y = p.y, .z = F.one };
        }

        /// arkworks `get_ys_from_x_unchecked` + flag selection: `greatest` picks the larger y.
        pub fn fromX(x: F, greatest: bool) ?Self {
            const y = x.sq().mul(x).add(b).sqrt() orelse return null;
            const ny = y.neg();
            const y_small_first = y.cmp(ny) == .lt;
            const small = if (y_small_first) y else ny;
            const large = if (y_small_first) ny else y;
            return .{ .x = x, .y = if (greatest) large else small, .infinity = false };
        }
    };
}

pub fn Jacobian(comptime F: type, comptime b: F) type {
    return struct {
        x: F,
        y: F,
        z: F,

        const Self = @This();
        pub const identity: Self = .{ .x = F.one, .y = F.one, .z = F.zero };

        pub fn isIdentity(p: Self) bool {
            return p.z.isZero();
        }

        pub fn dbl(p: Self) Self {
            if (p.isIdentity()) return p;
            // dbl-2009-l (a = 0)
            const A = p.x.sq();
            const B = p.y.sq();
            const C = B.sq();
            const D = p.x.add(B).sq().sub(A).sub(C).dbl();
            const E = A.dbl().add(A);
            const Fv = E.sq();
            const x3 = Fv.sub(D.dbl());
            const y3 = E.mul(D.sub(x3)).sub(C.dbl().dbl().dbl());
            const z3 = p.y.mul(p.z).dbl();
            return .{ .x = x3, .y = y3, .z = z3 };
        }

        pub fn add(p: Self, q: Self) Self {
            if (p.isIdentity()) return q;
            if (q.isIdentity()) return p;
            // add-2007-bl
            const z1z1 = p.z.sq();
            const z2z2 = q.z.sq();
            const uu1 = p.x.mul(z2z2);
            const uu2 = q.x.mul(z1z1);
            const s1 = p.y.mul(q.z).mul(z2z2);
            const s2 = q.y.mul(p.z).mul(z1z1);
            if (uu1.eql(uu2)) {
                if (s1.eql(s2)) return p.dbl();
                return identity;
            }
            const h = uu2.sub(uu1);
            const i = h.dbl().sq();
            const j = h.mul(i);
            const r = s2.sub(s1).dbl();
            const v = uu1.mul(i);
            const x3 = r.sq().sub(j).sub(v.dbl());
            const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
            const z3 = p.z.add(q.z).sq().sub(z1z1).sub(z2z2).mul(h);
            return .{ .x = x3, .y = y3, .z = z3 };
        }

        /// p + q with q affine (madd-2007-bl).
        pub fn addAffine(p: Self, q: Affine(F, b)) Self {
            if (q.infinity) return p;
            if (p.isIdentity()) return q.toJacobian();
            const z1z1 = p.z.sq();
            const uu2 = q.x.mul(z1z1);
            const s2 = q.y.mul(p.z).mul(z1z1);
            if (p.x.eql(uu2)) {
                if (p.y.eql(s2)) return p.dbl();
                return identity;
            }
            const h = uu2.sub(p.x);
            const hh = h.sq();
            const i = hh.dbl().dbl();
            const j = h.mul(i);
            const r = s2.sub(p.y).dbl();
            const v = p.x.mul(i);
            const x3 = r.sq().sub(j).sub(v.dbl());
            const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).dbl());
            const z3 = p.z.add(h).sq().sub(z1z1).sub(hh);
            return .{ .x = x3, .y = y3, .z = z3 };
        }

        pub fn neg(p: Self) Self {
            return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
        }

        pub fn toAffine(p: Self) Affine(F, b) {
            if (p.isIdentity()) return Affine(F, b).identity;
            const zi = p.z.inverse();
            const zi2 = zi.sq();
            return .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2).mul(zi), .infinity = false };
        }

        /// [k]p for little-endian limbs k (variable time; public scalars only).
        pub fn mulLimbs(p: Affine(F, b), k: []const u64) Self {
            var r = identity;
            var i: usize = k.len;
            var started = false;
            while (i > 0) {
                i -= 1;
                var bit: u7 = 64;
                while (bit > 0) {
                    bit -= 1;
                    if (started) r = r.dbl();
                    if ((k[i] >> @intCast(bit)) & 1 == 1) {
                        r = r.addAffine(p);
                        started = true;
                    }
                }
            }
            return r;
        }
    };
}

pub const g2_b: Fq2 = .{
    .c0 = Fq.fromInt(19485874751759354771024239261021720505790618469301721065564631296452457478373),
    .c1 = Fq.fromInt(266929791119991161246907387137283842545076965332900288569378510910307636690),
};

pub const G1 = Affine(Fq, Fq.fromInt(3));
pub const G1J = Jacobian(Fq, Fq.fromInt(3));
pub const G2 = Affine(Fq2, g2_b);
pub const G2J = Jacobian(Fq2, g2_b);

pub const g1_generator: G1 = .{ .x = Fq.fromInt(1), .y = Fq.fromInt(2), .infinity = false };
pub const g2_generator: G2 = .{
    .x = .{
        .c0 = Fq.fromInt(10857046999023057135944570762232829481370756359578518086990519993285655852781),
        .c1 = Fq.fromInt(11559732032986387107991004021392285783925812861821192530917403151452391805634),
    },
    .y = .{
        .c0 = Fq.fromInt(8495653923123431417604973247489272438418190587263600148770280649306958101930),
        .c1 = Fq.fromInt(4082367875863433681332203403145435568316851327593401208105741076214120093531),
    },
    .infinity = false,
};

/// [r]Q == identity: the definition of G2 membership (arkworks 0.4's check). Reference for tests.
pub fn g2InSubgroupSlow(q: G2) bool {
    if (q.infinity) return true;
    const r_limbs = comptime fp.limbsOf(fp.r_modulus);
    return G2J.mulLimbs(q, &r_limbs).isIdentity();
}

const psi_x: Fq2 = .{
    .c0 = Fq.fromInt(21575463638280843010398324269430826099269044274347216827212613867836435027261),
    .c1 = Fq.fromInt(10307601595873709700152284273816112264069230130616436755625194854815875713954),
};
const psi_y: Fq2 = .{
    .c0 = Fq.fromInt(2821565182194536844548159561693502659359617185244120367078079554186484126554),
    .c1 = Fq.fromInt(3505843767911556378687030309984248845540243509899259641013678093033130930403),
};

/// The untwist-Frobenius-twist endomorphism psi on E'(Fq2) (arkworks `mul_by_char`).
pub fn psi(q: G2) G2 {
    return .{ .x = q.x.frob(1).mul(psi_x), .y = q.y.frob(1).mul(psi_y), .infinity = q.infinity };
}

/// G2 membership for a point on the twist: psi(Q) == [6x^2]Q (El Housni, Guillevic, Piellard,
/// eprint 2022/348 section 4; the check ark-bn254 0.5 uses). Same answer as [r]Q == O for every
/// point on the curve, at half the cost; the tests cross-check it against `g2InSubgroupSlow`.
pub fn g2InSubgroup(q: G2) bool {
    if (q.infinity) return true;
    const six_x_sq = comptime limbs2(6 * 4965661367192848881 * 4965661367192848881);
    const a = G2J.mulLimbs(q, &six_x_sq);
    if (a.isIdentity()) return false;
    const b = psi(q);
    const z2 = a.z.sq();
    return a.x.eql(b.x.mul(z2)) and a.y.eql(b.y.mul(z2.mul(a.z)));
}

fn limbs2(comptime v: comptime_int) [2]u64 {
    return .{ v & 0xffffffffffffffff, v >> 64 };
}

test "psi subgroup check equals [r]Q == O" {
    // subgroup points
    var k: u64 = 1;
    while (k < 6) : (k += 1) {
        const q = G2J.mulLimbs(g2_generator, &.{ k *% 0x9e3779b97f4a7c15, k, 0, 0 }).toAffine();
        try std.testing.expect(g2InSubgroup(q) and g2InSubgroupSlow(q));
    }
    // arbitrary points on the twist (almost surely outside G2)
    var x = Fq2{ .c0 = Fq.fromU64(1), .c1 = Fq.fromU64(0) };
    var seen: usize = 0;
    while (seen < 12) : (x = x.add(Fq2.one)) {
        const q = G2.fromX(x, false) orelse continue;
        seen += 1;
        try std.testing.expectEqual(g2InSubgroupSlow(q), g2InSubgroup(q));
        try std.testing.expectEqual(g2InSubgroupSlow(q.neg()), g2InSubgroup(q.neg()));
    }
}

pub const DecodeError = error{InvalidPoint};

/// arkworks SW flags in the top two bits of the last byte: 0x80 = y is the larger root,
/// 0x40 = point at infinity, both set = invalid.
const Flags = enum { y_small, y_large, infinity };

fn takeFlags(last: *u8) ?Flags {
    const neg = (last.* >> 7) & 1 == 1;
    const inf = (last.* >> 6) & 1 == 1;
    last.* &= 0x3f;
    if (neg and inf) return null;
    if (inf) return .infinity;
    return if (neg) .y_large else .y_small;
}

/// G1 compressed (32 bytes LE x with flags). Validates as arkworks' `deserialize_compressed`.
pub fn g1FromCompressed(bytes: *const [32]u8) DecodeError!G1 {
    var b = bytes.*;
    const flags = takeFlags(&b[31]) orelse return error.InvalidPoint;
    const x = Fq.fromBytesLeCanonical(&b) orelse return error.InvalidPoint;
    if (flags == .infinity) return G1.identity;
    // G1 has cofactor 1: every curve point is in the subgroup.
    return G1.fromX(x, flags == .y_large) orelse error.InvalidPoint;
}

pub fn g1ToCompressed(p: G1) [32]u8 {
    if (p.infinity) {
        var out: [32]u8 = @splat(0);
        out[31] = 0x40;
        return out;
    }
    var out = p.x.toBytesLe();
    if (!p.y.isLexSmallest()) out[31] |= 0x80;
    return out;
}

/// G2 compressed (64 bytes: x.c0 LE, then x.c1 LE with flags). Validates on-curve and subgroup.
pub fn g2FromCompressed(bytes: *const [64]u8) DecodeError!G2 {
    var b = bytes.*;
    const c0 = Fq.fromBytesLeCanonical(b[0..32]) orelse return error.InvalidPoint;
    const flags = takeFlags(&b[63]) orelse return error.InvalidPoint;
    const c1 = Fq.fromBytesLeCanonical(b[32..64]) orelse return error.InvalidPoint;
    if (flags == .infinity) return G2.identity;
    const p = G2.fromX(.{ .c0 = c0, .c1 = c1 }, flags == .y_large) orelse return error.InvalidPoint;
    if (!g2InSubgroup(p)) return error.InvalidPoint;
    return p;
}

pub fn g2ToCompressed(p: G2) [64]u8 {
    var out: [64]u8 = @splat(0);
    if (p.infinity) {
        out[63] = 0x40;
        return out;
    }
    out[0..32].* = p.x.c0.toBytesLe();
    out[32..64].* = p.x.c1.toBytesLe();
    if (!p.y.isLexSmallest()) out[63] |= 0x80;
    return out;
}

test "generators and encodings" {
    try std.testing.expect(g1_generator.isOnCurve());
    try std.testing.expect(g2_generator.isOnCurve());
    try std.testing.expect(g2InSubgroup(g2_generator));
    const r_limbs = comptime fp.limbsOf(fp.r_modulus);
    try std.testing.expect(G1J.mulLimbs(g1_generator, &r_limbs).isIdentity());
    const p5 = G1J.mulLimbs(g1_generator, &.{ 5, 0, 0, 0 }).toAffine();
    const p5b = g1_generator.toJacobian().dbl().dbl().addAffine(g1_generator).toAffine();
    try std.testing.expect(p5.eql(p5b));
    const enc = g1ToCompressed(p5);
    try std.testing.expect((try g1FromCompressed(&enc)).eql(p5));
    const q3 = G2J.mulLimbs(g2_generator, &.{ 3, 0, 0, 0 }).toAffine();
    const qenc = g2ToCompressed(q3);
    try std.testing.expect((try g2FromCompressed(&qenc)).eql(q3));
    try std.testing.expect((try g2FromCompressed(&g2ToCompressed(q3.neg()))).eql(q3.neg()));
}
