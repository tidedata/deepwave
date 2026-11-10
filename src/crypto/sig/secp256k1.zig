//! secp256k1 arithmetic for ECDSA verification and public-key recovery (public data, variable
//! time), built the way libsecp256k1 gets its speed:
//!   - GF(p) in four 64-bit limbs with the special reduction 2^256 = 0x1000003D1 (mod p) and
//!     lazily reduced values (any 256-bit representative);
//!   - Jacobian coordinates with the a = 0 doubling (2M + 5S) and mixed/general additions;
//!   - the GLV endomorphism lambda*(x, y) = (beta*x, y) splits the variable-base scalar into two
//!     signed 128-bit halves (libsecp's `scalar_split_lambda` constants);
//!   - the generator scalar is split into 128-bit halves over comptime tables of G and 2^128 G
//!     (odd multiples up to 127, affine);
//!   - the final x check compares X with r*Z^2 (and (r+n)*Z^2), so verification needs no field
//!     inversion; scalars are inverted with Lehmer's extended Euclid.
//! The acceptance rules live in ecdsa.zig; this file only computes points.
const std = @import("std");
const ed = @import("ed25519.zig");
const lehmer = @import("lehmer.zig");

pub const p_int: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
pub const n_int: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
const C: u64 = 0x1000003D1; // 2^256 - p

pub const Fe = struct {
    l: [4]u64,

    pub const zero: Fe = .{ .l = .{ 0, 0, 0, 0 } };
    pub const one: Fe = .{ .l = .{ 1, 0, 0, 0 } };

    pub fn fromInt(x: u256) Fe {
        return .{ .l = .{ @truncate(x), @truncate(x >> 64), @truncate(x >> 128), @truncate(x >> 192) } };
    }

    pub fn toInt(a: Fe) u256 {
        const r = a.normalize();
        return @as(u256, r.l[0]) | (@as(u256, r.l[1]) << 64) | (@as(u256, r.l[2]) << 128) | (@as(u256, r.l[3]) << 192);
    }

    /// Fully reduced (< p).
    pub inline fn normalize(a: Fe) Fe {
        // a >= p iff a + C >= 2^256
        var r: [4]u64 = undefined;
        var c: u1 = 0;
        var t = @addWithOverflow(a.l[0], C);
        r[0] = t[0];
        c = t[1];
        inline for (1..4) |i| {
            t = @addWithOverflow(a.l[i], @as(u64, c));
            r[i] = t[0];
            c = t[1];
        }
        return if (c == 1) .{ .l = r } else a;
    }

    pub fn isZero(a: Fe) bool {
        const r = a.normalize();
        return (r.l[0] | r.l[1] | r.l[2] | r.l[3]) == 0;
    }

    pub fn eql(a: Fe, b: Fe) bool {
        return a.sub(b).isZero();
    }

    pub fn isOdd(a: Fe) bool {
        return a.normalize().l[0] & 1 == 1;
    }

    inline fn addC(r: *[4]u64, k: u64) u1 {
        var t = @addWithOverflow(r[0], k);
        r[0] = t[0];
        inline for (1..4) |i| {
            t = @addWithOverflow(r[i], @as(u64, t[1]));
            r[i] = t[0];
        }
        return t[1];
    }

    pub inline fn add(a: Fe, b: Fe) Fe {
        var r: [4]u64 = undefined;
        var c: u1 = 0;
        inline for (0..4) |i| {
            const s1 = @addWithOverflow(a.l[i], b.l[i]);
            const s2 = @addWithOverflow(s1[0], @as(u64, c));
            r[i] = s2[0];
            c = s1[1] | s2[1];
        }
        // wrap: add C per carry (at most twice)
        const c2 = addC(&r, C * @as(u64, c));
        if (c2 == 1) {
            @branchHint(.cold); // only when both inputs are >= p (non-canonical representatives)
            _ = addC(&r, C);
        }
        return .{ .l = r };
    }

    inline fn subC(r: *[4]u64, k: u64) u1 {
        var t = @subWithOverflow(r[0], k);
        r[0] = t[0];
        inline for (1..4) |i| {
            t = @subWithOverflow(r[i], @as(u64, t[1]));
            r[i] = t[0];
        }
        return t[1];
    }

    pub inline fn sub(a: Fe, b: Fe) Fe {
        var r: [4]u64 = undefined;
        var bw: u1 = 0;
        inline for (0..4) |i| {
            const s1 = @subWithOverflow(a.l[i], b.l[i]);
            const s2 = @subWithOverflow(s1[0], @as(u64, bw));
            r[i] = s2[0];
            bw = s1[1] | s2[1];
        }
        // borrow means the 256-bit result is a - b + 2^256: subtract C per borrow
        const b2 = subC(&r, C * @as(u64, bw));
        if (b2 == 1) {
            @branchHint(.cold);
            _ = subC(&r, C);
        }
        return .{ .l = r };
    }

    /// a * k for a small constant k (< 2^30).
    pub inline fn mulSmall(a: Fe, k: u64) Fe {
        var r: [4]u64 = undefined;
        var carry: u64 = 0;
        inline for (0..4) |i| {
            const pr = @as(u128, a.l[i]) * k + carry;
            r[i] = @truncate(pr);
            carry = @truncate(pr >> 64);
        }
        // carry < k: fold carry * 2^256 = carry * C
        const c2 = addC(&r, carry * C);
        if (c2 == 1) {
            @branchHint(.cold);
            _ = addC(&r, C);
        }
        return .{ .l = r };
    }

    /// x^-1 for a public x (variable time, Lehmer's extended Euclid). 0 for 0.
    pub fn invertVar(a: Fe) Fe {
        return fromInt(lehmer.invMod(a.toInt(), p_int));
    }

    pub inline fn neg(a: Fe) Fe {
        return zero.sub(a);
    }

    pub inline fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    inline fn reduce512(t: [8]u64) Fe {
        var r: [4]u64 = undefined;
        var carry: u64 = 0;
        inline for (0..4) |i| {
            const pr = @as(u128, t[4 + i]) * C + t[i] + carry;
            r[i] = @truncate(pr);
            carry = @truncate(pr >> 64);
        }
        // carry < 2^34: add carry * C
        const pr = @as(u128, carry) * C + r[0];
        r[0] = @truncate(pr);
        var t2 = @addWithOverflow(r[1], @as(u64, @truncate(pr >> 64)));
        r[1] = t2[0];
        t2 = @addWithOverflow(r[2], @as(u64, t2[1]));
        r[2] = t2[0];
        t2 = @addWithOverflow(r[3], @as(u64, t2[1]));
        r[3] = t2[0];
        _ = addC(&r, C * @as(u64, t2[1]));
        return .{ .l = r };
    }

    pub inline fn mul(a: Fe, b: Fe) Fe {
        var t: [8]u64 = @splat(0);
        inline for (0..4) |i| {
            var carry: u64 = 0;
            inline for (0..4) |j| {
                const pr = @as(u128, a.l[i]) * b.l[j] + t[i + j] + carry;
                t[i + j] = @truncate(pr);
                carry = @truncate(pr >> 64);
            }
            t[i + 4] = carry;
        }
        return reduce512(t);
    }

    pub inline fn sq(a: Fe) Fe {
        // cross products once, doubled, plus the diagonal
        var t: [8]u64 = @splat(0);
        inline for (0..3) |i| {
            var carry: u64 = 0;
            inline for (i + 1..4) |j| {
                const pr = @as(u128, a.l[i]) * a.l[j] + t[i + j] + carry;
                t[i + j] = @truncate(pr);
                carry = @truncate(pr >> 64);
            }
            t[i + 4] = carry;
        }
        // double
        var hi: u64 = 0;
        inline for (1..8) |k| {
            const v = t[k];
            t[k] = (v << 1) | hi;
            hi = v >> 63;
        }
        var carry: u64 = 0;
        inline for (0..4) |i| {
            const d = @as(u128, a.l[i]) * a.l[i];
            const lo = @as(u128, t[2 * i]) + @as(u64, @truncate(d)) + carry;
            t[2 * i] = @truncate(lo);
            const h2 = @as(u128, t[2 * i + 1]) + @as(u64, @truncate(d >> 64)) + @as(u64, @truncate(lo >> 64));
            t[2 * i + 1] = @truncate(h2);
            carry = @truncate(h2 >> 64);
        }
        return reduce512(t);
    }

    pub fn sqn(a: Fe, n: usize) Fe {
        var r = a;
        for (0..n) |_| r = r.sq();
        return r;
    }

    /// Shared prefix of the inversion and square-root chains (libsecp256k1 field_impl.h).
    fn chain(a: Fe) struct { x2: Fe, x3: Fe, x22: Fe, x223: Fe } {
        const x2 = a.sq().mul(a);
        const x3 = x2.sq().mul(a);
        const x6 = x3.sqn(3).mul(x3);
        const x9 = x6.sqn(3).mul(x3);
        const x11 = x9.sqn(2).mul(x2);
        const x22 = x11.sqn(11).mul(x11);
        const x44 = x22.sqn(22).mul(x22);
        const x88 = x44.sqn(44).mul(x44);
        const x176 = x88.sqn(88).mul(x88);
        const x220 = x176.sqn(44).mul(x44);
        const x223 = x220.sqn(3).mul(x3);
        return .{ .x2 = x2, .x3 = x3, .x22 = x22, .x223 = x223 };
    }

    /// a^(p-2)
    pub fn invert(a: Fe) Fe {
        const c = chain(a);
        var t = c.x223.sqn(23).mul(c.x22);
        t = t.sqn(5).mul(a);
        t = t.sqn(3).mul(c.x2);
        return t.sqn(2).mul(a);
    }

    /// A square root of a, or null if a is not a square: a^((p+1)/4).
    pub fn sqrt(a: Fe) ?Fe {
        const c = chain(a);
        var t = c.x223.sqn(23).mul(c.x22);
        t = t.sqn(6).mul(c.x2);
        const r = t.sqn(2);
        if (!r.sq().eql(a)) return null;
        return r;
    }

    pub fn fromBytes(b: *const [32]u8) Fe {
        return fromInt(std.mem.readInt(u256, b, .big));
    }

    pub fn toBytes(a: Fe) [32]u8 {
        var out: [32]u8 = undefined;
        std.mem.writeInt(u256, &out, a.toInt(), .big);
        return out;
    }
};

const b7: Fe = Fe.fromInt(7);
pub const beta: Fe = Fe.fromInt(0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee);
const beta52: F52 = blk: {
    @setEvalBranchQuota(100_000);
    break :blk F52.fromFe(beta);
};

pub const Affine = struct {
    x: Fe,
    y: Fe,

    pub fn isOnCurve(a: Affine) bool {
        return a.y.sq().eql(a.x.sq().mul(a.x).add(b7));
    }

    /// y with the requested parity for x, or null if x^3 + 7 is not a square.
    pub fn fromX(x: Fe, odd: bool) ?Affine {
        var y = (x.sq().mul(x).add(b7)).sqrt() orelse return null;
        y = y.normalize();
        if (y.isOdd() != odd) y = y.neg().normalize();
        return .{ .x = x, .y = y };
    }

    pub fn neg(a: Affine) Affine {
        return .{ .x = a.x, .y = a.y.neg() };
    }

    pub fn toCompressedSec1(a: Affine) [33]u8 {
        return a.compressed();
    }

    pub fn compressed(a: Affine) [33]u8 {
        var out: [33]u8 = undefined;
        out[0] = if (a.y.isOdd()) 3 else 2;
        out[1..33].* = a.x.toBytes();
        return out;
    }
};

pub const Jac = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    inf: bool,

    pub const infinity: Jac = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero, .inf = true };

    pub fn fromAffine(a: Affine) Jac {
        return .{ .x = a.x, .y = a.y, .z = Fe.one, .inf = false };
    }

    /// dbl-2009-l (a = 0): 2M + 5S.
    pub fn dbl(p: Jac) Jac {
        if (p.inf) return p;
        const a = p.x.sq();
        const b = p.y.sq();
        const c = b.sq();
        const d = p.x.add(b).sq().sub(a).sub(c).dbl();
        const e = a.mulSmall(3);
        const f = e.sq();
        const x3 = f.sub(d.dbl());
        const c8 = c.mulSmall(8);
        const y3 = e.mul(d.sub(x3)).sub(c8);
        const z3 = p.y.mul(p.z).dbl();
        // y = 0 cannot occur for a point of odd order (no 2-torsion on secp256k1)
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// madd-2007-bl (q affine): 7M + 4S, with the exceptional cases.
    pub fn addAffine(p: Jac, q: Affine) Jac {
        if (p.inf) return fromAffine(q);
        const z1z1 = p.z.sq();
        const uu2 = q.x.mul(z1z1);
        const s2 = q.y.mul(p.z).mul(z1z1);
        const h = uu2.sub(p.x);
        const r = s2.sub(p.y).dbl();
        if (h.isZero()) {
            if (r.isZero()) return p.dbl();
            return infinity;
        }
        const hh = h.sq();
        const i = hh.mulSmall(4);
        const j = h.mul(i);
        const v = p.x.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).dbl());
        const z3 = p.z.add(h).sq().sub(z1z1).sub(hh);
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// add-2007-bl: 11M + 5S, with the exceptional cases.
    pub fn add(p: Jac, q: Jac) Jac {
        if (p.inf) return q;
        if (q.inf) return p;
        const z1z1 = p.z.sq();
        const z2z2 = q.z.sq();
        const uu1 = p.x.mul(z2z2);
        const uu2 = q.x.mul(z1z1);
        const s1 = p.y.mul(q.z).mul(z2z2);
        const s2 = q.y.mul(p.z).mul(z1z1);
        const h = uu2.sub(uu1);
        const r = s2.sub(s1).dbl();
        if (h.isZero()) {
            if (r.isZero()) return p.dbl();
            return infinity;
        }
        const i = h.dbl().sq();
        const j = h.mul(i);
        const v = uu1.mul(i);
        const x3 = r.sq().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = p.z.add(q.z).sq().sub(z1z1).sub(z2z2).mul(h);
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    pub fn neg(p: Jac) Jac {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z, .inf = p.inf };
    }

    /// Affine form through the exponentiation inverse (usable at comptime).
    pub fn zToOne(p: Jac) Affine {
        const zi = p.z.invert();
        const zi2 = zi.sq();
        return .{ .x = p.x.mul(zi2).normalize(), .y = p.y.mul(zi2).mul(zi).normalize() };
    }

    pub fn toAffine(p: Jac) ?Affine {
        if (p.inf) return null;
        const zi = p.z.invertVar();
        const zi2 = zi.sq();
        return .{ .x = p.x.mul(zi2).normalize(), .y = p.y.mul(zi2).mul(zi).normalize() };
    }
};

// ---------------------------------------------------------------------------------------------
// The ladder field: libsecp256k1's 5x52 representation with magnitudes. A value of magnitude m
// has limbs below 2m(2^52 - 1) (top limb 2m(2^48 - 1)); add sums magnitudes, negate(m) gives
// m + 1, mul/sq take magnitude <= 8 and return magnitude 1. Linear operations carry nothing,
// which is what makes the point formulas cheap. Values enter from Fe (reduced) and leave
// through toFe.

const M52: u64 = 0xFFFFFFFFFFFFF;
const M48: u64 = 0x0FFFFFFFFFFFF;
const R52: u64 = 0x1000003D10;
const P0: u64 = 0xFFFFEFFFFFC2F;

pub const F52 = struct {
    n: [5]u64,

    pub fn fromFe(a: Fe) F52 {
        const x = a.toInt();
        return .{ .n = .{
            @as(u64, @truncate(x)) & M52,
            @as(u64, @truncate(x >> 52)) & M52,
            @as(u64, @truncate(x >> 104)) & M52,
            @as(u64, @truncate(x >> 156)) & M52,
            @truncate(x >> 208),
        } };
    }

    /// Fold and carry: value below 2^256 + 2^34, limbs 0..3 below 2^52.
    inline fn weak(a: F52) [5]u64 {
        var t = a.n;
        const x = t[4] >> 48;
        t[4] &= M48;
        t[0] += x * 0x1000003D1;
        t[1] += t[0] >> 52;
        t[0] &= M52;
        t[2] += t[1] >> 52;
        t[1] &= M52;
        t[3] += t[2] >> 52;
        t[2] &= M52;
        t[4] += t[3] >> 52;
        t[3] &= M52;
        return t;
    }

    pub fn toFe(a: F52) Fe {
        const t = a.weak();
        const v: u256 = @as(u256, t[0]) | (@as(u256, t[1]) << 52) | (@as(u256, t[2]) << 104) | (@as(u256, t[3]) << 156) | (@as(u256, t[4] & M48) << 208);
        // bit 256 (t[4] >> 48) folds as C
        return Fe.fromInt(v).add(Fe.fromInt(@as(u256, t[4] >> 48) * C)).normalize();
    }

    /// a == 0 (mod p), variable time.
    pub inline fn isZeroVar(a: F52) bool {
        const t = a.weak();
        const z0 = t[0] | t[1] | t[2] | t[3] | t[4];
        const z1 = (t[0] ^ 0x1000003D0) & t[1] & t[2] & t[3] & (t[4] ^ 0xF000000000000);
        return z0 == 0 or z1 == M52;
    }

    pub inline fn add(a: F52, b: F52) F52 {
        return .{ .n = .{ a.n[0] + b.n[0], a.n[1] + b.n[1], a.n[2] + b.n[2], a.n[3] + b.n[3], a.n[4] + b.n[4] } };
    }

    /// -a for a of magnitude at most m; magnitude m + 1.
    pub inline fn negate(a: F52, comptime m: u64) F52 {
        const k = 2 * (m + 1);
        return .{ .n = .{ P0 * k - a.n[0], M52 * k - a.n[1], M52 * k - a.n[2], M52 * k - a.n[3], M48 * k - a.n[4] } };
    }

    pub inline fn mulInt(a: F52, comptime k: u64) F52 {
        return .{ .n = .{ a.n[0] * k, a.n[1] * k, a.n[2] * k, a.n[3] * k, a.n[4] * k } };
    }

    /// a / 2; magnitude m becomes m/2 + 1.
    pub inline fn half(a: F52) F52 {
        var t = a.n;
        const mask = (0 -% (t[0] & 1)) >> 12;
        t[0] += P0 & mask;
        t[1] += mask;
        t[2] += mask;
        t[3] += mask;
        t[4] += mask >> 4;
        return .{ .n = .{
            (t[0] >> 1) + ((t[1] & 1) << 51),
            (t[1] >> 1) + ((t[2] & 1) << 51),
            (t[2] >> 1) + ((t[3] & 1) << 51),
            (t[3] >> 1) + ((t[4] & 1) << 51),
            t[4] >> 1,
        } };
    }

    inline fn lo(x: u128) u64 {
        return @truncate(x);
    }

    pub inline fn mul(a: F52, bb: F52) F52 {
        const a0 = a.n[0];
        const a1 = a.n[1];
        const a2 = a.n[2];
        const a3 = a.n[3];
        const a4 = a.n[4];
        const b = bb.n;
        var r: [5]u64 = undefined;
        var d: u128 = @as(u128, a0) * b[3] + @as(u128, a1) * b[2] + @as(u128, a2) * b[1] + @as(u128, a3) * b[0];
        var c: u128 = @as(u128, a4) * b[4];
        d += @as(u128, R52) * lo(c);
        c >>= 64;
        const t3: u64 = lo(d) & M52;
        d >>= 52;
        d += @as(u128, a0) * b[4] + @as(u128, a1) * b[3] + @as(u128, a2) * b[2] + @as(u128, a3) * b[1] + @as(u128, a4) * b[0];
        d += @as(u128, R52 << 12) * lo(c);
        var t4: u64 = lo(d) & M52;
        d >>= 52;
        const tx = t4 >> 48;
        t4 &= M48;
        c = @as(u128, a0) * b[0];
        d += @as(u128, a1) * b[4] + @as(u128, a2) * b[3] + @as(u128, a3) * b[2] + @as(u128, a4) * b[1];
        var w0: u64 = lo(d) & M52;
        d >>= 52;
        w0 = (w0 << 4) | tx;
        c += @as(u128, w0) * (R52 >> 4);
        r[0] = lo(c) & M52;
        c >>= 52;
        c += @as(u128, a0) * b[1] + @as(u128, a1) * b[0];
        d += @as(u128, a2) * b[4] + @as(u128, a3) * b[3] + @as(u128, a4) * b[2];
        c += @as(u128, lo(d) & M52) * R52;
        d >>= 52;
        r[1] = lo(c) & M52;
        c >>= 52;
        c += @as(u128, a0) * b[2] + @as(u128, a1) * b[1] + @as(u128, a2) * b[0];
        d += @as(u128, a3) * b[4] + @as(u128, a4) * b[3];
        c += @as(u128, R52) * lo(d);
        d >>= 64;
        r[2] = lo(c) & M52;
        c >>= 52;
        c += @as(u128, R52 << 12) * lo(d) + t3;
        r[3] = lo(c) & M52;
        c >>= 52;
        c += t4;
        r[4] = lo(c);
        return .{ .n = r };
    }

    pub inline fn sq(a: F52) F52 {
        var a0 = a.n[0];
        const a1 = a.n[1];
        const a2 = a.n[2];
        const a3 = a.n[3];
        var a4 = a.n[4];
        var r: [5]u64 = undefined;
        var d: u128 = @as(u128, a0 * 2) * a3 + @as(u128, a1 * 2) * a2;
        var c: u128 = @as(u128, a4) * a4;
        d += @as(u128, R52) * lo(c);
        c >>= 64;
        const t3: u64 = lo(d) & M52;
        d >>= 52;
        a4 *= 2;
        d += @as(u128, a0) * a4 + @as(u128, a1 * 2) * a3 + @as(u128, a2) * a2;
        d += @as(u128, R52 << 12) * lo(c);
        var t4: u64 = lo(d) & M52;
        d >>= 52;
        const tx = t4 >> 48;
        t4 &= M48;
        c = @as(u128, a0) * a0;
        d += @as(u128, a1) * a4 + @as(u128, a2 * 2) * a3;
        var w0: u64 = lo(d) & M52;
        d >>= 52;
        w0 = (w0 << 4) | tx;
        c += @as(u128, w0) * (R52 >> 4);
        r[0] = lo(c) & M52;
        c >>= 52;
        a0 *= 2;
        c += @as(u128, a0) * a1;
        d += @as(u128, a2) * a4 + @as(u128, a3) * a3;
        c += @as(u128, lo(d) & M52) * R52;
        d >>= 52;
        r[1] = lo(c) & M52;
        c >>= 52;
        c += @as(u128, a0) * a2 + @as(u128, a1) * a1;
        d += @as(u128, a3) * a4;
        c += @as(u128, R52) * lo(d);
        d >>= 64;
        r[2] = lo(c) & M52;
        c >>= 52;
        c += @as(u128, R52 << 12) * lo(d) + t3;
        r[3] = lo(c) & M52;
        c >>= 52;
        c += t4;
        r[4] = lo(c);
        return .{ .n = r };
    }
};

const one52: F52 = .{ .n = .{ 1, 0, 0, 0, 0 } };

/// Affine point in ladder form (magnitude 1).
pub const A52 = struct {
    x: F52,
    y: F52,

    pub fn from(a: Affine) A52 {
        return .{ .x = F52.fromFe(a.x), .y = F52.fromFe(a.y) };
    }
};

/// Jacobian point in ladder form: x magnitude <= 4, y <= 3, z = 1 (libsecp256k1 bounds).
pub const J52 = struct {
    x: F52,
    y: F52,
    z: F52,
    inf: bool,

    pub const infinity: J52 = .{ .x = .{ .n = @splat(0) }, .y = .{ .n = .{ 1, 0, 0, 0, 0 } }, .z = .{ .n = @splat(0) }, .inf = true };

    /// libsecp256k1 gej_double: 3M + 4S.
    pub inline fn dbl(a: J52) J52 {
        if (a.inf) return a;
        const z3 = a.z.mul(a.y);
        var s = a.y.sq();
        const l = a.x.sq().mulInt(3).half();
        const t = s.negate(1).mul(a.x);
        const x3 = l.sq().add(t).add(t);
        s = s.sq();
        const y3 = t.add(x3).mul(l).add(s).negate(2);
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// libsecp256k1 gej_add_ge_var: 8M + 3S. `b_y` is b.y or its negation (magnitude <= 2).
    pub inline fn addAffine(a: J52, bx: F52, by: F52) J52 {
        if (a.inf) return .{ .x = bx, .y = by, .z = one52, .inf = false };
        return a.addAffineZ(bx, by, a.z);
    }

    /// a + b where b is affine on a curve scaled by w relative to a's curve, given zz = a.z * w
    /// (libsecp256k1 gej_add_zinv_var); zz = a.z is the plain mixed addition. `a` is finite.
    pub inline fn addAffineZ(a: J52, bx: F52, by: F52, zz: F52) J52 {
        const z12 = zz.sq();
        const u_2 = bx.mul(z12);
        const s2 = by.mul(z12).mul(zz);
        const h = a.x.negate(4).add(u_2);
        const i = s2.negate(1).add(a.y);
        if (h.isZeroVar()) {
            @branchHint(.cold);
            if (i.isZeroVar()) return a.dbl();
            return infinity;
        }
        const z3 = a.z.mul(h);
        const h2 = h.sq().negate(1);
        const h3 = h2.mul(h);
        const t = a.x.mul(h2);
        const x3 = i.sq().add(h3).add(t).add(t);
        const y3 = t.add(x3).mul(i).add(h3.mul(a.y));
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    pub fn toJac(a: J52) Jac {
        if (a.inf) return Jac.infinity;
        return .{ .x = a.x.toFe(), .y = a.y.toFe(), .z = a.z.toFe(), .inf = false };
    }
};

pub const generator: Affine = .{
    .x = Fe.fromInt(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798),
    .y = Fe.fromInt(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
};

/// Width of the generator NAFs: tables hold the odd multiples up to 2^(g_w - 1) - 1.
const g_w = 12;
const g_n = 1 << (g_w - 2);

/// Comptime curve arithmetic on plain integers: the interpreter does a u512 multiply and
/// remainder as one step, far cheaper than evaluating the limb code, so the width-12 tables
/// cost little compile time.
const cmp = struct {
    const J = struct { x: u256, y: u256, z: u256 };

    fn m(a: u256, b: u256) u256 {
        return @intCast((@as(u512, a) * b) % p_int);
    }
    fn ad(a: u256, b: u256) u256 {
        return @intCast((@as(u257, a) + b) % p_int);
    }
    fn sb(a: u256, b: u256) u256 {
        return if (a >= b) a - b else @intCast(@as(u257, a) + p_int - b);
    }
    fn inv(a: u256) u256 {
        @setEvalBranchQuota(100_000_000);
        const e = p_int - 2;
        var r: u256 = 1;
        var i: usize = 256;
        while (i > 0) {
            i -= 1;
            r = m(r, r);
            if ((e >> @intCast(i)) & 1 == 1) r = m(r, a);
        }
        return r;
    }
    /// a = 0 doubling (dbl-2009-l).
    fn dbl(p: J) J {
        const a = m(p.x, p.x);
        const b = m(p.y, p.y);
        const c = m(b, b);
        const xb = ad(p.x, b);
        const d = m(sb(sb(m(xb, xb), a), c), 2);
        const e = m(a, 3);
        const x3 = sb(m(e, e), m(d, 2));
        const y3 = sb(m(e, sb(d, x3)), m(c, 8));
        const z3 = m(m(p.y, p.z), 2);
        return .{ .x = x3, .y = y3, .z = z3 };
    }
    /// p + q for distinct, non-opposite finite points.
    fn add(p: J, q: J) J {
        const z1z1 = m(p.z, p.z);
        const z2z2 = m(q.z, q.z);
        const uu1 = m(p.x, z2z2);
        const uu2 = m(q.x, z1z1);
        const s1 = m(m(p.y, q.z), z2z2);
        const s2 = m(m(q.y, p.z), z1z1);
        const h = sb(uu2, uu1);
        const r = sb(s2, s1);
        const hh = m(h, h);
        const hhh = m(hh, h);
        const v = m(uu1, hh);
        const x3 = sb(sb(m(r, r), hhh), ad(v, v));
        const y3 = sb(m(r, sb(v, x3)), m(s1, hhh));
        const z3 = m(m(p.z, q.z), h);
        return .{ .x = x3, .y = y3, .z = z3 };
    }
    fn affine(p: J) [2]u256 {
        const zi = inv(p.z);
        const zi2 = m(zi, zi);
        return .{ m(p.x, zi2), m(m(p.y, zi2), zi) };
    }
    fn f52(x: u256) F52 {
        return .{ .n = .{
            @as(u64, @truncate(x)) & M52,
            @as(u64, @truncate(x >> 52)) & M52,
            @as(u64, @truncate(x >> 104)) & M52,
            @as(u64, @truncate(x >> 156)) & M52,
            @truncate(x >> 208),
        } };
    }
    /// g, 3g, ..., (2N - 1)g, affine, ladder form.
    fn oddMultiples(comptime N: usize, gx: u256, gy: u256) [N]A52 {
        @setEvalBranchQuota(2_000_000_000);
        var pts: [N]J = undefined;
        pts[0] = .{ .x = gx, .y = gy, .z = 1 };
        const g2 = dbl(pts[0]);
        for (1..N) |i| pts[i] = add(pts[i - 1], g2);
        var acc: [N]u256 = undefined;
        var run: u256 = 1;
        for (0..N) |i| {
            acc[i] = run;
            run = m(run, pts[i].z);
        }
        var iv = inv(run);
        var out: [N]A52 = undefined;
        var i: usize = N;
        while (i > 0) {
            i -= 1;
            const zi = m(iv, acc[i]);
            iv = m(iv, pts[i].z);
            const zi2 = m(zi, zi);
            out[i] = .{ .x = f52(m(pts[i].x, zi2)), .y = f52(m(m(pts[i].y, zi2), zi)) };
        }
        return out;
    }
};

const gx_int: u256 = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
const gy_int: u256 = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;

/// G, 3G, ..., (2^(g_w-1) - 1)G and the same for 2^128 G (width-g_w NAF digits).
pub const g_table: [g_n]A52 = blk: {
    @setEvalBranchQuota(2_000_000_000);
    break :blk cmp.oddMultiples(g_n, gx_int, gy_int);
};
pub const g128_table: [g_n]A52 = blk: {
    @setEvalBranchQuota(2_000_000_000);
    var p: cmp.J = .{ .x = gx_int, .y = gy_int, .z = 1 };
    for (0..128) |_| p = cmp.dbl(p);
    const a = cmp.affine(p);
    break :blk cmp.oddMultiples(g_n, a[0], a[1]);
};

// ---------------------------------------------------------------------------------------------
// Scalars mod n

const n_c: u256 = 0x14551231950B75FC4402DA1732FC9BEBF; // 2^256 - n (129 bits)

/// x mod n using 2^256 = n_c (mod n): three folds, then at most two subtractions.
fn reduceN(x: u512) u256 {
    const m256: u512 = (@as(u512, 1) << 256) - 1;
    var v: u512 = x;
    v = @as(u512, @as(u256, @truncate(v >> 256))) * n_c + (v & m256); // < 2^386
    v = @as(u512, @as(u256, @truncate(v >> 256))) * n_c + (v & m256); // < 2^260
    v = @as(u512, @as(u256, @truncate(v >> 256))) * n_c + (v & m256); // < 2^256 + 2^133
    var r: u512 = v;
    while (r >= n_int) r -= n_int;
    return @intCast(r);
}

/// (a * b) mod n.
pub fn mulModN(a: u256, b: u256) u256 {
    return reduceN(@as(u512, a) * b);
}

/// (a + b) mod n for a, b < n.
pub fn addModN(a: u256, b: u256) u256 {
    const t = @addWithOverflow(a, b);
    if (t[1] == 1 or t[0] >= n_int) return t[0] -% n_int;
    return t[0];
}

/// (a - b) mod n for a, b < n.
pub fn subModN(a: u256, b: u256) u256 {
    return if (a >= b) a - b else a +% (n_int -% b);
}

pub fn invModN(a: u256) u256 {
    return lehmer.invMod(a, n_int);
}

const lambda: u256 = 0x5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72;
const minus_b1: u256 = 0xE4437ED6010E88286F547FA90ABFE4C3;
const minus_b2: u256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE8A280AC50774346DD765CDA83DB1562C;
const glv_g1: u256 = 0x3086D221A7D46BCDE86C90E49284EB153DAA8A1471E8CA7FE893209A45DBB031;
const glv_g2: u256 = 0xE4437ED6010E88286F547FA90ABFE4C4221208AC9DF506C61571B4AE8AC47F71;

/// round(k * g / 2^384)
fn mulShift384(k: u256, g: u256) u256 {
    const prod: u512 = @as(u512, k) * g;
    return @intCast((prod + (@as(u512, 1) << 383)) >> 384);
}

pub const Split = struct { k1: u128, k1_neg: bool, k2: u128, k2_neg: bool };

/// libsecp256k1 `scalar_split_lambda`: k = k1 + k2*lambda (mod n) with |k1|, |k2| < 2^128.
pub fn splitLambda(k: u256) Split {
    const c1 = mulShift384(k, glv_g1);
    const c2 = mulShift384(k, glv_g2);
    const r2 = addModN(mulModN(c1, minus_b1), mulModN(c2, minus_b2));
    const r1 = subModN(k, mulModN(r2, lambda));
    const half_n = n_int >> 1;
    var out: Split = undefined;
    if (r1 > half_n) {
        out.k1 = @intCast(n_int - r1);
        out.k1_neg = true;
    } else {
        out.k1 = @intCast(r1);
        out.k1_neg = false;
    }
    if (r2 > half_n) {
        out.k2 = @intCast(n_int - r2);
        out.k2_neg = true;
    } else {
        out.k2 = @intCast(r2);
        out.k2_neg = false;
    }
    return out;
}

// ---------------------------------------------------------------------------------------------
// [a]G + [b]Q

pub const qn = 132;

/// Width-w NAF of a 128-bit scalar, i16 digits (windows wider than 8).
pub fn wnaf128(x: u128, comptime w: u5, neg: bool) [qn]i16 {
    const width: u32 = @as(u32, 1) << w;
    const halfw: i32 = @intCast(width / 2);
    var out: [qn]i16 = @splat(0);
    var v: u136 = x;
    var pos: usize = 0;
    while (v != 0) {
        const z = @ctz(v);
        v >>= @intCast(z);
        pos += z;
        var d: i32 = @intCast(@as(u32, @truncate(v)) & (width - 1));
        if (d >= halfw) d -= @intCast(width);
        out[pos] = @intCast(if (neg) -d else d);
        if (d >= 0) v -= @as(u136, @intCast(d)) else v += @as(u136, @intCast(-d));
        v >>= w;
        pos += w;
    }
    return out;
}

inline fn half(d: i16) usize {
    return @as(usize, @abs(d)) >> 1;
}

/// Q, 3Q, ..., 15Q for a public point Q of order n, as affine points on an isomorphic curve
/// (libsecp256k1 `ecmult_odd_multiples_table`): 2Q = (X, Y, Z) is affine on y^2 = x^3 + 7 Z^6,
/// where the a = 0 formulas still hold, so the odd multiples come from mixed additions; their
/// Z ratios then bring all eight to the last entry's Z, making them affine on a curve scaled
/// once more. Returns the table and the total scale w: a point (x, y) of the table is the true
/// point (x / w^2, y / w^3). No inversion.
fn oddMultiplesIso(q: A52) struct { t: [8]A52, w: F52 } {
    const d = (J52{ .x = q.x, .y = q.y, .z = one52, .inf = false }).dbl();
    const z2 = d.z.sq();
    var j: [8]J52 = undefined;
    var hs: [8]F52 = undefined;
    j[0] = .{ .x = q.x.mul(z2), .y = q.y.mul(z2).mul(d.z), .z = one52, .inf = false };
    for (1..8) |i| {
        // j[i] = j[i-1] + d (d affine here), z ratio h_i = Z(j[i]) / Z(j[i-1])
        const a = j[i - 1];
        const z12 = a.z.sq();
        const u_2 = d.x.mul(z12);
        const s2 = d.y.mul(z12).mul(a.z);
        const h = a.x.negate(4).add(u_2);
        const ii = s2.negate(1).add(a.y);
        // h = 0 would need iQ = +-2Q for odd i <= 13: impossible in a group of prime order n
        const h2 = h.sq().negate(1);
        const h3 = h2.mul(h);
        const t = a.x.mul(h2);
        const x3 = ii.sq().add(h3).add(t).add(t);
        const y3 = t.add(x3).mul(ii).add(h3.mul(a.y));
        j[i] = .{ .x = x3, .y = y3, .z = a.z.mul(h), .inf = false };
        hs[i] = h;
    }
    var out: [8]A52 = undefined;
    out[7] = .{ .x = j[7].x.mul(one52), .y = j[7].y.mul(one52) };
    var rho = hs[7];
    var i: usize = 7;
    while (i > 0) {
        i -= 1;
        const rho2 = rho.sq();
        out[i] = .{ .x = j[i].x.mul(rho2), .y = j[i].y.mul(rho2).mul(rho) };
        if (i > 0) rho = rho.mul(hs[i]);
    }
    return .{ .t = out, .w = d.z.mul(j[7].z) };
}

/// Variable time [a]G + [b]Q for a, b < n.
pub fn mulDoubleG(a: u256, q: Affine, b: u256) Jac {
    @setEvalBranchQuota(100_000); // inline calls count as branches
    // Q side: GLV halves with width-5 NAFs over Q and lambda(Q)
    const sp = splitLambda(b);
    const n1 = wnaf128(sp.k1, 5, sp.k1_neg);
    const n2 = wnaf128(sp.k2, 5, sp.k2_neg);
    const iso = oddMultiplesIso(A52.from(q));
    const tq = iso.t;
    var tl: [8]A52 = undefined;
    for (0..8) |i| tl[i] = .{ .x = tq[i].x.mul(beta52), .y = tq[i].y };
    const w = iso.w;
    // G side: low and high 128 bits over G and 2^128 G
    const na = wnaf128(@truncate(a), g_w, false);
    const nb = wnaf128(@truncate(a >> 128), g_w, false);
    var i: usize = qn - 1;
    while (i > 0 and n1[i] == 0 and n2[i] == 0 and na[i] == 0 and nb[i] == 0) i -= 1;
    // the ladder runs on the scaled curve of the Q table; G points enter through addAffineZ
    var r = J52.infinity;
    const w2 = w.sq();
    const w3 = w2.mul(w);
    while (true) {
        r = r.dbl();
        addDigit(&r, &tq, n1[i]);
        addDigit(&r, &tl, n2[i]);
        addDigitG(&r, &g_table, na[i], w, w2, w3);
        addDigitG(&r, &g128_table, nb[i], w, w2, w3);
        if (i == 0) break;
        i -= 1;
    }
    if (r.inf) return Jac.infinity;
    r.z = r.z.mul(w);
    return r.toJac();
}

inline fn addDigitG(r: *J52, table: []const A52, d: i16, w: F52, w2: F52, w3: F52) void {
    if (d == 0) return;
    const e = table[@as(usize, @abs(d)) >> 1];
    const by = if (d > 0) e.y else e.y.negate(1);
    if (r.inf) {
        r.* = .{ .x = e.x.mul(w2), .y = by.mul(w3), .z = one52, .inf = false };
    } else {
        r.* = r.addAffineZ(e.x, by, r.z.mul(w));
    }
}

inline fn addDigit(r: *J52, table: []const A52, d: i16) void {
    if (d > 0) {
        const e = table[half(d)];
        r.* = r.addAffine(e.x, e.y);
    } else if (d < 0) {
        const e = table[half(d)];
        r.* = r.addAffine(e.x, e.y.negate(1));
    }
}

/// x(P) mod n == r for P in Jacobian coordinates, without an inversion: X == r*Z^2, or
/// X == (r + n)*Z^2 when r + n < p.
pub fn xModNEquals(pt: Jac, r: u256) bool {
    if (pt.inf) return false;
    const zz = pt.z.sq();
    if (Fe.fromInt(r).mul(zz).eql(pt.x)) return true;
    if (r < p_int - n_int) return Fe.fromInt(r + n_int).mul(zz).eql(pt.x);
    return false;
}

// ---------------------------------------------------------------------------------------------

const testing = std.testing;
const StdK1 = std.crypto.ecc.Secp256k1;

test "secp256k1 field agrees with std" {
    var prng: std.Random.DefaultPrng = .init(256);
    const rnd = prng.random();
    for (0..3000) |i| {
        var x = rnd.int(u256);
        var y = rnd.int(u256);
        if (i < 4) {
            x = p_int - 1 - @as(u256, i);
            y = std.math.maxInt(u256) - @as(u256, i);
        }
        const a = Fe.fromInt(x);
        const b = Fe.fromInt(y);
        var xb: [32]u8 = undefined;
        var yb: [32]u8 = undefined;
        std.mem.writeInt(u256, &xb, x % p_int, .big);
        std.mem.writeInt(u256, &yb, y % p_int, .big);
        const sa = StdK1.Fe.fromBytes(xb, .big) catch unreachable;
        const sb = StdK1.Fe.fromBytes(yb, .big) catch unreachable;
        try testing.expectEqual(sa.mul(sb).toBytes(.big), a.mul(b).toBytes());
        try testing.expectEqual(sa.sq().toBytes(.big), a.sq().toBytes());
        try testing.expectEqual(sa.add(sb).toBytes(.big), a.add(b).toBytes());
        try testing.expectEqual(sa.sub(sb).toBytes(.big), a.sub(b).toBytes());
        try testing.expectEqual(sa.invert().toBytes(.big), a.invert().toBytes());
        if (a.sqrt()) |s| try testing.expect(s.sq().eql(a));
    }
}

test "lambda split and double multiplication agree with std" {
    var prng: std.Random.DefaultPrng = .init(1256);
    const rnd = prng.random();
    for (0..300) |i| {
        var k = rnd.int(u256) % n_int;
        if (i == 0) k = n_int - 1;
        if (i == 1) k = 0;
        const sp = splitLambda(k);
        try testing.expect(sp.k1 < (1 << 129) and sp.k2 < (1 << 129));
        const k1: u256 = if (sp.k1_neg) n_int - sp.k1 else sp.k1;
        const k2: u256 = if (sp.k2_neg) n_int - sp.k2 else sp.k2;
        try testing.expectEqual(k, addModN(k1, mulModN(k2, lambda)));
        const x = rnd.int(u256);
        const y = rnd.int(u256);
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) * y) % n_int)), reduceN(@as(u512, x) * y));
        // [a]G + [b]Q with Q = [c]G
        const a = rnd.int(u256) % n_int;
        const c = rnd.int(u256) % n_int;
        var cb: [32]u8 = undefined;
        std.mem.writeInt(u256, &cb, c, .big);
        const sq = try StdK1.basePoint.mul(cb, .big);
        const sqa = sq.affineCoordinates();
        const q: Affine = .{ .x = Fe.fromInt(std.mem.readInt(u256, &sqa.x.toBytes(.big), .big)), .y = Fe.fromInt(std.mem.readInt(u256, &sqa.y.toBytes(.big), .big)) };
        var ab: [32]u8 = undefined;
        std.mem.writeInt(u256, &ab, a, .big);
        var kb: [32]u8 = undefined;
        std.mem.writeInt(u256, &kb, k, .big);
        const want = try StdK1.mulDoubleBasePublic(StdK1.basePoint, ab, sq, kb, .big);
        const got = mulDoubleG(a, q, k).toAffine().?;
        try testing.expectEqual(want.affineCoordinates().x.toBytes(.big), got.x.toBytes());
        try testing.expectEqual(want.affineCoordinates().y.toBytes(.big), got.y.toBytes());
    }
}

test "5x52 ladder field agrees with the 4x64 field at the magnitude limits" {
    var prng: std.Random.DefaultPrng = .init(5252);
    const rnd = prng.random();
    const val = struct {
        fn of(a: F52) u256 {
            var v: u512 = 0;
            inline for (0..5) |k| v += @as(u512, a.n[k]) << (52 * k);
            return @intCast(v % p_int);
        }
    }.of;
    for (0..20000) |it| {
        // random limbs up to magnitude 8 (limb < 16 * (2^52 - 1), top < 16 * (2^48 - 1))
        var a: F52 = undefined;
        var b: F52 = undefined;
        inline for (0..4) |k| {
            a.n[k] = rnd.uintLessThan(u64, 16 * M52 + 1);
            b.n[k] = rnd.uintLessThan(u64, 16 * M52 + 1);
        }
        a.n[4] = rnd.uintLessThan(u64, 16 * M48 + 1);
        b.n[4] = rnd.uintLessThan(u64, 16 * M48 + 1);
        if (it < 2) {
            inline for (0..4) |k| a.n[k] = 16 * M52;
            a.n[4] = 16 * M48;
            b = a;
        }
        const av = val(a);
        const bv = val(b);
        const want: u256 = @intCast((@as(u512, av) * bv) % p_int);
        try testing.expectEqual(want, val(a.mul(b)));
        try testing.expectEqual(@as(u256, @intCast((@as(u512, av) * av) % p_int)), val(a.sq()));
        try testing.expectEqual(want, a.mul(b).toFe().toInt());
        try testing.expectEqual(av, a.toFe().toInt());
        try testing.expectEqual(@as(u256, @intCast((@as(u512, av) * ((p_int + 1) / 2)) % p_int)), val(a.half()));
        try testing.expectEqual(@as(u256, @intCast((p_int - av) % p_int)), val(a.negate(8)));
        try testing.expectEqual(av == 0, a.isZeroVar());
        // the mul result has magnitude 1: its zero test and conversion hold too
        const m1 = a.mul(b);
        try testing.expectEqual(want == 0, m1.isZeroVar());
        const z = F52.fromFe(Fe.fromInt(av));
        try testing.expect(z.add(z.negate(1)).isZeroVar());
    }
    // p itself and 0 in non-canonical form
    const pz = F52{ .n = .{ P0, M52, M52, M52, M48 } };
    try testing.expect(pz.isZeroVar());
    try testing.expectEqual(@as(u256, 0), pz.toFe().toInt());
}

test "generator tables: every entry is (2i + 1) G or (2i + 1) 2^128 G" {
    // on the curve, and consecutive entries differ by 2G (resp. 2^129 G)
    const g2 = Jac.fromAffine(generator).dbl().toAffine().?;
    var h = Jac.fromAffine(generator);
    for (0..129) |_| h = h.dbl();
    const h2 = h.toAffine().?;
    for ([_]*const [g_n]A52{ &g_table, &g128_table }, [_]Affine{ g2, h2 }) |tbl, step| {
        for (tbl, 0..) |e, i| {
            const a: Affine = .{ .x = e.x.toFe(), .y = e.y.toFe() };
            try testing.expect(a.isOnCurve());
            if (i + 1 < g_n) {
                const next = Jac.fromAffine(a).addAffine(step).toAffine().?;
                try testing.expect(next.x.eql(tbl[i + 1].x.toFe()) and next.y.eql(tbl[i + 1].y.toFe()));
            }
        }
    }
    try testing.expect(g_table[0].x.toFe().eql(generator.x));
}

test "double multiplication on exceptional inputs: Q a small or lambda multiple of G" {
    // Q = [c]G with c related to G, scalars that make ladder sums collide (doubling and
    // infinity inside additions). Reference: [a + b*c mod n]G with std.
    const lam2 = mulModN(lambda, lambda);
    const cs = [_]u256{ 1, 2, 3, n_int - 1, n_int - 2, lambda, lam2, n_int - lambda, 1 << 128, 3 << 128, n_int - (1 << 128) };
    var vals: [64]u256 = undefined;
    var nv: usize = 0;
    for ([_]u256{ 0, 1, 2, 3, 5, 15, 17, 2047, 2049, 1 << 128, (1 << 128) + 1, 3 << 128, lambda, lam2 }) |v| {
        vals[nv] = v % n_int;
        nv += 1;
        vals[nv] = (n_int - v % n_int) % n_int;
        nv += 1;
    }
    var hits: usize = 0;
    for (cs) |c| {
        var cb: [32]u8 = undefined;
        std.mem.writeInt(u256, &cb, c, .big);
        const sq = (try StdK1.basePoint.mul(cb, .big)).affineCoordinates();
        const q: Affine = .{ .x = Fe.fromInt(std.mem.readInt(u256, &sq.x.toBytes(.big), .big)), .y = Fe.fromInt(std.mem.readInt(u256, &sq.y.toBytes(.big), .big)) };
        for (vals[0..nv]) |a| for (vals[0..nv]) |b| {
            const e = addModN(a, mulModN(b, c));
            const got = mulDoubleG(a, q, b).toAffine();
            if (e == 0) {
                try testing.expect(got == null);
                hits += 1;
                continue;
            }
            var eb: [32]u8 = undefined;
            std.mem.writeInt(u256, &eb, e, .big);
            const want = (try StdK1.basePoint.mul(eb, .big)).affineCoordinates();
            const g = got.?;
            try testing.expectEqual(want.x.toBytes(.big), g.x.toBytes());
            try testing.expectEqual(want.y.toBytes(.big), g.y.toBytes());
        };
    }
    try testing.expect(hits > 0);
}
