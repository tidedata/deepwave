//! Ed25519 exactly as Sui verifies it: fastcrypto's Ed25519PublicKey::verify on
//! ed25519-consensus 2.1 (ZIP-215 rules) over curve25519-dalek 4.1.
//!
//! Acceptance rules (ed25519-consensus `VerificationKey::verify_prehashed`):
//!   - A and R are decoded the dalek way: the low 255 bits are y (values >= p accepted and used
//!     as given), x is the non-negative square root of u/v flipped by the sign bit, and a zero x
//!     with the sign bit set is accepted ("negative zero"). A failing A is a bad public key; a
//!     failing R is an invalid signature.
//!   - s must be canonical (s < l).
//!   - k = SHA-512(R_bytes || A_bytes || msg) mod l over the bytes as given.
//!   - accept iff [8](R - ([s]B - [k]A)) is the identity (cofactored equation), so batch and
//!     single verification agree on every input.
//!
//! How deepwave evaluates the same equation faster than dalek (verdicts are identical on every input):
//!   - Half-size scalars (Pornin, "Optimized lattice basis reduction in dimension 2, and fast
//!     Schnorr and EdDSA signature verification", 2020). A truncated extended Euclid on (l, k)
//!     gives c0, c1 with c0 = k*c1 (mod l), |c0| < 2^126 and 0 < c1 < 2^127. With t = c1*s mod l,
//!     the check becomes [8]([c0]A + [c1]R - [t]B) = 0, where [t]B = [t_lo]B + [t_hi](2^128 B)
//!     uses two comptime tables. That is one 128-step doubling chain instead of 253.
//!     Equivalence: E(F_p) = Z/8 x Z/l. Let P = R - [s]B + [k]A. [c1]P differs from
//!     [c0]A + [c1]R - [t]B by [c1*k - c0]A - [c1*s - t]B, a multiple of l times points of the
//!     group, so a point killed by [8]. Hence [8]X = [8][c1]P = [c1]([8]P). [8]P lies in the
//!     order-l subgroup and c1 is not a multiple of l, so [8]X = 0 iff [8]P = 0.
//!   - A and R are decompressed together: their two 252-squaring exponentiations run
//!     interleaved, which the core overlaps (the chain is latency bound).
//!   - Field arithmetic is our own radix-2^51 code with 64x64-bit products (fe25519.zig). On
//!     x86-64 with AVX-512 IFMA the chain's point arithmetic runs four field operations per
//!     instruction stream instead (ed25519_ifma.zig).
//!
//!   - `verify`, `verifyDecoded`, `PublicKey.verifyPrehashed` and `verifyBatch` dispatch at
//!     runtime (core/cpu.zig): a baseline x86-64 binary runs this file compiled for AVX2 + BMI2
//!     + ADX, or for AVX-512 IFMA, when the CPU has them.
//!
//! Switched paths, all off by default (`Opts`; the paths above are what runs until one is on):
//!   - vec4 (core/cpu.zig `edVec4`, ZUI_ED25519_VEC4): the single chain and the batch chain run
//!     on the four-way point kernel of ed25519_avx2.zig. The AVX2 tier's default chains are scalar.
//!   - batch key cache and batch key merge (`setBatchKeys`, ZUI_ED25519_BATCH_KEYS): the batch
//!     takes decoded keys from sig/fast.zig's cache, and items of one chunk that share a key share
//!     one table and one summed scalar.
//!   Every switched path gives the verdict of the default path on every input
//!   (ed25519_exact.zig checks each one item by item against the reference rule).
//!
//! Verification works on public data and is variable time. Signing is constant time.
const std = @import("std");
const hash = @import("hash");
const dit = @import("dit.zig");
const verdict = @import("verdict.zig");
const Verdict = verdict.Verdict;
const fe25519 = @import("fe25519.zig");
const fe25519x4 = @import("fe25519x4.zig");
const ifma = @import("ed25519_ifma.zig");
const x4 = @import("ed25519_avx2.zig");
const fast = @import("fast.zig");
const cpu = @import("core").cpu;

pub const Fe = fe25519.Fe;
const scalar = std.crypto.ecc.Edwards25519.scalar;
const Sha512 = hash.Sha512;

/// The group order l, little endian.
pub const l_bytes: [32]u8 = .{
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};
pub const l_int: u256 = scalar.field_order;

/// Per-call switches of the verifier. The public wrappers read them in the caller's compilation
/// and pass them to the kernel entries: a kernel object (src/cpu_kernels.zig) has its own copy
/// of every global, so an entry cannot read a switch itself. All false: the default paths.
pub const Opts = packed struct(u32) {
    /// The chains run on the four-way point kernel (ed25519_avx2.zig). Where the AVX-512 IFMA
    /// kernel is compiled in it keeps the single chain; the batch chain follows this switch.
    vec4: bool = false,
    /// Batch: items of a chunk that share a key share one table and one summed scalar.
    merge_keys: bool = false,
    _: u30 = 0,
};

/// Batch switches, both off by default. `cache`: the batch takes decoded keys from the
/// decoded-key cache of sig/fast.zig and stores the ones it decodes there (only while that cache
/// is on, `fast.Config.pk_cache`). `merge`: see `Opts.merge_keys`.
/// ZUI_ED25519_BATCH_KEYS=cache,merge (or all, or off) sets them from the environment: exact
/// comma-separated names, and a token that is not a name leaves both off with a warning. The
/// state and the parser are in core/cpu.zig (`EdBatchKeys`), next to the vec4 switch;
/// `setBatchKeys` overrides the environment.
pub const BatchKeys = cpu.EdBatchKeys;

/// The switches a ZUI_ED25519_BATCH_KEYS value names (both off when a token is not a name).
pub fn parseBatchKeys(s: []const u8) BatchKeys {
    return cpu.parseEdBatchKeys(s).keys;
}

/// What ZUI_ED25519_BATCH_KEYS asks for (both off when unset).
pub fn batchKeysFromEnv() BatchKeys {
    return cpu.edBatchKeysFromEnv();
}

pub fn batchKeys() BatchKeys {
    return cpu.edBatchKeys();
}

pub fn setBatchKeys(k: BatchKeys) void {
    cpu.setEdBatchKeys(k);
}

/// The switches in force now. At comptime everything is off (the switches are runtime state).
fn liveOpts() Opts {
    if (@inComptime()) return .{};
    return .{ .vec4 = cpu.edVec4Live(), .merge_keys = batchKeys().merge };
}

// ---------------------------------------------------------------------------------------------
// Point arithmetic (extended twisted Edwards, a = -1), the dalek formula set.

pub const Point = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,

    pub const identity: Point = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one, .t = Fe.zero };

    pub inline fn neg(p: Point) Point {
        return .{ .x = p.x.neg(), .y = p.y, .z = p.z, .t = p.t.neg() };
    }

    pub inline fn toProjNiels(p: Point) ProjNiels {
        return .{ .ypx = p.y.add(p.x), .ymx = p.y.sub(p.x), .z = p.z, .t2d = p.t.mul(Fe.d2) };
    }

    pub inline fn toProjective(p: Point) Projective {
        return .{ .x = p.x, .y = p.y, .z = p.z };
    }

    pub inline fn dbl(p: Point) Point {
        return p.toProjective().dbl().toExtended();
    }

    pub inline fn addNiels(p: Point, q: ProjNiels) Completed {
        const pp = p.y.add(p.x).mul(q.ypx);
        const mm = p.y.sub(p.x).mul(q.ymx);
        const tt2d = p.t.mul(q.t2d);
        const zz = p.z.mul(q.z);
        const zz2 = zz.add(zz);
        return .{ .x = pp.sub(mm), .y = pp.add(mm), .z = zz2.add(tt2d), .t = zz2.sub(tt2d) };
    }

    pub inline fn subNiels(p: Point, q: ProjNiels) Completed {
        const pm = p.y.add(p.x).mul(q.ymx);
        const mp = p.y.sub(p.x).mul(q.ypx);
        const tt2d = p.t.mul(q.t2d);
        const zz = p.z.mul(q.z);
        const zz2 = zz.add(zz);
        return .{ .x = pm.sub(mp), .y = pm.add(mp), .z = zz2.sub(tt2d), .t = zz2.add(tt2d) };
    }

    pub inline fn addAffine(p: Point, q: AffineNiels) Completed {
        const pp = p.y.add(p.x).mul(q.ypx);
        const mm = p.y.sub(p.x).mul(q.ymx);
        const txy2d = p.t.mul(q.xy2d);
        const z2 = p.z.add(p.z);
        return .{ .x = pp.sub(mm), .y = pp.add(mm), .z = z2.add(txy2d), .t = z2.sub(txy2d) };
    }

    pub inline fn subAffine(p: Point, q: AffineNiels) Completed {
        const pm = p.y.add(p.x).mul(q.ymx);
        const mp = p.y.sub(p.x).mul(q.ypx);
        const txy2d = p.t.mul(q.xy2d);
        const z2 = p.z.add(p.z);
        return .{ .x = pm.sub(mp), .y = pm.add(mp), .z = z2.sub(txy2d), .t = z2.add(txy2d) };
    }

    pub fn add(p: Point, q: Point) Point {
        return p.addNiels(q.toProjNiels()).toExtended();
    }

    pub fn sub(p: Point, q: Point) Point {
        return p.subNiels(q.toProjNiels()).toExtended();
    }

    /// [8]P
    pub fn mulByCofactor(p: Point) Point {
        var q = p.toProjective();
        q = q.dbl().toProjective();
        q = q.dbl().toProjective();
        return q.dbl().toExtended();
    }

    /// Projective identity test (X = 0 and Y = Z), equal to dalek's compress() == identity.
    pub fn isIdentity(p: Point) bool {
        return p.x.isZero() and p.y.eql(p.z);
    }

    pub fn toBytes(p: Point) [32]u8 {
        const zi = p.z.invert();
        var s = p.y.mul(zi).toBytes();
        s[31] ^= @as(u8, @intFromBool(p.x.mul(zi).isNegative())) << 7;
        return s;
    }

    pub fn toAffineNiels(p: Point) AffineNiels {
        return p.toAffineNielsInv(p.z.invert());
    }

    fn toAffineNielsInv(p: Point, zi: Fe) AffineNiels {
        const x = p.x.mul(zi);
        const y = p.y.mul(zi);
        return .{ .ypx = y.add(x), .ymx = y.sub(x), .xy2d = x.mul(y).mul(Fe.d2) };
    }
};

pub const Projective = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    pub inline fn dbl(p: Projective) Completed {
        const xx = p.x.sq();
        const yy = p.y.sq();
        const zz2 = p.z.sq2();
        const xpy2 = p.x.add(p.y).sq();
        const yy_plus_xx = yy.add(xx);
        const yy_minus_xx = yy.sub(xx);
        return .{ .x = xpy2.sub(yy_plus_xx), .y = yy_plus_xx, .z = yy_minus_xx, .t = zz2.sub(yy_minus_xx) };
    }

    pub inline fn toExtended(p: Projective) Point {
        return .{ .x = p.x.mul(p.z), .y = p.y.mul(p.z), .z = p.z.sq(), .t = p.x.mul(p.y) };
    }
};

/// (X:Y:Z:T) with x = X/Z, y = Y/T: the output of every addition and doubling.
pub const Completed = struct {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,

    pub inline fn toExtended(c: Completed) Point {
        return .{ .x = c.x.mul(c.t), .y = c.y.mul(c.z), .z = c.z.mul(c.t), .t = c.x.mul(c.y) };
    }

    pub inline fn toProjective(c: Completed) Projective {
        return .{ .x = c.x.mul(c.t), .y = c.y.mul(c.z), .z = c.z.mul(c.t) };
    }
};

pub const ProjNiels = struct { ypx: Fe, ymx: Fe, z: Fe, t2d: Fe };
pub const AffineNiels = struct { ypx: Fe, ymx: Fe, xy2d: Fe };

fn fromStdFe(x: std.crypto.ecc.Edwards25519.Fe) Fe {
    const b = x.toBytes();
    return Fe.fromBytes(&b);
}

pub const basepoint: Point = blk: {
    @setEvalBranchQuota(1_000_000);
    const B = std.crypto.ecc.Edwards25519.basePoint;
    break :blk .{ .x = fromStdFe(B.x), .y = fromStdFe(B.y), .z = fromStdFe(B.z), .t = fromStdFe(B.t) };
};

// ---------------------------------------------------------------------------------------------
// Decoding (curve25519-dalek 4.1 CompressedEdwardsY::decompress)

/// Decodes 32 bytes as dalek does (ZIP-215: non-canonical y and negative zero accepted).
pub fn decompress(s: *const [32]u8) ?Point {
    const y = Fe.fromBytes(s);
    const yy = y.sq();
    const u = yy.sub(Fe.one);
    const v = yy.mul(Fe.d).add(Fe.one);
    const sr = Fe.sqrtRatioI(u, v);
    if (!sr.ok) return null;
    return finishDecompress(s, sr.r, y);
}

fn finishDecompress(s: *const [32]u8, r: Fe, y: Fe) Point {
    var x = r;
    if ((s[31] >> 7) != 0) x = x.neg();
    return .{ .x = x, .y = y, .z = Fe.one, .t = x.mul(y) };
}

/// (x^(2^252 - 3), y^(2^252 - 3)) with the two chains interleaved.
pub fn pow2523x2(x: Fe, y: Fe) [2]Fe {
    const S = struct {
        inline fn sqn2(a: *Fe, b: *Fe, n: usize) void {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                a.* = a.sq();
                b.* = b.sq();
            }
        }
    };
    var a0 = x.sq();
    var b0 = y.sq();
    var a1 = a0.sq().sq();
    var b1 = b0.sq().sq();
    const a2 = x.mul(a1);
    const b2 = y.mul(b1);
    const a3 = a0.mul(a2);
    const b3 = b0.mul(b2);
    a0 = a3.sq();
    b0 = b3.sq();
    const a5 = a2.mul(a0);
    const b5 = b2.mul(b0);
    a1 = a5;
    b1 = b5;
    S.sqn2(&a1, &b1, 5);
    const a7 = a1.mul(a5);
    const b7 = b1.mul(b5);
    a1 = a7;
    b1 = b7;
    S.sqn2(&a1, &b1, 10);
    const a9 = a1.mul(a7);
    const b9 = b1.mul(b7);
    a1 = a9;
    b1 = b9;
    S.sqn2(&a1, &b1, 20);
    const a11 = a1.mul(a9);
    const b11 = b1.mul(b9);
    a1 = a11;
    b1 = b11;
    S.sqn2(&a1, &b1, 10);
    const a13 = a1.mul(a7);
    const b13 = b1.mul(b7);
    a1 = a13;
    b1 = b13;
    S.sqn2(&a1, &b1, 50);
    const a15 = a1.mul(a13);
    const b15 = b1.mul(b13);
    a1 = a15;
    b1 = b15;
    S.sqn2(&a1, &b1, 100);
    const a17 = a1.mul(a15);
    const b17 = b1.mul(b15);
    a1 = a17;
    b1 = b17;
    S.sqn2(&a1, &b1, 50);
    a1 = a1.mul(a13);
    b1 = b1.mul(b13);
    S.sqn2(&a1, &b1, 2);
    return .{ a1.mul(x), b1.mul(y) };
}

pub const Sr = struct { ok: bool, r: Fe };

pub fn finishSqrtRatio(u: Fe, v: Fe, v3: Fe, uv7_pow: Fe) Sr {
    var r = u.mul(v3).mul(uv7_pow);
    const check = v.mul(r.sq());
    const neg_u = u.neg();
    const correct = check.eql(u);
    const flipped = check.eql(neg_u);
    const flipped_i = check.eql(neg_u.mul(Fe.sqrtm1));
    // constant time: the Elligator map (ECVRF prove, ECMH) runs this on hashed inputs
    r.cMov(r.mul(Fe.sqrtm1), flipped or flipped_i);
    r.cMov(r.neg(), r.isNegative());
    return .{ .ok = correct or flipped, .r = r };
}

/// Two `Fe.sqrtRatioI` calls with their exponentiations interleaved.
pub fn sqrtRatioI2(uu0: Fe, v0: Fe, uu1: Fe, v1: Fe) [2]Sr {
    const v03 = v0.sq().mul(v0);
    const v13 = v1.sq().mul(v1);
    const v07 = v03.sq().mul(v0);
    const v17 = v13.sq().mul(v1);
    const pw = pow2523x2(uu0.mul(v07), uu1.mul(v17));
    return .{ finishSqrtRatio(uu0, v0, v03, pw[0]), finishSqrtRatio(uu1, v1, v13, pw[1]) };
}

/// Decodes two encodings at once (same results as two `decompress` calls).
pub fn decompress2(s0: *const [32]u8, s1: *const [32]u8) [2]?Point {
    const y0 = Fe.fromBytes(s0);
    const y1 = Fe.fromBytes(s1);
    const yy0 = y0.sq();
    const yy1 = y1.sq();
    const uu0 = yy0.sub(Fe.one);
    const uu1 = yy1.sub(Fe.one);
    const v0 = yy0.mul(Fe.d).add(Fe.one);
    const v1 = yy1.mul(Fe.d).add(Fe.one);
    const v03 = v0.sq().mul(v0);
    const v13 = v1.sq().mul(v1);
    const v07 = v03.sq().mul(v0);
    const v17 = v13.sq().mul(v1);
    const pw = pow2523x2(uu0.mul(v07), uu1.mul(v17));
    const r0 = finishSqrtRatio(uu0, v0, v03, pw[0]);
    const r1 = finishSqrtRatio(uu1, v1, v13, pw[1]);
    return .{
        if (r0.ok) finishDecompress(s0, r0.r, y0) else null,
        if (r1.ok) finishDecompress(s1, r1.r, y1) else null,
    };
}

/// x^(2^252 - 3) for N elements with the N chains interleaved (the scalar multiplier is
/// throughput bound from N = 4 on an M5 Pro: 1.51 us for one chain, 0.88 us each for four).
pub fn pow2523N(comptime N: usize, x: [N]Fe) [N]Fe {
    const S = struct {
        inline fn sqn(a: *[N]Fe, n: usize) void {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                inline for (0..N) |j| a[j] = a[j].sq();
            }
        }
        inline fn mulv(a: [N]Fe, b: [N]Fe) [N]Fe {
            var o: [N]Fe = undefined;
            inline for (0..N) |j| o[j] = a[j].mul(b[j]);
            return o;
        }
    };
    var t0 = x;
    S.sqn(&t0, 1);
    var t1 = t0;
    S.sqn(&t1, 2);
    const t2 = S.mulv(x, t1);
    const t3 = S.mulv(t0, t2);
    t0 = t3;
    S.sqn(&t0, 1);
    const t5 = S.mulv(t2, t0);
    t1 = t5;
    S.sqn(&t1, 5);
    const t7 = S.mulv(t1, t5);
    t1 = t7;
    S.sqn(&t1, 10);
    const t9 = S.mulv(t1, t7);
    t1 = t9;
    S.sqn(&t1, 20);
    const t11 = S.mulv(t1, t9);
    t1 = t11;
    S.sqn(&t1, 10);
    const t13 = S.mulv(t1, t7);
    t1 = t13;
    S.sqn(&t1, 50);
    const t15 = S.mulv(t1, t13);
    t1 = t15;
    S.sqn(&t1, 100);
    const t17 = S.mulv(t1, t15);
    t1 = t17;
    S.sqn(&t1, 50);
    const t19 = S.mulv(t1, t13);
    t1 = t19;
    S.sqn(&t1, 2);
    return S.mulv(t1, x);
}

/// N encodings decoded at once (same results as N `decompress` calls).
pub fn decompressN(comptime N: usize, s: [N]*const [32]u8) [N]?Point {
    var y: [N]Fe = undefined;
    var u: [N]Fe = undefined;
    var v: [N]Fe = undefined;
    var v3: [N]Fe = undefined;
    var w: [N]Fe = undefined;
    inline for (0..N) |j| {
        y[j] = Fe.fromBytes(s[j]);
        const yy = y[j].sq();
        u[j] = yy.sub(Fe.one);
        v[j] = yy.mul(Fe.d).add(Fe.one);
        v3[j] = v[j].sq().mul(v[j]);
        w[j] = u[j].mul(v3[j].sq().mul(v[j]));
    }
    // eight at once: four in the vector unit, four on the scalar multiplier, side by side
    const pw = if (N == 8) fe25519x4.pow2523x8(w) else pow2523N(N, w);
    var out: [N]?Point = undefined;
    inline for (0..N) |j| {
        const r = finishSqrtRatio(u[j], v[j], v3[j], pw[j]);
        out[j] = if (r.ok) finishDecompress(s[j], r.r, y[j]) else null;
    }
    return out;
}

// ---------------------------------------------------------------------------------------------
// Scalars

/// s < l, as dalek's Scalar::from_canonical_bytes.
pub fn isCanonicalScalar(s: *const [32]u8) bool {
    return std.mem.readInt(u256, s, .little) < l_int;
}

/// Width-w non-adjacent form of a scalar below 2^255 (dalek `Scalar::non_adjacent_form`).
pub fn naf(s: *const [32]u8, comptime w: u4) [256]i8 {
    return wnaf(256, std.mem.readInt(u256, s, .little), w, false);
}

/// Width-w NAF of x (x < 2^254, at most N - 1 bits), digits negated when `neg`.
pub fn wnaf(comptime N: usize, x: u256, comptime w: u4, neg: bool) [N]i8 {
    const width: u32 = @as(u32, 1) << w;
    const halfw: i32 = @intCast(width / 2);
    var out: [N]i8 = @splat(0);
    var v = x;
    var pos: usize = 0;
    while (v != 0) {
        const z = @ctz(v);
        v >>= @intCast(z);
        pos += z;
        var d: i32 = @intCast(@as(u32, @truncate(v)) & (width - 1));
        if (d >= halfw) d -= @intCast(width);
        out[pos] = @intCast(if (neg) -d else d);
        if (d >= 0) v -= @as(u256, @intCast(d)) else v += @as(u256, @intCast(-d));
        v >>= w;
        pos += w;
    }
    return out;
}

/// c0 = k*c1 (mod l) with |c0| < 2^126 and 0 < c1 < 2^127: extended Euclid on (l, k) stopped
/// at the first remainder below 2^126 (then |c1| <= l / previous remainder < 2^127).
///
/// The Euclid steps run as Lehmer rounds (Knuth 4.5.2, Algorithm L): quotients come from the
/// leading 62 bits and are taken only when both of Knuth's bounds agree, so every taken step is
/// an exact Euclid step; a round also stops before any step whose divisor is not provably
/// >= 2^126, so the first remainder below 2^126 is never skipped. A round that cannot take a
/// step does one exact full-width step instead.
pub const HalfSize = struct { c0: u128, c0_neg: bool, c1: u128 };

pub fn halfSize(k: u256) HalfSize {
    var a: u256 = l_int;
    var b: u256 = k;
    var ta: i128 = 0;
    var tb: i128 = 1;
    const stop: u256 = @as(u256, 1) << 126;
    while (b >= stop) {
        const n: u32 = 256 - @as(u32, @clz(a)); // a > b >= 2^126, so n >= 127
        const sh: u8 = @intCast(n - 62);
        var x: i64 = @intCast(a >> sh);
        var y: i64 = @intCast(b >> sh);
        const thr: i64 = if (sh >= 126) 1 else @as(i64, 1) << @intCast(126 - sh);
        var A: i64 = 1;
        var B: i64 = 0;
        var C: i64 = 0;
        var D: i64 = 1;
        while (true) {
            const yc = y + C;
            const yd = y + D;
            if (@min(yc, yd) < thr) break; // divisor not provably >= 2^126
            const xa = x + A;
            const xb = x + B;
            if (xa < 0 or xb < 0) break;
            const q = @divTrunc(xa, yc);
            if (q != @divTrunc(xb, yd)) break;
            const t0 = A - q * C;
            A = C;
            C = t0;
            const t1 = B - q * D;
            B = D;
            D = t1;
            const t2 = x - q * y;
            x = y;
            y = t2;
        }
        if (B == 0) {
            // one exact step: a <- a mod b, then swap
            while (a >= b) {
                const la: u32 = 256 - @as(u32, @clz(a));
                const d: u32 = la - (256 - @as(u32, @clz(b)));
                if (d > 62) {
                    const sd: u8 = @intCast(d - 1);
                    a -= b << sd;
                    ta -%= @bitCast(@as(u128, @bitCast(tb)) << @intCast(sd));
                    continue;
                }
                const s2: u8 = @intCast(la - 64);
                const atop: u64 = @truncate(a >> s2);
                const btop: u64 = @truncate(b >> s2);
                var q: u64 = if (btop == std.math.maxInt(u64)) 1 else atop / (btop + 1);
                if (q == 0) q = 1;
                a -= @as(u256, q) * b;
                ta -%= @as(i128, @bitCast(@as(u128, q))) *% tb;
            }
            std.mem.swap(u256, &a, &b);
            std.mem.swap(i128, &ta, &tb);
        } else {
            const sa: u256 = @bitCast(@as(i256, A));
            const sb: u256 = @bitCast(@as(i256, B));
            const sc: u256 = @bitCast(@as(i256, C));
            const sd: u256 = @bitCast(@as(i256, D));
            const na = sa *% a +% sb *% b;
            const nb = sc *% a +% sd *% b;
            const nta = @as(i128, A) *% ta +% @as(i128, B) *% tb;
            const ntb = @as(i128, C) *% ta +% @as(i128, D) *% tb;
            a = na;
            b = nb;
            ta = nta;
            tb = ntb;
        }
    }
    // b = k*tb (mod l), b < 2^126, |tb| < 2^127, tb != 0
    const c0: u128 = @intCast(b);
    if (tb < 0) return .{ .c0 = c0, .c0_neg = true, .c1 = @intCast(-tb) };
    return .{ .c0 = c0, .c0_neg = false, .c1 = @intCast(tb) };
}

// ---------------------------------------------------------------------------------------------
// Tables

/// Odd multiples P, 3P, ..., 15P for width-5 NAF.
pub const Naf5Table = struct {
    t: [8]ProjNiels,

    pub fn init(p: Point) Naf5Table {
        var tbl: Naf5Table = undefined;
        const p2 = p.dbl();
        var cur = p;
        tbl.t[0] = cur.toProjNiels();
        for (1..8) |i| {
            cur = p2.addNiels(tbl.t[i - 1]).toExtended();
            tbl.t[i] = cur.toProjNiels();
        }
        return tbl;
    }
};

/// Two tables built with their additions interleaved.
pub fn naf5Tables2(p: Point, q: Point) [2]Naf5Table {
    var ta: Naf5Table = undefined;
    var tb: Naf5Table = undefined;
    naf5Tables2Into(p, q, &ta, &tb);
    return .{ ta, tb };
}

/// `naf5Tables2` written in place.
pub fn naf5Tables2Into(p: Point, q: Point, ta: *Naf5Table, tb: *Naf5Table) void {
    const p2 = p.dbl();
    const q2 = q.dbl();
    ta.t[0] = p.toProjNiels();
    tb.t[0] = q.toProjNiels();
    for (1..8) |i| {
        const cp = p2.addNiels(ta.t[i - 1]).toExtended();
        const cq = q2.addNiels(tb.t[i - 1]).toExtended();
        ta.t[i] = cp.toProjNiels();
        tb.t[i] = cq.toProjNiels();
    }
}

/// Odd multiples P, 3P, ..., 127P (width-8 NAF) as affine Niels, at compile time.
fn oddMultiplesAffine(comptime p: Point) [64]AffineNiels {
    @setEvalBranchQuota(1_000_000_000);
    var pts: [64]Point = undefined;
    const p2 = p.dbl();
    pts[0] = p;
    for (1..64) |i| pts[i] = pts[i - 1].add(p2);
    // Montgomery batch inversion of the Z coordinates
    var acc: [64]Fe = undefined;
    var run = Fe.one;
    for (0..64) |i| {
        acc[i] = run;
        run = run.mul(pts[i].z);
    }
    var inv = run.invert();
    var out: [64]AffineNiels = undefined;
    var i: usize = 64;
    while (i > 0) {
        i -= 1;
        const zi = inv.mul(acc[i]);
        inv = inv.mul(pts[i].z);
        out[i] = pts[i].toAffineNielsInv(zi);
    }
    return out;
}

/// B, 3B, ..., 127B.
pub const base_table: [64]AffineNiels = blk: {
    @setEvalBranchQuota(1_000_000_000);
    break :blk oddMultiplesAffine(basepoint);
};

/// 2^128 B and its odd multiples.
pub const base128_table: [64]AffineNiels = blk: {
    @setEvalBranchQuota(1_000_000_000);
    var p = basepoint;
    for (0..128) |_| p = p.dbl();
    break :blk oddMultiplesAffine(p);
};

inline fn half(d: i8) usize {
    return @as(usize, @abs(d)) >> 1;
}

/// [a]A + [b]B in variable time (dalek `vartime_double_scalar_mul_basepoint`). a, b < 2^255.
/// Kept for the batch verifier's single-item fallback and as a reference in tests.
pub fn doubleScalarMulBase(a: *const [32]u8, A: Point, b: *const [32]u8) Point {
    const an = naf(a, 5);
    const bn = naf(b, 8);
    var i: usize = 255;
    while (i > 0 and an[i] == 0 and bn[i] == 0) i -= 1;
    const ta = Naf5Table.init(A);
    var r: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };
    while (true) {
        var t = r.dbl();
        if (an[i] > 0) {
            t = t.toExtended().addNiels(ta.t[half(an[i])]);
        } else if (an[i] < 0) {
            t = t.toExtended().subNiels(ta.t[half(an[i])]);
        }
        if (bn[i] > 0) {
            t = t.toExtended().addAffine(base_table[half(bn[i])]);
        } else if (bn[i] < 0) {
            t = t.toExtended().subAffine(base_table[half(bn[i])]);
        }
        r = t.toProjective();
        if (i == 0) break;
        i -= 1;
    }
    return .{ .x = r.x.mul(r.z), .y = r.y.mul(r.z), .z = r.z.sq(), .t = r.x.mul(r.y) };
}

pub const qn = 130; // NAF length for values below 2^129

/// [a]A + [r]R + [b0]B + [b1](2^128 B) for half-size NAFs (one 128-step chain).
pub fn quadMul(ta: *const Naf5Table, na: *const [qn]i8, tr: *const Naf5Table, nr: *const [qn]i8, nb0: *const [qn]i8, nb1: *const [qn]i8) Projective {
    var i: usize = qn - 1;
    while (i > 0 and na[i] == 0 and nr[i] == 0 and nb0[i] == 0 and nb1[i] == 0) i -= 1;
    var r: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };
    while (true) {
        var t = r.dbl();
        const da = na[i];
        if (da > 0) t = t.toExtended().addNiels(ta.t[half(da)]) else if (da < 0) t = t.toExtended().subNiels(ta.t[half(da)]);
        const dr = nr[i];
        if (dr > 0) t = t.toExtended().addNiels(tr.t[half(dr)]) else if (dr < 0) t = t.toExtended().subNiels(tr.t[half(dr)]);
        const d0 = nb0[i];
        if (d0 > 0) t = t.toExtended().addAffine(base_table[half(d0)]) else if (d0 < 0) t = t.toExtended().subAffine(base_table[half(d0)]);
        const d1 = nb1[i];
        if (d1 > 0) t = t.toExtended().addAffine(base128_table[half(d1)]) else if (d1 < 0) t = t.toExtended().subAffine(base128_table[half(d1)]);
        r = t.toProjective();
        if (i == 0) break;
        i -= 1;
    }
    return r;
}

/// [8]P = 0 for P in projective coordinates.
fn isSmallOrder(p: Projective) bool {
    var q = p.dbl().toProjective();
    q = q.dbl().toProjective();
    q = q.dbl().toProjective();
    return q.x.isZero() and q.y.eql(q.z);
}

// ---------------------------------------------------------------------------------------------
// Constant-time scalar multiplication (secret scalars: signing, ECVRF prove)

/// Signed radix-16 digits a_i in [-8, 8) with s = sum a_i 16^i, for s < 2^255 (dalek
/// `Scalar::as_radix_16`). Branch-free.
pub fn radix16(s: *const [32]u8) [64]i8 {
    var e: [64]i8 = undefined;
    for (0..32) |i| {
        e[2 * i] = @intCast(s[i] & 15);
        e[2 * i + 1] = @intCast((s[i] >> 4) & 15);
    }
    var carry: i8 = 0;
    for (0..63) |i| {
        e[i] += carry;
        carry = (e[i] + 8) >> 4;
        e[i] -= carry << 4;
    }
    e[63] += carry;
    return e;
}

inline fn ctEq(a: u8, b: u8) bool {
    // branch-free equality on small values
    const x: u32 = a ^ b;
    return ((x -% 1) >> 31) == 1;
}

/// |d| and its sign bit, branch-free.
inline fn absSign(d: i8) struct { abs: u8, neg: bool } {
    const m: i8 = d >> 7;
    return .{ .abs = @intCast((d ^ m) -% m), .neg = m != 0 };
}

/// The nine selection masks of a signed radix-16 digit (entries 1..8 by |d|, then the sign), all
/// ones or zero, copied through a volatile so the optimizer sees arbitrary words. Without the
/// copy LLVM proves each mask is a sign-extended comparison, rewrites the masked moves as
/// selects, and its x86 cmov conversion may turn those into branches on the secret digit (an
/// x86_64_v3 build measured dudect t = -264 for signing that way).
inline fn digitMasks(d: i8) [9]u64 {
    const as = absSign(d);
    var m: [9]u64 = undefined;
    inline for (0..8) |k| m[k] = 0 -% @as(u64, @intFromBool(ctEq(as.abs, k + 1)));
    m[8] = 0 -% @as(u64, @intFromBool(as.neg));
    const vp: *volatile [9]u64 = &m;
    return vp.*;
}

inline fn maskMov(x: *Fe, a: Fe, msk: u64) void {
    inline for (0..5) |i| x.l[i] ^= (x.l[i] ^ a.l[i]) & msk;
}

fn selectProjCT(tbl: *const [8]ProjNiels, d: i8) ProjNiels {
    const ms = digitMasks(d);
    var r: ProjNiels = .{ .ypx = Fe.one, .ymx = Fe.one, .z = Fe.one, .t2d = Fe.zero };
    inline for (0..8) |k| {
        maskMov(&r.ypx, tbl[k].ypx, ms[k]);
        maskMov(&r.ymx, tbl[k].ymx, ms[k]);
        maskMov(&r.z, tbl[k].z, ms[k]);
        maskMov(&r.t2d, tbl[k].t2d, ms[k]);
    }
    const ypx = r.ypx;
    maskMov(&r.ypx, r.ymx, ms[8]);
    maskMov(&r.ymx, ypx, ms[8]);
    maskMov(&r.t2d, r.t2d.neg(), ms[8]);
    return r;
}

fn selectAffineCT(tbl: *const [8]AffineNiels, d: i8) AffineNiels {
    const ms = digitMasks(d);
    var r: AffineNiels = .{ .ypx = Fe.one, .ymx = Fe.one, .xy2d = Fe.zero };
    inline for (0..8) |k| {
        maskMov(&r.ypx, tbl[k].ypx, ms[k]);
        maskMov(&r.ymx, tbl[k].ymx, ms[k]);
        maskMov(&r.xy2d, tbl[k].xy2d, ms[k]);
    }
    const ypx = r.ypx;
    maskMov(&r.ypx, r.ymx, ms[8]);
    maskMov(&r.ymx, ypx, ms[8]);
    maskMov(&r.xy2d, r.xy2d.neg(), ms[8]);
    return r;
}

/// [s]P in constant time; s must be reduced (< l).
pub fn mulCT(p: Point, s: *const [32]u8) Point {
    var tbl: [8]ProjNiels = undefined;
    tbl[0] = p.toProjNiels();
    var cur = p;
    for (1..8) |i| {
        cur = cur.addNiels(tbl[0]).toExtended();
        tbl[i] = cur.toProjNiels();
    }
    const dg = radix16(s);
    var q = Point.identity;
    var i: usize = 64;
    while (i > 0) {
        i -= 1;
        var pr = q.toProjective();
        pr = pr.dbl().toProjective();
        pr = pr.dbl().toProjective();
        pr = pr.dbl().toProjective();
        q = pr.dbl().toExtended();
        q = q.addNiels(selectProjCT(&tbl, dg[i])).toExtended();
    }
    return q;
}

/// dalek's EdwardsBasepointTable: table j holds [k] 256^j B for k = 1..8, affine Niels.
pub const base_ct_table: [32][8]AffineNiels = blk: {
    @setEvalBranchQuota(4_000_000_000);
    var pts: [256]Point = undefined;
    var bj = basepoint;
    for (0..32) |j| {
        pts[8 * j] = bj;
        for (1..8) |k| pts[8 * j + k] = pts[8 * j + k - 1].add(bj);
        for (0..8) |_| bj = bj.dbl();
    }
    var acc: [256]Fe = undefined;
    var run = Fe.one;
    for (0..256) |i| {
        acc[i] = run;
        run = run.mul(pts[i].z);
    }
    var inv = run.invert();
    var out: [32][8]AffineNiels = undefined;
    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        const zi = inv.mul(acc[i]);
        inv = inv.mul(pts[i].z);
        out[i / 8][i % 8] = pts[i].toAffineNielsInv(zi);
    }
    break :blk out;
};

/// [s]B in constant time (s < l): 64 table lookups and 4 doublings.
pub fn mulBaseCT(s: *const [32]u8) Point {
    const dg = radix16(s);
    var q = Point.identity;
    var i: usize = 1;
    while (i < 64) : (i += 2) q = q.addAffine(selectAffineCT(&base_ct_table[i / 2], dg[i])).toExtended();
    var pr = q.toProjective();
    pr = pr.dbl().toProjective();
    pr = pr.dbl().toProjective();
    pr = pr.dbl().toProjective();
    q = pr.dbl().toExtended();
    i = 0;
    while (i < 64) : (i += 2) q = q.addAffine(selectAffineCT(&base_ct_table[i / 2], dg[i])).toExtended();
    return q;
}

/// Variable-time [a]P + [b]Q for public scalars (a, b < 2^255): Straus with width-5 NAFs.
pub fn doubleMulVartime(a: *const [32]u8, p: Point, b: *const [32]u8, q: Point) Point {
    const an = naf(a, 5);
    const bn = naf(b, 5);
    const tabs = naf5Tables2(p, q);
    var i: usize = 255;
    while (i > 0 and an[i] == 0 and bn[i] == 0) i -= 1;
    var r: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };
    while (true) {
        var t = r.dbl();
        if (an[i] > 0) t = t.toExtended().addNiels(tabs[0].t[half(an[i])]) else if (an[i] < 0) t = t.toExtended().subNiels(tabs[0].t[half(an[i])]);
        if (bn[i] > 0) t = t.toExtended().addNiels(tabs[1].t[half(bn[i])]) else if (bn[i] < 0) t = t.toExtended().subNiels(tabs[1].t[half(bn[i])]);
        r = t.toProjective();
        if (i == 0) break;
        i -= 1;
    }
    return r.toExtended();
}

// ---------------------------------------------------------------------------------------------
// Verification

fn hashK(r_bytes: *const [32]u8, a_bytes: *const [32]u8, msg: []const u8) [32]u8 {
    var h = Sha512.init();
    h.update(r_bytes);
    h.update(a_bytes);
    h.update(msg);
    var d: [64]u8 = undefined;
    h.final(&d);
    return scalar.reduce64(d);
}

/// The cofactored half-size check: [8]([c0]A + [c1]R - [c1*s]B) = 0. `s` must be canonical.
fn checkHalf(a: Point, r: Point, s: *const [32]u8, k: *const [32]u8, o: Opts) bool {
    const hs = halfSize(std.mem.readInt(u256, k, .little));
    var c1b: [32]u8 = @splat(0);
    std.mem.writeInt(u128, c1b[0..16], hs.c1, .little);
    const t = std.mem.readInt(u256, &scalar.mul(c1b, s.*), .little);
    const na = wnaf(qn, hs.c0, 5, hs.c0_neg);
    const nr = wnaf(qn, hs.c1, 5, false);
    const nb0 = wnaf(qn, @as(u128, @truncate(t)), 8, true);
    const nb1 = wnaf(qn, t >> 128, 8, true);
    if (comptime ifma.enabled) return isSmallOrder(ifma.quadMul(a, &na, r, &nr, &nb0, &nb1));
    if (o.vec4) return isSmallOrder(x4.quadMul(a, &na, r, &nr, &nb0, &nb1));
    const tabs = naf5Tables2(a, r);
    return isSmallOrder(quadMul(&tabs[0], &na, &tabs[1], &nr, &nb0, &nb1));
}

/// A decoded public key: keeps the bytes (they are hashed as given) and A.
pub const PublicKey = struct {
    bytes: [32]u8,
    a: Point,

    pub fn fromBytes(b: *const [32]u8) ?PublicKey {
        const a = decompress(b) orelse return null;
        return .{ .bytes = b.*, .a = a };
    }

    /// ed25519-consensus VerificationKey::verify_prehashed. Variable time (public inputs).
    pub fn verifyPrehashed(pk: *const PublicKey, sig: *const [64]u8, k: *const [32]u8) bool {
        return cpu.call("ed25519_verify_prehashed", verifyPrehashedImpl, .{ pk, sig, k, liveOpts() });
    }

    pub fn verifyPrehashedImpl(pk: *const PublicKey, sig: *const [64]u8, k: *const [32]u8, o: Opts) bool {
        const s = sig[32..64];
        if (!isCanonicalScalar(s)) return false;
        const r = decompress(sig[0..32]) orelse return false;
        return checkHalf(pk.a, r, s, k, o);
    }

    pub fn verify(pk: *const PublicKey, msg: []const u8, sig: *const [64]u8) bool {
        const k = hashK(sig[0..32], &pk.bytes, msg);
        return pk.verifyPrehashed(sig, &k);
    }
};

/// fastcrypto Ed25519PublicKey::from_bytes + Ed25519Signature::from_bytes + verify.
/// Verdicts: pk:InvalidInput (A does not decode), verify:InvalidSignature.
pub fn verify(pk: *const [32]u8, msg: []const u8, sig: *const [64]u8) Verdict {
    return cpu.call("ed25519_verify", verifyImpl, .{ pk, msg, sig, liveOpts() });
}

pub fn verifyImpl(pk: *const [32]u8, msg: []const u8, sig: *const [64]u8, o: Opts) Verdict {
    const pts = decompress2(pk, sig[0..32]);
    const a = pts[0] orelse return .{ .invalid = .pk_invalid_input };
    const s = sig[32..64];
    if (!isCanonicalScalar(s)) return .{ .invalid = .verify_invalid_signature };
    const r = pts[1] orelse return .{ .invalid = .verify_invalid_signature };
    const k = hashK(sig[0..32], pk, msg);
    if (!checkHalf(a, r, s, &k, o)) return .{ .invalid = .verify_invalid_signature };
    return .valid;
}

/// The verify step for an A already decoded (with `decompress2`, together with R): R that did
/// not decode, a non-canonical s or a failed equation are all false.
pub fn verifyDecoded(a: Point, r: ?Point, pk: *const [32]u8, msg: []const u8, sig: *const [64]u8) bool {
    return cpu.call("ed25519_verify_decoded", verifyDecodedImpl, .{ a, r, pk, msg, sig, liveOpts() });
}

pub fn verifyDecodedImpl(a: Point, r: ?Point, pk: *const [32]u8, msg: []const u8, sig: *const [64]u8, o: Opts) bool {
    const s = sig[32..64];
    if (!isCanonicalScalar(s)) return false;
    const rp = r orelse return false;
    const k = hashK(sig[0..32], pk, msg);
    return checkHalf(a, rp, s, &k, o);
}

/// Same as `verify` over slices: a signature that is not 64 bytes is sig:InvalidInput and a key
/// that is not 32 bytes is pk:InvalidInput (fastcrypto's from_bytes errors).
pub fn verifySlices(pk: []const u8, msg: []const u8, sig: []const u8) Verdict {
    if (pk.len != 32) return .{ .invalid = .pk_invalid_input };
    if (sig.len != 64) {
        if (decompress(pk[0..32]) == null) return .{ .invalid = .pk_invalid_input };
        return .{ .invalid = .sig_invalid_input };
    }
    return verify(pk[0..32], msg, sig[0..64]);
}

// ---------------------------------------------------------------------------------------------
// Batch verification (ed25519-consensus batch::Verifier semantics: accepts iff every single
// verification accepts, except with probability about 2^-128)

pub const BatchItem = struct {
    pk: *const [32]u8,
    msg: []const u8,
    sig: *const [64]u8,
};

/// Scratch bytes needed per batch item by `verifyBatch` (it chunks to fit any scratch size).
pub const batch_scratch_per_item: usize = @sizeOf(BatchEntry) + max_ops_per_item * @sizeOf(BatchOp);

/// The odd multiples of A and R for one item.
const BatchEntry = struct {
    ta: Naf5Table,
    tr: Naf5Table,
};

/// One nonzero NAF digit of the shared chain: add (or subtract) entry's table point at this
/// position. Ops of one position form a list through `next`, so the chain touches only the
/// digits that exist (about 63 per item) instead of scanning every item at every position.
const BatchOp = struct {
    next: u32,
    entry: u16,
    digit: i8,
    /// 0: A table, 1: R table
    tbl: u8,
};

/// Width-5 NAF digits of a 253-bit and a 128-bit scalar: at most 51 + 26.
const max_ops_per_item = 80;
const max_chunk = std.math.maxInt(u16);
const nil: u32 = std.math.maxInt(u32);

/// Verifies all items; one verdict for the batch: verify:InvalidInput for an empty batch
/// (fastcrypto `verify_batch_empty_fail`), verify:InvalidSignature on any failure. Coefficients are 128-bit values derived from
/// a Blake2b hash of the whole batch, so the result is deterministic. Variable time.
pub fn verifyBatch(items: []const BatchItem, scratch: []u8) Verdict {
    const kc: ?*const KeyCache = if (!@inComptime() and batchKeys().cache and fast.pkCacheOn()) &fast_key_cache else null;
    const o = liveOpts();
    if (!@inComptime() and items.len > 2 and batchCapacity(scratch.len) > 0) {
        _ = batch_equations.fetchAdd(1, .monotonic);
        _ = batch_equation_items.fetchAdd(items.len, .monotonic);
        if (o.vec4 or o.merge_keys or kc != null) _ = batch_switched.fetchAdd(1, .monotonic);
    }
    return cpu.call("ed25519_verify_batch", verifyBatchImpl, .{ items, scratch, o, kc });
}

/// What `verifyBatch` was asked to do so far in this process: the calls that ran the batch
/// equation (more than two items and scratch for a chunk; the others are single checks), the
/// items in those calls, and how many of the calls ran a switched path (four-way chain, key
/// cache or key merge: `batchChunkKeyed`). Counted here, in the caller's compilation, so the
/// numbers hold whatever kernel tier ran the batch. The conformance runner prints them per suite
/// and fails a run whose batch switch never reached a batch (sig/conformance.zig).
pub const BatchCalls = struct { equations: u64, items: u64, switched: u64 };

var batch_equations: std.atomic.Value(u64) = .init(0);
var batch_equation_items: std.atomic.Value(u64) = .init(0);
var batch_switched: std.atomic.Value(u64) = .init(0);

pub fn batchCalls() BatchCalls {
    return .{ .equations = batch_equations.load(.monotonic), .items = batch_equation_items.load(.monotonic), .switched = batch_switched.load(.monotonic) };
}

/// The decoded-key cache as the batch sees it. The cache itself (sig/fast.zig) lives in the
/// caller's compilation, so it reaches a kernel entry as two C-ABI function pointers.
pub const KeyCache = struct {
    /// 0: not cached. 1: cached, `out` written. 2: cached as a key that does not decode.
    get: *const fn (pk: *const [32]u8, out: *Point) callconv(.c) u8,
    /// `p` null: the key does not decode.
    put: *const fn (pk: *const [32]u8, p: ?*const Point) callconv(.c) void,
};

fn fastKeyGet(pk: *const [32]u8, out: *Point) callconv(.c) u8 {
    const v = fast.edGetKey(pk) orelse return 0;
    out.* = v orelse return 2;
    return 1;
}

fn fastKeyPut(pk: *const [32]u8, p: ?*const Point) callconv(.c) void {
    fast.edPutKey(pk, if (p) |x| x.* else null);
}

const fast_key_cache: KeyCache = .{ .get = &fastKeyGet, .put = &fastKeyPut };

pub fn verifyBatchImpl(items: []const BatchItem, scratch: []u8, o: Opts, kc: ?*const KeyCache) Verdict {
    if (items.len == 0) return .{ .invalid = .verify_invalid_input };
    // Tiny batches: the half-size single check is cheaper than a 253-step shared chain, and it
    // gives the same verdict (a batch is valid iff every item is).
    if (items.len <= 2) {
        for (items) |it| if (verifyImpl(it.pk, it.msg, it.sig, o) != .valid) return .{ .invalid = .verify_invalid_signature };
        return .valid;
    }
    // A switched path (four-way chain, key cache, key merge) runs `batchChunkKeyed`; with every
    // switch off the chunks run `batchChunk`, the path as it was.
    const keyed = o.vec4 or o.merge_keys or kc != null;
    const fit = batchCapacity(scratch.len);
    // Chunks above ~256 items get slower per item (the tables fall out of cache): on a test machine,
    // 64..256 items 16.8 us/sig, 1024 18.2, 4096 22.7 to 24.3, 30k 30.3 (slower than single
    // checks, 29.2). A caller handing over scratch for the whole batch still gets the fast size.
    const cap: usize = @max(1, @min(fit, batch_chunk_best));
    var seed: [32]u8 = undefined;
    {
        var h = hash.Blake2b256.init();
        h.update("zui ed25519 batch v1");
        for (items) |it| {
            h.update(it.pk);
            h.update(it.sig);
            var lb: [8]u8 = undefined;
            std.mem.writeInt(u64, &lb, it.msg.len, .little);
            h.update(&lb);
            h.update(it.msg);
        }
        h.final(&seed);
    }
    var start: usize = 0;
    var chunk_no: u64 = 0;
    while (start < items.len) : (chunk_no += 1) {
        const end = @min(items.len, start + cap);
        if (fit == 0) {
            // no room for tables: verify one by one
            for (items[start..end]) |it| {
                if (verifyImpl(it.pk, it.msg, it.sig, o) != .valid) return .{ .invalid = .verify_invalid_signature };
            }
        } else {
            const sa = alignedScratch(scratch);
            const entries: [*]BatchEntry = @ptrCast(@alignCast(sa.ptr));
            const ops: [*]BatchOp = @ptrCast(@alignCast(sa.ptr + cap * @sizeOf(BatchEntry)));
            const ce = entries[0 .. end - start];
            const co = ops[0 .. (end - start) * max_ops_per_item];
            const ok = if (!keyed)
                batchChunk(items[start..end], ce, co, &seed, chunk_no)
            else if (o.vec4)
                batchChunkKeyed(true, items[start..end], ce, co, &seed, chunk_no, kc, o.merge_keys)
            else
                batchChunkKeyed(false, items[start..end], ce, co, &seed, chunk_no, kc, o.merge_keys);
            if (!ok) return .{ .invalid = .verify_invalid_signature };
        }
        start = end;
    }
    return .valid;
}

fn alignedScratch(scratch: []u8) []u8 {
    const a = @alignOf(BatchEntry);
    const addr = @intFromPtr(scratch.ptr);
    const off = (a - addr % a) % a;
    return if (off > scratch.len) scratch[0..0] else scratch[off..];
}

/// Items per chunk at most: the fastest size measured (sig-fast bench, batch-chunk sweep).
pub const batch_chunk_best: usize = 256;

/// Max items per chunk for a scratch buffer of `len` bytes.
pub fn batchCapacity(len: usize) usize {
    if (len < batch_scratch_per_item + @alignOf(BatchEntry)) return 0;
    return @min(max_chunk, (len - @alignOf(BatchEntry)) / batch_scratch_per_item);
}

/// The per-position op lists of the shared chain.
const Chain = struct {
    head: [256]u32 = @splat(nil),
    ops: []BatchOp,
    n: u32 = 0,
    top: usize = 0,

    /// Width-5 NAF of x pushed as ops of `entry`'s table `tbl`.
    fn push(c: *Chain, x: u256, entry: u16, tbl: u8) void {
        var v = x;
        var pos: usize = 0;
        while (v != 0) {
            const z = @ctz(v);
            v >>= @intCast(z);
            pos += z;
            var d: i32 = @intCast(@as(u32, @truncate(v)) & 31);
            if (d >= 16) d -= 32;
            c.ops[c.n] = .{ .next = c.head[pos], .entry = entry, .digit = @intCast(d), .tbl = tbl };
            c.head[pos] = c.n;
            c.n += 1;
            if (pos > c.top) c.top = pos;
            v -%= @as(u256, @bitCast(@as(i256, d)));
            v >>= 5;
            pos += 5;
        }
    }

    /// The chain's point plus [b]B (b in width-8 NAF). The additions run at the field
    /// multiplier's throughput (about 43 ns each on an M5 Pro); splitting the ops over two or four
    /// interleaved accumulators measured slower (their extra doublings cost more than the
    /// overlap gains).
    fn run(c: *const Chain, entries: []const BatchEntry, bn: *const [256]i8) Point {
        var i: usize = 255;
        while (i > c.top and bn[i] == 0) i -= 1;
        var acc: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one };
        while (true) {
            var t = acc.dbl();
            var o = c.head[i];
            while (o != nil) {
                const op = c.ops[o];
                const e = &entries[op.entry];
                const tbl = if (op.tbl == 0) &e.ta else &e.tr;
                t = if (op.digit > 0) t.toExtended().addNiels(tbl.t[half(op.digit)]) else t.toExtended().subNiels(tbl.t[half(op.digit)]);
                o = op.next;
            }
            const db = bn[i];
            if (db > 0) t = t.toExtended().addAffine(base_table[half(db)]) else if (db < 0) t = t.toExtended().subAffine(base_table[half(db)]);
            acc = t.toProjective();
            if (i == 0) break;
            i -= 1;
        }
        return acc.toExtended();
    }

    /// `run` on the four-way point kernel: the same ops and digits, the entries' tables cached
    /// points of ed25519_avx2.zig.
    fn runX4(c: *const Chain, entries: []const BatchEntryOf(true), bn: *const [256]i8) Point {
        x4.countChain();
        var i: usize = 255;
        while (i > c.top and bn[i] == 0) i -= 1;
        var acc = x4.identity;
        while (true) {
            acc = x4.dbl(acc);
            var o = c.head[i];
            while (o != nil) {
                const op = c.ops[o];
                const e = &entries[op.entry];
                const tbl = if (op.tbl == 0) &e.ta else &e.tr;
                acc = x4.step(acc, op.digit, &tbl.t);
                o = op.next;
            }
            acc = x4.step(acc, bn[i], &x4.base_c);
            if (i == 0) break;
            i -= 1;
        }
        return x4.toPoint(acc);
    }
};

/// A batch entry for the scalar chain (`BatchEntry`) or the four-way one. Both are the same
/// size and neither needs more than the scratch's alignment, so a chunk's scratch holds either.
fn BatchEntryOf(comptime vec: bool) type {
    if (!vec) return BatchEntry;
    return struct { ta: x4.Table, tr: x4.Table };
}

comptime {
    std.debug.assert(@sizeOf(BatchEntryOf(true)) == @sizeOf(BatchEntry));
    std.debug.assert(@alignOf(BatchEntryOf(true)) <= @alignOf(BatchEntry));
}

/// Up to eight encodings waiting to be decoded together (the hybrid vector + scalar
/// exponentiation of `decompressN`), each with the table its point goes into.
fn DecodeQueue(comptime vec: bool) type {
    const T = if (vec) x4.Table else Naf5Table;
    return struct {
        const Self = @This();
        src: [8]*const [32]u8 = undefined,
        dst: [8]*T = undefined,
        is_key: [8]bool = undefined,
        n: usize = 0,
        kc: ?*const KeyCache,
        /// Scalar tables are built two at a time (their additions interleave): the point
        /// waiting for a partner.
        pend: ?struct { p: Point, dst: *T } = null,

        /// False: a point of a flushed group did not decode.
        fn push(q: *Self, src: *const [32]u8, dst: *T, is_key: bool) bool {
            q.src[q.n] = src;
            q.dst[q.n] = dst;
            q.is_key[q.n] = is_key;
            q.n += 1;
            return if (q.n == 8) q.flush() else true;
        }

        fn flush(q: *Self) bool {
            const n = q.n;
            q.n = 0;
            var pts: [8]?Point = undefined;
            if (n == 8) {
                pts = decompressN(8, q.src);
            } else {
                var done: usize = 0;
                if (n >= 4) {
                    pts[0..4].* = decompressN(4, q.src[0..4].*);
                    done = 4;
                }
                if (n - done >= 2) {
                    pts[done..][0..2].* = decompress2(q.src[done], q.src[done + 1]);
                    done += 2;
                }
                if (n - done == 1) pts[done] = decompress(q.src[done]);
            }
            if (q.kc) |c| for (0..n) |i| {
                if (q.is_key[i]) c.put(q.src[i], if (pts[i]) |*p| p else null);
            };
            for (0..n) |i| {
                const p = pts[i] orelse return false;
                q.table(p, q.dst[i]);
            }
            return true;
        }

        fn table(q: *Self, p: Point, dst: *T) void {
            if (vec) {
                dst.init(p);
                return;
            }
            if (q.pend) |w| {
                naf5Tables2Into(w.p, p, w.dst, dst);
                q.pend = null;
            } else q.pend = .{ .p = p, .dst = dst };
        }

        /// Decodes what is left and builds the last table.
        fn finish(q: *Self) bool {
            if (!q.flush()) return false;
            if (!vec) if (q.pend) |w| {
                w.dst.* = Naf5Table.init(w.p);
                q.pend = null;
            };
            return true;
        }
    };
}

/// `batchChunk` for the switched paths: the same batch equation with the same coefficients
/// z_i (so with no key merged it is term for term the equation `batchChunk` evaluates), and
///   - keys come from the decoded-key cache when `kc` is given (a cached point is the point the
///     decoder returns for those bytes; a key cached as not decoding fails the chunk, as decoding
///     it would), and the keys decoded here go into it;
///   - with `merge`, the items of the chunk with the same key bytes share one table and one scalar
///     sum of z_i k_i mod l. The sum differs from the separate terms by a multiple of l times A,
///     a small-order point, which the final multiplication by the cofactor removes: the same
///     argument as the reduction of each z_i k_i mod l. The verdict is unchanged, exactly;
///   - with `vec`, the tables and the chain are on the four-way point kernel.
/// A chunk has at most `batch_chunk_best` items (`verifyBatchImpl` caps it).
/// Test builds count what the switched batch path did (chunks, keys merged into an earlier item's
/// table, keys taken from the cache), so a test can tell each switch took effect.
pub var test_keyed: struct {
    chunks: std.atomic.Value(usize) = .init(0),
    merged: std.atomic.Value(usize) = .init(0),
    cached: std.atomic.Value(usize) = .init(0),
} = .{};

inline fn testCount(c: *std.atomic.Value(usize)) void {
    if (@import("builtin").is_test) _ = c.fetchAdd(1, .monotonic);
}

fn batchChunkKeyed(comptime vec: bool, items: []const BatchItem, scratch_entries: []BatchEntry, ops: []BatchOp, seed: *const [32]u8, chunk_no: u64, kc: ?*const KeyCache, merge: bool) bool {
    const n = items.len;
    testCount(&test_keyed.chunks);
    std.debug.assert(n <= batch_chunk_best and n <= scratch_entries.len);
    const entries: []BatchEntryOf(vec) = @as([*]BatchEntryOf(vec), @ptrCast(scratch_entries.ptr))[0..n];
    // owner[i]: the first item of the chunk with the same key bytes (i itself without `merge`).
    var owner: [batch_chunk_best]u16 = undefined;
    if (merge) {
        // open addressing over twice the chunk size; the hash is keyed by the batch seed, so the
        // probe lengths are not the sender's to choose
        var slots: [2 * batch_chunk_best]u16 = @splat(0xffff);
        const hseed = std.mem.readInt(u64, seed[0..8], .little);
        for (items, 0..) |it, i| {
            var h: usize = @intCast(std.hash.Wyhash.hash(hseed, it.pk) & (slots.len - 1));
            while (true) : (h = (h + 1) & (slots.len - 1)) {
                const s = slots[h];
                if (s == 0xffff) {
                    slots[h] = @intCast(i);
                    owner[i] = @intCast(i);
                    break;
                }
                if (std.mem.eql(u8, items[s].pk, it.pk)) {
                    owner[i] = s;
                    testCount(&test_keyed.merged);
                    break;
                }
            }
        }
    } else {
        for (0..n) |i| owner[i] = @intCast(i);
    }
    // Points and tables: R of every item, A of every owner (from the cache when it is there).
    var q: DecodeQueue(vec) = .{ .kc = kc };
    for (items, 0..) |it, i| {
        if (owner[i] == i) {
            var cached: Point = undefined;
            const st: u8 = if (kc) |c| c.get(it.pk, &cached) else 0;
            if (st == 2) return false;
            if (st == 1) {
                testCount(&test_keyed.cached);
                q.table(cached, &entries[i].ta);
            } else if (!q.push(it.pk, &entries[i].ta, true)) return false;
        }
        if (!q.push(it.sig[0..32], &entries[i].tr, false)) return false;
    }
    if (!q.finish()) return false;
    // Scalars: z_i for R_i, the sum of z_i k_i per owner for A, the sum of z_i s_i for B.
    var acc: [batch_chunk_best][32]u8 = undefined;
    for (0..n) |i| {
        if (owner[i] == i) acc[i] = @splat(0);
    }
    var chain: Chain = .{ .ops = ops };
    var bsum: u512 = 0;
    var zpair: [32]u8 = undefined;
    for (items, 0..) |it, i| {
        if (i % 2 == 0) {
            // two 128-bit coefficients per Blake2b of (seed, chunk, pair), as `batchChunk`
            var h = hash.Blake2b256.init();
            h.update(seed);
            var nb: [16]u8 = undefined;
            std.mem.writeInt(u64, nb[0..8], chunk_no, .little);
            std.mem.writeInt(u64, nb[8..16], i / 2, .little);
            h.update(&nb);
            h.final(&zpair);
        }
        const s = it.sig[32..64];
        if (!isCanonicalScalar(s)) return false;
        const k = hashK(it.sig[0..32], it.pk, it.msg);
        var z: [32]u8 = @splat(0);
        @memcpy(z[0..16], zpair[16 * (i % 2) ..][0..16]);
        const zi = std.mem.readInt(u128, z[0..16], .little);
        bsum += @as(u512, zi) * std.mem.readInt(u256, s, .little);
        const ow = owner[i];
        acc[ow] = scalar.add(acc[ow], scalar.mul(z, k));
        chain.push(zi, @intCast(i), 1);
    }
    for (0..n) |i| {
        if (owner[i] == i) chain.push(std.mem.readInt(u256, &acc[i], .little), @intCast(i), 0);
    }
    var bb: [64]u8 = undefined;
    std.mem.writeInt(u512, &bb, bsum, .little);
    const b_coeff = scalar.neg(scalar.reduce64(bb));
    const bn = naf(&b_coeff, 8);
    const r = if (vec) chain.runX4(entries, &bn) else chain.run(entries, &bn);
    return r.mulByCofactor().isIdentity();
}

/// The batch equation [8](sum z_i R_i + sum (z_i k_i) A_i - (sum z_i s_i) B) = 0 for one chunk,
/// by Straus with one shared doubling chain (ed25519-consensus evaluates the same equation).
/// Items are decoded four points at a time (A and R of two items: one interleaved
/// exponentiation that runs at the multiplier's throughput).
fn batchChunk(items: []const BatchItem, entries: []BatchEntry, ops: []BatchOp, seed: *const [32]u8, chunk_no: u64) bool {
    var chain: Chain = .{ .ops = ops };
    var bsum: u512 = 0;
    var zpair: [32]u8 = undefined;
    var idx: usize = 0;
    var quad: [8]?Point = undefined;
    var quad_hi = false; // quad[4..8] holds the points of items idx, idx + 1
    while (idx < items.len) : (idx += 2) {
        var pts: [4]?Point = undefined;
        if (quad_hi) {
            pts = quad[4..8].*;
            quad_hi = false;
        } else if (idx + 3 < items.len) {
            // A and R of four items in one hybrid vector + scalar exponentiation
            const it = items[idx..][0..4];
            quad = decompressN(8, .{ it[0].pk, it[0].sig[0..32], it[1].pk, it[1].sig[0..32], it[2].pk, it[2].sig[0..32], it[3].pk, it[3].sig[0..32] });
            pts = quad[0..4].*;
            quad_hi = true;
        } else if (idx + 1 < items.len) {
            const a = items[idx];
            const b = items[idx + 1];
            pts = decompressN(4, .{ a.pk, a.sig[0..32], b.pk, b.sig[0..32] });
        } else {
            const a = items[idx];
            const p2 = decompress2(a.pk, a.sig[0..32]);
            pts[0] = p2[0];
            pts[1] = p2[1];
        }
        // two 128-bit coefficients per Blake2b of (seed, chunk, pair)
        {
            var h = hash.Blake2b256.init();
            h.update(seed);
            var nb: [16]u8 = undefined;
            std.mem.writeInt(u64, nb[0..8], chunk_no, .little);
            std.mem.writeInt(u64, nb[8..16], idx / 2, .little);
            h.update(&nb);
            h.final(&zpair);
        }
        for (0..@min(2, items.len - idx)) |h| {
            const it = items[idx + h];
            const a = pts[2 * h] orelse return false;
            const r = pts[2 * h + 1] orelse return false;
            const s = it.sig[32..64];
            if (!isCanonicalScalar(s)) return false;
            const k = hashK(it.sig[0..32], it.pk, it.msg);
            var z: [32]u8 = @splat(0);
            @memcpy(z[0..16], zpair[16 * h ..][0..16]);
            const zi = std.mem.readInt(u128, z[0..16], .little);
            const zk = std.mem.readInt(u256, &scalar.mul(z, k), .little);
            bsum += @as(u512, zi) * std.mem.readInt(u256, s, .little);
            const e: u16 = @intCast(idx + h);
            naf5Tables2Into(a, r, &entries[e].ta, &entries[e].tr);
            chain.push(zk, e, 0);
            chain.push(zi, e, 1);
        }
    }
    var bb: [64]u8 = undefined;
    std.mem.writeInt(u512, &bb, bsum, .little);
    const b_coeff = scalar.neg(scalar.reduce64(bb));
    const bn = naf(&b_coeff, 8);
    return chain.run(entries, &bn).mulByCofactor().isIdentity();
}

// ---------------------------------------------------------------------------------------------
// Signing (RFC 8032, as ed25519-consensus SigningKey::sign). Constant time in the secret key.

/// An expanded signing key (ed25519-consensus SigningKey): the scalar a (clamped, reduced mod l),
/// the nonce prefix and the public key bytes. Derive once, sign many times.
pub const KeyPair = struct {
    a: [32]u8,
    prefix: [32]u8,
    pk: [32]u8,

    pub fn fromSeed(seed: *const [32]u8) KeyPair {
        const g = dit.Guard.enter();
        defer g.leave();
        var h: [64]u8 = undefined;
        Sha512.hash(seed, &h);
        var a: [32]u8 = h[0..32].*;
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        const ar = scalar.reduce(a);
        const pk = mulBaseCT(&ar).toBytes();
        const kp: KeyPair = .{ .a = ar, .prefix = h[32..64].*, .pk = pk };
        std.crypto.secureZero(u8, &h);
        std.crypto.secureZero(u8, &a);
        return kp;
    }

    /// RFC 8032 Ed25519 signature. Constant time in the secret key and nonce.
    pub fn sign(kp: *const KeyPair, msg: []const u8) [64]u8 {
        const g = dit.Guard.enter();
        defer g.leave();
        var h = Sha512.init();
        h.update(&kp.prefix);
        h.update(msg);
        var rh: [64]u8 = undefined;
        h.final(&rh);
        const r = scalar.reduce64(rh);
        const big_r = mulBaseCT(&r).toBytes();
        const k = hashK(&big_r, &kp.pk, msg);
        var sig: [64]u8 = undefined;
        sig[0..32].* = big_r;
        sig[32..64].* = scalar.mulAdd(k, kp.a, r);
        return sig;
    }
};

pub fn publicKey(sk: *const [32]u8) [32]u8 {
    return KeyPair.fromSeed(sk).pk;
}

/// Sign with a 32-byte seed (derives the key pair per call; prefer KeyPair for many signatures).
pub fn sign(sk: *const [32]u8, msg: []const u8) [64]u8 {
    const g = dit.Guard.enter();
    defer g.leave();
    const kp = KeyPair.fromSeed(sk);
    return kp.sign(msg);
}

// ---------------------------------------------------------------------------------------------

test "half-size scalars: c0 = k*c1 mod l and both below 2^127" {
    var prng: std.Random.DefaultPrng = .init(0x48616c66);
    const rnd = prng.random();
    const edges = [_]u256{ 0, 1, 2, (1 << 126) - 1, 1 << 126, l_int - 1, l_int - 2, (1 << 252), l_int / 2, l_int / 3 };
    var i: usize = 0;
    while (i < 20000) : (i += 1) {
        const k: u256 = if (i < edges.len) edges[i] else rnd.int(u256) % l_int;
        const hs = halfSize(k);
        try std.testing.expect(hs.c0 < (1 << 126));
        try std.testing.expect(hs.c1 > 0 and hs.c1 < (1 << 127));
        // k*c1 mod l == +-c0
        var kb: [32]u8 = undefined;
        std.mem.writeInt(u256, &kb, k, .little);
        var cb: [32]u8 = @splat(0);
        std.mem.writeInt(u128, cb[0..16], hs.c1, .little);
        const prod = std.mem.readInt(u256, &scalar.mul(kb, cb), .little);
        const want: u256 = if (hs.c0_neg) (l_int - hs.c0) % l_int else hs.c0;
        try std.testing.expectEqual(want, prod);
    }
}

test "wnaf reconstructs the scalar" {
    var prng: std.Random.DefaultPrng = .init(7);
    const rnd = prng.random();
    for (0..2000) |_| {
        const x = rnd.int(u256) >> 3;
        inline for (.{ 5, 8 }) |w| {
            const n = wnaf(256, x, w, false);
            var acc: i512 = 0;
            var j: usize = 256;
            while (j > 0) {
                j -= 1;
                acc = acc * 2 + n[j];
                if (n[j] != 0) try std.testing.expect(@rem(n[j], 2) != 0 and @abs(n[j]) < (1 << (w - 1)));
            }
            try std.testing.expectEqual(@as(i512, x), acc);
        }
    }
}

test "decompress2 equals two decompress calls" {
    var prng: std.Random.DefaultPrng = .init(11);
    const rnd = prng.random();
    for (0..500) |_| {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        rnd.bytes(&a);
        rnd.bytes(&b);
        const got = decompress2(&a, &b);
        const ea = decompress(&a);
        const eb = decompress(&b);
        try std.testing.expectEqual(ea == null, got[0] == null);
        try std.testing.expectEqual(eb == null, got[1] == null);
        if (ea) |p| try std.testing.expectEqual(p.toBytes(), got[0].?.toBytes());
        if (eb) |p| try std.testing.expectEqual(p.toBytes(), got[1].?.toBytes());
    }
}

test "constant-time multiplications agree with the variable-time ones" {
    var prng: std.Random.DefaultPrng = .init(99);
    const rnd = prng.random();
    for (0..200) |_| {
        var sb: [64]u8 = undefined;
        rnd.bytes(&sb);
        const sc = scalar.reduce64(sb);
        var tb: [64]u8 = undefined;
        rnd.bytes(&tb);
        const tc = scalar.reduce64(tb);
        const zero: [32]u8 = @splat(0);
        const ref = doubleScalarMulBase(&zero, basepoint, &sc).toBytes();
        try std.testing.expectEqual(ref, mulBaseCT(&sc).toBytes());
        const p = mulBaseCT(&tc);
        try std.testing.expectEqual(ref, mulCT(basepoint, &sc).toBytes());
        const ref2 = doubleScalarMulBase(&sc, p, &zero).toBytes();
        try std.testing.expectEqual(ref2, mulCT(p, &sc).toBytes());
        try std.testing.expectEqual(ref2, doubleMulVartime(&sc, p, &zero, basepoint).toBytes());
    }
}

test "basepoint table and double scalar mul agree with the reference" {
    const B = std.crypto.ecc.Edwards25519.basePoint;
    const ref = (try B.mulPublic(.{ 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 })).toBytes();
    const one: [32]u8 = blk1: {
        var t: [32]u8 = @splat(0);
        t[0] = 1;
        break :blk1 t;
    };
    const two: [32]u8 = blk2: {
        var t: [32]u8 = @splat(0);
        t[0] = 2;
        break :blk2 t;
    };
    const three: [32]u8 = blk3: {
        var t: [32]u8 = @splat(0);
        t[0] = 3;
        break :blk3 t;
    };
    // 2*B + 3*B
    const got = doubleScalarMulBase(&two, basepoint, &three).toBytes();
    try std.testing.expectEqualSlices(u8, &ref, &got);
    _ = one;
}

test "sign and verify round trip, RFC 8032 test 1" {
    const sk = [_]u8{ 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60 };
    const pk = publicKey(&sk);
    const sig = sign(&sk, "");
    var expect: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expect, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    try std.testing.expectEqualSlices(u8, &expect, &sig);
    try std.testing.expectEqual(Verdict.valid, verify(&pk, "", &sig));
    var bad = sig;
    bad[0] ^= 1;
    try std.testing.expect(verify(&pk, "", &bad) != .valid);
}

// dudect-style check (Reparaz, Balasch, Verbauwhede 2017) on the only secret-key path here:
// signing. Class 0 signs with one fixed key, class 1 with fresh random keys, in random order;
// Welch's t over the timings (after dropping the slowest 10% of samples, as dudect crops) must
// stay below 10, dudect's "definitely not constant time" bound. Run with
// `./zig build test -Dlane=sig -Doptimize=ReleaseFast` for the full sample count.
test "dudect: ed25519 sign time does not depend on the secret key" {
    const builtin = @import("builtin");
    const io = std.testing.io;
    const n: usize = if (builtin.mode == .debug) 2000 else 200_000;
    const gpa = std.testing.allocator;
    const times = try gpa.alloc(u64, n);
    defer gpa.free(times);
    const class = try gpa.alloc(u1, n);
    defer gpa.free(class);
    var prng: std.Random.DefaultPrng = .init(0x7a75_692d_6475_6463);
    const rnd = prng.random();
    const fixed: [32]u8 = @splat(0x42);
    const msg = "zui dudect message";
    var sink: u8 = 0;
    for (times, class) |*t, *c| {
        c.* = rnd.int(u1);
        var sk: [32]u8 = fixed;
        if (c.* == 1) rnd.bytes(&sk);
        const t0 = std.Io.Timestamp.now(io, .awake);
        const sig = sign(&sk, msg);
        const t1 = std.Io.Timestamp.now(io, .awake);
        sink ^= sig[0];
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
    const v0 = m2[0] / (cnt[0] - 1);
    const v1 = m2[1] / (cnt[1] - 1);
    const t_stat = (mean[0] - mean[1]) / @sqrt(v0 / cnt[0] + v1 / cnt[1]);
    if (dudectVerbose() or @abs(t_stat) >= 10) std.debug.print("dudect ed25519 sign: n={d} t={d:.3} mean0={d:.0}ns mean1={d:.0}ns\n", .{ n, t_stat, mean[0], mean[1] });
    try std.testing.expect(@abs(t_stat) < 10);
}

test "batch: large batches accept valid and reject one bad item" {
    const N = 160;
    const kps = try std.testing.allocator.alloc(KeyPair, N);
    defer std.testing.allocator.free(kps);
    var msgs: [N][24]u8 = undefined;
    var sigs: [N][64]u8 = undefined;
    var items: [N]BatchItem = undefined;
    for (0..N) |i| {
        var sd: [32]u8 = @splat(0x5a);
        sd[0] = @intCast(i);
        kps[i] = KeyPair.fromSeed(&sd);
        msgs[i] = @splat(@intCast(i ^ 0x33));
        sigs[i] = kps[i].sign(&msgs[i]);
        items[i] = .{ .pk = &kps[i].pk, .msg = &msgs[i], .sig = &sigs[i] };
    }
    const buf = try std.testing.allocator.alloc(u8, N * batch_scratch_per_item + 64);
    defer std.testing.allocator.free(buf);
    for ([_]usize{ 47, 64, 100, N }) |n| try std.testing.expect(verifyBatch(items[0..n], buf) == .valid);
    for ([_]usize{ 0, 1, 77, 158, 159 }) |bad| {
        msgs[bad][3] ^= 0x80;
        try std.testing.expect(verifyBatch(&items, buf) == .invalid);
        msgs[bad][3] ^= 0x80;
    }
    try std.testing.expect(verifyBatch(&items, buf) == .valid);
}

test "batch: whole-batch scratch above batch_chunk_best runs in capped chunks, a bad item in any chunk rejects" {
    const N = 2 * batch_chunk_best + 37;
    const kps = try std.testing.allocator.alloc(KeyPair, N);
    defer std.testing.allocator.free(kps);
    const msgs = try std.testing.allocator.alloc([16]u8, N);
    defer std.testing.allocator.free(msgs);
    const sigs = try std.testing.allocator.alloc([64]u8, N);
    defer std.testing.allocator.free(sigs);
    const items = try std.testing.allocator.alloc(BatchItem, N);
    defer std.testing.allocator.free(items);
    for (0..N) |i| {
        var sd: [32]u8 = @splat(0x77);
        std.mem.writeInt(u32, sd[0..4], @intCast(i), .little);
        kps[i] = KeyPair.fromSeed(&sd);
        msgs[i] = @splat(@truncate(i));
        sigs[i] = kps[i].sign(&msgs[i]);
        items[i] = .{ .pk = &kps[i].pk, .msg = &msgs[i], .sig = &sigs[i] };
    }
    const buf = try std.testing.allocator.alloc(u8, (N + 1) * batch_scratch_per_item + 64);
    defer std.testing.allocator.free(buf);
    try std.testing.expect(batchCapacity(buf.len) > batch_chunk_best);
    try std.testing.expect(verifyBatch(items, buf) == .valid);
    for ([_]usize{ 0, batch_chunk_best - 1, batch_chunk_best, 2 * batch_chunk_best + 5, N - 1 }) |bad| {
        sigs[bad][40] ^= 1;
        try std.testing.expect(verifyBatch(items, buf) == .invalid);
        sigs[bad][40] ^= 1;
    }
}

test "batch: chunking, odd sizes and one bad item agree with single verification" {
    const N = 11;
    var kps: [N]KeyPair = undefined;
    var msgs: [N][40]u8 = undefined;
    var sigs: [N][64]u8 = undefined;
    var items: [N]BatchItem = undefined;
    for (0..N) |i| {
        kps[i] = KeyPair.fromSeed(&@as([32]u8, @splat(@intCast(i + 9))));
        msgs[i] = @splat(@intCast(i));
        sigs[i] = kps[i].sign(&msgs[i]);
        items[i] = .{ .pk = &kps[i].pk, .msg = &msgs[i], .sig = &sigs[i] };
    }
    var buf: [N * batch_scratch_per_item + 64]u8 = undefined;
    // full scratch, three items per chunk, one item per chunk, no scratch at all
    for ([_]usize{ buf.len, 3 * batch_scratch_per_item + 16, batch_scratch_per_item + 16, 0 }) |len| {
        for ([_]usize{ 3, 4, 5, N }) |n| try std.testing.expect(verifyBatch(items[0..n], buf[0..len]) == .valid);
    }
    for (0..N) |bad| {
        sigs[bad][40] ^= 1;
        for ([_]usize{ buf.len, 3 * batch_scratch_per_item + 16 }) |len|
            try std.testing.expect(verifyBatch(&items, buf[0..len]) == .invalid);
        sigs[bad][40] ^= 1;
    }
}

test "batch calls: equations, their items and the switched ones are counted" {
    const N = 6;
    var kps: [N]KeyPair = undefined;
    var msgs: [N][8]u8 = undefined;
    var sigs: [N][64]u8 = undefined;
    var items: [N]BatchItem = undefined;
    for (0..N) |i| {
        kps[i] = KeyPair.fromSeed(&@as([32]u8, @splat(@intCast(i + 40))));
        msgs[i] = @splat(@intCast(i));
        sigs[i] = kps[i].sign(&msgs[i]);
        items[i] = .{ .pk = &kps[i].pk, .msg = &msgs[i], .sig = &sigs[i] };
    }
    var buf: [N * batch_scratch_per_item + 64]u8 = undefined;
    const keys_before = batchKeys();
    defer setBatchKeys(keys_before);
    const vec_before = cpu.edVec4();
    defer cpu.setEdVec4(vec_before);
    setBatchKeys(.{});
    cpu.setEdVec4(.off);
    // every switch off: equations are counted, none of them switched
    var c0 = batchCalls();
    try std.testing.expect(verifyBatch(&items, &buf) == .valid);
    try std.testing.expect(verifyBatch(items[0..3], &buf) == .valid);
    var c1 = batchCalls();
    try std.testing.expectEqual(c0.equations + 2, c1.equations);
    try std.testing.expectEqual(c0.items + N + 3, c1.items);
    try std.testing.expectEqual(c0.switched, c1.switched);
    // not the batch equation: one or two items (single checks), no scratch, an empty batch
    try std.testing.expect(verifyBatch(items[0..2], &buf) == .valid);
    try std.testing.expect(verifyBatch(items[0..1], &buf) == .valid);
    try std.testing.expect(verifyBatch(&items, buf[0..0]) == .valid);
    try std.testing.expect(verifyBatch(items[0..0], &buf) == .invalid);
    try std.testing.expect(std.meta.eql(c1, batchCalls()));
    // the key merge and the four-way chain are switched paths
    setBatchKeys(.{ .merge = true });
    c0 = batchCalls();
    try std.testing.expect(verifyBatch(&items, &buf) == .valid);
    c1 = batchCalls();
    try std.testing.expectEqual(c0.equations + 1, c1.equations);
    try std.testing.expectEqual(c0.switched + 1, c1.switched);
    setBatchKeys(.{});
    cpu.setEdVec4(.force);
    try std.testing.expect(verifyBatch(&items, &buf) == .valid);
    try std.testing.expectEqual(c1.switched + 1, batchCalls().switched);
    // the key cache switch without sig.fast's cache changes nothing, and is not counted
    cpu.setEdVec4(.off);
    setBatchKeys(.{ .cache = true });
    const fast_before = fast.config();
    defer fast.configure(fast_before);
    fast.configure(.{});
    c0 = batchCalls();
    try std.testing.expect(verifyBatch(&items, &buf) == .valid);
    try std.testing.expectEqual(c0.switched, batchCalls().switched);
    fast.configure(.{ .pk_cache = true });
    defer fast.clearCaches();
    try std.testing.expect(verifyBatch(&items, &buf) == .valid);
    try std.testing.expectEqual(c0.switched + 1, batchCalls().switched);
}

test "batch switches: names, set and read back, the environment read" {
    try std.testing.expect(std.meta.eql(parseBatchKeys("cache,merge"), BatchKeys{ .cache = true, .merge = true }));
    try std.testing.expect(std.meta.eql(parseBatchKeys("all"), BatchKeys{ .cache = true, .merge = true }));
    try std.testing.expect(std.meta.eql(parseBatchKeys("merge"), BatchKeys{ .merge = true }));
    try std.testing.expect(std.meta.eql(parseBatchKeys("cache"), BatchKeys{ .cache = true }));
    try std.testing.expect(std.meta.eql(parseBatchKeys("off"), BatchKeys{}));
    // exact tokens: a name inside a longer word switches nothing on
    try std.testing.expect(std.meta.eql(parseBatchKeys("nomerge"), BatchKeys{}));
    try std.testing.expect(std.meta.eql(parseBatchKeys("nocache,merge"), BatchKeys{}));
    try std.testing.expect(std.meta.eql(parseBatchKeys("cache,nomerge"), BatchKeys{}));
    // run the tests with ZUI_ED25519_BATCH_KEYS set to check the environment read end to end
    const want: BatchKeys = blk: {
        const v = std.testing.environ.getAlloc(std.testing.allocator, "ZUI_ED25519_BATCH_KEYS") catch break :blk .{};
        defer std.testing.allocator.free(v);
        break :blk parseBatchKeys(v);
    };
    if (comptime @import("builtin").link_libc) try std.testing.expect(std.meta.eql(want, batchKeysFromEnv()));
    // set and read back (whatever the environment asked for is put back at the end)
    const before = batchKeys();
    defer setBatchKeys(before);
    const vec_before = cpu.edVec4();
    defer cpu.setEdVec4(vec_before);
    cpu.setEdVec4(.off);
    setBatchKeys(.{ .merge = true });
    try std.testing.expect(std.meta.eql(batchKeys(), BatchKeys{ .merge = true }));
    try std.testing.expect(liveOpts().merge_keys);
    setBatchKeys(.{});
    try std.testing.expect(std.meta.eql(batchKeys(), BatchKeys{}));
    try std.testing.expect(!liveOpts().merge_keys and !liveOpts().vec4);
    cpu.setEdVec4(.force);
    try std.testing.expect(liveOpts().vec4);
}

test {
    _ = @import("ed25519_exact.zig");
    _ = @import("ed25519_avx2.zig");
}

/// ZUI_DUDECT=1 prints the t statistics (the build runner fails a test that writes to stderr).
fn dudectVerbose() bool {
    return std.testing.environ.containsUnempty(std.testing.allocator, "ZUI_DUDECT") catch false;
}
