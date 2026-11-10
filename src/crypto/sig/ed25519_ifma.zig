//! Ed25519 point arithmetic four field elements at a time on AVX-512 IFMA (radix 2^43, six limbs).
//!
//! Design:
//!
//!   - A field element is six limbs of 43 bits (the top one 40), so a limb product fits IFMA's
//!     52 x 52 -> 104-bit multiply-accumulate (`vpmadd52luq` / `vpmadd52huq`). The high half of a
//!     product sits 9 bits above the next limb (52 - 43), so it is added shifted left by 9.
//!   - A point (X, Y, Z, T) is three 8-lane vectors: `a` = limbs 0 and 3 of X, Y, Z, T, `b` = limbs
//!     1 and 4, `c` = limbs 2 and 5. One `mul` does four independent field multiplications with
//!     36 IFMA instructions and no wasted lanes; doubling is one squaring pass and one
//!     multiplication pass, an addition with a cached point two multiplication passes.
//!   - Limbs stay redundant between operations: `foldUnsigned` / `foldSigned` carry once per
//!     limb with no full reduction; only the final conversion back to `Fe` reduces.
//!
//! deepwave keeps its own scalar side (half-size scalars, width-5 NAF for A and R, width-8 NAF base
//! tables for B and 2^128 B); only the point arithmetic of the 128-step chain moves here.
//! Formulas are the extended twisted Edwards (a = -1) ones of Hisil, Wong, Carter and Dawson, as
//! in `ed25519.zig`, so the result is the same group element (verdicts are identical).
//!
//! `enabled` is a comptime switch (x86-64 with AVX-512F and AVX-512 IFMA, LLVM backend; for example
//! `-Dcpu=sapphirerapids` or `-Dcpu=icelake_server`). Elsewhere the same code runs with an
//! emulated multiply-accumulate, which is how the tests check it on any machine.
//! Verification is variable time (public inputs), like the scalar verifier.
const std = @import("std");
const builtin = @import("builtin");
const ed = @import("ed25519.zig");
const Fe = @import("fe25519.zig").Fe;

pub const enabled = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512ifma);

const V = @Vector(8, u64);
const VI = @Vector(8, i64);

const mask52: u64 = (1 << 52) - 1;
const m43: u64 = (1 << 43) - 1;
const m40: u64 = (1 << 40) - 1;

// ---------------------------------------------------------------------------------------------
// IFMA: acc + low / high 52 bits of (x mod 2^52) * (y mod 2^52), per lane.

inline fn madd52lo(acc: V, x: V, y: V) V {
    if (comptime enabled) {
        return asm ("vpmadd52luq %[y], %[x], %[out]"
            : [out] "=v" (-> V),
            : [acc] "0" (acc),
              [x] "v" (x),
              [y] "v" (y),
        );
    }
    const xa: [8]u64 = x;
    const ya: [8]u64 = y;
    var r: [8]u64 = acc;
    inline for (0..8) |i| {
        const p = @as(u128, xa[i] & mask52) * (ya[i] & mask52);
        r[i] +%= @as(u64, @truncate(p)) & mask52;
    }
    return r;
}

inline fn madd52hi(acc: V, x: V, y: V) V {
    if (comptime enabled) {
        return asm ("vpmadd52huq %[y], %[x], %[out]"
            : [out] "=v" (-> V),
            : [acc] "0" (acc),
              [x] "v" (x),
              [y] "v" (y),
        );
    }
    const xa: [8]u64 = x;
    const ya: [8]u64 = y;
    var r: [8]u64 = acc;
    inline for (0..8) |i| {
        const p = @as(u128, xa[i] & mask52) * (ya[i] & mask52);
        r[i] +%= @as(u64, @truncate(p >> 52)) & mask52;
    }
    return r;
}

// ---------------------------------------------------------------------------------------------
// Lane plumbing. Lanes 0..3 are X, Y, Z, T of the low limb of a vector, lanes 4..7 of the high one.

/// [x.half(ha) | y.half(hb)]
inline fn halves(comptime ha: u1, x: V, comptime hb: u1, y: V) V {
    const mask = comptime blk: {
        var m: [8]i32 = undefined;
        for (0..4) |i| {
            m[i] = @as(i32, ha) * 4 + @as(i32, i);
            m[4 + i] = ~(@as(i32, hb) * 4 + @as(i32, i));
        }
        break :blk m;
    };
    return @shuffle(u64, x, y, mask);
}

inline fn laneMask(comptime m: [4]u1) @Vector(8, bool) {
    return comptime .{ m[0] == 1, m[1] == 1, m[2] == 1, m[3] == 1, m[0] == 1, m[1] == 1, m[2] == 1, m[3] == 1 };
}

const lo_half: @Vector(8, bool) = .{ true, true, true, true, false, false, false, false };
const hi_half: @Vector(8, bool) = .{ false, false, false, false, true, true, true, true };

fn splat(x: u64) V {
    return @splat(x);
}

/// Four field elements (X, Y, Z, T of one point, or any four).
pub const Quad = struct {
    a: V, // limbs 0 | 3
    b: V, // limbs 1 | 4
    c: V, // limbs 2 | 5

    /// (S[p0], S[p1], S[p2], S[p3]) with 0..3 = X, Y, Z, T.
    inline fn permute(s: Quad, comptime p: [4]u2) Quad {
        const mask = comptime blk: {
            var m: [8]i32 = undefined;
            for (0..4) |i| {
                m[i] = p[i];
                m[4 + i] = 4 + @as(i32, p[i]);
            }
            break :blk m;
        };
        return .{
            .a = @shuffle(u64, s.a, undefined, mask),
            .b = @shuffle(u64, s.b, undefined, mask),
            .c = @shuffle(u64, s.c, undefined, mask),
        };
    }

    /// Lanes in m get p + q, the others keep s.
    inline fn addIf(s: Quad, comptime m: [4]u1, p: Quad, q: Quad) Quad {
        const k = laneMask(m);
        return .{
            .a = @select(u64, k, p.a +% q.a, s.a),
            .b = @select(u64, k, p.b +% q.b, s.b),
            .c = @select(u64, k, p.c +% q.c, s.c),
        };
    }

    /// Lanes in m get p - q (as p + (prime - q), limbs signed), the others keep s.
    inline fn subIf(s: Quad, comptime m: [4]u1, p: Quad, q: Quad) Quad {
        const k = laneMask(m);
        const pa: V = .{ m43 - 18, m43 - 18, m43 - 18, m43 - 18, m43, m43, m43, m43 };
        const pb: V = splat(m43);
        const pc: V = .{ m43, m43, m43, m43, m40, m40, m40, m40 };
        return .{
            .a = @select(u64, k, p.a +% (pa -% q.a), s.a),
            .b = @select(u64, k, p.b +% (pb -% q.b), s.b),
            .c = @select(u64, k, p.c +% (pc -% q.c), s.c),
        };
    }
};

const s43_40: @Vector(8, u6) = .{ 43, 43, 43, 43, 40, 40, 40, 40 };
const m43_40: V = .{ m43, m43, m43, m43, m40, m40, m40, m40 };

inline fn times19(x: V) V {
    return x +% (x << @splat(1)) +% (x << @splat(4));
}

/// Unsigned limbs (below 2^62) to limbs below about 2^44: one carry per limb, the top carry
/// times 19 into limb 0.
inline fn foldUnsigned(p: Quad) Quad {
    const ha = p.a >> @splat(43);
    const hb = p.b >> @splat(43);
    const hc = p.c >> s43_40;
    return .{
        .a = (p.a & splat(m43)) +% halves(1, times19(hc), 0, hc),
        .b = (p.b & splat(m43)) +% ha,
        .c = (p.c & m43_40) +% hb,
    };
}

/// Signed limbs (|x| below 2^62) to non-negative limbs below about 2^44. The bias keeps the
/// arithmetic-shift carries non-negative after they are added back; the value is unchanged.
inline fn foldSigned(p: Quad) Quad {
    const b0: u64 = 19 << 23;
    const bb: u64 = 1 << 20;
    const bias_a: V = .{ b0, b0, b0, b0, bb, bb, bb, bb };
    const bias: V = splat(bb);
    const pa = p.a -% bias_a;
    const pb = p.b -% bias;
    const pc = p.c -% bias;
    const ha: V = @bitCast(@as(VI, @bitCast(pa)) >> @splat(43));
    const hb: V = @bitCast(@as(VI, @bitCast(pb)) >> @splat(43));
    const hc: V = @bitCast(@as(VI, @bitCast(pc)) >> s43_40);
    return .{
        .a = (pa & splat(m43)) +% (halves(1, times19(hc), 0, hc) +% bias_a),
        .b = (pb & splat(m43)) +% (ha +% bias),
        .c = (pc & m43_40) +% (hb +% bias),
    };
}

/// Four products at once. Inputs: limbs below 2^47. Output: unsigned limbs below 2^62.
fn mul(x: Quad, y: Quad) Quad {
    const z: V = splat(0);
    const x00 = halves(0, x.a, 0, x.a);
    const x11 = halves(0, x.b, 0, x.b);
    const x22 = halves(0, x.c, 0, x.c);
    const x33 = halves(1, x.a, 1, x.a);
    const x44 = halves(1, x.b, 1, x.b);
    const x55 = halves(1, x.c, 1, x.c);
    const y03 = y.a;
    const y14 = y.b;
    const y25 = y.c;

    // pK_qL: the low half collects position K (2^(43K)), the high half position L = K + 3.
    const p0_q3 = madd52lo(z, x00, y03);
    var p1_q4 = madd52lo(madd52lo(z, x11, y03), x00, y14);
    var p2_q5 = madd52lo(madd52lo(madd52lo(z, x22, y03), x11, y14), x00, y25);
    var p3_q6 = madd52lo(madd52lo(madd52lo(z, x33, y03), x22, y14), x11, y25);
    var p4_q7 = madd52lo(madd52lo(madd52lo(z, x44, y03), x33, y14), x22, y25);
    var p5_q8 = madd52lo(madd52lo(madd52lo(z, x55, y03), x44, y14), x33, y25);
    var p6_q9 = madd52lo(madd52lo(z, x55, y14), x44, y25);
    var p7_qa = madd52lo(z, x55, y25);

    // High halves land one limb up, 9 bits in.
    const s9: @Vector(8, u6) = @splat(9);
    p1_q4 +%= madd52hi(z, x00, y03) << s9;
    p2_q5 +%= madd52hi(madd52hi(z, x11, y03), x00, y14) << s9;
    p3_q6 +%= madd52hi(madd52hi(madd52hi(z, x22, y03), x11, y14), x00, y25) << s9;
    p4_q7 +%= madd52hi(madd52hi(madd52hi(z, x33, y03), x22, y14), x11, y25) << s9;
    p5_q8 +%= madd52hi(madd52hi(madd52hi(z, x44, y03), x33, y14), x22, y25) << s9;
    p6_q9 +%= madd52hi(madd52hi(madd52hi(z, x55, y03), x44, y14), x33, y25) << s9;
    p7_qa +%= madd52hi(madd52hi(z, x55, y14), x44, y25) << s9;
    const p8_qb = madd52hi(z, x55, y25) << s9;

    const q6_p3 = halves(1, p3_q6, 0, p3_q6);
    const q7_p4 = halves(1, p4_q7, 0, p4_q7);
    const q8_p5 = halves(1, p5_q8, 0, p5_q8);
    // za: positions 0..5, zb: positions 6..11 (worth 2^258 = 152 mod p).
    const za03 = @select(u64, hi_half, p0_q3 +% q6_p3, p0_q3);
    const za14 = @select(u64, hi_half, p1_q4 +% q7_p4, p1_q4);
    const za25 = @select(u64, hi_half, p2_q5 +% q8_p5, p2_q5);
    const zb03 = @select(u64, lo_half, p6_q9 +% q6_p3, p6_q9);
    const zb14 = @select(u64, lo_half, p7_qa +% q7_p4, p7_qa);
    const zb25 = @select(u64, lo_half, p8_qb +% q8_p5, p8_qb);
    return .{ .a = za03 +% times152(zb03), .b = za14 +% times152(zb14), .c = za25 +% times152(zb25) };
}

inline fn times152(x: V) V {
    return (x << @splat(7)) +% (x << @splat(4)) +% (x << @splat(3));
}

// ---------------------------------------------------------------------------------------------
// Conversions with deepwave's radix-2^51 `Fe`.

fn limbsFromFe(x: Fe) [6]u64 {
    var v: u320 = 0;
    inline for (0..5) |i| v += @as(u320, x.l[i]) << (51 * i);
    var o: [6]u64 = undefined;
    inline for (0..5) |k| o[k] = @as(u64, @truncate(v >> (43 * k))) & m43;
    o[5] = @truncate(v >> 215);
    return o;
}

fn feFromLimbs(l: [6]u64) Fe {
    var v: u320 = 0;
    inline for (0..6) |k| v += @as(u320, l[k]) << (43 * k);
    const m255: u320 = (1 << 255) - 1;
    v = (v & m255) + 19 * (v >> 255);
    v = (v & m255) + 19 * (v >> 255);
    var o: Fe = undefined;
    inline for (0..4) |i| o.l[i] = @as(u64, @truncate(v >> (51 * i))) & Fe.mask51;
    o.l[4] = @truncate(v >> 204);
    return o;
}

fn pack(x: [6]u64, y: [6]u64, z: [6]u64, t: [6]u64) Quad {
    return .{
        .a = .{ x[0], y[0], z[0], t[0], x[3], y[3], z[3], t[3] },
        .b = .{ x[1], y[1], z[1], t[1], x[4], y[4], z[4], t[4] },
        .c = .{ x[2], y[2], z[2], t[2], x[5], y[5], z[5], t[5] },
    };
}

fn unpack(q: Quad) [4][6]u64 {
    const a: [8]u64 = q.a;
    const b: [8]u64 = q.b;
    const c: [8]u64 = q.c;
    var o: [4][6]u64 = undefined;
    for (0..4) |j| o[j] = .{ a[j], b[j], c[j], a[4 + j], b[4 + j], c[4 + j] };
    return o;
}

pub fn fromPoint(p: ed.Point) Quad {
    return pack(limbsFromFe(p.x), limbsFromFe(p.y), limbsFromFe(p.z), limbsFromFe(p.t));
}

pub fn toPoint(q: Quad) ed.Point {
    const u = unpack(q);
    return .{ .x = feFromLimbs(u[0]), .y = feFromLimbs(u[1]), .z = feFromLimbs(u[2]), .t = feFromLimbs(u[3]) };
}

pub fn toProjective(q: Quad) ed.Projective {
    const u = unpack(q);
    return .{ .x = feFromLimbs(u[0]), .y = feFromLimbs(u[1]), .z = feFromLimbs(u[2]) };
}

// ---------------------------------------------------------------------------------------------
// Points. An extended point is (X, Y, Z, T); a cached point is (Y - X, Y + X, 2Z, 2dT).

pub const identity: Quad = .{ .a = .{ 0, 1, 1, 0, 0, 0, 0, 0 }, .b = splat(0), .c = splat(0) };

const k1112d: Quad = blk: {
    const one = [6]u64{ 1, 0, 0, 0, 0, 0 };
    break :blk pack(one, one, one, limbsFromFe(Fe.d2));
};

/// 2P (dbl-2008-hwcd for a = -1, T of the input unused). Input limbs below 2^45.
pub fn dbl(p: Quad) Quad {
    var ta = p.permute(.{ 1, 1, 2, 0 }); // (Y, Y, Z, X)
    ta = ta.addIf(.{ 1, 0, 0, 0 }, ta, p); // (X+Y, Y, Z, X)
    // Squared with the general product (limbs below 2^62, one bit more than a dedicated
    // squaring), so fold before the sums: otherwise C = 2Z^2 and F = G + C can pass 2^63 and
    // foldSigned would read F as negative.
    ta = foldUnsigned(mul(ta, ta)); // ((X+Y)^2, B, Z^2, A)
    ta = ta.addIf(.{ 0, 0, 1, 0 }, ta, ta); // ((X+Y)^2, B, C, A)
    var tb = ta.permute(.{ 3, 3, 3, 3 }); // (A, A, A, A)
    const bb = ta.permute(.{ 1, 1, 1, 1 }); // (B, B, B, B)
    tb = tb.addIf(.{ 1, 0, 0, 1 }, tb, bb); // (H, A, A, H)
    tb = tb.subIf(.{ 0, 1, 1, 0 }, tb, bb); // (H, G, G, H)
    tb = tb.addIf(.{ 0, 0, 1, 0 }, tb, ta); // (H, G, F, H)
    tb = tb.subIf(.{ 1, 0, 0, 0 }, tb, ta); // (E, G, F, H)
    tb = foldSigned(tb);
    const l = tb.permute(.{ 0, 1, 1, 0 }); // (E, G, G, E)
    const r = tb.permute(.{ 2, 3, 2, 3 }); // (F, H, F, H)
    return foldUnsigned(mul(l, r)); // (EF, GH, GF, EH)
}

/// P + Q for Q cached (add-2008-hwcd-3). Input limbs below 2^44.
pub fn addCached(p: Quad, q: Quad) Quad {
    var ta = p.permute(.{ 1, 0, 2, 3 }); // (Y, X, Z, T)
    ta = ta.subIf(.{ 1, 0, 0, 0 }, ta, p); // (Y-X, X, Z, T)
    ta = ta.addIf(.{ 0, 1, 0, 0 }, ta, p); // (Y-X, Y+X, Z, T)
    ta = foldSigned(ta);
    ta = mul(ta, q); // (A, B, D, C)
    var tb = ta.permute(.{ 1, 0, 3, 2 }); // (B, A, C, D)
    tb = tb.subIf(.{ 1, 0, 0, 1 }, tb, ta); // (E, A, C, F)
    tb = tb.addIf(.{ 0, 1, 1, 0 }, tb, ta); // (E, H, G, F)
    tb = foldSigned(tb);
    const l = tb.permute(.{ 0, 2, 2, 0 }); // (E, G, G, E)
    const r = tb.permute(.{ 3, 1, 3, 1 }); // (F, H, F, H)
    return foldUnsigned(mul(l, r)); // (EF, GH, GF, EH)
}

/// (Y - X, Y + X, 2Z, 2dT).
pub fn toCached(p: Quad) Quad {
    var ta = p.permute(.{ 1, 0, 2, 3 });
    ta = ta.subIf(.{ 1, 0, 0, 0 }, ta, p);
    ta = ta.addIf(.{ 0, 1, 1, 0 }, ta, p);
    return foldUnsigned(mul(foldSigned(ta), k1112d));
}

/// The cached form of -P: (Y + X, Y - X, 2Z, -2dT).
pub fn negCached(c: Quad) Quad {
    const zero: Quad = .{ .a = splat(0), .b = splat(0), .c = splat(0) };
    const s = c.permute(.{ 1, 0, 2, 3 });
    return foldSigned(s.subIf(.{ 0, 0, 0, 1 }, zero, s));
}

/// Odd multiples P, 3P, ..., 15P and their negatives (width-5 NAF), cached.
pub const Table = struct {
    pos: [8]Quad,
    neg: [8]Quad,

    pub fn init(p: ed.Point) Table {
        var t: Table = undefined;
        const q = fromPoint(p);
        const c2 = toCached(dbl(q));
        var cur = q;
        t.pos[0] = toCached(cur);
        for (1..8) |i| {
            cur = addCached(cur, c2);
            t.pos[i] = toCached(cur);
        }
        for (0..8) |i| t.neg[i] = negCached(t.pos[i]);
        return t;
    }
};

const BaseTable = struct { pos: [64]Quad, neg: [64]Quad };

fn baseTable(comptime src: [64]ed.AffineNiels) BaseTable {
    @setEvalBranchQuota(100_000_000);
    var t: BaseTable = undefined;
    const two = [6]u64{ 2, 0, 0, 0, 0, 0 };
    for (0..64) |i| {
        const n = src[i];
        t.pos[i] = pack(limbsFromFe(n.ymx), limbsFromFe(n.ypx), two, limbsFromFe(n.xy2d));
        t.neg[i] = pack(limbsFromFe(n.ypx), limbsFromFe(n.ymx), two, limbsFromFe(n.xy2d.neg()));
    }
    return t;
}

/// B, 3B, ..., 127B and 2^128 B times the same, cached (affine: Z = 1).
const base_q: BaseTable = baseTable(ed.base_table);
const base128_q: BaseTable = baseTable(ed.base128_table);

inline fn half(d: i8) usize {
    return @as(usize, @abs(d)) >> 1;
}

inline fn step(acc: Quad, d: i8, pos: []const Quad, neg: []const Quad) Quad {
    if (d > 0) return addCached(acc, pos[half(d)]);
    if (d < 0) return addCached(acc, neg[half(d)]);
    return acc;
}

/// [a]A + [r]R + [b0]B + [b1](2^128 B) for the half-size NAFs of `ed.checkHalf`: the same chain as
/// `ed.quadMul`, with the point arithmetic on the quad kernel.
pub fn quadMul(a: ed.Point, na: *const [ed.qn]i8, r: ed.Point, nr: *const [ed.qn]i8, nb0: *const [ed.qn]i8, nb1: *const [ed.qn]i8) ed.Projective {
    var i: usize = ed.qn - 1;
    while (i > 0 and na[i] == 0 and nr[i] == 0 and nb0[i] == 0 and nb1[i] == 0) i -= 1;
    const ta = Table.init(a);
    const tr = Table.init(r);
    var acc = identity;
    while (true) {
        acc = dbl(acc);
        acc = step(acc, na[i], &ta.pos, &ta.neg);
        acc = step(acc, nr[i], &tr.pos, &tr.neg);
        acc = step(acc, nb0[i], &base_q.pos, &base_q.neg);
        acc = step(acc, nb1[i], &base128_q.pos, &base128_q.neg);
        if (i == 0) break;
        i -= 1;
    }
    return toProjective(acc);
}

// ---------------------------------------------------------------------------------------------
// Tests (run everywhere: off x86 IFMA they exercise the emulated multiply-accumulate).

fn projEql(p: ed.Projective, q: ed.Projective) bool {
    return p.x.mul(q.z).eql(q.x.mul(p.z)) and p.y.mul(q.z).eql(q.y.mul(p.z));
}

fn randPoint(rng: std.Random) ed.Point {
    var s: [32]u8 = undefined;
    rng.bytes(&s);
    s[31] &= 0x0f;
    return ed.mulBaseCT(&s);
}

test "ifma quad: field mul matches Fe.mul for four lanes" {
    var prng = std.Random.DefaultPrng.init(0x1f3a);
    const rng = prng.random();
    for (0..2000) |_| {
        var xs: [4]Fe = undefined;
        var ys: [4]Fe = undefined;
        for (0..4) |j| {
            var b: [32]u8 = undefined;
            rng.bytes(&b);
            xs[j] = Fe.fromBytes(&b);
            rng.bytes(&b);
            ys[j] = Fe.fromBytes(&b);
        }
        const qx = pack(limbsFromFe(xs[0]), limbsFromFe(xs[1]), limbsFromFe(xs[2]), limbsFromFe(xs[3]));
        const qy = pack(limbsFromFe(ys[0]), limbsFromFe(ys[1]), limbsFromFe(ys[2]), limbsFromFe(ys[3]));
        const u = unpack(foldUnsigned(mul(qx, qy)));
        for (0..4) |j| try std.testing.expect(feFromLimbs(u[j]).eql(xs[j].mul(ys[j])));
        // folds keep the value
        const s = unpack(foldSigned(qx.subIf(.{ 1, 1, 1, 1 }, qx, qy)));
        for (0..4) |j| try std.testing.expect(feFromLimbs(s[j]).eql(xs[j].sub(ys[j])));
    }
}

test "ifma quad: dbl, addCached and tables match the scalar formulas" {
    var prng = std.Random.DefaultPrng.init(0x77);
    const rng = prng.random();
    for (0..200) |_| {
        const p = randPoint(rng);
        const q = randPoint(rng);
        try std.testing.expect(projEql(toProjective(dbl(fromPoint(p))), p.dbl().toProjective()));
        const s = addCached(fromPoint(p), toCached(fromPoint(q)));
        try std.testing.expect(projEql(toProjective(s), p.add(q).toProjective()));
        const d = addCached(fromPoint(p), negCached(toCached(fromPoint(q))));
        try std.testing.expect(projEql(toProjective(d), p.sub(q).toProjective()));
    }
    // affine base entries: entry i is (2i+1)B
    var acc = ed.basepoint;
    const b2 = ed.basepoint.dbl();
    for (0..64) |i| {
        const got = addCached(identity, base_q.pos[i]);
        try std.testing.expect(projEql(toProjective(got), acc.toProjective()));
        acc = acc.add(b2);
    }
}

test "ifma quad: dbl with maximal unreduced limbs stays exact" {
    // Inputs as large as foldUnsigned can return: every limb 2^44 - 1. Before the fold in dbl,
    // inputs like these pushed F = G + C past 2^63 (seen on 2 of 84,076 sig-vectors).
    var prng = std.Random.DefaultPrng.init(0xb16);
    const rng = prng.random();
    for (0..2000) |_| {
        var l: [4][6]u64 = undefined;
        for (&l) |*e| for (e) |*x| {
            x.* = (1 << 44) - 1 - rng.uintLessThan(u64, 1 << 8);
        };
        const q = pack(l[0], l[1], l[2], l[3]);
        const p = toPoint(q);
        // dbl ignores T, so compare projective results of the same (X, Y, Z)
        try std.testing.expect(projEql(toProjective(dbl(q)), p.toProjective().dbl().toProjective()));
    }
}

test "ifma quad: quadMul equals the scalar quadMul" {
    var prng = std.Random.DefaultPrng.init(0x5eed);
    const rng = prng.random();
    for (0..64) |_| {
        const a = randPoint(rng);
        const r = randPoint(rng);
        var k: [4]u128 = undefined;
        for (&k) |*x| x.* = rng.int(u128);
        const na = ed.wnaf(ed.qn, k[0], 5, rng.boolean());
        const nr = ed.wnaf(ed.qn, k[1], 5, false);
        const nb0 = ed.wnaf(ed.qn, k[2], 8, true);
        const nb1 = ed.wnaf(ed.qn, k[3], 8, true);
        const tabs = ed.naf5Tables2(a, r);
        const want = ed.quadMul(&tabs[0], &na, &tabs[1], &nr, &nb0, &nb1);
        const got = quadMul(a, &na, r, &nr, &nb0, &nb1);
        try std.testing.expect(projEql(got, want));
    }
}
