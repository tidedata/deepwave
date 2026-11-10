//! GF(2^255 - 19) four elements at a time: one `@Vector(4, u32)` per limb in radix 2^25.5
//! (ten limbs of 26, 25, 26, ... bits, the ref10 shape), products as `@Vector(4, u64)` of
//! zero-extended u32 lanes. LLVM lowers the products to NEON `umull`/`umlal` on aarch64 and to
//! `vpmuludq` on x86-64 (one AVX2 instruction for all four lanes).
//!
//! What it is for: the vector unit and the scalar 64x64 multiplier are separate pipes, so a
//! loop that steps four `Fe4` lanes and four scalar `Fe` chains together does eight field
//! operations in about the time of four scalar ones (Apple M5 Pro: 8 squarings in 16.6 ns
//! against 13.3 ns for 4 scalar). Batch verification decodes its points that way (`pow2523x8`).
//!
//! Limb bounds: `sq`/`mul` take limbs below 2^26.6 (even) and 2^25.6 (odd) so every 19- and
//! 38-multiple fits in u32 and each output column stays below 2^62; outputs are carried to
//! 26/25 bits, except limbs 1 and 5: each takes one more carry after it was masked (limb 1 the
//! wrapped carry out of limb 0, limb 5 the second carry out of limb 4), so they can sit above
//! 2^25, limb 1 by less than 2^18 and limb 5 by less than 2^14 whatever the columns (`carry`).
//! `fromFe` takes `Fe` limbs below 2^51 + 2^13, which is what `Fe.mul`/`Fe.sq` return.
//! Constant time (no branches, no data-dependent indices).
const std = @import("std");
const Fe = @import("fe25519.zig").Fe;

const V = @Vector(4, u32);
const W = @Vector(4, u64);

fn wide(x: V) W {
    return @as(W, x);
}

/// 32 x 32 -> 64 per lane.
fn m(a: V, b: V) W {
    return wide(a) * wide(b);
}

const m26: W = @splat((1 << 26) - 1);
const m25: W = @splat((1 << 25) - 1);
const m26n: u64 = (1 << 26) - 1;

pub const Fe4 = struct {
    l: [10]V,

    /// Lane j holds a[j]. The 51-bit limbs split exactly into a 26-bit and a 25-bit limb.
    pub fn fromFe(a: [4]Fe) Fe4 {
        var o: Fe4 = undefined;
        inline for (0..5) |i| {
            var lo: [4]u32 = undefined;
            var hi: [4]u32 = undefined;
            inline for (0..4) |j| {
                const x = a[j].l[i];
                lo[j] = @truncate(x & m26n);
                hi[j] = @truncate(x >> 26);
            }
            o.l[2 * i] = lo;
            o.l[2 * i + 1] = hi;
        }
        return o;
    }

    /// Lane j as an `Fe`: limb i is l[2i] + 2^26 * l[2i + 1], with no carry, so the bound
    /// follows the input. A carried element (even limbs below 2^26, odd limbs at most 2^25,
    /// limbs 1 and 5 above that by less than 2^18 and 2^14) gives limbs below 2^51 + 2^26,
    /// except limb 0 (below 2^51 + 2^45) and limb 2 (below 2^51 + 2^41), which take what limbs
    /// 1 and 5 hold above 2^25. An uncarried element k times as large gives limbs about k * 2^51;
    /// `Fe.mul`, `Fe.sq` and `Fe.sub` take limbs below 2^54.
    pub fn toFe(f: Fe4) [4]Fe {
        var o: [4]Fe = undefined;
        inline for (0..5) |i| {
            const lo: [4]u32 = f.l[2 * i];
            const hi: [4]u32 = f.l[2 * i + 1];
            inline for (0..4) |j| o[j].l[i] = @as(u64, lo[j]) + (@as(u64, hi[j]) << 26);
        }
        return o;
    }

    pub fn sq(f: Fe4) Fe4 {
        const x = f.l;
        const c2: V = @splat(2);
        const c19: V = @splat(19);
        const c38: V = @splat(38);
        const f0_2 = x[0] * c2;
        const f1_2 = x[1] * c2;
        const f2_2 = x[2] * c2;
        const f3_2 = x[3] * c2;
        const f4_2 = x[4] * c2;
        const f5_2 = x[5] * c2;
        const f7_2 = x[7] * c2;
        const f5_38 = x[5] * c38;
        const f6_19 = x[6] * c19;
        const f7_38 = x[7] * c38;
        const f8_19 = x[8] * c19;
        const f8_38 = x[8] * c38;
        const f6_38 = x[6] * c38;
        const f9_38 = x[9] * c38;
        var h: [10]W = undefined;
        h[0] = m(x[0], x[0]) + m(f1_2, f9_38) + m(f2_2, f8_19) + m(f3_2, f7_38) + m(f4_2, f6_19) + m(x[5], f5_38);
        h[1] = m(f0_2, x[1]) + m(x[2], f9_38) + m(x[3], f8_38) + m(x[4], f7_38) + m(x[5], f6_38);
        h[2] = m(f0_2, x[2]) + m(f1_2, x[1]) + m(f3_2, f9_38) + m(f4_2, f8_19) + m(f5_2, f7_38) + m(x[6], f6_19);
        h[3] = m(f0_2, x[3]) + m(f1_2, x[2]) + m(x[4], f9_38) + m(x[5], f8_38) + m(x[6], f7_38);
        h[4] = m(f0_2, x[4]) + m(f1_2, f3_2) + m(x[2], x[2]) + m(f5_2, f9_38) + m(x[6] * c2, f8_19) + m(x[7], f7_38);
        h[5] = m(f0_2, x[5]) + m(f1_2, x[4]) + m(f2_2, x[3]) + m(x[6], f9_38) + m(x[7], f8_38);
        h[6] = m(f0_2, x[6]) + m(f1_2, f5_2) + m(f2_2, x[4]) + m(f3_2, x[3]) + m(f7_2, f9_38) + m(x[8], f8_19);
        h[7] = m(f0_2, x[7]) + m(f1_2, x[6]) + m(f2_2, x[5]) + m(f3_2, x[4]) + m(x[8], f9_38);
        h[8] = m(f0_2, x[8]) + m(f1_2, f7_2) + m(f2_2, x[6]) + m(f3_2, f5_2) + m(x[4], x[4]) + m(x[9], f9_38);
        h[9] = m(f0_2, x[9]) + m(f1_2, x[8]) + m(f2_2, x[7]) + m(f3_2, x[6]) + m(f4_2, x[5]);
        return carry(&h);
    }

    /// Wider inputs than the header's (the point kernel, ed25519_avx2.zig, relies on these):
    /// with f at most A times and g at most B times a carried element (limbs 2^26 even, 2^25
    /// odd), the u32 products need 19 * g limb below 2^32 (B below 3.36) and the largest column is
    /// 498 * 2^50 * A * B, so A * B must stay below 32. The kernel uses A up to 5.03 and B up to
    /// 3.03 (A * B at most 15.3).
    pub fn mul(f: Fe4, g: Fe4) Fe4 {
        const a = f.l;
        const b = g.l;
        const c2: V = @splat(2);
        const c19: V = @splat(19);
        var b19: [10]V = undefined;
        inline for (1..10) |i| b19[i] = b[i] * c19;
        const a1_2 = a[1] * c2;
        const a3_2 = a[3] * c2;
        const a5_2 = a[5] * c2;
        const a7_2 = a[7] * c2;
        const a9_2 = a[9] * c2;
        var h: [10]W = undefined;
        h[0] = m(a[0], b[0]) + m(a1_2, b19[9]) + m(a[2], b19[8]) + m(a3_2, b19[7]) + m(a[4], b19[6]) + m(a5_2, b19[5]) + m(a[6], b19[4]) + m(a7_2, b19[3]) + m(a[8], b19[2]) + m(a9_2, b19[1]);
        h[1] = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b19[9]) + m(a[3], b19[8]) + m(a[4], b19[7]) + m(a[5], b19[6]) + m(a[6], b19[5]) + m(a[7], b19[4]) + m(a[8], b19[3]) + m(a[9], b19[2]);
        h[2] = m(a[0], b[2]) + m(a1_2, b[1]) + m(a[2], b[0]) + m(a3_2, b19[9]) + m(a[4], b19[8]) + m(a5_2, b19[7]) + m(a[6], b19[6]) + m(a7_2, b19[5]) + m(a[8], b19[4]) + m(a9_2, b19[3]);
        h[3] = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b19[9]) + m(a[5], b19[8]) + m(a[6], b19[7]) + m(a[7], b19[6]) + m(a[8], b19[5]) + m(a[9], b19[4]);
        h[4] = m(a[0], b[4]) + m(a1_2, b[3]) + m(a[2], b[2]) + m(a3_2, b[1]) + m(a[4], b[0]) + m(a5_2, b19[9]) + m(a[6], b19[8]) + m(a7_2, b19[7]) + m(a[8], b19[6]) + m(a9_2, b19[5]);
        h[5] = m(a[0], b[5]) + m(a[1], b[4]) + m(a[2], b[3]) + m(a[3], b[2]) + m(a[4], b[1]) + m(a[5], b[0]) + m(a[6], b19[9]) + m(a[7], b19[8]) + m(a[8], b19[7]) + m(a[9], b19[6]);
        h[6] = m(a[0], b[6]) + m(a1_2, b[5]) + m(a[2], b[4]) + m(a3_2, b[3]) + m(a[4], b[2]) + m(a5_2, b[1]) + m(a[6], b[0]) + m(a7_2, b19[9]) + m(a[8], b19[8]) + m(a9_2, b19[7]);
        h[7] = m(a[0], b[7]) + m(a[1], b[6]) + m(a[2], b[5]) + m(a[3], b[4]) + m(a[4], b[3]) + m(a[5], b[2]) + m(a[6], b[1]) + m(a[7], b[0]) + m(a[8], b19[9]) + m(a[9], b19[8]);
        h[8] = m(a[0], b[8]) + m(a1_2, b[7]) + m(a[2], b[6]) + m(a3_2, b[5]) + m(a[4], b[4]) + m(a5_2, b[3]) + m(a[6], b[2]) + m(a7_2, b[1]) + m(a[8], b[0]) + m(a9_2, b19[9]);
        h[9] = m(a[0], b[9]) + m(a[1], b[8]) + m(a[2], b[7]) + m(a[3], b[6]) + m(a[4], b[5]) + m(a[5], b[4]) + m(a[6], b[3]) + m(a[7], b[2]) + m(a[8], b[1]) + m(a[9], b[0]);
        return carry(&h);
    }

    /// `sq` for the point kernel (ed25519_avx2.zig): wider inputs, and the lanes in `neg` come
    /// out negated mod p.
    ///
    /// Inputs: even limbs below 2^27.75 and odd limbs below 2^26.75 (3.36 times a carried limb;
    /// the kernel passes at most a sum of two carried elements). `sq` multiplies some even limbs
    /// by 38, which passes 2^32 from 2^26.75 on; here those four products are (2 * odd limb) *
    /// (19 * even limb), the same value, so the only u32 products are 2 * limb, 19 * even limb and
    /// 38 * odd limb. Every 64-bit column stays below 2^62.5 (even) and 2^61.8 (odd).
    ///
    /// Negation: each column of a negated lane is subtracted from the same column of 2^37 p
    /// (limbs just under 2^63 and 2^62, above any column), then the usual carry runs, so the
    /// output is carried like any other. Outputs: the bounds of `mul`.
    pub fn sqNeg(f: Fe4, comptime neg: [4]bool) Fe4 {
        const x = f.l;
        const c2: V = @splat(2);
        const c19: V = @splat(19);
        const c38: V = @splat(38);
        const f0_2 = x[0] * c2;
        const f1_2 = x[1] * c2;
        const f2_2 = x[2] * c2;
        const f3_2 = x[3] * c2;
        const f4_2 = x[4] * c2;
        const f5_2 = x[5] * c2;
        const f6_2 = x[6] * c2;
        const f7_2 = x[7] * c2;
        const f5_38 = x[5] * c38;
        const f6_19 = x[6] * c19;
        const f7_38 = x[7] * c38;
        const f8_19 = x[8] * c19;
        const f9_38 = x[9] * c38;
        var h: [10]W = undefined;
        h[0] = m(x[0], x[0]) + m(f1_2, f9_38) + m(f2_2, f8_19) + m(f3_2, f7_38) + m(f4_2, f6_19) + m(x[5], f5_38);
        h[1] = m(f0_2, x[1]) + m(x[2], f9_38) + m(f3_2, f8_19) + m(x[4], f7_38) + m(f5_2, f6_19);
        h[2] = m(f0_2, x[2]) + m(f1_2, x[1]) + m(f3_2, f9_38) + m(f4_2, f8_19) + m(f5_2, f7_38) + m(x[6], f6_19);
        h[3] = m(f0_2, x[3]) + m(f1_2, x[2]) + m(x[4], f9_38) + m(f5_2, f8_19) + m(x[6], f7_38);
        h[4] = m(f0_2, x[4]) + m(f1_2, f3_2) + m(x[2], x[2]) + m(f5_2, f9_38) + m(f6_2, f8_19) + m(x[7], f7_38);
        h[5] = m(f0_2, x[5]) + m(f1_2, x[4]) + m(f2_2, x[3]) + m(x[6], f9_38) + m(f7_2, f8_19);
        h[6] = m(f0_2, x[6]) + m(f1_2, f5_2) + m(f2_2, x[4]) + m(f3_2, x[3]) + m(f7_2, f9_38) + m(x[8], f8_19);
        h[7] = m(f0_2, x[7]) + m(f1_2, x[6]) + m(f2_2, x[5]) + m(f3_2, x[4]) + m(x[8], f9_38);
        h[8] = m(f0_2, x[8]) + m(f1_2, f7_2) + m(f2_2, x[6]) + m(f3_2, f5_2) + m(x[4], x[4]) + m(x[9], f9_38);
        h[9] = m(f0_2, x[9]) + m(f1_2, x[8]) + m(f2_2, x[7]) + m(f3_2, x[6]) + m(f4_2, x[5]);
        if (comptime (neg[0] or neg[1] or neg[2] or neg[3])) {
            const mask: @Vector(4, bool) = neg;
            inline for (0..10) |i| {
                const limb: u64 = if (i == 0) (1 << 26) - 19 else if (i % 2 == 0) (1 << 26) - 1 else (1 << 25) - 1;
                const bias: W = @splat(limb << 37);
                h[i] = @select(u64, mask, bias - h[i], h[i]);
            }
        }
        return carry(&h);
    }

    /// Lane j times the constant k[j] (below 2^19), carried. Input limbs below 2^30.
    pub fn mulSmall(f: Fe4, comptime k: [4]u32) Fe4 {
        const kv: V = k;
        var h: [10]W = undefined;
        inline for (0..10) |i| h[i] = m(f.l[i], kv);
        return carry(&h);
    }

    /// ref10's two interleaved carry chains (0,4), (1,5), ... then 9 -> 0 and 0 -> 1.
    /// Limbs 5 and 1 are masked in the first round and take a carry in the last steps (4 -> 5
    /// and 0 -> 1), which nothing masks again. With every column below 2^64 the carry out of
    /// limb 4 is at most 2^13 and the one out of limb 0 is below 2^18 (19 times the carry out of
    /// limb 9, below 2^39, shifted down by 26).
    fn carry(h: *[10]W) Fe4 {
        const s26: W = @splat(26);
        const s25: W = @splat(25);
        h[1] += h[0] >> s26;
        h[0] &= m26;
        h[5] += h[4] >> s26;
        h[4] &= m26;
        h[2] += h[1] >> s25;
        h[1] &= m25;
        h[6] += h[5] >> s25;
        h[5] &= m25;
        h[3] += h[2] >> s26;
        h[2] &= m26;
        h[7] += h[6] >> s26;
        h[6] &= m26;
        h[4] += h[3] >> s25;
        h[3] &= m25;
        h[8] += h[7] >> s25;
        h[7] &= m25;
        h[5] += h[4] >> s26;
        h[4] &= m26;
        h[9] += h[8] >> s26;
        h[8] &= m26;
        const c9 = h[9] >> s25;
        h[9] &= m25;
        h[0] += c9 * @as(W, @splat(19));
        h[1] += h[0] >> s26;
        h[0] &= m26;
        var o: Fe4 = undefined;
        inline for (0..10) |i| o.l[i] = @truncate(h[i]);
        return o;
    }
};

/// x^(2^252 - 3) for eight elements: x[0..4] in the vector lanes, x[4..8] as four scalar chains,
/// all stepped in one loop so both multipliers stay busy.
pub fn pow2523x8(x: [8]Fe) [8]Fe {
    const P = struct {
        v: Fe4,
        s: [4]Fe,
        inline fn sqn(p: *@This(), n: usize) void {
            var i: usize = 0;
            while (i < n) : (i += 1) {
                p.v = p.v.sq();
                inline for (0..4) |j| p.s[j] = p.s[j].sq();
            }
        }
        inline fn mulp(a: @This(), b: @This()) @This() {
            var o: @This() = .{ .v = a.v.mul(b.v), .s = undefined };
            inline for (0..4) |j| o.s[j] = a.s[j].mul(b.s[j]);
            return o;
        }
    };
    const z: P = .{ .v = Fe4.fromFe(x[0..4].*), .s = x[4..8].* };
    var t0 = z;
    t0.sqn(1);
    var t1 = t0;
    t1.sqn(2);
    const t2 = P.mulp(z, t1);
    const t3 = P.mulp(t0, t2);
    t0 = t3;
    t0.sqn(1);
    const t5 = P.mulp(t2, t0);
    t1 = t5;
    t1.sqn(5);
    const t7 = P.mulp(t1, t5);
    t1 = t7;
    t1.sqn(10);
    const t9 = P.mulp(t1, t7);
    t1 = t9;
    t1.sqn(20);
    const t11 = P.mulp(t1, t9);
    t1 = t11;
    t1.sqn(10);
    const t13 = P.mulp(t1, t7);
    t1 = t13;
    t1.sqn(50);
    const t15 = P.mulp(t1, t13);
    t1 = t15;
    t1.sqn(100);
    const t17 = P.mulp(t1, t15);
    t1 = t17;
    t1.sqn(50);
    const t19 = P.mulp(t1, t13);
    t1 = t19;
    t1.sqn(2);
    const r = P.mulp(t1, z);
    var out: [8]Fe = undefined;
    out[0..4].* = r.v.toFe();
    out[4..8].* = r.s;
    return out;
}

fn feEq(a: Fe, b: Fe) bool {
    return std.mem.eql(u8, &a.toBytes(), &b.toBytes());
}

test "Fe4 agrees with Fe: sq, mul, round trip, edge values, long chains" {
    var prng: std.Random.DefaultPrng = .init(0x4665_3478);
    const rnd = prng.random();
    const p: u256 = (1 << 255) - 19;
    // edge encodings: 0, 1, p-1, p, p+1, 2^255-1 (non-canonical), all-ones limbs
    const edges = [_]u256{ 0, 1, p - 1, p, p + 1, (1 << 255) - 1, (1 << 254), 19, p - 19 };
    var vals: [64]Fe = undefined;
    for (&vals, 0..) |*v, i| {
        var b: [32]u8 = undefined;
        if (i < edges.len) std.mem.writeInt(u256, &b, edges[i], .little) else rnd.bytes(&b);
        b[31] &= 0x7f;
        v.* = Fe.fromBytes(&b);
    }
    var i: usize = 0;
    while (i + 8 <= vals.len) : (i += 4) {
        const a = vals[i..][0..4].*;
        const b = vals[i + 4 ..][0..4].*;
        const fa = Fe4.fromFe(a);
        const fb = Fe4.fromFe(b);
        for (fa.toFe(), a) |x, y| try std.testing.expect(feEq(x, y));
        for (fa.sq().toFe(), a) |x, y| try std.testing.expect(feEq(x, y.sq()));
        for (fa.mul(fb).toFe(), a, b) |x, y, w| try std.testing.expect(feEq(x, y.mul(w)));
        // chains keep the bounds: 300 mixed steps, compared at the end
        var v = fa;
        var s = a;
        for (0..300) |k| {
            if (k % 7 == 3) {
                v = v.mul(fb);
                for (&s, b) |*x, w| x.* = x.mul(w);
            } else {
                v = v.sq();
                for (&s) |*x| x.* = x.sq();
            }
        }
        for (v.toFe(), s) |x, y| try std.testing.expect(feEq(x, y));
    }
    // maximal limbs the scalar field can hand over (2^51 + small in limb 1)
    const big: Fe = .{ .l = .{ (1 << 51) - 1, (1 << 51) + (1 << 13), (1 << 51) - 1, (1 << 51) - 1, (1 << 51) - 1 } };
    const fb4 = Fe4.fromFe(@splat(big));
    for (fb4.sq().toFe()) |x| try std.testing.expect(feEq(x, big.sq()));
    for (fb4.mul(fb4).toFe()) |x| try std.testing.expect(feEq(x, big.mul(big)));
}

test "Fe4.sqNeg and Fe4.mulSmall agree with Fe at and beyond the kernel's bounds" {
    var prng: std.Random.DefaultPrng = .init(0x7371_4e65);
    const rnd = prng.random();
    for (0..400) |round| {
        // limbs up to `top` times a carried limb: 1x (carried), 2.02x (the kernel's sum of two),
        // 3.3x (the documented limit), drawn at the very top on some rounds
        const scale: u64 = switch (round % 3) {
            0 => 100,
            1 => 202,
            else => 330,
        };
        var limbs: [4][10]u32 = undefined;
        var fes: [4]Fe = undefined;
        for (&limbs, &fes) |*l, *fe| {
            var v: u320 = 0;
            for (l, 0..) |*x, i| {
                const unit: u64 = if (i % 2 == 0) 1 << 26 else 1 << 25;
                const top = unit * scale / 100;
                x.* = @intCast(if (round % 5 == 0) top - 1 - rnd.uintLessThan(u64, 4) else rnd.uintLessThan(u64, top));
                v += @as(u320, x.*) << @intCast((51 * i + 1) / 2);
            }
            // the value mod p as an Fe
            const m255: u320 = (1 << 255) - 1;
            v = (v & m255) + 19 * (v >> 255);
            v = (v & m255) + 19 * (v >> 255);
            var b: [32]u8 = undefined;
            std.mem.writeInt(u256, &b, @intCast(v % ((1 << 255) - 19)), .little);
            fe.* = Fe.fromBytes(&b);
        }
        var f: Fe4 = undefined;
        inline for (0..10) |i| f.l[i] = .{ limbs[0][i], limbs[1][i], limbs[2][i], limbs[3][i] };
        const plain = f.sqNeg(.{ false, false, false, false }).toFe();
        const negd = f.sqNeg(.{ false, false, false, true }).toFe();
        const mixed = f.sqNeg(.{ true, false, true, false }).toFe();
        for (0..4) |j| {
            const want = fes[j].sq();
            try std.testing.expect(feEq(plain[j], want));
            try std.testing.expect(feEq(negd[j], if (j == 3) want.neg() else want));
            try std.testing.expect(feEq(mixed[j], if (j % 2 == 0) want.neg() else want));
        }
        // carried outputs: even limbs below 2^26, odd below 2^25 plus the last small carry
        const out = f.sqNeg(.{ false, true, false, true });
        inline for (0..10) |i| {
            const o: [4]u32 = out.l[i];
            for (o) |x| try std.testing.expect(x < (if (i % 2 == 0) @as(u32, 1 << 26) else (1 << 25) + (1 << 18)));
        }
        const ks = [4]u32{ 121666, 121666, 243332, 243330 };
        const sm = f.mulSmall(ks).toFe();
        for (0..4) |j| {
            var kb: [32]u8 = @splat(0);
            std.mem.writeInt(u32, kb[0..4], ks[j], .little);
            try std.testing.expect(feEq(sm[j], fes[j].mul(Fe.fromBytes(&kb))));
        }
        // mul at the kernel's operand bounds: f (up to 3.3x here) times a carried element, and
        // the widest pair the kernel forms (5.03x times 3.03x) on the top-of-range rounds
        const g = out;
        const pr = f.mul(g).toFe();
        const gf = g.toFe();
        for (0..4) |j| try std.testing.expect(feEq(pr[j], fes[j].mul(gf[j])));
    }
    // the widest operands the point kernel forms: a at 5.03x, b at 3.03x, every limb at the top
    var a: Fe4 = undefined;
    var b: Fe4 = undefined;
    inline for (0..10) |i| {
        const unit: u32 = if (i % 2 == 0) 1 << 26 else 1 << 25;
        a.l[i] = @splat(unit / 100 * 503);
        b.l[i] = @splat(unit / 100 * 303);
    }
    const af = a.toFe();
    const bf = b.toFe();
    for (a.mul(b).toFe(), af, bf) |x, y, w| try std.testing.expect(feEq(x, y.mul(w)));
}

/// The value of the columns (or of carried limbs widened to columns) mod p, lane j.
fn columnValue(h: *const [10]W, j: usize) u256 {
    const p: u512 = (1 << 255) - 19;
    var v: u512 = 0;
    for (0..10) |i| {
        const c: [4]u64 = h[i];
        v += @as(u512, c[j]) << @intCast((51 * i + 1) / 2);
    }
    return @intCast(v % p);
}

test "Fe4.carry: limbs 1 and 5 can both sit above 2^25, within the documented excess; toFe carries nothing" {
    // Columns as large as the carry chain takes (2^63: every step's sum stays below 2^64),
    // with the low bits of columns 1 and 5 all ones so the late carries land on a full limb.
    var prng: std.Random.DefaultPrng = .init(0x6361_7272);
    const rnd = prng.random();
    var seen1 = false;
    var seen5 = false;
    for (0..200) |round| {
        var cols: [10][4]u64 = undefined;
        for (&cols, 0..) |*c, i| for (c) |*x| {
            x.* = switch (round % 4) {
                0 => (1 << 63) - 1 - rnd.uintLessThan(u64, 1 << 20),
                1 => rnd.int(u64) >> 1,
                2 => rnd.int(u64) >> @intCast(1 + rnd.uintLessThan(u8, 40)),
                else => rnd.uintLessThan(u64, 1 << 26),
            };
            if (round % 4 != 3) {
                // a full 25-bit limb under the late carry: columns 0 and 4 send no first carry
                // into columns 1 and 5, whose low 25 bits are all ones
                if (i == 0 or i == 4) x.* &= (1 << 26) - 1;
                if (i == 1 or i == 5) x.* |= (1 << 25) - 1;
            }
        };
        var h: [10]W = undefined;
        for (&h, cols) |*v, c| v.* = c;
        const before = h;
        const out = Fe4.carry(&h);
        var wide_out: [10]W = undefined;
        inline for (0..10) |i| wide_out[i] = wide(out.l[i]);
        const fe = out.toFe();
        for (0..4) |j| {
            // the same value mod p, as limbs and through toFe
            try std.testing.expectEqual(columnValue(&before, j), columnValue(&wide_out, j));
            try std.testing.expectEqual(columnValue(&before, j), std.mem.readInt(u256, &fe[j].toBytes(), .little));
            inline for (0..10) |i| {
                const l: [4]u32 = out.l[i];
                const lim: u32 = switch (i) {
                    1 => (1 << 25) + (1 << 18),
                    5 => (1 << 25) + (1 << 14),
                    else => if (i % 2 == 0) 1 << 26 else 1 << 25,
                };
                try std.testing.expect(l[j] < lim);
            }
            const l1: [4]u32 = out.l[1];
            const l5: [4]u32 = out.l[5];
            seen1 = seen1 or l1[j] >= 1 << 25;
            seen5 = seen5 or l5[j] >= 1 << 25;
            // toFe: limb i is exactly l[2i] + 2^26 l[2i + 1]
            inline for (0..5) |i| {
                const lo: [4]u32 = out.l[2 * i];
                const hi: [4]u32 = out.l[2 * i + 1];
                try std.testing.expectEqual(@as(u64, lo[j]) + (@as(u64, hi[j]) << 26), fe[j].l[i]);
            }
            // so limbs 0 and 2 pass 2^51 + 2^26 when limbs 1 and 5 are above 2^25, and stay
            // below the documented bounds
            try std.testing.expect(fe[j].l[0] < (1 << 51) + (1 << 45) and fe[j].l[2] < (1 << 51) + (1 << 41));
            try std.testing.expect(fe[j].l[1] < (1 << 51) + (1 << 26) and fe[j].l[3] < (1 << 51) + (1 << 26) and fe[j].l[4] < (1 << 51) + (1 << 26));
        }
    }
    // both happened: limb 5 exceeds 2^25 as limb 1 does
    try std.testing.expect(seen1 and seen5);
    // near the largest excess: full limbs 0, 1, 4 and 5 under columns just below 2^64
    var h: [10]W = undefined;
    inline for (0..10) |i| h[i] = @splat(switch (i) {
        0, 4 => (1 << 26) - 1,
        1, 5 => (1 << 25) - 1,
        else => (1 << 64) - (1 << 40),
    });
    const top = Fe4.carry(&h);
    const t1: [4]u32 = top.l[1];
    const t5: [4]u32 = top.l[5];
    try std.testing.expect(t1[0] > (1 << 25) + (1 << 17) and t1[0] < (1 << 25) + (1 << 18));
    try std.testing.expect(t5[0] > (1 << 25) + (1 << 12) and t5[0] < (1 << 25) + (1 << 14));
    const tf = top.toFe();
    try std.testing.expect(tf[0].l[0] > (1 << 51) + (1 << 43) and tf[0].l[2] > (1 << 51) + (1 << 38));
}

test "pow2523x8 equals eight scalar exponentiations" {
    var prng: std.Random.DefaultPrng = .init(0x7032_3532);
    const rnd = prng.random();
    var x: [8]Fe = undefined;
    for (&x) |*v| {
        var b: [32]u8 = undefined;
        rnd.bytes(&b);
        b[31] &= 0x7f;
        v.* = Fe.fromBytes(&b);
    }
    const ed = @import("ed25519.zig");
    const want = ed.pow2523N(8, x);
    const got = pow2523x8(x);
    for (want, got) |a, b| try std.testing.expect(feEq(a, b));
}

fn benchOn() bool {
    return std.testing.environ.containsUnempty(std.testing.allocator, "ZUI_ED25519_MICROBENCH") catch false;
}

fn nowNs() u64 {
    return @intCast(std.Io.Timestamp.now(std.testing.io, .awake).nanoseconds);
}

// The first question for a four-way point kernel: what one vector field operation costs against
// the four scalar ones it replaces. Run with
//   ZUI_ED25519_MICROBENCH=1 ./zig build test -Dlane=sig -Doptimize=ReleaseFast [-Dcpu=x86_64_v3]
// (-Dcpu=x86_64_v3 on an x86 box: the test binary's own code is then the AVX2 code; without it
// this file is compiled for baseline x86-64 and the vector rows are SSE2). Each row is the best
// of 5 runs of a dependent chain: the scalar rows step four independent chains per iteration
// (what one point operation hands the multiplier), the vector rows one four-lane chain.
test "microbench: Fe4.mul and Fe4.sq against four Fe.mul and four Fe.sq" {
    if (!benchOn()) return;
    var prng: std.Random.DefaultPrng = .init(0x6265_6e63);
    const rnd = prng.random();
    var xs: [4]Fe = undefined;
    var ys: [4]Fe = undefined;
    for (&xs, &ys) |*x, *y| {
        var b: [32]u8 = undefined;
        rnd.bytes(&b);
        x.* = Fe.fromBytes(&b);
        rnd.bytes(&b);
        y.* = Fe.fromBytes(&b);
    }
    const n: usize = 2_000_000;
    var best: [6]u64 = @splat(std.math.maxInt(u64));
    var sink: u64 = 0;
    for (0..5) |_| {
        var s = xs;
        var t0 = nowNs();
        for (0..n) |_| {
            inline for (0..4) |j| s[j] = s[j].mul(ys[j]);
        }
        best[0] = @min(best[0], nowNs() - t0);
        sink +%= s[0].l[0];
        t0 = nowNs();
        for (0..n) |_| {
            inline for (0..4) |j| s[j] = s[j].sq();
        }
        best[1] = @min(best[1], nowNs() - t0);
        sink +%= s[1].l[0];
        var v = Fe4.fromFe(xs);
        const w = Fe4.fromFe(ys);
        std.mem.doNotOptimizeAway(&w);
        t0 = nowNs();
        for (0..n) |_| v = v.mul(w);
        best[2] = @min(best[2], nowNs() - t0);
        sink +%= @as([4]u32, v.l[0])[0];
        t0 = nowNs();
        for (0..n) |_| v = v.sq();
        best[3] = @min(best[3], nowNs() - t0);
        sink +%= @as([4]u32, v.l[0])[0];
        // one scalar chain alone (latency of a single multiply)
        var one = xs[0];
        t0 = nowNs();
        for (0..n) |_| one = one.mul(ys[0]);
        best[4] = @min(best[4], nowNs() - t0);
        sink +%= one.l[0];
        t0 = nowNs();
        for (0..n) |_| one = one.sq();
        best[5] = @min(best[5], nowNs() - t0);
        sink +%= one.l[0];
    }
    std.mem.doNotOptimizeAway(&sink);
    const f = struct {
        fn ns(t: u64, k: usize) f64 {
            return @as(f64, @floatFromInt(t)) / @as(f64, @floatFromInt(k));
        }
    };
    std.debug.print("ed25519 field microbench ({s}, {s}):\n", .{ @tagName(@import("builtin").cpu.arch), @tagName(@import("builtin").mode) });
    std.debug.print("  4 x Fe.mul (four chains)   {d:>7.2} ns\n", .{f.ns(best[0], n)});
    std.debug.print("  4 x Fe.sq  (four chains)   {d:>7.2} ns\n", .{f.ns(best[1], n)});
    std.debug.print("  Fe4.mul    (one chain)     {d:>7.2} ns   = {d:.2} scalar multiplies\n", .{ f.ns(best[2], n), 4.0 * f.ns(best[2], n) / f.ns(best[0], n) });
    std.debug.print("  Fe4.sq     (one chain)     {d:>7.2} ns   = {d:.2} scalar squarings\n", .{ f.ns(best[3], n), 4.0 * f.ns(best[3], n) / f.ns(best[1], n) });
    std.debug.print("  1 x Fe.mul (one chain)     {d:>7.2} ns\n", .{f.ns(best[4], n)});
    std.debug.print("  1 x Fe.sq  (one chain)     {d:>7.2} ns\n", .{f.ns(best[5], n)});
}
