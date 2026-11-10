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
//! 26/25 bits (limb 1 may exceed by a small carry). `fromFe` takes `Fe` limbs below 2^51 + 2^13,
//! which is what `Fe.mul`/`Fe.sq` return. Constant time (no branches, no data-dependent indices).
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

    /// Lane j as an `Fe` (limbs below 2^51 + 2^26).
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

    /// ref10's two interleaved carry chains (0,4), (1,5), ... then 9 -> 0 and 0 -> 1.
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
