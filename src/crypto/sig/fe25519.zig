//! GF(2^255 - 19) in radix 2^51 (five u64 limbs), the curve25519-dalek 4.1 u64 backend shape.
//!
//! Limb bounds (dalek's): a reduced element has limbs < 2^(51 + epsilon). `add` does not reduce,
//! so a sum of two reduced elements has limbs < 2^52.01; `mul` and `sq` accept limbs < 2^54
//! and return reduced limbs. `sub` and `neg` add 16p before subtracting (right side < 2^54) and
//! weakly reduce. All products are 64 x 64 -> 128: the factors of 19 are applied in u64 before
//! the multiply (std's field widens them to u128 first, which costs an extra multiply per term).
//!
//! Every function here is constant time except `isZero`/`isNegative`/`eql`, which branch on
//! nothing but return data-dependent booleans (callers on secret data use `cMov`).
const std = @import("std");

pub const Fe = struct {
    l: [5]u64,

    pub const mask51: u64 = (1 << 51) - 1;

    pub const zero: Fe = .{ .l = .{ 0, 0, 0, 0, 0 } };
    pub const one: Fe = .{ .l = .{ 1, 0, 0, 0, 0 } };
    /// sqrt(-1)
    pub const sqrtm1: Fe = .{ .l = .{ 1718705420411056, 234908883556509, 2233514472574048, 2117202627021982, 765476049583133 } };
    /// d = -121665/121666
    pub const d: Fe = .{ .l = .{ 929955233495203, 466365720129213, 1662059464998953, 2033849074728123, 1442794654840575 } };
    /// 2d
    pub const d2: Fe = .{ .l = .{ 1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903 } };

    fn m(x: u64, y: u64) u128 {
        return @as(u128, x) * @as(u128, y);
    }

    pub inline fn add(a: Fe, b: Fe) Fe {
        return .{ .l = .{ a.l[0] + b.l[0], a.l[1] + b.l[1], a.l[2] + b.l[2], a.l[3] + b.l[3], a.l[4] + b.l[4] } };
    }

    inline fn weakReduce(x: [5]u64) Fe {
        const c0 = x[0] >> 51;
        const c1 = x[1] >> 51;
        const c2 = x[2] >> 51;
        const c3 = x[3] >> 51;
        const c4 = x[4] >> 51;
        return .{ .l = .{
            (x[0] & mask51) + c4 * 19,
            (x[1] & mask51) + c0,
            (x[2] & mask51) + c1,
            (x[3] & mask51) + c2,
            (x[4] & mask51) + c3,
        } };
    }

    const p16_0: u64 = 36028797018963664; // 16 * (2^51 - 19)
    const p16_i: u64 = 36028797018963952; // 16 * (2^51 - 1)

    pub inline fn sub(a: Fe, b: Fe) Fe {
        return weakReduce(.{
            (a.l[0] + p16_0) - b.l[0],
            (a.l[1] + p16_i) - b.l[1],
            (a.l[2] + p16_i) - b.l[2],
            (a.l[3] + p16_i) - b.l[3],
            (a.l[4] + p16_i) - b.l[4],
        });
    }

    pub inline fn neg(a: Fe) Fe {
        return weakReduce(.{ p16_0 - a.l[0], p16_i - a.l[1], p16_i - a.l[2], p16_i - a.l[3], p16_i - a.l[4] });
    }

    inline fn carry(c0: u128, c1_in: u128, c2_in: u128, c3_in: u128, c4_in: u128) Fe {
        var c1 = c1_in;
        var c2 = c2_in;
        var c3 = c3_in;
        var c4 = c4_in;
        var o: [5]u64 = undefined;
        c1 += @as(u64, @truncate(c0 >> 51));
        o[0] = @as(u64, @truncate(c0)) & mask51;
        c2 += @as(u64, @truncate(c1 >> 51));
        o[1] = @as(u64, @truncate(c1)) & mask51;
        c3 += @as(u64, @truncate(c2 >> 51));
        o[2] = @as(u64, @truncate(c2)) & mask51;
        c4 += @as(u64, @truncate(c3 >> 51));
        o[3] = @as(u64, @truncate(c3)) & mask51;
        const cy: u64 = @truncate(c4 >> 51);
        o[4] = @as(u64, @truncate(c4)) & mask51;
        o[0] += cy * 19;
        o[1] += o[0] >> 51;
        o[0] &= mask51;
        return .{ .l = o };
    }

    pub inline fn mul(x: Fe, y: Fe) Fe {
        const a = x.l;
        const b = y.l;
        const b1_19 = b[1] * 19;
        const b2_19 = b[2] * 19;
        const b3_19 = b[3] * 19;
        const b4_19 = b[4] * 19;
        const c0 = m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19);
        const c1 = m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19);
        const c2 = m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19);
        const c3 = m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19);
        const c4 = m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]);
        return carry(c0, c1, c2, c3, c4);
    }

    pub inline fn sq(x: Fe) Fe {
        const a = x.l;
        const a3_19 = 19 * a[3];
        const a4_19 = 19 * a[4];
        const a0_2 = 2 * a[0];
        const a1_2 = 2 * a[1];
        const a2_2 = 2 * a[2];
        const c0 = m(a[0], a[0]) + m(a1_2, a4_19) + m(a2_2, a3_19);
        const c1 = m(a[3], a3_19) + m(a0_2, a[1]) + m(a2_2, a4_19);
        const c2 = m(a[1], a[1]) + m(a0_2, a[2]) + m(a[4], 2 * a3_19);
        const c3 = m(a[4], a4_19) + m(a0_2, a[3]) + m(a1_2, a[2]);
        const c4 = m(a[2], a[2]) + m(a0_2, a[4]) + m(a1_2, a[3]);
        return carry(c0, c1, c2, c3, c4);
    }

    /// 2 * x^2
    pub inline fn sq2(x: Fe) Fe {
        const s = sq(x);
        return s.add(s);
    }

    pub fn sqn(x: Fe, n: usize) Fe {
        var r = x;
        var i: usize = 0;
        while (i < n) : (i += 1) r = r.sq();
        return r;
    }

    /// Multiply by a small constant (< 2^13).
    pub inline fn mulSmall(x: Fe, comptime k: u64) Fe {
        const c0 = m(x.l[0], k);
        const c1 = m(x.l[1], k);
        const c2 = m(x.l[2], k);
        const c3 = m(x.l[3], k);
        const c4 = m(x.l[4], k);
        return carry(c0, c1, c2, c3, c4);
    }

    /// Low 255 bits of `s` (bit 255 ignored), as dalek's from_bytes. Values >= p are kept as is.
    pub fn fromBytes(s: *const [32]u8) Fe {
        const r0 = std.mem.readInt(u64, s[0..8], .little);
        const r1 = std.mem.readInt(u64, s[8..16], .little);
        const r2 = std.mem.readInt(u64, s[16..24], .little);
        const r3 = std.mem.readInt(u64, s[24..32], .little);
        return .{ .l = .{
            r0 & mask51,
            ((r0 >> 51) | (r1 << 13)) & mask51,
            ((r1 >> 38) | (r2 << 26)) & mask51,
            ((r2 >> 25) | (r3 << 39)) & mask51,
            (r3 >> 12) & mask51,
        } };
    }

    /// Canonical little-endian encoding (fully reduced mod p).
    pub fn toBytes(x: Fe) [32]u8 {
        var l = weakReduce(x.l).l;
        // q = 1 iff value >= p: computed by adding 19 and looking at bit 255.
        var q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= mask51;
        l[2] += l[1] >> 51;
        l[1] &= mask51;
        l[3] += l[2] >> 51;
        l[2] &= mask51;
        l[4] += l[3] >> 51;
        l[3] &= mask51;
        l[4] &= mask51;
        var out: [32]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], l[0] | (l[1] << 51), .little);
        std.mem.writeInt(u64, out[8..16], (l[1] >> 13) | (l[2] << 38), .little);
        std.mem.writeInt(u64, out[16..24], (l[2] >> 26) | (l[3] << 25), .little);
        std.mem.writeInt(u64, out[24..32], (l[3] >> 39) | (l[4] << 12), .little);
        return out;
    }

    pub fn isZero(x: Fe) bool {
        const b = x.toBytes();
        var acc: u8 = 0;
        for (b) |v| acc |= v;
        return acc == 0;
    }

    pub fn isNegative(x: Fe) bool {
        return (x.toBytes()[0] & 1) != 0;
    }

    pub fn eql(a: Fe, b: Fe) bool {
        return a.sub(b).isZero();
    }

    /// Constant-time: x = c ? a : x.
    pub inline fn cMov(x: *Fe, a: Fe, c: bool) void {
        const msk: u64 = 0 -% @as(u64, @intFromBool(c));
        inline for (0..5) |i| x.l[i] ^= (x.l[i] ^ a.l[i]) & msk;
    }

    /// x^(2^252 - 3), dalek's pow22501 chain.
    pub fn pow2523(x: Fe) Fe {
        const p = pow22501(x);
        return p.t19.sqn(2).mul(x);
    }

    /// (x^(2^250 - 1), x^11), the shared prefix of inversion and pow2523 (dalek).
    fn pow22501(x: Fe) struct { t19: Fe, t3: Fe } {
        const t0 = x.sq();
        const t1 = t0.sq().sq();
        const t2 = x.mul(t1);
        const t3 = t0.mul(t2);
        const t4 = t3.sq();
        const t5 = t2.mul(t4);
        const t6 = t5.sqn(5);
        const t7 = t6.mul(t5);
        const t8 = t7.sqn(10);
        const t9 = t8.mul(t7);
        const t10 = t9.sqn(20);
        const t11 = t10.mul(t9);
        const t12 = t11.sqn(10);
        const t13 = t12.mul(t7);
        const t14 = t13.sqn(50);
        const t15 = t14.mul(t13);
        const t16 = t15.sqn(100);
        const t17 = t16.mul(t15);
        const t18 = t17.sqn(50);
        const t19 = t18.mul(t13);
        return .{ .t19 = t19, .t3 = t3 };
    }

    /// x^(p - 2) (0 for 0).
    pub fn invert(x: Fe) Fe {
        const p = pow22501(x);
        return p.t19.sqn(5).mul(p.t3);
    }

    /// dalek `sqrt_ratio_i(u, v)`: (u/v is square, nonnegative r) with r^2 = u/v when square,
    /// r^2 = i*u/v when not.
    pub fn sqrtRatioI(u: Fe, v: Fe) struct { ok: bool, r: Fe } {
        const v3 = v.sq().mul(v);
        const v7 = v3.sq().mul(v);
        var r = u.mul(v3).mul(u.mul(v7).pow2523());
        const check = v.mul(r.sq());
        const neg_u = u.neg();
        const correct = check.eql(u);
        const flipped = check.eql(neg_u);
        const flipped_i = check.eql(neg_u.mul(sqrtm1));
        r.cMov(r.mul(sqrtm1), flipped or flipped_i);
        r.cMov(r.neg(), r.isNegative());
        return .{ .ok = correct or flipped, .r = r };
    }
};

const testing = std.testing;
const StdFe = std.crypto.ecc.Edwards25519.Fe;

fn fromStd(x: StdFe) Fe {
    return Fe.fromBytes(&x.toBytes());
}

test "fe25519 agrees with std on random elements" {
    var prng: std.Random.DefaultPrng = .init(25519);
    const rnd = prng.random();
    for (0..2000) |_| {
        var ab: [32]u8 = undefined;
        var bb: [32]u8 = undefined;
        rnd.bytes(&ab);
        rnd.bytes(&bb);
        ab[31] &= 0x7f;
        bb[31] &= 0x7f;
        const sa = StdFe.fromBytes(ab);
        const sb = StdFe.fromBytes(bb);
        const a = Fe.fromBytes(&ab);
        const b = Fe.fromBytes(&bb);
        try testing.expectEqual(sa.toBytes(), a.toBytes());
        try testing.expectEqual(sa.mul(sb).toBytes(), a.mul(b).toBytes());
        try testing.expectEqual(sa.sq().toBytes(), a.sq().toBytes());
        try testing.expectEqual(sa.sub(sb).toBytes(), a.sub(b).toBytes());
        try testing.expectEqual(sa.add(sb).mul(sa).toBytes(), a.add(b).mul(a).toBytes());
        try testing.expectEqual(sa.neg().toBytes(), a.neg().toBytes());
        try testing.expectEqual(sa.invert().toBytes(), a.invert().toBytes());
        try testing.expectEqual(sa.pow2523().toBytes(), a.pow2523().toBytes());
        try testing.expectEqual(sa.sq2().toBytes(), a.sq2().toBytes());
        // unreduced inputs: sums of sums
        const s4 = a.add(b).add(a).add(b);
        try testing.expectEqual(sa.add(sb).add(sa).add(sb).sq().toBytes(), s4.sq().toBytes());
    }
    _ = fromStd;
}

test "fe25519 canonical encoding edges" {
    // p, p + 1, 2^255 - 1 reduce like dalek (fromBytes keeps 255 bits, toBytes reduces).
    var pb: [32]u8 = @splat(0xff);
    pb[0] = 0xed;
    pb[31] = 0x7f;
    try testing.expect(Fe.fromBytes(&pb).isZero());
    var all: [32]u8 = @splat(0xff);
    all[31] = 0x7f;
    const r = Fe.fromBytes(&all).toBytes();
    var expect: [32]u8 = @splat(0);
    expect[0] = 18;
    try testing.expectEqual(expect, r);
}
