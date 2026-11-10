//! RFC 9380 hashing to BLS12-381 G1 and G2 (suites BLS12381G1_XMD:SHA-256_SSWU_RO_/NU_ and
//! BLS12381G2_XMD:SHA-256_SSWU_RO_/NU_), the same maps blst's hash_to_g1/hash_to_g2 compute.
//!
//! G1 (the min-sig signature hot path) works without inversions: simplified SWU in the
//! straight-line form of RFC 9380 F.2 with sqrt_ratio for q = 3 mod 4 returns a Jacobian point,
//! the 11-isogeny is evaluated on Jacobian coordinates (blst's isogeny_map_to_E1 layout), and the
//! cofactor is cleared with [1 - z] by an add/double chain. G2 hashing is off the hot path and
//! uses affine SWU with one inversion and one Fp2 square root per map.
const std = @import("std");
const Sha256 = @import("hash").Sha256;
const curve = @import("curve.zig");
const consts = @import("consts.zig");
const Fp = curve.Fp;
const Fp2 = curve.Fp2;
const G1 = curve.G1;
const G2 = curve.G2;

pub const max_expand_len = 256; // enough for 2 Fp2 elements (4 * 64 bytes)

/// expand_message_xmd with SHA-256 (RFC 9380 5.3.1), oversize DSTs hashed per 5.3.3.
pub fn expandMessageXmd(out: []u8, msg: []const u8, dst_in: []const u8) void {
    std.debug.assert(out.len <= 255 * 32 and out.len <= 65535);
    var dst_buf: [32]u8 = undefined;
    var dst = dst_in;
    if (dst.len > 255) {
        var h = Sha256.init();
        h.update("H2C-OVERSIZE-DST-");
        h.update(dst);
        h.final(&dst_buf);
        dst = &dst_buf;
    }
    const ell = (out.len + 31) / 32;
    const dst_len = [1]u8{@intCast(dst.len)};
    const l_i_b = [2]u8{ @intCast(out.len >> 8), @intCast(out.len & 0xff) };
    var h0 = Sha256.init();
    const zpad: [64]u8 = @splat(0);
    h0.update(&zpad);
    h0.update(msg);
    h0.update(&l_i_b);
    h0.update(&[1]u8{0});
    h0.update(dst);
    h0.update(&dst_len);
    var b0: [32]u8 = undefined;
    h0.final(&b0);
    var bi: [32]u8 = undefined;
    var h1 = Sha256.init();
    h1.update(&b0);
    h1.update(&[1]u8{1});
    h1.update(dst);
    h1.update(&dst_len);
    h1.final(&bi);
    var off: usize = 0;
    var i: usize = 1;
    while (true) : (i += 1) {
        const n = @min(32, out.len - off);
        @memcpy(out[off..][0..n], bi[0..n]);
        off += n;
        if (i == ell) break;
        var x: [32]u8 = undefined;
        for (&x, b0, bi) |*o, a, c| o.* = a ^ c;
        var h = Sha256.init();
        h.update(&x);
        h.update(&[1]u8{@intCast(i + 1)});
        h.update(dst);
        h.update(&dst_len);
        h.final(&bi);
    }
}

/// (2^256 * R^2) mod p as raw limbs: mulRawBy(hi, K) = hi * 2^256 in Montgomery form.
const k_2_256 = Fp.rawTimesR2(@as(u384, @intCast((@as(u768, 1) << 256) % consts.p)));
const k_1 = Fp.rawTimesR2(1);

/// OS2IP(64 bytes) mod p, in Montgomery form.
pub fn fpFrom64(b: *const [64]u8) Fp {
    var hi: [6]u64 = @splat(0);
    var lo: [6]u64 = @splat(0);
    for (0..4) |i| {
        hi[i] = std.mem.readInt(u64, b[32 - 8 * (i + 1) ..][0..8], .big);
        lo[i] = std.mem.readInt(u64, b[64 - 8 * (i + 1) ..][0..8], .big);
    }
    return Fp.mulRawBy(hi, k_2_256).add(Fp.mulRawBy(lo, k_1));
}

pub fn hashToFieldFp(comptime count: usize, msg: []const u8, dst: []const u8) [count]Fp {
    var buf: [64 * count]u8 = undefined;
    expandMessageXmd(&buf, msg, dst);
    var out: [count]Fp = undefined;
    for (0..count) |i| out[i] = fpFrom64(buf[64 * i ..][0..64]);
    return out;
}

pub fn hashToFieldFp2(comptime count: usize, msg: []const u8, dst: []const u8) [count]Fp2 {
    var buf: [128 * count]u8 = undefined;
    expandMessageXmd(&buf, msg, dst);
    var out: [count]Fp2 = undefined;
    for (0..count) |i| out[i] = .{ .c0 = fpFrom64(buf[128 * i ..][0..64]), .c1 = fpFrom64(buf[128 * i + 64 ..][0..64]) };
    return out;
}

// ---------------------------------------------------------------------------------------------
// G1

const a1 = Fp.fromInt(consts.sswu1_a);
const b1 = Fp.fromInt(consts.sswu1_b);
const z1 = Fp.fromInt(consts.sswu1_z);
const c2_1 = Fp.fromInt(consts.sswu1_c2);
const p_minus_3_div_4 = blk: {
    const v = (consts.p - 3) / 4;
    var out: [6]u64 = undefined;
    for (0..6) |i| out[i] = @truncate(v >> @intCast(64 * i));
    break :blk out;
};

/// Simplified SWU onto E1' (RFC 9380 F.2, sqrt_ratio for q = 3 mod 4), Jacobian result.
pub fn sswuG1(u: Fp) G1.Point {
    const tv1 = z1.mul(u.sqr());
    var tv2 = tv1.sqr().add(tv1);
    const tv3 = b1.mul(tv2.add(Fp.one));
    const tv4 = a1.mul(Fp.select(tv2.isZero(), z1, tv2.neg()));
    tv2 = tv3.sqr();
    var tv6 = tv4.sqr();
    var tv5 = a1.mul(tv6);
    tv2 = tv2.add(tv5).mul(tv3);
    tv6 = tv6.mul(tv4);
    tv5 = b1.mul(tv6);
    tv2 = tv2.add(tv5); // gx numerator, tv6 = denominator
    var x = tv1.mul(tv3);
    // sqrt_ratio(tv2, tv6)
    const s_tv1 = tv6.sqr();
    const s_tv2 = tv2.mul(tv6);
    const y1_0 = s_tv1.mul(s_tv2).powLimbs(p_minus_3_div_4).mul(s_tv2);
    const y2_0 = y1_0.mul(c2_1);
    const is_qr = y1_0.sqr().mul(tv6).eql(tv2);
    const y1 = Fp.select(is_qr, y1_0, y2_0);
    var y = tv1.mul(u).mul(y1);
    x = Fp.select(is_qr, tv3, x);
    y = Fp.select(is_qr, y1, y);
    y = y.condNeg(u.sgn0() != y.sgn0());
    // (x / tv4, y) in Jacobian: X = x * tv4, Y = y * tv4^3, Z = tv4
    return .{ .x = x.mul(tv4), .y = y.mul(tv4.sqr().mul(tv4)), .z = tv4 };
}

const iso1_xn = mkFp(consts.iso1_x_num);
const iso1_xd = mkFp(consts.iso1_x_den);
const iso1_yn = mkFp(consts.iso1_y_num);
const iso1_yd = mkFp(consts.iso1_y_den);

fn mkFp(comptime v: anytype) [v.len]Fp {
    var out: [v.len]Fp = undefined;
    inline for (v, 0..) |x, i| out[i] = comptime Fp.fromInt(x);
    return out;
}

fn mkFp2(comptime v: anytype) [v.len]Fp2 {
    var out: [v.len]Fp2 = undefined;
    inline for (v, 0..) |x, i| out[i] = comptime Fp2.fromInts(x);
    return out;
}

/// sum_i k[i] * X^i * Z2^(deg - i) for Jacobian X and Z2 = Z^2 powers (zz[j] = Z^(2j)),
/// with an implicit leading coefficient 1 at degree k.len when `monic`.
fn isoPoly(comptime F: type, k: []const F, x: F, zz: []const F, comptime monic: bool) F {
    const deg = if (monic) k.len else k.len - 1;
    var acc = if (monic) x.add(k[k.len - 1].mul(zz[1])) else k[k.len - 1].mul(x).add(k[k.len - 2].mul(zz[1]));
    const start = if (monic) k.len - 1 else k.len - 2;
    var i = start;
    while (i > 0) {
        i -= 1;
        acc = acc.mul(x).add(k[i].mul(zz[deg - i]));
    }
    return acc;
}

/// The 11-isogeny E1' -> E1 on Jacobian coordinates (blst isogeny_map_to_E1).
pub fn isoMapG1(p: G1.Point) G1.Point {
    var zz: [16]Fp = undefined; // zz[j] = Z^(2j)
    zz[0] = Fp.one;
    zz[1] = p.z.sqr();
    for (2..16) |j| zz[j] = zz[j - 1].mul(zz[1]);
    const xn = isoPoly(Fp, &iso1_xn, p.x, &zz, false); // degree 11
    const xd = isoPoly(Fp, &iso1_xd, p.x, &zz, true).mul(zz[1]); // degree 10, times Z^2
    const yn = isoPoly(Fp, &iso1_yn, p.x, &zz, false).mul(p.y); // degree 15, times Y
    const yd = isoPoly(Fp, &iso1_yd, p.x, &zz, true).mul(zz[1].mul(p.z)); // degree 15, times Z^3
    const z = xd.mul(yd);
    const x = xn.mul(yd).mul(z);
    const y = z.sqr().mul(xd).mul(yn);
    return .{ .x = x, .y = y, .z = z };
}

/// map_to_curve + clear_cofactor for one or two field elements (blst map_to_g1).
pub fn mapToG1(u: []const Fp) G1.Point {
    var p = isoMapG1(sswuG1(u[0]));
    if (u.len > 1) p = p.add(isoMapG1(sswuG1(u[1])));
    // clear the cofactor: [1 - z]P = [-z]P + P
    return p.timesMinusZ().add(p);
}

pub fn hashToG1(msg: []const u8, dst: []const u8) G1.Point {
    const u = hashToFieldFp(2, msg, dst);
    return mapToG1(&u);
}

pub fn encodeToG1(msg: []const u8, dst: []const u8) G1.Point {
    const u = hashToFieldFp(1, msg, dst);
    return mapToG1(&u);
}

// ---------------------------------------------------------------------------------------------
// G2

const a2 = Fp2.fromInts(consts.sswu2_a);
const b2 = Fp2.fromInts(consts.sswu2_b);
const z2 = Fp2.fromInts(consts.sswu2_z);
const iso2_xn = mkFp2(consts.iso2_x_num);
const iso2_xd = mkFp2(consts.iso2_x_den);
const iso2_yn = mkFp2(consts.iso2_y_num);
const iso2_yd = mkFp2(consts.iso2_y_den);

/// -b / a = (253 / 60)(-1 + u) for a = 240 u, b = 1012 (1 + u).
const neg_b_over_a2: Fp2 = blk: {
    const p: u512 = consts.p;
    var k: u512 = 0;
    while ((k * p + 1) % 60 != 0) k += 1;
    const c: u384 = @intCast((253 * ((k * p + 1) / 60)) % p);
    break :blk Fp2.fromInts(.{ consts.p - c, c });
};

/// Simplified SWU onto E2' (RFC 9380 6.6.2, plain form), affine result.
pub fn sswuG2(u: Fp2) G2.Affine {
    const zu2 = z2.mul(u.sqr());
    const tv = zu2.sqr().add(zu2);
    return sswuG2Finish(u, zu2, if (tv.isZero()) Fp2.zero else tv.invVartime());
}

/// The rest of `sswuG2` given zu2 = Z u^2 and tv_inv = 1 / (zu2^2 + zu2) (zero when that is
/// zero), so callers can batch the inversions.
fn sswuG2Finish(u: Fp2, zu2: Fp2, tv_inv: Fp2) G2.Affine {
    const x1 = if (tv_inv.isZero())
        b2.mul(z2.mul(a2).invVartime())
    else
        neg_b_over_a2.mul(Fp2.one.add(tv_inv));
    const gx1 = x1.sqr().add(a2).mul(x1).add(b2);
    var x: Fp2 = undefined;
    var y: Fp2 = undefined;
    if (gx1.sqrt()) |s| {
        x = x1;
        y = s;
    } else {
        x = zu2.mul(x1);
        const gx2 = x.sqr().add(a2).mul(x).add(b2);
        y = gx2.sqrt().?; // gx2 = Z^3 u^6 gx1 is a square when gx1 is not
    }
    y = y.condNeg(u.sgn0() != y.sgn0());
    return .{ .x = x, .y = y };
}

/// Inverts every nonzero element of `v` in place with one inversion (Montgomery's trick);
/// zeros stay zero. Public data.
fn batchInvFp2(comptime n: usize, v: *[n]Fp2) void {
    var pre: [n]Fp2 = undefined;
    var acc = Fp2.one;
    for (v, &pre) |x, *q| {
        q.* = acc;
        if (!x.isZero()) acc = acc.mul(x);
    }
    var inv = acc.invVartime();
    var i: usize = n;
    while (i > 0) {
        i -= 1;
        if (v[i].isZero()) continue;
        const x = v[i];
        v[i] = inv.mul(pre[i]);
        inv = inv.mul(x);
    }
}

fn polyAffine(k: []const Fp2, x: Fp2, comptime monic: bool) Fp2 {
    var acc = if (monic) Fp2.one else Fp2.zero;
    var i = k.len;
    while (i > 0) {
        i -= 1;
        acc = acc.mul(x).add(k[i]);
    }
    return acc;
}

pub fn isoMapG2(p: G2.Affine) G2.Affine {
    const xn = polyAffine(&iso2_xn, p.x, false);
    const xd = polyAffine(&iso2_xd, p.x, true);
    const yn = polyAffine(&iso2_yn, p.x, false);
    const yd = polyAffine(&iso2_yd, p.x, true);
    // the exceptional case xd = 0 or yd = 0 maps to infinity (RFC 9380 6.6.3)
    if (xd.isZero() or yd.isZero()) return G2.Affine.infinity;
    return .{ .x = xn.mul(xd.invVartime()), .y = p.y.mul(yn).mul(yd.invVartime()) };
}

/// Budroni-Pintore cofactor clearing (blst clear_cofactor for G2).
pub fn clearCofactorG2(p: G2.Point) G2.Point {
    var out = curve.psi(curve.psi(p.dbl())); // psi^2(2P)
    var t0 = p.neg(); // -P
    var t1 = curve.psi(t0); // -psi(P)
    out = out.add(t0).add(t1);
    t0 = p.timesMinusZ().add(p).add(t1); // [-z + 1]P - psi(P)
    t1 = t0.timesMinusZ(); // [z^2 - z]P + [z]psi(P)
    return out.add(t1);
}

pub fn mapToG2(u: []const Fp2) G2.Point {
    if (u.len != 2) {
        var p = isoMapG2(sswuG2(u[0])).toJacobian();
        if (u.len > 1) p = p.add(isoMapG2(sswuG2(u[1])).toJacobian());
        return clearCofactorG2(p);
    }
    // Both maps with two inversions in all instead of eight: one for the two SSWU
    // denominators, one for the four isogeny denominators.
    var zu2: [2]Fp2 = undefined;
    var inv: [2]Fp2 = undefined;
    for (0..2) |k| {
        zu2[k] = z2.mul(u[k].sqr());
        inv[k] = zu2[k].sqr().add(zu2[k]);
    }
    batchInvFp2(2, &inv);
    var q: [2]G2.Affine = undefined;
    for (0..2) |k| q[k] = sswuG2Finish(u[k], zu2[k], inv[k]);
    var num: [4]Fp2 = undefined;
    var den: [4]Fp2 = undefined;
    for (0..2) |k| {
        num[2 * k] = polyAffine(&iso2_xn, q[k].x, false);
        den[2 * k] = polyAffine(&iso2_xd, q[k].x, true);
        num[2 * k + 1] = polyAffine(&iso2_yn, q[k].x, false);
        den[2 * k + 1] = polyAffine(&iso2_yd, q[k].x, true);
    }
    batchInvFp2(4, &den);
    var p: [2]G2.Point = undefined;
    for (0..2) |k| {
        // the exceptional case xd = 0 or yd = 0 maps to infinity (RFC 9380 6.6.3)
        p[k] = if (den[2 * k].isZero() or den[2 * k + 1].isZero())
            G2.Point.infinity
        else
            (G2.Affine{ .x = num[2 * k].mul(den[2 * k]), .y = q[k].y.mul(num[2 * k + 1]).mul(den[2 * k + 1]) }).toJacobian();
    }
    return clearCofactorG2(p[0].add(p[1]));
}

pub fn hashToG2(msg: []const u8, dst: []const u8) G2.Point {
    const u = hashToFieldFp2(2, msg, dst);
    return mapToG2(&u);
}

pub fn encodeToG2(msg: []const u8, dst: []const u8) G2.Point {
    const u = hashToFieldFp2(1, msg, dst);
    return mapToG2(&u);
}

test "expand_message_xmd RFC 9380 K.1 (first vector)" {
    var out: [32]u8 = undefined;
    expandMessageXmd(&out, "", "QUUX-V01-CS02-with-expander-SHA256-128");
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235");
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "hash_to_G1 RFC 9380 J.9.1 msg=\"\"" {
    const p = hashToG1("", "QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_").toAffine();
    try std.testing.expectEqual(@as(u384, 0x052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1), p.x.toInt());
    try std.testing.expectEqual(@as(u384, 0x08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265), p.y.toInt());
}
