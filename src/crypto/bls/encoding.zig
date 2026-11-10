//! Point encodings exactly as blst 0.3.16 reads and writes them (ZCash format):
//!   compressed:   x big-endian with flags in the top 3 bits of byte 0:
//!                 0x80 compressed, 0x40 infinity, 0x20 y is the lexicographically larger root
//!   uncompressed: x || y big-endian (flags: 0x40 infinity only)
//! Fp2 coordinates are written c1 then c0.
//!
//! Decode results reproduce blst's acceptance rules bit for bit, including its quirks:
//!   - the top 3 bits of x are masked off before the range check;
//!   - infinity needs every other bit zero;
//!   - a G1 point with x = 0, on the curve as (0, +-2), is rejected as not in the group by the
//!     decoder itself (blst does this for G1 only).
//! No subgroup check is done here (blst's uncompress/deserialize do not do one either).
const std = @import("std");
const curve = @import("curve.zig");
const Fp = curve.Fp;
const Fp2 = curve.Fp2;
const G1 = curve.G1;
const G2 = curve.G2;

/// Mirror of the BLST_ERROR values a decoder can return.
pub const Error = enum { bad_encoding, point_not_on_curve, point_not_in_group };

pub fn Result(comptime T: type) type {
    return union(enum) { ok: T, err: Error };
}

fn bytesZero(b: []const u8) bool {
    var acc: u8 = 0;
    for (b) |x| acc |= x;
    return acc == 0;
}

/// Reads 48 big-endian bytes with the top 3 bits cleared; null when >= p.
fn fpMasked(b: *const [48]u8) ?Fp {
    var t = b.*;
    t[0] &= 0x1f;
    return Fp.fromBytesBE(&t);
}

// ---------------------------------------------------------------------------------------------
// G1

pub fn g1Uncompress(in: *const [48]u8) Result(G1.Affine) {
    const in0 = in[0];
    if (in0 & 0x80 == 0) return .{ .err = .bad_encoding };
    if (in0 & 0x40 != 0) {
        if (in0 & 0x3f == 0 and bytesZero(in[1..])) return .{ .ok = G1.Affine.infinity };
        return .{ .err = .bad_encoding };
    }
    const x = fpMasked(in) orelse return .{ .err = .bad_encoding };
    const y2 = x.sqr().mul(x).add(G1.b);
    var y = sqrtFp(y2) orelse return .{ .err = .point_not_on_curve };
    const want_large = in0 & 0x20 != 0;
    y = y.condNeg(y.isLexLargest() != want_large);
    if (x.isZero()) return .{ .err = .point_not_in_group };
    return .{ .ok = .{ .x = x, .y = y } };
}

pub fn g1Deserialize96(in: *const [96]u8) Result(G1.Affine) {
    const in0 = in[0];
    if (in0 & 0xe0 == 0) {
        const x = fpMasked(in[0..48]) orelse return .{ .err = .bad_encoding };
        const y = Fp.fromBytesBE(in[48..96]) orelse return .{ .err = .bad_encoding };
        const a: G1.Affine = .{ .x = x, .y = y };
        if (!a.onCurve()) return .{ .err = .point_not_on_curve };
        if (x.isZero()) return .{ .err = .point_not_in_group };
        return .{ .ok = a };
    }
    if (in0 & 0x80 != 0) return g1Uncompress(in[0..48]);
    if (in0 & 0x40 != 0) {
        if (in0 & 0x3f == 0 and bytesZero(in[1..])) return .{ .ok = G1.Affine.infinity };
    }
    return .{ .err = .bad_encoding };
}

/// blst `Signature::from_bytes` (min-sig) / `PublicKey::from_bytes` (min-pk): 48 bytes with the
/// compression bit, or 96 bytes without it.
pub fn g1FromBytes(in: []const u8) Result(G1.Affine) {
    if (in.len == 96 and in[0] & 0x80 == 0) return g1Deserialize96(in[0..96]);
    if (in.len == 48 and in[0] & 0x80 != 0) return g1Uncompress(in[0..48]);
    return .{ .err = .bad_encoding };
}

pub fn g1Compress(a: G1.Affine) [48]u8 {
    var out: [48]u8 = @splat(0);
    if (a.isInfinity()) {
        out[0] = 0xc0;
        return out;
    }
    out = a.x.toBytesBE();
    out[0] |= 0x80 | (@as(u8, @intFromBool(a.y.isLexLargest())) << 5);
    return out;
}

pub fn g1Serialize(a: G1.Affine) [96]u8 {
    var out: [96]u8 = @splat(0);
    if (a.isInfinity()) {
        out[0] = 0x40;
        return out;
    }
    out[0..48].* = a.x.toBytesBE();
    out[48..96].* = a.y.toBytesBE();
    return out;
}

// ---------------------------------------------------------------------------------------------
// G2

fn fp2Masked(in: *const [96]u8) ?Fp2 {
    const c1 = fpMasked(in[0..48]) orelse return null;
    const c0 = Fp.fromBytesBE(in[48..96]) orelse return null;
    return .{ .c0 = c0, .c1 = c1 };
}

fn fp2Plain(in: *const [96]u8) ?Fp2 {
    const c1 = Fp.fromBytesBE(in[0..48]) orelse return null;
    const c0 = Fp.fromBytesBE(in[48..96]) orelse return null;
    return .{ .c0 = c0, .c1 = c1 };
}

pub fn g2Uncompress(in: *const [96]u8) Result(G2.Affine) {
    const in0 = in[0];
    if (in0 & 0x80 == 0) return .{ .err = .bad_encoding };
    if (in0 & 0x40 != 0) {
        if (in0 & 0x3f == 0 and bytesZero(in[1..])) return .{ .ok = G2.Affine.infinity };
        return .{ .err = .bad_encoding };
    }
    const x = fp2Masked(in) orelse return .{ .err = .bad_encoding };
    const y2 = x.sqr().mul(x).add(G2.b);
    var y = y2.sqrt() orelse return .{ .err = .point_not_on_curve };
    const want_large = in0 & 0x20 != 0;
    y = y.condNeg(y.isLexLargest() != want_large);
    return .{ .ok = .{ .x = x, .y = y } };
}

/// `g2Uncompress` of two points at once (the square roots interleaved); the same results.
pub fn g2Uncompress2(a: *const [96]u8, b: *const [96]u8) [2]Result(G2.Affine) {
    const plain = struct {
        fn f(in: *const [96]u8) bool {
            return in[0] & 0xc0 == 0x80;
        }
    }.f;
    if (!plain(a) or !plain(b)) return .{ g2Uncompress(a), g2Uncompress(b) };
    const xa = fp2Masked(a) orelse return .{ .{ .err = .bad_encoding }, g2Uncompress(b) };
    const xb = fp2Masked(b) orelse return .{ g2Uncompress(a), .{ .err = .bad_encoding } };
    const ys = Fp2.sqrt2(xa.sqr().mul(xa).add(G2.b), xb.sqr().mul(xb).add(G2.b));
    var out: [2]Result(G2.Affine) = undefined;
    inline for (.{ a, b }, .{ xa, xb }, 0..) |in, x, k| {
        if (ys[k]) |y0| {
            const want_large = in[0] & 0x20 != 0;
            out[k] = .{ .ok = .{ .x = x, .y = y0.condNeg(y0.isLexLargest() != want_large) } };
        } else out[k] = .{ .err = .point_not_on_curve };
    }
    return out;
}

pub fn g2Deserialize192(in: *const [192]u8) Result(G2.Affine) {
    const in0 = in[0];
    if (in0 & 0xe0 == 0) {
        const x = fp2Masked(in[0..96]) orelse return .{ .err = .bad_encoding };
        const y = fp2Plain(in[96..192]) orelse return .{ .err = .bad_encoding };
        const a: G2.Affine = .{ .x = x, .y = y };
        if (!a.onCurve()) return .{ .err = .point_not_on_curve };
        return .{ .ok = a };
    }
    if (in0 & 0x80 != 0) return g2Uncompress(in[0..96]);
    if (in0 & 0x40 != 0) {
        if (in0 & 0x3f == 0 and bytesZero(in[1..])) return .{ .ok = G2.Affine.infinity };
    }
    return .{ .err = .bad_encoding };
}

/// blst `PublicKey::from_bytes` (min-sig) / `Signature::from_bytes` (min-pk).
pub fn g2FromBytes(in: []const u8) Result(G2.Affine) {
    if (in.len == 192 and in[0] & 0x80 == 0) return g2Deserialize192(in[0..192]);
    if (in.len == 96 and in[0] & 0x80 != 0) return g2Uncompress(in[0..96]);
    return .{ .err = .bad_encoding };
}

pub fn g2Compress(a: G2.Affine) [96]u8 {
    var out: [96]u8 = @splat(0);
    if (a.isInfinity()) {
        out[0] = 0xc0;
        return out;
    }
    out[0..48].* = a.x.c1.toBytesBE();
    out[48..96].* = a.x.c0.toBytesBE();
    out[0] |= 0x80 | (@as(u8, @intFromBool(a.y.isLexLargest())) << 5);
    return out;
}

pub fn g2Serialize(a: G2.Affine) [192]u8 {
    var out: [192]u8 = @splat(0);
    if (a.isInfinity()) {
        out[0] = 0x40;
        return out;
    }
    out[0..48].* = a.x.c1.toBytesBE();
    out[48..96].* = a.x.c0.toBytesBE();
    out[96..144].* = a.y.c1.toBytesBE();
    out[144..192].* = a.y.c0.toBytesBE();
    return out;
}

const p_plus_1_div_4 = blk: {
    const v = (@import("consts.zig").p + 1) / 4;
    var out: [6]u64 = undefined;
    for (0..6) |i| out[i] = @truncate(v >> @intCast(64 * i));
    break :blk out;
};

/// Square root in Fp (p = 3 mod 4), or null.
pub fn sqrtFp(a: Fp) ?Fp {
    const s = a.powLimbs(p_plus_1_div_4);
    if (!s.sqr().eql(a)) return null;
    return s;
}

test "generator round trips" {
    const g1 = curve.g1_generator;
    const c = g1Compress(g1);
    try std.testing.expectEqual(@as(u8, 0x97), c[0]);
    try std.testing.expect(g1Uncompress(&c).ok.eql(g1));
    try std.testing.expect(g1FromBytes(&g1Serialize(g1)).ok.eql(g1));
    const g2 = curve.g2_generator;
    const c2 = g2Compress(g2);
    try std.testing.expectEqual(@as(u8, 0x93), c2[0]);
    try std.testing.expect(g2Uncompress(&c2).ok.eql(g2));
    try std.testing.expect(g2FromBytes(&g2Serialize(g2)).ok.eql(g2));
    const neg = g2.neg();
    try std.testing.expect(g2Uncompress(&g2Compress(neg)).ok.eql(neg));
}
