//! Variable-time modular inverse by Lehmer's extended Euclid (Knuth 4.5.2, Algorithm L) on
//! 62-bit leading words. For public values only (signature verification and recovery).
const std = @import("std");

/// x^-1 mod m for an odd prime m < 2^256 and 0 < x < m. Returns 0 for x = 0.
pub fn invMod(x: u256, m: u256) u256 {
    if (x == 0) return 0;
    var a: u256 = m;
    var b: u256 = x;
    // invariant: a = x*ta, b = x*tb (mod m); |ta|, |tb| <= m, kept exactly in i320
    var ta: i320 = 0;
    var tb: i320 = 1;
    while (b != 0) {
        const n: u32 = 256 - @as(u32, @clz(a));
        const sh: u8 = if (n > 62) @intCast(n - 62) else 0;
        var xh: i64 = @intCast(a >> sh);
        var yh: i64 = @intCast(b >> sh);
        var A: i64 = 1;
        var B: i64 = 0;
        var C: i64 = 0;
        var D: i64 = 1;
        if (sh == 0) {
            // exact single-word Euclid
            while (yh != 0) {
                const q = @divTrunc(xh, yh);
                const t0 = A - q * C;
                A = C;
                C = t0;
                const t1 = B - q * D;
                B = D;
                D = t1;
                const t2 = xh - q * yh;
                xh = yh;
                yh = t2;
            }
        } else {
            while (true) {
                const yc = yh + C;
                const yd = yh + D;
                if (yc <= 0 or yd <= 0) break;
                const xa = xh + A;
                const xb = xh + B;
                if (xa < 0 or xb < 0) break;
                const q = @divTrunc(xa, yc);
                if (q != @divTrunc(xb, yd)) break;
                const t0 = A - q * C;
                A = C;
                C = t0;
                const t1 = B - q * D;
                B = D;
                D = t1;
                const t2 = xh - q * yh;
                xh = yh;
                yh = t2;
            }
        }
        if (B == 0) {
            // one exact step: q = a / b
            const q = a / b;
            const r = a - q * b;
            const nt = ta - @as(i320, @intCast(q)) * tb;
            a = b;
            b = r;
            ta = tb;
            tb = nt;
        } else {
            const sa: u256 = @bitCast(@as(i256, A));
            const sb: u256 = @bitCast(@as(i256, B));
            const sc: u256 = @bitCast(@as(i256, C));
            const sd: u256 = @bitCast(@as(i256, D));
            const na = sa *% a +% sb *% b;
            const nb = sc *% a +% sd *% b;
            const nta = @as(i320, A) * ta + @as(i320, B) * tb;
            const ntb = @as(i320, C) * ta + @as(i320, D) * tb;
            a = na;
            b = nb;
            ta = nta;
            tb = ntb;
        }
    }
    // a = gcd = 1 = x*ta (mod m)
    const mm: i320 = @intCast(m);
    var r = @mod(ta, mm);
    if (r < 0) r += mm;
    return @intCast(r);
}

test "invMod against Fermat on random values" {
    const n: u256 = std.crypto.ecc.Secp256k1.scalar.field_order;
    const p: u256 = std.crypto.ecc.Secp256k1.Fe.field_order;
    var prng: std.Random.DefaultPrng = .init(3);
    const rnd = prng.random();
    for (0..3000) |i| {
        const m = if (i % 2 == 0) n else p;
        var x = rnd.int(u256) % m;
        if (i < 6) x = @as(u256, i) + 1;
        if (i == 6) x = m - 1;
        if (x == 0) continue;
        const inv = invMod(x, m);
        const prod: u512 = (@as(u512, x) * inv) % m;
        try std.testing.expectEqual(@as(u512, 1), prod);
    }
}
