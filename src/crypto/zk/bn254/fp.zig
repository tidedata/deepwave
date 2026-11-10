//! Prime fields of BN254 in Montgomery form (R = 2^256), four 64-bit limbs.
//!
//! `Fq` is the base field (arkworks `ark_bn254::Fq`), `Fr` the scalar field (`ark_bn254::Fr`).
//! Elements are always fully reduced (< p), so limb equality is field equality, exactly like
//! arkworks' `Fp<MontBackend<_, 4>>`. Multiplication is CIOS with the "no final carry" shortcut
//! (valid because both moduli are below 2^255 - 1). Nothing here touches secret data: all
//! users are verifiers over public inputs, so the code may branch on values.
const std = @import("std");

pub fn Field(comptime modulus: comptime_int) type {
    comptime std.debug.assert(modulus < (1 << 254));
    return struct {
        /// Montgomery form, little-endian limbs, always < p.
        l: [4]u64,

        const Self = @This();
        pub const modulus_int: comptime_int = modulus;
        pub const p: [4]u64 = limbsOf(modulus);
        /// -p^{-1} mod 2^64.
        pub const inv: u64 = blk: {
            var x: u64 = 1;
            for (0..7) |_| x = x *% (2 -% p[0] *% x);
            break :blk 0 -% x;
        };
        pub const r2: [4]u64 = limbsOf(((1 << 512) % modulus));
        pub const zero: Self = .{ .l = .{ 0, 0, 0, 0 } };
        pub const one: Self = .{ .l = limbsOf((1 << 256) % modulus) };
        pub const bits: u16 = std.math.log2_int_ceil(u256, modulus);

        /// Comptime constant from an integer (any size, reduced mod p).
        pub fn fromInt(comptime v: comptime_int) Self {
            const m = @mod(v, modulus);
            return .{ .l = limbsOf((m << 256) % modulus) };
        }

        pub fn fromU64(v: u64) Self {
            return mul(.{ .l = .{ v, 0, 0, 0 } }, .{ .l = r2 });
        }

        /// From canonical little-endian limbs (value < p, checked by the caller).
        pub fn fromCanonicalLimbs(v: [4]u64) Self {
            return mul(.{ .l = v }, .{ .l = r2 });
        }

        /// Standard (non-Montgomery) limbs.
        pub fn toLimbs(a: Self) [4]u64 {
            return mul(a, .{ .l = .{ 1, 0, 0, 0 } }).l;
        }

        pub fn isZero(a: Self) bool {
            return (a.l[0] | a.l[1] | a.l[2] | a.l[3]) == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.l[0] == b.l[0] and a.l[1] == b.l[1] and a.l[2] == b.l[2] and a.l[3] == b.l[3];
        }

        pub fn isOne(a: Self) bool {
            return eql(a, one);
        }

        pub fn add(a: Self, b: Self) Self {
            var t: [4]u64 = undefined;
            var c: u1 = 0;
            inline for (0..4) |i| {
                const s1 = @addWithOverflow(a.l[i], b.l[i]);
                const s2 = @addWithOverflow(s1[0], @as(u64, c));
                t[i] = s2[0];
                c = s1[1] | s2[1];
            }
            // p < 2^254 so a + b < 2^255: no carry out of the top limb.
            return .{ .l = reduceOnce(t) };
        }

        pub fn dbl(a: Self) Self {
            return add(a, a);
        }

        pub fn sub(a: Self, b: Self) Self {
            var t: [4]u64 = undefined;
            var br: u1 = 0;
            inline for (0..4) |i| {
                const d1 = @subWithOverflow(a.l[i], b.l[i]);
                const d2 = @subWithOverflow(d1[0], @as(u64, br));
                t[i] = d2[0];
                br = d1[1] | d2[1];
            }
            if (br != 0) {
                var c: u1 = 0;
                inline for (0..4) |i| {
                    const s1 = @addWithOverflow(t[i], p[i]);
                    const s2 = @addWithOverflow(s1[0], @as(u64, c));
                    t[i] = s2[0];
                    c = s1[1] | s2[1];
                }
            }
            return .{ .l = t };
        }

        pub fn neg(a: Self) Self {
            if (a.isZero()) return a;
            return sub(.{ .l = p }, a);
        }

        fn reduceOnce(t: [4]u64) [4]u64 {
            var r: [4]u64 = undefined;
            var br: u1 = 0;
            inline for (0..4) |i| {
                const d1 = @subWithOverflow(t[i], p[i]);
                const d2 = @subWithOverflow(d1[0], @as(u64, br));
                r[i] = d2[0];
                br = d1[1] | d2[1];
            }
            return if (br != 0) t else r;
        }

        inline fn mac(acc: u64, x: u64, y: u64, carry: *u64) u64 {
            const w: u128 = @as(u128, x) * y + acc + carry.*;
            carry.* = @truncate(w >> 64);
            return @truncate(w);
        }

        /// Montgomery multiplication a * b * R^-1 mod p (CIOS, no-carry variant as ark-ff's
        /// `mul_assign`; valid because the top limb of p is below 2^63 - 1).
        pub fn mul(a: Self, b: Self) Self {
            var r: [4]u64 = .{ 0, 0, 0, 0 };
            inline for (0..4) |i| {
                var c1: u64 = 0;
                r[0] = mac(r[0], a.l[0], b.l[i], &c1);
                const k = r[0] *% inv;
                var c2: u64 = 0;
                _ = mac(r[0], k, p[0], &c2);
                inline for (1..4) |j| {
                    r[j] = mac(r[j], a.l[j], b.l[i], &c1);
                    r[j - 1] = mac(r[j], k, p[j], &c2);
                }
                r[3] = c1 +% c2;
            }
            return .{ .l = reduceOnce(r) };
        }

        /// sum_i a[i] * b[i] with one Montgomery reduction (lazy reduction of the wide
        /// products). Valid for n <= 20: the reduced value stays below 2^256 (n * p^2 / R + p).
        pub fn sumOfProducts(comptime n: usize, a: *const [n]Self, b: *const [n]Self) Self {
            comptime std.debug.assert(n >= 1 and n <= 20);
            var t: [9]u64 = @splat(0);
            inline for (0..n) |k| {
                // t += a[k] * b[k] (schoolbook 4x4 into the 9-limb accumulator)
                inline for (0..4) |i| {
                    var c: u64 = 0;
                    inline for (0..4) |j| {
                        t[i + j] = mac(t[i + j], a[k].l[i], b[k].l[j], &c);
                    }
                    var idx: usize = i + 4;
                    while (c != 0 and idx < 9) : (idx += 1) {
                        const s1 = @addWithOverflow(t[idx], c);
                        t[idx] = s1[0];
                        c = s1[1];
                    }
                }
            }
            // REDC over 4 limbs
            inline for (0..4) |i| {
                const m = t[i] *% inv;
                var c: u64 = 0;
                inline for (0..4) |j| {
                    t[i + j] = mac(t[i + j], m, p[j], &c);
                }
                var idx: usize = i + 4;
                while (c != 0 and idx < 9) : (idx += 1) {
                    const s1 = @addWithOverflow(t[idx], c);
                    t[idx] = s1[0];
                    c = s1[1];
                }
            }
            std.debug.assert(t[8] == 0);
            var r: [4]u64 = .{ t[4], t[5], t[6], t[7] };
            while (!ltModulus(r)) r = subP(r);
            return .{ .l = r };
        }

        fn subP(x: [4]u64) [4]u64 {
            var r: [4]u64 = undefined;
            var br: u1 = 0;
            inline for (0..4) |i| {
                const d1 = @subWithOverflow(x[i], p[i]);
                const d2 = @subWithOverflow(d1[0], @as(u64, br));
                r[i] = d2[0];
                br = d1[1] | d2[1];
            }
            return r;
        }

        pub fn sq(a: Self) Self {
            return mul(a, a);
        }

        /// a^e for a little-endian limb exponent (variable time).
        pub fn powLimbs(a: Self, e: []const u64) Self {
            var r = one;
            var i: usize = e.len;
            while (i > 0) {
                i -= 1;
                var bit: u7 = 64;
                while (bit > 0) {
                    bit -= 1;
                    r = r.sq();
                    if ((e[i] >> @intCast(bit)) & 1 == 1) r = r.mul(a);
                }
            }
            return r;
        }

        pub fn pow(a: Self, comptime e: comptime_int) Self {
            const el = comptime limbsOf(e);
            return a.powLimbs(&el);
        }

        /// Inverse (0 maps to 0; callers check for zero first where it matters).
        pub fn inverse(a: Self) Self {
            return a.pow(modulus - 2);
        }

        /// Legendre symbol: 1, -1 (as p-1) or 0.
        pub fn legendre(a: Self) i2 {
            if (a.isZero()) return 0;
            const l = a.pow((modulus - 1) / 2);
            return if (l.isOne()) 1 else -1;
        }

        /// Square root for p = 3 mod 4: a^((p+1)/4), or null when a is not a square.
        pub fn sqrt(a: Self) ?Self {
            comptime std.debug.assert(modulus % 4 == 3);
            const s = a.pow((modulus + 1) / 4);
            if (!s.sq().eql(a)) return null;
            return s;
        }

        /// Integer comparison of the canonical values (arkworks `Ord` on prime fields).
        pub fn cmp(a: Self, b: Self) std.math.Order {
            const x = a.toLimbs();
            const y = b.toLimbs();
            var i: usize = 4;
            while (i > 0) {
                i -= 1;
                if (x[i] != y[i]) return if (x[i] < y[i]) .lt else .gt;
            }
            return .eq;
        }

        /// arkworks `y <= -y` (the "positive" half used by compressed points).
        pub fn isLexSmallest(a: Self) bool {
            return a.cmp(a.neg()) != .gt;
        }

        /// 32 little-endian bytes of the canonical value.
        pub fn toBytesLe(a: Self) [32]u8 {
            const x = a.toLimbs();
            var out: [32]u8 = undefined;
            inline for (0..4) |i| std.mem.writeInt(u64, out[i * 8 ..][0..8], x[i], .little);
            return out;
        }

        pub fn toBytesBe(a: Self) [32]u8 {
            var le = a.toBytesLe();
            std.mem.reverse(u8, &le);
            return le;
        }

        /// Canonical little-endian limbs of 32 LE bytes, with no reduction.
        pub fn limbsLe(b: *const [32]u8) [4]u64 {
            var x: [4]u64 = undefined;
            inline for (0..4) |i| x[i] = std.mem.readInt(u64, b[i * 8 ..][0..8], .little);
            return x;
        }

        pub fn ltModulus(x: [4]u64) bool {
            var i: usize = 4;
            while (i > 0) {
                i -= 1;
                if (x[i] != p[i]) return x[i] < p[i];
            }
            return false;
        }

        /// 32 LE bytes that must be < p (arkworks `from_bigint` / canonical deserialize).
        pub fn fromBytesLeCanonical(b: *const [32]u8) ?Self {
            const x = limbsLe(b);
            if (!ltModulus(x)) return null;
            return fromCanonicalLimbs(x);
        }

        /// Any number of LE bytes, reduced mod p (arkworks `from_le_bytes_mod_order`).
        pub fn fromBytesLeModOrder(b: []const u8) Self {
            var acc = zero;
            // Horner over 31-byte (248-bit) chunks from the top: acc = acc * 2^248 + chunk.
            const shift = comptime fromInt(1 << 248);
            var end = b.len;
            const first = b.len % 31;
            var start: usize = b.len - (if (first == 0) @min(31, b.len) else first);
            while (true) {
                var chunk: [32]u8 = @splat(0);
                @memcpy(chunk[0 .. end - start], b[start..end]);
                acc = acc.mul(shift).add(fromCanonicalLimbs(limbsLe(&chunk)));
                if (start == 0) break;
                end = start;
                start -= 31;
            }
            return acc;
        }

        /// Big-endian bytes, reduced mod p (arkworks `from_be_bytes_mod_order`).
        pub fn fromBytesBeModOrder(b: []const u8) Self {
            var acc = zero;
            const shift = comptime fromInt(1 << 248);
            var i: usize = 0;
            const first = b.len % 31;
            var take: usize = if (first == 0) @min(31, b.len) else first;
            while (i < b.len) {
                var chunk: [32]u8 = @splat(0);
                for (0..take) |k| chunk[take - 1 - k] = b[i + k];
                acc = acc.mul(shift).add(fromCanonicalLimbs(limbsLe(&chunk)));
                i += take;
                take = 31;
            }
            return acc;
        }

        /// arkworks 0.4 `Fp::from_str`: ASCII decimal digits, no leading zero unless the
        /// string is exactly "0", any length, reduced mod p. Null where arkworks errors.
        pub fn fromDecimal(s: []const u8) ?Self {
            if (s.len == 0) return null;
            if (s.len == 1 and s[0] == '0') return zero;
            if (s[0] == '0') return null;
            // Fast path: up to 77 digits always fits in 256 bits.
            if (s.len <= 77) {
                var x: u256 = 0;
                for (s) |c| {
                    if (c < '0' or c > '9') return null;
                    x = x * 10 + (c - '0');
                }
                const pm: u256 = modulus;
                while (x >= pm) x -= pm; // x < 10^77 < 2^256: at most a handful of steps
                return fromCanonicalLimbs(@bitCast(x));
            }
            var acc = zero;
            const ten = comptime fromInt(10);
            const digits: [10]Self = comptime blk: {
                var d: [10]Self = undefined;
                for (0..10) |k| d[k] = fromInt(k);
                break :blk d;
            };
            for (s) |c| {
                if (c < '0' or c > '9') return null;
                acc = acc.mul(ten).add(digits[c - '0']);
            }
            return acc;
        }

        /// Decimal string of the canonical value into `buf` (at most 78 bytes).
        pub fn toDecimal(a: Self, buf: *[80]u8) []const u8 {
            var x: u256 = @bitCast(a.toLimbs());
            var i: usize = buf.len;
            if (x == 0) {
                buf[buf.len - 1] = '0';
                return buf[buf.len - 1 ..];
            }
            while (x != 0) {
                i -= 1;
                buf[i] = @intCast(x % 10);
                buf[i] += '0';
                x /= 10;
            }
            return buf[i..];
        }
    };
}

pub fn limbsOf(comptime v: comptime_int) [4]u64 {
    return comptime blk: {
        std.debug.assert(v >= 0 and v < (1 << 256));
        var out: [4]u64 = undefined;
        for (0..4) |i| out[i] = @truncate(v >> (64 * i));
        break :blk out;
    };
}

pub const q_modulus = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
pub const r_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

pub const Fq = Field(q_modulus);
pub const Fr = Field(r_modulus);

test "field basics" {
    const a = Fq.fromInt(5);
    const b = Fq.fromInt(7);
    try std.testing.expect(a.mul(b).eql(Fq.fromInt(35)));
    try std.testing.expect(a.sub(b).eql(Fq.fromInt(-2)));
    try std.testing.expect(a.mul(a.inverse()).isOne());
    try std.testing.expect(Fq.fromInt(4).sqrt().?.sq().eql(Fq.fromInt(4)));
    try std.testing.expectEqual(@as(u64, 35), a.mul(b).toLimbs()[0]);
    var buf: [80]u8 = undefined;
    const m1 = Fr.fromInt(-1);
    try std.testing.expectEqualStrings("21888242871839275222246405745257275088548364400416034343698204186575808495616", m1.toDecimal(&buf));
    try std.testing.expect(Fr.fromDecimal("21888242871839275222246405745257275088548364400416034343698204186575808495618").?.isOne());
    try std.testing.expect(Fr.fromDecimal("01") == null);
    try std.testing.expect(Fr.fromDecimal("0").?.isZero());
    const big: [100]u8 = @splat('1');
    try std.testing.expect(Fr.fromDecimal(&big) != null);
    var le: [40]u8 = @splat(0xff);
    const x = Fr.fromBytesLeModOrder(&le);
    var be: [40]u8 = @splat(0xff);
    try std.testing.expect(x.eql(Fr.fromBytesBeModOrder(&be)));
}
