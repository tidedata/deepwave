//! secp256r1 (NIST P-256) arithmetic for ECDSA verification and public-key recovery (public
//! data, variable time):
//!   - GF(p) in four 64-bit limbs, Montgomery form. p = 2^256 - 2^224 + 2^192 + 2^96 - 1 has
//!     -1/p = 1 (mod 2^64) and limbs (2^64 - 1, 2^32 - 1, 0, 2^64 - 2^32 + 1), so one reduction
//!     round costs a single 64x64 product plus shifts;
//!     On x86-64 with BMI2 (LLVM builds) multiplication and squaring run an inline-asm kernel
//!     (`x86` below: mulx rows, adcx/adox with ADX), tested equal to the portable Zig path;
//!   - Jacobian coordinates with an a = -3 doubling (4M + 4S, no small-constant multiplies) and
//!     madd-2004-hmv mixed additions; the Q table is built with co-Z additions;
//!   - the generator scalar is split into 128-bit halves over comptime tables of G and 2^128 G
//!     (odd multiples up to 127, width-8 NAF); the other scalar uses a width-5 NAF over Q..15Q,
//!     made affine with one Lehmer inversion;
//!   - the final x check compares X with r*Z^2 (and (r+n)*Z^2), so verification needs no field
//!     inversion.
//! The acceptance rules live in ecdsa.zig; this file only computes points.
const std = @import("std");
const builtin = @import("builtin");
const ed = @import("ed25519.zig");
const lehmer = @import("lehmer.zig");
const k1 = @import("secp256k1.zig");

pub const p_int: u256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF;
pub const n_int: u256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
const b_int: u256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B;

const P: [4]u64 = .{ 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFF, 0, 0xFFFFFFFF00000001 };
const r2_int: u256 = @intCast((@as(u1024, 1) << 512) % p_int);

pub const Fe = struct {
    /// Montgomery form, fully reduced (< p).
    l: [4]u64,

    pub const zero: Fe = .{ .l = .{ 0, 0, 0, 0 } };
    pub const one: Fe = blk: {
        @setEvalBranchQuota(100_000);
        break :blk fromInt(1);
    };

    pub inline fn raw(x: u256) [4]u64 {
        return .{ @truncate(x), @truncate(x >> 64), @truncate(x >> 128), @truncate(x >> 192) };
    }

    pub fn fromInt(x: u256) Fe {
        return (Fe{ .l = raw(x) }).mul(.{ .l = raw(r2_int) });
    }

    pub fn toInt(a: Fe) u256 {
        const r = a.mul(.{ .l = .{ 1, 0, 0, 0 } }).l;
        return @as(u256, r[0]) | (@as(u256, r[1]) << 64) | (@as(u256, r[2]) << 128) | (@as(u256, r[3]) << 192);
    }

    pub inline fn isZero(a: Fe) bool {
        return (a.l[0] | a.l[1] | a.l[2] | a.l[3]) == 0;
    }

    pub inline fn eql(a: Fe, b: Fe) bool {
        return a.l[0] == b.l[0] and a.l[1] == b.l[1] and a.l[2] == b.l[2] and a.l[3] == b.l[3];
    }

    pub fn isOdd(a: Fe) bool {
        return a.toInt() & 1 == 1;
    }

    /// r - p if r >= p (r given with its carry bit), else r.
    inline fn condSubP(r: [4]u64, carry: u1) Fe {
        var s: [4]u64 = undefined;
        var bw: u1 = 0;
        inline for (0..4) |i| {
            const d1 = @subWithOverflow(r[i], P[i]);
            const d2 = @subWithOverflow(d1[0], @as(u64, bw));
            s[i] = d2[0];
            bw = d1[1] | d2[1];
        }
        // r >= p iff carry or no borrow; select without a branch
        const keep: u64 = 0 -% @as(u64, bw & ~carry);
        var out: [4]u64 = undefined;
        inline for (0..4) |i| out[i] = (r[i] & keep) | (s[i] & ~keep);
        return .{ .l = out };
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
        return condSubP(r, c);
    }

    pub inline fn sub(a: Fe, b: Fe) Fe {
        var r: [4]u64 = undefined;
        var bw: u1 = 0;
        inline for (0..4) |i| {
            const d1 = @subWithOverflow(a.l[i], b.l[i]);
            const d2 = @subWithOverflow(d1[0], @as(u64, bw));
            r[i] = d2[0];
            bw = d1[1] | d2[1];
        }
        // branch-free: add p & mask (a borrow is data dependent and would mispredict)
        const mask: u64 = 0 -% @as(u64, bw);
        var c: u1 = 0;
        inline for (0..4) |i| {
            const s1 = @addWithOverflow(r[i], P[i] & mask);
            const s2 = @addWithOverflow(s1[0], @as(u64, c));
            r[i] = s2[0];
            c = s1[1] | s2[1];
        }
        return .{ .l = r };
    }

    pub inline fn neg(a: Fe) Fe {
        return zero.sub(a);
    }

    /// a * k for a small k (< 2^32); works the same on Montgomery values.
    pub inline fn mulSmall(a: Fe, comptime k: u64) Fe {
        var r: [4]u64 = undefined;
        var w: u64 = 0;
        inline for (0..4) |i| {
            const pr = @as(u128, a.l[i]) * k + w;
            r[i] = @truncate(pr);
            w = @truncate(pr >> 64);
        }
        // w * 2^256 = w * (2^256 - p) (mod p); 2^256 - p < 2^224, so the sum stays below 2p
        const R1: [4]u64 = .{ 1, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFF, 0x00000000FFFFFFFE };
        var c: u64 = 0;
        inline for (0..4) |i| {
            const pr = @as(u128, w) * R1[i] + r[i] + c;
            r[i] = @truncate(pr);
            c = @truncate(pr >> 64);
        }
        return condSubP(r, @intCast(c));
    }

    pub inline fn dbl(a: Fe) Fe {
        return a.add(a);
    }

    /// a / 2: a + p when a is odd (branch-free), then one right shift; the 257-bit sum keeps its
    /// carry in the top bit.
    pub inline fn half(a: Fe) Fe {
        const mask: u64 = 0 -% (a.l[0] & 1);
        var r: [4]u64 = undefined;
        var c: u1 = 0;
        inline for (0..4) |i| {
            const s1 = @addWithOverflow(a.l[i], P[i] & mask);
            const s2 = @addWithOverflow(s1[0], @as(u64, c));
            r[i] = s2[0];
            c = s1[1] | s2[1];
        }
        return .{ .l = .{
            (r[0] >> 1) | (r[1] << 63),
            (r[1] >> 1) | (r[2] << 63),
            (r[2] >> 1) | (r[3] << 63),
            (r[3] >> 1) | (@as(u64, c) << 63),
        } };
    }

    /// Montgomery reduction of a 512-bit value below p * 2^256. Round i adds m * p * 2^(64 i)
    /// with m = t[i]: the low limb cancels, m * 2^32 lands on limbs i+1..i+2 and m * p[3] on
    /// i+3..i+4; the carry out of limb i+4 is deferred to the next round (limb i+5).
    inline fn redc(t_in: [8]u64) Fe {
        var t = t_in;
        var pend: u64 = 0;
        inline for (0..4) |i| {
            const m = t[i];
            const mp3 = @as(u128, m) * P[3];
            var c: u128 = @as(u128, t[i + 1]) + (m << 32);
            t[i + 1] = @truncate(c);
            c = (c >> 64) + t[i + 2] + (m >> 32);
            t[i + 2] = @truncate(c);
            c = (c >> 64) + t[i + 3] + @as(u64, @truncate(mp3));
            t[i + 3] = @truncate(c);
            c = (c >> 64) + t[i + 4] + @as(u64, @truncate(mp3 >> 64)) + pend;
            t[i + 4] = @truncate(c);
            pend = @truncate(c >> 64);
        }
        return condSubP(.{ t[4], t[5], t[6], t[7] }, @intCast(pend));
    }

    pub inline fn mul(a: Fe, b: Fe) Fe {
        if (comptime x86_kernel) {
            if (!@inComptime()) return .{ .l = x86.mul(x86_adx, &a.l, b.l) };
        }
        return a.mulPortable(b);
    }

    pub inline fn sq(a: Fe) Fe {
        if (comptime x86_kernel) {
            if (!@inComptime()) return .{ .l = x86.sq(&a.l) };
        }
        return a.sqPortable();
    }

    pub inline fn mulPortable(a: Fe, b: Fe) Fe {
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
        return redc(t);
    }

    pub inline fn sqPortable(a: Fe) Fe {
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
        return redc(t);
    }

    pub fn sqn(a: Fe, k: usize) Fe {
        var r = a;
        for (0..k) |_| r = r.sq();
        return r;
    }

    /// a^(2^32 - 1)
    fn pow2_32m1(a: Fe) Fe {
        @setEvalBranchQuota(100_000);
        const x2 = a.sq().mul(a);
        const x4 = x2.sqn(2).mul(x2);
        const x8 = x4.sqn(4).mul(x4);
        const x16 = x8.sqn(8).mul(x8);
        return x16.sqn(16).mul(x16);
    }

    /// A square root of a, or null: a^((p+1)/4), (p+1)/4 = (2^32-1) 2^222 + 2^190 + 2^94.
    pub fn sqrt(a: Fe) ?Fe {
        @setEvalBranchQuota(100_000);
        var t = pow2_32m1(a);
        t = t.sqn(32).mul(a);
        t = t.sqn(96).mul(a);
        t = t.sqn(94);
        if (!t.sq().eql(a)) return null;
        return t;
    }

    /// a^(p-2) by square and multiply (comptime tables only).
    pub fn invertFermat(a: Fe) Fe {
        @setEvalBranchQuota(100_000_000);
        const e = p_int - 2;
        var r = one;
        var i: usize = 256;
        while (i > 0) {
            i -= 1;
            r = r.sq();
            if ((e >> @intCast(i)) & 1 == 1) r = r.mul(a);
        }
        return r;
    }

    /// x^-1 for a public x (Lehmer). 0 for 0.
    pub fn invertVar(a: Fe) Fe {
        return fromInt(lehmer.invMod(a.toInt(), p_int));
    }

    pub fn toBytes(a: Fe) [32]u8 {
        var out: [32]u8 = undefined;
        std.mem.writeInt(u256, &out, a.toInt(), .big);
        return out;
    }
};

/// x86-64 field kernel (ARCHITECTURE 5.1: field-arithmetic asm behind a comptime CPU check, the
/// portable Zig path above proven identical by the tests below). `mulx` needs BMI2 (x86_64_v3);
/// with ADX the multiplication rows run two carry chains (`adcx`/`adox`) side by side.
/// LLVM only: Zig's own x86 backend (the Debug default on x86_64-linux) has its own assembler
/// and takes the portable path.
const x86_kernel = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);
const x86_adx = x86_kernel and std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

/// The 512-bit product goes to t0..t7 (mulx rows, or the doubled cross products plus squares),
/// then four Montgomery rounds run on the low window t0..t3. With -1/p = 1 (mod 2^64) a round's
/// multiplier is the window's low word m, and m*p needs no multiply:
///   m + m*(2^64 - 1) + m*(2^32 - 1)*2^64 = m*2^96   (words 1, 2: m << 32, m >> 32)
///   m*p3 = m*2^64 - m*2^32 + m                       (words 3, 4: m - (m << 32), m - (m >> 32) - borrow)
/// so a round is two shifts, a sub/sbb pair and a four-word add whose top word replaces m. The
/// window then stays below 2^256 (it is below 2^192 + p after each round), the high half is
/// added, and one conditional subtraction of p brings the result (below 2p) under p.
const x86 = struct {
    const fmt = std.fmt.comptimePrint;

    /// Register names for the reduction: w[0..8] hold the product words, x, y and k are scratch,
    /// c takes the constant p1; k and c may be the same register.
    const Regs = struct { w: [8][]const u8, x: []const u8, y: []const u8, k: []const u8, c: []const u8 };

    /// The four rounds and the final subtraction; the result ends in w[4..8].
    fn reduceAndFinish(comptime g: Regs) []const u8 {
        comptime {
            @setEvalBranchQuota(1_000_000);
            var c: []const u8 = "";
            for (0..4) |r| {
                // m*p3 = (m - (m >> 32) - borrow, m - (m << 32)) comes off the critical path from m
                // alone, so each round is one four-word add chain (a shlx/shrx form with a second
                // subtraction chain measured 5% slower on Sapphire Rapids: longer dependency)
                c = c ++ fmt(
                    \\movq {0s}, {5s}
                    \\shlq $32, {5s}
                    \\movq {0s}, {6s}
                    \\shrq $32, {6s}
                    \\movq {0s}, {4s}
                    \\subq {5s}, {4s}
                    \\sbbq {6s}, {0s}
                    \\addq {5s}, {1s}
                    \\adcq {6s}, {2s}
                    \\adcq {4s}, {3s}
                    \\adcq $0, {0s}
                    \\
                , .{ g.w[r % 4], g.w[(r + 1) % 4], g.w[(r + 2) % 4], g.w[(r + 3) % 4], g.k, g.x, g.y });
            }
            return c ++ fmt(
                \\xorq {8s}, {8s}
                \\addq {4s}, {0s}
                \\adcq {5s}, {1s}
                \\adcq {6s}, {2s}
                \\adcq {7s}, {3s}
                \\adcq $0, {8s}
                \\movq {0s}, {4s}
                \\movq {1s}, {5s}
                \\movq {2s}, {6s}
                \\movq {3s}, {7s}
                \\movabsq $0xffffffff, {10s}
                \\movabsq $0xffffffff00000001, {9s}
                \\subq $-1, {4s}
                \\sbbq {10s}, {5s}
                \\sbbq $0, {6s}
                \\sbbq {9s}, {7s}
                \\sbbq $0, {8s}
                \\cmovcq {0s}, {4s}
                \\cmovcq {1s}, {5s}
                \\cmovcq {2s}, {6s}
                \\cmovcq {3s}, {7s}
            , .{ g.w[0], g.w[1], g.w[2], g.w[3], g.w[4], g.w[5], g.w[6], g.w[7], g.x, g.y, g.c });
        }
    }

    const mul_regs: Regs = .{
        .w = .{ "%[t0]", "%[t1]", "%[t2]", "%[t3]", "%[t4]", "%[t5]", "%[t6]", "%[t7]" },
        .x = "%[x]",
        .y = "%[y]",
        .k = "%%rdx",
        .c = "%%rdx",
    };

    fn mulCode(comptime adx: bool) []const u8 {
        comptime {
            @setEvalBranchQuota(1_000_000);
            // row 0: a * b0 into t0..t4
            var c: []const u8 =
                \\mulxq (%[a]), %[t0], %[t1]
                \\mulxq 8(%[a]), %[x], %[t2]
                \\addq %[x], %[t1]
                \\mulxq 16(%[a]), %[x], %[t3]
                \\adcq %[x], %[t2]
                \\mulxq 24(%[a]), %[x], %[t4]
                \\adcq %[x], %[t3]
                \\adcq $0, %[t4]
                \\
            ;
            for (1..4) |i| {
                c = c ++ fmt("movq %[t{d}], %%rdx\n", .{i + 4});
                if (adx) {
                    // lo words on the CF chain, hi words on the OF chain; t(i+4) starts at 0
                    c = c ++ fmt("xorq %[t{0d}], %[t{0d}]\n", .{i + 4});
                    for (0..4) |j| c = c ++ fmt(
                        \\mulxq {0d}(%[a]), %[x], %[y]
                        \\adcxq %[x], %[t{1d}]
                        \\adoxq %[y], %[t{2d}]
                        \\
                    , .{ 8 * j, i + j, i + j + 1 });
                    c = c ++ fmt("adcq $0, %[t{d}]\n", .{i + 4});
                } else {
                    // one carry word (y) handed along the row; mulx leaves the flags alone, so the
                    // previous carry is added before the next product overwrites y
                    c = c ++ fmt(
                        \\mulxq (%[a]), %[x], %[y]
                        \\addq %[x], %[t{d}]
                        \\adcq $0, %[y]
                        \\
                    , .{i});
                    for (1..4) |j| c = c ++ fmt(
                        \\addq %[y], %[t{0d}]
                        \\mulxq {1d}(%[a]), %[x], %[y]
                        \\adcq $0, %[y]
                        \\addq %[x], %[t{0d}]
                        \\adcq $0, %[y]
                        \\
                    , .{ i + j, 8 * j });
                    c = c ++ fmt("movq %[y], %[t{d}]\n", .{i + 4});
                }
            }
            return c ++ reduceAndFinish(mul_regs);
        }
    }

    /// Cross products a_i a_j (i < j) into t1..t6, doubled into t1..t7, plus the squares a_i^2.
    /// a is read through its pointer: an a-in-registers variant needs 14 operands, which fails
    /// register allocation at some inline sites.
    const sq_code =
        \\movq (%[a]), %%rdx
        \\mulxq 8(%[a]), %[t1], %[t2]
        \\mulxq 16(%[a]), %[x], %[t3]
        \\addq %[x], %[t2]
        \\mulxq 24(%[a]), %[x], %[t4]
        \\adcq %[x], %[t3]
        \\adcq $0, %[t4]
        \\movq 8(%[a]), %%rdx
        \\mulxq 16(%[a]), %[x], %[y]
        \\addq %[x], %[t3]
        \\adcq %[y], %[t4]
        \\mulxq 24(%[a]), %[x], %[t5]
        \\adcq $0, %[t5]
        \\addq %[x], %[t4]
        \\adcq $0, %[t5]
        \\movq 16(%[a]), %%rdx
        \\mulxq 24(%[a]), %[x], %[t6]
        \\addq %[x], %[t5]
        \\adcq $0, %[t6]
        \\xorq %[t7], %[t7]
        \\addq %[t1], %[t1]
        \\adcq %[t2], %[t2]
        \\adcq %[t3], %[t3]
        \\adcq %[t4], %[t4]
        \\adcq %[t5], %[t5]
        \\adcq %[t6], %[t6]
        \\adcq $0, %[t7]
        \\movq (%[a]), %%rdx
        \\mulxq %%rdx, %[t0], %[x]
        \\addq %[x], %[t1]
        \\movq 8(%[a]), %%rdx
        \\mulxq %%rdx, %[x], %[y]
        \\adcq %[x], %[t2]
        \\adcq %[y], %[t3]
        \\movq 16(%[a]), %%rdx
        \\mulxq %%rdx, %[x], %[y]
        \\adcq %[x], %[t4]
        \\adcq %[y], %[t5]
        \\movq 24(%[a]), %%rdx
        \\mulxq %%rdx, %[x], %[y]
        \\adcq %[x], %[t6]
        \\adcq %[y], %[t7]
        \\
    ++ reduceAndFinish(mul_regs);

    inline fn sq(a: *const [4]u64) [4]u64 {
        var t0: u64 = undefined;
        var t1: u64 = undefined;
        var t2: u64 = undefined;
        var t3: u64 = undefined;
        var t4: u64 = undefined;
        var t5: u64 = undefined;
        var t6: u64 = undefined;
        var t7: u64 = undefined;
        var x: u64 = undefined;
        var y: u64 = undefined;
        asm (sq_code
            : [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [t2] "=&r" (t2),
              [t3] "=&r" (t3),
              [t4] "=&r" (t4),
              [t5] "=&r" (t5),
              [t6] "=&r" (t6),
              [t7] "=&r" (t7),
              [x] "=&r" (x),
              [y] "=&r" (y),
            : [a] "r" (a),
            : .{ .rdx = true, .rflags = true, .memory = true });
        return .{ t4, t5, t6, t7 };
    }

    const mul_code = [2][]const u8{ mulCode(false), mulCode(true) };

    /// b arrives in registers: b0 in rdx, b1..b3 in t5..t7, each read at the start of its row
    /// before the row first writes that register; a is read through its pointer.
    inline fn mul(comptime adx: bool, a: *const [4]u64, b: [4]u64) [4]u64 {
        var t0: u64 = undefined;
        var t1: u64 = undefined;
        var t2: u64 = undefined;
        var t3: u64 = undefined;
        var t4: u64 = undefined;
        var t5: u64 = b[1];
        var t6: u64 = b[2];
        var t7: u64 = b[3];
        var x: u64 = undefined;
        var y: u64 = undefined;
        var d: u64 = b[0];
        asm (mul_code[@intFromBool(adx)]
            : [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [t2] "=&r" (t2),
              [t3] "=&r" (t3),
              [t4] "=&r" (t4),
              [t5] "+r" (t5),
              [t6] "+r" (t6),
              [t7] "+r" (t7),
              [x] "=&r" (x),
              [y] "=&r" (y),
              [d] "+{rdx}" (d),
            : [a] "r" (a),
            : .{ .rflags = true, .memory = true });
        return .{ t4, t5, t6, t7 };
    }
};

const b_fe: Fe = blk: {
    @setEvalBranchQuota(100_000);
    break :blk Fe.fromInt(b_int);
};

pub const Affine = struct {
    x: Fe,
    y: Fe,

    pub fn isOnCurve(a: Affine) bool {
        @setEvalBranchQuota(100_000);
        return a.y.sq().eql(rhs(a.x));
    }

    fn rhs(x: Fe) Fe {
        @setEvalBranchQuota(100_000);
        // x^3 - 3x + b
        return x.sq().mul(x).sub(x.dbl().add(x)).add(b_fe);
    }

    /// y with the requested parity for x, or null if x^3 - 3x + b is not a square.
    pub fn fromX(x: Fe, odd: bool) ?Affine {
        var y = rhs(x).sqrt() orelse return null;
        if (y.isOdd() != odd) y = y.neg();
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

    /// a = -3 doubling, 4M + 4S, arranged to need no small-constant multiplies:
    /// M = 3 (X - Z^2)(X + Z^2), S = 4 X Y^2, X3 = M^2 - 2S, Y3 = M (S - X3) - 8 Y^4, Z3 = 2 Y Z,
    /// with 2Y squared once for 4Y^2 and once more (halved) for 8Y^4.
    pub inline fn dbl(p: Jac) Jac {
        @setEvalBranchQuota(100_000);
        if (p.inf) return p;
        const y2 = p.y.dbl();
        const zz = p.z.sq();
        const z3 = y2.mul(p.z);
        const yy4 = y2.sq();
        const m0 = p.x.add(zz).mul(p.x.sub(zz));
        const m = m0.dbl().add(m0);
        const y8 = yy4.sq().half();
        const s = yy4.mul(p.x);
        const x3 = m.sq().sub(s.dbl());
        const y3 = s.sub(x3).mul(m).sub(y8);
        // y = 0 cannot occur: the group has odd prime order
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// madd-2004-hmv (q affine): 8M + 3S and few linear operations, with the exceptional cases.
    pub inline fn addAffine(p: Jac, q: Affine) Jac {
        @setEvalBranchQuota(100_000);
        if (p.inf) return fromAffine(q);
        const z1z1 = p.z.sq();
        const uu2 = q.x.mul(z1z1);
        const s2 = q.y.mul(z1z1.mul(p.z));
        const h = uu2.sub(p.x);
        const r = s2.sub(p.y);
        if (h.isZero()) {
            @branchHint(.cold);
            if (r.isZero()) return p.dbl();
            return infinity;
        }
        const hh = h.sq();
        const hhh = hh.mul(h);
        const v = hh.mul(p.x);
        const x3 = r.sq().sub(hhh).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(p.y.mul(hhh));
        const z3 = p.z.mul(h);
        return .{ .x = x3, .y = y3, .z = z3, .inf = false };
    }

    /// add-2007-bl: 11M + 5S, with the exceptional cases.
    pub fn add(p: Jac, q: Jac) Jac {
        @setEvalBranchQuota(100_000);
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

    pub fn toAffine(p: Jac) ?Affine {
        @setEvalBranchQuota(100_000);
        if (p.inf) return null;
        const zi = p.z.invertVar();
        const zi2 = zi.sq();
        return .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2).mul(zi) };
    }
};

pub const generator: Affine = blk: {
    @setEvalBranchQuota(100_000);
    break :blk .{
        .x = Fe.fromInt(0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296),
        .y = Fe.fromInt(0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5),
    };
};

fn batchAffine(comptime N: usize, pts: *const [N]Jac, comptime ct: bool) [N]Affine {
    @setEvalBranchQuota(100_000);
    var acc: [N]Fe = undefined;
    var run = Fe.one;
    for (0..N) |i| {
        acc[i] = run;
        run = run.mul(pts[i].z);
    }
    var inv = if (ct) run.invertFermat() else run.invertVar();
    var out: [N]Affine = undefined;
    var i: usize = N;
    while (i > 0) {
        i -= 1;
        const zi = inv.mul(acc[i]);
        inv = inv.mul(pts[i].z);
        const zi2 = zi.sq();
        out[i] = .{ .x = pts[i].x.mul(zi2), .y = pts[i].y.mul(zi2).mul(zi) };
    }
    return out;
}

/// Comptime curve arithmetic on plain integers: the interpreter does a u512 multiply and
/// remainder as one step, far cheaper than evaluating the limb code, so the large generator
/// tables cost little compile time.
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
    fn dbl(p: J) J {
        const delta = m(p.z, p.z);
        const gamma = m(p.y, p.y);
        const beta = m(p.x, gamma);
        const t = m(sb(p.x, delta), ad(p.x, delta));
        const alpha = ad(ad(t, t), t);
        const b4 = m(beta, 4);
        const x3 = sb(m(alpha, alpha), m(beta, 8));
        const z3 = m(m(p.y, p.z), 2);
        const y3 = sb(m(alpha, sb(b4, x3)), m(m(gamma, gamma), 8));
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
    fn mont(x: u256) Fe {
        return .{ .l = Fe.raw(@intCast((@as(u512, x) << 256) % p_int)) };
    }
    fn affine(p: J) [2]u256 {
        const zi = inv(p.z);
        const zi2 = m(zi, zi);
        return .{ m(p.x, zi2), m(m(p.y, zi2), zi) };
    }
    /// g, 3g, ..., (2N - 1)g in affine Montgomery form.
    fn oddMultiples(comptime N: usize, gx: u256, gy: u256) [N]Affine {
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
        var out: [N]Affine = undefined;
        var i: usize = N;
        while (i > 0) {
            i -= 1;
            const zi = m(iv, acc[i]);
            iv = m(iv, pts[i].z);
            const zi2 = m(zi, zi);
            out[i] = .{ .x = mont(m(pts[i].x, zi2)), .y = mont(m(m(pts[i].y, zi2), zi)) };
        }
        return out;
    }
};

const gx_int: u256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296;
const gy_int: u256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5;

/// Width of the generator NAFs: tables hold the odd multiples up to 2^(g_w - 1) - 1.
const g_w = 12;
const g_n = 1 << (g_w - 2);

/// G, 3G, ..., (2^(g_w-1) - 1)G and the same for 2^128 G (width-g_w NAF digits).
pub const g_table: [g_n]Affine = blk: {
    @setEvalBranchQuota(2_000_000_000);
    break :blk cmp.oddMultiples(g_n, gx_int, gy_int);
};
pub const g128_table: [g_n]Affine = blk: {
    @setEvalBranchQuota(2_000_000_000);
    var p: cmp.J = .{ .x = gx_int, .y = gy_int, .z = 1 };
    for (0..128) |_| p = cmp.dbl(p);
    const a = cmp.affine(p);
    break :blk cmp.oddMultiples(g_n, a[0], a[1]);
};

/// Q, 3Q, ..., 15Q in affine form (one Lehmer inversion). Built with co-Z additions (Meloni):
/// one doubling gives 2Q and Q on a common Z, then each step adds 2Q to the last multiple and
/// returns 2Q rescaled to the sum's Z (5M + 2S instead of a general 11M + 5S addition). Each
/// multiple keeps its own Z for the batch inversion. No step is exceptional: (2i - 1)Q = +-2Q
/// would need a point of order at most 15, and the group order is a large prime.
/// noinline: inlined into ECDSA verify, the unrolled steps made LLVM fail to place the x86
/// kernel's register operands ("inline assembly requires more registers than available") in
/// ReleaseFast; as a call (once per verification) it compiles everywhere at no measurable cost.
noinline fn oddMultiplesVar(q: Affine) [8]Affine {
    @setEvalBranchQuota(100_000);
    var pts: [8]Jac = undefined;
    // DBLU from Z = 1 (a = -3): 2Q = (M^2 - 2S, M (S - X) - 8 Y^4, 2Y) with S = 4 X Y^2,
    // M = 3 (X^2 - 1); Q on the same Z is (S, 8 Y^4, 2Y)
    const xx = q.x.sq();
    const yy = q.y.sq();
    const yyyy8 = yy.sq().dbl().dbl().dbl();
    const s = q.x.mul(yy).dbl().dbl();
    const m0 = xx.sub(Fe.one);
    const m = m0.dbl().add(m0);
    const z = q.y.dbl();
    var dx = m.sq().sub(s.dbl());
    var dy = m.mul(s.sub(dx)).sub(yyyy8);
    pts[0] = .{ .x = s, .y = yyyy8, .z = z, .inf = false };
    for (1..8) |i| {
        // ZADDU(D, R): R + D and D on the result's Z; both inputs share pts[i - 1].z
        const r = pts[i - 1];
        const dxr = dx.sub(r.x);
        const c = dxr.sq();
        const w1 = dx.mul(c);
        const w2 = r.x.mul(c);
        const dyr = dy.sub(r.y);
        const a1 = dy.mul(w1.sub(w2));
        const x3 = dyr.sq().sub(w1).sub(w2);
        pts[i] = .{ .x = x3, .y = dyr.mul(w1.sub(x3)).sub(a1), .z = r.z.mul(dxr), .inf = false };
        dx = w1;
        dy = a1;
    }
    return batchAffine(8, &pts, false);
}

pub fn invModN(a: u256) u256 {
    return lehmer.invMod(a, n_int);
}

const ln = 258;

inline fn half(d: i16) usize {
    return @as(usize, @abs(d)) >> 1;
}

inline fn addDigit(r: *Jac, table: []const Affine, d: i16) void {
    if (d > 0) {
        r.* = r.addAffine(table[half(d)]);
    } else if (d < 0) {
        r.* = r.addAffine(table[half(d)].neg());
    }
}

/// Variable time [a]G + [b]Q for a, b < n.
pub fn mulDoubleG(a: u256, q: Affine, b: u256) Jac {
    @setEvalBranchQuota(100_000);
    const tq = oddMultiplesVar(q);
    const nq = ed.wnaf(ln, b, 5, false);
    const na = k1.wnaf128(@truncate(a), g_w, false);
    const nb = k1.wnaf128(@truncate(a >> 128), g_w, false);
    var i: usize = ln - 1;
    while (i > 0 and nq[i] == 0 and (i >= k1.qn or (na[i] == 0 and nb[i] == 0))) i -= 1;
    var r = Jac.infinity;
    while (true) {
        r = r.dbl();
        addDigit(&r, &tq, nq[i]);
        if (i < k1.qn) {
            addDigit(&r, &g_table, na[i]);
            addDigit(&r, &g128_table, nb[i]);
        }
        if (i == 0) break;
        i -= 1;
    }
    return r;
}

/// x(P) mod n == r without an inversion: X == r*Z^2, or X == (r + n)*Z^2 when r + n < p.
pub fn xModNEquals(pt: Jac, r: u256) bool {
    @setEvalBranchQuota(100_000);
    if (pt.inf) return false;
    const zz = pt.z.sq();
    if (Fe.fromInt(r).mul(zz).eql(pt.x)) return true;
    if (r < p_int - n_int) return Fe.fromInt(r + n_int).mul(zz).eql(pt.x);
    return false;
}

// ---------------------------------------------------------------------------------------------

const testing = std.testing;
const StdP = std.crypto.ecc.P256;

fn fromStd(a: anytype) Affine {
    const c = a.affineCoordinates();
    return .{ .x = Fe.fromInt(std.mem.readInt(u256, &c.x.toBytes(.big), .big)), .y = Fe.fromInt(std.mem.readInt(u256, &c.y.toBytes(.big), .big)) };
}

test "p256 field agrees with u512 arithmetic" {
    var prng: std.Random.DefaultPrng = .init(256);
    const rnd = prng.random();
    for (0..5000) |i| {
        var x = rnd.int(u256) % p_int;
        var y = rnd.int(u256) % p_int;
        if (i < 4) {
            x = p_int - 1 - @as(u256, i);
            y = p_int - 1;
        }
        const a = Fe.fromInt(x);
        const b = Fe.fromInt(y);
        try testing.expectEqual(x, a.toInt());
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) * y) % p_int)), a.mul(b).toInt());
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) * x) % p_int)), a.sq().toInt());
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) + y) % p_int)), a.add(b).toInt());
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) * 8) % p_int)), a.mulSmall(8).toInt());
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) * 3) % p_int)), a.mulSmall(3).toInt());
        try testing.expect(a.half().dbl().eql(a));
        try testing.expect(a.half().toInt() < p_int);
        try testing.expectEqual(@as(u256, @intCast((@as(u512, x) + p_int - y) % p_int)), a.sub(b).toInt());
        if (x != 0) try testing.expectEqual(@as(u256, 1), a.mul(a.invertVar()).toInt());
        if (i < 50 and x != 0) try testing.expect(a.invertFermat().eql(a.invertVar()));
        if (a.sqrt()) |s| try testing.expect(s.sq().eql(a));
    }
}

test "p256 x86 kernel gives the portable path's results" {
    if (!x86_kernel) return error.SkipZigTest;
    var prng: std.Random.DefaultPrng = .init(2561);
    const rnd = prng.random();
    // edge values: 0, 1, small, p - 1, p - small, 2^k neighbours, all-ones-ish words below p
    const edges = [_]u256{ 0, 1, 2, 3, p_int - 1, p_int - 2, p_int - 3, 1 << 64, (1 << 128) - 1, 1 << 192, (1 << 255), (1 << 255) - 1, p_int >> 1, (p_int >> 1) + 1, 0xFFFFFFFF, 0xFFFFFFFF00000000, 0x00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF };
    var vals: [edges.len + 3000]Fe = undefined;
    for (edges, 0..) |e, i| vals[i] = .{ .l = Fe.raw(e % p_int) };
    for (vals[edges.len..]) |*v| v.* = .{ .l = Fe.raw(rnd.int(u256) % p_int) };
    for (vals, 0..) |a, i| {
        const want_sq = a.sqPortable();
        try testing.expectEqual(want_sq.l, x86.sq(&a.l));
        try testing.expectEqual(want_sq.l, a.sq().l);
        const inner = if (i < edges.len) vals[0..] else vals[i .. i + 1];
        for (inner) |b| {
            const want = a.mulPortable(b);
            try testing.expectEqual(want.l, x86.mul(false, &a.l, b.l));
            if (x86_adx) try testing.expectEqual(want.l, x86.mul(true, &a.l, b.l));
            try testing.expectEqual(want.l, a.mul(b).l);
        }
    }
    // long chains (inputs produced by the kernel itself)
    var x = vals[edges.len];
    var y = x;
    for (0..100_000) |_| {
        x = x.mul(vals[edges.len + 1]).sq();
        y = y.mulPortable(vals[edges.len + 1]).sqPortable();
    }
    try testing.expect(x.eql(y));
}

// Reviewer case: the reduction's result U = (T + M p) / 2^256 lies in [0, 2p), and U in [p, 2^256)
// (final subtraction with no carry word) has probability about 2^-32 for random operands, so the
// random tests above never reach it. Choose b (or a square root a) so the field result v is below
// 2^256 - p: then U is v or v + p, and about half the cases land in [p, 2^256). An integer model
// of the reduction counts the hits; every path (portable, kernel, ADX kernel) must return v.
test "p256 multiplication: reductions that land in [p, 2^256)" {
    const R = struct {
        fn mulmod(x: u256, y: u256) u256 {
            return @intCast((@as(u512, x) * y) % p_int);
        }
        fn powmod(x: u256, e: u256) u256 {
            var r: u256 = 1;
            var i: usize = 256;
            while (i > 0) {
                i -= 1;
                r = mulmod(r, r);
                if ((e >> @intCast(i)) & 1 == 1) r = mulmod(r, x);
            }
            return r;
        }
        // U before the final subtraction, from the definition of Montgomery reduction
        fn pre(t: u512) u512 {
            var pinv: u256 = ~@as(u256, 0); // p^-1 = -1 (mod 2^64); Newton doubles the bits
            for (0..2) |_| pinv *%= 2 -% p_int *% pinv;
            const m: u256 = (0 -% pinv) *% @as(u256, @truncate(t));
            const s: u768 = @as(u768, t) + @as(u768, m) * p_int;
            return @intCast(s >> 256);
        }
    };
    var prng: std.Random.DefaultPrng = .init(0x5032_3536);
    const rnd = prng.random();
    const span: u256 = 0 -% p_int; // 2^256 - p
    var hits_mul: usize = 0;
    var hits_sq: usize = 0;
    for (0..2000) |k| {
        const v = rnd.int(u256) % span;
        const a = 1 + rnd.int(u256) % (p_int - 1);
        const b = R.mulmod(@intCast((@as(u512, v) << 256) % p_int), lehmer.invMod(a, p_int));
        const fa: Fe = .{ .l = Fe.raw(a) };
        const fb: Fe = .{ .l = Fe.raw(b) };
        const u = R.pre(@as(u512, a) * b);
        try testing.expect(u == v or u == @as(u512, v) + p_int);
        if (u >= p_int) hits_mul += 1;
        try testing.expectEqual(Fe.raw(v), fa.mulPortable(fb).l);
        try testing.expectEqual(Fe.raw(v), fa.mul(fb).l);
        if (x86_kernel) {
            try testing.expectEqual(Fe.raw(v), x86.mul(false, &fa.l, fb.l));
            if (x86_adx) try testing.expectEqual(Fe.raw(v), x86.mul(true, &fa.l, fb.l));
        }
        if (k >= 400) continue;
        const w: u256 = @intCast((@as(u512, v) << 256) % p_int);
        const s = R.powmod(w, (p_int + 1) / 4);
        if (R.mulmod(s, s) != w) continue;
        const fs: Fe = .{ .l = Fe.raw(s) };
        if (R.pre(@as(u512, s) * s) >= p_int) hits_sq += 1;
        try testing.expectEqual(Fe.raw(v), fs.sqPortable().l);
        try testing.expectEqual(Fe.raw(v), fs.sq().l);
        if (x86_kernel) try testing.expectEqual(Fe.raw(v), x86.sq(&fs.l));
    }
    try testing.expect(hits_mul > 500);
    try testing.expect(hits_sq > 50);
}

test "p256 tables and double multiplication agree with std" {
    try testing.expect(generator.isOnCurve());
    for (g_table) |pt| try testing.expect(pt.isOnCurve());
    for (g128_table) |pt| try testing.expect(pt.isOnCurve());
    var prng: std.Random.DefaultPrng = .init(2560);
    const rnd = prng.random();
    for (0..200) |i| {
        var a = rnd.int(u256) % n_int;
        var b = rnd.int(u256) % n_int;
        if (i == 0) a = n_int - 1;
        if (i == 1) b = 1;
        if (i == 2) a = 0;
        const c = rnd.int(u256) % n_int;
        var cb: [32]u8 = undefined;
        std.mem.writeInt(u256, &cb, c, .big);
        const sq = try StdP.basePoint.mul(cb, .big);
        const q = fromStd(sq);
        try testing.expect(q.isOnCurve());
        var ab: [32]u8 = undefined;
        std.mem.writeInt(u256, &ab, a, .big);
        var bb: [32]u8 = undefined;
        std.mem.writeInt(u256, &bb, b, .big);
        const want = fromStd(try StdP.mulDoubleBasePublic(StdP.basePoint, ab, sq, bb, .big));
        const got = mulDoubleG(a, q, b).toAffine().?;
        try testing.expect(want.x.eql(got.x) and want.y.eql(got.y));
        const fx = Affine.fromX(q.x, q.y.isOdd()).?;
        try testing.expect(fx.y.eql(q.y));
    }
}

test "double multiplication on exceptional inputs: Q a small multiple of G" {
    const cs = [_]u256{ 1, 2, 3, n_int - 1, n_int - 2, 1 << 128, 3 << 128, n_int - (1 << 128) };
    var vals: [64]u256 = undefined;
    var nv: usize = 0;
    for ([_]u256{ 0, 1, 2, 3, 5, 15, 17, 2047, 2049, 1 << 128, (1 << 128) + 1, 3 << 128 }) |v| {
        vals[nv] = v % n_int;
        nv += 1;
        vals[nv] = (n_int - v % n_int) % n_int;
        nv += 1;
    }
    const nm = struct {
        fn mul(x: u256, y: u256) u256 {
            return @intCast((@as(u512, x) * y) % n_int);
        }
    };
    var hits: usize = 0;
    for (cs) |c| {
        var cb: [32]u8 = undefined;
        std.mem.writeInt(u256, &cb, c, .big);
        const q = fromStd(try StdP.basePoint.mul(cb, .big));
        for (vals[0..nv]) |a| for (vals[0..nv]) |b| {
            const e: u256 = @intCast((@as(u512, a) + nm.mul(b, c)) % n_int);
            const got = mulDoubleG(a, q, b).toAffine();
            if (e == 0) {
                try testing.expect(got == null);
                hits += 1;
                continue;
            }
            var eb: [32]u8 = undefined;
            std.mem.writeInt(u256, &eb, e, .big);
            const want = fromStd(try StdP.basePoint.mul(eb, .big));
            const g = got.?;
            try testing.expect(want.x.eql(g.x) and want.y.eql(g.y));
        };
    }
    try testing.expect(hits > 0);
}
