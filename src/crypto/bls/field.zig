//! Montgomery prime fields: Fp (BLS12-381 base field, 6 limbs) and Fr (scalar field, 4 limbs).
//!
//! Representation: little-endian u64 limbs of a*R mod m with R = 2^(64N), always fully reduced
//! (0 <= limbs < m), so equality and zero tests are limb compares. Every operation here is
//! constant time: no branch or index depends on a value (only on comptime constants), so the
//! same code serves secret scalars (signing, key generation) and public data.
//!
//! Multiplication is a full double-width product followed by a separate Montgomery reduction
//! (`mulWide`/`sqrWide` + `redc`, also used directly for lazy reduction in Fp2); `mulRaw` (CIOS
//! with the "no carry" shortcut) remains for conversions. Both end in one conditional
//! subtraction, so every result is fully reduced.
const std = @import("std");

/// a * b + c + d as (lo, hi). Native targets keep the plain u128 expression (one mul/umulh
/// pair). wasm32 has no 64x64->128 multiply: a u128 product there is a `__multi3` call (a
/// full 128x128 multiply through the shadow stack), so it is built from four 32x32->64
/// `i64.mul`s instead (lane wasm-light; native code generation is unchanged).
inline fn mac(a: u64, b: u64, c: u64, d: u64) struct { u64, u64 } {
    if (comptime @import("builtin").cpu.arch.isWasm()) {
        const M: u64 = 0xffff_ffff;
        const a0 = a & M;
        const a1 = a >> 32;
        const b0 = b & M;
        const b1 = b >> 32;
        const p00 = a0 * b0;
        const p01 = a0 * b1;
        const p10 = a1 * b0;
        const p11 = a1 * b1;
        const mid = (p00 >> 32) + (p01 & M) + (p10 & M);
        const lo = (mid << 32) | (p00 & M);
        var hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
        const s1 = @addWithOverflow(lo, c);
        const s2 = @addWithOverflow(s1[0], d);
        hi += @as(u64, s1[1]) + s2[1];
        return .{ s2[0], hi };
    }
    const uv: u128 = @as(u128, a) * b + c + d;
    return .{ @truncate(uv), @truncate(uv >> 64) };
}

const is_wasm = @import("builtin").cpu.arch.isWasm();
const M32: u64 = 0xffff_ffff;

/// wasm32 schoolbook product on 32-bit digits: every 32x32 product is one native `i64.mul`,
/// and its halves go into u64 column sums (a column takes at most 4N + 2 values < 2^32, so it
/// cannot overflow); one carry pass at the end. `sqr` adds each off-diagonal product twice.
inline fn mulWide32(comptime N: usize, comptime sqr: bool, a: [N]u64, b: [N]u64) [2 * N]u64 {
    const D = 2 * N;
    var x: [D]u64 = undefined;
    var y: [D]u64 = undefined;
    inline for (0..N) |i| {
        x[2 * i] = a[i] & M32;
        x[2 * i + 1] = a[i] >> 32;
        y[2 * i] = b[i] & M32;
        y[2 * i + 1] = b[i] >> 32;
    }
    var col: [2 * D]u64 = @splat(0);
    if (sqr) {
        inline for (0..D) |i| {
            const d = x[i] * x[i];
            col[2 * i] += d & M32;
            col[2 * i + 1] += d >> 32;
            inline for (i + 1..D) |j| {
                const p = x[i] * x[j];
                col[i + j] += (p & M32) << 1;
                col[i + j + 1] += (p >> 32) << 1;
            }
        }
    } else {
        inline for (0..D) |i| inline for (0..D) |j| {
            const p = x[i] * y[j];
            col[i + j] += p & M32;
            col[i + j + 1] += p >> 32;
        };
    }
    var out: [2 * N]u64 = undefined;
    var carry: u64 = 0;
    inline for (0..N * 2) |k| {
        const v0 = col[2 * k] + carry;
        const v1 = col[2 * k + 1] + (v0 >> 32);
        out[k] = (v0 & M32) | (v1 << 32);
        carry = v1 >> 32;
    }
    return out;
}

/// wasm32 Montgomery reduction on 32-bit digits (same column scheme): T / 2^(64N) mod m as
/// N limbs in [0, 2m), for T < m * 2^(64N).
inline fn redc32(comptime N: usize, comptime P: [N]u64, comptime inv: u64, t: [2 * N]u64) [N]u64 {
    const D = 2 * N;
    const inv32: u64 = inv & M32; // -m^-1 mod 2^32
    const pd = comptime blk: {
        var d: [D]u64 = undefined;
        for (0..N) |i| {
            d[2 * i] = P[i] & M32;
            d[2 * i + 1] = P[i] >> 32;
        }
        break :blk d;
    };
    var col: [2 * D + 1]u64 = undefined;
    inline for (0..N * 2) |k| {
        col[2 * k] = t[k] & M32;
        col[2 * k + 1] = t[k] >> 32;
    }
    col[2 * D] = 0;
    inline for (0..D) |i| {
        const ti = col[i] & M32;
        col[i + 1] += col[i] >> 32;
        const m = (ti * inv32) & M32;
        col[i] = ti;
        inline for (0..D) |j| {
            const p = m * pd[j];
            col[i + j] += p & M32;
            col[i + j + 1] += p >> 32;
        }
        col[i + 1] += col[i] >> 32; // col[i] is now 0 mod 2^32
    }
    var r: [N]u64 = undefined;
    var carry: u64 = 0;
    inline for (0..N) |k| {
        const v0 = col[D + 2 * k] + carry;
        const v1 = col[D + 2 * k + 1] + (v0 >> 32);
        r[k] = (v0 & M32) | (v1 << 32);
        carry = v1 >> 32;
    }
    return r;
}


const builtin = @import("builtin");

/// x86-64 Montgomery kernel (blst's mulx_mont_384 shape): CIOS rows of `mulx` with two carry
/// chains (`adcx`/`adox`) when the target has ADX, one `adc` chain with BMI2 alone. The N+1
/// accumulator words live in registers and rotate names each row instead of moving; P and -1/P
/// are read from memory. LLVM only (Zig's own x86 backend has its own assembler). Results are
/// below 2m, the same bound as `mulRaw`, and equal to it (tests below).
const x86_mont = builtin.cpu.arch == .x86_64 and builtin.zig_backend == .stage2_llvm and
    std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2);
const x86_adx = x86_mont and std.Target.x86.featureSetHas(builtin.cpu.features, .adx);

const x86_wide_asm = true;
/// Big-integer add/sub for limb vectors (one adc/sbb chain on x86-64).
const big_carry = false;
const x86_redc_asm = true;
const x86_sqr_wide = false;

const x86m = struct {
    const fmt = std.fmt.comptimePrint;

    fn w(comptime n: usize, comptime base: usize, comptime j: usize) []const u8 {
        return fmt("%[t{d}]", .{(base + j) % (n + 1)});
    }

    /// acc[base .. base+n] += src * rdx (src: "a" or "p"); acc word base+n starts at 0.
    fn row(comptime n: usize, comptime base: usize, comptime src: []const u8, comptime adx: bool, comptime into_top: bool) []const u8 {
        comptime {
            @setEvalBranchQuota(1_000_000);
            var c: []const u8 = "";
            if (adx) {
                if (!into_top) c = c ++ fmt("xorq {s}, {s}\n", .{ w(n, base, n), w(n, base, n) }) else c = c ++ "xorq %[x], %[x]\n";
                for (0..n) |j| c = c ++ fmt(
                    \\mulxq {d}(%[{s}]), %[x], %[y]
                    \\adcxq %[x], {s}
                    \\adoxq %[y], {s}
                    \\
                , .{ 8 * j, src, w(n, base, j), w(n, base, j + 1) });
                c = c ++ fmt("movq $0, %[x]\nadcxq %[x], {s}\n", .{w(n, base, n)});
            } else {
                c = c ++ fmt(
                    \\mulxq (%[{s}]), %[x], %[y]
                    \\addq %[x], {s}
                    \\adcq $0, %[y]
                    \\
                , .{ src, w(n, base, 0) });
                for (1..n) |j| c = c ++ fmt(
                    \\addq %[y], {0s}
                    \\mulxq {1d}(%[{2s}]), %[x], %[y]
                    \\adcq $0, %[y]
                    \\addq %[x], {0s}
                    \\adcq $0, %[y]
                    \\
                , .{ w(n, base, j), 8 * j, src });
                if (into_top) {
                    c = c ++ fmt("addq %[y], {s}\n", .{w(n, base, n)});
                } else {
                    c = c ++ fmt("movq %[y], {s}\n", .{w(n, base, n)});
                }
            }
            return c;
        }
    }

    fn code(comptime n: usize, comptime adx: bool) []const u8 {
        comptime {
            @setEvalBranchQuota(1_000_000);
            // row 0: plain product a * b0 into t0..tn
            var c: []const u8 = "movq (%[b]), %%rdx\n";
            c = c ++ fmt("mulxq (%[a]), {s}, {s}\n", .{ w(n, 0, 0), w(n, 0, 1) });
            for (1..n) |j| c = c ++ fmt(
                \\mulxq {d}(%[a]), %[x], {s}
                \\{s} %[x], {s}
                \\
            , .{ 8 * j, w(n, 0, j + 1), if (j == 1) "addq" else "adcq", w(n, 0, j) });
            c = c ++ fmt("adcq $0, {s}\n", .{w(n, 0, n)});
            for (0..n) |i| {
                if (i > 0) {
                    c = c ++ fmt("movq {d}(%[b]), %%rdx\n", .{8 * i});
                    c = c ++ row(n, i, "a", adx, false);
                }
                // reduction: m = acc0 * inv, acc += m * P; acc0 becomes 0
                c = c ++ fmt("movq {s}, %%rdx\nimulq {d}(%[p]), %%rdx\n", .{ w(n, i, 0), 8 * n });
                c = c ++ row(n, i, "p", adx, true);
            }
            return c;
        }
    }

    /// Schoolbook 6x6 product to memory: the same rows as `code` without reductions; each row
    /// stores its finished low word and reuses that register as the next row's top word.
    fn wideCode(comptime n: usize, comptime adx: bool) []const u8 {
        comptime {
            @setEvalBranchQuota(1_000_000);
            var c: []const u8 = "movq (%[b]), %%rdx\n";
            c = c ++ fmt("mulxq (%[a]), {s}, {s}\n", .{ w(n, 0, 0), w(n, 0, 1) });
            for (1..n) |j| c = c ++ fmt(
                \\mulxq {d}(%[a]), %[x], {s}
                \\{s} %[x], {s}
                \\
            , .{ 8 * j, w(n, 0, j + 1), if (j == 1) "addq" else "adcq", w(n, 0, j) });
            c = c ++ fmt("adcq $0, {s}\nmovq {s}, (%[o])\n", .{ w(n, 0, n), w(n, 0, 0) });
            for (1..n) |i| {
                c = c ++ fmt("movq {d}(%[b]), %%rdx\n", .{8 * i});
                c = c ++ row(n, i, "a", adx, false);
                c = c ++ fmt("movq {s}, {d}(%[o])\n", .{ w(n, i, 0), 8 * i });
            }
            for (1..n + 1) |j| c = c ++ fmt("movq {s}, {d}(%[o])\n", .{ w(n, n - 1, j), 8 * (n - 1 + j) });
            return c;
        }
    }

    /// Montgomery reduction of a 2n-word T < m * 2^(64n) in memory: n rounds on the low half
    /// (T_lo + M P) / R <= P, then + T_hi (< m): the result is below 2m.
    fn redcCode(comptime n: usize, comptime adx: bool) []const u8 {
        comptime {
            @setEvalBranchQuota(1_000_000);
            var c: []const u8 = "";
            for (0..n) |j| c = c ++ fmt("movq {d}(%[a]), {s}\n", .{ 8 * j, w(n, 0, j) });
            if (!adx) c = c ++ fmt("xorq {s}, {s}\n", .{ w(n, 0, n), w(n, 0, n) });
            for (0..n) |i| {
                c = c ++ fmt("movq {s}, %%rdx\nimulq {d}(%[p]), %%rdx\n", .{ w(n, i, 0), 8 * n });
                // the top word is fresh: zero it (adx: the xor in `row`; else here, after the
                // first round, where it is the register the previous round emptied)
                if (!adx and i > 0) c = c ++ fmt("xorq {s}, {s}\n", .{ w(n, i, n), w(n, i, n) });
                c = c ++ row(n, i, "p", adx, !adx);
            }
            for (0..n) |j| c = c ++ fmt("{s} {d}(%[a]), {s}\n", .{ if (j == 0) "addq" else "adcq", 8 * (n + j), w(n, n, j) });
            return c;
        }
    }

    const wide6 = [2][]const u8{ wideCode(6, false), wideCode(6, true) };
    const redc6 = [2][]const u8{ redcCode(6, false), redcCode(6, true) };

    inline fn mulWide6(a: *const [6]u64, b: *const [6]u64) [12]u64 {
        var out: [12]u64 = undefined;
        var t0: u64 = undefined;
        var t1: u64 = undefined;
        var t2: u64 = undefined;
        var t3: u64 = undefined;
        var t4: u64 = undefined;
        var t5: u64 = undefined;
        var t6: u64 = undefined;
        var x: u64 = undefined;
        var y: u64 = undefined;
        asm volatile (wide6[@intFromBool(x86_adx)]
            : [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [t2] "=&r" (t2),
              [t3] "=&r" (t3),
              [t4] "=&r" (t4),
              [t5] "=&r" (t5),
              [t6] "=&r" (t6),
              [x] "=&r" (x),
              [y] "=&r" (y),
            : [a] "r" (a),
              [b] "r" (b),
              [o] "r" (&out),
            : .{ .rdx = true, .rflags = true, .memory = true });
        return out;
    }

    inline fn redc6x(tw: *const [12]u64, p: *const [7]u64) [6]u64 {
        var t0: u64 = undefined;
        var t1: u64 = undefined;
        var t2: u64 = undefined;
        var t3: u64 = undefined;
        var t4: u64 = undefined;
        var t5: u64 = undefined;
        var t6: u64 = undefined;
        var x: u64 = undefined;
        var y: u64 = undefined;
        asm volatile (redc6[@intFromBool(x86_adx)]
            : [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [t2] "=&r" (t2),
              [t3] "=&r" (t3),
              [t4] "=&r" (t4),
              [t5] "=&r" (t5),
              [t6] "=&r" (t6),
              [x] "=&r" (x),
              [y] "=&r" (y),
            : [a] "r" (tw),
              [p] "r" (p),
            : .{ .rdx = true, .rflags = true, .memory = true });
        const t = [_]u64{ t0, t1, t2, t3, t4, t5, t6 };
        var r: [6]u64 = undefined;
        inline for (0..6) |j| r[j] = t[(6 + j) % 7];
        return r;
    }

    const code6 = [2][]const u8{ code(6, false), code(6, true) };
    const code4 = [2][]const u8{ code(4, false), code(4, true) };

    inline fn mul6(a: *const [6]u64, b: *const [6]u64, p: *const [7]u64) [6]u64 {
        var t0: u64 = undefined;
        var t1: u64 = undefined;
        var t2: u64 = undefined;
        var t3: u64 = undefined;
        var t4: u64 = undefined;
        var t5: u64 = undefined;
        var t6: u64 = undefined;
        var x: u64 = undefined;
        var y: u64 = undefined;
        asm volatile (code6[@intFromBool(x86_adx)]
            : [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [t2] "=&r" (t2),
              [t3] "=&r" (t3),
              [t4] "=&r" (t4),
              [t5] "=&r" (t5),
              [t6] "=&r" (t6),
              [x] "=&r" (x),
              [y] "=&r" (y),
            : [a] "r" (a),
              [b] "r" (b),
              [p] "r" (p),
            : .{ .rdx = true, .rflags = true, .memory = true });
        const t = [_]u64{ t0, t1, t2, t3, t4, t5, t6 };
        var r: [6]u64 = undefined;
        inline for (0..6) |j| r[j] = t[(6 + j) % 7];
        return r;
    }

    inline fn mul4(a: *const [4]u64, b: *const [4]u64, p: *const [5]u64) [4]u64 {
        var t0: u64 = undefined;
        var t1: u64 = undefined;
        var t2: u64 = undefined;
        var t3: u64 = undefined;
        var t4: u64 = undefined;
        var x: u64 = undefined;
        var y: u64 = undefined;
        asm volatile (code4[@intFromBool(x86_adx)]
            : [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [t2] "=&r" (t2),
              [t3] "=&r" (t3),
              [t4] "=&r" (t4),
              [x] "=&r" (x),
              [y] "=&r" (y),
            : [a] "r" (a),
              [b] "r" (b),
              [p] "r" (p),
            : .{ .rdx = true, .rflags = true, .memory = true });
        const t = [_]u64{ t0, t1, t2, t3, t4 };
        var r: [4]u64 = undefined;
        inline for (0..4) |j| r[j] = t[(4 + j) % 5];
        return r;
    }
};


/// AArch64 Montgomery product for the 6-limb field (blst's mul_mont_384 shape): a global asm
/// function with fixed registers, so all 28 values stay in registers. Each CIOS row is six
/// `mul` and six `umulh` added in two `adds`/`adcs` chains (LLVM's u128 form uses an
/// `adds`/`cinc` pair per product and twice the instructions): 22.1 against 24.2 ns on an M5
/// Pro. Wide products and reductions stay portable: as calls they lose to the inlined code
/// (25.2 against 23.0 ns for mulWide + redc). Results equal `mulRaw` (tests).
const arm_mont = builtin.cpu.arch == .aarch64 and builtin.zig_backend == .stage2_llvm;

const arm = struct {
    const fmt = std.fmt.comptimePrint;
    const pre = if (builtin.os.tag.isDarwin()) "_" else "";
    const A = [6][]const u8{ "x4", "x5", "x6", "x7", "x8", "x9" };
    const T = [7][]const u8{ "x10", "x11", "x12", "x13", "x14", "x15", "x16" };
    const U = [6][]const u8{ "x19", "x20", "x21", "x22", "x23", "x24" };

    fn t(comptime base: usize, comptime j: usize) []const u8 {
        return T[(base + j) % 7];
    }

    /// acc[base..base+6] += src * k: low products into words 0..5, high into 1..6.
    /// `fresh`: the top word starts from the carry (it holds garbage or zero); else it is added.
    fn row(comptime base: usize, comptime src: [6][]const u8, comptime k: []const u8, comptime fresh: bool) []const u8 {
        comptime {
            var c: []const u8 = "";
            for (0..6) |j| c = c ++ fmt("mul {s}, {s}, {s}\n", .{ U[j], src[j], k });
            for (0..6) |j| c = c ++ fmt("{s} {s}, {s}, {s}\n", .{ if (j == 0) "adds" else "adcs", t(base, j), t(base, j), U[j] });
            c = c ++ (if (fresh) fmt("adc {s}, xzr, xzr\n", .{t(base, 6)}) else fmt("adc {s}, {s}, xzr\n", .{ t(base, 6), t(base, 6) }));
            for (0..6) |j| c = c ++ fmt("umulh {s}, {s}, {s}\n", .{ U[j], src[j], k });
            for (0..5) |j| c = c ++ fmt("{s} {s}, {s}, {s}\n", .{ if (j == 0) "adds" else "adcs", t(base, j + 1), t(base, j + 1), U[j] });
            c = c ++ fmt("adc {s}, {s}, {s}\n", .{ t(base, 6), t(base, 6), U[5] });
            return c;
        }
    }

    /// Conditional subtraction of P (registers `pr`) from the result at `base`, stored to [x0].
    fn finish(comptime base: usize, comptime pr: [6][]const u8) []const u8 {
        comptime {
            var c: []const u8 = "";
            for (0..6) |j| c = c ++ fmt("{s} {s}, {s}, {s}\n", .{ if (j == 0) "subs" else "sbcs", U[j], t(base, j), pr[j] });
            for (0..6) |j| c = c ++ fmt("csel {s}, {s}, {s}, lo\n", .{ U[j], t(base, j), U[j] });
            c = c ++ fmt("stp {s}, {s}, [x0]\nstp {s}, {s}, [x0, #16]\nstp {s}, {s}, [x0, #32]\n", .{ U[0], U[1], U[2], U[3], U[4], U[5] });
            return c;
        }
    }

    const save =
        \\stp x19, x20, [sp, #-96]!
        \\stp x21, x22, [sp, #16]
        \\stp x23, x24, [sp, #32]
        \\stp x25, x26, [sp, #48]
        \\stp x27, x28, [sp, #64]
        \\str x30, [sp, #80]
        \\
    ;
    const restore =
        \\ldp x21, x22, [sp, #16]
        \\ldp x23, x24, [sp, #32]
        \\ldp x25, x26, [sp, #48]
        \\ldp x27, x28, [sp, #64]
        \\ldr x30, [sp, #80]
        \\ldp x19, x20, [sp], #96
        \\ret
        \\
    ;

    fn head(comptime name: []const u8) []const u8 {
        return fmt(".text\n.globl {0s}{1s}\n.p2align 4\n{0s}{1s}:\n", .{ pre, name });
    }

    /// r = a b / R (x0 = r, x1 = a, x2 = b, x3 = P followed by -1/P).
    const P_mul = [6][]const u8{ "x25", "x26", "x27", "x28", "x1", "x30" };
    const mul_code = blk: {
        @setEvalBranchQuota(1_000_000);
        var c: []const u8 = head("zui_bls_fp_mont_mul") ++ save ++
            \\ldp x4, x5, [x1]
            \\ldp x6, x7, [x1, #16]
            \\ldp x8, x9, [x1, #32]
            \\ldp x25, x26, [x3]
            \\ldp x27, x28, [x3, #16]
            \\ldp x1, x30, [x3, #32]
            \\ldr x3, [x3, #48]
            \\ldr x17, [x2]
            \\
        ;
        for (0..6) |j| c = c ++ fmt("mul {s}, {s}, x17\n", .{ T[j], A[j] });
        for (0..6) |j| c = c ++ fmt("umulh {s}, {s}, x17\n", .{ U[j], A[j] });
        for (0..5) |j| c = c ++ fmt("{s} {s}, {s}, {s}\n", .{ if (j == 0) "adds" else "adcs", T[j + 1], T[j + 1], U[j] });
        c = c ++ fmt("adc {s}, {s}, xzr\n", .{ T[6], U[5] });
        for (0..6) |i| {
            if (i > 0) {
                c = c ++ fmt("ldr x17, [x2, #{d}]\n", .{8 * i});
                c = c ++ row(i, A, "x17", true);
            }
            c = c ++ fmt("mul x17, {s}, x3\n", .{t(i, 0)});
            c = c ++ row(i, P_mul, "x17", false);
        }
        break :blk c ++ finish(6, P_mul) ++ restore;
    };

    comptime {
        if (arm_mont) asm (mul_code);
    }

    extern fn zui_bls_fp_mont_mul(r: *[6]u64, a: *const [6]u64, b: *const [6]u64, p: *const [7]u64) callconv(.c) void;
};

pub fn MontField(comptime N: usize, comptime modulus: @Int(.unsigned, 64 * N)) type {
    return struct {
        l: [N]u64,

        const Self = @This();
        pub const Limbs = [N]u64;
        pub const Int = @Int(.unsigned, 64 * N);
        const Wide = @Int(.unsigned, 128 * N + 1);
        pub const bytes_len = 8 * N;

        pub const P: Limbs = toLimbs(modulus);
        /// -m^-1 mod 2^64.
        pub const INV: u64 = blk: {
            var x: u64 = 1;
            for (0..6) |_| x *%= 2 -% P[0] *% x; // Newton: inv = P0^-1 mod 2^64
            break :blk 0 -% x;
        };
        const R2: Limbs = toLimbs(@intCast((@as(Wide, 1) << (128 * N)) % modulus));
        pub const zero: Self = .{ .l = @splat(0) };
        pub const one: Self = .{ .l = toLimbs(@intCast((@as(Wide, 1) << (64 * N)) % modulus)) };
        /// (m - 1) / 2, canonical, for the "sign" (lexicographically largest) test.
        const half: Limbs = toLimbs((modulus - 1) / 2);

        comptime {
            std.debug.assert(P[N - 1] < (1 << 63) - 1); // no-carry CIOS precondition
        }

        fn toLimbs(x: Int) Limbs {
            var out: Limbs = undefined;
            for (0..N) |i| out[i] = @truncate(x >> @intCast(64 * i));
            return out;
        }

        /// Comptime constant from its canonical integer value.
        pub fn fromInt(comptime x: Int) Self {
            const limbs = comptime blk: {
                std.debug.assert(x < modulus);
                break :blk toLimbs(@intCast((@as(Wide, x) << (64 * N)) % modulus));
            };
            return .{ .l = limbs };
        }

        /// Canonical value as an integer (tests, tooling).
        pub fn toInt(a: Self) Int {
            const c = a.fromMont();
            var x: Int = 0;
            for (0..N) |i| x |= @as(Int, c[i]) << @intCast(64 * i);
            return x;
        }

        pub fn fromU64(x: u64) Self {
            var raw: Limbs = @splat(0);
            raw[0] = x;
            return mulRaw(raw, R2);
        }

        // ---------------------------------------------------------------------------------
        // limb primitives

        // Limb vectors are little-endian, so a [N]u64 bit-casts to the N*64-bit integer; LLVM
        // lowers big-integer add/sub to one carry chain (the per-limb @addWithOverflow form
        // became setc/or sequences on x86).
        // (x86-64 only: on AArch64 the per-limb form is the faster one.)
        inline fn subLimbs(a: Limbs, b: Limbs) struct { Limbs, u64 } {
            if (comptime big_carry) {
                const d = @subWithOverflow(@as(Int, @bitCast(a)), @as(Int, @bitCast(b)));
                return .{ @bitCast(d[0]), d[1] };
            }
            var r: Limbs = undefined;
            var borrow: u64 = 0;
            inline for (0..N) |i| {
                const d1 = @subWithOverflow(a[i], b[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                r[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            return .{ r, borrow };
        }

        inline fn addLimbs(a: Limbs, b: Limbs) struct { Limbs, u64 } {
            if (comptime big_carry) {
                const r = @addWithOverflow(@as(Int, @bitCast(a)), @as(Int, @bitCast(b)));
                return .{ @bitCast(r[0]), r[1] };
            }
            var r: Limbs = undefined;
            var carry: u64 = 0;
            inline for (0..N) |i| {
                const s1 = @addWithOverflow(a[i], b[i]);
                const s2 = @addWithOverflow(s1[0], carry);
                r[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            return .{ r, carry };
        }

        /// t in [0, 2m) -> t mod m.
        inline fn reduceOnce(t: Limbs) Self {
            const s = subLimbs(t, P);
            const mask = 0 -% s[1]; // all ones when t < m (keep t)
            var r: Limbs = undefined;
            inline for (0..N) |i| r[i] = (t[i] & mask) | (s[0][i] & ~mask);
            return .{ .l = r };
        }

        /// Montgomery product a*b/R mod m of raw limbs, a and b < m.
        inline fn mulRaw(a: Limbs, b: Limbs) Self {
            @setEvalBranchQuota(20000); // comptime callers (constants, tests) through `mac`
            var t: Limbs = @splat(0);
            inline for (0..N) |i| {
                var uv = mac(a[0], b[i], t[0], 0);
                var A: u64 = uv[1];
                t[0] = uv[0];
                const m: u64 = t[0] *% INV;
                uv = mac(m, P[0], t[0], 0);
                var C: u64 = uv[1];
                inline for (1..N) |j| {
                    uv = mac(a[j], b[i], t[j], A);
                    A = uv[1];
                    t[j] = uv[0];
                    uv = mac(m, P[j], t[j], C);
                    C = uv[1];
                    t[j - 1] = uv[0];
                }
                t[N - 1] = C +% A;
            }
            return reduceOnce(t);
        }

        // ---------------------------------------------------------------------------------
        // double-width products (lazy reduction)

        pub const WideLimbs = [2 * N]u64;

        /// Full 2N-limb product of raw limbs (no reduction).
        pub inline fn mulWide(a: Limbs, b: Limbs) WideLimbs {
            @setEvalBranchQuota(20000); // comptime callers (constants, tests) through `mac`
            if (comptime is_wasm) return mulWide32(N, false, a, b);
            if (comptime use_x86 and N == 6 and x86_wide_asm) if (!@inComptime()) return x86m.mulWide6(&a, &b);
            return mulWideGeneric(a, b);
        }

        inline fn mulWideGeneric(a: Limbs, b: Limbs) WideLimbs {
            @setEvalBranchQuota(20000);
            var t: WideLimbs = @splat(0);
            inline for (0..N) |i| {
                var carry: u64 = 0;
                inline for (0..N) |j| {
                    const uv = mac(a[j], b[i], t[i + j], carry);
                    t[i + j] = uv[0];
                    carry = uv[1];
                }
                t[i + N] = carry;
            }
            return t;
        }

        /// Full 2N-limb square of raw limbs: off-diagonal products once, doubled, plus the
        /// diagonal (N(N+1)/2 limb products instead of N^2).
        pub inline fn sqrWide(a: Limbs) WideLimbs {
            @setEvalBranchQuota(20000); // comptime callers (constants, tests) through `mac`
            if (comptime is_wasm) return mulWide32(N, true, a, a);
            var t: WideLimbs = @splat(0);
            inline for (0..N - 1) |i| {
                var carry: u64 = 0;
                inline for (i + 1..N) |j| {
                    const uv = mac(a[j], a[i], t[i + j], carry);
                    t[i + j] = uv[0];
                    carry = uv[1];
                }
                t[i + N] = carry;
            }
            var top: u64 = 0;
            inline for (0..2 * N) |k| {
                const nt = (t[k] << 1) | top;
                top = t[k] >> 63;
                t[k] = nt;
            }
            var carry: u64 = 0;
            inline for (0..N) |i| {
                const sq = mac(a[i], a[i], 0, 0);
                const lo = @addWithOverflow(t[2 * i], sq[0]);
                const lo2 = @addWithOverflow(lo[0], carry);
                t[2 * i] = lo2[0];
                const c1: u64 = lo[1] | lo2[1];
                const hi = @addWithOverflow(t[2 * i + 1], sq[1]);
                const hi2 = @addWithOverflow(hi[0], c1);
                t[2 * i + 1] = hi2[0];
                carry = hi[1] | hi2[1];
            }
            return t;
        }

        /// Montgomery reduction of T < m * 2^(64N): T / 2^(64N) mod m, fully reduced.
        pub inline fn redc(t_in: WideLimbs) Self {
            @setEvalBranchQuota(20000); // comptime callers (constants, tests) through `mac`
            if (comptime is_wasm) return reduceOnce(redc32(N, P, INV, t_in));
            if (comptime use_x86 and N == 6 and x86_redc_asm) if (!@inComptime()) return reduceOnce(x86m.redc6x(&t_in, &p_inv));
            return redcGeneric(t_in);
        }

        inline fn redcGeneric(t_in: WideLimbs) Self {
            @setEvalBranchQuota(20000);
            var t = t_in;
            var c2: u64 = 0;
            inline for (0..N) |i| {
                const m: u64 = t[i] *% INV;
                var carry: u64 = 0;
                inline for (0..N) |j| {
                    const uv = mac(m, P[j], t[i + j], carry);
                    t[i + j] = uv[0];
                    carry = uv[1];
                }
                const s1 = @addWithOverflow(t[i + N], carry);
                const s2 = @addWithOverflow(s1[0], c2);
                t[i + N] = s2[0];
                c2 = s1[1] | s2[1];
            }
            var r: Limbs = undefined;
            inline for (0..N) |i| r[i] = t[N + i];
            return reduceOnce(r);
        }

        const WInt = @Int(.unsigned, 128 * N);

        inline fn wAdd(a: WideLimbs, b: WideLimbs) struct { WideLimbs, u64 } {
            @setEvalBranchQuota(100_000);
            if (comptime big_carry) {
                const r = @addWithOverflow(@as(WInt, @bitCast(a)), @as(WInt, @bitCast(b)));
                return .{ @bitCast(r[0]), r[1] };
            }
            var r: WideLimbs = undefined;
            var carry: u64 = 0;
            inline for (0..2 * N) |i| {
                const s1 = @addWithOverflow(a[i], b[i]);
                const s2 = @addWithOverflow(s1[0], carry);
                r[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            return .{ r, carry };
        }

        inline fn wSub(a: WideLimbs, b: WideLimbs) struct { WideLimbs, u64 } {
            @setEvalBranchQuota(100_000);
            if (comptime big_carry) {
                const d = @subWithOverflow(@as(WInt, @bitCast(a)), @as(WInt, @bitCast(b)));
                return .{ @bitCast(d[0]), d[1] };
            }
            var r: WideLimbs = undefined;
            var borrow: u64 = 0;
            inline for (0..2 * N) |i| {
                const d1 = @subWithOverflow(a[i], b[i]);
                const d2 = @subWithOverflow(d1[0], borrow);
                r[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            return .{ r, borrow };
        }

        inline fn wMask(m: u64, x: WideLimbs) WideLimbs {
            @setEvalBranchQuota(100_000);
            var r: WideLimbs = undefined;
            inline for (0..2 * N) |i| r[i] = x[i] & m;
            return r;
        }

        inline fn wSelect(m: u64, x: WideLimbs, y: WideLimbs) WideLimbs {
            @setEvalBranchQuota(100_000);
            var r: WideLimbs = undefined;
            inline for (0..2 * N) |i| r[i] = (x[i] & m) | (y[i] & ~m);
            return r;
        }

        pub inline fn addWide(a: WideLimbs, b: WideLimbs) WideLimbs {
            return wAdd(a, b)[0];
        }

        /// a - b for wide values, plus m^2 when that borrows (constant time). For a, b < m^2
        /// the result is in [0, m^2) and congruent to a - b.
        pub inline fn subWideModM2(a: WideLimbs, b: WideLimbs) WideLimbs {
            const d = wSub(a, b);
            return wAdd(d[0], wMask(0 -% d[1], P2))[0];
        }

        /// a - b for wide values when a >= b is known.
        pub inline fn subWide(a: WideLimbs, b: WideLimbs) WideLimbs {
            return wSub(a, b)[0];
        }

        const P2: WideLimbs = blk: {
            const sq: @Int(.unsigned, 128 * N) = @as(@Int(.unsigned, 128 * N), modulus) * modulus;
            var out: WideLimbs = undefined;
            for (0..2 * N) |i| out[i] = @truncate(sq >> @intCast(64 * i));
            break :blk out;
        };

        // Wide values modulo m * 2^(64N) (blst's add_mod_384x384 / sub_mod_384x384): kept in
        // [0, m R), the range Montgomery reduction accepts, by fixing only the top N limbs.

        const MR: WideLimbs = blk: {
            var out: WideLimbs = @splat(0);
            for (0..N) |i| out[N + i] = P[i];
            break :blk out;
        };

        /// a + b mod m R, for a, b in [0, m R).
        pub inline fn addWideModMR(a: WideLimbs, b: WideLimbs) WideLimbs {
            const r = wAdd(a, b)[0]; // < 2 m R: no wrap
            const d = wSub(r, MR);
            return wSelect(0 -% d[1], r, d[0]); // borrow: r < m R, keep it
        }

        /// a - b mod m R, for a, b in [0, m R).
        pub inline fn subWideModMR(a: WideLimbs, b: WideLimbs) WideLimbs {
            const d = wSub(a, b);
            return wAdd(d[0], wMask(0 -% d[1], MR))[0];
        }

        /// a + m - b without reduction (a, b < m): in (0, 2m), congruent to a - b.
        pub inline fn subRawPlusM(a: Self, b: Self) Limbs {
            const s = addLimbs(a.l, P)[0];
            return subLimbs(s, b.l)[0];
        }

        /// a + b without reduction (a, b < m, result < 2m < 2^(64N)).
        pub inline fn addRaw(a: Self, b: Self) Limbs {
            return addLimbs(a.l, b.l)[0];
        }

        /// a^-1 by a binary extended Euclid in variable time: for public values only.
        /// 0 maps to 0.
        pub fn invVartime(a: Self) Self {
            if (a.isZero()) return zero;
            // Work on the Montgomery representative x = aR: compute x^-1 mod m, then
            // a^-1 R = (x^-1) * R^2 needs two R factors: mulRaw(x^-1, R3) = x^-1 R^3 / R = a^-1 R.
            var u: Int = 0;
            inline for (0..N) |i| u |= @as(Int, a.l[i]) << (64 * i);
            var v: Int = modulus;
            var x1: Int = 1;
            var x2: Int = 0;
            // invariant: x1 * aR = u, x2 * aR = v (mod m); x1, x2 in [0, m)
            while (u != 1 and v != 1) {
                while (u & 1 == 0) {
                    u >>= 1;
                    x1 = if (x1 & 1 == 0) x1 >> 1 else @intCast((@as(@Int(.unsigned, 64 * N + 1), x1) + modulus) >> 1);
                }
                while (v & 1 == 0) {
                    v >>= 1;
                    x2 = if (x2 & 1 == 0) x2 >> 1 else @intCast((@as(@Int(.unsigned, 64 * N + 1), x2) + modulus) >> 1);
                }
                if (u >= v) {
                    u -= v;
                    x1 = if (x1 >= x2) x1 - x2 else x1 + (modulus - x2);
                } else {
                    v -= u;
                    x2 = if (x2 >= x1) x2 - x1 else x2 + (modulus - x1);
                }
            }
            const r: Int = if (u == 1) x1 else x2; // (aR)^-1 mod m
            return mulRaw(toLimbs(r), R3);
        }

        const R3: Limbs = toLimbs(@intCast((@as(@Int(.unsigned, 192 * N + 1), 1) << (192 * N)) % modulus));

        // ---------------------------------------------------------------------------------
        // arithmetic

        /// Fused CIOS Montgomery product.
        pub fn mul(a: Self, b: Self) Self {
            if (comptime is_wasm) return redc(mulWide(a.l, b.l));
            if (comptime use_x86) if (!@inComptime()) return reduceOnce(x86Mul(&a.l, &b.l));
            if (comptime use_arm) if (!@inComptime()) {
                var r: Self = undefined;
                arm.zui_bls_fp_mont_mul(&r.l, &a.l, &b.l, &p_inv);
                return r;
            };
            return mulRaw(a.l, b.l);
        }

        /// Dedicated squaring: 21 instead of 36 limb products for Fp (19.8 vs 24.3 ns). On x86
        /// with BMI2 the mulx kernel squares faster than the portable square.
        pub fn sqr(a: Self) Self {
            if (comptime use_x86 and !x86_sqr_wide) if (!@inComptime()) return reduceOnce(x86Mul(&a.l, &a.l));
            return redc(sqrWide(a.l));
        }

        pub const use_x86 = x86_mont and (N == 6 or N == 4);
        pub const use_arm = arm_mont and N == 6;
        /// P followed by -1/P mod 2^64, for the x86 kernel.
        const p_inv: [N + 1]u64 = P ++ [1]u64{INV};

        inline fn x86Mul(a: *const Limbs, b: *const Limbs) Limbs {
            return if (N == 6) x86m.mul6(a, b, &p_inv) else x86m.mul4(a, b, &p_inv);
        }

        /// Portable wide product and reduction (tests compare the x86 kernels with them).
        pub fn mulWidePortable(a: Limbs, b: Limbs) WideLimbs {
            return @call(.always_inline, mulWideGeneric, .{ a, b });
        }
        pub fn redcPortable(t: WideLimbs) Self {
            return @call(.always_inline, redcGeneric, .{t});
        }

        /// The portable CIOS product (tests compare the x86 kernel with it).
        pub fn mulPortable(a: Self, b: Self) Self {
            return mulRaw(a.l, b.l);
        }

        pub inline fn add(a: Self, b: Self) Self {
            const s = addLimbs(a.l, b.l); // < 2m < 2^(64N): no carry out
            return reduceOnce(s[0]);
        }

        pub inline fn sub(a: Self, b: Self) Self {
            const d = subLimbs(a.l, b.l);
            const mask = 0 -% d[1];
            var pm: Limbs = undefined;
            inline for (0..N) |i| pm[i] = P[i] & mask;
            return .{ .l = addLimbs(d[0], pm)[0] };
        }

        pub inline fn dbl(a: Self) Self {
            return a.add(a);
        }

        pub inline fn neg(a: Self) Self {
            return zero.sub(a);
        }

        /// 3a, 4a, 8a: for curve formulas.
        pub inline fn mul3(a: Self) Self {
            return a.dbl().add(a);
        }

        pub inline fn isZero(a: Self) bool {
            var acc: u64 = 0;
            inline for (0..N) |i| acc |= a.l[i];
            return acc == 0;
        }

        pub inline fn eql(a: Self, b: Self) bool {
            var acc: u64 = 0;
            inline for (0..N) |i| acc |= a.l[i] ^ b.l[i];
            return acc == 0;
        }

        /// c ? b : a, constant time.
        pub inline fn select(c: bool, b: Self, a: Self) Self {
            const mask = 0 -% @as(u64, @intFromBool(c));
            var r: Limbs = undefined;
            inline for (0..N) |i| r[i] = (b.l[i] & mask) | (a.l[i] & ~mask);
            return .{ .l = r };
        }

        pub inline fn condNeg(a: Self, c: bool) Self {
            return select(c, a.neg(), a);
        }

        pub inline fn fromMont(a: Self) Limbs {
            var one_raw: Limbs = @splat(0);
            one_raw[0] = 1;
            return mulRaw(a.l, one_raw).l;
        }

        /// Parity of the canonical value (RFC 9380 sgn0 for a prime field).
        pub fn sgn0(a: Self) bool {
            return a.fromMont()[0] & 1 == 1;
        }

        /// Canonical value > (m - 1) / 2 (the ZCash/blst compressed-point sign).
        pub fn isLexLargest(a: Self) bool {
            const d = subLimbs(half, a.fromMont());
            return d[1] == 1;
        }

        /// a^e for an exponent given as comptime limbs (the exponent is public: time depends
        /// only on it, never on `a`). Sliding window of 5 bits over a table of the 16 odd
        /// powers, the schedule built at compile time: about 63 multiplies for a 380-bit
        /// exponent instead of the 4-bit fixed window's 95.
        pub fn powLimbs(a: Self, comptime e: anytype) Self {
            const steps = comptime windowSteps(e);
            var table: [16]Self = undefined;
            oddPowers(a, &table);
            var acc = table[steps[0].idx];
            for (steps[1..]) |st| {
                for (0..st.sq) |_| acc = acc.sqr();
                if (st.idx != no_mul) acc = acc.mul(table[st.idx]);
            }
            return acc;
        }

        /// `powLimbs` of two independent bases with the same exponent, the two chains
        /// interleaved so the CPU overlaps their multiplications.
        pub fn powLimbs2(a: Self, b: Self, comptime e: anytype) [2]Self {
            const steps = comptime windowSteps(e);
            var ta: [16]Self = undefined;
            var tb: [16]Self = undefined;
            oddPowers2(a, b, &ta, &tb);
            var x = ta[steps[0].idx];
            var y = tb[steps[0].idx];
            for (steps[1..]) |st| {
                for (0..st.sq) |_| {
                    x = x.sqr();
                    y = y.sqr();
                }
                if (st.idx != no_mul) {
                    x = x.mul(ta[st.idx]);
                    y = y.mul(tb[st.idx]);
                }
            }
            return .{ x, y };
        }

        const no_mul = 0xff;
        const Step = struct { sq: u16, idx: u8 };

        /// table[i] = a^(2i + 1).
        inline fn oddPowers(a: Self, table: *[16]Self) void {
            const a2 = a.sqr();
            table[0] = a;
            for (1..16) |i| table[i] = table[i - 1].mul(a2);
        }

        inline fn oddPowers2(a: Self, b: Self, ta: *[16]Self, tb: *[16]Self) void {
            const a2 = a.sqr();
            const b2 = b.sqr();
            ta[0] = a;
            tb[0] = b;
            for (1..16) |i| {
                ta[i] = ta[i - 1].mul(a2);
                tb[i] = tb[i - 1].mul(b2);
            }
        }

        /// Left-to-right sliding-window schedule: the first step loads table[idx]; each later
        /// step squares `sq` times, then multiplies by table[idx] unless idx is `no_mul`.
        fn windowSteps(comptime e: anytype) []const Step {
            comptime {
                @setEvalBranchQuota(200_000);
                const w = 5;
                const nbits = 64 * e.len;
                const bitAt = struct {
                    fn f(i: usize) u1 {
                        return @intCast((e[i / 64] >> @intCast(i % 64)) & 1);
                    }
                }.f;
                var top: isize = nbits - 1;
                while (top >= 0 and bitAt(top) == 0) top -= 1;
                std.debug.assert(top >= 0);
                var steps: []const Step = &.{};
                var pending: u16 = 0;
                var i: isize = top;
                var first = true;
                while (i >= 0) {
                    if (bitAt(i) == 0) {
                        pending += 1;
                        i -= 1;
                        continue;
                    }
                    var j: isize = @max(i - (w - 1), 0);
                    while (bitAt(j) == 0) j += 1;
                    var v: usize = 0;
                    var k: isize = i;
                    while (k >= j) : (k -= 1) v = 2 * v + bitAt(k);
                    const len: u16 = @intCast(i - j + 1);
                    if (first) {
                        steps = steps ++ [1]Step{.{ .sq = 0, .idx = @intCast(v >> 1) }};
                        first = false;
                    } else {
                        steps = steps ++ [1]Step{.{ .sq = pending + len, .idx = @intCast(v >> 1) }};
                    }
                    pending = 0;
                    i = j - 1;
                }
                if (pending > 0) steps = steps ++ [1]Step{.{ .sq = pending, .idx = no_mul }};
                const out = steps[0..steps.len].*;
                return &out;
            }
        }

        fn expLimbs(comptime x: Int) Limbs {
            return toLimbs(x);
        }

        /// a^-1 (Fermat), 0 maps to 0.
        pub fn inv(a: Self) Self {
            return a.powLimbs(comptime expLimbs(modulus - 2));
        }

        // ---------------------------------------------------------------------------------
        // bytes

        /// Big-endian canonical bytes; null when the value is not below the modulus.
        pub fn fromBytesBE(b: *const [bytes_len]u8) ?Self {
            var raw: Limbs = undefined;
            inline for (0..N) |i| raw[i] = std.mem.readInt(u64, b[bytes_len - 8 * (i + 1) ..][0..8], .big);
            if (subLimbs(raw, P)[1] == 0) return null;
            return mulRaw(raw, R2);
        }

        /// Big-endian bytes, reduced mod m first (any 8N-byte input).
        pub fn fromBytesBEReduce(b: *const [bytes_len]u8) Self {
            var raw: Limbs = undefined;
            inline for (0..N) |i| raw[i] = std.mem.readInt(u64, b[bytes_len - 8 * (i + 1) ..][0..8], .big);
            // raw < 2^(64N). Fr: 2^256 < 3r, so this reduces fully. Fp: 2^384 < 10p, so raw can
            // stay at most 2p - 1 after 8 subtractions; mulRaw(raw, R2) still returns the fully
            // reduced residue (every CIOS intermediate stays below raw + p < 2^384 and the result
            // below 2p, which the final conditional subtraction handles).
            inline for (0..8) |_| {
                const s = subLimbs(raw, P);
                const keep = 0 -% s[1];
                inline for (0..N) |i| raw[i] = (raw[i] & keep) | (s[0][i] & ~keep);
            }
            return mulRaw(raw, R2);
        }

        pub fn toBytesBE(a: Self) [bytes_len]u8 {
            const c = a.fromMont();
            var out: [bytes_len]u8 = undefined;
            inline for (0..N) |i| std.mem.writeInt(u64, out[bytes_len - 8 * (i + 1) ..][0..8], c[i], .big);
            return out;
        }

        /// Value of raw limbs (any value < m) times R^-1 * R: i.e. Montgomery form of `raw`.
        pub inline fn fromRaw(raw: Limbs) Self {
            return mulRaw(raw, R2);
        }

        /// Montgomery product of raw limbs and a Montgomery constant: raw * c (as residues),
        /// returned in Montgomery form when `c` holds K*R^2.
        pub inline fn mulRawBy(raw: Limbs, c: Limbs) Self {
            return mulRaw(raw, c);
        }

        /// (k * R^2) mod m as raw limbs, for `mulRawBy`.
        pub fn rawTimesR2(comptime k: Int) Limbs {
            comptime {
                const R2int = (@as(Wide, 1) << (128 * N)) % modulus;
                return toLimbs(@intCast((@as(Wide, k) * R2int) % modulus));
            }
        }
    };
}

pub const p_int: u384 = @import("consts.zig").p;
pub const r_int: u256 = @import("consts.zig").r;

/// Base field of BLS12-381.
pub const Fp = MontField(6, p_int);

pub const Fr = MontField(4, r_int);

test "fp basics" {
    const F = Fp;
    const a = F.fromInt(12345);
    const b = F.fromInt(p_int - 2);
    try std.testing.expectEqual(@as(u384, 12343), a.add(b).toInt());
    try std.testing.expectEqual(@as(u384, 12347), a.sub(b).toInt());
    try std.testing.expect(a.mul(a.inv()).eql(F.one));
    try std.testing.expectEqual(@as(u384, p_int - 24690), a.mul(b).toInt());
    var prng = std.Random.DefaultPrng.init(1);
    for (0..200) |_| {
        var bytes: [48]u8 = undefined;
        prng.random().bytes(&bytes);
        const x = F.fromBytesBEReduce(&bytes);
        const y = F.fromBytesBEReduce(&bytes);
        try std.testing.expect(x.eql(y));
        try std.testing.expectEqual(std.mem.readInt(u384, &bytes, .big) % p_int, x.toInt());
        const xi: u384 = x.toInt();
        const sq: u768 = @as(u768, xi) * xi % p_int;
        try std.testing.expectEqual(@as(u384, @intCast(sq)), x.sqr().toInt());
        if (!x.isZero()) try std.testing.expect(x.mul(x.inv()).eql(F.one));
        try std.testing.expect(F.fromBytesBE(&x.toBytesBE()).?.eql(x));
    }
}

test "wide products agree with Montgomery multiplication" {
    var prng = std.Random.DefaultPrng.init(3);
    for (0..500) |_| {
        var b: [48]u8 = undefined;
        prng.random().bytes(&b);
        const x = Fp.fromBytesBEReduce(&b);
        prng.random().bytes(&b);
        const y = Fp.fromBytesBEReduce(&b);
        try std.testing.expect(Fp.redc(Fp.mulWide(x.l, y.l)).eql(x.mul(y)));
        try std.testing.expect(Fp.redc(Fp.sqrWide(x.l)).eql(x.sqr()));
        try std.testing.expect(Fp.redc(Fp.sqrWide(x.l)).eql(Fp.redc(Fp.mulWide(x.l, x.l))));
    }
    // reduction of the largest inputs: all-ones bytes (about 9.8p for Fp, 2.2r for Fr)
    const ff: [48]u8 = @splat(0xff);
    try std.testing.expectEqual(std.math.maxInt(u384) % p_int, Fp.fromBytesBEReduce(&ff).toInt());
    try std.testing.expectEqual(std.math.maxInt(u256) % r_int, Fr.fromBytesBEReduce(ff[0..32]).toInt());
    // the largest canonical value
    const m1 = Fp.zero.sub(Fp.one);
    try std.testing.expect(Fp.redc(Fp.sqrWide(m1.l)).eql(m1.sqr()));
}

test "asm Montgomery kernels equal the portable CIOS product" {
    var prng = std.Random.DefaultPrng.init(0x5eed_b15);
    const rnd = prng.random();
    inline for (.{ Fp, Fr }) |F| {
        const edge = [_]F{ F.zero, F.one, F.one.neg(), F.zero.sub(F.one.dbl()) };
        for (0..20000) |k| {
            var a: F = undefined;
            var b: F = undefined;
            if (k < edge.len * edge.len) {
                a = edge[k % edge.len];
                b = edge[k / edge.len];
            } else {
                var raw: F.Limbs = undefined;
                for (&raw) |*l| l.* = rnd.int(u64);
                raw[raw.len - 1] &= F.P[raw.len - 1];
                a = F.mulPortable(.{ .l = raw }, F.one);
                for (&raw) |*l| l.* = rnd.int(u64);
                raw[raw.len - 1] &= F.P[raw.len - 1];
                b = F.mulPortable(.{ .l = raw }, F.one);
                // keep values near P too
                if (k % 7 == 0) a = F.zero.sub(a);
            }
            try std.testing.expectEqual(F.mulPortable(a, b).l, a.mul(b).l);
            try std.testing.expectEqual(F.mulPortable(a, a).l, a.sqr().l);
            const wa = F.mulWide(a.l, b.l);
            try std.testing.expectEqual(F.mulWidePortable(a.l, b.l), wa);
            try std.testing.expectEqual(F.redcPortable(wa).l, F.redc(wa).l);
            // reduction inputs up to m * R - 1 (lazy Fp2 sums)
            var big = F.mulWidePortable(a.l, F.P);
            big = F.addWide(big, F.mulWidePortable(b.l, b.l));
            if (F == Fp) try std.testing.expectEqual(F.redcPortable(big).l, F.redc(big).l); // < 2m^2 < mR
        }
    }
}
