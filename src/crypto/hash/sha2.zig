//! SHA-256, SHA-384, SHA-512 (FIPS 180-4). Round 1 wraps the Zig standard library's block
//! functions (pure Zig, with SHA-NI / ARMv8 SHA2 paths); see BENCH.md for the comparison with the
//! Rust `sha2` crate and the hand kernels still to write.
const std = @import("std");
const cpu = @import("core").cpu;
const S = std.crypto.hash.sha2;
const builtin = @import("builtin");

fn Wrap(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const digest_length = T.digest_length;
        pub const block_length = T.block_length;
        inner: T,
        pub fn init() Self {
            return .{ .inner = T.init(.{}) };
        }
        pub fn update(s: *Self, data: []const u8) void {
            s.inner.update(data);
        }
        pub fn final(s: *Self, out: *[digest_length]u8) void {
            s.inner.final(out);
        }
        pub fn hash(data: []const u8, out: *[digest_length]u8) void {
            T.hash(data, out, .{});
        }
    };
}

// ---------------------------------------------------------------------------------------------
// SHA-256. aarch64 and everything else: the standard library's block function (ARMv8 SHA2 when the
// target has it). x86_64: own struct with the SHA-NI kernel below, chosen by CPUID at run time
// (the Rust `sha2` crate does the same via `cpufeatures`; a build for generic x86-64 must not
// fall to 5x slower code just because the build flags omit `+sha`), and a portable fallback.

pub const Sha256 = if (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64) Sha256X86 else Wrap(S.Sha256);

/// aarch64 target has the SHA2 instructions (std's block function then uses them).
const arm_sha2_hw = builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha2);

/// Whole 64-byte blocks through std's compression (the ARMv8 SHA2 path in a build that has it).
fn compress256Std(st: *[8]u32, data: []const u8) void {
    var d = S.Sha256.init(.{});
    d.s = st.*;
    d.update(data); // whole blocks only: compressed straight from `data`, nothing buffered
    st.* = d.s;
}

const k256 = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

fn compress256Soft(st: *[8]u32, data: []const u8) void {
    var in = data;
    while (in.len >= 64) : (in = in[64..]) {
        var w: [16]u32 = undefined;
        inline for (0..16) |i| w[i] = std.mem.readInt(u32, in[i * 4 ..][0..4], .big);
        var v: [8]u32 = st.*;
        inline for (0..64) |t| {
            if (t >= 16) {
                const a = w[(t + 1) & 15];
                const b = w[(t + 14) & 15];
                const s0 = std.math.rotr(u32, a, 7) ^ std.math.rotr(u32, a, 18) ^ (a >> 3);
                const s1 = std.math.rotr(u32, b, 17) ^ std.math.rotr(u32, b, 19) ^ (b >> 10);
                w[t & 15] = w[t & 15] +% s0 +% w[(t + 9) & 15] +% s1;
            }
            const r = (8 - (t % 8)) % 8;
            const e = v[(r + 4) % 8];
            const a = v[r % 8];
            const t1 = v[(r + 7) % 8] +% (std.math.rotr(u32, e, 6) ^ std.math.rotr(u32, e, 11) ^ std.math.rotr(u32, e, 25)) +%
                ((e & v[(r + 5) % 8]) ^ (~e & v[(r + 6) % 8])) +% k256[t] +% w[t & 15];
            const t2 = (std.math.rotr(u32, a, 2) ^ std.math.rotr(u32, a, 13) ^ std.math.rotr(u32, a, 22)) +%
                ((a & v[(r + 1) % 8]) ^ (a & v[(r + 2) % 8]) ^ (v[(r + 1) % 8] & v[(r + 2) % 8]));
            v[(r + 3) % 8] +%= t1;
            v[(r + 7) % 8] = t1 +% t2;
        }
        inline for (0..8) |i| st[i] +%= v[i];
    }
}

const V4u32 = @Vector(4, u32);

inline fn niRnds2(state1: V4u32, state0: V4u32, wk: V4u32) V4u32 {
    var r = state1;
    asm ("sha256rnds2 %[wk], %[s0], %[r]"
        : [r] "+x" (r),
        : [s0] "x" (state0),
          [wk] "{xmm0}" (wk),
    );
    return r;
}
inline fn niMsg1(a: V4u32, b: V4u32) V4u32 {
    var r = a;
    asm ("sha256msg1 %[b], %[r]"
        : [r] "+x" (r),
        : [b] "x" (b),
    );
    return r;
}
inline fn niMsg2(a: V4u32, b: V4u32) V4u32 {
    var r = a;
    asm ("sha256msg2 %[b], %[r]"
        : [r] "+x" (r),
        : [b] "x" (b),
    );
    return r;
}
/// (hi:lo) >> 4 bytes, as _mm_alignr_epi8(hi, lo, 4)
inline fn niAlignr4(hi: V4u32, lo: V4u32) V4u32 {
    var r = hi;
    asm ("palignr $4, %[lo], %[r]"
        : [r] "+x" (r),
        : [lo] "x" (lo),
    );
    return r;
}
inline fn niBswap(v: V4u32) V4u32 {
    const mask: V4u32 = @bitCast([16]u8{ 3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12 });
    var r = v;
    asm ("pshufb %[m], %[r]"
        : [r] "+x" (r),
        : [m] "x" (mask),
    );
    return r;
}

/// SHA-256 over whole 64-byte blocks with the x86 SHA extensions (Intel's reference sequence).
fn compress256Ni(st: *[8]u32, data: []const u8) void {
    var in = data;
    // state in the ABEF / CDGH layout the instructions want
    const dcba: V4u32 = st[0..4].*;
    const hgfe: V4u32 = st[4..8].*;
    const tmp = @shuffle(u32, dcba, undefined, [4]i32{ 1, 0, 3, 2 }); // CDAB
    const efgh = @shuffle(u32, hgfe, undefined, [4]i32{ 3, 2, 1, 0 }); // HGFE reversed -> EFGH
    var s0 = @shuffle(u32, efgh, tmp, [4]i32{ 2, 3, -1, -2 }); // ABEF = alignr(tmp, efgh, 8)
    var s1 = @shuffle(u32, efgh, tmp, [4]i32{ 0, 1, -3, -4 }); // CDGH = blend(efgh, tmp, 0xF0)
    while (in.len >= 64) : (in = in[64..]) {
        const s0_save = s0;
        const s1_save = s1;
        var m: [4]V4u32 = undefined;
        // one unaligned 16-byte load per word group (a `[16]u8` copy lowers to byte loads)
        inline for (0..4) |i| m[i] = niBswap(@as(*align(1) const V4u32, @ptrCast(in.ptr + i * 16)).*);
        inline for (0..16) |g| {
            const cur = m[g % 4];
            const wk = cur +% @as(V4u32, k256[4 * g ..][0..4].*);
            s1 = niRnds2(s1, s0, wk);
            const wk_hi = @shuffle(u32, wk, undefined, [4]i32{ 2, 3, 0, 1 });
            s0 = niRnds2(s0, s1, wk_hi);
            if (g >= 3 and g <= 14) {
                const prev = m[(g + 3) % 4];
                m[(g + 1) % 4] = niMsg2(m[(g + 1) % 4] +% niAlignr4(cur, prev), cur);
            }
            if (g >= 1 and g <= 12) {
                m[(g + 3) % 4] = niMsg1(m[(g + 3) % 4], cur);
            }
        }
        s0 = s0 +% s0_save;
        s1 = s1 +% s1_save;
    }
    // back to DCBA / HGFE
    const t2 = @shuffle(u32, s0, undefined, [4]i32{ 3, 2, 1, 0 }); // FEBA
    const s1b = @shuffle(u32, s1, undefined, [4]i32{ 1, 0, 3, 2 }); // DCHG
    const dcba2 = @shuffle(u32, t2, s1b, [4]i32{ 0, 1, -3, -4 }); // blend(t2, s1b, 0xF0) = DCBA
    const hgfe2 = @shuffle(u32, t2, s1b, [4]i32{ 2, 3, -1, -2 }); // alignr(s1b, t2, 8) = HGFE
    st[0..4].* = dcba2;
    st[4..8].* = hgfe2;
}

var x86_sha_state: std.atomic.Value(u8) = .init(0); // 0 unknown, 1 absent, 2 present

/// Zig's own x86 backend assembles inline asm only for the target's features: without SHA and
/// SSSE3 in the target it cannot compile compress256Ni. build.zig sends such Debug builds to
/// LLVM (llvmFor), which can, so this only drops the kernel from a bare `zig test -fno-llvm`.
const sha_ni_compiles = builtin.zig_backend != .stage2_x86_64 or
    std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .sha, .ssse3 });

fn cpuHasShaNi() bool {
    if (comptime std.Target.x86.featureSetHas(builtin.cpu.features, .sha)) return true;
    const st = x86_sha_state.load(.monotonic);
    if (st != 0) return st == 2;
    var eax: u32 = 0;
    var ebx: u32 = 0;
    var ecx: u32 = 0;
    var edx: u32 = 0;
    // leaf 0: max leaf
    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (@as(u32, 0)),
          [sub] "{ecx}" (@as(u32, 0)),
    );
    var present = false;
    if (eax >= 7) {
        asm volatile ("cpuid"
            : [eax] "={eax}" (eax),
              [ebx] "={ebx}" (ebx),
              [ecx] "={ecx}" (ecx),
              [edx] "={edx}" (edx),
            : [leaf] "{eax}" (@as(u32, 7)),
              [sub] "{ecx}" (@as(u32, 0)),
        );
        present = (ebx >> 29) & 1 == 1;
        // SSSE3 (pshufb, palignr) and SSE4.1 come with every CPU that has SHA, but check anyway
        asm volatile ("cpuid"
            : [eax] "={eax}" (eax),
              [ebx] "={ebx}" (ebx),
              [ecx] "={ecx}" (ecx),
              [edx] "={edx}" (edx),
            : [leaf] "{eax}" (@as(u32, 1)),
              [sub] "{ecx}" (@as(u32, 0)),
        );
        present = present and (ecx >> 9) & 1 == 1 and (ecx >> 19) & 1 == 1;
    }
    x86_sha_state.store(if (present) 2 else 1, .monotonic);
    return present;
}

fn compress256Blocks(st: *[8]u32, data: []const u8) void {
    if (comptime builtin.cpu.arch == .aarch64) {
        if (arm_sha2_hw and cpu.armSha2Allowed()) compress256Std(st, data) else compress256Soft(st, data);
        return;
    }
    if (sha_ni_compiles and cpu.shaNiAllowed() and cpuHasShaNi()) compress256Ni(st, data) else compress256Soft(st, data);
}

const Sha256X86 = struct {
    const Self = @This();
    pub const digest_length = 32;
    pub const block_length = 64;
    st: [8]u32,
    buf: [64]u8,
    buf_len: usize,
    total: u64,

    pub fn init() Self {
        return .{ .st = .{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }, .buf = undefined, .buf_len = 0, .total = 0 };
    }
    pub fn update(s: *Self, data: []const u8) void {
        var in = data;
        s.total += in.len;
        if (s.buf_len > 0) {
            const n = @min(64 - s.buf_len, in.len);
            @memcpy(s.buf[s.buf_len..][0..n], in[0..n]);
            s.buf_len += n;
            in = in[n..];
            if (s.buf_len < 64) return;
            compress256Blocks(&s.st, &s.buf);
            s.buf_len = 0;
        }
        const whole = in.len & ~@as(usize, 63);
        if (whole > 0) compress256Blocks(&s.st, in[0..whole]);
        in = in[whole..];
        @memcpy(s.buf[0..in.len], in);
        s.buf_len = in.len;
    }
    pub fn final(s: *Self, out: *[32]u8) void {
        s.buf[s.buf_len] = 0x80;
        @memset(s.buf[s.buf_len + 1 ..], 0);
        if (s.buf_len + 1 > 56) {
            compress256Blocks(&s.st, &s.buf);
            @memset(&s.buf, 0);
        }
        std.mem.writeInt(u64, s.buf[56..64], s.total * 8, .big);
        compress256Blocks(&s.st, &s.buf);
        inline for (0..8) |i| std.mem.writeInt(u32, out[i * 4 ..][0..4], s.st[i], .big);
    }
    pub fn hash(data: []const u8, out: *[32]u8) void {
        var s = init();
        s.update(data);
        s.final(out);
    }
};

// ---------------------------------------------------------------------------------------------
// SHA-512 / SHA-384: own kernel. The standard library's is a plain loop (1.73 ns/byte on Apple
// M5 Pro); this one fully unrolls the 80 rounds with comptime role rotation and keeps the message
// schedule in a 16-word ring, no copies of the working variables.

const k512 = [80]u64{
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

inline fn rr(x: u64, comptime n: u6) u64 {
    return std.math.rotr(u64, x, n);
}

inline fn rnd(a: u64, b: u64, c: u64, d: *u64, e: u64, f: u64, g: u64, h: *u64, kw: u64) void {
    const t1 = h.* +% (rr(e, 14) ^ rr(e, 18) ^ rr(e, 41)) +% ((e & f) ^ (~e & g)) +% kw;
    const t2 = (rr(a, 28) ^ rr(a, 34) ^ rr(a, 39)) +% ((a & b) ^ (a & c) ^ (b & c));
    d.* +%= t1;
    h.* = t1 +% t2;
}

/// ARMv8.2 FEAT_SHA512 (LLVM feature `sha3`): SHA512H/H2/SU0/SU1.
pub const has_sha512_hw = builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha3);

/// One SHA-512 block: the ARMv8.2 instructions where the target has them, else the portable
/// rounds, which dispatch at runtime on x86-64 (core/cpu.zig: BMI2 `rorx` in the AVX2 object).
pub fn compress512(st: *[8]u64, block: *const [128]u8) void {
    if (comptime has_sha512_hw) {
        if (cpu.armSha512Allowed()) return compress512Hw(st, block);
        return compress512Soft(st, block);
    }
    cpu.call("sha512_block", compress512Soft, .{ st, block });
}

const V2 = @Vector(2, u64);

inline fn ext1(a: V2, b: V2) V2 {
    return @shuffle(u64, a, b, [2]i32{ 1, -1 });
}
inline fn sha512h(acc: V2, n: V2, m: V2) V2 {
    var r = acc;
    asm ("sha512h.2d %[r], %[n], %[m]"
        : [r] "+w" (r),
        : [n] "w" (n),
          [m] "w" (m),
    );
    return r;
}
inline fn sha512h2(acc: V2, n: V2, m: V2) V2 {
    var r = acc;
    asm ("sha512h2.2d %[r], %[n], %[m]"
        : [r] "+w" (r),
        : [n] "w" (n),
          [m] "w" (m),
    );
    return r;
}
inline fn sha512su0(a: V2, b: V2) V2 {
    var r = a;
    asm ("sha512su0.2d %[r], %[b]"
        : [r] "+w" (r),
        : [b] "w" (b),
    );
    return r;
}
inline fn sha512su1(a: V2, b: V2, c: V2) V2 {
    var r = a;
    asm ("sha512su1.2d %[r], %[b], %[c]"
        : [r] "+w" (r),
        : [b] "w" (b),
          [c] "w" (c),
    );
    return r;
}
inline fn loadBe(p: *const [16]u8) V2 {
    const v: @Vector(16, u8) = p.*;
    const r = @shuffle(u8, v, undefined, [16]i32{ 7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8 });
    return @bitCast(r);
}

/// Two rounds: the Rust `sha2` crate's aarch64 schedule (adapted from mbedtls), written once
/// with the (ab, cd, ef, gh) roles passed in rotated.
inline fn rounds2(ab: *V2, cd: *V2, ef: *V2, gh: *V2, w: V2, comptime t: usize) void {
    const kv: V2 = k512[t..][0..2].*;
    const initial = w +% kv;
    const sum = ext1(initial, initial) +% gh.*;
    const inter = sha512h(sum, ext1(ef.*, gh.*), ext1(cd.*, ef.*));
    gh.* = sha512h2(inter, cd.*, ab.*);
    cd.* = cd.* +% inter;
}

pub fn compress512Hw(st: *[8]u64, block: *const [128]u8) void {
    var ab: V2 = st[0..2].*;
    var cd: V2 = st[2..4].*;
    var ef: V2 = st[4..6].*;
    var gh: V2 = st[6..8].*;
    var s: [8]V2 = undefined;
    inline for (0..8) |i| s[i] = loadBe(block[i * 16 ..][0..16]);
    // Round pair p uses the roles rotated by p: (ab,cd,ef,gh), (ef,ab,gh,cd)... as in the crate.
    inline for (0..40) |p| {
        const i = p % 8;
        if (p >= 8) {
            s[i] = sha512su1(sha512su0(s[i], s[(i + 1) % 8]), s[(i + 7) % 8], ext1(s[(i + 4) % 8], s[(i + 5) % 8]));
        }
        switch (p % 4) {
            0 => rounds2(&ab, &cd, &ef, &gh, s[i], 2 * p),
            1 => rounds2(&gh, &ab, &cd, &ef, s[i], 2 * p),
            2 => rounds2(&ef, &gh, &ab, &cd, s[i], 2 * p),
            else => rounds2(&cd, &ef, &gh, &ab, s[i], 2 * p),
        }
    }
    st[0..2].* = @as(V2, st[0..2].*) +% ab;
    st[2..4].* = @as(V2, st[2..4].*) +% cd;
    st[4..6].* = @as(V2, st[4..6].*) +% ef;
    st[6..8].* = @as(V2, st[6..8].*) +% gh;
}

pub fn compress512Soft(st: *[8]u64, block: *const [128]u8) void {
    var w: [16]u64 = undefined;
    inline for (0..16) |i| w[i] = std.mem.readInt(u64, block[i * 8 ..][0..8], .big);
    var v: [8]u64 = st.*;
    inline for (0..80) |t| {
        if (t >= 16) {
            const s0 = rr(w[(t + 1) & 15], 1) ^ rr(w[(t + 1) & 15], 8) ^ (w[(t + 1) & 15] >> 7);
            const s1 = rr(w[(t + 14) & 15], 19) ^ rr(w[(t + 14) & 15], 61) ^ (w[(t + 14) & 15] >> 6);
            w[t & 15] = w[t & 15] +% s0 +% w[(t + 9) & 15] +% s1;
        }
        // roles rotate by one each round: after round t, (a..h) = (h', a, b, c, d', e, f, g)
        const r = (8 - (t % 8)) % 8;
        rnd(v[r % 8], v[(r + 1) % 8], v[(r + 2) % 8], &v[(r + 3) % 8], v[(r + 4) % 8], v[(r + 5) % 8], v[(r + 6) % 8], &v[(r + 7) % 8], k512[t] +% w[t & 15]);
    }
    inline for (0..8) |i| st.*[i] +%= v[i];
}

fn Sha512Gen(comptime out_len: usize, comptime init_state: [8]u64) type {
    return struct {
        const Self = @This();
        pub const digest_length = out_len;
        pub const block_length = 128;
        st: [8]u64,
        buf: [128]u8,
        buf_len: usize,
        total: u128,

        pub fn init() Self {
            return .{ .st = init_state, .buf = undefined, .buf_len = 0, .total = 0 };
        }
        pub fn update(s: *Self, data: []const u8) void {
            var in = data;
            s.total += in.len;
            if (s.buf_len > 0) {
                const n = @min(128 - s.buf_len, in.len);
                @memcpy(s.buf[s.buf_len..][0..n], in[0..n]);
                s.buf_len += n;
                in = in[n..];
                if (s.buf_len < 128) return;
                compress512(&s.st, &s.buf);
                s.buf_len = 0;
            }
            while (in.len >= 128) {
                compress512(&s.st, in[0..128]);
                in = in[128..];
            }
            @memcpy(s.buf[0..in.len], in);
            s.buf_len = in.len;
        }
        pub fn final(s: *Self, out: *[out_len]u8) void {
            s.buf[s.buf_len] = 0x80;
            @memset(s.buf[s.buf_len + 1 ..], 0);
            if (s.buf_len + 1 > 112) {
                compress512(&s.st, &s.buf);
                @memset(&s.buf, 0);
            }
            std.mem.writeInt(u128, s.buf[112..128], s.total * 8, .big);
            compress512(&s.st, &s.buf);
            var full: [64]u8 = undefined;
            inline for (0..8) |i| std.mem.writeInt(u64, full[i * 8 ..][0..8], s.st[i], .big);
            @memcpy(out, full[0..out_len]);
        }
        pub fn hash(data: []const u8, out: *[out_len]u8) void {
            var s = init();
            s.update(data);
            s.final(out);
        }
    };
}

pub const Sha512 = Sha512Gen(64, .{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
});
pub const Sha384 = Sha512Gen(48, .{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
});

test "hardware and portable SHA-512 compression agree" {
    if (!has_sha512_hw) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(77);
    const r = prng.random();
    for (0..500) |_| {
        var a: [8]u64 = undefined;
        for (&a) |*x| x.* = r.int(u64);
        var b = a;
        var blk: [128]u8 = undefined;
        r.bytes(&blk);
        compress512Hw(&a, &blk);
        compress512Soft(&b, &blk);
        try std.testing.expectEqualSlices(u64, &b, &a);
    }
}

test "sha512/384 known answers and std agreement" {
    var out: [64]u8 = undefined;
    Sha512.hash("abc", &out);
    var want: [64]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    try std.testing.expectEqualSlices(u8, &want, &out);
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    var data: [700]u8 = undefined;
    r.bytes(&data);
    for (0..data.len + 1) |len| {
        var a: [64]u8 = undefined;
        var b: [64]u8 = undefined;
        Sha512.hash(data[0..len], &a);
        S.Sha512.hash(data[0..len], &b, .{});
        try std.testing.expectEqualSlices(u8, &b, &a);
        var a3: [48]u8 = undefined;
        var b3: [48]u8 = undefined;
        Sha384.hash(data[0..len], &a3);
        S.Sha384.hash(data[0..len], &b3, .{});
        try std.testing.expectEqualSlices(u8, &b3, &a3);
    }
}

test "x86 SHA-256 kernels agree with std" {
    if (builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(123);
    const r = prng.random();
    var data: [1500]u8 = undefined;
    r.bytes(&data);
    for (0..data.len + 1) |len| {
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        Sha256.hash(data[0..len], &a);
        S.Sha256.hash(data[0..len], &b, .{});
        try std.testing.expectEqualSlices(u8, &b, &a);
        // portable fallback on whole blocks
        var st1: [8]u32 = Sha256X86.init().st;
        var st2 = st1;
        const whole = len & ~@as(usize, 63);
        compress256Soft(&st1, data[0..whole]);
        if (sha_ni_compiles and cpuHasShaNi()) compress256Ni(&st2, data[0..whole]) else compress256Soft(&st2, data[0..whole]);
        try std.testing.expectEqualSlices(u32, &st1, &st2);
    }
}

test "known answers" {
    var out: [32]u8 = undefined;
    Sha256.hash("abc", &out);
    var want: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    try std.testing.expectEqualSlices(u8, &want, &out);
}
