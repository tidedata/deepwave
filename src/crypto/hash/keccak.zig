//! Keccak-f[1600] and the three sponges Sui uses: SHA3-256, SHA3-512 (FIPS 202, pad 0x06) and
//! Keccak-256 (original Keccak, pad 0x01; Ethereum / `sui::hash::keccak256`).
//!
//! The state is absorbed in place: input lanes are XORed straight into the 25-word state, there
//! is no staging buffer. Whole blocks come from the caller's slice. The permutation is fully
//! unrolled with comptime rotation constants. No allocation.
comptime {
    if (@import("builtin").cpu.arch.endian() != .little) @compileError("keccak.zig assumes a little-endian target");
}
const std = @import("std");
const cpu = @import("core").cpu;

const rc = [24]u64{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

/// Rotation offsets by lane index x + 5y.
const rho = [25]u6{
    0,  1,  62, 28, 27,
    36, 44, 6,  55, 20,
    3,  10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2,  61, 56, 14,
};

inline fn rotl(x: u64, comptime n: u6) u64 {
    if (n == 0) return x;
    return std.math.rotl(u64, x, n);
}

const builtin = @import("builtin");

/// ARMv8.2 FEAT_SHA3 (EOR3, RAX1, XAR, BCAX): LLVM feature `sha3`.
pub const has_sha3_hw = builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and std.Target.aarch64.featureSetHas(builtin.cpu.features, .sha3);

/// Runtime dispatched on x86-64 (core/cpu.zig): the BMI1 `andn`/`rorx` forms of the chi and
/// rho steps in the AVX2 kernel object.
pub fn permute(st: *[25]u64) void {
    cpu.call("keccak_f1600", permuteSoft, .{st});
}

const V2 = @Vector(2, u64);

inline fn eor3(a: V2, b: V2, c: V2) V2 {
    var r = a;
    asm ("eor3.16b %[r], %[r], %[b], %[c]"
        : [r] "+w" (r),
        : [b] "w" (b),
          [c] "w" (c),
    );
    return r;
}
inline fn rax1(a: V2, b: V2) V2 {
    return asm ("rax1.2d %[r], %[a], %[b]"
        : [r] "=w" (-> V2),
        : [a] "w" (a),
          [b] "w" (b),
    );
}
/// ror(a ^ b, imm)
inline fn xar(a: V2, b: V2, comptime imm: u6) V2 {
    const text = comptime blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk std.fmt.comptimePrint("xar.2d %[r], %[a], %[b], #{d}", .{imm});
    };
    return asm (text
        : [r] "=w" (-> V2),
        : [a] "w" (a),
          [b] "w" (b),
    );
}
/// a ^ (b & ~c)
inline fn bcax(a: V2, b: V2, c: V2) V2 {
    var r = a;
    asm ("bcax.16b %[r], %[r], %[b], %[c]"
        : [r] "+w" (r),
        : [b] "w" (b),
          [c] "w" (c),
    );
    return r;
}

/// Keccak-f[1600] on two states at once (lane 0 and lane 1 of every vector); the single-state
/// `permuteHw` uses lane 0.
pub fn permuteHw2(s: *[25]V2) void {
    @setEvalBranchQuota(100_000);
    var a = s.*;
    inline for (0..24) |round| {
        var c: [5]V2 = undefined;
        inline for (0..5) |x| c[x] = eor3(eor3(a[x], a[x + 5], a[x + 10]), a[x + 15], a[x + 20]);
        var d: [5]V2 = undefined;
        inline for (0..5) |x| d[x] = rax1(c[(x + 4) % 5], c[(x + 1) % 5]);
        // Output row yo needs b(X, yo) = rho(a[sx + 5X] ^ d[sx]) with sx = (3*yo + X) % 5. Doing
        // theta/rho/pi/chi one output row at a time lets each consumed input lane die at once, so
        // the live set stays within the 32 vector registers (no spills).
        var n: [25]V2 = undefined;
        inline for (0..5) |yo| {
            var br: [5]V2 = undefined;
            inline for (0..5) |X| {
                const sx = (3 * yo + X) % 5;
                const r = rho[sx + 5 * X];
                br[X] = if (r == 0) a[sx + 5 * X] ^ d[sx] else xar(a[sx + 5 * X], d[sx], @intCast(64 - @as(u7, r)));
            }
            inline for (0..5) |X| n[X + 5 * yo] = bcax(br[X], br[(X + 2) % 5], br[(X + 1) % 5]);
        }
        a = n;
        a[0] ^= @as(V2, @splat(rc[round]));
    }
    s.* = a;
}

pub fn permuteHw(st: *[25]u64) void {
    var v: [25]V2 = undefined;
    inline for (0..25) |i| v[i] = .{ st[i], 0 };
    permuteHw2(&v);
    inline for (0..25) |i| st[i] = v[i][0];
}

/// Portable Keccak-f[1600], 24 rounds. Theta, rho, pi and chi are done one output row at a
/// time (as in `permuteHw2`): each input lane dies as soon as its output row is written, which
/// keeps the live set small enough for x86-64's 16 registers to spill less.
pub fn permuteSoft(a: *[25]u64) void {
    absorbSoft(a, undefined, 0, 0);
}

inline fn rounds(s: *[25]u64) void {
    @setEvalBranchQuota(100_000);
    inline for (0..24) |round| {
        var c: [5]u64 = undefined;
        inline for (0..5) |x| c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        var d: [5]u64 = undefined;
        inline for (0..5) |x| d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1);
        var n: [25]u64 = undefined;
        inline for (0..5) |yo| {
            // B(X, yo) = rotl(A[sx, X] ^ D[sx], rho) with sx = (X + 3 yo) mod 5
            var br: [5]u64 = undefined;
            inline for (0..5) |X| {
                const sx = (3 * yo + X) % 5;
                br[X] = rotl(s[sx + 5 * X] ^ d[sx], rho[sx + 5 * X]);
            }
            inline for (0..5) |X| n[X + 5 * yo] = br[X] ^ (~br[(X + 1) % 5] & br[(X + 2) % 5]);
        }
        s.* = n;
        s[0] ^= rc[round];
    }
}

/// `blocks` whole blocks of `rate` bytes at `in`, each XORed into the state and permuted, with
/// the state held in locals for the whole run (no reload between blocks); `blocks` = 0 permutes
/// once. Runtime dispatched on x86-64 as one call per run of blocks.
pub fn absorbSoft(a: *[25]u64, in: [*]const u8, rate_words: usize, blocks: usize) void {
    var s = a.*;
    if (blocks == 0) {
        rounds(&s);
    } else {
        var p = in;
        for (0..blocks) |_| {
            switch (rate_words) {
                inline 9, 17, 18 => |w| inline for (0..w) |i| {
                    s[i] ^= std.mem.readInt(u64, p[i * 8 ..][0..8], .little);
                },
                else => for (0..rate_words) |i| {
                    s[i] ^= std.mem.readInt(u64, p[i * 8 ..][0..8], .little);
                },
            }
            rounds(&s);
            p += rate_words * 8;
        }
    }
    a.* = s;
}

pub fn absorb(a: *[25]u64, in: [*]const u8, rate_words: usize, blocks: usize) void {
    cpu.call("keccak_absorb", absorbSoft, .{ a, in, rate_words, blocks });
}

pub fn Sponge(comptime rate: usize, comptime pad: u8, comptime out_len: usize) type {
    return struct {
        const Self = @This();
        pub const digest_length = out_len;
        pub const block_length = rate;
        comptime {
            std.debug.assert(rate % 8 == 0 and rate < 200 and out_len <= rate);
        }

        st: [25]u64,
        pos: usize,

        pub fn init() Self {
            return .{ .st = @splat(0), .pos = 0 };
        }

        inline fn bytes(s: *Self) *[200]u8 {
            return @ptrCast(&s.st);
        }

        inline fn absorbBlock(s: *Self, block: *const [rate]u8) void {
            inline for (0..rate / 8) |i| s.st[i] ^= std.mem.readInt(u64, block[i * 8 ..][0..8], .little);
            permute(&s.st);
        }

        pub fn update(s: *Self, data: []const u8) void {
            var in = data;
            if (s.pos > 0) {
                const room = rate - s.pos;
                const n = @min(room, in.len);
                const b = s.bytes();
                for (in[0..n], b[s.pos..][0..n]) |x, *y| y.* ^= x;
                s.pos += n;
                in = in[n..];
                if (s.pos < rate) return;
                permute(&s.st);
                s.pos = 0;
            }
            if (in.len >= rate) {
                const nb = in.len / rate;
                absorb(&s.st, in.ptr, rate / 8, nb);
                in = in[nb * rate ..];
            }
            if (in.len > 0) {
                const b = s.bytes();
                for (in, b[0..in.len]) |x, *y| y.* ^= x;
                s.pos = in.len;
            }
        }

        pub fn final(s: *Self, out: *[out_len]u8) void {
            const b = s.bytes();
            b[s.pos] ^= pad;
            b[rate - 1] ^= 0x80;
            permute(&s.st);
            @memcpy(out, b[0..out_len]);
        }

        pub fn hash(data: []const u8, out: *[out_len]u8) void {
            var s = init();
            s.update(data);
            s.final(out);
        }
    };
}

pub const Sha3_256 = Sponge(136, 0x06, 32);
pub const Sha3_512 = Sponge(72, 0x06, 64);
pub const Keccak256 = Sponge(136, 0x01, 32);

test "keccak-f[1600] zero state, first permutation (Keccak team KAT)" {
    var st: [25]u64 = @splat(0);
    permute(&st);
    try std.testing.expectEqual(@as(u64, 0xF1258F7940E1DDE7), st[0]);
    try std.testing.expectEqual(@as(u64, 0x84D5CCF933C0478A), st[1]);
    try std.testing.expectEqual(@as(u64, 0xD598261EA65AA9EE), st[2]);
    permute(&st);
    try std.testing.expectEqual(@as(u64, 0x2D5C954DF96ECB3C), st[0]);
}

fn expectHash(comptime H: type, msg: []const u8, comptime want_hex: []const u8) !void {
    var out: [H.digest_length]u8 = undefined;
    H.hash(msg, &out);
    var want: [H.digest_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&want, want_hex);
    try std.testing.expectEqualSlices(u8, &want, &out);
}

test "hardware and portable permutations agree" {
    if (!has_sha3_hw) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(31);
    const r = prng.random();
    for (0..300) |_| {
        var a: [25]u64 = undefined;
        for (&a) |*x| x.* = r.int(u64);
        var b = a;
        permuteHw(&a);
        permuteSoft(&b);
        try std.testing.expectEqualSlices(u64, &b, &a);
    }
}

test "known answers" {
    try expectHash(Sha3_256, "", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    try expectHash(Sha3_256, "abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    try expectHash(Keccak256, "", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    try expectHash(Keccak256, "abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
    try expectHash(Sha3_512, "", "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

test "streaming equals one-shot at every split" {
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    var data: [500]u8 = undefined;
    r.bytes(&data);
    inline for (.{ Sha3_256, Sha3_512, Keccak256 }) |H| {
        for ([_]usize{ 0, 1, 71, 72, 73, 135, 136, 137, 271, 272, 273, 500 }) |len| {
            var want: [H.digest_length]u8 = undefined;
            H.hash(data[0..len], &want);
            for (0..len + 1) |split| {
                var h = H.init();
                h.update(data[0..split]);
                h.update(data[split..len]);
                var got: [H.digest_length]u8 = undefined;
                h.final(&got);
                try std.testing.expectEqualSlices(u8, &want, &got);
            }
        }
    }
}
