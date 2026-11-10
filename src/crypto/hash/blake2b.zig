//! BLAKE2b (RFC 7693) with runtime output length 1..64 and optional key, plus the Sui hot-path
//! form Blake2b-256 (fastcrypto `Blake2b256` = `blake2::Blake2b<U32>`: no key, no salt, no
//! personalization, sequential mode).
//!
//! Layout: the chaining state lives in registers during `compress`; whole blocks are read
//! straight from the caller's slice (no copy), only the tail is staged in a 128-byte buffer.
//! The final block is never compressed until `final`, so `update` can always be called again.
//! No allocation anywhere.
//!
//! Two compression kernels, both proven identical to each other by tests:
//!   * `compressScalar`: 64-bit scalar G, fully unrolled over the 12 rounds with comptime message
//!     indices (message words are never shuffled in memory).
//!   * `compressVec`: row-wise SIMD (the 4x4 state as four u64x4 rows, diagonal rounds via
//!     shuffles), the form AVX2 and NEON(2x u64x2) like.
//! `compress` selects at comptime per target (see `use_vec`). On x86-64 the streaming hasher and
//! `blake2b256Many` also dispatch at runtime (core/cpu.zig): a baseline binary runs the AVX2
//! kernel and the AVX-512 multi-buffer width on CPUs that have them.
const std = @import("std");
const builtin = @import("builtin");
const cpu = @import("core").cpu;

pub const block_len = 128;

const iv = [8]u64{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
};

const sigma = [12][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
};

/// The vector kernel wins where the CPU has 256-bit integer vectors (AVX2: 0.83 ns/byte against
/// 0.92 for the BMI2 scalar kernel on AWS r7i, BENCH.md). On NEON the scalar kernel is faster
/// (measured on Apple M5 Pro), so aarch64 keeps it.
pub const use_vec = switch (builtin.cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .avx2),
    else => false,
};

inline fn rotr(x: u64, comptime n: u6) u64 {
    return std.math.rotr(u64, x, n);
}

inline fn g(a: *u64, b: *u64, c: *u64, d: *u64, x: u64, y: u64) void {
    // (a + x) first: `a` is ready before `b` (b is the last word a G step writes), so the
    // message add comes off the dependency chain
    a.* = a.* +% x +% b.*;
    d.* = rotr(d.* ^ a.*, 32);
    c.* = c.* +% d.*;
    b.* = rotr(b.* ^ c.*, 24);
    a.* = a.* +% y +% b.*;
    d.* = rotr(d.* ^ a.*, 16);
    c.* = c.* +% d.*;
    b.* = rotr(b.* ^ c.*, 63);
}

inline fn loadWords(block: *const [128]u8) [16]u64 {
    var m: [16]u64 = undefined;
    inline for (0..16) |i| m[i] = std.mem.readInt(u64, block[i * 8 ..][0..8], .little);
    return m;
}

pub fn compressScalar(h: *[8]u64, block: *const [128]u8, t: u128, last: bool) void {
    const mp: *align(1) const [16]u64 = @ptrCast(block);
    var v0 = h[0];
    var v1 = h[1];
    var v2 = h[2];
    var v3 = h[3];
    var v4 = h[4];
    var v5 = h[5];
    var v6 = h[6];
    var v7 = h[7];
    var v8 = iv[0];
    var v9 = iv[1];
    var v10 = iv[2];
    var v11 = iv[3];
    var v12 = iv[4] ^ @as(u64, @truncate(t));
    var v13 = iv[5] ^ @as(u64, @truncate(t >> 64));
    var v14 = if (last) ~iv[6] else iv[6];
    var v15 = iv[7];
    inline for (0..12) |r| {
        const s = sigma[r];
        g(&v0, &v4, &v8, &v12, ld(mp, s[0]), ld(mp, s[1]));
        g(&v1, &v5, &v9, &v13, ld(mp, s[2]), ld(mp, s[3]));
        g(&v2, &v6, &v10, &v14, ld(mp, s[4]), ld(mp, s[5]));
        g(&v3, &v7, &v11, &v15, ld(mp, s[6]), ld(mp, s[7]));
        g(&v0, &v5, &v10, &v15, ld(mp, s[8]), ld(mp, s[9]));
        g(&v1, &v6, &v11, &v12, ld(mp, s[10]), ld(mp, s[11]));
        g(&v2, &v7, &v8, &v13, ld(mp, s[12]), ld(mp, s[13]));
        g(&v3, &v4, &v9, &v14, ld(mp, s[14]), ld(mp, s[15]));
    }
    h[0] ^= v0 ^ v8;
    h[1] ^= v1 ^ v9;
    h[2] ^= v2 ^ v10;
    h[3] ^= v3 ^ v11;
    h[4] ^= v4 ^ v12;
    h[5] ^= v5 ^ v13;
    h[6] ^= v6 ^ v14;
    h[7] ^= v7 ^ v15;
}

inline fn ld(mp: *align(1) const [16]u64, comptime i: u8) u64 {
    return std.mem.littleToNative(u64, mp[i]);
}

const V4 = @Vector(4, u64);

inline fn vrotr(x: V4, comptime n: u6) V4 {
    return (x >> @splat(n)) | (x << @splat(64 - @as(u7, n)));
}

/// Row-wise form: rows a=v[0..4], b=v[4..8], c=v[8..12], d=v[12..16]. Column step on the rows
/// directly, then rotate b, c, d lanes to make the diagonals columns, step, rotate back.
pub fn compressVec(h: *[8]u64, block: *const [128]u8, t: u128, last: bool) void {
    const m = loadWords(block);
    var a: V4 = h[0..4].*;
    var b: V4 = h[4..8].*;
    var c: V4 = iv[0..4].*;
    var d: V4 = V4{ iv[4] ^ @as(u64, @truncate(t)), iv[5] ^ @as(u64, @truncate(t >> 64)), if (last) ~iv[6] else iv[6], iv[7] };
    const a0 = a;
    const b0 = b;
    inline for (0..12) |r| {
        const s = sigma[r];
        // column step
        {
            const x = V4{ m[s[0]], m[s[2]], m[s[4]], m[s[6]] };
            const y = V4{ m[s[1]], m[s[3]], m[s[5]], m[s[7]] };
            a = a +% x +% b;
            d = vrotr(d ^ a, 32);
            c = c +% d;
            b = vrotr(b ^ c, 24);
            a = a +% y +% b;
            d = vrotr(d ^ a, 16);
            c = c +% d;
            b = vrotr(b ^ c, 63);
        }
        // Diagonalize by moving a, c and d, not b: b is the last word a step writes and the
        // first the next step reads, so a cross-lane permute of b (3 cycles) would sit on the
        // block's one dependency chain, while a, c and d are ready early enough to hide it.
        // Lane j then runs diagonal G(j-1) = (a[j-1], b[j], c[j+1], d[j+2]).
        a = @shuffle(u64, a, undefined, [4]i32{ 3, 0, 1, 2 });
        c = @shuffle(u64, c, undefined, [4]i32{ 1, 2, 3, 0 });
        d = @shuffle(u64, d, undefined, [4]i32{ 2, 3, 0, 1 });
        {
            const x = V4{ m[s[14]], m[s[8]], m[s[10]], m[s[12]] };
            const y = V4{ m[s[15]], m[s[9]], m[s[11]], m[s[13]] };
            a = a +% x +% b;
            d = vrotr(d ^ a, 32);
            c = c +% d;
            b = vrotr(b ^ c, 24);
            a = a +% y +% b;
            d = vrotr(d ^ a, 16);
            c = c +% d;
            b = vrotr(b ^ c, 63);
        }
        a = @shuffle(u64, a, undefined, [4]i32{ 1, 2, 3, 0 });
        c = @shuffle(u64, c, undefined, [4]i32{ 3, 0, 1, 2 });
        d = @shuffle(u64, d, undefined, [4]i32{ 2, 3, 0, 1 });
    }
    h[0..4].* = a0 ^ a ^ c;
    h[4..8].* = b0 ^ b ^ d;
}

pub const compress = if (use_vec) compressVec else compressScalar;

/// `n` consecutive blocks at `blocks`; block i is compressed with counter `t + 128 * i`, and
/// the last one is the final block if `last`. Runtime dispatched (one call per run of blocks).
pub fn compressBlocks(h: *[8]u64, blocks: [*]const u8, n: usize, t: u128, last: bool) void {
    cpu.call("blake2b_blocks", compressBlocksImpl, .{ h, blocks, n, t, last });
}

pub fn compressBlocksImpl(h: *[8]u64, blocks: [*]const u8, n: usize, t: u128, last: bool) void {
    var hh = h.*;
    for (0..n) |i| compress(&hh, blocks[i * 128 ..][0..128], t + 128 * @as(u128, i), last and i + 1 == n);
    h.* = hh;
}

/// Streaming BLAKE2b. `outlen` is 1..64; key (0..64 bytes) is absorbed as a zero-padded first block.
pub const Blake2b = struct {
    h: [8]u64,
    t: u128,
    buf: [128]u8,
    buf_len: u8,
    outlen: u8,

    pub fn init(outlen: u8, key: []const u8) Blake2b {
        std.debug.assert(outlen >= 1 and outlen <= 64 and key.len <= 64);
        var s: Blake2b = .{ .h = iv, .t = 0, .buf = undefined, .buf_len = 0, .outlen = outlen };
        s.h[0] ^= 0x01010000 ^ (@as(u64, @intCast(key.len)) << 8) ^ outlen;
        if (key.len > 0) {
            @memset(&s.buf, 0);
            @memcpy(s.buf[0..key.len], key);
            s.buf_len = 128;
        }
        return s;
    }

    pub fn update(s: *Blake2b, data: []const u8) void {
        var in = data;
        if (in.len == 0) return;
        const have: usize = s.buf_len;
        if (have > 0) {
            const room = 128 - have;
            if (in.len <= room) {
                @memcpy(s.buf[have..][0..in.len], in);
                s.buf_len += @intCast(in.len);
                return;
            }
            @memcpy(s.buf[have..128], in[0..room]);
            in = in[room..];
            s.t += 128;
            compressBlocks(&s.h, &s.buf, 1, s.t, false);
            s.buf_len = 0;
        }
        // Keep the last (possibly full) block for `final`: compress only while more than 128 remain.
        if (in.len > 128) {
            const n = (in.len - 1) / 128;
            compressBlocks(&s.h, in.ptr, n, s.t + 128, false);
            s.t += 128 * @as(u128, n);
            in = in[128 * n ..];
        }
        @memcpy(s.buf[0..in.len], in);
        s.buf_len = @intCast(in.len);
    }

    pub fn final(s: *Blake2b, out: []u8) void {
        std.debug.assert(out.len == s.outlen);
        s.t += s.buf_len;
        @memset(s.buf[s.buf_len..], 0);
        compressBlocks(&s.h, &s.buf, 1, s.t, true);
        var full: [64]u8 = undefined;
        inline for (0..8) |i| std.mem.writeInt(u64, full[i * 8 ..][0..8], s.h[i], .little);
        @memcpy(out, full[0..s.outlen]);
    }
};

/// Blake2b-256 as used by Sui (digests, object ids, addresses).
pub const Blake2b256 = struct {
    inner: Blake2b,

    pub const digest_length = 32;

    pub fn init() Blake2b256 {
        return .{ .inner = Blake2b.init(32, "") };
    }
    pub fn update(s: *Blake2b256, data: []const u8) void {
        s.inner.update(data);
    }
    pub fn final(s: *Blake2b256, out: *[32]u8) void {
        s.inner.final(out);
    }
    /// One-shot over one slice.
    pub fn hash(data: []const u8, out: *[32]u8) void {
        var h = init();
        h.update(data);
        h.final(out);
    }
};

/// Hash of the concatenation of `parts`, without concatenating. No allocation.
pub fn blake2b256(parts: []const []const u8) [32]u8 {
    var h = Blake2b256.init();
    for (parts) |p| h.update(p);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

fn hexTest(comptime in: []const u8, comptime key: []const u8, outlen: u8, comptime want: []const u8) !void {
    var h = Blake2b.init(outlen, key);
    h.update(in);
    var out: [64]u8 = undefined;
    h.final(out[0..outlen]);
    var want_b: [64]u8 = undefined;
    const wb = try std.fmt.hexToBytes(&want_b, want);
    try std.testing.expectEqualSlices(u8, wb, out[0..outlen]);
}

test "RFC 7693 appendix A: BLAKE2b-512 abc" {
    try hexTest("abc", "", 64, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
}

test "Blake2b-256 empty and abc" {
    var out: [32]u8 = undefined;
    Blake2b256.hash("", &out);
    try std.testing.expectEqualSlices(u8, &(try hex32("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8")), &out);
    Blake2b256.hash("abc", &out);
    try std.testing.expectEqualSlices(u8, &(try hex32("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")), &out);
}

fn hex32(comptime s: []const u8) ![32]u8 {
    var b: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&b, s);
    return b;
}

test "scalar and vector kernels agree" {
    var prng = std.Random.DefaultPrng.init(0xb1a4e2);
    const r = prng.random();
    for (0..2000) |_| {
        var h1: [8]u64 = undefined;
        for (&h1) |*x| x.* = r.int(u64);
        var h2 = h1;
        var blk: [128]u8 = undefined;
        r.bytes(&blk);
        const t = r.int(u128);
        const last = r.boolean();
        compressScalar(&h1, &blk, t, last);
        compressVec(&h2, &blk, t, last);
        try std.testing.expectEqualSlices(u64, &h1, &h2);
    }
}

test "streaming equals one-shot at every split" {
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    var data: [600]u8 = undefined;
    r.bytes(&data);
    for ([_]usize{ 0, 1, 127, 128, 129, 255, 256, 257, 383, 384, 600 }) |len| {
        var want: [32]u8 = undefined;
        Blake2b256.hash(data[0..len], &want);
        for (0..len + 1) |split| {
            var h = Blake2b256.init();
            h.update(data[0..split]);
            h.update(data[split..len]);
            var got: [32]u8 = undefined;
            h.final(&got);
            try std.testing.expectEqualSlices(u8, &want, &got);
        }
    }
}

// -------------------------------------------------------------------------------------------
// Multi-buffer Blake2b-256: L independent hashes in the lanes of one vector

/// Lanes per vector. AVX-512: 8, AVX2: 4, NEON and everything else: 4 (measured on Apple M5 Pro:
/// 4 lanes = 0.353 ns/byte, 2 lanes = 0.386, 6 lanes = 0.369; BENCH.md).
pub const lanes: comptime_int = switch (builtin.cpu.arch) {
    .x86_64 => if (std.Target.x86.featureSetHas(builtin.cpu.features, .avx512f)) 8 else if (std.Target.x86.featureSetHas(builtin.cpu.features, .avx2)) 4 else 2,
    else => 4,
};

fn compressLanes(comptime L: usize, h: *[8]@Vector(L, u64), mp: *const [L]*align(1) const [16]u64, t: @Vector(L, u64), last: @Vector(L, u64)) void {
    const V = @Vector(L, u64);
    var m: [16]V = undefined;
    inline for (0..16) |i| {
        var w: V = undefined;
        inline for (0..L) |l| w[l] = std.mem.littleToNative(u64, mp[l][i]);
        m[i] = w;
    }
    var v: [16]V = undefined;
    inline for (0..8) |i| {
        v[i] = h[i];
        v[8 + i] = @splat(iv[i]);
    }
    v[12] ^= t;
    v[14] ^= last;
    const r32: V = @splat(32);
    _ = r32;
    inline for (0..12) |r| {
        const s = sigma[r];
        inline for (0..8) |k| {
            const idx = if (k < 4) [4]usize{ k, 4 + k, 8 + k, 12 + k } else [4]usize{ k - 4, 4 + (k - 3) % 4, 8 + (k - 2) % 4, 12 + (k - 1) % 4 };
            vg(L, &v[idx[0]], &v[idx[1]], &v[idx[2]], &v[idx[3]], m[s[2 * k]], m[s[2 * k + 1]]);
        }
    }
    inline for (0..8) |i| h[i] ^= v[i] ^ v[8 + i];
}

inline fn vrotrL(comptime L: usize, x: @Vector(L, u64), comptime n: u6) @Vector(L, u64) {
    return (x >> @splat(n)) | (x << @splat(64 - @as(u7, n)));
}

inline fn vg(comptime L: usize, a: *@Vector(L, u64), b: *@Vector(L, u64), c: *@Vector(L, u64), d: *@Vector(L, u64), x: @Vector(L, u64), y: @Vector(L, u64)) void {
    a.* = a.* +% b.* +% x;
    d.* = vrotrL(L, d.* ^ a.*, 32);
    c.* = c.* +% d.*;
    b.* = vrotrL(L, b.* ^ c.*, 24);
    a.* = a.* +% b.* +% y;
    d.* = vrotrL(L, d.* ^ a.*, 16);
    c.* = c.* +% d.*;
    b.* = vrotrL(L, b.* ^ c.*, 63);
}

const zero_block: [128]u8 align(8) = @splat(0);

const Lane = struct {
    job: usize = std.math.maxInt(usize),
    part: usize = 0,
    off: usize = 0,
    rem: u64 = 0,
    t: u64 = 0,
    buf: [128]u8 align(8) = undefined,
    ptr: *align(1) const [16]u64 = @ptrCast(&zero_block),
    last: bool = false,
    active: bool = false,
};

/// Hashes `inputs.len` messages (each the concatenation of its parts) into `out`. Messages are
/// spread over `lanes` SIMD lanes; a lane that finishes picks up the next message, so mixed sizes
/// stay busy. Output equals `blake2b256(inputs[i])` for every i. No allocation.
pub fn blake2b256Many(inputs: []const []const []const u8, out: [][32]u8) void {
    cpu.call("blake2b256_many", blake2b256ManyImpl, .{ inputs, out });
}

pub fn blake2b256ManyImpl(inputs: []const []const []const u8, out: [][32]u8) void {
    std.debug.assert(out.len >= inputs.len);
    if (inputs.len == 1) {
        out[0] = blake2b256(inputs[0]);
    } else if (inputs.len <= 2 and lanes > 2) {
        many(2, inputs, out);
    } else if (inputs.len > 0) {
        many(lanes, inputs, out);
    }
}

fn many(comptime L: usize, inputs: []const []const []const u8, out: [][32]u8) void {
    const V = @Vector(L, u64);
    var ln: [L]Lane = @splat(.{});
    var next: usize = 0;
    var h: [8][L]u64 = undefined; // per-lane chaining state, lane-major so a lane can restart
    const param: u64 = 0x01010000 ^ 32;
    var live: usize = 0;

    const start = struct {
        fn f(l: *Lane, hh: *[8][L]u64, idx: usize, job: usize, ins: []const []const []const u8) void {
            l.job = job;
            l.part = 0;
            l.off = 0;
            l.t = 0;
            l.active = true;
            var tot: u64 = 0;
            for (ins[job]) |p| tot += p.len;
            l.rem = tot;
            for (0..8) |i| hh[i][idx] = if (i == 0) iv[0] ^ param else iv[i];
        }
    }.f;

    for (0..L) |l| {
        if (next < inputs.len) {
            start(&ln[l], &h, l, next, inputs);
            next += 1;
            live += 1;
        }
    }
    while (live > 0) {
        var ptrs: [L]*align(1) const [16]u64 = undefined;
        var ta: [L]u64 = @splat(0);
        var la: [L]u64 = @splat(0);
        for (&ln, 0..) |*l, li| {
            if (!l.active) {
                ptrs[li] = @ptrCast(&zero_block);
                continue;
            }
            const parts = inputs[l.job];
            while (l.part < parts.len and l.off == parts[l.part].len) {
                l.part += 1;
                l.off = 0;
            }
            if (l.rem > 128 and l.part < parts.len and parts[l.part].len - l.off >= 128) {
                ptrs[li] = @ptrCast(parts[l.part][l.off..].ptr);
                l.off += 128;
                l.rem -= 128;
                l.t += 128;
                l.last = false;
            } else {
                const take: usize = @intCast(@min(l.rem, 128));
                var got: usize = 0;
                while (got < take) {
                    const p = parts[l.part];
                    const n = @min(take - got, p.len - l.off);
                    @memcpy(l.buf[got..][0..n], p[l.off..][0..n]);
                    got += n;
                    l.off += n;
                    if (l.off == p.len and got < take) {
                        l.part += 1;
                        l.off = 0;
                    }
                }
                @memset(l.buf[take..], 0);
                ptrs[li] = @ptrCast(&l.buf);
                l.rem -= take;
                l.t += take;
                l.last = l.rem == 0;
            }
            ta[li] = l.t;
            la[li] = if (l.last) ~@as(u64, 0) else 0;
        }
        var hv: [8]V = undefined;
        inline for (0..8) |i| hv[i] = h[i];
        compressLanes(L, &hv, &ptrs, ta, la);
        inline for (0..8) |i| h[i] = hv[i];
        for (&ln, 0..) |*l, li| {
            if (!l.active or !l.last) continue;
            var full: [32]u8 = undefined;
            for (0..4) |i| std.mem.writeInt(u64, full[i * 8 ..][0..8], h[i][li], .little);
            out[l.job] = full;
            l.active = false;
            live -= 1;
            if (next < inputs.len) {
                start(l, &h, li, next, inputs);
                next += 1;
                live += 1;
            }
        }
    }
}

test "multi-buffer equals single-buffer for mixed sizes and part splits" {
    var prng = std.Random.DefaultPrng.init(99);
    const r = prng.random();
    var store: [4096 + 300]u8 = undefined;
    r.bytes(&store);
    const n = 53;
    var parts_store: [n][3][]const u8 = undefined;
    var inputs: [n][]const []const u8 = undefined;
    var want: [n][32]u8 = undefined;
    for (0..n) |i| {
        const sizes = [_]usize{ 0, 1, 127, 128, 129, 255, 256, 257, 1000, 4096 };
        const total = if (i < sizes.len) sizes[i] else r.uintLessThan(usize, 4096);
        const a = r.uintAtMost(usize, total);
        const b = a + r.uintAtMost(usize, total - a);
        parts_store[i] = .{ store[0..a], store[a..b], store[b..total] };
        inputs[i] = &parts_store[i];
        want[i] = blake2b256(inputs[i]);
    }
    var got: [n][32]u8 = undefined;
    blake2b256Many(&inputs, &got);
    for (want, got) |w, g2| try std.testing.expectEqualSlices(u8, &w, &g2);
    // fewer messages than lanes, and none
    for ([_]usize{ 0, 1, 2, 3, 5, 7, 9 }) |cnt| {
        var g3: [9][32]u8 = undefined;
        blake2b256Many(inputs[0..cnt], g3[0..cnt]);
        for (0..cnt) |i| try std.testing.expectEqualSlices(u8, &want[i], &g3[i]);
    }
}

test "multi-buffer kernel at every lane count (2, 4, 8) on any target" {
    // `lanes` picks one width per build; the other widths still compile everywhere, so the AVX-512
    // 8-lane path is proven on NEON/AVX2 machines too.
    var prng = std.Random.DefaultPrng.init(0x8a7e5);
    const r = prng.random();
    var store: [3000]u8 = undefined;
    r.bytes(&store);
    const n = 37;
    var parts_store: [n][4][]const u8 = undefined;
    var inputs: [n][]const []const u8 = undefined;
    var want: [n][32]u8 = undefined;
    for (0..n) |i| {
        const sizes = [_]usize{ 0, 128, 256, 129, 1, 2999, 384 };
        const total = if (i < sizes.len) sizes[i] else r.uintAtMost(usize, store.len);
        const a = r.uintAtMost(usize, total);
        const b = a + r.uintAtMost(usize, total - a);
        // an empty part in the middle of every message
        parts_store[i] = .{ store[0..a], store[a..a], store[a..b], store[b..total] };
        inputs[i] = &parts_store[i];
        want[i] = blake2b256(inputs[i]);
    }
    inline for (.{ 2, 4, 8 }) |L| {
        for ([_]usize{ 2, 3, L - 1, L, L + 1, n }) |cnt| {
            var got: [n][32]u8 = undefined;
            many(L, inputs[0..cnt], got[0..cnt]);
            for (0..cnt) |i| try std.testing.expectEqualSlices(u8, &want[i], &got[i]);
        }
    }
}
