//! Base58 (Bitcoin alphabet) of a 32-byte digest, the Display form of every Sui digest.
const std = @import("std");

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Two base58 digits (high, low) for every value below 58^2.
const pairs: [3364][2]u8 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [3364][2]u8 = undefined;
    for (0..58) |hi| for (0..58) |lo| {
        t[hi * 58 + lo] = .{ alphabet[hi], alphabet[lo] };
    };
    break :blk t;
};

pub const max_len_32 = 44;

/// Writes the base58 text of `in` into `out` (at least 44 bytes for 32 input bytes) and
/// returns it. The value is eight big-endian 32-bit words; each pass divides it by 58^5
/// (a constant, so the divisions are multiplications) and emits the remainder as 5 digits.
pub fn encode32(out: *[max_len_32]u8, in: *const [32]u8) []const u8 {
    const base: u64 = 656356768; // 58^5
    var w: [8]u32 = undefined;
    inline for (0..8) |i| w[i] = std.mem.readInt(u32, in[4 * i ..][0..4], .big);
    var tmp: [45]u8 = undefined;
    var t: usize = 0;
    var start: usize = 0;
    while (start < 8 and w[start] == 0) start += 1;
    while (start < 8) {
        var rem: u64 = 0;
        var i: usize = start;
        while (i < 8) : (i += 1) {
            const cur = (rem << 32) | w[i];
            w[i] = @intCast(cur / base);
            rem = cur % base;
        }
        while (start < 8 and w[start] == 0) start += 1;
        // five digits, least significant first: v = d4*58^4 + ... + d0
        const v: u32 = @intCast(rem);
        const q = v / 3364; // d4..d2 as a 3-digit value below 58^3
        const lo = pairs[v - q * 3364]; // d1 d0
        const q2 = q / 58;
        const mid = alphabet[q - q2 * 58]; // d2
        const hi = pairs[q2]; // d4 d3
        tmp[t] = lo[1];
        tmp[t + 1] = lo[0];
        tmp[t + 2] = mid;
        tmp[t + 3] = hi[1];
        tmp[t + 4] = hi[0];
        t += 5;
    }
    while (t > 0 and tmp[t - 1] == alphabet[0]) t -= 1;
    var zeros: usize = 0;
    while (zeros < 32 and in[zeros] == 0) zeros += 1;
    var o: usize = 0;
    while (o < zeros) : (o += 1) out[o] = alphabet[0];
    var i: usize = t;
    while (i > 0) {
        i -= 1;
        out[o] = tmp[i];
        o += 1;
    }
    return out[0..o];
}

const Entry = struct { key: [32]u8 = @splat(0), len: u8 = 0, text: [max_len_32]u8 = undefined };
threadlocal var cache: [256]Entry = @splat(.{});

/// `encode32` through a small direct-mapped cache: the same digest is written several times per
/// transaction (transaction digest, effects, dependencies of later transactions). Returns a
/// slice of `out` like `encode32`.
pub fn encode32Cached(out: *[max_len_32]u8, in: *const [32]u8) []const u8 {
    const e = &cache[in[0]];
    if (e.len != 0 and std.mem.eql(u8, &e.key, in)) {
        @memcpy(out[0..e.len], e.text[0..e.len]);
        return out[0..e.len];
    }
    const r = encode32(out, in);
    e.key = in.*;
    e.len = @intCast(r.len);
    @memcpy(e.text[0..r.len], r);
    return r;
}

const decode_table: [128]u8 = blk: {
    var t: [128]u8 = @splat(0xff);
    for (alphabet, 0..) |ch, i| t[ch] = i;
    break :blk t;
};

/// sui-sdk-types `Digest::from_str`: `bs58::decode(text).into_array_const::<32>()`. Any text that
/// decodes to at most 32 bytes is accepted and the decoded bytes are zero-padded on the right
/// ("" is the zero digest, "2" is 01 00 .. 00); null for a character outside the alphabet or more
/// than 32 decoded bytes (leading '1's count as zero bytes). Same steps as bs58's
/// `decode_into_const`: a little-endian accumulator, then the leading-'1' zeros, then a reverse of
/// the used prefix.
pub fn decode32(text: []const u8) ?[32]u8 {
    var out: [32]u8 = @splat(0);
    var index: usize = 0;
    for (text) |ch| {
        if (ch > 127) return null;
        const d = decode_table[ch];
        if (d == 0xff) return null;
        var val: u32 = d;
        for (out[0..index]) |*b| {
            val += @as(u32, b.*) * 58;
            b.* = @truncate(val);
            val >>= 8;
        }
        while (val > 0) {
            if (index >= out.len) return null;
            out[index] = @truncate(val);
            index += 1;
            val >>= 8;
        }
    }
    for (text) |ch| {
        if (ch != alphabet[0]) break;
        if (index >= out.len) return null;
        out[index] = 0;
        index += 1;
    }
    std.mem.reverse(u8, out[0..index]);
    return out;
}

test "decode32 round trip" {
    var out: [max_len_32]u8 = undefined;
    var x: [32]u8 = undefined;
    for (0..64) |seed| {
        for (&x, 0..) |*b, i| b.* = @truncate(seed *% 37 +% i *% 11);
        if (seed % 5 == 0) x[0] = 0;
        const t = encode32(&out, &x);
        try std.testing.expectEqualSlices(u8, &x, &decode32(t).?);
    }
    try std.testing.expect(decode32("0OIl") == null);
    try std.testing.expect(decode32("abc\xff") == null);
    // bs58 into_array_const::<32>: short values are zero-padded on the right
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &decode32("").?);
    var two: [32]u8 = @splat(0);
    two[0] = 1;
    try std.testing.expectEqualSlices(u8, &two, &decode32("2").?);
    var lead: [32]u8 = @splat(0);
    lead[1] = 1;
    try std.testing.expectEqualSlices(u8, &lead, &decode32("12").?);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0)), &decode32("11111111111111111111111111111111").?);
    try std.testing.expect(decode32("111111111111111111111111111111111") == null);
    try std.testing.expect(decode32("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFGG") == null);
}

test "encode32 equals the bytewise reference" {
    const alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    var prng = std.Random.DefaultPrng.init(58);
    var out: [max_len_32]u8 = undefined;
    for (0..20000) |n| {
        var x: [32]u8 = undefined;
        prng.random().bytes(&x);
        const zeros = n % 34;
        for (x[0..@min(zeros, 32)]) |*b| b.* = 0;
        // reference: repeated division of the byte string by 58
        var num = x;
        var digits: [64]u8 = undefined;
        var nd: usize = 0;
        var lead: usize = 0;
        while (lead < 32 and num[lead] == 0) lead += 1;
        var begin: usize = lead;
        while (begin < 32) {
            var rem: u32 = 0;
            for (begin..32) |i| {
                const cur = rem * 256 + num[i];
                num[i] = @intCast(cur / 58);
                rem = cur % 58;
            }
            digits[nd] = alpha[rem];
            nd += 1;
            while (begin < 32 and num[begin] == 0) begin += 1;
        }
        var expect: [80]u8 = undefined;
        var e: usize = 0;
        for (0..lead) |_| {
            expect[e] = '1';
            e += 1;
        }
        var k = nd;
        while (k > 0) {
            k -= 1;
            expect[e] = digits[k];
            e += 1;
        }
        try std.testing.expectEqualStrings(expect[0..e], encode32(&out, &x));
    }
}

test "known digests" {
    var out: [max_len_32]u8 = undefined;
    var z: [32]u8 = @splat(0);
    try std.testing.expectEqualStrings("11111111111111111111111111111111", encode32(&out, &z));
    var one: [32]u8 = @splat(0);
    one[31] = 1;
    try std.testing.expectEqualStrings("11111111111111111111111111111112", encode32(&out, &one));
    var ff: [32]u8 = @splat(0xff);
    try std.testing.expectEqualStrings("JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG", encode32(&out, &ff));
}
