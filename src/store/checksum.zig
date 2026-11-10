//! The store's checksum and hash: a pinned copy of Wyhash (final v4, the variant Zig 0.17.1's
//! std.hash.Wyhash implements, upstream test vectors below). Every on-disk checksum (records,
//! commit chains, meta, index pages, run files) and every on-disk hash table position uses this
//! copy, never std, so a toolchain upgrade cannot silently change the format. The algorithm id is
//! written into every segment, meta, run and journal header; an unknown id is refused.
const std = @import("std");

/// On-disk id of this algorithm. A new algorithm gets a new id; old files keep theirs.
pub const algo_wyhash_v4: u32 = 1;
pub const current_algo: u32 = algo_wyhash_v4;

const secret = [4]u64{
    0xa0761d6478bd642f,
    0xe7037ed1a0b428db,
    0x8ebc6af09c88c6e3,
    0x589965cc75374cc3,
};

inline fn read(comptime bytes: usize, data: []const u8) u64 {
    const T = @Int(.unsigned, 8 * bytes);
    return @as(u64, std.mem.readInt(T, data[0..bytes], .little));
}

inline fn mum(a: *u64, b: *u64) void {
    const x = @as(u128, a.*) *% b.*;
    a.* = @truncate(x);
    b.* = @truncate(x >> 64);
}

inline fn mix(a_: u64, b_: u64) u64 {
    var a = a_;
    var b = b_;
    mum(&a, &b);
    return a ^ b;
}

/// Wyhash of `input` with `seed` (one shot).
pub fn hash(seed: u64, input: []const u8) u64 {
    var s0 = seed ^ mix(seed ^ secret[0], secret[1]);
    var a: u64 = 0;
    var b: u64 = 0;
    if (input.len <= 16) {
        if (input.len >= 4) {
            const end = input.len - 4;
            const quarter = (input.len >> 3) << 2;
            a = (read(4, input[0..]) << 32) | read(4, input[quarter..]);
            b = (read(4, input[end..]) << 32) | read(4, input[end - quarter ..]);
        } else if (input.len > 0) {
            a = (@as(u64, input[0]) << 16) | (@as(u64, input[input.len >> 1]) << 8) | input[input.len - 1];
            b = 0;
        }
    } else {
        var i: usize = 0;
        if (input.len >= 48) {
            var s1 = s0;
            var s2 = s0;
            while (i + 48 < input.len) : (i += 48) {
                const p = input[i..][0..48];
                s0 = mix(read(8, p[0..]) ^ secret[1], read(8, p[8..]) ^ s0);
                s1 = mix(read(8, p[16..]) ^ secret[2], read(8, p[24..]) ^ s1);
                s2 = mix(read(8, p[32..]) ^ secret[3], read(8, p[40..]) ^ s2);
            }
            s0 ^= s1 ^ s2;
        }
        const rest = input[i..];
        var j: usize = 0;
        while (j + 16 < rest.len) : (j += 16) {
            s0 = mix(read(8, rest[j..]) ^ secret[1], read(8, rest[j + 8 ..]) ^ s0);
        }
        a = read(8, input[input.len - 16 ..]);
        b = read(8, input[input.len - 8 ..]);
    }
    a ^= secret[1];
    b ^= s0;
    mum(&a, &b);
    return mix(a ^ secret[0] ^ input.len, b ^ secret[1]);
}

/// Hash of one u64 (little endian), e.g. for chaining checksums.
pub fn hash64(seed: u64, x: u64) u64 {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, x, .little);
    return hash(seed, &b);
}

const Vector = struct { seed: u64, input: []const u8, expected: u64 };

// Upstream wyhash test_vector.cpp (wangyi-fudan/wyhash@77e50f2), as std.hash.Wyhash checks.
const upstream = [_]Vector{
    .{ .seed = 0, .expected = 0x409638ee2bde459, .input = "" },
    .{ .seed = 1, .expected = 0xa8412d091b5fe0a9, .input = "a" },
    .{ .seed = 2, .expected = 0x32dd92e4b2915153, .input = "abc" },
    .{ .seed = 3, .expected = 0x8619124089a3a16b, .input = "message digest" },
    .{ .seed = 4, .expected = 0x7a43afb61d7f5f40, .input = "abcdefghijklmnopqrstuvwxyz" },
    .{ .seed = 5, .expected = 0xff42329b90e50d58, .input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" },
    .{ .seed = 6, .expected = 0xc39cab13b115aad3, .input = "12345678901234567890123456789012345678901234567890123456789012345678901234567890" },
};

test "upstream wyhash vectors" {
    for (upstream) |v| try std.testing.expectEqual(v.expected, hash(v.seed, v.input));
}

// Pinned format vectors: lengths around every branch (0..16 small keys, 17..48 tail loop,
// 48-byte rounds and the exact-multiple case), fixed when the format was pinned. If one of
// these changes, every store on disk becomes unreadable: never edit them.
test "pinned format vectors" {
    var buf: [300]u8 = undefined;
    for (&buf, 0..) |*x, i| x.* = @truncate(i *% 31 +% 7);
    const lens = [_]usize{ 0, 1, 3, 4, 8, 15, 16, 17, 32, 47, 48, 49, 95, 96, 97, 144, 145, 300 };
    const want = [_]u64{
        0x7f5da66faf3801b5, 0x1c0cbb9fdbc8399c, 0xb5e01d40dfdbaac6, 0xc19c6e54cc4435ad,
        0xf017c8f7b8a623c7, 0x5a3579436ceb267b, 0x517c09a523c7d5fc, 0xbd22cde0c430ddcb,
        0x5dbd3ea0e2212946, 0xcf5148a1708cade3, 0xdae8918914e208be, 0x3fb1e1b9fa34d6db,
        0xfc7e045ff68a0480, 0xe2a10278b6ffa697, 0xa319a3e158674dc2, 0xebaa6112b237287b,
        0xff3e26d239e4cd87, 0xcc80cfd4bcf3898e,
    };
    for (lens, want) |n, w| try std.testing.expectEqual(w, hash(0x7a75692d7374, buf[0..n]));
}

test "hash64" {
    try std.testing.expectEqual(hash(9, &std.mem.toBytes(std.mem.nativeToLittle(u64, 77))), hash64(9, 77));
}
