//! Base64 as zkLogin uses it:
//! - `decodeUrlUnpadded`: base64ct `Base64UrlUnpadded::decode_vec` (strict: URL alphabet, no
//!   padding, remainder of 1 rejected, non-canonical trailing bits rejected).
//! - `encodeUrlUnpadded`: base64ct `encode`.
//! - `decodeBase64UrlBits`: fastcrypto-zkp `decode_base64_url(s, index_mod_4)`, the bit-array
//!   decoder for the iss claim slice of a JWT.
const std = @import("std");
const Fail = @import("errors.zig").Fail;

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const rev: [256]u8 = blk: {
    var t: [256]u8 = @splat(0xff);
    for (alphabet, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

pub fn decodedLen(n: usize) usize {
    return (n / 4) * 3 + ((n % 4) * 3) / 4;
}

pub fn encodedLen(n: usize) usize {
    return (n / 3) * 4 + ((n % 3) * 4 + 2) / 3;
}

/// Strict URL-safe unpadded decode into `out` (needs decodedLen(src.len) bytes).
pub fn decodeUrlUnpadded(src: []const u8, out: []u8) ?[]u8 {
    if (src.len % 4 == 1) return null;
    const n = decodedLen(src.len);
    if (out.len < n) return null;
    var o: usize = 0;
    var i: usize = 0;
    while (i + 4 <= src.len) : (i += 4) {
        var v: u32 = 0;
        for (0..4) |k| {
            const d = rev[src[i + k]];
            if (d == 0xff) return null;
            v = (v << 6) | d;
        }
        out[o] = @truncate(v >> 16);
        out[o + 1] = @truncate(v >> 8);
        out[o + 2] = @truncate(v);
        o += 3;
    }
    const rem = src.len - i;
    if (rem > 0) {
        var v: u32 = 0;
        for (0..rem) |k| {
            const d = rev[src[i + k]];
            if (d == 0xff) return null;
            v = (v << 6) | d;
        }
        if (rem == 2) {
            if (v & 0xf != 0) return null; // non-canonical trailing bits
            out[o] = @truncate(v >> 4);
            o += 1;
        } else { // rem == 3
            if (v & 0x3 != 0) return null;
            out[o] = @truncate(v >> 10);
            out[o + 1] = @truncate(v >> 2);
            o += 2;
        }
    }
    return out[0..o];
}

pub fn encodeUrlUnpadded(src: []const u8, out: []u8) []u8 {
    var o: usize = 0;
    var i: usize = 0;
    while (i + 3 <= src.len) : (i += 3) {
        const v = (@as(u32, src[i]) << 16) | (@as(u32, src[i + 1]) << 8) | src[i + 2];
        inline for (0..4) |k| out[o + k] = alphabet[(v >> (18 - 6 * k)) & 63];
        o += 4;
    }
    const rem = src.len - i;
    if (rem == 1) {
        const v = @as(u32, src[i]) << 16;
        out[o] = alphabet[(v >> 18) & 63];
        out[o + 1] = alphabet[(v >> 12) & 63];
        o += 2;
    } else if (rem == 2) {
        const v = (@as(u32, src[i]) << 16) | (@as(u32, src[i + 1]) << 8);
        out[o] = alphabet[(v >> 18) & 63];
        out[o + 1] = alphabet[(v >> 12) & 63];
        out[o + 2] = alphabet[(v >> 6) & 63];
        o += 3;
    }
    return out[0..o];
}

/// fastcrypto-zkp `decode_base64_url(s, i)`: decode `s` as a bit string after dropping 0, 2 or
/// 4 leading bits (i = 0, 1, 2) and the matching trailing bits; output must be UTF-8.
/// `out` needs at least s.len bytes. Errors mirror the Rust messages and order.
pub fn decodeBase64UrlBits(s: []const u8, index_mod_4: u8, out: []u8, fail: *Fail) ?[]u8 {
    if (s.len < 2) {
        fail.* = .{ .general = "Base64 string smaller than 2" };
        return null;
    }
    // base64_to_bitarray iterates chars: any byte outside the alphabet (including the lead
    // byte of a multi-byte UTF-8 char) is InvalidInput.
    for (s) |c| if (rev[c] == 0xff) {
        fail.* = .invalid_input;
        return null;
    };
    var drop_front: usize = undefined;
    switch (index_mod_4) {
        0 => drop_front = 0,
        1 => drop_front = 2,
        2 => drop_front = 4,
        else => {
            fail.* = .{ .general = "Invalid first_char_offset" };
            return null;
        },
    }
    // (i + s.len() as u8 - 1) % 4 in wrapping u8 arithmetic (release build, no overflow checks).
    const last: u8 = (index_mod_4 +% @as(u8, @truncate(s.len)) -% 1) % 4;
    var drop_back: usize = undefined;
    switch (last) {
        3 => drop_back = 0,
        2 => drop_back = 2,
        1 => drop_back = 4,
        else => {
            fail.* = .{ .general = "Invalid last_char_offset" };
            return null;
        },
    }
    const total = s.len * 6;
    if (drop_front + drop_back > total) {
        // Rust: bits.drain(bits.len() - k..) panics when fewer bits remain; unreachable for
        // len >= 2 (12 bits >= 8 dropped).
        unreachable;
    }
    const nbits = total - drop_front - drop_back;
    if (nbits % 8 != 0) {
        fail.* = .{ .general = "Invalid bits length" };
        return null;
    }
    const nbytes = nbits / 8;
    if (out.len < nbytes) @panic("decodeBase64UrlBits: output buffer too small");
    // Bit k of the kept string is bit (drop_front + k) of the 6-bit big-endian stream.
    for (0..nbytes) |bi| {
        var byte: u8 = 0;
        for (0..8) |bit| {
            const pos = drop_front + bi * 8 + bit;
            const d = rev[s[pos / 6]];
            const v: u8 = @intCast((d >> @intCast(5 - pos % 6)) & 1);
            byte = (byte << 1) | v;
        }
        out[bi] = byte;
    }
    if (!std.unicode.utf8ValidateSlice(out[0..nbytes])) {
        fail.* = .{ .general = "Invalid UTF8 string" };
        return null;
    }
    return out[0..nbytes];
}

test "base64" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hello", decodeUrlUnpadded("aGVsbG8", &buf).?);
    try std.testing.expect(decodeUrlUnpadded("aGVsbG9", &buf) == null); // non-canonical
    try std.testing.expect(decodeUrlUnpadded("aGVsbG8=", &buf) == null); // padding
    var e: [16]u8 = undefined;
    try std.testing.expectEqualStrings("aGVsbG8", encodeUrlUnpadded("hello", &e));
    var f: Fail = .none;
    // claim from Sui's test inputs: "wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw", index 2
    const got = decodeBase64UrlBits("wiaXNzIjoiaHR0cHM6Ly9pZC50d2l0Y2gudHYvb2F1dGgyIiw", 2, &buf, &f).?;
    try std.testing.expectEqualStrings("\"iss\":\"https://id.twitch.tv/oauth2\",", got);
}
