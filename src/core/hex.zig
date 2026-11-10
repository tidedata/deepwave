//! Hex helpers for tests, truth files and logs. Not for hot paths.
const std = @import("std");

pub const Error = error{ InvalidHexLength, InvalidHexCharacter };

/// Decodes hex (optional 0x prefix) into `out`. `out.len` must be exactly half the digits.
pub fn decode(out: []u8, text: []const u8) Error!void {
    const s = strip(text);
    if (s.len != out.len * 2) return error.InvalidHexLength;
    for (out, 0..) |*b, i| b.* = (try nibble(s[2 * i]) << 4) | try nibble(s[2 * i + 1]);
}

/// Decodes hex into a newly allocated slice.
pub fn decodeAlloc(gpa: std.mem.Allocator, text: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    const s = strip(text);
    if (s.len % 2 != 0) return error.InvalidHexLength;
    const out = try gpa.alloc(u8, s.len / 2);
    errdefer gpa.free(out);
    try decode(out, s);
    return out;
}

/// Comptime hex literal: `const k = hex.lit("00ff");` gives a `[2]u8`.
pub fn lit(comptime text: []const u8) [strip(text).len / 2]u8 {
    return comptime blk: {
        @setEvalBranchQuota(100_000);
        var out: [strip(text).len / 2]u8 = undefined;
        decode(&out, text) catch @compileError("bad hex literal: " ++ text);
        break :blk out;
    };
}

/// Lowercase hex into `out` (len = 2 * bytes.len).
pub fn encode(out: []u8, bytes: []const u8) void {
    const digits = "0123456789abcdef";
    std.debug.assert(out.len == bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 15];
    }
}

pub fn encodeAlloc(gpa: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, bytes.len * 2);
    encode(out, bytes);
    return out;
}

fn strip(text: []const u8) []const u8 {
    return if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) text[2..] else text;
}

fn nibble(c: u8) Error!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidHexCharacter,
    };
}

test "hex round trip" {
    const k = lit("0x00ff10");
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0xff, 0x10 }, &k);
    var buf: [6]u8 = undefined;
    encode(&buf, &k);
    try std.testing.expectEqualStrings("00ff10", &buf);
    try std.testing.expectError(error.InvalidHexLength, decode(buf[0..1], "abc"));
}
