//! QPACK (RFC 9204), the minimum WebTransport needs: static table only (we advertise
//! SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 and SETTINGS_QPACK_BLOCKED_STREAMS = 0), so a field
//! section must have Required Insert Count 0 and may not reference the dynamic table. Huffman
//! decoding and prefix integers come from the h2 HPACK code (same Huffman code, same integers).
//! The encoder writes static references or plain literals (no Huffman, nothing to the encoder
//! stream).
const std = @import("std");
const Allocator = std.mem.Allocator;
const hpack = @import("serve").h2.hpack;

pub const Error = error{ Malformed, TooLarge, OutOfMemory };

pub const Field = struct { name: []const u8, value: []const u8 };

/// Largest field section we decode (Chrome's CONNECT is about 200 bytes).
pub const max_section = 16 << 10;

/// RFC 9204 Appendix A.
pub const static_table = [_]Field{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

comptime {
    std.debug.assert(static_table.len == 99);
}

/// String literal whose length prefix has `prefix_bits` bits and whose Huffman flag is the bit
/// just above them.
fn readString(arena: Allocator, block: []const u8, pos: *usize, prefix_bits: u4) Error![]const u8 {
    if (pos.* >= block.len) return error.Malformed;
    const huffman = (block[pos.*] >> @as(u3, @intCast(prefix_bits))) & 1 == 1;
    const len = try hpack.readInt(block, pos, prefix_bits);
    if (len > block.len - pos.*) return error.Malformed;
    const raw = block[pos.*..][0..@intCast(len)];
    pos.* += @intCast(len);
    if (!huffman) return raw;
    var out: std.ArrayList(u8) = .empty;
    try hpack.huffmanDecode(&out, arena, raw);
    return out.items;
}

fn staticEntry(idx: u64) Error!Field {
    if (idx >= static_table.len) return error.Malformed;
    return static_table[@intCast(idx)];
}

/// Decodes one encoded field section (the payload of an HTTP/3 HEADERS frame). Strings point
/// into `block` or into `arena`.
pub fn decodeFieldSection(arena: Allocator, block: []const u8) Error![]Field {
    if (block.len > max_section) return error.TooLarge;
    var pos: usize = 0;
    // Encoded field section prefix: Required Insert Count (8-bit prefix), S + Delta Base (7-bit).
    if (try hpack.readInt(block, &pos, 8) != 0) return error.Malformed;
    _ = try hpack.readInt(block, &pos, 7);
    var fields: std.ArrayList(Field) = .empty;
    while (pos < block.len) {
        const b = block[pos];
        if (b & 0x80 != 0) {
            // Indexed field line: 1 T index(6)
            if (b & 0x40 == 0) return error.Malformed; // dynamic table
            try fields.append(arena, try staticEntry(try hpack.readInt(block, &pos, 6)));
        } else if (b & 0x40 != 0) {
            // Literal with name reference: 01 N T index(4), value H len(7)
            if (b & 0x10 == 0) return error.Malformed; // dynamic table
            const e = try staticEntry(try hpack.readInt(block, &pos, 4));
            try fields.append(arena, .{ .name = e.name, .value = try readString(arena, block, &pos, 7) });
        } else if (b & 0x20 != 0) {
            // Literal with literal name: 001 N H len(3) name, value H len(7)
            const name = try readString(arena, block, &pos, 3);
            try fields.append(arena, .{ .name = name, .value = try readString(arena, block, &pos, 7) });
        } else {
            // 0001xxxx indexed post-base, 0000xxxx literal with post-base name reference
            return error.Malformed;
        }
    }
    return fields.items;
}

/// Encodes a field section with the static table only (Required Insert Count 0, no Huffman).
pub fn encodeFieldSection(out: *std.ArrayList(u8), gpa: Allocator, fields: []const Field) Allocator.Error!void {
    try out.appendSlice(gpa, &.{ 0x00, 0x00 });
    for (fields) |f| {
        var name_idx: ?usize = null;
        var exact: ?usize = null;
        for (static_table, 0..) |e, i| {
            if (!std.mem.eql(u8, e.name, f.name)) continue;
            if (name_idx == null) name_idx = i;
            if (std.mem.eql(u8, e.value, f.value)) {
                exact = i;
                break;
            }
        }
        if (exact) |i| {
            try hpack.writeInt(out, gpa, 0xC0, 6, i);
        } else if (name_idx) |i| {
            try hpack.writeInt(out, gpa, 0x50, 4, i);
            try hpack.writeInt(out, gpa, 0x00, 7, f.value.len);
            try out.appendSlice(gpa, f.value);
        } else {
            try hpack.writeInt(out, gpa, 0x20, 3, f.name.len);
            try out.appendSlice(gpa, f.name);
            try hpack.writeInt(out, gpa, 0x00, 7, f.value.len);
            try out.appendSlice(gpa, f.value);
        }
    }
}

/// First value of `name` (names are lowercase on the wire).
pub fn get(fields: []const Field, name: []const u8) ?[]const u8 {
    for (fields) |f| if (std.mem.eql(u8, f.name, name)) return f.value;
    return null;
}

const testing = std.testing;

test "RFC 9204 B.1 literal with static name reference" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const block = [_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*;
    const f = try decodeFieldSection(arena_state.allocator(), &block);
    try testing.expectEqual(@as(usize, 1), f.len);
    try testing.expectEqualStrings(":path", f[0].name);
    try testing.expectEqualStrings("/index.html", f[0].value);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodeFieldSection(&out, testing.allocator, f);
    try testing.expectEqualSlices(u8, &block, out.items);
}

test "indexed static, Huffman value, literal name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // :method CONNECT (indexed 15), :authority "www.example.com" Huffman (RFC 7541 C.4.1 bytes),
    // literal name "x-a" value "b".
    const block = [_]u8{ 0x00, 0x00, 0xC0 | 15, 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff, 0x23, 'x', '-', 'a', 0x01, 'b' };
    const f = try decodeFieldSection(arena_state.allocator(), &block);
    try testing.expectEqual(@as(usize, 3), f.len);
    try testing.expectEqualStrings("CONNECT", f[0].value);
    try testing.expectEqualStrings(":authority", f[1].name);
    try testing.expectEqualStrings("www.example.com", f[1].value);
    try testing.expectEqualStrings("x-a", f[2].name);
    try testing.expectEqualStrings("b", f[2].value);
}

test "dynamic references and nonzero insert count are refused" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectError(error.Malformed, decodeFieldSection(a, &.{ 0x01, 0x00, 0xC1 }));
    try testing.expectError(error.Malformed, decodeFieldSection(a, &.{ 0x00, 0x00, 0x80 })); // dynamic indexed
    try testing.expectError(error.Malformed, decodeFieldSection(a, &.{ 0x00, 0x00, 0x10 })); // post-base
    try testing.expectError(error.Malformed, decodeFieldSection(a, &.{ 0x00, 0x00, 0x40, 0x00 })); // dynamic name ref
    try testing.expectError(error.Malformed, decodeFieldSection(a, &.{ 0x00, 0x00, 0xC0 | 63, 0x7f })); // index out of range
    try testing.expectError(error.Malformed, decodeFieldSection(a, &.{ 0x00, 0x00, 0x51, 0x05, 'a' })); // short string
}

test "Chrome-like CONNECT round trip" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const req = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost:9443" },
        .{ .name = ":path", .value = "/zui/1?token=abc" },
        .{ .name = "origin", .value = "http://localhost:8000" },
        .{ .name = "sec-webtransport-http3-draft02", .value = "1" },
        .{ .name = "user-agent", .value = "Mozilla/5.0 HeadlessChrome" },
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try encodeFieldSection(&out, testing.allocator, &req);
    const got = try decodeFieldSection(arena_state.allocator(), out.items);
    try testing.expectEqual(req.len, got.len);
    for (req, got) |w, g| {
        try testing.expectEqualStrings(w.name, g.name);
        try testing.expectEqualStrings(w.value, g.value);
    }
    try testing.expectEqualStrings("webtransport", get(got, ":protocol").?);
    // :method CONNECT is one indexed byte.
    try testing.expectEqual(@as(u8, 0xC0 | 15), out.items[2]);
}
