//! gRPC message compression and grpc-web text helpers.
//!
//! sui-node (tonic 0.14, `send_compressed(Zstd)` on every sui.rpc service but SubscriptionService)
//! compresses a response with the first of `gzip` / `zstd` named in the client's
//! `grpc-accept-encoding` (tonic only checks that some encoding is enabled, so `gzip` is answered
//! too; `deflate` is not compiled in). Compressed requests are rejected (no `accept_compressed`).
//! zstd frames come from `zstd.zig` (LZ77 + predefined FSE sequences); `zstdRaw` (stored blocks)
//! stays as a reference encoder for tests.
const std = @import("std");
const Allocator = std.mem.Allocator;
const flate = std.compress.flate;

pub const Encoding = enum {
    identity,
    gzip,
    zstd,

    pub fn name(e: Encoding) []const u8 {
        return switch (e) {
            .identity => "identity",
            .gzip => "gzip",
            .zstd => "zstd",
        };
    }
};

/// tonic `from_accept_encoding_header`: the first comma-separated value that is `gzip` or `zstd`.
/// tonic-web 0.14.6 `is_grpc_web`: the content-type equals one of four values exactly (no
/// parameters, case-sensitive); anything else is not gRPC-web (vectors h1-ct-json,
/// h1-ct-charset, h1-ct-upper answer HTTP 400).
pub const WebKind = enum { none, binary, text };
pub fn grpcWebKind(content_type: []const u8) WebKind {
    const eql = std.mem.eql;
    if (eql(u8, content_type, "application/grpc-web") or eql(u8, content_type, "application/grpc-web+proto")) return .binary;
    if (eql(u8, content_type, "application/grpc-web-text") or eql(u8, content_type, "application/grpc-web-text+proto")) return .text;
    return .none;
}

/// tonic-web `Encoding::from_accept`: base64 output only when `accept` equals one of the two
/// text types exactly (`accept: application/grpc-web-text, */*` gets binary: h1-accept-multi).
pub fn textAccept(accept: []const u8) bool {
    return std.mem.eql(u8, accept, "application/grpc-web-text") or std.mem.eql(u8, accept, "application/grpc-web-text+proto");
}

pub fn pickAccept(header: []const u8) Encoding {
    var it = std.mem.splitScalar(u8, header, ',');
    while (it.next()) |raw| {
        const v = std.mem.trim(u8, raw, " \t");
        if (std.mem.eql(u8, v, "gzip")) return .gzip;
        if (std.mem.eql(u8, v, "zstd")) return .zstd;
    }
    return .identity;
}

/// Compressed copy of `payload` (caller frees).
pub fn compress(gpa: Allocator, e: Encoding, payload: []const u8) ![]u8 {
    return switch (e) {
        .identity => gpa.dupe(u8, payload),
        .zstd => @import("zstd.zig").compress(gpa, payload),
        .gzip => gzip(gpa, payload),
    };
}

const zstd_block_max = 128 * 1024;

/// A zstd frame (RFC 8878) holding `payload` in raw blocks: Single_Segment with the content size.
pub fn zstdRaw(gpa: Allocator, payload: []const u8) ![]u8 {
    const n = payload.len;
    const fcs_len: usize, const fcs_flag: u8 = if (n < 256) .{ 1, 0 } else if (n < 65536 + 256) .{ 2, 1 } else if (n <= 0xffff_ffff) .{ 4, 2 } else .{ 8, 3 };
    const blocks = @max(1, (n + zstd_block_max - 1) / zstd_block_max);
    const out = try gpa.alloc(u8, 4 + 1 + fcs_len + blocks * 3 + n);
    @memcpy(out[0..4], &[_]u8{ 0x28, 0xb5, 0x2f, 0xfd });
    out[4] = (fcs_flag << 6) | (1 << 5); // Single_Segment_flag, no checksum, no dictionary
    var p: usize = 5;
    switch (fcs_len) {
        1 => out[p] = @intCast(n),
        2 => std.mem.writeInt(u16, out[p..][0..2], @intCast(n - 256), .little),
        4 => std.mem.writeInt(u32, out[p..][0..4], @intCast(n), .little),
        else => std.mem.writeInt(u64, out[p..][0..8], n, .little),
    }
    p += fcs_len;
    var off: usize = 0;
    var b: usize = 0;
    while (b < blocks) : (b += 1) {
        const len = @min(zstd_block_max, n - off);
        const last: u32 = if (b + 1 == blocks) 1 else 0;
        const hdr: u32 = last | (0 << 1) | (@as(u32, @intCast(len)) << 3); // Raw_Block
        out[p] = @truncate(hdr);
        out[p + 1] = @truncate(hdr >> 8);
        out[p + 2] = @truncate(hdr >> 16);
        p += 3;
        @memcpy(out[p..][0..len], payload[off..][0..len]);
        p += len;
        off += len;
    }
    std.debug.assert(p == out.len);
    return out;
}

pub fn gzip(gpa: Allocator, payload: []const u8) ![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, 64 + payload.len / 2);
    errdefer out.deinit();
    const window = try gpa.alloc(u8, flate.max_window_len);
    defer gpa.free(window);
    const c = try gpa.create(flate.Compress);
    defer gpa.destroy(c);
    c.* = try flate.Compress.init(&out.writer, window, .gzip, .default);
    try c.writer.writeAll(payload);
    try c.finish();
    return out.toOwnedSlice();
}

/// tonic `Status` message encoding: CONTROLS, non-ASCII and ` "#%<>`?{}` are percent-encoded.
pub fn percentEncode(list: *std.ArrayList(u8), gpa: Allocator, text: []const u8) !void {
    for (text) |ch| {
        const enc = ch < 0x20 or ch >= 0x7f or switch (ch) {
            ' ', '"', '#', '%', '<', '>', '`', '?', '{', '}' => true,
            else => false,
        };
        if (enc) {
            var pb: [3]u8 = undefined;
            _ = std.fmt.bufPrint(&pb, "%{X:0>2}", .{ch}) catch unreachable;
            try list.appendSlice(gpa, &pb);
        } else try list.append(gpa, ch);
    }
}

/// Decodes grpc-web-text: concatenated base64 chunks, each possibly padded (tonic-web accepts it).
pub fn base64DecodeChunks(gpa: Allocator, text: []const u8) ![]u8 {
    const d = std.base64.standard.Decoder;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var clean: std.ArrayList(u8) = .empty;
    defer clean.deinit(gpa);
    for (text) |ch| switch (ch) {
        ' ', '\t', '\r', '\n' => {},
        else => try clean.append(gpa, ch),
    };
    const s = clean.items;
    var i: usize = 0;
    while (i < s.len) {
        // one chunk ends after a quartet containing '='
        var j = i;
        while (j < s.len) : (j += 4) {
            if (j + 4 > s.len) return error.InvalidBase64;
            if (std.mem.indexOfScalar(u8, s[j .. j + 4], '=') != null) {
                j += 4;
                break;
            }
        } else {}
        const chunk = s[i..j];
        const n = d.calcSizeForSlice(chunk) catch return error.InvalidBase64;
        const at = out.items.len;
        try out.resize(gpa, at + n);
        d.decode(out.items[at..][0..n], chunk) catch return error.InvalidBase64;
        i = j;
    }
    return out.toOwnedSlice(gpa);
}

test "zstd raw frames decode with std" {
    const gpa = std.testing.allocator;
    for ([_]usize{ 0, 1, 200, 255, 256, 70000, 300_000 }) |n| {
        const src = try gpa.alloc(u8, n);
        defer gpa.free(src);
        for (src, 0..) |*b, i| b.* = @truncate(i *% 7);
        const z = try zstdRaw(gpa, src);
        defer gpa.free(z);
        var in: std.Io.Reader = .fixed(z);
        var dbuf: [std.compress.zstd.default_window_len + std.compress.zstd.block_size_max]u8 = undefined;
        var dz: std.compress.zstd.Decompress = .init(&in, &dbuf, .{});
        const got = try dz.reader.allocRemaining(gpa, .unlimited);
        defer gpa.free(got);
        try std.testing.expectEqualSlices(u8, src, got);
    }
}

test "gzip round trip and accept pick" {
    const gpa = std.testing.allocator;
    const z = try gzip(gpa, "hello hello hello hello");
    defer gpa.free(z);
    var in: std.Io.Reader = .fixed(z);
    var dbuf: [flate.max_window_len]u8 = undefined;
    var dz: flate.Decompress = .init(&in, .gzip, &dbuf);
    const got = try dz.reader.allocRemaining(gpa, .unlimited);
    defer gpa.free(got);
    try std.testing.expectEqualStrings("hello hello hello hello", got);
    try std.testing.expectEqual(Encoding.zstd, pickAccept("identity, deflate, zstd, gzip"));
    try std.testing.expectEqual(Encoding.gzip, pickAccept("gzip"));
    try std.testing.expectEqual(Encoding.identity, pickAccept("identity,deflate"));
}

test "percent encoding matches tonic and text chunks decode" {
    const gpa = std.testing.allocator;
    var l: std.ArrayList(u8) = .empty;
    defer l.deinit(gpa);
    try percentEncode(&l, gpa, "Content is compressed with `gzip` which isn't supported: 100%");
    try std.testing.expectEqualStrings("Content%20is%20compressed%20with%20%60gzip%60%20which%20isn't%20supported:%20100%25", l.items);
    const d = try base64DecodeChunks(gpa, "AAAAAAA=gAAAAA9ncnBjLXN0YXR1czowDQo=");
    defer gpa.free(d);
    try std.testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0fgrpc-status:0\r\n", d);
}
