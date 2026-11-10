//! zstd dictionaries for the edge feed (docs/EDGE.md section 3) and the frame envelope that names
//! them.
//!
//! A dictionary is raw content (no zstd dictionary header, no trainer): windows sampled from real
//! feeds of recent checkpoints, so the repeated material of mainnet traffic (package ids, type
//! names, effects and gas-object boilerplate, signature and public-key framing) is a back-reference
//! instead of bytes. Its id is the first four bytes of its SHA-256 (little endian, never 0), so
//! two builds from different samples never collide in practice and a client names the one it has.
//!
//! Compressed frame: `dict_id: u32 LE (0 = none) ++ raw_len: u32 LE ++ zstd frame`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const zc = store.zstd_c;

pub const Error = error{ Malformed, TooLarge, UnknownDictionary, Corrupt } || Allocator.Error;

pub const max_dict: usize = 1 << 20;
pub const default_dict: usize = 112 << 10;
/// Raw frames above this are refused on decode (a checkpoint's feed is far below; the transaction
/// and object size limits bound one checkpoint well under this).
pub const max_raw: usize = 64 << 20;
const unknown_size_max: usize = 8 << 20;

pub const Dictionary = struct {
    id: u32,
    sha256: [32]u8,
    content: []u8,
    z: zc.Dict,

    /// Takes a copy of `content`.
    pub fn init(gpa: Allocator, content: []const u8, level: i32) Error!Dictionary {
        if (content.len == 0 or content.len > max_dict) return error.TooLarge;
        const own = try gpa.dupe(u8, content);
        errdefer gpa.free(own);
        var h: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(own, &h, .{});
        var id = std.mem.readInt(u32, h[0..4], .little);
        if (id == 0) id = 1;
        const z = zc.Dict.init(own, level) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Corrupt => return error.Corrupt,
        };
        return .{ .id = id, .sha256 = h, .content = own, .z = z };
    }

    pub fn deinit(d: *Dictionary, gpa: Allocator) void {
        d.z.deinit();
        gpa.free(d.content);
    }
};

/// Dictionary content from sample feeds: an even share of each sample, taken from its start (the
/// summary and contents framing) and from windows spread over the rest, in sample order, at most
/// `target` bytes. Deterministic.
pub fn build(gpa: Allocator, samples: []const []const u8, target: usize) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (samples.len == 0) return out.toOwnedSlice(gpa);
    const per = @max(target / samples.len, 1);
    const win: usize = 512;
    for (samples) |s| {
        if (s.len <= per) {
            try out.appendSlice(gpa, s);
            continue;
        }
        // first quarter of the share from the start, the rest in windows over the body
        const head = per / 4;
        try out.appendSlice(gpa, s[0..head]);
        var left = per - head;
        const body = s.len - head;
        const n = @max(left / win, 1);
        const step = body / n;
        var k: usize = 0;
        while (k < n and left > 0) : (k += 1) {
            const at = head + k * step;
            const len = @min(@min(win, left), s.len - at);
            try out.appendSlice(gpa, s[at..][0..len]);
            left -= len;
        }
    }
    if (out.items.len > target) out.shrinkRetainingCapacity(target);
    return out.toOwnedSlice(gpa);
}

/// `raw` as a compressed frame (header, then zstd with `dict` when given, plain zstd otherwise).
pub fn compress(gpa: Allocator, dict: ?*const Dictionary, raw: []const u8) Error![]u8 {
    if (raw.len > max_raw) return error.TooLarge;
    const buf = try gpa.alloc(u8, 8 + zc.compressBound(raw.len));
    errdefer gpa.free(buf);
    std.mem.writeInt(u32, buf[0..4], if (dict) |d| d.id else 0, .little);
    std.mem.writeInt(u32, buf[4..8], @intCast(raw.len), .little);
    const n: usize = if (dict) |d|
        (d.z.compress(raw, buf[8..]) catch return error.OutOfMemory) orelse return error.TooLarge
    else blk: {
        var z: zc.Compressor = .{};
        defer z.deinit();
        break :blk (z.compressBounded(raw, buf[8..]) catch return error.OutOfMemory) orelse return error.TooLarge;
    };
    return gpa.realloc(buf, 8 + n) catch buf[0 .. 8 + n];
}

/// The dictionary id a frame names (0: none), without decoding it.
pub fn frameDict(frame: []const u8) ?u32 {
    if (frame.len < 8) return null;
    return std.mem.readInt(u32, frame[0..4], .little);
}

/// Decodes a frame (owned result). `dict` must be the one the frame names, if it names one.
pub fn decompress(gpa: Allocator, dict: ?*const Dictionary, frame: []const u8) Error![]u8 {
    if (frame.len < 8) return error.Malformed;
    const id = std.mem.readInt(u32, frame[0..4], .little);
    const n = std.mem.readInt(u32, frame[4..8], .little);
    if (n > max_raw) return error.TooLarge;
    // The header is the sender's claim: the zstd frame must declare the same size before a buffer
    // of that size exists (a few bytes of frame must not buy 64 MiB of memory).
    // (A frame that declares nothing is only believed for small sizes.)
    if (zc.frameContentSize(frame[8..])) |declared| {
        if (declared != n) return error.Corrupt;
    } else if (n > unknown_size_max) return error.Corrupt;
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    if (id == 0) {
        zc.decodeInto(frame[8..], out) catch return error.Corrupt;
    } else {
        const d = dict orelse return error.UnknownDictionary;
        if (d.id != id) return error.UnknownDictionary;
        d.z.decompress(frame[8..], out) catch return error.Corrupt;
    }
    return out;
}

test "dictionary build is deterministic and bounded; frames round trip with and without it" {
    const gpa = std.testing.allocator;
    var s0: [9000]u8 = undefined;
    var s1: [7000]u8 = undefined;
    var x: u32 = 5;
    for (&s0) |*b| {
        x = x *% 1103515245 +% 12345;
        b.* = @truncate(x >> 17);
    }
    @memcpy(&s1, s0[0..7000]);
    const c1 = try build(gpa, &.{ &s0, &s1 }, 6000);
    defer gpa.free(c1);
    const c2 = try build(gpa, &.{ &s0, &s1 }, 6000);
    defer gpa.free(c2);
    try std.testing.expectEqualSlices(u8, c1, c2);
    try std.testing.expect(c1.len <= 6000 and c1.len > 3000);

    var d = try Dictionary.init(gpa, c1, 3);
    defer d.deinit(gpa);
    try std.testing.expect(d.id != 0);
    const raw = s0[500..2500];
    const with = try compress(gpa, &d, raw);
    defer gpa.free(with);
    const without = try compress(gpa, null, raw);
    defer gpa.free(without);
    try std.testing.expectEqual(d.id, frameDict(with).?);
    try std.testing.expectEqual(@as(u32, 0), frameDict(without).?);
    const back = try decompress(gpa, &d, with);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, raw, back);
    const back2 = try decompress(gpa, null, without);
    defer gpa.free(back2);
    try std.testing.expectEqualSlices(u8, raw, back2);
    try std.testing.expectError(error.UnknownDictionary, decompress(gpa, null, with));
    try std.testing.expectError(error.Malformed, decompress(gpa, &d, with[0..5]));
    var bad = try gpa.dupe(u8, with);
    defer gpa.free(bad);
    bad[bad.len - 3] ^= 0xff;
    try std.testing.expect(std.meta.isError(decompress(gpa, &d, bad)));
    // a frame header claiming more than the zstd frame declares is refused before any allocation
    var lie = try gpa.dupe(u8, without);
    defer gpa.free(lie);
    std.mem.writeInt(u32, lie[4..8], @intCast(raw.len + 1000), .little);
    try std.testing.expectError(error.Corrupt, decompress(gpa, null, lie));
}
