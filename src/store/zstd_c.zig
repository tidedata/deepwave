//! Fast zstd through the reference C library (zstd 1.5.7, compress and decompress sides, vendored
//! at vendor/zstd with its BSD license and compiled into the `store` module by build.zig; no
//! multithreading, no legacy formats, no dictionaries).
//! Decoding keeps one context per thread, created on first use; encoding contexts are owned by
//! their holder (`Compressor`).
//! Decoding: `decodeInto` writes straight into the caller's buffer, which must be exactly the
//! frame's content size. std.compress.zstd stays as the fallback (`chunk.decode` uses it when
//! `enabled` is false or the C decoder fails).
//! Encoding: `Compressor.compressBounded` (segment chunks) and `compress` (snapshot files) at `level`
//! (default 3, from the compression level studies). The
//! frames carry the content size and no checksum; windows stay at or under 2 MiB (level 3's
//! windowLog 21; a chunk's window is at most its own size), inside every decoder's 8 MiB limit. deepwave's own encoder (zstd.zig) is the fallback: `ZUI_ZSTD=std` turns
//! the C library off in both directions.
const std = @import("std");

const DCtx = opaque {};
extern fn ZSTD_createDCtx() ?*DCtx;
extern fn ZSTD_decompressDCtx(dctx: *DCtx, dst: [*]u8, dst_cap: usize, src: [*]const u8, src_size: usize) usize;
extern fn ZSTD_isError(code: usize) c_uint;

const CCtx = opaque {};
extern fn ZSTD_createCCtx() ?*CCtx;
extern fn ZSTD_freeCCtx(cctx: *CCtx) usize;
extern fn ZSTD_CCtx_setParameter(cctx: *CCtx, param: c_int, value: c_int) usize;
extern fn ZSTD_compress2(cctx: *CCtx, dst: [*]u8, dst_cap: usize, src: [*]const u8, src_size: usize) usize;
extern fn ZSTD_compressBound(src_size: usize) usize;
const ZSTD_c_compressionLevel: c_int = 100;
const InBuf = extern struct { src: ?*const anyopaque, size: usize, pos: usize };
const OutBuf = extern struct { dst: ?*anyopaque, size: usize, pos: usize };
extern fn ZSTD_compressStream2(cctx: *CCtx, output: *OutBuf, input: *InBuf, end_op: c_int) usize;
extern fn ZSTD_CCtx_reset(cctx: *CCtx, reset: c_int) usize;
extern fn ZSTD_CStreamOutSize() usize;
const ZSTD_e_continue: c_int = 0;
const ZSTD_e_end: c_int = 2;
const ZSTD_reset_session_only: c_int = 1;
pub const CDict = opaque {};
extern fn ZSTD_createCDict(dict: [*]const u8, dict_size: usize, level: c_int) ?*CDict;
extern fn ZSTD_freeCDict(cdict: *CDict) usize;
extern fn ZSTD_compress_usingCDict(cctx: *CCtx, dst: [*]u8, dst_cap: usize, src: [*]const u8, src_size: usize, cdict: *const CDict) usize;
extern fn ZSTD_decompress_usingDict(dctx: *DCtx, dst: [*]u8, dst_cap: usize, src: [*]const u8, src_size: usize, dict: [*]const u8, dict_size: usize) usize;

/// zstd's dictionary magic: a dictionary whose first 4 bytes are not it is raw content (the
/// store's history dictionaries, chunk.zig, start with 8 zero bytes so they never are).
pub const dict_magic: u32 = 0xEC30A437;

/// A digested raw-content dictionary for compression at `level` (the content is copied).
pub fn createCDict(dict: []const u8, l: i32) Error!*CDict {
    std.debug.assert(dict.len < 8 or std.mem.readInt(u32, dict[0..4], .little) != dict_magic);
    return ZSTD_createCDict(dict.ptr, dict.len, l) orelse error.OutOfMemory;
}

pub fn freeCDict(c: *CDict) void {
    _ = ZSTD_freeCDict(c);
}

/// Decodes one zstd frame compressed with raw-content dictionary `dict` (referenced, not
/// copied: O(1) to set up) into `out`, whose length must be the frame's content size.
pub fn decodeIntoDict(src: []const u8, out: []u8, dict: []const u8) Error!void {
    const d = tl_dctx orelse blk: {
        const c = ZSTD_createDCtx() orelse return error.OutOfMemory;
        tl_dctx = c;
        break :blk c;
    };
    if (dict.len >= 8 and std.mem.readInt(u32, dict[0..4], .little) == dict_magic) return error.Corrupt;
    const n = ZSTD_decompress_usingDict(d, out.ptr, out.len, src.ptr, src.len, dict.ptr, dict.len);
    if (ZSTD_isError(n) != 0) return error.Corrupt;
    if (n != out.len) return error.Corrupt;
}

/// Set false to use deepwave's own encoder and std.compress.zstd only (`ZUI_ZSTD=std`, read once).
pub var enabled: bool = true;
/// Compression level of the C encoder (`ZUI_ZSTD_LEVEL=N` overrides it, read once). Level 3
/// since the disk-fit study: on the Mac fixture (`deepwave-store-bench levels`,
/// one thread, 256 KiB chunks) it writes +6.0% (history) and +3.8% (base) ratio over level -1 at
/// about 1 GB/s per thread, and its frames decode as fast (4.4 GB/s history, 5.5 GB/s base).
/// Compression runs on `compress_threads` workers per commit group, so a restore's 17 MB groups
/// take about 5 ms on 4 threads. Level 5 adds 1.7% (history) at a third of the speed; level -1
/// (lane fast-compress's default) is the fastest within 3% of deepwave's own encoder.
pub var level: i32 = 3;
var env_checked = std.atomic.Value(bool).init(false);

threadlocal var tl_dctx: ?*DCtx = null;

fn checkEnv() void {
    if (env_checked.load(.acquire)) return;
    if (std.c.getenv("ZUI_ZSTD")) |v| {
        if (std.mem.eql(u8, std.mem.span(v), "std")) enabled = false;
    }
    if (std.c.getenv("ZUI_ZSTD_LEVEL")) |v| {
        if (std.fmt.parseInt(i32, std.mem.span(v), 10)) |l| {
            level = std.math.clamp(l, -7, 19);
        } else |_| {}
    }
    env_checked.store(true, .release);
}

/// One C compression context, owned by its holder (a pool worker slot, a snapshot writer): no
/// thread-local contexts, so threads that come and go leak nothing. Not shared between threads.
pub const Compressor = struct {
    cctx: ?*CCtx = null,
    at_level: i32 = std.math.minInt(i32),

    pub fn deinit(z: *Compressor) void {
        if (z.cctx) |c| _ = ZSTD_freeCCtx(c);
        z.* = .{};
    }

    /// `compressBounded` with a digested dictionary (its level is the CDict's).
    pub fn compressDict(z: *Compressor, cdict: *const CDict, src: []const u8, dst: []u8) Error!?usize {
        checkEnv();
        const c = z.cctx orelse blk: {
            const c = ZSTD_createCCtx() orelse return error.OutOfMemory;
            z.cctx = c;
            break :blk c;
        };
        const n = ZSTD_compress_usingCDict(c, dst.ptr, dst.len, src.ptr, src.len, cdict);
        if (ZSTD_isError(n) != 0) return null;
        return n;
    }

    /// Compresses `src` as one zstd frame into `dst` at `level`. Returns its length, or null
    /// when the frame does not fit in `dst` (the caller stores the bytes raw).
    pub fn compressBounded(z: *Compressor, src: []const u8, dst: []u8) Error!?usize {
        checkEnv();
        const c = z.cctx orelse blk: {
            const c = ZSTD_createCCtx() orelse return error.OutOfMemory;
            z.cctx = c;
            break :blk c;
        };
        if (z.at_level != level) {
            if (ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level)) != 0) return error.OutOfMemory;
            z.at_level = level;
        }
        const n = ZSTD_compress2(c, dst.ptr, dst.len, src.ptr, src.len);
        if (ZSTD_isError(n) != 0) return null; // dstSize_tooSmall: the only error for valid params
        return n;
    }
};

/// One zstd frame written piece by piece (lane index-fast: snapshot part files are compressed as
/// they are filled, so a writer holds a few MiB instead of a whole 128 MiB part, and the frame is
/// hashed and written while the next objects are read). Same level and window as `compress`; the
/// frame carries no content size (every zstd decoder, deepwave's and Mysten's, reads it).
pub const FrameStream = struct {
    z: Compressor = .{},
    open: bool = false,

    pub fn deinit(f: *FrameStream) void {
        f.z.deinit();
        f.* = .{};
    }

    /// Starts a new frame (a reused context keeps no state from the last one).
    pub fn begin(f: *FrameStream) Error!void {
        checkEnv();
        const c = f.z.cctx orelse blk: {
            const c = ZSTD_createCCtx() orelse return error.OutOfMemory;
            f.z.cctx = c;
            break :blk c;
        };
        if (ZSTD_isError(ZSTD_CCtx_reset(c, ZSTD_reset_session_only)) != 0) return error.OutOfMemory;
        if (f.z.at_level != level) {
            if (ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, level)) != 0) return error.OutOfMemory;
            f.z.at_level = level;
        }
        f.open = true;
    }

    /// Compresses `src` into the frame, appending what the encoder emits to `out`; `end` closes
    /// the frame (everything buffered is flushed).
    pub fn feed(f: *FrameStream, gpa: std.mem.Allocator, src: []const u8, end: bool, out: *std.ArrayList(u8)) Error!void {
        std.debug.assert(f.open);
        const c = f.z.cctx.?;
        var in: InBuf = .{ .src = src.ptr, .size = src.len, .pos = 0 };
        const step = ZSTD_CStreamOutSize();
        while (true) {
            try out.ensureUnusedCapacity(gpa, step);
            const room = out.unusedCapacitySlice();
            var o: OutBuf = .{ .dst = room.ptr, .size = room.len, .pos = 0 };
            const r = ZSTD_compressStream2(c, &o, &in, if (end) ZSTD_e_end else ZSTD_e_continue);
            if (ZSTD_isError(r) != 0) return error.Corrupt;
            out.items.len += o.pos;
            if (end) {
                if (r == 0) break; // frame complete
            } else if (in.pos == in.size) break;
        }
        if (end) f.open = false;
    }
};

/// A zstd frame holding `src` (caller frees), at `level`, with a context of its own (one-shot:
/// for large inputs such as snapshot files, where a context's setup is noise).
pub fn compress(gpa: std.mem.Allocator, src: []const u8) Error![]u8 {
    var z: Compressor = .{};
    defer z.deinit();
    const buf = try gpa.alloc(u8, ZSTD_compressBound(src.len));
    errdefer gpa.free(buf);
    const n = (try z.compressBounded(src, buf)) orelse return error.OutOfMemory;
    if (gpa.resize(buf, n)) return buf[0..n];
    const out = try gpa.dupe(u8, buf[0..n]);
    gpa.free(buf);
    return out;
}

/// A zstd frame holding `src` (caller frees): the C encoder, or deepwave's own with `ZUI_ZSTD=std`.
pub fn compressAny(gpa: std.mem.Allocator, src: []const u8) ![]u8 {
    if (use()) return compress(gpa, src);
    return @import("zstd.zig").compress(gpa, src);
}

pub const Error = error{ OutOfMemory, Corrupt };

/// Decodes one complete zstd frame (or several concatenated) in `src` into `out`. The decoded
/// size must equal `out.len`.
pub fn decodeInto(src: []const u8, out: []u8) Error!void {
    const d = tl_dctx orelse blk: {
        const c = ZSTD_createDCtx() orelse return error.OutOfMemory;
        tl_dctx = c;
        break :blk c;
    };
    const n = ZSTD_decompressDCtx(d, out.ptr, out.len, src.ptr, src.len);
    if (ZSTD_isError(n) != 0) return error.Corrupt;
    if (n != out.len) return error.Corrupt;
}

/// True when the C decoder should be used (default; `ZUI_ZSTD=std` turns it off).
pub fn use() bool {
    checkEnv();
    return enabled;
}

test "zstd_c round trip against the store encoder" {
    const enc = @import("zstd.zig");
    const gpa = std.testing.allocator;
    var src: [70000]u8 = undefined;
    var x: u32 = 1;
    for (&src, 0..) |*b, i| {
        x = x *% 1103515245 +% 12345;
        b.* = if (i % 7 < 4) @truncate(i / 13) else @truncate(x >> 16);
    }
    for ([_]bool{ false, true }) |huf| {
        const z = try enc.compressWith(gpa, &src, .{ .huffman = huf });
        defer gpa.free(z);
        var out: [70000]u8 = undefined;
        try decodeInto(z, &out);
        try std.testing.expectEqualSlices(u8, &src, &out);
        var short: [69999]u8 = undefined;
        try std.testing.expectError(error.Corrupt, decodeInto(z, &short));
    }
}

test "zstd_c compress: round trip through both decoders, bounded output, deterministic" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 300_000);
    defer gpa.free(src);
    var x: u32 = 7;
    for (src, 0..) |*b, i| {
        x = x *% 1103515245 +% 12345;
        b.* = if (i % 11 < 6) @truncate(i / 17) else @truncate(x >> 16);
    }
    for ([_]i32{ -1, 1, 3 }) |l| {
        const saved = level;
        defer level = saved;
        checkEnv();
        level = l;
        const z = try compress(gpa, src);
        defer gpa.free(z);
        try std.testing.expect(z.len < src.len);
        const out = try gpa.alloc(u8, src.len);
        defer gpa.free(out);
        try decodeInto(z, out);
        try std.testing.expectEqualSlices(u8, src, out);
        // std.compress.zstd (the ZUI_ZSTD=std fallback decoder) reads the same frame.
        var in: std.Io.Reader = .fixed(z);
        var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{});
        const sc = try gpa.alloc(u8, src.len + std.compress.zstd.block_size_max);
        defer gpa.free(sc);
        var w: std.Io.Writer = .fixed(sc);
        _ = try d.reader.streamRemaining(&w);
        try std.testing.expectEqualSlices(u8, src, sc[0..w.end]);
        // Same input, same bytes (a reused context keeps no state between frames).
        const z2 = try compress(gpa, src);
        defer gpa.free(z2);
        try std.testing.expectEqualSlices(u8, z, z2);
        // Too small a destination: null, not an error.
        var tiny: [64]u8 = undefined;
        var cz: Compressor = .{};
        defer cz.deinit();
        try std.testing.expect((try cz.compressBounded(src, &tiny)) == null);
        const big = try gpa.alloc(u8, ZSTD_compressBound(src.len));
        defer gpa.free(big);
        const n = (try cz.compressBounded(src, big)).?;
        try std.testing.expectEqualSlices(u8, z, big[0..n]);
    }
}

test "zstd_c frame stream: pieces of any size make one frame both decoders read" {
    const gpa = std.testing.allocator;
    const src = try gpa.alloc(u8, 700_000);
    defer gpa.free(src);
    var x: u32 = 3;
    for (src, 0..) |*b, i| {
        x = x *% 1103515245 +% 12345;
        b.* = if (i % 13 < 7) @truncate(i / 19) else @truncate(x >> 16);
    }
    var fs: FrameStream = .{};
    defer fs.deinit();
    for (0..2) |_| { // the context is reused for a second frame
        try fs.begin();
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var i: usize = 0;
        var k: usize = 1;
        while (i < src.len) : (k = k * 3 + 1) {
            const n = @min(src.len - i, k % 90_000 + 1);
            try fs.feed(gpa, src[i..][0..n], false, &out);
            i += n;
        }
        try fs.feed(gpa, &.{}, true, &out);
        try std.testing.expect(out.items.len < src.len);
        var in: std.Io.Reader = .fixed(out.items);
        var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{});
        const sc = try gpa.alloc(u8, src.len + std.compress.zstd.block_size_max);
        defer gpa.free(sc);
        var w: std.Io.Writer = .fixed(sc);
        _ = try d.reader.streamRemaining(&w);
        try std.testing.expectEqualSlices(u8, src, sc[0..w.end]);
    }
}

test "zstd_c raw-content dictionary: round trip, smaller frames, wrong dictionary fails" {
    const gpa = std.testing.allocator;
    var dict: [64 << 10]u8 = undefined;
    var x: u32 = 5;
    for (&dict, 0..) |*b, i| {
        x = x *% 1103515245 +% 12345;
        b.* = if (i < 8) 0 else @truncate(x >> 16);
    }
    // The source repeats pieces of the dictionary (as history repeats recent objects).
    var src: [32 << 10]u8 = undefined;
    for (0..src.len / 512) |k| @memcpy(src[k * 512 ..][0..512], dict[(k * 1777) % (dict.len - 512) ..][0..512]);
    const cd = try createCDict(&dict, 3);
    defer freeCDict(cd);
    var cz: Compressor = .{};
    defer cz.deinit();
    var with: [40 << 10]u8 = undefined;
    const n = (try cz.compressDict(cd, &src, &with)).?;
    var without: [40 << 10]u8 = undefined;
    const m = (try cz.compressBounded(&src, &without)).?;
    try std.testing.expect(n * 4 < m);
    const out = try gpa.alloc(u8, src.len);
    defer gpa.free(out);
    try decodeIntoDict(with[0..n], out, &dict);
    try std.testing.expectEqualSlices(u8, &src, out);
    var other = dict;
    other[100] ^= 1;
    if (decodeIntoDict(with[0..n], out, &other)) |_| {
        try std.testing.expect(!std.mem.eql(u8, &src, out));
    } else |_| {}
    try std.testing.expectError(error.Corrupt, decodeInto(with[0..n], out));
}
