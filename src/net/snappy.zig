//! Snappy block and framing format, byte-exact with the `snap` 1.1.0 crate that mysten-network's
//! `BcsSnappyCodec` uses. Decoding follows `snap::read::FrameDecoder`; encoding reproduces
//! `snap::write::FrameEncoder` for one `write_all` of the whole message (all state-sync requests
//! and every message that fits one 64 KiB block are encoded that way by the Rust side).
const std = @import("std");
const Allocator = std.mem.Allocator;
const crc32c = @import("crc32c.zig");

pub const max_block_size: usize = 1 << 16;
pub const max_compress_block_size: usize = 76490;
pub const stream_identifier = "\xFF\x06\x00\x00sNaPpY";
const max_table_size: usize = 1 << 14;
const small_table_size: usize = 1 << 10;
const input_margin: usize = 16 - 1;
const min_non_literal_block_size: usize = 1 + 1 + input_margin;

pub const Error = error{
    Corrupt,
    TooLarge,
    StreamHeader,
    UnsupportedChunk,
    Checksum,
    OutOfMemory,
};

pub fn maxCompressedLen(n: usize) usize {
    return 32 + n + n / 6;
}

fn crc32cMasked(buf: []const u8) u32 {
    const sum = crc32c.crc32c(buf);
    return (std.math.rotr(u32, sum, 15)) +% 0xA282EAD8;
}

// ---------------------------------------------------------------- raw block

fn readVarint(in: []const u8) Error!struct { v: u64, n: usize } {
    var v: u64 = 0;
    var shift: u6 = 0;
    for (in, 0..) |b, i| {
        if (i >= 10) return error.Corrupt;
        v |= @as(u64, b & 0x7f) << shift;
        if (b < 0x80) return .{ .v = v, .n = i + 1 };
        shift += 7;
    }
    return error.Corrupt;
}

fn writeVarint(out: []u8, v_in: u64) usize {
    var v = v_in;
    var i: usize = 0;
    while (v >= 0x80) : (i += 1) {
        out[i] = @as(u8, @truncate(v)) | 0x80;
        v >>= 7;
    }
    out[i] = @truncate(v);
    return i + 1;
}

/// Length of the decompressed block.
pub fn blockLen(in: []const u8) Error!usize {
    const r = try readVarint(in);
    if (r.v > std.math.maxInt(u32)) return error.TooLarge;
    return @intCast(r.v);
}

/// Decompresses one snappy block into `out` (exactly `blockLen(in)` bytes). No allocation.
pub fn decompressBlock(in: []const u8, out: []u8) Error!void {
    const hdr = try readVarint(in);
    if (hdr.v != out.len) return error.Corrupt;
    var s: usize = hdr.n;
    var d: usize = 0;
    while (s < in.len) {
        const tag = in[s];
        s += 1;
        switch (tag & 3) {
            0 => {
                var len: usize = tag >> 2;
                if (len < 60) {
                    len += 1;
                } else {
                    const nb = len - 59;
                    if (s + nb > in.len) return error.Corrupt;
                    var v: usize = 0;
                    for (0..nb) |i| v |= @as(usize, in[s + i]) << @intCast(8 * i);
                    s += nb;
                    len = v + 1;
                }
                if (len > in.len - s or len > out.len - d) return error.Corrupt;
                @memcpy(out[d..][0..len], in[s..][0..len]);
                s += len;
                d += len;
            },
            else => {
                var len: usize = undefined;
                var off: usize = undefined;
                switch (tag & 3) {
                    1 => {
                        if (s + 1 > in.len) return error.Corrupt;
                        len = 4 + ((tag >> 2) & 7);
                        off = (@as(usize, tag >> 5) << 8) | in[s];
                        s += 1;
                    },
                    2 => {
                        if (s + 2 > in.len) return error.Corrupt;
                        len = 1 + (tag >> 2);
                        off = std.mem.readInt(u16, in[s..][0..2], .little);
                        s += 2;
                    },
                    else => {
                        if (s + 4 > in.len) return error.Corrupt;
                        len = 1 + (tag >> 2);
                        off = std.mem.readInt(u32, in[s..][0..4], .little);
                        s += 4;
                    },
                }
                if (off == 0 or off > d or len > out.len - d) return error.Corrupt;
                // overlapping copy semantics: byte by byte when the ranges overlap
                if (off >= len) {
                    @memcpy(out[d..][0..len], out[d - off ..][0..len]);
                } else {
                    for (0..len) |i| out[d + i] = out[d - off + i];
                }
                d += len;
            },
        }
    }
    if (d != out.len) return error.Corrupt;
}

const Encoder = struct {
    small: [small_table_size]u16 = undefined,
    big: [max_table_size]u16 = undefined,

    fn compress(e: *Encoder, input_in: []const u8, out: []u8) usize {
        std.debug.assert(out.len >= maxCompressedLen(input_in.len));
        if (input_in.len == 0) {
            out[0] = 0;
            return 1;
        }
        var d = writeVarint(out, input_in.len);
        var input = input_in;
        while (input.len > 0) {
            const n = @min(input.len, max_block_size);
            const src = input[0..n];
            input = input[n..];
            var b: Block = .{ .src = src, .s = 0, .s_limit = src.len, .dst = out, .d = d, .next_emit = 0 };
            if (src.len < min_non_literal_block_size) {
                b.emitLiteral(src.len);
            } else {
                var shift: u5 = 32 - 8;
                var table_size: usize = 256;
                while (table_size < max_table_size and table_size < src.len) {
                    shift -= 1;
                    table_size *= 2;
                }
                const table: []u16 = if (table_size <= small_table_size) e.small[0..table_size] else e.big[0..table_size];
                @memset(table, 0);
                b.compress(table, shift);
            }
            d = b.d;
        }
        return d;
    }
};

const Block = struct {
    src: []const u8,
    s: usize,
    s_limit: usize,
    dst: []u8,
    d: usize,
    next_emit: usize,

    inline fn hash(x: u32, shift: u5) usize {
        return (x *% 0x1E35A7BD) >> shift;
    }
    inline fn load32(src: []const u8, i: usize) u32 {
        return std.mem.readInt(u32, src[i..][0..4], .little);
    }

    fn compress(b: *Block, table: []u16, shift: u5) void {
        b.s += 1;
        b.s_limit -= input_margin;
        var next_hash = hash(load32(b.src, b.s), shift);
        while (true) {
            var skip: usize = 32;
            var candidate: usize = undefined;
            var s_next = b.s;
            while (true) {
                b.s = s_next;
                const between = skip >> 5;
                s_next = b.s + between;
                skip += between;
                if (s_next > b.s_limit) return b.done();
                candidate = table[next_hash];
                table[next_hash] = @intCast(b.s);
                next_hash = hash(load32(b.src, s_next), shift);
                if (load32(b.src, b.s) == load32(b.src, candidate)) break;
            }
            b.emitLiteral(b.s);
            while (true) {
                const base = b.s;
                b.s += 4;
                b.extendMatch(candidate + 4);
                const offset = base - candidate;
                const len = b.s - base;
                b.emitCopy(offset, len);
                b.next_emit = b.s;
                if (b.s >= b.s_limit) return b.done();
                const x = std.mem.readInt(u64, b.src[b.s - 1 ..][0..8], .little);
                const prev_hash = hash(@truncate(x), shift);
                table[prev_hash] = @intCast(b.s - 1);
                const cur_hash = hash(@truncate(x >> 8), shift);
                candidate = table[cur_hash];
                table[cur_hash] = @intCast(b.s);
                const y = load32(b.src, candidate);
                if (@as(u32, @truncate(x >> 8)) != y) {
                    next_hash = hash(@truncate(x >> 16), shift);
                    b.s += 1;
                    break;
                }
            }
        }
    }

    fn extendMatch(b: *Block, cand_in: usize) void {
        var cand = cand_in;
        while (b.s + 8 <= b.src.len) {
            const x = std.mem.readInt(u64, b.src[b.s..][0..8], .little);
            const y = std.mem.readInt(u64, b.src[cand..][0..8], .little);
            if (x == y) {
                b.s += 8;
                cand += 8;
            } else {
                b.s += @ctz(x ^ y) / 8;
                return;
            }
        }
        while (b.s < b.src.len and b.src[b.s] == b.src[cand]) {
            b.s += 1;
            cand += 1;
        }
    }

    fn done(b: *Block) void {
        if (b.next_emit < b.src.len) b.emitLiteral(b.src.len);
    }

    fn emitCopy(b: *Block, offset: usize, len_in: usize) void {
        var len = len_in;
        while (len >= 68) {
            b.emitCopy2(offset, 64);
            len -= 64;
        }
        if (len > 64) {
            b.emitCopy2(offset, 60);
            len -= 60;
        }
        if (len <= 11 and offset <= 2047) {
            b.dst[b.d] = (@as(u8, @intCast(offset >> 8)) << 5) | (@as(u8, @intCast(len - 4)) << 2) | 1;
            b.dst[b.d + 1] = @truncate(offset);
            b.d += 2;
        } else {
            b.emitCopy2(offset, len);
        }
    }

    fn emitCopy2(b: *Block, offset: usize, len: usize) void {
        b.dst[b.d] = (@as(u8, @intCast(len - 1)) << 2) | 2;
        std.mem.writeInt(u16, b.dst[b.d + 1 ..][0..2], @intCast(offset), .little);
        b.d += 3;
    }

    fn emitLiteral(b: *Block, lit_end: usize) void {
        const lit_start = b.next_emit;
        const len = lit_end - lit_start;
        const n = len - 1;
        if (n <= 59) {
            b.dst[b.d] = @as(u8, @intCast(n)) << 2;
            b.d += 1;
        } else if (n < 256) {
            b.dst[b.d] = 60 << 2;
            b.dst[b.d + 1] = @intCast(n);
            b.d += 2;
        } else {
            b.dst[b.d] = 61 << 2;
            std.mem.writeInt(u16, b.dst[b.d + 1 ..][0..2], @intCast(n), .little);
            b.d += 3;
        }
        @memcpy(b.dst[b.d..][0..len], b.src[lit_start..][0..len]);
        b.d += len;
    }
};

/// Compresses `in` as one snappy block (no framing) into `out`, which must hold
/// `maxCompressedLen(in.len)` bytes. Returns the compressed length. Does not allocate.
pub fn compressBlock(in: []const u8, out: []u8) usize {
    var e: Encoder = undefined;
    return e.compress(in, out);
}

// ---------------------------------------------------------------- framing

/// `snap::read::FrameDecoder` over a complete in-memory stream. Output is bounded at `max_out`.
pub fn decompressFrame(arena: Allocator, in: []const u8, max_out: usize) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var p: usize = 0;
    var seen_ident = false;
    while (p < in.len) {
        if (in.len - p < 4) return error.Corrupt; // truncated chunk header
        const ty = in[p];
        const len: usize = @as(usize, in[p + 1]) | (@as(usize, in[p + 2]) << 8) | (@as(usize, in[p + 3]) << 16);
        if (!seen_ident) {
            if (ty != 0xFF) return error.StreamHeader;
            seen_ident = true;
        }
        if (len > max_compress_block_size) return error.UnsupportedChunk;
        p += 4;
        if (in.len - p < len) return error.Corrupt;
        const body = in[p..][0..len];
        p += len;
        switch (ty) {
            0x02...0x7F => return error.UnsupportedChunk,
            0x80...0xFD, 0xFE => {},
            0xFF => {
                if (len != 6 or !std.mem.eql(u8, body, "sNaPpY")) return error.StreamHeader;
            },
            0x01 => {
                if (len < 4) return error.UnsupportedChunk;
                const n = len - 4;
                if (n > max_block_size) return error.UnsupportedChunk;
                const expect = std.mem.readInt(u32, body[0..4], .little);
                if (crc32cMasked(body[4..]) != expect) return error.Checksum;
                if (out.items.len + n > max_out) return error.TooLarge;
                try out.appendSlice(arena, body[4..]);
            },
            0x00 => {
                if (len < 4) return error.UnsupportedChunk;
                const expect = std.mem.readInt(u32, body[0..4], .little);
                const blk = body[4..];
                const dn = try blockLen(blk);
                if (dn > max_block_size) return error.UnsupportedChunk;
                if (out.items.len + dn > max_out) return error.TooLarge;
                const start = out.items.len;
                try out.resize(arena, start + dn);
                try decompressBlock(blk, out.items[start..]);
                if (crc32cMasked(out.items[start..]) != expect) return error.Checksum;
            },
        }
    }
    return out.items;
}

/// `snap::write::FrameEncoder` fed `in` with a single `write_all`: the stream identifier and one
/// chunk per 64 KiB, compressed unless that saves less than one eighth. Empty input yields empty
/// output (the Rust encoder writes nothing when nothing was written).
pub fn compressFrame(arena: Allocator, in: []const u8) Allocator.Error![]u8 {
    if (in.len == 0) return &.{};
    var out: std.ArrayList(u8) = .empty;
    const chunks = (in.len + max_block_size - 1) / max_block_size;
    try out.ensureTotalCapacity(arena, stream_identifier.len + chunks * (8 + max_compress_block_size));
    out.appendSliceAssumeCapacity(stream_identifier);
    var enc: *Encoder = try arena.create(Encoder);
    var tmp = try arena.alloc(u8, maxCompressedLen(max_block_size));
    var p: usize = 0;
    while (p < in.len) {
        const n = @min(in.len - p, max_block_size);
        const src = in[p..][0..n];
        p += n;
        const clen = enc.compress(src, tmp);
        const sum = crc32cMasked(src);
        const use_raw = clen >= src.len - src.len / 8;
        const chunk_len: u32 = @intCast(4 + (if (use_raw) src.len else clen));
        var hdr: [8]u8 = undefined;
        hdr[0] = if (use_raw) 0x01 else 0x00;
        hdr[1] = @truncate(chunk_len);
        hdr[2] = @truncate(chunk_len >> 8);
        hdr[3] = @truncate(chunk_len >> 16);
        std.mem.writeInt(u32, hdr[4..8], sum, .little);
        out.appendSliceAssumeCapacity(&hdr);
        out.appendSliceAssumeCapacity(if (use_raw) src else tmp[0..clen]);
    }
    arena.destroy(enc);
    arena.free(tmp);
    return out.items;
}

test "block round trip" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(1);
    const r = prng.random();
    for ([_]usize{ 0, 1, 15, 16, 17, 100, 5000, 65536, 70000 }) |n| {
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        for (data, 0..) |*b, i| b.* = if (i % 3 == 0) r.int(u8) else @truncate(i % 11);
        const out = try gpa.alloc(u8, maxCompressedLen(n));
        defer gpa.free(out);
        const cl = compressBlock(data, out);
        const back = try gpa.alloc(u8, try blockLen(out[0..cl]));
        defer gpa.free(back);
        try decompressBlock(out[0..cl], back);
        try std.testing.expectEqualSlices(u8, data, back);
    }
}

test "frame round trip and empty" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const e = try compressFrame(a, "");
    try std.testing.expectEqual(@as(usize, 0), e.len);
    try std.testing.expectEqual(@as(usize, 0), (try decompressFrame(a, e, 100)).len);
    const msg = "hello hello hello hello hello hello";
    const f = try compressFrame(a, msg);
    try std.testing.expectEqualSlices(u8, msg, try decompressFrame(a, f, 1000));
}
