//! Compressed segments (segment format 3, storage-fit lane).
//!
//! The logical layout of a segment is unchanged (format.zig): commit groups of records at
//! 4096-aligned logical offsets, every location `epoch << 44 | logical offset`, every record
//! checksum seeded with its logical location. Only the bytes on disk differ. A compressed segment
//! file is a 4096-byte `FileHeader` followed by chunk frames:
//!
//!   Frame (32 bytes) ++ body, padded to 8
//!     checksum      u64  checksum.hash seeded with the frame's physical offset ^ salt, over the
//!                        rest of the header and the body (torn, rotten and misdirected frames
//!                        are caught before a byte is decoded)
//!     logical_start u64  logical offset of the chunk's first byte
//!     logical_len   u32  logical bytes the chunk holds
//!     body_len      u32
//!     codec         u8   0 = stored, 1 = zstd frame (zstd_c.zig encodes and decodes; zstd.zig and
//!                        std.compress.zstd are the `ZUI_ZSTD=std` fallback), 2 = zstd frame of
//!                        the chunk with its record checksums elided (below), 3 = as 2, compressed
//!                        with the segment's history dictionary `dict` (below)
//!     _             [3]u8 zero
//!     dict          u32  codec 3: id of the dictionary in `index/<epoch>.zd` (1, 2, ...); else 0
//!
//! Codec 2 (lane disk-fit). A record checksum is a hash of the record's own bytes seeded with its
//! location (format.zig), so inside a compressed chunk it is derivable: 8 incompressible bytes per
//! record, about 7% of a compressed restored live set. The encoder zeroes the checksum of every
//! record except holes (a hole keeps a dead record's checksum, which its zeroed payload cannot
//! reproduce) and compresses that copy; decoding recomputes them, so the logical bytes, every
//! location and every reader are unchanged. The encoder uses codec 2 only when the chunk is a run
//! of whole records of known kinds whose checksums all verify, followed by nothing or zero
//! padding; any other chunk (a damaged record age-out kept, say) keeps its checksums (codec 1), so
//! decoding never turns a damaged record into a valid one. What the record checksums guarded on
//! disk (torn, rotten, misdirected bytes) the frame checksum guards for the whole chunk: it is
//! checked before a byte is decoded, and decoding is deterministic.
//!
//! Codec 3 (lane disk-fit): history dictionaries. A commit group at the tip is one checkpoint
//! (about 300 KiB: two chunks), compressed on its own, while consecutive checkpoints repeat the
//! same objects, types and packages. A raw-content dictionary of the most recent 1 MiB of
//! committed history (zstd references it like a window before the chunk) took the fixture's
//! history chunks from 3.76x to 4.97x (dictionary built from chunks written 10 minutes before
//! the ones compressed). Each compressed segment has an append-only
//! dictionary file `index/<epoch>.zd` (a 4 KiB block whose first 64 bytes are the header
//! `ZUIZD001` with epoch and seed, then records: id u32, len u32, checksum u64, the bytes, each
//! record padded to a 4 KiB block so a torn append never touches an earlier record's sectors:
//! store-dst pending/22 garbled the previous record's last sector through an interrupted
//! append when records were packed). The writer appends and syncs
//! a dictionary before the first frame that names it, so a durable frame's dictionary is
//! durable; at open the file's trusted prefix (ids 1, 2, ... with valid checksums) is loaded,
//! and a frame naming any other id is Corrupt. Dictionary bytes start with 8 zero bytes, so
//! zstd never reads them as a formatted dictionary. The anchors (above) catch a chunk decoded
//! with the wrong dictionary bytes. std.compress.zstd has no dictionaries, so codec 3 always
//! decodes through the C library (also under `ZUI_ZSTD=std`, which only stops writing it).
//!
//! Chunks tile the logical segment: each starts where the previous one ends. A chunk holds whole
//! records (cut at record boundaries once it reaches `chunk_bytes`; a larger record is a chunk of
//! its own) and the last chunk of a group also holds the commit record and the group's zero
//! padding, so a group is a run of whole chunks. A group's frames are written with one write and
//! one sync, and padded to a 4096-byte physical boundary so the next group's write never touches
//! a sector of a durable group.
//!
//! Readers find a chunk through the segment's directory (logical start -> frame), in memory and
//! persisted as `index/<epoch>.dir` (append-only entries with checksums, trusted when they chain;
//! the frames after the last trusted entry are walked at open). Decoded chunks live in a shared
//! cache (cache.zig) whose evicted buffers are reclaimed through the store's grace periods, so a
//! slice handed to a reader stays valid until its snapshot is released, as with mmap views.
const std = @import("std");
const format = @import("format.zig");
const cs = @import("checksum.zig");
const zstd_enc = @import("zstd.zig");
pub const zstd_c = @import("zstd_c.zig");

pub const file_magic = "ZUISEGC1";
pub const file_header_len: u64 = 4096;
pub const frame_len = 32;
const salt: u64 = 0x7a75_692d_6368_6e6b; // "zui-chnk"

pub const Codec = enum(u8) { stored = 0, zstd = 1, zstd_elided = 2, zstd_dict = 3 };
/// Highest codec number a frame, dir entry or age record may carry.
pub const max_codec = 3;
/// Dictionary ids are 1..max_dicts per segment (an age record keeps the id in 16 bits).
pub const max_dicts = 4096;

/// `Entry.codec` holds the frame's codec in its low byte and its dictionary id above it.
pub inline fn codecOf(c: u32) u8 {
    return @truncate(c);
}
pub inline fn dictOf(c: u32) u32 {
    return c >> 8;
}
pub inline fn codecWord(codec: u8, dict: u32) u32 {
    return @as(u32, codec) | (dict << 8);
}

/// Checks a codec word (frame, dir entry or age record): a known codec, and a dictionary id
/// exactly when the codec is 3.
pub fn codecValid(c: u32) bool {
    const k = codecOf(c);
    const d = dictOf(c);
    if (k > max_codec) return false;
    return if (k == 3) d >= 1 and d <= max_dicts else d == 0;
}

pub const FileHeader = extern struct {
    magic: [8]u8 = file_magic.*,
    epoch: u64,
    format: u32 = 3,
    algo: u32 = cs.current_algo,
    checksum: u64 = 0,

    pub fn sum(h: *const FileHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return cs.hash(0x63736567, std.mem.asBytes(&c));
    }
};

pub const Frame = extern struct {
    checksum: u64,
    logical_start: u64,
    logical_len: u32,
    body_len: u32,
    codec: u8,
    _r: [3]u8 = @splat(0),
    dict: u32 = 0,
};

/// Directory entry: where a chunk's frame is and what it holds (also the on-disk dir record).
pub const Entry = extern struct {
    ls: u64,
    phys: u64,
    ll: u32,
    bl: u32,
    /// `codecWord`: codec in the low byte, dictionary id above it.
    codec: u32,
    sum: u32 = 0,

    pub fn end(e: Entry) u64 {
        return e.ls + e.ll;
    }
    pub fn span(e: Entry) u64 {
        return frameSpan(e.bl);
    }
    fn calc(e: Entry, seed: u64) u32 {
        var c = e;
        c.sum = 0;
        return @truncate(cs.hash(seed ^ 0x646972, std.mem.asBytes(&c)));
    }
};

comptime {
    std.debug.assert(@sizeOf(Frame) == frame_len);
    std.debug.assert(@sizeOf(Entry) == 32);
    std.debug.assert(@sizeOf(FileHeader) <= file_header_len);
}

pub inline fn frameSpan(body_len: u64) u64 {
    return std.mem.alignForward(u64, frame_len + body_len, 8);
}

pub fn frameSum(phys: u64, frame_and_body: []const u8) u64 {
    return cs.hash(phys ^ salt, frame_and_body[8..]);
}

pub const Error = error{Corrupt} || std.mem.Allocator.Error;

/// Checks a frame read at `phys` (`buf` = header ++ body). Returns its entry.
pub fn checkFrame(phys: u64, buf: []const u8) Error!Entry {
    if (buf.len < frame_len) return error.Corrupt;
    const f: *align(1) const Frame = @ptrCast(buf[0..frame_len]);
    if (f.dict >= 1 << 24 or !codecValid(codecWord(f.codec, f.dict)) or f.logical_len == 0 or frame_len + @as(u64, f.body_len) > buf.len) return error.Corrupt;
    if (frameSum(phys, buf[0 .. frame_len + f.body_len]) != f.checksum) return error.Corrupt;
    if (f.codec == 0 and f.body_len != f.logical_len) return error.Corrupt;
    return .{ .ls = f.logical_start, .phys = phys, .ll = f.logical_len, .bl = f.body_len, .codec = codecWord(f.codec, f.dict) };
}

// ------------------------------------------------------------------------------- encoding

/// Logical cut points of the group `g` (logical bytes: whole records, the commit record, then
/// zero padding): chunk ends relative to `g`, each chunk ending at a record boundary once it
/// holds at least `target` bytes; the last one ends at `g.len`.
pub fn cutGroup(gpa: std.mem.Allocator, g: []const u8, target: usize, cuts: *std.ArrayList(u32)) !void {
    var start: usize = 0;
    var p: usize = 0;
    while (p + format.short_len <= g.len) {
        const h = format.short(g[p..]);
        const n = format.lenOf(h.kind, h.size);
        if (h.kind == .commit or p + n > g.len) break;
        p += n;
        if (p - start >= target and p < g.len) {
            try cuts.append(gpa, @intCast(p));
            start = p;
        }
    }
    if (cuts.items.len == 0 or cuts.items[cuts.items.len - 1] != g.len) try cuts.append(gpa, @intCast(g.len));
}

/// A compressed chunk body (owned by its allocator) and the codec word it was written with.
pub const Body = struct { bytes: []u8, codec: u32 };

/// The history dictionary a chunk may be compressed with (codec 3): its id in the segment's
/// dictionary file and its digested form.
pub const DictRef = struct { id: u32, cdict: *const zstd_c.CDict };

/// One compressed chunk body (owned by `gpa`), or null to store it raw. A body is kept only
/// when it saves more than 16 bytes. Codec 1 (record checksums kept).
pub fn compressChunk(gpa: std.mem.Allocator, cz: *zstd_c.Compressor, src: []const u8) !?[]u8 {
    const b = (try compressChunkAt(gpa, cz, src, null, 0, null)) orelse return null;
    return b.bytes;
}

/// `compressChunk` for the chunk at logical offset `ls` of segment `epoch`: codec 3 (record
/// checksums elided, history dictionary `dict`) or 2 (elided, no dictionary) when `elideSums`
/// accepts the chunk, else codec 1. `epoch` null: codec 1.
pub fn compressChunkAt(gpa: std.mem.Allocator, cz: *zstd_c.Compressor, src: []const u8, epoch: ?u64, ls: u64, dict: ?DictRef) !?Body {
    if (src.len <= 17) return null;
    var codec: u32 = 1;
    var in = src;
    var copy: ?[]u8 = null;
    defer if (copy) |c| gpa.free(c);
    if (epoch) |ep| {
        const c = try gpa.alloc(u8, src.len);
        copy = c;
        if (elideSums(src, c, ep, ls)) {
            in = c;
            codec = 2;
        }
    }
    const dst = try gpa.alloc(u8, src.len - 17);
    errdefer gpa.free(dst);
    const got = if (codec == 2 and dict != null and zstd_c.use()) blk: {
        codec = codecWord(3, dict.?.id);
        break :blk try cz.compressDict(dict.?.cdict, in, dst);
    } else try compressInto(cz, in, dst);
    const n = got orelse {
        gpa.free(dst);
        return null;
    };
    if (gpa.resize(dst, n)) return .{ .bytes = dst[0..n], .codec = codec };
    const out = try gpa.dupe(u8, dst[0..n]);
    gpa.free(dst);
    return .{ .bytes = out, .codec = codec };
}

/// The kinds a record walk inside a chunk accepts for checksum elision.
fn knownKind(k: format.Kind) bool {
    return switch (k) {
        .segment, .checkpoint, .tx, .object, .remove, .commit, .object_c, .link, .xref, .hole => true,
        _ => false,
    };
}

/// Copies chunk `src` (logical offset `ls` of segment `epoch`) into `dst` (same length) with the
/// checksum of every record zeroed except holes and the first and last non-hole records. True
/// only when `src` is a run of whole records of known kinds, each non-hole record's checksum
/// valid at its location, followed by nothing or zero bytes (a group's padding), and at least
/// one checksum was zeroed; otherwise false and `dst` is unspecified, and the chunk keeps its
/// checksums (codec 1).
///
/// The first and last non-hole records keep their checksums as the chunk's anchors. They are
/// seeded with the records' locations (epoch and logical offset), which the frame checksum
/// (seeded with the physical offset only) does not cover, and they cover bytes at both ends of
/// the decoded chunk. Decoding checks them, so a valid frame of another segment or another
/// logical place (a write misdirected across files), or a chunk decoded with the wrong history
/// dictionary (codec 3), is still Corrupt. 16 bytes per chunk.
pub fn elideSums(src: []const u8, dst: []u8, epoch: u64, ls: u64) bool {
    std.debug.assert(dst.len == src.len);
    if (epoch > format.max_epoch or ls > format.offset_mask or src.len > format.offset_mask - ls) return false;
    if (ls % 8 != 0) return false;
    @memcpy(dst, src);
    var p: usize = 0;
    var anchored = false;
    var zeroed: usize = 0;
    var last: ?usize = null;
    while (p + format.short_len <= src.len) {
        const h = format.short(src[p..]);
        if (@intFromEnum(h.kind) == 0) break; // zero padding (checked below)
        if (!knownKind(h.kind)) return false;
        const hl = format.hdrLen(h.kind);
        const n = format.lenOf(h.kind, h.size);
        if (n > src.len - p or hl + @as(usize, h.size) > n) return false;
        if (h.kind != .hole) {
            const rec = src[p..][0 .. hl + h.size];
            if (format.checksum(format.loc(epoch, ls + p), rec) != h.checksum) return false;
            if (anchored) {
                @memset(dst[p..][0..8], 0);
                zeroed += 1;
                last = p;
            }
            anchored = true;
        }
        p += n;
    }
    if (!std.mem.allEqual(u8, src[p..], 0)) return false;
    // The last non-hole record keeps its checksum too.
    if (last) |q| {
        @memcpy(dst[q..][0..8], src[q..][0..8]);
        zeroed -= 1;
    }
    return zeroed > 0;
}

/// Inverse of `elideSums` on a decoded chunk `out` (codec 2 or 3): checks the anchors (the first
/// and last non-hole records' kept checksums) at this location and recomputes every other
/// non-hole record's checksum in place. The walk is `elideSums`'s (it reads only sizes and
/// kinds, which elision keeps), so it finds the same records. A chunk that does not walk, a
/// wrong anchor, or a kept checksum that does not verify is Corrupt.
pub fn restoreSums(out: []u8, epoch: u64, ls: u64) error{Corrupt}!void {
    if (epoch > format.max_epoch or ls > format.offset_mask or out.len > format.offset_mask - ls) return error.Corrupt;
    var p: usize = 0;
    var first = true;
    var nonhole: usize = 0;
    // The last non-hole record seen: whether its checksum field was kept (non-zero) or elided.
    var last_kept = false;
    var last_sum: u64 = 0;
    while (p + format.short_len <= out.len) {
        const h: *align(1) format.Short = @ptrCast(out[p..][0..format.short_len]);
        if (@intFromEnum(h.kind) == 0) break;
        if (!knownKind(h.kind)) return error.Corrupt;
        const hl = format.hdrLen(h.kind);
        const n = format.lenOf(h.kind, h.size);
        if (n > out.len - p or hl + @as(usize, h.size) > n) return error.Corrupt;
        if (h.kind != .hole) {
            const sum = format.checksum(format.loc(epoch, ls + p), out[p..][0 .. hl + h.size]);
            nonhole += 1;
            if (first) {
                if (h.checksum != sum) return error.Corrupt;
                first = false;
            } else if (h.checksum == 0) {
                h.checksum = sum;
                last_kept = false;
            } else {
                // A kept checksum: only the last non-hole record has one (checked below).
                if (h.checksum != sum) return error.Corrupt;
                last_kept = true;
            }
            last_sum = sum;
        }
        p += n;
    }
    if (nonhole < 3 or !std.mem.allEqual(u8, out[p..], 0)) return error.Corrupt;
    // The last record's checksum was kept, unless its true checksum is 0 (then kept and elided
    // read the same).
    if (!last_kept and last_sum != 0) return error.Corrupt;
}

/// Compresses chunk `src` into `dst` (`dst.len == src.len - 17`: a body is kept only when it
/// saves more than 16 bytes). Returns the body length, or null to store the chunk raw. The
/// vendored C encoder (zstd_c.zig) by default; deepwave's own encoder (zstd.zig) with `ZUI_ZSTD=std`.
/// Allocates only through the C heap, so pool workers can call it (each with its own `cz`).
pub fn compressInto(cz: *zstd_c.Compressor, src: []const u8, dst: []u8) zstd_c.Error!?usize {
    std.debug.assert(src.len > 17 and dst.len == src.len - 17);
    if (zstd_c.use()) return cz.compressBounded(src, dst);
    const z = zstd_enc.compress(std.heap.c_allocator, src) catch return error.OutOfMemory;
    defer std.heap.c_allocator.free(z);
    if (z.len > dst.len) return null;
    @memcpy(dst[0..z.len], z);
    return z.len;
}

/// Appends one frame for logical chunk `src` at logical `ls`, physical `phys` (= out.items.len
/// + `out_base`). `body` is the compressed body or null (stored).
pub fn appendFrame(gpa: std.mem.Allocator, out: *std.ArrayList(u8), out_base: u64, ls: u64, src: []const u8, body: ?[]const u8, ents: *std.ArrayList(Entry)) !void {
    return appendFrameC(gpa, out, out_base, ls, src, body, 1, ents);
}

/// `appendFrame` with the body's codec word (`codecWord`: 1, 2 or 3 with its dictionary;
/// ignored when `body` is null: stored).
pub fn appendFrameC(gpa: std.mem.Allocator, out: *std.ArrayList(u8), out_base: u64, ls: u64, src: []const u8, body: ?[]const u8, codec: u32, ents: *std.ArrayList(Entry)) !void {
    std.debug.assert(body == null or (codecOf(codec) >= 1 and codecValid(codec)));
    const b = body orelse src;
    const phys = out_base + out.items.len;
    const span = frameSpan(b.len);
    const at = out.items.len;
    try out.appendNTimes(gpa, 0, span);
    const f: *align(1) Frame = @ptrCast(out.items[at..][0..frame_len]);
    const cw: u32 = if (body != null) codec else 0;
    f.* = .{ .checksum = 0, .logical_start = ls, .logical_len = @intCast(src.len), .body_len = @intCast(b.len), .codec = codecOf(cw), .dict = dictOf(cw) };
    @memcpy(out.items[at + frame_len ..][0..b.len], b);
    f.checksum = frameSum(phys, out.items[at..][0 .. frame_len + b.len]);
    try ents.append(gpa, .{ .ls = ls, .phys = phys, .ll = @intCast(src.len), .bl = @intCast(b.len), .codec = cw });
}

/// Pads `out` so that `out_base + out.len` is 4096-aligned.
pub fn padGroup(gpa: std.mem.Allocator, out: *std.ArrayList(u8), out_base: u64) !void {
    const end = out_base + out.items.len;
    const to = std.mem.alignForward(u64, end, format.block);
    try out.appendNTimes(gpa, 0, to - end);
}

/// Encodes the logical group `g` (at logical offset `base`) as frames at physical `out_base +
/// out.items.len`, single-threaded (`Encoder` compresses a group's chunks in parallel).
/// `epoch`: the segment's epoch, for codec 2 (record checksums elided); null writes codec 1.
/// `dict`: the segment's history dictionary (codec 3), or null.
pub fn encodeGroup(gpa: std.mem.Allocator, target: usize, g: []const u8, base: u64, out: *std.ArrayList(u8), out_base: u64, ents: *std.ArrayList(Entry), epoch: ?u64, dict: ?DictRef) !void {
    var e: Encoder = .{ .threads = 1 };
    defer e.deinit(gpa);
    try e.encodeGroup(gpa, target, g, base, out, out_base, ents, epoch, dict);
}

/// Group encoder with reusable buffers. A group's chunks are independent zstd frames, so they
/// are compressed on up to `threads` threads (the calling thread and `threads - 1` spawned for
/// the group, each taking the next chunk); the frames are then appended in logical order on the
/// calling thread. Every chunk is compressed by the same function with the same input and
/// destination size whichever thread runs it, so the output is byte-identical for any `threads`.
pub const Encoder = struct {
    threads: u32 = 1,
    /// Groups smaller than this are compressed on the calling thread (a spawn costs more).
    min_parallel_bytes: usize = 128 << 10,
    scratch: std.ArrayList(u8) = .empty,
    /// The group with record checksums elided (codec 2), chunk by chunk at the group's offsets.
    elided: std.ArrayList(u8) = .empty,
    jobs: std.ArrayList(Job) = .empty,
    cuts: std.ArrayList(u32) = .empty,
    /// One compression context per worker slot (slot 0: the calling thread), kept across groups.
    cz: [max_threads]zstd_c.Compressor = @splat(.{}),

    pub const max_threads = 64;

    const Job = struct {
        src: []const u8,
        dst: []u8,
        /// Room for `src` with its checksums elided (empty: codec 1 only).
        copy: []u8 = &.{},
        epoch: u64 = 0,
        ls: u64 = 0,
        dict: ?DictRef = null,
        len: ?usize = null,
        codec: u32 = 1,
        failed: bool = false,
    };

    const Run = struct {
        jobs: []Job,
        next: std.atomic.Value(usize) = .init(0),

        fn work(r: *Run, cz: *zstd_c.Compressor) void {
            while (true) {
                const i = r.next.fetchAdd(1, .monotonic);
                if (i >= r.jobs.len) return;
                const j = &r.jobs[i];
                if (j.dst.len == 0) continue;
                var in = j.src;
                j.codec = 1;
                if (j.copy.len == j.src.len and elideSums(j.src, j.copy, j.epoch, j.ls)) {
                    in = j.copy;
                    j.codec = 2;
                    if (j.dict) |d| if (zstd_c.use()) {
                        j.codec = codecWord(3, d.id);
                        j.len = cz.compressDict(d.cdict, in, j.dst) catch {
                            j.failed = true;
                            continue;
                        };
                        continue;
                    };
                }
                j.len = compressInto(cz, in, j.dst) catch {
                    j.failed = true;
                    continue;
                };
            }
        }
    };

    pub fn deinit(e: *Encoder, gpa: std.mem.Allocator) void {
        e.scratch.deinit(gpa);
        e.elided.deinit(gpa);
        e.jobs.deinit(gpa);
        e.cuts.deinit(gpa);
        for (&e.cz) |*z| z.deinit();
    }

    /// `epoch`: the segment's epoch, for codec 2 (record checksums elided); null writes codec 1.
    /// `dict`: the segment's history dictionary (codec 3, with `epoch`), or null.
    pub fn encodeGroup(e: *Encoder, gpa: std.mem.Allocator, target: usize, g: []const u8, base: u64, out: *std.ArrayList(u8), out_base: u64, ents: *std.ArrayList(Entry), epoch: ?u64, dict: ?DictRef) !void {
        e.cuts.clearRetainingCapacity();
        try cutGroup(gpa, g, target, &e.cuts);
        // Destination slots, carved before any worker starts (the scratch never moves under them).
        var need: usize = 0;
        var from: usize = 0;
        for (e.cuts.items) |c| {
            need += (c - from) -| 17;
            from = c;
        }
        e.scratch.clearRetainingCapacity();
        try e.scratch.ensureTotalCapacity(gpa, need);
        e.scratch.items.len = need;
        e.elided.clearRetainingCapacity();
        if (epoch != null) {
            try e.elided.ensureTotalCapacity(gpa, g.len);
            e.elided.items.len = g.len;
        }
        e.jobs.clearRetainingCapacity();
        try e.jobs.ensureTotalCapacity(gpa, e.cuts.items.len);
        from = 0;
        var at: usize = 0;
        for (e.cuts.items) |c| {
            const n = (c - from) -| 17;
            e.jobs.appendAssumeCapacity(.{
                .src = g[from..c],
                .dst = e.scratch.items[at..][0..n],
                .copy = if (epoch != null) e.elided.items[from..c] else &.{},
                .epoch = epoch orelse 0,
                .ls = base + from,
                .dict = dict,
            });
            at += n;
            from = c;
        }

        var run: Run = .{ .jobs = e.jobs.items };
        const nt: usize = if (g.len < e.min_parallel_bytes) 1 else @min(@max(e.threads, 1), max_threads, e.jobs.items.len);
        var threads: [max_threads]?std.Thread = @splat(null);
        for (1..nt) |i| threads[i] = std.Thread.spawn(.{}, Run.work, .{ &run, &e.cz[i] }) catch null;
        run.work(&e.cz[0]);
        for (threads[1..nt]) |t| if (t) |th| th.join();

        from = 0;
        for (e.cuts.items, e.jobs.items) |c, j| {
            if (j.failed) return error.OutOfMemory;
            try appendFrameC(gpa, out, out_base, base + from, j.src, if (j.len) |n| j.dst[0..n] else null, j.codec, ents);
            from = c;
        }
        try padGroup(gpa, out, out_base);
    }
};

/// Default compression threads for a store: min(4, cores).
pub fn defaultThreads() u32 {
    const n = std.Thread.getCpuCount() catch 1;
    return @intCast(@max(1, @min(4, n)));
}

// ------------------------------------------------------------------------------- decoding

threadlocal var tl_scratch: []u8 = &.{};

/// Decodes a checked frame body of segment `epoch` into `out` (`out.len == e.ll`). `dicts`:
/// the segment's history dictionaries (codec 3 frames are Corrupt without theirs).
pub fn decode(e: Entry, epoch: u64, dicts: ?*const Dicts, body: []const u8, out: []u8) Error!void {
    std.debug.assert(out.len == e.ll);
    const k = codecOf(e.codec);
    if (k == 0) {
        if (body.len != out.len) return error.Corrupt;
        @memcpy(out, body);
        return;
    }
    if (k == 3) {
        const d = (if (dicts) |ds| ds.get(dictOf(e.codec)) else null) orelse return error.Corrupt;
        try zstd_c.decodeIntoDict(body, out, d);
        return restoreSums(out, epoch, e.ls);
    }
    // The reference C decoder writes straight into `out` (zstd_c.zig); std.compress.zstd is the
    // fallback (`ZUI_ZSTD=std`, or a frame the C decoder rejects).
    if (zstd_c.use()) {
        if (zstd_c.decodeInto(body, out)) |_| {
            if (k == 2) try restoreSums(out, epoch, e.ls);
            return;
        } else |err| if (err == error.OutOfMemory) return error.OutOfMemory;
    }
    return decodeStd(e, epoch, body, out);
}

/// `decode` through std.compress.zstd only (codecs 0 to 2).
pub fn decodeStd(e: Entry, epoch: u64, body: []const u8, out: []u8) Error!void {
    if (codecOf(e.codec) == 3) return error.Corrupt;
    try decodeStdRaw(e, body, out);
    if (codecOf(e.codec) == 2) try restoreSums(out, epoch, e.ls);
}

fn decodeStdRaw(e: Entry, body: []const u8, out: []u8) Error!void {
    const zstd = std.compress.zstd;
    // Direct mode needs a block of slack past the content.
    const need = @as(usize, e.ll) + zstd.block_size_max;
    if (tl_scratch.len < need) {
        if (tl_scratch.len > 0) std.heap.page_allocator.free(tl_scratch);
        tl_scratch = &.{};
        tl_scratch = try std.heap.page_allocator.alloc(u8, std.mem.alignForward(usize, need, 1 << 16));
    }
    var in: std.Io.Reader = .fixed(body);
    var d: zstd.Decompress = .init(&in, &.{}, .{});
    var w: std.Io.Writer = .fixed(tl_scratch[0..need]);
    _ = d.reader.streamRemaining(&w) catch return error.Corrupt;
    if (w.end != out.len) return error.Corrupt;
    @memcpy(out, tl_scratch[0..out.len]);
}

// ------------------------------------------------------------------------------- directory

/// A segment's chunk directory as readers see it: `entries[0..n]`, sorted by logical start
/// (published with release stores; a grown copy replaces it, the old one is retired).
pub const Dir = struct {
    entries: []Entry,
    n: std.atomic.Value(usize) = .init(0),
    /// Physical end of the frames in the segment file itself, once age-out moved chunks to the
    /// sidecar (`side_bit` entries; 0: computed from the last entry).
    main_end: u64 = 0,

    pub fn create(gpa: std.mem.Allocator, cap: usize) !*Dir {
        const d = try gpa.create(Dir);
        errdefer gpa.destroy(d);
        d.* = .{ .entries = try gpa.alloc(Entry, @max(cap, 64)) };
        return d;
    }

    pub fn destroy(d: *Dir, gpa: std.mem.Allocator) void {
        gpa.free(d.entries);
        gpa.destroy(d);
    }

    pub fn len(d: *const Dir) usize {
        return d.n.load(.acquire);
    }

    pub fn slice(d: *const Dir) []const Entry {
        return d.entries[0..d.len()];
    }

    /// The chunk holding logical offset `off`.
    pub fn find(d: *const Dir, off: u64) ?Entry {
        const es = d.slice();
        var lo: usize = 0;
        var hi: usize = es.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (es[mid].ls <= off) lo = mid + 1 else hi = mid;
        }
        if (lo == 0) return null;
        const e = es[lo - 1];
        return if (off < e.end()) e else null;
    }

    /// Index of the chunk starting exactly at `ls`.
    pub fn indexAt(d: *const Dir, ls: u64) ?usize {
        const es = d.slice();
        var lo: usize = 0;
        var hi: usize = es.len;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (es[mid].ls < ls) lo = mid + 1 else hi = mid;
        }
        return if (lo < es.len and es[lo].ls == ls) lo else null;
    }

    pub fn logicalEnd(d: *const Dir) u64 {
        const es = d.slice();
        return if (es.len == 0) 0 else es[es.len - 1].end();
    }

    pub fn physEnd(d: *const Dir) u64 {
        if (d.main_end != 0) return d.main_end;
        const es = d.slice();
        return if (es.len == 0) file_header_len else es[es.len - 1].phys + es[es.len - 1].span();
    }
};

// ------------------------------------------------------------------------------- dir file

pub const DirHeader = extern struct {
    magic: [8]u8 = "ZUIDIR01".*,
    epoch: u64,
    seed: u64,
    checksum: u64 = 0,

    pub fn sum(h: *const DirHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return cs.hash(0x64697268, std.mem.asBytes(&c));
    }
};
pub const dir_header_len: u64 = 64;

// ------------------------------------------------------------------------------- dictionaries

/// A segment's history dictionaries as readers see them: the bytes of id `i` at `items[i - 1]`
/// for `i <= n`. The writer appends (`push`, publishing `n` with a release store); entries never
/// move or change until the segment is closed, so readers need no lock.
pub const Dicts = struct {
    items: [][]u8 = &.{},
    n: std.atomic.Value(usize) = .init(0),

    pub fn create(gpa: std.mem.Allocator) !*Dicts {
        const d = try gpa.create(Dicts);
        d.* = .{};
        return d;
    }

    pub fn destroy(d: *Dicts, gpa: std.mem.Allocator) void {
        for (d.items[0..d.n.raw]) |b| gpa.free(b);
        if (d.items.len > 0) gpa.free(d.items);
        gpa.destroy(d);
    }

    pub fn len(d: *const Dicts) usize {
        return d.n.load(.acquire);
    }

    /// The bytes of dictionary `id`, or null.
    pub fn get(d: *const Dicts, id: u32) ?[]const u8 {
        if (id == 0 or id > d.n.load(.acquire)) return null;
        return d.items[id - 1];
    }

    /// Writer: appends `bytes` (owned by the set from now on) as the next id, which it returns.
    pub fn push(d: *Dicts, gpa: std.mem.Allocator, bytes: []u8) !u32 {
        const n = d.n.raw;
        if (n >= max_dicts) return error.TooManyDicts;
        if (d.items.len == 0) {
            // Published before `n` moves past 0 (readers load `n` first, with acquire).
            d.items = try gpa.alloc([]u8, max_dicts);
        }
        d.items[n] = bytes;
        d.n.store(n + 1, .release);
        return @intCast(n + 1);
    }
};

pub const dict_magic = "ZUIZD001";
/// The header block; every record starts on a `dict_align` boundary too.
pub const dict_header_len: u64 = 4096;
pub const dict_align = 4096;

pub const DictHeader = extern struct {
    magic: [8]u8 = dict_magic.*,
    epoch: u64,
    seed: u64,
    checksum: u64 = 0,

    pub fn sum(h: *const DictHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return cs.hash(0x7a6468, std.mem.asBytes(&c));
    }
};

/// One record of a dictionary file: this header, then `len` bytes, padded to `dict_align`.
pub const DictRec = extern struct {
    id: u32,
    len: u32,
    sum: u64,

    fn calc(id: u32, bytes: []const u8, seed: u64) u64 {
        var h: [8]u8 = undefined;
        std.mem.writeInt(u32, h[0..4], id, .little);
        std.mem.writeInt(u32, h[4..8], @intCast(bytes.len), .little);
        return cs.hash(cs.hash(seed ^ 0x7a6472 ^ (@as(u64, id) *% 0x9e3779b97f4a7c15), &h), bytes);
    }
};

/// The bytes of the dictionary file header for segment `epoch`.
pub fn dictFileHeader(epoch: u64, seed: u64) [dict_header_len]u8 {
    var h: DictHeader = .{ .epoch = epoch, .seed = seed };
    h.checksum = h.sum();
    var page: [dict_header_len]u8 = @splat(0);
    @memcpy(page[0..@sizeOf(DictHeader)], std.mem.asBytes(&h));
    return page;
}

/// Appends the file record of dictionary `id` (`bytes`) to `out`.
pub fn dictRecord(gpa: std.mem.Allocator, out: *std.ArrayList(u8), seed: u64, id: u32, bytes: []const u8) !void {
    const r: DictRec = .{ .id = id, .len = @intCast(bytes.len), .sum = DictRec.calc(id, bytes, seed) };
    try out.appendSlice(gpa, std.mem.asBytes(&r));
    try out.appendSlice(gpa, bytes);
    const n = @sizeOf(DictRec) + bytes.len;
    try out.appendNTimes(gpa, 0, std.mem.alignForward(usize, n, dict_align) - n);
}

/// Loads the trusted prefix of a dictionary file image into `out` (ids 1, 2, ... in order, each
/// checksum valid). Returns the file's seed and the end of the trusted prefix, or null when the
/// header is not valid for `epoch`.
pub fn dictsTrusted(img: []const u8, epoch: u64, out: *Dicts, gpa: std.mem.Allocator) !?struct { seed: u64, end: u64 } {
    if (img.len < dict_header_len) return null;
    var h: DictHeader = undefined;
    @memcpy(std.mem.asBytes(&h), img[0..@sizeOf(DictHeader)]);
    if (!std.mem.eql(u8, &h.magic, dict_magic) or h.sum() != h.checksum or h.epoch != epoch) return null;
    var p: usize = dict_header_len;
    while (p + @sizeOf(DictRec) <= img.len) {
        var r: DictRec = undefined;
        @memcpy(std.mem.asBytes(&r), img[p..][0..@sizeOf(DictRec)]);
        const want: u32 = @intCast(out.len() + 1);
        if (r.id != want or want > max_dicts or r.len == 0 or r.len > img.len - p - @sizeOf(DictRec)) break;
        const bytes = img[p + @sizeOf(DictRec) ..][0..r.len];
        if (DictRec.calc(r.id, bytes, h.seed) != r.sum) break;
        const own = try gpa.dupe(u8, bytes);
        _ = out.push(gpa, own) catch |e| {
            gpa.free(own);
            return e;
        };
        p += std.mem.alignForward(usize, @sizeOf(DictRec) + r.len, dict_align);
    }
    return .{ .seed = h.seed, .end = p };
}

/// A history dictionary from the most recent committed bytes `recent`: 8 zero bytes (so zstd
/// reads it as raw content, never as a formatted dictionary) then the last `size - 8` bytes.
pub fn dictFrom(gpa: std.mem.Allocator, recent: []const u8, size: usize) ![]u8 {
    std.debug.assert(size > 8);
    const take = @min(recent.len, size - 8);
    const d = try gpa.alloc(u8, 8 + take);
    @memset(d[0..8], 0);
    @memcpy(d[8..], recent[recent.len - take ..]);
    return d;
}

// ------------------------------------------------------------------------------- age-out

/// Entry `phys` bit: the frame is in the segment's sidecar (`index/<epoch>.side`), written by
/// age-out when it rewrote the chunk with dead records replaced by holes (format.Kind.hole).
/// The chunk keeps its logical range, so every location and index stays valid.
pub const side_bit: u64 = 1 << 63;

pub inline fn isSide(phys: u64) bool {
    return phys & side_bit != 0;
}

/// One record of a segment's age log (`index/<epoch>.age`): a chunk rewritten into the sidecar
/// (`kind` 0, the frame it replaces is `old_phys`/`old_bl`), or a pass mark (`kind` 1: the
/// checkpoint pass is done up to logical `ls`; `kind` 2: the segment pass ran for object floor
/// epoch `phys`). Appended and synced before the replaced frame is punched, so a record that
/// reads back intact names a durable frame; a torn tail only loses rewrites whose old frames
/// are still whole.
pub const AgeRec = extern struct {
    ls: u64,
    phys: u64,
    old_phys: u64 = 0,
    ll: u32 = 0,
    bl: u32 = 0,
    old_bl: u32 = 0,
    codec: u8 = 0,
    kind: u8 = 0,
    /// Codec 3: the rewritten frame's dictionary id (0 otherwise; was reserved, always 0).
    dict: u16 = 0,
    sum: u64 = 0,

    pub fn calc(r: AgeRec, seed: u64, i: u64) u64 {
        var c = r;
        c.sum = 0;
        return cs.hash(seed ^ 0x616765 ^ (i *% 0x9e3779b97f4a7c15), std.mem.asBytes(&c));
    }
};

pub const age_magic = "ZUIAGE01";
pub const age_header_len: u64 = 64;

pub const AgeHeader = extern struct {
    magic: [8]u8 = age_magic.*,
    epoch: u64,
    seed: u64,
    checksum: u64 = 0,

    pub fn sum(h: *const AgeHeader) u64 {
        var c = h.*;
        c.checksum = 0;
        return cs.hash(0x61676568, std.mem.asBytes(&c));
    }
};

comptime {
    std.debug.assert(@sizeOf(AgeRec) == 48);
}

/// The records of an age log image that can be trusted (checksums valid, in order); null when
/// the header is not valid. Returns the seed.
pub fn ageTrusted(img: []const u8, epoch: u64, out: *std.ArrayList(AgeRec), gpa: std.mem.Allocator) !?u64 {
    if (img.len < age_header_len) return null;
    var h: AgeHeader = undefined;
    @memcpy(std.mem.asBytes(&h), img[0..@sizeOf(AgeHeader)]);
    if (!std.mem.eql(u8, &h.magic, age_magic) or h.sum() != h.checksum or h.epoch != epoch) return null;
    var p: usize = age_header_len;
    var i: u64 = 0;
    while (p + @sizeOf(AgeRec) <= img.len) : ({
        p += @sizeOf(AgeRec);
        i += 1;
    }) {
        var r: AgeRec = undefined;
        @memcpy(std.mem.asBytes(&r), img[p..][0..@sizeOf(AgeRec)]);
        if (r.sum != r.calc(h.seed, i) or r.kind > 2) break;
        if (r.kind == 0 and (r.ll == 0 or !codecValid(codecWord(r.codec, r.dict)) or !isSide(r.phys))) break;
        try out.append(gpa, r);
    }
    return h.seed;
}

pub fn sealEntry(e: *Entry, seed: u64) void {
    e.sum = e.calc(seed);
}

/// Entries of a dir file image that can be trusted: valid checksums, chaining logically from 0
/// and physically from the file header, every frame inside the segment's `phys_size`.
/// Returns the file's entry seed (null: no valid header).
pub fn trustedPrefix(img: []const u8, epoch: u64, phys_size: u64, out: *std.ArrayList(Entry), gpa: std.mem.Allocator) !?u64 {
    if (img.len < dir_header_len) return null;
    var h: DirHeader = undefined;
    @memcpy(std.mem.asBytes(&h), img[0..@sizeOf(DirHeader)]);
    if (!std.mem.eql(u8, &h.magic, "ZUIDIR01") or h.sum() != h.checksum or h.epoch != epoch) return null;
    var p: usize = dir_header_len;
    var want_ls: u64 = 0;
    var min_phys: u64 = file_header_len;
    while (p + 32 <= img.len) : (p += 32) {
        var e: Entry = undefined;
        @memcpy(std.mem.asBytes(&e), img[p..][0..32]);
        if (e.sum != e.calc(h.seed) or e.ls != want_ls or e.ll == 0 or !codecValid(e.codec)) break;
        // Frames of one group are adjacent; a group's last frame is padded to 4096.
        if (e.phys < min_phys or e.phys > std.mem.alignForward(u64, min_phys, format.block)) break;
        if (e.phys + e.span() > phys_size) break;
        try out.append(gpa, e);
        want_ls = e.end();
        min_phys = e.phys + e.span();
    }
    return h.seed;
}

test "cut, encode, check and decode a group" {
    const gpa = std.testing.allocator;
    // A fake group: 300 records of 200 bytes each (kind tx), a commit record, zero padding.
    var g: std.ArrayList(u8) = .empty;
    defer g.deinit(gpa);
    var payload: [160]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i % 7);
    var buf: [256]u8 align(8) = undefined;
    for (0..300) |i| {
        const n = format.write(&buf, format.loc(1, 4096 + g.items.len), .tx, 0, i, 0, &.{&payload});
        try g.appendSlice(gpa, buf[0..n]);
    }
    const cf: format.CommitFixed = .{ .epoch = 1, .group_start = format.loc(1, 4096), .records = 301, .group_hash = 0, .prev_commit = 0 };
    const n = format.write(&buf, format.loc(1, 4096 + g.items.len), .commit, 0, 9, 0, &.{std.mem.asBytes(&cf)});
    try g.appendSlice(gpa, buf[0..n]);
    try g.appendNTimes(gpa, 0, std.mem.alignForward(usize, g.items.len, 4096) - g.items.len);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var ents: std.ArrayList(Entry) = .empty;
    defer ents.deinit(gpa);
    try encodeGroup(gpa, 16 << 10, g.items, 4096, &out, file_header_len, &ents, 1, null);
    try std.testing.expect(ents.items.len >= 4);
    try std.testing.expect(out.items.len % 4096 == 0 and out.items.len < g.items.len);
    for (ents.items) |e| try std.testing.expectEqual(@as(u32, 2), e.codec); // checksums elided
    var logical: u64 = 4096;
    for (ents.items) |e| {
        try std.testing.expectEqual(logical, e.ls);
        logical = e.end();
        const at = e.phys - file_header_len;
        const ce = try checkFrame(e.phys, out.items[at..][0..frame_len + e.bl]);
        try std.testing.expectEqual(e.ls, ce.ls);
        const dec = try gpa.alloc(u8, e.ll);
        defer gpa.free(dec);
        try decode(ce, 1, null, out.items[at + frame_len ..][0..e.bl], dec);
        try std.testing.expectEqualSlices(u8, g.items[e.ls - 4096 ..][0..e.ll], dec);
        // a flipped body byte or a frame read at the wrong place is caught
        out.items[at + frame_len] ^= 1;
        try std.testing.expectError(error.Corrupt, checkFrame(e.phys, out.items[at..][0..frame_len + e.bl]));
        out.items[at + frame_len] ^= 1;
        try std.testing.expectError(error.Corrupt, checkFrame(e.phys + 8, out.items[at..][0..frame_len + e.bl]));
    }
    try std.testing.expectEqual(@as(u64, 4096 + g.items.len), logical);

    // directory lookup and the dir file's trusted prefix
    var d = try Dir.create(gpa, ents.items.len);
    defer d.destroy(gpa);
    @memcpy(d.entries[0..ents.items.len], ents.items);
    d.n.store(ents.items.len, .release);
    try std.testing.expectEqual(ents.items[1].ls, d.find(ents.items[1].ls + 5).?.ls);
    try std.testing.expect(d.find(100) == null);
    try std.testing.expect(d.find(logical) == null);
}

test "parallel group encoding is byte-identical to single-threaded, for both encoders" {
    const gpa = std.testing.allocator;
    var g: std.ArrayList(u8) = .empty;
    defer g.deinit(gpa);
    var payload: [400]u8 = undefined;
    var buf: [512]u8 align(8) = undefined;
    var x: u32 = 3;
    for (0..2000) |i| {
        for (&payload, 0..) |*b, k| {
            x = x *% 1103515245 +% 12345;
            b.* = if (k % 5 < 3) @truncate(k + i % 9) else @truncate(x >> 16);
        }
        const n = format.write(&buf, format.loc(1, 4096 + g.items.len), .tx, 0, i, 0, &.{&payload});
        try g.appendSlice(gpa, buf[0..n]);
    }
    const cf: format.CommitFixed = .{ .epoch = 1, .group_start = format.loc(1, 4096), .records = 2001, .group_hash = 0, .prev_commit = 0 };
    const n = format.write(&buf, format.loc(1, 4096 + g.items.len), .commit, 0, 9, 0, &.{std.mem.asBytes(&cf)});
    try g.appendSlice(gpa, buf[0..n]);
    try g.appendNTimes(gpa, 0, std.mem.alignForward(usize, g.items.len, 4096) - g.items.len);

    const saved = zstd_c.enabled;
    defer zstd_c.enabled = saved;
    _ = zstd_c.use();
    for ([_]bool{ true, false }) |c_enc| {
        zstd_c.enabled = c_enc;
        var ref: std.ArrayList(u8) = .empty;
        defer ref.deinit(gpa);
        var ref_ents: std.ArrayList(Entry) = .empty;
        defer ref_ents.deinit(gpa);
        try encodeGroup(gpa, 16 << 10, g.items, 4096, &ref, file_header_len, &ref_ents, 1, null);
        try std.testing.expect(ref_ents.items.len > 20 and ref.items.len < g.items.len);
        for ([_]u32{ 2, 4, 6, 64 }) |t| {
            var e: Encoder = .{ .threads = t, .min_parallel_bytes = 0 };
            defer e.deinit(gpa);
            for (0..2) |_| { // reused buffers give the same bytes too
                var out: std.ArrayList(u8) = .empty;
                defer out.deinit(gpa);
                var ents: std.ArrayList(Entry) = .empty;
                defer ents.deinit(gpa);
                try e.encodeGroup(gpa, 16 << 10, g.items, 4096, &out, file_header_len, &ents, 1, null);
                try std.testing.expectEqualSlices(u8, ref.items, out.items);
                try std.testing.expectEqual(ref_ents.items.len, ents.items.len);
                for (ref_ents.items, ents.items) |a, b| try std.testing.expectEqual(a, b);
            }
        }
        // Every frame checks and decodes (with the C decoder and with std.compress.zstd).
        for (ref_ents.items) |en| {
            const off = en.phys - file_header_len;
            const ce = try checkFrame(en.phys, ref.items[off..][0 .. frame_len + en.bl]);
            const dec = try gpa.alloc(u8, en.ll);
            defer gpa.free(dec);
            try decode(ce, 1, null, ref.items[off + frame_len ..][0..en.bl], dec);
            try std.testing.expectEqualSlices(u8, g.items[en.ls - 4096 ..][0..en.ll], dec);
            if (codecOf(ce.codec) == 0) continue;
            @memset(dec, 0);
            try decodeStd(ce, 1, ref.items[off + frame_len ..][0..en.bl], dec);
            try std.testing.expectEqualSlices(u8, g.items[en.ls - 4096 ..][0..en.ll], dec);
        }
    }
}

test "codec 2: record checksums elided and restored; holes, damaged records and padding" {
    const gpa = std.testing.allocator;
    // A group at logical 8192 of epoch 5: object_c, tx, a hole, an xref, the commit, padding.
    const ep: u64 = 5;
    const base: u64 = 8192;
    var g: std.ArrayList(u8) = .empty;
    defer g.deinit(gpa);
    var buf: [1024]u8 align(8) = undefined;
    var payload: [300]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i * 7 % 13);
    var recs: usize = 0;
    for (0..400) |i| {
        const kind: format.Kind = switch (i % 4) {
            0 => .object_c,
            1 => .tx,
            2 => .xref,
            else => .object,
        };
        const n = format.write(&buf, format.loc(ep, base + g.items.len), kind, 0, i, 0, &.{payload[0 .. 40 + i % 200]});
        if (i % 37 == 5) format.makeHole(buf[0..n]); // age-out holes keep their old checksum
        try g.appendSlice(gpa, buf[0..n]);
        recs += 1;
    }
    const cf: format.CommitFixed = .{ .epoch = ep, .group_start = format.loc(ep, base), .records = @intCast(recs + 1), .group_hash = 0, .prev_commit = 0 };
    const n = format.write(&buf, format.loc(ep, base + g.items.len), .commit, 0, 9, 0, &.{std.mem.asBytes(&cf)});
    try g.appendSlice(gpa, buf[0..n]);
    try g.appendNTimes(gpa, 0, std.mem.alignForward(usize, g.items.len, 4096) - g.items.len);

    // The whole group elides; the copy differs from the source only in zeroed checksums.
    const copy = try gpa.alloc(u8, g.items.len);
    defer gpa.free(copy);
    try std.testing.expect(elideSums(g.items, copy, ep, base));
    try std.testing.expect(!std.mem.eql(u8, g.items, copy));
    const back = try gpa.dupe(u8, copy);
    defer gpa.free(back);
    try restoreSums(back, ep, base);
    try std.testing.expectEqualSlices(u8, g.items, back);
    // Wrong epoch or offset: the checksums do not verify, so no elision.
    try std.testing.expect(!elideSums(g.items, copy, ep + 1, base));
    try std.testing.expect(!elideSums(g.items, copy, ep, base + 8));

    // Encoded: every frame is codec 2 and decodes byte for byte (C and std decoders).
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var ents: std.ArrayList(Entry) = .empty;
    defer ents.deinit(gpa);
    try encodeGroup(gpa, 8 << 10, g.items, base, &out, file_header_len, &ents, ep, null);
    try std.testing.expect(ents.items.len > 4);
    var codec1: std.ArrayList(u8) = .empty;
    defer codec1.deinit(gpa);
    var ents1: std.ArrayList(Entry) = .empty;
    defer ents1.deinit(gpa);
    try encodeGroup(gpa, 8 << 10, g.items, base, &codec1, file_header_len, &ents1, null, null);
    try std.testing.expect(out.items.len <= codec1.items.len);
    for (ents.items, ents1.items) |en, en1| {
        try std.testing.expectEqual(@as(u32, 2), en.codec);
        try std.testing.expectEqual(@as(u32, 1), en1.codec);
        const off = en.phys - file_header_len;
        const ce = try checkFrame(en.phys, out.items[off..][0 .. frame_len + en.bl]);
        const dec = try gpa.alloc(u8, en.ll);
        defer gpa.free(dec);
        try decode(ce, ep, null, out.items[off + frame_len ..][0..en.bl], dec);
        try std.testing.expectEqualSlices(u8, g.items[en.ls - base ..][0..en.ll], dec);
        @memset(dec, 0);
        try decodeStd(ce, ep, out.items[off + frame_len ..][0..en.bl], dec);
        try std.testing.expectEqualSlices(u8, g.items[en.ls - base ..][0..en.ll], dec);
    }

    // A damaged record (its checksum no longer verifies) keeps codec 1 for its chunk, so decoding
    // returns it damaged, as it was.
    const bad = try gpa.dupe(u8, g.items);
    defer gpa.free(bad);
    bad[format.short_len + 3] ^= 0x40; // first record's payload
    try std.testing.expect(!elideSums(bad, copy, ep, base));
    var cz: zstd_c.Compressor = .{};
    defer cz.deinit();
    const b1 = (try compressChunkAt(gpa, &cz, bad[0..ents.items[0].ll], ep, base, null)).?;
    defer gpa.free(b1.bytes);
    try std.testing.expectEqual(@as(u32, 1), b1.codec);
    const b2 = (try compressChunkAt(gpa, &cz, g.items[0..ents.items[0].ll], ep, base, null)).?;
    defer gpa.free(b2.bytes);
    try std.testing.expectEqual(@as(u32, 2), b2.codec);
    // Non-zero bytes after the records, or an unknown kind: no elision.
    const tail = try gpa.dupe(u8, g.items);
    defer gpa.free(tail);
    tail[tail.len - 1] = 1;
    try std.testing.expect(!elideSums(tail, copy, ep, base));
    // The anchor ties a decoded chunk to its place: restoring it at another epoch or offset
    // (a valid frame of another segment) is Corrupt.
    try std.testing.expect(elideSums(g.items, copy, ep, base));
    const moved = try gpa.dupe(u8, copy);
    defer gpa.free(moved);
    try std.testing.expectError(error.Corrupt, restoreSums(moved, ep + 1, base));
    @memcpy(moved, copy);
    try std.testing.expectError(error.Corrupt, restoreSums(moved, ep, base + 4096));
    // The first record keeps its checksum; an elided one that is not zero is Corrupt.
    try std.testing.expectEqualSlices(u8, g.items[0..8], copy[0..8]);
    const second = format.lenAt(copy);
    try std.testing.expect(std.mem.allEqual(u8, copy[second..][0..8], 0));
    copy[second] = 1;
    try std.testing.expectError(error.Corrupt, restoreSums(copy, ep, base));
    copy[second] = 0;
    // The last non-hole record (the commit) keeps its checksum too; a damaged byte in it is
    // Corrupt even though no elided checksum covers it.
    @memcpy(moved, copy);
    try restoreSums(moved, ep, base);
    try std.testing.expectEqualSlices(u8, g.items, moved);
    const cpos = std.mem.indexOf(u8, g.items, std.mem.asBytes(&cf)).? - format.header_len;
    try std.testing.expect(!std.mem.allEqual(u8, copy[cpos..][0..8], 0));
    @memcpy(moved, copy);
    moved[cpos + format.header_len] ^= 1;
    try std.testing.expectError(error.Corrupt, restoreSums(moved, ep, base));
}

test "codec 3: history dictionary frames, the dictionary file, and the wrong dictionary" {
    const gpa = std.testing.allocator;
    const ep: u64 = 7;
    const base: u64 = 4096;
    // Two groups whose records repeat each other (as consecutive checkpoints do).
    var g: std.ArrayList(u8) = .empty;
    defer g.deinit(gpa);
    // "Recent history": random bytes the group's records repeat (each record a different piece,
    // so the group alone hardly compresses, but against the dictionary it does).
    var buf: [2048]u8 align(8) = undefined;
    const recent = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(recent);
    var x: u32 = 9;
    for (recent) |*b| {
        x = x *% 1103515245 +% 12345;
        b.* = @truncate(x >> 16);
    }
    for (0..80) |i| {
        const n = format.write(&buf, format.loc(ep, base + g.items.len), .tx, 0, i, 0, &.{recent[i * 800 ..][0..600]});
        try g.appendSlice(gpa, buf[0..n]);
    }
    const cf: format.CommitFixed = .{ .epoch = ep, .group_start = format.loc(ep, base), .records = 81, .group_hash = 0, .prev_commit = 0 };
    const n = format.write(&buf, format.loc(ep, base + g.items.len), .commit, 0, 9, 0, &.{std.mem.asBytes(&cf)});
    try g.appendSlice(gpa, buf[0..n]);
    try g.appendNTimes(gpa, 0, std.mem.alignForward(usize, g.items.len, 4096) - g.items.len);

    // The dictionary: "recent history" holding the payload, persisted and loaded back.
    const dbytes = try dictFrom(gpa, recent, (64 << 10) + 8);
    var file: std.ArrayList(u8) = .empty;
    defer file.deinit(gpa);
    try file.appendSlice(gpa, &dictFileHeader(ep, 0x55));
    try dictRecord(gpa, &file, 0x55, 1, dbytes);
    var ds = try Dicts.create(gpa);
    defer ds.destroy(gpa);
    _ = try ds.push(gpa, dbytes);
    var loaded = try Dicts.create(gpa);
    defer loaded.destroy(gpa);
    const t = (try dictsTrusted(file.items, ep, loaded, gpa)).?;
    try std.testing.expectEqual(@as(u64, file.items.len), t.end);
    try std.testing.expectEqualSlices(u8, dbytes, loaded.get(1).?);
    // A torn or rotten record is not trusted; another epoch's file is not this one's.
    file.items[dict_header_len + @sizeOf(DictRec) + 100] ^= 1; // in the bytes
    var torn = try Dicts.create(gpa);
    defer torn.destroy(gpa);
    _ = (try dictsTrusted(file.items, ep, torn, gpa)).?;
    try std.testing.expectEqual(@as(usize, 0), torn.len());
    try std.testing.expect((try dictsTrusted(file.items, ep + 1, torn, gpa)) == null);

    const cd = try zstd_c.createCDict(dbytes, 3);
    defer zstd_c.freeCDict(cd);
    var with: std.ArrayList(u8) = .empty;
    defer with.deinit(gpa);
    var ents: std.ArrayList(Entry) = .empty;
    defer ents.deinit(gpa);
    try encodeGroup(gpa, 64 << 10, g.items, base, &with, file_header_len, &ents, ep, .{ .id = 1, .cdict = cd });
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    var ents2: std.ArrayList(Entry) = .empty;
    defer ents2.deinit(gpa);
    try encodeGroup(gpa, 64 << 10, g.items, base, &plain, file_header_len, &ents2, ep, null);
    try std.testing.expect(with.items.len * 2 < plain.items.len);
    for (ents.items) |en| {
        try std.testing.expectEqual(@as(u8, 3), codecOf(en.codec));
        try std.testing.expectEqual(@as(u32, 1), dictOf(en.codec));
        const off = en.phys - file_header_len;
        const ce = try checkFrame(en.phys, with.items[off..][0 .. frame_len + en.bl]);
        try std.testing.expectEqual(en.codec, ce.codec);
        const dec = try gpa.alloc(u8, en.ll);
        defer gpa.free(dec);
        try decode(ce, ep, loaded, with.items[off + frame_len ..][0..en.bl], dec);
        try std.testing.expectEqualSlices(u8, g.items[en.ls - base ..][0..en.ll], dec);
        // Without its dictionary, or with other bytes under its id, the frame is Corrupt.
        try std.testing.expectError(error.Corrupt, decode(ce, ep, null, with.items[off + frame_len ..][0..en.bl], dec));
        var wrong = try Dicts.create(gpa);
        defer wrong.destroy(gpa);
        const wb = try gpa.dupe(u8, dbytes);
        for (wb[8..], 0..) |*b, i| b.* +%= @truncate(i);
        _ = try wrong.push(gpa, wb);
        try std.testing.expectError(error.Corrupt, decode(ce, ep, wrong, with.items[off + frame_len ..][0..en.bl], dec));
        try std.testing.expectError(error.Corrupt, decodeStd(ce, ep, with.items[off + frame_len ..][0..en.bl], dec));
    }
    // A codec word with a dictionary id but codec 2 (or codec 3 without one) is not valid.
    try std.testing.expect(!codecValid(codecWord(2, 1)));
    try std.testing.expect(!codecValid(codecWord(3, 0)));
    try std.testing.expect(codecValid(codecWord(3, max_dicts)));
}
