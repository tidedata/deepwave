//! seg: one sealed ledger-history segment, the on-disk unit of the history index (root.zig).
//!
//! A segment covers 65,536 tx_seq (`seg * 65_536 ..`): exactly one tx-space bucket (id `seg`) and
//! 16 event-space buckets (ids `seg * 16 ..`, 2^28 packed event positions = 4,096 tx_seq each).
//! It is written once, when the index moves past it, and is immutable afterwards: a file
//! `s<seg>.seg` mapped read-only (the page cache holds it, never the heap), or the same bytes on
//! the heap for an in-memory index.
//!
//! Layout (little-endian; every array 8-byte aligned, offsets from the start of the blob):
//! - `Hdr` (checksummed) with the array table;
//! - tx records: per tx_seq `start .. start + ntx` its digest (32) and event count (u32);
//! - digest index: the records' first 8 digest bytes sorted, with their tx offsets, behind a
//!   radix directory on the top bits (`dir[p] .. dir[p + 1]` holds every prefix starting `p`);
//! - per space: the keys sorted by a 64-bit hash of their bytes (radix directory as above),
//!   key bytes, and per key its buckets (`erel`: bucket id relative to the segment) with the
//!   bucket's bits (`eb[j] .. eb[j + 1]` in `bits`, the bucket-relative positions exactly as
//!   the in-memory index held them, ascending).
//!
//! A lookup is one directory read plus a short scan of equal-prefix hashes (about two cache
//! lines), then a byte compare of the key.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const seg_txs: u64 = 65_536;
pub const ev_per_seg: u32 = 16;
pub const rec_len = 36;
const magic = "ZHSEG001";
const version: u32 = 1;
/// Event positions inside a segment: `(tx_off << 16) | event_index` (32 bits); the event bucket
/// is the top 4 bits, the bit inside it the low 28.
pub const ev_bit_mask: u32 = (1 << 28) - 1;

pub const Arr = extern struct { off: u64 = 0, len: u64 = 0 };

pub const SpaceHdr = extern struct {
    dir_bits: u32 = 0,
    _pad: u32 = 0,
    dir: Arr = .{},
    hash: Arr = .{},
    koff: Arr = .{},
    eoff: Arr = .{},
    erel: Arr = .{},
    eb: Arr = .{},
    bits: Arr = .{},
    kbytes: Arr = .{},
};

pub const Hdr = extern struct {
    magic: [8]u8,
    version: u32,
    hdr_len: u32,
    seg: u64,
    start: u32,
    ntx: u32,
    total: u64,
    recs: Arr = .{},
    dg_bits: u32 = 0,
    _pad: u32 = 0,
    dg_dir: Arr = .{},
    dg_pfx: Arr = .{},
    dg_off: Arr = .{},
    sp: [2]SpaceHdr = .{ .{}, .{} },
    crc: u32 = 0,
    _pad2: u32 = 0,
};

pub fn hashKey(key: []const u8) u64 {
    return std.hash.Wyhash.hash(0x5a5f_6869_7374_6f72, key);
}

fn dirBits(n: usize) u32 {
    if (n <= 8) return 0;
    const l = std.math.log2_int_ceil(usize, n);
    return @min(@as(u32, @intCast(l)) - 2, 24);
}

fn dirSlot(bits: u32, h: u64) usize {
    if (bits == 0) return 0;
    return @intCast(h >> @intCast(64 - bits));
}

pub const SpaceView = struct {
    dir_bits: u32 = 0,
    dir: []const u32 = &.{0},
    hash: []const u64 = &.{},
    koff: []const u32 = &.{0},
    eoff: []const u32 = &.{0},
    erel: []const u32 = &.{},
    eb: []const u32 = &.{0},
    bits: []const u32 = &.{},
    kbytes: []const u8 = &.{},

    pub fn keyCount(s: *const SpaceView) usize {
        return s.hash.len;
    }
    pub fn key(s: *const SpaceView, i: usize) []const u8 {
        return s.kbytes[s.koff[i]..s.koff[i + 1]];
    }
    /// Index of `key` (hash `h`), or null.
    pub fn find(s: *const SpaceView, h: u64, k: []const u8) ?usize {
        if (s.hash.len == 0) return null;
        const p = dirSlot(s.dir_bits, h);
        var i: usize = s.dir[p];
        const end: usize = s.dir[p + 1];
        while (i < end) : (i += 1) {
            const x = s.hash[i];
            if (x < h) continue;
            if (x > h) return null;
            if (std.mem.eql(u8, s.key(i), k)) return i;
        }
        return null;
    }
    /// Buckets of key `i`: entries `eoff[i] .. eoff[i + 1]`.
    pub fn ents(s: *const SpaceView, i: usize) [2]u32 {
        return .{ s.eoff[i], s.eoff[i + 1] };
    }
    pub fn entBits(s: *const SpaceView, j: usize) []const u32 {
        return s.bits[s.eb[j]..s.eb[j + 1]];
    }
};

pub const View = struct {
    seg: u64,
    start: u32,
    ntx: u32,
    recs: []const u8,
    dg_bits: u32,
    dg_dir: []const u32,
    dg_pfx: []const u64,
    dg_off: []const u32,
    sp: [2]SpaceView,

    fn arr(comptime T: type, mem: []const u8, a: Arr) ![]const T {
        const bytes = std.math.mul(u64, a.len, @sizeOf(T)) catch return error.Corrupt;
        const end = std.math.add(u64, a.off, bytes) catch return error.Corrupt;
        if (end > mem.len or a.off % @alignOf(T) != 0) return error.Corrupt;
        const p: [*]const T = @ptrCast(@alignCast(mem.ptr + @as(usize, @intCast(a.off))));
        return p[0..@intCast(a.len)];
    }

    /// Parses a blob (mapped file or heap); checks the header checksum and array bounds only
    /// (the body is trusted as written: tmp file, fsync, rename).
    pub fn parse(mem: []const u8) !View {
        if (mem.len < @sizeOf(Hdr) or @intFromPtr(mem.ptr) % 8 != 0) return error.Corrupt;
        var h: Hdr = undefined;
        @memcpy(std.mem.asBytes(&h), mem[0..@sizeOf(Hdr)]);
        if (!std.mem.eql(u8, &h.magic, magic) or h.version != version or h.hdr_len != @sizeOf(Hdr)) return error.Corrupt;
        if (h.total != mem.len) return error.Corrupt;
        const want = h.crc;
        h.crc = 0;
        if (std.hash.Crc32.hash(std.mem.asBytes(&h)) != want) return error.Corrupt;
        var v: View = .{
            .seg = h.seg,
            .start = h.start,
            .ntx = h.ntx,
            .recs = try arr(u8, mem, h.recs),
            .dg_bits = h.dg_bits,
            .dg_dir = try arr(u32, mem, h.dg_dir),
            .dg_pfx = try arr(u64, mem, h.dg_pfx),
            .dg_off = try arr(u32, mem, h.dg_off),
            .sp = undefined,
        };
        if (v.recs.len != @as(usize, v.ntx) * rec_len or v.dg_pfx.len != v.ntx or v.dg_off.len != v.ntx) return error.Corrupt;
        if (v.dg_dir.len != (@as(usize, 1) << @intCast(v.dg_bits)) + 1) return error.Corrupt;
        if (@as(u64, v.start) + v.ntx > seg_txs) return error.Corrupt;
        for (&v.sp, h.sp) |*s, sh| {
            s.* = .{
                .dir_bits = sh.dir_bits,
                .dir = try arr(u32, mem, sh.dir),
                .hash = try arr(u64, mem, sh.hash),
                .koff = try arr(u32, mem, sh.koff),
                .eoff = try arr(u32, mem, sh.eoff),
                .erel = try arr(u32, mem, sh.erel),
                .eb = try arr(u32, mem, sh.eb),
                .bits = try arr(u32, mem, sh.bits),
                .kbytes = try arr(u8, mem, sh.kbytes),
            };
            const n = s.hash.len;
            if (sh.dir_bits > 24 or s.dir.len != (@as(usize, 1) << @intCast(sh.dir_bits)) + 1) return error.Corrupt;
            if (s.koff.len != n + 1 or s.eoff.len != n + 1 or s.eb.len != s.erel.len + 1) return error.Corrupt;
            if (s.dir[s.dir.len - 1] != n or s.koff[n] != s.kbytes.len or s.eoff[n] != s.erel.len or s.eb[s.erel.len] != s.bits.len) return error.Corrupt;
        }
        return v;
    }

    pub fn has(v: *const View, off: u32) bool {
        return off >= v.start and off - v.start < v.ntx;
    }
    pub fn digest(v: *const View, off: u32) *const [32]u8 {
        return v.recs[(off - v.start) * rec_len ..][0..32];
    }
    pub fn evCount(v: *const View, off: u32) u32 {
        return std.mem.readInt(u32, v.recs[(off - v.start) * rec_len + 32 ..][0..4], .little);
    }
    /// The tx offset of `d` in this segment, or null.
    pub fn findDigest(v: *const View, d: *const [32]u8) ?u32 {
        if (v.ntx == 0) return null;
        const pfx = std.mem.readInt(u64, d[0..8], .little);
        const p = dirSlot(v.dg_bits, pfx);
        var i: usize = v.dg_dir[p];
        const end: usize = v.dg_dir[p + 1];
        while (i < end) : (i += 1) {
            const x = v.dg_pfx[i];
            if (x < pfx) continue;
            if (x > pfx) return null;
            const off = v.dg_off[i];
            if (std.mem.eql(u8, v.digest(off), d)) return off;
        }
        return null;
    }
};

/// One key of a space with its sorted positions (tx space: tx offset in the segment; event
/// space: `(tx_off << 16) | event_index`).
pub const KeyList = struct { key: []const u8, list: []const u32 };

pub const Input = struct {
    seg: u64,
    start: u32,
    /// `ntx * rec_len` bytes.
    recs: []const u8,
    spaces: [2][]const KeyList,
};

const Layout = struct {
    at: u64,
    fn take(l: *Layout, comptime T: type, n: usize) Arr {
        l.at = std.mem.alignForward(u64, l.at, 8);
        const a: Arr = .{ .off = l.at, .len = n };
        l.at += @as(u64, n) * @sizeOf(T);
        return a;
    }
};

fn put(comptime T: type, mem: []u8, a: Arr) []T {
    const p: [*]T = @ptrCast(@alignCast(mem.ptr + @as(usize, @intCast(a.off))));
    return p[0..@intCast(a.len)];
}

const Sorted = struct { h: u64, i: u32 };

fn buildDir(dir: []u32, bits: u32, hashes: []const u64) void {
    var p: usize = 0;
    for (hashes, 0..) |h, i| {
        const s = dirSlot(bits, h);
        while (p <= s) : (p += 1) dir[p] = @intCast(i);
    }
    while (p < dir.len) : (p += 1) dir[p] = @intCast(hashes.len);
}

/// Builds the blob of `in` in page-aligned memory from `std.heap.page_allocator` (free with
/// `freeBlob`). Temporary memory: about one hash and index per key.
pub fn build(gpa: Allocator, in: *const Input) ![]align(std.heap.page_size_min) u8 {
    const ntx: usize = in.recs.len / rec_len;
    std.debug.assert(in.recs.len == ntx * rec_len);
    var order: [2][]Sorted = .{ &.{}, &.{} };
    defer for (order) |o| gpa.free(o);
    var nents: [2]usize = .{ 0, 0 };
    var nbits: [2]usize = .{ 0, 0 };
    var nkb: [2]usize = .{ 0, 0 };
    for (in.spaces, 0..) |keys, si| {
        order[si] = try gpa.alloc(Sorted, keys.len);
        for (keys, order[si], 0..) |k, *o, i| {
            o.* = .{ .h = hashKey(k.key), .i = @intCast(i) };
            nbits[si] += k.list.len;
            nkb[si] += k.key.len;
            if (si == 0) {
                nents[si] += 1;
            } else {
                var prev: ?u32 = null;
                for (k.list) |r| {
                    const b = r >> 28;
                    if (prev == null or prev.? != b) nents[si] += 1;
                    prev = b;
                }
            }
        }
        const ctx = keys;
        std.mem.sort(Sorted, order[si], ctx, struct {
            fn lt(ks: []const KeyList, a: Sorted, b: Sorted) bool {
                if (a.h != b.h) return a.h < b.h;
                return std.mem.order(u8, ks[a.i].key, ks[b.i].key) == .lt;
            }
        }.lt);
    }
    const Dg = struct { pfx: u64, off: u32 };
    const dg = try gpa.alloc(Dg, ntx);
    defer gpa.free(dg);
    for (dg, 0..) |*e, i| e.* = .{ .pfx = std.mem.readInt(u64, in.recs[i * rec_len ..][0..8], .little), .off = in.start + @as(u32, @intCast(i)) };
    std.mem.sort(Dg, dg, {}, struct {
        fn lt(_: void, a: Dg, b: Dg) bool {
            return if (a.pfx != b.pfx) a.pfx < b.pfx else a.off < b.off;
        }
    }.lt);

    var h: Hdr = .{ .magic = magic.*, .version = version, .hdr_len = @sizeOf(Hdr), .seg = in.seg, .start = in.start, .ntx = @intCast(ntx), .total = 0 };
    var l: Layout = .{ .at = @sizeOf(Hdr) };
    h.recs = l.take(u8, in.recs.len);
    h.dg_bits = dirBits(ntx);
    h.dg_dir = l.take(u32, (@as(usize, 1) << @intCast(h.dg_bits)) + 1);
    h.dg_pfx = l.take(u64, ntx);
    h.dg_off = l.take(u32, ntx);
    for (&h.sp, 0..) |*s, si| {
        const n = in.spaces[si].len;
        s.dir_bits = dirBits(n);
        s.dir = l.take(u32, (@as(usize, 1) << @intCast(s.dir_bits)) + 1);
        s.hash = l.take(u64, n);
        s.koff = l.take(u32, n + 1);
        s.eoff = l.take(u32, n + 1);
        s.erel = l.take(u32, nents[si]);
        s.eb = l.take(u32, nents[si] + 1);
        s.bits = l.take(u32, nbits[si]);
        s.kbytes = l.take(u8, nkb[si]);
    }
    h.total = std.mem.alignForward(u64, l.at, 8);
    const mem = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), @intCast(h.total));
    errdefer std.heap.page_allocator.free(mem);
    @memset(mem, 0);

    @memcpy(put(u8, mem, h.recs), in.recs);
    const pfx = put(u64, mem, h.dg_pfx);
    const offs = put(u32, mem, h.dg_off);
    for (dg, pfx, offs) |e, *p, *o| {
        p.* = e.pfx;
        o.* = e.off;
    }
    buildDir(put(u32, mem, h.dg_dir), h.dg_bits, pfx);

    for (&h.sp, 0..) |*s, si| {
        const keys = in.spaces[si];
        const hash = put(u64, mem, s.hash);
        const koff = put(u32, mem, s.koff);
        const eoff = put(u32, mem, s.eoff);
        const erel = put(u32, mem, s.erel);
        const eb = put(u32, mem, s.eb);
        const bits = put(u32, mem, s.bits);
        const kb = put(u8, mem, s.kbytes);
        var ka: u32 = 0;
        var ea: u32 = 0;
        var ba: u32 = 0;
        for (order[si], 0..) |o, i| {
            const k = keys[o.i];
            hash[i] = o.h;
            koff[i] = ka;
            @memcpy(kb[ka..][0..k.key.len], k.key);
            ka += @intCast(k.key.len);
            eoff[i] = ea;
            if (si == 0) {
                erel[ea] = 0;
                eb[ea] = ba;
                ea += 1;
                @memcpy(bits[ba..][0..k.list.len], k.list);
                ba += @intCast(k.list.len);
            } else {
                var prev: ?u32 = null;
                for (k.list) |r| {
                    const b = r >> 28;
                    if (prev == null or prev.? != b) {
                        erel[ea] = b;
                        eb[ea] = ba;
                        ea += 1;
                    }
                    prev = b;
                    bits[ba] = r & ev_bit_mask;
                    ba += 1;
                }
            }
        }
        koff[keys.len] = ka;
        eoff[keys.len] = ea;
        eb[ea] = ba;
        buildDir(put(u32, mem, s.dir), s.dir_bits, hash);
    }
    h.crc = 0;
    h.crc = std.hash.Crc32.hash(std.mem.asBytes(&h));
    @memcpy(mem[0..@sizeOf(Hdr)], std.mem.asBytes(&h));
    return mem;
}

pub fn freeBlob(mem: []align(std.heap.page_size_min) u8) void {
    std.heap.page_allocator.free(mem);
}

test "segment blob round trip" {
    const gpa = std.testing.allocator;
    var recs: [3 * rec_len]u8 = undefined;
    for (0..3) |i| {
        @memset(recs[i * rec_len ..][0..32], @intCast(i + 1));
        std.mem.writeInt(u32, recs[i * rec_len + 32 ..][0..4], @intCast(i * 2), .little);
    }
    const tx = [_]KeyList{ .{ .key = "\x01abc", .list = &.{ 5, 6 } }, .{ .key = "\x02zz", .list = &.{7} } };
    const ev = [_]KeyList{.{ .key = "\x06t", .list = &.{ (5 << 16) | 1, (4097 << 16) | 0, (4097 << 16) | 3 } }};
    const in: Input = .{ .seg = 9, .start = 5, .recs = &recs, .spaces = .{ &tx, &ev } };
    const mem = try build(gpa, &in);
    defer freeBlob(mem);
    const v = try View.parse(mem);
    try std.testing.expectEqual(@as(u64, 9), v.seg);
    try std.testing.expect(v.has(7) and !v.has(8) and !v.has(4));
    try std.testing.expectEqual(@as(u32, 4), v.evCount(7));
    const d: [32]u8 = @splat(2);
    try std.testing.expectEqual(@as(?u32, 6), v.findDigest(&d));
    const i = v.sp[0].find(hashKey("\x01abc"), "\x01abc").?;
    const e = v.sp[0].ents(i);
    try std.testing.expectEqualSlices(u32, &.{ 5, 6 }, v.sp[0].entBits(e[0]));
    try std.testing.expect(v.sp[0].find(hashKey("\x01abd"), "\x01abd") == null);
    const j = v.sp[1].find(hashKey("\x06t"), "\x06t").?;
    const ej = v.sp[1].ents(j);
    try std.testing.expectEqual(@as(u32, 2), ej[1] - ej[0]);
    try std.testing.expectEqual(@as(u32, 0), v.sp[1].erel[ej[0]]);
    try std.testing.expectEqualSlices(u32, &.{(5 << 16) | 1}, v.sp[1].entBits(ej[0]));
    try std.testing.expectEqual(@as(u32, 1), v.sp[1].erel[ej[0] + 1]);
    try std.testing.expectEqualSlices(u32, &.{ (1 << 16) | 0, (1 << 16) | 3 }, v.sp[1].entBits(ej[0] + 1));
}
