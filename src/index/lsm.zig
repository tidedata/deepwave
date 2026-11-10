//! lsm: the StateService index on disk (FULLNODE-PARITY top-10 item 2, lane index-disk).
//!
//! One ordered byte keyspace, with the key bytes of sui-node 1.83.1's `sui-rpc-store` behind a
//! one-byte table prefix, so every scan and page token orders exactly as before:
//!
//! - `0x00 || kind || owner(32) || bcs(StructTag) || balance_tag || !balance BE? || id` -> version
//!   (owner index, `object_by_owner`);
//! - `0x01 || owner(32) || bcs(TypeTag)` -> (coin i128, address i128) as merge deltas (`balance`,
//!   summed like sui-node's merge operator; a sum of zero reads as absent);
//! - `0x02 || wrapper kind || bcs(TypeTag) || id` -> () (`object_by_type`, the three coin wrappers).
//!
//! Layout (a log-structured merge tree, files under `<dir>/index/` through `store.RealIo`):
//! - a memtable (`sorted.Sorted(Val)`) takes one checkpoint's changes under the index write lock;
//! - at a checkpoint boundary a full memtable (bytes or checkpoints) is frozen; a background
//!   thread writes it as a table (`<gen>.tbl`: prefix-compressed 16 KiB blocks with a checksum each,
//!   then a block index of first keys, then a footer), fsyncs it, then records it in the manifest
//!   with the frozen memtable's checkpoint as the durable watermark;
//! - runs (one or more tables with disjoint key ranges) are kept oldest first; size-tiered
//!   compaction merges the newest runs once they reach 1/ratio of the run before them, so the run
//!   count stays logarithmic. A merge that includes the oldest run drops deletes and zero sums.
//! - `meta`: two checksummed 16 KiB manifest slots written alternately (the higher valid counter
//!   wins): runs, watermark, next table number, and the state of an unfinished bulk build.
//!
//! Reads (index lock shared) merge the memtable, the frozen memtables and every run, newest
//! first; blocks are read with pread (the OS page cache is the block cache, so the index's own
//! memory is the memtables plus one block index per table).
//!
//! Bulk build from the live set (`Builder`, node start without a usable index): the key ranges are
//! split into `groups`; per group, every thread walks parts of the live set in store order (location ranges from `snap.liveBounds`), emits the
//! group's rows into a sort buffer and spills sorted temp tables; then the group's ranges are merged
//! (one thread per range) into the base run's tables. Finished parts and groups are in the
//! manifest, so a crashed build resumes where it stopped (same store tip), and the temp space at
//! any time is about one group's rows.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const store = @import("store");
const sorted = @import("sorted.zig");
const root = @import("root.zig");
const bulk = @import("bulk.zig");

pub const Op = enum(u8) { put = 1, del = 2, delta = 3 };
pub const max_val = 32;

pub const Val = struct {
    op: Op,
    len: u8 = 0,
    b: [max_val]u8 = @splat(0),

    pub fn bytes(v: *const Val) []const u8 {
        return v.b[0..v.len];
    }
    pub fn put(data: []const u8) Val {
        var v: Val = .{ .op = .put, .len = @intCast(data.len) };
        @memcpy(v.b[0..data.len], data);
        return v;
    }
    pub const del: Val = .{ .op = .del };
    pub fn delta(a: i128, b: i128) Val {
        var v: Val = .{ .op = .delta, .len = 32 };
        std.mem.writeInt(i128, v.b[0..16], a, .little);
        std.mem.writeInt(i128, v.b[16..32], b, .little);
        return v;
    }
    pub fn pair(v: *const Val) [2]i128 {
        if (v.len != 32) return .{ 0, 0 };
        return .{ std.mem.readInt(i128, v.b[0..16], .little), std.mem.readInt(i128, v.b[16..32], .little) };
    }
    pub fn version(v: *const Val) u64 {
        if (v.len < 8) return 0;
        return std.mem.readInt(u64, v.b[0..8], .little);
    }
    /// A delete, or a delta that sums to zero (the identity): reads as absent.
    pub fn empty(v: *const Val) bool {
        if (v.op == .del) return true;
        if (v.op == .delta) {
            const p = v.pair();
            return p[0] == 0 and p[1] == 0;
        }
        return false;
    }
};

/// `newer` over `older`: a put or delete hides what is older; a delta adds to it.
pub fn combine(newer: Val, older: Val) Val {
    if (newer.op != .delta or older.op == .del) return newer;
    const x = newer.pair();
    const y = older.pair();
    var r = Val.delta(x[0] +% y[0], x[1] +% y[1]);
    r.op = older.op;
    return r;
}

fn lessKey(a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

// ---------------------------------------------------------------------------- files

pub const Files = struct {
    rio: *store.RealIo,
    /// RealIo's file table is not thread safe: opens, closes and removes take this.
    mu: SpinLock = .{},

    pub fn open(f: *Files, name: []const u8, create: bool) !store.io.Fd {
        f.mu.lock();
        defer f.mu.unlock();
        if (create) try f.rio.remove(name);
        return f.rio.openFile(name, create);
    }
    pub fn close(f: *Files, fd: store.io.Fd) void {
        f.mu.lock();
        defer f.mu.unlock();
        f.rio.closeFile(fd);
    }
    pub fn remove(f: *Files, name: []const u8) void {
        f.mu.lock();
        defer f.mu.unlock();
        f.rio.remove(name) catch {};
    }
};

pub const SpinLock = struct {
    v: std.atomic.Value(u32) = .init(0),
    pub fn lock(l: *SpinLock) void {
        while (l.v.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    }
    pub fn unlock(l: *SpinLock) void {
        l.v.store(0, .release);
    }
};

pub fn tableName(buf: []u8, gen: u64) []const u8 {
    return std.fmt.bufPrint(buf, "index/{d}.tbl", .{gen}) catch unreachable;
}
fn tempName(buf: []u8, part: u64, k: u64) []const u8 {
    return std.fmt.bufPrint(buf, "index/b{d}-{d}.tmp", .{ part, k }) catch unreachable;
}

// ---------------------------------------------------------------------------- table format

/// Table format 1: each block is the prefix-compressed entries ++ checksum u64 (read only now).
const magic: u64 = 0x31305844495f4955; // "UI_IDX01"
/// Table format 2 (lane disk-fit): each block on disk is `codec u8` ++ (codec 1: the logical
/// length u32 LE ++ one zstd frame; codec 0: the logical bytes) ++ checksum u64 over everything
/// before it. The logical bytes are format 1's block body, so entries, first keys, scan order
/// and answers are unchanged; only the bytes on disk shrink. The checksum covers what is on
/// disk and is checked before anything is decoded. Footer, block index and offsets (physical)
/// are as in format 1.
const magic2: u64 = 0x32305844495f4955; // "UI_IDX02"
const footer_len = 48;
/// Logical block size of format-2 tables. Measured on the getcp fixture's tables (zstd level 3,
/// over format 1's 16 KiB blocks): 16 KiB 1.64x/2.11x, 32 KiB 1.70x/2.18x, 64 KiB 1.76x/2.25x.
/// 32 KiB keeps a point read at one ~32 KiB pread plus ~30 us of decode.
const block_target = 32 << 10;
const sum_seed: u64 = 0x1d;
const codec_stored: u8 = 0;
const codec_zstd: u8 = 1;
/// zstd level of table blocks (`ZUI_INDEX_ZSTD_LEVEL=N` overrides, read once; 0 or below -7
/// is clamped). Temp tables of a bulk build use `temp_level`.
pub var table_level: i32 = 3;
pub const temp_level: i32 = -1;
var level_env_checked = std.atomic.Value(bool).init(false);

fn tableLevel() i32 {
    if (!level_env_checked.load(.acquire)) {
        if (std.c.getenv("ZUI_INDEX_ZSTD_LEVEL")) |v| {
            if (std.fmt.parseInt(i32, std.mem.span(v), 10)) |l| {
                table_level = std.math.clamp(l, -7, 19);
            } else |_| {}
        }
        level_env_checked.store(true, .release);
    }
    return table_level;
}

// The vendored zstd 1.5.7 (compiled into the store module, src/store/zstd_c.zig): compression
// with an explicit level per call, so the store's chunk level setting is not shared.
const ZCCtx = opaque {};
extern fn ZSTD_createCCtx() ?*ZCCtx;
extern fn ZSTD_freeCCtx(cctx: *ZCCtx) usize;
extern fn ZSTD_compressCCtx(cctx: *ZCCtx, dst: [*]u8, dst_cap: usize, src: [*]const u8, src_size: usize, level: c_int) usize;
extern fn ZSTD_isError(code: usize) c_uint;

/// Max logical bytes of one block: a block ends once it reaches `block_target`, and one entry
/// is at most a key (u16-bounded in practice) plus `max_val`; a block claiming more is corrupt.
const max_block_logical: u32 = 16 << 20;

fn putUleb(l: *std.ArrayList(u8), gpa: Allocator, v: u64) !void {
    var x = v;
    while (true) {
        const b: u8 = @truncate(x & 0x7f);
        x >>= 7;
        if (x == 0) return l.append(gpa, b);
        try l.append(gpa, b | 0x80);
    }
}
fn getUleb(d: []const u8, pos: *usize) !u64 {
    var r: u64 = 0;
    var s: u6 = 0;
    while (true) {
        if (pos.* >= d.len) return error.Corrupt;
        const b = d[pos.*];
        pos.* += 1;
        r |= @as(u64, b & 0x7f) << s;
        if (b & 0x80 == 0) return r;
        if (s >= 56) return error.Corrupt;
        s += 7;
    }
}

pub const TableWriter = struct {
    gpa: Allocator,
    files: *Files,
    fd: store.io.Fd,
    file_off: u64 = 0,
    /// Bytes written back and dropped from the page cache so far (flush pacing).
    paced: u64 = 0,
    out: std.ArrayList(u8) = .empty,
    block: std.ArrayList(u8) = .empty,
    last: std.ArrayList(u8) = .empty,
    block_n: u32 = 0,
    offs: std.ArrayList(u64) = .empty,
    koffs: std.ArrayList(u32) = .empty,
    keys: std.ArrayList(u8) = .empty,
    entries: u64 = 0,
    /// Logical bytes of the blocks plus a checksum each (what format 1 would have written).
    raw_bytes: u64 = 0,
    /// zstd level of the blocks (format 2).
    level: i32,
    /// Logical block size (`block_target`; the fixture study varies it).
    target: usize = block_target,
    cctx: ?*ZCCtx = null,
    zbuf: std.ArrayList(u8) = .empty,

    /// A table writer at the table level (`tableLevel`).
    pub fn create(gpa: Allocator, files: *Files, name: []const u8) !TableWriter {
        return createLevel(gpa, files, name, tableLevel());
    }

    pub fn createLevel(gpa: Allocator, files: *Files, name: []const u8, level: i32) !TableWriter {
        return .{ .gpa = gpa, .files = files, .fd = try files.open(name, true), .level = level };
    }

    pub fn deinit(w: *TableWriter) void {
        w.out.deinit(w.gpa);
        w.block.deinit(w.gpa);
        w.last.deinit(w.gpa);
        w.offs.deinit(w.gpa);
        w.koffs.deinit(w.gpa);
        w.keys.deinit(w.gpa);
        w.zbuf.deinit(w.gpa);
        if (w.cctx) |c| _ = ZSTD_freeCCtx(c);
        w.cctx = null;
    }

    /// Abandons the file (caller removes it).
    pub fn abort(w: *TableWriter) void {
        w.files.close(w.fd);
        w.deinit();
    }

    /// Entries must come in strictly increasing key order.
    pub fn add(w: *TableWriter, key: []const u8, val: Val) !void {
        if (w.block.items.len >= w.target) try w.endBlock();
        var shared: usize = 0;
        if (w.block_n == 0) {
            try w.offs.append(w.gpa, w.file_off + w.out.items.len);
            try w.koffs.append(w.gpa, @intCast(w.keys.items.len));
            try w.keys.appendSlice(w.gpa, key);
        } else {
            const m = @min(key.len, w.last.items.len);
            while (shared < m and key[shared] == w.last.items[shared]) shared += 1;
        }
        try putUleb(&w.block, w.gpa, shared);
        try putUleb(&w.block, w.gpa, key.len - shared);
        try w.block.append(w.gpa, @intFromEnum(val.op));
        try w.block.append(w.gpa, val.len);
        try w.block.appendSlice(w.gpa, key[shared..]);
        try w.block.appendSlice(w.gpa, val.bytes());
        w.last.clearRetainingCapacity();
        try w.last.appendSlice(w.gpa, key);
        w.block_n += 1;
        w.entries += 1;
    }

    /// The zstd frame of `src` in `w.zbuf`, or null when it would not save at least 8 bytes
    /// (the block is then stored).
    fn compressBlock(w: *TableWriter, src: []const u8) !?[]const u8 {
        if (src.len <= 16) return null;
        const c = w.cctx orelse blk: {
            const c = ZSTD_createCCtx() orelse return error.OutOfMemory;
            w.cctx = c;
            break :blk c;
        };
        // Codec 1 spends 4 bytes on the logical length: a frame must save 8 more than that.
        const cap = src.len - 12;
        try w.zbuf.resize(w.gpa, cap);
        const n = ZSTD_compressCCtx(c, w.zbuf.items.ptr, cap, src.ptr, src.len, w.level);
        if (ZSTD_isError(n) != 0) return null; // dstSize_tooSmall: store it
        return w.zbuf.items[0..n];
    }

    fn endBlock(w: *TableWriter) !void {
        if (w.block_n == 0) return;
        const start = w.out.items.len;
        if (try w.compressBlock(w.block.items)) |z| {
            try w.out.append(w.gpa, codec_zstd);
            var l: [4]u8 = undefined;
            std.mem.writeInt(u32, &l, @intCast(w.block.items.len), .little);
            try w.out.appendSlice(w.gpa, &l);
            try w.out.appendSlice(w.gpa, z);
        } else {
            try w.out.append(w.gpa, codec_stored);
            try w.out.appendSlice(w.gpa, w.block.items);
        }
        var s: [8]u8 = undefined;
        std.mem.writeInt(u64, &s, store.checksum.hash(sum_seed, w.out.items[start..]), .little);
        try w.out.appendSlice(w.gpa, &s);
        w.raw_bytes += w.block.items.len + 8;
        w.block.clearRetainingCapacity();
        w.block_n = 0;
        if (w.out.items.len >= 1 << 20) try w.flushOut();
    }

    fn flushOut(w: *TableWriter) !void {
        if (w.out.items.len == 0) return;
        try w.files.rio.write(w.fd, w.file_off, w.out.items);
        w.file_off += w.out.items.len;
        w.out.clearRetainingCapacity();
        // Flush pacing (lane fast-start): every 32 MiB written goes to disk and out of the page
        // cache, so a bulk build inside a memory-capped cgroup never stalls on dirty pages.
        if (w.file_off - w.paced >= 32 << 20) {
            w.files.rio.dropCache(w.fd, w.paced, w.file_off - w.paced, true);
            w.paced = w.file_off;
        }
    }

    /// Writes the block index and the footer, fsyncs and closes. Returns the file size.
    pub fn finish(w: *TableWriter) !u64 {
        defer w.deinit();
        errdefer w.files.close(w.fd);
        try w.endBlock();
        const nblocks = w.offs.items.len;
        const end_blocks = w.file_off + w.out.items.len;
        try w.offs.append(w.gpa, end_blocks);
        try w.koffs.append(w.gpa, @intCast(w.keys.items.len));
        const index_off = end_blocks;
        const istart = w.out.items.len;
        for (w.offs.items) |o| {
            var b: [8]u8 = undefined;
            std.mem.writeInt(u64, &b, o, .little);
            try w.out.appendSlice(w.gpa, &b);
        }
        for (w.koffs.items) |o| {
            var b: [4]u8 = undefined;
            std.mem.writeInt(u32, &b, o, .little);
            try w.out.appendSlice(w.gpa, &b);
        }
        try w.out.appendSlice(w.gpa, w.keys.items);
        const index_len = w.out.items.len - istart;
        const isum = store.checksum.hash(sum_seed, w.out.items[istart..]);
        var f: [footer_len]u8 = undefined;
        std.mem.writeInt(u64, f[0..8], magic2, .little);
        std.mem.writeInt(u64, f[8..16], index_off, .little);
        std.mem.writeInt(u64, f[16..24], nblocks, .little);
        std.mem.writeInt(u64, f[24..32], w.entries, .little);
        std.mem.writeInt(u64, f[32..40], index_len, .little);
        std.mem.writeInt(u64, f[40..48], isum, .little);
        try w.out.appendSlice(w.gpa, &f);
        try w.flushOut();
        try w.files.rio.sync(w.fd);
        w.files.rio.dropCache(w.fd, w.paced, w.file_off - w.paced, false);
        w.files.close(w.fd);
        return w.file_off;
    }
};

pub const Table = struct {
    gen: u64,
    fd: store.io.Fd,
    size: u64,
    entries: u64,
    /// 1 (blocks stored as is) or 2 (codec byte per block, zstd).
    format: u8,
    /// Block offsets (nblocks + 1: the last is the end of the blocks).
    offs: []u64,
    koffs: []u32,
    keys: []u8,

    pub fn open(gpa: Allocator, files: *Files, name: []const u8, gen: u64) !*Table {
        const fd = try files.open(name, false);
        errdefer files.close(fd);
        const size = try files.rio.size(fd);
        if (size < footer_len) return error.Corrupt;
        var f: [footer_len]u8 = undefined;
        try files.rio.read(fd, size - footer_len, &f);
        const fmt: u8 = switch (std.mem.readInt(u64, f[0..8], .little)) {
            magic => 1,
            magic2 => 2,
            else => return error.Corrupt,
        };
        const index_off = std.mem.readInt(u64, f[8..16], .little);
        const nb = std.mem.readInt(u64, f[16..24], .little);
        const entries = std.mem.readInt(u64, f[24..32], .little);
        const index_len = std.mem.readInt(u64, f[32..40], .little);
        if (index_off + index_len + footer_len != size or index_len < (nb + 1) * 12) return error.Corrupt;
        const raw = try gpa.alloc(u8, index_len);
        defer gpa.free(raw);
        try files.rio.read(fd, index_off, raw);
        if (store.checksum.hash(sum_seed, raw) != std.mem.readInt(u64, f[40..48], .little)) return error.Corrupt;
        const t = try gpa.create(Table);
        errdefer gpa.destroy(t);
        const offs = try gpa.alloc(u64, nb + 1);
        errdefer gpa.free(offs);
        const koffs = try gpa.alloc(u32, nb + 1);
        errdefer gpa.free(koffs);
        for (offs, 0..) |*o, i| o.* = std.mem.readInt(u64, raw[i * 8 ..][0..8], .little);
        const kb = (nb + 1) * 8;
        for (koffs, 0..) |*o, i| o.* = std.mem.readInt(u32, raw[kb + i * 4 ..][0..4], .little);
        const keys = try gpa.dupe(u8, raw[kb + (nb + 1) * 4 ..]);
        t.* = .{ .gen = gen, .fd = fd, .size = size, .entries = entries, .format = fmt, .offs = offs, .koffs = koffs, .keys = keys };
        return t;
    }

    pub fn close(t: *Table, gpa: Allocator, files: *Files) void {
        files.close(t.fd);
        gpa.free(t.offs);
        gpa.free(t.koffs);
        gpa.free(t.keys);
        gpa.destroy(t);
    }

    pub fn nblocks(t: *const Table) usize {
        return t.offs.len - 1;
    }
    pub fn firstKey(t: *const Table, i: usize) []const u8 {
        return t.keys[t.koffs[i]..t.koffs[i + 1]];
    }
    /// The last block whose first key is <= key (0 when none is).
    fn blockFor(t: *const Table, key: []const u8) usize {
        var lo: usize = 0;
        var hi: usize = t.nblocks();
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            if (!lessKey(key, t.firstKey(mid))) lo = mid + 1 else hi = mid;
        }
        return if (lo == 0) 0 else lo - 1;
    }
    pub fn indexBytes(t: *const Table) u64 {
        return t.offs.len * 12 + t.keys.len;
    }
};

/// The logical bytes of a checked block body (`body` = what is on disk minus the checksum).
/// Format 1: the body itself. Format 2: by its codec byte; a zstd frame decodes into `dec`.
fn decodeBlock(format: u8, body: []const u8, dec: *std.ArrayList(u8), a: Allocator) ![]const u8 {
    if (format == 1) return body;
    if (body.len < 1) return error.Corrupt;
    switch (body[0]) {
        codec_stored => return body[1..],
        codec_zstd => {
            if (body.len < 5) return error.Corrupt;
            const n = std.mem.readInt(u32, body[1..5], .little);
            if (n == 0 or n > max_block_logical) return error.Corrupt;
            try dec.resize(a, n);
            store.zstd_c.decodeInto(body[5..], dec.items) catch |e| return switch (e) {
                error.OutOfMemory => error.OutOfMemory,
                error.Corrupt => error.Corrupt,
            };
            return dec.items;
        },
        else => return error.Corrupt,
    }
}

/// Iterator over one table's entries.
const TableIter = struct {
    t: *const Table,
    files: *Files,
    a: Allocator,
    blk: usize = 0,
    buf: std.ArrayList(u8) = .empty,
    /// Decoded block of a format-2 table (codec 1).
    dec: std.ArrayList(u8) = .empty,
    data: []const u8 = &.{},
    pos: usize = 0,
    key: std.ArrayList(u8) = .empty,
    val: Val = .del,
    valid: bool = false,

    fn load(it: *TableIter, b: usize) !void {
        it.blk = b;
        it.key.clearRetainingCapacity();
        const off = it.t.offs[b];
        const len = it.t.offs[b + 1] - off;
        if (len < 8) return error.Corrupt;
        try it.buf.resize(it.a, len);
        try it.files.rio.read(it.t.fd, off, it.buf.items);
        const body = it.buf.items[0 .. len - 8];
        if (store.checksum.hash(sum_seed, body) != std.mem.readInt(u64, it.buf.items[len - 8 ..][0..8], .little)) return error.Corrupt;
        it.data = try decodeBlock(it.t.format, body, &it.dec, it.a);
        it.pos = 0;
    }

    fn decode(it: *TableIter) !void {
        while (it.pos >= it.data.len) {
            const nb = it.blk + 1;
            if (nb >= it.t.nblocks()) {
                it.blk = it.t.nblocks();
                it.valid = false;
                return;
            }
            try it.load(nb);
        }
        const d = it.data;
        const shared = try getUleb(d, &it.pos);
        const unshared = try getUleb(d, &it.pos);
        if (it.pos + 2 > d.len) return error.Corrupt;
        const op: Op = switch (d[it.pos]) {
            1 => .put,
            2 => .del,
            3 => .delta,
            else => return error.Corrupt,
        };
        const vlen = d[it.pos + 1];
        it.pos += 2;
        if (shared > it.key.items.len or vlen > max_val or it.pos + unshared + vlen > d.len) return error.Corrupt;
        it.key.shrinkRetainingCapacity(shared);
        try it.key.appendSlice(it.a, d[it.pos..][0..unshared]);
        it.pos += unshared;
        it.val = .{ .op = op, .len = vlen };
        @memcpy(it.val.b[0..vlen], d[it.pos..][0..vlen]);
        it.pos += vlen;
        it.valid = true;
    }

    fn seek(it: *TableIter, key: []const u8) !void {
        if (it.t.nblocks() == 0) {
            it.valid = false;
            return;
        }
        try it.load(it.t.blockFor(key));
        while (true) {
            try it.decode();
            if (!it.valid or !lessKey(it.key.items, key)) return;
        }
    }

    fn next(it: *TableIter) !void {
        try it.decode();
    }
};

/// A run: tables with disjoint key ranges in key order (one table except the bulk-built base).
pub const Run = struct {
    tables: []*Table,

    pub fn bytes(r: *const Run) u64 {
        var n: u64 = 0;
        for (r.tables) |t| n += t.size;
        return n;
    }
    pub fn entries(r: *const Run) u64 {
        var n: u64 = 0;
        for (r.tables) |t| n += t.entries;
        return n;
    }
    fn destroy(r: *Run, gpa: Allocator, files: *Files, unlink: bool) void {
        for (r.tables) |t| {
            var nb: [64]u8 = undefined;
            const g = t.gen;
            t.close(gpa, files);
            if (unlink) files.remove(tableName(&nb, g));
        }
        gpa.free(r.tables);
        gpa.destroy(r);
    }
    /// The table a key falls into (by first keys).
    fn tableFor(r: *const Run, key: []const u8) usize {
        var lo: usize = 0;
        var hi: usize = r.tables.len;
        while (lo < hi) {
            const mid = (lo + hi) / 2;
            const t = r.tables[mid];
            if (t.nblocks() > 0 and !lessKey(key, t.firstKey(0))) lo = mid + 1 else hi = mid;
        }
        return if (lo == 0) 0 else lo - 1;
    }
};

const RunIter = struct {
    run: *const Run,
    ti: usize = 0,
    it: TableIter,

    fn init(a: Allocator, files: *Files, run: *const Run) RunIter {
        return .{ .run = run, .it = .{ .t = if (run.tables.len > 0) run.tables[0] else undefined, .files = files, .a = a } };
    }
    fn settle(r: *RunIter) !void {
        if (r.run.tables.len == 0) return;
        while (!r.it.valid and r.ti + 1 < r.run.tables.len) {
            r.ti += 1;
            r.it.t = r.run.tables[r.ti];
            try r.it.seek("");
        }
    }
    fn seek(r: *RunIter, key: []const u8) !void {
        if (r.run.tables.len == 0) {
            r.it.valid = false;
            return;
        }
        r.ti = r.run.tableFor(key);
        r.it.t = r.run.tables[r.ti];
        try r.it.seek(key);
        try r.settle();
    }
    fn next(r: *RunIter) !void {
        try r.it.next();
        try r.settle();
    }
};

// ---------------------------------------------------------------------------- merge

pub const Entry = struct { key: []const u8, val: Val };

const Src = struct {
    kind: union(enum) {
        mem: sorted.Sorted(Val).Iter,
        run: RunIter,
    },
    key: []const u8 = &.{},
    val: Val = .del,
    valid: bool = false,

    fn pull(s: *Src) void {
        switch (s.kind) {
            .mem => |*m| if (m.next()) |e| {
                s.key = e.key;
                s.val = e.val;
                s.valid = true;
            } else {
                s.valid = false;
            },
            .run => unreachable,
        }
    }
    fn fromRun(s: *Src) void {
        const r = &s.kind.run;
        s.valid = r.it.valid;
        if (s.valid) {
            s.key = r.it.key.items;
            s.val = r.it.val;
        }
    }
    fn seek(s: *Src, key: []const u8) !void {
        switch (s.kind) {
            .mem => |*m| {
                m.* = m.s.seek(key);
                s.pull();
            },
            .run => |*r| {
                try r.seek(key);
                s.fromRun();
            },
        }
    }
    fn advance(s: *Src) !void {
        switch (s.kind) {
            .mem => s.pull(),
            .run => |*r| {
                try r.next();
                s.fromRun();
            },
        }
    }
};

/// Merges sources (index 0 newest) in key order; equal keys resolve newest first, deltas add up.
pub const MergeIter = struct {
    a: Allocator,
    srcs: []Src,
    heap: []u32,
    hn: usize = 0,
    key: std.ArrayList(u8) = .empty,
    /// Keep deletes and non-zero deltas (a merge that is not the bottom of the tree).
    keep_deletes: bool = false,

    fn before(m: *const MergeIter, x: u32, y: u32) bool {
        return switch (std.mem.order(u8, m.srcs[x].key, m.srcs[y].key)) {
            .lt => true,
            .gt => false,
            .eq => x < y,
        };
    }
    fn down(m: *MergeIter, from: usize) void {
        var i = from;
        while (true) {
            const l = 2 * i + 1;
            if (l >= m.hn) return;
            var c = l;
            if (l + 1 < m.hn and m.before(m.heap[l + 1], m.heap[l])) c = l + 1;
            if (!m.before(m.heap[c], m.heap[i])) return;
            std.mem.swap(u32, &m.heap[c], &m.heap[i]);
            i = c;
        }
    }
    fn rebuild(m: *MergeIter) void {
        m.hn = 0;
        for (m.srcs, 0..) |s, i| if (s.valid) {
            m.heap[m.hn] = @intCast(i);
            m.hn += 1;
        };
        var i = m.hn / 2;
        while (i > 0) {
            i -= 1;
            m.down(i);
        }
    }

    pub fn seek(m: *MergeIter, key: []const u8) !void {
        for (m.srcs) |*s| try s.seek(key);
        m.rebuild();
    }

    fn popTop(m: *MergeIter) !void {
        const top = m.heap[0];
        try m.srcs[top].advance();
        if (!m.srcs[top].valid) {
            m.hn -= 1;
            m.heap[0] = m.heap[m.hn];
        }
        if (m.hn > 0) m.down(0);
    }

    /// The next live entry (key valid until the next call).
    pub fn next(m: *MergeIter) !?Entry {
        while (m.hn > 0) {
            const top = m.heap[0];
            m.key.clearRetainingCapacity();
            try m.key.appendSlice(m.a, m.srcs[top].key);
            var acc = m.srcs[top].val;
            try m.popTop();
            while (m.hn > 0 and std.mem.eql(u8, m.srcs[m.heap[0]].key, m.key.items)) {
                if (acc.op == .delta) acc = combine(acc, m.srcs[m.heap[0]].val);
                try m.popTop();
            }
            if (acc.op == .delta) {
                const p = acc.pair();
                if (p[0] == 0 and p[1] == 0) continue;
            } else if (acc.op == .del and !m.keep_deletes) continue;
            return .{ .key = m.key.items, .val = acc };
        }
        return null;
    }
};

// ---------------------------------------------------------------------------- memtable

pub const Mem = struct {
    s: sorted.Sorted(Val) = .{},
    bytes: usize = 0,
    /// The checkpoint this memtable's changes end at (set at each checkpoint boundary).
    seq: ?u64 = null,
    checkpoints: u64 = 0,

    fn deinit(m: *Mem, gpa: Allocator) void {
        m.s.deinit(gpa);
    }

    /// `drop_deletes`: nothing older than this memtable exists (memory mode), so a delete removes.
    pub fn apply(m: *Mem, gpa: Allocator, key: []const u8, val: Val, drop_deletes: bool) !void {
        if (m.s.get(key)) |cur| {
            const r = combine(val, cur.*);
            if (r.empty() and (r.op == .delta or drop_deletes)) {
                _ = m.s.remove(gpa, key);
                m.bytes -|= key.len + 64;
            } else cur.* = r;
            return;
        }
        if (val.empty() and (val.op == .delta or drop_deletes)) return;
        _ = try m.s.put(gpa, key, val);
        m.bytes += key.len + 64;
    }
};

// ---------------------------------------------------------------------------- manifest

const slot_len = 16 << 10;
const meta_name = "meta";
pub const build_parts = 64;

pub const BuildState = struct {
    tip: u64,
    groups: u32,
    /// Group being built; its finished parts and their temp table counts.
    group: u32 = 0,
    done: u64 = 0,
    chunks: [build_parts]u32 = @splat(0),
};

const Manifest = struct {
    counter: u64 = 0,
    watermark: ?u64 = null,
    next_gen: u64 = 1,
    build: ?BuildState = null,

    fn encode(m: *const Manifest, runs: []const *Run, buf: *[slot_len]u8) !void {
        @memset(buf, 0);
        var p: usize = 0;
        const W = struct {
            fn int(b: *[slot_len]u8, pos: *usize, comptime T: type, v: T) !void {
                if (pos.* + @sizeOf(T) > slot_len - 8) return error.ManifestFull;
                std.mem.writeInt(T, b[pos.*..][0..@sizeOf(T)], v, .little);
                pos.* += @sizeOf(T);
            }
        };
        try W.int(buf, &p, u64, magic);
        try W.int(buf, &p, u64, m.counter);
        try W.int(buf, &p, u64, m.watermark orelse std.math.maxInt(u64));
        try W.int(buf, &p, u64, m.next_gen);
        if (m.build) |b| {
            try W.int(buf, &p, u8, 1);
            try W.int(buf, &p, u64, b.tip);
            try W.int(buf, &p, u32, b.groups);
            try W.int(buf, &p, u32, b.group);
            try W.int(buf, &p, u64, b.done);
            for (b.chunks) |c| try W.int(buf, &p, u32, c);
        } else try W.int(buf, &p, u8, 0);
        try W.int(buf, &p, u32, @intCast(runs.len));
        for (runs) |r| {
            try W.int(buf, &p, u32, @intCast(r.tables.len));
            for (r.tables) |t| try W.int(buf, &p, u64, t.gen);
        }
        std.mem.writeInt(u64, buf[slot_len - 8 ..][0..8], store.checksum.hash(sum_seed, buf[0 .. slot_len - 8]), .little);
    }

    const Decoded = struct { m: Manifest, runs: [][]u64 };

    fn decode(a: Allocator, buf: []const u8) !?Decoded {
        if (buf.len != slot_len) return null;
        if (store.checksum.hash(sum_seed, buf[0 .. slot_len - 8]) != std.mem.readInt(u64, buf[slot_len - 8 ..][0..8], .little)) return null;
        var p: usize = 0;
        const R = struct {
            fn int(b: []const u8, pos: *usize, comptime T: type) T {
                defer pos.* += @sizeOf(T);
                return std.mem.readInt(T, b[pos.*..][0..@sizeOf(T)], .little);
            }
        };
        if (R.int(buf, &p, u64) != magic) return null;
        var m: Manifest = .{};
        m.counter = R.int(buf, &p, u64);
        const wm = R.int(buf, &p, u64);
        m.watermark = if (wm == std.math.maxInt(u64)) null else wm;
        m.next_gen = R.int(buf, &p, u64);
        if (R.int(buf, &p, u8) == 1) {
            var b: BuildState = .{ .tip = R.int(buf, &p, u64), .groups = R.int(buf, &p, u32) };
            b.group = R.int(buf, &p, u32);
            b.done = R.int(buf, &p, u64);
            for (&b.chunks) |*c| c.* = R.int(buf, &p, u32);
            m.build = b;
        }
        const nr = R.int(buf, &p, u32);
        if (nr > 4096) return null;
        const runs = try a.alloc([]u64, nr);
        for (runs) |*r| {
            if (p + 4 > slot_len - 8) return null;
            const nt = R.int(buf, &p, u32);
            if (nt > 4096 or p + nt * 8 > slot_len) return null;
            r.* = try a.alloc(u64, nt);
            for (r.*) |*g| g.* = R.int(buf, &p, u64);
        }
        return .{ .m = m, .runs = runs };
    }
};

// ---------------------------------------------------------------------------- db

pub const Options = struct {
    /// Freeze the memtable once it holds this many bytes (approximate)...
    mem_bytes: usize = 64 << 20,
    /// ... or covers this many checkpoints (bounds the replay after a restart).
    max_checkpoints: u64 = 2048,
    /// Merge the newest runs once their total reaches 1/ratio of the run before them.
    ratio: u64 = 4,
    max_runs: usize = 12,
    /// The writer waits once this many frozen memtables wait for the background thread.
    max_frozen: usize = 8,
    /// Bulk build: threads (0 = CPUs, at most 32), sort buffer per thread, key-range groups.
    build_threads: usize = 0,
    build_chunk_bytes: usize = 96 << 20,
    build_groups: u32 = 4,
    /// Bulk build by key-range partitions (bulk.zig): one pass over the live set, rows spilled
    /// to one file per partition, each partition sorted in memory and written straight into the
    /// base run's tables. False: the sort-and-merge build below (`Builder.runFromMerge`).
    bulk: bool = true,
    /// Memory the partitioned build may allocate (lane buffers while rows arrive, then the
    /// partitions being sorted). `build_chunk_bytes` caps one lane's buffer.
    build_mem_bytes: usize = 2 << 30,
    sync: store.SyncMode = .data,
};

pub const Stats = struct {
    flushes: u64 = 0,
    compactions: u64 = 0,
    compacted_bytes: u64 = 0,
    bg_errors: u64 = 0,
    frozen_waits: u64 = 0,
};

pub const Db = struct {
    gpa: Allocator,
    opts: Options = .{},
    files: ?*Files = null,
    rio: ?*store.RealIo = null,
    mem: *Mem,
    /// Oldest first.
    frozen: std.ArrayList(*Mem) = .empty,
    /// Flushed memtables, freed on the writer's thread (`reclaim`), never the background one.
    /// smp_allocator puts a free on the freeing thread's slot list and the writer, which
    /// allocated every key, only looks at its own slot and one other (max_alloc_search 1): a
    /// memtable freed by the background thread stranded its small blocks there for good (rig
    /// rehearsal 2026-11-09: anon +150 MiB a minute in catch-up, outside `node gpa`, all of it
    /// `Mem.deinit` on this thread). The background thread appends under `lock`; the writer
    /// moves them to `to_free` at a checkpoint boundary (under `lock`) and frees them after.
    retired: std.ArrayList(*Mem) = .empty,
    /// Writer only: retired memtables `reclaim` frees.
    to_free: std.ArrayList(*Mem) = .empty,
    /// Oldest first.
    runs: std.ArrayList(*Run) = .empty,
    man: Manifest = .{},
    slot: u1 = 0,
    meta_fd: ?store.io.Fd = null,
    /// Background flush and compaction (disk mode).
    lock: ?*root.RwLock = null,
    io: ?std.Io = null,
    thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),
    /// Set by a caller that may stop a bulk build (node shutdown): the builder checks it between
    /// parts and every 64k keys of a merge, and returns error.Stopped (the build resumes).
    build_stop: ?*const std.atomic.Value(bool) = null,
    work: std.atomic.Value(u32) = .init(0),
    stats: Stats = .{},
    last_err: ?anyerror = null,

    /// In-memory only (tests, fixtures): one memtable, never frozen.
    pub fn memory(gpa: Allocator) !Db {
        const m = try gpa.create(Mem);
        m.* = .{};
        return .{ .gpa = gpa, .mem = m };
    }

    /// Opens (or creates) the on-disk index under `dir`. The caller decides from `watermark()` and
    /// `buildPending()` whether to replay or build.
    pub fn open(gpa: Allocator, io: std.Io, dir: []const u8, opts: Options) !Db {
        const rio = try store.RealIo.init(gpa, io, dir, .{ .sync = opts.sync, .uring = false });
        errdefer rio.deinit();
        const files = try gpa.create(Files);
        errdefer gpa.destroy(files);
        files.* = .{ .rio = rio };
        const m = try gpa.create(Mem);
        errdefer gpa.destroy(m);
        m.* = .{};
        var db: Db = .{ .gpa = gpa, .opts = opts, .files = files, .rio = rio, .mem = m, .io = io };
        errdefer db.deinitInner();
        try db.loadManifest();
        return db;
    }

    fn deinitInner(db: *Db) void {
        const files = db.files;
        for (db.runs.items) |r| r.destroy(db.gpa, files.?, false);
        db.runs.deinit(db.gpa);
        for (db.frozen.items) |f| {
            f.deinit(db.gpa);
            db.gpa.destroy(f);
        }
        db.frozen.deinit(db.gpa);
        db.reclaimAll();
        db.mem.deinit(db.gpa);
        db.gpa.destroy(db.mem);
        if (files) |f| {
            if (db.meta_fd) |fd| f.close(fd);
            db.gpa.destroy(f);
        }
        if (db.rio) |r| r.deinit();
    }

    pub fn deinit(db: *Db) void {
        db.stopBackground();
        // A clean stop makes everything applied durable, so the next start replays nothing.
        if (db.files != null and db.lock != null) db.flushAtClose() catch |e| std.log.err("state index: flush at close: {s}", .{@errorName(e)});
        if (db.files == null) {
            db.mem.deinit(db.gpa);
            db.gpa.destroy(db.mem);
            db.frozen.deinit(db.gpa);
            db.runs.deinit(db.gpa);
            return;
        }
        db.deinitInner();
    }

    /// More frozen memtables wait than `max_frozen` (the writer should wait; racy read is fine).
    pub fn frozenBacklog(db: *const Db) bool {
        return @atomicLoad(usize, &db.frozen.items.len, .monotonic) > db.opts.max_frozen;
    }

    pub fn onDisk(db: *const Db) bool {
        return db.files != null;
    }
    pub fn watermark(db: *const Db) ?u64 {
        return db.man.watermark;
    }
    pub fn buildPending(db: *const Db) ?BuildState {
        return db.man.build;
    }

    // ---------------------------------------------------------------- manifest i/o

    fn loadManifest(db: *Db) !void {
        const files = db.files.?;
        const fd = files.open(meta_name, false) catch |e| switch (e) {
            error.FileNotFound => blk: {
                const fd = try files.open(meta_name, true);
                try files.rio.truncate(fd, 2 * slot_len);
                break :blk fd;
            },
            else => return e,
        };
        db.meta_fd = fd;
        var arena = std.heap.ArenaAllocator.init(db.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const size = try files.rio.size(fd);
        var best: ?Manifest.Decoded = null;
        var best_slot: u1 = 0;
        if (size >= 2 * slot_len) {
            for (0..2) |i| {
                const buf = try a.alloc(u8, slot_len);
                try files.rio.read(fd, i * slot_len, buf);
                if (try Manifest.decode(a, buf)) |d| if (best == null or d.m.counter > best.?.m.counter) {
                    best = d;
                    best_slot = @intCast(i);
                };
            }
        } else try files.rio.truncate(fd, 2 * slot_len);
        const d = best orelse {
            try db.gc();
            return;
        };
        db.man = d.m;
        db.slot = best_slot +% 1;
        for (d.runs) |gens| {
            const r = try db.gpa.create(Run);
            errdefer db.gpa.destroy(r);
            const tabs = try db.gpa.alloc(*Table, gens.len);
            var n: usize = 0;
            errdefer {
                for (tabs[0..n]) |t| t.close(db.gpa, files);
                db.gpa.free(tabs);
            }
            for (gens) |g| {
                var nb: [64]u8 = undefined;
                tabs[n] = try Table.open(db.gpa, files, tableName(&nb, g), g);
                n += 1;
            }
            r.* = .{ .tables = tabs };
            try db.runs.append(db.gpa, r);
        }
        try db.gc();
    }

    pub fn writeManifest(db: *Db) !void {
        const files = db.files.?;
        db.man.counter += 1;
        const buf = try db.gpa.create([slot_len]u8);
        defer db.gpa.destroy(buf);
        try db.man.encode(db.runs.items, buf);
        try files.rio.writeSync(db.meta_fd.?, @as(u64, db.slot) * slot_len, buf);
        db.slot +%= 1;
    }

    /// Removes files no manifest state refers to (a crash mid-flush, mid-compaction or mid-build).
    pub fn gc(db: *Db) !void {
        const files = db.files.?;
        const names = files.rio.listDir(db.gpa, "index") catch return;
        defer {
            for (names) |n| db.gpa.free(n);
            db.gpa.free(names);
        }
        // A pending partitioned build (bulk.zig) keeps its state file, its partition files and
        // the tables of its finished ranges.
        const load: ?*bulk.State = if (db.man.build) |b| (if (b.tip == pending_tip) bulk.State.read(db.gpa, files) else null) else null;
        defer if (load) |l| db.gpa.destroy(l);
        for (names) |n| {
            var keep = false;
            if (load) |l| if (l.keeps(n)) {
                keep = true;
            };
            if (keep) continue;
            if (std.mem.endsWith(u8, n, ".tbl")) {
                if (std.fmt.parseInt(u64, n[0 .. n.len - 4], 10)) |g| {
                    for (db.runs.items) |r| for (r.tables) |t| {
                        if (t.gen == g) keep = true;
                    };
                } else |_| {}
            } else if (std.mem.endsWith(u8, n, ".tmp") and n.len > 1 and n[0] == 'b') {
                if (db.man.build) |b| {
                    var it = std.mem.splitScalar(u8, n[1 .. n.len - 4], '-');
                    const p = std.fmt.parseInt(u64, it.next() orelse "", 10) catch build_parts;
                    const k = std.fmt.parseInt(u64, it.next() orelse "", 10) catch std.math.maxInt(u64);
                    if (p < build_parts and b.done & (@as(u64, 1) << @intCast(p)) != 0 and k < b.chunks[p]) keep = true;
                }
            }
            if (!keep) {
                var nb: [300]u8 = undefined;
                files.remove(std.fmt.bufPrint(&nb, "index/{s}", .{n}) catch continue);
            }
        }
    }

    /// Drops every run and the watermark (a rebuild from the live set follows).
    pub fn reset(db: *Db) !void {
        for (db.runs.items) |r| r.destroy(db.gpa, db.files.?, true);
        db.runs.clearRetainingCapacity();
        db.mem.deinit(db.gpa);
        db.mem.* = .{};
        db.man.watermark = null;
        db.man.build = null;
        try db.writeManifest();
        try db.gc();
    }

    // ---------------------------------------------------------------- writes (index lock exclusive)

    pub fn apply(db: *Db, key: []const u8, val: Val) !void {
        try db.mem.apply(db.gpa, key, val, db.files == null);
    }

    /// Checkpoint boundary: the memtable now covers `seq`. Freezes it when it is full (disk mode).
    /// Returns true when a frozen memtable waits for the background thread.
    pub fn endCheckpoint(db: *Db, seq: u64) !bool {
        db.mem.seq = seq;
        db.mem.checkpoints += 1;
        if (db.files == null) return false;
        if (db.retired.items.len != 0 and db.to_free.items.len == 0) std.mem.swap(std.ArrayList(*Mem), &db.retired, &db.to_free);
        if (db.mem.bytes < db.opts.mem_bytes and db.mem.checkpoints < db.opts.max_checkpoints) return false;
        const fresh = try db.gpa.create(Mem);
        fresh.* = .{};
        db.frozen.append(db.gpa, db.mem) catch |e| {
            db.gpa.destroy(fresh);
            return e;
        };
        db.mem = fresh;
        _ = db.work.fetchAdd(1, .release);
        return db.frozen.items.len > db.opts.max_frozen;
    }

    /// Writer thread, after releasing the index lock: frees the memtables the background thread
    /// flushed (handed over by `endCheckpoint`), so their blocks go back to the writer's
    /// allocator slot and the next memtable reuses them.
    pub fn reclaim(db: *Db) void {
        for (db.to_free.items) |m| {
            m.deinit(db.gpa);
            db.gpa.destroy(m);
        }
        db.to_free.clearRetainingCapacity();
    }

    /// Close: every retired memtable, whatever thread (the background one is stopped).
    fn reclaimAll(db: *Db) void {
        db.reclaim();
        db.to_free.deinit(db.gpa);
        for (db.retired.items) |m| {
            m.deinit(db.gpa);
            db.gpa.destroy(m);
        }
        db.retired.deinit(db.gpa);
    }

    // ---------------------------------------------------------------- reads (index lock shared)

    /// A merging iterator over everything, positioned at the first live key >= `start`.
    /// Buffers come from `a` (a request arena).
    pub fn iter(db: *const Db, a: Allocator, start: []const u8) !MergeIter {
        const n = 1 + db.frozen.items.len + db.runs.items.len;
        const srcs = try a.alloc(Src, n);
        var i: usize = 0;
        srcs[i] = .{ .kind = .{ .mem = db.mem.s.seek("") } };
        i += 1;
        var f = db.frozen.items.len;
        while (f > 0) {
            f -= 1;
            srcs[i] = .{ .kind = .{ .mem = db.frozen.items[f].s.seek("") } };
            i += 1;
        }
        var r = db.runs.items.len;
        while (r > 0) {
            r -= 1;
            srcs[i] = .{ .kind = .{ .run = RunIter.init(a, db.files.?, db.runs.items[r]) } };
            i += 1;
        }
        var m: MergeIter = .{ .a = a, .srcs = srcs, .heap = try a.alloc(u32, n) };
        try m.seek(start);
        return m;
    }

    pub fn get(db: *const Db, a: Allocator, key: []const u8) !?Val {
        var m = try db.iter(a, key);
        const e = try m.next() orelse return null;
        if (!std.mem.eql(u8, e.key, key)) return null;
        return e.val;
    }

    pub fn diskBytes(db: *const Db) u64 {
        var n: u64 = 0;
        for (db.runs.items) |r| n += r.bytes();
        return n;
    }
    pub fn indexMemory(db: *const Db) u64 {
        var n: u64 = db.mem.bytes;
        for (db.frozen.items) |f| n += f.bytes;
        for (db.runs.items) |r| for (r.tables) |t| {
            n += t.indexBytes();
        };
        return n;
    }

    // ---------------------------------------------------------------- background

    pub fn startBackground(db: *Db, lock: *root.RwLock) !void {
        if (db.files == null or db.thread != null) return;
        db.lock = lock;
        db.thread = try std.Thread.spawn(.{ .stack_size = 8 << 20 }, bgMain, .{db});
    }

    pub fn stopBackground(db: *Db) void {
        if (db.thread) |t| {
            db.stop.store(true, .release);
            t.join();
            db.thread = null;
        }
    }

    /// Runs the pending flushes and compactions on the calling thread (tests; the node start).
    pub fn settle(db: *Db, lock: *root.RwLock) !void {
        db.lock = lock;
        while (try db.step()) {}
    }

    fn bgMain(db: *Db) void {
        while (!db.stop.load(.acquire)) {
            const did = db.step() catch |e| blk: {
                db.stats.bg_errors += 1;
                db.last_err = e;
                std.log.err("state index: background: {s}", .{@errorName(e)});
                break :blk false;
            };
            if (!did) db.io.?.sleep(.fromMilliseconds(if (db.last_err != null) 1000 else 20), .awake) catch {};
        }
    }

    /// One flush or one compaction. Only this thread changes `runs` and pops `frozen`.
    fn step(db: *Db) !bool {
        const lock = db.lock.?;
        lock.lockShared();
        const oldest: ?*Mem = if (db.frozen.items.len > 0) db.frozen.items[0] else null;
        lock.unlockShared();
        if (oldest) |fm| {
            try db.flush(fm);
            return true;
        }
        if (db.pickCompaction()) |from| {
            try db.compact(from);
            return true;
        }
        return false;
    }

    fn flushAtClose(db: *Db) !void {
        if (db.mem.seq != null and db.mem.s.len > 0) {
            const fresh = try db.gpa.create(Mem);
            fresh.* = .{};
            db.frozen.append(db.gpa, db.mem) catch |e| {
                db.gpa.destroy(fresh);
                return e;
            };
            db.mem = fresh;
        }
        while (db.frozen.items.len > 0) try db.flush(db.frozen.items[0]);
    }

    fn newGen(db: *Db) u64 {
        defer db.man.next_gen += 1;
        return db.man.next_gen;
    }

    fn flush(db: *Db, fm: *Mem) !void {
        const files = db.files.?;
        // Room to retire `fm` once it leaves `frozen` (under the lock, which must not fail).
        try db.retired.ensureUnusedCapacity(db.gpa, 1);
        if (fm.s.len == 0) {
            const lock = db.lock.?;
            lock.lock();
            _ = db.frozen.orderedRemove(0);
            db.retired.appendAssumeCapacity(fm);
            lock.unlock();
            if (fm.seq) |s| db.man.watermark = s;
            try db.writeManifest();
            return;
        }
        const run = try db.gpa.create(Run);
        errdefer db.gpa.destroy(run);
        const tabs = try db.gpa.alloc(*Table, 1);
        errdefer db.gpa.free(tabs);
        const gen = db.newGen();
        var nb: [64]u8 = undefined;
        const name = tableName(&nb, gen);
        var w = try TableWriter.create(db.gpa, files, name);
        {
            errdefer w.abort();
            var it = fm.s.seek("");
            while (it.next()) |e| try w.add(e.key, e.val);
        }
        _ = try w.finish();
        tabs[0] = try Table.open(db.gpa, files, name, gen);
        run.* = .{ .tables = tabs };
        const lock = db.lock.?;
        lock.lock();
        db.runs.append(db.gpa, run) catch |e| {
            lock.unlock();
            run.destroy(db.gpa, files, true);
            return e;
        };
        _ = db.frozen.orderedRemove(0);
        db.retired.appendAssumeCapacity(fm);
        lock.unlock();
        if (fm.seq) |s| db.man.watermark = s;
        try db.writeManifest();
        db.stats.flushes += 1;
    }

    /// The oldest run of the newest stretch to merge, if any.
    fn pickCompaction(db: *Db) ?usize {
        const rs = db.runs.items;
        if (rs.len < 2) return null;
        var newer: u64 = 0;
        var i = rs.len - 1;
        newer = rs[i].bytes();
        while (i > 0) {
            i -= 1;
            if (newer * db.opts.ratio >= rs[i].bytes()) {
                // merge rs[i..]; keep looking for an older run the merged one would also reach
                var j = i;
                var sum = newer + rs[i].bytes();
                while (j > 0 and sum * db.opts.ratio >= rs[j - 1].bytes()) {
                    j -= 1;
                    sum += rs[j].bytes();
                }
                return j;
            }
            newer += rs[i].bytes();
        }
        if (rs.len > db.opts.max_runs) return rs.len - db.opts.max_runs / 2;
        return null;
    }

    fn compact(db: *Db, from: usize) !void {
        const files = db.files.?;
        const rs = db.runs.items[from..];
        var arena = std.heap.ArenaAllocator.init(db.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const srcs = try a.alloc(Src, rs.len);
        for (srcs, 0..) |*s, k| s.* = .{ .kind = .{ .run = RunIter.init(a, files, rs[rs.len - 1 - k]) } };
        var m: MergeIter = .{ .a = a, .srcs = srcs, .heap = try a.alloc(u32, rs.len), .keep_deletes = from != 0 };
        try m.seek("");
        const gen = db.newGen();
        var nb: [64]u8 = undefined;
        const name = tableName(&nb, gen);
        var w = try TableWriter.create(db.gpa, files, name);
        var in_bytes: u64 = 0;
        for (rs) |r| in_bytes += r.bytes();
        {
            errdefer w.abort();
            while (try m.next()) |e| try w.add(e.key, e.val);
        }
        _ = try w.finish();
        const run = try db.gpa.create(Run);
        errdefer db.gpa.destroy(run);
        const tabs = try db.gpa.alloc(*Table, 1);
        errdefer db.gpa.free(tabs);
        tabs[0] = try Table.open(db.gpa, files, name, gen);
        run.* = .{ .tables = tabs };
        const old = try db.gpa.dupe(*Run, rs);
        defer db.gpa.free(old);
        const lock = db.lock.?;
        lock.lock();
        db.runs.shrinkRetainingCapacity(from);
        db.runs.appendAssumeCapacity(run);
        lock.unlock();
        try db.writeManifest();
        for (old) |r| r.destroy(db.gpa, files, true);
        db.stats.compactions += 1;
        db.stats.compacted_bytes += in_bytes;
    }
};

// ---------------------------------------------------------------------------- bulk build

/// Key ranges of the bulk build: 32 owner ranges (kind x high nibble of the owner's first byte),
/// then one for the balance and coin tables. Ranges are in key order.
pub const n_ranges = 33;
pub fn rangeOf(key: []const u8) u32 {
    if (key[0] != 0) return 32;
    return @as(u32, key[1] & 1) * 16 + (key[2] >> 4);
}
fn rangeLo(r: u32, buf: *[3]u8) []const u8 {
    if (r == 32) {
        buf[0] = 1;
        return buf[0..1];
    }
    buf.* = .{ 0, @intCast(r / 16), @intCast((r % 16) << 4) };
    return buf[0..3];
}
fn groupOf(r: u32, groups: u32) u32 {
    return r * groups / n_ranges;
}

/// Emits the index rows of one live object: `f(ctx, key, val)`.
pub const Emit = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, key: []const u8, val: Val) anyerror!void,
};

/// Tests: `Builder.run` fails after finishing this group (a crash mid-build).
pub var test_fail_after_group: ?u32 = null;

/// Where a bulk build reads the live set from (lane fast-start): `walk` calls `sink` for every
/// live object of part `part` of `build_parts`; `at` is the checkpoint that live set is at (the
/// built index's watermark). `Builder.run` walks the snapshot's live table; a node over a restored
/// store walks the restore image in log order instead (`store.Snapshot.forEachImageObject`).
pub const Source = struct {
    ctx: *anyopaque,
    at: u64,
    walk: *const fn (ctx: *anyopaque, part: u32, parts: u32, sink: Sink) anyerror!void,
};

pub const Sink = struct {
    ctx: *anyopaque,
    f: *const fn (ctx: *anyopaque, id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void,
};

/// The snapshot's live set in store order (lane live-walk2): part p sorts the live locations in
/// its range of `bounds` (`Snapshot.liveBounds`, `build_parts + 1` entries) and reads that
/// stretch of the segments front to back (slot ranges are hash order: one random page fault per
/// object on a store above the page cache). Per thread, one part's locations at a time (about
/// 97 MB at 772.9M objects).
const LiveSource = struct {
    snap: *const store.Snapshot,
    gpa: Allocator,
    bounds: []const u64,
    fn walk(ctx: *anyopaque, part: u32, parts: u32, sink: Sink) anyerror!void {
        const ls: *const LiveSource = @ptrCast(@alignCast(ctx));
        std.debug.assert(ls.bounds.len == @as(usize, parts) + 1);
        const locs = try ls.snap.liveLocationsIn(ls.gpa, ls.bounds[part], ls.bounds[part + 1]);
        defer ls.gpa.free(locs);
        var wb: store.Store.WalkBuf = .{};
        defer wb.deinit(ls.gpa);
        for (locs) |l| {
            const item = (try ls.snap.liveAtWalk(l, &wb)) orelse continue;
            try sink.f(sink.ctx, &item.id, item.version, item.bytes);
        }
    }
};

pub const Builder = struct {
    db: *Db,
    src: Source,
    /// Turns a live object into rows (root.zig `rowsOf` with sign +1).
    rows: *const fn (arena: Allocator, raw: []const u8, sign: i2, emit: Emit) anyerror!void,
    threads: usize,
    progress: std.atomic.Value(u64) = .init(0),
    next_part: std.atomic.Value(u32) = .init(0),
    next_range: std.atomic.Value(u32) = .init(0),
    man_lock: SpinLock = .{},
    err: ?anyerror = null,
    temps: std.ArrayList(*Table) = .empty,
    base: [n_ranges]?*Table = @splat(null),

    pub const Report = struct {
        objects: u64,
        entries: u64,
        bytes: u64,
        ms: u64,
        resumed_parts: u32,
        /// Ranges a resumed partitioned build found finished.
        resumed_ranges: u32 = 0,
        /// The two stages: until every row is on disk (the partitioned build: rows appended to
        /// partition files; the sort-and-merge build: walks and sorted spills), then until the
        /// tables are written (partitions sorted; temp tables merged).
        rows_ms: u64 = 0,
        sort_ms: u64 = 0,
        /// Partitioned build: bytes of the partition files.
        temp_bytes: u64 = 0,
        /// Sorted chunks written for partitions larger than a worker's share of the budget.
        sort_chunks: u32 = 0,
    };

    /// Builds the base run from the snapshot's live set (resuming a build of the same tip) and
    /// installs it with the snapshot's checkpoint as the watermark. Index lock must be held
    /// exclusively by the caller, or no reader may exist yet.
    pub fn run(db: *Db, snap: *const store.Snapshot, rows: *const fn (Allocator, []const u8, i2, Emit) anyerror!void) !Report {
        const bounds = try snap.liveBounds(db.gpa, build_parts);
        defer db.gpa.free(bounds);
        var ls: LiveSource = .{ .snap = snap, .gpa = db.gpa, .bounds = bounds };
        return runFrom(db, .{ .ctx = &ls, .at = snap.highestCommitted() orelse 0, .walk = LiveSource.walk }, rows);
    }

    /// `run` over any live-set source; the watermark is `src.at`. The caller holds the index
    /// lock or no reader or other writer touches `db` until it returns (fast start: readers are
    /// held off by the index's `ready` flag, and the commit feed starts after the catch-up).
    pub fn runFrom(db: *Db, src: Source, rows: *const fn (Allocator, []const u8, i2, Emit) anyerror!void) !Report {
        if (db.opts.bulk) return bulk.Loader.runFrom(db, src, rows);
        return runFromMerge(db, src, rows);
    }

    /// The sort-and-merge build (`Options.bulk` false): per key-range group, every thread walks
    /// parts of the live set and spills sorted temp tables, then the group's ranges are merged
    /// from all of them. `build_groups` passes over the live set.
    pub fn runFromMerge(db: *Db, src: Source, rows: *const fn (Allocator, []const u8, i2, Emit) anyerror!void) !Report {
        const t0 = nowMs();
        const tip = src.at;
        var resumed: u32 = 0;
        // A pending build of the same tip resumes with its own group count (every row emit and
        // merge reads the manifest's), so a build streamed during a restore (`Stream`, one group)
        // or a changed ZUI_INDEX_BUILD_GROUPS does not throw finished work away.
        if (db.man.build) |b| {
            if (b.tip != tip) {
                try db.reset();
            } else resumed = @popCount(b.done);
        } else if (db.runs.items.len > 0 or db.man.watermark != null) try db.reset();
        if (db.man.build == null) {
            db.man.build = .{ .tip = tip, .groups = @max(db.opts.build_groups, 1) };
            try db.writeManifest();
        }
        raiseFdLimit();
        const cpus = std.Thread.getCpuCount() catch 4;
        var b: Builder = .{ .db = db, .src = src, .rows = rows, .threads = if (db.opts.build_threads != 0) db.opts.build_threads else @min(cpus, 32) };
        defer b.deinitTemps();
        // A resumed build: the base tables of finished groups are the partial run.
        if (db.runs.items.len > 0) {
            for (db.runs.items[0].tables) |t| {
                const r = if (t.nblocks() > 0) rangeOf(t.firstKey(0)) else continue;
                b.base[r] = t;
            }
        }
        const groups = db.man.build.?.groups;
        var sort_ms: u64 = 0;
        var merge_ms: u64 = 0;
        while (db.man.build.?.group < groups) {
            const g = db.man.build.?.group;
            std.log.info("state index: build group {d}/{d} (tip {d}, {d} parts done)", .{ g + 1, groups, tip, @popCount(db.man.build.?.done) });
            const ta = nowMs();
            try b.phaseSort(g);
            const tb = nowMs();
            try b.phaseMerge(g);
            sort_ms += tb - ta;
            merge_ms += nowMs() - tb;
            if (builtin.is_test) if (test_fail_after_group) |fg| if (fg == g) return error.TestCrash;
        }
        // install: the base run is the only run, the watermark is the tip
        const objs: u64 = b.progress.load(.monotonic);
        db.man.build = null;
        db.man.watermark = tip;
        try db.writeManifest();
        try db.gc();
        const entries: u64 = if (db.runs.items.len > 0) db.runs.items[0].entries() else 0;
        std.log.info("state index: sort-and-merge build: walks and sorted spills {d} s, merges {d} s ({d} groups, {d} threads)", .{ sort_ms / 1000, merge_ms / 1000, groups, b.threads });
        return .{ .objects = objs, .entries = entries, .bytes = db.diskBytes(), .ms = nowMs() - t0, .resumed_parts = resumed, .rows_ms = sort_ms, .sort_ms = merge_ms };
    }

    fn deinitTemps(b: *Builder) void {
        for (b.temps.items) |t| t.close(b.db.gpa, b.db.files.?);
        b.temps.deinit(b.db.gpa);
    }

    fn phaseSort(b: *Builder, g: u32) !void {
        b.next_part.store(0, .monotonic);
        b.err = null;
        const ts = try b.db.gpa.alloc(std.Thread, b.threads);
        defer b.db.gpa.free(ts);
        var n: usize = 0;
        for (ts) |*t| {
            t.* = std.Thread.spawn(.{ .stack_size = 16 << 20 }, sortWorker, .{ b, g }) catch break;
            n += 1;
        }
        if (n == 0) sortWorker(b, g);
        for (ts[0..n]) |t| t.join();
        if (b.err) |e| return e;
    }

    const Ent = struct { off: u64, len: u32, val: Val };

    const Buf = struct {
        gpa: Allocator,
        keys: std.ArrayList(u8) = .empty,
        ents: std.ArrayList(Ent) = .empty,
        group: u32,
        groups: u32,
        fn deinit(x: *Buf) void {
            x.keys.deinit(x.gpa);
            x.ents.deinit(x.gpa);
        }
        fn bytes(x: *const Buf) usize {
            return x.keys.items.len + x.ents.items.len * @sizeOf(Ent);
        }
        fn emit(ctx: *anyopaque, k: []const u8, val: Val) anyerror!void {
            const x: *Buf = @ptrCast(@alignCast(ctx));
            if (groupOf(rangeOf(k), x.groups) != x.group) return;
            try x.ents.append(x.gpa, .{ .off = x.keys.items.len, .len = @intCast(k.len), .val = val });
            try x.keys.appendSlice(x.gpa, k);
        }
        fn key(x: *const Buf, e: Ent) []const u8 {
            return x.keys.items[e.off..][0..e.len];
        }
    };

    fn sortWorker(b: *Builder, g: u32) void {
        b.sortWorkerInner(g) catch |e| {
            b.man_lock.lock();
            defer b.man_lock.unlock();
            if (b.err == null) b.err = e;
        };
    }

    fn sortWorkerInner(b: *Builder, g: u32) !void {
        const gpa = b.db.gpa;
        var buf: Buf = .{ .gpa = gpa, .group = g, .groups = b.db.man.build.?.groups };
        defer buf.deinit();
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const chunk = b.db.opts.build_chunk_bytes;
        while (b.err == null) {
            if (b.db.build_stop) |x| if (x.load(.acquire)) return error.Stopped;
            const p = b.next_part.fetchAdd(1, .monotonic);
            if (p >= build_parts) return;
            {
                b.man_lock.lock();
                defer b.man_lock.unlock();
                if (b.db.man.build.?.done & (@as(u64, 1) << @intCast(p)) != 0) continue;
            }
            const W = struct {
                b: *Builder,
                buf: *Buf,
                arena: *std.heap.ArenaAllocator,
                p: u32,
                k: u32 = 0,
                n: u64 = 0,
                chunk: usize,
                fn each(ctx: *anyopaque, _: *const [32]u8, _: u64, bytes: []const u8) anyerror!void {
                    const w: *@This() = @ptrCast(@alignCast(ctx));
                    _ = w.arena.reset(.retain_capacity);
                    try w.b.rows(w.arena.allocator(), bytes, 1, .{ .ctx = w.buf, .f = Buf.emit });
                    w.n += 1;
                    if (w.n % 65536 == 0) _ = w.b.progress.fetchAdd(65536, .monotonic);
                    if (w.buf.bytes() >= w.chunk) {
                        try w.b.spill(w.buf, w.p, w.k);
                        w.k += 1;
                    }
                }
            };
            var w: W = .{ .b = b, .buf = &buf, .arena = &arena, .p = p, .chunk = chunk };
            try b.src.walk(b.src.ctx, p, build_parts, .{ .ctx = &w, .f = W.each });
            var k = w.k;
            const n = w.n;
            _ = b.progress.fetchAdd(n % 65536, .monotonic);
            if (buf.ents.items.len > 0) {
                try b.spill(&buf, p, k);
                k += 1;
            }
            b.man_lock.lock();
            defer b.man_lock.unlock();
            const bs = &b.db.man.build.?;
            bs.done |= @as(u64, 1) << @intCast(p);
            bs.chunks[p] = k;
            try b.db.files.?.rio.syncDir();
            try b.db.writeManifest();
        }
    }

    fn spill(b: *Builder, buf: *Buf, p: u32, k: u32) !void {
        return spillTo(b.db, buf, p, k);
    }

    /// Sorts `buf` and writes it as temp table (part `p`, chunk `k`), equal keys combined.
    fn spillTo(db: *Db, buf: *Buf, p: u32, k: u32) !void {
        const Ctx = struct {
            x: *const Buf,
            fn lt(c: @This(), l: Ent, r: Ent) bool {
                return lessKey(c.x.key(l), c.x.key(r));
            }
        };
        std.mem.sort(Ent, buf.ents.items, Ctx{ .x = buf }, Ctx.lt);
        var nb: [64]u8 = undefined;
        var w = try TableWriter.createLevel(db.gpa, db.files.?, tempName(&nb, p, k), temp_level);
        errdefer w.abort();
        var i: usize = 0;
        const es = buf.ents.items;
        while (i < es.len) {
            var v = es[i].val;
            const key = buf.key(es[i]);
            var j = i + 1;
            while (j < es.len and std.mem.eql(u8, buf.key(es[j]), key)) : (j += 1) v = combine(es[j].val, v);
            if (!(v.op == .delta and v.empty())) try w.add(key, v);
            i = j;
        }
        _ = try w.finish();
        buf.ents.clearRetainingCapacity();
        buf.keys.clearRetainingCapacity();
    }

    fn phaseMerge(b: *Builder, g: u32) !void {
        const db = b.db;
        const files = db.files.?;
        const bs = db.man.build.?;
        // open the group's temp tables
        b.deinitTemps();
        b.temps = .empty;
        for (0..build_parts) |p| for (0..bs.chunks[p]) |k| {
            var nb: [64]u8 = undefined;
            const t = try Table.open(db.gpa, files, tempName(&nb, p, k), 0);
            b.temps.append(db.gpa, t) catch |e| {
                t.close(db.gpa, files);
                return e;
            };
        };
        // reserve one table number per range of the group
        var first: ?u32 = null;
        var last: u32 = 0;
        for (0..n_ranges) |r| if (groupOf(@intCast(r), bs.groups) == g) {
            if (first == null) first = @intCast(r);
            last = @intCast(r);
        };
        const gen0 = db.man.next_gen;
        db.man.next_gen += n_ranges;
        if (first) |f0| {
            b.next_range.store(f0, .monotonic);
            b.err = null;
            const ts = try db.gpa.alloc(std.Thread, b.threads);
            defer db.gpa.free(ts);
            var n: usize = 0;
            for (ts) |*t| {
                t.* = std.Thread.spawn(.{ .stack_size = 16 << 20 }, mergeWorker, .{ b, last, gen0 }) catch break;
                n += 1;
            }
            if (n == 0) mergeWorker(b, last, gen0);
            for (ts[0..n]) |t| t.join();
            if (b.err) |e| return e;
        }
        // record the group: base run = every finished range's table, in range order
        var tabs: std.ArrayList(*Table) = .empty;
        defer tabs.deinit(db.gpa);
        for (b.base) |t| if (t) |x| try tabs.append(db.gpa, x);
        const owned = try db.gpa.dupe(*Table, tabs.items);
        if (owned.len == 0) {
            db.gpa.free(owned);
        } else if (db.runs.items.len == 0) {
            const r = try db.gpa.create(Run);
            r.* = .{ .tables = owned };
            try db.runs.append(db.gpa, r);
        } else {
            db.gpa.free(db.runs.items[0].tables);
            db.runs.items[0].tables = owned;
        }
        var nbs = db.man.build.?;
        nbs.group += 1;
        nbs.done = 0;
        nbs.chunks = @splat(0);
        db.man.build = nbs;
        try files.rio.syncDir();
        try db.writeManifest();
        b.deinitTemps();
        b.temps = .empty;
        try db.gc();
    }

    fn mergeWorker(b: *Builder, last: u32, gen0: u64) void {
        while (b.err == null) {
            const r = b.next_range.fetchAdd(1, .monotonic);
            if (r > last) return;
            b.mergeRange(r, gen0 + r) catch |e| {
                b.man_lock.lock();
                defer b.man_lock.unlock();
                if (b.err == null) b.err = e;
                return;
            };
        }
    }

    fn mergeRange(b: *Builder, r: u32, gen: u64) !void {
        const db = b.db;
        const files = db.files.?;
        var arena = std.heap.ArenaAllocator.init(db.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const n = b.temps.items.len;
        const srcs = try a.alloc(Src, n);
        const runs = try a.alloc(Run, n);
        const one = try a.alloc([1]*Table, n);
        for (b.temps.items, 0..) |t, i| {
            one[i] = .{t};
            runs[i] = .{ .tables = &one[i] };
            srcs[i] = .{ .kind = .{ .run = RunIter.init(a, files, &runs[i]) } };
        }
        var m: MergeIter = .{ .a = a, .srcs = srcs, .heap = try a.alloc(u32, n) };
        var lo_buf: [3]u8 = undefined;
        try m.seek(rangeLo(r, &lo_buf));
        var nb: [64]u8 = undefined;
        const name = tableName(&nb, gen);
        var w = try TableWriter.create(db.gpa, files, name);
        {
            errdefer w.abort();
            var k: u64 = 0;
            while (try m.next()) |e| {
                if (rangeOf(e.key) != r) break;
                try w.add(e.key, e.val);
                k += 1;
                if (k % 65536 == 0) if (db.build_stop) |x| if (x.load(.acquire)) return error.Stopped;
            }
        }
        const entries = w.entries;
        _ = try w.finish();
        if (entries == 0) {
            files.remove(name);
            return;
        }
        const t = try Table.open(db.gpa, files, name, gen);
        b.man_lock.lock();
        defer b.man_lock.unlock();
        b.base[r] = t;
    }
};

/// A bulk build fed by producer threads instead of a walk (lane index-fast): a snapshot restore
/// hands every verified partition's objects to `put` on its fetch threads, so the rows are
/// emitted, sorted and spilled as temp tables while the objects download, not in a second pass
/// over the restored segment afterwards. One lane per producer (`lane % build_parts`; a lane's
/// buffer is locked per object, so any thread may use any lane, but one thread per lane is the
/// fast path). Every lane is a build part of a one-group build: `finish(tip)` spills what is
/// left, records every part done with its chunk count, and runs the builder's merge phase
/// (`Builder.runFrom` resumes a build whose parts are all done: it merges and installs the base
/// run with watermark `tip`). Temp space is every row once (one group); memory is one sort
/// buffer per lane in use. A crash before `finish` leaves a pending build with an impossible tip,
/// which the next build (or `begin`) resets.
pub const Stream = struct {
    db: *Db,
    rows: *const fn (Allocator, []const u8, i2, Emit) anyerror!void,
    chunk: usize,
    lanes: []Lane,
    objects: std.atomic.Value(u64) = .init(0),
    /// Temp tables written so far (progress; the partitioned build counts its frames).
    spills: std.atomic.Value(u64) = .init(0),
    /// The partitioned build behind this stream (`Options.bulk`): `lanes` is then empty.
    loader: ?*bulk.Loader = null,

    pub const Lane = struct {
        lock: SpinLock = .{},
        buf: Builder.Buf,
        arena: std.heap.ArenaAllocator,
        k: u32 = 0,
        bad: ?anyerror = null,
    };

    /// Drops whatever the index holds and starts an empty one-group build. `chunk` is each lane's
    /// sort buffer (0: the db's build_chunk_bytes).
    pub fn begin(db: *Db, rows: *const fn (Allocator, []const u8, i2, Emit) anyerror!void, chunk: usize) !*Stream {
        if (db.opts.bulk) {
            const s = try db.gpa.create(Stream);
            errdefer db.gpa.destroy(s);
            const l = try bulk.Loader.begin(db, rows, chunk);
            s.* = .{ .db = db, .rows = rows, .chunk = l.staging, .lanes = &.{}, .loader = l };
            return s;
        }
        try db.reset();
        db.man.build = .{ .tip = pending_tip, .groups = 1 };
        try db.writeManifest();
        raiseFdLimit();
        const s = try db.gpa.create(Stream);
        errdefer db.gpa.destroy(s);
        const lanes = try db.gpa.alloc(Lane, build_parts);
        for (lanes) |*l| l.* = .{ .buf = .{ .gpa = db.gpa, .group = 0, .groups = 1 }, .arena = .init(db.gpa) };
        s.* = .{ .db = db, .rows = rows, .chunk = if (chunk != 0) chunk else db.opts.build_chunk_bytes, .lanes = lanes };
        return s;
    }

    /// Frees the lanes (temp tables of an unfinished stream stay until the next build's reset).
    pub fn destroy(s: *Stream) void {
        const gpa = s.db.gpa;
        if (s.loader) |l| {
            l.destroy();
            gpa.destroy(s);
            return;
        }
        for (s.lanes) |*l| {
            l.buf.deinit();
            l.arena.deinit();
        }
        gpa.free(s.lanes);
        gpa.destroy(s);
    }

    /// The rows of one live object (BCS Object) into lane `lane`; spills the lane when its buffer
    /// is full.
    pub fn put(s: *Stream, lane: usize, raw: []const u8) !void {
        if (s.loader) |ld| {
            try ld.put(lane, raw);
            _ = s.objects.fetchAdd(1, .monotonic);
            s.spills.store(ld.frames.load(.monotonic), .monotonic);
            return;
        }
        const l = &s.lanes[lane % build_parts];
        l.lock.lock();
        defer l.lock.unlock();
        if (l.bad) |e| return e;
        s.putLocked(l, lane % build_parts, raw) catch |e| {
            l.bad = e;
            return e;
        };
    }

    fn putLocked(s: *Stream, l: *Lane, p: usize, raw: []const u8) !void {
        _ = l.arena.reset(.retain_capacity);
        try s.rows(l.arena.allocator(), raw, 1, .{ .ctx = &l.buf, .f = Builder.Buf.emit });
        _ = s.objects.fetchAdd(1, .monotonic);
        if (l.buf.bytes() >= s.chunk) {
            try Builder.spillTo(s.db, &l.buf, @intCast(p), l.k);
            l.k += 1;
            _ = s.spills.fetchAdd(1, .monotonic);
        }
    }

    /// No producer may call `put` any more: spills the lanes (on `threads` threads), records
    /// every part done and merges the temp tables into the base run, watermark `tip`. Index lock
    /// held, or no reader yet.
    pub fn finish(s: *Stream, tip: u64, stop: ?*const std.atomic.Value(bool)) !Builder.Report {
        const db = s.db;
        const t0 = nowMs();
        if (s.loader) |ld| {
            const saved = db.build_stop;
            if (stop) |x| db.build_stop = x;
            defer db.build_stop = saved;
            var rep = try ld.finish(tip);
            s.spills.store(ld.frames.load(.monotonic), .monotonic);
            rep.objects = s.objects.load(.monotonic);
            rep.ms = nowMs() - t0;
            return rep;
        }
        // spill the lanes in parallel (each a sort of up to `chunk` bytes)
        const Spill = struct {
            s: *Stream,
            next: std.atomic.Value(usize) = .init(0),
            err: ?anyerror = null,
            fn work(x: *@This()) void {
                while (true) {
                    const i = x.next.fetchAdd(1, .monotonic);
                    if (i >= x.s.lanes.len) return;
                    const l = &x.s.lanes[i];
                    if (l.bad) |e| {
                        x.err = e;
                        return;
                    }
                    if (l.buf.ents.items.len == 0) continue;
                    Builder.spillTo(x.s.db, &l.buf, @intCast(i), l.k) catch |e| {
                        x.err = e;
                        return;
                    };
                    l.k += 1;
                }
            }
        };
        var sp: Spill = .{ .s = s };
        var ts: [16]?std.Thread = @splat(null);
        for (&ts) |*t| t.* = std.Thread.spawn(.{ .stack_size = 16 << 20 }, Spill.work, .{&sp}) catch null;
        Spill.work(&sp);
        for (ts) |t| if (t) |x| x.join();
        if (sp.err) |e| return e;
        var bs: BuildState = .{ .tip = tip, .groups = 1, .done = std.math.maxInt(u64) };
        for (s.lanes, 0..) |*l, i| bs.chunks[i] = l.k;
        db.man.build = bs;
        try db.files.?.rio.syncDir();
        try db.writeManifest();
        const saved = db.build_stop;
        if (stop) |x| db.build_stop = x;
        defer db.build_stop = saved;
        var rep = try Builder.runFromMerge(db, .{ .ctx = s, .at = tip, .walk = noWalk }, s.rows);
        rep.objects = s.objects.load(.monotonic);
        rep.ms = nowMs() - t0;
        return rep;
    }

    fn noWalk(_: *anyopaque, _: u32, _: u32, _: Sink) anyerror!void {
        return error.StreamPartMissing; // every part is done before runFrom runs
    }
};

/// A pending build with this tip has no live-set checkpoint yet (a stream before `finish`) or is
/// a partitioned build, whose own state file holds the tip (bulk.zig). The sort-and-merge build
/// never matches it, so it resets such a build.
pub const pending_tip = std.math.maxInt(u64);

/// Merges whole temp tables (equal keys: deltas add up, index 0 wins otherwise; deletes and zero
/// sums are dropped) into `w` in key order. `stop` is checked every 64k rows.
pub fn mergeTablesInto(gpa: Allocator, files: *Files, tables: []const *Table, w: *TableWriter, stop: ?*const std.atomic.Value(bool)) !void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const n = tables.len;
    const srcs = try a.alloc(Src, n);
    const runs = try a.alloc(Run, n);
    const one = try a.alloc([1]*Table, n);
    for (tables, 0..) |t, i| {
        one[i] = .{t};
        runs[i] = .{ .tables = &one[i] };
        srcs[i] = .{ .kind = .{ .run = RunIter.init(a, files, &runs[i]) } };
    }
    var m: MergeIter = .{ .a = a, .srcs = srcs, .heap = try a.alloc(u32, n) };
    try m.seek("");
    var k: u64 = 0;
    while (try m.next()) |e| {
        try w.add(e.key, e.val);
        k += 1;
        if (k % 65536 == 0) if (stop) |x| if (x.load(.acquire)) return error.Stopped;
    }
}

pub fn raiseFdLimit() void {
    if (builtin.os.tag != .linux and !builtin.os.tag.isDarwin()) return;
    var lim = std.posix.getrlimit(.NOFILE) catch return;
    const want: @TypeOf(lim.cur) = if (builtin.os.tag.isDarwin()) @min(lim.max, 10240) else lim.max;
    if (lim.cur >= want) return;
    lim.cur = want;
    std.posix.setrlimit(.NOFILE, lim) catch {};
}

pub fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

// ---------------------------------------------------------------------------- format tests

const TestFiles = struct {
    rio: *store.RealIo,
    files: *Files,
    path: []const u8,

    fn init(gpa: Allocator, tmp: *std.testing.TmpDir) !TestFiles {
        const path = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ix", .{tmp.sub_path});
        errdefer gpa.free(path);
        const rio = try store.RealIo.init(gpa, std.testing.io, path, .{ .sync = .none, .uring = false });
        const files = try gpa.create(Files);
        files.* = .{ .rio = rio };
        return .{ .rio = rio, .files = files, .path = path };
    }
    fn deinit(t: *TestFiles, gpa: Allocator) void {
        t.rio.deinit();
        gpa.destroy(t.files);
        gpa.free(t.path);
    }
};

/// Test rows: owner-index-like keys (shared prefixes, a random id tail) and small values.
fn testRows(gpa: Allocator, n: usize) !struct { keys: [][]u8, vals: []Val } {
    var prng = std.Random.DefaultPrng.init(42);
    const r = prng.random();
    const keys = try gpa.alloc([]u8, n);
    const vals = try gpa.alloc(Val, n);
    for (keys, vals, 0..) |*k, *v, i| {
        k.* = try gpa.alloc(u8, 1 + 1 + 32 + 20 + 32);
        @memset(k.*, 0);
        k.*[1] = @intCast(i * 4 / n);
        r.bytes(k.*[2..10]); // owner, partly random
        @memcpy(k.*[34..54], "0x2::coin::Coin<SUI>");
        std.mem.writeInt(u64, k.*[54..62], @intCast(i), .big); // sorted by construction
        r.bytes(k.*[62..]);
        var ver: [8]u8 = undefined;
        std.mem.writeInt(u64, &ver, r.uintLessThan(u64, 1 << 20), .little);
        v.* = if (i % 7 == 0) Val.delta(@intCast(i), -1) else Val.put(&ver);
    }
    // Sort (the owner bytes are random): the writer needs increasing keys.
    const Ctx = struct {
        fn lt(_: void, x: []u8, y: []u8) bool {
            return lessKey(x, y);
        }
    };
    std.mem.sort([]u8, keys, {}, Ctx.lt);
    return .{ .keys = keys, .vals = vals };
}

fn freeRows(gpa: Allocator, keys: [][]u8, vals: []Val) void {
    for (keys) |k| gpa.free(k);
    gpa.free(keys);
    gpa.free(vals);
}

/// Writes `keys`/`vals` as a format-1 table (the pre-disk-fit layout), for the compatibility test.
fn writeFormat1(gpa: Allocator, files: *Files, name: []const u8, keys: []const []const u8, vals: []const Val) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var blk: std.ArrayList(u8) = .empty;
    defer blk.deinit(gpa);
    var offs: std.ArrayList(u64) = .empty;
    defer offs.deinit(gpa);
    var koffs: std.ArrayList(u32) = .empty;
    defer koffs.deinit(gpa);
    var firsts: std.ArrayList(u8) = .empty;
    defer firsts.deinit(gpa);
    var last: []const u8 = &.{};
    for (keys, vals) |k, v| {
        if (blk.items.len >= 16 << 10) {
            const sum = store.checksum.hash(sum_seed, blk.items);
            try out.appendSlice(gpa, blk.items);
            try out.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u64, sum)));
            blk.clearRetainingCapacity();
        }
        var shared: usize = 0;
        if (blk.items.len == 0) {
            try offs.append(gpa, out.items.len);
            try koffs.append(gpa, @intCast(firsts.items.len));
            try firsts.appendSlice(gpa, k);
        } else {
            const m = @min(k.len, last.len);
            while (shared < m and k[shared] == last[shared]) shared += 1;
        }
        try putUleb(&blk, gpa, shared);
        try putUleb(&blk, gpa, k.len - shared);
        try blk.append(gpa, @intFromEnum(v.op));
        try blk.append(gpa, v.len);
        try blk.appendSlice(gpa, k[shared..]);
        try blk.appendSlice(gpa, v.bytes());
        last = k;
    }
    if (blk.items.len > 0) {
        const sum = store.checksum.hash(sum_seed, blk.items);
        try out.appendSlice(gpa, blk.items);
        try out.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u64, sum)));
    }
    const nb = offs.items.len;
    try offs.append(gpa, out.items.len);
    try koffs.append(gpa, @intCast(firsts.items.len));
    const index_off = out.items.len;
    for (offs.items) |o| try out.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u64, o)));
    for (koffs.items) |o| try out.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u32, o)));
    try out.appendSlice(gpa, firsts.items);
    const index_len = out.items.len - index_off;
    const isum = store.checksum.hash(sum_seed, out.items[index_off..]);
    for ([_]u64{ magic, index_off, nb, keys.len, index_len, isum }) |x| try out.appendSlice(gpa, std.mem.asBytes(&std.mem.nativeToLittle(u64, x)));
    const fd = try files.open(name, true);
    defer files.close(fd);
    try files.rio.write(fd, 0, out.items);
}

/// Checks a full scan and point seeks of table `name` against `keys`/`vals`.
fn expectTable(gpa: Allocator, files: *Files, name: []const u8, keys: []const []const u8, vals: []const Val, want_format: u8) !void {
    const t = try Table.open(gpa, files, name, 1);
    defer t.close(gpa, files);
    try std.testing.expectEqual(want_format, t.format);
    try std.testing.expectEqual(@as(u64, keys.len), t.entries);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var it: TableIter = .{ .t = t, .files = files, .a = arena.allocator() };
    try it.seek("");
    for (keys, vals) |k, v| {
        try std.testing.expect(it.valid);
        try std.testing.expectEqualSlices(u8, k, it.key.items);
        try std.testing.expectEqual(v.op, it.val.op);
        try std.testing.expectEqualSlices(u8, v.bytes(), it.val.bytes());
        try it.next();
    }
    try std.testing.expect(!it.valid);
    var i: usize = 0;
    while (i < keys.len) : (i += 997) {
        var s: TableIter = .{ .t = t, .files = files, .a = arena.allocator() };
        try s.seek(keys[i]);
        try std.testing.expect(s.valid);
        try std.testing.expectEqualSlices(u8, keys[i], s.key.items);
        try std.testing.expectEqualSlices(u8, vals[i].bytes(), s.val.bytes());
    }
}

test "lsm format 2: zstd blocks round trip (scan and seeks), are smaller, and format-1 tables still read" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var tf = try TestFiles.init(gpa, &tmp);
    defer tf.deinit(gpa);
    const rows = try testRows(gpa, 20_000);
    defer freeRows(gpa, rows.keys, rows.vals);

    var w = try TableWriter.create(gpa, tf.files, "index/2.tbl");
    for (rows.keys, rows.vals) |k, v| try w.add(k, v);
    const raw = w.raw_bytes;
    const size = try w.finish();
    try expectTable(gpa, tf.files, "index/2.tbl", rows.keys, rows.vals, 2);

    try writeFormat1(gpa, tf.files, "index/1.tbl", rows.keys, rows.vals);
    try expectTable(gpa, tf.files, "index/1.tbl", rows.keys, rows.vals, 1);
    const fd = try tf.files.open("index/1.tbl", false);
    const size1 = try tf.rio.size(fd);
    tf.files.close(fd);
    // The random id tails (32 of ~100 bytes a row) bound the ratio; the shared parts compress.
    try std.testing.expect(size < size1);
    try std.testing.expect(raw > size);

    // A temp-level (fast) table reads the same.
    var wt = try TableWriter.createLevel(gpa, tf.files, "index/3.tbl", temp_level);
    for (rows.keys, rows.vals) |k, v| try wt.add(k, v);
    _ = try wt.finish();
    try expectTable(gpa, tf.files, "index/3.tbl", rows.keys, rows.vals, 2);
}

test "lsm format 2: a damaged compressed block reads as Corrupt, never as other rows" {
    const gpa = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var tf = try TestFiles.init(gpa, &tmp);
    defer tf.deinit(gpa);
    const rows = try testRows(gpa, 5_000);
    defer freeRows(gpa, rows.keys, rows.vals);
    var w = try TableWriter.create(gpa, tf.files, "index/7.tbl");
    for (rows.keys, rows.vals) |k, v| try w.add(k, v);
    _ = try w.finish();
    const t = try Table.open(gpa, tf.files, "index/7.tbl", 7);
    const blk_off = t.offs[0];
    const blk_len = t.offs[1] - t.offs[0];
    t.close(gpa, tf.files);
    const fd = try tf.files.open("index/7.tbl", false);
    var buf: [1]u8 = undefined;
    // First the codec byte, then a byte inside the zstd frame: both must be caught.
    for ([_]u64{ 0, 9, blk_len / 2 }) |at| {
        try tf.rio.read(fd, blk_off + at, &buf);
        try std.testing.expect(at != 0 or buf[0] == codec_zstd);
        buf[0] ^= 0x41;
        try tf.rio.write(fd, blk_off + at, &buf);
        const t2 = try Table.open(gpa, tf.files, "index/7.tbl", 7);
        defer t2.close(gpa, tf.files);
        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        var it: TableIter = .{ .t = t2, .files = tf.files, .a = arena.allocator() };
        try std.testing.expectError(error.Corrupt, it.seek(""));
        buf[0] ^= 0x41;
        try tf.rio.write(fd, blk_off + at, &buf);
    }
    tf.files.close(fd);
    try expectTable(gpa, tf.files, "index/7.tbl", rows.keys, rows.vals, 2);
}

// Block-size and level study over real tables: `ZUI_LSM_STUDY_DIR=<dir with *.tbl copies>`
// (never the live index). Rewrites each table at 16/32/64 KiB x levels -1/1/3 into the test's
// temp dir and prints the bytes. Skipped without the variable.
test "lsm format 2: study over real tables (ZUI_LSM_STUDY_DIR)" {
    const dir_z = std.c.getenv("ZUI_LSM_STUDY_DIR") orelse return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const src_dir = std.mem.span(dir_z);
    const src_rio = try store.RealIo.init(gpa, std.testing.io, src_dir, .{ .sync = .none, .uring = false });
    defer src_rio.deinit();
    var src_files: Files = .{ .rio = src_rio };
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var tf = try TestFiles.init(gpa, &tmp);
    defer tf.deinit(gpa);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var d = try std.Io.Dir.cwd().openDir(std.testing.io, src_dir, .{ .iterate = true });
    defer d.close(std.testing.io);
    var di = d.iterate();
    var tot_old: u64 = 0;
    var tot_new: [9]u64 = @splat(0);
    while (try di.next(std.testing.io)) |ent| {
        if (!std.mem.endsWith(u8, ent.name, ".tbl")) continue;
        const name = try std.fmt.allocPrint(a, "{s}", .{ent.name});
        const t = Table.open(gpa, &src_files, name, 0) catch continue;
        defer t.close(gpa, &src_files);
        tot_old += t.size;
        var keys: std.ArrayList([]const u8) = .empty;
        var vals: std.ArrayList(Val) = .empty;
        var it: TableIter = .{ .t = t, .files = &src_files, .a = a };
        try it.seek("");
        while (it.valid) : (try it.next()) {
            try keys.append(a, try a.dupe(u8, it.key.items));
            try vals.append(a, it.val);
        }
        for ([_]usize{ 16, 32, 64 }, 0..) |kib, si| for ([_]i32{ -1, 1, 3 }, 0..) |lv, li| {
            var w = try TableWriter.createLevel(gpa, tf.files, "index/s.tbl", lv);
            w.target = kib << 10;
            for (keys.items, vals.items) |k, v| try w.add(k, v);
            const n = try w.finish();
            tot_new[si * 3 + li] += n;
            std.debug.print("{s} format {d} {d} bytes, {d} entries -> {d} KiB level {d}: {d} bytes ({d:.3}x)\n", .{ name, t.format, t.size, t.entries, kib, lv, n, @as(f64, @floatFromInt(t.size)) / @as(f64, @floatFromInt(n)) });
        };
    }
    for ([_]usize{ 16, 32, 64 }, 0..) |kib, si| for ([_]i32{ -1, 1, 3 }, 0..) |lv, li| {
        const n = tot_new[si * 3 + li];
        std.debug.print("total {d} -> {d} KiB level {d}: {d} ({d:.3}x)\n", .{ tot_old, kib, lv, n, @as(f64, @floatFromInt(tot_old)) / @as(f64, @floatFromInt(@max(n, 1))) });
    };
}

