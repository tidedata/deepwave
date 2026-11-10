//! history: the ledger-history index behind ListCheckpoints, ListTransactions and ListEvents
//! (sui-node 1.83.1 `rpc.enable-indexing` ledger history, docs/DROP-IN.md G7). Owner lane: ledger.
//!
//! - Per checkpoint: its first tx_seq (`network_total_transactions` of the previous checkpoint).
//! - Per transaction (tx_seq): digest, event count; checkpoint and offset are derived.
//! - Bitmaps exactly as sui-rpc-store's `transaction_bitmap` / `event_bitmap` column families:
//!   dimension key `[tag][value]` (sui-inverted-index), tx-space buckets of 65,536 tx_seq and
//!   event-space buckets of 2^28 packed `(tx_seq << 16) | event_index`, bits as sorted u32 lists.
//!
//! On disk, off the heap (lane history-index-disk). The heap holds one segment, never the
//! retention window, so memory does not grow with retention and an open does not replay history:
//! - A segment is 65,536 tx_seq: one tx bucket and 16 event buckets, plus the transactions'
//!   digests and event counts (seg.zig). The open (newest) segment is in memory: per space a
//!   map key bytes -> sorted positions. When the index moves past it, it is frozen, written as
//!   `s<seg>.seg` (tmp, fsync, rename) and mapped read-only: the page cache holds it, readers get
//!   slices into the mapping exactly as they got slices into the heap before.
//! - Checkpoint -> first tx_seq: `c<chunk>.cp`, 65,536 u64 per file, mapped shared and written in
//!   place.
//! - Write-ahead log: one CRC'd record per checkpoint (the checkpoint's keys inline), fsync'd
//!   before the in-memory apply, in `log-<n>.bin`. At every segment boundary the index rotates:
//!   the sealed segment and the checkpoint chunks are synced, the open segment (small right after
//!   the boundary) goes to `open-<n+1>.bin`, the next records to `log-<n+1>.bin`, and `meta`
//!   (two-phase: tmp, fsync, rename) names them. An open maps the sealed segments, loads the open
//!   file and replays at most one segment of log: bounded, whatever the retention.
//! - Prune (`pruneBelow`) raises the floors in `meta`, then unlinks whole segments and chunks
//!   below them. No rewrite, no key remap.
//! - Each data generation lives in its own directory `g<gen>/` named by `CURRENT`: a reset (a hole)
//!   or an `adopt` (backfill) builds the new generation beside the old one and switches `CURRENT`.
//! - Crash consistency: every file is either written whole before `meta`/`CURRENT` names it, or
//!   rebuilt from the log on the next open (a segment past `meta`'s rotation point is rewritten
//!   by the replay). The log record of checkpoint `seq` is fsync'd before the store commits
//!   `seq`, so the index never ends behind the store's watermark.
//! - One writer (the node's commit path), any number of readers: `std.Io.RwLock`. The writer
//!   takes the exclusive lock only around in-memory changes, never around file I/O. Readers see
//!   checkpoints up to `publish`; bucket bits may run ahead of it, callers clamp to `range()`.
//! - Legacy `snapshot.bin` / `log.bin` (the in-memory index) are deleted on open; the node's
//!   backfill rebuilds the window from the store (lhfill.zig).
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const bcs = @import("bcs");
const types = @import("types");
pub const dims = @import("dims.zig");
pub const conformance = @import("conformance.zig");
pub const seg = @import("seg.zig");

pub const tx_bucket_size: u64 = 65_536;
pub const event_bucket_size: u64 = 1 << 28;
pub const event_bits: u6 = 16;
pub const Dim = dims.Dim;

const seg_txs = seg.seg_txs;
const cp_chunk: u64 = 65_536;
const chunk_bytes: usize = cp_chunk * 8;
const page = std.heap.page_size_min;

comptime {
    std.debug.assert(seg_txs == tx_bucket_size);
    std.debug.assert(seg_txs << event_bits == event_bucket_size * seg.ev_per_seg);
    std.debug.assert(builtin.cpu.arch.endian() == .little);
}

pub fn encodeEventSeq(tx_seq: u64, event_idx: u32) u64 {
    return (tx_seq << event_bits) | event_idx;
}

pub const Space = enum(u1) { tx = 0, event = 1 };

pub const TxRow = struct { tx_seq: u64, digest: [32]u8, checkpoint: u64, tx_offset: u32, event_count: u32 };
pub const Bucket = struct { id: u64, bits: []const u32 };
pub const CheckpointTxs = struct { first: u64, count: u64 };
pub const Range = struct { lo: u64, hi: u64 };

/// What the write-ahead log does (the live index: `sync`; a backfill staging index: `none`,
/// durable at segment rotations only, so a restart resumes from the last rotation).
pub const LogMode = enum { sync, nosync, none };
pub const Options = struct { log: LogMode = .sync };

/// Tests: crash injection. Every persistence step counts down; at zero it fails with
/// `error.Crash` (a torn log record writes a prefix first) and the test abandons the index.
pub const Fault = struct {
    left: u64,
    rng: std.Random.DefaultPrng,
    fn hit(f: *Fault) bool {
        if (f.left == 0) return true;
        f.left -= 1;
        return f.left == 0;
    }
};

// ---------------------------------------------------------------------- open segment (heap)

const List = std.ArrayList(u32);
const KeyMap = std.StringHashMapUnmanaged(List);

fn addSorted(gpa: Allocator, l: *List, v: u32) !void {
    const items = l.items;
    if (items.len == 0 or items[items.len - 1] < v) return l.append(gpa, v);
    // Out of order within the bucket (rare): sorted insert, no duplicates.
    const at = std.sort.lowerBound(u32, items, v, struct {
        fn cmp(x: u32, y: u32) std.math.Order {
            return std.math.order(x, y);
        }
    }.cmp);
    if (at < items.len and items[at] == v) return;
    try l.insert(gpa, at, v);
}

/// The newest segment, in memory: transaction records, digest map, and per space key -> sorted
/// positions (tx: offset in the segment; event: `(tx_off << 16) | event_index`).
const OpenSeg = struct {
    id: u64,
    start: u32 = 0,
    recs: std.ArrayList(u8) = .empty,
    dg: std.AutoHashMapUnmanaged(u64, u32) = .empty,
    maps: [2]KeyMap = .{ .empty, .empty },
    kb: std.heap.ArenaAllocator,

    fn create(gpa: Allocator, id: u64) !*OpenSeg {
        const o = try gpa.create(OpenSeg);
        o.* = .{ .id = id, .kb = std.heap.ArenaAllocator.init(gpa) };
        return o;
    }
    fn destroy(o: *OpenSeg, gpa: Allocator) void {
        o.recs.deinit(gpa);
        o.dg.deinit(gpa);
        for (&o.maps) |*m| {
            var it = m.valueIterator();
            while (it.next()) |l| l.deinit(gpa);
            m.deinit(gpa);
        }
        o.kb.deinit();
        gpa.destroy(o);
    }
    fn ntx(o: *const OpenSeg) u32 {
        return @intCast(o.recs.items.len / seg.rec_len);
    }
    fn has(o: *const OpenSeg, off: u32) bool {
        return o.ntx() > 0 and off >= o.start and off - o.start < o.ntx();
    }
    fn digest(o: *const OpenSeg, off: u32) *const [32]u8 {
        return o.recs.items[(off - o.start) * seg.rec_len ..][0..32];
    }
    fn evCount(o: *const OpenSeg, off: u32) u32 {
        return std.mem.readInt(u32, o.recs.items[(off - o.start) * seg.rec_len + 32 ..][0..4], .little);
    }
    fn addRec(o: *OpenSeg, gpa: Allocator, off: u32, d: *const [32]u8, evc: u32) !void {
        if (o.ntx() == 0) o.start = off else if (off != o.start + o.ntx()) return error.Gap;
        try o.recs.ensureUnusedCapacity(gpa, seg.rec_len);
        try o.dg.ensureUnusedCapacity(gpa, 1);
        o.recs.appendSliceAssumeCapacity(d);
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, evc, .little);
        o.recs.appendSliceAssumeCapacity(&b);
        o.dg.putAssumeCapacity(std.mem.readInt(u64, d[0..8], .little), off);
    }
    fn addBit(o: *OpenSeg, gpa: Allocator, si: usize, key: []const u8, v: u32) !void {
        const gop = try o.maps[si].getOrPut(gpa, key);
        if (!gop.found_existing) {
            gop.key_ptr.* = o.kb.allocator().dupe(u8, key) catch |e| {
                o.maps[si].removeByPtr(gop.key_ptr);
                return e;
            };
            gop.value_ptr.* = .empty;
        }
        try addSorted(gpa, gop.value_ptr, v);
    }
    fn findDigest(o: *const OpenSeg, d: *const [32]u8) ?u32 {
        const off = o.dg.get(std.mem.readInt(u64, d[0..8], .little)) orelse return null;
        if (!o.has(off) or !std.mem.eql(u8, o.digest(off), d)) return null;
        return off;
    }
    fn keyLists(o: *const OpenSeg, gpa: Allocator, si: usize) ![]seg.KeyList {
        const out = try gpa.alloc(seg.KeyList, o.maps[si].count());
        var it = o.maps[si].iterator();
        var i: usize = 0;
        while (it.next()) |kv| : (i += 1) out[i] = .{ .key = kv.key_ptr.*, .list = kv.value_ptr.items };
        return out;
    }
    fn memBytes(o: *const OpenSeg) u64 {
        var n: u64 = o.recs.capacity + o.dg.capacity() * 16 + o.kb.queryCapacity();
        for (&o.maps) |*m| {
            n += m.capacity() * (@sizeOf([]const u8) + @sizeOf(List) + 1);
            var it = m.valueIterator();
            while (it.next()) |l| n += l.capacity * 4;
        }
        return n;
    }
};

// ---------------------------------------------------------------------- sealed segments, chunks

const Sealed = struct {
    v: seg.View,
    mem: []align(page) u8,
    mapped: bool,

    fn release(s: *Sealed) void {
        if (s.mapped) std.posix.munmap(s.mem) else seg.freeBlob(s.mem);
    }
};

const Chunk = struct {
    id: u64,
    mem: []align(page) u8,
    mapped: bool,

    fn release(c: *Chunk) void {
        if (c.mapped) std.posix.munmap(c.mem) else std.heap.page_allocator.free(c.mem);
    }
    fn get(c: *const Chunk, cp: u64) u64 {
        return std.mem.readInt(u64, c.mem[@intCast((cp % cp_chunk) * 8)..][0..8], .little);
    }
    fn set(c: *Chunk, cp: u64, v: u64) void {
        std.mem.writeInt(u64, c.mem[@intCast((cp % cp_chunk) * 8)..][0..8], v, .little);
    }
};

fn mapFile(io: Io, d: Io.Dir, name: []const u8, writable: bool, len: ?u64) ![]align(page) u8 {
    const f = if (writable) try d.createFile(io, name, .{ .read = true, .truncate = false }) else try d.openFile(io, name, .{});
    defer f.close(io);
    var n = try f.length(io);
    if (len) |l| if (n != l) {
        if (!writable) return error.Corrupt;
        try f.setLength(io, l);
        n = l;
    };
    if (n == 0) return error.Corrupt;
    const prot: std.posix.PROT = if (writable) .{ .READ = true, .WRITE = true } else .{ .READ = true };
    const m = try std.posix.mmap(null, @intCast(n), prot, .{ .TYPE = .SHARED }, f.handle, 0);
    return m;
}

/// One data generation: everything a reset or an adopt swaps.
const State = struct {
    dir: ?Io.Dir = null,
    gen: u64 = 1,
    /// A checkpoint was ever indexed in this generation (the floors and ends below are set).
    started: bool = false,
    cp_lo: u64 = 0,
    cp_next: u64 = 0,
    tx_lo: u64 = 0,
    tx_end: u64 = 0,
    chunks: std.ArrayList(Chunk) = .empty,
    sealed: std.ArrayList(Sealed) = .empty,
    frozen: std.ArrayList(*OpenSeg) = .empty,
    open: ?*OpenSeg = null,
    log: ?Io.File = null,
    log_end: u64 = 0,
    /// The log/open-file generation of the last rotation (`meta.log_n`).
    log_n: u64 = 1,
    /// The state at the last rotation (what `meta` holds).
    rot: Rot = .{},

    const Rot = struct { started: bool = false, cp_next: u64 = 0, tx_end: u64 = 0, open_seg: u64 = 0 };

    fn destroy(s: *State, gpa: Allocator, io: Io) void {
        if (s.open) |o| o.destroy(gpa);
        s.open = null;
        for (s.frozen.items) |o| o.destroy(gpa);
        s.frozen.deinit(gpa);
        for (s.sealed.items) |*x| x.release();
        s.sealed.deinit(gpa);
        for (s.chunks.items) |*c| c.release();
        s.chunks.deinit(gpa);
        if (s.log) |f| f.close(io);
        s.log = null;
        if (s.dir) |d| d.close(io);
        s.dir = null;
    }

    fn nonEmpty(s: *const State) bool {
        return s.started and s.cp_lo < s.cp_next;
    }

    fn chunkOf(s: *const State, cp: u64) ?*Chunk {
        if (s.chunks.items.len == 0) return null;
        const id = cp / cp_chunk;
        const base = s.chunks.items[0].id;
        if (id < base or id - base >= s.chunks.items.len) return null;
        return &s.chunks.items[@intCast(id - base)];
    }
    fn cpFirst(s: *const State, cp: u64) u64 {
        return s.chunkOf(cp).?.get(cp);
    }

    /// The segment holding `tx` (sealed, frozen or open).
    const SegRef = union(enum) { sealed: *const seg.View, mem: *const OpenSeg };
    fn segOf(s: *const State, tx: u64) ?SegRef {
        const id = tx / seg_txs;
        if (s.open) |o| if (o.id == id) return .{ .mem = o };
        for (s.frozen.items) |o| if (o.id == id) return .{ .mem = o };
        if (s.sealed.items.len == 0) return null;
        const base = s.sealed.items[0].v.seg;
        if (id < base or id - base >= s.sealed.items.len) return null;
        const v = &s.sealed.items[@intCast(id - base)].v;
        std.debug.assert(v.seg == id);
        return .{ .sealed = v };
    }

    fn memBytes(s: *const State) u64 {
        var n: u64 = s.chunks.capacity * @sizeOf(Chunk) + s.sealed.capacity * @sizeOf(Sealed) + s.frozen.capacity * 8;
        for (s.chunks.items) |c| if (!c.mapped) {
            n += c.mem.len;
        };
        for (s.sealed.items) |x| if (!x.mapped) {
            n += x.mem.len;
        };
        if (s.open) |o| n += o.memBytes();
        for (s.frozen.items) |o| n += o.memBytes();
        return n;
    }
};

// ---------------------------------------------------------------------- write path helpers

/// Key interner of one checkpoint's record (local ids).
const Keys = struct {
    bytes: std.ArrayList(u8) = .empty,
    offs: std.ArrayList(u32) = .empty, // len = count + 1 (offs[0] = 0)
    map: std.HashMapUnmanaged(u32, void, Ctx, 80) = .empty,

    const Ctx = struct {
        k: *const Keys,
        pub fn hash(c: Ctx, id: u32) u64 {
            return std.hash.Wyhash.hash(0, c.k.get(id));
        }
        pub fn eql(c: Ctx, a: u32, b: u32) bool {
            return std.mem.eql(u8, c.k.get(a), c.k.get(b));
        }
    };
    const Adapted = struct {
        k: *const Keys,
        pub fn hash(_: Adapted, key: []const u8) u64 {
            return std.hash.Wyhash.hash(0, key);
        }
        pub fn eql(c: Adapted, a: []const u8, b: u32) bool {
            return std.mem.eql(u8, a, c.k.get(b));
        }
    };

    fn deinit(k: *Keys, gpa: Allocator) void {
        k.bytes.deinit(gpa);
        k.offs.deinit(gpa);
        k.map.deinit(gpa);
    }
    fn count(k: *const Keys) u32 {
        return if (k.offs.items.len == 0) 0 else @intCast(k.offs.items.len - 1);
    }
    fn get(k: *const Keys, id: u32) []const u8 {
        return k.bytes.items[k.offs.items[id]..k.offs.items[id + 1]];
    }
    fn push(k: *Keys, gpa: Allocator, key: []const u8) !u32 {
        if (k.offs.items.len == 0) try k.offs.append(gpa, 0);
        const id = k.count();
        try k.bytes.appendSlice(gpa, key);
        try k.offs.append(gpa, @intCast(k.bytes.items.len));
        try k.map.putContext(gpa, id, {}, Ctx{ .k = k });
        return id;
    }
    fn intern(k: *Keys, gpa: Allocator, key: []const u8) !u32 {
        if (k.map.getKeyAdapted(key, Adapted{ .k = k })) |id| return id;
        return k.push(gpa, key);
    }
};

const Pending = struct {
    gpa: Allocator,
    /// Entries in emission order: local key id, position.
    tx: std.ArrayList(struct { u32, u32 }) = .empty,
    ev: std.ArrayList(struct { u32, u32, u32 }) = .empty,
    keys: Keys = .{},
    /// Per transaction: tx-space key ids already emitted (dedup like the Rust HashSet).
    seen: std.AutoHashMapUnmanaged(u32, void) = .empty,
    cur_tx: u32 = std.math.maxInt(u32),

    fn deinit(p: *Pending) void {
        p.tx.deinit(p.gpa);
        p.ev.deinit(p.gpa);
        p.keys.deinit(p.gpa);
        p.seen.deinit(p.gpa);
    }
    fn emit(ctx: *anyopaque, tx_off: u32, ev: ?u32, key: []const u8) Allocator.Error!void {
        const p: *Pending = @ptrCast(@alignCast(ctx));
        const id = try p.keys.intern(p.gpa, key);
        if (ev) |e| {
            try p.ev.append(p.gpa, .{ id, tx_off, e });
        } else {
            if (tx_off != p.cur_tx) {
                p.seen.clearRetainingCapacity();
                p.cur_tx = tx_off;
            }
            const g = try p.seen.getOrPut(p.gpa, id);
            if (g.found_existing) return;
            try p.tx.append(p.gpa, .{ id, tx_off });
        }
    }
};

/// One checkpoint's index rows (what a log record holds).
const Record = struct {
    seq: u64,
    first_tx: u64,
    digests: []const [32]u8,
    ev_counts: []const u32,
    keys: *const Keys,
    tx: []const struct { u32, u32 },
    ev: []const struct { u32, u32, u32 },
};

const meta_magic = "ZHMETA01";
const log_magic = "ZHLOG003";
const open_magic = "ZHOPEN01";
const log_hdr = 24;

const Meta = extern struct {
    magic: [8]u8 = meta_magic.*,
    gen: u64 = 0,
    started: u64 = 0,
    cp_lo: u64 = 0,
    tx_lo: u64 = 0,
    log_n: u64 = 1,
    rot_cp_next: u64 = 0,
    rot_tx_end: u64 = 0,
    open_seg: u64 = 0,
    crc: u32 = 0,
    _pad: u32 = 0,
};

pub const Index = struct {
    gpa: Allocator,
    lock: Io.RwLock = .init,
    io: Io,
    /// The index root (`CURRENT`, `g<gen>/`); null keeps everything in memory.
    root: ?Io.Dir = null,
    opts: Options = .{},
    s: State = .{},
    /// Highest published checkpoint + 1 (0: none). Monotonic.
    published: std.atomic.Value(u64) = .init(0),
    /// The generation whose state is durable (see `persistedGeneration`).
    persisted: std.atomic.Value(u64) = .init(0),
    /// Tests: crash injection (see `Fault`).
    fault: ?*Fault = null,
    /// Tests: counts of segment writes and rotations.
    stats: struct { flushes: u64 = 0, rotations: u64 = 0, replayed: u64 = 0 } = .{},

    /// `dir`: where the index persists (created if missing); null keeps it in memory only.
    pub fn init(gpa: Allocator, io: Io, dir: ?[]const u8) !*Index {
        return initOpts(gpa, io, dir, .{});
    }

    pub fn initOpts(gpa: Allocator, io: Io, dir: ?[]const u8, opts: Options) !*Index {
        return initFault(gpa, io, dir, opts, null);
    }

    /// `initOpts` with crash injection from the first step (tests).
    pub fn initFault(gpa: Allocator, io: Io, dir: ?[]const u8, opts: Options, fault: ?*Fault) !*Index {
        const ix = try gpa.create(Index);
        ix.* = .{ .gpa = gpa, .io = io, .opts = opts, .fault = fault };
        errdefer ix.deinit();
        if (dir) |d| {
            try Io.Dir.cwd().createDirPath(io, d);
            ix.root = try Io.Dir.cwd().openDir(io, d, .{ .iterate = true });
            try ix.openRoot();
        } else ix.opts.log = .none;
        return ix;
    }

    /// Backfill staging (node lhfill.zig): an index on disk whose durability is its segment
    /// rotations (no per-checkpoint log), so an interrupted build resumes from the last one.
    pub fn openStaging(gpa: Allocator, io: Io, dir: []const u8) !*Index {
        return initOpts(gpa, io, dir, .{ .log = .none });
    }

    /// Staging: makes the whole state durable now (a rotation).
    pub fn saveStaging(ix: *Index) !void {
        try ix.flushFrozen(false);
        try ix.rotate();
    }

    /// Kept for callers of the in-memory index: `adopt` takes a staging index with its directory.
    pub fn detachDir(ix: *Index) void {
        _ = ix;
    }

    /// The generation whose state is durable: `adopt` is durable when it returns.
    pub fn persistedGeneration(ix: *const Index) u64 {
        return ix.persisted.load(.acquire);
    }

    pub fn deinit(ix: *Index) void {
        ix.s.destroy(ix.gpa, ix.io);
        if (ix.root) |d| d.close(ix.io);
        ix.gpa.destroy(ix);
    }

    /// No background work is left (kept for callers of the in-memory index).
    pub fn joinSnapshot(ix: *Index) void {
        _ = ix;
    }

    pub fn generation(ix: *const Index) u64 {
        return ix.s.gen;
    }

    /// Heap bytes held (the open and frozen segments; for an in-memory index everything), for
    /// metrics and the memory budget. Mapped segments are page cache, not counted.
    pub fn memoryBytes(ix: *Index) u64 {
        ix.lock.lockSharedUncancelable(ix.io);
        defer ix.lock.unlockShared(ix.io);
        return ix.s.memBytes();
    }

    /// Transactions indexed.
    pub fn txCount(ix: *Index) u64 {
        ix.lock.lockSharedUncancelable(ix.io);
        defer ix.lock.unlockShared(ix.io);
        return if (ix.s.started) ix.s.tx_end -| ix.s.tx_lo else 0;
    }

    /// Sealed segments (mapped or, in memory, on the heap).
    pub fn segmentCount(ix: *Index) usize {
        ix.lock.lockSharedUncancelable(ix.io);
        defer ix.lock.unlockShared(ix.io);
        return ix.s.sealed.items.len;
    }

    /// Lowest indexed checkpoint.
    pub fn indexedLo(ix: *Index) ?u64 {
        ix.lock.lockSharedUncancelable(ix.io);
        defer ix.lock.unlockShared(ix.io);
        return if (ix.s.nonEmpty()) ix.s.cp_lo else null;
    }

    /// Highest indexed checkpoint (published or not).
    pub fn indexedHi(ix: *Index) ?u64 {
        ix.lock.lockSharedUncancelable(ix.io);
        defer ix.lock.unlockShared(ix.io);
        return if (ix.s.nonEmpty()) ix.s.cp_next - 1 else null;
    }

    /// Hash of the whole index content (checkpoint and transaction tables, every bucket's key and
    /// bits), independent of generation, of storage (heap or files) and of how it was built: two
    /// indexes over the same checkpoints hash equal (tests, backfill checks).
    pub fn contentHash(ix: *Index) !u64 {
        const gpa = ix.gpa;
        ix.lock.lockSharedUncancelable(ix.io);
        defer ix.lock.unlockShared(ix.io);
        const s = &ix.s;
        var h = std.hash.Wyhash.init(0);
        if (!s.nonEmpty()) return h.final();
        const ints = [_]u64{ s.cp_lo, s.cp_next, s.tx_lo, s.tx_end };
        h.update(std.mem.sliceAsBytes(&ints));
        var cp = s.cp_lo;
        while (cp < s.cp_next) : (cp += 1) h.update(std.mem.asBytes(&s.cpFirst(cp)));
        var tx = s.tx_lo;
        while (tx < s.tx_end) : (tx += 1) {
            const r = s.segOf(tx) orelse return error.Corrupt;
            const off: u32 = @intCast(tx % seg_txs);
            switch (r) {
                .sealed => |v| {
                    h.update(v.digest(off));
                    h.update(std.mem.asBytes(&v.evCount(off)));
                },
                .mem => |o| {
                    h.update(o.digest(off));
                    h.update(std.mem.asBytes(&o.evCount(off)));
                },
            }
        }
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const E = struct { id: u64, key: []const u8, bits: []const u32 };
        for (0..2) |si| {
            var es: std.ArrayList(E) = .empty;
            var keyset: std.StringHashMapUnmanaged(void) = .empty;
            for (s.sealed.items) |*x| for (0..x.v.sp[si].keyCount()) |i| try keyset.put(a, x.v.sp[si].key(i), {});
            for (s.frozen.items) |o| {
                var it = o.maps[si].keyIterator();
                while (it.next()) |k| try keyset.put(a, k.*, {});
            }
            if (s.open) |o| {
                var it = o.maps[si].keyIterator();
                while (it.next()) |k| try keyset.put(a, k.*, {});
            }
            var kit = keyset.keyIterator();
            while (kit.next()) |k| for (try bucketsIn(s, a, @enumFromInt(si), k.*)) |b| try es.append(a, .{ .id = b.id, .key = k.*, .bits = b.bits });
            std.mem.sort(E, es.items, {}, struct {
                fn lt(_: void, x: E, y: E) bool {
                    return if (x.id != y.id) x.id < y.id else std.mem.order(u8, x.key, y.key) == .lt;
                }
            }.lt);
            for (es.items) |e| {
                h.update(std.mem.asBytes(&e.id));
                h.update(e.key);
                h.update(std.mem.sliceAsBytes(e.bits));
            }
        }
        return h.final();
    }

    // ------------------------------------------------------------------ write path

    /// Index checkpoint `seq` (the node observer's blob: 0x01 ++ BCS CheckpointData). Checkpoints
    /// must come in order; one already indexed is skipped.
    ///
    /// One writer: the node's commit path (`addCheckpoint`, `pruneBelow`) is the only thread that
    /// mutates the index, so it reads the index without the lock. The log record is written and
    /// fsync'd before the exclusive lock is taken; readers wait only for the in-memory `apply`.
    pub fn addCheckpoint(ix: *Index, seq: u64, blob: []const u8) !void {
        if (blob.len == 0 or blob[0] != 1) return error.InvalidValue;
        var arena_state = std.heap.ArenaAllocator.init(ix.gpa);
        defer arena_state.deinit();
        const cp = try bcs.decode(types.CheckpointData, arena_state.allocator(), blob[1..]);
        return ix.addData(seq, &cp);
    }

    /// `addCheckpoint` for an already decoded checkpoint. Only the summary's sequence number and
    /// `network_total_transactions`, and each transaction's transaction, effects, events and the
    /// input/output objects its changed objects name (owner and package-ness by (id, version))
    /// are read: the backfill (node lhfill.zig) builds exactly that from the store.
    pub fn addData(ix: *Index, seq: u64, cp: *const types.CheckpointData) !void {
        if (try ix.skipOrReset(seq)) return;
        var arena_state = std.heap.ArenaAllocator.init(ix.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const sm = &cp.checkpoint_summary.data;
        if (sm.sequence_number != seq) return error.InvalidValue;
        const ntx: u64 = cp.transactions.len;
        const first_tx = sm.network_total_transactions - ntx;

        var p: Pending = .{ .gpa = ix.gpa };
        defer p.deinit();
        try dims.extract(ix.gpa, arena, cp, .{ .ctx = &p, .emit = Pending.emit });

        const digests = try arena.alloc([32]u8, cp.transactions.len);
        const evc = try arena.alloc(u32, cp.transactions.len);
        for (cp.transactions, digests, evc) |*t, *d, *c| {
            d.* = switch (t.effects) {
                .V1 => |v| v.transaction_digest.@"0".@"0",
                .V2 => |v| v.transaction_digest.@"0".@"0",
            };
            c.* = if (t.events) |e| @intCast(e.data.len) else 0;
        }
        const r: Record = .{ .seq = seq, .first_tx = first_tx, .digests = digests, .ev_counts = evc, .keys = &p.keys, .tx = p.tx.items, .ev = p.ev.items };
        try ix.addRecord(&r);
    }

    /// Tests (synthetic checkpoints): index one checkpoint given its rows. `keys[i]` is the key
    /// bytes of local id `i`; `tx` entries are (key, tx offset), `ev` (key, tx offset, event).
    pub fn addRows(ix: *Index, seq: u64, first_tx: u64, digests: []const [32]u8, ev_counts: []const u32, keys: []const []const u8, tx: []const struct { u32, u32 }, ev: []const struct { u32, u32, u32 }) !void {
        if (try ix.skipOrReset(seq)) return;
        var k: Keys = .{};
        defer k.deinit(ix.gpa);
        for (keys) |key| _ = try k.push(ix.gpa, key);
        const r: Record = .{ .seq = seq, .first_tx = first_tx, .digests = digests, .ev_counts = ev_counts, .keys = &k, .tx = @ptrCast(tx), .ev = @ptrCast(ev) };
        try ix.addRecord(&r);
    }

    /// True when `seq` is already indexed; resets the index at a hole.
    fn skipOrReset(ix: *Index, seq: u64) !bool {
        const s = &ix.s;
        if (!s.started) return false;
        if (seq < s.cp_next) return true;
        if (seq == s.cp_next) return false;
        // A hole (the index fell behind the store, or the node jumped ahead): the index cannot
        // answer across it, so it restarts at `seq`, as a fresh node's index would.
        if (!builtin.is_test) std.log.warn("history: checkpoint {d} after indexed tip {d}; restarting the index at {d}", .{ seq, s.cp_next -| 1, seq });
        try ix.reset();
        return false;
    }

    fn addRecord(ix: *Index, r: *const Record) !void {
        if (ix.s.log != null and ix.opts.log != .none) try ix.writeRecord(r);
        {
            ix.lock.lockUncancelable(ix.io);
            defer ix.lock.unlock(ix.io);
            try ix.apply(r);
        }
        if (ix.s.frozen.items.len != 0) {
            try ix.flushFrozen(false);
            try ix.rotate();
        }
    }

    /// Under the exclusive lock.
    fn apply(ix: *Index, r: *const Record) !void {
        const gpa = ix.gpa;
        const s = &ix.s;
        if (s.started) {
            if (r.seq < s.cp_next) return;
            if (r.seq != s.cp_next or r.first_tx != s.tx_end) return error.Gap;
        } else {
            s.started = true;
            s.cp_lo = r.seq;
            s.cp_next = r.seq;
            s.tx_lo = r.first_tx;
            s.tx_end = r.first_tx;
        }
        if (r.digests.len != r.ev_counts.len) return error.InvalidValue;
        try ix.setCp(r.seq, r.first_tx);
        const end = r.first_tx + r.digests.len;
        var tx = r.first_tx;
        while (tx < end) {
            const sid = tx / seg_txs;
            const seg_end = @min(end, (sid + 1) * seg_txs);
            const o = try ix.openFor(sid);
            const lo: u32 = @intCast(tx - r.first_tx);
            const hi: u32 = @intCast(seg_end - r.first_tx);
            for (lo..hi) |i| try o.addRec(gpa, @intCast((r.first_tx + i) % seg_txs), &r.digests[i], r.ev_counts[i]);
            for (r.tx) |e| if (e[1] >= lo and e[1] < hi) {
                try o.addBit(gpa, 0, r.keys.get(e[0]), @intCast((r.first_tx + e[1]) % seg_txs));
            };
            for (r.ev) |e| if (e[1] >= lo and e[1] < hi) {
                if (e[2] >= 1 << event_bits) return error.InvalidValue;
                const off: u32 = @intCast((r.first_tx + e[1]) % seg_txs);
                try o.addBit(gpa, 1, r.keys.get(e[0]), (off << event_bits) | e[2]);
            };
            tx = seg_end;
        }
        s.cp_next = r.seq + 1;
        s.tx_end = end;
        if (s.open) |o| if (o.id < s.tx_end / seg_txs) try ix.freeze();
    }

    fn freeze(ix: *Index) !void {
        const s = &ix.s;
        const o = s.open orelse return;
        try s.frozen.append(ix.gpa, o);
        s.open = null;
    }

    fn openFor(ix: *Index, sid: u64) !*OpenSeg {
        const s = &ix.s;
        if (s.open) |o| {
            if (o.id == sid) return o;
            if (o.id > sid) return error.OutOfOrder;
            try ix.freeze();
        }
        s.open = try OpenSeg.create(ix.gpa, sid);
        return s.open.?;
    }

    fn setCp(ix: *Index, cp: u64, first: u64) !void {
        const s = &ix.s;
        if (cp < s.cp_lo) {
            // Replayed below a floor raised after the rotation: never read.
            if (s.chunkOf(cp)) |c| c.set(cp, first);
            return;
        }
        const id = cp / cp_chunk;
        if (s.chunks.items.len == 0 or id > s.chunks.items[s.chunks.items.len - 1].id) {
            var next = if (s.chunks.items.len == 0) id else s.chunks.items[s.chunks.items.len - 1].id + 1;
            while (next <= id) : (next += 1) {
                try s.chunks.ensureUnusedCapacity(ix.gpa, 1);
                s.chunks.appendAssumeCapacity(try ix.newChunk(next));
            }
        }
        const c = s.chunkOf(cp) orelse return error.OutOfOrder;
        c.set(cp, first);
    }

    fn newChunk(ix: *Index, id: u64) !Chunk {
        if (ix.s.dir) |d| {
            var nb: [32]u8 = undefined;
            const mem = try mapFile(ix.io, d, chunkName(&nb, id), true, chunk_bytes);
            return .{ .id = id, .mem = mem, .mapped = true };
        }
        const mem = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(page), chunk_bytes);
        @memset(mem, 0);
        return .{ .id = id, .mem = mem, .mapped = false };
    }

    /// Writes every frozen segment (outside the lock; readers keep reading it from memory), then
    /// swaps it for its mapped file under the lock.
    fn flushFrozen(ix: *Index, replaying: bool) !void {
        _ = replaying;
        const gpa = ix.gpa;
        const s = &ix.s;
        while (s.frozen.items.len != 0) {
            const o = s.frozen.items[0];
            var lists: [2][]seg.KeyList = .{ &.{}, &.{} };
            defer for (lists) |l| gpa.free(l);
            for (&lists, 0..) |*l, si| l.* = try o.keyLists(gpa, si);
            const in: seg.Input = .{ .seg = o.id, .start = o.start, .recs = o.recs.items, .spaces = lists };
            const built = try seg.build(gpa, &in);
            var blob = built;
            var mapped = false;
            if (s.dir) |d| {
                defer seg.freeBlob(built);
                var nb: [32]u8 = undefined;
                const name = segName(&nb, o.id);
                try ix.writeFileAtomic(d, name, built);
                blob = try mapFile(ix.io, d, name, false, built.len);
                mapped = true;
            }
            var x: Sealed = .{ .v = undefined, .mem = blob, .mapped = mapped };
            x.v = seg.View.parse(blob) catch |e| {
                x.release();
                return e;
            };
            if (s.sealed.items.len != 0 and s.sealed.items[s.sealed.items.len - 1].v.seg + 1 != o.id) {
                x.release();
                return error.Gap;
            }
            s.sealed.ensureUnusedCapacity(gpa, 1) catch |e| {
                x.release();
                return e;
            };
            {
                ix.lock.lockUncancelable(ix.io);
                defer ix.lock.unlock(ix.io);
                s.sealed.appendAssumeCapacity(x);
                _ = s.frozen.orderedRemove(0);
            }
            o.destroy(gpa);
            ix.stats.flushes += 1;
        }
    }

    /// Readers see checkpoints <= seq (monotonic: a lower seq than already published is a no-op).
    /// The node publishes the store's committed tip; after a restart nothing is published until it does.
    pub fn publish(ix: *Index, seq: u64) void {
        _ = ix.published.fetchMax(seq + 1, .acq_rel);
    }

    /// A read view under the shared lock. Keep it short: the writer's next `apply` (every
    /// checkpoint) waits for every reader, and new readers queue behind a waiting writer.
    pub fn reader(ix: *Index) Reader {
        ix.lock.lockSharedUncancelable(ix.io);
        const pub_seq = ix.published.load(.acquire);
        return .{ .ix = ix, .published = pub_seq, .scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator) };
    }

    // ------------------------------------------------------------------ generations

    /// A fresh, empty generation `gen` (its directory created and initialised when on disk).
    fn freshState(ix: *Index, gen: u64) !State {
        var st: State = .{ .gen = gen };
        errdefer st.destroy(ix.gpa, ix.io);
        if (ix.root) |r| {
            var nb: [32]u8 = undefined;
            const name = genName(&nb, gen);
            r.deleteTree(ix.io, name) catch {};
            try ix.step();
            try r.createDirPath(ix.io, name);
            st.dir = try r.openDir(ix.io, name, .{ .iterate = true });
            try ix.writeMeta(&st);
            if (ix.opts.log != .none) try ix.newLog(&st, st.log_n);
            syncDir(ix.io, r);
        }
        return st;
    }

    /// Swaps `st` in as the live generation (CURRENT first when on disk), destroys the old one.
    fn switchTo(ix: *Index, st: *State, reset_published: bool) !void {
        if (ix.root) |r| try ix.writeCurrent(r, st.gen);
        const old_gen = ix.s.gen;
        {
            ix.lock.lockUncancelable(ix.io);
            defer ix.lock.unlock(ix.io);
            std.mem.swap(State, &ix.s, st);
            if (reset_published) ix.published.store(0, .release);
        }
        st.destroy(ix.gpa, ix.io);
        if (ix.root) |r| {
            var nb: [32]u8 = undefined;
            r.deleteTree(ix.io, genName(&nb, old_gen)) catch {};
        }
        ix.persisted.store(ix.s.gen, .release);
    }

    /// Empties the index (a new generation).
    fn reset(ix: *Index) !void {
        var st = try ix.freshState(ix.s.gen + 1);
        try ix.switchTo(&st, true);
    }

    /// Takes over the state of `src`, an index built by the backfill (in memory, or a staging
    /// index on the same filesystem), which must end exactly where this index's next checkpoint
    /// begins (the caller catches it up first). Readers see the swap atomically (exclusive
    /// lock); the published tip is kept. On disk the new generation is written beside the
    /// current one (a staging directory is renamed in, an in-memory one exported) and `CURRENT`
    /// switched, so a crash before that reopens the old state (the node then backfills again).
    /// `src` is left empty; the caller deinits it.
    pub fn adopt(ix: *Index, src: *Index) !void {
        try src.flushFrozen(false);
        const gen = @max(ix.s.gen, src.s.gen) + 2;
        if (ix.root == null) {
            // A staging index needs a root to land in (checked before taking its state, so a
            // refused adopt leaves `src` whole for its owner to free).
            if (src.s.dir != null) return error.InvalidValue;
            var st: State = .{};
            std.mem.swap(State, &st, &src.s);
            st.gen = gen;
            try ix.switchTo(&st, false);
            return;
        }
        const r = ix.root.?;
        var nb: [32]u8 = undefined;
        const name = genName(&nb, gen);
        r.deleteTree(ix.io, name) catch {};
        if (src.root) |sr| {
            // Staging: make it durable whole, then move its generation directory in.
            try src.rotate();
            var sb: [32]u8 = undefined;
            const sname = genName(&sb, src.s.gen);
            src.s.destroy(src.gpa, src.io);
            src.s = .{ .gen = src.s.gen };
            try sr.rename(sname, r, name, ix.io);
            syncDir(ix.io, r);
            sr.deleteFile(ix.io, "CURRENT") catch {};
            syncDir(ix.io, sr);
            // The moved directory carries its own generation in meta; restamp it.
            var d = try r.openDir(ix.io, name, .{ .iterate = true });
            defer d.close(ix.io);
            var m = (try readMeta(ix.io, d)) orelse return error.Corrupt;
            m.gen = gen;
            try ix.putMeta(d, &m);
        } else {
            try r.createDirPath(ix.io, name);
            var d = try r.openDir(ix.io, name, .{ .iterate = true });
            defer d.close(ix.io);
            try ix.export_(&src.s, d, gen);
            src.s.destroy(src.gpa, src.io);
            src.s = .{};
        }
        var st: State = .{ .gen = gen };
        errdefer st.destroy(ix.gpa, ix.io);
        st.dir = try r.openDir(ix.io, name, .{ .iterate = true });
        try ix.loadInto(&st);
        try ix.switchTo(&st, false);
    }

    /// Writes an in-memory state into the empty directory `d` as a rotated generation.
    fn export_(ix: *Index, src: *State, d: Io.Dir, gen: u64) !void {
        std.debug.assert(src.dir == null and src.frozen.items.len == 0);
        var nb: [32]u8 = undefined;
        for (src.sealed.items) |x| try ix.writeFileAtomic(d, segName(&nb, x.v.seg), x.mem);
        for (src.chunks.items) |c| try ix.writeFileAtomic(d, chunkName(&nb, c.id), c.mem);
        var st: State = .{ .gen = gen, .started = src.started, .cp_lo = src.cp_lo, .cp_next = src.cp_next, .tx_lo = src.tx_lo, .tx_end = src.tx_end, .open = src.open, .log_n = 1 };
        if (src.open) |o| try ix.writeOpen(d, 1, o);
        st.rot = .{ .started = src.started, .cp_next = src.cp_next, .tx_end = src.tx_end, .open_seg = if (src.open) |o| o.id else src.tx_end / seg_txs };
        try ix.putMetaOf(d, &st);
    }

    // ------------------------------------------------------------------ pruning

    /// Drop checkpoints below `checkpoint`, their transactions, and every segment and checkpoint
    /// chunk wholly below the new floors (buckets wholly below the floor stop being served at
    /// once, as sui-rpc-store's compaction filter drops them). `meta` takes the floors before any
    /// file is unlinked.
    pub fn pruneBelow(ix: *Index, checkpoint: u64) void {
        ix.tryPruneBelow(checkpoint) catch |e| std.log.err("history: prune below {d}: {s}", .{ checkpoint, @errorName(e) });
    }

    pub fn tryPruneBelow(ix: *Index, checkpoint: u64) !void {
        const gpa = ix.gpa;
        const s = &ix.s;
        if (!s.nonEmpty() or checkpoint <= s.cp_lo) return;
        const cut = @min(checkpoint, s.cp_next);
        const floor_tx = if (cut >= s.cp_next) s.tx_end else s.cpFirst(cut);
        var nseg: usize = 0;
        while (nseg < s.sealed.items.len and (s.sealed.items[nseg].v.seg + 1) * seg_txs <= floor_tx) nseg += 1;
        var nch: usize = 0;
        // The chunk holding `cut` stays (cp_next may sit at a chunk boundary: keep the last one).
        while (nch + 1 < s.chunks.items.len and (s.chunks.items[nch].id + 1) * cp_chunk <= cut) nch += 1;
        const dropped_segs = try gpa.dupe(Sealed, s.sealed.items[0..nseg]);
        defer gpa.free(dropped_segs);
        const dropped_chunks = try gpa.dupe(Chunk, s.chunks.items[0..nch]);
        defer gpa.free(dropped_chunks);
        {
            ix.lock.lockUncancelable(ix.io);
            defer ix.lock.unlock(ix.io);
            s.cp_lo = cut;
            s.tx_lo = floor_tx;
            s.sealed.replaceRangeAssumeCapacity(0, nseg, &.{});
            s.chunks.replaceRangeAssumeCapacity(0, nch, &.{});
        }
        // Readers are out of the dropped mappings (they were removed under the exclusive lock).
        var err: ?anyerror = null;
        if (s.dir != null) ix.writeMeta(s) catch |e| {
            err = e;
        };
        var nb: [32]u8 = undefined;
        for (dropped_segs) |*x| {
            if (err == null) if (s.dir) |d| d.deleteFile(ix.io, segName(&nb, x.v.seg)) catch {};
            x.release();
        }
        for (dropped_chunks) |*c| {
            if (err == null) if (s.dir) |d| d.deleteFile(ix.io, chunkName(&nb, c.id)) catch {};
            c.release();
        }
        if (err) |e| return e;
    }

    // ------------------------------------------------------------------ persistence

    fn step(ix: *Index) !void {
        if (ix.fault) |f| if (f.hit()) return error.Crash;
    }

    fn writeFileAtomic(ix: *Index, d: Io.Dir, name: []const u8, bytes: []const u8) !void {
        const io = ix.io;
        var tb: [48]u8 = undefined;
        const tmp = try std.fmt.bufPrint(&tb, "{s}.tmp", .{name});
        {
            const f = try d.createFile(io, tmp, .{ .truncate = true });
            defer f.close(io);
            try ix.step();
            try f.writePositionalAll(io, bytes, 0);
            try ix.step();
            try f.sync(io);
        }
        try ix.step();
        try d.rename(tmp, d, name, io);
        syncDir(io, d);
        try ix.step();
    }

    fn writeCurrent(ix: *Index, r: Io.Dir, gen: u64) !void {
        var nb: [32]u8 = undefined;
        var lb: [40]u8 = undefined;
        const line = try std.fmt.bufPrint(&lb, "{s}\n", .{genName(&nb, gen)});
        try ix.writeFileAtomic(r, "CURRENT", line);
    }

    fn metaOf(st: *const State) Meta {
        return .{
            .gen = st.gen,
            .started = @intFromBool(st.rot.started),
            .cp_lo = st.cp_lo,
            .tx_lo = st.tx_lo,
            .log_n = st.log_n,
            .rot_cp_next = st.rot.cp_next,
            .rot_tx_end = st.rot.tx_end,
            .open_seg = st.rot.open_seg,
        };
    }

    fn writeMeta(ix: *Index, st: *const State) !void {
        try ix.putMetaOf(st.dir.?, st);
    }
    fn putMetaOf(ix: *Index, d: Io.Dir, st: *const State) !void {
        var m = metaOf(st);
        try ix.putMeta(d, &m);
    }
    fn putMeta(ix: *Index, d: Io.Dir, m: *Meta) !void {
        m.crc = 0;
        m.crc = std.hash.Crc32.hash(std.mem.asBytes(m));
        try ix.writeFileAtomic(d, "meta", std.mem.asBytes(m));
    }

    fn readMeta(io: Io, d: Io.Dir) !?Meta {
        var m: Meta = undefined;
        const got = d.readFile(io, "meta", std.mem.asBytes(&m)) catch |e| switch (e) {
            error.FileNotFound => return null,
            else => return e,
        };
        if (got.len != @sizeOf(Meta) or !std.mem.eql(u8, &m.magic, meta_magic)) return error.Corrupt;
        const want = m.crc;
        m.crc = 0;
        if (std.hash.Crc32.hash(std.mem.asBytes(&m)) != want) return error.Corrupt;
        m.crc = want;
        return m;
    }

    /// Creates `log-<n>.bin` (header, fsync, rename) and makes it the live log of `st`.
    fn newLog(ix: *Index, st: *State, n: u64) !void {
        const io = ix.io;
        const d = st.dir.?;
        var hdr: [log_hdr]u8 = undefined;
        @memcpy(hdr[0..8], log_magic);
        std.mem.writeInt(u64, hdr[8..16], st.gen, .little);
        std.mem.writeInt(u64, hdr[16..24], n, .little);
        var nb: [32]u8 = undefined;
        const name = logName(&nb, n);
        try ix.writeFileAtomic(d, name, &hdr);
        const f = try d.openFile(io, name, .{ .mode = .read_write });
        if (st.log) |old| old.close(io);
        st.log = f;
        st.log_end = log_hdr;
    }

    fn writeRecord(ix: *Index, r: *const Record) !void {
        const gpa = ix.gpa;
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(gpa);
        try w.appendNTimes(gpa, 0, 8);
        try putInt(gpa, &w, u64, r.seq);
        try putInt(gpa, &w, u64, r.first_tx);
        try putInt(gpa, &w, u32, @intCast(r.digests.len));
        for (r.digests, r.ev_counts) |*d, c| {
            try w.appendSlice(gpa, d);
            try putInt(gpa, &w, u32, c);
        }
        try putInt(gpa, &w, u32, r.keys.count());
        var k: u32 = 0;
        while (k < r.keys.count()) : (k += 1) {
            const key = r.keys.get(k);
            try putInt(gpa, &w, u16, @intCast(key.len));
            try w.appendSlice(gpa, key);
        }
        try putInt(gpa, &w, u32, @intCast(r.tx.len));
        for (r.tx) |e| {
            try putInt(gpa, &w, u32, e[0]);
            try putInt(gpa, &w, u32, e[1]);
        }
        try putInt(gpa, &w, u32, @intCast(r.ev.len));
        for (r.ev) |e| {
            try putInt(gpa, &w, u32, e[0]);
            try putInt(gpa, &w, u32, e[1]);
            try putInt(gpa, &w, u32, e[2]);
        }
        const body = w.items[8..];
        std.mem.writeInt(u32, w.items[0..4], @intCast(body.len), .little);
        std.mem.writeInt(u32, w.items[4..8], std.hash.Crc32.hash(body), .little);
        const f = ix.s.log.?;
        if (ix.fault) |fl| if (fl.hit()) {
            // Torn: a prefix of the record reaches the file.
            const n = fl.rng.random().uintLessThan(usize, w.items.len);
            f.writePositionalAll(ix.io, w.items[0..n], ix.s.log_end) catch {};
            return error.Crash;
        };
        try f.writePositionalAll(ix.io, w.items, ix.s.log_end);
        if (ix.opts.log == .sync) try f.sync(ix.io);
        ix.s.log_end += w.items.len;
    }

    fn parseRecord(gpa: Allocator, body: []const u8, keys: *Keys, digests: *std.ArrayList([32]u8), evc: *std.ArrayList(u32), txe: *std.ArrayList(struct { u32, u32 }), eve: *std.ArrayList(struct { u32, u32, u32 })) !struct { u64, u64 } {
        var r = Rd{ .b = body };
        const seq = try r.int(u64);
        const first_tx = try r.int(u64);
        const ntx = try r.int(u32);
        for (0..ntx) |_| {
            try digests.append(gpa, (try r.take(32))[0..32].*);
            try evc.append(gpa, try r.int(u32));
        }
        const nkeys = try r.int(u32);
        for (0..nkeys) |_| {
            const l = try r.int(u16);
            _ = try keys.push(gpa, try r.take(l));
        }
        const ntxe = try r.int(u32);
        for (0..ntxe) |_| {
            const e = .{ try r.int(u32), try r.int(u32) };
            if (e[0] >= nkeys or e[1] >= ntx) return error.InvalidValue;
            try txe.append(gpa, e);
        }
        const neve = try r.int(u32);
        for (0..neve) |_| {
            const e = .{ try r.int(u32), try r.int(u32), try r.int(u32) };
            if (e[0] >= nkeys or e[1] >= ntx) return error.InvalidValue;
            try eve.append(gpa, e);
        }
        if (r.at != body.len) return error.InvalidValue;
        return .{ seq, first_tx };
    }

    /// Replays the records of one log file; returns the end of its valid prefix.
    fn replayLog(ix: *Index, data: []const u8) usize {
        const gpa = ix.gpa;
        var at: usize = log_hdr;
        var keys: Keys = .{};
        defer keys.deinit(gpa);
        var digests: std.ArrayList([32]u8) = .empty;
        defer digests.deinit(gpa);
        var evc: std.ArrayList(u32) = .empty;
        defer evc.deinit(gpa);
        var txe: std.ArrayList(struct { u32, u32 }) = .empty;
        defer txe.deinit(gpa);
        var eve: std.ArrayList(struct { u32, u32, u32 }) = .empty;
        defer eve.deinit(gpa);
        while (at + 8 <= data.len) {
            const len = std.mem.readInt(u32, data[at..][0..4], .little);
            const crc = std.mem.readInt(u32, data[at + 4 ..][0..4], .little);
            if (at + 8 + len > data.len) break;
            const body = data[at + 8 ..][0..len];
            if (std.hash.Crc32.hash(body) != crc) break;
            keys.deinit(gpa);
            keys = .{};
            digests.clearRetainingCapacity();
            evc.clearRetainingCapacity();
            txe.clearRetainingCapacity();
            eve.clearRetainingCapacity();
            const hd = parseRecord(gpa, body, &keys, &digests, &evc, &txe, &eve) catch |e| {
                std.log.warn("history: log record at {d} unusable ({s}); truncating", .{ at, @errorName(e) });
                break;
            };
            const rec: Record = .{ .seq = hd[0], .first_tx = hd[1], .digests = digests.items, .ev_counts = evc.items, .keys = &keys, .tx = txe.items, .ev = eve.items };
            ix.apply(&rec) catch |e| {
                std.log.warn("history: log record at {d} (checkpoint {d}) not applicable ({s}); truncating", .{ at, hd[0], @errorName(e) });
                break;
            };
            if (ix.s.frozen.items.len != 0) ix.flushFrozen(true) catch |e| {
                std.log.warn("history: segment write during replay: {s}; truncating the log here", .{@errorName(e)});
                break;
            };
            ix.stats.replayed += 1;
            at += 8 + len;
        }
        return at;
    }

    /// The rotation: called right after a segment boundary was flushed (or to make a staging
    /// index durable). The next records go to `log-<n+1>.bin`, the open segment to
    /// `open-<n+1>.bin`, the checkpoint chunks are synced, then `meta` names them; older logs
    /// and open files are deleted after.
    fn rotate(ix: *Index) !void {
        const s = &ix.s;
        const d = s.dir orelse return;
        std.debug.assert(s.frozen.items.len == 0);
        const n = s.log_n + 1;
        if (ix.opts.log != .none) try ix.newLog(s, n);
        if (s.open) |o| try ix.writeOpen(d, n, o);
        for (s.chunks.items) |c| if (c.mapped) {
            if (s.rot.started and (c.id + 1) * cp_chunk <= s.rot.cp_next) continue;
            try ix.step();
            try std.posix.msync(c.mem, std.posix.MSF.SYNC);
        };
        const old_n = s.log_n;
        const old_rot = s.rot;
        s.log_n = n;
        s.rot = .{ .started = s.started, .cp_next = s.cp_next, .tx_end = s.tx_end, .open_seg = if (s.open) |o| o.id else s.tx_end / seg_txs };
        ix.writeMeta(s) catch |e| {
            s.log_n = old_n;
            s.rot = old_rot;
            return e;
        };
        ix.stats.rotations += 1;
        var nb: [32]u8 = undefined;
        var k = old_n;
        while (k < n) : (k += 1) {
            d.deleteFile(ix.io, logName(&nb, k)) catch {};
            d.deleteFile(ix.io, openName(&nb, k)) catch {};
        }
    }

    fn writeOpen(ix: *Index, d: Io.Dir, n: u64, o: *const OpenSeg) !void {
        const gpa = ix.gpa;
        var w: std.ArrayList(u8) = .empty;
        defer w.deinit(gpa);
        try w.appendSlice(gpa, open_magic);
        try putInt(gpa, &w, u64, o.id);
        try putInt(gpa, &w, u32, o.start);
        try putInt(gpa, &w, u32, o.ntx());
        try w.appendSlice(gpa, o.recs.items);
        for (&o.maps) |*m| {
            try putInt(gpa, &w, u32, m.count());
            var it = m.iterator();
            while (it.next()) |kv| {
                try putInt(gpa, &w, u16, @intCast(kv.key_ptr.len));
                try w.appendSlice(gpa, kv.key_ptr.*);
                try putInt(gpa, &w, u32, @intCast(kv.value_ptr.items.len));
                try w.appendSlice(gpa, std.mem.sliceAsBytes(kv.value_ptr.items));
            }
        }
        try putInt(gpa, &w, u32, std.hash.Crc32.hash(w.items));
        var nb: [32]u8 = undefined;
        try ix.writeFileAtomic(d, openName(&nb, n), w.items);
    }

    fn readOpen(ix: *Index, data: []const u8) !*OpenSeg {
        const gpa = ix.gpa;
        if (data.len < 8 + 16 + 4 or !std.mem.eql(u8, data[0..8], open_magic)) return error.Corrupt;
        const body = data[0 .. data.len - 4];
        if (std.hash.Crc32.hash(body) != std.mem.readInt(u32, data[data.len - 4 ..][0..4], .little)) return error.Corrupt;
        var r = Rd{ .b = body, .at = 8 };
        const o = try OpenSeg.create(gpa, try r.int(u64));
        errdefer o.destroy(gpa);
        const start = try r.int(u32);
        const n = try r.int(u32);
        for (0..n) |i| {
            const rec = try r.take(seg.rec_len);
            try o.addRec(gpa, start + @as(u32, @intCast(i)), rec[0..32], std.mem.readInt(u32, rec[32..36], .little));
        }
        for (0..2) |si| {
            const nk = try r.int(u32);
            for (0..nk) |_| {
                const kl = try r.int(u16);
                const key = try r.take(kl);
                const nl = try r.int(u32);
                const raw = try r.take(@as(usize, nl) * 4);
                const gop = try o.maps[si].getOrPut(gpa, key);
                if (gop.found_existing) return error.Corrupt;
                gop.key_ptr.* = try o.kb.allocator().dupe(u8, key);
                gop.value_ptr.* = .empty;
                try gop.value_ptr.ensureTotalCapacityPrecise(gpa, nl);
                for (0..nl) |i| gop.value_ptr.appendAssumeCapacity(std.mem.readInt(u32, raw[i * 4 ..][0..4], .little));
            }
        }
        if (r.at != body.len) return error.Corrupt;
        return o;
    }

    /// Opens the root: drops the legacy in-memory index files, follows `CURRENT` (creating the
    /// first generation), removes orphan generation directories, loads the live one.
    fn openRoot(ix: *Index) !void {
        const io = ix.io;
        const r = ix.root.?;
        var dropped_legacy = false;
        for ([_][]const u8{ "snapshot.bin", "snapshot.bin.tmp", "log.bin", "log.bin.tmp", "log.next.bin", "log.next.bin.tmp", "CURRENT.tmp" }) |name| {
            r.deleteFile(io, name) catch |e| switch (e) {
                error.FileNotFound => continue,
                else => return e,
            };
            if (std.mem.startsWith(u8, name, "snapshot") or std.mem.startsWith(u8, name, "log")) dropped_legacy = true;
        }
        if (dropped_legacy and !builtin.is_test) std.log.info("history: dropped the legacy in-memory index files; the backfill rebuilds the window from the store", .{});
        var cur: ?u64 = null;
        var cb: [64]u8 = undefined;
        if (r.readFile(io, "CURRENT", &cb)) |txt| {
            const t = std.mem.trim(u8, txt, " \n\r\t");
            if (t.len > 1 and t[0] == 'g') cur = std.fmt.parseInt(u64, t[1..], 10) catch null;
            if (cur == null) return error.Corrupt;
        } else |e| if (e != error.FileNotFound) return e;
        // Orphans: a generation built by a reset or adopt that crashed before CURRENT named it.
        {
            var names: std.ArrayList([]u8) = .empty;
            defer {
                for (names.items) |x| ix.gpa.free(x);
                names.deinit(ix.gpa);
            }
            var it = r.iterate();
            while (try it.next(io)) |e| {
                if (e.kind != .directory or e.name.len < 2 or e.name[0] != 'g') continue;
                const g = std.fmt.parseInt(u64, e.name[1..], 10) catch continue;
                if (cur != null and g == cur.?) continue;
                try names.append(ix.gpa, try ix.gpa.dupe(u8, e.name));
            }
            for (names.items) |x| r.deleteTree(io, x) catch {};
        }
        if (cur == null) {
            var st = try ix.freshState(1);
            errdefer st.destroy(ix.gpa, ix.io);
            try ix.writeCurrent(r, 1);
            ix.s = st;
            ix.persisted.store(1, .release);
            return;
        }
        var nb: [32]u8 = undefined;
        var st: State = .{ .gen = cur.? };
        const loaded: anyerror!void = blk: {
            st.dir = r.openDir(io, genName(&nb, cur.?), .{ .iterate = true }) catch |e| break :blk e;
            break :blk ix.loadInto(&st);
        };
        loaded catch |e| {
            st.destroy(ix.gpa, ix.io);
            if (e == error.Crash) return e;
            // Derived data: start a new generation; the node's backfill rebuilds the window.
            std.log.err("history: index generation {d} unusable ({s}); starting a new one", .{ cur.?, @errorName(e) });
            var fresh = try ix.freshState(cur.? + 1);
            errdefer fresh.destroy(ix.gpa, ix.io);
            try ix.writeCurrent(r, fresh.gen);
            r.deleteTree(io, genName(&nb, cur.?)) catch {};
            ix.s = fresh;
            ix.persisted.store(fresh.gen, .release);
            return;
        };
        ix.s = st;
        ix.persisted.store(st.gen, .release);
    }

    /// `load` through a scratch index, so the live state is untouched until the caller swaps.
    fn loadInto(ix: *Index, st: *State) !void {
        var tmp: Index = .{ .gpa = ix.gpa, .io = ix.io, .opts = ix.opts, .fault = ix.fault };
        defer {
            ix.stats.flushes += tmp.stats.flushes;
            ix.stats.rotations += tmp.stats.rotations;
            ix.stats.replayed += tmp.stats.replayed;
        }
        try tmp.load(st);
    }

    /// Loads generation `st` (its `dir` open) as of `meta`, then replays the log chain.
    /// Bounded: maps sealed segments and chunks, reads one open file, replays at most one
    /// segment of records.
    fn load(ix: *Index, st: *State) !void {
        const io = ix.io;
        const gpa = ix.gpa;
        const d = st.dir.?;
        const m = (try readMeta(io, d)) orelse Meta{ .gen = st.gen };
        st.started = m.started != 0;
        st.cp_lo = m.cp_lo;
        st.tx_lo = m.tx_lo;
        st.log_n = m.log_n;
        st.rot = .{ .started = st.started, .cp_next = m.rot_cp_next, .tx_end = m.rot_tx_end, .open_seg = m.open_seg };
        st.cp_next = m.rot_cp_next;
        st.tx_end = m.rot_tx_end;

        var segs: std.ArrayList(u64) = .empty;
        defer segs.deinit(gpa);
        var chunks: std.ArrayList(u64) = .empty;
        defer chunks.deinit(gpa);
        var logs: std.ArrayList(u64) = .empty;
        defer logs.deinit(gpa);
        var junk: std.ArrayList([]u8) = .empty;
        defer {
            for (junk.items) |x| gpa.free(x);
            junk.deinit(gpa);
        }
        {
            var it = d.iterate();
            while (try it.next(io)) |e| {
                if (e.kind != .file) continue;
                const nm = e.name;
                if (std.mem.endsWith(u8, nm, ".tmp")) {
                    try junk.append(gpa, try gpa.dupe(u8, nm));
                } else if (parseName(nm, "s", ".seg")) |x| {
                    try segs.append(gpa, x);
                } else if (parseName(nm, "c", ".cp")) |x| {
                    try chunks.append(gpa, x);
                } else if (parseName(nm, "log-", ".bin")) |x| {
                    try logs.append(gpa, x);
                } else if (parseName(nm, "open-", ".bin")) |x| {
                    if (x != m.log_n) try junk.append(gpa, try gpa.dupe(u8, nm));
                }
            }
        }
        for (junk.items) |x| d.deleteFile(io, x) catch {};
        std.mem.sort(u64, segs.items, {}, std.sort.asc(u64));
        std.mem.sort(u64, chunks.items, {}, std.sort.asc(u64));
        std.mem.sort(u64, logs.items, {}, std.sort.asc(u64));
        var nb: [32]u8 = undefined;

        // Sealed segments: [seg(tx_lo), open_seg) must all be there; anything else is either
        // pruned (below) or a segment the replay rewrites (at or past open_seg).
        const seg_lo = st.tx_lo / seg_txs;
        const seg_hi = if (st.started) m.open_seg else 0;
        var want = seg_lo;
        for (segs.items) |id| {
            if (id < seg_lo or id >= seg_hi) {
                d.deleteFile(io, segName(&nb, id)) catch {};
                continue;
            }
            if (id != want) return error.Corrupt;
            try st.sealed.ensureUnusedCapacity(gpa, 1);
            const mem = try mapFile(io, d, segName(&nb, id), false, null);
            var x: Sealed = .{ .v = undefined, .mem = mem, .mapped = true };
            x.v = seg.View.parse(mem) catch |e| {
                x.release();
                return e;
            };
            if (x.v.seg != id) {
                x.release();
                return error.Corrupt;
            }
            st.sealed.appendAssumeCapacity(x);
            want += 1;
        }
        if (st.started and seg_lo < seg_hi and want != seg_hi) return error.Corrupt;
        // Checkpoint chunks from the floor's up (the replay may add more).
        const ch_lo = st.cp_lo / cp_chunk;
        for (chunks.items) |id| {
            if (!st.started or id < ch_lo) {
                d.deleteFile(io, chunkName(&nb, id)) catch {};
                continue;
            }
            if (st.chunks.items.len != 0 and st.chunks.items[st.chunks.items.len - 1].id + 1 != id) return error.Corrupt;
            try st.chunks.ensureUnusedCapacity(gpa, 1);
            st.chunks.appendAssumeCapacity(.{ .id = id, .mem = try mapFile(io, d, chunkName(&nb, id), true, chunk_bytes), .mapped = true });
        }
        if (st.started and st.cp_lo < st.cp_next) {
            if (st.chunkOf(st.cp_lo) == null or st.chunkOf(st.cp_next - 1) == null) return error.Corrupt;
        }
        // The open segment as of the rotation.
        if (d.readFileAlloc(io, openName(&nb, m.log_n), gpa, .unlimited)) |data| {
            defer gpa.free(data);
            st.open = try ix.readOpen(data);
        } else |e| if (e != error.FileNotFound) return e;

        // Replay: the log chain from log_n (older ones are leftovers of the last rotation).
        std.mem.swap(State, &ix.s, st);
        defer std.mem.swap(State, &ix.s, st);
        var flushed = false;
        var live: ?struct { n: u64, end: usize, len: usize } = null;
        var broken = false;
        for (logs.items) |n| {
            if (n < m.log_n or broken) {
                ix.s.dir.?.deleteFile(io, logName(&nb, n)) catch {};
                continue;
            }
            const data = try ix.s.dir.?.readFileAlloc(io, logName(&nb, n), gpa, .unlimited);
            defer gpa.free(data);
            if (data.len < log_hdr or !std.mem.eql(u8, data[0..8], log_magic) or std.mem.readInt(u64, data[16..24], .little) != n) {
                // A torn header: nothing was ever appended past it.
                ix.s.dir.?.deleteFile(io, logName(&nb, n)) catch {};
                broken = true;
                continue;
            }
            const before = ix.stats.flushes;
            const end = ix.replayLog(data);
            if (ix.stats.flushes != before) flushed = true;
            live = .{ .n = n, .end = end, .len = data.len };
            if (end != data.len) broken = true;
        }
        if (ix.s.started) {
            // A prune before the first rotation: meta holds the floors only.
            ix.s.cp_lo = @max(ix.s.cp_lo, m.cp_lo);
            ix.s.tx_lo = @max(ix.s.tx_lo, m.tx_lo);
            if (ix.s.cp_lo > ix.s.cp_next) ix.s.cp_lo = ix.s.cp_next;
            if (ix.s.tx_lo > ix.s.tx_end) ix.s.tx_lo = ix.s.tx_end;
        }
        if (ix.opts.log != .none) {
            if (live) |l| {
                const f = try ix.s.dir.?.openFile(io, logName(&nb, l.n), .{ .mode = .read_write });
                if (l.end != l.len) {
                    try ix.step();
                    f.setLength(io, l.end) catch |e| {
                        f.close(io);
                        return e;
                    };
                    try f.sync(io);
                }
                ix.s.log = f;
                ix.s.log_end = l.end;
                ix.s.log_n = @max(ix.s.log_n, l.n);
            } else {
                try ix.newLog(&ix.s, ix.s.log_n);
            }
        }
        // A replay that sealed segments rotates now, so the next open starts from them.
        if (flushed or (ix.opts.log == .none and logs.items.len != 0)) try ix.rotate();
    }
};

fn genName(buf: []u8, gen: u64) []const u8 {
    return std.fmt.bufPrint(buf, "g{d}", .{gen}) catch unreachable;
}
fn segName(buf: []u8, id: u64) []const u8 {
    return std.fmt.bufPrint(buf, "s{d}.seg", .{id}) catch unreachable;
}
fn chunkName(buf: []u8, id: u64) []const u8 {
    return std.fmt.bufPrint(buf, "c{d}.cp", .{id}) catch unreachable;
}
fn logName(buf: []u8, n: u64) []const u8 {
    return std.fmt.bufPrint(buf, "log-{d}.bin", .{n}) catch unreachable;
}
fn openName(buf: []u8, n: u64) []const u8 {
    return std.fmt.bufPrint(buf, "open-{d}.bin", .{n}) catch unreachable;
}
fn parseName(name: []const u8, prefix: []const u8, suffix: []const u8) ?u64 {
    if (!std.mem.startsWith(u8, name, prefix) or !std.mem.endsWith(u8, name, suffix)) return null;
    if (name.len <= prefix.len + suffix.len) return null;
    return std.fmt.parseInt(u64, name[prefix.len .. name.len - suffix.len], 10) catch null;
}

/// fsync of a directory. Directories are opened with `.iterate` so they are not O_PATH handles on
/// Linux (fsync on O_PATH is EBADF, which std treats as a programmer bug and panics on).
fn syncDir(io: Io, dir: Io.Dir) void {
    const f: Io.File = .{ .handle = dir.handle, .flags = .{ .nonblocking = false } };
    f.sync(io) catch {};
}

fn putInt(gpa: Allocator, w: *std.ArrayList(u8), comptime T: type, v: T) !void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    try w.appendSlice(gpa, &b);
}

const Rd = struct {
    b: []const u8,
    at: usize = 0,
    fn take(r: *Rd, n: usize) ![]const u8 {
        if (r.b.len - r.at < n) return error.EndOfInput;
        defer r.at += n;
        return r.b[r.at..][0..n];
    }
    fn int(r: *Rd, comptime T: type) !T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
};

/// Every bucket of `key` in `space`, ascending by id, from the sealed, frozen and open segments;
/// buckets wholly below the floor are left out. Event buckets of the in-memory segments are
/// copied into `a` (their positions carry the bucket in the top bits).
fn bucketsIn(s: *const State, a: Allocator, space: Space, key: []const u8) ![]const Bucket {
    if (!s.started) return &.{};
    const si = @intFromEnum(space);
    const h = seg.hashKey(key);
    const floor_tx = s.tx_lo;
    var out: std.ArrayList(Bucket) = .empty;
    for (s.sealed.items) |*x| {
        if ((x.v.seg + 1) * seg_txs <= floor_tx) continue;
        const sv = &x.v.sp[si];
        const i = sv.find(h, key) orelse continue;
        const e = sv.ents(i);
        var j = e[0];
        while (j < e[1]) : (j += 1) {
            const id = if (si == 0) x.v.seg else x.v.seg * seg.ev_per_seg + sv.erel[j];
            if (belowFloor(space, id, floor_tx)) continue;
            try out.append(a, .{ .id = id, .bits = sv.entBits(j) });
        }
    }
    const mems = [2][]const *OpenSeg{ s.frozen.items, if (s.open) |*o| @as([*]const *OpenSeg, @ptrCast(o))[0..1] else &.{} };
    for (mems) |list| for (list) |o| {
        const l = o.maps[si].getPtr(key) orelse continue;
        if (l.items.len == 0) continue;
        if (si == 0) {
            if (!belowFloor(space, o.id, floor_tx)) try out.append(a, .{ .id = o.id, .bits = l.items });
            continue;
        }
        var at: usize = 0;
        while (at < l.items.len) {
            const b = l.items[at] >> 28;
            var end = at;
            while (end < l.items.len and l.items[end] >> 28 == b) end += 1;
            const id = o.id * seg.ev_per_seg + b;
            if (!belowFloor(space, id, floor_tx)) {
                const bits = try a.alloc(u32, end - at);
                for (bits, l.items[at..end]) |*d, v| d.* = v & seg.ev_bit_mask;
                try out.append(a, .{ .id = id, .bits = bits });
            }
            at = end;
        }
    };
    return out.items;
}

fn belowFloor(space: Space, id: u64, floor_tx: u64) bool {
    return switch (space) {
        .tx => (id + 1) * tx_bucket_size <= floor_tx,
        .event => (id + 1) * event_bucket_size <= encodeEventSeq(floor_tx, 0),
    };
}

/// A read view under the index's shared lock. Slices it returns stay valid until `release`.
pub const Reader = struct {
    ix: *Index,
    published: u64,
    scratch: std.heap.ArenaAllocator,

    pub fn release(r: *Reader) void {
        r.scratch.deinit();
        r.ix.lock.unlockShared(r.ix.io);
    }

    fn st(r: *const Reader) *const State {
        return &r.ix.s;
    }

    fn pubHi(r: *const Reader) ?u64 {
        const s = r.st();
        if (!s.nonEmpty()) return null;
        if (r.published == 0 or r.published - 1 < s.cp_lo) return null;
        return @min(s.cp_next - 1, r.published - 1);
    }

    /// Indexed and published checkpoints, inclusive.
    pub fn range(r: *const Reader) ?Range {
        const hi = r.pubHi() orelse return null;
        return .{ .lo = r.st().cp_lo, .hi = hi };
    }

    pub fn checkpointTxs(r: *const Reader, cp: u64) ?CheckpointTxs {
        const s = r.st();
        const hi = r.pubHi() orelse return null;
        if (cp < s.cp_lo or cp > hi) return null;
        const first = s.cpFirst(cp);
        const next = if (cp + 1 < s.cp_next) s.cpFirst(cp + 1) else s.tx_end;
        return .{ .first = first, .count = next - first };
    }

    /// One past the last published transaction.
    fn txEnd(r: *const Reader) u64 {
        const s = r.st();
        const hi = r.pubHi() orelse return s.tx_lo;
        return if (hi + 1 < s.cp_next) s.cpFirst(hi + 1) else s.tx_end;
    }

    pub fn checkpointOfTx(r: *const Reader, tx_seq: u64) ?u64 {
        const s = r.st();
        if (tx_seq < s.tx_lo or tx_seq >= r.txEnd()) return null;
        // Last checkpoint whose first tx_seq <= tx_seq (checkpoints with no transactions share a
        // first with their successor; the holder is the last such one).
        var lo: u64 = s.cp_lo;
        var hi: u64 = s.cp_next;
        while (lo < hi) {
            const mid = lo + (hi - lo) / 2;
            if (s.cpFirst(mid) <= tx_seq) lo = mid + 1 else hi = mid;
        }
        if (lo == s.cp_lo) return null;
        return lo - 1;
    }

    pub fn txRow(r: *const Reader, tx_seq: u64) ?TxRow {
        const s = r.st();
        const cp = r.checkpointOfTx(tx_seq) orelse return null;
        const off: u32 = @intCast(tx_seq % seg_txs);
        const ref = s.segOf(tx_seq) orelse return null;
        var row: TxRow = .{ .tx_seq = tx_seq, .digest = undefined, .checkpoint = cp, .tx_offset = @intCast(tx_seq - s.cpFirst(cp)), .event_count = 0 };
        switch (ref) {
            .sealed => |v| {
                if (!v.has(off)) return null;
                row.digest = v.digest(off).*;
                row.event_count = v.evCount(off);
            },
            .mem => |o| {
                if (!o.has(off)) return null;
                row.digest = o.digest(off).*;
                row.event_count = o.evCount(off);
            },
        }
        return row;
    }

    pub fn txSeqOfDigest(r: *const Reader, digest: *const [32]u8) ?u64 {
        const s = r.st();
        const end = r.txEnd();
        const ok = struct {
            fn f(tx: u64, lo: u64, e: u64) ?u64 {
                return if (tx >= lo and tx < e) tx else null;
            }
        }.f;
        if (s.open) |o| if (o.findDigest(digest)) |off| return ok(o.id * seg_txs + off, s.tx_lo, end);
        var i = s.frozen.items.len;
        while (i > 0) {
            i -= 1;
            const o = s.frozen.items[i];
            if (o.findDigest(digest)) |off| return ok(o.id * seg_txs + off, s.tx_lo, end);
        }
        i = s.sealed.items.len;
        while (i > 0) {
            i -= 1;
            const v = &s.sealed.items[i].v;
            if ((v.seg + 1) * seg_txs <= s.tx_lo) break;
            if (v.findDigest(digest)) |off| return ok(v.seg * seg_txs + off, s.tx_lo, end);
        }
        return null;
    }

    /// Every bucket of key `key` (`[tag][value]`) in `space`, ascending by id. Empty when unknown.
    pub fn buckets(r: *const Reader, space: Space, key: []const u8) []const Bucket {
        const self: *Reader = @constCast(r);
        return bucketsIn(r.st(), self.scratch.allocator(), space, key) catch &.{};
    }
};

test {
    _ = dims;
    _ = seg;
    _ = @import("tests.zig");
    _ = @import("dst.zig");
}
