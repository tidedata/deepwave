//! bulk: the partitioned bulk build of the StateService index's base run.
//!
//! The sort-and-merge build (lsm.zig `Builder.runFromMerge`) spills sorted temp tables of rows
//! drawn from the whole key space and then merges every range from all of them: about two
//! thousand temp tables at mainnet scale, each read by every range's merge in 32 KiB steps (a
//! seek storm on a slow disk, an 11-step heap per row), one sort buffer per thread whatever the
//! memory limit, and `build_groups` passes over the live set to bound the temp space.
//!
//! Here the rows are split by key range before anything is sorted:
//!
//! 1. **Rows.** Every producer (a restore's fetch thread, or a thread walking a part of the
//!    restore image or of the live table) turns its objects into rows in a lane buffer. A full
//!    lane groups its rows by partition (`partOf`: 256 owner sub-ranges per owner kind, 256 for
//!    the balance table, one for the coin table; each of lsm's 33 ranges is a run of partitions)
//!    and appends one compressed frame per partition to that partition's file. Appends only: the
//!    disk sees one sequential stream per partition file.
//! 2. **Sort.** One worker per range, largest range first: each partition file is read front to
//!    back once, sorted in memory (`sortEnts`: common prefixes skipped, eight key bytes cached
//!    per row) and added to the range's table in key order. The tables are the final base run:
//!    the same 33 tables, byte for byte, as the sort-and-merge build writes, with no merge and
//!    no compaction afterwards. A partition that does not fit the worker's share of the memory
//!    budget (one owner with tens of millions of dynamic fields) is sorted in chunks that are
//!    written as temp tables and merged, a handful of them, not thousands.
//! 3. **Install.** The base run and the watermark go into the manifest in one write.
//!
//! One pass over the live set, temp space of every row once (each range's partition files are
//! removed when its table is durable), memory bounded by `Options.build_mem_bytes`.
//!
//! **Resume.** `index/load.state` (two checksummed slots, written alternately) holds the phase,
//! the durable length of every partition file, the source parts whose rows are complete and the
//! finished ranges; the manifest holds a pending build with `lsm.pending_tip`, which the
//! sort-and-merge build (and a binary without this file) resets. A crash while rows arrive
//! resumes at the last durable cut (every `cut_every` source parts): frames carry their source
//! part and the attempt that wrote them, so the frames of a part that was cut short are ignored
//! when the part is walked again. A crash in the sort resumes at the first unfinished range.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const store = @import("store");
const lsm = @import("lsm.zig");
const root = @import("root.zig");

const Val = lsm.Val;
const Atomic = std.atomic.Value;
const Fd = store.io.Fd;

pub const RowsFn = *const fn (Allocator, []const u8, i2, lsm.Emit) anyerror!void;

// ---------------------------------------------------------------------------- partitions

/// Partitions in key order: 0..255 the address owners by first owner byte, 256..511 the object
/// owners, 512..767 the balance table by first owner byte, 768 the coin table.
pub const n_parts: u32 = 769;
const src_parts = lsm.build_parts;

pub fn partOf(key: []const u8) u32 {
    const b1: u32 = if (key.len > 1) key[1] else 0;
    return switch (key[0]) {
        0 => ((b1 & 1) << 8) | @as(u32, if (key.len > 2) key[2] else 0),
        1 => 512 + b1,
        else => 768,
    };
}

/// The range (`lsm.rangeOf`) partition `q` belongs to.
pub fn rangeOfPart(q: u32) u32 {
    return if (q >= 512) 32 else q >> 4;
}

/// The partitions `[lo, hi)` of range `r`.
fn rangeParts(r: u32) struct { lo: u32, hi: u32 } {
    if (r == 32) return .{ .lo = 512, .hi = n_parts };
    return .{ .lo = r * 16, .hi = r * 16 + 16 };
}

fn partName(buf: []u8, q: u32) []const u8 {
    return std.fmt.bufPrint(buf, "index/p{d}.rows", .{q}) catch unreachable;
}
fn chunkName(buf: []u8, q: u32, k: u32) []const u8 {
    return std.fmt.bufPrint(buf, "index/x{d}-{d}.tmp", .{ q, k }) catch unreachable;
}
const state_name = "index/load.state";

// ---------------------------------------------------------------------------- state file

const state_slot = 32 << 10;
const state_magic: u64 = 0x314b4c5542495a55; // "UZIBULK1"
const sum_seed: u64 = 0x2b;

pub const State = struct {
    counter: u64 = 0,
    phase: Phase = .rows,
    /// The checkpoint of the live set (`lsm.pending_tip` while a stream has not finished).
    tip: u64 = lsm.pending_tip,
    /// Bumped at every resume while rows arrive: frames of an earlier attempt count only for
    /// the source parts that attempt finished.
    attempt: u16 = 0,
    /// Table numbers of the ranges: `gen0 + r` (set when the rows are sealed).
    gen0: u64 = 0,
    objects: u64 = 0,
    /// Source parts whose rows are complete, and the attempt that wrote each.
    src_done: u64 = 0,
    accept: [src_parts]u16 = @splat(0),
    ranges_done: u64 = 0,
    range_entries: [lsm.n_ranges]u64 = @splat(0),
    /// Per partition file: the durable length, and its rows' bytes and count (upper bounds:
    /// they include frames a resume ignores).
    len: [n_parts]u64 = @splat(0),
    raw: [n_parts]u64 = @splat(0),
    rows: [n_parts]u64 = @splat(0),

    pub const Phase = enum(u8) { rows = 0, sort = 1 };

    fn encode(s: *const State, buf: *[state_slot]u8) void {
        @memset(buf, 0);
        var p: usize = 0;
        const W = struct {
            fn int(b: *[state_slot]u8, pos: *usize, comptime T: type, v: T) void {
                std.mem.writeInt(T, b[pos.*..][0..@sizeOf(T)], v, .little);
                pos.* += @sizeOf(T);
            }
        };
        W.int(buf, &p, u64, state_magic);
        W.int(buf, &p, u64, s.counter);
        W.int(buf, &p, u8, @backingInt(s.phase));
        W.int(buf, &p, u64, s.tip);
        W.int(buf, &p, u16, s.attempt);
        W.int(buf, &p, u64, s.gen0);
        W.int(buf, &p, u64, s.objects);
        W.int(buf, &p, u64, s.src_done);
        for (s.accept) |a| W.int(buf, &p, u16, a);
        W.int(buf, &p, u64, s.ranges_done);
        for (s.range_entries) |e| W.int(buf, &p, u64, e);
        W.int(buf, &p, u32, n_parts);
        for (0..n_parts) |q| {
            W.int(buf, &p, u64, s.len[q]);
            W.int(buf, &p, u64, s.raw[q]);
            W.int(buf, &p, u64, s.rows[q]);
        }
        std.debug.assert(p <= state_slot - 8);
        std.mem.writeInt(u64, buf[state_slot - 8 ..][0..8], store.checksum.hash(sum_seed, buf[0 .. state_slot - 8]), .little);
    }

    fn decode(s: *State, buf: *const [state_slot]u8) bool {
        if (store.checksum.hash(sum_seed, buf[0 .. state_slot - 8]) != std.mem.readInt(u64, buf[state_slot - 8 ..][0..8], .little)) return false;
        var p: usize = 0;
        const R = struct {
            fn int(b: *const [state_slot]u8, pos: *usize, comptime T: type) T {
                defer pos.* += @sizeOf(T);
                return std.mem.readInt(T, b[pos.*..][0..@sizeOf(T)], .little);
            }
        };
        if (R.int(buf, &p, u64) != state_magic) return false;
        s.* = .{};
        s.counter = R.int(buf, &p, u64);
        s.phase = switch (R.int(buf, &p, u8)) {
            0 => .rows,
            1 => .sort,
            else => return false,
        };
        s.tip = R.int(buf, &p, u64);
        s.attempt = R.int(buf, &p, u16);
        s.gen0 = R.int(buf, &p, u64);
        s.objects = R.int(buf, &p, u64);
        s.src_done = R.int(buf, &p, u64);
        for (&s.accept) |*a| a.* = R.int(buf, &p, u16);
        s.ranges_done = R.int(buf, &p, u64);
        for (&s.range_entries) |*e| e.* = R.int(buf, &p, u64);
        if (R.int(buf, &p, u32) != n_parts) return false;
        for (0..n_parts) |q| {
            s.len[q] = R.int(buf, &p, u64);
            s.raw[q] = R.int(buf, &p, u64);
            s.rows[q] = R.int(buf, &p, u64);
        }
        return true;
    }

    /// The newest valid slot of the state file and the slot to write next (null: no state).
    fn load(gpa: Allocator, files: *lsm.Files) ?struct { st: *State, next: u1 } {
        const fd = files.open(state_name, false) catch return null;
        defer files.close(fd);
        const size = files.rio.size(fd) catch return null;
        if (size < 2 * state_slot) return null;
        const buf = gpa.create([state_slot]u8) catch return null;
        defer gpa.destroy(buf);
        const best = gpa.create(State) catch return null;
        const cur = gpa.create(State) catch {
            gpa.destroy(best);
            return null;
        };
        defer gpa.destroy(cur);
        var found: ?u1 = null;
        for (0..2) |i| {
            files.rio.read(fd, i * state_slot, buf) catch continue;
            if (!cur.decode(buf)) continue;
            if (found == null or cur.counter > best.counter) {
                best.* = cur.*;
                found = @intCast(i);
            }
        }
        const slot = found orelse {
            gpa.destroy(best);
            return null;
        };
        return .{ .st = best, .next = slot +% 1 };
    }

    /// The state of a pending partitioned build (the caller owns it), for the index's file
    /// cleanup at open.
    pub fn read(gpa: Allocator, files: *lsm.Files) ?*State {
        const l = load(gpa, files) orelse return null;
        return l.st;
    }

    /// Whether file `name` (in `index/`) belongs to this build: the state file, the partition
    /// files of unfinished ranges, the tables of finished ones.
    pub fn keeps(s: *const State, name: []const u8) bool {
        if (std.mem.eql(u8, name, "load.state")) return true;
        if (std.mem.endsWith(u8, name, ".rows") and name.len > 6 and name[0] == 'p') {
            const q = std.fmt.parseInt(u32, name[1 .. name.len - 5], 10) catch return false;
            if (q >= n_parts) return false;
            return s.ranges_done & (@as(u64, 1) << @intCast(rangeOfPart(q))) == 0;
        }
        if (s.phase == .sort and std.mem.endsWith(u8, name, ".tbl")) {
            const g = std.fmt.parseInt(u64, name[0 .. name.len - 4], 10) catch return false;
            if (g < s.gen0 or g >= s.gen0 + lsm.n_ranges) return false;
            return s.ranges_done & (@as(u64, 1) << @intCast(g - s.gen0)) != 0;
        }
        return false;
    }
};

// ---------------------------------------------------------------------------- frames

/// A frame of a partition file: this header, then the rows (`codec` 1: one zstd frame).
/// Rows are records `klen u16 || op u8 || vlen u8 || key || val`.
const frame_hdr = 32;
const frame_magic: u32 = 0x3152425a; // "ZBR1"
const max_frame: u32 = 1 << 30;
const rec_hdr = 4;

const Frame = struct {
    src: u16,
    attempt: u16,
    raw_len: u32,
    rows: u32,
    codec: u8,
    payload: []const u8,
};

const ZCCtx = opaque {};
extern fn ZSTD_createCCtx() ?*ZCCtx;
extern fn ZSTD_freeCCtx(cctx: *ZCCtx) usize;
extern fn ZSTD_compressCCtx(cctx: *ZCCtx, dst: [*]u8, dst_cap: usize, src: [*]const u8, src_size: usize, level: c_int) usize;
extern fn ZSTD_isError(code: usize) c_uint;

fn frameSum(hdr: []const u8, payload: []const u8) u64 {
    return store.checksum.hash(store.checksum.hash(sum_seed, hdr[0..24]), payload);
}

/// Reads the frames of one partition file front to back through one buffer.
const FrameReader = struct {
    gpa: Allocator,
    rio: *store.RealIo,
    fd: Fd,
    off: u64 = 0,
    end: u64,
    buf: *[]u8,
    start: usize = 0,
    filled: usize = 0,
    read_bytes: usize,

    /// At least `need` bytes buffered from `start`. False at the end of the file.
    fn fill(fr: *FrameReader, need: usize) !bool {
        if (fr.filled - fr.start >= need) return true;
        const have = fr.filled - fr.start;
        const left = fr.end - fr.off;
        if (have + left < need) {
            if (have == 0 and left == 0) return false;
            return error.Corrupt;
        }
        if (fr.buf.len < need or fr.buf.len < fr.read_bytes) {
            const want = @max(need, fr.read_bytes);
            const nb = try fr.gpa.alloc(u8, want);
            @memcpy(nb[0..have], fr.buf.*[fr.start..fr.filled]);
            fr.gpa.free(fr.buf.*);
            fr.buf.* = nb;
        } else if (fr.start != 0) {
            std.mem.copyForwards(u8, fr.buf.*[0..have], fr.buf.*[fr.start..fr.filled]);
        }
        fr.start = 0;
        fr.filled = have;
        const n: usize = @intCast(@min(fr.buf.len - have, left));
        try fr.rio.read(fr.fd, fr.off, fr.buf.*[have..][0..n]);
        fr.off += n;
        fr.filled += n;
        return true;
    }

    /// The next frame (its payload is valid until the next call), checksum verified.
    fn next(fr: *FrameReader) !?Frame {
        if (!try fr.fill(frame_hdr)) return null;
        var h: [frame_hdr]u8 = undefined;
        @memcpy(&h, fr.buf.*[fr.start..][0..frame_hdr]);
        if (std.mem.readInt(u32, h[0..4], .little) != frame_magic) return error.Corrupt;
        const raw_len = std.mem.readInt(u32, h[8..12], .little);
        const disk_len = std.mem.readInt(u32, h[12..16], .little);
        if (raw_len > max_frame or disk_len > max_frame or h[20] > 1) return error.Corrupt;
        if (!try fr.fill(frame_hdr + disk_len)) return error.Corrupt;
        const payload = fr.buf.*[fr.start + frame_hdr ..][0..disk_len];
        if (frameSum(&h, payload) != std.mem.readInt(u64, h[24..32], .little)) return error.Corrupt;
        fr.start += frame_hdr + disk_len;
        return .{
            .src = std.mem.readInt(u16, h[4..6], .little),
            .attempt = std.mem.readInt(u16, h[6..8], .little),
            .raw_len = raw_len,
            .rows = std.mem.readInt(u32, h[16..20], .little),
            .codec = h[20],
            .payload = payload,
        };
    }
};

// ---------------------------------------------------------------------------- sort

/// One row of a partition being sorted: its record's offset in the rows buffer, its key
/// length, and eight key bytes at the depth the sort works at.
pub const Ent = extern struct { cache: u64, off: u32, klen: u16, _pad: u16 = 0 };

fn keyOf(raw: []const u8, e: Ent) []const u8 {
    return raw[e.off + rec_hdr ..][0..e.klen];
}

fn valOf(raw: []const u8, e: Ent) Val {
    const op: lsm.Op = @fromBackingInt(@intCast(raw[e.off + 2]));
    const vlen = raw[e.off + 3];
    var v: Val = .{ .op = op, .len = vlen };
    @memcpy(v.b[0..vlen], raw[e.off + rec_hdr + e.klen ..][0..vlen]);
    return v;
}

/// Key bytes `[d, d + 8)` as a big-endian integer, zero-padded past the key's end.
fn cacheAt(raw: []const u8, e: Ent, d: usize) u64 {
    const k = keyOf(raw, e);
    if (k.len >= d + 8) return std.mem.readInt(u64, k[d..][0..8], .big);
    var b: [8]u8 = @splat(0);
    if (k.len > d) @memcpy(b[0 .. k.len - d], k[d..]);
    return std.mem.readInt(u64, &b, .big);
}

fn lessCache(_: void, a: Ent, b: Ent) bool {
    return a.cache < b.cache;
}

const SmallCtx = struct {
    raw: []const u8,
    d: usize,
    fn lt(c: SmallCtx, a: Ent, b: Ent) bool {
        return switch (std.mem.order(u8, keyOf(c.raw, a)[c.d..], keyOf(c.raw, b)[c.d..])) {
            .lt => true,
            .gt => false,
            .eq => a.off < b.off,
        };
    }
};

fn lessEnded(_: void, a: Ent, b: Ent) bool {
    if (a.klen != b.klen) return a.klen < b.klen;
    return a.off < b.off;
}

/// Sorts `es` by key (equal keys in arrival order, by `off`). Every key is at least `depth`
/// bytes long and all share their first `depth` bytes. Per level: the common prefix of the
/// group is skipped, then the rows are ordered by the next eight key bytes as one integer and
/// only rows that tie there go a level deeper, so a long shared prefix (one owner's rows, one
/// type's dynamic fields) is compared once per level, not once per comparison.
pub fn sortEnts(raw: []const u8, es: []Ent, depth: usize) void {
    if (es.len < 2) return;
    if (es.len <= 24) {
        std.sort.insertion(Ent, es, SmallCtx{ .raw = raw, .d = depth }, SmallCtx.lt);
        return;
    }
    var d = depth;
    {
        const first = keyOf(raw, es[0])[d..];
        var l = first.len;
        for (es[1..]) |e| {
            if (l == 0) break;
            const k = keyOf(raw, e)[d..];
            const m = @min(l, k.len);
            l = std.mem.findDiff(u8, first[0..m], k[0..m]) orelse m;
        }
        d += l;
    }
    for (es) |*e| e.cache = cacheAt(raw, e.*, d);
    std.sort.pdq(Ent, es, {}, lessCache);
    var i: usize = 0;
    while (i < es.len) {
        var j = i + 1;
        while (j < es.len and es[j].cache == es[i].cache) j += 1;
        if (j - i > 1) sortTied(raw, es[i..j], d);
        i = j;
    }
}

/// Rows whose eight bytes at `d` tie. A key that ends inside those bytes is a prefix of every
/// longer key of the group (the padding is zeros), so the ended keys come first, shortest first;
/// the rest are sorted from `d + 8`.
fn sortTied(raw: []const u8, g: []Ent, d: usize) void {
    var n_end: usize = 0;
    for (g, 0..) |e, i| if (e.klen <= d + 8) {
        std.mem.swap(Ent, &g[n_end], &g[i]);
        n_end += 1;
    };
    if (n_end > 1) std.sort.pdq(Ent, g[0..n_end], {}, lessEnded);
    sortEnts(raw, g[n_end..], d + 8);
}

// ---------------------------------------------------------------------------- loader

/// Tests: the build fails with error.TestCrash at this point (a crash; the test then reopens
/// the index).
pub const TestCrash = union(enum) {
    /// After this many source parts finished in this process (a walk).
    rows_parts: u32,
    /// After the rows are sealed, before any range is sorted.
    sealed,
    /// After this many ranges finished in this process.
    ranges: u32,
    /// Inside the n-th range started in this process, after its first partition.
    mid_range: u32,
    /// After every range, before the base run is installed.
    before_install,
};
pub var test_crash: ?TestCrash = null;
/// Tests: the bytes a sort worker may hold (forces the chunked sort on small inputs).
pub var test_sort_cap: ?usize = null;
/// Source parts between two durable cuts while rows arrive (tests lower it).
pub var cut_every: u32 = 8;
/// Bytes of a partition file written before they are pushed to disk and out of the page cache.
const pace_bytes = 4 << 20;
const lane_slack = 64 << 10;
const no_fd: Fd = std.math.maxInt(Fd);

const Ref = extern struct { off: u32, part: u16, _pad: u16 = 0 };

const Lane = struct {
    gpa: Allocator,
    lock: lsm.SpinLock = .{},
    arena: std.heap.ArenaAllocator,
    /// The lane's rows as records, in arrival order, and where each starts.
    recs: std.ArrayList(u8) = .empty,
    idx: std.ArrayList(Ref) = .empty,
    /// The rows grouped by partition (flush), and one frame being built.
    grouped: std.ArrayList(u8) = .empty,
    zbuf: std.ArrayList(u8) = .empty,
    cctx: ?*ZCCtx = null,
    /// The source part this lane's rows belong to, and the objects it took from it.
    src: u16 = 0,
    n: u64 = 0,
    bad: ?anyerror = null,

    fn deinit(ln: *Lane) void {
        ln.arena.deinit();
        ln.recs.deinit(ln.gpa);
        ln.idx.deinit(ln.gpa);
        ln.grouped.deinit(ln.gpa);
        ln.zbuf.deinit(ln.gpa);
        if (ln.cctx) |c| _ = ZSTD_freeCCtx(c);
        ln.* = .{ .gpa = ln.gpa, .arena = .init(ln.gpa) };
    }

    fn emit(ctx: *anyopaque, key: []const u8, val: Val) anyerror!void {
        const ln: *Lane = @ptrCast(@alignCast(ctx));
        if (key.len == 0 or key.len > std.math.maxInt(u16)) return error.KeyTooLong;
        const off = ln.recs.items.len;
        if (off > std.math.maxInt(u32) - (1 << 20)) return error.LaneTooLarge;
        var h: [rec_hdr]u8 = undefined;
        std.mem.writeInt(u16, h[0..2], @intCast(key.len), .little);
        h[2] = @backingInt(val.op);
        h[3] = val.len;
        try ln.recs.appendSlice(ln.gpa, &h);
        try ln.recs.appendSlice(ln.gpa, key);
        try ln.recs.appendSlice(ln.gpa, val.bytes());
        try ln.idx.append(ln.gpa, .{ .off = @intCast(off), .part = @intCast(partOf(key)) });
    }
};

const Part = struct {
    fd: Atomic(Fd) = .init(no_fd),
    open_lock: lsm.SpinLock = .{},
    len: Atomic(u64) = .init(0),
    raw: Atomic(u64) = .init(0),
    rows: Atomic(u64) = .init(0),
    paced: Atomic(u64) = .init(0),
    pacing: Atomic(bool) = .init(false),
    /// Length at the last sync (a durable cut skips unchanged files).
    synced: u64 = 0,
};

pub const Loader = struct {
    db: *lsm.Db,
    gpa: Allocator,
    files: *lsm.Files,
    rows_fn: RowsFn,
    st: *State,
    st_fd: Fd,
    st_slot: u1 = 0,
    /// Guards `st` and its file.
    st_lock: root.RwLock = .{},
    budget: usize,
    /// Bytes of rows one lane holds before it flushes.
    staging: usize,
    threads: usize,
    lanes: []Lane,
    parts: []Part,
    /// Lane flushes hold it shared; a durable cut holds it exclusively, so every frame below a
    /// recorded length is complete.
    gate: root.RwLock = .{},
    objects: Atomic(u64) = .init(0),
    /// Frames written so far (progress).
    frames: Atomic(u64) = .init(0),
    parts_since_cut: u32 = 0,
    parts_this_run: u32 = 0,
    ranges_this_run: Atomic(u32) = .init(0),
    ranges_started: Atomic(u32) = .init(0),
    resumed_src: u32 = 0,
    resumed_ranges: u32 = 0,
    /// Sorted chunks written for partitions over a worker's share of the budget.
    chunks: Atomic(u32) = .init(0),
    t0_ms: u64,
    rows_ms: u64 = 0,
    temp_bytes: u64 = 0,
    /// What the phases held of the budget (`lsm.Builder.Report`).
    lane_bytes: u64 = 0,
    sort_bytes: Atomic(u64) = .init(0),
    walkers: u32 = 0,
    sort_workers: u32 = 0,

    // ------------------------------------------------------------ open

    fn create(db: *lsm.Db, rows_fn: RowsFn, st: *State) !*Loader {
        const gpa = db.gpa;
        const l = try gpa.create(Loader);
        errdefer gpa.destroy(l);
        const lanes = try gpa.alloc(Lane, src_parts);
        errdefer gpa.free(lanes);
        for (lanes) |*ln| ln.* = .{ .gpa = gpa, .arena = .init(gpa) };
        const parts = try gpa.alloc(Part, n_parts);
        errdefer gpa.free(parts);
        for (parts) |*p| p.* = .{};
        const cpus = std.Thread.getCpuCount() catch 4;
        l.* = .{
            .db = db,
            .gpa = gpa,
            .files = db.files.?,
            .rows_fn = rows_fn,
            .st = st,
            .st_fd = no_fd,
            .budget = @max(db.opts.build_mem_bytes, 8 << 20),
            .staging = 0,
            .threads = if (db.opts.build_threads != 0) db.opts.build_threads else @min(cpus, 32),
            .lanes = lanes,
            .parts = parts,
            .t0_ms = lsm.nowMs(),
        };
        return l;
    }

    /// The smallest lane buffer: below it a lane's frames are too small to compress or write well.
    const min_staging = 256 << 10;

    /// The lane buffer for `lanes` producers: a fifth of the budget between them (a lane holds
    /// its rows, the same rows grouped, at worst one frame of all of them, and 8 bytes a row),
    /// at most 32 MiB and `cap`.
    fn stagingFor(l: *const Loader, lanes: usize, cap: usize) usize {
        const top = @min(32 << 20, if (cap != 0) cap else l.db.opts.build_chunk_bytes);
        return std.math.clamp(l.budget / (5 * @max(lanes, 1)), @min(min_staging, top), top);
    }

    /// Walkers the budget has room for: each needs five times the smallest lane buffer. More
    /// threads than that (32 by default on a large box, a budget of a few MiB) held more in
    /// their lanes than the budget.
    fn walkersFor(l: *const Loader) usize {
        return std.math.clamp(l.budget / (5 * min_staging), 1, @min(l.threads, src_parts));
    }

    /// A new build: the index is emptied, the manifest holds a pending build no tip matches.
    fn fresh(db: *lsm.Db, rows_fn: RowsFn, tip: u64) !*Loader {
        if (!db.onDisk()) return error.IndexNotOnDisk;
        try db.reset();
        db.man.build = .{ .tip = lsm.pending_tip, .groups = 1 };
        try db.writeManifest();
        lsm.raiseFdLimit();
        const st = try db.gpa.create(State);
        st.* = .{ .tip = tip };
        const l = create(db, rows_fn, st) catch |e| {
            db.gpa.destroy(st);
            return e;
        };
        errdefer l.release();
        l.st_fd = try l.files.open(state_name, true);
        try l.files.rio.truncate(l.st_fd, 2 * state_slot);
        try l.writeState();
        return l;
    }

    /// A stream's build (rows arrive through `put` from any thread, the tip is known at
    /// `finish`). `chunk` caps a lane's buffer (0: the db's build_chunk_bytes).
    pub fn begin(db: *lsm.Db, rows_fn: RowsFn, chunk: usize) !*Loader {
        const l = try fresh(db, rows_fn, lsm.pending_tip);
        l.staging = l.stagingFor(16, chunk);
        return l;
    }

    /// The pending build of live set `tip` if there is one, else a new one.
    fn open(db: *lsm.Db, rows_fn: RowsFn, tip: u64) !*Loader {
        if (!db.onDisk()) return error.IndexNotOnDisk;
        const pending = if (db.man.build) |b| b.tip == lsm.pending_tip else false;
        if (pending and db.runs.items.len == 0) if (State.load(db.gpa, db.files.?)) |ld| {
            if (ld.st.tip == tip and ld.st.attempt < std.math.maxInt(u16)) {
                if (resumeFrom(db, rows_fn, ld.st, ld.next)) |l| return l else |e| switch (e) {
                    error.OutOfMemory => return e,
                    else => std.log.warn("state index: the pending build cannot be resumed ({s}); starting over", .{@errorName(e)}),
                }
            } else db.gpa.destroy(ld.st);
        };
        return fresh(db, rows_fn, tip);
    }

    fn resumeFrom(db: *lsm.Db, rows_fn: RowsFn, st: *State, next: u1) !*Loader {
        errdefer db.gpa.destroy(st);
        lsm.raiseFdLimit();
        const l = try create(db, rows_fn, st);
        errdefer {
            l.st = undefined;
            l.releaseKeepState();
        }
        l.st_slot = next;
        l.st_fd = try l.files.open(state_name, false);
        l.resumed_src = @popCount(st.src_done);
        l.resumed_ranges = @popCount(st.ranges_done);
        if (st.phase == .rows) {
            // Everything past the last durable cut goes (it may be torn); the frames below it
            // of parts that were not finished are skipped by their attempt.
            for (l.parts, 0..) |*p, q| {
                var nb: [64]u8 = undefined;
                const name = partName(&nb, @intCast(q));
                if (st.len[q] == 0) {
                    l.files.remove(name);
                    continue;
                }
                const fd = try l.files.open(name, false);
                p.fd.store(fd, .release);
                const size = try l.files.rio.size(fd);
                if (size < st.len[q]) return error.Corrupt;
                if (size > st.len[q]) try l.files.rio.truncate(fd, st.len[q]);
                p.len.store(st.len[q], .monotonic);
                p.raw.store(st.raw[q], .monotonic);
                p.rows.store(st.rows[q], .monotonic);
                p.paced.store(st.len[q], .monotonic);
                p.synced = st.len[q];
            }
            st.attempt += 1;
            try l.writeState();
        }
        return l;
    }

    fn releaseKeepState(l: *Loader) void {
        const gpa = l.gpa;
        for (l.lanes) |*ln| ln.deinit();
        gpa.free(l.lanes);
        for (l.parts) |*p| {
            const fd = p.fd.load(.acquire);
            if (fd != no_fd) l.files.close(fd);
        }
        gpa.free(l.parts);
        if (l.st_fd != no_fd) l.files.close(l.st_fd);
        gpa.destroy(l);
    }

    fn release(l: *Loader) void {
        const st = l.st;
        const gpa = l.gpa;
        l.releaseKeepState();
        gpa.destroy(st);
    }

    /// Frees the loader. An unfinished build stays on disk for a resume.
    pub fn destroy(l: *Loader) void {
        l.release();
    }

    fn stopped(l: *const Loader) bool {
        if (l.db.build_stop) |x| return x.load(.acquire);
        return false;
    }

    /// Caller holds `st_lock` (or is the only thread).
    fn writeState(l: *Loader) !void {
        l.st.counter += 1;
        const buf = try l.gpa.create([state_slot]u8);
        defer l.gpa.destroy(buf);
        l.st.encode(buf);
        try l.files.rio.writeSync(l.st_fd, @as(u64, l.st_slot) * state_slot, buf);
        l.st_slot +%= 1;
    }

    // ------------------------------------------------------------ rows

    /// The rows of one live object (BCS Object) into lane `lane` (any thread may use any lane;
    /// one thread per lane is the fast path).
    pub fn put(l: *Loader, lane: usize, raw: []const u8) !void {
        const ln = &l.lanes[lane % l.lanes.len];
        ln.lock.lock();
        defer ln.lock.unlock();
        if (ln.bad) |e| return e;
        l.putLocked(ln, raw) catch |e| {
            ln.bad = e;
            return e;
        };
    }

    fn putLocked(l: *Loader, ln: *Lane, raw: []const u8) !void {
        if (ln.recs.capacity == 0) try ln.recs.ensureTotalCapacityPrecise(l.gpa, l.staging + lane_slack);
        _ = ln.arena.reset(.retain_capacity);
        try l.rows_fn(ln.arena.allocator(), raw, 1, .{ .ctx = ln, .f = Lane.emit });
        ln.n += 1;
        _ = l.objects.fetchAdd(1, .monotonic);
        if (ln.recs.items.len >= l.staging) try l.flushLane(ln);
    }

    fn recLen(recs: []const u8, off: usize) usize {
        return rec_hdr + @as(usize, std.mem.readInt(u16, recs[off..][0..2], .little)) + recs[off + 3];
    }

    /// Groups the lane's rows by partition and appends one frame per partition. Lane lock held.
    fn flushLane(l: *Loader, ln: *Lane) !void {
        const refs = ln.idx.items;
        if (refs.len == 0) return;
        l.gate.lockShared();
        defer l.gate.unlockShared();
        const recs = ln.recs.items;
        // bytes and rows per partition, then each partition's start in `grouped`
        var start: [n_parts + 1]u32 = @splat(0);
        var count: [n_parts]u32 = @splat(0);
        for (refs) |r| {
            start[r.part + 1] += @intCast(recLen(recs, r.off));
            count[r.part] += 1;
        }
        for (1..n_parts + 1) |q| start[q] += start[q - 1];
        if (ln.grouped.capacity < recs.len) try ln.grouped.ensureTotalCapacityPrecise(l.gpa, recs.len);
        ln.grouped.items.len = recs.len;
        var pos: [n_parts]u32 = start[0..n_parts].*;
        for (refs) |r| {
            const n = recLen(recs, r.off);
            @memcpy(ln.grouped.items[pos[r.part]..][0..n], recs[r.off..][0..n]);
            pos[r.part] += @intCast(n);
        }
        for (0..n_parts) |q| {
            if (count[q] == 0) continue;
            try l.writeFrame(ln, @intCast(q), ln.grouped.items[start[q]..start[q + 1]], count[q]);
        }
        ln.recs.clearRetainingCapacity();
        ln.idx.clearRetainingCapacity();
    }

    fn writeFrame(l: *Loader, ln: *Lane, q: u32, rows: []const u8, n_rows: u32) !void {
        const bound = store.zstd_c.compressBound(rows.len);
        if (ln.zbuf.capacity < frame_hdr + bound) try ln.zbuf.ensureTotalCapacityPrecise(l.gpa, frame_hdr + bound);
        ln.zbuf.items.len = frame_hdr + bound;
        const c = ln.cctx orelse blk: {
            const c = ZSTD_createCCtx() orelse return error.OutOfMemory;
            ln.cctx = c;
            break :blk c;
        };
        const out = ln.zbuf.items;
        var n = ZSTD_compressCCtx(c, out.ptr + frame_hdr, bound, rows.ptr, rows.len, lsm.temp_level);
        var codec: u8 = 1;
        if (ZSTD_isError(n) != 0 or n >= rows.len) {
            @memcpy(out[frame_hdr..][0..rows.len], rows);
            n = rows.len;
            codec = 0;
        }
        const h = out[0..frame_hdr];
        @memset(h, 0);
        std.mem.writeInt(u32, h[0..4], frame_magic, .little);
        std.mem.writeInt(u16, h[4..6], ln.src, .little);
        std.mem.writeInt(u16, h[6..8], l.st.attempt, .little);
        std.mem.writeInt(u32, h[8..12], @intCast(rows.len), .little);
        std.mem.writeInt(u32, h[12..16], @intCast(n), .little);
        std.mem.writeInt(u32, h[16..20], n_rows, .little);
        h[20] = codec;
        std.mem.writeInt(u64, h[24..32], frameSum(h, out[frame_hdr..][0..n]), .little);
        try l.appendFrame(q, out[0 .. frame_hdr + n], rows.len, n_rows);
    }

    fn partFd(l: *Loader, q: u32, create_it: bool) !Fd {
        const p = &l.parts[q];
        var fd = p.fd.load(.acquire);
        if (fd != no_fd) return fd;
        p.open_lock.lock();
        defer p.open_lock.unlock();
        fd = p.fd.load(.acquire);
        if (fd != no_fd) return fd;
        var nb: [64]u8 = undefined;
        fd = try l.files.open(partName(&nb, q), create_it);
        p.fd.store(fd, .release);
        return fd;
    }

    fn closePart(l: *Loader, q: u32) void {
        const p = &l.parts[q];
        const fd = p.fd.swap(no_fd, .acq_rel);
        if (fd != no_fd) l.files.close(fd);
    }

    /// Appends one frame to partition `q`'s file. The offset is reserved first, so lanes never
    /// wait for each other.
    fn appendFrame(l: *Loader, q: u32, frame: []const u8, raw: usize, n_rows: u32) !void {
        const p = &l.parts[q];
        const fd = try l.partFd(q, true);
        const off = p.len.fetchAdd(frame.len, .monotonic);
        try l.files.rio.write(fd, off, frame);
        _ = p.raw.fetchAdd(raw, .monotonic);
        _ = p.rows.fetchAdd(n_rows, .monotonic);
        _ = l.frames.fetchAdd(1, .monotonic);
        // Flush pacing, as lsm.TableWriter: written rows go to disk and out of the page cache.
        const end = off + frame.len;
        const paced = p.paced.load(.monotonic);
        if (end > paced and end - paced >= pace_bytes and p.pacing.cmpxchgStrong(false, true, .acquire, .monotonic) == null) {
            l.files.rio.dropCache(fd, paced, end - paced, true);
            p.paced.store(end, .monotonic);
            p.pacing.store(false, .release);
        }
    }

    /// A durable cut: every partition file synced and its length recorded with the state. Holds
    /// the gate, so no frame is half written below a recorded length. Caller holds `st_lock`.
    fn cut(l: *Loader, phase: State.Phase, tip: u64) !void {
        l.gate.lock();
        defer l.gate.unlock();
        const Sync = struct {
            l: *Loader,
            fn one(x: @This(), q: usize) anyerror!void {
                const p = &x.l.parts[q];
                const fd = p.fd.load(.acquire);
                const len = p.len.load(.monotonic);
                if (fd == no_fd or len == p.synced) return;
                try x.l.files.rio.sync(fd);
                x.l.files.rio.dropCache(fd, 0, len, false);
                p.synced = len;
                p.paced.store(len, .monotonic);
            }
        };
        try forEachPar(l.gpa, @min(l.threads, 8), n_parts, Sync{ .l = l }, Sync.one);
        const st = l.st;
        var temp: u64 = 0;
        for (l.parts, 0..) |*p, q| {
            st.len[q] = p.len.load(.monotonic);
            st.raw[q] = p.raw.load(.monotonic);
            st.rows[q] = p.rows.load(.monotonic);
            temp += st.len[q];
        }
        l.temp_bytes = temp;
        if (phase == .sort and st.phase != .sort) {
            // one table number per range, never handed out again
            st.gen0 = l.db.man.next_gen;
            l.db.man.next_gen += lsm.n_ranges;
            try l.db.writeManifest();
        }
        st.phase = phase;
        st.tip = tip;
        try l.files.rio.syncDir();
        try l.writeState();
    }

    /// Lane `lane` finished source part `part`: its rows are in the files (durable at the next
    /// cut).
    fn endPart(l: *Loader, lane: usize, part: u32) !void {
        const ln = &l.lanes[lane];
        {
            ln.lock.lock();
            defer ln.lock.unlock();
            if (ln.bad) |e| return e;
            try l.flushLane(ln);
        }
        l.st_lock.lock();
        defer l.st_lock.unlock();
        l.st.src_done |= @as(u64, 1) << @intCast(part);
        l.st.accept[part] = l.st.attempt;
        l.st.objects += ln.n;
        ln.n = 0;
        l.parts_since_cut += 1;
        l.parts_this_run += 1;
        if (l.parts_since_cut >= cut_every) {
            try l.cut(.rows, l.st.tip);
            l.parts_since_cut = 0;
        }
        if (builtin.is_test) if (test_crash) |tc| switch (tc) {
            .rows_parts => |n| if (l.parts_this_run >= n) return error.TestCrash,
            else => {},
        };
    }

    /// Walks the source parts that are not done yet on `threads` threads, one lane each.
    fn walk(l: *Loader, src: lsm.Source) !void {
        const nt = l.walkersFor();
        l.walkers = @intCast(nt);
        l.staging = l.stagingFor(nt, 0);
        const W = struct {
            l: *Loader,
            src: lsm.Source,
            next: Atomic(u32) = .init(0),
            failed: Atomic(bool) = .init(false),
            err_lock: lsm.SpinLock = .{},
            err: ?anyerror = null,

            const Each = struct {
                l: *Loader,
                ln: *Lane,
                fn f(ctx: *anyopaque, _: *const [32]u8, _: u64, bytes: []const u8) anyerror!void {
                    const e: *@This() = @ptrCast(@alignCast(ctx));
                    e.ln.lock.lock();
                    defer e.ln.lock.unlock();
                    try e.l.putLocked(e.ln, bytes);
                }
            };

            fn work(w: *@This(), lane: usize) void {
                w.inner(lane) catch |e| {
                    w.err_lock.lock();
                    defer w.err_lock.unlock();
                    if (w.err == null) w.err = e;
                    w.failed.store(true, .release);
                };
            }

            fn inner(w: *@This(), lane: usize) !void {
                const ld = w.l;
                const ln = &ld.lanes[lane];
                while (!w.failed.load(.acquire)) {
                    if (ld.stopped()) return error.Stopped;
                    const p = w.next.fetchAdd(1, .monotonic);
                    if (p >= src_parts) return;
                    {
                        ld.st_lock.lock();
                        defer ld.st_lock.unlock();
                        if (ld.st.src_done & (@as(u64, 1) << @intCast(p)) != 0) continue;
                    }
                    ln.src = @intCast(p);
                    var each: Each = .{ .l = ld, .ln = ln };
                    try w.src.walk(w.src.ctx, p, src_parts, .{ .ctx = &each, .f = Each.f });
                    try ld.endPart(lane, p);
                }
            }
        };
        var w: W = .{ .l = l, .src = src };
        const ts = try l.gpa.alloc(?std.Thread, nt);
        defer l.gpa.free(ts);
        @memset(ts, null);
        for (ts[1..], 1..) |*t, i| t.* = std.Thread.spawn(.{ .stack_size = 16 << 20 }, W.work, .{ &w, i }) catch null;
        W.work(&w, 0);
        for (ts) |t| if (t) |x| x.join();
        if (w.err) |e| return e;
    }

    /// No row arrives any more: the lanes are freed and the rows are durable. From here a
    /// resume needs no source.
    fn seal(l: *Loader, tip: u64) !void {
        // what the lanes grew to (their buffers only grow): the read phase's share of the budget
        for (l.lanes) |*ln| {
            l.lane_bytes += ln.recs.capacity + ln.idx.capacity * @sizeOf(Ref) + ln.grouped.capacity + ln.zbuf.capacity + ln.arena.queryCapacity();
            ln.deinit();
        }
        l.st_lock.lock();
        defer l.st_lock.unlock();
        try l.cut(.sort, tip);
        l.rows_ms = lsm.nowMs() - l.t0_ms;
        var files: u32 = 0;
        var raw: u64 = 0;
        for (l.st.len, l.st.raw) |n, r| {
            if (n != 0) files += 1;
            raw += r;
        }
        std.log.info("state index: rows of {d} objects in {d} partition files ({d} MiB of rows, {d} MiB on disk) after {d} s", .{ l.st.objects, files, raw >> 20, l.temp_bytes >> 20, l.rows_ms / 1000 });
        if (builtin.is_test) if (test_crash) |tc| if (tc == .sealed) return error.TestCrash;
    }

    /// A stream's end: no producer calls `put` any more. Flushes the lanes, seals the rows at
    /// live-set checkpoint `tip`, sorts and installs. Index lock held, or no reader yet.
    pub fn finish(l: *Loader, tip: u64) !lsm.Builder.Report {
        for (l.lanes) |*ln| {
            if (ln.bad) |e| return e;
            try l.flushLane(ln);
            l.st.objects += ln.n;
            ln.n = 0;
        }
        // a stream is one source part, written by attempt 0
        l.st.src_done = 1;
        l.st.accept[0] = l.st.attempt;
        try l.seal(tip);
        return l.sortAndInstall();
    }

    /// `lsm.Builder.runFrom` as a partitioned build: resumes the pending build of `src.at` or
    /// starts one, walks the source parts still missing, sorts and installs.
    pub fn runFrom(db: *lsm.Db, src: lsm.Source, rows_fn: RowsFn) !lsm.Builder.Report {
        const l = try open(db, rows_fn, src.at);
        defer l.destroy();
        if (l.st.phase == .rows) {
            std.log.info("state index: partitioned build at checkpoint {d}: {d} threads ({d} read the live set), {d} MiB budget ({d} source parts done)", .{ src.at, l.threads, l.walkersFor(), l.budget >> 20, l.resumed_src });
            try l.walk(src);
            // the source is not read again: what it held goes before the sorters allocate
            if (src.release) |f| f(src.ctx);
            try l.seal(src.at);
        } else {
            std.log.info("state index: resuming the partitioned build at checkpoint {d}: rows complete, {d} of {d} ranges written", .{ src.at, l.resumed_ranges, lsm.n_ranges });
            if (src.release) |f| f(src.ctx);
        }
        return l.sortAndInstall();
    }

    // ------------------------------------------------------------ sort

    const Sorter = struct {
        l: *Loader,
        raw: std.ArrayList(u8) = .empty,
        ents: std.ArrayList(Ent) = .empty,
        rbuf: []u8 = &.{},
        /// Bytes `raw` and `ents` may hold together.
        cap: usize,
        /// The most this worker's three buffers held at once.
        peak: usize = 0,

        fn note(s: *Sorter) void {
            s.peak = @max(s.peak, s.raw.capacity + s.ents.capacity * @sizeOf(Ent) + s.rbuf.len);
        }

        fn deinit(s: *Sorter) void {
            s.raw.deinit(s.l.gpa);
            s.ents.deinit(s.l.gpa);
            s.l.gpa.free(s.rbuf);
        }
        fn used(s: *const Sorter) usize {
            return s.raw.items.len + s.ents.items.len * @sizeOf(Ent);
        }
        fn reset(s: *Sorter) void {
            s.raw.clearRetainingCapacity();
            s.ents.clearRetainingCapacity();
        }

        /// Decodes frame `f` behind the rows held and indexes its rows.
        fn add(s: *Sorter, f: Frame, hint_raw: usize, hint_rows: usize) !void {
            const gpa = s.l.gpa;
            const off0 = s.raw.items.len;
            const end = off0 + f.raw_len;
            if (end > std.math.maxInt(u32)) return error.PartitionTooLarge;
            if (s.raw.capacity < end) try s.raw.ensureTotalCapacityPrecise(gpa, @max(end, hint_raw));
            if (s.ents.capacity < s.ents.items.len + f.rows) try s.ents.ensureTotalCapacityPrecise(gpa, @max(s.ents.items.len + f.rows, hint_rows));
            s.raw.items.len = end;
            const dst = s.raw.items[off0..end];
            if (f.codec == 1) {
                store.zstd_c.decodeInto(f.payload, dst) catch |e| return switch (e) {
                    error.OutOfMemory => error.OutOfMemory,
                    error.Corrupt => error.Corrupt,
                };
            } else {
                if (f.payload.len != dst.len) return error.Corrupt;
                @memcpy(dst, f.payload);
            }
            var pos = off0;
            var n: u32 = 0;
            while (pos < end) : (n += 1) {
                if (pos + rec_hdr > end) return error.Corrupt;
                const klen = std.mem.readInt(u16, s.raw.items[pos..][0..2], .little);
                const op = s.raw.items[pos + 2];
                const vlen = s.raw.items[pos + 3];
                if (klen == 0 or op < 1 or op > 4 or vlen > lsm.max_val or pos + rec_hdr + klen + vlen > end) return error.Corrupt;
                if (n == f.rows) return error.Corrupt;
                s.ents.appendAssumeCapacity(.{ .cache = 0, .off = @intCast(pos), .klen = klen });
                pos += rec_hdr + klen + vlen;
            }
            if (n != f.rows) return error.Corrupt;
        }

        /// The sorted rows into `w`, equal keys combined in arrival order. `final`: deletes
        /// are dropped too (nothing older exists under a base run).
        fn emit(s: *Sorter, w: *lsm.TableWriter, final: bool) !void {
            const raw = s.raw.items;
            const es = s.ents.items;
            var i: usize = 0;
            var k: u64 = 0;
            while (i < es.len) {
                const key = keyOf(raw, es[i]);
                var v = valOf(raw, es[i]);
                var j = i + 1;
                while (j < es.len and es[j].klen == es[i].klen and std.mem.eql(u8, keyOf(raw, es[j]), key)) : (j += 1) v = lsm.combine(valOf(raw, es[j]), v);
                // a plain zero sum is the identity; a held one stays until the base run
                const zero = v.zeroSum() and (v.op == .delta or final);
                if (!zero and !(final and v.op == .del)) try w.add(key, v);
                i = j;
                k += 1;
                if (k % 65536 == 0 and s.l.stopped()) return error.Stopped;
            }
        }
    };

    fn accepts(l: *const Loader, f: Frame) bool {
        if (f.src >= src_parts) return false;
        return l.st.src_done & (@as(u64, 1) << @intCast(f.src)) != 0 and l.st.accept[f.src] == f.attempt;
    }

    /// The rows of partition `q` into `w`, in key order.
    fn addPart(l: *Loader, s: *Sorter, q: u32, w: *lsm.TableWriter) !void {
        const gpa = l.gpa;
        const end = l.st.len[q];
        const fd = try l.partFd(q, false);
        defer l.closePart(q);
        if (try l.files.rio.size(fd) < end) return error.Corrupt;
        l.files.rio.willNeedFile(fd, 0, end);
        var fr: FrameReader = .{ .gpa = gpa, .rio = l.files.rio, .fd = fd, .end = end, .buf = &s.rbuf, .read_bytes = @min(1 << 20, @max(l.staging, 64 << 10)) };
        s.reset();
        // One allocation when the partition fits; else the worker's share, split as the rows are.
        const want: u64 = l.st.raw[q] + l.st.rows[q] * @sizeOf(Ent);
        var hint_raw: usize = @intCast(@min(l.st.raw[q], std.math.maxInt(u32)));
        var hint_rows: usize = @intCast(@min(l.st.rows[q], std.math.maxInt(u32)));
        const chunked = want > s.cap;
        if (chunked) {
            hint_raw = @intCast(@as(u128, s.cap) * l.st.raw[q] / want);
            hint_rows = @intCast(@as(u128, s.cap) * l.st.rows[q] / want);
        }
        // The buffers of an earlier partition are kept only when both are large enough; else
        // both are freed before the new ones are allocated. Growing one in place holds the old
        // and the new allocation at once (bench, 256 MiB budget, 1.1M-row partitions: peak 278
        // MiB grown in place, 205 MiB this way).
        if (s.raw.capacity < hint_raw or s.ents.capacity < hint_rows) {
            s.raw.clearAndFree(gpa);
            s.ents.clearAndFree(gpa);
            try s.raw.ensureTotalCapacityPrecise(gpa, hint_raw);
            try s.ents.ensureTotalCapacityPrecise(gpa, hint_rows);
        }
        var chunks: u32 = 0;
        errdefer for (0..chunks) |k| {
            var nb: [64]u8 = undefined;
            l.files.remove(chunkName(&nb, q, @intCast(k)));
        };
        while (try fr.next()) |f| {
            if (!l.accepts(f)) continue;
            const need = @as(usize, f.raw_len) + @as(usize, f.rows) * @sizeOf(Ent);
            // A chunk ends where the next frame would grow either buffer (a grown buffer is
            // held twice while it is copied).
            const over = s.used() + need > s.cap or (chunked and (s.raw.items.len + f.raw_len > @max(s.raw.capacity, hint_raw) or s.ents.items.len + f.rows > @max(s.ents.capacity, hint_rows)));
            if (s.used() != 0 and over) {
                // more rows than the worker's share of the budget: sorted chunks, merged below
                try l.spillChunk(s, q, chunks);
                chunks += 1;
            }
            try s.add(f, hint_raw, hint_rows);
            s.note();
            if (l.stopped()) return error.Stopped;
        }
        l.files.rio.dropCache(fd, 0, end, false);
        if (chunks == 0) {
            sortEnts(s.raw.items, s.ents.items, 0);
            try s.emit(w, true);
            return;
        }
        if (s.used() != 0) {
            try l.spillChunk(s, q, chunks);
            chunks += 1;
        }
        const tabs = try gpa.alloc(*lsm.Table, chunks);
        defer gpa.free(tabs);
        var opened: usize = 0;
        defer for (tabs[0..opened]) |t| t.close(gpa, l.files);
        for (tabs, 0..) |*t, k| {
            var nb: [64]u8 = undefined;
            t.* = try lsm.Table.open(gpa, l.files, chunkName(&nb, q, @intCast(k)), 0);
            opened += 1;
        }
        try lsm.mergeTablesInto(gpa, l.files, tabs, w, l.db.build_stop);
        for (0..chunks) |k| {
            var nb: [64]u8 = undefined;
            l.files.remove(chunkName(&nb, q, @intCast(k)));
        }
    }

    fn spillChunk(l: *Loader, s: *Sorter, q: u32, k: u32) !void {
        sortEnts(s.raw.items, s.ents.items, 0);
        var nb: [64]u8 = undefined;
        var w = try lsm.TableWriter.createLevel(l.gpa, l.files, chunkName(&nb, q, k), lsm.temp_level);
        {
            errdefer w.abort();
            try s.emit(&w, false);
        }
        _ = try w.finish();
        _ = l.chunks.fetchAdd(1, .monotonic);
        s.reset();
    }

    /// Writes range `r`'s table from its partitions. Returns its row count (0: no table).
    fn buildRange(l: *Loader, s: *Sorter, r: u32) !u64 {
        var nb: [64]u8 = undefined;
        const name = lsm.tableName(&nb, l.st.gen0 + r);
        var w = try lsm.TableWriter.create(l.gpa, l.files, name);
        {
            errdefer {
                w.abort();
                l.files.remove(name);
            }
            const nth = l.ranges_started.fetchAdd(1, .monotonic) + 1;
            const pr = rangeParts(r);
            var q = pr.lo;
            var first = true;
            while (q < pr.hi) : (q += 1) {
                if (l.st.len[q] == 0) continue;
                try l.addPart(s, q, &w);
                if (builtin.is_test and first) if (test_crash) |tc| switch (tc) {
                    .mid_range => |n| if (nth == n) return error.TestCrash,
                    else => {},
                };
                first = false;
            }
        }
        const entries = w.entries;
        _ = try w.finish();
        if (entries == 0) l.files.remove(name);
        return entries;
    }

    fn rangeDone(l: *Loader, r: u32, entries: u64) !void {
        {
            l.st_lock.lock();
            defer l.st_lock.unlock();
            l.st.ranges_done |= @as(u64, 1) << @intCast(r);
            l.st.range_entries[r] = entries;
            try l.files.rio.syncDir();
            try l.writeState();
        }
        // the range's rows are in its table: its partition files go
        const pr = rangeParts(r);
        var q = pr.lo;
        while (q < pr.hi) : (q += 1) {
            l.closePart(q);
            if (l.st.len[q] == 0) continue;
            var nb: [64]u8 = undefined;
            l.files.remove(partName(&nb, q));
        }
        if (builtin.is_test) if (test_crash) |tc| switch (tc) {
            .ranges => |n| if (l.ranges_this_run.fetchAdd(1, .monotonic) + 1 >= n) return error.TestCrash,
            else => {},
        };
    }

    fn sortAndInstall(l: *Loader) !lsm.Builder.Report {
        const t1 = lsm.nowMs();
        const st = l.st;
        // the unfinished ranges, the one with the most rows on disk first
        var order: [lsm.n_ranges]u32 = undefined;
        var weight: [lsm.n_ranges]u64 = @splat(0);
        var n: usize = 0;
        for (0..lsm.n_ranges) |r| {
            if (st.ranges_done & (@as(u64, 1) << @intCast(r)) != 0) continue;
            const pr = rangeParts(@intCast(r));
            for (st.len[pr.lo..pr.hi]) |x| weight[r] += x;
            order[n] = @intCast(r);
            n += 1;
        }
        const Ctx = struct {
            w: *const [lsm.n_ranges]u64,
            fn lt(c: @This(), a: u32, b: u32) bool {
                if (c.w[a] != c.w[b]) return c.w[a] > c.w[b];
                return a < b;
            }
        };
        std.mem.sort(u32, order[0..n], Ctx{ .w = &weight }, Ctx.lt);
        // Workers: each holds one partition's rows (or a chunk of them), a read buffer of up
        // to one frame, and two table writers (the range's, and a chunk's beside it).
        var max_frame_raw: usize = l.staging;
        if (max_frame_raw == 0) max_frame_raw = l.stagingFor(l.threads, 0);
        const fixed = max_frame_raw + (5 << 20);
        const workers = std.math.clamp(l.budget / (2 * fixed + max_frame_raw), 1, @max(@min(l.threads, n), 1));
        const per_worker = l.budget / workers;
        var cap: usize = @min(per_worker -| fixed, std.math.maxInt(u32) - (64 << 20));
        if (builtin.is_test) if (test_sort_cap) |c| {
            cap = c;
        };
        const Job = struct {
            l: *Loader,
            order: []const u32,
            cap: usize,
            next: Atomic(usize) = .init(0),
            failed: Atomic(bool) = .init(false),
            err_lock: lsm.SpinLock = .{},
            err: ?anyerror = null,
            fn work(j: *@This()) void {
                var s: Sorter = .{ .l = j.l, .cap = j.cap };
                defer {
                    _ = j.l.sort_bytes.fetchAdd(s.peak, .monotonic);
                    s.deinit();
                }
                while (!j.failed.load(.acquire)) {
                    const i = j.next.fetchAdd(1, .monotonic);
                    if (i >= j.order.len) return;
                    j.one(&s, j.order[i]) catch |e| {
                        j.err_lock.lock();
                        defer j.err_lock.unlock();
                        if (j.err == null) j.err = e;
                        j.failed.store(true, .release);
                        return;
                    };
                }
            }
            fn one(j: *@This(), s: *Sorter, r: u32) !void {
                if (j.l.stopped()) return error.Stopped;
                const entries = try j.l.buildRange(s, r);
                try j.l.rangeDone(r, entries);
            }
        };
        var job: Job = .{ .l = l, .order = order[0..n], .cap = cap };
        if (n > 0) l.sort_workers = @intCast(workers);
        if (n > 0) {
            const ts = try l.gpa.alloc(?std.Thread, workers);
            defer l.gpa.free(ts);
            @memset(ts, null);
            for (ts[1..]) |*t| t.* = std.Thread.spawn(.{ .stack_size = 16 << 20 }, Job.work, .{&job}) catch null;
            Job.work(&job);
            for (ts) |t| if (t) |x| x.join();
            if (job.err) |e| return e;
        }
        if (builtin.is_test) if (test_crash) |tc| if (tc == .before_install) return error.TestCrash;
        try l.install();
        const db = l.db;
        const entries: u64 = if (db.runs.items.len > 0) db.runs.items[0].entries() else 0;
        const sort_ms = lsm.nowMs() - t1;
        std.log.info("state index: {d} rows in {d} tables ({d} MiB) sorted and written in {d} s by {d} workers of {d} MiB", .{ entries, if (db.runs.items.len > 0) db.runs.items[0].tables.len else 0, db.diskBytes() >> 20, sort_ms / 1000, workers, per_worker >> 20 });
        std.log.info("state index: build memory: {d} MiB budget; the lanes of {d} walkers held {d} MiB, {d} sort workers at most {d} MiB", .{ l.budget >> 20, l.walkers, l.lane_bytes >> 20, l.sort_workers, l.sort_bytes.load(.monotonic) >> 20 });
        return .{
            .objects = st.objects,
            .entries = entries,
            .bytes = db.diskBytes(),
            .ms = lsm.nowMs() - l.t0_ms,
            .resumed_parts = l.resumed_src,
            .resumed_ranges = l.resumed_ranges,
            .rows_ms = l.rows_ms,
            .sort_ms = sort_ms,
            .temp_bytes = l.temp_bytes,
            .sort_chunks = l.chunks.load(.monotonic),
            .lane_bytes = l.lane_bytes,
            .sort_bytes = l.sort_bytes.load(.monotonic),
            .walkers = l.walkers,
            .sort_workers = l.sort_workers,
        };
    }

    /// The base run and the watermark into the manifest, then the build's own files go.
    fn install(l: *Loader) !void {
        const db = l.db;
        const gpa = l.gpa;
        const st = l.st;
        if (db.runs.items.len != 0) return error.IndexNotEmpty;
        var tabs: std.ArrayList(*lsm.Table) = .empty;
        defer tabs.deinit(gpa);
        errdefer for (tabs.items) |t| t.close(gpa, l.files);
        for (0..lsm.n_ranges) |r| {
            if (st.range_entries[r] == 0) continue;
            var nb: [64]u8 = undefined;
            const t = try lsm.Table.open(gpa, l.files, lsm.tableName(&nb, st.gen0 + r), st.gen0 + r);
            tabs.append(gpa, t) catch |e| {
                t.close(gpa, l.files);
                return e;
            };
        }
        try db.runs.ensureUnusedCapacity(gpa, 1);
        if (tabs.items.len > 0) {
            const owned = try gpa.dupe(*lsm.Table, tabs.items);
            errdefer gpa.free(owned);
            const run = try gpa.create(lsm.Run);
            run.* = .{ .tables = owned };
            db.runs.appendAssumeCapacity(run);
            tabs.clearRetainingCapacity();
        }
        db.man.build = null;
        db.man.watermark = st.tip;
        try db.writeManifest();
        l.files.close(l.st_fd);
        l.st_fd = no_fd;
        try db.gc();
    }
};

/// Runs `f(ctx, i)` for i in 0..n on up to `threads` threads; the first error wins.
fn forEachPar(gpa: Allocator, threads: usize, n: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx), usize) anyerror!void) !void {
    const P = struct {
        ctx: @TypeOf(ctx),
        n: usize,
        next: Atomic(usize) = .init(0),
        err_lock: lsm.SpinLock = .{},
        err: ?anyerror = null,
        fn work(p: *@This()) void {
            while (true) {
                const i = p.next.fetchAdd(1, .monotonic);
                if (i >= p.n) return;
                f(p.ctx, i) catch |e| {
                    p.err_lock.lock();
                    defer p.err_lock.unlock();
                    if (p.err == null) p.err = e;
                    return;
                };
            }
        }
    };
    var p: P = .{ .ctx = ctx, .n = n };
    const nt = @max(threads, 1);
    const ts = try gpa.alloc(?std.Thread, nt);
    defer gpa.free(ts);
    @memset(ts, null);
    for (ts[1..]) |*t| t.* = std.Thread.spawn(.{}, P.work, .{&p}) catch null;
    P.work(&p);
    for (ts) |t| if (t) |x| x.join();
    if (p.err) |e| return e;
}

// ---------------------------------------------------------------------------- tests

test "bulk: partitions refine the ranges and follow key order" {
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    var prev: [40]u8 = @splat(0);
    var keys: [4000][40]u8 = undefined;
    for (&keys) |*k| {
        r.bytes(k);
        k[0] = r.uintLessThan(u8, 3);
        if (k[0] == 0) k[1] = r.uintLessThan(u8, 2);
    }
    const Ctx = struct {
        fn lt(_: void, a: [40]u8, b: [40]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    };
    std.mem.sort([40]u8, &keys, {}, Ctx.lt);
    for (keys) |k| {
        try std.testing.expect(partOf(&prev) <= partOf(&k));
        try std.testing.expectEqual(lsm.rangeOf(&k), rangeOfPart(partOf(&k)));
        const pr = rangeParts(lsm.rangeOf(&k));
        try std.testing.expect(partOf(&k) >= pr.lo and partOf(&k) < pr.hi);
        prev = k;
    }
    // every partition is in exactly one range, ranges in order
    var q: u32 = 0;
    for (0..lsm.n_ranges) |rr| {
        const pr = rangeParts(@intCast(rr));
        try std.testing.expectEqual(q, pr.lo);
        q = pr.hi;
    }
    try std.testing.expectEqual(n_parts, q);
}

test "bulk: sortEnts orders rows as a full key comparison does (shared prefixes, zero bytes, keys that are prefixes of others, duplicates)" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(17);
    const r = prng.random();
    for (0..40) |round| {
        var raw: std.ArrayList(u8) = .empty;
        defer raw.deinit(gpa);
        var ents: std.ArrayList(Ent) = .empty;
        defer ents.deinit(gpa);
        const n = 1 + r.uintLessThan(usize, 6000);
        const shared = r.uintLessThan(usize, 70);
        const alphabet: u16 = if (round % 3 == 0) 2 else if (round % 3 == 1) 4 else 256;
        var prefix: [70]u8 = undefined;
        r.bytes(&prefix);
        for (0..n) |i| {
            var kb: [256]u8 = undefined;
            var kl: usize = 0;
            if (i > 0 and r.uintLessThan(u8, 10) == 0) {
                // a copy of an earlier key, sometimes cut short or extended with zeros
                const e = ents.items[r.uintLessThan(usize, ents.items.len)];
                const k = keyOf(raw.items, e);
                kl = k.len;
                @memcpy(kb[0..kl], k);
                switch (r.uintLessThan(u8, 3)) {
                    0 => {},
                    1 => kl = 1 + r.uintLessThan(usize, kl),
                    else => {
                        const add = if (kl < 200) r.uintLessThan(usize, 12) else 0;
                        @memset(kb[kl..][0..add], 0);
                        kl += add;
                    },
                }
            } else {
                const ps = @min(shared, r.uintLessThan(usize, shared + 1) + shared / 2);
                @memcpy(kb[0..ps], prefix[0..ps]);
                const tail = r.uintLessThan(usize, 40);
                for (kb[ps..][0..tail]) |*b| b.* = @intCast(r.uintLessThan(u16, alphabet));
                kl = ps + tail;
                if (kl == 0) {
                    kb[0] = 0;
                    kl = 1;
                }
            }
            const off = raw.items.len;
            var h: [rec_hdr]u8 = undefined;
            std.mem.writeInt(u16, h[0..2], @intCast(kl), .little);
            h[2] = 1;
            h[3] = 0;
            try raw.appendSlice(gpa, &h);
            try raw.appendSlice(gpa, kb[0..kl]);
            try ents.append(gpa, .{ .cache = 0, .off = @intCast(off), .klen = @intCast(kl) });
        }
        const want = try gpa.dupe(Ent, ents.items);
        defer gpa.free(want);
        std.mem.sort(Ent, want, SmallCtx{ .raw = raw.items, .d = 0 }, SmallCtx.lt);
        sortEnts(raw.items, ents.items, 0);
        for (want, ents.items) |w, g| try std.testing.expectEqual(w.off, g.off);
    }
}

test "bulk: the state file round-trips, the newer slot wins, a damaged slot is ignored" {
    var a: State = .{ .tip = 77, .phase = .sort, .attempt = 3, .gen0 = 12, .objects = 9, .src_done = 0xff00, .ranges_done = 5 };
    a.accept[9] = 2;
    a.range_entries[2] = 44;
    a.len[768] = 1 << 40;
    a.raw[5] = 7;
    a.rows[511] = 8;
    a.counter = 4;
    const buf = try std.testing.allocator.create([state_slot]u8);
    defer std.testing.allocator.destroy(buf);
    a.encode(buf);
    var b: State = .{};
    try std.testing.expect(b.decode(buf));
    try std.testing.expectEqual(a.tip, b.tip);
    try std.testing.expectEqual(a.phase, b.phase);
    try std.testing.expectEqual(a.attempt, b.attempt);
    try std.testing.expectEqual(a.gen0, b.gen0);
    try std.testing.expectEqual(a.src_done, b.src_done);
    try std.testing.expectEqual(a.ranges_done, b.ranges_done);
    try std.testing.expectEqualSlices(u16, &a.accept, &b.accept);
    try std.testing.expectEqualSlices(u64, &a.range_entries, &b.range_entries);
    try std.testing.expectEqualSlices(u64, &a.len, &b.len);
    try std.testing.expectEqualSlices(u64, &a.raw, &b.raw);
    try std.testing.expectEqualSlices(u64, &a.rows, &b.rows);
    buf[100] ^= 1;
    try std.testing.expect(!b.decode(buf));
    // files it keeps: its state, partition files of unfinished ranges, tables of finished ones
    try std.testing.expect(a.keeps("load.state"));
    try std.testing.expect(!a.keeps("p0.rows")); // range 0 is done
    try std.testing.expect(a.keeps("p16.rows")); // range 1 is not
    try std.testing.expect(!a.keeps("p47.rows")); // range 2 is done
    try std.testing.expect(a.keeps("p768.rows"));
    try std.testing.expect(a.keeps("12.tbl") and a.keeps("14.tbl"));
    try std.testing.expect(!a.keeps("13.tbl") and !a.keeps("45.tbl") and !a.keeps("11.tbl"));
    try std.testing.expect(!a.keeps("x3-0.tmp") and !a.keeps("b3-0.tmp"));
}
