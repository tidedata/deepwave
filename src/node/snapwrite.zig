//! Formal snapshot producer (sui-node `state-snapshot-write-config`, sui-snapshot writer.rs at
//! mainnet-v1.83.1): the live object set at the end of epoch E written as `epoch_E/` with
//! `<bucket>_<part>.obj`/`.ref` partitions and a MANIFEST, the format deepwave and `sui-tool
//! download-formal-snapshot` restore from (layout in snapshot.zig).
//!
//! The set is read from deepwave's own store through a snapshot pinned at E's last checkpoint S
//! (`c1 = S + 1`), so the node keeps following while it writes: object chains give the version
//! each object had at S, read in location order (`store.LiveScan`: the live-table locations
//! sorted, records read front to back, versions written after S resolved in a second sorted pass). Like Mysten's writer, the ECMH of every written ref
//! digest must equal the certified `ECMHLiveObjectSetDigest` of checkpoint S, or nothing is
//! published: the MANIFEST (which readers start from) is written only after the root matched.
//!
//! Throughput (lane index-fast): every writer thread (one bucket each) streams its part files:
//! objects are staged 4 MiB at a time, compressed into the file's single zstd frame with the C
//! encoder (`store.zstd_c.FrameStream`, level -1), hashed and written, and written-back pages are
//! dropped from the page cache every 32 MiB. So all cores compress at once with ~10 MiB of
//! buffers each, and the scan (`store.LiveScan`, its location sort now on every core) feeds them.
//!
//! Format details matched to Mysten's writer: one `LiveObject::Normal` blob per object
//! (BlobEncoding::Bcs, uvarint length), parts cut before 128 MiB, zstd per file, refs as
//! id ++ version (BE) ++ digest, the sha3-256 of every stored file in the manifest, manifest
//! version 1 with address length 32. Wrapped tombstones are not written (mainnet and testnet
//! have `simplified_unwrap_then_delete`, which leaves them out of the commitment). Mysten writes
//! a single bucket; deepwave writes one bucket per writer thread (the reader takes any (bucket, part)).
const std = @import("std");
const Io = std.Io;
const store = @import("store");
const sig = @import("sig");
const serve = @import("serve");
const snapshot = @import("snapshot.zig");
const hash = @import("hash");
const source_mod = @import("source.zig");
const Atomic = std.atomic.Value;

pub const file_max_bytes: usize = 128 * 1024 * 1024;

pub const Options = struct {
    epoch: u64,
    /// Last checkpoint of `epoch` (the snapshot sees every checkpoint up to it, none after).
    checkpoint: u64,
    /// The certified ECMH root of checkpoint `checkpoint`; null writes without the check (tests).
    expect_root: ?[32]u8,
    threads: u32 = 8,
    compression: snapshot.Compression = .zstd,
    part_max: usize = file_max_bytes,
    /// Set to stop early (node shutdown): partial output is removed.
    cancel: ?*const Atomic(bool) = null,
    /// Progress line every this many seconds (0: none).
    log_every_s: u64 = 10,
};

/// Writer threads for `threads` (0: half the cores, at least 4, at most 16: each writer is a
/// bucket streaming its own files, ~10 MiB of buffers).
pub fn defaultThreads(threads: u32) u32 {
    if (threads != 0) return threads;
    const c: u32 = @intCast(std.Thread.getCpuCount() catch 8);
    return std.math.clamp(c / 2, 4, 16);
}

pub const Stats = struct {
    objects: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
    stored: Atomic(u64) = .init(0),
    files: Atomic(u64) = .init(0),
};

pub const Result = struct { root: [32]u8, objects: u64, bytes: u64, stored: u64, files: u64, ms: u64 };

/// Plain bytes staged before they go to the compressor (and, compressed, to the file).
const stage_bytes = 4 << 20;
/// Written bytes after which a part file's pages are written back and dropped from the page
/// cache (a 158 GB write inside the node's memory cap must not pile up dirty pages).
const drop_every = 32 << 20;

/// One part file written as it is filled (lane index-fast): plain bytes are staged, compressed in
/// 4 MiB pieces into one zstd frame (`store.zstd_c.FrameStream`), hashed and appended to the
/// file, which is opened at its first write. A writer holds about 10 MiB per file instead of a
/// whole 128 MiB part, so every core can write a bucket. With `ZUI_ZSTD=std` (deepwave's own encoder,
/// one-shot only) the part is staged whole and compressed at the end, as before.
const PartFile = struct {
    name_buf: [64]u8 = undefined,
    name_len: usize = 0,
    file: ?Io.File = null,
    /// Plain bytes in this file so far (magic included): Mysten's cut rule counts these.
    plain: u64 = 0,
    /// Stored bytes written so far.
    off: u64 = 0,
    /// Written back and dropped up to here.
    dropped: u64 = 0,
    stage: std.ArrayList(u8) = .empty,
    out: std.ArrayList(u8) = .empty,
    sha: hash.Sha3_256 = undefined,
    fs: store.zstd_c.FrameStream = .{},
    comp: snapshot.Compression = .none,
    whole: bool = false,

    fn deinit(pf: *PartFile, gpa: std.mem.Allocator, io: Io) void {
        if (pf.file) |f| f.close(io);
        pf.file = null;
        pf.stage.deinit(gpa);
        pf.out.deinit(gpa);
        pf.fs.deinit();
    }

    fn begin(pf: *PartFile, gpa: std.mem.Allocator, fm: snapshot.FileMeta, magic: u32) !void {
        const n = fm.name(&pf.name_buf);
        pf.name_len = n.len;
        pf.plain = 0;
        pf.off = 0;
        pf.dropped = 0;
        pf.comp = fm.compression;
        pf.whole = fm.compression == .zstd and !store.zstd_c.use();
        pf.sha = hash.Sha3_256.init();
        pf.stage.clearRetainingCapacity();
        pf.out.clearRetainingCapacity();
        if (pf.comp == .zstd and !pf.whole) try pf.fs.begin();
        var m4: [4]u8 = undefined;
        std.mem.writeInt(u32, &m4, magic, .big);
        try pf.stage.appendSlice(gpa, &m4);
        pf.plain = 4;
    }

    fn append(pf: *PartFile, w: *Worker, bytes: []const u8) !void {
        try pf.stage.appendSlice(w.gpa, bytes);
        pf.plain += bytes.len;
        if (!pf.whole and pf.stage.items.len >= stage_bytes) try pf.pump(w, false);
    }

    /// The staged bytes to the file (compressed when the part is); `end` closes the frame.
    fn pump(pf: *PartFile, w: *Worker, end: bool) !void {
        const gpa = w.gpa;
        const data: []const u8 = switch (pf.comp) {
            .none => pf.stage.items,
            .zstd => blk: {
                pf.out.clearRetainingCapacity();
                if (pf.whole) {
                    if (end) {
                        const z = try store.zstd_c.compressAny(gpa, pf.stage.items);
                        defer gpa.free(z);
                        try pf.out.appendSlice(gpa, z);
                    } else break :blk &.{};
                } else try pf.fs.feed(gpa, pf.stage.items, end, &pf.out);
                break :blk pf.out.items;
            },
        };
        const f = pf.file orelse blk: {
            const f = try w.dir.createFile(w.io, pf.name_buf[0..pf.name_len], .{});
            pf.file = f;
            break :blk f;
        };
        if (data.len > 0) {
            pf.sha.update(data);
            try f.writePositionalAll(w.io, data, pf.off);
            pf.off += data.len;
            if (pf.off - pf.dropped >= drop_every) {
                dropWritten(f, pf.dropped, pf.off - pf.dropped);
                pf.dropped = pf.off;
            }
        }
        if (!(pf.whole and !end)) pf.stage.clearRetainingCapacity();
    }

    /// Ends the file: the rest staged, the frame closed, written back, closed. Its sha3.
    fn finish(pf: *PartFile, w: *Worker) ![32]u8 {
        try pf.pump(w, true);
        const f = pf.file.?;
        dropWritten(f, pf.dropped, pf.off - pf.dropped);
        f.close(w.io);
        pf.file = null;
        var h: [32]u8 = undefined;
        pf.sha.final(&h);
        _ = w.stats.stored.fetchAdd(pf.off, .monotonic);
        _ = w.stats.files.fetchAdd(1, .monotonic);
        return h;
    }
};

/// Linux: the written range out to disk and out of the page cache.
fn dropWritten(f: Io.File, off: u64, len: u64) void {
    if (@import("builtin").os.tag != .linux or len == 0) return;
    const linux = std.os.linux;
    const hu: usize = @bitCast(@as(isize, f.handle));
    // SYNC_FILE_RANGE_WAIT_BEFORE | WRITE | WAIT_AFTER
    _ = linux.syscall4(.sync_file_range, hu, off, len, 7);
    _ = linux.fadvise(f.handle, @intCast(off), @intCast(len), linux.POSIX_FADV.DONTNEED);
}

const Worker = struct {
    gpa: std.mem.Allocator,
    io: Io,
    scan: *store.LiveScan,
    dir: Io.Dir,
    opts: *const Options,
    stats: *Stats,
    bucket: u32,
    acc: sig.Ecmh = .{},
    files: std.ArrayList(snapshot.FileMeta) = .empty,
    err: ?anyerror = null,
    obj: PartFile = .{},
    ref: PartFile = .{},
    /// A part is open (its two files begun).
    open: bool = false,
    part: u32 = 1,
    digests: [64][32]u8 = undefined,
    dp: [64][]const u8 = undefined,
    nd: usize = 0,

    fn run(w: *Worker) void {
        w.body() catch |e| {
            w.err = e;
        };
        w.obj.deinit(w.gpa, w.io);
        w.ref.deinit(w.gpa, w.io);
    }

    fn body(w: *Worker) !void {
        while (w.scan.next()) |g| {
            // group first: a range handed out is always finished (LiveScan waits on it).
            try w.scan.group(g, w, onItem);
            if (w.opts.cancel) |c| if (c.load(.acquire)) return error.Canceled;
        }
        w.acc.insertAll(w.dp[0..w.nd]);
        w.nd = 0;
        if (w.open) try w.finishPart();
    }

    fn meta(w: *const Worker, kind: snapshot.FileType, h: [32]u8) snapshot.FileMeta {
        return .{ .kind = kind, .bucket = w.bucket, .part = w.part, .compression = w.opts.compression, .sha3 = h };
    }

    fn startPart(w: *Worker) !void {
        try w.obj.begin(w.gpa, w.meta(.object, @splat(0)), snapshot.object_magic);
        try w.ref.begin(w.gpa, w.meta(.reference, @splat(0)), snapshot.reference_magic);
        w.open = true;
    }

    fn finishPart(w: *Worker) !void {
        const ho = try w.obj.finish(w);
        const hr = try w.ref.finish(w);
        try w.files.append(w.gpa, w.meta(.object, ho));
        try w.files.append(w.gpa, w.meta(.reference, hr));
        w.open = false;
        w.part += 1;
    }

    fn onItem(w: *Worker, o: store.LiveIter.Item) anyerror!void {
        const d = o.digest();
        const blob_len = 1 + o.bytes.len; // LiveObject::Normal tag + Object
        const need = uvarintLen(blob_len) + 1 + blob_len;
        if (w.open and w.obj.plain > 4 and w.obj.plain + need > w.opts.part_max) try w.finishPart();
        if (!w.open) try w.startPart();
        var hdr: [16]u8 = undefined;
        var hn: usize = 0;
        var v = blob_len;
        while (v >= 0x80) : (v >>= 7) {
            hdr[hn] = @as(u8, @truncate(v)) | 0x80;
            hn += 1;
        }
        hdr[hn] = @truncate(v);
        hdr[hn + 1] = 1; // BlobEncoding::Bcs
        hdr[hn + 2] = 0; // LiveObject::Normal
        try w.obj.append(w, hdr[0 .. hn + 3]);
        try w.obj.append(w, o.bytes);
        var r: [72]u8 = undefined;
        @memcpy(r[0..32], &o.id);
        std.mem.writeInt(u64, r[32..40], o.version, .big);
        @memcpy(r[40..72], &d);
        try w.ref.append(w, &r);
        w.digests[w.nd] = d;
        w.dp[w.nd] = &w.digests[w.nd];
        w.nd += 1;
        if (w.nd == w.digests.len) {
            w.acc.insertAll(w.dp[0..w.nd]);
            w.nd = 0;
        }
        _ = w.stats.objects.fetchAdd(1, .monotonic);
        _ = w.stats.bytes.fetchAdd(o.bytes.len, .monotonic);
    }
};

fn uvarintLen(v: usize) usize {
    var n: usize = 1;
    var x = v >> 7;
    while (x != 0) : (x >>= 7) n += 1;
    return n;
}

fn epochDirName(buf: []u8, epoch: u64) []const u8 {
    return std.fmt.bufPrint(buf, "epoch_{d}", .{epoch}) catch unreachable;
}

/// Writes `<out>/epoch_<E>/` from the store as of checkpoint `opts.checkpoint`. An existing
/// `epoch_<E>` is replaced. On any failure (root mismatch included) the directory is removed.
pub fn write(gpa: std.mem.Allocator, io: Io, st: *store.Store, out: Io.Dir, opts: Options, stats: *Stats) !Result {
    const t0 = source_mod.nowNs();
    if (st.committed()) |c| {
        if (c < opts.checkpoint) return error.CheckpointNotCommitted;
    } else return error.CheckpointNotCommitted;
    var nb: [64]u8 = undefined;
    const dname = epochDirName(&nb, opts.epoch);
    out.deleteTree(io, dname) catch {};
    try out.createDirPath(io, dname);
    errdefer out.deleteTree(io, dname) catch {};
    const dir = try out.openDir(io, dname, .{});
    defer dir.close(io);

    var scan = try store.LiveScan.init(gpa, st, opts.checkpoint + 1);
    defer scan.deinit();
    const t_scan = source_mod.nowNs();
    if (opts.log_every_s > 0) std.log.info("snapshot write: epoch {d}: {d} live-table entries sorted in {d} ms; writing on {d} threads", .{ opts.epoch, scan.total(), (t_scan - t0) / std.time.ns_per_ms, defaultThreads(opts.threads) });
    const nt: u32 = defaultThreads(opts.threads);
    const workers = try gpa.alloc(Worker, nt);
    defer gpa.free(workers);
    for (workers, 0..) |*w, i| w.* = .{ .gpa = gpa, .io = io, .scan = &scan, .dir = dir, .opts = &opts, .stats = stats, .bucket = @intCast(i + 1) };
    defer for (workers) |*w| w.files.deinit(gpa);
    const threads = try gpa.alloc(?std.Thread, nt);
    defer gpa.free(threads);
    var finished: Atomic(u32) = .init(0);
    const Run = struct {
        fn run(w: *Worker, f: *Atomic(u32)) void {
            w.run();
            _ = f.fetchAdd(1, .release);
        }
    };
    var spawned: u32 = 0;
    for (workers, threads) |*w, *t| {
        t.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, Run.run, .{ w, &finished }) catch null;
        if (t.* != null) spawned += 1;
    }
    // progress while the writers run (rig measurement: MB/s of stored output)
    var last = t_scan;
    while (finished.load(.acquire) < spawned) {
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 200 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
        const now = source_mod.nowNs();
        if (opts.log_every_s == 0 or now - last < opts.log_every_s * std.time.ns_per_s) continue;
        last = now;
        const secs = @as(f64, @floatFromInt(now - t_scan)) / 1e9;
        const stored = stats.stored.load(.monotonic);
        const plain = stats.bytes.load(.monotonic);
        std.log.info("snapshot write: epoch {d}: {d}/{d} objects, {d} MiB of objects, {d} MiB stored, {d:.0} MB/s stored, {d:.0} MB/s of objects", .{ opts.epoch, stats.objects.load(.monotonic), scan.total(), plain >> 20, stored >> 20, @as(f64, @floatFromInt(stored)) / 1e6 / secs, @as(f64, @floatFromInt(plain)) / 1e6 / secs });
    }
    for (workers, threads) |*w, t| {
        if (t) |th| th.join() else w.run();
    }
    var acc: sig.Ecmh = .{};
    var files: std.ArrayList(snapshot.FileMeta) = .empty;
    defer files.deinit(gpa);
    for (workers) |*w| {
        if (w.err) |e| return e;
        acc.add(&w.acc);
        try files.appendSlice(gpa, w.files.items);
    }
    const root = acc.digest();
    if (opts.expect_root) |want| if (!std.mem.eql(u8, &want, &root)) {
        std.log.err("snapshot write: epoch {d}: root {x} != certified {x}; nothing published", .{ opts.epoch, root, want });
        return error.RootMismatch;
    };
    const m: snapshot.Manifest = .{ .snapshot_version = 1, .address_length = 32, .files = files.items, .epoch = opts.epoch };
    var mb: std.ArrayList(u8) = .empty;
    defer mb.deinit(gpa);
    try snapshot.writeManifest(gpa, &m, &mb);
    try dir.writeFile(io, .{ .sub_path = "MANIFEST", .data = mb.items });
    return .{
        .root = root,
        .objects = stats.objects.load(.monotonic),
        .bytes = stats.bytes.load(.monotonic),
        .stored = stats.stored.load(.monotonic),
        .files = stats.files.load(.monotonic),
        .ms = (source_mod.nowNs() - t0) / std.time.ns_per_ms,
    };
}

/// The ECMH live object set root as of checkpoint `checkpoint` (no files): `deepwave-tool
/// state-hash`, sui-node's end-of-epoch state check.
pub fn liveRoot(gpa: std.mem.Allocator, st: *store.Store, checkpoint: u64, threads: u32, objects: *Atomic(u64)) ![32]u8 {
    const Hasher = struct {
        scan: *store.LiveScan,
        objects: *Atomic(u64),
        acc: sig.Ecmh = .{},
        err: ?anyerror = null,
        digests: [64][32]u8 = undefined,
        dp: [64][]const u8 = undefined,
        nd: usize = 0,
        fn run(h: *@This()) void {
            while (h.scan.next()) |g| h.scan.group(g, h, onItem) catch |e| {
                h.err = e;
                return;
            };
            h.acc.insertAll(h.dp[0..h.nd]);
        }
        fn onItem(h: *@This(), o: store.LiveIter.Item) anyerror!void {
            h.digests[h.nd] = o.digest();
            h.dp[h.nd] = &h.digests[h.nd];
            h.nd += 1;
            if (h.nd == h.digests.len) {
                h.acc.insertAll(h.dp[0..h.nd]);
                h.nd = 0;
            }
            _ = h.objects.fetchAdd(1, .monotonic);
        }
    };
    var scan = try store.LiveScan.init(gpa, st, checkpoint + 1);
    defer scan.deinit();
    const nt: u32 = @max(1, threads);
    const hs = try gpa.alloc(Hasher, nt);
    defer gpa.free(hs);
    for (hs) |*h| h.* = .{ .scan = &scan, .objects = objects };
    const ts = try gpa.alloc(?std.Thread, nt);
    defer gpa.free(ts);
    for (hs, ts) |*h, *t| t.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, Hasher.run, .{h}) catch null;
    for (hs, ts) |*h, t| {
        if (t) |th| th.join() else h.run();
    }
    var acc: sig.Ecmh = .{};
    for (hs) |*h| {
        if (h.err) |e| return e;
        acc.add(&h.acc);
    }
    return acc.digest();
}

// ------------------------------------------------------------------ tests

fn testId(n: u64) [32]u8 {
    var id: [32]u8 = @splat(0);
    std.mem.writeInt(u64, id[24..32], n, .big);
    return id;
}

fn testPut(b: *store.Batch, n: u64, version: u64, payload: []const u8) !void {
    var d: [32]u8 = @splat(@intCast(version & 0xff));
    d[0] = @intCast(n & 0xff);
    try b.putObject(&testId(n), version, &d, payload);
}

fn histSet(gpa: std.mem.Allocator, st: *store.Store, c1: u64) !std.AutoHashMapUnmanaged(u64, u64) {
    var m: std.AutoHashMapUnmanaged(u64, u64) = .empty;
    var snap: store.Snapshot = .{ .store = st, .c1 = c1, .parity = st.rcu.enter(), .cepoch = st.creaders.enter() };
    defer snap.release();
    var it = store.HistIter.init(&snap, 0, store.HistIter.slots(&snap));
    while (try it.next()) |o| {
        const k = std.mem.readInt(u64, o.id[24..32], .big);
        try std.testing.expect(!m.contains(k)); // each object once
        try m.put(gpa, k, o.version);
    }
    return m;
}

test "snapshot write: the live set as of a past checkpoint, deletions and wraps after it included" {
    try pastViewCase(false);
    try pastViewCase(true);
}

fn pastViewCase(compress: bool) !void {
    const gpa = std.testing.allocator;
    const sim = try store.sim.SimIo.init(gpa, 21, .{}, 8 << 20);
    defer sim.deinit();
    const cfg: store.Config = .{ .max_live_objects = 1024, .max_object_versions = 4096, .max_transactions = 1024, .max_checkpoints = 1024, .max_batch_bytes = 1 << 20, .max_batch_objects = 256, .max_segments = 64, .index_flush_interval = 8, .segment_reserve = 8 << 20, .seed = 5, .compress = compress };
    var s = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var b = try s.begin(10, 1);
    try b.checkpoint("s10", "");
    try testPut(b, 1, 5, "o1v5");
    try testPut(b, 2, 3, "o2v3");
    try testPut(b, 3, 1, "o3v1");
    try s.commit(b);
    b = try s.begin(11, 1); // end of epoch 1
    try b.checkpoint("s11", "");
    try testPut(b, 1, 6, "o1v6");
    try s.commit(b);
    b = try s.begin(12, 2);
    try b.checkpoint("s12", "");
    try testPut(b, 1, 7, "o1v7");
    try b.removeObject(&testId(2), 4, .wrapped);
    try b.removeObject(&testId(3), 2, .deleted);
    try testPut(b, 4, 1, "o4v1");
    try s.commit(b);

    const Want = struct { c1: u64, objs: []const [2]u64 };
    for ([_]Want{
        .{ .c1 = 11, .objs = &.{ .{ 1, 5 }, .{ 2, 3 }, .{ 3, 1 } } },
        .{ .c1 = 12, .objs = &.{ .{ 1, 6 }, .{ 2, 3 }, .{ 3, 1 } } },
        .{ .c1 = 13, .objs = &.{ .{ 1, 7 }, .{ 4, 1 } } },
    }) |want| {
        var m = try histSet(gpa, s, want.c1);
        defer m.deinit(gpa);
        try std.testing.expectEqual(want.objs.len, m.count());
        for (want.objs) |kv| try std.testing.expectEqual(kv[1], m.get(kv[0]).?);
    }

    // the segment-order scan sees the same set at every point (raw segments only: it walks the mapping)
    if (!compress) for ([_]u64{ 11, 12, 13 }) |c1| {
        var want = try histSet(gpa, s, c1);
        defer want.deinit(gpa);
        var sc = store.SegScan.init(s, c1);
        var got: std.AutoHashMapUnmanaged(u64, u64) = .empty;
        defer got.deinit(gpa);
        const Ctx = struct {
            m: *std.AutoHashMapUnmanaged(u64, u64),
            fn add(c: @This(), o: store.LiveIter.Item) anyerror!void {
                const k = std.mem.readInt(u64, o.id[24..32], .big);
                try std.testing.expect(!c.m.contains(k));
                try c.m.put(std.testing.allocator, k, o.version);
            }
        };
        while (sc.next()) |g| try sc.group(g, Ctx{ .m = &got }, Ctx.add);
        try std.testing.expectEqual(want.count(), got.count());
        var it = want.iterator();
        while (it.next()) |kv| try std.testing.expectEqual(kv.value_ptr.*, got.get(kv.key_ptr.*).?);
    };

    // the sorted live scan too, one location per range so the second pass gets several ranges
    for ([_]u64{ 11, 12, 13 }) |c1| {
        var want = try histSet(gpa, s, c1);
        defer want.deinit(gpa);
        var sc = try store.LiveScan.init(gpa, s, c1);
        defer sc.deinit();
        sc.chunk = 1;
        var got: std.AutoHashMapUnmanaged(u64, u64) = .empty;
        defer got.deinit(gpa);
        const Ctx = struct {
            m: *std.AutoHashMapUnmanaged(u64, u64),
            fn add(c: @This(), o: store.LiveIter.Item) anyerror!void {
                const k = std.mem.readInt(u64, o.id[24..32], .big);
                try std.testing.expect(!c.m.contains(k));
                try c.m.put(std.testing.allocator, k, o.version);
            }
        };
        while (sc.next()) |g| try sc.group(g, Ctx{ .m = &got }, Ctx.add);
        try std.testing.expectEqual(want.count(), got.count());
        var it = want.iterator();
        while (it.next()) |kv| try std.testing.expectEqual(kv.value_ptr.*, got.get(kv.key_ptr.*).?);
    }

    // the root as of checkpoint 11 is the ECMH of the stored digests live then, on any thread count
    var acc: sig.Ecmh = .{};
    for ([_][2]u64{ .{ 1, 6 }, .{ 2, 3 }, .{ 3, 1 } }) |kv| {
        var d: [32]u8 = @splat(@intCast(kv[1] & 0xff));
        d[0] = @intCast(kv[0] & 0xff);
        acc.insert(&d);
    }
    var count: Atomic(u64) = .init(0);
    for ([_]u32{ 1, 3 }) |threads| {
        count.store(0, .monotonic);
        const root = try liveRoot(gpa, s, 11, threads, &count);
        try std.testing.expectEqualSlices(u8, &acc.digest(), &root);
        try std.testing.expectEqual(@as(u64, 3), count.load(.monotonic));
    }
}

test "snapshot write: streamed part files pass the restore's checks, on any thread count, zstd or raw" {
    const gpa = std.testing.allocator;
    const types = @import("types");
    const bcs = @import("bcs");
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const sim = try store.sim.SimIo.init(gpa, 23, .{}, 16 << 20);
    defer sim.deinit();
    const cfg: store.Config = .{ .max_live_objects = 4096, .max_object_versions = 8192, .max_transactions = 1024, .max_checkpoints = 1024, .max_batch_bytes = 4 << 20, .max_batch_objects = 2048, .max_segments = 64, .index_flush_interval = 8, .segment_reserve = 16 << 20, .seed = 7 };
    var s = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    const n_obj = 700;
    var b = try s.begin(10, 1);
    try b.checkpoint("s10", "");
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    for (0..n_obj) |i| {
        var id: [32]u8 = undefined;
        r.bytes(&id);
        var contents: [40]u8 = undefined;
        @memcpy(contents[0..32], &id);
        std.mem.writeInt(u64, contents[32..40], i * 7 + 1, .little);
        // a few large objects so parts cut inside the 4 MiB stage and across it
        const big: []u8 = if (i % 97 == 0) try a.alloc(u8, 300_000) else &.{};
        for (big, 0..) |*x, k| x.* = @truncate(k * 31 + i);
        if (big.len > 0) @memcpy(big[0..32], &id);
        const o: types.Object = .{
            .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = 5 + i % 3 }, .contents = if (big.len > 0) big else &contents } },
            .owner = .{ .AddressOwner = .{ .@"0" = @splat(@intCast(i % 11)) } },
            .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
            .storage_rebate = 0,
        };
        const raw = try bcs.encodeAlloc(types.Object, a, &o);
        const k = try @import("exec").objects.keyOf(raw);
        try b.putObject(&k.id, k.version, &types.digest.objectDigest(raw), raw);
    }
    try s.commit(b);
    var count: Atomic(u64) = .init(0);
    const want_root = try liveRoot(gpa, s, 10, 2, &count);
    try std.testing.expectEqual(@as(u64, n_obj), count.load(.monotonic));
    for ([_]snapshot.Compression{ .zstd, .none }) |comp| for ([_]u32{ 1, 3 }) |threads| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var stats: Stats = .{};
        const res = try write(gpa, std.testing.io, s, tmp.dir, .{ .epoch = 1, .checkpoint = 10, .expect_root = want_root, .threads = threads, .compression = comp, .part_max = 64 << 10, .log_every_s = 0 }, &stats);
        try std.testing.expectEqual(@as(u64, n_obj), res.objects);
        try std.testing.expectEqualSlices(u8, &want_root, &res.root);
        const ep = try tmp.dir.openDir(std.testing.io, "epoch_1", .{});
        defer ep.close(std.testing.io);
        const mbytes = try ep.readFileAlloc(std.testing.io, "MANIFEST", a, .limited(1 << 20));
        const m = try snapshot.parseManifest(a, mbytes);
        const parts = try m.partitions(a);
        try std.testing.expect(parts.len > threads); // several parts per writer
        var acc: sig.Ecmh = .{};
        var seen: usize = 0;
        var nb: [64]u8 = undefined;
        for (parts) |p| {
            const ob = try ep.readFileAlloc(std.testing.io, p.obj.?.name(&nb), a, .limited(1 << 30));
            const rb = try ep.readFileAlloc(std.testing.io, p.ref.?.name(&nb), a, .limited(1 << 30));
            var c: snapshot.Checked = .{};
            defer c.deinit(gpa);
            try snapshot.checkPartition(gpa, p, ob, rb, &c);
            seen += c.entries.items.len;
            acc.add(&c.acc);
        }
        try std.testing.expectEqual(@as(usize, n_obj), seen);
        try std.testing.expectEqualSlices(u8, &want_root, &acc.digest());
    };
}
