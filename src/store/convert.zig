//! Offline migration of uncompressed segments (format 2) to compressed ones (format 3,
//! chunk.zig), with identical logical offsets: the live table, the runs and every stored
//! location stay valid, so nothing else is rebuilt. Run on a closed store (`deepwave
//! store-compress DIR`).
//!
//! Per segment: the durable groups (each fully checked, as recovery would) are cut into chunks,
//! compressed on `threads` threads, and written to `seg/<epoch>.log.ctmp` with their directory
//! in `index/<epoch>.dir.ctmp`; both are synced, then renamed over `index/<epoch>.dir` and
//! `seg/<epoch>.log` (dir first: a raw segment ignores a dir file, so a crash between the two
//! renames leaves a valid store either way). Bytes after the last durable group (an
//! unacknowledged tail, which recovery would truncate) are dropped.
const std = @import("std");
const format = @import("format.zig");
const chunk = @import("chunk.zig");
const io_mod = @import("io.zig");
const store = @import("store.zig");

pub const Options = struct {
    threads: u32 = 8,
    chunk_bytes: u32 = 256 << 10,
    /// Logical bytes compressed per parallel batch.
    batch_bytes: usize = 256 << 20,
    max_batch_bytes: usize = 64 << 20,
    /// Chunk codec 2 (record checksums elided, chunk.zig) where a chunk allows it.
    elide_sums: bool = true,
};

pub const Report = struct {
    epoch: u64 = 0,
    raw_bytes: u64 = 0,
    logical_bytes: u64 = 0,
    phys_bytes: u64 = 0,
    dir_bytes: u64 = 0,
    groups: u64 = 0,
    chunks: u64 = 0,
    dropped_tail: u64 = 0,
    ns: u64 = 0,
    skipped: bool = false,
};

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const Job = struct {
    src: []const u8,
    ls: u64,
    ends_group: bool,
    body: ?[]u8 = null,
    codec: u32 = 0,
    failed: bool = false,
};

const Pool = struct {
    jobs: []Job,
    next: std.atomic.Value(usize) = .init(0),
    gpa: std.mem.Allocator,
    /// Segment epoch for codec 2, or null for codec 1.
    epoch: ?u64 = null,

    fn work(p: *Pool, cz: *chunk.zstd_c.Compressor) void {
        defer cz.deinit();
        while (true) {
            const i = p.next.fetchAdd(1, .monotonic);
            if (i >= p.jobs.len) return;
            const j = &p.jobs[i];
            const b = chunk.compressChunkAt(p.gpa, cz, j.src, p.epoch, j.ls, null) catch {
                j.failed = true;
                continue;
            };
            if (b) |x| {
                j.body = x.bytes;
                j.codec = x.codec;
            }
        }
    }
};

/// Converts `seg/<epoch>.log` of the store at `r` (a RealIo on the store directory).
pub fn convertSegment(gpa: std.mem.Allocator, r: *io_mod.RealIo, epoch: u64, opts: Options) !Report {
    const t0 = nowNs();
    var rep: Report = .{ .epoch = epoch };
    var nb: [64]u8 = undefined;
    const name = io_mod.segName(&nb, epoch);
    const fd = try r.openFile(name, false);
    defer r.closeFile(fd);
    const size = try r.size(fd);
    rep.raw_bytes = size;
    if (size >= 8) {
        var m: [8]u8 = undefined;
        try r.read(fd, 0, &m);
        if (std.mem.eql(u8, &m, chunk.file_magic)) {
            rep.skipped = true;
            return rep;
        }
    }
    const data = try r.map(fd, @max(size, 1));
    defer r.unmap(fd, data);
    const view = data[0..size];

    var tb: [80]u8 = undefined;
    const tmp_seg = try std.fmt.bufPrint(&tb, "seg/{d:0>8}.log.ctmp", .{epoch});
    const out_fd = try r.openFile(tmp_seg, true);
    var out_open = true;
    defer if (out_open) r.closeFile(out_fd);
    try r.truncate(out_fd, 0);

    var ents: std.ArrayList(chunk.Entry) = .empty;
    defer ents.deinit(gpa);
    var wbuf: std.ArrayList(u8) = .empty;
    defer wbuf.deinit(gpa);
    var cuts: std.ArrayList(u32) = .empty;
    defer cuts.deinit(gpa);
    var jobs: std.ArrayList(Job) = .empty;
    defer jobs.deinit(gpa);

    var fh: chunk.FileHeader = .{ .epoch = epoch };
    fh.checksum = fh.sum();
    try wbuf.appendNTimes(gpa, 0, chunk.file_header_len);
    @memcpy(wbuf.items[0..@sizeOf(chunk.FileHeader)], std.mem.asBytes(&fh));
    var phys: u64 = 0; // physical offset of wbuf[0]

    var off: u64 = 0;
    var prev: ?u64 = null;
    var done = false;
    while (!done) {
        // One batch of whole groups.
        jobs.clearRetainingCapacity();
        const batch_from = off;
        var batch: usize = 0;
        while (batch < opts.batch_bytes) {
            const g = scanGroupAt(view, epoch, off, prev) orelse {
                done = true;
                break;
            };
            const gb = view[off..][0..g.len];
            cuts.clearRetainingCapacity();
            try chunk.cutGroup(gpa, gb, opts.chunk_bytes, &cuts);
            var from: usize = 0;
            for (cuts.items, 0..) |c, ci| {
                try jobs.append(gpa, .{ .src = gb[from..c], .ls = off + from, .ends_group = ci + 1 == cuts.items.len });
                from = c;
            }
            prev = g.commit_checksum;
            off += g.len;
            batch += g.len;
            rep.groups += 1;
        }
        if (jobs.items.len == 0) break;
        var pool: Pool = .{ .jobs = jobs.items, .gpa = gpa, .epoch = if (opts.elide_sums) epoch else null };
        const nt = @max(1, @min(opts.threads, 256));
        var threads: [256]?std.Thread = @splat(null);
        var czs: [256]chunk.zstd_c.Compressor = @splat(.{});
        for (1..nt) |i| threads[i] = std.Thread.spawn(.{}, Pool.work, .{ &pool, &czs[i] }) catch null;
        pool.work(&czs[0]);
        for (threads[1..nt]) |t| if (t) |th| th.join();
        defer for (jobs.items) |j| if (j.body) |b| gpa.free(b);
        for (jobs.items) |j| {
            if (j.failed) return error.OutOfMemory;
            try chunk.appendFrameC(gpa, &wbuf, phys, j.ls, j.src, j.body, j.codec, &ents);
            if (j.ends_group) try chunk.padGroup(gpa, &wbuf, phys);
            rep.chunks += 1;
        }
        // Flush the written image (whole groups end 4096-aligned), then drop what this batch
        // read and wrote from the page cache: a 200 GB pass must not fill a memory-limited cgroup
        // (the first run on the runner sat in reclaim at 60 GB, 85 MB/s).
        try r.write(out_fd, phys, wbuf.items);
        try r.sync(out_fd);
        r.dropCache(out_fd, phys, wbuf.items.len, false);
        phys += wbuf.items.len;
        wbuf.clearRetainingCapacity();
        io_mod.dontNeed(view[batch_from..off]);
        r.dropCache(fd, batch_from, off - batch_from, false);
        if (off < view.len) io_mod.willNeed(view[off..@min(view.len, off + opts.batch_bytes)]);
    }
    rep.logical_bytes = off;
    rep.dropped_tail = size - off;
    rep.phys_bytes = phys;
    try r.sync(out_fd);

    // Directory file.
    var db: [80]u8 = undefined;
    const tmp_dir = try std.fmt.bufPrint(&db, "index/{d:0>8}.dir.ctmp", .{epoch});
    {
        const dfd = try r.openFile(tmp_dir, true);
        defer r.closeFile(dfd);
        try r.truncate(dfd, 0);
        const seed: u64 = (nowNs() *% 0x9e3779b97f4a7c15) | 1;
        var h: chunk.DirHeader = .{ .epoch = epoch, .seed = seed };
        h.checksum = h.sum();
        var img: std.ArrayList(u8) = .empty;
        defer img.deinit(gpa);
        try img.appendNTimes(gpa, 0, chunk.dir_header_len);
        @memcpy(img.items[0..@sizeOf(chunk.DirHeader)], std.mem.asBytes(&h));
        for (ents.items) |e0| {
            var e = e0;
            chunk.sealEntry(&e, seed);
            try img.appendSlice(gpa, std.mem.asBytes(&e));
        }
        try r.write(dfd, 0, img.items);
        try r.sync(dfd);
        rep.dir_bytes = img.items.len;
    }
    r.closeFile(out_fd);
    out_open = false;
    var fb: [80]u8 = undefined;
    const final_dir = try std.fmt.bufPrint(&fb, "index/{d:0>8}.dir", .{epoch});
    r.root.rename(tmp_dir, r.root, final_dir, r.io) catch return error.Io;
    r.root.rename(tmp_seg, r.root, name, r.io) catch return error.Io;
    try r.syncDir();
    rep.ns = nowNs() - t0;
    return rep;
}

pub const BenchRow = struct {
    chunk_bytes: u32,
    logical: u64,
    phys: u64,
    chunks: u64,
    compress_ns: u64,
    decode_ns: u64,
};

/// Chunk-size study on the first `sample` logical bytes of raw segment `epoch`: for each size,
/// the physical bytes the converter would write (frames and group padding), the compression
/// wall time on `threads` threads, and the single-thread decode time of every chunk.
pub fn benchSegment(gpa: std.mem.Allocator, r: *io_mod.RealIo, epoch: u64, sample: u64, sizes: []const u32, threads: u32, rows: []BenchRow) !void {
    var nb: [64]u8 = undefined;
    const fd = try r.openFile(io_mod.segName(&nb, epoch), false);
    defer r.closeFile(fd);
    const size = try r.size(fd);
    const data = try r.map(fd, @max(size, 1));
    defer r.unmap(fd, data);
    const view = data[0..size];
    var cuts: std.ArrayList(u32) = .empty;
    defer cuts.deinit(gpa);
    var jobs: std.ArrayList(Job) = .empty;
    defer jobs.deinit(gpa);
    var ends: std.ArrayList(bool) = .empty;
    defer ends.deinit(gpa);
    for (sizes, rows) |cb, *row| {
        jobs.clearRetainingCapacity();
        var off: u64 = 0;
        var prev: ?u64 = null;
        while (off < sample) {
            const g = scanGroupAt(view, epoch, off, prev) orelse break;
            const gb = view[off..][0..g.len];
            cuts.clearRetainingCapacity();
            try chunk.cutGroup(gpa, gb, cb, &cuts);
            var from: usize = 0;
            for (cuts.items, 0..) |c, ci| {
                try jobs.append(gpa, .{ .src = gb[from..c], .ls = off + from, .ends_group = ci + 1 == cuts.items.len });
                from = c;
            }
            prev = g.commit_checksum;
            off += g.len;
        }
        const t0 = nowNs();
        var pool: Pool = .{ .jobs = jobs.items, .gpa = gpa, .epoch = epoch };
        const nt = @max(1, @min(threads, 256));
        var ths: [256]?std.Thread = @splat(null);
        var czs: [256]chunk.zstd_c.Compressor = @splat(.{});
        for (1..nt) |i| ths[i] = std.Thread.spawn(.{}, Pool.work, .{ &pool, &czs[i] }) catch null;
        pool.work(&czs[0]);
        for (ths[1..nt]) |t| if (t) |th| th.join();
        const t1 = nowNs();
        defer for (jobs.items) |j| if (j.body) |b| gpa.free(b);
        var phys: u64 = chunk.file_header_len;
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        var dec_ns: u64 = 0;
        for (jobs.items) |j| {
            if (j.failed) return error.OutOfMemory;
            const body = j.body orelse j.src;
            phys += chunk.frameSpan(body.len);
            if (j.ends_group) phys = std.mem.alignForward(u64, phys, format.block);
            try out.resize(gpa, j.src.len);
            const e: chunk.Entry = .{ .ls = j.ls, .phys = 0, .ll = @intCast(j.src.len), .bl = @intCast(body.len), .codec = if (j.body != null) j.codec else 0 };
            const d0 = nowNs();
            try chunk.decode(e, epoch, null, body, out.items);
            dec_ns += nowNs() - d0;
            if (!std.mem.eql(u8, out.items, j.src)) return error.Corrupt;
        }
        row.* = .{ .chunk_bytes = cb, .logical = off, .phys = phys, .chunks = jobs.items.len, .compress_ns = t1 - t0, .decode_ns = dec_ns };
    }
}

fn scanGroupAt(view: []const u8, epoch: u64, off: u64, prev: ?u64) ?struct { len: u64, commit_checksum: u64 } {
    if (off >= view.len) return null;
    const g = store.scanGroupPub(view, epoch, off, prev) orelse return null;
    return .{ .len = g.len, .commit_checksum = g.commit_checksum };
}

test "convert a raw store to compressed segments; it reopens with every record" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPath(io, &pb);
    const path = pb[0..n];
    var cfg: store.Config = .{ .compress = false, .max_batch_bytes = 1 << 20, .segment_reserve = 1 << 20, .max_live_objects = 1 << 12, .max_object_versions = 1 << 12, .max_transactions = 1 << 10, .max_checkpoints = 1 << 10 };
    var payload: [500]u8 = undefined;
    var id: [32]u8 = @splat(0);
    var seq: u64 = 0;
    {
        const r = try io_mod.RealIo.init(gpa, io, path, .{ .sync = .none });
        defer r.deinit();
        const s = try store.Store.open(gpa, .{ .real = r }, &cfg);
        for (0..3) |epoch| for (0..30) |_| {
            seq += 1;
            const b = try s.begin(seq, epoch);
            try b.checkpoint("summary", "contents");
            for (0..10) |k| {
                @memset(&payload, @truncate(seq + k));
                std.mem.writeInt(u64, id[24..32], k + 1, .big);
                try b.putObject(&id, seq, &@as([32]u8, @splat(1)), &payload);
            }
            try s.commit(b);
        };
        try s.close();
    }
    {
        // Baseline: the raw store reads back.
        const r = try io_mod.RealIo.init(gpa, io, path, .{ .sync = .none });
        defer r.deinit();
        const s = try store.Store.open(gpa, .{ .real = r }, &cfg);
        defer s.deinit();
        try checkStore(s, seq);
        var rows: [2]BenchRow = undefined;
        try benchSegment(gpa, r, 1, 1 << 30, &.{ 2048, 8192 }, 2, &rows);
        try std.testing.expect(rows[0].chunks > rows[1].chunks and rows[1].phys < rows[1].logical);
    }
    {
        const r = try io_mod.RealIo.init(gpa, io, path, .{ .sync = .none });
        defer r.deinit();
        for (0..3) |e| {
            const rep = try convertSegment(gpa, r, e, .{ .threads = 3, .chunk_bytes = 2048, .batch_bytes = 64 << 10 });
            try std.testing.expect(!rep.skipped and rep.phys_bytes < rep.logical_bytes and rep.dropped_tail == 0);
        }
        try std.testing.expect((try convertSegment(gpa, r, 0, .{})).skipped);
    }
    cfg.compress = true;
    const r = try io_mod.RealIo.init(gpa, io, path, .{ .sync = .none });
    defer r.deinit();
    const s = try store.Store.open(gpa, .{ .real = r }, &cfg);
    defer s.deinit();
    try checkStore(s, seq);
    try std.testing.expectEqual(@as(u64, 0), s.stats.replayed_groups);
}

fn checkStore(s: *store.Store, seq: u64) !void {
    var id: [32]u8 = @splat(0);
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(?u64, seq), snap.highestCommitted());
    for (1..seq + 1) |q| try std.testing.expectEqualStrings("contents", snap.checkpoint(q).?.contents);
    for (0..10) |k| {
        std.mem.writeInt(u64, id[24..32], k + 1, .big);
        const o = snap.liveObject(&id).?;
        try std.testing.expectEqual(seq, o.version);
        try std.testing.expectEqual(@as(u8, @truncate(seq + k)), o.bytes[0]);
        try std.testing.expect(snap.objectAt(&id, seq - 1) != null);
    }
}
