//! Read-ahead for the store's writer (lane fast-start): warms the page cache for what the next
//! batches will touch, with many reads in flight, so the writer's own accesses through the
//! mappings are minor faults.
//!
//! Why. The live table (34 GB at mainnet scale) and the segments are mapped MADV_RANDOM. Inside a
//! memory-capped cgroup (for example 12 GB high, 16 GB max) the page cache holds a fraction of
//! them, so a follower applying a checkpoint takes one blocking 4 KiB fault per live-table slot
//! and per old record it touches: queue depth 1 against NVMe, 7-18 checkpoints/s.
//!
//! What. `run(ids)` reads, for each object id, (1) the live-table page holding the id's home slot
//! and then, once those are in, (2) the first 8 KiB of the id's live record (the input version a
//! checkpoint's history and index observers read). Reads go through io_uring at `qd` in flight
//! into private buffers that are thrown away: only the page cache side effect matters. Reads are
//! hints. Running concurrently with the writer is safe: lookups are the readers' (`LiveTable.get`)
//! under a store snapshot, which also keeps every file descriptor read here open.
//!
//! Off Linux, with the simulator backend, or without io_uring, `init` returns null.
const std = @import("std");
const builtin = @import("builtin");
const store_mod = @import("store.zig");
const table = @import("table.zig");
const format = @import("format.zig");
const chunk = @import("chunk.zig");
const linux = std.os.linux;
const Atomic = std.atomic.Value;

const is_linux = builtin.os.tag == .linux;
const page = table.page_size;
/// Bytes read at a record's location (header, fixed part and the start of the object).
const rec_bytes = 2 * page;

pub const Stats = struct {
    rounds: Atomic(u64) = .init(0),
    ids: Atomic(u64) = .init(0),
    table_reads: Atomic(u64) = .init(0),
    record_reads: Atomic(u64) = .init(0),
    /// Records in compressed segments: chunk already decoded and cached / frame read ahead.
    chunk_cached: Atomic(u64) = .init(0),
    chunk_reads: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
    ns: Atomic(u64) = .init(0),
};

const Req = struct {
    fd: i32,
    off: u64,
    len: u32,
    fn lt(_: void, a: Req, b: Req) bool {
        return if (a.fd != b.fd) a.fd < b.fd else a.off < b.off;
    }
};

pub const Prefetcher = struct {
    gpa: std.mem.Allocator,
    qd: u32,
    ring: if (is_linux) linux.IoUring else void,
    bufs: []align(page) u8,
    free: []u32,
    reqs: std.ArrayList(Req) = .empty,
    /// Set after a ring failure with reads possibly still in flight: never reused, buffers leaked.
    broken: bool = false,
    stats: Stats = .{},

    /// Null off Linux or when io_uring cannot be set up. `qd`: reads in flight (1..256).
    pub fn init(gpa: std.mem.Allocator, qd_in: u32) !?*Prefetcher {
        if (!is_linux) return null;
        const qd: u32 = std.math.clamp(qd_in, 1, 256);
        const entries: u16 = @intCast(std.math.ceilPowerOfTwo(u32, qd) catch 256);
        var ring = linux.IoUring.init(entries, 0) catch return null;
        errdefer ring.deinit();
        const bufs = try gpa.alignedAlloc(u8, .fromByteUnits(page), @as(usize, qd) * rec_bytes);
        errdefer gpa.free(bufs);
        const free = try gpa.alloc(u32, qd);
        errdefer gpa.free(free);
        const p = try gpa.create(Prefetcher);
        p.* = .{ .gpa = gpa, .qd = qd, .ring = ring, .bufs = bufs, .free = free };
        return p;
    }

    pub fn deinit(p: *Prefetcher) void {
        if (is_linux) {
            if (!p.broken) {
                p.ring.deinit();
                p.gpa.free(p.bufs);
            }
        }
        p.gpa.free(p.free);
        p.reqs.deinit(p.gpa);
        p.gpa.destroy(p);
    }

    /// Warms the live-table pages and live records of `ids` (duplicates are fine).
    pub fn run(p: *Prefetcher, st: *store_mod.Store, ids: []const [32]u8) void {
        if (!is_linux or p.broken or ids.len == 0) return;
        const r = switch (st.backend) {
            .real => |r| r,
            else => return,
        };
        const start = monoNs();
        var snap = st.snapshot();
        defer snap.release();
        const lh = st.live.load(.acquire) orelse return;
        const t = &lh.t;
        const tfd = (r.files[lh.fd] orelse return).handle;

        // (1) live-table pages: the page of each id's home slot, unless the writer holds it dirty
        // (then it is a private copy in memory already).
        p.reqs.clearRetainingCapacity();
        for (ids) |*id| {
            const pg = t.homeSlot(id) / table.per_page;
            const w = @atomicLoad(u64, &t.dirty[pg / 64], .monotonic);
            if (w & (@as(u64, 1) << @intCast(pg % 64)) != 0) continue;
            p.reqs.append(p.gpa, .{ .fd = tfd, .off = pg * page, .len = page }) catch return;
        }
        const n1 = p.drain();
        _ = p.stats.table_reads.fetchAdd(n1, .monotonic);
        if (p.broken) return;

        // (2) the live record of each id (its first 8 KiB, clipped to the segment's durable end).
        // In a compressed segment (the restore image) a location's offset is logical, not the
        // file's: the record is in a chunk's frame, which the reader decodes into the shared
        // chunk cache. Nothing to do when that chunk is cached; else the frame is asked for
        // (POSIX_FADV_WILLNEED: asynchronous, no buffer) so the reader's pread finds it in the
        // page cache. Reading the logical offset instead (before lane catchup-io) read unrelated
        // pages of the compressed file.
        p.reqs.clearRetainingCapacity();
        for (ids) |*id| {
            const lv = t.get(id) orelse continue;
            if (lv & table.tomb != 0) continue;
            const l = table.locOf(lv);
            const e = format.epochOf(l);
            const slot = &st.segs[e & st.seg_mask];
            if (slot.epoch.load(.seq_cst) != e) continue;
            const end = slot.end.load(.acquire);
            const off = format.offsetOf(l);
            if (off >= end) continue;
            if (slot.comp.load(.acquire)) |c| {
                const en = c.dir.load(.acquire).find(off) orelse continue;
                if (st.cache.contains((c.id << format.offset_bits) | en.ls)) {
                    _ = p.stats.chunk_cached.fetchAdd(1, .monotonic);
                    continue;
                }
                const fd = if (chunk.isSide(en.phys)) (r.files[c.side_fd orelse continue] orelse continue) else (r.files[c.fd] orelse continue);
                const phys = en.phys & ~chunk.side_bit;
                _ = linux.fadvise(fd.handle, @intCast(phys), @intCast(chunk.frame_len + en.bl), linux.POSIX_FADV.WILLNEED);
                _ = p.stats.chunk_reads.fetchAdd(1, .monotonic);
                continue;
            }
            const a = std.mem.alignBackward(u64, off, page);
            const len: u32 = @intCast(@min(rec_bytes, std.mem.alignForward(u64, end, page) - a));
            const f = r.files[slot.fd] orelse continue;
            p.reqs.append(p.gpa, .{ .fd = f.handle, .off = a, .len = len }) catch return;
        }
        const n2 = p.drain();
        _ = p.stats.record_reads.fetchAdd(n2, .monotonic);
        _ = p.stats.ids.fetchAdd(ids.len, .monotonic);
        _ = p.stats.rounds.fetchAdd(1, .monotonic);
        _ = p.stats.ns.fetchAdd(monoNs() - start, .monotonic);
    }

    /// Reads the pages `page_nos` (sorted, distinct page numbers) of the file `handle`, `qd` in
    /// flight, and returns once all are in (the ager's read-ahead of live-table pages,
    /// store.zig `ageWarm`): only the page cache side effect matters. Neighbours go in one read.
    /// Returns the reads issued (0 off Linux or after a ring failure).
    pub fn pages(p: *Prefetcher, handle: i32, page_nos: []const u64) u64 {
        if (!is_linux or p.broken or page_nos.len == 0) return 0;
        p.reqs.clearRetainingCapacity();
        for (page_nos) |pg| {
            if (p.reqs.items.len > 0) {
                const last = &p.reqs.items[p.reqs.items.len - 1];
                if (last.len == page and last.off + page == pg * page) {
                    last.len = rec_bytes;
                    continue;
                }
            }
            p.reqs.append(p.gpa, .{ .fd = handle, .off = pg * page, .len = page }) catch break;
        }
        const n = p.drain();
        _ = p.stats.table_reads.fetchAdd(n, .monotonic);
        return n;
    }

    /// Reads every distinct request, `qd` in flight. Returns the reads issued.
    fn drain(p: *Prefetcher) u64 {
        if (!is_linux) return 0;
        std.mem.sort(Req, p.reqs.items, {}, Req.lt);
        // dedup (same fd and page start; keep the longer read)
        var w: usize = 0;
        for (p.reqs.items) |q| {
            if (w > 0 and p.reqs.items[w - 1].fd == q.fd and p.reqs.items[w - 1].off == q.off) {
                p.reqs.items[w - 1].len = @max(p.reqs.items[w - 1].len, q.len);
                continue;
            }
            p.reqs.items[w] = q;
            w += 1;
        }
        const reqs = p.reqs.items[0..w];
        var nfree: usize = p.qd;
        for (p.free, 0..) |*f, i| f.* = @intCast(i);
        var next: usize = 0;
        var inflight: u32 = 0;
        var cqes: [64]linux.io_uring_cqe = undefined;
        while (next < reqs.len or inflight > 0) {
            var queued: u32 = 0;
            while (nfree > 0 and next < reqs.len) {
                const b = p.free[nfree - 1];
                const q = reqs[next];
                const buf = p.bufs[@as(usize, b) * rec_bytes ..][0..q.len];
                _ = p.ring.read(b, q.fd, .{ .buffer = buf }, q.off) catch break;
                nfree -= 1;
                next += 1;
                queued += 1;
            }
            inflight += queued;
            _ = p.ring.submit_and_wait(1) catch {
                p.fail(inflight);
                return next;
            };
            const n = p.ring.copy_cqes(&cqes, 0) catch {
                p.fail(inflight);
                return next;
            };
            for (cqes[0..n]) |c| {
                if (c.res < 0) _ = p.stats.errors.fetchAdd(1, .monotonic);
                p.free[nfree] = @intCast(c.user_data);
                nfree += 1;
                inflight -= 1;
            }
        }
        return reqs.len;
    }

    /// The ring failed: wait out what is in flight if possible, then never use it again.
    fn fail(p: *Prefetcher, inflight_in: u32) void {
        var inflight = inflight_in;
        var cqes: [64]linux.io_uring_cqe = undefined;
        while (inflight > 0) {
            const n = p.ring.copy_cqes(&cqes, 1) catch break;
            inflight -= @min(inflight, n);
        }
        _ = p.stats.errors.fetchAdd(1, .monotonic);
        if (inflight == 0) {
            p.ring.deinit();
            p.gpa.free(p.bufs);
            p.ring = undefined;
            p.bufs = &.{};
        }
        // else: the kernel may still write into bufs; leak them with the ring.
        p.broken = true;
    }
};

test "prefetch: pages reads the given pages of a file, neighbours in one read" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const pf = (try Prefetcher.init(gpa, 8)) orelse return error.SkipZigTest;
    defer pf.deinit();
    const f = try tmp.dir.createFile(io, "t", .{ .read = true });
    defer f.close(io);
    const bytes = try gpa.alloc(u8, 64 * page);
    defer gpa.free(bytes);
    @memset(bytes, 0x5a);
    try f.writePositionalAll(io, bytes, 0);
    // 3 and 4 are neighbours (one read), 5 would be a third page (its own read).
    try std.testing.expectEqual(@as(u64, 6), pf.pages(f.handle, &.{ 0, 3, 4, 5, 9, 40, 41, 63 }));
    try std.testing.expect(!pf.broken);
    try std.testing.expectEqual(@as(u64, 0), pf.stats.errors.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 6), pf.stats.table_reads.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), pf.pages(f.handle, &.{}));
}

fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "prefetch: warms live-table pages and records without changing anything" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    const rio = try @import("io.zig").RealIo.init(gpa, io, path_buf[0..n], .{});
    defer rio.deinit();
    const cfg: store_mod.Config = .{
        .max_live_objects = 4096,
        .max_object_versions = 4096,
        .max_transactions = 1024,
        .max_checkpoints = 1024,
        .max_batch_bytes = 1 << 20,
        .max_batch_objects = 1024,
        .max_segments = 64,
        .segment_reserve = 8 << 20,
    };
    const st = try store_mod.Store.open(gpa, .{ .real = rio }, &cfg);
    defer st.deinit();
    var ids: [300][32]u8 = undefined;
    const b = try st.begin(10, 1);
    try b.checkpoint("summary", "contents");
    for (&ids, 0..) |*id, i| {
        id.* = @splat(0);
        std.mem.writeInt(u64, id[24..32], i *% 0x9e3779b97f4a7c15 +% 1, .little);
        try b.putObject(id, 1, &@as([32]u8, @splat(7)), "object bytes");
    }
    try st.commit(b);
    const pf = (try Prefetcher.init(gpa, 16)) orelse return error.SkipZigTest;
    defer pf.deinit();
    var all: [600][32]u8 = undefined;
    @memcpy(all[0..300], &ids);
    for (all[300..], 0..) |*id, i| { // ids the store does not hold
        id.* = @splat(0xee);
        std.mem.writeInt(u64, id[0..8], i, .little);
    }
    pf.run(st, &all);
    try std.testing.expect(!pf.broken);
    try std.testing.expectEqual(@as(u64, 0), pf.stats.errors.load(.monotonic));
    // The store compresses by default: records are in chunks (cached by the writer's seeding,
    // or read ahead), never read at their logical offsets.
    const st_ = &pf.stats;
    try std.testing.expect(st_.chunk_cached.load(.monotonic) + st_.chunk_reads.load(.monotonic) >= 1);
    try std.testing.expectEqual(@as(u64, 0), st_.record_reads.load(.monotonic));
    var snap = st.snapshot();
    defer snap.release();
    for (&ids) |*id| try std.testing.expectEqualStrings("object bytes", snap.liveObject(id).?.bytes);
}
