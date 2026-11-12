//! Unit tests of the node lane (trust, source, convert, history, snapshot, execute-mode gas price).
//! Tests that need the corpus (`$ZUI_CORPUS`) skip without it.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const store = @import("store");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const sync = @import("sync");
const trust = @import("trust.zig");
const source_mod = @import("source.zig");
const convert = @import("convert.zig");
const history = @import("history.zig");
const snapshot = @import("snapshot.zig");
const retention = @import("retention.zig");
const execute = @import("execute.zig");
const lhfill = @import("lhfill.zig");
const removal_log = @import("removal_log.zig");
const lhist = @import("history");
const p2p_exec = @import("p2p_exec.zig");
const reconcile = @import("reconcile.zig");
const stream_mod = @import("stream.zig");
const sigorder = @import("sigorder.zig");
const netguard = @import("netguard.zig");
const bcs = @import("bcs");
const statehash = @import("statehash.zig");
const sig = @import("sig");
const hash = @import("hash");
const index = @import("index");
const restore_index = @import("restore_index.zig");
const fast_start = @import("fast_start.zig");

fn corpus() ?[]const u8 {
    const p = std.c.getenv("ZUI_CORPUS") orelse return null;
    return std.mem.span(p);
}

fn tmpPath(tmp: *testing.TmpDir, buf: []u8) ![]const u8 {
    const n = try tmp.dir.realPath(testing.io, buf);
    return buf[0..n];
}

fn readCorpus(gpa: std.mem.Allocator, rel: []const u8) ![]u8 {
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, "{s}/{s}", .{ c, rel });
    return Io.Dir.cwd().readFileAlloc(testing.io, path, gpa, .limited(1 << 30)) catch |e| switch (e) {
        error.FileNotFound => return error.SkipZigTest,
        else => return e,
    };
}

// ------------------------------------------------------------------ trust

test "trust: epoch file round trip, with and without epoch parameters" {
    // `.iterate`: trust.save fsyncs the directory, which fails with EBADF on Linux's O_PATH handles
    // (the node opens its epochs dir the same way).
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const keys = [_][96]u8{ @splat(1), @splat(2) };
    const stakes = [_]u64{ 7, 9 };
    const e: trust.EpochInfo = .{ .epoch = 41, .protocol_version = 140, .keys = &keys, .stakes = &stakes, .rgp = 100, .start_ms = 1794009944668 };
    try trust.save(testing.io, tmp.dir, &e);
    const got = (try trust.load(a, testing.io, tmp.dir, 41)).?;
    try testing.expectEqual(@as(u64, 140), got.protocol_version);
    try testing.expectEqualSlices([96]u8, &keys, got.keys);
    try testing.expectEqualSlices(u64, &stakes, got.stakes);
    try testing.expectEqual(@as(?u64, 100), got.rgp);
    try testing.expectEqual(@as(?u64, 1794009944668), got.start_ms);
    // Round 1 files carry no rgp/start_ms.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "42.json", .data = "{\"epoch\":42,\"pv\":141,\"keys\":[],\"stakes\":[]}\n" });
    const old = (try trust.load(a, testing.io, tmp.dir, 42)).?;
    try testing.expectEqual(@as(?u64, null), old.rgp);
    // A file whose epoch does not match its name is refused.
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "43.json", .data = "{\"epoch\":44,\"pv\":141,\"keys\":[],\"stakes\":[]}\n" });
    try testing.expectError(error.BadEpochFile, trust.load(a, testing.io, tmp.dir, 43));
    try testing.expectEqual(@as(?trust.EpochInfo, null), try trust.load(a, testing.io, tmp.dir, 99));
    const hs = (try trust.highestSaved(a, testing.io, tmp.dir, 43)).?;
    try testing.expectEqual(@as(u64, 42), hs.epoch);
}

fn corpusWalker(gpa: std.mem.Allocator, a: std.mem.Allocator, src: *const source_mod.Source, srcs: *[1]*const source_mod.Source) !trust.Walker {
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    srcs[0] = src;
    var w: trust.Walker = .{ .gpa = gpa, .io = testing.io, .sources = srcs, .log = false };
    w.index = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    return w;
}

test "trust: walk from genesis; a wrong end-of-epoch hint fails instead of planting a committee" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const chk = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk.close(testing.io);
    const src: source_mod.Source = .{ .gpa = gpa, .io = testing.io, .kind = .{ .dir = chk } };
    var srcs: [1]*const source_mod.Source = undefined;
    var w = try corpusWalker(gpa, a, &src, &srcs);
    const genesis = try readCorpus(gpa, "vectors/bls-cert/upstream/genesis.blob");
    defer gpa.free(genesis);
    const good = try w.walk(a, genesis, null, 5, std.math.maxInt(u64));
    try testing.expectEqual(@as(u64, 5), good.epoch);
    try testing.expect(good.keys.len > 0);
    try testing.expect(good.start_ms != null);
    // Point epoch 2's end at epoch 3's end: the certificate is checked with committee 2 and the
    // summary's epoch must be 2, so the walk fails.
    const last = try a.dupe(?u64, w.index.last);
    last[2] = last[3];
    w.index.last = last;
    try testing.expectError(error.UntrustedCheckpoint, w.walk(a, genesis, null, 5, std.math.maxInt(u64)));
}

test "trust: a parallel prefetch walk equals the serial walk, and a wrong hint still fails" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const chk = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk.close(testing.io);
    const src: source_mod.Source = .{ .gpa = gpa, .io = testing.io, .kind = .{ .dir = chk } };
    var srcs: [1]*const source_mod.Source = undefined;
    var w = try corpusWalker(gpa, a, &src, &srcs);
    const genesis = try readCorpus(gpa, "vectors/bls-cert/upstream/genesis.blob");
    defer gpa.free(genesis);
    const target: u64 = @min(200, w.index.last.len);
    const serial = try w.walk(a, genesis, null, target, std.math.maxInt(u64));
    w.parallel = 8;
    const par = try w.walk(a, genesis, null, target, std.math.maxInt(u64));
    try testing.expectEqual(serial.epoch, par.epoch);
    try testing.expectEqual(serial.protocol_version, par.protocol_version);
    try testing.expectEqualSlices([96]u8, serial.keys, par.keys);
    try testing.expectEqualSlices(u64, serial.stakes, par.stakes);
    try testing.expectEqual(serial.rgp, par.rgp);
    try testing.expectEqual(serial.start_ms, par.start_ms);
    // With a shared CPU pool the prefetched certificates are checked in parallel windows
    // (trust.zig PreWindow): same answer, and the timing of both for the record.
    const pool = try @import("core").pool.Pool.init(testing.io, gpa, 4);
    defer pool.deinit();
    {
        const old = @import("core").pool.setShared(pool);
        defer _ = @import("core").pool.setShared(old);
        var t0 = std.Io.Timestamp.now(testing.io, .awake);
        const win = try w.walk(a, genesis, null, target, std.math.maxInt(u64));
        const t_win = t0.durationTo(std.Io.Timestamp.now(testing.io, .awake)).nanoseconds;
        try testing.expectEqualSlices([96]u8, serial.keys, win.keys);
        try testing.expectEqualSlices(u64, serial.stakes, win.stakes);
        try testing.expectEqual(serial.epoch, win.epoch);
        try testing.expectEqual(serial.protocol_version, win.protocol_version);
        try testing.expectEqual(serial.rgp, win.rgp);
        try testing.expectEqual(serial.start_ms, win.start_ms);
        _ = @import("core").pool.setShared(old);
        t0 = std.Io.Timestamp.now(testing.io, .awake);
        _ = try w.walk(a, genesis, null, target, std.math.maxInt(u64));
        const t_one = t0.durationTo(std.Io.Timestamp.now(testing.io, .awake)).nanoseconds;
        _ = @import("core").pool.setShared(pool);
        std.debug.print("trust walk {d} epochs (prefetched): one lane {d} ms, 4-lane windows {d} ms\n", .{ target, @divTrunc(t_one, 1_000_000), @divTrunc(t_win, 1_000_000) });
        // a wrong hint inside a window still fails
        const bad = try a.dupe(?u64, w.index.last);
        const saved = w.index.last;
        bad[40] = bad[41];
        w.index.last = bad;
        try testing.expectError(error.UntrustedCheckpoint, w.walk(a, genesis, null, target, std.math.maxInt(u64)));
        w.index.last = saved;
    }
    // Resumed from a saved committee (a short walk) gives the same answer.
    const mid = try w.walk(a, genesis, null, target / 2, std.math.maxInt(u64));
    const resumed = try w.walk(a, genesis, mid, target, std.math.maxInt(u64));
    try testing.expectEqualSlices([96]u8, serial.keys, resumed.keys);
    // A wrong hint in the prefetched range: the certificate is still checked in order.
    const last = try a.dupe(?u64, w.index.last);
    last[40] = last[41];
    w.index.last = last;
    try testing.expectError(error.UntrustedCheckpoint, w.walk(a, genesis, null, target, std.math.maxInt(u64)));
}

test "trust: epoch parameters of every corpus end-of-epoch checkpoint equal the epoch index" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    const L = struct { epoch: u64, last: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var lines: std.ArrayList(L) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        try lines.append(a, try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true }));
    }
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var checked: usize = 0;
    var no_event: usize = 0;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    // Every epoch change in the corpus index (epochs.jsonl comes from Mysten's RPC).
    for (lines.items[0 .. lines.items.len - 1], 0..) |l, i| {
        const next = lines.items[i + 1];
        const last = l.last orelse continue;
        const blob = Io.Dir.cwd().readFileAlloc(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk/{d}.chk", .{ c, last }), gpa, .limited(1 << 30)) catch continue;
        defer gpa.free(blob);
        _ = tmp.reset(.retain_capacity);
        const p = try trust.epochParamsOfBlob(tmp.allocator(), blob, &idx);
        try testing.expectEqual(next.start_ms, p.start_ms);
        // No SystemEpochInfoEvent (safe mode): the node keeps the previous epoch's price.
        try testing.expectEqual(next.rgp, p.rgp orelse l.rgp);
        if (p.rgp == null) no_event += 1;
        checked += 1;
    }
    try testing.expect(checked > 1000);
    try testing.expect(no_event < 4);
}

test "node: pools sized by the node use the usable CPU count (cgroup quota), not the host's" {
    const Node = @import("node.zig").Node;
    try testing.expectEqual(@as(usize, 6), Node.indexBuildThreads(6)); // CPUQuota=600% on a 32-thread host: was 32
    try testing.expectEqual(@as(usize, 32), Node.indexBuildThreads(64));
    try testing.expectEqual(@as(usize, 1), Node.indexBuildThreads(0));
    const usable = Node.usableCpus();
    try testing.expect(usable >= 1 and usable <= (std.Thread.getCpuCount() catch 1));
    try testing.expectEqual(@import("core").hw.detect(null).logical_cores, usable);
}

test "node: the state index build's memory follows the memory the process can use" {
    const Node = @import("node.zig").Node;
    try testing.expectEqual(@as(usize, 2 << 30), Node.indexBuildMemory(16 << 30)); // MemoryMax=16G: 2 GiB
    try testing.expectEqual(@as(usize, 1 << 30), Node.indexBuildMemory(8 << 30));
    try testing.expectEqual(@as(usize, 512 << 20), Node.indexBuildMemory(2 << 30));
    try testing.expectEqual(@as(usize, 4 << 30), Node.indexBuildMemory(256 << 30));
    try testing.expectEqual(@as(usize, 1 << 30), Node.indexBuildMemory(0)); // unknown
    // a restore's row buffers: 64 MiB asked for stays (the build caps it for up to 16 threads);
    // 32 and 64 fetch threads share a fifth of the 2 GiB budget
    try testing.expectEqual(@as(usize, 64 << 20), restore_index.laneBytes(64 << 20, 16, 2 << 30));
    try testing.expectEqual(@as(usize, (2 << 30) / 160), restore_index.laneBytes(64 << 20, 32, 2 << 30));
    try testing.expectEqual(@as(usize, (2 << 30) / 320), restore_index.laneBytes(64 << 20, 64, 2 << 30));
    try testing.expectEqual(@as(usize, 1 << 20), restore_index.laneBytes(64 << 20, 64, 64 << 20));
}

// ------------------------------------------------------------------ state index of a restore

/// Real mainnet objects with distinct ids (the newest version seen of each), from the inputs
/// and outputs of a few corpus checkpoints: a live set to restore.
fn sampleLiveSet(gpa: std.mem.Allocator, a: std.mem.Allocator) ![]const []const u8 {
    const Newest = struct { ver: u64, raw: []const u8 };
    var by_id: std.AutoArrayHashMapUnmanaged([32]u8, Newest) = .empty;
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var seq: u64 = 342451160;
    while (seq < 342451184) : (seq += 1) {
        var nb: [64]u8 = undefined;
        const blob = readCorpus(gpa, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{seq})) catch |e| switch (e) {
            error.SkipZigTest => continue,
            else => return e,
        };
        defer gpa.free(blob);
        try types.indexCheckpointData(blob, &idx);
        for (0..idx.tx_count) |i| {
            const t = idx.txAt(i);
            for (idx.objs[t.in_first..][0 .. t.in_count + t.out_count]) |r| {
                const raw = r.slice(blob);
                const k = try exec.objects.keyOf(raw);
                const gop = try by_id.getOrPut(a, k.id);
                if (gop.found_existing and gop.value_ptr.ver >= k.version) continue;
                gop.value_ptr.* = .{ .ver = k.version, .raw = try a.dupe(u8, raw) };
            }
        }
    }
    if (by_id.count() == 0) return error.SkipZigTest;
    const out = try a.alloc([]const u8, by_id.count());
    for (by_id.values(), out) |v, *o| o.* = v.raw;
    return out;
}

/// The table files of a finished state index's base run, in key order.
fn indexTablePaths(gpa: std.mem.Allocator, a: std.mem.Allocator, dir: []const u8, watermark: ?u64) ![]const []const u8 {
    const ix = try index.Index.open(gpa, testing.io, dir, .{ .sync = .none });
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    try testing.expect(ix.db.buildPending() == null);
    try testing.expectEqual(watermark, ix.db.watermark());
    try testing.expectEqual(@as(usize, 1), ix.db.runs.items.len);
    const tabs = ix.db.runs.items[0].tables;
    const out = try a.alloc([]const u8, tabs.len);
    for (tabs, out) |t, *o| o.* = try std.fmt.allocPrint(a, "{s}/index/{d}.tbl", .{ dir, t.gen });
    return out;
}

fn expectSameIndexTables(gpa: std.mem.Allocator, a: std.mem.Allocator, want_dir: []const u8, got_dir: []const u8, watermark: ?u64) !void {
    const want = try indexTablePaths(gpa, a, want_dir, watermark);
    const got = try indexTablePaths(gpa, a, got_dir, watermark);
    try testing.expectEqual(want.len, got.len);
    for (want, got) |wp, gp| {
        const w = try Io.Dir.cwd().readFileAlloc(testing.io, wp, gpa, .limited(1 << 30));
        defer gpa.free(w);
        const g = try Io.Dir.cwd().readFileAlloc(testing.io, gp, gpa, .limited(1 << 30));
        defer gpa.free(g);
        try testing.expect(std.mem.eql(u8, w, g));
    }
}

test "restore: the state index built from the download equals inserts, the image walk and the old build; a killed build resumes without reading the image again" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pb: [512]u8 = undefined;
    const objs = try sampleLiveSet(gpa, a);
    // The end-of-epoch checkpoint the restore ends with (the test root stands in for its
    // commitment, as the snapshot holds a sample, not the epoch's live set).
    const eidx = trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c})) catch return error.SkipZigTest;
    const epoch: u64 = 1303;
    if (epoch >= eidx.last.len) return error.SkipZigTest;
    const seq = eidx.last[@intCast(epoch)] orelse return error.SkipZigTest;
    const blob = try readCorpus(a, try std.fmt.bufPrint(&pb, "chk/{d}.chk", .{seq}));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "snap");
    const snap_dir = try tmp.dir.openDir(testing.io, "snap", .{});
    defer snap_dir.close(testing.io);
    const root = try snapshot.writeSnapshot(gpa, testing.io, snap_dir, epoch, objs, 97);
    const base = try a.dupe(u8, try tmpPath(&tmp, &pb));
    // the node's record codec: restored objects are compact records, which the image walk reads
    var cfg: store.Config = .{ .dir = try std.fs.path.join(a, &.{ base, "store" }), .max_live_objects = 1 << 16, .segment_reserve = 1 << 28, .codec = exec.objects.store_codec };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var stop: std.atomic.Value(bool) = .init(false);
    const opts: index.lsm.Options = .{ .build_threads = 3, .build_mem_bytes = 16 << 20, .sync = .none };

    // 1. The restore, with the index fed by its fetch threads and built beside the live table.
    const dl_dir = try std.fs.path.join(a, &.{ base, "ix-download" });
    {
        const rib = (try restore_index.Build.begin(gpa, testing.io, h.store, .{ .state_dir = dl_dir, .rpc_dir = null, .lsm = opts, .chunk = 64 << 10, .threads = 3, .signal = &stop })).?;
        defer rib.destroy();
        var stats: snapshot.Stats = .{};
        try snapshot.restore(gpa, testing.io, h.store, .{
            .epoch = epoch,
            .origin = .{ .dir = .{ .root = snap_dir } },
            .threads = 3,
            .eoe_blob = blob,
            .expect_root = root,
            .bulk_live = true,
            .log_every_s = 0,
            .on_partition = rib.partitionHook(),
            .after_objects = rib.doneHook(),
        }, &stats);
        try testing.expectEqual(@as(u64, objs.len), stats.objects.load(.monotonic));
        try h.store.persistLive();
        try rib.finish();
        // level with the store, and the rows inserting the live set gives
        const ix = rib.ix.?;
        try testing.expectEqual(@as(?u64, seq), ix.checkpoint);
        try testing.expectEqual(@as(?u64, seq), ix.db.watermark());
        var mem = try index.Index.init(gpa);
        defer mem.deinit();
        for (objs) |raw| try mem.insert(raw);
        var x = try mem.all(a);
        var y = try ix.all(a);
        var n: usize = 0;
        while (try x.next()) |e| {
            const g = (try y.next()) orelse return error.TestMissingRow;
            try testing.expectEqualSlices(u8, e.key, g.key);
            try testing.expectEqualSlices(u8, e.val.bytes(), g.val.bytes());
            n += 1;
        }
        try testing.expect((try y.next()) == null);
        try testing.expect(n > objs.len / 2);
    }

    // 2. The image walk (a store restored without the stream, or one whose index is gone): one
    //    pass over the restored segment, the same tables.
    const Walk = struct {
        fn run(g: std.mem.Allocator, st: *store.Store, dir: []const u8, o: index.lsm.Options, img: fast_start.Image, flag: *const std.atomic.Value(bool)) !u64 {
            const ix = try index.Index.open(g, testing.io, dir, o);
            defer {
                ix.deinit();
                g.destroy(ix);
            }
            var feed = index.feed.Feed.init(g, ix, st);
            defer feed.deinit();
            var j: fast_start.Job = .{ .gpa = g, .st = st, .image = img, .feed = &feed, .build = true, .signal = flag };
            try j.buildNow();
            return j.image_objects.load(.monotonic);
        }
    };
    const img: fast_start.Image = .{ .epoch = epoch, .at = seq };
    const img_dir = try std.fs.path.join(a, &.{ base, "ix-image" });
    try testing.expect(try Walk.run(gpa, h.store, img_dir, opts, img, &stop) >= objs.len);
    try expectSameIndexTables(gpa, a, dl_dir, img_dir, seq);

    // 3. The old build (four passes over the image): the same tables.
    const old_dir = try std.fs.path.join(a, &.{ base, "ix-old" });
    var old_opts = opts;
    old_opts.bulk = false;
    old_opts.build_chunk_bytes = 64 << 10;
    try testing.expect(try Walk.run(gpa, h.store, old_dir, old_opts, img, &stop) >= 4 * objs.len);
    try expectSameIndexTables(gpa, a, dl_dir, old_dir, seq);

    // 4. Killed while it writes its tables: the next build reads no object again.
    const kill_dir = try std.fs.path.join(a, &.{ base, "ix-killed" });
    index.bulk.test_crash = .{ .ranges = 5 };
    defer index.bulk.test_crash = null;
    try testing.expectError(error.TestCrash, Walk.run(gpa, h.store, kill_dir, opts, img, &stop));
    index.bulk.test_crash = null;
    try testing.expectEqual(@as(u64, 0), try Walk.run(gpa, h.store, kill_dir, opts, img, &stop));
    try expectSameIndexTables(gpa, a, dl_dir, kill_dir, seq);
}

test "restore: a stop while the index tables are written leaves a restored store; the next start resumes the build, reads no object again and is not live before the index is" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pb: [512]u8 = undefined;
    const objs = try sampleLiveSet(gpa, a);
    const eidx = trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c})) catch return error.SkipZigTest;
    const epoch: u64 = 1303;
    if (epoch >= eidx.last.len) return error.SkipZigTest;
    const seq = eidx.last[@intCast(epoch)] orelse return error.SkipZigTest;
    const blob = try readCorpus(a, try std.fmt.bufPrint(&pb, "chk/{d}.chk", .{seq}));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "snap");
    const snap_dir = try tmp.dir.openDir(testing.io, "snap", .{});
    defer snap_dir.close(testing.io);
    const root = try snapshot.writeSnapshot(gpa, testing.io, snap_dir, epoch, objs, 97);
    const base = try a.dupe(u8, try tmpPath(&tmp, &pb));
    const opts: index.lsm.Options = .{ .build_threads = 3, .build_mem_bytes = 16 << 20, .sync = .none };
    defer index.bulk.test_crash = null;

    // Run 0 is not interrupted (the reference tables). Then: stopped after the rows are sealed,
    // before any table; and stopped with five ranges written.
    const kills = [_]?index.bulk.TestCrash{ null, .sealed, .{ .ranges = 5 } };
    var ref_dir: []const u8 = "";
    for (kills, 0..) |kill, ki| {
        const run = try std.fmt.allocPrint(a, "run{d}", .{ki});
        try tmp.dir.createDirPath(testing.io, try std.fmt.allocPrint(a, "{s}/node", .{run}));
        const node_dir = try tmp.dir.openDir(testing.io, try std.fmt.allocPrint(a, "{s}/node", .{run}), .{});
        defer node_dir.close(testing.io);
        var cfg: store.Config = .{ .dir = try std.fs.path.join(a, &.{ base, run, "store" }), .max_live_objects = 1 << 16, .segment_reserve = 1 << 28, .codec = exec.objects.store_codec };
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        const ix_dir = try std.fs.path.join(a, &.{ base, run, "state-index" });
        var stop: std.atomic.Value(bool) = .init(false);

        // The restore, as Node.restoreSnapshot runs it.
        try snapshot.writeMarker(testing.io, node_dir, .loading, epoch);
        index.bulk.test_crash = kill;
        {
            const rib = (try restore_index.Build.begin(gpa, testing.io, h.store, .{ .state_dir = ix_dir, .rpc_dir = null, .lsm = opts, .chunk = 64 << 10, .threads = 3, .signal = &stop })).?;
            defer rib.destroy();
            var stats: snapshot.Stats = .{};
            try snapshot.restore(gpa, testing.io, h.store, .{
                .epoch = epoch,
                .origin = .{ .dir = .{ .root = snap_dir } },
                .threads = 3,
                .eoe_blob = blob,
                .expect_root = root,
                .bulk_live = true,
                .log_every_s = 0,
                .on_partition = rib.partitionHook(),
                .after_objects = rib.doneHook(),
            }, &stats);
            try testing.expectEqual(snapshot.Marker.loading, (try snapshot.readMarker(testing.io, node_dir)).state);
            if (kill == null) {
                try testing.expect(try restore_index.finishRestore(testing.io, node_dir, h.store, epoch, rib));
            } else {
                // The index build has stopped at the kill point; then the signal, as a SIGTERM
                // (or a kill: nothing more is written to the index either way).
                while (!rib.merged.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
                try testing.expectEqual(@as(?anyerror, error.TestCrash), rib.merge_err);
                stop.store(true, .release);
                try testing.expectError(error.Stopped, restore_index.finishRestore(testing.io, node_dir, h.store, epoch, rib));
            }
        }
        index.bulk.test_crash = null;
        stop.store(false, .release);

        // What the next start reads. The marker: the store is restored, so Node.init neither
        // wipes it nor restores again (it does both only for `loading`, and restores only into
        // an empty store).
        const m = try snapshot.readMarker(testing.io, node_dir);
        try testing.expectEqual(snapshot.Marker.done, m.state);
        try testing.expectEqual(epoch, m.epoch);
        try testing.expectEqual(@as(?u64, seq), h.store.committed());
        try testing.expectEqual(@as(u64, objs.len), h.store.liveCount());
        if (kill == null) {
            ref_dir = ix_dir;
            _ = try indexTablePaths(gpa, a, ix_dir, seq);
            continue;
        }
        // The index: its own state says it is not built, whatever the marker says.
        const ix = try index.Index.open(gpa, testing.io, ix_dir, opts);
        var ix_open = true;
        defer if (ix_open) {
            ix.deinit();
            gpa.destroy(ix);
        };
        try testing.expect(ix.db.watermark() == null);
        try testing.expect(ix.db.buildPending() != null);
        var feed = index.feed.Feed.init(gpa, ix, h.store);
        defer feed.deinit();
        var img: fast_start.Image = undefined;
        {
            var snap = h.store.snapshot();
            defer snap.release();
            // Node.startIndexes: a reason to build and a restore image mean the background job
            try testing.expectEqualStrings("resume build", feed.buildReason(&snap).?);
            img = fast_start.findImage(&snap, m.epoch) orelse return error.TestNoImage;
            try testing.expectEqual(seq, img.at);
        }
        {
            const st = index.bulk.State.read(gpa, ix.db.files.?) orelse return error.TestNoState;
            defer gpa.destroy(st);
            try testing.expectEqual(index.bulk.State.Phase.sort, st.phase);
            try testing.expectEqual(seq, st.tip);
            switch (kill.?) {
                .sealed => try testing.expectEqual(@as(u64, 0), st.ranges_done),
                .ranges => |n| try testing.expect(@popCount(st.ranges_done) >= n),
                else => unreachable,
            }
        }
        // Node.run: the job starts before the servers do. Until it hands over, StateService is
        // UNAVAILABLE (`ready`) and /health is 503 (`indexCaughtUp`).
        var svc: serve.service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0) };
        defer svc.deinit();
        svc.state = index.state.hook(ix);
        var j: fast_start.Job = .{ .gpa = gpa, .st = h.store, .image = img, .feed = &feed, .build = true };
        try j.start();
        try testing.expect(!ix.ready.load(.acquire));
        try testing.expect(!serve.service.indexCaughtUp(&svc, seq));
        while (!j.handoff.load(.acquire) and !j.done.load(.acquire)) {
            try testing.expect(!ix.ready.load(.acquire));
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
        try testing.expect(j.failed == null);
        // built and replayed, but not live until the follower's thread hands over
        try testing.expect(!ix.ready.load(.acquire));
        try testing.expect(!serve.service.indexCaughtUp(&svc, seq));
        j.onCommitted(seq);
        try testing.expect(j.failed == null);
        try testing.expect(ix.ready.load(.acquire));
        try testing.expect(serve.service.indexCaughtUp(&svc, seq));
        try testing.expectEqual(@as(?u64, seq), ix.checkpoint);
        // resumed from load.state: no object of the image was read, let alone fetched
        try testing.expectEqual(@as(u64, 0), j.image_objects.load(.monotonic));
        try testing.expect(ix.db.buildPending() == null);
        ix.deinit();
        gpa.destroy(ix);
        ix_open = false;
        try expectSameIndexTables(gpa, a, ref_dir, ix_dir, seq);
    }
}

const IndexDiff = struct {
    /// Rows both hold, by table (key byte 0: owners, 1: balances, 2 and up: coins).
    same: [3]u64 = @splat(0),
    /// Rows only `got` holds, rows only `want` holds, rows whose values differ.
    extra: [3]u64 = @splat(0),
    missing: [3]u64 = @splat(0),
    changed: [3]u64 = @splat(0),

    fn total(d: *const IndexDiff) u64 {
        var n: u64 = 0;
        for (d.extra, d.missing, d.changed) |x, y, z| n += x + y + z;
        return n;
    }
};

/// Every row of two state indexes, compared in key order.
fn indexDiff(a: std.mem.Allocator, want: *const index.Index, got: *const index.Index) !IndexDiff {
    var d: IndexDiff = .{};
    var x = try got.all(a);
    var y = try want.all(a);
    var ex = try x.next();
    var ey = try y.next();
    while (ex != null or ey != null) {
        const ord: std.math.Order = if (ex == null) .gt else if (ey == null) .lt else std.mem.order(u8, ex.?.key, ey.?.key);
        switch (ord) {
            .lt => {
                d.extra[@min(ex.?.key[0], 2)] += 1;
                ex = try x.next();
            },
            .gt => {
                d.missing[@min(ey.?.key[0], 2)] += 1;
                ey = try y.next();
            },
            .eq => {
                const t = @min(ex.?.key[0], 2);
                if (ex.?.val.op == ey.?.val.op and std.mem.eql(u8, ex.?.val.bytes(), ey.?.val.bytes())) d.same[t] += 1 else d.changed[t] += 1;
                ex = try x.next();
                ey = try y.next();
            },
        }
    }
    return d;
}

const FastBuilt = struct { ix: *index.Index, missing_old: u64, replayed: u64, objects: u64 };

/// A fast-start job as the node runs it: the state index built in `dir` from the restore image
/// `img` (null: from a live-table scan), the stored checkpoints after it replayed, the handoff.
fn fastBuild(gpa: std.mem.Allocator, st: *store.Store, dir: []const u8, img: ?fast_start.Image, tip: u64) !FastBuilt {
    const ix = try index.Index.open(gpa, testing.io, dir, .{ .build_threads = 3, .build_mem_bytes = 16 << 20, .sync = .none });
    errdefer {
        ix.deinit();
        gpa.destroy(ix);
    }
    var feed = index.feed.Feed.init(gpa, ix, st);
    defer feed.deinit();
    var j: fast_start.Job = .{ .gpa = gpa, .st = st, .image = img, .feed = &feed, .build = true };
    try j.start();
    while (!j.handoff.load(.acquire) and !j.done.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    if (j.failed) |e| {
        j.shutdown();
        return e;
    }
    j.onCommitted(tip);
    if (j.failed) |e| return e;
    try testing.expect(ix.ready.load(.acquire));
    try testing.expectEqual(@as(?u64, tip), ix.checkpoint);
    return .{ .ix = ix, .missing_old = feed.missing_old, .replayed = j.replayed, .objects = j.image_objects.load(.monotonic) };
}

test "fast start: the restore image is refused once the object floor has passed its checkpoint (an index built from it keeps the rows of versions the replay can no longer read)" {
    const gpa = testing.allocator;
    _ = corpus() orelse return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pb: [512]u8 = undefined;
    // 16 consecutive corpus checkpoints. The store is shaped like a restored one: the state of
    // every object they touch as it was before them is the image (compact records in segment
    // e0, the "restored" checkpoint `at` just before the run), the first 8 checkpoints are
    // epoch e0 + 1 and the last 8 epoch e0 + 2.
    const first: u64 = 342451160;
    const n_cp = 16;
    const half = n_cp / 2;
    const at = first - 1;
    const tip = first + n_cp - 1;
    const e0: u64 = 1303;
    const ci = try gpa.create(types.CheckpointIndex);
    defer gpa.destroy(ci);
    ci.* = try types.CheckpointIndex.init(gpa);
    defer ci.deinit(gpa);
    var blobs: [n_cp][]const u8 = undefined;
    var changes: [n_cp][]const index.Index.Change = undefined;
    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    var image: std.ArrayList([]const u8) = .empty;
    var superseded: u64 = 0;
    var removed: u64 = 0;
    for (&blobs, &changes, 0..) |*blob, *chs, i| {
        blob.* = try readCorpus(a, try std.fmt.bufPrint(&pb, "chk/{d}.chk", .{first + i}));
        try types.indexCheckpointData(blob.*, ci);
        var fst: index.feed.Stats = .{};
        chs.* = try index.feed.changesOf(a, ci, blob.*, null, &fst);
        for (chs.*) |c| {
            const k = exec.objects.keyOf(c.new orelse c.old.?) catch continue;
            const g = try seen.getOrPut(a, k.id);
            if (g.found_existing) continue;
            if (c.old) |raw| {
                try image.append(a, raw);
                if (c.new == null) removed += 1 else superseded += 1;
            }
        }
    }
    try testing.expect(image.items.len > 100 and superseded > 50);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const base = try a.dupe(u8, try tmpPath(&tmp, &pb));
    var cfg: store.Config = .{ .dir = try std.fs.path.join(a, &.{ base, "store" }), .max_live_objects = 1 << 16, .segment_reserve = 1 << 28, .codec = exec.objects.store_codec };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    var st = h.store;
    defer st.deinit();
    {
        const b = try st.begin(at, e0);
        try b.checkpoint("restored", "c");
        for (image.items) |raw| {
            const k = try exec.objects.keyOf(raw);
            try b.putBase(&k.id, k.version, &store.objectDigest(raw), raw);
        }
        try st.commit(b);
    }
    // The checkpoints as the follower stores them: summary, contents, transactions with their
    // effects, output objects and removals. No input copies: an old version is found through
    // the link its successor's record carries.
    for (blobs, changes, 0..) |blob, chs, i| {
        const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
        const b = try st.begin(first + i, if (i < half) e0 + 1 else e0 + 2);
        try b.checkpoint(try bcs.encodeAlloc(@TypeOf(cp.checkpoint_summary), a, &cp.checkpoint_summary), try bcs.encodeAlloc(types.CheckpointContents, a, &cp.checkpoint_contents));
        for (cp.transactions, 0..) |*t, ti| {
            const dg: types.ExecutionDigests = switch (cp.checkpoint_contents) {
                .V1 => |v| v.transactions[ti],
                .V2 => |v| v.transactions[ti].digest,
            };
            const ev: ?[]const u8 = if (t.events) |*e| try bcs.encodeAlloc(types.TransactionEvents, a, e) else null;
            try b.transaction(&dg.transaction.@"0".@"0", &dg.effects.@"0".@"0", try bcs.encodeAlloc(@TypeOf(t.transaction), a, &t.transaction), try bcs.encodeAlloc(types.TransactionEffects, a, &t.effects), ev);
        }
        for (chs) |c| {
            if (c.new) |raw| {
                const k = exec.objects.keyOf(raw) catch continue;
                try b.putObject(&k.id, k.version, &store.objectDigest(raw), raw);
            } else if (c.old) |raw| {
                const k = exec.objects.keyOf(raw) catch continue;
                try b.removeObject(&k.id, k.version + 1, .deleted);
            }
        }
        try st.commit(b);
        // The end of epoch e0 + 1: a close seals the store's memtable into a run of that
        // epoch, as a node's fills and seals within the hour. (A link still in the memtable
        // counts as the newest epoch's and would keep every image version below readable.)
        if (i == half - 1) {
            try st.close();
            st = try store.Store.open(gpa, .{ .real = h.io }, &cfg);
        }
    }
    try testing.expectEqual(@as(?u64, tip), st.committed());
    const dirs = [_][]const u8{ "ix-scan", "ix-image", "ix-late", "ix-node" };
    var built: [dirs.len]?*index.Index = @splat(null);
    defer for (built) |b| if (b) |ix| {
        ix.deinit();
        gpa.destroy(ix);
    };

    // 1. As after the restore (both floors at `at`): the image is found, and an index built
    //    from it and the replay of the 16 checkpoints holds the rows a live-table scan gives.
    _ = try st.setFloors(.{ .cp_pruned = at, .obj_pruned = at, .cp_epoch = e0 + 1, .obj_epoch = e0 + 1 });
    const scan = try fastBuild(gpa, st, try std.fs.path.join(a, &.{ base, dirs[0] }), null, tip);
    built[0] = scan.ix;
    const img: fast_start.Image = blk: {
        var snap = st.snapshot();
        defer snap.release();
        break :blk fast_start.findImage(&snap, e0) orelse return error.TestNoImage;
    };
    try testing.expectEqual(at, img.at);
    const early = try fastBuild(gpa, st, try std.fs.path.join(a, &.{ base, dirs[1] }), img, tip);
    built[1] = early.ix;
    try testing.expectEqual(@as(u64, n_cp), early.replayed);
    try testing.expect(early.objects >= image.items.len);
    const d1 = try indexDiff(a, scan.ix, early.ix);
    std.debug.print("fast start, floors at the restore: image {d} objects ({d} superseded, {d} removed in the 16 checkpoints), {d} rows, {d} differ from the live-table scan's, missing_old {d}\n", .{ image.items.len, superseded, removed, d1.same[0] + d1.same[1] + d1.same[2], d1.total(), early.missing_old });
    try testing.expectEqual(@as(u64, 0), d1.total());
    try testing.expectEqual(@as(u64, 0), early.missing_old);

    // 2. The object floor moves past epoch e0 + 1 while its checkpoints are still held
    //    (object versions are kept for fewer epochs than checkpoints), nothing aged. The
    //    versions superseded in those 8 checkpoints no longer read. An index built from the
    //    image now (what findImage allowed before) lists them from the image, and the replay,
    //    which cannot read them, removes none of their rows.
    _ = try st.setFloors(.{ .cp_pruned = at, .obj_pruned = first + half - 1, .cp_epoch = e0 + 1, .obj_epoch = e0 + 2 });
    const late = try fastBuild(gpa, st, try std.fs.path.join(a, &.{ base, dirs[2] }), img, tip);
    built[2] = late.ix;
    const d2 = try indexDiff(a, scan.ix, late.ix);
    std.debug.print("fast start, object floor past the image's checkpoint, index from the image: owner rows {d} stale, {d} missing, {d} wrong; balance rows {d} stale, {d} missing, {d} wrong; coin rows {d} stale, {d} missing, {d} wrong; missing_old {d}\n", .{ d2.extra[0], d2.missing[0], d2.changed[0], d2.extra[1], d2.missing[1], d2.changed[1], d2.extra[2], d2.missing[2], d2.changed[2], late.missing_old });
    try testing.expect(late.missing_old > 0);
    try testing.expect(d2.extra[0] > 0);
    try testing.expect(d2.total() > 0);

    // 3. So the image is refused, and the node builds from the live-table scan: the right rows.
    const now_img: ?fast_start.Image = blk: {
        var snap = st.snapshot();
        defer snap.release();
        break :blk fast_start.findImage(&snap, e0);
    };
    const node = try fastBuild(gpa, st, try std.fs.path.join(a, &.{ base, dirs[3] }), now_img, tip);
    built[3] = node.ix;
    const d3 = try indexDiff(a, scan.ix, node.ix);
    try testing.expectEqual(@as(u64, 0), d3.total());
    try testing.expectEqual(@as(u64, 0), node.missing_old);
    try testing.expect(now_img == null);
}

// ------------------------------------------------------------------ source

test "source: latest() finds the highest sequence by doubling and bisection" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    for (1000..1138) |s| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "" });
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    try testing.expectEqual(@as(u64, 1137), try src.latest(1000));
    try testing.expectEqual(@as(u64, 1137), try src.latest(1137));
    try testing.expectError(error.SourceMissing, src.latest(999));
    try testing.expect(!source_mod.isTransient(error.WrongCheckpoint));
    try testing.expect(!source_mod.isTransient(error.BadData));
    try testing.expect(source_mod.isTransient(error.ConnectionResetByPeer));
}

test "source: a fetcher that falls behind the tip fetches in parallel again" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    for (100..400) |s| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "x" });
    try tmp.dir.createDir(testing.io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(testing.io, "spool", .{ .iterate = true });
    defer spool.close(testing.io);
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    var applied: std.atomic.Value(u64) = .init(100);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = spool, .next = .init(100), .applied_next = &applied, .window = 1000, .poll_ms = 1, .to = 399 };
    // As after a miss at the tip: one poller at a time.
    f.frontier.store(100, .release);
    try f.start(4);
    var waited: u32 = 0;
    while (f.stats.fetched.load(.acquire) < 300 and waited < 5000) : (waited += 1) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    f.stop();
    try testing.expectEqual(@as(u64, 300), f.stats.fetched.load(.acquire));
    try testing.expectEqual(@as(u64, 0), f.stats.misses.load(.acquire));
    try testing.expect(f.stats.behind.load(.acquire) >= 1);
    try testing.expectEqual(std.math.maxInt(u64), f.frontier.load(.acquire));
}

test "source: at the tip, a burst of checkpoints is fetched by lookahead tries, and every checkpoint arrives once" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    try tmp.dir.createDir(testing.io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(testing.io, "spool", .{ .iterate = true });
    defer spool.close(testing.io);
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    var applied: std.atomic.Value(u64) = .init(100);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = spool, .next = .init(100), .applied_next = &applied, .window = 1000, .poll_ms = 2, .to = 159, .lookahead = 4, .behind_hits = 1000 };
    try f.start(6);
    // The source publishes in bursts of 6 every 20 ms; the node is at the tip throughout.
    var s: u64 = 100;
    while (s < 160) : (s += 6) {
        for (s..s + 6) |q| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{q}), .data = "x" });
        testing.io.sleep(.fromMilliseconds(20), .awake) catch {};
    }
    var waited: u32 = 0;
    while (f.stats.fetched.load(.acquire) < 60 and waited < 5000) : (waited += 1) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    f.stop();
    try testing.expectEqual(@as(u64, 60), f.stats.fetched.load(.acquire));
    for (100..160) |q| _ = try spool.statFile(testing.io, try std.fmt.bufPrint(&nb, "{d}.chk", .{q}), .{});
    // Bursts were fetched in parallel, not one request at a time.
    try testing.expect(f.stats.lookahead_hits.load(.acquire) > 0);
}

test "source: a frontier left on an already fetched checkpoint moves on" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var nb: [32]u8 = undefined;
    for (100..400) |s| try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "x" });
    try tmp.dir.createDir(testing.io, "spool", .default_dir);
    const spool = try tmp.dir.openDir(testing.io, "spool", .{ .iterate = true });
    defer spool.close(testing.io);
    // 150 and 151 were fetched by requests that returned before an earlier miss lowered the
    // frontier; that miss's own hit then left the frontier on 150, which no thread owns.
    for (150..152) |s| try spool.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.chk", .{s}), .data = "x" });
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .{ .dir = tmp.dir } };
    var applied: std.atomic.Value(u64) = .init(140);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = spool, .next = .init(152), .applied_next = &applied, .window = 1000, .poll_ms = 1, .to = 399 };
    f.frontier.store(150, .release);
    try f.start(4);
    var waited: u32 = 0;
    while (f.stats.fetched.load(.acquire) < 248 and waited < 5000) : (waited += 1) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    f.stop();
    try testing.expectEqual(@as(u64, 248), f.stats.fetched.load(.acquire));
}

test "source: writeSpool announces a checkpoint once its .chk and .aux are in place" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .none };
    var applied: std.atomic.Value(u64) = .init(100);
    const Seen = struct {
        dir: Io.Dir,
        calls: u32 = 0,
        last: u64 = 0,
        complete: bool = true,
        fn on(ctx: *anyopaque, seq: u64) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.calls += 1;
            s.last = seq;
            // A follower worker woken here opens the file at once: both must be readable.
            var nb: [32]u8 = undefined;
            inline for (.{ "{d}.chk", "{d}.aux" }) |fmt| {
                _ = s.dir.statFile(testing.io, std.fmt.bufPrint(&nb, fmt, .{seq}) catch unreachable, .{}) catch {
                    s.complete = false;
                };
            }
        }
    };
    var seen: Seen = .{ .dir = tmp.dir };
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = tmp.dir, .next = .init(100), .applied_next = &applied, .window = 64, .poll_ms = 25, .to = std.math.maxInt(u64) };
    f.on_spooled = .{ .ctx = &seen, .call = Seen.on };
    try f.writeSpool(100, "blob", "aux");
    try testing.expectEqual(@as(u32, 1), seen.calls);
    try testing.expectEqual(@as(u64, 100), seen.last);
    try testing.expect(seen.complete);
    try f.writeSpool(101, "blob", "aux");
    try testing.expectEqual(@as(u32, 2), seen.calls);
    try testing.expectEqual(@as(u64, 101), seen.last);
    try testing.expect(seen.complete);
    // The node's safety net is far above the old 2 ms poll and at most a checkpoint interval.
    const fb = @import("node.zig").Node.spool_fallback_ms;
    try testing.expect(fb >= 100 and fb <= 250);
}

// ------------------------------------------------------------------ convert

fn pbField(out: *std.ArrayList(u8), gpa: std.mem.Allocator, num: u32, payload: []const u8) !void {
    try pbVarint(out, gpa, (@as(u64, num) << 3) | 2);
    try pbVarint(out, gpa, payload.len);
    try out.appendSlice(gpa, payload);
}
fn pbVarint(out: *std.ArrayList(u8), gpa: std.mem.Allocator, v: u64) !void {
    var x = v;
    while (x >= 0x80) : (x >>= 7) try out.append(gpa, @as(u8, @truncate(x)) | 0x80);
    try out.append(gpa, @truncate(x));
}
/// A `Bcs`-holder message: field 1 = Bcs { value = 2 }.
fn holder(gpa: std.mem.Allocator, value: []const u8) ![]u8 {
    var bcs_msg: std.ArrayList(u8) = .empty;
    defer bcs_msg.deinit(gpa);
    try pbField(&bcs_msg, gpa, 2, value);
    var h: std.ArrayList(u8) = .empty;
    try pbField(&h, gpa, 1, bcs_msg.items);
    return h.toOwnedSlice(gpa);
}

test "convert: repeated scalar and message fields merge like prost" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var p: std.ArrayList(u8) = .empty;
    defer p.deinit(gpa);
    const s1 = try holder(gpa, "first");
    defer gpa.free(s1);
    const s2 = try holder(gpa, "second");
    defer gpa.free(s2);
    try pbField(&p, gpa, 3, s1); // summary
    try pbField(&p, gpa, 3, s2); // summary again: merged, the last bcs value wins
    // signature twice: epoch from the first, bytes from the second (message merge).
    var sig1: std.ArrayList(u8) = .empty;
    defer sig1.deinit(gpa);
    try pbVarint(&sig1, gpa, (1 << 3) | 0);
    try pbVarint(&sig1, gpa, 77);
    var sig2: std.ArrayList(u8) = .empty;
    defer sig2.deinit(gpa);
    try pbField(&sig2, gpa, 2, "sig-bytes");
    try pbField(&p, gpa, 4, sig1.items);
    try pbField(&p, gpa, 4, sig2.items);
    // one transaction whose effects carry two loaded runtime objects
    var refm: std.ArrayList(u8) = .empty;
    defer refm.deinit(gpa);
    try pbField(&refm, gpa, 1, "0x2");
    try pbVarint(&refm, gpa, (2 << 3) | 0);
    try pbVarint(&refm, gpa, 9);
    var eff: std.ArrayList(u8) = .empty;
    defer eff.deinit(gpa);
    try pbField(&eff, gpa, 15, refm.items);
    try pbField(&eff, gpa, 15, refm.items);
    var tx: std.ArrayList(u8) = .empty;
    defer tx.deinit(gpa);
    try pbField(&tx, gpa, 4, eff.items);
    try pbField(&p, gpa, 6, tx.items);
    const parsed = try convert.parse(arena.allocator(), p.items);
    try testing.expectEqualStrings("second", parsed.summary.?);
    try testing.expectEqual(@as(u64, 77), parsed.sig.epoch);
    try testing.expectEqualStrings("sig-bytes", parsed.sig.signature);
    try testing.expectEqual(@as(usize, 1), parsed.txs.items.len);
    try testing.expectEqual(@as(usize, 2), parsed.txs.items[0].loaded.items.len);
}

test "convert: content signatures, V1 with fewer signature lists than transactions, V2 alias versions" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    // V1: 2 transactions, 1 signature list of 1 signature (3 bytes).
    var v1: std.ArrayList(u8) = .empty;
    defer v1.deinit(gpa);
    try v1.appendSlice(gpa, &.{ 0, 2 });
    for (0..4) |_| {
        try v1.append(gpa, 32);
        try v1.appendSlice(gpa, &@as([32]u8, @splat(5)));
    }
    try v1.appendSlice(gpa, &.{ 1, 1, 3, 0xaa, 0xbb, 0xcc });
    const s1 = try convert.contentSignaturesForTest(a, v1.items);
    try testing.expectEqual(@as(usize, 1), s1.len); // zip: min(2 transactions, 1 list)
    try testing.expectEqualSlices(u8, &.{ 1, 3, 0xaa, 0xbb, 0xcc }, s1[0].raw.?);
    // V2: 1 transaction with 2 signatures, one with an alias version (dropped in the envelope).
    var v2: std.ArrayList(u8) = .empty;
    defer v2.deinit(gpa);
    try v2.appendSlice(gpa, &.{ 1, 1 });
    for (0..2) |_| {
        try v2.append(gpa, 32);
        try v2.appendSlice(gpa, &@as([32]u8, @splat(6)));
    }
    try v2.appendSlice(gpa, &.{ 2, 2, 0x11, 0x22, 0 });
    try v2.appendSlice(gpa, &.{ 1, 0x33, 1 });
    try v2.appendSlice(gpa, &@as([8]u8, @splat(0)));
    const s2 = try convert.contentSignaturesForTest(a, v2.items);
    try testing.expectEqual(@as(usize, 1), s2.len);
    try testing.expectEqual(@as(usize, 2), s2[0].parts.len);
    try testing.expectEqualSlices(u8, &.{ 2, 0x11, 0x22 }, s2[0].parts[0]);
    try testing.expectEqualSlices(u8, &.{ 1, 0x33 }, s2[0].parts[1]);
}

test "convert: a source's own signature order is kept only when it is the contents' signatures" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sa = [_]u8{ 0, 0xa1, 0xa2 };
    const sb = [_]u8{ 1, 0xb1 };
    // V1 list [A, B]: count 2, then each signature length-prefixed
    const v1: convert.SigList = .{ .raw = &[_]u8{ 2, 3, 0, 0xa1, 0xa2, 2, 1, 0xb1 } };
    // V2 parts [A, B]
    const v2: convert.SigList = .{ .parts = &.{ &[_]u8{ 3, 0, 0xa1, 0xa2 }, &[_]u8{ 2, 1, 0xb1 } } };
    for ([_]convert.SigList{ v1, v2 }) |s| {
        try testing.expect(try convert.txSignaturesForTest(a, &.{ &sb, &sa }, s)); // sponsor first: kept
        try testing.expect(try convert.txSignaturesForTest(a, &.{ &sa, &sb }, s));
        try testing.expect(!try convert.txSignaturesForTest(a, &.{}, s)); // none rendered: contents
        try testing.expect(!try convert.txSignaturesForTest(a, &.{&sa}, s)); // one missing
        try testing.expect(!try convert.txSignaturesForTest(a, &.{ &sa, &sa }, s)); // not a multiset match
        try testing.expect(!try convert.txSignaturesForTest(a, &.{ &sa, &[_]u8{ 1, 0xb2 } }, s)); // foreign
    }
}

test "convert: aux records of a corpus checkpoint parse, and corrupt ones are refused" {
    const gpa = testing.allocator;
    const z = readCorpus(gpa, "binpb-done/342451160.binpb.zst") catch |e| return e;
    defer gpa.free(z);
    const proto = try convert.unzstd(gpa, z, 1 << 30);
    defer gpa.free(proto);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    // The fetch path's direct decode gives the same bytes.
    try testing.expectEqual(@as(?u64, null), convert.zstdContentSize(z)); // streamed frame
    try testing.expectEqualSlices(u8, proto, try convert.unzstdArena(arena.allocator(), z, 1 << 30));
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    const seq = try convert.protoToChkAux(gpa, arena.allocator(), proto, &blob, &aux);
    try testing.expectEqual(@as(u64, 342451160), seq);
    const x = try convert.Aux.parse(arena.allocator(), aux.items);
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(blob.items, &idx);
    try testing.expectEqual(@as(usize, idx.tx_count), x.loaded.len);
    // The same blob as protoToChk.
    var blob2: std.ArrayList(u8) = .empty;
    defer blob2.deinit(gpa);
    _ = try convert.protoToChk(gpa, arena.allocator(), proto, &blob2);
    try testing.expectEqualSlices(u8, blob2.items, blob.items);
    try testing.expectError(error.BadAux, convert.Aux.parse(arena.allocator(), aux.items[0 .. aux.items.len - 1]));
    try testing.expectError(error.BadAux, convert.Aux.parse(arena.allocator(), "ZUIAUX00"));
}

// ------------------------------------------------------------------ convert: signature order

/// Checkpoint 343111673 from fullnode.mainnet.sui.io's GetCheckpoint with the stream's fields
/// (no objects or events): `sequence_number, summary.bcs, signature, contents.bcs,
/// transactions.transaction.bcs, transactions.effects.bcs, transactions.signatures.bcs`.
/// Transaction 21 (E7yjPX2E3vCrihF1PLvozejauMBSLi6HdgmXZJt9GgwQ) is sponsored and was submitted
/// as [sponsor (secp256k1), sender (ed25519)]; the contents certify [sender, sponsor].
const sigorder_proto = @embedFile("testdata/sigorder-343111673.binpb");
/// sui-node 1.83.1's GetTransaction `signatures` for E7yj... on a production node (2026-11-08), in order.
const sigorder_sui_node = [_][]const u8{
    "014685afc38a32a99b587da789147cd6c389e4cf1ec0bcd798c65b6d2ccf3ebd331d3a212821f129c5bcf06d7fe9c9d3803a09c1f5c273b3e306cd63724b15521d0295e8840129ad8968724518d25f45dfdc29ef7a98efd80799c098df63b9f789fe",
    "0089de0b09a821d278909e89c52ad16c1ddc0e40fc958af7c6297cdda44e3c67fc64fd13a0bab77d11cd62a3cd2849e15e949d20cb41db40bdf937de5d33e87100c0fa2d9c33bf2b110bde70bef8b6a6f3d9d23e2c9bee4a94b48ed512544990a0",
};

fn blobSigs(a: std.mem.Allocator, idx: *types.CheckpointIndex, blob: []const u8, tx: usize) ![]const []const u8 {
    try types.indexCheckpointData(blob, idx);
    const t = idx.txs[tx];
    const out = try a.alloc([]const u8, t.sig_count);
    for (out, idx.sigs[t.sig_first..][0..t.sig_count]) |*o, r| {
        var rd = bcs.Reader.init(r.slice(blob));
        o.* = try rd.bytes(try rd.length());
    }
    return out;
}

test "convert: a full node's transaction signature order is kept when it permutes the certified signatures (sponsored E7yj...)" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var want: [2][]const u8 = undefined;
    for (&want, sigorder_sui_node) |*w, hex| {
        const b = try a.alloc(u8, hex.len / 2);
        _ = try std.fmt.hexToBytes(b, hex);
        w.* = b;
    }

    // Stream proto: sui-node's order (sponsor first).
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    try testing.expectEqual(@as(u64, 343111673), try convert.protoToChk(gpa, a, sigorder_proto, &blob));
    const got = try blobSigs(a, &idx, blob.items, 21);
    try testing.expectEqual(@as(usize, 2), got.len);
    for (want, got) |w, g| try testing.expectEqualSlices(u8, w, g);

    // Contents order (the bucket, or sui-types' conversion): sender first.
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    const certified = try blobSigs(a, &idx, plain.items, 21);
    try testing.expectEqualSlices(u8, want[1], certified[0]);
    try testing.expectEqualSlices(u8, want[0], certified[1]);
    // Same length, and the only bytes that differ are the two signatures of transaction 21.
    try testing.expectEqual(plain.items.len, blob.items.len);
    try types.indexCheckpointData(blob.items, &idx);
    const t21 = idx.txs[21];
    const lo = idx.sigs[t21.sig_first].o;
    const hi = idx.sigs[t21.sig_first + 1].o + idx.sigs[t21.sig_first + 1].n;
    try testing.expectEqualSlices(u8, plain.items[0..lo], blob.items[0..lo]);
    try testing.expectEqualSlices(u8, plain.items[hi..], blob.items[hi..]);
    // Every other transaction keeps the same signatures either way (all equal to the contents').
    for (0..idx.tx_count) |i| {
        if (i == 21) continue;
        const x = try blobSigs(a, &idx, blob.items, i);
        const y = try blobSigs(a, &idx, plain.items, i);
        try testing.expectEqual(x.len, y.len);
        for (x, y) |p, q| try testing.expectEqualSlices(u8, p, q);
    }

    // A proto signature the contents do not certify: the contents order, never the proto's bytes.
    const bad = try a.dupe(u8, sigorder_proto);
    const at = std.mem.lastIndexOf(u8, bad, want[0]).?; // the transaction's copy (after contents)
    bad[at + 10] ^= 1;
    var tampered: std.ArrayList(u8) = .empty;
    defer tampered.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, bad, &tampered);
    try testing.expectEqualSlices(u8, plain.items, tampered.items);
}

// ------------------------------------------------------------------ signature order: bucket overlay

fn pbReadVarint(b: []const u8, i: *usize) !u64 {
    var r: u64 = 0;
    var shift: u6 = 0;
    while (i.* < b.len) {
        const x = b[i.*];
        i.* += 1;
        r |= @as(u64, x & 0x7f) << shift;
        if (x < 0x80) return r;
        if (shift >= 63) return error.Malformed;
        shift += 7;
    }
    return error.Malformed;
}

fn pbPutVarint(a: std.mem.Allocator, out: *std.ArrayList(u8), v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) : (v >>= 7) try out.append(a, @as(u8, @truncate(v)) | 0x80);
    try out.append(a, @truncate(v));
}

fn pbPutLen(a: std.mem.Allocator, out: *std.ArrayList(u8), field: u64, bytes: []const u8) !void {
    try pbPutVarint(a, out, (field << 3) | 2);
    try pbPutVarint(a, out, bytes.len);
    try out.appendSlice(a, bytes);
}

/// One protobuf field: its number, and the bytes of the whole field (key included) and of a
/// length-delimited payload.
const PbField = struct { number: u64, whole: []const u8, payload: []const u8 };

fn pbFields(a: std.mem.Allocator, b: []const u8) ![]PbField {
    var out: std.ArrayList(PbField) = .empty;
    var i: usize = 0;
    while (i < b.len) {
        const start = i;
        const key = try pbReadVarint(b, &i);
        var payload: []const u8 = &.{};
        switch (key & 7) {
            0 => _ = try pbReadVarint(b, &i),
            1 => i += 8,
            5 => i += 4,
            2 => {
                const n = try pbReadVarint(b, &i);
                payload = b[i..][0..n];
                i += n;
            },
            else => return error.Malformed,
        }
        try out.append(a, .{ .number = key >> 3, .whole = b[start..i], .payload = payload });
    }
    return out.items;
}

/// A Checkpoint proto as Mysten's bucket serves it: every transaction's `signatures` (field 3 of
/// ExecutedTransaction, field 6 of Checkpoint) removed.
fn bucketProto(a: std.mem.Allocator, proto: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (try pbFields(a, proto)) |f| {
        if (f.number != 6) {
            try out.appendSlice(a, f.whole);
            continue;
        }
        var tx: std.ArrayList(u8) = .empty;
        for (try pbFields(a, f.payload)) |tf| if (tf.number != 3) try tx.appendSlice(a, tf.whole);
        try pbPutLen(a, &out, 6, tx.items);
    }
    return out.items;
}

/// What `GetCheckpoint { read_mask: sequence_number, transactions.signatures.bcs }` answers:
/// `seq`, then each transaction with only its signatures (the first `max_tx`).
fn overlayProto(a: std.mem.Allocator, proto: []const u8, seq: u64, max_tx: usize) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try pbPutVarint(a, &out, 1 << 3);
    try pbPutVarint(a, &out, seq);
    var n: usize = 0;
    for (try pbFields(a, proto)) |f| {
        if (f.number != 6) continue;
        if (n == max_tx) break;
        n += 1;
        var tx: std.ArrayList(u8) = .empty;
        for (try pbFields(a, f.payload)) |tf| if (tf.number == 3) try tx.appendSlice(a, tf.whole);
        try pbPutLen(a, &out, 6, tx.items);
    }
    return out.items;
}

test "convert: a bucket checkpoint takes the submitted signature order from a GetCheckpoint signatures overlay" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 343111673;

    // sui-node's order (the full node proto as served) and the contents order.
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, sigorder_proto, &want);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    try testing.expect(!std.mem.eql(u8, want.items, plain.items));

    const bucket = try bucketProto(a, sigorder_proto);
    // The bucket proto wants an overlay (transaction 21 is sponsored); the full node's does not.
    try testing.expect(try convert.wantsSigOrder(a, bucket));
    try testing.expect(!try convert.wantsSigOrder(a, sigorder_proto));

    // Without an overlay: the contents order (what main stored for bucket-filled checkpoints).
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, bucket, &got);
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // With the overlay: byte-equal to sui-node's.
    const ov = try overlayProto(a, sigorder_proto, seq, std.math.maxInt(usize));
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = ov });
    try testing.expectEqualSlices(u8, want.items, got.items);
    // The aux record is the same either way.
    var aux_a: std.ArrayList(u8) = .empty;
    defer aux_a.deinit(gpa);
    var aux_b: std.ArrayList(u8) = .empty;
    defer aux_b.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &got, &aux_a, .{});
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, &aux_b, .{ .sig_overlay = ov });
    try testing.expectEqualSlices(u8, aux_a.items, aux_b.items);

    // The option off ignores the overlay (stream-check's comparison).
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = ov, .tx_signature_order = false });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // An overlay for another checkpoint is ignored.
    const other = try overlayProto(a, sigorder_proto, seq + 1, std.math.maxInt(usize));
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = other });
    try testing.expectEqualSlices(u8, plain.items, got.items);
    try testing.expect(convert.overlaySigsForTest(a, other, seq) == null);

    // A short overlay (transaction 21 missing): the contents order.
    const short = try overlayProto(a, sigorder_proto, seq, 21);
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = short });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // A signature the contents do not certify: the contents order, never the overlay's bytes.
    const bad = try a.dupe(u8, ov);
    var sui_sig: [200]u8 = undefined;
    const s0 = try std.fmt.hexToBytes(&sui_sig, sigorder_sui_node[0]);
    const at = std.mem.indexOf(u8, bad, s0).?;
    bad[at + 10] ^= 1;
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = bad });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // Garbage: ignored, the conversion still succeeds.
    _ = try convert.protoToChkOpts(gpa, a, bucket, &got, null, .{ .sig_overlay = &.{ 0xff, 0xff } });
    try testing.expectEqualSlices(u8, plain.items, got.items);

    // The full node's own list wins over an overlay (the overlay only fills absent lists).
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &got, null, .{ .sig_overlay = other });
    try testing.expectEqualSlices(u8, want.items, got.items);
}

test "source: decodeOrdered asks the stream node for a bucket checkpoint's signature order" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 343111673;
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, sigorder_proto, &want);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });

    // The bucket proto in a raw-block zstd frame (single segment, 4-byte content size).
    const bucket = try bucketProto(a, sigorder_proto);
    try testing.expect(bucket.len < 128 << 10);
    var z: std.ArrayList(u8) = .empty;
    try z.appendSlice(a, &.{ 0x28, 0xB5, 0x2F, 0xFD, 0xA0 });
    var fcs: [4]u8 = undefined;
    std.mem.writeInt(u32, &fcs, @intCast(bucket.len), .little);
    try z.appendSlice(a, &fcs);
    const bh: u24 = @intCast(1 | (bucket.len << 3));
    try z.appendSlice(a, &.{ @truncate(bh), @truncate(bh >> 8), @truncate(bh >> 16) });
    try z.appendSlice(a, bucket);

    // The stream node: a grpc-web GetCheckpoint answer carrying the overlay.
    const ov = try overlayProto(a, sigorder_proto, seq, std.math.maxInt(usize));
    var msg: std.ArrayList(u8) = .empty;
    try pbPutLen(a, &msg, 1, ov); // GetCheckpointResponse.checkpoint
    var body: std.ArrayList(u8) = .empty;
    var h: [5]u8 = .{ 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[1..5], @intCast(msg.items.len), .big);
    try body.appendSlice(a, &h);
    try body.appendSlice(a, msg.items);
    const trailer = "grpc-status:0\r\n";
    h = .{ 0x80, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[1..5], trailer.len, .big);
    try body.appendSlice(a, &h);
    try body.appendSlice(a, trailer);
    const reply = try std.fmt.allocPrint(a, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}", .{ body.items.len, body.items });
    var srv: netguard.TestServer = undefined;
    try srv.start(testing.io, reply);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = sigorder.Overlay.init(gpa, testing.io, srv.url(&ub), 20);
    defer o.deinit();

    const src: source_mod.Source = .{ .gpa = gpa, .io = testing.io, .kind = .none };
    var sc = source_mod.Scratch.init(gpa);
    defer sc.deinit(gpa);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    // No overlay configured: the contents order.
    try sc.raw.appendSlice(gpa, z.items);
    try src.decodeOrdered(&sc, seq, &blob, null);
    try testing.expectEqualSlices(u8, plain.items, blob.items);
    // With it: sui-node's order, one request.
    try src.decodeOrdered(&sc, seq, &blob, &o);
    try testing.expectEqualSlices(u8, want.items, blob.items);
    try testing.expectEqual(@as(u64, 1), o.stats.served.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
    // Over budget: no request, the contents order.
    o.pace = .{ .interval_ns = std.time.ns_per_s * 3600, .burst = 1, .tat = .init(std.math.maxInt(u64) / 2) };
    try src.decodeOrdered(&sc, seq, &blob, &o);
    try testing.expectEqualSlices(u8, plain.items, blob.items);
    try testing.expectEqual(@as(u64, 1), o.stats.throttled.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
}

test "p2p: a peer's transaction copy is accepted only when its signatures permute the certified ones" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(testing.allocator);
    _ = try convert.protoToChkOpts(testing.allocator, a, sigorder_proto, &blob, null, .{ .tx_signature_order = false });
    var idx = try types.CheckpointIndex.init(testing.allocator);
    defer idx.deinit(testing.allocator);
    try types.indexCheckpointData(blob.items, &idx);
    const t = idx.txs[21];
    const env = t.transaction.slice(blob.items); // [sender, sponsor]: the contents order
    const s0 = idx.sigs[t.sig_first].slice(blob.items);
    const s1 = idx.sigs[t.sig_first + 1].slice(blob.items);
    const head = env[0 .. env.len - s0.len - s1.len - 1];
    // V2 certified list: (signature, None) each.
    const certified = try std.mem.concat(a, u8, &.{ &.{2}, s0, &.{0}, s1, &.{0} });
    const swapped = try std.mem.concat(a, u8, &.{ head, &.{2}, s1, s0 });
    try testing.expect(try p2p_exec.samePermutation(a, env, certified, true));
    try testing.expect(try p2p_exec.samePermutation(a, swapped, certified, true));
    const one = try std.mem.concat(a, u8, &.{ head, &.{1}, s0 });
    try testing.expect(!try p2p_exec.samePermutation(a, one, certified, true));
    const twice = try std.mem.concat(a, u8, &.{ head, &.{2}, s0, s0 });
    try testing.expect(!try p2p_exec.samePermutation(a, twice, certified, true));
    const flipped = try a.dupe(u8, swapped);
    flipped[flipped.len - 5] ^= 1;
    try testing.expect(!try p2p_exec.samePermutation(a, flipped, certified, true));
    // V1 list: no alias versions.
    const v1 = try std.mem.concat(a, u8, &.{ &.{2}, s0, s1 });
    try testing.expect(try p2p_exec.samePermutation(a, swapped, v1, false));
}

// ------------------------------------------------------------------ store: historical records

test "history: a historical version is readable but never live" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const id: [32]u8 = @splat(1);
    const id2: [32]u8 = @splat(2);
    const d: [32]u8 = @splat(9);
    const b = try h.store.begin(10, 1);
    try b.putObject(&id, 7, &d, "seven");
    try b.putHistorical(&id, 5, &d, "five");
    try b.putHistorical(&id2, 3, &d, "only-historical");
    try h.store.commit(b);
    const b2 = try h.store.begin(11, 1);
    try b2.putHistorical(&id, 6, &d, "six");
    try h.store.commit(b2);
    var snap = h.store.snapshot();
    defer snap.release();
    try testing.expectEqualStrings("seven", snap.liveObject(&id).?.bytes);
    try testing.expectEqualStrings("five", snap.objectAt(&id, 5).?);
    try testing.expectEqualStrings("six", snap.objectAt(&id, 6).?);
    try testing.expect(snap.liveObject(&id2) == null);
    try testing.expectEqualStrings("only-historical", snap.objectAt(&id2, 3).?);
    try testing.expectEqual(@as(u64, 1), h.store.liveCount());
}

fn tKey(bytes: []const u8) ?store.ObjKey {
    if (bytes.len < 40) return null;
    return .{ .id = bytes[0..32].*, .version = std.mem.readInt(u64, bytes[32..40], .little) };
}

fn tObj(buf: []u8, id: u8, version: u64, payload: []const u8) []const u8 {
    buf[0..32].* = @splat(id);
    std.mem.writeInt(u64, buf[32..40], version, .little);
    @memcpy(buf[40..][0..payload.len], payload);
    return buf[0 .. 40 + payload.len];
}

/// What history.onBatch does for one input version of a transaction in `b`'s checkpoint.
fn histInput(st: *store.Store, b: *store.Batch, id: u8, version: u64, consumed: bool, payload: []const u8) !bool {
    var snap = st.snapshot();
    defer snap.release();
    const k: [32]u8 = @splat(id);
    switch (try history.inputAction(&snap, b.epoch, &k, version, consumed)) {
        .present => return false,
        .xref => |target| try b.putXref(&k, version, target),
        .copy => {
            var buf: [128]u8 = undefined;
            const raw = tObj(&buf, id, version, payload);
            try b.putHistorical(&k, version, &store.objectDigest(raw), raw);
        },
    }
    return true;
}

fn putLive(b: *store.Batch, base: bool, id: u8, version: u64, payload: []const u8) !void {
    var buf: [128]u8 = undefined;
    const raw = tObj(&buf, id, version, payload);
    const k: [32]u8 = @splat(id);
    if (base) try b.putBase(&k, version, &store.objectDigest(raw), raw) else try b.putObject(&k, version, &store.objectDigest(raw), raw);
}

test "history: a transaction's input versions stay readable after the epochs that wrote them age out and are cleaned" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20, .codec = .{ .key = tKey }, .clean_record_bytes = 64 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const st = h.store;
    // Epoch 0: a restored set (compact records: X=1, Y=2, plus 100 others), end-of-epoch checkpoint 10.
    {
        const b = try st.begin(0, 0);
        try putLive(b, true, 1, 3, "x3");
        try putLive(b, true, 2, 3, "y3");
        for (0..100) |i| try putLive(b, true, @intCast(100 + i), 3, "filler-object");
        try st.commit(b);
        const c = try st.begin(10, 0);
        try c.checkpoint("s10", "c");
        try st.commit(c);
    }
    // Epoch 1, checkpoint 11: a transaction mutates X (3 -> 11) and reads Y; creates Z=3.
    {
        const b = try st.begin(11, 1);
        try b.checkpoint("s11", "c");
        try testing.expect(try histInput(st, b, 1, 3, true, "x3")); // superseded here: an xref
        try testing.expect(!try histInput(st, b, 2, 3, false, "y3")); // stays live: no copy
        try putLive(b, false, 1, 11, "x11");
        try putLive(b, false, 3, 11, "z11");
        try st.commit(b);
    }
    // Checkpoint 12 (same epoch): the xref of X@3 is already in epoch 1.
    {
        const b = try st.begin(12, 1);
        try b.checkpoint("s12", "c");
        try testing.expect(!try histInput(st, b, 1, 3, true, "x3"));
        try st.commit(b);
    }
    // Epoch 2, checkpoint 13: mutates Z (written in epoch 1) and Y (restored).
    {
        const b = try st.begin(13, 2);
        try b.checkpoint("s13", "c");
        try testing.expect(try histInput(st, b, 3, 11, true, "z11"));
        try testing.expect(try histInput(st, b, 2, 3, true, "y3"));
        try putLive(b, false, 3, 13, "z13");
        try putLive(b, false, 2, 13, "y13");
        try st.commit(b);
    }
    {
        const b = try st.begin(14, 3);
        try b.checkpoint("s14", "c");
        try st.commit(b);
    }
    // Window 1..3: epoch 0 (the restored segment) ages out. Checkpoint 11's inputs still read.
    _ = try st.ageOut(1);
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expectEqualSlices(u8, "x3", snap.objectAt(&@as([32]u8, @splat(1)), 3).?[40..]);
        try testing.expectEqualSlices(u8, "y3", snap.objectAt(&@as([32]u8, @splat(2)), 3).?[40..]);
        try testing.expectEqual(@as(?u64, 11), snap.lowestCheckpoint());
    }
    // Window 2..3: epoch 1 ages out and, being sparse, is cleaned away. Checkpoint 13's inputs
    // (Z@11 was written in epoch 1, Y@3 restored in epoch 0) still read.
    _ = try st.ageOut(2);
    var dropped: u64 = 0;
    var versions: u64 = 0;
    var steps: usize = 0;
    while (true) : (steps += 1) {
        try testing.expect(steps < 1000);
        const r = try st.cleanStep(1 << 16);
        dropped += r.segments_dropped;
        versions += r.versions_carried;
        if (r.idle) break;
    }
    try testing.expectEqual(@as(u64, 1), dropped);
    // Z@11's bytes were only in epoch 1; checkpoint 13's xref (epoch 2) names them: carried.
    try testing.expectEqual(@as(u64, 1), versions);
    try testing.expectEqual(@as(u64, 1), st.agedSegments().count); // the dense restored one
    var snap = st.snapshot();
    defer snap.release();
    try testing.expectEqualSlices(u8, "z11", snap.objectAt(&@as([32]u8, @splat(3)), 11).?[40..]);
    try testing.expectEqualSlices(u8, "y3", snap.objectAt(&@as([32]u8, @splat(2)), 3).?[40..]);
    try testing.expectEqualSlices(u8, "x11", snap.liveObject(&@as([32]u8, @splat(1))).?.bytes[40..]);
    try testing.expect(snap.objectAt(&@as([32]u8, @splat(1)), 3) == null); // its transaction left the window
    // Window 3: checkpoint 13's xrefs leave it, and with them Z@11 (the carried copy keeps its
    // xref's retention, not its own segment's) and Y@3 (still in the dense restored segment).
    _ = try st.ageOut(3);
    var snap3 = st.snapshot();
    defer snap3.release();
    try testing.expect(snap3.objectAt(&@as([32]u8, @splat(3)), 11) == null);
    try testing.expect(snap3.objectAt(&@as([32]u8, @splat(2)), 3) == null);
    try testing.expectEqualSlices(u8, "z13", snap3.liveObject(&@as([32]u8, @splat(3))).?.bytes[40..]);
    try testing.expectEqualSlices(u8, "y13", snap3.liveObject(&@as([32]u8, @splat(2))).?.bytes[40..]);
}

/// One checkpoint of the floor test: a transaction that mutates X (id 1), reads Y (id 2) and
/// every seventh checkpoint mutates it, with its read set written as history.onBatch does.
const FloorCp = struct { x_in: u64, y_in: u64, y_out: bool };

fn floorDigest(seq: u64) [32]u8 {
    var d: [32]u8 = @splat(0xd1);
    std.mem.writeInt(u64, d[0..8], seq, .little);
    return d;
}

fn floorPayload(buf: []u8, id: u8, version: u64) []const u8 {
    return std.fmt.bufPrint(buf, "object {d} at version {d}, some bytes to carry", .{ id, version }) catch unreachable;
}

/// What GetCheckpoint and GetTransaction need of checkpoint `seq` for a mask with effects,
/// balance changes or objects: its record, its transaction, and every version the transaction
/// read or wrote (serve `collectObjects`).
const FloorRead = enum { whole, no_objects, no_record };
fn floorRead(snap: *const store.Snapshot, seq: u64, c: FloorCp) FloorRead {
    if (snap.checkpoint(seq) == null) return .no_record;
    const t = snap.transaction(&floorDigest(seq)) orelse return .no_record;
    if (t.checkpoint != seq) return .no_record;
    var pb: [64]u8 = undefined;
    const keys = [_]struct { id: u8, v: u64, on: bool }{
        .{ .id = 1, .v = c.x_in, .on = true },
        .{ .id = 1, .v = seq, .on = true },
        .{ .id = 2, .v = c.y_in, .on = true },
        .{ .id = 2, .v = seq, .on = c.y_out },
    };
    for (keys) |k| {
        if (!k.on) continue;
        const raw = snap.objectNear(&@as([32]u8, @splat(k.id)), k.v, t.loc) orelse return .no_objects;
        if (!std.mem.eql(u8, floorPayload(&pb, k.id, k.v), raw[40..])) return .no_objects;
    }
    return .whole;
}

test "retention: the served floor is the higher of the two pruners' (sui-node's RPC reader); every checkpoint from it up answers with its transactions' objects, the checkpoint floor alone does not" {
    const gpa = testing.allocator;
    for ([_]bool{ false, true }) |age_on| {
        var tmp = testing.tmpDir(.{});
        defer tmp.cleanup();
        var pb: [512]u8 = undefined;
        var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20, .codec = .{ .key = tKey }, .clean_record_bytes = 64, .chunk_bytes = 16 << 10, .age_lag_checkpoints = 0 };
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        const st = h.store;
        var buf: [64]u8 = undefined;
        // A formal snapshot restored at S = 500, the end of epoch 5: the live set as compact
        // records and the end-of-epoch checkpoint, marked pruned (snapshot.zig restore).
        {
            const b = try st.begin(500, 5);
            try putLive(b, true, 1, 500, floorPayload(&buf, 1, 500));
            try putLive(b, true, 2, 500, floorPayload(&buf, 2, 500));
            for (0..100) |i| try putLive(b, true, @intCast(100 + i), 3, "filler-object");
            try b.checkpoint("s500", "c");
            try b.highestPruned(500);
            try st.commit(b);
        }
        // Epochs 6, 7 and 8 followed since, 20 checkpoints each (501..560).
        var cps: [561]FloorCp = undefined;
        var x: u64 = 500;
        var y: u64 = 500;
        for (501..561) |seq| {
            const epoch = 6 + (seq - 501) / 20;
            const b = try st.begin(seq, epoch);
            try b.checkpoint("s", "c");
            try b.transaction(&floorDigest(seq), &@as([32]u8, @splat(7)), "tx", "fx", null);
            const y_out = seq % 7 == 0;
            cps[seq] = .{ .x_in = x, .y_in = y, .y_out = y_out };
            _ = try histInput(st, b, 1, x, true, floorPayload(&buf, 1, x));
            _ = try histInput(st, b, 2, y, y_out, floorPayload(&buf, 2, y));
            try putLive(b, false, 1, seq, floorPayload(&buf, 1, seq));
            x = seq;
            if (y_out) {
                try putLive(b, false, 2, seq, floorPayload(&buf, 2, seq));
                y = seq;
            }
            try st.commit(b);
        }
        {
            var snap = st.snapshot();
            defer snap.release();
            // Nothing pruned since the restore: both floors are S + 1.
            try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, 5));
            try testing.expectEqual(@as(?u64, 501), snapshot.lowestServed(&snap, 5));
            for (501..561) |seq| try testing.expectEqual(FloorRead.whole, floorRead(&snap, seq, cps[seq]));
        }
        // The pruners' marks as smoothing leaves them in epoch 8 at the defaults (checkpoints 2
        // epochs, objects 1): the checkpoint mark inside epoch 6, the objects mark inside epoch
        // 7. The floors' epochs as retentionTick computes them.
        const marks: retention.Marks = .{ .checkpoints = 510, .objects = 530 };
        var cp_epoch: u64 = 0;
        var obj_epoch: u64 = 0;
        {
            var snap = st.snapshot();
            defer snap.release();
            const HeldOf = struct {
                fn epochOf(ctx: *anyopaque, seq: u64) ?u64 {
                    const sn: *const store.Snapshot = @ptrCast(@alignCast(ctx));
                    return if (sn.checkpointHeld(seq)) |r| r.epoch else null;
                }
            };
            const held: retention.Held = .{ .ctx = &snap, .epoch_of = HeldOf.epochOf };
            cp_epoch = retention.floorEpoch(held, marks.checkpoints + 1, 501, 560, 8);
            obj_epoch = retention.floorEpoch(held, marks.objects + 1, 501, 560, 8);
        }
        try testing.expectEqual(@as(u64, 6), cp_epoch);
        try testing.expectEqual(@as(u64, 7), obj_epoch);
        const rep = try st.setFloors(.{ .cp_pruned = marks.checkpoints, .obj_pruned = marks.objects, .cp_epoch = cp_epoch, .obj_epoch = obj_epoch });
        try testing.expectEqual(@as(u64, 1), rep.segments_aged); // the restore's segment
        if (age_on) {
            try st.flushIndex();
            _ = try st.ageAll();
        }
        // Cleaning runs too (the dense restored segment stays).
        var steps: usize = 0;
        while (!(try st.cleanStep(1 << 16)).idle) : (steps += 1) try testing.expect(steps < 1000);
        var snap = st.snapshot();
        defer snap.release();
        // State sync's floor: the checkpoint pruner's. The RPC floor: the objects pruner's.
        try testing.expectEqual(@as(?u64, 511), snapshot.lowestAvailable(&snap, 5));
        try testing.expectEqual(@as(?u64, 531), snapshot.lowestServed(&snap, 5));
        // The invariant: every checkpoint at or above the served floor is whole.
        for (531..561) |seq| try testing.expectEqual(FloorRead.whole, floorRead(&snap, seq, cps[seq]));
        // Between the checkpoint floor and the object window (epoch 6): records read, objects
        // do not. This is what GetServiceInfo promised and GetCheckpoint answered INTERNAL for.
        for (511..521) |seq| try testing.expectEqual(FloorRead.no_objects, floorRead(&snap, seq, cps[seq]));
        try testing.expectEqual(FloorRead.no_record, floorRead(&snap, 510, cps[510]));
        // The partially pruned epoch below the floor (521..530): whole while nothing was freed
        // (deepwave hides whole segments), not promised.
        if (!age_on) for (521..531) |seq| try testing.expectEqual(FloorRead.whole, floorRead(&snap, seq, cps[seq]));
    }
}

test "snapshot: a snapshot-started store reports lowest available S + 1, like sui-node" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const st = h.store;
    {
        const b = try st.begin(500, 9); // the restored end-of-epoch checkpoint S = 500, without the record
        try b.checkpoint("s500", "c");
        try st.commit(b);
    }
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expectEqual(@as(?u64, 500), snapshot.lowestAvailable(&snap, null));
        try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, 9)); // marker fallback
        try testing.expectEqual(@as(?u64, 500), snapshot.lowestAvailable(&snap, 8));
    }
    {
        const b = try st.begin(501, 10);
        try b.checkpoint("s501", "c");
        try b.highestPruned(500);
        try st.commit(b);
    }
    var snap = st.snapshot();
    defer snap.release();
    try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, null));
    try testing.expectEqual(@as(?u64, 501), snapshot.lowestAvailable(&snap, 9));
    try testing.expect(snap.checkpoint(500) != null); // held, but not served
}

test "history: loaded runtime object list layout" {
    const Ref = @import("serve").objset.Ref;
    try testing.expectEqual(@as(usize, history.entry_len), @sizeOf(Ref));
    try testing.expectEqual(@as(usize, 0), @offsetOf(Ref, "version"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(Ref, "id"));
    try testing.expectEqual(@sizeOf(history.LoadedEntry), @sizeOf(Ref));
}

test "history: historical versions stay out of the live set after the store reopens (recovery)" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const path = try tmpPath(&tmp, &pb);
    const id: [32]u8 = @splat(1);
    const id2: [32]u8 = @splat(2);
    const d: [32]u8 = @splat(9);
    {
        var cfg: store.Config = .{ .dir = path, .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
        const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .data });
        defer h.io.deinit();
        defer h.store.deinit();
        const b = try h.store.begin(10, 1);
        try b.putObject(&id, 7, &d, "seven");
        try b.putHistorical(&id, 5, &d, "five");
        try b.putHistorical(&id2, 3, &d, "only-historical");
        try h.store.commit(b);
        const b2 = try h.store.begin(11, 1);
        try b2.putHistorical(&id, 9, &d, "nine-historical");
        try h.store.commit(b2);
    }
    var cfg: store.Config = .{ .dir = path, .max_live_objects = 1 << 10, .segment_reserve = 1 << 20 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .data });
    defer h.io.deinit();
    defer h.store.deinit();
    var snap = h.store.snapshot();
    defer snap.release();
    // A historical record newer than the live version must not become the live one on replay.
    try testing.expectEqualStrings("seven", snap.liveObject(&id).?.bytes);
    try testing.expectEqualStrings("nine-historical", snap.objectAt(&id, 9).?);
    try testing.expectEqualStrings("five", snap.objectAt(&id, 5).?);
    try testing.expect(snap.liveObject(&id2) == null);
    try testing.expectEqualStrings("only-historical", snap.objectAt(&id2, 3).?);
    try testing.expectEqual(@as(u64, 1), h.store.liveCount());
}

test "node: an interrupted snapshot restore without --snapshot refuses to start and keeps the store" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const path = try tmpPath(&tmp, &pb);
    try tmp.dir.createDirPath(testing.io, "node");
    try tmp.dir.createDirPath(testing.io, "store");
    const nd = try tmp.dir.openDir(testing.io, "node", .{ .iterate = true });
    defer nd.close(testing.io);
    try snapshot.writeMarker(testing.io, nd, .loading, 1303);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "store/sentinel", .data = "x" });
    const node_mod = @import("node.zig");
    try testing.expectError(error.SnapshotRestoreInterrupted, node_mod.Node.init(gpa, testing.io, .{ .dir = path, .source = .{ .dir = path } }));
    _ = try tmp.dir.statFile(testing.io, "store/sentinel", .{});
    try testing.expectEqual(snapshot.Marker.loading, (try snapshot.readMarker(testing.io, nd)).state);
}

// ------------------------------------------------------------------ snapshot

fn sampleObjects(gpa: std.mem.Allocator, a: std.mem.Allocator) ![]const []const u8 {
    const blob = try readCorpus(gpa, "chk/342451160.chk");
    defer gpa.free(blob);
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(blob, &idx);
    var out: std.ArrayList([]const u8) = .empty;
    var seen: std.AutoHashMapUnmanaged(exec.objects.Key, void) = .empty;
    for (0..idx.tx_count) |i| {
        const t = idx.txAt(i);
        for (idx.objs[t.in_first..][0 .. t.in_count + t.out_count]) |r| {
            const raw = r.slice(blob);
            const k = try exec.objects.keyOf(raw);
            if ((try seen.getOrPut(a, k)).found_existing) continue;
            try out.append(a, try a.dupe(u8, raw));
        }
    }
    return out.items;
}

test "snapshot: write, read back, and refuse tampering" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const objs = try sampleObjects(gpa, a);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try snapshot.writeSnapshot(gpa, testing.io, tmp.dir, 7, objs, 5);
    const ep = try tmp.dir.openDir(testing.io, "epoch_7", .{});
    defer ep.close(testing.io);
    const mbytes = try ep.readFileAlloc(testing.io, "MANIFEST", a, .limited(1 << 20));
    const m = try snapshot.parseManifest(a, mbytes);
    try testing.expectEqual(@as(u64, 7), m.epoch);
    const parts = try m.partitions(a);
    try testing.expectEqual((objs.len + 4) / 5, parts.len);
    var acc: @import("sig").Ecmh = .{};
    var n: usize = 0;
    var nb: [64]u8 = undefined;
    for (parts) |p| {
        const ob = try ep.readFileAlloc(testing.io, p.obj.?.name(&nb), a, .limited(1 << 30));
        const rb = try ep.readFileAlloc(testing.io, p.ref.?.name(&nb), a, .limited(1 << 30));
        var c: snapshot.Checked = .{};
        defer c.deinit(gpa);
        try snapshot.checkPartition(gpa, p, ob, rb, &c);
        n += c.entries.items.len;
        acc.add(&c.acc);
        // Damage: one object byte (checksum), then with a matching checksum (ref mismatch).
        const bad = try a.dupe(u8, ob);
        bad[bad.len - 1] ^= 1;
        var c2: snapshot.Checked = .{};
        defer c2.deinit(gpa);
        try testing.expectError(error.ObjectFileChecksum, snapshot.checkPartition(gpa, p, bad, rb, &c2));
        var p2 = p;
        var h = @import("hash").Sha3_256.init();
        h.update(bad);
        h.final(&p2.obj.?.sha3);
        try testing.expect(std.meta.isError(snapshot.checkPartition(gpa, p2, bad, rb, &c2)));
    }
    try testing.expectEqual(objs.len, n);
    try testing.expectEqualSlices(u8, &root, &acc.digest());
    // A damaged manifest is refused.
    const bad_m = try a.dupe(u8, mbytes);
    bad_m[10] ^= 1;
    try testing.expectError(error.ManifestChecksum, snapshot.parseManifest(a, bad_m));
}

test "snapshot: sortForStore groups objects by type, keeps every entry, wrapped last" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const objs = try sampleObjects(gpa, a);
    var es: std.ArrayList(snapshot.Entry) = .empty;
    defer es.deinit(gpa);
    var wid: [32]u8 = @splat(0xab);
    try es.append(gpa, .{ .wrapped = .{ .id = wid, .version = 3 } });
    for (objs) |raw| {
        const k = try exec.objects.keyOf(raw);
        try es.append(gpa, .{ .object = .{ .bytes = raw, .id = k.id, .version = k.version, .digest = @splat(0) } });
    }
    wid[0] = 1;
    try es.append(gpa, .{ .wrapped = .{ .id = wid, .version = 4 } });
    // The entries as a multiset of (id, version) (sample objects may share an id).
    const Key = struct { id: [32]u8, version: u64 };
    var before: std.AutoHashMapUnmanaged(Key, u32) = .empty;
    for (es.items) |e| {
        const k: Key = switch (e) {
            .object => |o| .{ .id = o.id, .version = o.version },
            .wrapped => |w| .{ .id = w.id, .version = w.version },
        };
        const g = try before.getOrPut(a, k);
        g.value_ptr.* = if (g.found_existing) g.value_ptr.* + 1 else 1;
    }
    const n_before = es.items.len;
    var keys: std.ArrayList(snapshot.SortKey) = .empty;
    defer keys.deinit(gpa);
    var seen: std.DynamicBitSetUnmanaged = .{};
    defer seen.deinit(gpa);
    try snapshot.sortForStore(gpa, es.items, &keys, &seen);
    try testing.expectEqual(n_before, es.items.len);
    var class_prev: u8 = 0;
    var ty_prev: []const u8 = &.{};
    var types_seen: usize = 0;
    for (es.items) |e| {
        var class: u8 = 2;
        var ty: []const u8 = &.{};
        switch (e) {
            .object => |o| {
                const c = before.getPtr(.{ .id = o.id, .version = o.version }).?;
                try testing.expect(c.* > 0);
                c.* -= 1;
                const v = try exec.objects.ObjectView.parse(o.bytes);
                class = if (v.is_package) 1 else 0;
                if (!v.is_package) ty = o.bytes[1 .. v.version_at - 1];
            },
            .wrapped => |w| {
                const c = before.getPtr(.{ .id = w.id, .version = w.version }).?;
                try testing.expect(c.* > 0);
                c.* -= 1;
            },
        }
        try testing.expect(class >= class_prev);
        if (class == 0 and class_prev == 0) {
            try testing.expect(std.mem.order(u8, ty_prev, ty) != .gt);
            if (!std.mem.eql(u8, ty_prev, ty)) types_seen += 1;
        }
        class_prev = class;
        ty_prev = ty;
    }
    try testing.expect(types_seen > 1);
    try testing.expect(es.items[es.items.len - 1] == .wrapped and es.items[es.items.len - 2] == .wrapped);
}

// ------------------------------------------------------------------ execute mode: gas price

test "execute: the reference gas price caps an aborted transaction's gas price (protocol 90+)" {
    // The node passes the epoch's verified reference gas price (trust.epochParamsOfBlob, 100 on
    // mainnet in epochs 1303/1304). An aborted transaction priced at 200x RGP is charged at 100x
    // RGP: the same computation cost as a successful transaction priced at 100x. With RGP 0 (what
    // round 1 passed) the cap would be 0 and execute mode would report a false mismatch.
    const cfg = try protocol.get(141, .mainnet);
    try testing.expect(cfg.getOpt("max_gas_price_rgp_factor_for_aborted_transactions") != null);
    const factor = cfg.getOpt("max_gas_price_rgp_factor_for_aborted_transactions").?;
    const rgp: u64 = 100;
    const budget: u64 = 5_000_000_000;
    const used_units: u64 = 10_000;
    const Run = struct {
        fn cost(c: *const protocol.ProtocolConfig, price: u64, r: u64, aborted: bool, units: u64, b: u64) !u64 {
            var g = try exec.gas.SuiGasStatus.initWithBudget(c, b, price, r);
            try g.move.deductGas(exec.gas.MoveGasStatus.toInternalUnits(units));
            _ = try g.bucketizeComputation(aborted);
            return g.summary().computation_cost;
        }
    };
    const capped = try Run.cost(cfg, 2 * factor * rgp, rgp, true, used_units, budget);
    const at_cap = try Run.cost(cfg, factor * rgp, rgp, false, used_units, budget);
    try testing.expect(capped > 0);
    try testing.expectEqual(at_cap, capped);
    const uncapped = try Run.cost(cfg, 2 * factor * rgp, rgp, false, used_units, budget);
    try testing.expect(uncapped > capped);
    try testing.expectEqual(@as(u64, 0), try Run.cost(cfg, 2 * factor * rgp, 0, true, used_units, budget));
}

test "execute: Move-call, system and prologue transactions of corpus checkpoints run through exec and match" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    // Epoch 1304's protocol, reference gas price and start (epochs.jsonl, Mysten RPC).
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const idx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    try testing.expect(x.seedSystemPackages(chk_dir, idx.last, 1305) > 0);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    var seq: u64 = 342451162;
    while (seq < 342451172) : (seq += 1) {
        const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
        defer gpa.free(z);
        _ = arena.reset(.retain_capacity);
        const proto = try convert.unzstd(gpa, z, 1 << 30);
        defer gpa.free(proto);
        blob.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        try testing.expectEqual(seq, try convert.protoToChkAux(gpa, arena.allocator(), proto, &blob, &aux));
        try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });
        x.checkpoint(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
    }
    const st = &x.stats;
    try testing.expectEqual(@as(u64, 0), st.mismatched.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.errors.load(.monotonic));
    try testing.expect(st.ran_move.load(.monotonic) > 0);
    try testing.expect(st.ran_system.load(.monotonic) > 0);
    try testing.expect(st.ran_ccp.load(.monotonic) > 0);
    try testing.expectEqual(st.executed.load(.monotonic), st.matched.load(.monotonic));
}

test "execute: a settlement's child deleted by an earlier transaction of the checkpoint reads as none, not the store's stale version" {
    // Checkpoint 342452223: accumulator field 0x8f81d515810b... was created at 912304889 (an
    // earlier checkpoint's settlement), an earlier transaction of this checkpoint deleted it, and
    // settlement tx 38 (bound 912305083) must read none (Rust read_child_object). A store as of
    // the previous checkpoint still holds 912304889 live; reading it made the effects differ.
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    const seq: u64 = 342452223;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));

    const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
    defer gpa.free(z);
    const proto = try convert.unzstd(gpa, z, 1 << 30);
    defer gpa.free(proto);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    try testing.expectEqual(seq, try convert.protoToChkAux(gpa, a, proto, &blob, &aux));
    try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });

    // The store as of the previous checkpoint: the field live at 912304889 (the deleting
    // transaction's input carries those bytes).
    var cidx = try types.CheckpointIndex.init(gpa);
    defer cidx.deinit(gpa);
    try types.indexCheckpointData(blob.items, &cidx);
    const field_prefix = [_]u8{ 0x8f, 0x81, 0xd5, 0x15, 0x81, 0x0b };
    var planted = false;
    const b = try h.store.begin(seq - 1, 1304);
    for (0..cidx.tx_count) |i| {
        const t = cidx.txAt(i);
        for (cidx.objs[t.in_first..][0..t.in_count]) |r| {
            const raw = r.slice(blob.items);
            const k = try exec.objects.keyOf(raw);
            if (!planted and std.mem.startsWith(u8, &k.id, &field_prefix) and k.version == 912304889) {
                try b.putObject(&k.id, k.version, &sync.verify.objectDigest(raw), raw);
                planted = true;
            }
        }
    }
    try h.store.commit(b);
    try testing.expect(planted);

    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    try testing.expect(x.seedSystemPackages(chk_dir, eidx.last, 1305) > 0);
    x.checkpoint(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
    const st = &x.stats;
    try testing.expectEqual(@as(u64, 0), st.mismatched.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.errors.load(.monotonic));
    try testing.expect(st.ran_system.load(.monotonic) > 0);
    try testing.expectEqual(st.executed.load(.monotonic), st.matched.load(.monotonic));
}

/// Runs checkpoints `from..to` (epoch 1304, archive protos) through an executor on an empty store.
/// `deny`: load the corpus deny-list state (--deny-state); `complete`: claim the full live set.
fn onThread(deny: bool, complete: bool, out: *DenyOut) !void {
    const T = struct {
        fn run(d: bool, c: bool, o: *DenyOut, r: *?anyerror) void {
            runDenyCase(d, c, o) catch |e| {
                r.* = e;
            };
        }
    };
    var res: ?anyerror = null;
    const t = try std.Thread.spawn(.{}, T.run, .{ deny, complete, out, &res });
    t.join();
    if (res) |e| return e;
}

const DenyOut = struct { gaps: u64 = 0, executed: u64 = 0, mismatched: u64 = 0, errors: u64 = 0 };

fn runDenyCase(deny: bool, complete: bool, out: *DenyOut) !void {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    _ = x.seedSystemPackages(chk_dir, eidx.last, 1305);
    if (deny) _ = x.loadDenyState(try std.fmt.bufPrint(&pb, "{s}/deny/objects.bin.zst", .{c})) catch return error.SkipZigTest;
    if (complete) x.complete_from = 0;
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    var seq: u64 = 342451162;
    while (seq < 342451182) : (seq += 1) {
        const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
        defer gpa.free(z);
        const proto = try convert.unzstd(gpa, z, 1 << 30);
        defer gpa.free(proto);
        blob.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        _ = try convert.protoToChkAux(gpa, a, proto, &blob, &aux);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });
        x.checkpoint(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
    }
    out.gaps = 0;
    for (x.whys.keys(), x.whys.values()) |k, v| if (std.mem.startsWith(u8, k, "deny list state not available")) {
        out.gaps += v;
    };
    out.executed = x.stats.executed.load(.monotonic);
    out.mismatched = x.stats.mismatched.load(.monotonic);
    out.errors = x.stats.errors.load(.monotonic);
}

test "execute: deny-list reads without the full live set are a gap (verify-only), never a guess; --deny-state or a full live set answers them" {
    // Each case on its own thread: exec's per-thread package caches are keyed by the packages
    // store's address, which a second executor on this stack would reuse.
    var bare: DenyOut = .{};
    try onThread(false, false, &bare);
    // Regulated-coin transfers (USDC) read the 0x403 per-type config: an empty store cannot say
    // whether it exists, so those transactions stay verify-only instead of guessing "not denied".
    try testing.expect(bare.gaps > 0);
    try testing.expectEqual(@as(u64, 0), bare.mismatched);
    try testing.expectEqual(@as(u64, 0), bare.errors);
    var seeded: DenyOut = .{};
    try onThread(true, false, &seeded);
    try testing.expectEqual(@as(u64, 0), seeded.gaps);
    try testing.expectEqual(bare.executed + bare.gaps, seeded.executed);
    try testing.expectEqual(@as(u64, 0), seeded.mismatched);
    try testing.expectEqual(@as(u64, 0), seeded.errors);
}

const ParOut = struct { executed: u64 = 0, matched: u64 = 0, mismatched: u64 = 0, errors: u64 = 0, unsupported: u64 = 0, reruns: u64 = 0, done_seq: u64 = 0 };

/// Checkpoints 342451162..342451182 through an executor with `threads` pipeline threads (0: one at
/// a time on this thread), each checkpoint committed to the store right after it is submitted, as
/// the follower does: execution must see the store as of the previous checkpoint, never later.
fn runPipelineCase(threads: u32, out: *ParOut) !void {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 26 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const L = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };
    const text = try readCorpus(gpa, "epochs.jsonl");
    defer gpa.free(text);
    var meta: ?L = null;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| if (line.len > 0) {
        const l = try std.json.parseFromSliceLeaky(L, a, line, .{ .ignore_unknown_fields = true });
        if (l.epoch == 1304) meta = l;
    };
    const m = meta orelse return error.SkipZigTest;
    const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
    defer pkg_dir.close(testing.io);
    const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
    defer chk_dir.close(testing.io);
    const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));
    var x = try execute.Executor.init(gpa, testing.io, h.store, tmp.dir);
    defer x.deinit();
    x.pkg_dir = pkg_dir;
    _ = x.seedSystemPackages(chk_dir, eidx.last, 1305);
    _ = x.loadDenyState(try std.fmt.bufPrint(&pb, "{s}/deny/objects.bin.zst", .{c})) catch return error.SkipZigTest;
    try x.start(threads, 4);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(gpa);
    var aux: std.ArrayList(u8) = .empty;
    defer aux.deinit(gpa);
    var cidx = try types.CheckpointIndex.init(gpa);
    defer cidx.deinit(gpa);
    var seq: u64 = 342451162;
    while (seq < 342451182) : (seq += 1) {
        const z = readCorpus(gpa, try std.fmt.bufPrint(&pb, "binpb-done/{d}.binpb.zst", .{seq})) catch return error.SkipZigTest;
        defer gpa.free(z);
        const proto = try convert.unzstd(gpa, z, 1 << 30);
        defer gpa.free(proto);
        blob.clearRetainingCapacity();
        aux.clearRetainingCapacity();
        _ = try convert.protoToChkAux(gpa, a, proto, &blob, &aux);
        try tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux.items });
        x.submit(seq, 1304, m.pv.?, .{ .rgp = m.rgp, .start_ms = m.start_ms }, blob.items);
        // Commit the checkpoint's outputs (later checkpoints' jobs must not see them early).
        try types.indexCheckpointData(blob.items, &cidx);
        const b = try h.store.begin(seq, 1304);
        for (0..cidx.tx_count) |i| {
            const t = cidx.txAt(i);
            for (cidx.objs[t.out_first..][0..t.out_count]) |r| {
                const raw = r.slice(blob.items);
                const k = try exec.objects.keyOf(raw);
                try b.putObject(&k.id, k.version, &sync.verify.objectDigest(raw), raw);
            }
        }
        try h.store.commit(b);
        // The spool drops the archive record once the checkpoint commits.
        try tmp.dir.deleteFile(testing.io, try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}));
    }
    x.drain();
    const st = &x.stats;
    out.* = .{ .executed = st.executed.load(.monotonic), .matched = st.matched.load(.monotonic), .mismatched = st.mismatched.load(.monotonic), .errors = st.errors.load(.monotonic), .unsupported = st.unsupported.load(.monotonic), .reruns = st.reruns.load(.monotonic), .done_seq = st.done_seq.load(.monotonic) };
}

fn pipelineOnThread(threads: u32, out: *ParOut) !void {
    const T = struct {
        fn run(n: u32, o: *ParOut, r: *?anyerror) void {
            runPipelineCase(n, o) catch |e| {
                r.* = e;
            };
        }
    };
    var res: ?anyerror = null;
    const t = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, T.run, .{ threads, out, &res });
    t.join();
    if (res) |e| return e;
}

test "execute: the parallel pipeline gives the same verdicts as one transaction at a time" {
    var serial: ParOut = .{};
    try pipelineOnThread(0, &serial);
    var par: ParOut = .{};
    try pipelineOnThread(4, &par);
    try testing.expect(serial.executed > 0);
    try testing.expectEqual(@as(u64, 0), serial.mismatched);
    try testing.expectEqual(@as(u64, 0), serial.errors);
    try testing.expectEqual(serial.executed, par.executed);
    try testing.expectEqual(serial.matched, par.matched);
    try testing.expectEqual(serial.unsupported, par.unsupported);
    try testing.expectEqual(@as(u64, 0), par.mismatched);
    try testing.expectEqual(@as(u64, 0), par.errors);
    try testing.expectEqual(@as(u64, 0), par.reruns);
    try testing.expectEqual(@as(u64, 342451181), par.done_seq);
}

test "zstd: the vendored table-driven decoder equals std's on archive protos" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var pb: [512]u8 = undefined;
    var dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/binpb-done", .{c}), .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(testing.io);
    var it = dir.iterate();
    var n: usize = 0;
    while (try it.next(testing.io)) |e| {
        if (!std.mem.endsWith(u8, e.name, ".binpb.zst")) continue;
        const z = try dir.readFileAlloc(testing.io, e.name, gpa, .limited(1 << 30));
        defer gpa.free(z);
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        const got = try convert.unzstdArena(arena.allocator(), z, 1 << 30);
        var in: std.Io.Reader = .fixed(z);
        var d: std.compress.zstd.Decompress = .init(&in, &.{}, .{});
        var w: std.Io.Writer.Allocating = .init(gpa);
        defer w.deinit();
        _ = try d.reader.streamRemaining(&w.writer);
        try testing.expectEqualSlices(u8, w.written(), got);
        n += 1;
        if (n == 300) break;
    }
    try testing.expect(n > 0);
}

// ------------------------------------------------------------------ state hash at the end of epoch

test "state hash: forced epoch boundary on a corpus end-of-epoch checkpoint: equal, stored, reloaded; a planted object is caught" {
    const gpa = testing.allocator;
    const c = corpus() orelse return error.SkipZigTest;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pb: [512]u8 = undefined;
    const eidx = trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c})) catch return error.SkipZigTest;
    const epoch: u64 = 1303;
    if (epoch >= eidx.last.len) return error.SkipZigTest;
    const seq = eidx.last[@intCast(epoch)] orelse return error.SkipZigTest;
    const blob = try readCorpus(a, try std.fmt.bufPrint(&pb, "chk/{d}.chk", .{seq}));
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    try types.indexCheckpointData(blob, &idx);
    const checked = switch (try sync.verify.check(a, blob, &idx)) {
        .ok => |x| x,
        .bad => return error.TestUnexpectedResult,
    };
    try testing.expect(checked.end_of_epoch != null);
    const pv = 140; // epoch 1303 (epochs.jsonl)

    // The live set before the checkpoint, as a restore would leave it (any multiset will do), and
    // the root after it, computed apart from the checker.
    var base: sig.Ecmh = .{};
    base.insert("live object set at the end of epoch 1302 (test)");
    var expect = base;
    {
        var out: exec.state_hash.CheckpointHash = .{};
        try exec.state_hash.accumulateCheckpoint(a, exec.state_hash.pathFor(try protocol.get(pv, .mainnet)), blob, &idx, &out);
        expect.add(&out.acc);
    }
    const want = expect.digest();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var cfg: store.Config = .{ .dir = try tmpPath(&tmp, &pb), .max_live_objects = 1 << 16, .segment_reserve = 1 << 26 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();

    // 1. Equal at the boundary; the new root is committed with the checkpoint.
    var k = try statehash.Checker.init(gpa, .verify_only);
    defer k.deinit();
    k.running = base;
    k.expect_root = want;
    const b = try h.store.begin(seq, epoch);
    try testing.expectEqual(statehash.Verdict.ok, try k.onBatch(seq, &checked, blob, b, pv));
    try h.store.commit(b);
    try testing.expectEqual(@as(u64, 1), k.stats.checks_ok.load(.monotonic));
    try testing.expectEqualSlices(u8, &want, &k.running.?.digest());

    // 2. A restart reads the root back at the last committed checkpoint.
    {
        var k2 = try statehash.Checker.init(gpa, .verify_only);
        defer k2.deinit();
        var snap = h.store.snapshot();
        defer snap.release();
        k2.load(&snap, seq);
        try testing.expectEqualSlices(u8, &want, &k2.running.?.digest());
        var k3 = try statehash.Checker.init(gpa, .verify_only);
        defer k3.deinit();
        k3.load(&snap, seq - 1);
        try testing.expect(k3.running == null);
    }

    // 3. A planted object in the live set: caught at the boundary, the root is dropped and the
    //    checker stays quiet afterwards (verify-only until the next restore).
    var bad = base;
    bad.insert("planted object (test)");
    var k4 = try statehash.Checker.init(gpa, .verify_only);
    defer k4.deinit();
    k4.running = bad;
    k4.expect_root = want;
    k4.quiet = true;
    const b2 = try h.store.begin(seq + 1, epoch);
    try testing.expectEqual(statehash.Verdict.mismatch, try k4.onBatch(seq, &checked, blob, b2, pv));
    h.store.abort(b2);
    try testing.expectEqual(@as(u64, 1), k4.stats.failed.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), k4.stats.mismatches.load(.monotonic));
    try testing.expect(k4.running == null);

    // 4. Without a test root, the checkpoint's certified ECMH commitment is the one compared.
    var k5 = try statehash.Checker.init(gpa, .verify_only);
    defer k5.deinit();
    k5.running = base;
    k5.quiet = true;
    const b3 = try h.store.begin(seq + 1, epoch);
    try testing.expectEqual(statehash.Verdict.mismatch, try k5.onBatch(seq, &checked, blob, b3, pv));
    h.store.abort(b3);
    var commitment: ?[32]u8 = null;
    for (checked.end_of_epoch.?.epochCommitments) |cm| switch (cm) {
        .ECMHLiveObjectSetDigest => |d| commitment = d.digest.@"0",
        else => {},
    };
    try testing.expect(commitment != null);
    try testing.expect(!std.mem.eql(u8, &commitment.?, &want));
}

test "transport limits: node.zig serves with sui-node 1.83.1's values" {
    const node = @import("node.zig");
    const o = node.sui_node_limits;
    try testing.expectEqual(@as(u32, 200), o.h2.max_streams);
    try testing.expectEqual(@as(usize, 4 << 20), o.h2.max_request_bytes);
    try testing.expectEqual(@as(?u64, 60 * std.time.ns_per_s), o.h2.default_timeout_ns);
    try testing.expectEqual(@as(usize, 4 << 20), o.web.max_request_bytes);
    try testing.expectEqual(@as(?u64, 60 * std.time.ns_per_s), o.web.default_timeout_ns);
    try testing.expectEqual(@as(u64, 30 * std.time.ns_per_s), o.web.idle_ns);
    try testing.expectEqual(@as(?u64, 4 * 3600 * std.time.ns_per_s), o.max_age_ns);
    try testing.expectEqual(@as(u64, 600 * std.time.ns_per_s), o.age_grace_ns);
    try testing.expectEqual(@as(?u64, null), o.keepalive_ns);
    try testing.expectEqual(@as(u31, 128), node.listen_backlog);
    const cfg: node.Config = .{ .dir = "", .source = .{ .dir = "" } };
    try testing.expectEqual(o.h2.max_streams, cfg.serve_opts.h2.max_streams);
    try testing.expectEqual(o.h2.default_timeout_ns, cfg.serve_opts.h2.default_timeout_ns);
}

/// Writes a corpus checkpoint into `st` the way the follower and history writer do, as far as the
/// ledger-history backfill reads it: the checkpoint record, every transaction record, output
/// objects as live versions and input objects as historical versions.
fn storeBlob(st: *store.Store, a: std.mem.Allocator, blob: []const u8) !u64 {
    const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
    const sum = &cp.checkpoint_summary.data;
    const b = try st.begin(sum.sequence_number, sum.epoch);
    try b.checkpoint(try bcs.encodeAlloc(@TypeOf(cp.checkpoint_summary), a, &cp.checkpoint_summary), try bcs.encodeAlloc(types.CheckpointContents, a, &cp.checkpoint_contents));
    for (cp.transactions, 0..) |*t, i| {
        const dg: types.ExecutionDigests = switch (cp.checkpoint_contents) {
            .V1 => |v| v.transactions[i],
            .V2 => |v| v.transactions[i].digest,
        };
        const ev: ?[]const u8 = if (t.events) |*e| try bcs.encodeAlloc(types.TransactionEvents, a, e) else null;
        try b.transaction(&dg.transaction.@"0".@"0", &dg.effects.@"0".@"0", try bcs.encodeAlloc(@TypeOf(t.transaction), a, &t.transaction), try bcs.encodeAlloc(types.TransactionEffects, a, &t.effects), ev);
        for ([2][]const types.Object{ t.input_objects, t.output_objects }, 0..) |list, out| for (list) |*o| {
            const id: [32]u8, const ver: u64 = switch (o.data) {
                .Move => |m| .{ m.contents[0..32].*, m.version.@"0" },
                .Package => |pk| .{ pk.id.@"0".@"0", pk.version.@"0" },
            };
            const raw = try bcs.encodeAlloc(types.Object, a, o);
            const d = store.objectDigest(raw);
            if (out == 1) try b.putObject(&id, ver, &d, raw) else try b.putHistorical(&id, ver, &d, raw);
        };
    }
    try st.commit(b);
    return sum.sequence_number;
}

test "ledger-history backfill: more loaders than ring slots never share a slot (drop-in r2 SEGV in ArenaAllocator under lhfill worker)" {
    // deepwave 72c7914 on the epoch-1304 restore crashed 1 s after "history: backfilling the
    // ledger-history index for checkpoints 342814415..343266015 (12 loaders)": loaders for seq
    // and seq + ring both saw the slot empty and reset the same arena. A ring of 2 slots with 8
    // loaders over mainnet checkpoints 342456120.. makes that reuse constant.
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const sdir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir});
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    var seqs: [12]u64 = undefined;
    for (&seqs, 0..) |*s, i| {
        var nb: [64]u8 = undefined;
        const blob = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
        s.* = try storeBlob(h.store, a, blob);
        try want.addCheckpoint(s.*, blob);
    }
    const want_hash = try want.contentHash();
    for (0..20) |_| {
        const bf = try lhfill.Backfill.startRing(gpa, testing.io, h.store, seqs[0], seqs[11], 8, 2);
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        const out = try bf.finish(seqs[11]);
        try testing.expectEqual(want_hash, try out.contentHash());
        bf.destroy();
    }
}

test "ledger-history backfill: an index built from the store equals one built while following, and adopt swaps it in durably" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var blobs: [12][]const u8 = undefined;
    for (&blobs, 0..) |*b, i| {
        var nb: [64]u8 = undefined;
        b.* = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const sdir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir});
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    // The reference: an index fed the blobs as the follower would.
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    var seqs: [12]u64 = undefined;
    for (blobs, &seqs) |b, *s| {
        s.* = try storeBlob(h.store, a, b);
        try want.addCheckpoint(s.*, b);
    }
    const want_hash = try want.contentHash();

    // Backfill the first nine from the store; the commit path takes the rest at the swap.
    const bf = try lhfill.Backfill.start(gpa, testing.io, h.store, seqs[0], seqs[8], 3);
    while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    try testing.expectEqual(lhfill.Status.ready, bf.status());
    try testing.expectEqual(@as(u64, 0), bf.counters.missing_objects.load(.monotonic));

    // The live index started late (at the eleventh checkpoint), persisted on disk.
    const hdir = try std.fmt.allocPrint(a, "{s}/lh", .{root_dir});
    {
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        try live.addCheckpoint(seqs[10], blobs[10]);
        // The commit path, before indexing the twelfth: catch up to the eleventh, swap, index.
        const out = try bf.finish(seqs[11] - 1);
        try live.adopt(out);
        bf.destroy();
        try live.addCheckpoint(seqs[11], blobs[11]);
        try testing.expectEqual(seqs[0], live.indexedLo().?);
        try testing.expectEqual(want_hash, try live.contentHash());
    }
    // Reopened from its snapshot and log: the same state.
    const again = try lhist.Index.init(gpa, testing.io, hdir);
    defer again.deinit();
    try testing.expectEqual(want_hash, try again.contentHash());
}

test "ledger-history backfill: resumes from its on-disk staging watermark after a crash; a crash inside adopt keeps the live index and the staging state" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var blobs: [12][]const u8 = undefined;
    for (&blobs, 0..) |*b, i| {
        var nb: [64]u8 = undefined;
        b.* = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const sdir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir});
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    var seqs: [12]u64 = undefined;
    for (blobs, &seqs) |b, *s| {
        s.* = try storeBlob(h.store, a, b);
        try want.addCheckpoint(s.*, b);
    }
    const want_hash = try want.contentHash();
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{root_dir});
    const hdir = try std.fmt.allocPrint(a, "{s}/lh", .{root_dir});

    // A staging dir that does not fit (starts above the requested low end) is built again.
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[2], seqs[3], .{ .workers = 2, .staging = staging });
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        bf.destroy();
    }
    // Run 1: crash right after the third save (one save, a rotation, per checkpoint): the
    // watermark is seqs[2].
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[0], seqs[8], .{ .workers = 2, .staging = staging, .save_every_ns = 0, .stop_after_saves = 3 });
        try testing.expectEqual(@as(?u64, null), bf.resumed_at);
        while (bf.thread != null and bf.status() == .running and !bf.cancel.load(.acquire)) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        if (bf.thread) |t| t.join();
        bf.thread = null;
        try testing.expectEqual(lhfill.Status.running, bf.status());
        // kill -9: nothing more is written (no destroy-time save).
        bf.staged = false;
        bf.destroy();
    }
    // Torn tmp files from a save in flight (CURRENT and the generation's meta) are ignored.
    {
        var cb: [64]u8 = undefined;
        const cur = std.mem.trim(u8, try Io.Dir.cwd().readFile(testing.io, try std.fmt.allocPrint(a, "{s}/CURRENT", .{staging}), &cb), " \n");
        try Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = try std.fmt.allocPrint(a, "{s}/CURRENT.tmp", .{staging}), .data = "torn" });
        try Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = try std.fmt.allocPrint(a, "{s}/{s}/meta.tmp", .{ staging, cur }), .data = "torn" });
        // The staging index is on disk with no per-checkpoint log.
        var gd = try Io.Dir.cwd().openDir(testing.io, try std.fmt.allocPrint(a, "{s}/{s}", .{ staging, cur }), .{ .iterate = true });
        defer gd.close(testing.io);
        var it = gd.iterate();
        while (try it.next(testing.io)) |en| try testing.expect(!std.mem.startsWith(u8, en.name, "log-"));
    }
    // Run 2 resumes at seqs[3] and ends equal to a full build. The adopt crashes before the
    // staging generation moves (inside the staging index's final rotation): the live index keeps
    // its state and the staging dir its last save.
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[0], seqs[8], .{ .workers = 3, .staging = staging });
        try testing.expectEqual(@as(?u64, seqs[3]), bf.resumed_at);
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expect(bf.counters.checkpoints.load(.monotonic) <= seqs[11] - seqs[3] + 1);
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        try live.addCheckpoint(seqs[10], blobs[10]);
        const g0 = live.generation();
        const out = try bf.finish(seqs[11] - 1);
        var fault: lhist.Fault = .{ .left = 1, .rng = std.Random.DefaultPrng.init(7) };
        out.fault = &fault;
        try testing.expectError(error.Crash, live.adopt(out));
        out.fault = null;
        bf.destroy();
        try testing.expectEqual(g0, live.generation());
        try testing.expectEqual(seqs[10], live.indexedLo().?);
    }
    // Reopened: the old live state (from seqs[10]); the staging dir resumes past seqs[8]; the
    // adopt now lands and is durable when it returns (the node then drops the staging dir).
    {
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        try testing.expectEqual(seqs[10], live.indexedLo().?);
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, h.store, seqs[0], seqs[9], .{ .workers = 2, .staging = staging });
        try testing.expect(bf.resumed_at.? > seqs[8]);
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        const out = try bf.finish(seqs[11] - 1);
        try live.adopt(out);
        bf.destroy();
        try testing.expectEqual(live.generation(), live.persistedGeneration());
        // The staging generation was moved into the live root: nothing is left to resume from.
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().access(testing.io, try std.fmt.allocPrint(a, "{s}/CURRENT", .{staging}), .{}));
        try live.addCheckpoint(seqs[11], blobs[11]);
        try testing.expectEqual(want_hash, try live.contentHash());
    }
    // A kill -9 right after: the reopen has the adopted window plus the logged tip.
    const again = try lhist.Index.init(gpa, testing.io, hdir);
    defer again.deinit();
    try testing.expectEqual(seqs[0], again.indexedLo().?);
    try testing.expectEqual(seqs[11], again.indexedHi().?);
    try testing.expectEqual(want_hash, try again.contentHash());
}

test "removal-prior index: the store derivation equals the one from the checkpoint's objects, and survives a reopen" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    var cfg: store.Config = .{ .dir = try std.fmt.allocPrint(a, "{s}/store", .{root_dir}), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
    const h = try store.openDir(gpa, testing.io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const path = try std.fmt.allocPrint(a, "{s}/node/removed-prior.log", .{root_dir});
    var want: removal_log.Map = .empty;
    defer want.deinit(gpa);
    var map: removal_log.Map = .empty;
    defer map.deinit(gpa);
    var log = try removal_log.Log.open(gpa, testing.io, path, &map);
    var total: usize = 0;
    for (0..12) |i| {
        var nb: [64]u8 = undefined;
        const blob = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
        const seq = try storeBlob(h.store, a, blob);
        // The executor's rule (noteRemovals), from the checkpoint's objects.
        const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
        for (cp.transactions) |*t| {
            const lamport = switch (t.effects) {
                .V2 => |v| v.lamport_version.@"0",
                .V1 => continue,
            };
            ins: for (t.input_objects) |*o| {
                const m = switch (o.data) {
                    .Move => |m| m,
                    .Package => continue,
                };
                if (o.owner != .ObjectOwner) continue;
                for (t.output_objects) |*q| switch (q.data) {
                    .Move => |qm| if (std.mem.eql(u8, qm.contents[0..32], m.contents[0..32])) continue :ins,
                    .Package => {},
                };
                try want.put(gpa, .{ .id = m.contents[0..32].*, .version = lamport }, m.version.@"0");
            }
        }
        var snap = h.store.snapshot();
        defer snap.release();
        var list: std.ArrayList(removal_log.Entry) = .empty;
        defer list.deinit(gpa);
        try testing.expect(try removal_log.fromStore(gpa, a, &snap, seq, &list));
        for (list.items) |e| try map.put(gpa, .{ .id = e.id, .version = e.version }, e.prior);
        try log.appendCheckpoint(gpa, seq, list.items);
        total += list.items.len;
    }
    log.close();
    std.debug.print("removal-prior: {d} child removals in 12 corpus checkpoints\n", .{total});
    try testing.expectEqual(want.count(), map.count());
    var it = want.iterator();
    while (it.next()) |e| try testing.expectEqual(e.value_ptr.*, map.get(e.key_ptr.*).?);
    // Reopened (a restart, or a kill -9: the records were written, not fsync'd): the same map.
    var again: removal_log.Map = .empty;
    defer again.deinit(gpa);
    var l2 = try removal_log.Log.open(gpa, testing.io, path, &again);
    defer l2.close();
    try testing.expectEqual(map.count(), again.count());
    // The watermark is the last mark (written with removals, or every mark_every checkpoints);
    // the checkpoints after it are derived from the store again at open (openPriorLog).
    try testing.expect(l2.wm.? >= 342456120 and l2.wm.? <= 342456131);
}

// ------------------------------------------------------------- sigorder: the sweep and fixes

const CDigest = struct { tx: [32]u8, fx: [32]u8, k: u64 };

/// Each transaction of V1/V2 checkpoint contents: digests and certified signature count.
fn contentsDigests(a: std.mem.Allocator, contents: []const u8) ![]CDigest {
    var r = bcs.Reader.init(contents);
    const tag = try r.uleb32();
    const n = try r.length();
    const out = try a.alloc(CDigest, n);
    for (out) |*d| {
        const b = try r.bytes(66);
        d.* = .{ .tx = b[1..33].*, .fx = b[34..66].*, .k = 0 };
        if (tag == 1) {
            d.k = try r.length();
            for (0..d.k) |_| {
                _ = try r.bytes(try r.length());
                if (try r.int(u8) == 1) _ = try r.int(u64);
            }
        }
    }
    if (tag == 0) {
        const m = try r.length();
        for (out[0..@min(m, n)]) |*d| {
            d.k = try r.length();
            for (0..d.k) |_| _ = try r.bytes(try r.length());
        }
    }
    return out;
}

test "sigorder: reorder takes a permutation of the stored signatures only (sponsored E7yj...)" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, sigorder_proto, &want);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    try types.indexCheckpointData(want.items, &idx);
    const want_env = try a.dupe(u8, idx.txs[21].transaction.slice(want.items));
    try types.indexCheckpointData(plain.items, &idx);
    const plain_env = idx.txs[21].transaction.slice(plain.items);
    var node: [2][]const u8 = undefined;
    for (&node, sigorder_sui_node) |*w, hex| {
        const b = try a.alloc(u8, hex.len / 2);
        _ = try std.fmt.hexToBytes(b, hex);
        w.* = b;
    }
    // The stored contents order, sui-node's order: the envelope sui-node serves, byte for byte.
    const fixed = (try sigorder.reorder(a, plain_env, &node)).?;
    try testing.expectEqualSlices(u8, want_env, fixed);
    try testing.expectEqual(plain_env.len, fixed.len);
    // Already in that order: nothing to fix.
    try testing.expect(try sigorder.reorder(a, want_env, &node) == null);
    // Not a permutation: a duplicate, a foreign signature, a short list.
    try testing.expect(try sigorder.reorder(a, plain_env, &.{ node[0], node[0] }) == null);
    const foreign = try a.dupe(u8, node[0]);
    foreign[9] ^= 1;
    try testing.expect(try sigorder.reorder(a, plain_env, &.{ foreign, node[1] }) == null);
    try testing.expect(try sigorder.reorder(a, plain_env, &.{node[0]}) == null);
    // A truncated envelope does not parse.
    if (sigorder.reorder(a, plain_env[0 .. plain_env.len - 1], &node)) |_| return error.TestUnexpectedResult else |_| {}
}

test "sigorder: BatchGetTransactions request and answer" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d1: [32]u8 = @splat(1);
    const d2: [32]u8 = @splat(2);
    const body = try sigorder.batchBody(a, &.{ d1, d2 });
    try testing.expectEqual(@as(u8, 0), body[0]);
    try testing.expectEqual(@as(usize, body.len - 5), std.mem.readInt(u32, body[1..5], .big));
    try testing.expect(std.mem.indexOf(u8, body, "signatures.bcs") != null);
    var tb: [44]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, body, @import("serve").b58.encode32(&tb, &d2)) != null);
    // { transactions: [ { transaction: { digest, signatures: [{bcs{name,value}} x2] } }, { error: { code 5 } } ] }
    var t: std.ArrayList(u8) = .empty;
    try pbPutLen(a, &t, 1, @import("serve").b58.encode32(&tb, &d1));
    for ([_][]const u8{ "\x00ab", "\x01cd" }) |sv| {
        var bb: std.ArrayList(u8) = .empty;
        try pbPutLen(a, &bb, 1, "UserSignatureBytes");
        try pbPutLen(a, &bb, 2, sv);
        var us: std.ArrayList(u8) = .empty;
        try pbPutLen(a, &us, 1, bb.items);
        try pbPutLen(a, &t, 3, us.items);
    }
    var r1: std.ArrayList(u8) = .empty;
    try pbPutLen(a, &r1, 1, t.items);
    var r2: std.ArrayList(u8) = .empty;
    try pbPutLen(a, &r2, 2, &.{ 0x08, 0x05 });
    var msg: std.ArrayList(u8) = .empty;
    try pbPutLen(a, &msg, 1, r1.items);
    try pbPutLen(a, &msg, 1, r2.items);
    const got = try sigorder.parseBatch(a, msg.items);
    try testing.expectEqual(@as(usize, 2), got.len);
    try testing.expectEqualSlices(u8, &d1, &got[0].tx.digest.?);
    try testing.expectEqual(@as(usize, 2), got[0].tx.sigs.len);
    try testing.expectEqualStrings("\x01cd", got[0].tx.sigs[1]);
    try testing.expectEqual(@as(u64, 5), got[1].err);
    try testing.expectError(error.Malformed, sigorder.parseBatch(a, &.{ 0x0a, 0x05, 0x01 }));
}

/// A grpc-web unary HTTP reply carrying `msg`.
fn grpcWebReply(a: std.mem.Allocator, msg: []const u8) ![]const u8 {
    var body: std.ArrayList(u8) = .empty;
    var h: [5]u8 = .{ 0, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[1..5], @intCast(msg.len), .big);
    try body.appendSlice(a, &h);
    try body.appendSlice(a, msg);
    const trailer = "grpc-status:0\r\n";
    h = .{ 0x80, 0, 0, 0, 0 };
    std.mem.writeInt(u32, h[1..5], trailer.len, .big);
    try body.appendSlice(a, &h);
    try body.appendSlice(a, trailer);
    return std.fmt.allocPrint(a, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}", .{ body.items.len, body.items });
}

test "sigorder: the sweep serves the node's order for a bucket-stored sponsored transaction, durably" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 343111673;
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);

    // sui-node's envelopes (the full node proto) and the bucket's (the contents order).
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    _ = try convert.protoToChk(gpa, a, sigorder_proto, &want);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    try types.indexCheckpointData(want.items, &idx);
    const node_envs = try a.alloc([]const u8, idx.tx_count);
    for (node_envs, idx.txs[0..idx.tx_count]) |*e, t| e.* = try a.dupe(u8, t.transaction.slice(want.items));

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try tmp.dir.realPath(io, &pb)];
    const sdir = try std.fs.path.join(a, &.{ base, "store" });
    var cfg: store.Config = .{ .dir = sdir, .max_live_objects = 1 << 10, .max_object_versions = 1 << 10, .max_transactions = 1 << 10, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 26, .max_batch_objects = 1 << 10, .max_segments = 4, .segment_reserve = 1 << 22, .seed = 7 };
    var h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    // The checkpoint as a bucket catch-up stored it.
    try types.indexCheckpointData(plain.items, &idx);
    const blob = plain.items;
    const contents = idx.contents.slice(blob);
    const ds = try contentsDigests(a, contents);
    try testing.expectEqual(@as(usize, idx.tx_count), ds.len);
    var sr = bcs.Reader.init(idx.summary.slice(blob));
    const epoch = try sr.int(u64);
    {
        const b = try h.store.begin(seq, epoch);
        try b.checkpoint(blob[idx.summary.o .. idx.sig.o + idx.sig.n], contents);
        for (idx.txs[0..idx.tx_count], ds) |t, d| try b.transaction(&d.tx, &d.fx, t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |e| e.slice(blob) else null);
        try h.store.commit(b);
    }
    const e7: [32]u8 = ds[21].tx;
    {
        var snap = h.store.snapshot();
        defer snap.release();
        try testing.expect(!std.mem.eql(u8, snap.transaction(&e7).?.tx, node_envs[21]));
    }

    // The node's answer: every multi-signer transaction of the checkpoint, in contents order.
    var msg: std.ArrayList(u8) = .empty;
    var asked: usize = 0;
    for (ds, 0..) |d, i| {
        if (d.k < 2) continue;
        asked += 1;
        var tb: [44]u8 = undefined;
        var t: std.ArrayList(u8) = .empty;
        try pbPutLen(a, &t, 1, @import("serve").b58.encode32(&tb, &d.tx));
        for ((try sigorder.envelopeSigs(a, node_envs[i])).sigs) |g| {
            var bb: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &bb, 2, g);
            var us: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &us, 1, bb.items);
            try pbPutLen(a, &t, 3, us.items);
        }
        var res: std.ArrayList(u8) = .empty;
        try pbPutLen(a, &res, 1, t.items);
        try pbPutLen(a, &msg, 1, res.items);
    }
    try testing.expect(asked >= 1);
    var srv: netguard.TestServer = undefined;
    try srv.start(io, try grpcWebReply(a, msg.items));
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = sigorder.Overlay.init(gpa, io, srv.url(&ub), 20);
    defer o.deinit();

    try tmp.dir.createDir(io, "node", .default_dir);
    const node_dir = try tmp.dir.openDir(io, "node", .{});
    defer node_dir.close(io);
    {
        const sw = try sigorder.Sweep.open(gpa, io, h.store, &o, node_dir);
        defer sw.deinit();
        sw.behind = 0;
        try testing.expect(sw.next == null);
        try testing.expectEqual(sigorder.Sweep.Step.progress, try sw.step());
        try testing.expectEqual(@as(?u64, seq + 1), sw.next);
        try testing.expectEqual(@as(u64, 1), sw.stats.requests.load(.monotonic));
        try testing.expectEqual(@as(u64, asked), sw.stats.candidates.load(.monotonic));
        try testing.expect(sw.stats.fixed.load(.monotonic) >= 1);
        try testing.expectEqual(@as(u64, asked), sw.stats.fixed.load(.monotonic) + sw.stats.same.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), sw.stats.rejected.load(.monotonic));
        // Nothing new to sweep: no request.
        try testing.expectEqual(sigorder.Sweep.Step.idle, try sw.step());
        try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
    }
    // Every transaction now reads as sui-node's envelope (also through the hinted lookup).
    {
        var snap = h.store.snapshot();
        defer snap.release();
        for (ds, node_envs) |d, env| {
            try testing.expectEqualSlices(u8, env, snap.transaction(&d.tx).?.tx);
            try testing.expectEqualSlices(u8, env, snap.transactionNear(&d.tx, seq).?.tx);
        }
    }
    // A restart: the log reinstalls the fixes (before any request) and resumes after the mark.
    const fixed = h.store.tx_fix.count();
    h.store.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.open(gpa, io, h.store, &o, node_dir);
        defer sw.deinit();
        try testing.expectEqual(@as(u64, fixed), sw.stats.loaded.load(.monotonic));
        try testing.expectEqual(@as(?u64, seq + 1), sw.next);
        // One bulk build: one generation, everything in the base.
        try testing.expectEqual(@as(u64, 1), h.store.tx_fix.generation());
        try testing.expectEqual(fixed, h.store.tx_fix.count());
        var snap = h.store.snapshot();
        defer snap.release();
        try testing.expectEqualSlices(u8, node_envs[21], snap.transaction(&e7).?.tx);
    }
    // A torn tail is cut; the records before it still load.
    {
        const f = try node_dir.openFile(io, sigorder.log_name, .{ .mode = .read_write });
        defer f.close(io);
        const len = (try f.stat(io)).size;
        try f.writePositionalAll(io, "garbage-tail", len);
    }
    h.store.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.open(gpa, io, h.store, &o, node_dir);
        defer sw.deinit();
        try testing.expectEqual(@as(u64, fixed), sw.stats.loaded.load(.monotonic));
    }
    try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
}

test "sigorder: a sweep answer that is not the stored signatures changes nothing" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 343111673;
    var idx = try types.CheckpointIndex.init(gpa);
    defer idx.deinit(gpa);
    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    _ = try convert.protoToChkOpts(gpa, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
    try types.indexCheckpointData(plain.items, &idx);
    const blob = plain.items;
    const contents = idx.contents.slice(blob);
    const ds = try contentsDigests(a, contents);
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try tmp.dir.realPath(io, &pb)];
    var cfg: store.Config = .{ .dir = try std.fs.path.join(a, &.{ base, "store" }), .max_live_objects = 1 << 10, .max_object_versions = 1 << 10, .max_transactions = 1 << 10, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 26, .max_batch_objects = 1 << 10, .max_segments = 4, .segment_reserve = 1 << 22, .seed = 7 };
    var h = try store.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var sr = bcs.Reader.init(idx.summary.slice(blob));
    const b = try h.store.begin(seq, try sr.int(u64));
    try b.checkpoint(blob[idx.summary.o .. idx.sig.o + idx.sig.n], contents);
    for (idx.txs[0..idx.tx_count], ds) |t, d| try b.transaction(&d.tx, &d.fx, t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |e| e.slice(blob) else null);
    try h.store.commit(b);
    // Each multi-signer transaction answered with its stored signatures reversed, the first
    // signature's bytes flipped: not the certified multiset.
    var msg: std.ArrayList(u8) = .empty;
    var asked: u64 = 0;
    for (ds, idx.txs[0..idx.tx_count]) |d, t| {
        if (d.k < 2) continue;
        asked += 1;
        var tx: std.ArrayList(u8) = .empty;
        const sigs = (try sigorder.envelopeSigs(a, t.transaction.slice(blob))).sigs;
        var k = sigs.len;
        while (k > 0) {
            k -= 1;
            const g = try a.dupe(u8, sigs[k]);
            if (k == sigs.len - 1) g[5] ^= 1;
            var bb: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &bb, 2, g);
            var us: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &us, 1, bb.items);
            try pbPutLen(a, &tx, 3, us.items);
        }
        var res: std.ArrayList(u8) = .empty;
        try pbPutLen(a, &res, 1, tx.items);
        try pbPutLen(a, &msg, 1, res.items);
    }
    var srv: netguard.TestServer = undefined;
    try srv.start(io, try grpcWebReply(a, msg.items));
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = sigorder.Overlay.init(gpa, io, srv.url(&ub), 20);
    defer o.deinit();
    try tmp.dir.createDir(io, "node", .default_dir);
    const node_dir = try tmp.dir.openDir(io, "node", .{});
    defer node_dir.close(io);
    const sw = try sigorder.Sweep.open(gpa, io, h.store, &o, node_dir);
    defer sw.deinit();
    sw.behind = 0;
    try testing.expectEqual(sigorder.Sweep.Step.progress, try sw.step());
    try testing.expectEqual(asked, sw.stats.rejected.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), sw.stats.fixed.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), h.store.tx_fix.count());
}

// ------------------------------------------------------------------ sigorder: the log reload

const sig_seq: u64 = 343111673;
const StoreHandle = @typeInfo(@typeInfo(@TypeOf(store.openDir)).@"fn".return_type.?).error_union.payload;

/// The sweep tests' store: checkpoint 343111673 stored as a bucket catch-up stores it (every
/// transaction's signatures in the contents' order), sui-node's envelope of each transaction,
/// and an empty node directory.
const SigStore = struct {
    arena: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    cfg: store.Config,
    h: StoreHandle,
    node_dir: Io.Dir,
    ds: []CDigest,
    node_envs: [][]const u8,

    /// `gpa`: the store's allocator (and so its fix table's).
    fn init(s: *SigStore, gpa: std.mem.Allocator) !void {
        const io = testing.io;
        s.arena = .init(testing.allocator);
        errdefer s.arena.deinit();
        const a = s.arena.allocator();
        var idx = try types.CheckpointIndex.init(testing.allocator);
        defer idx.deinit(testing.allocator);
        var want: std.ArrayList(u8) = .empty;
        defer want.deinit(testing.allocator);
        _ = try convert.protoToChk(testing.allocator, a, sigorder_proto, &want);
        var plain: std.ArrayList(u8) = .empty;
        defer plain.deinit(testing.allocator);
        _ = try convert.protoToChkOpts(testing.allocator, a, sigorder_proto, &plain, null, .{ .tx_signature_order = false });
        try types.indexCheckpointData(want.items, &idx);
        s.node_envs = try a.alloc([]const u8, idx.tx_count);
        for (s.node_envs, idx.txs[0..idx.tx_count]) |*e, t| e.* = try a.dupe(u8, t.transaction.slice(want.items));

        s.tmp = testing.tmpDir(.{ .iterate = true });
        errdefer s.tmp.cleanup();
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const base = pb[0..try s.tmp.dir.realPath(io, &pb)];
        s.cfg = .{ .dir = try std.fs.path.join(a, &.{ base, "store" }), .max_live_objects = 1 << 10, .max_object_versions = 1 << 10, .max_transactions = 1 << 10, .max_checkpoints = 1 << 6, .max_batch_bytes = 1 << 26, .max_batch_objects = 1 << 10, .max_segments = 4, .segment_reserve = 1 << 22, .seed = 7 };
        s.h = try store.openDir(gpa, io, &s.cfg, .{ .sync = .none });
        errdefer {
            s.h.store.deinit();
            s.h.io.deinit();
        }
        try types.indexCheckpointData(plain.items, &idx);
        const blob = plain.items;
        const contents = idx.contents.slice(blob);
        s.ds = try contentsDigests(a, contents);
        try testing.expectEqual(@as(usize, idx.tx_count), s.ds.len);
        var sr = bcs.Reader.init(idx.summary.slice(blob));
        const b = try s.h.store.begin(sig_seq, try sr.int(u64));
        try b.checkpoint(blob[idx.summary.o .. idx.sig.o + idx.sig.n], contents);
        for (idx.txs[0..idx.tx_count], s.ds) |t, d| try b.transaction(&d.tx, &d.fx, t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |e| e.slice(blob) else null);
        try s.h.store.commit(b);
        try s.tmp.dir.createDir(io, "node", .default_dir);
        s.node_dir = try s.tmp.dir.openDir(io, "node", .{ .iterate = true });
    }

    fn deinit(s: *SigStore) void {
        s.node_dir.close(testing.io);
        s.h.store.deinit();
        s.h.io.deinit();
        s.tmp.cleanup();
        s.arena.deinit();
    }

    /// The full node's BatchGetTransactions answer (an HTTP reply) for the checkpoint's
    /// multi-signer transactions: sui-node's signature order of each.
    fn batchReply(s: *SigStore) ![]const u8 {
        const a = s.arena.allocator();
        var msg: std.ArrayList(u8) = .empty;
        for (s.ds, 0..) |d, i| {
            if (d.k < 2) continue;
            var tb: [44]u8 = undefined;
            var t: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &t, 1, serve.b58.encode32(&tb, &d.tx));
            for ((try sigorder.envelopeSigs(a, s.node_envs[i])).sigs) |g| {
                var bb: std.ArrayList(u8) = .empty;
                try pbPutLen(a, &bb, 2, g);
                var us: std.ArrayList(u8) = .empty;
                try pbPutLen(a, &us, 1, bb.items);
                try pbPutLen(a, &t, 3, us.items);
            }
            var res: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &res, 1, t.items);
            try pbPutLen(a, &msg, 1, res.items);
        }
        return grpcWebReply(a, msg.items);
    }

    fn writeLog(s: *SigStore, bytes: []const u8) !void {
        const f = try s.node_dir.createFile(testing.io, sigorder.log_name, .{ .truncate = true });
        defer f.close(testing.io);
        try f.writePositionalAll(testing.io, bytes, 0);
    }

    fn readLog(s: *SigStore, gpa: std.mem.Allocator) ![]u8 {
        return s.node_dir.readFileAlloc(testing.io, sigorder.log_name, gpa, .unlimited);
    }

    /// The fix table's entry of each of `digests` (null: none).
    fn table(s: *SigStore, a: std.mem.Allocator, digests: []const [32]u8) ![]?store.txfix.Entry {
        var snap = s.h.store.snapshot();
        defer snap.release();
        const out = try a.alloc(?store.txfix.Entry, digests.len);
        for (out, digests) |*o, *d| o.* = if (s.h.store.tx_fix.find(d)) |f| .{ .seq = f.seq, .digest = f.digest, .tx = try a.dupe(u8, f.tx) } else null;
        return out;
    }

    /// GetTransaction of every transaction (the response messages one after another), one
    /// BatchGetTransactions of all of them, and GetCheckpoint: digests, signatures and
    /// transaction bytes.
    fn served(s: *SigStore, a: std.mem.Allocator) ![3][]const u8 {
        var svc: serve.service.Service = .{ .gpa = testing.allocator, .store = s.h.store, .chain_id = @splat(0), .json = false, .display = false, .lowest_checkpoint = sig_seq };
        defer svc.deinit();
        const tx_mask = try rsMask(a, &.{ "digest", "signatures", "transaction.bcs" });
        var one: std.ArrayList(u8) = .empty;
        var breq: std.ArrayList(u8) = .empty;
        for (s.ds) |*d| {
            var tb: [44]u8 = undefined;
            const text = serve.b58.encode32(&tb, &d.tx);
            try pbPutLen(a, &breq, 1, text);
            var req: std.ArrayList(u8) = .empty;
            try pbPutLen(a, &req, 1, text);
            try pbPutLen(a, &req, 2, tx_mask);
            const r = try serve.loopback.unary(a, svc.handler(), "/sui.rpc.v2.LedgerService/GetTransaction", req.items);
            try testing.expectEqual(@as(u32, 0), r.status);
            try one.appendSlice(a, r.message);
        }
        try pbPutLen(a, &breq, 2, tx_mask);
        const bt = try serve.loopback.unary(a, svc.handler(), "/sui.rpc.v2.LedgerService/BatchGetTransactions", breq.items);
        try testing.expectEqual(@as(u32, 0), bt.status);
        var creq: std.ArrayList(u8) = .empty;
        try pbPutVarint(a, &creq, 1 << 3);
        try pbPutVarint(a, &creq, sig_seq);
        try pbPutLen(a, &creq, 3, try rsMask(a, &.{ "sequence_number", "transactions.digest", "transactions.signatures", "transactions.transaction.bcs" }));
        const cp = try serve.loopback.unary(a, svc.handler(), "/sui.rpc.v2.LedgerService/GetCheckpoint", creq.items);
        try testing.expectEqual(@as(u32, 0), cp.status);
        return .{ one.items, bt.message, cp.message };
    }
};

fn expectSameTable(want: []const ?store.txfix.Entry, got: []const ?store.txfix.Entry) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| {
        try testing.expectEqual(w == null, g == null);
        if (w == null) continue;
        try testing.expectEqual(w.?.seq, g.?.seq);
        try testing.expectEqualSlices(u8, &w.?.digest, &g.?.digest);
        try testing.expectEqualSlices(u8, w.?.tx, g.?.tx);
    }
}

/// Fixes for transactions that never were: sui-node's envelope of the fixture's smallest
/// multi-signer transaction with the gas budget set to `i`, so each has its own digest and
/// proves itself (`sigorder.selfProven`), and no store holds it.
const SynthFix = struct {
    env: []u8,
    from: usize,
    to: usize,

    fn init(a: std.mem.Allocator, fx: *const SigStore) !SynthFix {
        var best: ?[]const u8 = null;
        for (fx.ds, fx.node_envs) |d, e| {
            if (d.k >= 2 and (best == null or e.len < best.?.len)) best = e;
        }
        const env = try a.dupe(u8, best.?);
        const head = (try sigorder.envelopeSigs(a, env)).head;
        // TransactionData V1 ends `gas price u64, gas budget u64, expiration`; None is one 0.
        try testing.expectEqual(@as(u8, 0), env[head - 1]);
        return .{ .env = env, .from = 4, .to = head };
    }

    /// The `i`th envelope (valid until the next call) and its transaction digest.
    fn get(s: *SynthFix, i: u64) struct { digest: [32]u8, env: []const u8 } {
        std.mem.writeInt(u64, s.env[s.to - 9 ..][0..8], i, .little);
        return .{ .digest = hash.blake2b256(&.{ "TransactionData::", s.env[s.from..s.to] }), .env = s.env };
    }
};

fn txReads() u64 {
    return store.readstats.hist[@intFromEnum(store.readstats.Table.transactions)].count();
}

test "sigorder: a restart installs the logged fixes of held checkpoints from the log alone, with no stored transaction read" {
    const gpa = testing.allocator;
    const io = testing.io;
    var fx: SigStore = undefined;
    try fx.init(gpa);
    defer fx.deinit();
    const a = fx.arena.allocator();
    var syn = try SynthFix.init(a, &fx);
    var o = sigorder.Overlay.init(gpa, io, "http://127.0.0.1:1", 20);
    defer o.deinit();

    // 6000 fixes around the store's only checkpoint: three in eight below it (pruned).
    const n: u64 = 6000;
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(gpa);
    try log.appendSlice(gpa, sigorder.log_magic);
    var held: u64 = 0;
    for (0..n) |i| {
        const t = syn.get(i);
        try testing.expect(sigorder.selfProven(&t.digest, t.env));
        const seq = sig_seq - 3 + i % 8;
        held += @intFromBool(seq >= sig_seq);
        try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, seq, &t.digest, t.env);
    }
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq, &@as([32]u8, @splat(0)), "");
    try fx.writeLog(log.items);
    const st = fx.h.store;

    // The reload before this one asked the store for every fix's transaction (the counters see
    // it: the sampled read histogram and the reload's own count), and these it never held.
    {
        const before = txReads();
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .proof = .store });
        defer sw.deinit();
        try testing.expectEqual(n, sw.reload.store_lookups);
        try testing.expect(txReads() - before >= n / store.readstats.sample_every - 64);
        try testing.expectEqual(@as(u64, 0), sw.reload.installed);
        try testing.expectEqual(n, sw.reload.unproven);
        try testing.expectEqual(@as(usize, 0), st.tx_fix.count());
    }
    // From the log alone: no transaction read, exactly the fixes at or above the floor. (No
    // rewrite here: the next tests cover it.)
    {
        const before = txReads();
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_min = std.math.maxInt(u64) });
        defer sw.deinit();
        try testing.expectEqual(@as(u64, 0), sw.reload.store_lookups);
        try testing.expectEqual(before, txReads());
        try testing.expectEqual(sig_seq, sw.reload.floor);
        try testing.expectEqual(n, sw.reload.fixes);
        try testing.expectEqual(n - held, sw.reload.pruned);
        try testing.expectEqual(held, sw.reload.installed);
        try testing.expectEqual(held, sw.stats.loaded.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), sw.reload.rejected);
        try testing.expectEqual(@as(u64, 0), sw.reload.cut);
        try testing.expect(!sw.reload.compacted);
        try testing.expect(sw.reload.dead_bytes * 4 > log.items.len);
        try testing.expectEqual(@as(?u64, sig_seq + 1), sw.next);
        try testing.expectEqual(@as(usize, @intCast(held)), st.tx_fix.count());
        try testing.expectEqual(@as(u64, 1), st.tx_fix.generation());
        // No snapshot outlives the reload.
        try testing.expect(st.creaders.oldest() == null);
    }
    var snap = st.snapshot();
    defer snap.release();
    for (0..n) |i| {
        const t = syn.get(i);
        const seq = sig_seq - 3 + i % 8;
        const f = st.tx_fix.find(&t.digest);
        if (seq < sig_seq) {
            try testing.expect(f == null);
            continue;
        }
        try testing.expectEqual(seq, f.?.seq);
        try testing.expectEqualSlices(u8, t.env, f.?.tx);
    }
    // The log is as it was.
    const now = try fx.readLog(gpa);
    defer gpa.free(now);
    try testing.expectEqualSlices(u8, log.items, now);
}

test "sigorder: the table reloaded from the log is the live sweep's; GetTransaction, BatchGetTransactions and GetCheckpoint answer the same bytes" {
    const gpa = testing.allocator;
    const io = testing.io;
    var fx: SigStore = undefined;
    try fx.init(gpa);
    defer fx.deinit();
    const a = fx.arena.allocator();
    const st = fx.h.store;
    const digests = try a.alloc([32]u8, fx.ds.len);
    for (digests, fx.ds) |*d, c| d.* = c.tx;
    var srv: netguard.TestServer = undefined;
    try srv.start(io, try fx.batchReply());
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = sigorder.Overlay.init(gpa, io, srv.url(&ub), 20);
    defer o.deinit();

    // As stored: the contents' order.
    const plain = try fx.served(a);
    // The live sweep.
    {
        const sw = try sigorder.Sweep.open(gpa, io, st, &o, fx.node_dir);
        defer sw.deinit();
        sw.behind = 0;
        try testing.expectEqual(sigorder.Sweep.Step.progress, try sw.step());
        try testing.expect(sw.stats.fixed.load(.monotonic) >= 1);
    }
    const live = try fx.table(a, digests);
    const live_n = st.tx_fix.count();
    try testing.expect(live_n >= 1);
    const live_served = try fx.served(a);
    for (plain, live_served) |p, l| try testing.expect(!std.mem.eql(u8, p, l));
    {
        var snap = st.snapshot();
        defer snap.release();
        for (fx.ds, fx.node_envs) |d, env| try testing.expectEqualSlices(u8, env, snap.transaction(&d.tx).?.tx);
    }

    // A restart, from the log alone.
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try testing.expectEqual(@as(u64, live_n), sw.reload.installed);
        try testing.expectEqual(@as(u64, live_n), sw.reload.fixes);
        try testing.expectEqual(@as(u64, 0), sw.reload.store_lookups);
        try testing.expectEqual(@as(u64, 0), sw.reload.rejected);
        try testing.expectEqual(@as(?u64, sig_seq + 1), sw.next);
        // Nothing left to sweep, nothing asked.
        sw.behind = 0;
        try testing.expectEqual(sigorder.Sweep.Step.idle, try sw.step());
    }
    try testing.expectEqual(live_n, st.tx_fix.count());
    try expectSameTable(live, try fx.table(a, digests));
    const again = try fx.served(a);
    for (live_served, again) |l, g| try testing.expectEqualSlices(u8, l, g);

    // And the same table as the reload that proves every fix against its stored transaction.
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .proof = .store });
        defer sw.deinit();
        try testing.expectEqual(@as(u64, live_n), sw.reload.installed);
        try testing.expectEqual(@as(u64, live_n), sw.reload.store_lookups);
    }
    try expectSameTable(live, try fx.table(a, digests));
    try testing.expectEqual(@as(u64, 1), srv.accepts.load(.monotonic));
}

test "sigorder: a corrupt log record is rejected and the rest still loads; no mark after it counts; the log is rewritten without it; a torn tail is cut" {
    const gpa = testing.allocator;
    const io = testing.io;
    var fx: SigStore = undefined;
    try fx.init(gpa);
    defer fx.deinit();
    const a = fx.arena.allocator();
    const st = fx.h.store;
    var syn = try SynthFix.init(a, &fx);
    var o = sigorder.Overlay.init(gpa, io, "http://127.0.0.1:1", 20);
    defer o.deinit();
    const zero: [32]u8 = @splat(0);

    var ds: [8][32]u8 = undefined;
    var envs: [8][]const u8 = undefined;
    for (&ds, &envs, 0..) |*d, *e, i| {
        const t = syn.get(i);
        d.* = t.digest;
        e.* = try a.dupe(u8, t.env);
    }
    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(gpa);
    try log.appendSlice(gpa, sigorder.log_magic);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[0], envs[0]);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq - 10, &zero, "");
    // A flipped byte in the envelope: the checksum fails.
    const bad_at = log.items.len;
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[1], envs[1]);
    log.items[bad_at + sigorder.rec_head + 40] ^= 0x10;
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[2], envs[2]);
    // Good checksums, but not the transaction's envelope: a digest no transaction has, and a
    // stored transaction's digest over another transaction's envelope.
    var wrong = ds[3];
    wrong[7] ^= 1;
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &wrong, envs[3]);
    var e7: [32]u8 = undefined;
    for (fx.ds) |d| if (d.k >= 2) {
        e7 = d.tx;
    };
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &e7, envs[4]);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq, &zero, "");
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[5], envs[5]);
    const whole = log.items.len;
    // A record half written.
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[6], envs[6]);
    log.shrinkRetainingCapacity(whole + 30);
    try fx.writeLog(log.items);

    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try testing.expectEqual(@as(u64, 3), sw.reload.installed);
        try testing.expectEqual(@as(u64, 3), sw.reload.rejected);
        // Only the two records that do not prove themselves were looked up.
        try testing.expectEqual(@as(u64, 2), sw.reload.store_lookups);
        try testing.expectEqual(@as(u64, 30), sw.reload.cut);
        // The mark after the first rejected record does not count: its fix is to be found again.
        try testing.expectEqual(@as(?u64, sig_seq - 9), sw.next);
        var snap = st.snapshot();
        defer snap.release();
        for ([_]usize{ 0, 2, 5 }) |i| try testing.expectEqualSlices(u8, envs[i], st.tx_fix.find(&ds[i]).?.tx);
        for ([_]usize{ 1, 3, 4, 6 }) |i| try testing.expect(st.tx_fix.find(&ds[i]) == null);
        try testing.expect(st.tx_fix.find(&wrong) == null);
        try testing.expect(st.tx_fix.find(&e7) == null);
        try testing.expectEqual(@as(usize, 3), st.tx_fix.count());
        // The stored transaction still reads as stored.
        try testing.expect(snap.transaction(&e7) != null);
        try testing.expect(sw.reload.compacted);
    }
    // The log now holds the three intact fixes and the mark that counts, so the next start
    // rejects nothing, reads no transaction and resumes at the same place.
    {
        var want: std.ArrayList(u8) = .empty;
        defer want.deinit(gpa);
        try want.appendSlice(gpa, sigorder.log_magic);
        for ([_]usize{ 0, 2, 5 }) |i| try sigorder.encodeRec(gpa, &want, sigorder.kind_fix, sig_seq, &ds[i], envs[i]);
        try sigorder.encodeRec(gpa, &want, sigorder.kind_mark, sig_seq - 10, &zero, "");
        const now = try fx.readLog(gpa);
        defer gpa.free(now);
        try testing.expectEqualSlices(u8, want.items, now);
        st.tx_fix.reset();
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try testing.expectEqual(@as(u64, 3), sw.reload.installed);
        try testing.expectEqual(@as(u64, 0), sw.reload.rejected);
        try testing.expectEqual(@as(u64, 0), sw.reload.store_lookups);
        try testing.expectEqual(@as(u64, 0), sw.reload.dead_bytes);
        try testing.expect(!sw.reload.compacted);
        try testing.expectEqual(@as(u64, want.items.len), sw.end);
        try testing.expectEqual(@as(?u64, sig_seq - 9), sw.next);
    }

    // A bad checksum in the last record is a torn tail: cut, as a half-written record is.
    st.tx_fix.reset();
    log.shrinkRetainingCapacity(sigorder.log_magic.len);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[0], envs[0]);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq, &zero, "");
    const keep = log.items.len;
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[1], envs[1]);
    log.items[log.items.len - 1] ^= 1;
    try fx.writeLog(log.items);
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try testing.expectEqual(@as(u64, 1), sw.reload.installed);
        try testing.expectEqual(@as(u64, 0), sw.reload.rejected);
        try testing.expectEqual(@as(u64, log.items.len - keep), sw.reload.cut);
        try testing.expect(!sw.reload.compacted);
        try testing.expectEqual(@as(?u64, sig_seq + 1), sw.next);
    }
    const now = try fx.readLog(gpa);
    defer gpa.free(now);
    try testing.expectEqualSlices(u8, log.items[0..keep], now);
}

test "sigorder: 100,000 logged fixes reload in memory proportional to the log, with no snapshot held" {
    const io = testing.io;
    const n: u64 = 100_000;
    var counting: store.txfix.Counting = .{ .child = testing.allocator };
    const gpa = counting.allocator();
    var fx: SigStore = undefined;
    try fx.init(gpa);
    defer fx.deinit();
    const a = fx.arena.allocator();
    const st = fx.h.store;
    var syn = try SynthFix.init(a, &fx);
    var o = sigorder.Overlay.init(testing.allocator, io, "http://127.0.0.1:1", 20);
    defer o.deinit();

    // One fix in ten below the store's lowest checkpoint; the log written in pieces.
    var held: u64 = 0;
    var log_bytes: u64 = sigorder.log_magic.len;
    {
        const f = try fx.node_dir.createFile(io, sigorder.log_name, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, sigorder.log_magic, 0);
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(testing.allocator);
        for (0..n) |i| {
            const t = syn.get(i);
            const seq = if (i % 10 == 0) sig_seq - 1 else sig_seq + i / 100;
            held += @intFromBool(seq >= sig_seq);
            try sigorder.encodeRec(testing.allocator, &buf, sigorder.kind_fix, seq, &t.digest, t.env);
            if (buf.items.len >= 1 << 20 or i + 1 == n) {
                try f.writePositionalAll(io, buf.items, log_bytes);
                log_bytes += buf.items.len;
                buf.clearRetainingCapacity();
            }
        }
    }
    const before_reads = txReads();
    const live0 = counting.live.load(.monotonic);
    counting.peak.store(live0, .monotonic);
    const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
    defer sw.deinit();
    // One dead record in ten (6 MB): not worth a rewrite.
    try testing.expect(!sw.reload.compacted);
    try testing.expectEqual(log_bytes, sw.end);
    const peak = counting.peak.load(.monotonic) - live0;
    const kept = counting.live.load(.monotonic) - live0;
    try testing.expectEqual(held, sw.reload.installed);
    try testing.expectEqual(n - held, sw.reload.pruned);
    try testing.expectEqual(@as(u64, 0), sw.reload.store_lookups);
    try testing.expectEqual(before_reads, txReads());
    try testing.expect(st.creaders.oldest() == null);
    try testing.expectEqual(@as(usize, @intCast(held)), st.tx_fix.count());
    // The peak: the log read once and the table's copy of the installed envelopes, plus the
    // table's and the reload's per-fix bookkeeping. No store chunk: the reload that looked
    // every fix up held a snapshot's decoded chunks (12 GB at 65k fixes, 3 GB renewed).
    try testing.expect(peak <= 2 * log_bytes + n * 1024);
    try testing.expect(kept <= log_bytes + n * 256);
    {
        var snap = st.snapshot();
        defer snap.release();
        var i: u64 = 1;
        while (i < n) : (i += 997) {
            const t = syn.get(i);
            if (i % 10 == 0) try testing.expect(st.tx_fix.find(&t.digest) == null) else try testing.expectEqualSlices(u8, t.env, st.tx_fix.find(&t.digest).?.tx);
        }
    }
    std.debug.print("sig-order reload 100k: {d} fixes ({d} B log) in {d} ms; {d} installed, {d} below the floor; peak {d} B ({d} B/fix), kept {d} B; stored transactions read 0\n", .{ n, log_bytes, sw.reload.ns / std.time.ns_per_ms, sw.reload.installed, sw.reload.pruned, peak, peak / n, kept });

    // The same start with the rewrite forced (a lower byte threshold): the table is the same,
    // the log loses the pruned tenth, and the rewrite's buffer adds nothing that grows with it.
    st.tx_fix.reset();
    const live1 = counting.live.load(.monotonic);
    counting.peak.store(live1, .monotonic);
    const sw2 = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_bytes = 1 << 20 });
    defer sw2.deinit();
    const peak2 = counting.peak.load(.monotonic) - live1;
    try testing.expect(sw2.reload.compacted);
    try testing.expectEqual(held, sw2.reload.installed);
    try testing.expectEqual(log_bytes - sw2.reload.dead_bytes, sw2.reload.size);
    try testing.expectEqual((try fx.node_dir.statFile(io, sigorder.log_name, .{})).size, sw2.reload.size);
    try testing.expect(peak2 <= 2 * log_bytes + n * 1024);
    std.debug.print("sig-order reload 100k with a rewrite: {d} ms, log {d} -> {d} B, peak {d} B\n", .{ sw2.reload.ns / std.time.ns_per_ms, log_bytes, sw2.reload.size, peak2 });
}

test "sigorder: a restart rewrites the log without pruned and superseded fixes and old marks; a crash before or after the rename leaves a whole log" {
    const gpa = testing.allocator;
    const io = testing.io;
    var fx: SigStore = undefined;
    try fx.init(gpa);
    defer fx.deinit();
    const a = fx.arena.allocator();
    const st = fx.h.store;
    var syn = try SynthFix.init(a, &fx);
    var o = sigorder.Overlay.init(gpa, io, "http://127.0.0.1:1", 20);
    defer o.deinit();
    const zero: [32]u8 = @splat(0);
    var ds: [6][32]u8 = undefined;
    var envs: [6][]const u8 = undefined;
    for (&ds, &envs, 0..) |*d, *e, i| {
        const t = syn.get(i);
        d.* = t.digest;
        e.* = try a.dupe(u8, t.env);
    }
    // Transaction 1 logged twice: first with its signatures the other way round.
    const sigs = (try sigorder.envelopeSigs(a, envs[1])).sigs;
    const rev = try a.alloc([]const u8, sigs.len);
    for (rev, 0..) |*r, j| r.* = sigs[sigs.len - 1 - j];
    const first = (try sigorder.reorder(a, envs[1], rev)).?;
    try testing.expect(sigorder.selfProven(&ds[1], first));

    var log: std.ArrayList(u8) = .empty;
    defer log.deinit(gpa);
    try log.appendSlice(gpa, sigorder.log_magic);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq - 1, &ds[0], envs[0]); // pruned
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq - 20, &zero, "");
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[1], first); // superseded
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[2], envs[2]);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq - 10, &zero, "");
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[1], envs[1]);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq - 2, &ds[3], envs[3]); // pruned
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq + 1, &ds[4], envs[4]);
    try sigorder.encodeRec(gpa, &log, sigorder.kind_mark, sig_seq, &zero, "");
    // A fix after the last mark (a pass that logged its fixes and then failed).
    try sigorder.encodeRec(gpa, &log, sigorder.kind_fix, sig_seq, &ds[5], envs[5]);
    try fx.writeLog(log.items);
    // The live records in their order, then the last mark.
    var want: std.ArrayList(u8) = .empty;
    defer want.deinit(gpa);
    try want.appendSlice(gpa, sigorder.log_magic);
    try sigorder.encodeRec(gpa, &want, sigorder.kind_fix, sig_seq, &ds[2], envs[2]);
    try sigorder.encodeRec(gpa, &want, sigorder.kind_fix, sig_seq, &ds[1], envs[1]);
    try sigorder.encodeRec(gpa, &want, sigorder.kind_fix, sig_seq + 1, &ds[4], envs[4]);
    try sigorder.encodeRec(gpa, &want, sigorder.kind_fix, sig_seq, &ds[5], envs[5]);
    try sigorder.encodeRec(gpa, &want, sigorder.kind_mark, sig_seq, &zero, "");

    const Check = struct {
        fn table(s: *store.Store, d: *const [6][32]u8, e: *const [6][]const u8) !void {
            var snap = s.snapshot();
            defer snap.release();
            try testing.expectEqual(@as(usize, 4), s.tx_fix.count());
            for ([_]usize{ 1, 2, 4, 5 }) |i| try testing.expectEqualSlices(u8, e[i], s.tx_fix.find(&d[i]).?.tx);
            for ([_]usize{ 0, 3 }) |i| try testing.expect(s.tx_fix.find(&d[i]) == null);
        }
        fn logIs(f: *SigStore, bytes: []const u8) !void {
            const now = try f.readLog(testing.allocator);
            defer testing.allocator.free(now);
            try testing.expectEqualSlices(u8, bytes, now);
        }
    };

    // Too little to be worth a rewrite (the default: 64 KiB of dead records at least).
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try testing.expectEqual(@as(u64, 4), sw.reload.installed);
        try testing.expectEqual(@as(u64, 2), sw.reload.pruned);
        try testing.expectEqual(@as(u64, 1), sw.reload.superseded);
        try testing.expectEqual(@as(u64, log.items.len - want.items.len), sw.reload.dead_bytes);
        try testing.expect(!sw.reload.compacted);
        try testing.expectEqual(@as(?u64, sig_seq + 1), sw.next);
        try Check.table(st, &ds, &envs);
    }
    try Check.logIs(&fx, log.items);

    // A crash after the new log is written and synced, before the rename: the old log stands.
    st.tx_fix.reset();
    try testing.expectError(error.CrashInjected, sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_min = 0, .crash_at = .before_rename }));
    try Check.logIs(&fx, log.items);
    _ = try fx.node_dir.statFile(io, sigorder.log_tmp, .{});
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try testing.expectEqual(@as(?u64, sig_seq + 1), sw.next);
        try Check.table(st, &ds, &envs);
    }
    try Check.logIs(&fx, log.items);
    try testing.expectError(error.FileNotFound, fx.node_dir.statFile(io, sigorder.log_tmp, .{}));
    // A crash while the new log was being written: the same, whatever the leftover holds.
    {
        const f = try fx.node_dir.createFile(io, sigorder.log_tmp, .{ .truncate = true });
        defer f.close(io);
        try f.writePositionalAll(io, want.items[0 .. want.items.len / 2], 0);
    }
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{});
        defer sw.deinit();
        try Check.table(st, &ds, &envs);
    }
    try Check.logIs(&fx, log.items);
    try testing.expectError(error.FileNotFound, fx.node_dir.statFile(io, sigorder.log_tmp, .{}));

    // A crash after the rename (before the directory sync): the new log stands.
    st.tx_fix.reset();
    try testing.expectError(error.CrashInjected, sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_min = 0, .crash_at = .after_rename }));
    try Check.logIs(&fx, want.items);
    try testing.expectError(error.FileNotFound, fx.node_dir.statFile(io, sigorder.log_tmp, .{}));
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_min = 0 });
        defer sw.deinit();
        try testing.expectEqual(@as(u64, 4), sw.reload.installed);
        try testing.expectEqual(@as(u64, 4), sw.reload.fixes);
        try testing.expectEqual(@as(u64, 1), sw.reload.marks);
        try testing.expectEqual(@as(u64, 0), sw.reload.dead_bytes);
        try testing.expect(!sw.reload.compacted);
        try testing.expectEqual(@as(u64, want.items.len), sw.end);
        try testing.expectEqual(@as(?u64, sig_seq + 1), sw.next);
        try Check.table(st, &ds, &envs);
    }
    try Check.logIs(&fx, want.items);

    // The whole rewrite, and its thresholds: under a quarter dead it waits for `compact_bytes`.
    try sigorder.encodeRec(gpa, &want, sigorder.kind_fix, sig_seq - 1, &ds[0], envs[0]);
    try fx.writeLog(want.items);
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_min = 0 });
        defer sw.deinit();
        try testing.expect(sw.reload.dead_bytes > 0 and sw.reload.dead_bytes * 4 < want.items.len);
        try testing.expect(!sw.reload.compacted);
        try testing.expectEqual(@as(u64, want.items.len), sw.end);
    }
    try Check.logIs(&fx, want.items);
    st.tx_fix.reset();
    {
        const sw = try sigorder.Sweep.openWith(gpa, io, st, &o, fx.node_dir, .{ .compact_min = 0, .compact_bytes = 1 });
        defer sw.deinit();
        try testing.expect(sw.reload.compacted);
        try testing.expectEqual(@as(u64, 1), sw.reload.pruned);
        try testing.expectEqual(sw.reload.size, sw.end);
        try Check.table(st, &ds, &envs);
    }
    want.shrinkRetainingCapacity(want.items.len - sigorder.rec_head - envs[0].len);
    // The mark moved behind the fix that followed it; nothing else changed.
    var last: std.ArrayList(u8) = .empty;
    defer last.deinit(gpa);
    try last.appendSlice(gpa, sigorder.log_magic);
    try sigorder.encodeRec(gpa, &last, sigorder.kind_fix, sig_seq, &ds[2], envs[2]);
    try sigorder.encodeRec(gpa, &last, sigorder.kind_fix, sig_seq, &ds[1], envs[1]);
    try sigorder.encodeRec(gpa, &last, sigorder.kind_fix, sig_seq + 1, &ds[4], envs[4]);
    try sigorder.encodeRec(gpa, &last, sigorder.kind_fix, sig_seq, &ds[5], envs[5]);
    try sigorder.encodeRec(gpa, &last, sigorder.kind_mark, sig_seq, &zero, "");
    try testing.expectEqualSlices(u8, want.items, last.items);
    try Check.logIs(&fx, last.items);
}

// ------------------------------------------------------------------ p2p: read sets

const serve = @import("serve");
const RsKey = exec.objects.Key;
const RsMeta = struct { epoch: u64, pv: ?u64 = null, rgp: ?u64 = null, start_ms: ?u64 = null };

/// `packages/<id>.obj` of the corpus behind a p2p `PackageSource`'s own lookup (the store): a
/// node holds every package, a store seeded with one checkpoint's objects does not.
const RsPkgs = struct {
    inner: exec.packages.Store.Lookup,
    dir: Io.Dir,
    keep: std.mem.Allocator,
    lock: std.atomic.Mutex = .unlocked,
    seen: std.AutoHashMapUnmanaged([32]u8, ?[]const u8) = .empty,

    fn get(p: *const anyopaque, id: *const [32]u8, epoch: u64) ?[]const u8 {
        const c: *RsPkgs = @ptrCast(@alignCast(@constCast(p)));
        if (c.inner.get(c.inner.ctx, id, epoch)) |raw| return raw;
        return c.file(id);
    }

    fn file(c: *RsPkgs, id: *const [32]u8) ?[]const u8 {
        while (!c.lock.tryLock()) std.atomic.spinLoopHint();
        defer c.lock.unlock();
        if (c.seen.get(id.*)) |hit| return hit;
        var nb: [80]u8 = undefined;
        const name = std.fmt.bufPrint(&nb, "{x}.obj", .{id}) catch unreachable;
        const raw: ?[]const u8 = c.dir.readFileAlloc(testing.io, name, c.keep, .limited(1 << 28)) catch null;
        c.seen.put(c.keep, id.*, raw) catch {};
        return raw;
    }
};

/// Execution's own allocator (per-thread package caches and VM runtimes, kept for the thread's
/// life as on a node): not the test allocator, which would report the pool threads' caches.
const rs_exec_gpa = std.heap.smp_allocator;

const RsEnv = struct {
    gpa: std.mem.Allocator,
    base: []const u8,
    tmp: *testing.TmpDir,
    metas: []const RsMeta,
    ps: *p2p_exec.PackageSource,
    pkgs: *RsPkgs,
    sys: *execute.Executor,
    /// The node's exec threads: the level-parallel build must give the in-order build's bytes.
    pool: ?*p2p_exec.Pool = null,
    stats: p2p_exec.Stats = .{},
    idx: types.CheckpointIndex,
    /// Print every difference (exploration: ZUI_P2P_READSETS=FROM-TO).
    diag: bool = false,
    built: u64 = 0,
    fallbacks: u64 = 0,
    /// Transactions whose p2p loaded list differs from the bucket's, and checkpoints whose
    /// extra objects differ.
    list_diffs: u64 = 0,
    extra_diffs: u64 = 0,
    store_diffs: u64 = 0,
    render_diffs: u64 = 0,
    loaded_txs: u64 = 0,
    loaded_refs: u64 = 0,
    /// Implicit system object reads (the accumulator root of an object funds check).
    implicit_reads: u64 = 0,
    /// Entries of sui-node's lists for the two objects the production shadow saw missing.
    seen_count_field: u64 = 0,
    seen_usdc_config: u64 = 0,
};

/// The accumulator object count field every settlement reads (0xea4eb7...c468) and the coin deny
/// list v2 config of USDC under 0x403 (0x184a29...9284, read through `ObjectStore::get_object`
/// when a transaction leaves a USDC coin with an owner): the entries a p2p-built checkpoint
/// missed on the production shadow.
const rs_count_field: [32]u8 = .{ 0xea, 0x4e, 0xb7, 0x7f, 0x2a, 0x5a, 0x8b, 0xa1, 0x72, 0xde, 0x0c, 0x4d, 0x2c, 0x51, 0xbe, 0x91, 0x68, 0x6e, 0xc8, 0x4f, 0xdc, 0xcd, 0x9a, 0x9d, 0xad, 0xd3, 0xba, 0x76, 0x74, 0xba, 0xc4, 0x68 };
const rs_usdc_config: [32]u8 = .{ 0x18, 0x4a, 0x29, 0x2d, 0x5c, 0xf7, 0x92, 0x04, 0x4a, 0xf5, 0xe2, 0x6f, 0x00, 0x1e, 0x4c, 0x87, 0x9e, 0xc6, 0x4b, 0x7a, 0x34, 0x57, 0xa8, 0xbc, 0x90, 0xa0, 0xcd, 0x77, 0xe8, 0x83, 0x92, 0x84 };

fn rsLess(_: void, a: RsKey, b: RsKey) bool {
    const o = std.mem.order(u8, &a.id, &b.id);
    return if (o == .eq) a.version < b.version else o == .lt;
}

const RsStore = struct { store: *store.Store, io: *store.RealIo };

fn rsStore(env: *RsEnv, a: std.mem.Allocator, name: []const u8) !RsStore {
    var cfg: store.Config = .{ .dir = try std.fs.path.join(a, &.{ env.base, name }), .max_live_objects = 1 << 16, .max_object_versions = 1 << 16, .max_transactions = 1 << 14, .max_checkpoints = 1 << 6, .max_segments = 16, .segment_reserve = 1 << 26, .seed = 7 };
    const h = try store.openDir(env.gpa, testing.io, &cfg, .{ .sync = .none });
    return .{ .store = h.store, .io = h.io };
}

/// The store as of the checkpoint before `blob`'s: every object version the checkpoint read that
/// it did not write itself (its input objects and the archive's object set) is live, with the
/// system packages of `epoch`. It holds nothing sui-node did not read, so a read of some other
/// object that a node's full store would answer is not seen here (`deepwave check` against the
/// bucket on a store followed with --p2p covers that).
fn rsSeed(env: *RsEnv, a: std.mem.Allocator, st: *store.Store, seq: u64, epoch: u64, blob: []const u8, bucket: convert.Aux) !void {
    return rsSeedWithout(env, a, st, seq, epoch, blob, bucket, null);
}

/// `rsSeed` leaving out one object version (a store that never held it).
fn rsSeedWithout(env: *RsEnv, a: std.mem.Allocator, st: *store.Store, seq: u64, epoch: u64, blob: []const u8, bucket: convert.Aux, skip: ?RsKey) !void {
    const idx = &env.idx;
    var outs: std.AutoHashMapUnmanaged(RsKey, void) = .empty;
    for (0..idx.tx_count) |i| {
        const t = idx.txAt(i);
        for (idx.objs[t.out_first..][0..t.out_count]) |r| try outs.put(a, try exec.objects.keyOf(r.slice(blob)), {});
    }
    var pre: std.AutoArrayHashMapUnmanaged(RsKey, []const u8) = .empty;
    for (0..idx.tx_count) |i| {
        const t = idx.txAt(i);
        for (idx.objs[t.in_first..][0..t.in_count]) |r| {
            const k = try exec.objects.keyOf(r.slice(blob));
            if (!outs.contains(k)) try pre.put(a, k, r.slice(blob));
        }
    }
    for (bucket.objects) |raw| {
        const k = try exec.objects.keyOf(raw);
        if (skip) |x| if (x.version == k.version and std.mem.eql(u8, &x.id, &k.id)) continue;
        if (!outs.contains(k)) try pre.put(a, k, raw);
    }
    const keys = try a.dupe(RsKey, pre.keys());
    std.mem.sort(RsKey, keys, {}, rsLess);
    const b = try st.begin(seq - 1, epoch);
    var live: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    for (keys) |k| {
        const raw = pre.get(k).?;
        const d = sync.verify.objectDigest(raw);
        // One pre-state version per id is live (the lowest); any other is only readable by version.
        if ((try live.getOrPut(a, k.id)).found_existing) try b.putHistorical(&k.id, k.version, &d, raw) else try b.putObject(&k.id, k.version, &d, raw);
    }
    var it = env.sys.pkgs.system.keyIterator();
    while (it.next()) |id| {
        if ((try live.getOrPut(a, id.*)).found_existing) continue;
        const raw = env.sys.pkgs.get(id, epoch) orelse continue;
        const v = try exec.objects.ObjectView.parse(raw);
        try b.putObject(id, v.version, &sync.verify.objectDigest(raw), raw);
    }
    // The packages a system transaction's commands name (a settlement's coin types): the system
    // executor reads them from the store, which on a node holds every package.
    var named: std.ArrayList([32]u8) = .empty;
    for (0..idx.tx_count) |i| {
        const td = try bcs.decode(types.TransactionData, a, idx.txAt(i).data.slice(blob));
        switch (td.V1.kind) {
            .ProgrammableSystemTransaction => |*pt| for (pt.commands) |*cmd| switch (cmd.*) {
                .MoveCall => |*mc| {
                    try named.append(a, mc.package.@"0".@"0");
                    for (mc.type_arguments) |*ty| try rsTypeIds(a, &named, ty);
                },
                else => {},
            },
            else => {},
        }
    }
    for (named.items) |*id| {
        if ((try live.getOrPut(a, id.*)).found_existing) continue;
        const raw = env.pkgs.file(id) orelse continue;
        const v = try exec.objects.ObjectView.parse(raw);
        try b.putObject(id, v.version, &sync.verify.objectDigest(raw), raw);
    }
    try st.commit(b);
}

fn rsTypeIds(a: std.mem.Allocator, out: *std.ArrayList([32]u8), t: *const types.TypeInput) std.mem.Allocator.Error!void {
    switch (t.*) {
        .vector => |e| try rsTypeIds(a, out, e),
        .@"struct" => |*st| {
            try out.append(a, st.address.@"0");
            for (st.type_args) |*x| try rsTypeIds(a, out, x);
        },
        else => {},
    }
}

/// The follower's apply of one checkpoint (sync/follower.zig `applyOne`, certificate aside) with
/// the node's read-set hook reading `<seq>.aux` from `aux_dir`.
fn rsApply(env: *RsEnv, a: std.mem.Allocator, st: *store.Store, seq: u64, blob: []const u8, aux_dir: Io.Dir) !void {
    return rsApplyOpts(env, a, st, seq, blob, aux_dir, null);
}

/// `rsApply` as the node does it when it reconciles p2p-built checkpoints: history marks a
/// checkpoint whose spool holds `<seq>.p2p`, and the reconciler's batch hook follows.
fn rsApplyOpts(env: *RsEnv, a: std.mem.Allocator, st: *store.Store, seq: u64, blob: []const u8, aux_dir: Io.Dir, rec: ?*reconcile.Reconciler) !void {
    const idx = &env.idx;
    try types.indexCheckpointData(blob, idx);
    const c = switch (try sync.verify.check(a, blob, idx)) {
        .ok => |c| c,
        .bad => return error.BadCheckpoint,
    };
    var h = try history.History.init(env.gpa, testing.io, aux_dir);
    defer h.deinit();
    h.mark_built = rec != null;
    const b = try st.begin(seq, c.epoch);
    try b.checkpoint(blob[idx.summary.o .. idx.sig.o + idx.sig.n], idx.contents.slice(blob));
    try b.checkpointDigest(&c.digest);
    for (c.txs, 0..) |plan, i| {
        const t = idx.txAt(i);
        try b.transaction(plan.tx_digest, &plan.effects_digest, t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |ev| ev.slice(blob) else null);
        for (plan.puts) |p| try b.putObject(p.id, p.version, &p.digest, idx.objs[p.index].slice(blob));
        for (plan.removes) |r| try b.removeObject(&r.id, r.version, if (r.kind == 1) .wrapped else .deleted);
    }
    try h.onBatch(st, seq, &c, blob, b);
    if (rec) |r| try r.applied(seq, h.last_built, b);
    try st.commit(b);
}

fn rsLoadedOf(_: *const anyopaque, snap: *const store.Snapshot, digest: *const [32]u8, at: u64) []const serve.objset.Ref {
    return history.loadedListNear(serve.objset.Ref, snap, digest, at);
}

fn rsMask(a: std.mem.Allocator, paths: []const []const u8) ![]const u8 {
    var m: std.ArrayList(u8) = .empty;
    for (paths) |p| try pbPutLen(a, &m, 1, p);
    return m.items;
}

const rs_cp_mask = [_][]const u8{ "sequence_number", "digest", "transactions.digest", "transactions.effects.unchanged_loaded_runtime_objects", "transactions.objects", "objects" };
/// The same without the per-transaction objects, whose `display` keeps a GetCheckpoint response
/// out of the response cache: this one is cached.
const rs_cp_mask_cached = [_][]const u8{ "sequence_number", "digest", "transactions.digest", "transactions.effects.unchanged_loaded_runtime_objects", "objects" };
const rs_tx_mask = [_][]const u8{ "digest", "effects.unchanged_loaded_runtime_objects", "objects" };

fn rsService(env: *RsEnv, st: *store.Store, seq: u64) serve.service.Service {
    return .{ .gpa = env.gpa, .store = st, .chain_id = @splat(0), .json = false, .display = false, .lowest_checkpoint = seq, .loaded = .{ .ctx = st, .get = rsLoadedOf } };
}

/// GetCheckpoint (objects and every transaction's unchanged loaded runtime objects) as response
/// message bytes.
fn rsGetCheckpoint(a: std.mem.Allocator, svc: *serve.service.Service, seq: u64, mask: []const []const u8) ![]const u8 {
    var req: std.ArrayList(u8) = .empty;
    try pbPutVarint(a, &req, 1 << 3);
    try pbPutVarint(a, &req, seq);
    try pbPutLen(a, &req, 3, try rsMask(a, mask));
    const cp = try serve.loopback.unary(a, svc.handler(), "/sui.rpc.v2.LedgerService/GetCheckpoint", req.items);
    if (cp.status != 0) {
        std.debug.print("GetCheckpoint {d}: grpc-status {d} {s}\n", .{ seq, cp.status, cp.grpc_message });
        return error.RenderFailed;
    }
    return cp.message;
}

/// BatchGetTransactions (the same per transaction) as response message bytes.
fn rsBatchGet(a: std.mem.Allocator, svc: *serve.service.Service, seq: u64, digests: []const [32]u8) ![]const u8 {
    var all: std.ArrayList(u8) = .empty;
    // BatchGetTransactions takes at most 200 digests a request.
    var i: usize = 0;
    while (i < digests.len) : (i += 200) {
        var breq: std.ArrayList(u8) = .empty;
        for (digests[i..@min(i + 200, digests.len)]) |*d| {
            var tb: [44]u8 = undefined;
            try pbPutLen(a, &breq, 1, serve.b58.encode32(&tb, d));
        }
        try pbPutLen(a, &breq, 2, try rsMask(a, &rs_tx_mask));
        const bt = try serve.loopback.unary(a, svc.handler(), "/sui.rpc.v2.LedgerService/BatchGetTransactions", breq.items);
        if (bt.status != 0) {
            std.debug.print("BatchGetTransactions {d}: grpc-status {d} {s}\n", .{ seq, bt.status, bt.grpc_message });
            return error.RenderFailed;
        }
        try all.appendSlice(a, bt.message);
    }
    return all.items;
}

/// Both answers from the store, each from a service of its own (nothing cached).
fn rsRender(env: *RsEnv, a: std.mem.Allocator, st: *store.Store, seq: u64, digests: []const [32]u8) ![2][]const u8 {
    var svc = rsService(env, st, seq);
    defer svc.deinit();
    return .{ try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask), try rsBatchGet(a, &svc, seq, digests) };
}

/// One corpus checkpoint as both paths take it (everything in the caller's arena). `env.idx`
/// is left indexing `blob`.
const RsCp = struct {
    seq: u64,
    epoch: u64,
    meta: RsMeta,
    /// The bucket's blob and aux record (`convert.protoToChkAux` of the archive proto).
    blob: []const u8,
    aux: []const u8,
    bucket: convert.Aux,
    digests: []const [32]u8,
    /// The archive proto (what the stream sends for the checkpoint).
    proto: []const u8,
    /// What a peer sends: the certificate, the contents, each transaction and its effects.
    cert: []const u8,
    contents: []const u8,
    txs: []const p2p_exec.ExecData,
};

fn rsLoad(env: *RsEnv, a: std.mem.Allocator, seq: u64) !RsCp {
    const gpa = env.gpa;
    var pb: [96]u8 = undefined;
    // The archive proto: the dense window, or (exploration) the corpus's older protos.
    const z = for ([_][]const u8{ "binpb-done", "binpb-hist", "binpb-r4", "binpb-exec" }) |dir| {
        break readCorpus(gpa, try std.fmt.bufPrint(&pb, "{s}/{d}.binpb.zst", .{ dir, seq })) catch continue;
    } else return error.SkipZigTest;
    defer gpa.free(z);
    const proto = try convert.unzstd(gpa, z, 1 << 30);
    defer gpa.free(proto);
    var blob_b: std.ArrayList(u8) = .empty;
    defer blob_b.deinit(gpa);
    var aux_b: std.ArrayList(u8) = .empty;
    defer aux_b.deinit(gpa);
    try testing.expectEqual(seq, try convert.protoToChkAux(gpa, a, proto, &blob_b, &aux_b));
    const blob = try a.dupe(u8, blob_b.items);
    const aux = try a.dupe(u8, aux_b.items);
    const idx = &env.idx;
    try types.indexCheckpointData(blob, idx);
    var sr = bcs.Reader.init(idx.summary.slice(blob));
    const epoch = try sr.int(u64);
    const m = for (env.metas) |x| {
        if (x.epoch == epoch) break x;
    } else return error.SkipZigTest;
    const n = idx.tx_count;
    const txs = try a.alloc(p2p_exec.ExecData, n);
    const digests = try a.alloc([32]u8, n);
    for (txs, digests, 0..) |*t, *d, i| {
        const x = idx.txAt(i);
        t.* = .{ .tx = x.transaction.slice(blob), .effects = x.effects.slice(blob) };
        d.* = types.digest.transactionDataDigest(x.data.slice(blob));
    }
    return .{
        .seq = seq,
        .epoch = epoch,
        .meta = m,
        .blob = blob,
        .aux = aux,
        .bucket = try convert.Aux.parse(a, aux),
        .proto = try a.dupe(u8, proto),
        .digests = digests,
        .cert = blob[idx.summary.o .. idx.sig.o + idx.sig.n],
        .contents = idx.contents.slice(blob),
        .txs = txs,
    };
}

/// The p2p build of `cp` on a store as of the checkpoint before it (in `dir`, removed after), in
/// order and, with `env.pool`, on the exec threads (the same bytes). Returns its aux record;
/// null: it fell back.
fn rsBuild(env: *RsEnv, a: std.mem.Allocator, cp: *const RsCp, dir: []const u8) !?[]const u8 {
    defer env.tmp.dir.deleteTree(testing.io, dir) catch {};
    const h = try rsStore(env, a, dir);
    defer h.io.deinit();
    defer h.store.deinit();
    try types.indexCheckpointData(cp.blob, &env.idx);
    try rsSeed(env, a, h.store, cp.seq, cp.epoch, cp.blob, cp.bucket);
    var snap = h.store.snapshot();
    defer snap.release();
    const params: p2p_exec.Params = .{ .pv = cp.meta.pv.?, .rgp = cp.meta.rgp.?, .start_ms = cp.meta.start_ms.? };
    const serial = switch (try p2p_exec.run(rs_exec_gpa, a, &snap, env.ps, params, cp.epoch, cp.cert, cp.contents, cp.txs, &env.stats, null, null)) {
        .ok => |o| o,
        .fallback => |why| {
            if (env.diag) std.debug.print("p2p read sets: checkpoint {d} fell back: {s}\n", .{ cp.seq, why });
            return null;
        },
    };
    try testing.expectEqualSlices(u8, cp.blob, serial.blob);
    if (env.pool) |pl| switch (try p2p_exec.run(rs_exec_gpa, a, &snap, env.ps, params, cp.epoch, cp.cert, cp.contents, cp.txs, &env.stats, null, pl)) {
        .ok => |o| {
            try testing.expectEqualSlices(u8, serial.blob, o.blob);
            try testing.expectEqualSlices(u8, serial.aux, o.aux);
        },
        .fallback => |why| {
            std.debug.print("p2p read sets: checkpoint {d}: the level-parallel build fell back: {s}\n", .{ cp.seq, why });
            return error.ParallelFellBack;
        },
    };
    return serial.aux;
}

/// One corpus checkpoint through both paths. False: the p2p build fell back (nothing compared).
fn rsOne(env: *RsEnv, seq: u64) !bool {
    const gpa = env.gpa;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var pb: [96]u8 = undefined;
    const cp = try rsLoad(env, a, seq);
    const blob = cp.blob;
    const bucket = cp.bucket;
    const idx = &env.idx;
    const epoch = cp.epoch;
    const digests = cp.digests;
    const n = digests.len;
    const names = [3][]const u8{ try std.fmt.allocPrint(a, "{d}-pre", .{seq}), try std.fmt.allocPrint(a, "{d}-bucket", .{seq}), try std.fmt.allocPrint(a, "{d}-p2p", .{seq}) };
    defer for (names) |nm| env.tmp.dir.deleteTree(testing.io, nm) catch {};
    // ---- the p2p build: local execution on the store as of the previous checkpoint
    const built_aux = (try rsBuild(env, a, &cp, names[0])) orelse {
        env.fallbacks += 1;
        return false;
    };
    env.built += 1;
    const p2p = try convert.Aux.parse(a, built_aux);
    try testing.expectEqual(n, p2p.loaded.len);

    // The rule for implicit system object reads against the archive: a read-only root entry of
    // the accumulator root or the Clock that the transaction does not declare is in sui-node's
    // list at that version.
    for (bucket.loaded, 0..) |want, i| {
        const x = idx.txAt(i);
        const td = try bcs.decode(types.TransactionData, a, x.data.slice(blob));
        const fx = switch (try bcs.decode(types.TransactionEffects, a, x.effects.slice(blob))) {
            .V2 => |v| v,
            .V1 => continue,
        };
        for (try p2p_exec.implicitReads(a, &td.V1, &fx)) |r| {
            env.implicit_reads += 1;
            if (env.diag) std.debug.print("p2p read sets: checkpoint {d} tx {d}: implicit read of {x} v{d}\n", .{ seq, i, &r.id, r.version });
            const listed = for (want) |w| {
                if (w.version == r.version and std.mem.eql(u8, &w.id, &r.id)) break true;
            } else false;
            if (!listed) {
                std.debug.print("p2p read sets: checkpoint {d} tx {d}: implicit read of {x} v{d} is not in the bucket's list\n", .{ seq, i, &r.id, r.version });
                return error.ImplicitReadNotListed;
            }
        }
    }

    // ---- the aux records: each transaction's loaded runtime objects, and the extra objects
    var oset = try serve.objset.ObjSet.build(a, bucket.objects);
    for (bucket.loaded, p2p.loaded, 0..) |want, got, i| {
        if (want.len > 0) {
            env.loaded_txs += 1;
            env.loaded_refs += want.len;
        }
        for (want) |w| {
            env.seen_count_field += @intFromBool(std.mem.eql(u8, &w.id, &rs_count_field));
            env.seen_usdc_config += @intFromBool(std.mem.eql(u8, &w.id, &rs_usdc_config));
        }
        var same = want.len == got.len;
        if (same) for (want, got) |w, g| {
            if (w.version != g.version or !std.mem.eql(u8, &w.id, &g.id)) same = false;
        };
        if (same) continue;
        env.list_diffs += 1;
        if (!env.diag) continue;
        const td = try bcs.decode(types.TransactionData, a, idx.txAt(i).data.slice(blob));
        std.debug.print("p2p read sets: checkpoint {d} tx {d} ({s}): bucket {d} loaded, p2p {d}\n", .{ seq, i, @tagName(td.V1.kind), want.len, got.len });
        for (want, 0..) |w, j| {
            const at = for (got, 0..) |g, k| {
                if (g.version == w.version and std.mem.eql(u8, &g.id, &w.id)) break k;
            } else null;
            if (at) |k| {
                if (k != j) std.debug.print("    order   {x} v{d}: bucket #{d}, p2p #{d}\n", .{ &w.id, w.version, j, k });
                continue;
            }
            std.debug.print("    missing {x} v{d}: {s}\n", .{ &w.id, w.version, (oset.typeString(a, &w.id, w.version) catch null) orelse "?" });
        }
        for (got) |g| {
            const found = for (want) |w| {
                if (g.version == w.version and std.mem.eql(u8, &g.id, &w.id)) break true;
            } else false;
            if (!found) std.debug.print("    extra   {x} v{d}\n", .{ &g.id, g.version });
        }
    }
    {
        var want: std.AutoHashMapUnmanaged(RsKey, []const u8) = .empty;
        for (bucket.objects) |raw| try want.put(a, try exec.objects.keyOf(raw), raw);
        var got: std.AutoHashMapUnmanaged(RsKey, []const u8) = .empty;
        for (p2p.objects) |raw| try got.put(a, try exec.objects.keyOf(raw), raw);
        var differs = want.count() != got.count();
        var wi = want.iterator();
        while (wi.next()) |e| {
            if (got.get(e.key_ptr.*)) |raw| {
                if (std.mem.eql(u8, raw, e.value_ptr.*)) continue;
            }
            differs = true;
            if (env.diag) std.debug.print("p2p read sets: checkpoint {d}: object {x} v{d} in the bucket's aux only: {s}\n", .{ seq, &e.key_ptr.id, e.key_ptr.version, (oset.typeString(a, &e.key_ptr.id, e.key_ptr.version) catch null) orelse "?" });
        }
        var gi = got.iterator();
        while (gi.next()) |e| if (!want.contains(e.key_ptr.*)) {
            differs = true;
            if (env.diag) std.debug.print("p2p read sets: checkpoint {d}: object {x} v{d} in the p2p aux only\n", .{ seq, &e.key_ptr.id, e.key_ptr.version });
        };
        if (differs) env.extra_diffs += 1;
    }

    // ---- stored and served: the same checkpoint applied with each aux record
    var rendered: [2][2][]const u8 = undefined;
    var lists: [2][]const []const u8 = undefined;
    var objs: [2][]const ?[]const u8 = undefined;
    for ([2][]const u8{ cp.aux, built_aux }, 0..) |aux_bytes, side| {
        const h = try rsStore(env, a, names[1 + side]);
        defer h.io.deinit();
        defer h.store.deinit();
        try types.indexCheckpointData(blob, idx);
        try rsSeed(env, a, h.store, seq, epoch, blob, bucket);
        try env.tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&pb, "{d}.aux", .{seq}), .data = aux_bytes });
        try rsApply(env, a, h.store, seq, blob, env.tmp.dir);
        var snap = h.store.snapshot();
        defer snap.release();
        const ll = try a.alloc([]const u8, n);
        var os: std.ArrayList(?[]const u8) = .empty;
        for (ll, digests, 0..) |*l, *d, i| {
            const refs = history.loadedList(serve.objset.Ref, &snap, d);
            l.* = try a.dupe(u8, std.mem.sliceAsBytes(refs));
            const x = idx.txAt(i);
            const td = try bcs.decode(types.TransactionData, a, x.data.slice(blob));
            const fx = try bcs.decode(types.TransactionEffects, a, x.effects.slice(blob));
            // The transaction's object set by the bucket's list: every version must be stored.
            const want_refs = try a.alloc(serve.objset.Ref, bucket.loaded[i].len);
            for (bucket.loaded[i], want_refs) |w, *r| r.* = .{ .id = w.id, .version = w.version };
            for (try serve.txobjects.keys(a, td, fx, want_refs)) |k| {
                try os.append(a, if (snap.objectAt(&k.id, k.version)) |raw| try a.dupe(u8, raw) else null);
            }
        }
        lists[side] = ll;
        objs[side] = os.items;
        rendered[side] = try rsRender(env, a, h.store, seq, digests);
    }
    var stored_same = objs[0].len == objs[1].len;
    for (lists[0], lists[1]) |x, y| {
        if (!std.mem.eql(u8, x, y)) stored_same = false;
    }
    if (stored_same) for (objs[0], objs[1]) |x, y| {
        if (x == null or y == null or !std.mem.eql(u8, x.?, y.?)) stored_same = false;
    };
    if (!stored_same) env.store_diffs += 1;
    for (rendered[0], rendered[1], [2][]const u8{ "GetCheckpoint", "BatchGetTransactions" }) |x, y, what| {
        if (std.mem.eql(u8, x, y)) continue;
        env.render_diffs += 1;
        if (env.diag) std.debug.print("p2p read sets: checkpoint {d}: {s} differs: bucket {d} bytes, p2p {d} bytes\n", .{ seq, what, x.len, y.len });
    }
    return true;
}

test "p2p: unchanged loaded runtime objects are one per id at the highest version read, without the effects' object changes, in id order" {
    // sui-core transaction_outputs.rs `unchanged_loaded_runtime_objects`.
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const T = struct {
        fn id(b: u8) types.ObjectID {
            return .{ .@"0" = .{ .@"0" = @splat(b) } };
        }
        fn ref(b: u8, v: u64) exec.ptb.Ref {
            return .{ .id = @splat(b), .version = v };
        }
        fn oref(b: u8, v: u64) struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest } {
            return .{ id(b), .{ .@"0" = v }, .{ .@"0" = .{ .@"0" = @splat(0) } } };
        }
    };
    const dz: types.ObjectDigest = .{ .@"0" = .{ .@"0" = @splat(0) } };
    const owner: types.Owner = .{ .AddressOwner = .{ .@"0" = @splat(7) } };
    const gas: types.GasCostSummary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 };
    // Read in execution order: 0x50, 0x10 twice (two versions), 0x30 (mutated), 0x20 (only named
    // by an accumulator write, which is not an object change), 0x40 (deleted), 0x10 again.
    const loads = [_]exec.ptb.Ref{ T.ref(0x50, 9), T.ref(0x10, 4), T.ref(0x30, 5), T.ref(0x20, 6), T.ref(0x40, 7), T.ref(0x10, 8), T.ref(0x10, 4) };
    const fx: types.TransactionEffectsV2 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = gas,
        .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 10 },
        .changed_objects = &.{
            .{ T.id(0x30), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 5 }, dz }, owner } }, .output_state = .{ .ObjectWrite = .{ dz, owner } }, .id_operation = .None } },
            .{ T.id(0x20), .{ .input_state = .NotExist, .output_state = .{ .AccumulatorWriteV1 = .{ .address = .{ .address = .{ .@"0" = @splat(7) }, .ty = .u64 }, .operation = .Merge, .value = .{ .Integer = 1 } } }, .id_operation = .None } },
            .{ T.id(0x40), .{ .input_state = .{ .Exist = .{ .{ .{ .@"0" = 7 }, dz }, owner } }, .output_state = .NotExist, .id_operation = .Deleted } },
        },
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    };
    const got = try p2p_exec.unchangedLoaded(a, &loads, &fx, null);
    try testing.expectEqualSlices(exec.ptb.Ref, &.{ T.ref(0x10, 8), T.ref(0x20, 6), T.ref(0x50, 9) }, got);
    // V1 effects: created, mutated, unwrapped, deleted, unwrapped_then_deleted and wrapped are the
    // object changes (`fx` is then only the driver's view and is not consulted).
    const v1: types.TransactionEffectsV1 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = gas,
        .modified_at_versions = &.{},
        .shared_objects = &.{},
        .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .created = &.{},
        .mutated = &.{.{ T.oref(0x30, 10), owner }},
        .unwrapped = &.{},
        .deleted = &.{},
        .unwrapped_then_deleted = &.{T.oref(0x50, 10)},
        .wrapped = &.{T.oref(0x40, 10)},
        .gas_object = .{ T.oref(0x30, 10), owner },
        .events_digest = null,
        .dependencies = &.{},
    };
    const got1 = try p2p_exec.unchangedLoaded(a, &loads, &fx, &v1);
    try testing.expectEqualSlices(exec.ptb.Ref, &.{ T.ref(0x10, 8), T.ref(0x20, 6) }, got1);
    try testing.expectEqual(@as(usize, 0), (try p2p_exec.unchangedLoaded(a, &.{}, &fx, null)).len);
}

test "p2p: an undeclared read-only root entry of the accumulator root or the Clock is an implicit store read" {
    // TemporaryStore::load_implicitly_read_system_object goes through the tracking store; the
    // effects list the read as a read-only consensus object (loaded_system_objects).
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const T = struct {
        fn sys(lo: u16) [32]u8 {
            var id: [32]u8 = @splat(0);
            id[30] = @intCast(lo >> 8);
            id[31] = @intCast(lo & 0xff);
            return id;
        }
        fn oid(b: [32]u8) types.ObjectID {
            return .{ .@"0" = .{ .@"0" = b } };
        }
        fn shared(b: [32]u8) types.CallArg {
            return .{ .Object = .{ .SharedObject = .{ .id = oid(b), .initial_shared_version = .{ .@"0" = 1 }, .mutability = .Immutable } } };
        }
        fn data(inputs: []const types.CallArg) types.TransactionDataV1 {
            return .{
                .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = &.{} } },
                .sender = .{ .@"0" = @splat(7) },
                .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = @splat(7) }, .price = 1, .budget = 1 },
                .expiration = .None,
            };
        }
    };
    const dz: types.ObjectDigest = .{ .@"0" = .{ .@"0" = @splat(0) } };
    const root = T.sys(0x0acc);
    const clock = T.sys(6);
    const other: [32]u8 = @splat(0x44);
    const fx: types.TransactionEffectsV2 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 10 },
        .changed_objects = &.{},
        .unchanged_consensus_objects = &.{
            .{ T.oid(clock), .{ .ReadOnlyRoot = .{ .{ .@"0" = 31 }, dz } } },
            .{ T.oid(other), .{ .ReadOnlyRoot = .{ .{ .@"0" = 32 }, dz } } },
            .{ T.oid(T.sys(0x0403)), .PerEpochConfig },
            .{ T.oid(root), .{ .ReadOnlyRoot = .{ .{ .@"0" = 33 }, dz } } },
        },
        .aux_data_digest = null,
    };
    // Clock and another shared object declared, the accumulator root not: one implicit read.
    const declared = [_]types.CallArg{ .{ .Pure = "x" }, T.shared(clock), T.shared(other) };
    const d1 = T.data(&declared);
    try testing.expectEqualSlices(exec.ptb.Ref, &.{.{ .id = root, .version = 33 }}, try p2p_exec.implicitReads(a, &d1, &fx));
    // Nothing declared: both system objects were read implicitly; the other object never is.
    const d2 = T.data(&.{});
    try testing.expectEqualSlices(exec.ptb.Ref, &.{ .{ .id = clock, .version = 31 }, .{ .id = root, .version = 33 } }, try p2p_exec.implicitReads(a, &d2, &fx));
    // Both declared: none.
    const both = [_]types.CallArg{ T.shared(root), T.shared(clock) };
    const d3 = T.data(&both);
    try testing.expectEqual(@as(usize, 0), (try p2p_exec.implicitReads(a, &d3, &fx)).len);
}

const RsOut = struct { built: u64 = 0, fallbacks: u64 = 0, list_diffs: u64 = 0, extra_diffs: u64 = 0, store_diffs: u64 = 0, render_diffs: u64 = 0, loaded_txs: u64 = 0, loaded_refs: u64 = 0, implicit_reads: u64 = 0, seen_count_field: u64 = 0, seen_usdc_config: u64 = 0 };

/// Runs `body(ctx, env)` with the corpus environment (system packages of every epoch, the
/// corpus packages behind a p2p package source, the exec threads) on a thread of its own: exec's
/// per-thread package caches are keyed by the packages store's address, and the Move VM wants
/// the stack the p2p exec threads have.
fn rsWith(ctx: anytype, comptime body: fn (@TypeOf(ctx), *RsEnv) anyerror!void) !void {
    const Ctx = @TypeOf(ctx);
    const T = struct {
        fn run(c: Ctx, r: *?anyerror) void {
            setup(c) catch |e| {
                r.* = e;
            };
        }
        fn setup(cx: Ctx) !void {
            const gpa = testing.allocator;
            const c = corpus() orelse return error.SkipZigTest;
            var arena: std.heap.ArenaAllocator = .init(gpa);
            defer arena.deinit();
            const a = arena.allocator();
            var tmp = testing.tmpDir(.{});
            defer tmp.cleanup();
            var pb: [std.fs.max_path_bytes]u8 = undefined;
            const base = try a.dupe(u8, pb[0..try tmp.dir.realPath(testing.io, &pb)]);
            const text = try readCorpus(gpa, "epochs.jsonl");
            defer gpa.free(text);
            var metas: std.ArrayList(RsMeta) = .empty;
            var it = std.mem.splitScalar(u8, text, '\n');
            while (it.next()) |line| if (line.len > 0) {
                try metas.append(a, try std.json.parseFromSliceLeaky(RsMeta, a, line, .{ .ignore_unknown_fields = true }));
            };
            const pkg_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/packages", .{c}), .{}) catch return error.SkipZigTest;
            defer pkg_dir.close(testing.io);
            const chk_dir = Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/chk", .{c}), .{}) catch return error.SkipZigTest;
            defer chk_dir.close(testing.io);
            const eidx = try trust.EpochIndex.load(a, testing.io, try std.fmt.bufPrint(&pb, "{s}/epochs.jsonl", .{c}));

            var env: RsEnv = .{ .gpa = gpa, .base = base, .tmp = &tmp, .metas = metas.items, .ps = undefined, .pkgs = undefined, .sys = undefined, .idx = try types.CheckpointIndex.init(gpa) };
            defer env.idx.deinit(gpa);
            // System packages of every epoch (the executor's loader; its store is not used).
            const sh = try rsStore(&env, a, "sys");
            defer sh.io.deinit();
            defer sh.store.deinit();
            var sys = try execute.Executor.init(gpa, testing.io, sh.store, null);
            defer sys.deinit();
            try testing.expect(sys.seedSystemPackages(chk_dir, eidx.last, eidx.last.len) > 0);
            env.sys = &sys;
            var ps: p2p_exec.PackageSource = .{ .keep = .init(gpa) };
            defer ps.deinit();
            ps.bind();
            var corpus_pkgs: RsPkgs = .{ .inner = ps.pkgs.lookup.?, .dir = pkg_dir, .keep = a };
            ps.pkgs.lookup = .{ .ctx = &corpus_pkgs, .get = RsPkgs.get };
            env.ps = &ps;
            env.pkgs = &corpus_pkgs;
            defer exec.ptb.pkgs.releaseThreadCaches();
            defer exec.system.movecall.releaseThreadCaches();
            var pool: p2p_exec.Pool = .{ .gpa = gpa, .io = testing.io };
            try pool.start(4);
            defer pool.stop();
            env.pool = &pool;
            try body(cx, &env);
        }
    };
    var res: ?anyerror = null;
    const t = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, T.run, .{ ctx, &res });
    t.join();
    if (res) |e| return e;
}

/// The stored-layout bytes of a loaded list (`history.entry_len` per entry).
fn rsListBytes(a: std.mem.Allocator, list: []const convert.LoadedRef) ![]u8 {
    const out = try a.alloc(u8, list.len * history.entry_len);
    for (list, 0..) |r, j| {
        std.mem.writeInt(u64, out[j * history.entry_len ..][0..8], r.version, .little);
        out[j * history.entry_len + 8 ..][0..32].* = r.id;
    }
    return out;
}

/// The bucket path's store of `cp` in `dir`: seeded, then applied with the bucket's aux record.
fn rsBucketStore(env: *RsEnv, a: std.mem.Allocator, cp: *const RsCp, dir: []const u8) !RsStore {
    const h = try rsStore(env, a, dir);
    errdefer {
        h.store.deinit();
        h.io.deinit();
    }
    try types.indexCheckpointData(cp.blob, &env.idx);
    try rsSeed(env, a, h.store, cp.seq, cp.epoch, cp.blob, cp.bucket);
    var nb: [48]u8 = undefined;
    try env.tmp.dir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.aux", .{cp.seq}), .data = cp.aux });
    try rsApply(env, a, h.store, cp.seq, cp.blob, env.tmp.dir);
    return h;
}

fn rsListFixBody(_: void, env: *RsEnv) anyerror!void {
    var arena: std.heap.ArenaAllocator = .init(env.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 342451165;
    const cp = try rsLoad(env, a, seq);
    const h = try rsBucketStore(env, a, &cp, "listfix");
    defer h.io.deinit();
    defer h.store.deinit();
    const st = h.store;
    var svc = rsService(env, st, seq);
    defer svc.deinit();
    const r1 = try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached);
    const b1 = try rsBatchGet(a, &svc, seq, cp.digests);
    // The second call is the cached response.
    try testing.expect(svc.cp_cache.bytesHeld() > 0);
    try testing.expectEqualSlices(u8, r1, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));

    // A transaction with two or more loaded objects: its list in another order is the fix.
    const i = for (cp.bucket.loaded, 0..) |l, k| {
        if (l.len >= 2) break k;
    } else return error.SkipZigTest;
    const good = try rsListBytes(a, cp.bucket.loaded[i]);
    const reversed = try a.alloc(convert.LoadedRef, cp.bucket.loaded[i].len);
    for (reversed, 0..) |*r, k| r.* = cp.bucket.loaded[i][reversed.len - 1 - k];
    const wrong = try rsListBytes(a, reversed);
    const d = &cp.digests[i];
    try testing.expect(try st.list_fix.put(seq, d, wrong));
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expectEqualSlices(u8, wrong, std.mem.sliceAsBytes(history.loadedList(serve.objset.Ref, &snap, d)));
        const rec = snap.transaction(d).?;
        try testing.expectEqualSlices(u8, wrong, std.mem.sliceAsBytes(history.loadedListNear(serve.objset.Ref, &snap, d, rec.loc)));
        // Other transactions read their stored records.
        for (cp.bucket.loaded, cp.digests, 0..) |l, *od, k| {
            if (k != i) try testing.expectEqualSlices(u8, try rsListBytes(a, l), std.mem.sliceAsBytes(history.loadedList(serve.objset.Ref, &snap, od)));
        }
    }
    // The cached response is stale: both answers are rendered again, with the installed list.
    const r2 = try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached);
    try testing.expect(!std.mem.eql(u8, r1, r2));
    try testing.expect(!std.mem.eql(u8, b1, try rsBatchGet(a, &svc, seq, cp.digests)));
    {
        var uncached = rsService(env, st, seq);
        defer uncached.deinit();
        try testing.expectEqualSlices(u8, try rsGetCheckpoint(a, &uncached, seq, &rs_cp_mask_cached), r2);
    }
    // A later fix replaces the earlier one (here: back to sui-node's list), again for every read.
    try testing.expect(try st.list_fix.put(seq, d, good));
    try testing.expectEqualSlices(u8, r1, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqualSlices(u8, b1, try rsBatchGet(a, &svc, seq, cp.digests));
    // An empty list is a fix as well.
    try testing.expect(try st.list_fix.put(seq, d, &.{}));
    var snap = st.snapshot();
    defer snap.release();
    try testing.expectEqual(@as(usize, 0), history.loadedList(serve.objset.Ref, &snap, d).len);
}

test "history: a loaded list installed in the store's list table replaces the stored record for every read and stales the cached GetCheckpoint response" {
    try rsWith({}, rsListFixBody);
}

const RsRun = struct { seqs: []const u64, diag: bool, out: *RsOut };

fn rsRunBody(r: RsRun, env: *RsEnv) anyerror!void {
    env.diag = r.diag;
    for (r.seqs) |seq| _ = rsOne(env, seq) catch |e| switch (e) {
        error.SkipZigTest => return e,
        else => {
            std.debug.print("p2p read sets: checkpoint {d}: {s}\n", .{ seq, @errorName(e) });
            return e;
        },
    };
    r.out.* = .{ .built = env.built, .fallbacks = env.fallbacks, .list_diffs = env.list_diffs, .extra_diffs = env.extra_diffs, .store_diffs = env.store_diffs, .render_diffs = env.render_diffs, .loaded_txs = env.loaded_txs, .loaded_refs = env.loaded_refs, .implicit_reads = env.implicit_reads, .seen_count_field = env.seen_count_field, .seen_usdc_config = env.seen_usdc_config };
}

fn rsOnThread(seqs: []const u64, diag: bool, out: *RsOut) !void {
    return rsWith(RsRun{ .seqs = seqs, .diag = diag, .out = out }, rsRunBody);
}

test "p2p: a checkpoint built by local execution stores and serves the same read sets as the bucket's" {
    const gpa = testing.allocator;
    var seqs: std.ArrayList(u64) = .empty;
    defer seqs.deinit(gpa);
    var diag = false;
    if (std.c.getenv("ZUI_P2P_READSETS")) |r| {
        // Exploration: ZUI_P2P_READSETS=FROM-TO[,SEQ,...] prints every difference over those
        // checkpoints.
        var parts = std.mem.tokenizeScalar(u8, std.mem.span(r), ',');
        while (parts.next()) |text| {
            const dash = std.mem.indexOfScalar(u8, text, '-') orelse text.len;
            var s = try std.fmt.parseInt(u64, text[0..dash], 10);
            const to = if (dash == text.len) s else try std.fmt.parseInt(u64, text[dash + 1 ..], 10);
            while (s <= to) : (s += 1) try seqs.append(gpa, s);
        }
        diag = true;
    } else {
        // The end of epoch 1303 (342451160: the epoch change and its system state reads) and the
        // start of 1304: Move calls with dynamic-field reads and read-only shared inputs,
        // regulated-coin transfers (coin deny list reads) and a settlement in every checkpoint.
        var s: u64 = 342451158;
        while (s < 342451170) : (s += 1) try seqs.append(gpa, s);
        // Transaction 29 checks an object's funds: the accumulator root is read implicitly.
        try seqs.append(gpa, 342453625);
    }
    var out: RsOut = .{};
    try rsOnThread(seqs.items, diag, &out);
    std.debug.print("p2p read sets: {d} checkpoints built, {d} fell back; {d} transactions with loaded objects ({d} refs: {d} implicit system object reads, {d} of the accumulator object count field, {d} of the USDC deny list config); differences: {d} lists, {d} extra-object sets, {d} stores, {d} renders\n", .{ out.built, out.fallbacks, out.loaded_txs, out.loaded_refs, out.implicit_reads, out.seen_count_field, out.seen_usdc_config, out.list_diffs, out.extra_diffs, out.store_diffs, out.render_diffs });
    try testing.expectEqual(@as(u64, 0), out.fallbacks);
    try testing.expect(out.loaded_refs > 0);
    if (!diag) {
        // The fixed set holds what the production shadow saw missing, and an implicit read.
        try testing.expect(out.seen_count_field > 0);
        try testing.expect(out.seen_usdc_config > 0);
        try testing.expect(out.implicit_reads > 0);
    }
    try testing.expectEqual(@as(u64, 0), out.list_diffs);
    try testing.expectEqual(@as(u64, 0), out.extra_diffs);
    try testing.expectEqual(@as(u64, 0), out.store_diffs);
    try testing.expectEqual(@as(u64, 0), out.render_diffs);
}

// ------------------------------------------------------------------ p2p: read-set reconcile

test "source: a checkpoint built here is spooled with its .p2p mark, removed with the blob" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const src: source_mod.Source = .{ .gpa = testing.allocator, .io = testing.io, .kind = .none };
    var applied: std.atomic.Value(u64) = .init(100);
    var f: source_mod.Fetcher = .{ .gpa = testing.allocator, .io = testing.io, .source = &src, .spool = tmp.dir, .next = .init(100), .applied_next = &applied, .window = 64, .poll_ms = 25, .to = std.math.maxInt(u64) };
    try f.writeSpoolBuilt(100, "blob", "aux");
    try f.writeSpool(101, "blob", "aux");
    _ = try tmp.dir.statFile(testing.io, "100.p2p", .{});
    _ = try tmp.dir.statFile(testing.io, "100.chk", .{});
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, "101.p2p", .{}));
    f.clean(100, 102);
    inline for (.{ "100.p2p", "100.chk", "100.aux", "101.chk" }) |name| try testing.expectError(error.FileNotFound, tmp.dir.statFile(testing.io, name, .{}));
}

/// An aux record (`convert.Aux` layout) of the given lists and extra objects.
fn rsAuxBytes(a: std.mem.Allocator, loaded: []const []const convert.LoadedRef, objects: []const []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, convert.aux_magic);
    try pbPutVarint(a, &out, loaded.len);
    for (loaded) |l| {
        try pbPutVarint(a, &out, l.len);
        for (l) |r| {
            try out.appendSlice(a, &r.id);
            var vb: [8]u8 = undefined;
            std.mem.writeInt(u64, &vb, r.version, .little);
            try out.appendSlice(a, &vb);
            if (r.digest) |d| {
                try out.append(a, 1);
                try out.appendSlice(a, &d);
            } else try out.append(a, 0);
        }
    }
    try pbPutVarint(a, &out, objects.len);
    for (objects) |raw| {
        try pbPutVarint(a, &out, raw.len);
        try out.appendSlice(a, raw);
    }
    return out.items;
}

/// A store as a node following with --p2p leaves it: the reconciler opened on the store as of
/// the checkpoint before `cp`, then `cp` applied from a spool that holds a p2p build's aux
/// record and its `.p2p` mark.
const RsNode = struct {
    env: *RsEnv,
    dir: []const u8,
    h: RsStore,
    rec: *reconcile.Reconciler,
    node_dir: Io.Dir,
    spool: Io.Dir,
    bucket: ?*const source_mod.Source,

    fn init(env: *RsEnv, a: std.mem.Allocator, cp: *const RsCp, dir: []const u8, aux: []const u8, skip: ?RsKey, bucket: ?*const source_mod.Source, cfg: reconcile.Config) !RsNode {
        const h = try rsStore(env, a, dir);
        errdefer {
            h.store.deinit();
            h.io.deinit();
        }
        try types.indexCheckpointData(cp.blob, &env.idx);
        try rsSeedWithout(env, a, h.store, cp.seq, cp.epoch, cp.blob, cp.bucket, skip);
        const node_name = try std.fmt.allocPrint(a, "{s}-node", .{dir});
        const spool_name = try std.fmt.allocPrint(a, "{s}-spool", .{dir});
        try env.tmp.dir.createDir(testing.io, node_name, .default_dir);
        try env.tmp.dir.createDir(testing.io, spool_name, .default_dir);
        const node_dir = try env.tmp.dir.openDir(testing.io, node_name, .{});
        const spool = try env.tmp.dir.openDir(testing.io, spool_name, .{});
        const rec = try reconcile.Reconciler.open(env.gpa, testing.io, h.store, node_dir, bucket, cfg);
        errdefer rec.deinit();
        var nb: [48]u8 = undefined;
        try spool.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.aux", .{cp.seq}), .data = aux });
        try spool.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.p2p", .{cp.seq}), .data = "" });
        try rsApplyOpts(env, a, h.store, cp.seq, cp.blob, spool, rec);
        var snap = h.store.snapshot();
        defer snap.release();
        try testing.expect(history.p2pBuilt(&snap, cp.seq));
        try testing.expect(!history.p2pBuilt(&snap, cp.seq - 1));
        try testing.expect(rec.isWaiting(cp.seq));
        return .{ .env = env, .dir = dir, .h = h, .rec = rec, .node_dir = node_dir, .spool = spool, .bucket = bucket };
    }

    /// The process ends (nothing is settled or marked on the way out beyond what `deinit`
    /// writes, which is nothing while no checkpoint settled) and starts again on the same dirs.
    fn restart(n: *RsNode, a: std.mem.Allocator, cfg: reconcile.Config) !void {
        n.rec.deinit();
        n.h.store.deinit();
        n.h.io.deinit();
        n.h = try rsStore(n.env, a, n.dir);
        n.rec = try reconcile.Reconciler.open(n.env.gpa, testing.io, n.h.store, n.node_dir, n.bucket, cfg);
    }

    fn deinit(n: *RsNode) void {
        n.rec.deinit();
        n.node_dir.close(testing.io);
        n.spool.close(testing.io);
        n.h.store.deinit();
        n.h.io.deinit();
    }

    /// Every transaction's stored list, as the readers get it.
    fn lists(n: *RsNode, a: std.mem.Allocator, cp: *const RsCp) ![]const []const u8 {
        var snap = n.h.store.snapshot();
        defer snap.release();
        const out = try a.alloc([]const u8, cp.digests.len);
        for (out, cp.digests) |*l, *d| l.* = try a.dupe(u8, std.mem.sliceAsBytes(history.loadedList(serve.objset.Ref, &snap, d)));
        return out;
    }
};

/// sui-node's lists of `cp` in the stored layout.
fn rsWantLists(a: std.mem.Allocator, cp: *const RsCp) ![]const []const u8 {
    const out = try a.alloc([]const u8, cp.digests.len);
    for (out, cp.bucket.loaded) |*l, refs| l.* = try rsListBytes(a, refs);
    return out;
}

fn rsSameLists(x: []const []const u8, y: []const []const u8) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!std.mem.eql(u8, p, q)) return false;
    return true;
}

/// The live stream's message for `cp`, after another source delivered it: a duplicate there.
fn rsStreamDuplicate(env: *RsEnv, rec: *reconcile.Reconciler, cp: *const RsCp) !void {
    const src: source_mod.Source = .{ .gpa = env.gpa, .io = testing.io, .kind = .none };
    var applied: std.atomic.Value(u64) = .init(cp.seq + 1);
    var f: source_mod.Fetcher = .{ .gpa = env.gpa, .io = testing.io, .source = &src, .spool = env.tmp.dir, .next = .init(cp.seq + 1), .applied_next = &applied, .window = 64, .poll_ms = 25, .to = std.math.maxInt(u64) };
    var st: stream_mod.Stream = .{ .gpa = env.gpa, .io = testing.io, .base = "test", .fetcher = &f, .reconcile = rec };
    var sc = source_mod.Scratch.init(env.gpa);
    defer sc.deinit(env.gpa);
    var blob: std.ArrayList(u8) = .empty;
    defer blob.deinit(env.gpa);
    st.handle(.{ .cursor = cp.seq, .checkpoint = cp.proto }, &sc, &blob);
    try testing.expectEqual(@as(u64, 1), st.stats.dups.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.stats.delivered.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), st.stats.bad.load(.monotonic));
}

/// The p2p build's lists of `cp` damaged the ways the production shadow showed: one list in
/// another order, one without an entry, one with an entry too many.
const RsDamage = struct {
    lists: []const []const convert.LoadedRef,
    reordered: usize,
    short: usize,
    long: usize,
    /// The entry `short` lost.
    lost: convert.LoadedRef,
};

fn rsDamage(a: std.mem.Allocator, cp: *const RsCp, built: convert.Aux) !RsDamage {
    const lists = try a.dupe([]const convert.LoadedRef, built.loaded);
    // One with two or more entries, reversed.
    const reordered = for (lists, 0..) |l, i| {
        if (l.len >= 2) break i;
    } else return error.SkipZigTest;
    const rev = try a.dupe(convert.LoadedRef, lists[reordered]);
    std.mem.reverse(convert.LoadedRef, rev);
    lists[reordered] = rev;
    // One that loses an entry whose object only the object set carries (not the blob).
    var extras: std.AutoHashMapUnmanaged(RsKey, void) = .empty;
    for (cp.bucket.objects) |raw| try extras.put(a, try exec.objects.keyOf(raw), {});
    var short: usize = 0;
    var lost: convert.LoadedRef = undefined;
    const found = for (lists, 0..) |l, i| {
        if (i == reordered) continue;
        if (l.len == 0 or !extras.contains(.{ .id = l[0].id, .version = l[0].version })) continue;
        short = i;
        lost = l[0];
        break true;
    } else false;
    if (!found) return error.SkipZigTest;
    lists[short] = lists[short][1..];
    // One that gains an entry (another transaction's).
    const long = for (lists, 0..) |_, i| {
        if (i != reordered and i != short) break i;
    } else return error.SkipZigTest;
    const more = try a.alloc(convert.LoadedRef, lists[long].len + 1);
    @memcpy(more[0..lists[long].len], lists[long]);
    more[lists[long].len] = rev[0];
    lists[long] = more;
    return .{ .lists = lists, .reordered = reordered, .short = short, .long = long, .lost = lost };
}

/// One checkpoint and its p2p build, shared by the reconcile scenarios.
const RsShared = struct { cp: RsCp, built_aux: []const u8, built: convert.Aux };

fn rsRepair(env: *RsEnv, a: std.mem.Allocator, sh: *const RsShared) anyerror!void {
    const cp = sh.cp;
    const seq = cp.seq;
    const built = sh.built;
    const dmg = try rsDamage(a, &cp, built);
    // The lost entry's object is not in the damaged aux record either, and this store never
    // held it (the node did not read it): the repair has to bring the object too.
    var objs: std.ArrayList([]const u8) = .empty;
    for (built.objects) |raw| {
        const k = try exec.objects.keyOf(raw);
        if (k.version == dmg.lost.version and std.mem.eql(u8, &k.id, &dmg.lost.id)) continue;
        try objs.append(a, raw);
    }
    const skip: RsKey = .{ .id = dmg.lost.id, .version = dmg.lost.version };

    // What the bucket path stores and serves.
    const want_lists = try rsWantLists(a, &cp);
    const want = blk: {
        const bh = try rsBucketStore(env, a, &cp, "repair-bucket");
        defer bh.io.deinit();
        defer bh.store.deinit();
        var svc = rsService(env, bh.store, seq);
        defer svc.deinit();
        break :blk [3][]const u8{ try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask), try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached), try rsBatchGet(a, &svc, seq, cp.digests) };
    };

    var node = try RsNode.init(env, a, &cp, "repair", try rsAuxBytes(a, dmg.lists, objs.items), skip, null, .{});
    defer node.deinit();
    const st = node.h.store;
    const r = node.rec;
    // Before: the three lists differ, the object is absent, and the answers are not sui-node's.
    const before = try node.lists(a, &cp);
    for (before, want_lists, 0..) |have, w, i| {
        const damaged = i == dmg.reordered or i == dmg.short or i == dmg.long;
        try testing.expectEqual(!damaged, std.mem.eql(u8, have, w));
    }
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expect(snap.objectAt(&skip.id, skip.version) == null);
    }
    var svc = rsService(env, st, seq);
    defer svc.deinit();
    const stale = try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached);
    try testing.expect(!std.mem.eql(u8, stale, want[1]));
    try testing.expect(svc.cp_cache.bytesHeld() > 0);
    try testing.expectEqualSlices(u8, stale, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));

    // The stream's copy arrives: a duplicate, handed to the reconciler.
    try rsStreamDuplicate(env, r, &cp);
    try testing.expectEqual(@as(u64, 1), r.stats.from_stream.load(.monotonic));
    // Compared; the missing object has to be committed first, so nothing is served yet.
    try testing.expect(try r.step());
    try testing.expectEqual(@as(u64, 1), r.stats.reconciled.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), r.stats.repairs.load(.monotonic));
    try testing.expect(rsSameLists(before, try node.lists(a, &cp)));
    try testing.expect(!try r.step());
    // The next checkpoint's commit group carries the object.
    {
        const b = try st.begin(seq + 1, cp.epoch);
        try r.applied(seq + 1, false, b);
        try st.commit(b);
    }
    try testing.expect(try r.step());
    try testing.expectEqual(@as(u64, 3), r.stats.repairs.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), r.stats.repaired_checkpoints.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), r.stats.objects_added.load(.monotonic));
    try testing.expect(!r.isWaiting(seq));
    try testing.expectEqual(@as(u64, 0), r.stats.pending.load(.monotonic));

    // After: the stored lists and object, and every answer, are the bucket path's.
    try testing.expect(rsSameLists(want_lists, try node.lists(a, &cp)));
    {
        var snap = st.snapshot();
        defer snap.release();
        try testing.expect(snap.objectAt(&skip.id, skip.version) != null);
    }
    // The cached response was dropped: the same service answers the repaired bytes.
    try testing.expectEqualSlices(u8, want[1], try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqualSlices(u8, want[0], try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask));
    try testing.expectEqualSlices(u8, want[2], try rsBatchGet(a, &svc, seq, cp.digests));
    // Nothing left to do, and a second copy is not wanted.
    try testing.expect(!try r.step());
    try testing.expect(!r.wantsCopy(seq));
    // A restart serves the repaired lists from the log and does not compare the checkpoint again.
    try node.restart(a, .{});
    try testing.expectEqual(@as(u64, 3), node.rec.stats.loaded.load(.monotonic));
    try testing.expect(!node.rec.isWaiting(seq));
    try testing.expect(rsSameLists(want_lists, try node.lists(a, &cp)));
}

fn rsClean(env: *RsEnv) anyerror!void {
    var compared: u64 = 0;
    var s: u64 = 342451158;
    const seqs = blk: {
        var list: [13]u64 = undefined;
        for (list[0..12]) |*x| {
            x.* = s;
            s += 1;
        }
        list[12] = 342453625;
        break :blk list;
    };
    for (seqs) |seq| {
        var arena: std.heap.ArenaAllocator = .init(env.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const cp = try rsLoad(env, a, seq);
        const dir = try std.fmt.allocPrint(a, "clean-{d}", .{seq});
        const built_aux = (try rsBuild(env, a, &cp, try std.fmt.allocPrint(a, "{s}-pre", .{dir}))) orelse return error.SkipZigTest;
        var node = try RsNode.init(env, a, &cp, dir, built_aux, null, null, .{});
        defer {
            node.deinit();
            for ([_][]const u8{ "", "-node", "-spool" }) |sfx| env.tmp.dir.deleteTree(testing.io, std.fmt.allocPrint(a, "{s}{s}", .{ dir, sfx }) catch dir) catch {};
        }
        const before = try node.lists(a, &cp);
        try rsStreamDuplicate(env, node.rec, &cp);
        try testing.expect(try node.rec.step());
        const x = &node.rec.stats;
        try testing.expectEqual(@as(u64, 1), x.reconciled.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), x.repairs.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), x.repaired_checkpoints.load(.monotonic));
        try testing.expectEqual(@as(u64, 0), x.objects_added.load(.monotonic));
        try testing.expectEqual(@as(usize, 0), node.h.store.list_fix.count());
        try testing.expectEqual(@as(u64, 0), node.h.store.list_fix.generation());
        try testing.expect(!node.rec.isWaiting(seq));
        try testing.expect(rsSameLists(before, try node.lists(a, &cp)));
        // No repair record: a restart reinstalls nothing and has nothing waiting.
        try node.restart(a, .{});
        try testing.expectEqual(@as(u64, 0), node.rec.stats.loaded.load(.monotonic));
        try testing.expect(!node.rec.isWaiting(seq));
        compared += 1;
    }
    try testing.expectEqual(@as(u64, 13), compared);
}

fn rsCrash(env: *RsEnv, a: std.mem.Allocator, sh: *const RsShared) anyerror!void {
    const cp = sh.cp;
    const seq = cp.seq;
    const built = sh.built;
    // One list in another order (no object is missing: the repair is the log record alone).
    const lists = try a.dupe([]const convert.LoadedRef, built.loaded);
    const i = for (lists, 0..) |l, k| {
        if (l.len >= 2) break k;
    } else return error.SkipZigTest;
    const rev = try a.dupe(convert.LoadedRef, lists[i]);
    std.mem.reverse(convert.LoadedRef, rev);
    lists[i] = rev;
    const want_lists = try rsWantLists(a, &cp);
    var node = try RsNode.init(env, a, &cp, "crash", try rsAuxBytes(a, lists, built.objects), null, null, .{});
    defer node.deinit();
    const old = try node.lists(a, &cp);
    try testing.expect(!rsSameLists(old, want_lists));

    // Killed between the compare and the commit: the old lists, the checkpoint still waiting.
    {
        const plan = try node.rec.compare(a, seq, cp.aux, .stream);
        try testing.expectEqual(@as(usize, 1), plan.fixes.len);
        try testing.expectEqual(@as(usize, 0), plan.objects.len);
    }
    try node.restart(a, .{});
    try testing.expect(node.rec.isWaiting(seq));
    try testing.expectEqual(@as(u64, 0), node.rec.stats.loaded.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), node.h.store.list_fix.count());
    try testing.expect(rsSameLists(old, try node.lists(a, &cp)));

    // Killed inside the commit (the log record is torn): the same.
    const log_len = (try node.node_dir.statFile(testing.io, reconcile.log_name, .{})).size;
    {
        const plan = try node.rec.compare(a, seq, cp.aux, .stream);
        try node.rec.commit(&plan);
        try testing.expect(rsSameLists(want_lists, try node.lists(a, &cp)));
    }
    const full_len = (try node.node_dir.statFile(testing.io, reconcile.log_name, .{})).size;
    try testing.expect(full_len > log_len);
    {
        const f = try node.node_dir.openFile(testing.io, reconcile.log_name, .{ .mode = .read_write });
        defer f.close(testing.io);
        try f.setLength(testing.io, full_len - 7);
    }
    try node.restart(a, .{});
    try testing.expect(node.rec.isWaiting(seq));
    try testing.expectEqual(@as(u64, 0), node.rec.stats.loaded.load(.monotonic));
    try testing.expect(rsSameLists(old, try node.lists(a, &cp)));
    try testing.expectEqual(log_len, (try node.node_dir.statFile(testing.io, reconcile.log_name, .{})).size);

    // Killed right after the commit (before the checkpoint is settled or a watermark written):
    // the repaired lists, and the checkpoint no longer waiting.
    {
        const plan = try node.rec.compare(a, seq, cp.aux, .stream);
        try node.rec.commit(&plan);
        try testing.expect(node.rec.isWaiting(seq));
    }
    try node.restart(a, .{});
    try testing.expect(!node.rec.isWaiting(seq));
    try testing.expectEqual(@as(u64, 1), node.rec.stats.loaded.load(.monotonic));
    try testing.expect(rsSameLists(want_lists, try node.lists(a, &cp)));
    // And again: the log is replayed the same way every time.
    try node.restart(a, .{});
    try testing.expect(!node.rec.isWaiting(seq));
    try testing.expect(rsSameLists(want_lists, try node.lists(a, &cp)));
}

fn rsBucket(env: *RsEnv, a: std.mem.Allocator, sh: *const RsShared) anyerror!void {
    const cp = sh.cp;
    const seq = cp.seq;
    const built = sh.built;
    const lists = try a.dupe([]const convert.LoadedRef, built.loaded);
    const i = for (lists, 0..) |l, k| {
        if (l.len >= 2) break k;
    } else return error.SkipZigTest;
    const rev = try a.dupe(convert.LoadedRef, lists[i]);
    std.mem.reverse(convert.LoadedRef, rev);
    lists[i] = rev;
    const want_lists = try rsWantLists(a, &cp);
    // The bucket: a directory the checkpoint's archive proto appears in later.
    try env.tmp.dir.createDir(testing.io, "the-bucket", .default_dir);
    const bdir = try env.tmp.dir.openDir(testing.io, "the-bucket", .{});
    const bucket: source_mod.Source = .{ .gpa = env.gpa, .io = testing.io, .kind = .{ .dir = bdir } };
    var node = try RsNode.init(env, a, &cp, "bucket", try rsAuxBytes(a, lists, built.objects), null, &bucket, .{ .wait_ms = 3_600_000, .retry_ms = 0 });
    defer node.deinit();
    const r = node.rec;
    const old = try node.lists(a, &cp);
    // No duplicate from the stream. Within the wait the bucket is not asked.
    try testing.expect(!try r.step());
    try testing.expectEqual(@as(u64, 0), r.stats.bucket_waits.load(.monotonic));
    // The wait is over, the bucket has not published the checkpoint yet: asked, still waiting.
    r.cfg.wait_ms = 0;
    try testing.expect(!try r.step());
    try testing.expectEqual(@as(u64, 1), r.stats.bucket_waits.load(.monotonic));
    try testing.expect(r.isWaiting(seq));
    try testing.expect(rsSameLists(old, try node.lists(a, &cp)));
    // Published: fetched once, compared, repaired.
    {
        var nb: [64]u8 = undefined;
        const z = try readCorpus(env.gpa, try std.fmt.bufPrint(&nb, "binpb-done/{d}.binpb.zst", .{seq}));
        defer env.gpa.free(z);
        try bdir.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq}), .data = z });
    }
    try testing.expect(try r.step());
    try testing.expectEqual(@as(u64, 1), r.stats.from_bucket.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), r.stats.from_stream.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), r.stats.reconciled.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), r.stats.repairs.load(.monotonic));
    try testing.expect(!r.isWaiting(seq));
    try testing.expect(rsSameLists(want_lists, try node.lists(a, &cp)));
    try testing.expect(!try r.step());
    try testing.expectEqual(@as(u64, 1), r.stats.from_bucket.load(.monotonic));
}

fn rsUntouched(env: *RsEnv, a: std.mem.Allocator, sh: *const RsShared) anyerror!void {
    // A checkpoint from the bucket or the stream (no `.p2p` mark in the spool) is not marked,
    // does not wait, and a copy offered for it before it was applied is dropped at apply.
    const cp = sh.cp;
    const seq = cp.seq;
    const h = try rsStore(env, a, "untouched");
    defer h.io.deinit();
    defer h.store.deinit();
    try types.indexCheckpointData(cp.blob, &env.idx);
    try rsSeed(env, a, h.store, seq, cp.epoch, cp.blob, cp.bucket);
    try env.tmp.dir.createDir(testing.io, "untouched-node", .default_dir);
    const node_dir = try env.tmp.dir.openDir(testing.io, "untouched-node", .{});
    try env.tmp.dir.createDir(testing.io, "untouched-spool", .default_dir);
    const spool = try env.tmp.dir.openDir(testing.io, "untouched-spool", .{});
    const r = try reconcile.Reconciler.open(env.gpa, testing.io, h.store, node_dir, null, .{});
    defer r.deinit();
    // Not applied yet: p2p may still build it, so the stream's copy is kept for now.
    try testing.expect(r.wantsCopy(seq));
    r.offer(seq, cp.aux, .stream);
    try testing.expect(!r.wantsCopy(seq));
    var nb: [48]u8 = undefined;
    try spool.writeFile(testing.io, .{ .sub_path = try std.fmt.bufPrint(&nb, "{d}.aux", .{seq}), .data = cp.aux });
    try rsApplyOpts(env, a, h.store, seq, cp.blob, spool, r);
    var snap = h.store.snapshot();
    defer snap.release();
    try testing.expect(!history.p2pBuilt(&snap, seq));
    try testing.expect(!r.isWaiting(seq));
    try testing.expect(!r.wantsCopy(seq));
    try testing.expectEqual(@as(usize, 0), r.held_bytes);
    try testing.expect(!try r.step());
    try testing.expectEqual(@as(u64, 0), r.stats.reconciled.load(.monotonic));
    // The watermark still moves past it, so a restart does not look for its marker again.
    try testing.expectEqual(seq + 1, r.settled_below);
    try testing.expectEqual(seq + 1, r.marked_below);
}

fn rsThreaded(env: *RsEnv, a: std.mem.Allocator, sh: *const RsShared) anyerror!void {
    // The node's wiring: the reconciler's own thread picks up the stream's duplicate.
    const cp = sh.cp;
    const seq = cp.seq;
    const lists = try a.dupe([]const convert.LoadedRef, sh.built.loaded);
    const i = for (lists, 0..) |l, k| {
        if (l.len >= 2) break k;
    } else return error.SkipZigTest;
    const rev = try a.dupe(convert.LoadedRef, lists[i]);
    std.mem.reverse(convert.LoadedRef, rev);
    lists[i] = rev;
    var node = try RsNode.init(env, a, &cp, "threaded", try rsAuxBytes(a, lists, sh.built.objects), null, null, .{ .tick_ms = 5 });
    defer node.deinit();
    try node.rec.start();
    try rsStreamDuplicate(env, node.rec, &cp);
    var waited: u32 = 0;
    while (node.rec.isWaiting(seq) and waited < 2_000) : (waited += 1) testing.io.sleep(.fromMilliseconds(5), .awake) catch {};
    node.rec.stop();
    try testing.expect(!node.rec.isWaiting(seq));
    try testing.expectEqual(@as(u64, 1), node.rec.stats.repairs.load(.monotonic));
    try testing.expect(rsSameLists(try rsWantLists(a, &cp), try node.lists(a, &cp)));
}

fn rsReconcileBody(_: void, env: *RsEnv) anyerror!void {
    // The in-order build (the level-parallel one is compared with it in the read-set test).
    env.pool = null;
    var arena: std.heap.ArenaAllocator = .init(env.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const cp = try rsLoad(env, a, 342451165);
    const built_aux = (try rsBuild(env, a, &cp, "shared-pre")) orelse return error.SkipZigTest;
    const sh: RsShared = .{ .cp = cp, .built_aux = built_aux, .built = try convert.Aux.parse(a, built_aux) };
    // 1. wrong order, a missing entry (and its object), an extra entry: repaired from the
    //    stream's duplicate; the cached GetCheckpoint response is dropped.
    // 2. a kill before, inside and after the repair's commit.
    // 3. no duplicate: the bucket's copy, after the wait, once it is published.
    // 4. a checkpoint from the stream or the bucket is not marked and never compared.
    inline for (.{ .{ "repair", rsRepair }, .{ "kill", rsCrash }, .{ "bucket", rsBucket }, .{ "other sources", rsUntouched }, .{ "thread", rsThreaded } }) |c| {
        c[1](env, a, &sh) catch |e| {
            std.debug.print("p2p reconcile ({s}): {s}\n", .{ c[0], @errorName(e) });
            return e;
        };
    }
    // 5. lists that already equal sui-node's (the read-set test's 13 checkpoints): no repair.
    rsClean(env) catch |e| {
        std.debug.print("p2p reconcile (13 clean checkpoints): {s}\n", .{@errorName(e)});
        return e;
    };
}

test "p2p reconcile: wrong, short and long lists are repaired from the stream's duplicate or the bucket's copy, across kills; equal lists and other sources' checkpoints are left alone" {
    try rsWith({}, rsReconcileBody);
}

/// The GetCheckpoint response cache across a repair, on the lookup that runs before any store
/// read (serve service.zig `getCheckpointCached`): a p2p-built checkpoint with one list in
/// another order is served and cached, then repaired by the reconciler while its entry is still
/// within the recheck time.
fn rsCachedRepairBody(_: void, env: *RsEnv) anyerror!void {
    env.pool = null;
    var arena: std.heap.ArenaAllocator = .init(env.gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const seq: u64 = 342451165;
    const cp = try rsLoad(env, a, seq);
    const built_aux = (try rsBuild(env, a, &cp, "cached-pre")) orelse return error.SkipZigTest;
    const built = try convert.Aux.parse(a, built_aux);
    const lists = try a.dupe([]const convert.LoadedRef, built.loaded);
    const i = for (lists, 0..) |l, k| {
        if (l.len >= 2) break k;
    } else return error.SkipZigTest;
    const rev = try a.dupe(convert.LoadedRef, lists[i]);
    std.mem.reverse(convert.LoadedRef, rev);
    lists[i] = rev;
    // What the bucket path serves.
    const want = blk: {
        const bh = try rsBucketStore(env, a, &cp, "cached-bucket");
        defer bh.io.deinit();
        defer bh.store.deinit();
        var svc = rsService(env, bh.store, seq);
        defer svc.deinit();
        break :blk try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached);
    };
    var node = try RsNode.init(env, a, &cp, "cached", try rsAuxBytes(a, lists, built.objects), null, null, .{});
    defer node.deinit();
    const st = node.h.store;
    var svc = rsService(env, st, seq);
    defer svc.deinit();
    // Every call below is within the recheck time, however slow the machine.
    svc.cp_recheck_ns = std.time.ns_per_hour;
    const fast = &svc.cp_fast_hits;
    const inserts = &svc.cp_cache.stats.inserts;

    // Rendered from the store and cached; the same call again never reaches the store.
    const stale = try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached);
    try testing.expect(!std.mem.eql(u8, stale, want));
    try testing.expectEqual(@as(u64, 1), inserts.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), fast.load(.monotonic));
    try testing.expectEqualSlices(u8, stale, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 1), fast.load(.monotonic));

    // A repaired list and a signature-order fix of ANOTHER checkpoint: this entry is not
    // touched, and is still answered before any store read.
    const da: [32]u8 = @splat(0x5a);
    const db: [32]u8 = @splat(0x5b);
    const dc: [32]u8 = @splat(0x5c);
    try testing.expect(try st.list_fix.put(seq + 1, &da, try rsListBytes(a, rev)));
    try testing.expectEqualSlices(u8, stale, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 2), fast.load(.monotonic));
    try testing.expect(try st.tx_fix.put(seq + 1, &db, "x"));
    try testing.expectEqualSlices(u8, stale, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 3), fast.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), inserts.load(.monotonic));

    // The stream's duplicate arrives and the reconciler replaces the list (no object is
    // missing: one step).
    try rsStreamDuplicate(env, node.rec, &cp);
    try testing.expect(try node.rec.step());
    try testing.expectEqual(@as(u64, 1), node.rec.stats.repairs.load(.monotonic));
    try testing.expect(!node.rec.isWaiting(seq));

    // Within the recheck time: the entry is not answered ahead of the store. It is dropped, and
    // the response is rendered again with the repaired list: the bucket path's bytes.
    try testing.expectEqualSlices(u8, want, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 3), fast.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), inserts.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), svc.cp_cache.entries());
    // The new entry is answered before the store read again.
    try testing.expectEqualSlices(u8, want, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 4), fast.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), inserts.load(.monotonic));

    // The same for a signature-order fix of this checkpoint (no transaction has the digest, so
    // the bytes stay): dropped and rendered once, then answered before the store read again.
    try testing.expect(try st.tx_fix.put(seq, &dc, "x"));
    try testing.expectEqualSlices(u8, want, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 4), fast.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), inserts.load(.monotonic));
    try testing.expectEqualSlices(u8, want, try rsGetCheckpoint(a, &svc, seq, &rs_cp_mask_cached));
    try testing.expectEqual(@as(u64, 5), fast.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), inserts.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), svc.cp_cache.entries());
}

test "p2p reconcile: a list repaired within the recheck time drops the cached GetCheckpoint response before it is served ahead of the store; a fix of another checkpoint leaves it there" {
    try rsWith({}, rsCachedRepairBody);
}

/// A store of twelve corpus checkpoints (342456120..) and their blobs, for the backfill tests.
const LhWorld = struct {
    arena: std.heap.ArenaAllocator,
    tmp: testing.TmpDir,
    root: []const u8 = "",
    cfg: store.Config = undefined,
    store_: ?*store.Store = null,
    rio: ?*store.RealIo = null,
    blobs: [12][]const u8 = undefined,
    seqs: [12]u64 = undefined,

    fn init(w: *LhWorld) !void {
        w.* = .{ .arena = std.heap.ArenaAllocator.init(testing.allocator), .tmp = testing.tmpDir(.{}) };
        errdefer w.deinit();
        const a = w.arena.allocator();
        for (&w.blobs, 0..) |*b, i| {
            var nb: [64]u8 = undefined;
            b.* = try readCorpus(a, try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{342456120 + i}));
        }
        var pb: [512]u8 = undefined;
        w.root = try a.dupe(u8, try tmpPath(&w.tmp, &pb));
        w.cfg = .{ .dir = try std.fmt.allocPrint(a, "{s}/store", .{w.root}), .max_live_objects = 1 << 16, .segment_reserve = 1 << 24 };
        try w.open();
        for (w.blobs, &w.seqs) |b, *s| s.* = try storeBlob(w.store_.?, a, b);
    }

    fn open(w: *LhWorld) !void {
        const h = try store.openDir(testing.allocator, testing.io, &w.cfg, .{ .sync = .none });
        w.store_ = h.store;
        w.rio = h.io;
    }

    /// The process dies: nothing is flushed or closed.
    fn kill(w: *LhWorld) void {
        if (w.store_) |x| x.deinit();
        if (w.rio) |x| x.deinit();
        w.store_ = null;
        w.rio = null;
    }

    fn deinit(w: *LhWorld) void {
        w.kill();
        w.tmp.cleanup();
        w.arena.deinit();
    }

    fn st(w: *LhWorld) *store.Store {
        return w.store_.?;
    }

    fn lowest(w: *LhWorld) ?u64 {
        var snap = w.st().snapshot();
        defer snap.release();
        return snap.lowestAvailable();
    }

    /// The content hash of an index of checkpoints `from..` built from the blobs.
    fn hashFrom(w: *LhWorld, from: usize) !u64 {
        const ix = try lhist.Index.init(testing.allocator, testing.io, null);
        defer ix.deinit();
        for (w.blobs[from..], w.seqs[from..]) |b, s| try ix.addCheckpoint(s, b);
        return ix.contentHash();
    }

    fn wait(bf: *lhfill.Backfill) void {
        while (bf.status() == .running) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
};

test "ledger-history backfill: checkpoints retention prunes under the build move its start up; that is not a failure and costs no try (TransactionNotStored on two edges, three times, then silence)" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    const a = w.arena.allocator();
    // The node read its lowest checkpoint, then a retention tick raised the store's floor
    // before the loaders got to the bottom of the range (cold reads at a start).
    _ = try w.st().setFloors(.{ .cp_pruned = w.seqs[2] });
    try testing.expectEqual(@as(?u64, w.seqs[3]), w.lowest());
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 3 });
        defer bf.destroy();
        LhWorld.wait(bf);
        try testing.expectEqual(@as(?anyerror, null), bf.failure);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expectEqual(@as(u32, 1), bf.floor_moves);
        const out = try bf.finish(w.seqs[11]);
        try testing.expectEqual(@as(?u64, w.seqs[3]), out.indexedLo());
        try testing.expectEqual(try w.hashFrom(3), try out.contentHash());
        // and its low end is the store's floor: the witness of an unclean stop to come
        try testing.expect(out.lowIsFloor());
    }
    // The same under a build that had rows on disk below the new floor: they cannot join what
    // is left of the window, so the output starts again at the floor.
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{w.root});
    var w2: LhWorld = undefined;
    try w2.init();
    defer w2.deinit();
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w2.st(), w2.seqs[0], w2.seqs[11], .{ .workers = 2, .staging = staging, .save_every_ns = 0, .stop_after_saves = 2 });
        while (bf.saves < 2) testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        bf.destroy();
    }
    _ = try w2.st().setFloors(.{ .cp_pruned = w2.seqs[7] });
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w2.st(), w2.seqs[0], w2.seqs[11], .{ .workers = 2, .staging = staging });
        defer bf.destroy();
        try testing.expect(bf.resumed_at != null and bf.resumed_at.? < w2.seqs[8]);
        LhWorld.wait(bf);
        try testing.expectEqual(@as(?anyerror, null), bf.failure);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expectEqual(@as(u32, 1), bf.floor_moves);
        try testing.expect(bf.dropped >= 2);
        const out = try bf.finish(w2.seqs[11]);
        try testing.expectEqual(@as(?u64, w2.seqs[8]), out.indexedLo());
        try testing.expectEqual(try w2.hashFrom(8), try out.contentHash());
    }
    // A checkpoint that is missing above the floor is still a failure.
    {
        var c: lhfill.Counters = .{};
        var snap = w.st().snapshot();
        defer snap.release();
        try testing.expect((try lhfill.load(a, &snap, w.seqs[11] + 5, &c)) == null);
    }
}

test "ledger-history: after an unclean stop the store's checkpoint floor comes back lower; the index's pruned low end gives it back, and nothing is backfilled (the whole retained window was, on two edges)" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    const a = w.arena.allocator();
    const hdir = try std.fmt.allocPrint(a, "{s}/lh", .{w.root});
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{w.root});
    const tip = w.seqs[11];
    {
        const live = try lhist.Index.init(gpa, testing.io, hdir);
        defer live.deinit();
        for (w.blobs, w.seqs) |b, s| try live.addCheckpoint(s, b);
        // nothing to restore on a store and an index that agree
        try testing.expectEqual(@as(?u64, null), try lhfill.restoreFloor(w.st(), testing.io, live, staging, w.lowest().?, tip));
        // a retention tick: the store's floor in memory, the index pruned to it durably
        _ = try w.st().setFloors(.{ .cp_pruned = w.seqs[4] });
        try testing.expectEqual(@as(?u64, w.seqs[5]), w.lowest());
        live.pruneBelow(w.seqs[5]);
        try testing.expectEqual(@as(u64, 0), lhfill.gapOf(live, w.lowest().?, tip).count());
    }
    // kill -9 before the store's next meta write
    w.kill();
    try w.open();
    const live = try lhist.Index.init(gpa, testing.io, hdir);
    defer live.deinit();
    // the store's floor is back where its last meta write had it: the index now begins above
    // the store's lowest checkpoint. This is what started the backfill of the whole window.
    const low = w.lowest().?;
    try testing.expectEqual(w.seqs[0], low);
    try testing.expectEqual(@as(?u64, w.seqs[5]), live.indexedLo());
    try testing.expectEqual(@as(u64, 5), lhfill.gapOf(live, low, tip).count());
    // the node's start: the floor the index witnessed goes back to the store
    try testing.expectEqual(@as(?u64, w.seqs[5]), try lhfill.restoreFloor(w.st(), testing.io, live, staging, low, tip));
    try testing.expectEqual(@as(?u64, w.seqs[5]), w.lowest());
    try testing.expectEqual(@as(u64, 0), lhfill.gapOf(live, w.lowest().?, tip).count());
    // an index that only began above the store's lowest checkpoint says nothing about a floor
    const late = try lhist.Index.init(gpa, testing.io, null);
    defer late.deinit();
    for (w.blobs[8..], w.seqs[8..]) |b, s| try late.addCheckpoint(s, b);
    try testing.expectEqual(@as(?u64, null), try lhfill.restoreFloor(w.st(), testing.io, late, null, w.lowest().?, tip));
    try testing.expectEqual(@as(u64, 3), lhfill.gapOf(late, w.lowest().?, tip).count());
}

test "ledger-history backfill: with an index that covers the upper part of the window, only the checkpoints below it are read from the store; the rest is copied from the index (2 checkpoints a second from a cold store, for 525,000)" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    const a = w.arena.allocator();
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{w.root});
    // the live index began at the fifth checkpoint and follows the tip
    const live = try lhist.Index.init(gpa, testing.io, null);
    defer live.deinit();
    for (w.blobs[4..11], w.seqs[4..11]) |b, s| try live.addCheckpoint(s, b);
    try testing.expectEqual(@as(u64, 4), lhfill.gapOf(live, w.seqs[0], w.seqs[10]).count());
    const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[10], .{ .workers = 2, .staging = staging, .live = live });
    defer bf.destroy();
    try testing.expectEqual(w.seqs[3], bf.store_to.load(.monotonic));
    LhWorld.wait(bf);
    try testing.expectEqual(lhfill.Status.ready, bf.status());
    // four from the store, seven from the index: none of those was read from the store again
    try testing.expectEqual(@as(u64, 4), bf.counters.checkpoints.load(.monotonic));
    try testing.expectEqual(@as(u64, 7), bf.copied.load(.monotonic));
    // the commit path: the twelfth is indexed by the live index, the build catches up and is equal
    const out = try bf.finish(w.seqs[10]);
    try testing.expectEqual(@as(?u64, w.seqs[0]), out.indexedLo());
    try testing.expectEqual(@as(?u64, w.seqs[10]), out.indexedHi());
    const want = try lhist.Index.init(gpa, testing.io, null);
    defer want.deinit();
    for (w.blobs[0..11], w.seqs[0..11]) |b, s| try want.addCheckpoint(s, b);
    try testing.expectEqual(try want.contentHash(), try out.contentHash());
}

test "ledger-history backfill: a stop ends a load between two transactions, and a stopped build resumes after the checkpoint it had saved" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    const a = w.arena.allocator();
    var c: lhfill.Counters = .{};
    {
        var snap = w.st().snapshot();
        defer snap.release();
        var stop: std.atomic.Value(bool) = .init(true);
        try testing.expectError(error.Cancelled, lhfill.loadCancel(a, &snap, w.seqs[0], &c, &stop));
        stop.store(false, .release);
        try testing.expect((try lhfill.loadCancel(a, &snap, w.seqs[0], &c, &stop)) != null);
    }
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{w.root});
    var through: ?u64 = null;
    {
        // stopped at once: whatever it had built is saved by the stop, nothing is half-written
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 2, .staging = staging, .ring = 2 });
        bf.requestStop();
        const t0 = source_mod.nowNs();
        through = bf.out.indexedHi();
        bf.destroy();
        try testing.expect((source_mod.nowNs() - t0) / std.time.ns_per_ms < 2000);
    }
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 2, .staging = staging });
        defer bf.destroy();
        // the next start goes on after the last checkpoint the stopped build had
        if (bf.resumed_at) |r| try testing.expect(through == null or r >= through.? + 1);
        LhWorld.wait(bf);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        const out = try bf.finish(w.seqs[11]);
        try testing.expectEqual(try w.hashFrom(0), try out.contentHash());
    }
}

test "ledger-history backfill: the ring holds loaded checkpoints up to a byte budget, not a count, and gives their memory back once indexed (3 GiB to 6.3 GiB and all the swap of a live edge)" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    // The smallest budget: a loader may load only when the ring holds nothing, or when its
    // checkpoint is the next one to index. Eight loaders and a ring of 64 never hold more than
    // those two, where they used to fill the ring.
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 8, .mem_bytes = 1 });
        defer bf.destroy();
        LhWorld.wait(bf);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        const largest = bf.largest.load(.monotonic);
        std.debug.print("ledger-history backfill ring, budget 1 byte, 8 loaders: at most {d} checkpoints and {d} KiB held at once; the largest of the 12 corpus checkpoints is {d} KiB loaded; the idle ring keeps {d} KiB\n", .{ bf.peak_slots.load(.monotonic), bf.peak_bytes.load(.monotonic) >> 10, largest >> 10, bf.ringBytes() >> 10 });
        try testing.expect(bf.peak_slots.load(.monotonic) <= 2);
        try testing.expect(bf.peak_bytes.load(.monotonic) <= 2 * @max(largest, 1 << 20));
        // nothing is counted as held once everything is indexed
        try testing.expectEqual(@as(u64, 0), bf.inflight.load(.monotonic));
        // and a slot keeps a small arena, not the largest checkpoint it ever held
        try testing.expect(bf.ringBytes() <= bf.slots.len * lhfill.Backfill.slot_retain_bytes);
        const out = try bf.finish(w.seqs[11]);
        try testing.expectEqual(try w.hashFrom(0), try out.contentHash());
    }
    // A budget of a few checkpoints: the ring stays within it plus the one checkpoint the
    // index is waiting for.
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 8, .mem_bytes = 4 << 20 });
        defer bf.destroy();
        LhWorld.wait(bf);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expect(bf.peak_bytes.load(.monotonic) <= (4 << 20) + 2 * @max(bf.largest.load(.monotonic), 1 << 20));
        try testing.expect(bf.memoryBytes() >= bf.out.memoryBytes());
    }
}

test "ledger-history backfill: it waits while the node is behind the tip (more than 10 s, until 3 s; or no checkpoint committed yet) and goes on when the node is back (a tip latency of 39 minutes on a live edge)" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    const now_ms: u64 = @intCast(@divTrunc(std.Io.Clock.real.now(testing.io).toNanoseconds(), std.time.ns_per_ms));
    // the node has committed nothing yet in this run (a start): the build waits
    var tip: std.atomic.Value(u64) = .init(0);
    const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 3, .tip_ms = &tip });
    defer bf.destroy();
    testing.io.sleep(.fromMilliseconds(250), .awake) catch {};
    try testing.expectEqual(lhfill.Status.running, bf.status());
    try testing.expectEqual(@as(u64, 0), bf.counters.checkpoints.load(.monotonic));
    try testing.expect(bf.paused.load(.monotonic));
    // its newest checkpoint is a minute old (catch-up, or a stall): still waiting
    tip.store(now_ms - 60_000, .monotonic);
    testing.io.sleep(.fromMilliseconds(250), .awake) catch {};
    try testing.expectEqual(@as(u64, 0), bf.counters.checkpoints.load(.monotonic));
    try testing.expectEqual(@as(?u64, null), bf.out.indexedHi());
    // 5 s behind is not back at the tip for a build that was waiting (3 s is)
    tip.store(@as(u64, @intCast(@divTrunc(std.Io.Clock.real.now(testing.io).toNanoseconds(), std.time.ns_per_ms))) - 5_000, .monotonic);
    testing.io.sleep(.fromMilliseconds(250), .awake) catch {};
    try testing.expectEqual(@as(u64, 0), bf.counters.checkpoints.load(.monotonic));
    // at the tip (a future timestamp reads as no lag): the build runs to its end
    tip.store(now_ms + 3_600_000, .monotonic);
    LhWorld.wait(bf);
    try testing.expectEqual(lhfill.Status.ready, bf.status());
    try testing.expect(bf.pauses.load(.monotonic) >= 1);
    try testing.expect(bf.paused_ms.load(.monotonic) >= 500);
    try testing.expect(!bf.paused.load(.monotonic));
    const out = try bf.finish(w.seqs[11]);
    try testing.expectEqual(try w.hashFrom(0), try out.contentHash());
    // a stop does not wait for the node to come back either
    var never: std.atomic.Value(u64) = .init(0);
    const bf2 = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 2, .tip_ms = &never });
    testing.io.sleep(.fromMilliseconds(50), .awake) catch {};
    const t0 = source_mod.nowNs();
    bf2.destroy();
    try testing.expect((source_mod.nowNs() - t0) / std.time.ns_per_ms < 1000);
}

test "ledger-history backfill: the operator's switch (--no-history-backfill, ZUI_LH_BACKFILL=0)" {
    try testing.expect(lhfill.enabled(true, null));
    try testing.expect(lhfill.enabled(true, "1"));
    try testing.expect(!lhfill.enabled(true, "0"));
    try testing.expect(!lhfill.enabled(true, "off"));
    try testing.expect(!lhfill.enabled(true, "false"));
    try testing.expect(!lhfill.enabled(false, null));
    try testing.expect(!lhfill.enabled(false, "1"));
    const node = @import("node.zig");
    const cfg: node.Config = .{ .dir = "", .source = .{ .dir = "" } };
    try testing.expect(cfg.lh_backfill);
}

test "ledger-history backfill: a restart with the index a little above the store's lowest checkpoint and a staging watermark present reads only what neither holds, and a resume does not widen it to the window (a clean close did not clear the trigger; the resume reloaded 343538813..344071316)" {
    const gpa = testing.allocator;
    var w: LhWorld = undefined;
    try w.init();
    defer w.deinit();
    const a = w.arena.allocator();
    const want = try w.hashFrom(0);
    // The store serves 0..11. The live index begins at the fifth checkpoint (its low end
    // stayed above the store's lowest after an unclean stop, and a clean close since changed
    // nothing about that) and follows the tip.
    const live = try lhist.Index.init(gpa, testing.io, null);
    defer live.deinit();
    for (w.blobs[4..], w.seqs[4..]) |b, s| try live.addCheckpoint(s, b);
    const gap = lhfill.gapOf(live, w.seqs[0], w.seqs[11]);
    try testing.expectEqual(@as(u64, 4), gap.count());
    try testing.expectEqual(w.seqs[3], gap.to);

    // An earlier run's build left a staging index through the seventh checkpoint: past the
    // live index's low end, so everything missing is already there.
    const staging = try std.fmt.allocPrint(a, "{s}/lh/backfill", .{w.root});
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[6], .{ .workers = 2, .staging = staging });
        LhWorld.wait(bf);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        bf.destroy();
    }
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 2, .staging = staging, .live = live });
        defer bf.destroy();
        try testing.expectEqual(@as(?u64, w.seqs[7]), bf.resumed_at);
        // nothing is left to read from the store (the node's start line says so: 0 checkpoints)
        try testing.expect(bf.store_to.load(.monotonic) < bf.resumed_at.?);
        LhWorld.wait(bf);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expectEqual(@as(u64, 0), bf.counters.checkpoints.load(.monotonic));
        try testing.expectEqual(@as(u64, 5), bf.copied.load(.monotonic));
        const out = try bf.finish(w.seqs[11]);
        try testing.expectEqual(@as(?u64, w.seqs[0]), out.indexedLo());
        try testing.expectEqual(want, try out.contentHash());
    }
    // The same with a watermark below the live index's low end: the two checkpoints between
    // them are read from the store, no more.
    const staging2 = try std.fmt.allocPrint(a, "{s}/lh2/backfill", .{w.root});
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[1], .{ .workers = 2, .staging = staging2 });
        LhWorld.wait(bf);
        bf.destroy();
    }
    {
        const bf = try lhfill.Backfill.startOpts(gpa, testing.io, w.st(), w.seqs[0], w.seqs[11], .{ .workers = 2, .staging = staging2, .live = live });
        defer bf.destroy();
        try testing.expectEqual(@as(?u64, w.seqs[2]), bf.resumed_at);
        try testing.expectEqual(w.seqs[3], bf.store_to.load(.monotonic));
        LhWorld.wait(bf);
        try testing.expectEqual(lhfill.Status.ready, bf.status());
        try testing.expectEqual(@as(u64, 2), bf.counters.checkpoints.load(.monotonic));
        try testing.expectEqual(@as(u64, 8), bf.copied.load(.monotonic));
        const out = try bf.finish(w.seqs[11]);
        try testing.expectEqual(want, try out.contentHash());
    }
}

test "ledger-history backfill: an abandoned staging directory is measured and removed whole, CURRENT first; a stop ends the removal between files and what is left opens as an empty index (10 GiB of a dead build beside an 11 GiB index)" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var pb: [512]u8 = undefined;
    const root_dir = try tmpPath(&tmp, &pb);
    const staging = try std.fmt.allocPrint(gpa, "{s}/lh/backfill", .{root_dir});
    defer gpa.free(staging);
    // nothing there: nothing to measure, nothing to remove, and that is done
    try testing.expectEqual(@as(u64, 0), lhfill.stagingUse(testing.io, staging).bytes);
    {
        const r = lhfill.removeStaging(testing.io, staging, null);
        try testing.expect(r.done and r.err == null and r.files == 0);
    }
    // a build's staging index, saved (a segment rotation), as a killed or abandoned build leaves it
    const Fill = struct {
        fn go(dir: []const u8) !void {
            const st = try lhist.Index.openStaging(testing.allocator, testing.io, dir);
            defer st.deinit();
            var first_tx: u64 = 500;
            for (0..6) |c| {
                var digests: [40][32]u8 = undefined;
                var evc: [40]u32 = @splat(0);
                var txe: [40]struct { u32, u32 } = undefined;
                for (&digests, &txe, 0..) |*d, *t, i| {
                    d.* = @splat(0);
                    std.mem.writeInt(u64, d[0..8], first_tx + i, .little);
                    t.* = .{ @intCast(i % 2), @intCast(i) };
                }
                try st.addRows(1000 + c, first_tx, &digests, &evc, &.{ "\x01sender-a", "\x01sender-b" }, &txe, &.{});
                first_tx += digests.len;
            }
            st.vouchLow();
            try st.saveStaging();
        }
    };
    try Fill.go(staging);
    const use = lhfill.stagingUse(testing.io, staging);
    try testing.expect(use.files >= 3 and use.bytes > 4096);
    try testing.expectEqual(@as(?u64, 1000), lhist.Index.peekFloor(testing.io, staging));
    // a stop that has begun: nothing is touched, the build's state is whole for the next start
    {
        var stop: std.atomic.Value(bool) = .init(true);
        const r = lhfill.removeStaging(testing.io, staging, &stop);
        try testing.expect(!r.done and r.err == null and r.files == 0);
        try testing.expectEqual(use.bytes, lhfill.stagingUse(testing.io, staging).bytes);
        const st = try lhist.Index.openStaging(gpa, testing.io, staging);
        defer st.deinit();
        try testing.expectEqual(@as(?u64, 1005), st.indexedHi());
    }
    // removed: every file and byte counted, the directory gone
    {
        var stop: std.atomic.Value(bool) = .init(false);
        const r = lhfill.removeStaging(testing.io, staging, &stop);
        try testing.expect(r.done and r.err == null);
        try testing.expectEqual(use.files, r.files);
        try testing.expectEqual(use.bytes, r.bytes);
        try testing.expectEqual(@as(u64, 0), lhfill.stagingUse(testing.io, staging).files);
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().openDir(testing.io, staging, .{}));
        try testing.expectEqual(@as(?u64, null), lhist.Index.peekFloor(testing.io, staging));
    }
    // A removal that ended after CURRENT (the first file to go): what is left is no floor
    // witness and no watermark, and the index clears it when it opens.
    try Fill.go(staging);
    {
        var d = try Io.Dir.cwd().openDir(testing.io, staging, .{});
        defer d.close(testing.io);
        try d.deleteFile(testing.io, "CURRENT");
    }
    try testing.expectEqual(@as(?u64, null), lhist.Index.peekFloor(testing.io, staging));
    try testing.expect(lhfill.stagingUse(testing.io, staging).bytes > 4096);
    {
        const st = try lhist.Index.openStaging(gpa, testing.io, staging);
        defer st.deinit();
        try testing.expectEqual(@as(?u64, null), st.indexedHi());
    }
    try testing.expect(lhfill.stagingUse(testing.io, staging).bytes < use.bytes);
    // something that is not a directory at the path (an operator's stand-in): an error, not a crash
    const file_path = try std.fmt.allocPrint(gpa, "{s}/notdir", .{root_dir});
    defer gpa.free(file_path);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "notdir", .data = "" });
    {
        const r = lhfill.removeStaging(testing.io, file_path, null);
        try testing.expect(!r.done and r.err != null);
        try testing.expectEqual(@as(u64, 0), lhfill.stagingUse(testing.io, file_path).bytes);
    }
}
