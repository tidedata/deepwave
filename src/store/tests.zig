//! Unit tests of the engine on the simulated disk (fast, deterministic) and on real files.
const std = @import("std");
const root = @import("root.zig");
const Store = root.Store;
const SimIo = root.sim.SimIo;

fn idOf(n: u64) [32]u8 {
    var id: [32]u8 = @splat(0);
    std.mem.writeInt(u64, id[24..32], n, .big);
    return id;
}

fn smallCfg() root.Config {
    return .{
        .max_live_objects = 1024,
        .max_object_versions = 4096,
        .max_transactions = 1024,
        .max_checkpoints = 1024,
        .max_batch_bytes = 1 << 20,
        .max_batch_objects = 256,
        .max_segments = 64,
        .index_flush_interval = 8,
        .segment_reserve = 8 << 20,
        .seed = 99,
    };
}

fn put(b: *root.Batch, n: u64, version: u64, payload: []const u8) !void {
    var d: [32]u8 = @splat(@intCast(version & 0xff));
    d[0] = @intCast(n & 0xff);
    try b.putObject(&idOf(n), version, &d, payload);
}

test "commit, read, reopen, MVCC" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 7, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);

    var b = try s.begin(10, 1);
    try b.checkpoint("summary-10", "contents-10");
    const txd: [32]u8 = @splat(0xab);
    const efd: [32]u8 = @splat(0xcd);
    try b.transaction(&txd, &efd, "tx", "fx", "ev");
    try put(b, 1, 5, "obj1-v5");
    try put(b, 2, 3, "obj2-v3");
    try put(b, 1, 6, "obj1-v6");
    try s.commit(b);

    var old = s.snapshot();
    b = try s.begin(11, 1);
    try b.checkpoint("summary-11", "");
    try put(b, 1, 7, "obj1-v7");
    try b.removeObject(&idOf(2), 4, .wrapped);
    try s.commit(b);

    // the old snapshot still sees checkpoint 10's state
    try std.testing.expectEqualStrings("obj1-v6", old.liveObject(&idOf(1)).?.bytes);
    try std.testing.expectEqualStrings("obj2-v3", old.liveObject(&idOf(2)).?.bytes);
    try std.testing.expect(old.checkpoint(11) == null);
    old.release();

    var snap = s.snapshot();
    try std.testing.expectEqual(@as(?u64, 11), snap.highestCommitted());
    const o1 = snap.liveObject(&idOf(1)).?;
    try std.testing.expectEqual(@as(u64, 7), o1.version);
    try std.testing.expectEqualStrings("obj1-v7", o1.bytes);
    try std.testing.expect(snap.liveObject(&idOf(2)) == null);
    const l2 = (try snap.latest(&idOf(2))).?;
    try std.testing.expectEqual(root.RemoveKind.wrapped, l2.removed.kind);
    try std.testing.expectEqualStrings("obj1-v5", snap.objectAt(&idOf(1), 5).?);
    try std.testing.expectEqualStrings("obj1-v6", snap.objectAt(&idOf(1), 6).?);
    try std.testing.expect(snap.objectAt(&idOf(1), 4) == null);
    const t = snap.transaction(&txd).?;
    try std.testing.expectEqualStrings("tx", t.tx);
    try std.testing.expectEqualStrings("fx", t.effects);
    try std.testing.expectEqualStrings("ev", t.events.?);
    try std.testing.expectEqual(@as(u64, 10), t.checkpoint);
    const c = snap.checkpoint(10).?;
    try std.testing.expectEqualStrings("summary-10", c.summary_cert);
    try std.testing.expectEqualStrings("contents-10", c.contents);
    snap.release();

    // crash with nothing in flight: everything committed survives
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    snap = s.snapshot();
    try std.testing.expectEqual(@as(?u64, 11), snap.highestCommitted());
    try std.testing.expectEqualStrings("obj1-v7", snap.liveObject(&idOf(1)).?.bytes);
    try std.testing.expectEqualStrings("obj1-v5", snap.objectAt(&idOf(1), 5).?);
    try std.testing.expectEqualStrings("summary-11", snap.checkpoint(11).?.summary_cert);
    snap.release();
    try s.close();

    // clean close then reopen replays nothing
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expectEqual(@as(u64, 0), s.stats.replayed_groups);
    try std.testing.expectEqual(@as(?u64, 11), s.committed());
    s.deinit();
}

test "stats.open_clean: true only when the open found a clean close (the live table's page check is skipped)" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 21, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expect(!s.stats.open_clean); // a new store
    var b = try s.begin(10, 1);
    try b.checkpoint("summary-10", "");
    try put(b, 1, 5, "obj1-v5");
    try s.commit(b);
    try s.flushIndex();
    // the process ends without a close (a kill, the stop deadline): the next open checks the table
    s.deinit();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expect(!s.stats.open_clean);
    try std.testing.expectEqual(@as(?u64, 10), s.committed());
    try s.close();
    // a clean close: nothing replayed, no page check
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expect(s.stats.open_clean);
    try std.testing.expectEqual(@as(u64, 0), s.stats.replayed_groups);
    // written to and flushed again, then ended without a close: checked again
    b = try s.begin(11, 1);
    try b.checkpoint("summary-11", "");
    try put(b, 1, 6, "obj1-v6");
    try s.commit(b);
    try s.flushIndex();
    s.deinit();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expect(!s.stats.open_clean);
    try std.testing.expectEqual(@as(?u64, 11), s.committed());
    s.deinit();
}

test "epochs, pruning, carry-forward" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 8, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var seq: u64 = 0;
    var epoch: u64 = 0;
    while (epoch < 5) : (epoch += 1) {
        for (0..3) |_| {
            seq += 1;
            const b = try s.begin(seq, epoch);
            try b.checkpoint("s", "c");
            try put(b, 100 + epoch, seq, "per-epoch");
            try put(b, 1, seq, "hot");
            if (epoch == 0) try put(b, 7, seq, "cold"); // last written in epoch 0
            try s.commit(b);
        }
    }
    const b = try s.begin(seq + 1, 4);
    try b.removeObject(&idOf(100), seq + 1, .deleted);
    try s.commit(b);
    seq += 1;
    const rep = try s.pruneBefore(3);
    try std.testing.expectEqual(@as(u64, 3), rep.segments_dropped);
    // live in dropped segments: object 7 (epoch 0), 101, 102. 100 was deleted in epoch 4.
    try std.testing.expectEqual(@as(u64, 3), rep.objects_carried);
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqualStrings("cold", snap.liveObject(&idOf(7)).?.bytes);
    try std.testing.expectEqualStrings("per-epoch", snap.liveObject(&idOf(101)).?.bytes);
    try std.testing.expect(snap.liveObject(&idOf(100)) == null);
    try std.testing.expect(snap.checkpoint(1) == null);
    try std.testing.expect(snap.checkpoint(10) != null);
    try std.testing.expect(snap.objectAt(&idOf(1), 2) == null);
    try std.testing.expectEqualStrings("hot", snap.objectAt(&idOf(1), 12).?);
    try std.testing.expectEqualStrings("cold", snap.objectAt(&idOf(7), 3).?);
}

test "real files: write, reopen, prune" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var cfg = smallCfg();
    cfg.dir = path_buf[0..n];
    {
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        var seq: u64 = 0;
        for (0..4) |e| for (0..5) |_| {
            seq += 1;
            const b = try h.store.begin(seq, e);
            try b.checkpoint("summary", "contents");
            try put(b, seq % 7, seq, "payload");
            try h.store.commit(b);
        };
        _ = try h.store.pruneBefore(2);
        try h.store.close();
    }
    {
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        var snap = h.store.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 20), snap.highestCommitted());
        for (0..7) |k| try std.testing.expect(snap.liveObject(&idOf(k)) != null);
        try std.testing.expect(snap.checkpoint(3) == null);
        try std.testing.expect(snap.checkpoint(11) != null);
    }
}

test "real files: background flushes with parallel direct writers keep the table coherent (every value, after drops, close and reopen)" {
    // On Linux this takes the O_DIRECT path (flush_writers, one fdatasync, drops after it):
    // a stale page-cache page behind a dropped private copy would read an old location here.
    try parallelFlushCoherence(true);
}

test "real files: background flushes with parallel buffered writers keep the table coherent (every value, after drops, close and reopen)" {
    // Buffered writers on their own slices, write-back as they go, drops right after each run.
    try parallelFlushCoherence(false);
}

fn parallelFlushCoherence(direct: bool) !void {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var cfg = smallCfg();
    cfg.dir = path_buf[0..n];
    cfg.max_live_objects = 1 << 16;
    cfg.max_object_versions = 1 << 16;
    cfg.max_batch_objects = 4096;
    cfg.max_batch_bytes = 4 << 20;
    cfg.max_segments = 256;
    cfg.index_flush_interval = 1 << 20;
    cfg.max_dirty_pages = 256;
    cfg.flush_writers = 8;
    cfg.flush_direct = direct;
    const objs: u64 = 20_000;
    const rounds: u64 = 24;
    var last: [objs]u16 = @splat(0);
    var seq: u64 = 0;
    var pay: [32]u8 = undefined;
    {
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        errdefer h.store.deinit();
        var rng: std.Random.DefaultPrng = .init(7);
        for (0..rounds) |r| {
            seq += 1;
            const b = try h.store.begin(seq, 0);
            try b.checkpoint("s", "c");
            // 3,000 random objects per round: dirty pages scattered over the table.
            for (0..3000) |_| {
                const k = rng.random().uintLessThan(u64, objs) + 1;
                last[k - 1] = @intCast(r + 1);
                try put(b, k, seq, std.fmt.bufPrint(&pay, "{d}:{d}", .{ k, r + 1 }) catch unreachable);
            }
            try h.store.commit(b);
            var snap = h.store.snapshot();
            defer snap.release();
            for (0..objs) |i| if (last[i] != 0) {
                const want = std.fmt.bufPrint(&pay, "{d}:{d}", .{ i + 1, last[i] }) catch unreachable;
                try std.testing.expectEqualStrings(want, snap.liveObject(&idOf(i + 1)).?.bytes);
            };
        }
        // The flush counters move when the writer takes a finished flush's result: at a later
        // commit, or here. The first background flush starts at the first commit (it dirties
        // more than max_dirty_pages) and is a parallel one (more than 128 pages), whatever
        // the scheduling; but on a busy disk it can still be running after the last commit,
        // and then nothing was counted yet (the store lane failed here once on a shared disk,
        // with nothing printed). So its result is taken before the counters are read.
        try h.store.waitFlush();
        const fs = &h.store.stats;
        try flushStat(fs.index_flushes > 0, "a flush was taken (index_flushes > 0)", fs);
        try flushStat(fs.flush_parallel > 0, "a flush wrote with parallel writers and synced (flush_parallel > 0)", fs);
        if (direct and @import("builtin").os.tag == .linux) try flushStat(fs.flush_direct > 0, "a parallel flush wrote unbuffered (flush_direct > 0; the file system must take O_DIRECT)", fs);
        if (!direct) try flushStat(fs.flush_direct == 0, "no flush wrote unbuffered (flush_direct == 0)", fs);
        try h.store.close();
    }
    {
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        try flushStat(!h.store.stats.rebuilt_index, "the reopen after a clean close did not rebuild the index (!rebuilt_index)", &h.store.stats);
        var snap = h.store.snapshot();
        defer snap.release();
        for (0..objs) |i| if (last[i] != 0) {
            const want = std.fmt.bufPrint(&pay, "{d}:{d}", .{ i + 1, last[i] }) catch unreachable;
            try std.testing.expectEqualStrings(want, snap.liveObject(&idOf(i + 1)).?.bytes);
        };
    }
}

/// `parallelFlushCoherence`: a condition on the flush statistics, with the statistics printed
/// when it does not hold.
fn flushStat(ok: bool, what: []const u8, st: *const root.Stats) !void {
    if (ok) return;
    std.debug.print("parallel flush test: expected that {s}; index_flushes {d}, flush_bg {d}, flush_parallel {d}, flush_direct {d}, flush_runs {d}, flush_last_pages {d}, flush_wait_ns {d}, rebuilt_index {}\n", .{ what, st.index_flushes, st.flush_bg, st.flush_parallel, st.flush_direct, st.flush_runs, st.flush_last_pages, st.flush_wait_ns, st.rebuilt_index });
    return error.TestUnexpectedResult;
}

test "carry-forward fills many groups to the brim" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 9, .{}, 32 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.max_batch_bytes = 16 << 10;
    cfg.max_live_objects = 8192;
    cfg.max_object_versions = 16384;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var payload: [700]u8 = undefined;
    for (&payload, 0..) |*x, i| x.* = @truncate(i);
    var n: u64 = 0;
    for (0..40) |k| {
        const b = try s.begin(k + 1, 0);
        for (0..12) |j| {
            n += 1;
            // varying sizes so groups end at every alignment
            try put(b, n, k + 1, payload[0 .. (n * 37 + j) % payload.len]);
        }
        try s.commit(b);
    }
    const b = try s.begin(41, 1);
    try b.checkpoint("s", "c");
    try s.commit(b);
    const rep = try s.pruneBefore(1);
    try std.testing.expectEqual(n, rep.objects_carried);
    var snap = s.snapshot();
    defer snap.release();
    var i: u64 = 1;
    while (i <= n) : (i += 1) {
        const o = snap.liveObject(&idOf(i)).?;
        try std.testing.expectEqual(@as(usize, (i * 37 + (i - 1) % 12) % payload.len), o.bytes.len);
    }
}

test "a segment grows past 4x its initial mapping; every record reads back, also after a crash" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 12, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.segment_reserve = 64 << 10;
    cfg.max_batch_bytes = 64 << 10;
    cfg.compress = false; // mmap growth of raw segments
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    var big: [20_000]u8 = undefined;
    const n: u64 = 64; // ~1.3 MiB in one epoch: 20x the initial mapping
    var seq: u64 = 0;
    // A snapshot held across the remaps keeps its zero-copy view valid.
    var held: ?root.Snapshot = null;
    var held_bytes: []const u8 = &.{};
    while (seq < n) : (seq += 1) {
        @memset(&big, @truncate(seq));
        const b = try s.begin(seq, 1);
        try put(b, seq, seq + 1, &big);
        try s.commit(b);
        if (seq == 2) {
            held = s.snapshot();
            held_bytes = held.?.liveObject(&idOf(1)).?.bytes;
        }
    }
    try std.testing.expect(s.stats.segment_remaps >= 4);
    try std.testing.expect(std.mem.allEqual(u8, held_bytes, 1));
    held.?.release();
    var snap = s.snapshot();
    for (0..n) |k| {
        @memset(&big, @truncate(k));
        try std.testing.expectEqualSlices(u8, &big, snap.liveObject(&idOf(k)).?.bytes);
    }
    snap.release();
    s.deinit();
    sim.crash();
    // Reopen with an even smaller reservation: everything durable is still mapped.
    cfg.segment_reserve = 4096;
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(?u64, n - 1), snap.highestCommitted());
    for (0..n) |k| {
        @memset(&big, @truncate(k));
        try std.testing.expectEqualSlices(u8, &big, snap.liveObject(&idOf(k)).?.bytes);
        try std.testing.expectEqualSlices(u8, &big, snap.objectAt(&idOf(k), k + 1).?);
    }
}

test "a failed group write poisons the store" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 13, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var b = try s.begin(1, 1);
    try b.checkpoint("s", "c");
    try s.commit(b);
    b = try s.begin(2, 1);
    try b.checkpoint("s", "c");
    sim.scheduleCrash(0);
    try std.testing.expectError(error.Crashed, s.commit(b));
    try std.testing.expectError(error.Poisoned, s.begin(3, 1));
}

test "index capacity is bounded by retention, not by history" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 15, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.max_live_objects = 64;
    cfg.max_object_versions = 256;
    cfg.max_transactions = 256;
    cfg.max_checkpoints = 64;
    cfg.max_batch_objects = 64;
    cfg.retention_epochs = 2;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var seq: u64 = 0;
    var version: u64 = 0;
    var epoch: u64 = 0;
    while (epoch < 100) : (epoch += 1) {
        for (0..8) |_| {
            const b = try s.begin(seq, epoch);
            try b.checkpoint("summary", "contents");
            var txd: [32]u8 = @splat(0);
            std.mem.writeInt(u64, txd[0..8], seq *% 0x9e3779b97f4a7c15 +% 1, .little);
            const efd: [32]u8 = @splat(7);
            try b.transaction(&txd, &efd, "tx", "fx", null);
            for (0..4) |k| {
                version += 1;
                try put(b, (seq * 4 + k) % 16, version, "v");
            }
            try s.commit(b);
            seq += 1;
        }
        _ = try s.pruneRetained();
        // Only the retained epochs' runs exist, and the live index holds the 16 ids.
        try std.testing.expectEqual(@as(u64, 16), s.liveSlots().used);
    }
    try std.testing.expectEqual(@as(u64, 0), s.stats.live_grows);
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expect(snap.checkpoint(seq - 1) != null);
    try std.testing.expect(snap.checkpoint(8) == null);
    for (0..16) |k| try std.testing.expect(snap.liveObject(&idOf(k)) != null);
}

test "the live index grows past its initial capacity and survives crashes" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 16, .{}, 16 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.max_live_objects = 32;
    cfg.max_object_versions = 8192;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    var seq: u64 = 0;
    var n: u64 = 0;
    while (n < 3000) : (seq += 1) {
        const b = try s.begin(seq, seq / 40);
        for (0..30) |_| {
            try put(b, n, n + 1, "grow");
            n += 1;
        }
        if (seq % 7 == 3) try b.removeObject(&idOf(n - 5), n + 1, .deleted);
        try s.commit(b);
        if (seq % 23 == 0) {
            s.deinit();
            sim.crash();
            s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        }
    }
    try std.testing.expect(s.liveSlots().capacity > 3000);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expect(s.stats.live_grows == 0); // grown before the last crash, loaded as is
    for (0..n) |k| {
        const got = (try snap.latest(&idOf(k))).?;
        switch (got) {
            .live => |o| try std.testing.expectEqualStrings("grow", o.bytes),
            .removed => {},
        }
    }
}

test "lost index files are rebuilt from the logs" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 17, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    // A memtable holds 5 checkpoints: 24 checkpoints seal 4 runs (spanning epoch changes).
    cfg.max_checkpoints = 5;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    var seq: u64 = 0;
    for (0..4) |e| for (0..6) |_| {
        seq += 1;
        const b = try s.begin(seq, e);
        try b.checkpoint("summary", "contents");
        var txd: [32]u8 = @splat(@truncate(seq));
        txd[31] = 0xee;
        try b.transaction(&txd, &txd, "tx", "fx", "ev");
        try put(b, seq % 9, seq, "payload");
        try s.commit(b);
    };
    try s.close();
    const names = try sim.listDir(gpa, "index");
    defer {
        for (names) |x| gpa.free(x);
        gpa.free(names);
    }
    try std.testing.expect(names.len >= 4);
    for (names) |x| {
        var nb: [96]u8 = undefined;
        try sim.remove(try std.fmt.bufPrint(&nb, "index/{s}", .{x}));
    }
    try sim.syncDir();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try std.testing.expect(s.stats.rebuilt_index);
    try std.testing.expect(s.stats.rebuilt_runs >= 3);
    var snap = s.snapshot();
    defer snap.release();
    for (1..seq + 1) |q| {
        try std.testing.expectEqualStrings("summary", snap.checkpoint(q).?.summary_cert);
        var txd: [32]u8 = @splat(@truncate(q));
        txd[31] = 0xee;
        try std.testing.expectEqualStrings("ev", snap.transaction(&txd).?.events.?);
        try std.testing.expectEqualStrings("payload", snap.objectAt(&idOf(q % 9), q).?);
    }
}

test "a crash at every step of an index flush recovers the same state" {
    const gpa = std.testing.allocator;
    var k: u64 = 0;
    while (k < 40) : (k += 1) {
        const sim = try SimIo.init(gpa, 100 + k, .{}, 8 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.index_flush_interval = 1 << 30;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (1..30) |q| {
            const b = try s.begin(q, q / 10);
            try b.checkpoint("s", "c");
            try put(b, q % 11, q, "x");
            if (q % 4 == 0) try b.removeObject(&idOf((q + 3) % 11), q, .wrapped);
            try s.commit(b);
            if (q == 12) try s.flushIndex();
        }
        sim.scheduleCrash(k);
        const r = s.flushIndex();
        s.deinit();
        sim.crash();
        if (r) |_| {} else |e| try std.testing.expectEqual(error.Crashed, e);
        s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 29), snap.highestCommitted());
        for (0..11) |id| {
            // newest write of id among q in 1..29 (puts and removes)
            var want: ?u64 = null;
            var removed = false;
            for (1..30) |q| {
                if (q % 11 == id) {
                    want = q;
                    removed = false;
                }
                if (q % 4 == 0 and (q + 3) % 11 == id) {
                    want = q;
                    removed = true;
                }
            }
            const got = try snap.latest(&idOf(id));
            if (want) |v| switch (got.?) {
                .live => |o| {
                    try std.testing.expect(!removed);
                    try std.testing.expectEqual(v, o.version);
                },
                .removed => |x| {
                    try std.testing.expect(removed);
                    try std.testing.expectEqual(v, x.version);
                },
            } else try std.testing.expect(got == null);
        }
    }
}

fn flushModelCheck(s: *Store, upto: u64) !void {
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(?u64, upto), snap.highestCommitted());
    for (0..11) |id| {
        var want: ?u64 = null;
        var removed = false;
        for (1..upto + 1) |q| {
            if (q % 11 == id) {
                want = q;
                removed = false;
            }
            if (q % 4 == 0 and (q + 3) % 11 == id) {
                want = q;
                removed = true;
            }
        }
        const got = try snap.latest(&idOf(id));
        if (want) |v| switch (got.?) {
            .live => |o| {
                try std.testing.expect(!removed);
                try std.testing.expectEqual(v, o.version);
            },
            .removed => |x| {
                try std.testing.expect(removed);
                try std.testing.expectEqual(v, x.version);
            },
        } else try std.testing.expect(got == null);
    }
}

fn flushModelCommit(s: *Store, q: u64) !void {
    const b = try s.begin(q, q / 10);
    try b.checkpoint("s", "c");
    try put(b, q % 11, q, "x");
    if (q % 4 == 0) try b.removeObject(&idOf((q + 3) % 11), q, .wrapped);
    try s.commit(b);
}

test "a flush frozen while commits go on (copy on write): a crash at every flusher step recovers the same state" {
    const gpa = std.testing.allocator;
    var k: u64 = 0;
    var completed: u64 = 0;
    while (k < 60) : (k += 1) {
        const sim = try SimIo.init(gpa, 300 + k, .{}, 8 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.index_flush_interval = 1 << 30;
        cfg.flush_gap_pages = 3;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (1..21) |q| try flushModelCommit(s, q);
        try s.flushIndex();
        for (21..31) |q| try flushModelCommit(s, q);
        // Freeze, then change the frozen pages again before the flusher runs.
        try s.flushBegin();
        for (31..41) |q| try flushModelCommit(s, q);
        try std.testing.expect(s.flush.?.cow.saves > 0);
        sim.scheduleCrash(k);
        s.flushRun();
        const r = s.waitFlush();
        if (r) |_| {
            sim.scheduleCrash(null);
            completed += 1;
            // The table is the one at the freeze plus the later commits, read back exactly.
            try flushModelCheck(s, 40);
            try s.close();
            s = try Store.open(gpa, .{ .sim = sim }, &cfg);
            try std.testing.expect(!s.stats.rebuilt_index);
        } else |e| {
            try std.testing.expectEqual(error.Crashed, e);
            s.deinit();
            sim.crash();
            s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        }
        defer s.deinit();
        try flushModelCheck(s, 40);
    }
    try std.testing.expect(completed > 0 and completed < 60);
}

test "segments without a valid meta: open refuses instead of deleting them" {

    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 14, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    const b = try s.begin(1, 1);
    try b.checkpoint("s", "c");
    try s.commit(b);
    s.deinit();
    try sim.remove("meta");
    try sim.syncDir();
    try std.testing.expectError(error.Corrupt, Store.open(gpa, .{ .sim = sim }, &cfg));
}

test "rot in a live record of a segment being pruned fails the prune, never loses the object silently" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 8, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.compress = false; // flips a byte through the mmap view
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var seq: u64 = 0;
    var epoch: u64 = 0;
    while (epoch < 4) : (epoch += 1) {
        seq += 1;
        const b = try s.begin(seq, epoch);
        try b.checkpoint("s", "c");
        try put(b, 1, seq, "hot");
        if (epoch == 0) try put(b, 7, seq, "cold");
        try s.commit(b);
    }
    {
        var snap = s.snapshot();
        defer snap.release();
        const o = snap.liveObject(&idOf(7)).?;
        // flip one bit of the record's object id (latent sector error)
        const p: [*]u8 = @constCast(o.bytes.ptr);
        (p - 72)[3] ^= 0x10;
    }
    // Without the full check the damaged id misses its live-table entry, the record is not
    // carried, and the object would read as never existing once the segment is gone.
    try std.testing.expectError(error.Corrupt, s.pruneBefore(2));
    try std.testing.expectError(error.Poisoned, s.begin(seq + 1, 3));
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectError(error.Corrupt, snap.latest(&idOf(7)));
    try std.testing.expectEqualStrings("hot", snap.liveObject(&idOf(1)).?.bytes);
}

test "checkpoint digest index and lowest checkpoint follow retention (CONTRACTS 6.8)" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 11, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.lowestCheckpoint() == null);
    }
    // A snapshot-style start: groups 0..2 hold objects only, then the restored checkpoint 40.
    for (0..3) |g| {
        const b = try s.begin(g, 0);
        try put(b, 500 + g, 1, "restored");
        try s.commit(b);
    }
    var seq: u64 = 40;
    var epoch: u64 = 0;
    while (epoch < 5) : (epoch += 1) {
        for (0..4) |_| {
            const b = try s.begin(seq, epoch);
            try b.checkpoint("s", "c");
            try b.checkpointDigest(&idOf(9000 + seq));
            try put(b, 1, seq, "hot");
            try s.commit(b);
            seq += 1;
        }
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 40), snap.lowestCheckpoint());
    }
    var snap0 = s.snapshot();
    try std.testing.expectEqual(@as(?u64, 41), snap0.checkpointByDigest(&idOf(9041)));
    try std.testing.expectEqual(@as(?u64, 59), snap0.checkpointByDigest(&idOf(9059)));
    try std.testing.expect(snap0.checkpointByDigest(&idOf(9060)) == null);
    try std.testing.expect(snap0.checkpointByDigest(&idOf(1)) == null); // an object id is not a checkpoint digest
    snap0.release();
    // Epoch 4 is current: retention 2 keeps epochs 2, 3, 4 (checkpoints 48..59).
    _ = try s.pruneRetained();
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(?u64, 48), snap.lowestCheckpoint());
    try std.testing.expect(snap.checkpointByDigest(&idOf(9047)) == null);
    try std.testing.expectEqual(@as(?u64, 48), snap.checkpointByDigest(&idOf(9048)));
    try std.testing.expectEqualStrings("restored", snap.liveObject(&idOf(501)).?.bytes); // carried forward
}

// ------------------------------------------------------------------ liveness retention

/// Test objects: id (32) ++ version (u64 le) ++ payload, parsed by `testCodec`.
fn tObj(buf: []u8, n: u64, version: u64, payload: []const u8) []const u8 {
    buf[0..32].* = idOf(n);
    std.mem.writeInt(u64, buf[32..40], version, .little);
    @memcpy(buf[40..][0..payload.len], payload);
    return buf[0 .. 40 + payload.len];
}

fn tKey(bytes: []const u8) ?root.ObjKey {
    if (bytes.len < 40) return null;
    return .{ .id = bytes[0..32].*, .version = std.mem.readInt(u64, bytes[32..40], .little) };
}

const testCodec: root.Codec = .{ .key = tKey };

fn putT(b: *root.Batch, base: bool, n: u64, version: u64, payload: []const u8) !void {
    var buf: [256]u8 = undefined;
    const bytes = tObj(&buf, n, version, payload);
    const d = root.objectDigest(bytes);
    if (base) try b.putBase(&idOf(n), version, &d, bytes) else try b.putObject(&idOf(n), version, &d, bytes);
}

fn expectObj(snap: *const root.Snapshot, n: u64, version: u64) !void {
    const o = snap.liveObject(&idOf(n)) orelse return error.TestMissingObject;
    try std.testing.expectEqual(version, o.version);
    try std.testing.expectEqual(root.objectDigest(o.bytes), o.digest);
    try std.testing.expectEqualSlices(u8, &idOf(n), o.bytes[0..32]);
}

test "liveness retention: compact base stays in place, sparse segments are cleaned, reopen and rebuild" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 21, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    cfg.clean_record_bytes = 64;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);

    // Epoch 0: a restored live set of 200 objects in compact records, then the restored
    // checkpoint 40.
    for (0..2) |g| {
        const b = try s.begin(g, 0);
        for (0..100) |i| try putT(b, true, 1000 + g * 100 + i, 3, "base-object-bytes");
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 0);
        try b.checkpoint("s40", "c");
        try s.commit(b);
    }
    const base_loc = s.liveLocation(&idOf(1050)).?;
    try std.testing.expectEqual(@as(u64, 0), s.curMemVersions());
    {
        var snap = s.snapshot();
        defer snap.release();
        try expectObj(&snap, 1050, 3);
        try std.testing.expect(snap.objectAt(&idOf(1050), 3) != null);
        // The live-object iterator sees exactly the restored set, split over 3 parts.
        var seen: usize = 0;
        for (0..3) |p| {
            var it = snap.liveIter(p, 3);
            defer it.deinit();
            while (try it.next()) |o| {
                try std.testing.expectEqual(@as(u64, 3), o.version);
                try std.testing.expectEqual(root.objectDigest(o.bytes), o.digest());
                seen += 1;
            }
        }
        try std.testing.expectEqual(@as(usize, 200), seen);
    }

    // Epochs 1..4, three checkpoints each. Epoch 1 touches base objects 1000..1009 and creates
    // 2000..2019; epoch 2 updates 2000..2014 again, so epoch 1's segment is mostly dead.
    var seq: u64 = 41;
    var epoch: u64 = 1;
    while (epoch <= 4) : (epoch += 1) {
        for (0..3) |c| {
            const b = try s.begin(seq, epoch);
            try b.checkpoint("s", "c");
            try b.checkpointDigest(&idOf(9000 + seq));
            try putT(b, false, 1, seq, "hot");
            if (epoch == 1 and c == 0) {
                for (0..10) |i| try putT(b, false, 1000 + i, seq, "touched");
                for (0..20) |i| try putT(b, false, 2000 + i, seq, "new");
            }
            if (epoch == 2 and c == 0) for (0..15) |i| try putT(b, false, 2000 + i, seq, "again");
            try s.commit(b);
            seq += 1;
        }
        if (epoch == 4) break;
    }
    {
        // A superseded restored version is indexed by its link record (and the newer
        // record's previous link reaches it too).
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.objectAt(&idOf(1005), 3) != null);
        try std.testing.expect(snap.objectAt(&idOf(1004), 3) != null);
        try std.testing.expect(snap.objectAt(&idOf(1005), 2) == null);
        try std.testing.expect(snap.objectAt(&idOf(1005), 41) != null);
    }
    // Epoch 4 is current (checkpoints 50..52): the window keeps 2, 3, 4 (44..52); 0 and 1 age out.
    const rep = try s.ageRetained();
    try std.testing.expectEqual(@as(u64, 2), rep.segments_aged);
    try std.testing.expectEqual(@as(u64, 0), rep.objects_carried);
    try std.testing.expectEqual(@as(u64, 2), s.agedSegments().count);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 44), snap.lowestCheckpoint());
        try std.testing.expect(snap.checkpoint(43) == null);
        try std.testing.expect(snap.checkpointByDigest(&idOf(9043)) == null);
        try std.testing.expectEqual(@as(?u64, 44), snap.checkpointByDigest(&idOf(9044)));
        // Old object versions left the window; live ones in aged segments did not move.
        try std.testing.expect(snap.objectAt(&idOf(1), 41) == null);
        try std.testing.expect(snap.objectAt(&idOf(1), 52) != null);
        try expectObj(&snap, 1050, 3);
        try std.testing.expect(snap.objectAt(&idOf(1050), 3) != null);
        try expectObj(&snap, 1005, 41);
        try expectObj(&snap, 2017, 41);
        try expectObj(&snap, 2003, 44);
        // Nothing is asserted here about object 1005's restored version 3 (superseded in epoch
        // 1, which aged out): its link is still in the memtable, which nothing has sealed in a
        // store this small, and a memtable entry counts as the newest epoch's, the epoch its
        // run will get. The two link tests seal first and check that the version is gone.
    }
    try std.testing.expectEqual(base_loc, s.liveLocation(&idOf(1050)).?);

    // Cleaning, between checkpoints: epoch 1 (15 live of 34 written) goes, epoch 0 stays.
    var carried: u64 = 0;
    var dropped: u64 = 0;
    var steps: usize = 0;
    while (true) : (steps += 1) {
        try std.testing.expect(steps < 1000);
        const r = try s.cleanStep(8192);
        carried += r.objects_carried;
        dropped += r.segments_dropped;
        if (r.idle) break;
        const b = try s.begin(seq, 4);
        try b.checkpoint("s", "c");
        try putT(b, false, 1, seq, "hot");
        try s.commit(b);
        seq += 1;
    }
    try std.testing.expectEqual(@as(u64, 1), dropped);
    try std.testing.expectEqual(@as(u64, 15), carried);
    try std.testing.expectEqual(@as(u64, 1), s.agedSegments().count);
    try std.testing.expectEqual(base_loc, s.liveLocation(&idOf(1050)).?);
    try std.testing.expectEqual(@as(u64, 4), root.format.epochOf(s.liveLocation(&idOf(2017)).?));
    {
        var snap = s.snapshot();
        defer snap.release();
        try expectObj(&snap, 2017, 41);
        try expectObj(&snap, 1005, 41);
        try expectObj(&snap, 1150, 3);
    }
    s.deinit();

    // Reopen: the aged base segment is still there and still serves its objects.
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expectEqual(@as(u64, 1), s.agedSegments().count);
    {
        var snap = s.snapshot();
        defer snap.release();
        try expectObj(&snap, 1050, 3);
        try expectObj(&snap, 2017, 41);
        try std.testing.expect(snap.checkpoint(43) == null);
        try std.testing.expectEqual(@as(?u64, 44), snap.lowestCheckpoint());
    }
    const live_before = s.liveCount();
    s.deinit();

    // Rebuild the live table from the logs (aged segment included).
    {
        const names = try sim.listDir(gpa, "index");
        defer {
            for (names) |x| gpa.free(x);
            gpa.free(names);
        }
        for (names) |x| {
            var nb: [96]u8 = undefined;
            try sim.remove(try std.fmt.bufPrint(&nb, "index/{s}", .{x}));
        }
        try sim.syncDir();
    }
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try std.testing.expect(s.stats.rebuilt_index);
    try std.testing.expectEqual(live_before, s.liveCount());
    var snap = s.snapshot();
    defer snap.release();
    for (0..200) |i| try std.testing.expect(snap.liveObject(&idOf(1000 + i)) != null);
    try expectObj(&snap, 2017, 41);
    try expectObj(&snap, 2003, 44);
    try std.testing.expect(snap.checkpoint(43) == null);
}

test "compact records need the codec" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 22, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    // Without a codec putBase writes full records.
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    {
        const b = try s.begin(0, 0);
        try putT(b, true, 7, 2, "x");
        try s.commit(b);
    }
    {
        var snap = s.snapshot();
        defer snap.release();
        try expectObj(&snap, 7, 2);
    }
    s.deinit();
    cfg.codec = testCodec;
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    const b = try s.begin(1, 0);
    try putT(b, true, 8, 5, "y");
    try s.commit(b);
    var snap = s.snapshot();
    defer snap.release();
    try expectObj(&snap, 7, 2);
    try expectObj(&snap, 8, 5);
}

test "a superseded compact version is found by its link past the chain bound" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 23, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    {
        const b = try s.begin(0, 0);
        try putT(b, true, 5, 1, "base");
        try s.commit(b);
    }
    for (0..80) |i| {
        const b = try s.begin(1 + i, 0);
        try b.checkpoint("s", "c");
        try putT(b, false, 5, 2 + i, "hot");
        try s.commit(b);
    }
    var snap = s.snapshot();
    defer snap.release();
    const o = snap.objectAtChecked(&idOf(5), 1) catch unreachable orelse return error.TestMissingObject;
    try std.testing.expectEqual(@as(u64, 1), o.version);
    try std.testing.expectEqual(root.objectDigest(o.bytes), o.digest);
    try std.testing.expect(snap.objectAt(&idOf(5), 40) != null);
    try std.testing.expect(snap.objectAt(&idOf(5), 0) == null);
}

test "a tombstone in a cleaned segment is carried while an older aged segment remains, so a rebuild keeps the object deleted" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 24, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    cfg.clean_record_bytes = 64;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);

    // Epoch 0: a dense restored set (never cleaned), then its end-of-epoch checkpoint 40.
    for (0..2) |g| {
        const b = try s.begin(g, 0);
        for (0..100) |i| try putT(b, true, 1000 + g * 100 + i, 3, "base-object-bytes");
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 0);
        try b.checkpoint("s40", "c");
        try s.commit(b);
    }
    // Epoch 1: restored 1000 is deleted and 1001 wrapped (their tombstones are the live
    // entries), 1002 mutated; 20 new objects that epoch 2 supersedes, so epoch 1 is sparse.
    var seq: u64 = 41;
    {
        const b = try s.begin(seq, 1);
        try b.checkpoint("s", "c");
        try b.removeObject(&idOf(1000), 41, .deleted);
        try b.removeObject(&idOf(1001), 41, .wrapped);
        try putT(b, false, 1002, 41, "mutated");
        for (0..20) |i| try putT(b, false, 2000 + i, 41, "new");
        try s.commit(b);
        seq += 1;
    }
    var epoch: u64 = 2;
    while (epoch <= 4) : (epoch += 1) {
        const b = try s.begin(seq, epoch);
        try b.checkpoint("s", "c");
        try putT(b, false, 1, seq, "hot");
        if (epoch == 2) for (0..20) |i| try putT(b, false, 2000 + i, seq, "again");
        try s.commit(b);
        seq += 1;
    }
    _ = try s.ageRetained(); // window 2..4: epochs 0 and 1 age out
    try std.testing.expectEqual(@as(u64, 2), s.agedSegments().count);
    var carried_tombs: u64 = 0;
    var dropped_tombs: u64 = 0;
    var segs: u64 = 0;
    var steps: usize = 0;
    while (true) : (steps += 1) {
        try std.testing.expect(steps < 1000);
        const r = try s.cleanStep(8192);
        carried_tombs += r.tombstones_carried;
        dropped_tombs += r.tombstones_dropped;
        segs += r.segments_dropped;
        if (r.idle) break;
        const b = try s.begin(seq, 4);
        try b.checkpoint("s", "c");
        try putT(b, false, 1, seq, "hot");
        try s.commit(b);
        seq += 1;
    }
    // Epoch 1 was cleaned out of order (epoch 0 stays): its two tombstones were carried.
    try std.testing.expectEqual(@as(u64, 1), segs);
    try std.testing.expectEqual(@as(u64, 2), carried_tombs);
    try std.testing.expectEqual(@as(u64, 0), dropped_tombs);
    try std.testing.expectEqual(@as(u64, 1), s.agedSegments().count);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.liveObject(&idOf(1000)) == null);
        try std.testing.expect(snap.liveObject(&idOf(1001)) == null);
        const g = (try snap.latest(&idOf(1001))).?;
        try std.testing.expectEqual(root.RemoveKind.wrapped, g.removed.kind);
        try expectObj(&snap, 1002, 41);
        try expectObj(&snap, 1003, 3);
    }
    const live_before = s.liveCount();
    s.deinit();

    // Lose the index: the rebuild replays the aged epoch-0 segment first (restored 1000 and
    // 1001 look live there), then the carried tombstones delete them again.
    {
        const names = try sim.listDir(gpa, "index");
        defer {
            for (names) |x| gpa.free(x);
            gpa.free(names);
        }
        for (names) |x| {
            var nb: [96]u8 = undefined;
            try sim.remove(try std.fmt.bufPrint(&nb, "index/{s}", .{x}));
        }
        try sim.syncDir();
    }
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try std.testing.expect(s.stats.rebuilt_index);
    try std.testing.expectEqual(live_before, s.liveCount());
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expect(snap.liveObject(&idOf(1000)) == null);
    try std.testing.expect(snap.liveObject(&idOf(1001)) == null);
    try expectObj(&snap, 1002, 41);
    try expectObj(&snap, 1003, 3);
    try expectObj(&snap, 2005, 42);
    var n: usize = 0;
    var it = snap.liveIter(0, 1);
    defer it.deinit();
    while (try it.next()) |o| {
        try std.testing.expect(!std.mem.eql(u8, &o.id, &idOf(1000)) and !std.mem.eql(u8, &o.id, &idOf(1001)));
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 198 + 20 + 1), n);
    // forEachLive (location order) visits the same objects at the same versions as liveIter (slot order).
    const Sum = struct {
        n: usize = 0,
        ver: u64 = 0,
        ids: u64 = 0,
        fn add(x: *@This(), id: *const [32]u8, version: u64) void {
            x.n += 1;
            x.ver +%= version;
            x.ids +%= std.hash.Wyhash.hash(0, id) ^ version;
        }
    };
    var a: Sum = .{};
    var it2 = snap.liveIter(0, 1);
    defer it2.deinit();
    while (try it2.next()) |o| a.add(&o.id, o.version);
    var b: Sum = .{};
    try snap.forEachLive(&b, struct {
        fn each(x: *Sum, id: *const [32]u8, version: u64, _: []const u8) anyerror!void {
            x.add(id, version);
        }
    }.each);
    try std.testing.expectEqual(a, b);
    // liveBounds splits the live set into location ranges that cover it once, in store order.
    for ([_]usize{ 1, 7, 64, 500 }) |parts| {
        const bounds = try snap.liveBounds(gpa, parts);
        defer gpa.free(bounds);
        try std.testing.expectEqual(parts + 1, bounds.len);
        var c: Sum = .{};
        var prev: u64 = 0;
        for (bounds[0..parts], bounds[1..]) |lo, hi| {
            try std.testing.expect(lo <= hi);
            const locs = try snap.liveLocationsIn(gpa, lo, hi);
            defer gpa.free(locs);
            for (locs) |l| {
                try std.testing.expect(l >= prev);
                prev = l;
                if (try snap.liveAt(l)) |o| c.add(&o.id, o.version);
            }
        }
        try std.testing.expectEqual(a, c);
    }
}

test "objectFind reports the record's epoch and whether it is live; highest pruned checkpoint raises the lowest available one" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 25, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    {
        const b = try s.begin(0, 7);
        try putT(b, true, 5, 3, "base");
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 7);
        try b.checkpoint("s40", "c");
        try b.highestPruned(40);
        try s.commit(b);
    }
    {
        var snap = s.snapshot();
        defer snap.release();
        const f = (try snap.objectFind(&idOf(5), 3)).?;
        try std.testing.expect(f.live);
        try std.testing.expectEqual(@as(u64, 7), root.format.epochOf(f.loc));
        try std.testing.expectEqual(@as(?u64, 40), snap.lowestCheckpoint());
        try std.testing.expectEqual(@as(?u64, 40), snap.highestPruned());
        try std.testing.expectEqual(@as(?u64, 41), snap.lowestAvailable());
    }
    {
        const b = try s.begin(41, 8);
        try b.checkpoint("s41", "c");
        try putT(b, false, 5, 41, "next");
        try s.commit(b);
    }
    var snap = s.snapshot();
    defer snap.release();
    const f = (try snap.objectFind(&idOf(5), 3)).?; // through its link
    try std.testing.expect(!f.live);
    try std.testing.expectEqual(@as(u64, 7), root.format.epochOf(f.loc));
    try std.testing.expectEqual(@as(?u64, 41), snap.lowestAvailable());
    try std.testing.expect(snap.liveObject(&@as([32]u8, @splat(0))) == null);
}

test "compressed segments: beside raw ones, with the dir file lost or damaged, every record reads back" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 31, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.compress = false;
    cfg.chunk_bytes = 512;
    var payload: [300]u8 = undefined;
    var seq: u64 = 0;
    var n_obj: u64 = 0;
    for (0..4) |epoch| {
        if (epoch == 2) cfg.compress = true;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (0..20) |_| {
            seq += 1;
            const b = try s.begin(seq, epoch);
            try b.checkpoint("summary", "contents");
            for (0..8) |k| {
                @memset(&payload, @truncate(seq * 31 + k));
                try put(b, n_obj % 100 + 1, seq, &payload);
                n_obj += 1;
            }
            try s.commit(b);
        }
        try s.close();
    }
    {
        var buf: [64]u8 = undefined;
        // Epoch 2: dir file gone. Epoch 3: a damaged entry in the middle.
        try sim.remove(try std.fmt.bufPrint(&buf, "index/{d:0>8}.dir", .{2}));
        const f = try sim.openFile(try std.fmt.bufPrint(&buf, "index/{d:0>8}.dir", .{3}), false);
        try sim.write(f, 64 + 32 * 5 + 3, "xx");
        sim.closeFile(f);
    }
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(?u64, seq), snap.highestCommitted());
    var q: u64 = 1;
    while (q <= seq) : (q += 1) try std.testing.expectEqualStrings("summary", snap.checkpoint(q).?.summary_cert);
    // The live objects are the last writes of ids 1..100.
    for (1..101) |id| {
        const o = snap.liveObject(&idOf(id)).?;
        try std.testing.expectEqual(@as(usize, 300), o.bytes.len);
        try std.testing.expectEqual(@as(?[]const u8, o.bytes), snap.objectAt(&idOf(id), o.version));
    }
    var it = snap.liveIter(0, 1);
    defer it.deinit();
    try std.testing.expect(it.scan != null);
    var count: u64 = 0;
    while (try it.next()) |o| {
        count += 1;
        try std.testing.expectEqualSlices(u8, snap.liveObject(&o.id).?.bytes, o.bytes);
    }
    try std.testing.expectEqual(@as(u64, 100), count);
    try std.testing.expect(s.stats.bytes_appended == 0);
}

test "retention floors: checkpoints by checkpoint, object versions by segment, aging only below both, reopen keeps them" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 21, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    // Epochs 0..3, 4 checkpoints each (0..15): each writes a tx, a cp digest, and versions of
    // object 1 (superseded every checkpoint) and object 100+seq (stays live).
    var seq: u64 = 0;
    while (seq < 16) : (seq += 1) {
        const b = try s.begin(seq, seq / 4);
        try b.checkpoint("s", "c");
        try b.checkpointDigest(&idOf(9000 + seq));
        const txd = idOf(7000 + seq);
        const efd: [32]u8 = @splat(7);
        try b.transaction(&txd, &efd, "tx", "fx", null);
        try put(b, 1, seq + 1, "hot");
        try put(b, 100 + seq, 1, "cold");
        try s.commit(b);
    }
    // sui-node marks: checkpoints pruned to 5 (lowest 6, epoch 1), objects pruned to 9
    // (epoch 2 is the first not fully pruned).
    const rep = try s.setFloors(.{ .cp_pruned = 5, .obj_pruned = 9, .cp_epoch = 1, .obj_epoch = 2 });
    try std.testing.expectEqual(@as(u64, 1), rep.segments_aged); // epoch 0: below both
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 6), snap.lowestCheckpoint());
        try std.testing.expectEqual(@as(?u64, 6), snap.lowestAvailable());
        try std.testing.expect(snap.checkpoint(5) == null);
        try std.testing.expect(snap.checkpoint(6) != null);
        try std.testing.expect(snap.transaction(&idOf(7005)) == null);
        try std.testing.expect(snap.transaction(&idOf(7006)) != null);
        try std.testing.expect(snap.checkpointByDigest(&idOf(9005)) == null);
        try std.testing.expectEqual(@as(?u64, 6), snap.checkpointByDigest(&idOf(9006)));
        // The checkpoint below the floor is still held (retention needs its epoch).
        try std.testing.expectEqual(@as(u64, 1), snap.checkpointHeld(5).?.epoch);
        // Object versions: segment 1 (versions 5..8) is below the object floor, segment 2 is not.
        try std.testing.expect(snap.objectAt(&idOf(1), 8) == null);
        try std.testing.expect(snap.objectAt(&idOf(1), 9) != null);
        try std.testing.expectEqualStrings("hot", snap.liveObject(&idOf(1)).?.bytes);
        // Live objects in aged or object-pruned segments stay readable.
        try std.testing.expectEqualStrings("cold", snap.liveObject(&idOf(100)).?.bytes);
        try std.testing.expect(snap.objectAt(&idOf(100), 1) != null);
    }
    // Floors only rise.
    _ = try s.setFloors(.{ .cp_pruned = 2, .obj_pruned = 1, .cp_epoch = 0, .obj_epoch = 0 });
    try std.testing.expectEqual(@as(u64, 6), s.cp_floor.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), s.obj_floor_epoch.load(.monotonic));
    // Durable with the next meta write (a flush), and kept across a crash.
    try s.flushIndex();
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 6), snap.lowestAvailable());
        try std.testing.expect(snap.objectAt(&idOf(1), 8) == null);
        try std.testing.expect(snap.objectAt(&idOf(1), 9) != null);
    }
    // Both floors pass epoch 2: it ages too, epoch 3 (current) stays.
    const r2 = try s.setFloors(.{ .cp_pruned = 11, .obj_pruned = 11, .cp_epoch = 3, .obj_epoch = 3 });
    try std.testing.expectEqual(@as(u64, 2), r2.segments_aged);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, 12), snap.lowestAvailable());
        try std.testing.expect(snap.checkpoint(11) == null);
        try std.testing.expect(snap.checkpoint(15) != null);
    }
    s.deinit();
}

test "xref: a superseded version referenced from a later epoch reads through age-out, cleaning (carried) and crashes, and leaves with its xref's epoch" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 26, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    cfg.clean_record_bytes = 64;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    // Epoch 0 (sparse once superseded): object 7 at version 1 among 30 history-only versions.
    {
        const b = try s.begin(1, 0);
        try b.checkpoint("s1", "c");
        try putT(b, false, 7, 1, "seven-v1");
        for (0..30) |i| {
            var buf: [256]u8 = undefined;
            const bytes = tObj(&buf, 500 + i, 1, "history-only-filler-bytes");
            try b.putHistorical(&idOf(500 + i), 1, &root.objectDigest(bytes), bytes);
        }
        try s.commit(b);
    }
    // Epoch 1: a transaction supersedes 7@1; its input version is cross-referenced, not copied.
    {
        var snap = s.snapshot();
        const f = (try snap.objectFind(&idOf(7), 1)).?;
        snap.release();
        try std.testing.expect(f.live);
        try std.testing.expectEqual(f.loc, f.data_loc);
        const b = try s.begin(2, 1);
        try b.checkpoint("s2", "c");
        try b.putXref(&idOf(7), 1, f.data_loc);
        try putT(b, false, 7, 2, "seven-v2");
        try s.commit(b);
    }
    {
        var snap = s.snapshot();
        defer snap.release();
        const f = (try snap.objectFind(&idOf(7), 1)).?;
        try std.testing.expect(!f.live);
        try std.testing.expectEqual(@as(u64, 1), root.format.epochOf(f.loc)); // the xref
        try std.testing.expectEqual(@as(u64, 0), root.format.epochOf(f.data_loc)); // the bytes
        try std.testing.expectEqualSlices(u8, "seven-v1", f.ref.bytes[40..]);
    }
    // Crash: the xref is rebuilt into the index from the log.
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    // Epoch 0 ages out: 7@1 still reads (its xref is in epoch 1); a filler does not.
    {
        const b = try s.begin(3, 2);
        try b.checkpoint("s3", "c");
        try s.commit(b);
    }
    _ = try s.ageOut(1);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqualSlices(u8, "seven-v1", snap.objectAt(&idOf(7), 1).?[40..]);
        try std.testing.expect(snap.objectAt(&idOf(500), 1) == null);
    }
    // Cleaning deletes epoch 0 (nothing live in it) and carries 7@1, which the xref names.
    var rep: root.PruneReport = .{};
    var steps: usize = 0;
    while (true) : (steps += 1) {
        try std.testing.expect(steps < 1000);
        const r = try s.cleanStep(1 << 16);
        rep.segments_dropped += r.segments_dropped;
        rep.versions_carried += r.versions_carried;
        if (r.idle) break;
    }
    try std.testing.expectEqual(@as(u64, 1), rep.segments_dropped);
    try std.testing.expectEqual(@as(u64, 1), rep.versions_carried);
    try std.testing.expectEqual(@as(u64, 0), s.agedSegments().count);
    {
        var snap = s.snapshot();
        defer snap.release();
        const f = (try snap.objectFind(&idOf(7), 1)).?;
        try std.testing.expectEqualSlices(u8, "seven-v1", f.ref.bytes[40..]);
        try std.testing.expectEqual(@as(u64, 2), root.format.epochOf(f.data_loc)); // the carried copy
        try std.testing.expectEqual(root.objectDigest(f.ref.bytes), f.ref.digest);
    }
    // Crash again: the carried copy and its anchor survive.
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expectEqualSlices(u8, "seven-v1", snap.objectAt(&idOf(7), 1).?[40..]);
    }
    // Epoch 1 (the xref's) leaves the window: the carried copy, though in epoch 2, goes with it.
    _ = try s.ageOut(2);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.objectAt(&idOf(7), 1) == null);
        try expectObj(&snap, 7, 2);
    }
    try s.close();
}

test "compressed segments: a store that only serves reads frees its evicted chunks" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 41, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    cfg.cache_bytes = 1; // the floor: 64 KiB per shard
    var payload: [12000]u8 = undefined;
    var seq: u64 = 0;
    {
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (0..600) |_| {
            seq += 1;
            const b = try s.begin(seq, 0);
            try b.checkpoint("summary", "contents");
            for (&payload, 0..) |*x, i| x.* = @truncate(seq *% 131 +% i *% 7);
            try put(b, seq, seq, &payload);
            try s.commit(b);
        }
        try s.close();
    }
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var peak: usize = 0;
    for (0..3) |_| {
        var q: u64 = 1;
        while (q <= seq) : (q += 1) {
            var snap = s.snapshot();
            defer snap.release();
            try std.testing.expect(snap.liveObject(&idOf(q)) != null);
            peak = @max(peak, s.chunk_kept.items.len);
        }
    }
    try std.testing.expect(s.cache.stats.evictions.load(.monotonic) > 100);
    // Without commits the evicted chunks are still reclaimed as snapshots end.
    try std.testing.expect(peak < 16);
    try std.testing.expectEqual(@as(u64, 0), s.cache.evicted_bytes.load(.monotonic));
}

test "compressed segments: forEachLive walks every live object without the shared chunk cache" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 43, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    cfg.cache_bytes = 1;
    var payload: [12000]u8 = undefined;
    var seq: u64 = 0;
    {
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (0..400) |_| {
            seq += 1;
            const b = try s.begin(seq, 0);
            try b.checkpoint("summary", "contents");
            for (&payload, 0..) |*x, i| x.* = @truncate(seq *% 131 +% i *% 7);
            try put(b, seq, seq, &payload);
            try s.commit(b);
        }
        try s.close();
    }
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    const misses0 = s.cache.stats.misses.load(.monotonic);
    const Ctx = struct {
        n: u64 = 0,
        bad: u64 = 0,
        fn f(c: *@This(), id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
            c.n += 1;
            if (!std.mem.eql(u8, id, &idOf(version))) c.bad += 1;
            for (bytes[bytes.len - 16 ..], bytes.len - 16..) |x, i| {
                if (x != @as(u8, @truncate(version *% 131 +% i *% 7))) c.bad += 1;
            }
        }
    };
    var ctx: Ctx = .{};
    var snap = s.snapshot();
    defer snap.release();
    try snap.forEachLive(&ctx, Ctx.f);
    try std.testing.expectEqual(seq, ctx.n);
    try std.testing.expectEqual(@as(u64, 0), ctx.bad);
    // The walk decodes into its own buffer: nothing entered (or will be pinned in) the cache.
    try std.testing.expectEqual(misses0, s.cache.stats.misses.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), s.cache.evicted_bytes.load(.monotonic));
}

test "restore image: every compact base record once, in any number of parts, while batches commit" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 23, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    // epoch 0: 37 groups of restored objects with payloads of varied length, then the end-of-epoch
    // checkpoint with a full (non-compact) output record that must not be listed
    var n: u64 = 0;
    for (0..37) |g| {
        const b = try s.begin(g, 0);
        for (0..(g * 7) % 53 + 1) |i| {
            var pl: [180]u8 = @splat('x');
            try putT(b, true, 10_000 + n, 3, pl[0 .. (n * 13 + i) % 180]);
            n += 1;
        }
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 0);
        try b.checkpoint("s40", "c");
        try putT(b, false, 10_000, 4, "eoe-output");
        try s.commit(b);
    }
    // epoch 1 commits go to another segment
    {
        const b = try s.begin(41, 1);
        try b.checkpoint("s41", "c");
        try putT(b, false, 10_001, 5, "later");
        try s.commit(b);
    }
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expect(snap.segmentBytes(0) != null);
    const Seen = struct {
        seen: []u8,
        fn each(x: *@This(), id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
            try std.testing.expectEqual(@as(u64, 3), version);
            try std.testing.expectEqualSlices(u8, id, bytes[0..32]);
            var k: u64 = 0;
            while (k < x.seen.len) : (k += 1) if (std.mem.eql(u8, &idOf(10_000 + k), id)) break;
            try std.testing.expect(k < x.seen.len);
            x.seen[k] += 1;
        }
    };
    for ([_]u64{ 1, 2, 3, 7, 64 }) |parts| {
        const seen = try gpa.alloc(u8, n);
        defer gpa.free(seen);
        @memset(seen, 0);
        var x: Seen = .{ .seen = seen };
        var st: root.Snapshot.ImageStats = .{};
        for (0..parts) |p| try snap.forEachImageObject(0, p, parts, &st, &x, Seen.each);
        try std.testing.expectEqual(n, st.objects);
        try std.testing.expectEqual(@as(u64, 0), st.resyncs);
        for (seen) |c| try std.testing.expectEqual(@as(u8, 1), c);
    }
}

test "restore image walk: after age-out turned the image's dead records into holes, every record the live table still names is listed once" {
    const gpa = std.testing.allocator;
    const groups = 6;
    const per = 100;
    const total = groups * per;
    // Groups rewritten whole, then chunk by chunk: a hole is followed by live records in the
    // same chunk either way.
    for ([_]u64{ 64 << 10, 0 }) |whole| {
        const sim = try SimIo.init(gpa, 57, .{}, 2 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.codec = testCodec;
        cfg.segment_reserve = 2 << 20;
        cfg.chunk_bytes = 4 << 10;
        cfg.age_lag_checkpoints = 1;
        cfg.age_whole_group_bytes = whole;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        // Epoch 0, the image: compact records of version 3, then the end-of-epoch checkpoint.
        for (0..groups) |g| {
            const b = try s.begin(g, 0);
            for (0..per) |i| {
                const n = g * per + i;
                var pl: [180]u8 = @splat('x');
                try putT(b, true, 20_000 + n, 3, pl[0 .. 40 + (n * 13) % 140]);
            }
            try s.commit(b);
        }
        {
            const b = try s.begin(40, 0);
            try b.checkpoint("s40", "c");
            try s.commit(b);
        }
        // Epoch 1: every fifth object of the first four groups gets version 4 (the last two
        // groups stay as restored). Epoch 2: two checkpoints, so both floors pass those.
        var seq: u64 = 41;
        for (0..4) |g| {
            const b = try s.begin(seq, 1);
            try b.checkpoint("s", "c");
            var i: u64 = 2;
            while (i < per) : (i += 5) try putT(b, false, 20_000 + g * per + i, 4, "superseding");
            try s.commit(b);
            seq += 1;
        }
        // The links that name the superseded restored records are sealed into a run of epoch 1
        // (a close), and the object floor passes epoch 1 below: no read follows them any more,
        // so the records may go (while a link in the window names one it stays readable).
        try s.close();
        s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (0..2) |_| {
            const b = try s.begin(seq, 2);
            try b.checkpoint("s", "c");
            try s.commit(b);
            seq += 1;
        }
        _ = try s.setFloors(.{ .cp_pruned = seq - 2, .obj_pruned = seq - 2, .cp_epoch = 2, .obj_epoch = 2 });
        try s.flushIndex();
        const rep = try s.ageAll();
        // The image's 80 superseded records went, in rewritten chunks.
        try std.testing.expect(rep.chunks_rewritten > 0);
        try std.testing.expect(s.age_stats.objects_dropped.load(.monotonic) >= 80);
        var snap = s.snapshot();
        defer snap.release();
        const Seen = struct {
            seen: [total]u8 = @splat(0),
            fn each(x: *@This(), id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
                try std.testing.expectEqual(@as(u64, 3), version);
                try std.testing.expectEqualSlices(u8, id, bytes[0..32]);
                const n = std.mem.readInt(u64, id[24..32], .big) - 20_000;
                try std.testing.expect(n < total);
                x.seen[n] += 1;
            }
        };
        for ([_]u64{ 1, 3, 64 }) |parts| {
            var x: Seen = .{};
            var st: root.Snapshot.ImageStats = .{};
            for (0..parts) |p| try snap.forEachImageObject(0, p, parts, &st, &x, Seen.each);
            var live: u64 = 0;
            var missed: u64 = 0;
            var listed: u64 = 0;
            for (x.seen, 0..) |c, n| {
                try std.testing.expect(c <= 1);
                listed += c;
                // The table still names the image's record: the walk must list it.
                if (snap.liveObject(&idOf(20_000 + n)).?.version == 3) {
                    live += 1;
                    if (c != 1) missed += 1;
                }
            }
            if (missed != 0) std.debug.print("image walk (whole {d}, {d} parts): {d} of {d} live records not listed\n", .{ whole, parts, missed, live });
            try std.testing.expectEqual(@as(u64, 0), missed);
            try std.testing.expectEqual(@as(u64, total - 80), live);
            // And only those: the 80 holes are stepped over, not listed.
            try std.testing.expectEqual(live, listed);
            try std.testing.expectEqual(listed, st.objects);
            try std.testing.expectEqual(@as(u64, 0), st.resyncs);
        }
    }
}

test "bulk live-table load (restore): same table as in place, durable, a reopen replays nothing" {
    const gpa = std.testing.allocator;
    var sims: [2]*SimIo = undefined;
    var stores: [2]*Store = undefined;
    var cfg = smallCfg();
    cfg.codec = testCodec;
    cfg.max_live_objects = 64;
    cfg.max_object_versions = 16384;
    // a restore-like load: many groups of base records and wrapped tombstones, in both stores;
    // store 0 bulk-loads its live table, store 1 applies in place
    const n_obj: u64 = 6000;
    for (0..2) |k| {
        sims[k] = try SimIo.init(gpa, 31, .{}, 32 << 20);
        stores[k] = try Store.open(gpa, .{ .sim = sims[k] }, &cfg);
        const s = stores[k];
        if (k == 0) try s.bulkLiveBegin();
        var n: u64 = 0;
        var g: u64 = 0;
        while (n < n_obj) : (g += 1) {
            const b = try s.begin(g, 0);
            for (0..100) |_| {
                var pl: [64]u8 = @splat('r');
                try putT(b, true, 1000 + n, 3, pl[0 .. n % 64]);
                n += 1;
            }
            try b.removeObject(&idOf(900_000 + g), 2, .wrapped);
            try s.commit(b);
        }
        if (k == 0) {
            const r = try s.bulkLiveFinish(null);
            try std.testing.expectEqual(n_obj + g, r.objects);
            try std.testing.expectEqual(n_obj, r.live);
        }
        // the end-of-epoch checkpoint through the normal path, over the loaded table
        const b = try s.begin(500, 0);
        try b.checkpoint("s500", "c");
        try putT(b, false, 1000, 4, "eoe");
        try b.removeObject(&idOf(1001), 4, .deleted);
        try s.commit(b);
        try s.persistLive();
    }
    defer for (0..2) |k| sims[k].deinit();
    for (0..n_obj + 2) |i| {
        const id = idOf(1000 + i);
        try std.testing.expectEqual(stores[1].liveLocation(&id), stores[0].liveLocation(&id));
    }
    try std.testing.expectEqual(stores[1].liveSlots().used, stores[0].liveSlots().used);
    // reopen: the table loads as is (no rebuild from the logs), nothing to replay
    try stores[0].close();
    stores[1].deinit();
    var s = try Store.open(gpa, .{ .sim = sims[0] }, &cfg);
    defer s.deinit();
    try std.testing.expect(!s.stats.rebuilt_index);
    {
        var snap = s.snapshot();
        defer snap.release();
        try expectObj(&snap, 1000, 4);
        try expectObj(&snap, 1000 + n_obj - 1, 3);
        try std.testing.expect(snap.liveObject(&idOf(1001)) == null);
    }
    // a crash right after a clean close recovers the same (the journal was retired)
    s.deinit();
    sims[0].crash();
    s = try Store.open(gpa, .{ .sim = sims[0] }, &cfg);
    try std.testing.expect(!s.stats.rebuilt_index);
    var snap2 = s.snapshot();
    defer snap2.release();
    try expectObj(&snap2, 2000, 3);
}

test "a full batch map refuses before appending: a restore's commit-and-retry writes each object once" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 37, .{}, 16 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    cfg.max_object_versions = 16384;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try s.bulkLiveBegin();
    var g: u64 = 0;
    var b = try s.begin(g, 0);
    const n: u64 = 1000; // max_batch_objects is 256: three batches fill up
    for (0..n) |i| {
        while (true) {
            putT(b, true, 5000 + i, 3, "x") catch |e| switch (e) {
                error.BatchFull => {
                    try s.commit(b);
                    g += 1;
                    b = try s.begin(g, 0);
                    continue;
                },
                else => return e,
            };
            break;
        }
    }
    try s.commit(b);
    const r = try s.bulkLiveFinish(null);
    try std.testing.expectEqual(n, r.objects);
    var snap = s.snapshot();
    defer snap.release();
    var st: root.Snapshot.ImageStats = .{};
    const C = struct {
        fn each(_: *@This(), _: *const [32]u8, _: u64, _: []const u8) anyerror!void {}
    };
    var c: C = .{};
    try snap.forEachImageObject(0, 0, 1, &st, &c, C.each);
    try std.testing.expectEqual(n, st.objects);
}

fn fillPayload(p: []u8, seq: u64) void {
    for (p, 0..) |*x, i| x.* = @truncate(seq *% 131 +% i *% 7);
}

fn payloadOk(bytes: []const u8, seq: u64) bool {
    for (bytes, 0..) |x, i| if (x != @as(u8, @truncate(seq *% 131 +% i *% 7))) return false;
    return true;
}

/// Decoded chunks evicted from the cache and not freed yet (waiting to be taken, or held for
/// readers that could still have them).
fn unfreedChunkBytes(s: *Store) u64 {
    const m = s.chunkMemory();
    return m.evicted_bytes + m.kept_bytes;
}

test "compressed segments: a snapshot held across commits pins only the chunks it read" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 47, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    cfg.cache_bytes = 1; // the floor: 64 KiB per shard, 4 MiB in all
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var payload: [12000]u8 = undefined;
    var long: ?root.Snapshot = null;
    defer if (long) |*l| l.release();
    var held: []const u8 = &.{};
    var prev: ?root.Snapshot = null;
    defer if (prev) |*p| p.release();
    var peak: u64 = 0;
    var seq: u64 = 0;
    while (seq < 1200) {
        seq += 1;
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        fillPayload(&payload, seq);
        try put(b, seq, seq, &payload);
        try s.commit(b);
        if (seq == 40) {
            // The long reader: one object read early, its bytes held to the end.
            long = s.snapshot();
            held = (long.?.liveObject(&idOf(3)) orelse return error.TestMissingObject).bytes;
        }
        // Overlapping short readers: each lives across one commit and reads an older object.
        var sn = s.snapshot();
        const q = 1 + (seq *% 7919) % seq;
        const o = sn.liveObject(&idOf(q)) orelse return error.TestMissingObject;
        try std.testing.expect(payloadOk(o.bytes, q));
        if (prev) |*p| p.release();
        prev = sn;
        if (seq > 40) peak = @max(peak, unfreedChunkBytes(s));
    }
    const evicted = s.cache.stats.evictions.load(.monotonic);
    std.debug.print("held-snapshot test: evictions {d}, peak unfreed {d} bytes\n", .{ evicted, peak });
    try std.testing.expect(evicted > 500);
    // What the long reader got is intact after 1,160 commits evicted everything around it.
    try std.testing.expect(payloadOk(held, 3));
    // It may pin the chunks it read (and those short readers had at the time), not every
    // chunk evicted while it lived (about 13 MiB here).
    try std.testing.expect(peak < 512 << 10);
    long.?.release();
    long = null;
    prev.?.release();
    prev = null;
    var sn = s.snapshot();
    sn.release();
    try std.testing.expectEqual(@as(u64, 0), unfreedChunkBytes(s));
}

test "LiveScan reads compressed segments through walk-private buffers: a scan of many times the chunk cache decodes nothing into it and leaves no chunk unfreed" {
    // A scan reads every chunk of the live set once. Through the shared cache each chunk was an
    // allocation of its own, held until the range's snapshot ended (65,536 records) and then
    // freed by whichever thread ran the next reclaim: on a 32-core box the walkers decoded
    // faster than that freed (private memory at 152 GB for a 150 GB live set, a test machine, 2026-11-11).
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 59, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    cfg.cache_bytes = 1; // the floor: 64 KiB per shard, 4 MiB in all
    cfg.max_live_objects = 4096;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    // 1,500 objects of 12 KB, each its own chunk: 18 MiB of live set.
    const n_objs: u64 = 1500;
    var payload: [12000]u8 = undefined;
    var seq: u64 = 0;
    while (seq < n_objs) {
        seq += 1;
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        fillPayload(&payload, seq);
        try put(b, seq, 1, &payload);
        try s.commit(b);
    }
    // Then objects 1..50 get a version 2 and objects 51..100 are deleted, one a checkpoint.
    while (seq < n_objs + 100) {
        seq += 1;
        const k = seq - n_objs;
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        if (k <= 50) {
            fillPayload(&payload, k + 5000);
            try put(b, k, 2, &payload);
        } else try b.removeObject(&idOf(k), 2, .deleted);
        try s.commit(b);
    }
    {
        var sn = s.snapshot();
        sn.release();
    }
    try std.testing.expectEqual(@as(u64, 0), unfreedChunkBytes(s));

    const Walk = struct {
        s: *Store,
        sc: *root.LiveScan,
        /// The view is as of the first 1,500 checkpoints (every object at version 1), else the tip.
        past: bool,
        lock: std.atomic.Value(bool) = .init(false),
        seen: [1501]u8 = @splat(0),
        count: u64 = 0,
        bad: u64 = 0,
        peak: u64 = 0,
        err: ?anyerror = null,

        fn each(w: *@This(), o: root.LiveIter.Item) anyerror!void {
            const n = std.mem.readInt(u64, o.id[24..32], .big);
            const v2 = !w.past and n <= 50;
            const ok = n >= 1 and n <= 1500 and o.version == @as(u64, if (v2) 2 else 1) and o.bytes.len == 12000 and payloadOk(o.bytes, if (v2) n + 5000 else n);
            const unfreed = unfreedChunkBytes(w.s);
            while (w.lock.cmpxchgWeak(false, true, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
            defer w.lock.store(false, .release);
            if (!ok) w.bad += 1 else w.seen[@intCast(n)] += 1;
            w.count += 1;
            w.peak = @max(w.peak, unfreed);
        }
        fn part(w: *@This(), p: u32) void {
            w.sc.walkPart(p, 3, w, each) catch |e| {
                w.err = e;
            };
        }
    };
    for ([_]bool{ false, true }) |past| {
        const misses = s.cache.stats.misses.load(.monotonic);
        const hits = s.cache.stats.hits.load(.monotonic);
        var sc = try root.LiveScan.init(gpa, s, if (past) n_objs + 1 else seq + 1);
        defer sc.deinit();
        var w: Walk = .{ .s = s, .sc = &sc, .past = past };
        var ts: [2]std.Thread = undefined;
        for (&ts, 1..) |*t, p| t.* = try std.Thread.spawn(.{}, Walk.part, .{ &w, @as(u32, @intCast(p)) });
        w.part(0);
        for (ts) |t| t.join();
        if (w.err) |e| return e;
        try std.testing.expectEqual(@as(u64, 0), w.bad);
        // every object of the view once: all 1,500, or the 1,450 left with 1..50 at version 2
        try std.testing.expectEqual(@as(u64, if (past) 1500 else 1450), w.count);
        for (w.seen[1..], 1..) |c, n| try std.testing.expectEqual(@as(u8, if (!past and n > 50 and n <= 100) 0 else 1), c);
        // nothing went through the shared cache, so nothing waits to be freed
        try std.testing.expectEqual(misses, s.cache.stats.misses.load(.monotonic));
        try std.testing.expectEqual(hits, s.cache.stats.hits.load(.monotonic));
        try std.testing.expectEqual(@as(u64, 0), w.peak);
    }
    try std.testing.expectEqual(@as(u64, 0), s.chunkMemory().readers);
}

test "compressed segments: a long reader that quiesces between units frees the chunks it read" {
    // The startup seed's shape: one snapshot over a long replay, no commits, no other readers.
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 53, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    cfg.cache_bytes = 1;
    var payload: [12000]u8 = undefined;
    var seq: u64 = 0;
    {
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (0..600) |_| {
            seq += 1;
            const b = try s.begin(seq, 0);
            try b.checkpoint("summary", "contents");
            fillPayload(&payload, seq);
            try put(b, seq, seq, &payload);
            try s.commit(b);
        }
        try s.close();
    }
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var snap = s.snapshot();
    defer snap.release();
    // Without quiescing, the reader pins what it reads (it may still hold any of it)...
    var q: u64 = 1;
    while (q <= seq) : (q += 1) {
        const o = snap.liveObject(&idOf(q)) orelse return error.TestMissingObject;
        try std.testing.expect(payloadOk(o.bytes, q));
    }
    const pinned = unfreedChunkBytes(s);
    try std.testing.expect(pinned > 2 << 20); // 7.2 MB read through a 4 MiB cache
    // ...and one quiesce frees all of it; quiescing per unit keeps it at about one unit.
    snap.quiesce();
    try std.testing.expectEqual(@as(u64, 0), unfreedChunkBytes(s));
    var peak: u64 = 0;
    for (0..2) |_| {
        q = 1;
        while (q <= seq) : (q += 1) {
            const o = snap.liveObject(&idOf(q)) orelse return error.TestMissingObject;
            try std.testing.expect(payloadOk(o.bytes, q));
            snap.quiesce();
            peak = @max(peak, unfreedChunkBytes(s));
        }
    }
    std.debug.print("quiesce test: pinned without quiesce {d} bytes, peak with {d}\n", .{ pinned, peak });
    try std.testing.expect(peak < 256 << 10);
    // The snapshot still reads at its checkpoint after quiescing.
    try std.testing.expectEqual(@as(?u64, seq), snap.highestCommitted());
}

test "real files: compressed segments under parallel readers and commits, evicted chunks stay readable to their holders and are freed after" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var cfg = smallCfg();
    cfg.dir = path_buf[0..n];
    cfg.chunk_bytes = 4096;
    cfg.cache_bytes = 1;
    const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    defer h.store.deinit();
    const s = h.store;
    var payload: [12000]u8 = undefined;
    var seq: u64 = 0;
    for (0..64) |_| {
        seq += 1;
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        fillPayload(&payload, seq);
        try put(b, seq, seq, &payload);
        try s.commit(b);
    }
    const Reader = struct {
        st: *Store,
        stop: *std.atomic.Value(bool),
        bad: std.atomic.Value(u64) = .init(0),
        reads: u64 = 0,
        seed: u64,

        fn run(r: *@This()) void {
            var rng: std.Random.DefaultPrng = .init(r.seed);
            // Some snapshots are kept for a while with a slice they read, checked at release.
            const Held = struct { snap: root.Snapshot, bytes: []const u8, q: u64, left: u32 };
            var held: [4]?Held = @splat(null);
            while (!r.stop.load(.acquire)) {
                var snap = r.st.snapshot();
                const hi = snap.highestCommitted() orelse {
                    snap.release();
                    continue;
                };
                var keep: ?Held = null;
                for (0..4) |_| {
                    const q = 1 + rng.random().uintLessThan(u64, hi);
                    const o = snap.liveObject(&idOf(q)) orelse {
                        _ = r.bad.fetchAdd(1, .monotonic);
                        continue;
                    };
                    r.reads += 1;
                    if (!payloadOk(o.bytes, q)) _ = r.bad.fetchAdd(1, .monotonic);
                    keep = .{ .snap = snap, .bytes = o.bytes, .q = q, .left = 8 + rng.random().uintLessThan(u32, 64) };
                }
                for (&held) |*slot| if (slot.*) |*x| {
                    x.left -= 1;
                    if (x.left == 0) {
                        if (!payloadOk(x.bytes, x.q)) _ = r.bad.fetchAdd(1, .monotonic);
                        x.snap.release();
                        slot.* = null;
                    }
                };
                const free_slot = for (&held, 0..) |*slot, i| {
                    if (slot.* == null) break i;
                } else null;
                if (keep != null and free_slot != null and rng.random().uintLessThan(u32, 8) == 0) {
                    held[free_slot.?] = keep;
                } else snap.release();
            }
            for (&held) |*slot| if (slot.*) |*x| {
                if (!payloadOk(x.bytes, x.q)) _ = r.bad.fetchAdd(1, .monotonic);
                x.snap.release();
            };
        }
    };
    var stop: std.atomic.Value(bool) = .init(false);
    var readers: [4]Reader = undefined;
    var threads: [4]std.Thread = undefined;
    for (&readers, &threads, 0..) |*r, *t, i| {
        r.* = .{ .st = s, .stop = &stop, .seed = 100 + i };
        t.* = try std.Thread.spawn(.{}, Reader.run, .{r});
    }
    var peak: u64 = 0;
    for (0..500) |_| {
        seq += 1;
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        fillPayload(&payload, seq);
        try put(b, seq, seq, &payload);
        try s.commit(b);
        peak = @max(peak, unfreedChunkBytes(s));
    }
    stop.store(true, .release);
    for (threads) |t| t.join();
    var reads: u64 = 0;
    for (&readers) |*r| {
        try std.testing.expectEqual(@as(u64, 0), r.bad.load(.monotonic));
        reads += r.reads;
    }
    std.debug.print("parallel readers: {d} reads, {d} evictions, peak unfreed {d} bytes\n", .{ reads, s.cache.stats.evictions.load(.monotonic), peak });
    try std.testing.expect(s.cache.stats.evictions.load(.monotonic) > 100);
    var sn = s.snapshot();
    sn.release();
    try std.testing.expectEqual(@as(u64, 0), unfreedChunkBytes(s));
    try std.testing.expectEqual(@as(u64, 0), s.chunkMemory().readers);
}

test "a restored version superseded after the restore is found by its link at mainnet epoch numbers, while the link is still in the memtable and after it is in a run" {
    // The link's epoch decides the retention. For a link still in the memtable the lookup took
    // the snapshot's reader counter (1 at a process start, a few thousand after hours) for
    // that epoch: with epochs 0, 1, 2 any counter passes; at epoch 1305 the version read as
    // absent until the counter had passed 1305.
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 33, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    const n: u64 = 0x2538;
    {
        const b = try s.begin(0, 1304);
        try putT(b, true, n, 3, "restored");
        for (0..8) |i| try putT(b, true, 100 + i, 3, "other-restored");
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 1304);
        try b.checkpoint("s40", "c");
        try s.commit(b);
    }
    {
        const b = try s.begin(41, 1305);
        try b.checkpoint("s41", "c");
        try s.commit(b);
    }
    // The floors after a restore: both pruners at S.
    _ = try s.setFloors(.{ .cp_pruned = 40, .obj_pruned = 40, .cp_epoch = 1305, .obj_epoch = 1305 });
    {
        const b = try s.begin(42, 1305);
        try b.checkpoint("s42", "c");
        try putT(b, false, n, 4, "superseding");
        try s.commit(b);
    }
    // Nothing has sealed the memtable: the link is in it.
    {
        var snap = s.snapshot();
        defer snap.release();
        const o = (try snap.objectAtChecked(&idOf(n), 3)) orelse return error.TestMissingObject;
        try std.testing.expectEqual(@as(u64, 3), o.version);
        try expectObj(&snap, n, 4);
    }
    // A close seals the memtable as a run of epoch 1305 (in a store this small nothing else
    // does): the link's epoch is its run's from here, still inside the object window.
    try s.close();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect((try snap.objectAtChecked(&idOf(n), 3)) != null);
    }
    // The objects pruner past epoch 1305: gone.
    {
        const b = try s.begin(80, 1306);
        try b.checkpoint("s80", "c");
        try s.commit(b);
    }
    _ = try s.setFloors(.{ .cp_pruned = 40, .obj_pruned = 79, .cp_epoch = 1305, .obj_epoch = 1306 });
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect((try snap.objectAtChecked(&idOf(n), 3)) == null);
        try expectObj(&snap, n, 4);
    }
}

test "a restored version superseded after the restore is found by its link while the link's epoch is retained (mainnet 0x2537 v1076557667)" {
    // sui-node 1.83.1 bytes (testdata/obj-2537-1076557667.bcs, GetObject bcs): object
    // 0x253766691d6c3aa07c41acfc2d9ef1bf0e0ba8a4d3fd86c42a6023247e1889dc v1076557667, written at
    // checkpoint 342782571 (epoch 1304, so in the epoch-1304 restore's live set), read by
    // EcBSKdwMgXBa54aVZ9ZvZBjgBWnPLNgA4GrWRvtJj33P at 342864290 and superseded by v1076809002 at
    // 342894884 (epoch 1305). deepwave 66c6154 on the restored store answered GetObject at the
    // version NOT_FOUND and every effects mask of checkpoint 342864290 INTERNAL ("unable to fetch
    // object"): the link lookup tested the compact record's segment (1304, below the object floor
    // a restore sets) instead of the link's epoch. Epochs 0, 1, 2 stand for 1304, 1305, 1306.
    const bcs = @embedFile("testdata/obj-2537-1076557667.bcs");
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 31, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.codec = testCodec;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    const n: u64 = 0x2537;
    const v0: u64 = 1076557667;
    const v1: u64 = 1076809002;
    var buf: [512]u8 = undefined;
    {
        // The restored live set, then the end-of-epoch checkpoint S = 40.
        const b = try s.begin(0, 0);
        const bytes = tObj(&buf, n, v0, bcs);
        const d = root.objectDigest(bytes);
        try b.putBase(&idOf(n), v0, &d, bytes);
        for (0..8) |i| try putT(b, true, 100 + i, 3, "other-restored");
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 0);
        try b.checkpoint("s40", "c");
        try s.commit(b);
    }
    {
        const b = try s.begin(41, 1);
        try b.checkpoint("s41", "c");
        try s.commit(b);
    }
    // The floors after a restore: both pruners at S.
    _ = try s.setFloors(.{ .cp_pruned = 40, .obj_pruned = 40, .cp_epoch = 1, .obj_epoch = 1 });
    {
        const b = try s.begin(52, 1);
        try b.checkpoint("s52", "c");
        try putT(b, false, n, v1, "superseding");
        try s.commit(b);
    }
    {
        var snap = s.snapshot();
        defer snap.release();
        const o = (try snap.objectAtChecked(&idOf(n), v0)) orelse return error.TestMissingObject;
        try std.testing.expectEqual(v0, o.version);
        try std.testing.expectEqualSlices(u8, bcs, o.bytes[40..]);
        try expectObj(&snap, n, v1);
    }
    // Epoch 1 sealed into its run (a close does that; nothing else in a store this small, and
    // a link still in the memtable counts as the newest epoch's): still found while the
    // objects pruner is below epoch 1's end.
    try s.close();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    {
        const b = try s.begin(80, 2);
        try b.checkpoint("s80", "c");
        try s.commit(b);
    }
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect((try snap.objectAtChecked(&idOf(n), v0)) != null);
    }
    // The objects pruner past epoch 1 (sui-node prunes versions superseded in it): gone.
    _ = try s.setFloors(.{ .cp_pruned = 40, .obj_pruned = 79, .cp_epoch = 1, .obj_epoch = 2 });
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect((try snap.objectAtChecked(&idOf(n), v0)) == null);
        try expectObj(&snap, n, v1);
    }
}

test "a live-table rebuild over an aged segment fails on a read error instead of dropping the live objects after it (store-dst io/196)" {
    const gpa = std.testing.allocator;
    const io_mod = root.io;
    const sim = try SimIo.init(gpa, 196, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    // Epoch 0: eight groups of live objects; epochs 1 and 2 follow.
    var seq: u64 = 0;
    for (0..8) |g| {
        seq += 1;
        const b = try s.begin(seq, 0);
        try b.checkpoint("s", "c");
        for (0..10) |i| try put(b, 100 + g * 10 + i, seq, "aged-but-live");
        try s.commit(b);
    }
    for (1..3) |e| {
        seq += 1;
        const b = try s.begin(seq, e);
        try b.checkpoint("s", "c");
        try put(b, 1, seq, "new");
        try s.commit(b);
    }
    // Epoch 0 ages out: its runs go, its live objects stay readable through the live table.
    _ = try s.ageOut(2);
    try s.close();
    // The live table is lost: the next open rebuilds it from the logs, aged segment first.
    const names = try sim.listDir(gpa, "index");
    defer {
        for (names) |x| gpa.free(x);
        gpa.free(names);
    }
    for (names) |x| {
        var nb: [96]u8 = undefined;
        try sim.remove(try std.fmt.bufPrint(&nb, "index/{s}", .{x}));
    }
    try sim.syncDir();
    var nb: [64]u8 = undefined;
    const seg0 = io_mod.segName(&nb, 0);
    // A transient EIO part way through the aged segment: the open fails, and leaves the disk as
    // it was (before the fix the rebuild stopped there and persisted a table missing the rest).
    var refused = false;
    var skip: u32 = 0;
    while (true) : (skip += 1) {
        sim.failReads(seg0, skip, 1);
        if (Store.open(gpa, .{ .sim = sim }, &cfg)) |s2| {
            defer s2.deinit();
            const consumed = sim.fail_left == 0;
            try std.testing.expect(s2.stats.rebuilt_index);
            sim.failReads(seg0, 0, 0);
            var snap = s2.snapshot();
            defer snap.release();
            for (0..80) |i| try std.testing.expectEqualStrings("aged-but-live", (try snap.latest(&idOf(100 + i))).?.live.bytes);
            if (!consumed) break;
            // An error a reader consumed (not the rebuild) leaves nothing to persist.
            try s2.close();
        } else |e| {
            try std.testing.expectEqual(error.Io, e);
            refused = true;
            sim.crash();
        }
    }
    try std.testing.expect(refused);
    sim.failReads(seg0, 0, 0);
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var snap = s.snapshot();
    defer snap.release();
    for (0..80) |i| try std.testing.expectEqualStrings("aged-but-live", (try snap.latest(&idOf(100 + i))).?.live.bytes);
}

test "an all-zero page in a sealed live table is a lost write: the open rebuilds the table" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 41, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    for (1..4) |q| {
        const b = try s.begin(q, 0);
        try b.checkpoint("s", "c");
        try put(b, q, q, "obj");
        try s.commit(b);
    }
    try s.close();
    // A rebuild writes the whole table sealed (every page, empty ones too).
    const Names = struct {
        fn live(sm: *SimIo, a: std.mem.Allocator, buf: []u8, remove: bool) !?[]const u8 {
            const names = try sm.listDir(a, "index");
            defer {
                for (names) |x| a.free(x);
                a.free(names);
            }
            var found: ?[]const u8 = null;
            for (names) |x| {
                const full = try std.fmt.bufPrint(buf, "index/{s}", .{x});
                if (remove) try sm.remove(full) else if (root.io.parseIndexName(x) == .live) found = full;
                if (found != null) break;
            }
            return found;
        }
    };
    var nb: [96]u8 = undefined;
    _ = try Names.live(sim, gpa, &nb, true);
    try sim.syncDir();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try std.testing.expect(s.stats.rebuilt_index);
    {
        const b = try s.begin(4, 0);
        try b.checkpoint("s", "c");
        try s.commit(b);
    }
    s.deinit();
    sim.crash();
    // The last page of the table (no entry of 3 objects lands there) reads back as zeros.
    const name = (try Names.live(sim, gpa, &nb, false)).?;
    const fd = try sim.openFile(name, false);
    const size = try sim.size(fd);
    sim.closeFile(fd);
    try std.testing.expect(sim.zeroAt(name, size - 4096, 4096));
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try std.testing.expect(s.stats.rebuilt_index);
    var snap = s.snapshot();
    defer snap.release();
    for (1..4) |q| try std.testing.expectEqualStrings("obj", (try snap.latest(&idOf(q))).?.live.bytes);
}

test "meta slots: a misdirected copy is noticed and kept, a slot from another history is refused" {
    const gpa = std.testing.allocator;
    const Run = struct {
        fn build(sim: *SimIo, cfg: *const root.Config, payload: []const u8) !void {
            var s = try Store.open(gpa, .{ .sim = sim }, cfg);
            for (1..4) |q| {
                const b = try s.begin(q, 0);
                try b.checkpoint("s", "c");
                try put(b, q, q, payload);
                try s.commit(b);
                try s.flushIndex();
            }
            s.deinit();
            sim.crash();
        }
        fn slot(sim: *SimIo, i: u64) ![4096]u8 {
            var b: [4096]u8 = undefined;
            const fd = try sim.openFile("meta", false);
            defer sim.closeFile(fd);
            try sim.read(fd, i * 4096, &b);
            return b;
        }
        fn store(sim: *SimIo, i: u64, b: *const [4096]u8) !void {
            const fd = try sim.openFile("meta", false);
            defer sim.closeFile(fd);
            try sim.writeSync(fd, i * 4096, b);
        }
        fn gen(b: *const [4096]u8) u64 {
            return std.mem.readInt(u64, b[16..24], .little);
        }
    };
    const cfg = smallCfg();
    const a = try SimIo.init(gpa, 51, .{}, 8 << 20);
    defer a.deinit();
    const b = try SimIo.init(gpa, 51, .{}, 8 << 20);
    defer b.deinit();
    try Run.build(a, &cfg, "history-a");
    try Run.build(b, &cfg, "history-b");
    const a0 = try Run.slot(a, 0);
    const a1 = try Run.slot(a, 1);
    const new_i: u64 = if (Run.gen(&a0) > Run.gen(&a1)) 0 else 1;
    const newest = if (new_i == 0) a0 else a1;
    // Same generations, other contents: the other slot is not this history's parent.
    const b_other = try Run.slot(b, 1 - new_i);
    try std.testing.expectEqual(Run.gen(&newest) - 1, Run.gen(&b_other));
    const keep_other = if (new_i == 0) a1 else a0;
    try Run.store(a, 1 - new_i, &b_other);
    try std.testing.expectError(error.Corrupt, Store.open(gpa, .{ .sim = a }, &cfg));
    a.crash();
    // The newest copy written over the other slot too (a misdirected write): opens on it.
    try Run.store(a, 1 - new_i, &newest);
    {
        var s = try Store.open(gpa, .{ .sim = a }, &cfg);
        defer s.deinit();
        try std.testing.expectEqual(@as(u64, 3), s.committed().?);
    }
    a.crash();
    // Only the misdirected copy, in the wrong slot, with an older copy in its own slot.
    try Run.store(a, 1 - new_i, &newest);
    try Run.store(a, new_i, &keep_other);
    {
        var s = try Store.open(gpa, .{ .sim = a }, &cfg);
        defer s.deinit();
        try std.testing.expectEqual(@as(u64, 1), s.stats.meta_misdirected);
        try std.testing.expectEqual(@as(u64, 3), s.committed().?);
    }
}

// ------------------------------------------------------------------ age-out

fn noise(seed: u64, buf: []u8) []const u8 {
    var prng: std.Random.DefaultPrng = .init(seed);
    prng.random().bytes(buf);
    return buf;
}

/// Epochs of checkpoints with incompressible payloads: a checkpoint (2 KiB), a transaction
/// (4 KiB), object 1 rewritten every checkpoint (3 KiB, superseded at once), object 100+seq
/// (256 B, stays live). Returns the next seq.
fn ageFill(s: *Store, seq0: u64, epoch: u64, n: u64) !u64 {
    var seq = seq0;
    var b1: [4096]u8 = undefined;
    var b2: [4096]u8 = undefined;
    var b3: [3072]u8 = undefined;
    var b4: [256]u8 = undefined;
    for (0..n) |_| {
        const b = try s.begin(seq, epoch);
        try b.checkpoint(noise(seq *% 31 + 1, b1[0..1024]), noise(seq *% 31 + 2, b2[0..1024]));
        try b.checkpointDigest(&idOf(90000 + seq));
        const txd = idOf(70000 + seq);
        const efd: [32]u8 = @splat(7);
        try b.transaction(&txd, &efd, noise(seq *% 31 + 3, &b1), "fx", null);
        try put(b, 1, seq + 1, noise(seq *% 31 + 4, &b3));
        try put(b, 100 + seq, 1, noise(seq *% 31 + 5, &b4));
        try s.commit(b);
        seq += 1;
    }
    return seq;
}

/// Checkpoints as a node with read sets writes them (node history.zig `inputAction`): each one
/// holds a transaction that reads object 1 at version `seq` and writes version `seq + 1`. An
/// input whose record sits in an older segment gets an xref, so the transaction keeps its input
/// for as long as its own segment is in the object window. Returns the next seq.
fn servedFill(s: *Store, seq0: u64, epoch: u64, n: u64) !u64 {
    var seq = seq0;
    var b1: [4096]u8 = undefined;
    var b2: [1024]u8 = undefined;
    var b3: [3072]u8 = undefined;
    for (0..n) |_| {
        const b = try s.begin(seq, epoch);
        try b.checkpoint(noise(seq *% 31 + 1, b1[0..1024]), noise(seq *% 31 + 2, &b2));
        const txd = idOf(70000 + seq);
        const efd: [32]u8 = @splat(7);
        try b.transaction(&txd, &efd, noise(seq *% 31 + 3, &b1), "fx", null);
        if (seq > 0) {
            var snap = s.snapshot();
            defer snap.release();
            const f = (try snap.objectFind(&idOf(1), seq)).?;
            if (root.format.epochOf(f.loc) < epoch) try b.putXref(&idOf(1), seq, f.data_loc);
        }
        try put(b, 1, seq + 1, noise(seq *% 31 + 4, &b3));
        try s.commit(b);
        seq += 1;
    }
    return seq;
}

/// What GetCheckpoint with `transactions.effects` needs of checkpoint `seq` written by
/// `servedFill`: the record, its transaction, and the versions the transaction read and wrote.
const ServedRead = enum { whole, no_objects, no_record };
fn servedRead(snap: *const root.Snapshot, seq: u64) ServedRead {
    var b1: [4096]u8 = undefined;
    var b3: [3072]u8 = undefined;
    const c = snap.checkpoint(seq) orelse return .no_record;
    if (!std.mem.eql(u8, noise(seq *% 31 + 1, b1[0..1024]), c.summary_cert)) return .no_record;
    const t = snap.transaction(&idOf(70000 + seq)) orelse return .no_record;
    if (t.checkpoint != seq) return .no_record;
    if (seq > 0) {
        const in = snap.objectNear(&idOf(1), seq, t.loc) orelse return .no_objects;
        if (!std.mem.eql(u8, noise((seq - 1) *% 31 + 4, &b3), in)) return .no_objects;
    }
    const out = snap.objectNear(&idOf(1), seq + 1, t.loc) orelse return .no_objects;
    if (!std.mem.eql(u8, noise(seq *% 31 + 4, &b3), out)) return .no_objects;
    return .whole;
}

test "lowest served: the higher of the checkpoint floor and the object floor; every checkpoint from it up reads with its transaction's objects, age-out off and on" {
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |age_on| {
        const sim = try SimIo.init(gpa, 77, .{}, 64 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.chunk_bytes = 16 << 10;
        cfg.age_lag_checkpoints = 0;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        // Epochs 0..3 of 40 checkpoints (0..159). Epoch 0 stands for what the restore left.
        var seq: u64 = 0;
        for (0..4) |e| seq = try servedFill(s, seq, e, 40);
        const tip = seq - 1;
        {
            var snap = s.snapshot();
            defer snap.release();
            // Nothing pruned: one floor.
            try std.testing.expectEqual(@as(?u64, 0), snap.lowestAvailable());
            try std.testing.expectEqual(@as(?u64, 0), snap.lowestServed());
            for (0..seq) |q| try std.testing.expectEqual(ServedRead.whole, servedRead(&snap, q));
        }
        // A store whose object window is ahead of its object floor (floors an older deepwave left:
        // the mark at 50, in epoch 1, the window at epoch 2): the first checkpoint of the window.
        _ = try s.setFloors(.{ .cp_pruned = 45, .obj_pruned = 50, .cp_epoch = 1, .obj_epoch = 2 });
        try s.flushIndex();
        if (age_on) _ = try s.ageAll();
        {
            var snap = s.snapshot();
            defer snap.release();
            try std.testing.expectEqual(@as(?u64, 46), snap.lowestAvailable());
            try std.testing.expectEqual(@as(?u64, 80), snap.lowestServed());
            for (80..seq) |q| try std.testing.expectEqual(ServedRead.whole, servedRead(&snap, q));
            // Between the two: the records read, the objects do not. The checkpoint floor alone
            // (what GetServiceInfo reported) promised these with their effects.
            for (46..80) |q| try std.testing.expectEqual(ServedRead.no_objects, servedRead(&snap, q));
            try std.testing.expectEqual(ServedRead.no_record, servedRead(&snap, 45));
        }
        // The state of the box: floors one epoch apart, as retention sets them. Checkpoints
        // pruned to 45 (epoch 1), objects pruned to 95 (epoch 2 is the first not fully pruned).
        _ = try s.setFloors(.{ .cp_pruned = 45, .obj_pruned = 95, .cp_epoch = 1, .obj_epoch = 2 });
        try s.flushIndex();
        if (age_on) {
            const rep = try s.ageAll();
            try std.testing.expect(rep.records_dropped > 0);
        }
        for (0..2) |pass| {
            if (pass == 1) {
                // The same after a crash and a reopen.
                sim.scheduleCrash(0);
                s.deinit();
                sim.crash();
                s = try Store.open(gpa, .{ .sim = sim }, &cfg);
            }
            var snap = s.snapshot();
            defer snap.release();
            try std.testing.expectEqual(@as(?u64, 46), snap.lowestAvailable());
            try std.testing.expectEqual(@as(?u64, 96), snap.lowestServed());
            try std.testing.expectEqual(@as(u64, 96), snap.objectsFrom(0));
            for (96..seq) |q| try std.testing.expectEqual(ServedRead.whole, servedRead(&snap, q));
            for (46..80) |q| try std.testing.expectEqual(ServedRead.no_objects, servedRead(&snap, q));
            // Inside the partially pruned epoch (80..95): without age-out the segment still
            // reads whole (a superset of sui-node, below the reported floor); with it the
            // versions superseded below the object floor are gone, as in sui-node.
            for (81..96) |q| try std.testing.expectEqual(if (age_on) ServedRead.no_objects else ServedRead.whole, servedRead(&snap, q));
            try std.testing.expectEqual(tip, snap.highestCommitted().?);
        }
        // A checkpoint floor above the object floor (a restore's S + 1 over floors not yet set,
        // or retention with more object epochs than checkpoint epochs) is the floor.
        try std.testing.expectEqual(@as(u64, 120), blk: {
            var snap = s.snapshot();
            defer snap.release();
            break :blk snap.objectsFrom(120);
        });
    }
}

fn ageExpectLive(s: *Store, seq_end: u64) !void {
    var snap = s.snapshot();
    defer snap.release();
    var b3: [3072]u8 = undefined;
    var b4: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, noise((seq_end - 1) *% 31 + 4, &b3), snap.liveObject(&idOf(1)).?.bytes);
    for (0..seq_end) |q| try std.testing.expectEqualSlices(u8, noise(q *% 31 + 5, &b4), snap.liveObject(&idOf(100 + q)).?.bytes);
}

test "age-out: object versions go when their successor is below the object floor, checkpoint data below the checkpoint floor (simulator)" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 31, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 16 << 10;
    cfg.age_lag_checkpoints = 0;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var seq = try ageFill(s, 0, 0, 200);
    seq = try ageFill(s, seq, 1, 10);
    // Inside the object window (epoch 0 is not aged): versions of object 1 superseded below 150
    // go; checkpoints below 50 go (49, just below the floor, stays held).
    _ = try s.setFloors(.{ .cp_pruned = 49, .obj_pruned = 149, .cp_epoch = 0, .obj_epoch = 0 });
    try s.flushIndex();
    {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.objectAt(&idOf(1), 11) != null); // before: all retained
    }
    const rep = try s.ageAll();
    try std.testing.expect(rep.records_dropped > 0 and rep.chunks_rewritten > 0);
    // Counted by kind too (sui-node's num_pruned_objects): object 1's versions went.
    try std.testing.expect(s.age_stats.objects_dropped.load(.monotonic) > 100);
    var b1: [4096]u8 = undefined;
    var b3: [3072]u8 = undefined;
    {
        var snap = s.snapshot();
        defer snap.release();
        // v(q+1) was written by q and superseded by q+1: gone when q+1 < 150.
        try std.testing.expect(snap.objectAt(&idOf(1), 11) == null);
        try std.testing.expect(snap.objectAt(&idOf(1), 148) == null);
        // Superseded at 150 and up (the object floor): kept, byte for byte.
        for (150..211) |v| try std.testing.expectEqualSlices(u8, noise((v - 1) *% 31 + 4, &b3), snap.objectAt(&idOf(1), v).?);
        try std.testing.expect(snap.checkpoint(10) == null);
        try std.testing.expect(snap.checkpointHeld(48) == null);
        try std.testing.expect(snap.checkpointHeld(49) != null);
        for (50..210) |q| {
            try std.testing.expectEqualSlices(u8, noise(q *% 31 + 1, b1[0..1024]), snap.checkpoint(q).?.summary_cert);
            try std.testing.expectEqualSlices(u8, noise(q *% 31 + 3, &b1), snap.transaction(&idOf(70000 + q)).?.tx);
        }
        try std.testing.expect(snap.transaction(&idOf(70000 + 20)) == null);
    }
    try ageExpectLive(s, seq);
    // A crash after age-out: the age log brings the rewritten chunks back.
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try ageExpectLive(s, seq);
    {
        var snap = s.snapshot();
        defer snap.release();
        for (150..211) |v| try std.testing.expectEqualSlices(u8, noise((v - 1) *% 31 + 4, &b3), snap.objectAt(&idOf(1), v).?);
        for (50..210) |q| try std.testing.expectEqualSlices(u8, noise(q *% 31 + 1, b1[0..1024]), snap.checkpoint(q).?.summary_cert);
    }
    // Idempotent: nothing more to drop at the same floors.
    const again = try s.ageAll();
    try std.testing.expectEqual(@as(u64, 0), again.chunks_rewritten);
}

/// Every file of the simulated disk, name and bytes, in name order: what a store wrote.
fn simImage(gpa: std.mem.Allocator, sim: *SimIo) ![]u8 {
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);
    for (sim.files) |*f| if (f.used and f.live) try names.append(gpa, f.name[0..f.name_len]);
    std.mem.sort([]const u8, names.items, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return std.mem.lessThan(u8, x, y);
        }
    }.lt);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (names.items) |name| for (sim.files) |*f| {
        if (!f.used or !f.live or !std.mem.eql(u8, f.name[0..f.name_len], name)) continue;
        try out.append(gpa, f.name_len);
        try out.appendSlice(gpa, name);
        try out.appendSlice(gpa, std.mem.asBytes(&f.cache_len));
        try out.appendSlice(gpa, f.cache[0..f.cache_len]);
    };
    return out.toOwnedSlice(gpa);
}

/// Prints where two `simImage`s first differ (file and offset in it).
fn simImageDiff(a: []const u8, b: []const u8) void {
    const n = @min(a.len, b.len);
    var d: usize = 0;
    while (d < n and a[d] == b[d]) d += 1;
    var p: usize = 0;
    while (p < a.len) {
        const nl: usize = a[p];
        const name = a[p + 1 ..][0..nl];
        const len: usize = @intCast(std.mem.readInt(u64, a[p + 1 + nl ..][0..8], .little));
        const data = p + 1 + nl + 8;
        if (d < data + len) {
            std.debug.print("images differ at byte {d} of {d}: file {s}, offset {d} of {d}{s}\n", .{ d, a.len, name, d -| data, len, if (d < data) " (name or length)" else "" });
            return;
        }
        p = data + len;
    }
    std.debug.print("images differ in length: {d} and {d}\n", .{ a.len, b.len });
}

/// One age-out workload on a fresh simulated disk: floors inside the object window, an aged
/// epoch (whole-segment rule), steps of several budgets, a close and a reopen. Returns the
/// disk image and the totals. (No crash: what a simulated crash tears is drawn from the disk's
/// random numbers, which the read-ahead's reads advance. The crash seeds are in dst.zig.)
fn ageWorkload(gpa: std.mem.Allocator, serial: bool, totals: *[4]u64) ![]u8 {
    const sim = try SimIo.init(gpa, 77, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 8 << 10;
    cfg.age_lag_checkpoints = 3;
    cfg.age_whole_group_bytes = 16 << 10;
    cfg.age_serial = serial;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    var is_open = true;
    errdefer if (is_open) s.deinit();
    var seq = try ageFill(s, 0, 0, 120);
    seq = try ageFill(s, seq, 1, 120);
    seq = try ageFill(s, seq, 2, 20);
    var tot: [4]u64 = @splat(0);
    const add = struct {
        fn f(t: *[4]u64, r: Store.AgeReport) void {
            t[0] += r.records_dropped;
            t[1] += r.chunks_rewritten;
            t[2] += r.bytes_dropped;
            t[3] += r.groups_rewritten;
        }
    }.f;
    // Floors inside epoch 0: the object pass and the checkpoint pass, no segment rule.
    _ = try s.setFloors(.{ .cp_pruned = 40, .obj_pruned = 90, .cp_epoch = 0, .obj_epoch = 0 });
    try s.flushIndex();
    for ([_]u64{ 4096, 64 << 10, 9000, 1 << 20, 1 << 20, 4096, 64 << 20 }) |budget| add(&tot, try s.ageStep(budget));
    // The object window leaves epoch 0: the segment pass over it, the other passes in epoch 1.
    _ = try s.setFloors(.{ .cp_pruned = 150, .obj_pruned = 200, .cp_epoch = 1, .obj_epoch = 1 });
    try s.flushIndex();
    for ([_]u64{ 4096, 20 << 10, 1 << 20, 4096, 300 << 10 }) |budget| add(&tot, try s.ageStep(budget));
    seq = try ageFill(s, seq, 2, 10);
    add(&tot, try s.ageAll());
    // A close and a reopen, more history, floors into epoch 2, age-out to the end.
    is_open = false;
    try s.close();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    is_open = true;
    seq = try ageFill(s, seq, 3, 12);
    _ = try s.setFloors(.{ .cp_pruned = 255, .obj_pruned = 262, .cp_epoch = 2, .obj_epoch = 2 });
    try s.flushIndex();
    for ([_]u64{ 4096, 50 << 10, 1 << 20 }) |budget| add(&tot, try s.ageStep(budget));
    add(&tot, try s.ageAll());
    try ageExpectLive(s, seq);
    is_open = false;
    try s.close();
    totals.* = tot;
    return simImage(gpa, sim);
}

test "age-out: the serial path and the read-ahead path drop the same records and leave the same bytes in every file" {
    const gpa = std.testing.allocator;
    var t_old: [4]u64 = undefined;
    var t_new: [4]u64 = undefined;
    const old = try ageWorkload(gpa, true, &t_old);
    defer gpa.free(old);
    const new = try ageWorkload(gpa, false, &t_new);
    defer gpa.free(new);
    try std.testing.expect(t_old[0] > 200 and t_old[1] > 20);
    try std.testing.expectEqualSlices(u64, &t_old, &t_new);
    if (!std.mem.eql(u8, old, new)) {
        simImageDiff(old, new);
        return error.TestUnexpectedResult;
    }
}

test "age-out deferred: the ager waits while the node is behind, catches up in one run (no segment pass) once enough history lies below the checkpoint floor, and a restart does not reset that" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 41, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 8 << 10;
    cfg.age_lag_checkpoints = 0;
    cfg.age_defer_bytes = 256 << 10;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    const Gate = Store.AgeGate;
    // Not deferred: the ager always runs.
    s.ageBehind(true);
    try std.testing.expectEqual(Gate.run, s.ageGate());
    s.age_mode = .deferred;
    var seq = try ageFill(s, 0, 0, 200);
    seq = try ageFill(s, seq, 1, 60);
    seq = try ageFill(s, seq, 2, 10);
    // Nothing is below the floors: nothing is held back, however much was appended.
    try std.testing.expectEqual(Gate.wait, s.ageGate());
    try std.testing.expectEqual(@as(u64, 0), s.age_stats.backlog.load(.monotonic));
    // A little history below the checkpoint floor: still waiting.
    _ = try s.setFloors(.{ .cp_pruned = 9, .obj_pruned = 9, .cp_epoch = 0, .obj_epoch = 0 });
    try s.flushIndex();
    try std.testing.expectEqual(Gate.wait, s.ageGate());
    const small = s.age_stats.backlog.load(.monotonic);
    try std.testing.expect(small > 0 and small < cfg.age_defer_bytes);
    // More than age_defer_bytes of it: a bulk catch-up.
    _ = try s.setFloors(.{ .cp_pruned = 150, .obj_pruned = 150, .cp_epoch = 0, .obj_epoch = 0 });
    try s.flushIndex();
    // A restart in between measures the same backlog from what is durable.
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    s.age_mode = .deferred;
    s.ageBehind(true);
    try std.testing.expectEqual(Gate.bulk, s.ageGate());
    try std.testing.expect(s.age_stats.backlog.load(.monotonic) >= cfg.age_defer_bytes);
    var dropped: u64 = 0;
    var steps: u32 = 0;
    while (true) : (steps += 1) {
        try std.testing.expect(steps < 2000);
        const r = try s.ageStepOpts(64 << 10, .{ .skip_seg = true });
        dropped += r.records_dropped;
        if (r.idle) break;
        try std.testing.expectEqual(Gate.bulk, s.ageGate());
    }
    s.ageBulkDone();
    try std.testing.expect(steps > 4 and dropped > 100);
    // Caught up: waiting again, nothing held back.
    try std.testing.expectEqual(Gate.wait, s.ageGate());
    try std.testing.expectEqual(@as(u64, 0), s.age_stats.backlog.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), s.age_stats.bulk_runs.load(.monotonic));
    // Epoch 0 leaves both windows while the node is still behind: the rest of it and the start
    // of epoch 1 are a new backlog. The bulk run frees it without the segment pass.
    _ = try s.setFloors(.{ .cp_pruned = 215, .obj_pruned = 230, .cp_epoch = 1, .obj_epoch = 1 });
    try s.flushIndex();
    try std.testing.expectEqual(Gate.bulk, s.ageGate());
    steps = 0;
    while (true) : (steps += 1) {
        try std.testing.expect(steps < 2000);
        if ((try s.ageStepOpts(64 << 10, .{ .skip_seg = true })).idle) break;
    }
    s.ageBulkDone();
    try std.testing.expectEqual(Gate.wait, s.ageGate());
    try std.testing.expectEqual(@as(u64, 0), s.ager.seg_target);
    // At the tip the ager runs everything, the segment pass included.
    s.ageBehind(false);
    try std.testing.expectEqual(Gate.run, s.ageGate());
    _ = try s.ageAll();
    try std.testing.expectEqual(@as(u64, 1), s.ager.seg_target);
    try ageExpectLive(s, seq);
    var snap = s.snapshot();
    defer snap.release();
    var b1: [4096]u8 = undefined;
    for (216..270) |q| try std.testing.expectEqualSlices(u8, noise(q *% 31 + 1, b1[0..1024]), snap.checkpoint(q).?.summary_cert);
}

test "age-out read-ahead: the dry run before a step asks for the live-table page of every lookup the step makes; the serial path asks for none" {
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |serial| {
        const sim = try SimIo.init(gpa, 43, .{}, 64 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.chunk_bytes = 8 << 10;
        cfg.age_lag_checkpoints = 2;
        cfg.age_serial = serial;
        const s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        var seq = try ageFill(s, 0, 0, 150);
        seq = try ageFill(s, seq, 1, 20);
        seq = try ageFill(s, seq, 2, 5);
        // The first step only places the cursors (no read-ahead before it).
        _ = try s.ageStep(4096);
        // Epoch 0 leaves the object window: every pass over it looks up every object version
        // and tombstone (the whole-segment rule), as the segment pass does over a restore image.
        _ = try s.setFloors(.{ .cp_pruned = 149, .obj_pruned = 149, .cp_epoch = 1, .obj_epoch = 1 });
        try s.flushIndex();
        var dropped: u64 = 0;
        var steps: u32 = 0;
        var idle = false;
        while (!idle) : (steps += 1) {
            try std.testing.expect(steps < 4000);
            const r = try s.ageStep(if (steps % 3 == 0) 4096 else if (steps % 3 == 1) 40 << 10 else 300 << 10);
            dropped += r.records_dropped;
            idle = r.idle;
        }
        const st = &s.age_stats;
        const lookups = st.lookups.load(.monotonic);
        try std.testing.expect(dropped > 100 and lookups >= 300);
        if (serial) {
            try std.testing.expectEqual(lookups, st.lookups_cold.load(.monotonic));
            try std.testing.expectEqual(@as(u64, 0), st.warm_pages.load(.monotonic));
            try std.testing.expectEqual(@as(u64, 0), st.warm_groups.load(.monotonic));
        } else {
            try std.testing.expectEqual(@as(u64, 0), st.lookups_cold.load(.monotonic));
            try std.testing.expect(st.warm_pages.load(.monotonic) > 0);
            try std.testing.expect(st.warm_groups.load(.monotonic) >= 150);
        }
        try ageExpectLive(s, seq);
    }
}

const SegMode = enum { serial, set, set_verify };

/// The age counters a `SegWorld` leaves behind.
const SegStats = struct {
    lookups: u64,
    objects_dropped: u64,
    chunks_rewritten: u64,
    seg_passes: u64,
    set_builds: u64,
    set_kept: u64,
    set_dead: u64,
    set_groups_skipped: u64,
    set_chunks_skipped: u64,
    set_inexact: u64,
    set_misses: u64,

    fn of(s: *Store) SegStats {
        var r: SegStats = undefined;
        inline for (comptime std.meta.fieldNames(SegStats)) |name| @field(r, name) = @field(s.age_stats, name).load(.monotonic);
        return r;
    }
};

/// A store shaped like a restored one for the segment pass: epoch 0 holds `seg_objs` live
/// objects per checkpoint and little else (an image), later epochs supersede some of them.
const SegWorld = struct {
    gpa: std.mem.Allocator,
    sim: *SimIo,
    cfg: root.Config,
    s: *Store,
    seq: u64 = 0,
    /// Newest version of each image object (index = object number).
    ver: [seg_cps * seg_objs]u64 = @splat(1),

    const seg_cps = 48;
    const seg_objs = 24;
    const base_id = 5000;

    fn open(gpa: std.mem.Allocator, mode: SegMode, whole_bytes: u64, set_bytes: u64) !SegWorld {
        // Small files: the simulator holds two copies of every file at its cap.
        const sim = try SimIo.init(gpa, 91, .{}, 2 << 20);
        errdefer sim.deinit();
        var cfg = smallCfg();
        cfg.max_live_objects = 4096;
        cfg.segment_reserve = 2 << 20;
        cfg.cache_bytes = 1 << 20;
        cfg.chunk_bytes = 4 << 10;
        cfg.age_lag_checkpoints = 1;
        cfg.age_whole_group_bytes = whole_bytes;
        cfg.age_serial = mode == .serial;
        cfg.age_live_set = mode == .set or mode == .set_verify;
        cfg.age_set_verify = mode == .set_verify;
        cfg.age_set_bytes = set_bytes;
        const s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        return .{ .gpa = gpa, .sim = sim, .cfg = cfg, .s = s };
    }

    fn close(w: *SegWorld) void {
        w.s.deinit();
        w.sim.deinit();
    }

    fn payloadOf(buf: *[300]u8, obj: u64, version: u64) []const u8 {
        return noise(obj *% 131 + version *% 7 + 3, buf);
    }

    /// Epoch 0: the image.
    fn image(w: *SegWorld) !void {
        var buf: [300]u8 = undefined;
        for (0..seg_cps) |c| {
            const b = try w.s.begin(w.seq, 0);
            try b.checkpoint("summary", "contents");
            for (0..seg_objs) |k| {
                const obj = c * seg_objs + k;
                try put(b, base_id + obj, 1, payloadOf(&buf, obj, 1));
            }
            try w.s.commit(b);
            w.seq += 1;
        }
        // The index entries of the image are sealed into a run of its own epoch (a close does
        // that), as a node's are long before a segment leaves the window. Left in a memtable
        // that is still in the window they would make the live set's bits for the image's
        // full records ambiguous (`AgeSet`), and every such record would be looked up.
        const cfg = w.s.cfg;
        try w.s.close();
        w.cfg = cfg;
        w.s = try Store.open(w.gpa, .{ .sim = w.sim }, &w.cfg);
    }

    /// One checkpoint of `epoch` that writes a new version of each object in `objs`.
    fn update(w: *SegWorld, epoch: u64, objs: []const u64) !void {
        var buf: [300]u8 = undefined;
        const b = try w.s.begin(w.seq, epoch);
        try b.checkpoint("summary", "contents");
        for (objs) |obj| {
            w.ver[obj] += 1;
            try put(b, base_id + obj, w.ver[obj], payloadOf(&buf, obj, w.ver[obj]));
        }
        try w.s.commit(b);
        w.seq += 1;
    }

    /// Both floors just below the newest checkpoint, epochs given: durable.
    fn floors(w: *SegWorld, epoch: u64) !void {
        _ = try w.s.setFloors(.{ .cp_pruned = w.seq - 2, .obj_pruned = w.seq - 2, .cp_epoch = epoch, .obj_epoch = epoch });
        try w.s.flushIndex();
    }

    /// Age-out to the end, in steps of mixed budgets.
    fn ageToEnd(w: *SegWorld) !void {
        var i: u32 = 0;
        while (true) : (i += 1) {
            try std.testing.expect(i < 20000);
            const budget: u64 = switch (i % 4) {
                0 => 4096,
                1 => 24 << 10,
                2 => 9000,
                else => 1 << 20,
            };
            if ((try w.s.ageStep(budget)).idle) break;
        }
    }

    /// Every image object reads back at its newest version.
    fn expectLive(w: *SegWorld) !void {
        var snap = w.s.snapshot();
        defer snap.release();
        var buf: [300]u8 = undefined;
        for (0..seg_cps * seg_objs) |obj| {
            const got = snap.liveObject(&idOf(base_id + obj)) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqualSlices(u8, payloadOf(&buf, obj, w.ver[obj]), got.bytes);
        }
    }

    fn hashes(w: *SegWorld, out: *[6]?u64) !void {
        for (out, 0..) |*h, e| h.* = try w.s.segmentLogicalHash(e);
    }

    /// The same history in every mode: updates that leave most chunks of the image nearly all
    /// live, a few with every record superseded, then two more epochs of the same.
    fn run(w: *SegWorld, out: *[3][6]?u64) !void {
        try w.image();
        // Epoch 1: a twentieth of the image, spread; and three whole checkpoints of it.
        var few: [seg_cps * seg_objs / 20]u64 = undefined;
        for (&few, 0..) |*o, i| o.* = (i * 20 + 7) % (seg_cps * seg_objs);
        try w.update(1, &few);
        for ([_]u64{ 5, 6, 30 }) |c| {
            var all: [seg_objs]u64 = undefined;
            for (&all, 0..) |*o, k| o.* = c * seg_objs + k;
            try w.update(1, &all);
        }
        try w.update(2, &.{0});
        try w.update(2, &.{1});
        try w.floors(1);
        try w.ageToEnd();
        try w.expectLive();
        try w.hashes(&out[0]);
        // Epoch 2 and 3: more of the image dies, the object window moves on.
        for ([_]u64{ 11, 12, 40, 41 }) |c| {
            var all: [seg_objs]u64 = undefined;
            for (&all, 0..) |*o, k| o.* = c * seg_objs + k;
            try w.update(2, &all);
        }
        try w.update(3, &few);
        try w.update(3, &.{2});
        try w.floors(2);
        try w.ageToEnd();
        try w.expectLive();
        try w.hashes(&out[1]);
        for ([_]u64{ 20, 21 }) |c| {
            var all: [seg_objs]u64 = undefined;
            for (&all, 0..) |*o, k| o.* = c * seg_objs + k;
            try w.update(3, &all);
        }
        try w.update(4, &.{3});
        try w.update(4, &.{4});
        try w.floors(3);
        try w.ageToEnd();
        try w.expectLive();
        try w.hashes(&out[2]);
    }
};

test "age-out segment pass: with the live set the same records survive as with a lookup per record, and far fewer lookups are made" {
    const gpa = std.testing.allocator;
    // Groups rewritten whole with a set that covers everything in one table pass; groups
    // rewritten chunk by chunk with a set of 64 bytes (512 cells, 32 KiB of segment) that
    // needs many.
    for ([_][2]u64{ .{ 64 << 10, 1 << 20 }, .{ 2 << 10, 64 } }) |v| {
        // One store at a time (the lane's memory): each leaves its hashes and its counters.
        var h_old: [3][6]?u64 = undefined;
        var h_new: [3][6]?u64 = undefined;
        var h_ver: [3][6]?u64 = undefined;
        var stats: [3]SegStats = undefined;
        inline for (.{ SegMode.serial, SegMode.set, SegMode.set_verify }, .{ &h_old, &h_new, &h_ver }, 0..) |mode, out, i| {
            var w = try SegWorld.open(gpa, mode, v[0], v[1]);
            defer w.close();
            try w.run(out);
            stats[i] = SegStats.of(w.s);
        }
        const old = &stats[0];
        const new = &stats[1];
        const ver = &stats[2];
        for (0..3) |phase| for (0..6) |e| {
            if (h_old[phase][e] != h_new[phase][e] or h_old[phase][e] != h_ver[phase][e]) {
                std.debug.print("whole {d} set {d}: phase {d} segment {d}: serial {?x}, live set {?x}, live set with lookups {?x}\n", .{ v[0], v[1], phase, e, h_old[phase][e], h_new[phase][e], h_ver[phase][e] });
                return error.TestUnexpectedResult;
            }
        };
        inline for (.{ old, new, ver }, .{ "serial", "live set", "live set + lookups" }) |x, name| {
            std.debug.print("segment pass ({s}; whole {d}, set {d} B): {d} lookups, {d} objects dropped, {d} chunks rewritten, {d} table passes, {d} kept by the set, {d} judged dead by it, {d} groups and {d} chunks left unexamined\n", .{
                name, v[0], v[1], x.lookups, x.objects_dropped, x.chunks_rewritten, x.set_builds, x.set_kept, x.set_dead, x.set_groups_skipped, x.set_chunks_skipped,
            });
        }
        // The set alone judged the dead; with the cross-check on, no clear bit was wrong.
        try std.testing.expect(new.set_dead > 0);
        try std.testing.expectEqual(@as(u64, 0), new.set_inexact);
        try std.testing.expectEqual(@as(u64, 0), ver.set_misses);
        try std.testing.expect(ver.lookups > new.lookups);
        // Something was freed, and the image is still held.
        try std.testing.expect(h_new[2][0] != null);
        try std.testing.expect(old.chunks_rewritten > 0);
        try std.testing.expect(new.set_builds >= 3);
        try std.testing.expect(new.set_kept > 0);
        try std.testing.expect(new.seg_passes >= 3);
        try std.testing.expect(new.set_groups_skipped + new.set_chunks_skipped > 0);
        if (v[1] == 64) try std.testing.expect(new.set_builds >= 12);
        // Serial looks every object record of every aged segment up, each pass.
        try std.testing.expect(old.lookups >= 3 * SegWorld.seg_cps * SegWorld.seg_objs);
        try std.testing.expect(new.lookups * 4 < old.lookups);
    }
}

test "age-out segment pass: a record that dies after the table pass named it is kept by that pass and goes with the next; no live record goes" {
    const gpa = std.testing.allocator;
    var w = try SegWorld.open(gpa, .set, 64 << 10, 1 << 20);
    defer w.close();
    try w.image();
    // One dead record in each of three groups: under an eighth, so none of them is rewritten.
    try w.update(1, &.{0});
    try w.update(2, &.{SegWorld.seg_objs});
    try w.update(2, &.{2 * SegWorld.seg_objs});
    try w.floors(1);
    // Steps until the table pass is done and the walk has begun, not ended.
    const st = &w.s.age_stats;
    var i: u32 = 0;
    while (st.set_builds.load(.monotonic) == 0) : (i += 1) {
        try std.testing.expect(i < 1000);
        _ = try w.s.ageStep(4096);
    }
    try std.testing.expectEqual(@as(u64, 0), st.seg_passes.load(.monotonic));
    // Commits race the pass: every object of checkpoints 40 to 43 (not walked yet) gets a new
    // version. The set still names their image records.
    const dropped0 = st.objects_dropped.load(.monotonic);
    for ([_]u64{ 40, 41, 42, 43 }) |c| {
        var all: [SegWorld.seg_objs]u64 = undefined;
        for (&all, 0..) |*o, k| o.* = c * SegWorld.seg_objs + k;
        try w.update(2, &all);
    }
    try w.ageToEnd();
    try w.expectLive();
    try std.testing.expectEqual(@as(u64, 1), st.seg_passes.load(.monotonic));
    // Kept by this pass: the set named them when the table was read.
    try std.testing.expectEqual(dropped0, st.objects_dropped.load(.monotonic));
    // The next pass (the object window moves on) names them no longer: they go.
    try w.update(3, &.{3 * SegWorld.seg_objs});
    try w.update(3, &.{4 * SegWorld.seg_objs});
    try w.floors(2);
    try w.ageToEnd();
    try w.expectLive();
    try std.testing.expect(st.objects_dropped.load(.monotonic) >= dropped0 + 4 * SegWorld.seg_objs);
    try std.testing.expectEqual(@as(u64, 0), st.set_misses.load(.monotonic));
    // A crash and a reopen: the image's live objects are all there.
    w.sim.scheduleCrash(0);
    w.s.deinit();
    w.sim.crash();
    w.s = try Store.open(gpa, .{ .sim = w.sim }, &w.cfg);
    try w.expectLive();
}

test "age-out: a snapshot held across a rewrite keeps reading the old frames; the punch waits for it" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 32, .{}, 64 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 8 << 10;
    cfg.age_lag_checkpoints = 0;
    cfg.cache_bytes = 0; // every read decodes its frame
    const s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var seq = try ageFill(s, 0, 0, 60);
    seq = try ageFill(s, seq, 1, 4);
    _ = try s.setFloors(.{ .cp_pruned = 30, .obj_pruned = 40, .cp_epoch = 0, .obj_epoch = 0 });
    try s.flushIndex();
    var held = s.snapshot();
    const punched0 = s.age_stats.phys_punched.load(.monotonic);
    _ = try s.ageStep(64 << 20);
    _ = try s.ageStep(64 << 20);
    // Rewritten and published, not punched: the held snapshot may still use the old directory.
    try std.testing.expectEqual(punched0, s.age_stats.phys_punched.load(.monotonic));
    var b1: [4096]u8 = undefined;
    for (31..64) |q| try std.testing.expectEqualSlices(u8, noise(q *% 31 + 1, b1[0..1024]), held.checkpoint(q).?.summary_cert);
    held.release();
    _ = try s.ageAll();
    try std.testing.expect(s.age_stats.phys_punched.load(.monotonic) > punched0);
    var snap = s.snapshot();
    defer snap.release();
    for (31..64) |q| try std.testing.expectEqualSlices(u8, noise(q *% 31 + 1, b1[0..1024]), snap.checkpoint(q).?.summary_cert);
}

test "real files: the ager's read-ahead reads live-table pages through the reader it reports (io_uring, or madvise and a touch)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var cfg = smallCfg();
    cfg.dir = path_buf[0..n];
    cfg.chunk_bytes = 16 << 10;
    cfg.age_lag_checkpoints = 0;
    const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    const s = h.store;
    defer s.close() catch {};
    var seq = try ageFill(s, 0, 0, 120);
    seq = try ageFill(s, seq, 1, 20);
    seq = try ageFill(s, seq, 2, 5);
    // The first step only places the cursors; then epoch 0 leaves the object window and every
    // object version in it is looked up. The flush makes the table's pages clean: a page the
    // writer holds dirty is in memory and is not read ahead.
    _ = try s.ageStep(4096);
    _ = try s.setFloors(.{ .cp_pruned = 119, .obj_pruned = 119, .cp_epoch = 1, .obj_epoch = 1 });
    try s.flushIndex();
    const reader = s.ageReader();
    const rep = try s.ageAll();
    try std.testing.expect(rep.records_dropped > 100);
    const st = &s.age_stats;
    const uring = st.warm_uring_pages.load(.monotonic);
    const fallback = st.warm_fallback_pages.load(.monotonic);
    std.debug.print("age-out read-ahead: reader {s}, {d} pages through io_uring, {d} by the fallback, {d} errors\n", .{ @tagName(reader), uring, fallback, st.warm_errors.load(.monotonic) });
    try std.testing.expect(st.lookups.load(.monotonic) > 100);
    try std.testing.expectEqual(@as(u64, 0), st.warm_errors.load(.monotonic));
    switch (reader) {
        .uring => try std.testing.expect(uring > 0 and fallback == 0),
        .fallback => try std.testing.expect(fallback > 0 and uring == 0),
        .none => return error.TestUnexpectedResult,
    }
    // Off Linux there is no io_uring.
    if (@import("builtin").os.tag != .linux) try std.testing.expectEqual(Store.AgeReader.fallback, reader);
    try ageExpectLive(s, seq);
}

test "real files: a close does not wait for a saturated ager (pending set full, checkpoint pass unable to move)" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var cfg = smallCfg();
    cfg.dir = path_buf[0..n];
    cfg.max_live_objects = 4096;
    cfg.max_object_versions = 1 << 17;
    cfg.max_batch_objects = 1024;
    cfg.segment_reserve = 64 << 20;
    cfg.age_lag_checkpoints = 0;
    cfg.age_pending_max = 40_000;
    cfg.age_budget = 64 << 20; // the whole epoch is one step
    cfg.age_mbps = 1 << 20; // no pacing naps
    const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
    defer h.io.deinit();
    const s = h.store;
    var is_open = true;
    defer if (is_open) s.deinit();
    // 300 checkpoints, each a new version of the same 400 objects: 119,600 records name a
    // previous version, three times what the pending set holds.
    const payload: [16]u8 = @splat(0x5a);
    for (0..300) |seq| {
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        for (0..400) |o| try put(b, 7000 + o, seq + 1, &payload);
        try s.commit(b);
    }
    for (300..303) |seq| {
        const b = try s.begin(seq, 1);
        try b.checkpoint("summary", "contents");
        try put(b, 9000, seq, &payload);
        try s.commit(b);
    }
    // The object floor at the end of epoch 0, no checkpoint floor: the scan goes through every
    // group, the checkpoint pass cannot move, so nothing in the pending set is ever behind it
    // (on a test machine a raw segment in the window had the same effect).
    _ = try s.setFloors(.{ .obj_pruned = 298 });
    try s.flushIndex();
    try s.startAgerMode(.on);
    const st = &s.age_stats;
    const clock = @import("clock.zig");
    const t_wait = clock.now();
    while (st.pending_full.load(.monotonic) == 0) {
        try std.testing.expect(clock.now() - t_wait < 120 * std.time.ns_per_s);
        clock.sleep(std.time.ns_per_ms);
    }
    // Saturated, and in the middle of the step that found it so. Close now.
    const t0 = clock.now();
    is_open = false;
    try s.close();
    const ms = (clock.now() - t0) / std.time.ns_per_ms;
    std.debug.print("close with a saturated ager: {d} ms\n", .{ms});
    // The bound: the ager gives up within its next check, and the close is a flush of a small
    // table. Before, the step went on with a pass over the whole pending set for every
    // remaining record of its groups, and the close waited for all of it.
    try std.testing.expect(ms < 2000);
}

test "age-out stop: a stop at every point of a step, its read-ahead, a table pass and a bulk catch-up leaves a store that closes or crashes clean and ages on" {
    const gpa = std.testing.allocator;
    const Kind = enum { lookups, live_set, bulk };
    var stops: [3]u32 = @splat(0);
    for ([_]Kind{ .lookups, .live_set, .bulk }, 0..) |kind, ki| {
        var k: u64 = 0;
        var rounds: u32 = 0;
        while (true) : (rounds += 1) {
            try std.testing.expect(rounds < 400);
            var w = try SegWorld.open(gpa, if (kind == .live_set) .set else .set_verify, 2 << 10, 256);
            defer w.close();
            if (kind != .live_set) {
                // The lookup path: read-ahead, no live set.
                w.s.cfg.age_live_set = false;
                w.cfg.age_live_set = false;
            }
            try w.image();
            for ([_]u64{ 5, 6, 30 }) |c| {
                var all: [SegWorld.seg_objs]u64 = undefined;
                for (&all, 0..) |*o, i| o.* = c * SegWorld.seg_objs + i;
                try w.update(1, &all);
            }
            try w.update(2, &.{0});
            try w.update(2, &.{1});
            try w.floors(1);
            // The first step places the cursors; the stop is counted from the next one.
            _ = try w.s.ageStep(4096);
            w.s.age_stop_at = k;
            var i: u32 = 0;
            var idle = false;
            while (!idle and !w.s.age_stop.load(.monotonic)) : (i += 1) {
                try std.testing.expect(i < 20000);
                const budget: u64 = if (i % 3 == 0) 4096 else if (i % 3 == 1) 24 << 10 else 1 << 20;
                idle = (try w.s.ageStepOpts(budget, .{ .skip_seg = kind == .bulk })).idle;
            }
            const stopped = w.s.age_stop.load(.monotonic);
            if (stopped) {
                stops[ki] += 1;
                // The stopped step wrote nothing: no batch is open, and the store reads whole.
                try std.testing.expect(w.s.ager.batch_c == null);
                try w.expectLive();
            }
            // A close, or a crash, and a reopen.
            if (k % 2 == 0) {
                try w.s.close();
            } else {
                w.sim.scheduleCrash(0);
                w.s.deinit();
                w.sim.crash();
            }
            w.s = try Store.open(gpa, .{ .sim = w.sim }, &w.cfg);
            try w.expectLive();
            // And age-out runs to its end from what is durable.
            try w.ageToEnd();
            try w.expectLive();
            if (!stopped) break; // the countdown outlasted the work
            // Every point at first, then in growing strides.
            k += 1 + k / 6;
        }
    }
    std.debug.print("age-out stop points hit: {d} (lookups), {d} (live set), {d} (bulk)\n", .{ stops[0], stops[1], stops[2] });
    try std.testing.expect(stops[0] > 20 and stops[1] > 20 and stops[2] > 10);
}

test "age-out segment pass: a restored version superseded in an epoch still inside the object window stays readable through its link (stores without read sets: edges)" {
    const gpa = std.testing.allocator;
    // Serial lookups, the live set, the live set with its cross-check.
    for ([_]SegMode{ .serial, .set, .set_verify }) |mode| {
        const sim = try SimIo.init(gpa, 93, .{}, 2 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.codec = testCodec;
        cfg.max_live_objects = 4096;
        cfg.segment_reserve = 2 << 20;
        cfg.chunk_bytes = 4 << 10;
        cfg.age_lag_checkpoints = 1;
        cfg.age_serial = mode == .serial;
        cfg.age_live_set = mode != .serial;
        cfg.age_set_verify = mode == .set_verify;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        // Epoch 0, the image: 600 compact records of version 3, then the restored checkpoint.
        const total = 600;
        for (0..6) |g| {
            const b = try s.begin(g, 0);
            for (0..100) |i| {
                var pl: [120]u8 = @splat('x');
                try putT(b, true, 30_000 + g * 100 + i, 3, pl[0 .. 60 + (i * 7) % 60]);
            }
            try s.commit(b);
        }
        {
            const b = try s.begin(40, 0);
            try b.checkpoint("s40", "c");
            try s.commit(b);
        }
        // Epoch 1: every second object gets version 4 (a link names its restored record: no
        // read sets, so no cross-reference). Epoch 2: one checkpoint.
        var seq: u64 = 41;
        for (0..6) |g| {
            const b = try s.begin(seq, 1);
            try b.checkpoint("s", "c");
            var i: u64 = 0;
            while (i < 100) : (i += 2) try putT(b, false, 30_000 + g * 100 + i, 4, "superseding");
            try s.commit(b);
            seq += 1;
        }
        // The end of epoch 1: a close seals the index entries (the links) into a run of epoch 1,
        // as a node's are sealed while the epoch runs.
        try s.close();
        s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        {
            const b = try s.begin(seq, 2);
            try b.checkpoint("s", "c");
            try s.commit(b);
            seq += 1;
        }
        // As a node a day after its restore: checkpoints from epoch 1 on are held, and the
        // object floor is still inside epoch 1, below every checkpoint that superseded
        // something. The image (epoch 0) is an aged segment, kept for its live objects.
        _ = try s.setFloors(.{ .cp_pruned = 40, .obj_pruned = 40, .cp_epoch = 1, .obj_epoch = 1 });
        try s.flushIndex();
        const Check = struct {
            fn all(st: *Store) !u64 {
                var snap = st.snapshot();
                defer snap.release();
                var missing: u64 = 0;
                for (0..total) |n| {
                    const id = idOf(30_000 + n);
                    const superseded = n % 2 == 0;
                    try std.testing.expectEqual(@as(u64, if (superseded) 4 else 3), snap.liveObject(&id).?.version);
                    // sui-node keeps a version until the checkpoint that superseded it is
                    // pruned; here none is.
                    if ((try snap.objectAtChecked(&id, 3)) == null) missing += 1;
                }
                return missing;
            }
        };
        try std.testing.expectEqual(@as(u64, 0), try Check.all(s));
        const rep = try s.ageAll();
        if (mode != .serial) try std.testing.expect(s.age_stats.set_builds.load(.monotonic) >= 1 and s.age_stats.set_links.load(.monotonic) >= 300);
        if (mode == .serial) try std.testing.expectEqual(@as(u64, 300), s.age_stats.link_kept.load(.monotonic));
        const missing = try Check.all(s);
        if (missing != 0) std.debug.print("segment pass ({s}): {d} of 300 restored versions superseded inside the object window no longer read ({d} records dropped, {d} chunks rewritten)\n", .{ @tagName(mode), missing, rep.records_dropped, rep.chunks_rewritten });
        try std.testing.expectEqual(@as(u64, 0), missing);
        // The object floor past epoch 1: now they go, and the pass frees them.
        {
            const b = try s.begin(seq, 3);
            try b.checkpoint("s", "c");
            try s.commit(b);
            seq += 1;
        }
        _ = try s.setFloors(.{ .cp_pruned = seq - 2, .obj_pruned = seq - 2, .cp_epoch = 2, .obj_epoch = 2 });
        try s.flushIndex();
        const rep2 = try s.ageAll();
        try std.testing.expect(rep.records_dropped + rep2.records_dropped >= 300);
        var snap = s.snapshot();
        defer snap.release();
        for (0..total) |n| {
            try std.testing.expectEqual(@as(u64, if (n % 2 == 0) 4 else 3), snap.liveObject(&idOf(30_000 + n)).?.version);
            if (n % 2 == 0) try std.testing.expect((try snap.objectAtChecked(&idOf(30_000 + n), 3)) == null);
        }
    }
}

test "age-out pending set: a superseded record behind both passes (a restore image's) is never remembered, so the set keeps its room for the window" {
    const gpa = std.testing.allocator;
    var w = try SegWorld.open(gpa, .serial, 64 << 10, 1 << 20);
    defer w.close();
    w.s.cfg.age_serial = false;
    // Room for 40 locations; the image loses 72 records to epoch 1 and 24 more to epoch 2.
    w.s.cfg.age_pending_max = 40;
    try w.image();
    for ([_]u64{ 5, 6, 30 }) |c| {
        var all: [SegWorld.seg_objs]u64 = undefined;
        for (&all, 0..) |*o, i| o.* = c * SegWorld.seg_objs + i;
        try w.update(1, &all);
    }
    // Inside the window: checkpoint 5's objects get a third version (their second is in epoch 1).
    {
        var all: [SegWorld.seg_objs]u64 = undefined;
        for (&all, 0..) |*o, i| o.* = 5 * SegWorld.seg_objs + i;
        try w.update(1, &all);
    }
    for ([_]u64{40}) |c| {
        var all: [SegWorld.seg_objs]u64 = undefined;
        for (&all, 0..) |*o, i| o.* = c * SegWorld.seg_objs + i;
        try w.update(2, &all);
    }
    try w.update(2, &.{0});
    try w.floors(1);
    try w.ageToEnd();
    try w.expectLive();
    const st = &w.s.age_stats;
    // The image's 96 (and object 0's one) were behind both passes when their successors were
    // scanned: not remembered, and not counted as lost. The 24 inside the window were
    // remembered, in a set of 40 that never filled.
    try std.testing.expect(st.pending_behind.load(.monotonic) >= 72);
    try std.testing.expectEqual(@as(u64, 0), st.pending_full.load(.monotonic));
    try std.testing.expect(st.objects_dropped.load(.monotonic) >= 24);
}

test "age-out memory: a pending set driven to its cap stays inside its share of age_mem_bytes, and the ager inside the whole" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 57, .{}, 32 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.max_live_objects = 4096;
    cfg.max_object_versions = 1 << 17;
    cfg.max_batch_objects = 1024;
    cfg.segment_reserve = 32 << 20;
    cfg.age_lag_checkpoints = 0;
    // 4 MiB for the ager: 1 MiB for the pending set, which is a table of 65,536 slots at most
    // (9 bytes each, and half as much again while it doubles) and so 52,427 entries.
    cfg.age_mem_bytes = 4 << 20;
    const s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try std.testing.expectEqual(@as(u64, 52_427), s.agePendingMax());
    // 160 checkpoints, each a new version of the same 400 objects: 63,600 records name a
    // previous version. No checkpoint floor, so nothing in the set is ever behind the
    // checkpoint pass and the set fills to its cap.
    const payload: [16]u8 = @splat(0x5a);
    for (0..160) |seq| {
        const b = try s.begin(seq, 0);
        try b.checkpoint("summary", "contents");
        for (0..400) |o| try put(b, 7000 + o, seq + 1, &payload);
        try s.commit(b);
    }
    for (160..163) |seq| {
        const b = try s.begin(seq, 1);
        try b.checkpoint("summary", "contents");
        try put(b, 9000, seq, &payload);
        try s.commit(b);
    }
    _ = try s.setFloors(.{ .obj_pruned = 158 });
    try s.flushIndex();
    const st = &s.age_stats;
    var steps: u64 = 0;
    var idle = false;
    while (!idle) : (steps += 1) {
        try std.testing.expect(steps < 5000);
        idle = (try s.ageStep(512 << 10)).idle;
        try std.testing.expect(st.mem.load(.monotonic) <= cfg.age_mem_bytes);
    }
    // Full, at the cap, inside its quarter; the whole inside the budget at every step.
    try std.testing.expect(st.pending_full.load(.monotonic) > 5000);
    try std.testing.expectEqual(@as(u64, 52_427), st.pending.load(.monotonic));
    try std.testing.expect(@as(u64, s.ager.pending.capacity()) * 9 * 3 / 2 <= cfg.age_mem_bytes / 4);
    try std.testing.expect(st.mem_pending.load(.monotonic) <= cfg.age_mem_bytes / 4);
    try std.testing.expect(st.mem_max.load(.monotonic) <= cfg.age_mem_bytes);
    try std.testing.expect(st.mem_max.load(.monotonic) >= st.mem_pending.load(.monotonic));
    // A full set is pruned once per move of the checkpoint pass, never once per record.
    try std.testing.expect(st.pending_prunes.load(.monotonic) <= steps);
    std.debug.print("age-out memory: budget {d} KiB, most held {d} KiB, pending set {d} KiB for {d} entries, {d} records not remembered, {d} prune passes in {d} steps\n", .{
        cfg.age_mem_bytes >> 10, st.mem_max.load(.monotonic) >> 10, st.mem_pending.load(.monotonic) >> 10, st.pending.load(.monotonic), st.pending_full.load(.monotonic), st.pending_prunes.load(.monotonic), steps,
    });
    // The store's default budget and the configured entry count: the smaller wins.
    var d = smallCfg();
    d.dir = "";
    const sim2 = try SimIo.init(gpa, 58, .{}, 8 << 20);
    defer sim2.deinit();
    const s2 = try Store.open(gpa, .{ .sim = sim2 }, &d);
    defer s2.deinit();
    try std.testing.expectEqual(@as(u64, 3_355_442), s2.agePendingMax());
    s2.cfg.age_pending_max = 1000;
    try std.testing.expectEqual(@as(u64, 1000), s2.agePendingMax());
}

test "real files: age-out at retention 0 across an epoch change frees the bytes (st_blocks) and reads stay correct" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [512]u8 = undefined;
    const n = try tmp.dir.realPath(io, &path_buf);
    var cfg = smallCfg();
    cfg.dir = path_buf[0..n];
    cfg.chunk_bytes = 64 << 10;
    cfg.age_lag_checkpoints = 0;
    var seq: u64 = 0;
    var e0_last: u64 = 0;
    {
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        const s = h.store;
        defer s.close() catch {};
        seq = try ageFill(s, 0, 0, 300);
        seq = try ageFill(s, seq, 1, 300);
        e0_last = seq - 1;
        // The synthetic epoch change.
        seq = try ageFill(s, seq, 2, 5);
        const before = s.segmentDisk();
        // --retention-epochs 0 --object-retention-epochs 0: both floors at the end of epoch 1.
        _ = try s.setFloors(.{ .cp_pruned = e0_last, .obj_pruned = e0_last, .cp_epoch = 2, .obj_epoch = 2 });
        try s.flushIndex();
        const rep = try s.ageAll();
        const after = s.segmentDisk();
        std.debug.print("age-out retention 0: segment files {d} -> {d} bytes on disk (logical {d}, sidecars {d}); {d} records dropped, {d} chunks rewritten, {d} bytes punched\n", .{
            before.disk, after.disk, after.logical, after.side, rep.records_dropped, rep.chunks_rewritten, s.age_stats.phys_punched.load(.monotonic),
        });
        try std.testing.expect(after.disk * 4 < before.disk);
        try ageExpectLive(s, seq);
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.checkpoint(e0_last) == null);
        try std.testing.expectEqual(@as(?u64, e0_last + 1), snap.lowestAvailable());
        var b1: [4096]u8 = undefined;
        for (e0_last + 1..seq) |q| try std.testing.expectEqualSlices(u8, noise(q *% 31 + 1, b1[0..1024]), snap.checkpoint(q).?.summary_cert);
    }
    {
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        try h.store.close();
    }
    {
        // Reopen: the age logs put the rewritten chunks back; nothing is lost or replayed wrong.
        const h = try root.openDir(gpa, io, &cfg, .{ .sync = .none });
        defer h.io.deinit();
        defer h.store.deinit();
        try ageExpectLive(h.store, seq);
        var snap = h.store.snapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(?u64, seq - 1), snap.highestCommitted());
    }
}

/// Commits checkpoint `seq` (epoch 0): `n` objects of 1000 incompressible bytes.
fn commitNoise(s: *Store, seq: u64, n: u64) !void {
    var prng: std.Random.DefaultPrng = .init(seq);
    var payload: [1000]u8 = undefined;
    const b = try s.begin(seq, 0);
    try b.checkpoint("s", "c");
    for (0..n) |i| {
        prng.random().bytes(&payload);
        try put(b, seq * 1000 + i, seq, &payload);
    }
    try s.commit(b);
}

test "torn or rotted newest group: torn and rot with nothing durable after it truncate, rot before durable data or under dir entries is Corrupt (2a)" {
    const gpa = std.testing.allocator;
    const io_mod = root.io;
    const chunk = root.chunk;
    for ([_]bool{ true, false }) |compress| {
        // 1. The newest group's first frame (raw: first sector) never landed, the rest did:
        // what a torn multi-chunk write leaves. Nothing after it: truncate. Before the fix the
        // surviving later frames of the same group read as "durable data follows" (Corrupt).
        {
            const sim = try SimIo.init(gpa, 550, .{}, 8 << 20);
            defer sim.deinit();
            var cfg = smallCfg();
            cfg.compress = compress;
            cfg.chunk_bytes = 4096;
            var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
            for (1..6) |q| try commitNoise(s, q, 20);
            const tg = s.tailGroup().?;
            try std.testing.expect(tg.phys_end - tg.phys > 3 * 4096);
            s.deinit();
            var nb: [64]u8 = undefined;
            const name = io_mod.segName(&nb, tg.epoch);
            try std.testing.expect(sim.zeroAt(name, tg.phys, 512));
            sim.crash();
            s = try Store.open(gpa, .{ .sim = sim }, &cfg);
            defer s.deinit();
            try std.testing.expectEqual(@as(?u64, 4), s.committed());
        }
        // 2. Rot inside the newest-but-one group, a durable group after it: Corrupt.
        {
            const sim = try SimIo.init(gpa, 551, .{}, 8 << 20);
            defer sim.deinit();
            var cfg = smallCfg();
            cfg.compress = compress;
            cfg.chunk_bytes = 4096;
            var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
            for (1..6) |q| try commitNoise(s, q, 20);
            const tg = s.tailGroup().?;
            try commitNoise(s, 6, 20);
            s.deinit();
            var nb: [64]u8 = undefined;
            const name = io_mod.segName(&nb, tg.epoch);
            try std.testing.expect(sim.rotAt(name, tg.phys + @as(u64, if (compress) chunk.frame_len + 100 else 300)));
            sim.crash();
            try std.testing.expectError(error.Corrupt, Store.open(gpa, .{ .sim = sim }, &cfg));
        }
    }
    // 3. Compressed: rot in the newest group with nothing after it, but the dir file names its
    // chunks (written only after the group's writeSync returned): Corrupt, never truncate.
    // Without the dir entries the same damage truncates (case 1).
    {
        const sim = try SimIo.init(gpa, 552, .{ .persist_256 = 256, .torn_sectors = false, .meta_persist_256 = 256 }, 8 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.chunk_bytes = 1024;
        cfg.max_batch_objects = 1024;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (1..3) |q| try commitNoise(s, q, 20);
        // Past the dir batch: its entries are written (unsynced, kept by this crash model).
        try commitNoise(s, 3, 300);
        const tg = s.tailGroup().?;
        s.deinit();
        var nb: [64]u8 = undefined;
        const name = io_mod.segName(&nb, tg.epoch);
        sim.crash();
        try std.testing.expect(sim.rotAt(name, tg.phys_end - 4096 - 64));
        try std.testing.expectError(error.Corrupt, Store.open(gpa, .{ .sim = sim }, &cfg));
    }
}

test "a compressed segment whose first write was lost opens as raw, and its later frames still refuse the truncation (store-dst misdir/4065)" {
    const gpa = std.testing.allocator;
    const io_mod = root.io;
    const sim = try SimIo.init(gpa, 4065, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.chunk_bytes = 4096;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try commitNoise(s, 1, 20);
    const first = s.tailGroup().?;
    for (2..5) |q| try commitNoise(s, q, 20);
    s.deinit();
    // The segment's first write (file header and the first group) never reached the disk.
    var nb: [64]u8 = undefined;
    try std.testing.expect(sim.zeroAt(io_mod.segName(&nb, first.epoch), 0, first.phys_end));
    sim.crash();
    try std.testing.expectError(error.Corrupt, Store.open(gpa, .{ .sim = sim }, &cfg));
}

test "an old live table is freed only after the next meta: a rotted newest meta falls back to the older slot without a rebuild (2b)" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 2, .{ .meta_persist_256 = 256 }, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.index_flush_interval = 1000;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    var seq: u64 = 0;
    while (s.stats.live_grows == 0) {
        seq += 1;
        const b = try s.begin(seq, 0);
        try b.checkpoint("s", "c");
        for (0..200) |i| try put(b, seq * 1000 + i, seq, "grow");
        try s.commit(b);
        try std.testing.expect(seq < 40);
    }
    // The grow wrote one meta naming the new table; the other slot still names the old one.
    const newest = s.meta_slot;
    try s.backend.syncDir();
    s.deinit();
    sim.crash();
    try std.testing.expect(sim.rotAt("meta", newest * 4096 + 16));
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    try std.testing.expect(!s.stats.rebuilt_index);
    try std.testing.expectEqual(@as(?u64, seq), s.committed());
    var snap = s.snapshot();
    defer snap.release();
    for (1..seq + 1) |q| for (0..200) |i| try std.testing.expectEqualStrings("grow", (try snap.latest(&idOf(q * 1000 + i))).?.live.bytes);
}

// ------------------------------------------------------------- hinted lookups and run filters

const NearKey = struct { id: u64, version: u64 };
const NearTx = struct { digest: [32]u8, cp: u64, keys: [6]NearKey = undefined, nkeys: u8 = 0, loaded: bool = false };

fn nearPayload(buf: []u8, id: u64, version: u64) []const u8 {
    return std.fmt.bufPrint(buf, "o{d}v{d}", .{ id, version }) catch unreachable;
}

fn expectSameBytes(want: ?[]const u8, got: ?[]const u8) !void {
    if (want) |w| {
        try std.testing.expect(got != null);
        try std.testing.expectEqualSlices(u8, w, got.?);
    } else try std.testing.expect(got == null);
}

fn expectSameTx(want: ?root.TransactionRecord, got: ?root.TransactionRecord) !void {
    if (want) |w| {
        const g = got orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(w.checkpoint, g.checkpoint);
        try std.testing.expectEqual(w.loc, g.loc);
        try std.testing.expectEqualSlices(u8, w.digest, g.digest);
        try std.testing.expectEqualSlices(u8, w.tx, g.tx);
        try std.testing.expectEqualSlices(u8, w.effects, g.effects);
    } else try std.testing.expect(got == null);
}

/// Every hinted lookup of `txs` through `snap` against the plain one: right hints, wrong hints,
/// no hint. Returns how many transactions the snapshot holds.
fn checkNear(snap: *root.Snapshot, txs: []const NearTx, rnd: std.Random) !usize {
    var held: usize = 0;
    for (txs) |t| {
        const plain = snap.transaction(&t.digest);
        try expectSameTx(plain, snap.transactionNear(&t.digest, t.cp));
        try expectSameTx(plain, snap.transactionNear(&t.digest, t.cp + 1 + rnd.uintLessThan(u64, 20)));
        try expectSameTx(plain, snap.transactionNear(&t.digest, t.cp -| (1 + rnd.uintLessThan(u64, 20))));
        if (plain) |p| {
            held += 1;
            try std.testing.expectEqual(t.cp, p.checkpoint);
            try std.testing.expect(p.loc != 0);
            try std.testing.expectEqualStrings("tx", p.tx);
        }
        // The right hint, another transaction's, a location before every run, one after all.
        const other = txs[rnd.uintLessThan(usize, txs.len)];
        const other_loc = if (snap.transaction(&other.digest)) |o| o.loc else 0;
        const hints = [_]u64{ if (plain) |p| p.loc else 0, other_loc, 8, @as(u64, 1) << 62 };
        var buf: [64]u8 = undefined;
        for (t.keys[0..t.nkeys]) |k| {
            const want = snap.objectAt(&idOf(k.id), k.version);
            if (want) |w| try std.testing.expectEqualStrings(nearPayload(&buf, k.id, k.version), w);
            for (hints) |h| try expectSameBytes(want, snap.objectNear(&idOf(k.id), k.version, h));
        }
        const lw = snap.objectAt(&t.digest, root.aux_loaded);
        if (lw) |w| try std.testing.expectEqualSlices(u8, t.digest[0..16], w);
        if (!t.loaded) try std.testing.expect(lw == null);
        for (hints) |h| try expectSameBytes(lw, snap.objectNear(&t.digest, root.aux_loaded, h));
    }
    return held;
}

fn nearRandomStore(seed: u64, resident: bool) !void {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, seed, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    // Small memtables: many runs per epoch, so the hints and filters have runs to skip.
    cfg.max_object_versions = 48;
    cfg.max_transactions = 16;
    cfg.max_checkpoints = 8;
    cfg.retention_epochs = 2;
    cfg.run_filters_resident = resident;
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var prng: std.Random.DefaultPrng = .init(seed *% 0x9e3779b97f4a7c15 +% 1);
    const rnd = prng.random();

    var txs: std.ArrayList(NearTx) = .empty;
    defer txs.deinit(gpa);
    var written: std.ArrayList(NearKey) = .empty;
    defer written.deinit(gpa);
    var cur: [24]u64 = @splat(0);
    var old_snap: ?root.Snapshot = null;
    defer if (old_snap) |*o| o.release();
    var seq: u64 = 0;
    var buf: [64]u8 = undefined;
    const efd: [32]u8 = @splat(0xef);
    const zero: [32]u8 = @splat(0);

    for (0..6) |epoch| {
        for (0..10) |_| {
            seq += 1;
            const b = try s.begin(seq, epoch);
            try b.checkpoint("summary", "contents");
            const ntx = 1 + rnd.uintLessThan(usize, 3);
            var new_keys: [12]NearKey = undefined;
            var nnew: usize = 0;
            for (0..ntx) |_| {
                var t: NearTx = .{ .digest = undefined, .cp = seq };
                rnd.bytes(&t.digest);
                const tx_first = rnd.boolean();
                if (tx_first) try b.transaction(&t.digest, &efd, "tx", "fx", null);
                // Inputs: versions written before (possibly superseded since, or pruned).
                for (0..rnd.uintLessThan(usize, 3)) |_| {
                    if (written.items.len == 0) break;
                    t.keys[t.nkeys] = written.items[rnd.uintLessThan(usize, written.items.len)];
                    t.nkeys += 1;
                }
                // Outputs.
                for (0..1 + rnd.uintLessThan(usize, 3)) |_| {
                    const id = rnd.uintLessThan(u64, cur.len);
                    cur[id] += 1 + rnd.uintLessThan(u64, 3);
                    try put(b, id, cur[id], nearPayload(&buf, id, cur[id]));
                    t.keys[t.nkeys] = .{ .id = id, .version = cur[id] };
                    t.nkeys += 1;
                    new_keys[nnew] = t.keys[t.nkeys - 1];
                    nnew += 1;
                }
                if (rnd.uintLessThan(u8, 3) != 0) {
                    try b.putHistorical(&t.digest, root.aux_loaded, &zero, t.digest[0..16]);
                    t.loaded = true;
                }
                if (!tx_first) try b.transaction(&t.digest, &efd, "tx", "fx", null);
                try txs.append(gpa, t);
            }
            try s.commit(b);
            try written.appendSlice(gpa, new_keys[0..nnew]);
        }
        _ = try s.pruneRetained();
        if (epoch == 3) {
            // Runs reopened from their files (their filters loaded, or pinned, at open).
            try s.close();
            s = try Store.open(gpa, .{ .sim = sim }, &cfg);
            old_snap = s.snapshot();
        }
    }
    try std.testing.expect(s.stats.runs_sealed > 0);

    const ps0 = root.probeStats().*;
    var snap = s.snapshot();
    defer snap.release();
    const held = try checkNear(&snap, txs.items, rnd);
    // The current epoch's transactions and the outputs they wrote are all held (no filter or
    // hint loses one).
    var last_epoch: usize = 0;
    for (txs.items) |t| if (t.cp > 50) {
        last_epoch += 1;
        try std.testing.expect(snap.transaction(&t.digest) != null);
    };
    try std.testing.expect(held >= last_epoch and last_epoch > 0);
    for (written.items[written.items.len - 10 ..]) |k| try std.testing.expect(snap.objectAt(&idOf(k.id), k.version) != null);
    const ps = root.probeStats().*;
    try std.testing.expect(ps.near_hits > ps0.near_hits);
    try std.testing.expect(ps.filter_skips > ps0.filter_skips);
    // A snapshot from before the last epochs: what it cannot see, both lookups miss alike.
    _ = try checkNear(&old_snap.?, txs.items, rnd);
}

test "hinted lookups (transactionNear, objectNear) answer as the plain ones over random stores, with wrong hints, across runs, epochs, pruning and a reopen; run filters lose no key" {
    for (1..9) |seed| try nearRandomStore(seed, seed % 2 == 0);
}

/// Epochs 0..4 as in the liveness retention test: a compact restored base (epoch 0), epoch 1
/// mostly dead (15 of its objects stay live), epochs 0 and 1 aged out.
fn cleanScenario(s: *Store) !u64 {
    for (0..2) |g| {
        const b = try s.begin(g, 0);
        for (0..100) |i| try putT(b, true, 1000 + g * 100 + i, 3, "base-object-bytes");
        try s.commit(b);
    }
    {
        const b = try s.begin(40, 0);
        try b.checkpoint("s40", "c");
        try s.commit(b);
    }
    var seq: u64 = 41;
    var epoch: u64 = 1;
    while (epoch <= 4) : (epoch += 1) {
        for (0..3) |c| {
            const b = try s.begin(seq, epoch);
            try b.checkpoint("s", "c");
            try putT(b, false, 1, seq, "hot");
            // Epoch 1 has three commit groups (one per checkpoint): a sweep can stop between them.
            if (epoch == 1 and c == 0) {
                for (0..10) |i| try putT(b, false, 1000 + i, seq, "touched");
                for (0..20) |i| try putT(b, false, 2000 + i, seq, "new");
            }
            if (epoch == 2 and c == 0) for (0..15) |i| try putT(b, false, 2000 + i, seq, "again");
            try s.commit(b);
            seq += 1;
        }
    }
    const rep = try s.ageRetained();
    try std.testing.expectEqual(@as(u64, 2), rep.segments_aged);
    return seq;
}

test "cleaning paced by a deadline (lane catchup-1306): a deadline already past still advances one window or group per step and ends where an unpaced clean ends" {
    const gpa = std.testing.allocator;
    var results: [2]struct { steps: usize, carried: u64, dropped: u64, cut: u64 } = undefined;
    for (0..2) |run| {
        const sim = try SimIo.init(gpa, 21, .{}, 8 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.codec = testCodec;
        cfg.clean_record_bytes = 64;
        const s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        var seq = try cleanScenario(s);
        var carried: u64 = 0;
        var dropped: u64 = 0;
        var steps: usize = 0;
        while (true) : (steps += 1) {
            try std.testing.expect(steps < 20_000);
            // run 0: bytes only; run 1: a deadline that has passed (1 ns after boot), so every
            // step stops at its first check, with a tiny budget to need many steps either way.
            const r = if (run == 0) try s.cleanStep(4096) else try s.cleanStepUntil(1 << 20, 1);
            carried += r.objects_carried;
            dropped += r.segments_dropped;
            if (r.idle) break;
            const b = try s.begin(seq, 4);
            try b.checkpoint("s", "c");
            try putT(b, false, 1, seq, "hot");
            try s.commit(b);
            seq += 1;
        }
        const pr = s.cleanProgress();
        try std.testing.expectEqual(@as(u8, 0), pr.phase);
        // The simulator has no page cache: nothing is read ahead there.
        try std.testing.expectEqual(@as(u64, 0), pr.table_ahead);
        results[run] = .{ .steps = steps, .carried = carried, .dropped = dropped, .cut = pr.cut };
        // Every live object of epoch 1 is still readable, wherever it went.
        var snap = s.snapshot();
        defer snap.release();
        for (0..10) |i| try expectObj(&snap, 1000 + i, 41);
        for (15..20) |i| try expectObj(&snap, 2000 + i, 41);
        for (0..15) |i| try expectObj(&snap, 2000 + i, 44);
        try expectObj(&snap, 1150, 3);
    }
    try std.testing.expectEqual(@as(u64, 1), results[0].dropped);
    try std.testing.expectEqual(@as(u64, 15), results[0].carried);
    try std.testing.expectEqual(results[0].dropped, results[1].dropped);
    try std.testing.expectEqual(results[0].carried, results[1].carried);
    try std.testing.expectEqual(@as(u64, 0), results[0].cut);
    // The live-table count pass (1024 slots: a few pages) fits one window; the sweep of epoch 1
    // has one group per checkpoint, so the paced run cut at least once.
    try std.testing.expect(results[1].cut > 0);
}

/// Lane disk-fit history-dictionary tests: checkpoint `seq` of epoch `seq / 40` writes 8 object
/// versions whose bytes repeat earlier checkpoints' (as the chain repeats recent objects).
const DictPool = struct {
    blobs: [64][1500]u8,

    fn init() DictPool {
        var p: DictPool = undefined;
        var x: u64 = 77;
        for (&p.blobs) |*b| for (b) |*c| {
            x = x *% 6364136223846793005 +% 1442695040888963407;
            c.* = @truncate(x >> 33);
        };
        return p;
    }

    fn blob(p: *const DictPool, seq: u64, k: u64) []const u8 {
        return &p.blobs[(seq * 5 + k) % 64];
    }

    fn commit(p: *const DictPool, s: *Store, seq: u64) !void {
        const b = try s.begin(seq, seq / 40);
        try b.checkpoint("summary", "contents");
        for (0..8) |k| try put(b, (seq * 8 + k) % 200 + 1, seq, p.blob(seq, k));
        try s.commit(b);
    }

    /// Every checkpoint and object version of checkpoints 1..last reads back byte for byte.
    fn check(p: *const DictPool, s: *Store, last: u64) !void {
        var snap = s.snapshot();
        defer snap.release();
        try std.testing.expect(snap.highestCommitted().? >= last);
        for (1..last + 1) |seq| {
            try std.testing.expectEqualStrings("summary", snap.checkpoint(seq).?.summary_cert);
            for (0..8) |k| try std.testing.expectEqualSlices(u8, p.blob(seq, k), snap.objectAt(&idOf((seq * 8 + k) % 200 + 1), seq).?);
        }
    }
};

fn dictCfg() root.Config {
    var cfg = smallCfg();
    cfg.max_object_versions = 8192;
    cfg.max_checkpoints = 4096;
    cfg.dict_bytes = 16 << 10;
    cfg.dict_refresh_bytes = 96 << 10;
    return cfg;
}

test "history dictionaries (codec 3): smaller history, kept across reopen, every record reads back" {
    const gpa = std.testing.allocator;
    const pool = DictPool.init();
    var phys: [2]u64 = undefined;
    for ([_]bool{ false, true }, 0..) |on, i| {
        const sim = try SimIo.init(gpa, 41, .{}, 16 << 20);
        defer sim.deinit();
        var cfg = dictCfg();
        cfg.history_dicts = on;
        // The dictionary holds the whole blob pool (96 KiB), as 1 MiB holds minutes of mainnet.
        cfg.dict_bytes = 128 << 10;
        cfg.dict_refresh_bytes = 256 << 10;
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (1..61) |q| try pool.commit(s, q);
        try s.close();
        // Reopened: the writer has no recent history yet and reuses the segment's newest
        // dictionary, then cuts new ones; a new segment (epoch 2) gets its own file.
        s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        for (61..121) |q| try pool.commit(s, q);
        phys[i] = s.stats.bytes_written_phys;
        try s.close();
        s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        try pool.check(s, 120);
        var nb: [64]u8 = undefined;
        var have: [4]bool = undefined;
        for (0..4) |e| have[e] = sim.exists(try std.fmt.bufPrint(&nb, "index/{d:0>8}.zd", .{e}));
        for (have) |h| try std.testing.expectEqual(on, h);
    }
    // Each checkpoint's objects are new to its own group but not to the recent history.
    std.debug.print("history dictionaries: physical bytes written without {d}, with {d}\n", .{ phys[0], phys[1] });
    try std.testing.expect(phys[1] * 2 < phys[0]);
}

test "history dictionaries (codec 3): a crash at every point keeps every acknowledged checkpoint readable" {
    const gpa = std.testing.allocator;
    const pool = DictPool.init();
    var k: u64 = 0;
    var crashed: usize = 0;
    while (k < 48) : (k += 1) {
        const sim = try SimIo.init(gpa, 500 + k, .{}, 16 << 20);
        defer sim.deinit();
        const cfg = dictCfg();
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        var acked: u64 = 0;
        for (1..21) |q| {
            try pool.commit(s, q);
            acked = q;
        }
        // Crash after k more device operations: inside a dictionary write, between it and the
        // group that names it, or in a later group.
        sim.scheduleCrash(k * 3);
        var q: u64 = 21;
        while (q <= 90) : (q += 1) {
            pool.commit(s, q) catch |e| {
                try std.testing.expectEqual(error.Crashed, e);
                crashed += 1;
                break;
            };
            acked = q;
        }
        sim.scheduleCrash(null);
        s.deinit();
        sim.crash();
        s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        try pool.check(s, acked);
        // And it keeps writing after the crash, with dictionaries.
        var snap = s.snapshot();
        const next = snap.highestCommitted().? + 1;
        snap.release();
        for (next..next + 10) |r| try pool.commit(s, r);
        try pool.check(s, next + 9);
    }
    try std.testing.expect(crashed > 40);
}

// ------------------------------------------------------------------ live table: 20-byte slots

/// Writes `n` objects (ids 1..n, some removed) in a few commits, closes cleanly, and returns
/// each id's raw live-table value (tomb and compact bits included; 0: absent).
fn liveFixture(gpa: std.mem.Allocator, sim: *SimIo, cfg: *const root.Config, n: u64) ![]u64 {
    var s = try Store.open(gpa, .{ .sim = sim }, cfg);
    var seq: u64 = 100;
    var k: u64 = 1;
    while (k <= n) : (seq += 1) {
        var b = try s.begin(seq, 1);
        try b.checkpoint("summary", "contents");
        var j: u64 = 0;
        while (j < 40 and k <= n) : ({
            j += 1;
            k += 1;
        }) try put(b, k, 3, "payload-of-some-object");
        try s.commit(b);
    }
    var b = try s.begin(seq, 1);
    try b.checkpoint("summary", "contents");
    k = 1;
    while (k <= n) : (k += 7) try b.removeObject(&idOf(k), 4, .deleted);
    try s.commit(b);
    const locs = try gpa.alloc(u64, n + 1);
    for (locs, 0..) |*l, i| l.* = s.live.raw.?.t.get(&idOf(i)) orelse 0;
    try s.close();
    return locs;
}

fn checkFixture(s: *Store, locs: []const u64) !void {
    var snap = s.snapshot();
    defer snap.release();
    for (locs, 0..) |l, i| {
        const lat = try snap.latest(&idOf(i));
        if (l == 0) {
            try std.testing.expect(lat == null);
        } else if (l & root.table.tomb != 0) {
            try std.testing.expectEqual(root.RemoveKind.deleted, lat.?.removed.kind);
        } else {
            try std.testing.expectEqualStrings("payload-of-some-object", lat.?.live.bytes);
            try std.testing.expectEqual(@as(u64, 3), lat.?.live.version);
        }
        try std.testing.expectEqual(l, s.live.raw.?.t.get(&idOf(i)) orelse 0);
    }
}

/// Turns a cleanly closed store's newest meta and live table into the format written before
/// lane disk-fit: 32-byte slots holding the id tails (`table.LegacyPage`), and a 128-byte
/// "ZUIMETA2" meta (no key secret) naming it.
fn makeLegacy(sim: *SimIo, locs: []const u64) !void {
    const cs = root.checksum;
    const tbl = root.table;
    const mfd = try sim.openFile("meta", false);
    defer sim.closeFile(mfd);
    var pages: [2][4096]u8 = undefined;
    try sim.read(mfd, 0, &pages[0]);
    try sim.read(mfd, 4096, &pages[1]);
    const g0 = std.mem.readInt(u64, pages[0][16..24], .little);
    const g1 = std.mem.readInt(u64, pages[1][16..24], .little);
    const slot: usize = if (g1 > g0) 1 else 0;
    const pg = &pages[slot];
    try std.testing.expectEqualStrings("ZUIMETA3", pg[0..8]);
    const seed = std.mem.readInt(u64, pg[32..40], .little);
    const tg = std.mem.readInt(u64, pg[64..72], .little);
    // Store.liveSeed
    const tseed = seed ^ (tg *% 0x9e3779b97f4a7c15) ^ 0x6c697665;
    const npages: u64 = 16;
    const nslots = npages * tbl.legacy_per_page;
    const lp = try std.testing.allocator.alignedAlloc(tbl.LegacyPage, .fromByteUnits(4096), npages);
    defer std.testing.allocator.free(lp);
    @memset(std.mem.sliceAsBytes(lp), 0);
    var count: u64 = 0;
    var live: u64 = 0;
    for (locs, 0..) |l, i| {
        if (l == 0) continue;
        const id = idOf(i);
        const tail = tbl.tailOf(&id);
        var p: u64 = @truncate((@as(u128, cs.hash(tseed, tail)) * nslots) >> 64);
        while (lp[p / tbl.legacy_per_page].slots[p % tbl.legacy_per_page].loc != 0) p = (p + 1) % nslots;
        lp[p / tbl.legacy_per_page].slots[p % tbl.legacy_per_page] = .{ .id = tail.*, .loc = l };
        count += 1;
        if (l & tbl.tomb == 0) live += 1;
    }
    for (lp, 0..) |*page, p| page.sum = tbl.pageChecksum(tseed, p, @ptrCast(page));
    var nb: [64]u8 = undefined;
    const tfd = try sim.openFile(root.io.liveName(&nb, tg), true);
    try sim.truncate(tfd, 0);
    try sim.write(tfd, 0, std.mem.sliceAsBytes(lp));
    try sim.sync(tfd);
    sim.closeFile(tfd);
    if (sim.exists(root.io.journal_name)) try sim.remove(root.io.journal_name);
    // The meta: 128 bytes, "ZUIMETA2", flags 0 (not clean), the legacy page count.
    @memcpy(pg[0..8], "ZUIMETA2");
    std.mem.writeInt(u32, pg[28..32], 0, .little);
    std.mem.writeInt(u64, pg[72..80], npages, .little);
    try std.testing.expectEqual(count, std.mem.readInt(u64, pg[112..120], .little));
    try std.testing.expectEqual(live, std.mem.readInt(u64, pg[120..128], .little));
    @memset(pg[128..1024], 0);
    @memset(pg[8..16], 0);
    std.mem.writeInt(u64, pg[8..16], cs.hash(0x6d657461, pg[0..128]), .little);
    // Its chain link names the new checksum (MetaChain at 1024: meta_sum at +24, 56 bytes).
    @memcpy(pg[1024 + 24 ..][0..8], pg[8..16]);
    @memset(pg[1024 + 8 ..][0..8], 0);
    std.mem.writeInt(u64, pg[1024 + 8 ..][0..8], cs.hash(0x6368616e, pg[1024..][0..56]), .little);
    try sim.write(mfd, slot * 4096, pg);
    try sim.sync(mfd);
    try sim.syncDir();
}

test "live table: a legacy table (32-byte slots, ZUIMETA2 meta) is migrated at open" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 21, .{}, 8 << 20);
    defer sim.deinit();
    var cfg = smallCfg();
    cfg.max_live_objects = 200;
    const locs = try liveFixture(gpa, sim, &cfg, 300);
    defer gpa.free(locs);
    try makeLegacy(sim, locs);

    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    try checkFixture(s, locs);
    const t = &s.live.raw.?.t;
    try std.testing.expectEqual(@as(u64, 300), t.count);
    try std.testing.expectEqual(@as(u64, 300 - 43), t.live);
    // Writes go on, then a clean close and an open read the new format directly.
    var b = try s.begin(1000, 1);
    try b.checkpoint("summary", "contents");
    try put(b, 301, 5, "payload-of-some-object");
    try s.commit(b);
    try s.close();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(u64, 5), snap.liveObject(&idOf(301)).?.version);
    try std.testing.expectEqual(@as(u64, 3), snap.liveObject(&idOf(2)).?.version);
    try std.testing.expect(snap.liveObject(&idOf(1)) == null);
    // The legacy file is gone after the next meta write: one table file left.
    const names = try sim.listDir(gpa, "index");
    defer {
        for (names) |nm| gpa.free(nm);
        gpa.free(names);
    }
    var tables: u32 = 0;
    for (names) |nm| if (std.mem.startsWith(u8, nm, "live-")) {
        tables += 1;
    };
    try std.testing.expectEqual(@as(u32, 1), tables);
}

test "live table: a crash at any point of the migration leaves a store that opens with every object" {
    const gpa = std.testing.allocator;
    var k: u64 = 0;
    var done = false;
    var crashed_runs: u32 = 0;
    while (!done) : (k += 11) {
        const sim = try SimIo.init(gpa, 22 + k, .{}, 8 << 20);
        defer sim.deinit();
        var cfg = smallCfg();
        cfg.max_live_objects = 200;
        const locs = try liveFixture(gpa, sim, &cfg, 120);
        defer gpa.free(locs);
        try makeLegacy(sim, locs);
        sim.scheduleCrash(k);
        const opened = if (Store.open(gpa, .{ .sim = sim }, &cfg)) |s| blk: {
            s.deinit();
            break :blk true;
        } else |_| false;
        if (sim.crashed) crashed_runs += 1 else {
            // No crash: the migration ran to the end.
            try std.testing.expect(opened);
            done = true;
        }
        sim.scheduleCrash(null);
        sim.crash();
        var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
        defer s.deinit();
        try checkFixture(s, locs);
        try std.testing.expect(k < 20_000);
    }
    try std.testing.expect(crashed_runs > 3);
}

test "live table: a slot whose record holds another id (a key collision) reads as absent" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 23, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var b = try s.begin(10, 1);
    try b.checkpoint("summary", "contents");
    try put(b, 1, 3, "object-one");
    try s.commit(b);
    // Give id 2's key id 1's location, as a collision would: a lookup of 2 finds 1's record.
    const t = &s.live.raw.?.t;
    const k2 = t.keyFor(&idOf(2));
    _ = try t.upsertKey(&k2, t.get(&idOf(1)).?);
    try std.testing.expectEqual(t.get(&idOf(1)), t.get(&idOf(2)));
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expect((try snap.latest(&idOf(2))) == null);
    try std.testing.expect(snap.liveObject(&idOf(2)) == null);
    try std.testing.expect((try snap.visibleLoc(&idOf(2))) == null);
    try std.testing.expect(snap.objectAt(&idOf(2), 3) == null);
}

test "certificate fixes: a checkpoint's certified summary is served from the fix once one is installed; a snapshot from before keeps valid bytes, other checkpoints keep theirs, and a reopened store serves the stored bytes again" {
    const gpa = std.testing.allocator;
    const sim = try SimIo.init(gpa, 31, .{}, 8 << 20);
    defer sim.deinit();
    const cfg = smallCfg();
    var s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    for (10..14) |q| {
        const b = try s.begin(q, 1);
        try b.checkpoint(if (q == 11) "summary+bucket-cert" else "summary+core-cert", "contents");
        try s.commit(b);
    }
    // no fix: the stored bytes, and nothing changed
    try std.testing.expectEqual(@as(usize, 0), s.cert_fix.count());
    var before = s.snapshot();
    const old = before.checkpoint(11).?.summary_cert;
    try std.testing.expectEqualStrings("summary+bucket-cert", old);
    const gen0 = s.cert_fix.generation();
    // the core's certificate for 11 (another length than the stored one)
    try std.testing.expect(try s.cert_fix.put(11, &root.certFixKey(11), "summary+core-certificate"));
    try std.testing.expect(!try s.cert_fix.put(11, &root.certFixKey(11), "summary+core-certificate"));
    {
        var snap = s.snapshot();
        defer snap.release();
        const c = snap.checkpoint(11).?;
        try std.testing.expectEqualStrings("summary+core-certificate", c.summary_cert);
        try std.testing.expectEqualStrings("contents", c.contents);
        try std.testing.expectEqual(@as(u64, 1), c.epoch);
        try std.testing.expectEqualStrings("summary+core-certificate", snap.checkpointHeld(11).?.summary_cert);
        for ([_]u64{ 10, 12, 13 }) |q| try std.testing.expectEqualStrings("summary+core-cert", snap.checkpoint(q).?.summary_cert);
        // what a response cache asks: only checkpoint 11 changed since `gen0`
        try std.testing.expect(s.cert_fix.changedSince(11, gen0));
        try std.testing.expect(!s.cert_fix.changedSince(12, gen0));
        try std.testing.expect(!s.cert_fix.changedSince(11, s.cert_fix.generation()));
    }
    // bytes read before the fix stay readable while their snapshot lives
    try std.testing.expectEqualStrings("summary+bucket-cert", old);
    before.release();
    // memory only: after a reopen the stored bytes are served until the owner reinstalls its fixes
    sim.scheduleCrash(0);
    s.deinit();
    sim.crash();
    s = try Store.open(gpa, .{ .sim = sim }, &cfg);
    defer s.deinit();
    var snap = s.snapshot();
    defer snap.release();
    try std.testing.expectEqual(@as(usize, 0), s.cert_fix.count());
    try std.testing.expectEqualStrings("summary+bucket-cert", snap.checkpoint(11).?.summary_cert);
}
