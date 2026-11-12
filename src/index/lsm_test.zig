//! Unit tests of the on-disk index (lsm.zig): the LSM against a model across flushes,
//! compactions and a reopen; the bulk build against inserts, including a resumed build.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const index = @import("root.zig");
const lsm = @import("lsm.zig");

const testing = std.testing;

const Model = std.StringArrayHashMapUnmanaged(lsm.Val);

fn modelApply(gpa: std.mem.Allocator, m: *Model, key: []const u8, v: lsm.Val) !void {
    if (m.getPtr(key)) |cur| {
        const r = lsm.combine(v, cur.*);
        if (r.empty()) {
            const kv = m.fetchOrderedRemove(key).?;
            gpa.free(kv.key);
        } else cur.* = r;
        return;
    }
    if (v.empty()) return;
    try m.put(gpa, try gpa.dupe(u8, key), v);
}

fn lt(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn expectSame(db: *const lsm.Db, m: *const Model, a: std.mem.Allocator, start: []const u8) !void {
    const keys = try a.dupe([]const u8, m.keys());
    std.mem.sort([]const u8, keys, {}, lt);
    var it = try db.iter(a, start);
    for (keys) |k| {
        if (std.mem.order(u8, k, start) == .lt) continue;
        const e = (try it.next()) orelse return error.TestMissingRow;
        try testing.expectEqualSlices(u8, k, e.key);
        const want = m.get(k).?;
        try testing.expectEqual(want.op, e.val.op);
        try testing.expectEqualSlices(u8, want.bytes(), e.val.bytes());
    }
    try testing.expect((try it.next()) == null);
}

test "lsm: random puts, deletes and deltas across flushes, compactions and a reopen match a model" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const dir = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ix", .{tmp.sub_path});
    defer gpa.free(dir);
    const opts: lsm.Options = .{ .mem_bytes = 6 << 10, .max_checkpoints = 5, .ratio = 2, .max_runs = 6, .sync = .none };
    var lock: index.RwLock = .{};
    var db = try lsm.Db.open(gpa, testing.io, dir, opts);
    var open = true;
    defer if (open) db.deinit();
    var model: Model = .empty;
    defer {
        for (model.keys()) |k| gpa.free(k);
        model.deinit(gpa);
    }
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    var seq: u64 = 0;
    while (seq < 400) : (seq += 1) {
        for (0..r.uintLessThan(usize, 60)) |_| {
            var kb: [8]u8 = undefined;
            r.bytes(&kb);
            kb[0] = r.uintLessThan(u8, 3);
            kb[1] &= 0x07;
            const key = kb[0 .. 2 + r.uintLessThan(usize, 4)];
            const v: lsm.Val = switch (kb[0]) {
                1 => lsm.Val.delta(r.intRangeAtMost(i128, -3, 3), r.intRangeAtMost(i128, -2, 2)),
                else => if (r.uintLessThan(u8, 3) == 0) lsm.Val.del else blk: {
                    var ver: [8]u8 = undefined;
                    std.mem.writeInt(u64, &ver, seq, .little);
                    break :blk lsm.Val.put(&ver);
                },
            };
            lock.lock();
            try db.apply(key, v);
            lock.unlock();
            try modelApply(gpa, &model, key, v);
        }
        lock.lock();
        _ = try db.endCheckpoint(seq);
        lock.unlock();
        // as index.Index.applyChanges: the writer frees the memtables flushed since
        db.reclaim();
        try db.settle(&lock);
        // the one just flushed waits for the writer's next checkpoint boundary, no more
        try testing.expect(db.retired.items.len <= 1 and db.to_free.items.len == 0);
        if (seq % 37 == 0) {
            _ = arena_state.reset(.retain_capacity);
            try expectSame(&db, &model, arena_state.allocator(), "");
            try expectSame(&db, &model, arena_state.allocator(), &.{ 0, 3 });
            try expectSame(&db, &model, arena_state.allocator(), &.{1});
        }
    }
    try testing.expect(db.stats.flushes > 10);
    try testing.expect(db.stats.compactions > 3);
    try testing.expect(db.runs.items.len <= opts.max_runs);
    // the last checkpoint durable, then a reopen sees the same rows
    db.opts.max_checkpoints = 1;
    lock.lock();
    _ = try db.endCheckpoint(seq);
    lock.unlock();
    try db.settle(&lock);
    try testing.expectEqual(@as(?u64, seq), db.watermark());
    // crash leftovers: an unreferenced table and a stray temp file are removed on open
    {
        _ = arena_state.reset(.retain_capacity);
        const f = try std.Io.Dir.cwd().createFile(testing.io, try std.fmt.allocPrint(arena_state.allocator(), "{s}/index/999999.tbl", .{dir}), .{});
        f.close(testing.io);
    }
    db.deinit();
    open = false;
    db = try lsm.Db.open(gpa, testing.io, dir, opts);
    open = true;
    try testing.expectEqual(@as(?u64, seq), db.watermark());
    try testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(testing.io, try std.fmt.allocPrint(arena_state.allocator(), "{s}/index/999999.tbl", .{dir}), .{}));
    _ = arena_state.reset(.retain_capacity);
    try expectSame(&db, &model, arena_state.allocator(), "");
}

fn addr(n: u8) [32]u8 {
    var a: [32]u8 = @splat(0);
    a[0] = n;
    a[31] = n;
    return a;
}

/// BCS(Object) of a `Coin<SUI>` owned by `owner`.
fn coin(a: std.mem.Allocator, id: [32]u8, version: u64, balance: u64, owner: [32]u8, object_owned: bool) ![]const u8 {
    var contents: [40]u8 = undefined;
    @memcpy(contents[0..32], &id);
    std.mem.writeInt(u64, contents[32..40], balance, .little);
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = version }, .contents = &contents } },
        .owner = if (object_owned) .{ .ObjectOwner = .{ .@"0" = owner } } else .{ .AddressOwner = .{ .@"0" = owner } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

test "lsm: bulk build from the live set equals inserts, and a crashed build resumes" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var cfg: store.Config = .{
        .max_live_objects = 8192,
        .max_object_versions = 16384,
        .max_transactions = 1024,
        .max_checkpoints = 1024,
        .max_batch_bytes = 4 << 20,
        .max_batch_objects = 4096,
        .max_segments = 64,
        .index_flush_interval = 8,
        .segment_reserve = 16 << 20,
        .seed = 43,
    };
    const sim = try store.SimIo.init(gpa, 43, .{}, 64 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var mem = try index.Index.init(gpa);
    defer mem.deinit();
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    {
        const b = try st.begin(1, 0);
        for (0..3000) |i| {
            var id: [32]u8 = undefined;
            r.bytes(&id);
            const owner = addr(r.uintLessThan(u8, 255));
            const raw = try coin(a, id, 3 + i % 5, r.uintLessThan(u64, 1000) + 1, owner, i % 7 == 0);
            try b.putObject(&id, 3 + i % 5, &types.digest.objectDigest(raw), raw);
            try mem.insert(raw);
        }
        try b.checkpoint("summary", "contents");
        try st.commit(b);
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/ix", .{tmp.sub_path});
    // the sort-and-merge build (the partitioned one is in bulk_test.zig)
    const opts: lsm.Options = .{ .build_chunk_bytes = 16 << 10, .build_groups = 4, .build_threads = 3, .bulk = false, .sync = .none };
    // first attempt dies after group 1 of 4
    {
        const ix = try index.Index.open(gpa, testing.io, dir, opts);
        defer {
            ix.deinit();
            gpa.destroy(ix);
        }
        var f = index.feed.Feed.init(gpa, ix, st);
        defer f.deinit();
        lsm.test_fail_after_group = 1;
        defer lsm.test_fail_after_group = null;
        try testing.expectError(error.TestCrash, f.start());
    }
    const ix = try index.Index.open(gpa, testing.io, dir, opts);
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    try testing.expect(ix.db.buildPending() != null);
    try testing.expectEqual(@as(u32, 2), ix.db.buildPending().?.group);
    var f = index.feed.Feed.init(gpa, ix, st);
    defer f.deinit();
    const rep = try f.start();
    try testing.expect(rep.built);
    try testing.expectEqual(@as(?u64, 1), ix.db.watermark());
    try testing.expectEqual(@as(usize, 1), ix.db.runs.items.len);
    try testing.expect(ix.db.runs.items[0].tables.len > 4);
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
    try testing.expect(n > 3000);
    // owner pages read the same through the index API
    const o = addr(7);
    var p = try mem.ownedIter(a, .address, &o, "");
    var q = try ix.ownedIter(a, .address, &o, "");
    while (try p.next()) |e| {
        const g = (try q.next()).?;
        try testing.expectEqualSlices(u8, e.key, g.key);
        try testing.expectEqual(e.ver, g.ver);
    }
    try testing.expect((try q.next()) == null);
}

test "lsm: a build streamed by several producer threads equals inserts, survives a crash before finish, and keeps its watermark" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var mem = try index.Index.init(gpa);
    defer mem.deinit();
    var prng = std.Random.DefaultPrng.init(11);
    const r = prng.random();
    const n_obj = 4000;
    const raws = try a.alloc([]const u8, n_obj);
    for (raws, 0..) |*raw, i| {
        var id: [32]u8 = undefined;
        r.bytes(&id);
        const owner = addr(r.uintLessThan(u8, 40));
        raw.* = try coin(a, id, 3 + i % 5, r.uintLessThan(u64, 1000) + 1, owner, i % 7 == 0);
        try mem.insert(raw.*);
    }
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/ix", .{tmp.sub_path});
    const opts: lsm.Options = .{ .build_chunk_bytes = 16 << 10, .build_groups = 4, .build_threads = 3, .bulk = false, .sync = .none };
    // a stream that dies before finish (a restore that failed): the next open sees a pending
    // build no tip matches, and the next stream starts over
    {
        const ix = try index.Index.open(gpa, testing.io, dir, opts);
        defer {
            ix.deinit();
            gpa.destroy(ix);
        }
        const s = try lsm.Stream.begin(&ix.db, index.rowsOf, 8 << 10);
        defer s.destroy();
        for (raws[0 .. n_obj / 2], 0..) |raw, i| try s.put(i % 3, raw);
        try testing.expect(s.spills.load(.monotonic) > 0);
    }
    const ix = try index.Index.open(gpa, testing.io, dir, opts);
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    try testing.expect(ix.db.buildPending() != null);
    const s = try lsm.Stream.begin(&ix.db, index.rowsOf, 8 << 10);
    defer s.destroy();
    // four producers, five lanes (lane 4 shared), objects in any order
    const P = struct {
        s: *lsm.Stream,
        raws: []const []const u8,
        k: usize,
        err: ?anyerror = null,
        fn run(p: *@This()) void {
            var i = p.k;
            while (i < p.raws.len) : (i += 4) p.s.put(if (i % 9 == 0) 4 else p.k, p.raws[i]) catch |e| {
                p.err = e;
                return;
            };
        }
    };
    var ps: [4]P = undefined;
    var ts: [4]std.Thread = undefined;
    for (&ps, &ts, 0..) |*p, *t, k| {
        p.* = .{ .s = s, .raws = raws, .k = k };
        t.* = try std.Thread.spawn(.{}, P.run, .{p});
    }
    for (ts) |t| t.join();
    for (ps) |p| if (p.err) |e| return e;
    const rep = try s.finish(77, null);
    try testing.expectEqual(@as(u64, n_obj), rep.objects);
    try testing.expectEqual(@as(?u64, 77), ix.db.watermark());
    try testing.expect(ix.db.buildPending() == null);
    try testing.expectEqual(@as(usize, 1), ix.db.runs.items.len);
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
    try testing.expect(n > n_obj);
}

test "lsm: a stop ends a compaction between two entries, leaves the runs and the directory as they were, and the next settle does the same compaction" {
    const gpa = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try std.fmt.allocPrint(gpa, ".zig-cache/tmp/{s}/ix", .{tmp.sub_path});
    defer gpa.free(dir);
    const opts: lsm.Options = .{ .mem_bytes = 6 << 10, .max_checkpoints = 5, .ratio = 2, .max_runs = 6, .sync = .none };
    var lock: index.RwLock = .{};
    var db = try lsm.Db.open(gpa, testing.io, dir, opts);
    defer db.deinit();
    // the node's stop has begun (`stopBackground` sets the flag before it joins the thread)
    db.stop.store(true, .release);
    var prng = std.Random.DefaultPrng.init(5);
    const r = prng.random();
    var stopped: u32 = 0;
    var seq: u64 = 0;
    while (seq < 120) : (seq += 1) {
        for (0..40) |_| {
            var kb: [6]u8 = undefined;
            r.bytes(&kb);
            kb[0] = 0;
            var ver: [8]u8 = undefined;
            std.mem.writeInt(u64, &ver, seq, .little);
            lock.lock();
            try db.apply(&kb, lsm.Val.put(&ver));
            lock.unlock();
        }
        lock.lock();
        _ = try db.endCheckpoint(seq);
        lock.unlock();
        db.reclaim();
        // flushes go on (a memtable is small); a compaction that comes due is ended at once
        db.settle(&lock) catch |e| {
            try testing.expectEqual(error.Stopped, e);
            stopped += 1;
        };
    }
    try testing.expect(stopped > 0);
    try testing.expectEqual(@as(u64, 0), db.stats.compactions);
    try testing.expect(db.runs.items.len > 2);
    // nothing of an ended merge is left: one table file per run
    const tables = struct {
        fn count(d: []const u8) !usize {
            var pb: [600]u8 = undefined;
            var it_dir = try std.Io.Dir.cwd().openDir(testing.io, try std.fmt.bufPrint(&pb, "{s}/index", .{d}), .{ .iterate = true });
            defer it_dir.close(testing.io);
            var n: usize = 0;
            var it = it_dir.iterate();
            while (try it.next(testing.io)) |e| {
                if (std.mem.endsWith(u8, e.name, ".tbl")) n += 1;
            }
            return n;
        }
    }.count;
    try testing.expectEqual(db.runs.items.len, try tables(dir));
    // without the stop the same compaction runs to its end
    db.stop.store(false, .release);
    try db.settle(&lock);
    try testing.expect(db.stats.compactions > 0);
    try testing.expectEqual(db.runs.items.len, try tables(dir));
}
