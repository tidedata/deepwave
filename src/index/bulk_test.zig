//! Tests of the partitioned bulk build (bulk.zig) against the sort-and-merge build (lsm.zig
//! `Builder.runFromMerge`): the same tables byte for byte from the same live set, a resume from
//! every kill point, the memory budget, and a build followed by checkpoint changes against a
//! build at the later point.
//!
//! `ZUI_BULK_BENCH=<objects>` runs the timing comparison (skipped otherwise):
//! `ZUI_BULK_BENCH=8000000 ./zig build test -Dlane=index -Doptimize=ReleaseFast`.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const index = @import("root.zig");
const lsm = @import("lsm.zig");
const bulk = @import("bulk.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;

fn addrOf(seed: u64) [32]u8 {
    var a: [32]u8 = undefined;
    var x = seed *% 0x9e3779b97f4a7c15 +% 0x2545f4914f6cdd1d;
    for (0..4) |i| {
        x ^= x >> 29;
        x *%= 0xbf58476d1ce4e5b9;
        x ^= x >> 32;
        std.mem.writeInt(u64, a[i * 8 ..][0..8], x, .little);
    }
    return a;
}

fn ident(s: []const u8) types.Identifier {
    return .{ .@"0" = s };
}

fn structTag(a: Allocator, addr: [32]u8, m: []const u8, n: []const u8, args: []const types.TypeTag) !types.StructTag {
    return .{ .address = .{ .@"0" = addr }, .module = ident(m), .name = ident(n), .type_args = try a.dupe(types.TypeTag, args) };
}

fn two() [32]u8 {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    return a;
}

/// One live object, by `i`: gas coins and other coins of a few hundred owners (some with a
/// zero balance), a few owners with very many objects, dynamic-field-like objects under a few
/// parents (one of them huge), coin wrappers, accumulator balances, and shared and immutable
/// objects that no index lists.
fn makeObject(a: Allocator, r: std.Random, i: usize) ![]const u8 {
    var id: [32]u8 = undefined;
    r.bytes(&id);
    const owners = 600;
    const whale = r.uintLessThan(u8, 10) < 3;
    const owner = addrOf(if (whale) r.uintLessThan(u64, 3) else 10 + r.uintLessThan(u64, owners));
    const version: u64 = 3 + i % 7;
    const kind = r.uintLessThan(u8, 100);
    var contents: []const u8 = undefined;
    var ty: types.MoveObjectType_ = undefined;
    var own: types.Owner = .{ .AddressOwner = .{ .@"0" = owner } };
    const usd: types.TypeTag = .{ .@"struct" = try structTag(a, addrOf(900 + r.uintLessThan(u64, 5)), "usd", "USD", &.{}) };
    if (kind < 50) {
        const c = try a.alloc(u8, 40);
        @memcpy(c[0..32], &id);
        std.mem.writeInt(u64, c[32..40], if (r.uintLessThan(u8, 20) == 0) 0 else r.uintLessThan(u64, 1 << 40), .little);
        contents = c;
        ty = .GasCoin;
        if (kind < 3) own = .{ .ConsensusAddressOwner = .{ .start_version = .{ .@"0" = 2 }, .owner = .{ .@"0" = owner } } };
    } else if (kind < 62) {
        const c = try a.alloc(u8, 40);
        @memcpy(c[0..32], &id);
        std.mem.writeInt(u64, c[32..40], r.uintLessThan(u64, 1 << 30), .little);
        contents = c;
        ty = .{ .Coin = usd };
    } else if (kind < 88) {
        // a dynamic field: Field<u64, V> under one of a few parents
        const c = try a.alloc(u8, 32 + 8 + r.uintLessThan(usize, 24));
        r.bytes(c);
        @memcpy(c[0..32], &id);
        contents = c;
        const v: types.TypeTag = .{ .@"struct" = try structTag(a, addrOf(700 + r.uintLessThan(u64, 3)), "book", "Order", &.{usd}) };
        ty = .{ .Other = try structTag(a, two(), "dynamic_field", "Field", &.{ .u64, v }) };
        own = .{ .ObjectOwner = .{ .@"0" = addrOf(if (r.uintLessThan(u8, 3) != 0) 500 else 501 + r.uintLessThan(u64, 40)) } };
    } else if (kind < 91) {
        const c = try a.alloc(u8, 48);
        r.bytes(c);
        @memcpy(c[0..32], &id);
        contents = c;
        const names = [_][]const u8{ "CoinMetadata", "TreasuryCap", "RegulatedCoinMetadata" };
        ty = .{ .Other = try structTag(a, two(), "coin", names[r.uintLessThan(usize, 3)], &.{usd}) };
        if (kind == 88) own = .Immutable;
    } else if (kind < 94) {
        // an address balance under the accumulator root
        const c = try a.alloc(u8, 80);
        @memcpy(c[0..32], &id);
        @memcpy(c[32..64], &owner);
        std.mem.writeInt(u128, c[64..80], r.uintLessThan(u64, 1 << 50), .little);
        contents = c;
        ty = if (kind == 91) .SuiBalanceAccumulatorField else .{ .BalanceAccumulatorField = usd };
        own = .{ .ObjectOwner = .{ .@"0" = index.accumulator_root } };
    } else {
        const c = try a.alloc(u8, 64);
        r.bytes(c);
        @memcpy(c[0..32], &id);
        contents = c;
        ty = .{ .Other = try structTag(a, addrOf(800), "pool", "Pool", &.{}) };
        own = if (kind < 97) .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } } else .Immutable;
    }
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = ty }, .has_public_transfer = true, .version = .{ .@"0" = version }, .contents = contents } },
        .owner = own,
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

fn makeObjects(a: Allocator, seed: u64, n: usize) ![]const []const u8 {
    var prng = std.Random.DefaultPrng.init(seed);
    const raws = try a.alloc([]const u8, n);
    for (raws, 0..) |*raw, i| raw.* = try makeObject(a, prng.random(), i);
    return raws;
}

/// A live set held in memory, split into the builder's parts by position.
const ArraySource = struct {
    raws: []const []const u8,
    walks: std.atomic.Value(u32) = .init(0),

    fn walk(ctx: *anyopaque, part: u32, parts: u32, sink: lsm.Sink) anyerror!void {
        const s: *ArraySource = @ptrCast(@alignCast(ctx));
        _ = s.walks.fetchAdd(1, .monotonic);
        const id: [32]u8 = @splat(0);
        var i: usize = part;
        while (i < s.raws.len) : (i += parts) try sink.f(sink.ctx, &id, 0, s.raws[i]);
    }
    fn source(s: *ArraySource, at: u64) lsm.Source {
        return .{ .ctx = s, .at = at, .walk = walk };
    }
};

fn tmpDirPath(a: Allocator, tmp: *testing.TmpDir, name: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/{s}", .{ tmp.sub_path, name });
}

fn buildIn(gpa: Allocator, dir: []const u8, opts: lsm.Options, raws: []const []const u8, at: u64) !struct { rep: lsm.Builder.Report, walks: u32 } {
    const ix = try index.Index.open(gpa, testing.io, dir, opts);
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    var src: ArraySource = .{ .raws = raws };
    const rep = try lsm.Builder.runFrom(&ix.db, src.source(at), index.rowsOf);
    return .{ .rep = rep, .walks = src.walks.load(.monotonic) };
}

/// The base run's table file paths of a finished index, in key order, and its watermark.
fn tablesOf(gpa: Allocator, a: Allocator, dir: []const u8) !struct { paths: [][]const u8, watermark: ?u64, entries: u64 } {
    const ix = try index.Index.open(gpa, testing.io, dir, .{ .sync = .none });
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    try testing.expect(ix.db.buildPending() == null);
    if (ix.db.runs.items.len == 0) return .{ .paths = &.{}, .watermark = ix.db.watermark(), .entries = 0 };
    try testing.expectEqual(@as(usize, 1), ix.db.runs.items.len);
    const tabs = ix.db.runs.items[0].tables;
    const out = try a.alloc([]const u8, tabs.len);
    for (tabs, out) |t, *o| o.* = try std.fmt.allocPrint(a, "{s}/index/{d}.tbl", .{ dir, t.gen });
    // nothing of the build is left beside the tables
    var d = try std.Io.Dir.cwd().openDir(testing.io, try std.fmt.allocPrint(a, "{s}/index", .{dir}), .{ .iterate = true });
    defer d.close(testing.io);
    var it = d.iterate();
    var n: usize = 0;
    while (try it.next(testing.io)) |e| {
        try testing.expect(std.mem.endsWith(u8, e.name, ".tbl"));
        n += 1;
    }
    try testing.expectEqual(tabs.len, n);
    return .{ .paths = out, .watermark = ix.db.watermark(), .entries = ix.db.runs.items[0].entries() };
}

/// Both indexes hold the same base run: the same watermark and the same table files, byte for
/// byte, in key order.
fn expectSameTables(gpa: Allocator, a: Allocator, want_dir: []const u8, got_dir: []const u8) !void {
    const want = try tablesOf(gpa, a, want_dir);
    const got = try tablesOf(gpa, a, got_dir);
    try testing.expectEqual(want.watermark, got.watermark);
    try testing.expectEqual(want.entries, got.entries);
    try testing.expectEqual(want.paths.len, got.paths.len);
    for (want.paths, got.paths, 0..) |wp, gp, i| {
        const w = try std.Io.Dir.cwd().readFileAlloc(testing.io, wp, gpa, .limited(4 << 30));
        defer gpa.free(w);
        const g = try std.Io.Dir.cwd().readFileAlloc(testing.io, gp, gpa, .limited(4 << 30));
        defer gpa.free(g);
        if (!std.mem.eql(u8, w, g)) {
            std.debug.print("table {d} of {d} differs: {s} {d} bytes, {s} {d} bytes\n", .{ i, want.paths.len, gp, g.len, wp, w.len });
            return error.TestTablesDiffer;
        }
    }
}

test "bulk: the partitioned build writes the sort-and-merge build's tables byte for byte (walk and stream, small and large budgets)" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const raws = try makeObjects(a, 21, 30_000);

    // the old path: one group (as a restore's stream), and four passes (as a node start)
    const old1 = try tmpDirPath(a, &tmp, "old1");
    const o1 = try buildIn(gpa, old1, .{ .build_chunk_bytes = 96 << 10, .build_groups = 1, .build_threads = 3, .bulk = false, .sync = .none }, raws, 9);
    try testing.expectEqual(@as(u32, 64), o1.walks);
    const old4 = try tmpDirPath(a, &tmp, "old4");
    const o4 = try buildIn(gpa, old4, .{ .build_chunk_bytes = 200 << 10, .build_groups = 4, .build_threads = 4, .bulk = false, .sync = .none }, raws, 9);
    try testing.expectEqual(@as(u32, 4 * 64), o4.walks); // four passes over the live set
    try expectSameTables(gpa, a, old1, old4);
    try testing.expect(o1.rep.entries > 20_000);

    // the new path, one pass: a budget every partition fits in
    const new_big = try tmpDirPath(a, &tmp, "new-big");
    const nb = try buildIn(gpa, new_big, .{ .build_threads = 4, .build_mem_bytes = 256 << 20, .sync = .none }, raws, 9);
    try testing.expectEqual(@as(u32, 64), nb.walks);
    try testing.expectEqual(o1.rep.entries, nb.rep.entries);
    try testing.expectEqual(@as(u64, raws.len), nb.rep.objects);
    try testing.expectEqual(@as(u32, 0), nb.rep.sort_chunks);
    try expectSameTables(gpa, a, old1, new_big);

    // a budget the large partitions do not fit in: sorted in chunks and merged
    const new_small = try tmpDirPath(a, &tmp, "new-small");
    bulk.test_sort_cap = 96 << 10;
    const ns = buildIn(gpa, new_small, .{ .build_threads = 3, .build_chunk_bytes = 16 << 10, .build_mem_bytes = 8 << 20, .sync = .none }, raws, 9);
    bulk.test_sort_cap = null;
    try testing.expect((try ns).rep.sort_chunks > 20);
    try expectSameTables(gpa, a, old1, new_small);

    // one thread
    const new_one = try tmpDirPath(a, &tmp, "new-one");
    _ = try buildIn(gpa, new_one, .{ .build_threads = 1, .build_mem_bytes = 64 << 20, .sync = .none }, raws, 9);
    try expectSameTables(gpa, a, old1, new_one);

    // a stream fed by four producers (a restore's fetch threads), after a stream that died
    const st_dir = try tmpDirPath(a, &tmp, "stream");
    const opts: lsm.Options = .{ .build_threads = 4, .build_mem_bytes = 32 << 20, .sync = .none };
    {
        const ix = try index.Index.open(gpa, testing.io, st_dir, opts);
        defer {
            ix.deinit();
            gpa.destroy(ix);
        }
        const s = try lsm.Stream.begin(&ix.db, index.rowsOf, 128 << 10);
        defer s.destroy();
        for (raws[0 .. raws.len / 2], 0..) |raw, i| try s.put(i % 3, raw);
        try testing.expect(s.spills.load(.monotonic) > 0);
    }
    {
        const ix = try index.Index.open(gpa, testing.io, st_dir, opts);
        defer {
            ix.deinit();
            gpa.destroy(ix);
        }
        try testing.expect(ix.db.buildPending() != null);
        const s = try lsm.Stream.begin(&ix.db, index.rowsOf, 128 << 10);
        defer s.destroy();
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
        const rep = try s.finish(9, null);
        try testing.expectEqual(@as(u64, raws.len), rep.objects);
        try testing.expectEqual(@as(?u64, 9), ix.db.watermark());
        try testing.expect(ix.db.buildPending() == null);
    }
    try expectSameTables(gpa, a, old1, st_dir);

    // an empty live set installs an empty index at the tip
    const empty = try tmpDirPath(a, &tmp, "empty");
    const e = try buildIn(gpa, empty, .{ .build_threads = 2, .sync = .none }, &.{}, 4);
    try testing.expectEqual(@as(u64, 0), e.rep.entries);
    const et = try tablesOf(gpa, a, empty);
    try testing.expectEqual(@as(?u64, 4), et.watermark);
    try testing.expectEqual(@as(usize, 0), et.paths.len);
}

test "bulk: a build killed at any point resumes where it stopped and ends with the same tables" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const raws = try makeObjects(a, 33, 12_000);
    const opts: lsm.Options = .{ .build_threads = 3, .build_chunk_bytes = 48 << 10, .build_mem_bytes = 8 << 20, .sync = .none };
    const ref = try tmpDirPath(a, &tmp, "ref");
    _ = try buildIn(gpa, ref, opts, raws, 5);

    const saved_cut = bulk.cut_every;
    bulk.cut_every = 4;
    defer bulk.cut_every = saved_cut;
    defer bulk.test_crash = null;

    const Kill = struct { first: bulk.TestCrash, second: ?bulk.TestCrash = null };
    const kills = [_]Kill{
        .{ .first = .{ .rows_parts = 1 } }, // before any durable cut
        .{ .first = .{ .rows_parts = 6 } }, // after one cut
        .{ .first = .{ .rows_parts = 6 }, .second = .{ .rows_parts = 5 } }, // twice while rows arrive
        .{ .first = .{ .rows_parts = 41 }, .second = .sealed },
        .{ .first = .sealed },
        .{ .first = .{ .mid_range = 1 } },
        .{ .first = .{ .mid_range = 4 }, .second = .{ .mid_range = 2 } },
        .{ .first = .{ .ranges = 1 } },
        .{ .first = .{ .ranges = 7 }, .second = .{ .ranges = 3 } },
        .{ .first = .before_install },
    };
    for (kills, 0..) |k, ki| {
        const dir = try tmpDirPath(a, &tmp, try std.fmt.allocPrint(a, "kill{d}", .{ki}));
        bulk.test_crash = k.first;
        try testing.expectError(error.TestCrash, buildIn(gpa, dir, opts, raws, 5));
        var crashes = [_]?bulk.TestCrash{ k.second, null };
        var prev = k.first;
        for (&crashes) |next| {
            // what the next open finds: a pending build, no watermark, nothing served
            var done_src: u32 = 0;
            {
                const ix = try index.Index.open(gpa, testing.io, dir, opts);
                defer {
                    ix.deinit();
                    gpa.destroy(ix);
                }
                try testing.expect(ix.db.buildPending() != null);
                try testing.expect(ix.db.watermark() == null);
                try testing.expectEqual(@as(usize, 0), ix.db.runs.items.len);
                const st = bulk.State.read(gpa, ix.db.files.?) orelse return error.TestNoState;
                defer gpa.destroy(st);
                try testing.expectEqual(@as(u64, 5), st.tip);
                done_src = @popCount(st.src_done);
                switch (prev) {
                    .rows_parts => |n| {
                        try testing.expectEqual(bulk.State.Phase.rows, st.phase);
                        // the parts of every cut reached before the kill are kept
                        try testing.expect(done_src >= (n / bulk.cut_every) * bulk.cut_every);
                    },
                    .sealed => try testing.expectEqual(@as(u64, 0), st.ranges_done),
                    .mid_range, .ranges, .before_install => try testing.expectEqual(bulk.State.Phase.sort, st.phase),
                }
                switch (prev) {
                    .ranges => |n| try testing.expect(@popCount(st.ranges_done) >= n),
                    .before_install => try testing.expectEqual(@as(u32, lsm.n_ranges), @popCount(st.ranges_done)),
                    else => {},
                }
            }
            bulk.test_crash = next;
            const r = buildIn(gpa, dir, opts, raws, 5);
            if (next) |nx| {
                try testing.expectError(error.TestCrash, r);
                prev = nx;
                continue;
            }
            const res = try r;
            // only the source parts that were not durable are walked again, none once sealed
            try testing.expectEqual(64 - done_src, res.walks);
            try testing.expectEqual(done_src, res.rep.resumed_parts);
            switch (prev) {
                .rows_parts => {},
                else => try testing.expectEqual(@as(u32, 0), res.walks),
            }
            break;
        }
        bulk.test_crash = null;
        try expectSameTables(gpa, a, ref, dir);
    }

    // a pending build of another live set is not resumed: the index is built for the new tip
    const other = try tmpDirPath(a, &tmp, "other-tip");
    bulk.test_crash = .{ .ranges = 2 };
    try testing.expectError(error.TestCrash, buildIn(gpa, other, opts, raws[0..5000], 4));
    bulk.test_crash = null;
    const res = try buildIn(gpa, other, opts, raws, 5);
    try testing.expectEqual(@as(u32, 64), res.walks);
    try testing.expectEqual(@as(u32, 0), res.rep.resumed_ranges);
    try expectSameTables(gpa, a, ref, other);

    // the sort-and-merge build resets a pending partitioned build (and the other way round)
    const mixed = try tmpDirPath(a, &tmp, "mixed");
    bulk.test_crash = .{ .ranges = 2 };
    try testing.expectError(error.TestCrash, buildIn(gpa, mixed, opts, raws, 5));
    bulk.test_crash = null;
    var old_opts = opts;
    old_opts.bulk = false;
    old_opts.build_groups = 2;
    lsm.test_fail_after_group = 0;
    try testing.expectError(error.TestCrash, buildIn(gpa, mixed, old_opts, raws, 5));
    lsm.test_fail_after_group = null;
    const res2 = try buildIn(gpa, mixed, opts, raws, 5);
    try testing.expectEqual(@as(u32, 64), res2.walks);
    try expectSameTables(gpa, a, ref, mixed);
}

/// Counts the bytes allocated through it (current and peak).
const Counting = struct {
    child: Allocator,
    cur: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),

    fn allocator(c: *Counting) Allocator {
        return .{ .ptr = c, .vtable = &vt };
    }
    const vt: Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };

    fn grew(c: *Counting, n: usize) void {
        const v = c.cur.fetchAdd(n, .monotonic) + n;
        var p = c.peak.load(.monotonic);
        while (v > p) p = c.peak.cmpxchgWeak(p, v, .monotonic, .monotonic) orelse break;
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const r = c.child.rawAlloc(len, alignment, ra) orelse return null;
        c.grew(len);
        return r;
    }
    fn resize(ctx: *anyopaque, mem: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        if (!c.child.rawResize(mem, alignment, new_len, ra)) return false;
        if (new_len > mem.len) c.grew(new_len - mem.len) else _ = c.cur.fetchSub(mem.len - new_len, .monotonic);
        return true;
    }
    fn remap(ctx: *anyopaque, mem: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const r = c.child.rawRemap(mem, alignment, new_len, ra) orelse return null;
        if (new_len > mem.len) c.grew(new_len - mem.len) else _ = c.cur.fetchSub(mem.len - new_len, .monotonic);
        return r;
    }
    fn free(ctx: *anyopaque, mem: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.child.rawFree(mem, alignment, ra);
        _ = c.cur.fetchSub(mem.len, .monotonic);
    }
};

test "bulk: the build's peak allocation stays under its memory budget (the old build's does not)" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // about 45 MiB of rows, a third of them under three owners and one parent
    const raws = try makeObjects(a, 44, 300_000);
    const budgets = [_]usize{ 8 << 20, 24 << 20 };
    var dirs: [2][]const u8 = undefined;
    for (budgets, 0..) |budget, bi| {
        var counting: Counting = .{ .child = gpa };
        const g = counting.allocator();
        const dir = try tmpDirPath(a, &tmp, try std.fmt.allocPrint(a, "mem{d}", .{bi}));
        dirs[bi] = dir;
        const ix = try index.Index.open(g, testing.io, dir, .{ .build_threads = 4, .build_mem_bytes = budget, .sync = .none });
        defer {
            ix.deinit();
            g.destroy(ix);
        }
        const base = counting.cur.load(.monotonic);
        counting.peak.store(base, .monotonic);
        var src: ArraySource = .{ .raws = raws };
        const rep = try lsm.Builder.runFrom(&ix.db, src.source(3), index.rowsOf);
        const peak = counting.peak.load(.monotonic) - base;
        std.debug.print("bulk memory: budget {d} KiB, peak {d} KiB, {d} rows, {d} sorted chunks, {d} KiB temp\n", .{ budget >> 10, peak >> 10, rep.entries, rep.sort_chunks, rep.temp_bytes >> 10 });
        try testing.expect(peak <= budget);
        // the small budget does not hold the large partitions: they are sorted in chunks
        if (bi == 0) try testing.expect(rep.sort_chunks > 0);
        try testing.expect(rep.entries > 250_000);
    }
    try expectSameTables(gpa, a, dirs[0], dirs[1]);
    // the old build with the same threads: one sort buffer a thread, whatever is configured
    var counting: Counting = .{ .child = gpa };
    const g = counting.allocator();
    const dir = try tmpDirPath(a, &tmp, "mem-old");
    {
        const ix = try index.Index.open(g, testing.io, dir, .{ .build_threads = 4, .build_groups = 1, .build_mem_bytes = 8 << 20, .bulk = false, .sync = .none });
        defer {
            ix.deinit();
            g.destroy(ix);
        }
        const base = counting.cur.load(.monotonic);
        counting.peak.store(base, .monotonic);
        var src: ArraySource = .{ .raws = raws };
        _ = try lsm.Builder.runFrom(&ix.db, src.source(3), index.rowsOf);
        const peak = counting.peak.load(.monotonic) - base;
        std.debug.print("bulk memory: the sort-and-merge build, same input: peak {d} KiB\n", .{peak >> 10});
        try testing.expect(peak > 8 << 20);
    }
    try expectSameTables(gpa, a, dirs[0], dir);
}

fn expectSameRows(a: Allocator, x: *const index.Index, y: *const index.Index) !u64 {
    var p = try x.all(a);
    var q = try y.all(a);
    var n: u64 = 0;
    while (try p.next()) |e| {
        const g = (try q.next()) orelse return error.TestMissingRow;
        try testing.expectEqualSlices(u8, e.key, g.key);
        try testing.expectEqual(e.val.op, g.val.op);
        try testing.expectEqualSlices(u8, e.val.bytes(), g.val.bytes());
        n += 1;
    }
    try testing.expect((try q.next()) == null);
    return n;
}

test "bulk: checkpoints applied after the build give the index a build at the later point gives" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var prng = std.Random.DefaultPrng.init(55);
    const r = prng.random();
    // the live set at checkpoint 10
    const n0 = 8000;
    var live: std.ArrayList([]const u8) = .empty;
    for (0..n0) |i| try live.append(a, try makeObject(a, r, i));
    // small memtables, so the changes flush into runs above the base and compact
    const opts: lsm.Options = .{ .build_threads = 3, .build_mem_bytes = 16 << 20, .mem_bytes = 24 << 10, .max_checkpoints = 7, .ratio = 2, .sync = .none };
    const dir_a = try tmpDirPath(a, &tmp, "then-fed");
    const ix = try index.Index.open(gpa, testing.io, dir_a, opts);
    defer {
        ix.deinit();
        gpa.destroy(ix);
    }
    {
        var src: ArraySource = .{ .raws = live.items };
        _ = try lsm.Builder.runFrom(&ix.db, src.source(10), index.rowsOf);
        ix.setCheckpoint(ix.db.watermark());
    }
    try testing.expectEqual(@as(?u64, 10), ix.checkpoint);
    // checkpoints 11..70: objects are deleted, replaced by a new version (another balance or
    // owner under the same id is a different object here, which the index treats alike: old
    // rows out, new rows in), and created
    var seq: u64 = 11;
    while (seq <= 70) : (seq += 1) {
        var changes: std.ArrayList(index.Index.Change) = .empty;
        for (0..40 + r.uintLessThan(usize, 80)) |k| {
            switch (r.uintLessThan(u8, 3)) {
                0 => if (live.items.len > 100) {
                    const i = r.uintLessThan(usize, live.items.len);
                    try changes.append(a, .{ .old = live.swapRemove(i), .new = null });
                },
                1 => {
                    const i = r.uintLessThan(usize, live.items.len);
                    const new = try makeObject(a, r, k + seq);
                    try changes.append(a, .{ .old = live.items[i], .new = new });
                    live.items[i] = new;
                },
                else => {
                    const new = try makeObject(a, r, k + seq);
                    try changes.append(a, .{ .old = null, .new = new });
                    try live.append(a, new);
                },
            }
        }
        try ix.applyChanges(seq, changes.items);
        try ix.db.settle(&ix.lock);
    }
    try testing.expectEqual(@as(?u64, 70), ix.checkpoint);
    try testing.expect(ix.db.stats.flushes > 5);
    try testing.expect(ix.db.stats.compactions > 0);
    // a build at checkpoint 70 from the live set as it is then
    const dir_b = try tmpDirPath(a, &tmp, "built-later");
    const later = try index.Index.open(gpa, testing.io, dir_b, opts);
    defer {
        later.deinit();
        gpa.destroy(later);
    }
    {
        var src: ArraySource = .{ .raws = live.items };
        _ = try lsm.Builder.runFrom(&later.db, src.source(70), index.rowsOf);
    }
    const n = try expectSameRows(a, ix, later);
    try testing.expect(n > 6000);
    // and both equal the index that only ever took inserts
    var mem = try index.Index.init(gpa);
    defer mem.deinit();
    for (live.items) |raw| try mem.insert(raw);
    _ = try expectSameRows(a, &mem, later);
}

/// A synthetic live set made on the fly, part by part (nothing is held in memory): the bench's
/// source. Object `i` of part `p` is a function of (seed, p, i) only.
const GenSource = struct {
    per_part: usize,
    objects: std.atomic.Value(u64) = .init(0),

    fn walk(ctx: *anyopaque, part: u32, _: u32, sink: lsm.Sink) anyerror!void {
        const s: *GenSource = @ptrCast(@alignCast(ctx));
        var prng = std.Random.DefaultPrng.init(0xb01d + @as(u64, part));
        var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena_state.deinit();
        const id: [32]u8 = @splat(0);
        for (0..s.per_part) |i| {
            _ = arena_state.reset(.retain_capacity);
            const raw = try makeBenchObject(arena_state.allocator(), prng.random(), i);
            try sink.f(sink.ctx, &id, 0, raw);
        }
        _ = s.objects.fetchAdd(s.per_part, .monotonic);
    }
    fn source(s: *GenSource, at: u64) lsm.Source {
        return .{ .ctx = s, .at = at, .walk = walk };
    }
};

/// As `makeObject`, with mainnet-like spread: owners over the whole address space (a few
/// million of them), a tenth of the objects under a few huge owners and parents.
fn makeBenchObject(a: Allocator, r: std.Random, i: usize) ![]const u8 {
    var id: [32]u8 = undefined;
    r.bytes(&id);
    const whale = r.uintLessThan(u8, 10) == 0;
    var owner = addrOf(if (whale) r.uintLessThan(u64, 8) else 100 + r.uintLessThan(u64, 4_000_000));
    narrowOwner(&owner, r);
    const kind = r.uintLessThan(u8, 100);
    var contents: []const u8 = undefined;
    var ty: types.MoveObjectType_ = undefined;
    var own: types.Owner = .{ .AddressOwner = .{ .@"0" = owner } };
    const usd: types.TypeTag = .{ .@"struct" = try structTag(a, addrOf(900 + r.uintLessThan(u64, 40)), "usd", "USD", &.{}) };
    if (kind < 30) {
        const c = try a.alloc(u8, 40);
        @memcpy(c[0..32], &id);
        std.mem.writeInt(u64, c[32..40], r.uintLessThan(u64, 1 << 40), .little);
        contents = c;
        ty = .GasCoin;
    } else if (kind < 45) {
        const c = try a.alloc(u8, 40);
        @memcpy(c[0..32], &id);
        std.mem.writeInt(u64, c[32..40], r.uintLessThan(u64, 1 << 30), .little);
        contents = c;
        ty = .{ .Coin = usd };
    } else if (kind < 60) {
        // an address-owned object of some other type
        const c = try a.alloc(u8, 32 + 40 + r.uintLessThan(usize, 200));
        r.bytes(c);
        @memcpy(c[0..32], &id);
        contents = c;
        ty = .{ .Other = try structTag(a, addrOf(1000 + r.uintLessThan(u64, 300)), "collection", "Item", &.{}) };
    } else if (kind < 95) {
        const c = try a.alloc(u8, 32 + 8 + 48 + r.uintLessThan(usize, 120));
        r.bytes(c);
        @memcpy(c[0..32], &id);
        contents = c;
        const v: types.TypeTag = .{ .@"struct" = try structTag(a, addrOf(700 + r.uintLessThan(u64, 60)), "book", "Order", &.{usd}) };
        ty = .{ .Other = try structTag(a, two(), "dynamic_field", "Field", &.{ .u64, v }) };
        var parent = addrOf(if (whale) 500 + r.uintLessThan(u64, 6) else 5000 + r.uintLessThan(u64, 2_000_000));
        narrowOwner(&parent, r);
        own = .{ .ObjectOwner = .{ .@"0" = parent } };
    } else {
        const c = try a.alloc(u8, 96);
        r.bytes(c);
        @memcpy(c[0..32], &id);
        contents = c;
        ty = .{ .Other = try structTag(a, addrOf(800), "pool", "Pool", &.{}) };
        own = .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 1 } } };
    }
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = ty }, .has_public_transfer = true, .version = .{ .@"0" = 3 + i % 7 }, .contents = contents } },
        .owner = own,
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(7) } },
        .storage_rebate = 0,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

/// Real objects of an index-parity fixture (`$ZUI_CORPUS/vectors/index/live-1.bin`), walked
/// `reps` times; each repetition gives every Move object a new pseudo-random id, so the rows of
/// one repetition never equal another's. Types, sizes and owners are the fixture's (owners:
/// the few hundred addresses and parents the fixture was captured around, so partitions are
/// few and large).
const FixtureSource = struct {
    objs: []const []const u8,
    /// Offset of the 32 id bytes in each object (0: not a Move object, walked unchanged).
    id_off: []const u32,
    reps: usize,
    objects: std.atomic.Value(u64) = .init(0),

    fn load(a: Allocator, path: []const u8, reps: usize) !FixtureSource {
        const data = try std.Io.Dir.cwd().readFileAlloc(testing.io, path, a, .limited(1 << 30));
        if (data.len < 9 or !std.mem.eql(u8, data[0..5], "ZIDX1")) return error.BadFixture;
        const n = std.mem.readInt(u32, data[5..9], .little);
        const objs = try a.alloc([]const u8, n);
        const offs = try a.alloc(u32, n);
        var pos: usize = 9;
        var scratch = std.heap.ArenaAllocator.init(a);
        for (objs, offs) |*o, *off| {
            const len = std.mem.readInt(u32, data[pos..][0..4], .little);
            o.* = data[pos + 4 ..][0..len];
            pos += 4 + len;
            off.* = 0;
            _ = scratch.reset(.retain_capacity);
            const obj = bcs.decode(types.Object, scratch.allocator(), o.*) catch continue;
            switch (obj.data) {
                .Move => |m| if (m.contents.len >= 32) {
                    // the id is the first 32 bytes of the contents; find them in the object
                    if (std.mem.indexOf(u8, o.*, m.contents[0..32])) |i| off.* = @intCast(i);
                },
                .Package => {},
            }
        }
        return .{ .objs = objs, .id_off = offs, .reps = reps };
    }

    fn walk(ctx: *anyopaque, part: u32, parts: u32, sink: lsm.Sink) anyerror!void {
        const s: *FixtureSource = @ptrCast(@alignCast(ctx));
        const gpa = std.heap.page_allocator;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        const id: [32]u8 = @splat(0);
        var n: u64 = 0;
        for (0..s.reps) |rep| {
            var i: usize = part;
            while (i < s.objs.len) : (i += parts) {
                const o = s.objs[i];
                n += 1;
                if (rep == 0 or s.id_off[i] == 0) {
                    if (rep == 0) try sink.f(sink.ctx, &id, 0, o);
                    continue;
                }
                buf.clearRetainingCapacity();
                try buf.appendSlice(gpa, o);
                const at = buf.items[s.id_off[i]..][0..32];
                at.* = addrOf(std.mem.readInt(u64, at[0..8], .little) +% @as(u64, rep) *% 0x9e3779b97f4a7c15);
                try sink.f(sink.ctx, &id, 0, buf.items);
            }
        }
        _ = s.objects.fetchAdd(n, .monotonic);
    }
    fn source(s: *FixtureSource, at: u64) lsm.Source {
        return .{ .ctx = s, .at = at, .walk = walk };
    }
};

/// ZUI_BULK_BENCH_NARROW=1: every owner starts with one of four bytes, so the rows fall into a
/// few partitions (four per owner kind and four of the balance table, in four ranges each) and
/// a partition holds as many rows as at mainnet scale or more.
var bench_narrow = false;
fn narrowOwner(o: *[32]u8, r: std.Random) void {
    if (!bench_narrow) return;
    o[0] = ([4]u8{ 0x10, 0x51, 0x92, 0xd3 })[r.uintLessThan(usize, 4)];
}

fn nowMs() u64 {
    return lsm.nowMs();
}

// Timing of the old and the new build over the same generated live set, 4 threads each:
//   ZUI_BULK_BENCH=<objects> [ZUI_BULK_BENCH_MEM_MB=2048] [ZUI_BULK_BENCH_THREADS=4] [ZUI_BULK_BENCH_OLD=0]
//   [ZUI_BULK_BENCH_DIR=<dir>] [ZUI_BULK_BENCH_GEN=1: objects made during the walk, not held in memory]
//   [ZUI_BULK_BENCH_OLD_CHUNK_KB=<n>: the old build's sort buffer, to reach mainnet's temp table count
//   on a small input] [ZUI_BULK_BENCH_NARROW=1: mainnet-size partitions, see narrowOwner]
//   [ZUI_BULK_BENCH_FIXTURE=<index fixture .bin>: real objects, repeated to reach <objects>, see FixtureSource]
//   ./zig build test -Dlane=index -Doptimize=ReleaseFast
// Prints objects, rows, seconds, rows per second and the peak allocation of each, and checks
// that both wrote the same tables.
test "bulk: bench against the sort-and-merge build (ZUI_BULK_BENCH)" {
    const n_z = std.c.getenv("ZUI_BULK_BENCH") orelse return error.SkipZigTest;
    const n_obj = try std.fmt.parseInt(usize, std.mem.span(n_z), 10);
    const mem_mb: usize = if (std.c.getenv("ZUI_BULK_BENCH_MEM_MB")) |v| try std.fmt.parseInt(usize, std.mem.span(v), 10) else 2048;
    const run_old = if (std.c.getenv("ZUI_BULK_BENCH_OLD")) |v| !std.mem.eql(u8, std.mem.span(v), "0") else true;
    const threads: usize = if (std.c.getenv("ZUI_BULK_BENCH_THREADS")) |v| try std.fmt.parseInt(usize, std.mem.span(v), 10) else 4;
    bench_narrow = std.c.getenv("ZUI_BULK_BENCH_NARROW") != null;
    const old_chunk: usize = if (std.c.getenv("ZUI_BULK_BENCH_OLD_CHUNK_KB")) |v| (try std.fmt.parseInt(usize, std.mem.span(v), 10)) << 10 else 96 << 20;
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    // ZUI_BULK_BENCH_DIR: a new, empty directory on the disk to measure (it is left behind)
    const base: []const u8 = if (std.c.getenv("ZUI_BULK_BENCH_DIR")) |v| std.mem.span(v) else try tmpDirPath(a, &tmp, "bench");
    const per_part = n_obj / lsm.build_parts;
    // The live set in memory (about 200 bytes an object), so the timings are the build's own;
    // with ZUI_BULK_BENCH_GEN=1 every walk makes its objects again (no memory, but the old
    // build's four passes then pay the generator four times).
    var fixture: ?FixtureSource = null;
    if (std.c.getenv("ZUI_BULK_BENCH_FIXTURE")) |v| {
        fixture = try FixtureSource.load(a, std.mem.span(v), 1);
        fixture.?.reps = @max(1, n_obj / fixture.?.objs.len);
    }
    const pregen = std.c.getenv("ZUI_BULK_BENCH_GEN") == null and fixture == null;
    var held: []const []const u8 = &.{};
    if (pregen) {
        const all = try a.alloc([]const u8, per_part * lsm.build_parts);
        const G = struct {
            all: [][]const u8,
            per_part: usize,
            next: std.atomic.Value(u32) = .init(0),
            fn work(x: *@This()) void {
                var keep = std.heap.ArenaAllocator.init(std.heap.page_allocator); // kept until exit
                var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                defer scratch.deinit();
                while (true) {
                    const p = x.next.fetchAdd(1, .monotonic);
                    if (p >= lsm.build_parts) return;
                    var prng = std.Random.DefaultPrng.init(0xb01d + @as(u64, p));
                    for (0..x.per_part) |i| {
                        _ = scratch.reset(.retain_capacity);
                        const raw = makeBenchObject(scratch.allocator(), prng.random(), i) catch @panic("oom");
                        x.all[i * lsm.build_parts + p] = keep.allocator().dupe(u8, raw) catch @panic("oom");
                    }
                }
            }
        };
        var gen: G = .{ .all = all, .per_part = per_part };
        var gts: [8]?std.Thread = @splat(null);
        for (&gts) |*t| t.* = std.Thread.spawn(.{}, G.work, .{&gen}) catch null;
        G.work(&gen);
        for (gts) |t| if (t) |x| x.join();
        held = all;
    }
    const Run = struct { name: []const u8, opts: lsm.Options };
    const runs = [_]Run{
        .{ .name = "new", .opts = .{ .build_threads = threads, .build_mem_bytes = mem_mb << 20 } },
        .{ .name = "old-1-pass", .opts = .{ .build_threads = threads, .build_groups = 1, .build_chunk_bytes = old_chunk, .bulk = false } },
        .{ .name = "old-4-pass", .opts = .{ .build_threads = threads, .build_groups = 4, .build_chunk_bytes = old_chunk, .bulk = false } },
    };
    var dirs: [runs.len]?[]const u8 = @splat(null);
    for (runs, 0..) |run, ri| {
        if (ri > 0 and !run_old) continue;
        var counting: Counting = .{ .child = gpa };
        const g = counting.allocator();
        const dir = try std.fmt.allocPrint(a, "{s}/{s}", .{ base, run.name });
        dirs[ri] = dir;
        const ix = try index.Index.open(g, testing.io, dir, run.opts);
        defer {
            ix.deinit();
            g.destroy(ix);
        }
        const b0 = counting.cur.load(.monotonic);
        counting.peak.store(b0, .monotonic);
        var gsrc: GenSource = .{ .per_part = per_part };
        var asrc: ArraySource = .{ .raws = held };
        if (fixture) |*f| f.objects.store(0, .monotonic);
        const t0 = nowMs();
        const rep = try lsm.Builder.runFrom(&ix.db, if (fixture) |*f| f.source(1) else if (pregen) asrc.source(1) else gsrc.source(1), index.rowsOf);
        const ms = nowMs() - t0;
        const walked = if (fixture) |*f| f.objects.load(.monotonic) else if (pregen) @as(u64, asrc.walks.load(.monotonic)) * per_part else gsrc.objects.load(.monotonic);
        std.debug.print("bulk bench {s}: {d} objects ({d} walked), {d} rows, {d} MiB of tables, {d} ms ({d} rows/s, {d} objects/s walked); rows {d} ms, sort {d} ms, temp {d} MiB, {d} sorted chunks, peak allocation {d} MiB, {d} threads\n", .{
            run.name,                                    if (fixture) |f| f.objs.len * f.reps else per_part * lsm.build_parts, walked,      rep.entries, rep.bytes >> 20,      ms,
            rep.entries * 1000 / @max(ms, 1),            walked * 1000 / @max(ms, 1),                                          rep.rows_ms, rep.sort_ms, rep.temp_bytes >> 20, rep.sort_chunks,
            (counting.peak.load(.monotonic) - b0) >> 20, threads,
        });
    }
    if (run_old) {
        try expectSameTables(testing.allocator, a, dirs[0].?, dirs[1].?);
        try expectSameTables(testing.allocator, a, dirs[0].?, dirs[2].?);
    }
}
