//! Conformance suites of the indexes lane (DROP-IN G4).
//!
//! `index-parity`: `$ZUI_CORPUS/vectors/index/*.bin` (each made by
//! `tools/truth/indexes/capture.py` against sui-node 1.83.1) holds a set of live objects and
//! StateService requests with sui-node's answers (ListBalances already normalised: zero rows
//! dropped). The suite restores the objects into a fresh store, builds the index from them with
//! `Index.insert` (the restore path), serves every request through the real gRPC stack in-process
//! (loopback HTTP/2 into `Service` with the StateService hook) and compares status, message and
//! response bytes. Items are the case names (`owned-full/<addr>/<page>`, `df-full/<parent>/<page>`,
//! `balances/...`, `balance/...`, `coin/<type>`, ...). With `ZUI_INDEX_DUMP=<dir>` the deepwave answer of
//! every failing case is written to `<dir>/<fixture file>-<n>.zui` for tools/truth/indexes/diff.py.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("root.zig");
const state = @import("state.zig");
const feed = @import("feed.zig");

pub const suites = [_]harness.Suite{
    .{ .name = "index-parity", .lane = "indexes", .doc = "StateService answers over the restored live set equal sui-node 1.83.1 (G4 fixture)", .run = runParity },
    .{ .name = "index-feed", .lane = "indexes", .doc = "the per-checkpoint effects feed over consecutive corpus checkpoints ends at the same index as inserting the final states", .run = runFeed },
};

const fixture_dir = "vectors/index";

const Case = struct { n: usize, path: []const u8, body: []const u8, status: u32, msg: []const u8, resp: []const u8 };

const Fixture = struct {
    objects: [][]const u8,
    names: [][]const u8,
    cases: std.StringHashMapUnmanaged(Case),
};

const Rd = struct {
    b: []const u8,
    i: usize = 0,
    fn take(r: *Rd, n: usize) ![]const u8 {
        if (r.b.len - r.i < n) return error.Truncated;
        defer r.i += n;
        return r.b[r.i..][0..n];
    }
    fn int(r: *Rd, comptime T: type) !T {
        return std.mem.readInt(T, (try r.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }
};

fn parseFixture(gpa: std.mem.Allocator, data: []const u8) !Fixture {
    var r: Rd = .{ .b = data };
    if (!std.mem.eql(u8, try r.take(5), "ZIDX1")) return error.BadFixture;
    const no = try r.int(u32);
    const objects = try gpa.alloc([]const u8, no);
    for (objects) |*o| o.* = try r.take(try r.int(u32));
    const nc = try r.int(u32);
    const names = try gpa.alloc([]const u8, nc);
    var cases: std.StringHashMapUnmanaged(Case) = .empty;
    for (names, 0..) |*name, i| {
        name.* = try r.take(try r.int(u16));
        const path = try r.take(try r.int(u16));
        const body = try r.take(try r.int(u32));
        const st = try r.int(u32);
        const msg = try r.take(try r.int(u16));
        const resp = try r.take(try r.int(u32));
        try cases.put(gpa, name.*, .{ .n = i, .path = path, .body = body, .status = st, .msg = msg, .resp = resp });
    }
    return .{ .objects = objects, .names = names, .cases = cases };
}

const State = struct { handler: serve.h2.Handler, fx: *const Fixture, dump: ?[]const u8, file: []const u8 };

fn runParity(ctx: *harness.Ctx) !void {
    const files = ctx.listFiles(fixture_dir, ".bin") catch |e| {
        ctx.skip(fixture_dir, "no fixtures (run tools/truth/indexes/capture.py)");
        if (e == error.FileNotFound) return;
        return e;
    };
    defer ctx.freeNames(files);
    if (files.len == 0) ctx.skip(fixture_dir, "no fixtures (run tools/truth/indexes/capture.py)");
    for (files) |f| try runFixture(ctx, f);
}

/// One fixture file: its own store and index (fixtures are captured at different times).
fn runFixture(ctx: *harness.Ctx, file: []const u8) !void {
    const gpa = ctx.gpa;
    const path = try std.fmt.allocPrint(gpa, fixture_dir ++ "/{s}", .{file});
    defer gpa.free(path);
    const data = try ctx.corpus.readFileAlloc(ctx.io, path, gpa, .limited(8 << 30));
    defer gpa.free(data);
    var fx = try parseFixture(gpa, data);
    defer {
        gpa.free(fx.objects);
        gpa.free(fx.names);
        fx.cases.deinit(gpa);
    }

    var total: usize = 0;
    for (fx.objects) |o| total += o.len;
    const dir = try std.fmt.allocPrint(gpa, "{s}/sessions/index/{d}", .{ ctx.corpus_path, std.c.getpid() });
    defer gpa.free(dir);
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    const n_obj: u64 = @max(fx.objects.len, 1);
    const cap = std.math.ceilPowerOfTwo(u64, n_obj * 2 + 1024) catch unreachable;
    var cfg: store.Config = .{
        .dir = dir,
        .max_live_objects = cap,
        .max_object_versions = cap,
        .max_transactions = 1 << 10,
        .max_checkpoints = 1 << 6,
        .max_batch_bytes = total + (n_obj * 256) + (1 << 20),
        .max_batch_objects = @intCast(n_obj + 16),
        .max_segments = 16,
        .segment_reserve = std.math.ceilPowerOfTwo(u64, total * 2 + (n_obj * 256) + (1 << 26)) catch unreachable,
        .seed = 7,
    };
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var mem_ix = try index.Index.init(gpa);
    defer mem_ix.deinit();
    {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const b = try h.store.begin(1, 0);
        for (fx.objects) |raw| {
            _ = arena_state.reset(.retain_capacity);
            const obj = try bcs.decode(types.Object, arena_state.allocator(), raw);
            switch (obj.data) {
                .Move => |mo| try b.putObject(mo.contents[0..32], mo.version.@"0", &types.digest.objectDigest(raw), raw),
                .Package => |p| try b.putObject(&p.id.@"0".@"0", p.version.@"0", &types.digest.objectDigest(raw), raw),
            }
        }
        try b.checkpoint("summary", "contents");
        try h.store.commit(b);
    }
    // The index under test is the on-disk one, built from the store's live set by the bulk
    // builder (small sort buffers and four key-range groups, so every fixture spills and merges
    // many temp tables), as on a production node. ZUI_INDEX_MEMORY=1 serves the in-memory index instead.
    const ix_dir = try std.fmt.allocPrint(gpa, "{s}/state-index", .{dir});
    defer gpa.free(ix_dir);
    const disk = try index.Index.open(gpa, ctx.io, ix_dir, .{ .build_chunk_bytes = 1 << 20, .build_groups = 4, .build_threads = 4, .sync = .none });
    defer {
        disk.deinit();
        gpa.destroy(disk);
    }
    var fd = index.feed.Feed.init(gpa, disk, h.store);
    defer fd.deinit();
    _ = try fd.start();
    const use_mem = std.c.getenv("ZUI_INDEX_MEMORY") != null;
    if (use_mem) {
        var fm = index.feed.Feed.init(gpa, &mem_ix, h.store);
        defer fm.deinit();
        try fm.rebuild();
    }
    const ix = if (use_mem) &mem_ix else disk;
    var svc: serve.service.Service = .{ .gpa = gpa, .store = h.store, .chain_id = @splat(0) };
    defer svc.deinit();
    svc.state = state.hook(ix);
    const dump: ?[]const u8 = if (std.c.getenv("ZUI_INDEX_DUMP")) |p| std.mem.span(p) else null;
    if (dump) |d| std.Io.Dir.cwd().createDirPath(ctx.io, d) catch {};
    var st: State = .{ .handler = svc.handler(), .fx = &fx, .dump = dump, .file = file };
    try ctx.forEachName(fx.names, &st, one);
}

fn one(st: *const State, ctx: *harness.Ctx, name: []const u8) !void {
    const cs = st.fx.cases.get(name).?;
    const a = ctx.scratch();
    const rep = try serve.loopback.unary(a, st.handler, cs.path, cs.body);
    var c = ctx.check(name);
    if (rep.status != cs.status) c.failf("status {d} ({s}), sui-node {d} ({s})", .{ rep.status, rep.grpc_message, cs.status, cs.msg });
    if (cs.status != 0) {
        c.text("grpc-message", cs.msg, rep.grpc_message);
    } else c.bytes("response", cs.resp, rep.message);
    if (!c.finish()) if (st.dump) |d| {
        const p = try std.fmt.allocPrint(a, "{s}/{s}-{d}.zui", .{ d, st.file, cs.n });
        std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = p, .data = rep.message }) catch {};
    };
}

// ============================================================================ index-feed

/// The last run of consecutive `chk/<seq>.chk` files, up to `max_run` checkpoints: index A starts
/// with every touched object's state before the run (its first input version) and follows the run
/// through `feed.changesOf` + `applyChanges`; index B inserts every touched object's final state.
/// Items: `feed/owners`, `feed/balances`, `feed/coins` (A == B), `feed/inputs` (every old version
/// was in the checkpoint's object set).
const max_run = 500;

fn runFeed(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    const names = try ctx.listFiles("chk", ".chk");
    defer ctx.freeNames(names);
    var seqs: std.ArrayList(u64) = .empty;
    defer seqs.deinit(gpa);
    for (names) |n| try seqs.append(gpa, std.fmt.parseInt(u64, n[0 .. n.len - 4], 10) catch continue);
    std.mem.sort(u64, seqs.items, {}, std.sort.asc(u64));
    if (seqs.items.len == 0) return ctx.skip("feed", "no chk/ checkpoints");
    // the latest run of at least 100 consecutive checkpoints (else the longest), its last max_run
    var best_s: usize = 0;
    var best_e: usize = 1;
    var rs: usize = 0;
    for (1..seqs.items.len + 1) |i| {
        if (i < seqs.items.len and seqs.items[i] == seqs.items[i - 1] + 1) continue;
        if (i - rs >= 100 or i - rs > best_e - best_s) {
            best_s = rs;
            best_e = i;
        }
        rs = i;
    }
    const run = seqs.items[@max(best_s, best_e -| max_run)..best_e];

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ci = try gpa.create(types.CheckpointIndex);
    defer gpa.destroy(ci);
    ci.* = try types.CheckpointIndex.init(gpa);
    defer ci.deinit(gpa);

    var first: std.AutoHashMapUnmanaged([32]u8, ?[]const u8) = .empty; // pre-run state
    var last: std.AutoHashMapUnmanaged([32]u8, ?[]const u8) = .empty; // final state
    var per_cp: std.ArrayList([]const index.Index.Change) = .empty;
    var stats: feed.Stats = .{};
    for (run) |seq| {
        const path = try std.fmt.allocPrint(a, "chk/{d}.chk", .{seq});
        const blob = try ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(1 << 30));
        try types.index.indexCheckpointData(blob, ci);
        const changes = try feed.changesOf(a, ci, blob, null, &stats);
        try per_cp.append(a, changes);
        for (changes) |c| {
            const raw = c.new orelse c.old.?;
            const id = idOf(a, raw) orelse continue;
            const g = try first.getOrPut(a, id);
            if (!g.found_existing) g.value_ptr.* = c.old;
            try last.put(a, id, c.new);
        }
    }
    var ia = try index.Index.init(gpa);
    defer ia.deinit();
    var ib = try index.Index.init(gpa);
    defer ib.deinit();
    var it = first.valueIterator();
    while (it.next()) |v| if (v.*) |raw| try ia.insert(raw);
    for (per_cp.items, run) |changes, seq| try ia.applyChanges(seq, changes);
    var lt = last.valueIterator();
    while (lt.next()) |v| if (v.*) |raw| try ib.insert(raw);

    var cmp_arena = std.heap.ArenaAllocator.init(gpa);
    defer cmp_arena.deinit();
    const ca = cmp_arena.allocator();
    var rows: [3]u64 = @splat(0);
    var bad: [3]u64 = @splat(0);
    {
        var x = try ia.all(ca);
        var y = try ib.all(ca);
        while (true) {
            const ex = try x.next();
            const ey = try y.next();
            if (ex == null and ey == null) break;
            const k = if (ey) |e| e.key else ex.?.key;
            const t = @min(k[0], 2);
            if (ey != null) rows[t] += 1;
            const same = ex != null and ey != null and std.mem.eql(u8, ex.?.key, ey.?.key) and ex.?.val.op == ey.?.val.op and std.mem.eql(u8, ex.?.val.bytes(), ey.?.val.bytes());
            if (!same) {
                bad[t] += 1;
                break; // streams are out of step from here
            }
        }
    }
    ctx.stderr.print("index-feed: checkpoints {d}..{d} ({d}), objects touched {d}, missing old {d}, undecodable effects {d}, owner rows {d}, balance rows {d}, coin rows {d}\n", .{ run[0], run[run.len - 1], run.len, first.count(), stats.missing_old, stats.undecodable, rows[0], rows[1], rows[2] }) catch {};
    {
        var c = ctx.check("feed/inputs");
        if (stats.missing_old != 0 or stats.undecodable != 0) c.failf("{d} old versions missing, {d} effects undecodable", .{ stats.missing_old, stats.undecodable });
        _ = c.finish();
    }
    inline for (.{ "feed/owners", "feed/balances", "feed/coins" }, 0..) |name, t| {
        var c = ctx.check(name);
        if (bad[t] != 0) c.failf("rows differ (first difference in this table)", .{});
        _ = c.finish();
    }
}

fn idOf(a: std.mem.Allocator, raw: []const u8) ?[32]u8 {
    const obj = bcs.decode(types.Object, a, raw) catch return null;
    return switch (obj.data) {
        .Move => |mo| mo.contents[0..32].*,
        .Package => |p| p.id.@"0".@"0",
    };
}
