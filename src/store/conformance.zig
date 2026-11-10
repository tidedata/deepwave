//! Conformance suites of the storage lane (CONTRACTS.md section 3.3).
//!
//! `store-replay`: ingests every corpus checkpoint in sequence order into a real on-disk store
//! (one commit group per checkpoint), using the ops truth that `tools/truth/storage` derives
//! with Mysten's sui-types (byte ranges, object refs, removals). Items:
//!   cp/<seq>            the checkpoint record and every transaction (tx, effects, events,
//!                       effects digest) read back byte-identical
//!   obj/<seq>/<i>/<j>   every object version written reads back with its exact bytes and digest
//!   live/<id>           the live set equals Mysten's (`latest_live_output_objects` folded in
//!                       sequence order): version, digest, bytes
//!   live-count          and nothing else is live
//! then prunes every epoch before the dense window and repeats the checks with pruning
//! semantics (prune/...: retained history present, dropped history absent, live set unchanged
//! through carry-forward), then reopens from disk and checks the live set again (reopen/...).
//!
//! `store-dst`: deterministic simulation (dst.zig). One item per seed: 2048 synthetic crash
//! seeds, 256 corruption seeds (rot, misdirection, and a prune over rotted live records),
//! 64 seeds replaying windows of real dense-window checkpoints,
//! 64 steady-state seeds (2000+ checkpoints each, tiny index limits, a prune every epoch),
//! 512 age-out seeds (floors moving, holes and punches, crashes inside age-out steps, mixed raw
//! and compressed segments, a snapshot held across the steps),
//! 512 `tail` seeds (the newest group torn, rotted before a durable group, rotted under dir
//! entries, or rotted with nothing after it), 512 `pending` seeds (every crash garbles the
//! pending write's target) and 512 `misdir` seeds (whole writes land at wrong places).
//! Every seed also emits the Lean store-model trace (lean/Zui/Store/Trace.lean) and passes only
//! if both the in-memory model and `zui-spec store-trace` accept it (`./zig build lean`).
const std = @import("std");
const harness = @import("harness");
const store = @import("root.zig");
const ops = @import("ops.zig");
const clock = @import("clock.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "store-dst",
        .lane = "storage",
        .doc = "deterministic simulation: seeds x faults, crash recovery invariants hold",
        .run = runDst,
    },
    .{
        .name = "store-replay",
        .lane = "storage",
        .doc = "ingest corpus checkpoints; every object version and live set read back equals truth",
        .run = runReplay,
        .bench = benchReplay,
        .baselines = &.{
            .{ .name = "ingest", .argv = &.{ "{release}/zui-store-truth", "bench", "ingest" } },
            .{ .name = "ingest-sync", .argv = &.{ "{release}/zui-store-truth", "bench", "ingest-sync" } },
            .{ .name = "get-live", .argv = &.{ "{release}/zui-store-truth", "bench", "get-live" } },
            .{ .name = "get-version", .argv = &.{ "{release}/zui-store-truth", "bench", "get-version" } },
            .{ .name = "get-tx", .argv = &.{ "{release}/zui-store-truth", "bench", "get-tx" } },
        },
    },
};

const ops_dir = "vectors/store-replay/ops";
const max_blob = 1 << 30;

fn seqOf(name: []const u8) u64 {
    return harness.leadingNumber(name) orelse 0;
}

/// Reads chk/<seq>.chk and its ops file into scratch memory and parses them.
fn loadCheckpoint(ctx: *harness.Ctx, seq: u64) !ops.Checkpoint {
    var nb: [96]u8 = undefined;
    const blob = try ctx.readFile(try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{seq}), max_blob);
    const o = try ctx.readFile(try std.fmt.bufPrint(&nb, ops_dir ++ "/{d}.ops", .{seq}), max_blob);
    return ops.parse(ctx.scratch(), o, blob);
}

fn hexId(buf: []u8, id: *const [32]u8) []const u8 {
    return std.fmt.bufPrint(buf, "{x}", .{id}) catch unreachable;
}

/// Small initial live table and memtables, so the replay grows the live table and seals runs
/// on real data (reads below go through runs, memtables and the live table alike).
const replay_cfg: store.Config = .{
    .retention_epochs = 2,
    .max_live_objects = 1 << 16,
    .max_object_versions = 1 << 19,
    .max_transactions = 1 << 17,
    .max_checkpoints = 1 << 12,
    .max_batch_bytes = 64 << 20,
    .max_batch_objects = 1 << 16,
    .max_segments = 4096,
    .index_flush_interval = 8192,
    .segment_reserve = 16 << 30,
    .seed = 0x7a75692d7265706c,
};

const ReplayState = struct {
    s: *store.Store,
    /// Epoch boundary of the prune phase (0: no pruning yet).
    pruned_before: u64 = 0,
    phase: []const u8 = "",
    live: []const u8,
};

/// One item per checkpoint plus one per object version.
fn verifyCheckpoint(st: *const ReplayState, ctx: *harness.Ctx, name: []const u8) !void {
    const seq = seqOf(name);
    const cp = loadCheckpoint(ctx, seq) catch |e| {
        var ib: [64]u8 = undefined;
        ctx.fail(std.fmt.bufPrint(&ib, "{s}cp/{d}", .{ st.phase, seq }) catch "cp", "load: {s}", .{@errorName(e)});
        return;
    };
    var snap = st.s.snapshot();
    defer snap.release();
    const retained = cp.epoch >= st.pruned_before;
    var ib: [160]u8 = undefined;
    {
        const item = std.fmt.bufPrint(&ib, "{s}cp/{d}", .{ st.phase, seq }) catch unreachable;
        var c = ctx.check(item);
        const got = snap.checkpointChecked(seq) catch |e| blk: {
            c.failf("checkpoint read: {s}", .{@errorName(e)});
            break :blk null;
        };
        if (retained) {
            if (got) |r| {
                c.bytes("summary_cert", cp.summary_cert, r.summary_cert);
                c.bytes("contents", cp.contents, r.contents);
                c.eql("epoch", cp.epoch, r.epoch);
            } else c.failf("checkpoint missing", .{});
        } else if (got != null) c.failf("pruned checkpoint still readable", .{});
        for (cp.txs, 0..) |*t, i| {
            const r = snap.transactionChecked(t.digest) catch |e| {
                c.failf("tx[{d}]: {s}", .{ i, @errorName(e) });
                continue;
            };
            if (!retained) {
                if (r != null) c.failf("tx[{d}]: pruned but readable", .{i});
                continue;
            }
            const tr = r orelse {
                c.failf("tx[{d}] missing", .{i});
                continue;
            };
            c.bytes("tx", t.tx, tr.tx);
            c.bytes("effects", t.effects, tr.effects);
            c.bytes("effects_digest", t.effects_digest, tr.effects_digest);
            c.eql("checkpoint", seq, tr.checkpoint);
            c.eql("has_events", t.events != null, tr.events != null);
            if (t.events) |ev| if (tr.events) |got_ev| c.bytes("events", ev, got_ev);
        }
        _ = c.finish();
    }
    for (cp.txs, 0..) |*t, i| for (t.puts, 0..) |*p, j| {
        const item = std.fmt.bufPrint(&ib, "{s}obj/{d}/{d}/{d}", .{ st.phase, seq, i, j }) catch unreachable;
        var c = ctx.check(item);
        const got = snap.objectAtChecked(p.id, p.version) catch |e| blk: {
            c.failf("objectAt: {s}", .{@errorName(e)});
            break :blk null;
        };
        // After pruning, a version stays readable when its epoch is retained or it is the
        // live version (carried forward).
        const want = retained or isLive(st.live, p.id, p.version);
        if (want) {
            if (got) |o| {
                c.bytes("bytes", p.bytes, o.bytes);
                c.bytes("digest", p.digest, &o.digest);
            } else c.failf("version {d} missing", .{p.version});
        } else if (got != null) c.failf("pruned version {d} still readable", .{p.version});
        _ = c.finish();
    };
}

/// live.bin is sorted by id: 72-byte entries (id, version LE, digest).
fn isLive(live: []const u8, id: *const [32]u8, version: u64) bool {
    var lo: usize = 0;
    var hi: usize = live.len / 72;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        const e = live[mid * 72 ..][0..72];
        switch (std.mem.order(u8, e[0..32], id)) {
            .lt => lo = mid + 1,
            .gt => hi = mid,
            .eq => return std.mem.readInt(u64, e[32..40], .little) == version,
        }
    }
    return false;
}

fn verifyLiveChunk(st: *const ReplayState, ctx: *harness.Ctx, name: []const u8) !void {
    // name = "<start>" index into live.bin, chunks of 4096 entries
    const start = seqOf(name);
    const n = st.live.len / 72;
    var snap = st.s.snapshot();
    defer snap.release();
    var i = start;
    while (i < @min(n, start + 4096)) : (i += 1) {
        const e = st.live[i * 72 ..][0..72];
        const id: *const [32]u8 = e[0..32];
        const version = std.mem.readInt(u64, e[32..40], .little);
        var ib: [160]u8 = undefined;
        var hb: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&ib, "{s}live/{s}", .{ st.phase, hexId(&hb, id) }) catch unreachable;
        var c = ctx.check(item);
        const got = snap.latest(id) catch |err| blk: {
            c.failf("latest: {s}", .{@errorName(err)});
            break :blk null;
        };
        if (got) |g| switch (g) {
            .live => |o| {
                c.eql("version", version, o.version);
                c.bytes("digest", e[40..72], &o.digest);
                // The live bytes are the stored bytes of that exact version.
                if (snap.objectAtChecked(id, version) catch null) |v| c.bytes("bytes", v.bytes, o.bytes) else c.failf("live version not readable by version", .{});
            },
            .removed => |r| c.failf("removed at v{d}, truth live at v{d}", .{ r.version, version }),
        } else c.failf("not live, truth live at v{d}", .{version});
        _ = c.finish();
    }
}

fn liveChunkNames(gpa: std.mem.Allocator, n: usize) ![][]const u8 {
    const count = std.math.divCeil(usize, n, 4096) catch unreachable;
    const names = try gpa.alloc([]const u8, count);
    for (names, 0..) |*nm, k| nm.* = try std.fmt.allocPrint(gpa, "{d}", .{k * 4096});
    return names;
}

fn freeNames(gpa: std.mem.Allocator, names: [][]const u8) void {
    for (names) |n| gpa.free(n);
    gpa.free(names);
}

fn checkLiveSet(ctx: *harness.Ctx, st: *const ReplayState) !void {
    const names = try liveChunkNames(ctx.gpa, st.live.len / 72);
    defer freeNames(ctx.gpa, names);
    try ctx.forEachName(names, st, verifyLiveChunk);
    var ib: [64]u8 = undefined;
    var c = ctx.check(std.fmt.bufPrint(&ib, "{s}live-count", .{st.phase}) catch unreachable);
    c.eql("live objects", @as(u64, st.live.len / 72), st.s.liveCount());
    _ = c.finish();
}

fn runReplay(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    const names = try ctx.listFiles(ops_dir, ".ops");
    defer ctx.freeNames(names);
    const chk = try ctx.listFiles("chk", ".chk");
    defer ctx.freeNames(chk);
    if (names.len != chk.len) {
        ctx.fail("ops-coverage", "{d} ops files for {d} checkpoints: run zui-store-truth build", .{ names.len, chk.len });
        return;
    }
    const live = try ctx.corpus.readFileAlloc(ctx.io, "vectors/store-replay/live.bin", gpa, .limited(1 << 32));
    defer gpa.free(live);

    const dir = try std.fmt.allocPrint(gpa, "{s}/sessions/storage/replay-store-{d}", .{ ctx.corpus_path, std.c.getpid() });
    defer gpa.free(dir);
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var cfg = replay_cfg;
    cfg.dir = dir;
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .data });
    var closed = false;
    defer if (!closed) {
        h.store.deinit();
        h.io.deinit();
    };

    // Ingest, sequentially, one commit group per checkpoint.
    const t0 = clock.now();
    var bytes_in: u64 = 0;
    var dense_epoch: u64 = 0;
    for (names) |name| {
        ctx.nextItem();
        const seq = seqOf(name);
        const cp = loadCheckpoint(ctx, seq) catch |e| {
            ctx.fail(name, "load: {s}", .{@errorName(e)});
            continue;
        };
        const b = try h.store.begin(cp.seq, cp.epoch);
        try ops.apply(b, &cp);
        try h.store.commit(b);
        bytes_in += cp.summary_cert.len;
        dense_epoch = cp.epoch;
    }
    const ingest_ns = clock.now() - t0;
    {
        const ss = &h.store.stats;
        const mem = h.store.indexMemory();
        const ls = h.store.liveSlots();
        const n = @max(1, names.len);
        try ctx.stderr.print("store-replay: ingested {d} checkpoints in {d} ms ({d} MiB appended); index: {d} live of {d} slots ({d} MiB file, {d} grows), {d} runs sealed ({d} MiB, {d} B/cp), {d} live flushes ({d} MiB, {d} B/cp); RAM: memtables {d} MiB, dirty live pages {d} KiB\n", .{
            names.len,                     ingest_ns / 1_000_000,        ss.bytes_appended >> 20,
            ls.used,                       ls.capacity,                  mem.live_file >> 20,
            ss.live_grows,                 ss.runs_sealed,               ss.run_bytes_written >> 20,
            ss.run_bytes_written / n,      ss.index_flushes,             ss.index_bytes_written >> 20,
            ss.index_bytes_written / n,    mem.memtables >> 20,          mem.live_dirty >> 10,
        });
    }

    var st: ReplayState = .{ .s = h.store, .live = live };
    try ctx.forEachName(names, &st, verifyCheckpoint);
    try checkLiveSet(ctx, &st);

    // Prune everything before the newest epoch but one (the dense window's epoch change).
    const target = dense_epoch -| 1;
    const rep = try h.store.pruneBefore(target);
    try ctx.stderr.print("store-replay: pruneBefore({d}) dropped {d} segments ({d} MiB), carried {d} live objects ({d} MiB), dropped {d} tombstones in {d} ms\n", .{ target, rep.segments_dropped, rep.bytes_dropped >> 20, rep.objects_carried, rep.bytes_carried >> 20, rep.tombstones_dropped, rep.ns / 1_000_000 });
    st.pruned_before = target;
    st.phase = "prune/";
    try ctx.forEachName(names, &st, verifyCheckpoint);
    try checkLiveSet(ctx, &st);

    // Clean close, then reopen from the index snapshot.
    try h.store.close();
    h.io.deinit();
    closed = true;
    const last = seqOf(names[names.len - 1]);
    h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .data });
    closed = false;
    st.s = h.store;
    st.phase = "reopen/";
    try reopenChecks(ctx, &st, last, target, 0);
    h.store.deinit();
    h.io.deinit();
    closed = true;

    // Without any index files the store rebuilds every index from the segment logs alone. The
    // segments' own decode data that lives beside the index stays: history dictionaries
    // (`<e>.zd`, lane disk-fit: chunk codec 3 names them) and age-out sidecars (`<e>.side`).
    // They are removed only with their segment; losing one is damage, not a rebuild.
    {
        const idx = try std.fmt.allocPrint(gpa, "{s}/index", .{dir});
        defer gpa.free(idx);
        var d = try std.Io.Dir.cwd().openDir(ctx.io, idx, .{ .iterate = true });
        defer d.close(ctx.io);
        var doomed: std.ArrayList([]u8) = .empty;
        defer {
            for (doomed.items) |n| gpa.free(n);
            doomed.deinit(gpa);
        }
        var it = d.iterate();
        while (try it.next(ctx.io)) |e| {
            if (std.mem.endsWith(u8, e.name, ".zd") or std.mem.endsWith(u8, e.name, ".side")) continue;
            try doomed.append(gpa, try gpa.dupe(u8, e.name));
        }
        for (doomed.items) |n| try d.deleteTree(ctx.io, n);
    }
    h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .data });
    closed = false;
    st.s = h.store;
    st.phase = "rebuild/";
    try reopenChecks(ctx, &st, last, target, 1);
    try ctx.forEachName(names, &st, verifyCheckpoint);
}

fn reopenChecks(ctx: *harness.Ctx, st: *const ReplayState, last: u64, oldest: u64, rebuilt: u64) !void {
    var ib: [64]u8 = undefined;
    var c = ctx.check(std.fmt.bufPrint(&ib, "{s}state", .{st.phase}) catch unreachable);
    c.eql("committed", @as(?u64, last), st.s.committed());
    c.eql("oldest epoch", oldest, st.s.oldest_epoch.load(.monotonic));
    c.eql("full rebuild", rebuilt != 0, st.s.stats.rebuilt_index);
    _ = c.finish();
    try checkLiveSet(ctx, st);
}

// ------------------------------------------------------------------ store-dst

fn runDst(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    // Corpus windows from the dense range (contiguous checkpoints, real epoch change).
    const dense_text = ctx.corpus.readFileAlloc(ctx.io, "plan/dense.txt", gpa, .limited(64 << 20)) catch null;
    defer if (dense_text) |t| gpa.free(t);
    var dense: std.ArrayList(u64) = .empty;
    defer dense.deinit(gpa);
    if (dense_text) |t| {
        var it = harness.lines(t);
        while (it.next()) |l| try dense.append(gpa, std.fmt.parseInt(u64, std.mem.trim(u8, l, " \r"), 10) catch continue);
    }
    var names: std.ArrayList([]const u8) = .empty;
    defer {
        for (names.items) |n| gpa.free(n);
        names.deinit(gpa);
    }
    for (1..2049) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "seed/{d}", .{k}));
    for (1..257) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "corrupt/{d}", .{k}));
    for (1..257) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "io/{d}", .{k}));
    for (1..65) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "corpus/{d}", .{k}));
    for (1..65) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "steady/{d}", .{k}));
    for (1..513) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "age/{d}", .{k}));
    for (1..513) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "tail/{d}", .{k}));
    for (1..513) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "pending/{d}", .{k}));
    for (1..513) |k| try names.append(gpa, try std.fmt.allocPrint(gpa, "misdir/{d}", .{k}));
    var totals: Totals = .{};
    const trace_dir = try std.fmt.allocPrint(gpa, "{s}/sessions/storage/dst-traces-{d}", .{ ctx.corpus_path, std.c.getpid() });
    defer gpa.free(trace_dir);
    // Per process: two store-dst runs on one runner box would otherwise check each other's traces.
    defer std.Io.Dir.cwd().deleteTree(ctx.io, trace_dir) catch {};
    try std.Io.Dir.cwd().createDirPath(ctx.io, trace_dir);
    const st: DstState = .{ .dense = dense.items, .totals = &totals, .trace_dir = trace_dir };
    try ctx.forEachName(names.items, &st, runSeed);
    try ctx.stderr.print("store-dst: lean traces: {d} events checked; steady: max {d} runs, max {d} live slots for {d} distinct ids\n", .{
        totals.lean_events.load(.monotonic), totals.max_runs.load(.monotonic), totals.max_slots.load(.monotonic), totals.steady_ids.load(.monotonic),
    });
    try ctx.stderr.print("store-dst: age-out: {d} floor moves, {d} steps, {d} records dropped, {d} chunks rewritten\n", .{
        totals.floor_moves.load(.monotonic), totals.age_steps.load(.monotonic), totals.age_dropped.load(.monotonic), totals.age_rewrites.load(.monotonic),
    });
    try ctx.stderr.print("store-dst: {d} commits, {d} crashes, {d} recoveries, in-flight kept {d} lost {d}, {d} prunes, {d} reopens, {d} mvcc checks, {d} reads checked, corruption: {d} detected reads, {d} refused opens, {d} rolled back, prunes over rot {d} kept every intact live object and {d} refused; sim: {d} torn sectors, {d} lost sectors, {d} lost files, {d} resurrected files, {d} misdirected, {d} rotted\n", .{
        totals.commits.load(.monotonic),          totals.crashes.load(.monotonic),     totals.recoveries.load(.monotonic),
        totals.kept.load(.monotonic),             totals.lost.load(.monotonic),        totals.prunes.load(.monotonic),
        totals.reopens.load(.monotonic),          totals.mvcc.load(.monotonic),        totals.reads.load(.monotonic),
        totals.detected.load(.monotonic),         totals.refused.load(.monotonic),     totals.rolled.load(.monotonic),
        totals.rot_prunes.load(.monotonic),       totals.rot_refused.load(.monotonic),
        totals.torn.load(.monotonic),             totals.sect_lost.load(.monotonic),   totals.files_lost.load(.monotonic),
        totals.resurrected.load(.monotonic),      totals.misdirected.load(.monotonic), totals.rotted.load(.monotonic),
    });
    try io_totals.print(ctx);
    try ctx.stderr.print("store-dst: tail: modes {d}/{d}/{d}/{d} (rot+later, lost sector, rot under dir proof, rot alone), {d} truncated, {d} refused; pending: {d} sectors garbled; misdir: {d} writes misdirected\n", .{
        totals.tail_modes[0].load(.monotonic), totals.tail_modes[1].load(.monotonic), totals.tail_modes[2].load(.monotonic), totals.tail_modes[3].load(.monotonic),
        totals.tail_truncated.load(.monotonic), totals.tail_refused.load(.monotonic),
        totals.garbled.load(.monotonic),        totals.misdir_writes.load(.monotonic),
    });
}

const A = std.atomic.Value(u64);
const Totals = struct {
    commits: A = .init(0),
    crashes: A = .init(0),
    recoveries: A = .init(0),
    kept: A = .init(0),
    lost: A = .init(0),
    prunes: A = .init(0),
    reopens: A = .init(0),
    mvcc: A = .init(0),
    reads: A = .init(0),
    detected: A = .init(0),
    refused: A = .init(0),
    rolled: A = .init(0),
    rot_prunes: A = .init(0),
    rot_refused: A = .init(0),
    torn: A = .init(0),
    sect_lost: A = .init(0),
    files_lost: A = .init(0),
    resurrected: A = .init(0),
    misdirected: A = .init(0),
    rotted: A = .init(0),
    lean_events: A = .init(0),
    age_steps: A = .init(0),
    age_dropped: A = .init(0),
    age_rewrites: A = .init(0),
    floor_moves: A = .init(0),
    max_runs: A = .init(0),
    max_slots: A = .init(0),
    steady_ids: A = .init(0),
    tail_modes: [4]A = @splat(.init(0)),
    tail_truncated: A = .init(0),
    tail_refused: A = .init(0),
    garbled: A = .init(0),
    misdir_writes: A = .init(0),
};

const DstState = struct { dense: []const u64, totals: *Totals, trace_dir: []const u8 };

const spec_bin = "lean/.lake/build/bin/zui-spec";

/// Runs the Lean checker on a seed's traces; null when it accepted all, else its output tail.
fn leanCheck(ctx: *harness.Ctx, paths: []const []const u8) !?[]const u8 {
    const argv = try ctx.scratch().alloc([]const u8, 2 + paths.len);
    argv[0] = spec_bin;
    argv[1] = "store-trace";
    @memcpy(argv[2..], paths);
    const r = std.process.run(ctx.gpa, ctx.io, .{ .argv = argv }) catch |e|
        return try std.fmt.allocPrint(ctx.scratch(), "cannot run {s}: {s} (./zig build lean)", .{ spec_bin, @errorName(e) });
    defer ctx.gpa.free(r.stdout);
    defer ctx.gpa.free(r.stderr);
    const t = std.mem.trimEnd(u8, r.stdout, "\n");
    const last = t[(if (std.mem.lastIndexOfScalar(u8, t, '\n')) |i| i + 1 else 0)..];
    if (r.term.success() and std.mem.indexOf(u8, last, "\"done\":true") != null) return null;
    const out = if (r.stdout.len > 1500) r.stdout[r.stdout.len - 1500 ..] else r.stdout;
    return try std.fmt.allocPrint(ctx.scratch(), "{s}{s}", .{ out, if (r.stderr.len > 500) r.stderr[r.stderr.len - 500 ..] else r.stderr });
}

fn runSeed(st: *const DstState, ctx: *harness.Ctx, name: []const u8) !void {
    const slash = std.mem.indexOfScalar(u8, name, '/').?;
    const kind = name[0..slash];
    const k = try std.fmt.parseInt(u64, name[slash + 1 ..], 10);
    var opts: store.sim.dst.Options = .{ .seed = k *% 0x9e3779b97f4a7c15 ^ 0x5eed_0001, .lean = true };
    var corpus_cps: std.ArrayList(ops.Checkpoint) = .empty;
    // ZUI_DST_DEBUG=1 with -Dfilter=<seed>: the driver's step-by-step prints (dst.Options.debug).
    opts.debug = std.c.getenv("ZUI_DST_DEBUG") != null;
    if (std.mem.eql(u8, kind, "steady")) {
        opts.steady = true;
        opts.seed ^= 0x57ea;
        // More distinct ids than the smallest live table's 3,264 slots (20-byte slots since lane
        // disk-fit; 2,400 checkpoints passed at most 3,215 ids).
        opts.checkpoints = 4400;
        opts.lean_window = 200;
    } else if (std.mem.eql(u8, kind, "age")) {
        opts.age = true;
        opts.lean = false;
        opts.seed ^= 0xa9e;
        opts.checkpoints = 200;
    } else if (std.mem.eql(u8, kind, "corrupt")) {
        opts.corruption = true;
        opts.seed ^= 0xc0;
    } else if (std.mem.eql(u8, kind, "tail")) {
        opts.tail = true;
        opts.seed ^= 0x7a11;
    } else if (std.mem.eql(u8, kind, "pending")) {
        opts.pending = true;
        opts.seed ^= 0x9e4d;
    } else if (std.mem.eql(u8, kind, "misdir")) {
        opts.misdir = true;
        opts.seed ^= 0x3d1e;
    } else if (std.mem.eql(u8, kind, "io")) {
        opts.io_faults = true;
        opts.seed ^= 0x10e;
    } else if (std.mem.eql(u8, kind, "corpus")) {
        if (st.dense.len < 64) {
            ctx.skip(name, "plan/dense.txt missing or short");
            return;
        }
        const window = 24;
        const start = (opts.seed >> 7) % (st.dense.len - window);
        for (st.dense[start..][0..window]) |seq| {
            const cp = loadCheckpoint(ctx, seq) catch |e| {
                ctx.fail(name, "load {d}: {s}", .{ seq, @errorName(e) });
                return;
            };
            try corpus_cps.append(ctx.scratch(), cp);
        }
        opts.corpus = corpus_cps.items;
        opts.file_cap = 512 << 20;
    }
    const r = store.sim.dst.run(ctx.gpa, opts) catch |e| {
        if (opts.debug) if (@errorReturnTrace()) |t| std.debug.dumpErrorReturnTrace(t);
        ctx.fail(name, "error {s}", .{@errorName(e)});
        return;
    };
    defer if (r.lean_trace) |x| ctx.gpa.free(x);
    defer if (r.lean_cuts) |x| ctx.gpa.free(x);
    const t = st.totals;
    _ = t.lean_events.fetchAdd(r.lean_events, .monotonic);
    _ = t.age_steps.fetchAdd(r.age_steps, .monotonic);
    _ = t.age_dropped.fetchAdd(r.age_dropped, .monotonic);
    _ = t.age_rewrites.fetchAdd(r.age_rewrites, .monotonic);
    _ = t.floor_moves.fetchAdd(r.floor_moves, .monotonic);
    if (opts.steady) {
        _ = t.max_runs.fetchMax(r.max_runs, .monotonic);
        _ = t.max_slots.fetchMax(r.max_live_slots, .monotonic);
        _ = t.steady_ids.fetchMax(r.distinct_ids, .monotonic);
        if (r.max_live_slots >= r.distinct_ids) {
            ctx.fail(name, "steady: {d} live slots for {d} distinct ids (index grows with history)", .{ r.max_live_slots, r.distinct_ids });
            return;
        }
    }
    _ = t.commits.fetchAdd(r.commits, .monotonic);
    _ = t.crashes.fetchAdd(r.crashes, .monotonic);
    _ = t.recoveries.fetchAdd(r.recoveries, .monotonic);
    _ = t.kept.fetchAdd(r.in_flight_kept, .monotonic);
    _ = t.lost.fetchAdd(r.in_flight_lost, .monotonic);
    _ = t.prunes.fetchAdd(r.prunes, .monotonic);
    _ = t.reopens.fetchAdd(r.reopens, .monotonic);
    _ = t.mvcc.fetchAdd(r.mvcc_checks, .monotonic);
    _ = t.reads.fetchAdd(r.reads_checked, .monotonic);
    _ = t.detected.fetchAdd(r.corrupt_detected, .monotonic);
    _ = t.refused.fetchAdd(@intFromBool(r.open_refused), .monotonic);
    _ = t.rolled.fetchAdd(@intFromBool(r.rolled_back), .monotonic);
    _ = t.rot_prunes.fetchAdd(r.rot_prunes, .monotonic);
    _ = t.rot_refused.fetchAdd(r.rot_prunes_refused, .monotonic);
    _ = t.torn.fetchAdd(r.sim.sectors_torn, .monotonic);
    _ = t.sect_lost.fetchAdd(r.sim.sectors_lost, .monotonic);
    _ = t.files_lost.fetchAdd(r.sim.files_lost, .monotonic);
    _ = t.resurrected.fetchAdd(r.sim.files_resurrected, .monotonic);
    _ = t.misdirected.fetchAdd(r.sim.misdirected, .monotonic);
    _ = t.rotted.fetchAdd(r.sim.rotted, .monotonic);
    if (opts.io_faults) io_totals.add(&r);
    if (opts.tail) {
        _ = t.tail_modes[r.tail_mode].fetchAdd(1, .monotonic);
        _ = t.tail_truncated.fetchAdd(@intFromBool(r.tail_truncated), .monotonic);
        _ = t.tail_refused.fetchAdd(@intFromBool(r.open_refused), .monotonic);
    }
    _ = t.garbled.fetchAdd(r.sim.sectors_garbled, .monotonic);
    _ = t.misdir_writes.fetchAdd(r.sim.misdirected_writes, .monotonic);
    if (!r.ok) return ctx.fail(name, "{s} (commits {d}, crashes {d})", .{ r.msg(), r.commits, r.crashes });
    // The Lean model must accept the same run (every window of it).
    const a = ctx.scratch();
    const trace = r.lean_trace orelse "";
    const cuts = r.lean_cuts orelse &.{};
    const paths = try a.alloc([]const u8, cuts.len);
    var from: usize = 0;
    for (cuts, paths, 0..) |end, *path, w| {
        path.* = try std.fmt.allocPrint(a, "{s}/{s}-{d}.{d}.jsonl", .{ st.trace_dir, kind, k, w });
        try std.Io.Dir.cwd().writeFile(ctx.io, .{ .sub_path = path.*, .data = trace[from..end] });
        from = end;
    }
    // Seeds without a Lean trace (age-out: opts.lean false) have no windows to check; zui-spec
    // given no file fails, and paths[0] of an empty list is out of bounds (a SEGV in ReleaseFast
    // that took the whole harness process down).
    if (paths.len > 0) if (try leanCheck(ctx, paths)) |why| return ctx.fail(name, "lean store-trace rejects {s}:\n{s}", .{ paths[0], why });
    for (paths) |path| std.Io.Dir.cwd().deleteFile(ctx.io, path) catch {};
    ctx.pass(name);
}

// ------------------------------------------------------------------ bench

const BenchData = struct {
    cps: []ops.Checkpoint,
    dir: []const u8,
    io: std.Io,
    gpa: std.mem.Allocator,
    sync: store.SyncMode,
};

/// One ingest pass into a fresh store; returns the time spent in begin/apply/commit only
/// (the Rust side likewise times only its writes, not opening or dropping the database).
fn ingestPass(d: *const BenchData, bytes: *u64) !u64 {
    std.Io.Dir.cwd().deleteTree(d.io, d.dir) catch {};
    var cfg = bench_cfg;
    cfg.dir = d.dir;
    const h = try store.openDir(d.gpa, d.io, &cfg, .{ .sync = d.sync });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    const t0 = clock.now();
    for (d.cps) |*cp| {
        const b = try h.store.begin(cp.seq, cp.epoch);
        try ops.apply(b, cp);
        try h.store.commit(b);
    }
    const dt = clock.now() - t0;
    bytes.* = h.store.stats.bytes_appended;
    return dt;
}

/// Warm-up pass, then `iters` timed passes; records the median (harness protocol).
fn benchIngest(ctx: *harness.Ctx, name: []const u8, d: *const BenchData) !void {
    var bytes: u64 = 0;
    _ = try ingestPass(d, &bytes);
    const iters = @max(1, ctx.opts.iters);
    const times = try ctx.gpa.alloc(u64, iters);
    defer ctx.gpa.free(times);
    for (times) |*t| t.* = try ingestPass(d, &bytes);
    // benchRecordTimes sorts; the median is computed the same way here for the log line.
    const sorted = try ctx.gpa.dupe(u64, times);
    defer ctx.gpa.free(sorted);
    std.mem.sort(u64, sorted, {}, std.sort.asc(u64));
    const med = sorted[sorted.len / 2];
    try ctx.stderr.print("store-replay/{s}: {d} checkpoints, {d} bytes appended, median {d} ms of {d} passes (min {d} ms), {d} MB/s\n", .{
        name, d.cps.len, bytes, med / std.time.ns_per_ms, iters, sorted[0] / std.time.ns_per_ms, bytes * 1000 / @max(1, med),
    });
    ctx.benchRecordTimes(name, "checkpoint", d.cps.len, times);
}

/// Bench-sized indexes (the bench set has ~150k object versions and ~28k transactions).
const bench_cfg: store.Config = .{
    .max_live_objects = 1 << 18,
    .max_object_versions = 1 << 19,
    .max_transactions = 1 << 16,
    .max_checkpoints = 1 << 12,
    .max_batch_bytes = 64 << 20,
    .max_batch_objects = 1 << 16,
    .max_segments = 4096,
    .index_flush_interval = 1 << 30,
    .segment_reserve = 16 << 30,
    .seed = 0x7a75692d62656e63,
};

fn orderKey(id: *const [32]u8) u64 {
    return std.mem.readInt(u64, id[16..24], .little);
}

fn lessId(_: void, a: [32]u8, b: [32]u8) bool {
    const ka = orderKey(&a);
    const kb = orderKey(&b);
    if (ka != kb) return ka < kb;
    return std.mem.order(u8, &a, &b) == .lt;
}

const VKey = struct { id: [32]u8, v: u64 };
fn lessV(_: void, a: VKey, b: VKey) bool {
    const ka = orderKey(&a.id);
    const kb = orderKey(&b.id);
    if (ka != kb) return ka < kb;
    return switch (std.mem.order(u8, &a.id, &b.id)) {
        .lt => true,
        .gt => false,
        .eq => a.v < b.v,
    };
}

const ReadBench = struct {
    s: *store.Store,
    ids: [][32]u8,
    keys: []VKey,
    txs: [][32]u8,
    fn live(r: *const ReadBench) !void {
        var snap = r.s.snapshot();
        defer snap.release();
        var acc: u64 = 0;
        for (r.ids) |*id| {
            const g = (try snap.latest(id)) orelse return error.Missing;
            acc +%= switch (g) {
                .live => |o| o.version ^ o.bytes.len,
                .removed => |x| x.version,
            };
        }
        std.mem.doNotOptimizeAway(acc);
    }
    fn version(r: *const ReadBench) !void {
        var snap = r.s.snapshot();
        defer snap.release();
        var acc: u64 = 0;
        for (r.keys) |*k| acc +%= ((try snap.objectAtChecked(&k.id, k.v)) orelse return error.Missing).bytes.len;
        std.mem.doNotOptimizeAway(acc);
    }
    fn tx(r: *const ReadBench) !void {
        var snap = r.s.snapshot();
        defer snap.release();
        var acc: u64 = 0;
        for (r.txs) |*d| acc +%= ((try snap.transactionChecked(d)) orelse return error.Missing).tx.len;
        std.mem.doNotOptimizeAway(acc);
    }
};

fn benchReplay(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const inputs = ctx.benchInputs();
    const cps = try arena.alloc(ops.Checkpoint, inputs.len);
    for (inputs, cps) |p, *cp| {
        const seq = seqOf(p[(std.mem.lastIndexOfScalar(u8, p, '/') orelse 0) + 1 ..]);
        var nb: [96]u8 = undefined;
        const blob = try ctx.corpus.readFileAlloc(ctx.io, p, arena, .limited(max_blob));
        const o = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.bufPrint(&nb, ops_dir ++ "/{d}.ops", .{seq}), arena, .limited(max_blob));
        cp.* = try ops.parse(arena, o, blob);
    }
    const dir = try std.fmt.allocPrint(arena, "{s}/sessions/storage/bench-store-{d}", .{ ctx.corpus_path, std.c.getpid() });
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var d: BenchData = .{ .cps = cps, .dir = dir, .io = ctx.io, .gpa = gpa, .sync = .none };
    try benchIngest(ctx, "ingest", &d);
    // fdatasync per checkpoint (macOS: fsync, as RocksDB's sync writes do there).
    d.sync = .data;
    try benchIngest(ctx, "ingest-sync", &d);

    // Reads, on a store holding the bench set (page cache warm, as on the Rust side).
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var cfg = bench_cfg;
    cfg.dir = dir;
    const h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var ids: std.ArrayList([32]u8) = .empty;
    var keys: std.ArrayList(VKey) = .empty;
    var txs: std.ArrayList([32]u8) = .empty;
    for (cps) |*cp| {
        const b = try h.store.begin(cp.seq, cp.epoch);
        try ops.apply(b, cp);
        try h.store.commit(b);
        for (cp.txs) |*t| {
            try txs.append(arena, t.digest.*);
            for (t.puts) |*p| {
                try ids.append(arena, p.id.*);
                try keys.append(arena, .{ .id = p.id.*, .v = p.version });
            }
            for (t.removes) |*r| try ids.append(arena, r.id.*);
        }
    }
    std.mem.sort([32]u8, ids.items, {}, lessId);
    std.mem.sort(VKey, keys.items, {}, lessV);
    std.mem.sort([32]u8, txs.items, {}, lessId);
    const rb: ReadBench = .{ .s = h.store, .ids = dedup([32]u8, ids.items), .keys = dedup(VKey, keys.items), .txs = dedup([32]u8, txs.items) };
    try ctx.benchPasses("get-live", "read", rb.ids.len, &rb, ReadBench.live);
    try ctx.benchPasses("get-version", "read", rb.keys.len, &rb, ReadBench.version);
    try ctx.benchPasses("get-tx", "read", rb.txs.len, &rb, ReadBench.tx);
}

fn dedup(comptime T: type, items: []T) []T {
    if (items.len == 0) return items;
    var n: usize = 1;
    for (items[1..]) |x| {
        if (!std.meta.eql(x, items[n - 1])) {
            items[n] = x;
            n += 1;
        }
    }
    return items[0..n];
}

/// The `io/<k>` seeds' I/O error faults (sim.zig) and how the store took them.
const IoTotals = struct {
    store_errors: A = .init(0),
    retried: A = .init(0),
    read: A = .init(0),
    write: A = .init(0),
    sync: A = .init(0),
    dropped: A = .init(0),

    fn add(t: *IoTotals, r: *const store.sim.dst.Result) void {
        _ = t.store_errors.fetchAdd(r.io_errors, .monotonic);
        _ = t.retried.fetchAdd(r.io_retried, .monotonic);
        _ = t.read.fetchAdd(r.sim.read_errors, .monotonic);
        _ = t.write.fetchAdd(r.sim.write_errors, .monotonic);
        _ = t.sync.fetchAdd(r.sim.sync_errors, .monotonic);
        _ = t.dropped.fetchAdd(r.sim.sectors_dropped, .monotonic);
    }

    fn print(t: *IoTotals, ctx: *harness.Ctx) !void {
        try ctx.stderr.print("store-dst: io: {d} read, {d} write, {d} sync errors injected ({d} dirty sectors dropped by failed syncs); store reported {d}, {d} commits retried\n", .{
            t.read.load(.monotonic), t.write.load(.monotonic), t.sync.load(.monotonic), t.dropped.load(.monotonic), t.store_errors.load(.monotonic), t.retried.load(.monotonic),
        });
    }
};
var io_totals: IoTotals = .{};
