//! Conformance suite `sync-follow` of the state-sync lane (CONTRACTS.md 3.3 and 6.5.1).
//!
//! Truth: `zui-sync-truth` (tools/truth/state-sync), which runs Mysten's sui-types over the corpus
//! (`CertifiedCheckpointSummary::verify_authority_signatures`, `TransactionEffects::all_changed_objects`
//! and friends), and the committees of the bls lane's `vectors/bls-cert`.
//!
//! Items:
//!   committee/<epoch>      the committee derived from the previous epoch's end-of-epoch checkpoint
//!                          (chained from the epoch 0 committee) equals the Mysten-derived committee
//!   eoe-cert/<epoch>       that end-of-epoch checkpoint's certificate verifies under the derived
//!                          committee of its own epoch (the whole 1305-epoch chain)
//!   all/<seq>             every corpus checkpoint (all 1305 epochs, every protocol version), no chain:
//!                          index, check and certificate verdict, digest, counts and plan hash
//!   <window>/cp/<seq>      follower over a contiguous window into a fresh store: accepted, digest,
//!                          transaction/put/remove counts and the plan hash equal the truth
//!   <window>/state/<id>    the store's latest version/digest/removal of every object touched in the
//!                          window equals the truth's net state; stored bytes hash to the digest
//!   <window>/state-count   and nothing else was recorded
//!   <window>/mutant/<n>    a single-fault mutation of a real blob is accepted or rejected with the
//!                          class Mysten's checks report
//!   edge/<name>            hand-made blobs (`zui-sync-truth edge`): signer bitmap encodings sui-node
//!                          accepts or rejects, quorum edges, aggregate signature bytes, output
//!                          object/event/transaction lists; verdict class equals Mysten's
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const store = @import("store");
const verify = @import("verify.zig");
const archive = @import("archive.zig");
const committee_mod = @import("committee.zig");
const follower = @import("follower.zig");
const Committee = committee_mod.Committee;

pub const suites = [_]harness.Suite{
    .{
        .name = "sync-follow",
        .lane = "state-sync",
        .doc = "follow corpus windows from the archive source: verify, apply, stored state equals Mysten-derived truth",
        .run = run,
        .bench = bench,
        .baselines = &.{
            .{ .name = "apply-check", .argv = &.{ "{release}/zui-sync-truth", "bench", "apply-check" } },
        },
    },
};

const vec_dir = "vectors/sync-follow";

fn hex32(h: *const [32]u8) [64]u8 {
    return std.fmt.bytesToHex(h.*, .lower);
}

const CommitteeCache = struct {
    arena: std.heap.ArenaAllocator,
    map: std.AutoHashMap(u64, Committee),

    fn init(gpa: std.mem.Allocator) CommitteeCache {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa), .map = std.AutoHashMap(u64, Committee).init(gpa) };
    }
    fn deinit(c: *CommitteeCache) void {
        c.map.deinit();
        c.arena.deinit();
    }
    fn get(c: *CommitteeCache, ctx: *harness.Ctx, epoch: u64) !*const Committee {
        if (c.map.getPtr(epoch)) |p| return p;
        var nb: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&nb, "vectors/bls-cert/{d}.jsonl", .{epoch});
        const text = try ctx.corpus.readFileAlloc(ctx.io, path, ctx.gpa, .limited(1 << 28));
        defer ctx.gpa.free(text);
        const nl = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
        const com = try committee_mod.fromJsonLine(c.arena.allocator(), text[0..nl]);
        try c.map.put(epoch, com);
        return c.map.getPtr(epoch).?;
    }
};

fn readBlob(ctx: *harness.Ctx, seq: u64) ![]u8 {
    var nb: [64]u8 = undefined;
    return ctx.readFile(try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{seq}), 1 << 30);
}

fn run(ctx: *harness.Ctx) !void {
    var cache = CommitteeCache.init(ctx.gpa);
    defer cache.deinit();
    try committeeChain(ctx, &cache);
    try scanAll(ctx);
    try liveTail(ctx, &cache);
    try mutants(ctx, &cache, "sparse");
    try edges(ctx, &cache);
    const names = try ctx.listFiles(vec_dir, ".summary.json");
    defer ctx.freeNames(names);
    for (names) |n| {
        if (ctx.done()) break;
        try window(ctx, &cache, n[0 .. n.len - ".summary.json".len]);
    }
}

// ------------------------------------------------------------------------------------------------
// committees

const EpochRec = struct { epoch: u64, first: u64, last: ?u64 = null };

fn committeeChain(ctx: *harness.Ctx, cache: *CommitteeCache) !void {
    const text = try ctx.corpus.readFileAlloc(ctx.io, "epochs.jsonl", ctx.gpa, .limited(1 << 26));
    defer ctx.gpa.free(text);
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    var idx = try types.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    var recs: std.ArrayList(EpochRec) = .empty;
    defer recs.deinit(ctx.gpa);
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |l| {
        if (l.len == 0) continue;
        const r = try std.json.parseFromSliceLeaky(EpochRec, arena.allocator(), l, .{ .ignore_unknown_fields = true });
        try recs.append(ctx.gpa, r);
    }
    // The chain starts at the epoch 0 committee (root), then every epoch's committee comes from the
    // previous epoch's end-of-epoch checkpoint.
    var derived_arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer derived_arena.deinit();
    var prev: Committee = (try cache.get(ctx, 0)).*;
    for (recs.items) |r| {
        const e = r.epoch;
        if (r.last == null) break; // current epoch
        if (ctx.done()) return;
        ctx.nextItem();
        var ib: [64]u8 = undefined;
        const item_cert = std.fmt.bufPrint(&ib, "eoe-cert/{d}", .{e}) catch unreachable;
        const want_next = cache.get(ctx, e + 1) catch {
            ctx.skip(item_cert, "no committee vector for epoch");
            continue;
        };
        const blob = try readBlob(ctx, r.last.?);
        const a = ctx.scratch();
        const v = try verify.full(a, blob, &idx, &prev, null);
        if (selectedItem(ctx, item_cert)) {
            if (v.isOk()) ctx.pass(item_cert) else ctx.fail(item_cert, "verdict {s}", .{verify.class(v)});
        }
        const summary = try bcs.decode(types.CheckpointSummary, a, idx.summary.slice(blob));
        const eoe = summary.end_of_epoch_data orelse {
            ctx.fail(item_cert, "last checkpoint of epoch has no end-of-epoch data", .{});
            continue;
        };
        const next = try Committee.fromEndOfEpoch(derived_arena.allocator(), e + 1, eoe);
        var ib2: [64]u8 = undefined;
        const item = std.fmt.bufPrint(&ib2, "committee/{d}", .{e + 1}) catch unreachable;
        if (selectedItem(ctx, item)) {
            var c = ctx.check(item);
            c.eql("members", want_next.keys.len, next.keys.len);
            if (want_next.keys.len == next.keys.len) {
                for (want_next.keys, next.keys, want_next.stakes, next.stakes, 0..) |wk, nk, ws, ns, i| {
                    if (!std.mem.eql(u8, &wk, &nk) or ws != ns) {
                        c.failf("member {d} differs", .{i});
                        break;
                    }
                }
            }
            _ = c.finish();
        }
        prev = next;
    }
}

/// ZUI_SYNC_CERT_BATCH=N runs the suite's followers with `Config.cert_batch = N` (default 0), so
/// the same windows are checked with and without certificate batching.
fn certBatchEnv() u32 {
    const v = std.c.getenv("ZUI_SYNC_CERT_BATCH") orelse return 0;
    return std.fmt.parseInt(u32, std.mem.span(v), 10) catch 0;
}

/// Batched certificate checks (`verify.checkCerts`) against `verify.checkCert`, item by item, over
/// the blobs of a group that pass `verify.check`: one check item per group.
const BatchCmp = struct {
    arena: std.heap.ArenaAllocator,
    jobs: std.ArrayList(verify.CertJob) = .empty,
    names: std.ArrayList([]const u8) = .empty,
    single: std.ArrayList(verify.Verdict) = .empty,
    comms: std.ArrayList(*const Committee) = .empty,

    fn init(gpa: std.mem.Allocator) BatchCmp {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa) };
    }
    fn deinit(b: *BatchCmp) void {
        b.arena.deinit();
    }

    fn add(b: *BatchCmp, name: []const u8, comm: *const Committee, blob: []const u8, idx: *types.CheckpointIndex) !void {
        const a = b.arena.allocator();
        types.indexCheckpointData(blob, idx) catch return;
        const r = try verify.check(a, blob, idx);
        if (r != .ok) return;
        const summary = try a.dupe(u8, idx.summary.slice(blob));
        const sig = try a.dupe(u8, idx.sig.slice(blob));
        try b.jobs.append(a, .{ .committee = comm, .summary_epoch = r.ok.epoch, .summary = summary, .sig = sig });
        try b.names.append(a, try a.dupe(u8, name));
        try b.single.append(a, try verify.checkCert(a, comm, r.ok.epoch, summary, sig));
        for (b.comms.items) |c| {
            if (c == comm) break;
        } else try b.comms.append(a, comm);
    }

    fn finish(b: *BatchCmp, ctx: *harness.Ctx, item: []const u8) !void {
        if (b.jobs.items.len == 0 or !ctx.selected(item)) return;
        ctx.nextItem();
        const a = b.arena.allocator();
        var in_g2 = true;
        for (b.comms.items) |c| in_g2 = in_g2 and verify.keysInG2(c);
        var seed: [32]u8 = undefined;
        ctx.io.random(&seed);
        var chacha = std.Random.ChaCha.init(seed);
        const out = try a.alloc(verify.Verdict, b.jobs.items.len);
        var c = ctx.check(item);
        var bad: usize = 0;
        for ([_]bool{ false, true }) |kig| {
            if (kig and !in_g2) continue;
            try verify.checkCerts(ctx.gpa, a, b.jobs.items, chacha.random(), .{ .keys_in_group = kig }, out);
            for (b.names.items, b.single.items, out) |n, want, got| {
                if (std.meta.eql(want, got)) continue;
                bad += 1;
                if (bad <= 8) c.failf("{s} (keys_in_group {}): checkCert {s}, batch {s}", .{ n, kig, want.name(), got.name() });
            }
        }
        c.eql("committees in G2", true, in_g2);
        c.eql("batch mismatches", @as(usize, 0), bad);
        var okn: usize = 0;
        for (b.single.items) |v| okn += @intFromBool(v.isOk());
        // per-epoch groups stay quiet unless they hold a rejection or a mismatch
        if (bad > 0 or okn != b.jobs.items.len or !std.mem.startsWith(u8, item, "all-batch/"))
            try ctx.stderr.print("sync-follow {s}: {d} certificates batched ({d} ok, {d} rejected), {d} mismatches\n", .{ item, b.jobs.items.len, okn, b.jobs.items.len - okn, bad });
        _ = c.finish();
    }
};

fn selectedItem(ctx: *harness.Ctx, item: []const u8) bool {
    return ctx.selected(item);
}

// ------------------------------------------------------------------------------------------------
// live mode: checkpoints appear in the archive directory while the follower runs

const Producer = struct {
    ctx: *harness.Ctx,
    dir: []const u8,
    first: u64,
    count: u64,
    f: *follower.Follower,
    err: ?anyerror = null,

    fn main(p: *Producer) void {
        p.work() catch |e| {
            p.err = e;
        };
        p.f.stop();
    }

    fn work(p: *Producer) !void {
        const io = p.ctx.io;
        var d = try std.Io.Dir.cwd().openDir(io, p.dir, .{});
        defer d.close(io);
        var seq = p.first;
        while (seq < p.first + p.count) : (seq += 1) {
            var nb: [64]u8 = undefined;
            const src = try std.fmt.bufPrint(&nb, "chk/{d}.chk", .{seq});
            const bytes = try p.ctx.corpus.readFileAlloc(io, src, p.ctx.gpa, .limited(1 << 30));
            defer p.ctx.gpa.free(bytes);
            var tb: [64]u8 = undefined;
            var fb: [64]u8 = undefined;
            const tmp = try std.fmt.bufPrint(&tb, "{d}.part", .{seq});
            const fin = try std.fmt.bufPrint(&fb, "{d}.chk", .{seq});
            {
                const f = try d.createFile(io, tmp, .{});
                defer f.close(io);
                try f.writeStreamingAll(io, bytes);
            }
            try std.Io.Dir.rename(d, tmp, d, fin, io);
            if (seq % 16 == 0) try std.Io.sleep(io, .fromMilliseconds(20), .awake);
        }
        // let the follower drain, then stop it
        var waited: u32 = 0;
        while (p.f.metrics.checkpoints.load(.monotonic) < p.count and waited < 2000) : (waited += 1) {
            try std.Io.sleep(io, .fromMilliseconds(10), .awake);
        }
    }
};

fn liveTail(ctx: *harness.Ctx, cache: *CommitteeCache) !void {
    const item = "live/archive-tail";
    if (!ctx.selected(item) or ctx.done()) return;
    const gpa = ctx.gpa;
    const first: u64 = 342446161;
    const count: u64 = 300;
    const dir = try std.fmt.allocPrint(gpa, "{s}/sessions/state-sync/live-archive", .{ctx.corpus_path});
    defer gpa.free(dir);
    const sdir = try std.fmt.allocPrint(gpa, "{s}/sessions/state-sync/live-store", .{ctx.corpus_path});
    defer gpa.free(sdir);
    for ([_][]const u8{ dir, sdir }) |d| std.Io.Dir.cwd().deleteTree(ctx.io, d) catch {};
    try std.Io.Dir.cwd().createDirPath(ctx.io, dir);
    defer for ([_][]const u8{ dir, sdir }) |d| std.Io.Dir.cwd().deleteTree(ctx.io, d) catch {};
    var cfg = window_store_cfg;
    cfg.dir = sdir;
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }
    var arch = try archive.Archive.open(ctx.io, dir);
    defer arch.close(ctx.io);
    const comm = try cache.get(ctx, 1303);
    var f = try follower.Follower.init(gpa, ctx.io, h.store, .{ .archive = &arch }, .{ .poll_ms = 20, .cert_batch = certBatchEnv() }, .{ .committee = comm.*, .first_seq = first });
    defer f.deinit();
    var prod: Producer = .{ .ctx = ctx, .dir = dir, .first = first, .count = count, .f = f };
    const th = try std.Thread.spawn(.{}, Producer.main, .{&prod});
    const run_err: ?anyerror = if (f.run(null)) |_| null else |e| e;
    th.join();
    var c = ctx.check(item);
    if (run_err) |e| c.failf("follower: {s}", .{@errorName(e)});
    if (prod.err) |e| c.failf("producer: {s}", .{@errorName(e)});
    c.eql("applied", count, f.metrics.checkpoints.load(.monotonic));
    var snap = h.store.snapshot();
    defer snap.release();
    c.eql("highest committed", @as(?u64, first + count - 1), snap.highestCommitted());
    c.eql("lag at the end", @as(u64, 0), f.metrics.lag());
    _ = c.finish();
}

// ------------------------------------------------------------------------------------------------
// every corpus checkpoint

const ScanState = struct { lines: []const CpLine, groups: []const [2]usize };

fn scanAll(ctx: *harness.Ctx) !void {
    const gpa = ctx.gpa;
    const text = try ctx.corpus.readFileAlloc(ctx.io, vec_dir ++ "/all.scan.jsonl", gpa, .limited(1 << 30));
    defer gpa.free(text);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var lines: std.ArrayList(CpLine) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |l| {
        if (l.len == 0) continue;
        try lines.append(a, try std.json.parseFromSliceLeaky(CpLine, a, l, .{ .ignore_unknown_fields = true }));
    }
    var groups: std.ArrayList([2]usize) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    var start: usize = 0;
    for (lines.items, 0..) |l, i| {
        if (i + 1 == lines.items.len or lines.items[i + 1].epoch != l.epoch) {
            try groups.append(a, .{ start, i + 1 });
            try names.append(a, try std.fmt.allocPrint(a, "{d}", .{l.epoch}));
            start = i + 1;
        }
    }
    var st: ScanState = .{ .lines = lines.items, .groups = groups.items };
    try ctx.forEachName(names.items, &st, scanEpoch);
}

fn scanEpoch(st: *const ScanState, ctx: *harness.Ctx, name: []const u8) !void {
    const epoch = harness.leadingNumber(name).?;
    var nb: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&nb, "vectors/bls-cert/{d}.jsonl", .{epoch});
    const text = try ctx.corpus.readFileAlloc(ctx.io, path, ctx.gpa, .limited(1 << 28));
    defer ctx.gpa.free(text);
    var carena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer carena.deinit();
    const nl = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    const comm = try committee_mod.fromJsonLine(carena.allocator(), text[0..nl]);
    var idx = try types.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    var bc = BatchCmp.init(ctx.gpa);
    defer bc.deinit();
    var bib: [64]u8 = undefined;
    defer bc.finish(ctx, std.fmt.bufPrint(&bib, "all-batch/{d}", .{epoch}) catch unreachable) catch |e| ctx.fail("all-batch", "{s}", .{@errorName(e)});
    for (st.groups) |g| {
        if (st.lines[g[0]].epoch != epoch) continue;
        for (st.lines[g[0]..g[1]]) |l| {
            if (ctx.done()) return;
            ctx.nextItem();
            var ib: [64]u8 = undefined;
            const item = std.fmt.bufPrint(&ib, "all/{d}", .{l.seq}) catch unreachable;
            if (!ctx.selected(item)) continue;
            const a = ctx.scratch();
            const blob = try readBlob(ctx, l.seq);
            const v = try verify.full(a, blob, &idx, &comm, null);
            try bc.add(item, &comm, blob, &idx);
            var c = ctx.check(item);
            c.eql("accepted", std.mem.eql(u8, l.verify, "ok"), v.isOk());
            if (!std.mem.eql(u8, verify.class(v), l.verify)) c.failf("zui verdict {s}, truth {s}", .{ verify.class(v), l.verify });
            if (v.isOk()) {
                const r = try verify.check(a, blob, &idx);
                const ck = r.ok;
                c.digestHex("digest", l.digest, &ck.digest);
                c.eql("txs", l.txs, @as(u64, ck.txs.len));
                c.eql("puts", l.puts, @as(u64, ck.puts));
                c.eql("removes", l.removes, @as(u64, ck.removes));
                c.digestHex("plan", l.plan, &planHash(&ck));
            }
            _ = c.finish();
        }
    }
}

// ------------------------------------------------------------------------------------------------
// windows

const CpLine = struct { seq: u64, epoch: u64, digest: []const u8, txs: u64, puts: u64, removes: u64, plan: []const u8, verify: []const u8 };
const StateLine = struct { id: []const u8, v: u64, d: ?[]const u8 = null, rm: ?u8 = null };
const Mutant = struct { seq: u64, mutation: []const u8, flips: []const [2]u64, prev: []const u8, committee_epoch: ?u64 = null, expect: []const u8, class: []const u8 };

const Seen = struct { seq: u64, digest: [32]u8, plan: [32]u8, txs: u64, puts: u64, removes: u64 };

const Collect = struct {
    gpa: std.mem.Allocator,
    seen: std.ArrayList(Seen) = .empty,
    oom: bool = false,

    fn on(ctx: *anyopaque, seq: u64, c: *const verify.Checked, blob: []const u8) void {
        _ = blob;
        const self: *Collect = @ptrCast(@alignCast(ctx));
        self.seen.append(self.gpa, .{ .seq = seq, .digest = c.digest, .plan = planHash(c), .txs = c.txs.len, .puts = c.puts, .removes = c.removes }) catch {
            self.oom = true;
        };
    }
};

fn lessPut(_: void, a: verify.Put, b: verify.Put) bool {
    return std.mem.order(u8, a.id, b.id) == .lt;
}
fn lessRm(_: void, a: verify.Remove, b: verify.Remove) bool {
    return std.mem.order(u8, &a.id, &b.id) == .lt;
}

/// The plan hash of tools/truth/state-sync (CONTRACTS.md 6.5.1): puts and removes sorted by id.
fn planHash(c: *const verify.Checked) [32]u8 {
    var h = hash.Blake2b256.init();
    var scratch_puts: [4096]verify.Put = undefined;
    var scratch_rm: [4096]verify.Remove = undefined;
    for (c.txs) |t| {
        h.update(t.tx_digest);
        h.update(&t.effects_digest);
        var puts: []verify.Put = undefined;
        var heap_p: ?[]verify.Put = null;
        defer if (heap_p) |hp| std.heap.page_allocator.free(hp);
        if (t.puts.len <= scratch_puts.len) {
            puts = scratch_puts[0..t.puts.len];
        } else {
            heap_p = std.heap.page_allocator.alloc(verify.Put, t.puts.len) catch @panic("oom");
            puts = heap_p.?;
        }
        @memcpy(puts, t.puts);
        std.mem.sort(verify.Put, puts, {}, lessPut);
        var rms: []verify.Remove = undefined;
        var heap_r: ?[]verify.Remove = null;
        defer if (heap_r) |hr| std.heap.page_allocator.free(hr);
        if (t.removes.len <= scratch_rm.len) {
            rms = scratch_rm[0..t.removes.len];
        } else {
            heap_r = std.heap.page_allocator.alloc(verify.Remove, t.removes.len) catch @panic("oom");
            rms = heap_r.?;
        }
        @memcpy(rms, t.removes);
        std.mem.sort(verify.Remove, rms, {}, lessRm);
        var u32b: [4]u8 = undefined;
        std.mem.writeInt(u32, &u32b, @intCast(puts.len), .little);
        h.update(&u32b);
        for (puts) |p| {
            h.update(p.id);
            var v8: [8]u8 = undefined;
            std.mem.writeInt(u64, &v8, p.version, .little);
            h.update(&v8);
            h.update(&p.digest);
        }
        std.mem.writeInt(u32, &u32b, @intCast(rms.len), .little);
        h.update(&u32b);
        for (rms) |r| {
            h.update(&r.id);
            var v8: [8]u8 = undefined;
            std.mem.writeInt(u64, &v8, r.version, .little);
            h.update(&v8);
            h.update(&.{r.kind});
        }
    }
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

pub const window_store_cfg: store.Config = .{
    .retention_epochs = 2,
    .max_live_objects = 1 << 16,
    .max_object_versions = 1 << 20,
    .max_transactions = 1 << 19,
    .max_checkpoints = 1 << 14,
    .max_batch_bytes = 256 << 20,
    .max_batch_objects = 1 << 18,
    .max_segments = 4096,
    .index_flush_interval = 8192,
    .segment_reserve = 8 << 30,
    .seed = 0x7a75692d73796e63,
};

fn window(ctx: *harness.Ctx, cache: *CommitteeCache, prefix: []const u8) !void {
    const gpa = ctx.gpa;
    var nb: [256]u8 = undefined;
    const cp_text = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.bufPrint(&nb, "{s}/{s}.cp.jsonl", .{ vec_dir, prefix }), gpa, .limited(1 << 30));
    defer gpa.free(cp_text);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var lines: std.ArrayList(CpLine) = .empty;
    var it = std.mem.splitScalar(u8, cp_text, '\n');
    while (it.next()) |l| {
        if (l.len == 0) continue;
        try lines.append(a, try std.json.parseFromSliceLeaky(CpLine, a, l, .{ .ignore_unknown_fields = true }));
    }
    if (lines.items.len == 0) return;
    const first = lines.items[0];
    const last = lines.items[lines.items.len - 1];

    // Store.
    const dir = try std.fmt.allocPrint(gpa, "{s}/sessions/state-sync/{s}-store", .{ ctx.corpus_path, prefix });
    defer gpa.free(dir);
    std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, dir) catch {};
    var cfg = window_store_cfg;
    cfg.dir = dir;
    var h = try store.openDir(gpa, ctx.io, &cfg, .{ .sync = .none });
    defer {
        h.store.deinit();
        h.io.deinit();
    }

    const chk_path = try std.fmt.allocPrint(gpa, "{s}/chk", .{ctx.corpus_path});
    defer gpa.free(chk_path);
    var arch = try archive.Archive.open(ctx.io, chk_path);
    defer arch.close(ctx.io);

    const anchor_committee = try cache.get(ctx, first.epoch);
    var col: Collect = .{ .gpa = gpa };
    defer col.seen.deinit(gpa);
    var f = try follower.Follower.init(gpa, ctx.io, h.store, .{ .archive = &arch }, .{ .cert_batch = certBatchEnv() }, .{ .committee = anchor_committee.*, .first_seq = first.seq });
    defer f.deinit();
    f.observer = .{ .ctx = &col, .on_checkpoint = Collect.on };
    const t0 = follower.now();
    var failed_run: ?anyerror = null;
    f.run(last.seq) catch |e| {
        failed_run = e;
    };
    const dt = follower.now() - t0;
    {
        try ctx.stderr.print("sync-follow {s}: {d} checkpoints, {d} txs in {d} ms with {d} workers (read {d} ms, index {d} ms, check {d} ms, cert {d} ms, apply {d} ms, commit {d} ms; ordered stall {d} ms)\n", .{
            prefix,
            f.metrics.checkpoints.load(.monotonic),
            f.metrics.transactions.load(.monotonic),
            dt / 1_000_000,
            f.cfg.workers,
            f.metrics.read_ns.load(.monotonic) / 1_000_000,
            f.metrics.index_ns.load(.monotonic) / 1_000_000,
            f.metrics.check_ns.load(.monotonic) / 1_000_000,
            f.metrics.cert_ns.load(.monotonic) / 1_000_000,
            f.metrics.apply_ns.load(.monotonic) / 1_000_000,
            f.metrics.commit_ns.load(.monotonic) / 1_000_000,
            f.metrics.stall_ns.load(.monotonic) / 1_000_000,
        });
    }
    if (failed_run) |e| {
        if (f.failure) |fl| {
            var ib: [96]u8 = undefined;
            ctx.fail(std.fmt.bufPrint(&ib, "{s}/run", .{prefix}) catch "run", "rejected checkpoint {d}: {s}", .{ fl.seq, verify.class(fl.verdict) });
        } else {
            ctx.fail("run", "follower error {s}", .{@errorName(e)});
        }
    }

    // Per-checkpoint items.
    var si: usize = 0;
    for (lines.items) |l| {
        if (ctx.done()) return;
        var ib: [96]u8 = undefined;
        const item = std.fmt.bufPrint(&ib, "{s}/cp/{d}", .{ prefix, l.seq }) catch unreachable;
        if (!ctx.selected(item)) {
            continue;
        }
        var c = ctx.check(item);
        if (si < col.seen.items.len and col.seen.items[si].seq == l.seq) {
            const s = col.seen.items[si];
            si += 1;
            c.eql("verdict", true, std.mem.eql(u8, l.verify, "ok"));
            c.digestHex("digest", l.digest, &s.digest);
            c.eql("txs", l.txs, s.txs);
            c.eql("puts", l.puts, s.puts);
            c.eql("removes", l.removes, s.removes);
            c.digestHex("plan", l.plan, &s.plan);
        } else c.failf("checkpoint not applied", .{});
        _ = c.finish();
    }

    // State.
    {
        const st_text = try ctx.corpus.readFileAlloc(ctx.io, try std.fmt.bufPrint(&nb, "{s}/{s}.state.jsonl", .{ vec_dir, prefix }), gpa, .limited(1 << 31));
        defer gpa.free(st_text);
        var snap = h.store.snapshot();
        defer snap.release();
        var live_truth: u64 = 0;
        var lit = std.mem.splitScalar(u8, st_text, '\n');
        var sa = std.heap.ArenaAllocator.init(gpa);
        defer sa.deinit();
        while (lit.next()) |l| {
            if (l.len == 0) continue;
            _ = sa.reset(.retain_capacity);
            const s = try std.json.parseFromSliceLeaky(StateLine, sa.allocator(), l, .{ .ignore_unknown_fields = true });
            if (s.d != null) live_truth += 1;
            var ib: [160]u8 = undefined;
            const item = std.fmt.bufPrint(&ib, "{s}/state/{s}", .{ prefix, s.id }) catch unreachable;
            if (!ctx.selected(item) or ctx.done()) continue;
            var c = ctx.check(item);
            var id: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&id, s.id);
            const got = snap.latest(&id) catch |e| blk: {
                c.failf("latest: {s}", .{@errorName(e)});
                break :blk null;
            };
            if (got) |g| switch (g) {
                .live => |o| {
                    if (s.d) |dhex| {
                        c.eql("version", s.v, o.version);
                        c.digestHex("digest", dhex, &o.digest);
                        const real = verify.objectDigest(o.bytes);
                        c.digestHex("bytes digest", dhex, &real);
                    } else c.failf("live but truth says removed {d}", .{s.rm.?});
                },
                .removed => |r| {
                    if (s.rm) |k| {
                        c.eql("version", s.v, r.version);
                        // wrapped is kind 1; deleted and unwrapped_then_deleted are stored as deleted
                        c.eql("kind", k == 1, r.kind == .wrapped);
                    } else c.failf("removed but truth says live v{d}", .{s.v});
                },
            } else c.failf("object absent", .{});
            _ = c.finish();
        }
        if (ctx.selected("state-count")) {
            var ib: [96]u8 = undefined;
            const item = std.fmt.bufPrint(&ib, "{s}/state-count", .{prefix}) catch unreachable;
            var c = ctx.check(item);
            // the store knows exactly the truth's live objects (tombstones are not live)
            c.eql("live objects", live_truth, h.store.liveCount());
            _ = c.finish();
        }
    }

    try mutants(ctx, cache, prefix);
}

fn mutants(ctx: *harness.Ctx, cache: *CommitteeCache, prefix: []const u8) !void {
    var nb: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&nb, "{s}/{s}.mutants.jsonl", .{ vec_dir, prefix });
    const text = ctx.corpus.readFileAlloc(ctx.io, path, ctx.gpa, .limited(1 << 28)) catch return;
    defer ctx.gpa.free(text);
    var idx = try types.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    var bc = BatchCmp.init(ctx.gpa);
    defer bc.deinit();
    var bib: [128]u8 = undefined;
    defer bc.finish(ctx, std.fmt.bufPrint(&bib, "{s}/mutant-batch", .{prefix}) catch unreachable) catch |e| ctx.fail("mutant-batch", "{s}", .{@errorName(e)});
    var it = std.mem.splitScalar(u8, text, '\n');
    var n: u64 = 0;
    while (it.next()) |l| {
        if (l.len == 0) continue;
        if (ctx.done()) return;
        ctx.nextItem();
        const a = ctx.scratch();
        const m = try std.json.parseFromSliceLeaky(Mutant, a, l, .{ .ignore_unknown_fields = true });
        n += 1;
        var ib: [128]u8 = undefined;
        const item = std.fmt.bufPrint(&ib, "{s}/mutant/{d}/{d}-{s}", .{ prefix, n, m.seq, m.mutation }) catch unreachable;
        if (!ctx.selected(item)) continue;
        const orig = try readBlob(ctx, m.seq);
        const blob = try a.dupe(u8, orig);
        for (m.flips) |fl| blob[@intCast(fl[0])] ^= @intCast(fl[1]);
        const epoch = std.mem.readInt(u64, orig[1..9], .little); // the truth tool picks the committee from the unmutated blob
        const comm = try cache.get(ctx, m.committee_epoch orelse epoch);
        var prev: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&prev, m.prev);
        // The epoch-mismatch classes depend on the committee passed, as in the truth tool.
        const v = try verify.full(a, blob, &idx, comm, prev);
        try bc.add(item, comm, blob, &idx);
        const got = verify.class(v);
        var c = ctx.check(item);
        c.eql("accepted", std.mem.eql(u8, m.expect, "ok"), v.isOk());
        const same = std.mem.eql(u8, got, m.class);
        if (!same) c.failf("class: truth {s}, zui {s}", .{ m.class, got });
        _ = c.finish();
    }
}

const Edge = struct { name: []const u8, committee_epoch: u64, prev: []const u8, expect: []const u8, class: []const u8 };

fn edges(ctx: *harness.Ctx, cache: *CommitteeCache) !void {
    const text = try ctx.corpus.readFileAlloc(ctx.io, vec_dir ++ "/edge/edge.jsonl", ctx.gpa, .limited(1 << 24));
    defer ctx.gpa.free(text);
    var idx = try types.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    var bc = BatchCmp.init(ctx.gpa);
    defer bc.deinit();
    defer bc.finish(ctx, "edge/cert-batch") catch |e| ctx.fail("edge/cert-batch", "{s}", .{@errorName(e)});
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |l| {
        if (l.len == 0) continue;
        if (ctx.done()) return;
        ctx.nextItem();
        const a = ctx.scratch();
        const e = try std.json.parseFromSliceLeaky(Edge, a, l, .{ .ignore_unknown_fields = true });
        var ib: [128]u8 = undefined;
        const item = std.fmt.bufPrint(&ib, "edge/{s}", .{e.name}) catch unreachable;
        if (!ctx.selected(item)) continue;
        var nb: [256]u8 = undefined;
        const blob = try ctx.readFile(try std.fmt.bufPrint(&nb, "{s}/edge/{s}.chk", .{ vec_dir, e.name }), 1 << 30);
        const comm = try cache.get(ctx, e.committee_epoch);
        var prev: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&prev, e.prev);
        const v = try verify.full(a, blob, &idx, comm, prev);
        try bc.add(item, comm, blob, &idx);
        var c = ctx.check(item);
        c.eql("accepted", std.mem.eql(u8, e.expect, "ok"), v.isOk());
        if (!std.mem.eql(u8, verify.class(v), e.class)) c.failf("class: truth {s}, zui {s}", .{ e.class, verify.class(v) });
        _ = c.finish();
    }
}

// ------------------------------------------------------------------------------------------------
// bench: the per-checkpoint work of apply mode, without certificate, I/O and store

const BenchState = struct { blobs: []const []const u8, arena: *std.heap.ArenaAllocator, idx: *types.CheckpointIndex, txs: u64 };

fn benchPass(st: *BenchState) !void {
    for (st.blobs) |b| {
        _ = st.arena.reset(.retain_capacity);
        try types.indexCheckpointData(b, st.idx);
        const r = try verify.check(st.arena.allocator(), b, st.idx);
        if (r != .ok) return error.BenchCheckFailed;
    }
}

fn bench(ctx: *harness.Ctx) !void {
    const inputs = ctx.benchInputs();
    var arena = std.heap.ArenaAllocator.init(ctx.gpa);
    defer arena.deinit();
    const blobs = try arena.allocator().alloc([]const u8, inputs.len);
    var txs: u64 = 0;
    var idx = try types.CheckpointIndex.init(ctx.gpa);
    defer idx.deinit(ctx.gpa);
    for (inputs, blobs) |p, *b| {
        b.* = try ctx.corpus.readFileAlloc(ctx.io, p, arena.allocator(), .limited(1 << 30));
        try types.indexCheckpointData(b.*, &idx);
        txs += idx.tx_count;
    }
    var scratch = std.heap.ArenaAllocator.init(ctx.gpa);
    defer scratch.deinit();
    var st: BenchState = .{ .blobs = blobs, .arena = &scratch, .idx = &idx, .txs = txs };
    try ctx.benchPasses("apply-check", "tx", txs, &st, struct {
        fn f(s: *BenchState) !void {
            try benchPass(s);
        }
    }.f);
}
