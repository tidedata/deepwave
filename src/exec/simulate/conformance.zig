//! `simulate-engine`: the native simulation API (api.zig) over the rpc-simulate records
//! (`$ZUI_CORPUS/vectors/rpc-simulate/<seq>.rec.zst`: each user transaction's pre-state and
//! sui-node's SimulateTransaction answers on it).
//!
//! Per request with a BCS transaction and no gas selection, the API runs the TransactionData
//! (checks on, or DevInspect when the request disables them) and:
//!   - sui-node parity: an executed result rendered with `grpcResponse` under the request's read
//!     mask equals sui-node's response bytes; a rejection has sui-node's gRPC code and message;
//!   - certified: when the request is the corpus transaction itself (checks on), the effects
//!     equal the certified effects of `chk/<seq>.chk` byte for byte (a transaction whose
//!     sui-node simulation also differs from its certified effects is counted, not failed).
//! The run covers every `stride`-th record (a few thousand transactions on the Mac); the bench
//! times the newest records (the chain tip as a node serves it): 1, 4 and 16 threads, and p50/p99
//! latency of DeepBook and Cetus swaps.
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const bcs = @import("bcs");
const exec = @import("exec");
const serve = @import("serve");
const rpc_exec = @import("rpc_exec");
const api = @import("api.zig");
const batch = @import("batch.zig");

const Allocator = std.mem.Allocator;
const rconf = rpc_exec.conformance;
const proto = serve.proto;

pub const suites = [_]harness.Suite{.{
    .name = "simulate-engine",
    .lane = "simulate",
    .doc = "native simulation API vs sui-node's SimulateTransaction answers (response bytes under the request's mask, or code and message) and vs the certified effects, over the rpc-simulate records",
    .run = run,
    .bench = bench,
    .inputs = .{ .dir = "vectors/rpc-simulate", .suffix = ".rec.zst" },
}};

const rec_dir = "vectors/rpc-simulate";
const max_rec: usize = 1 << 31;
/// Records the correctness run covers (evenly spaced over the corpus).
const run_files: usize = 240;
/// Newest records the bench loads.
const bench_files: usize = 160;

const Shared = struct {
    engine: api.Engine,
    chain_id: [32]u8,
    skips: exec.replay.SkipTally = .{},
    certified_eq: std.atomic.Value(u64) = .init(0),
    certified_rust_differs: std.atomic.Value(u64) = .init(0),
    parity: std.atomic.Value(u64) = .init(0),
};

fn setup(ctx: *harness.Ctx, arena: Allocator) !*Shared {
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const pkgs = try arena.create(exec.packages.Store);
    pkgs.* = try exec.packages.load(ctx, arena, last);
    const sh = try arena.create(Shared);
    sh.* = .{
        .engine = .{ .core = .{ .gpa = std.heap.smp_allocator, .pkgs = pkgs } },
        .chain_id = serve.b58.decode32(rconf.mainnet_chain_id_b58) orelse return error.InvalidChainId,
    };
    return sh;
}

/// The parts of a SimulateTransactionRequest the native API takes.
const Req = struct {
    tx_raw: []const u8,
    checks: bool,
    paths: []const []const u8,
    has_mask: bool,
};

fn parseRequest(arena: Allocator, body: []const u8) !?Req {
    var tx_msg: ?[]const u8 = null;
    var paths: std.ArrayList([]const u8) = .empty;
    var has_mask = false;
    var checks_v: u64 = 0;
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => tx_msg = try proto.Reader.bytesOf(f),
        2 => {
            has_mask = true;
            var mr = proto.Reader.init(try proto.Reader.bytesOf(f));
            while (try mr.next()) |mf| if (mf.number == 1) try paths.append(arena, try proto.Reader.stringOf(mf));
        },
        3 => checks_v = try proto.Reader.varintOf(f),
        4 => if (try proto.Reader.varintOf(f) != 0) return null, // gas selection: not an API input
        else => {},
    };
    var tr = proto.Reader.init(tx_msg orelse return null);
    var bcs_msg: ?[]const u8 = null;
    while (try tr.next()) |f| if (f.number == 1) {
        bcs_msg = try proto.Reader.bytesOf(f);
    };
    var br = proto.Reader.init(bcs_msg orelse return null);
    var raw: ?[]const u8 = null;
    while (try br.next()) |f| if (f.number == 2) {
        raw = try proto.Reader.bytesOf(f);
    };
    // read-mask validation is the gRPC request layer's (rpc_exec.simulate), not the engine's
    if (has_mask and serve.status.invalidPath(serve.schema.index("SimulateTransactionResponse"), paths.items) != null) return null;
    for (paths.items) |p| if (std.mem.startsWith(u8, p, "command_outputs") or std.mem.startsWith(u8, p, "suggested_gas_price")) return null;
    return .{ .tx_raw = raw orelse return null, .checks = checks_v != 1, .paths = paths.items, .has_mask = has_mask };
}

fn run(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sh = try setup(ctx, arena);
    const names = try ctx.listFiles(rec_dir, ".rec.zst");
    defer ctx.freeNames(names);
    const stride = @max(1, names.len / run_files);
    var picked: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < names.len) : (i += stride) try picked.append(arena, names[i]);
    try ctx.forEachName(picked.items, sh, runFile);
    const vs = api.verifiedStats();
    ctx.stderr.print("simulate-engine: {d} records; sui-node parity {d}; certified effects equal {d} (sui-node's own simulation differs from certified: {d}); verifier shared: {d} packages, {d} loads skipped it, {d} ran it\n", .{ picked.items.len, sh.parity.load(.monotonic), sh.certified_eq.load(.monotonic), sh.certified_rust_differs.load(.monotonic), vs.packages, vs.hits, vs.misses }) catch {};
    sh.skips.print(ctx.stderr);
    ctx.stderr.flush() catch {};
}

/// The certified (transaction data, effects) of each transaction of checkpoint `seq`.
fn certified(ctx: *harness.Ctx, arena: Allocator, seq: []const u8) !?[]const [2][]const u8 {
    const blob = ctx.corpus.readFileAlloc(ctx.io, try std.fmt.allocPrint(arena, "chk/{s}.chk", .{seq}), arena, .limited(1 << 30)) catch return null;
    var idx = try types.CheckpointIndex.init(std.heap.page_allocator);
    defer idx.deinit(std.heap.page_allocator);
    types.indexCheckpointData(blob, &idx) catch return null;
    const out = try arena.alloc([2][]const u8, idx.tx_count);
    for (out, 0..) |*o, k| {
        const t = idx.txAt(k);
        o.* = .{ t.data.slice(blob), t.effects.slice(blob) };
    }
    return out;
}

fn runFile(sh: *Shared, ctx: *harness.Ctx, name: []const u8) !void {
    const seq = name[0 .. name.len - ".rec.zst".len];
    const data = ctx.readZstd(try std.fmt.allocPrint(ctx.scratch(), "{s}/{s}", .{ rec_dir, name }), max_rec) catch |e| {
        ctx.fail(seq, "read: {s}", .{@errorName(e)});
        return;
    };
    const blocks = rconf.parseRecord(ctx.scratch(), data) catch |e| {
        ctx.fail(seq, "record: {s}", .{@errorName(e)});
        return;
    };
    const cert = try certified(ctx, ctx.scratch(), seq);
    var tx_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer tx_arena.deinit();
    for (blocks) |*b| {
        _ = tx_arena.reset(.retain_capacity);
        const a = tx_arena.allocator();
        const ms = try rconf.mapState(a, b.objects);
        const env = rconf.envOf(sh.chain_id, b) catch continue;
        for (b.cases) |*k| {
            const id = try std.fmt.allocPrint(a, "{s}/{d}/{d}", .{ seq, b.tx_index, k.case });
            if (!ctx.selected(id)) continue;
            const req = (parseRequest(a, k.request) catch null) orelse continue;
            const r = try sh.engine.simulateAt(a, &env, ms.state(), .{ .tx = .{ .data = req.tx_raw }, .mode = if (req.checks) .simulate else .dev_inspect });
            switch (r) {
                .rejected => |rj| {
                    if (rj.code == 12 and k.code != 12) {
                        sh.skips.add(ctx.io, rj.message);
                        ctx.skip(id, rj.message);
                        continue;
                    }
                    if (rj.code != k.code or !std.mem.eql(u8, rj.message, k.message)) {
                        ctx.fail(id, "rejected: zui code {d} \"{s}\", sui-node code {d} \"{s}\"", .{ rj.code, rj.message, k.code, k.message });
                        continue;
                    }
                },
                .executed => |x| {
                    if (k.code != 0) {
                        ctx.fail(id, "zui executed ({s}), sui-node code {d} \"{s}\"", .{ @tagName(x.status), k.code, k.message });
                        continue;
                    }
                    const mask = if (req.has_mask) try std.mem.join(a, ",", req.paths) else "*";
                    const resp = api.grpcResponse(&sh.engine, a, &env, &x, mask) catch |e| switch (e) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {
                            ctx.skip(id, "render unimplemented");
                            continue;
                        },
                    };
                    if (!std.mem.eql(u8, resp, k.response)) {
                        ctx.fail(id, "response differs from sui-node's (zui {d} bytes, sui-node {d})", .{ resp.len, k.response.len });
                        continue;
                    }
                    _ = sh.parity.fetchAdd(1, .monotonic);
                    if (req.checks) if (cert) |cs| if (b.tx_index < cs.len and std.mem.eql(u8, cs[b.tx_index][0], req.tx_raw)) {
                        const want = cs[b.tx_index][1];
                        if (std.mem.eql(u8, x.effects, want)) {
                            _ = sh.certified_eq.fetchAdd(1, .monotonic);
                        } else if (std.mem.indexOf(u8, k.response, want) == null) {
                            _ = sh.certified_rust_differs.fetchAdd(1, .monotonic);
                        } else {
                            ctx.fail(id, "effects differ from certified: {s}", .{exec.replay.effectsDiff(a, x.effects, want)});
                            continue;
                        }
                    };
                },
            }
            ctx.pass(id);
        }
    }
    try chainItems(sh, ctx, seq, blocks);
}

/// `chain/<seq>`: the record's first transaction run twice as a chained simulation. Step 2 must
/// read step 1's outputs (its owned inputs rebased to step 1's versions). `override/<seq>`: the
/// same transaction with a gas budget and Clock override; the budget must be what ran.
fn chainItems(sh: *Shared, ctx: *harness.Ctx, seq: []const u8, blocks: []const rconf.Block) !void {
    var tx_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer tx_arena.deinit();
    const a = tx_arena.allocator();
    for (blocks) |*b| for (b.cases) |*k| {
        if (k.code != 0) continue;
        const req = (parseRequest(a, k.request) catch null) orelse continue;
        if (!req.checks) continue;
        const env = rconf.envOf(sh.chain_id, b) catch continue;
        const ms = try rconf.mapState(a, b.objects);
        const one: api.Request = .{ .tx = .{ .data = req.tx_raw } };
        const cid = try std.fmt.allocPrint(a, "chain/{s}", .{seq});
        if (ctx.selected(cid)) {
            const rs = try sh.engine.simulateChainAt(a, &env, ms.state(), &.{ one, one });
            if (rs[0] != .executed) {
                ctx.skip(cid, "step 1 not executed");
            } else switch (rs[1]) {
                .rejected => |rj| if (rj.code == 12) ctx.skip(cid, rj.message) else {
                    // a rejection caused by step 1 (it moved, spent or deleted an input) names that object
                    const caused = for (rs[0].executed.object_changes) |c| {
                        if (std.mem.indexOf(u8, rj.message, try std.fmt.allocPrint(a, "0x{x}", .{&c.id})) != null) break true;
                    } else false;
                    if (caused) ctx.pass(cid) else ctx.fail(cid, "step 2 rejected: {d} {s}", .{ rj.code, rj.message });
                },
                .executed => |x2| {
                    // every object step 1 wrote and step 2 took as an owned input is at step 1's version
                    var bad: ?[32]u8 = null;
                    for (rs[0].executed.written) |w| {
                        const v1 = (exec.objects.ObjectView.parse(w.bytes) catch continue).version;
                        for (x2.object_changes) |c| if (std.mem.eql(u8, &c.id, &w.id)) if (c.previous) |p| {
                            const pv = (exec.objects.ObjectView.parse(p) catch continue).version;
                            if (pv != v1) bad = w.id;
                        };
                    }
                    if (bad) |id| ctx.fail(cid, "step 2 read {x} at a version step 1 did not write", .{&id}) else ctx.pass(cid);
                },
            }
        }
        const oid = try std.fmt.allocPrint(a, "override/{s}", .{seq});
        if (ctx.selected(oid)) {
            var o = one;
            o.overrides = .{ .gas_budget = 2_000_000_000, .clock_ms = 1_900_000_000_000 };
            switch (try sh.engine.simulateAt(a, &env, ms.state(), o)) {
                .executed => |x| if (x.gas.budget != 2_000_000_000) ctx.fail(oid, "budget {d} ran", .{x.gas.budget}) else ctx.pass(oid),
                .rejected => |rj| if (rj.code == 12) ctx.skip(oid, rj.message) else ctx.pass(oid), // a budget the coin cannot cover is a valid answer
            }
        }
        const bid = try std.fmt.allocPrint(a, "batch/{s}", .{seq});
        if (ctx.selected(bid)) {
            // the same jobs sequentially and through a 4-worker pool (core.io is null here: no random nonce)
            const jobs = [_]batch.Job{ &.{one}, &.{ one, one }, &.{one}, &.{ one, one }, &.{one}, &.{one} };
            var pool: batch.Pool = undefined;
            try pool.init(std.heap.smp_allocator, ctx.io, .{ .workers = 4, .on_exit = api.releaseThreadCaches });
            defer pool.deinit();
            var bt = try pool.runAt(&sh.engine, &env, ms.state(), &jobs);
            defer bt.deinit();
            var diffs: usize = 0;
            for (jobs, 0..) |j, i| {
                const want = try sh.engine.simulateChainAt(a, &env, ms.state(), j);
                if (bt.results[i].len != want.len) diffs += 1 else for (want, bt.results[i]) |w, g| {
                    if (!batch.sameResult(w, g)) diffs += 1;
                }
            }
            if (diffs == 0) ctx.pass(bid) else ctx.fail(bid, "{d} batch answers differ from sequential", .{diffs});
        }
        return;
    };
}

// ---- bench ----------------------------------------------------------------------------------

const Item = struct {
    env: rpc_exec.EpochEnv,
    state: rpc_exec.state.MapState,
    tx_raw: []const u8,
    swap: ?[]const u8 = null,
};

/// "deepbook" / "cetus" for a PTB that calls a swap on one of them (by module and function, so
/// every package upgrade counts).
fn swapKind(arena: Allocator, raw: []const u8) ?[]const u8 {
    const td = bcs.decode(types.TransactionData, arena, raw) catch return null;
    const pt = switch (td.V1.kind) {
        .ProgrammableTransaction => |p| p,
        else => return null,
    };
    for (pt.commands) |c| switch (c) {
        .MoveCall => |m| {
            const f = m.function.@"0";
            const mod = m.module.@"0";
            if (std.mem.indexOf(u8, f, "swap") == null) continue;
            if (std.mem.eql(u8, mod, "pool") and std.mem.startsWith(u8, f, "swap_exact_")) return "deepbook";
            if (std.mem.startsWith(u8, mod, "pool_script") or std.mem.eql(u8, mod, "router")) return "cetus";
        },
        else => {},
    };
    return null;
}

const Bench = struct {
    sh: *Shared,
    items: []const Item,
    next: std.atomic.Value(usize) = .init(0),
    total: usize = 0,
    ready: std.atomic.Value(usize) = .init(0),
    go: std.atomic.Value(bool) = .init(false),
    done_ok: std.atomic.Value(u64) = .init(0),
};

fn simOnce(sh: *Shared, a: Allocator, it: *const Item) !bool {
    const r = try sh.engine.simulateAt(a, &it.env, it.state.state(), .{ .tx = .{ .data = it.tx_raw } });
    return r == .executed;
}

fn worker(b: *Bench) void {
    defer api.releaseThreadCaches();
    var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer a.deinit();
    // warm this worker's package cache (as a long-lived node worker is)
    for (b.items) |*it| {
        _ = a.reset(.retain_capacity);
        _ = simOnce(b.sh, a.allocator(), it) catch {};
    }
    _ = b.ready.fetchAdd(1, .acq_rel);
    while (!b.go.load(.acquire)) std.atomic.spinLoopHint();
    var ok: u64 = 0;
    while (true) {
        const i = b.next.fetchAdd(1, .monotonic);
        if (i >= b.total) break;
        _ = a.reset(.retain_capacity);
        if (simOnce(b.sh, a.allocator(), &b.items[i % b.items.len]) catch false) ok += 1;
    }
    _ = b.done_ok.fetchAdd(ok, .monotonic);
}

fn nowNs(io: std.Io) i96 {
    return std.Io.Timestamp.now(io, .awake).nanoseconds;
}

fn bench(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sh = try setup(ctx, arena);
    const names = try ctx.listFiles(rec_dir, ".rec.zst");
    defer ctx.freeNames(names);
    var items: std.ArrayList(Item) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var n_cases: usize = 0;
    var n_parsed: usize = 0;
    var n_env: usize = 0;
    for (names[names.len -| bench_files..]) |name| {
        const data = try ctx.readZstd(try std.fmt.allocPrint(arena, "{s}/{s}", .{ rec_dir, name }), max_rec);
        const owned = try arena.dupe(u8, data);
        const blocks = try rconf.parseRecord(arena, owned);
        for (blocks) |*b| for (b.cases) |k| {
            n_cases += 1;
            if (k.code != 0) continue;
            const req = (parseRequest(arena, k.request) catch null) orelse continue;
            n_parsed += 1;
            if (!req.checks) continue;
            const env = rconf.envOf(sh.chain_id, b) catch continue;
            n_env += 1;
            if (seen.contains(req.tx_raw)) continue;
            try seen.put(arena, req.tx_raw, {});
            try items.append(arena, .{ .env = env, .state = try rconf.mapState(arena, b.objects), .tx_raw = req.tx_raw, .swap = swapKind(arena, req.tx_raw) });
        };
        _ = ctx.arena.reset(.retain_capacity);
    }
    var e_lo: u64 = std.math.maxInt(u64);
    var e_hi: u64 = 0;
    for (items.items) |it| {
        e_lo = @min(e_lo, it.env.epoch);
        e_hi = @max(e_hi, it.env.epoch);
    }
    ctx.stderr.print("simulate-engine bench: {d} transactions from the newest {d} records (epochs {d}..{d}; {d} cases, {d} API requests, {d} with a known protocol)\n", .{ items.items.len, bench_files, e_lo, e_hi, n_cases, n_parsed, n_env }) catch {};

    // ---- latency: one warm thread, each swap run `reps` times; also every item once
    {
        var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer a.deinit();
        for (items.items) |*it| {
            _ = a.reset(.retain_capacity);
            _ = simOnce(sh, a.allocator(), it) catch {};
        }
        const reps = 30;
        inline for (.{ "deepbook", "cetus", "all" }) |label| {
            var lat: std.ArrayList(u64) = .empty;
            for (items.items) |*it| {
                const want = std.mem.eql(u8, label, "all") or (it.swap != null and std.mem.eql(u8, it.swap.?, label));
                if (!want) continue;
                const n: usize = if (std.mem.eql(u8, label, "all")) 1 else reps;
                for (0..n) |_| {
                    _ = a.reset(.retain_capacity);
                    const t0 = nowNs(ctx.io);
                    _ = simOnce(sh, a.allocator(), it) catch {};
                    try lat.append(arena, @intCast(nowNs(ctx.io) - t0));
                }
            }
            if (lat.items.len > 0) {
                std.mem.sort(u64, lat.items, {}, std.sort.asc(u64));
                const p50 = lat.items[lat.items.len / 2];
                const p99 = lat.items[@min(lat.items.len - 1, lat.items.len * 99 / 100)];
                ctx.stderr.print("  latency {s}: {d} runs, p50 {d} us, p99 {d} us\n", .{ label, lat.items.len, p50 / 1000, p99 / 1000 }) catch {};
            }
        }
        // the same, rendered to sui-node's response bytes (what gRPC answers)
        var lat: std.ArrayList(u64) = .empty;
        for (items.items) |*it| {
            _ = a.reset(.retain_capacity);
            const t0 = nowNs(ctx.io);
            const r = try sh.engine.simulateAt(a.allocator(), &it.env, it.state.state(), .{ .tx = .{ .data = it.tx_raw } });
            if (r == .executed) _ = api.grpcResponse(&sh.engine, a.allocator(), &it.env, &r.executed, "*") catch {};
            try lat.append(arena, @intCast(nowNs(ctx.io) - t0));
        }
        if (lat.items.len > 0) {
            var sum: u64 = 0;
            for (lat.items) |l| sum += l;
            std.mem.sort(u64, lat.items, {}, std.sort.asc(u64));
            ctx.stderr.print("  with gRPC render: mean {d} us/tx, p50 {d} us, p99 {d} us\n", .{ sum / lat.items.len / 1000, lat.items[lat.items.len / 2] / 1000, lat.items[@min(lat.items.len - 1, lat.items.len * 99 / 100)] / 1000 }) catch {};
        }
    }

    // ---- throughput: T workers, each warmed, then a shared queue of passes over the items
    const passes = @max(1, ctx.opts.iters);
    // ZUI_SIM_THREADS="1,2,4" picks the thread counts (default 1,4,16)
    var nts_buf: [8]usize = .{ 1, 4, 16, 0, 0, 0, 0, 0 };
    var nts: []const usize = nts_buf[0..3];
    if (std.c.getenv("ZUI_SIM_THREADS")) |v| {
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, std.mem.span(v), ',');
        while (it.next()) |x| if (n < nts_buf.len) {
            nts_buf[n] = std.fmt.parseInt(usize, x, 10) catch continue;
            if (nts_buf[n] > 0) n += 1;
        };
        if (n > 0) nts = nts_buf[0..n];
    }
    for (nts) |nt| {
        var b: Bench = .{ .sh = sh, .items = items.items, .total = items.items.len * passes * @max(1, nt / 2) };
        const threads = try arena.alloc(std.Thread, nt);
        for (threads) |*t| t.* = try std.Thread.spawn(.{}, worker, .{&b});
        while (b.ready.load(.acquire) < nt) std.atomic.spinLoopHint();
        const t0 = nowNs(ctx.io);
        b.go.store(true, .release);
        for (threads) |t| t.join();
        const dt: u64 = @intCast(nowNs(ctx.io) - t0);
        const per_s = @as(f64, @floatFromInt(b.total)) * 1e9 / @as(f64, @floatFromInt(dt));
        ctx.stderr.print("  throughput {d} threads: {d} simulations in {d} ms = {d:.0} sims/s ({d} executed)\n", .{ nt, b.total, dt / 1_000_000, per_s, b.done_ok.load(.monotonic) }) catch {};
        ctx.benchRecord(try std.fmt.allocPrint(arena, "simulate-{d}t", .{nt}), "tx", b.total, dt * nt);
    }
    // ---- batch.Pool: each item as one batch of `per` independent copies at its own pre-state,
    // W pool workers; every batch answer is checked against the sequential answer of that item
    const per = 8;
    for (nts) |w| {
        var pool: batch.Pool = undefined;
        try pool.init(std.heap.smp_allocator, ctx.io, .{ .workers = w, .on_exit = api.releaseThreadCaches });
        defer pool.deinit();
        var diffs: usize = 0;
        var executed: usize = 0;
        var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
        defer a.deinit();
        // warm pass (fills every worker's package cache), compared with the sequential answer
        for (items.items) |*it| {
            _ = a.reset(.retain_capacity);
            const one = [_]api.Request{.{ .tx = .{ .data = it.tx_raw } }};
            const jobs: [per]batch.Job = @splat(&one);
            var bt = try pool.runAt(&sh.engine, &it.env, it.state.state(), &jobs);
            defer bt.deinit();
            const want = try sh.engine.simulateAt(a.allocator(), &it.env, it.state.state(), one[0]);
            for (0..per) |i| {
                if (!batch.sameResult(want, bt.one(i))) diffs += 1;
                if (bt.one(i) == .executed) executed += 1;
            }
        }
        const t0 = nowNs(ctx.io);
        for (0..passes) |_| for (items.items) |*it| {
            const one = [_]api.Request{.{ .tx = .{ .data = it.tx_raw } }};
            const jobs: [per]batch.Job = @splat(&one);
            var bt = try pool.runAt(&sh.engine, &it.env, it.state.state(), &jobs);
            bt.deinit();
        };
        const dt: u64 = @intCast(nowNs(ctx.io) - t0);
        const total = items.items.len * passes * per;
        const per_s = @as(f64, @floatFromInt(total)) * 1e9 / @as(f64, @floatFromInt(dt));
        ctx.stderr.print("  batch.Pool {d} workers: {d} batches of {d} = {d} simulations in {d} ms = {d:.0} sims/s; warm pass vs sequential: {d} diffs, {d} executed of {d}\n", .{ w, items.items.len * passes, per, total, dt / 1_000_000, per_s, diffs, executed, items.items.len * per }) catch {};
        ctx.benchRecord(try std.fmt.allocPrint(arena, "batch-pool-{d}w", .{w}), "tx", total, dt * w);
    }
    const vs = api.verifiedStats();
    ctx.stderr.print("  verifier shared: {d} packages verified once, {d} loads skipped the verifier, {d} ran it\n", .{ vs.packages, vs.hits, vs.misses }) catch {};
    ctx.stderr.flush() catch {};
}
