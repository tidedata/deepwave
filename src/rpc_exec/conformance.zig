//! `rpc-simulate`: for every record in `$ZUI_CORPUS/vectors/rpc-simulate/<seq>.rec.zst` (made by
//! `tools/truth/rpc-exec gen`: Mysten's sui-rpc-api SimulateTransaction handler over
//! sui-core's `transaction_simulation::simulate_transaction`, run on the pre-state each corpus
//! user transaction read), deepwave's `simulate.Engine` answers the same request over the same
//! pre-state; the gRPC code, the message, `grpc-status-details-bin` and the response bytes must
//! be equal. A request deepwave does not model yet (UNIMPLEMENTED: an executor skip, a resolution
//! shape) counts as a skip. Gas-selection cases (5-7) read `MapState`'s owner index over the
//! same pre-state objects the truth tool's `RpcIndexes` lists.
const std = @import("std");
const harness = @import("harness");
const protocol = @import("protocol");
/// The corpus these suites replay ($ZUI_CORPUS) is mainnet history.
const corpus_chain: protocol.Chain = .mainnet;
const exec = @import("exec");
const serve = @import("serve");

const root = @import("root.zig");
const state_mod = @import("state.zig");
const simulate = @import("simulate.zig");

const Allocator = std.mem.Allocator;
const ObjectView = exec.objects.ObjectView;

pub const suites = [_]harness.Suite{
    .{
        .name = "rpc-simulate",
        .lane = "rpc-exec",
        .doc = "SimulateTransaction (code, message, status details, response bytes) vs Mysten's sui-rpc-api handler + transaction_simulation over each user transaction's pre-state",
        .run = run,
        .bench = bench,
        .baselines = &.{.{ .name = "simulate", .argv = &.{ "{release}/zui-truth-rpc-exec", "bench", "simulate" } }},
        .inputs = .{ .dir = "vectors/rpc-simulate", .suffix = ".rec.zst" },
    },
    .{
        .name = "rpc-execute",
        .lane = "rpc-exec",
        .doc = driver_conformance.doc,
        .run = driver_conformance.run,
    },
};
const driver_conformance = @import("driver/root.zig").conformance;

const rec_dir = "vectors/rpc-simulate";
const max_rec: usize = 1 << 31;

/// Mainnet's chain identifier (the digest of checkpoint 0).
pub const mainnet_chain_id_b58 = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S";

pub const SkipTally = exec.replay.SkipTally;

const Shared = struct {
    engine: simulate.Engine,
    chain_id: [32]u8,
    skips: SkipTally = .{},
    per_case: [256]Counts = @splat(.{}),

    const Counts = struct {
        pass: std.atomic.Value(u64) = .init(0),
        fail: std.atomic.Value(u64) = .init(0),
        skip: std.atomic.Value(u64) = .init(0),
    };
};

fn setup(ctx: *harness.Ctx, arena: Allocator) !*Shared {
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const pkgs = try arena.create(exec.packages.Store);
    pkgs.* = try exec.packages.load(ctx, arena, last);
    const sh = try arena.create(Shared);
    sh.* = .{
        .engine = .{ .gpa = std.heap.smp_allocator, .pkgs = pkgs },
        .chain_id = serve.b58.decode32(mainnet_chain_id_b58) orelse return error.InvalidChainId,
    };
    return sh;
}

fn run(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sh = try setup(ctx, arena);
    ctx.stderr.print("rpc-simulate: {d} non-system packages, {d} system package ids\n", .{ sh.engine.pkgs.user.count(), sh.engine.pkgs.system.count() }) catch {};
    try ctx.forEachFile(rec_dir, ".rec.zst", sh, runFile);
    for (&sh.per_case, 0..) |*c, i| {
        const p = c.pass.load(.monotonic);
        const f = c.fail.load(.monotonic);
        const s = c.skip.load(.monotonic);
        if (p + f + s == 0) continue;
        ctx.stderr.print("  case {d}: {d} passed, {d} failed, {d} skipped\n", .{ i, p, f, s }) catch {};
    }
    sh.skips.print(ctx.stderr);
    ctx.stderr.flush() catch {};
}

/// One transaction block of a record.
pub const Block = struct {
    tx_index: u32,
    epoch: u64,
    pv: u64,
    rgp: u64,
    start_ms: u64,
    committee_size: u32,
    objects: []const []const u8,
    cases: []const Case,
};

pub const Case = struct {
    case: u8,
    request: []const u8,
    code: u8,
    message: []const u8,
    details: []const u8,
    response: []const u8,
    flags: u8,
};

const Cursor = struct {
    b: []const u8,
    at: usize = 0,

    fn int(c: *Cursor, comptime T: type) !T {
        if (c.at + @sizeOf(T) > c.b.len) return error.Truncated;
        const v = std.mem.readInt(T, c.b[c.at..][0..@sizeOf(T)], .little);
        c.at += @sizeOf(T);
        return v;
    }
    fn bytes(c: *Cursor) ![]const u8 {
        const n = try c.int(u32);
        if (c.at + n > c.b.len) return error.Truncated;
        const v = c.b[c.at..][0..n];
        c.at += n;
        return v;
    }
};

/// Parses one decompressed record into blocks (slices borrow `data`).
pub fn parseRecord(arena: Allocator, data: []const u8) ![]const Block {
    var c: Cursor = .{ .b = data };
    var out: std.ArrayList(Block) = .empty;
    while (c.at < data.len) {
        var b: Block = undefined;
        b.tx_index = try c.int(u32);
        b.epoch = try c.int(u64);
        b.pv = try c.int(u64);
        b.rgp = try c.int(u64);
        b.start_ms = try c.int(u64);
        b.committee_size = try c.int(u32);
        const n = try c.int(u32);
        const objs = try arena.alloc([]const u8, n);
        for (objs) |*o| o.* = try c.bytes();
        b.objects = objs;
        const nc = try c.int(u8);
        const cases = try arena.alloc(Case, nc);
        for (cases) |*k| {
            k.case = try c.int(u8);
            k.request = try c.bytes();
            k.code = try c.int(u8);
            k.message = try c.bytes();
            k.details = try c.bytes();
            k.response = try c.bytes();
            k.flags = try c.int(u8);
        }
        b.cases = cases;
        try out.append(arena, b);
    }
    return out.items;
}

/// The pre-state of one block as a `MapState`.
pub fn mapState(arena: Allocator, objects: []const []const u8) !state_mod.MapState {
    var m: state_mod.MapState = .{};
    try m.map.ensureTotalCapacity(arena, @intCast(objects.len));
    for (objects) |raw| {
        const v = try ObjectView.parse(raw);
        m.map.putAssumeCapacity(v.id, .{ .version = v.version, .raw = raw });
    }
    return m;
}

pub fn envOf(chain_id: [32]u8, b: *const Block) !root.EpochEnv {
    return .{
        .chain_id = chain_id,
        .epoch = b.epoch,
        .pv = b.pv,
        .cfg = try protocol.get(b.pv, corpus_chain),
        .rgp = b.rgp,
        .epoch_start_ms = b.start_ms,
        .committee_size = b.committee_size,
    };
}

fn runFile(sh: *Shared, ctx: *harness.Ctx, name: []const u8) !void {
    const seq = name[0 .. name.len - ".rec.zst".len];
    const data = ctx.readZstd(try std.fmt.allocPrint(ctx.scratch(), "{s}/{s}", .{ rec_dir, name }), max_rec) catch |e| {
        ctx.fail(seq, "read: {s}", .{@errorName(e)});
        return;
    };
    const blocks = parseRecord(ctx.scratch(), data) catch |e| {
        ctx.fail(seq, "record: {s}", .{@errorName(e)});
        return;
    };
    var tx_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer tx_arena.deinit();
    for (blocks) |*b| {
        _ = tx_arena.reset(.retain_capacity);
        const a = tx_arena.allocator();
        const ms = try mapState(a, b.objects);
        const env = envOf(sh.chain_id, b) catch {
            for (b.cases) |k| {
                const id = try std.fmt.allocPrint(a, "{s}/{d}/{d}", .{ seq, b.tx_index, k.case });
                ctx.skip(id, "protocol version not supported");
            }
            continue;
        };
        for (b.cases) |*k| {
            const id = try std.fmt.allocPrint(a, "{s}/{d}/{d}", .{ seq, b.tx_index, k.case });
            if (!ctx.selected(id)) continue;
            const r = try sh.engine.simulate(a, &env, ms.state(), k.request);
            const counts = &sh.per_case[k.case];
            switch (r) {
                .err => |er| {
                    if (er.code == 12 and k.code != 12) {
                        sh.skips.add(ctx.io, er.message);
                        _ = counts.skip.fetchAdd(1, .monotonic);
                        ctx.skip(id, er.message);
                        continue;
                    }
                    if (er.code != k.code or !std.mem.eql(u8, er.message, k.message) or !std.mem.eql(u8, er.details, k.details)) {
                        _ = counts.fail.fetchAdd(1, .monotonic);
                        dumpPair(ctx, id, er.message, k.message);
                        ctx.fail(id, "error: zui code {d} \"{s}\", Rust code {d} \"{s}\" (details equal: {})", .{ er.code, er.message, k.code, k.message, std.mem.eql(u8, er.details, k.details) });
                        continue;
                    }
                },
                .ok => |resp| {
                    if (k.code != 0) {
                        _ = counts.fail.fetchAdd(1, .monotonic);
                        dumpPair(ctx, id, resp, k.message);
                        ctx.fail(id, "zui answered OK, Rust code {d} \"{s}\"", .{ k.code, k.message });
                        continue;
                    }
                    if (!std.mem.eql(u8, resp, k.response)) {
                        _ = counts.fail.fetchAdd(1, .monotonic);
                        dumpPair(ctx, id, resp, k.response);
                        ctx.fail(id, "response differs (zui {d} bytes, Rust {d} bytes) at byte {d}", .{ resp.len, k.response.len, firstDiff(resp, k.response) });
                        continue;
                    }
                },
            }
            _ = counts.pass.fetchAdd(1, .monotonic);
            ctx.pass(id);
        }
    }
}

/// Writes both answers of a differing case next to each other (for protoc --decode_raw):
/// `zig-out/rpcx-diff/<seq>_<tx>_<case>.{deepwave,rust}` (failures are rare; any build mode).
fn dumpPair(ctx: *harness.Ctx, id: []const u8, zui: []const u8, rust: []const u8) void {
    var buf: [256]u8 = undefined;
    var name: [128]u8 = undefined;
    const n = @min(id.len, name.len);
    for (id[0..n], name[0..n]) |ch, *o| o.* = if (ch == '/') '_' else ch;
    const dir = std.Io.Dir.cwd();
    dir.createDirPath(ctx.io, "zig-out/rpcx-diff") catch {};
    const pz = std.fmt.bufPrint(&buf, "zig-out/rpcx-diff/{s}.zui", .{name[0..n]}) catch return;
    dir.writeFile(ctx.io, .{ .sub_path = pz, .data = zui }) catch {};
    const pr = std.fmt.bufPrint(&buf, "zig-out/rpcx-diff/{s}.rust", .{name[0..n]}) catch return;
    dir.writeFile(ctx.io, .{ .sub_path = pr, .data = rust }) catch {};
}

fn firstDiff(a: []const u8, b: []const u8) usize {
    const n = @min(a.len, b.len);
    for (0..n) |i| if (a[i] != b[i]) return i;
    return n;
}

// ---- bench ----------------------------------------------------------------------------------

const BenchState = struct {
    sh: *Shared,
    items: []const BenchItem,
};

const BenchItem = struct {
    env: root.EpochEnv,
    state: state_mod.MapState,
    request: []const u8,
};

/// Case 1 of every block of the bench inputs (the same requests the Rust baseline times), one
/// thread, warm package caches, prepared pre-states.
fn bench(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const sh = try setup(ctx, arena);
    var items: std.ArrayList(BenchItem) = .empty;
    for (ctx.benchInputs()) |path| {
        const z = try ctx.corpus.readFileAlloc(ctx.io, path, arena, .limited(max_rec));
        const data = try harness.decompressZstd(arena, z, max_rec);
        const blocks = try parseRecord(arena, data);
        for (blocks) |*b| for (b.cases) |k| if (k.case == 1) {
            const env = envOf(sh.chain_id, b) catch continue;
            try items.append(arena, .{ .env = env, .state = try mapState(arena, b.objects), .request = k.request });
        };
    }
    // "simulate": what a node serving one epoch sees. The items are in checkpoint order, so
    // grouped by epoch; each epoch group runs once untimed (its package cache warms, as Rust's
    // process-wide Move runtime cache is warm after the baseline's warm-up pass), then `iters`
    // timed runs. Pass i is the sum over the groups of their i-th timed run.
    const iters = @max(1, ctx.opts.iters);
    const times = try arena.alloc(u64, iters);
    @memset(times, 0);
    var i: usize = 0;
    while (i < items.items.len) {
        var j = i + 1;
        while (j < items.items.len and items.items[j].env.epoch == items.items[i].env.epoch) j += 1;
        const group: BenchState = .{ .sh = sh, .items = items.items[i..j] };
        try benchPass(&group);
        for (times) |*t| {
            const t0 = std.Io.Timestamp.now(ctx.io, .awake);
            try benchPass(&group);
            const t1 = std.Io.Timestamp.now(ctx.io, .awake);
            t.* += @intCast(t0.durationTo(t1).nanoseconds);
        }
        i = j;
    }
    ctx.benchRecordTimes("simulate", "tx", items.items.len, times);
    // every pass over all epochs in order: the per-thread package caches keep 4 epochs, so each
    // pass re-links (and re-verifies) every package at each epoch switch
    const st: BenchState = .{ .sh = sh, .items = items.items };
    try ctx.benchPasses("simulate-epoch-switch", "tx", items.items.len, &st, benchPass);
}

fn benchPass(st: *const BenchState) !void {
    var a: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer a.deinit();
    for (st.items) |*it| {
        _ = a.reset(.retain_capacity);
        const r = try st.sh.engine.simulate(a.allocator(), &it.env, it.state.state(), it.request);
        std.mem.doNotOptimizeAway(&r);
    }
}
