//! Suite `exec-state-hash`: one item per corpus checkpoint. deepwave's GlobalStateHasher over the
//! checkpoint's effects (protocol config of its epoch) must equal sui-core's
//! `accumulate_effects`, run by `tools/truth/exec` against the same checkpoint-local store:
//! the accumulator point (BCS, 32 bytes), its digest, the history lookups of the v1 path and
//! the object keys the store could not answer.
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const protocol = @import("protocol");
/// The corpus these suites replay ($ZUI_CORPUS) is mainnet history.
const corpus_chain: protocol.Chain = .mainnet;
const state_hash = @import("state_hash.zig");

const truth_path = "vectors/exec-state-hash/truth.jsonl.zst";
const history_path = "vectors/exec-state-hash/history.jsonl.zst";
const max_blob = 1 << 30;

const TruthLine = struct {
    seq: u64,
    epoch: u64,
    pv: u64,
    path: []const u8,
    txs: u64,
    acc: ?[]const u8,
    digest: ?[]const u8,
    lookups: []const []const u8,
    missing: []const []const u8,
};

const State = struct {
    /// seq -> truth line
    truth: std.AutoHashMapUnmanaged(u64, []const u8),
    pv: []const u64,
};

pub fn run(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const st = try loadState(ctx, arena);
    try ctx.forEachFile("chk", ".chk", &st, checkFile);
    try runHistory(ctx, arena, &st);
}

const HistoryLine = struct {
    seq: u64,
    answers: []const u8,
    pv: u64,
    fixed: bool,
    history: []const []const u8,
    acc: ?[]const u8,
    digest: ?[]const u8,
};

/// History items (`tools/truth/exec state-hash-history`): each v1-path checkpoint with
/// lookups, with the store answering every lookup `Some(ref)` (synthetic wrapped and live
/// digests, or the newest corpus ref), at its own protocol version and at version 2
/// (`loaded_child_objects_fixed` off). deepwave accumulates the checkpoint and finishes each lookup
/// with `applyHistory` using the same answers.
fn runHistory(ctx: *harness.Ctx, arena: std.mem.Allocator, st: *const State) !void {
    const z = ctx.corpus.readFileAlloc(ctx.io, history_path, arena, .limited(1 << 30)) catch |e| {
        ctx.fail("history", "read {s}: {s}", .{ history_path, @errorName(e) });
        return;
    };
    const text = try harness.decompressZstd(arena, z, 1 << 30);
    var it = harness.lines(text);
    while (it.next()) |line| {
        const t = std.json.parseFromSliceLeaky(HistoryLine, arena, line, .{}) catch |e| {
            ctx.fail("history", "truth: {s}", .{@errorName(e)});
            continue;
        };
        const item = try std.fmt.allocPrint(arena, "history/{d}/{s}/pv{d}", .{ t.seq, t.answers, t.pv });
        if (!ctx.selected(item)) continue;
        _ = st;
        checkHistory(ctx, arena, item, &t) catch |e| ctx.fail(item, "{s}", .{@errorName(e)});
    }
}

fn checkHistory(ctx: *harness.Ctx, arena: std.mem.Allocator, item: []const u8, t: *const HistoryLine) !void {
    const blob = try ctx.readFile(try std.fmt.allocPrint(arena, "chk/{d}.chk", .{t.seq}), max_blob);
    var idx = try types.CheckpointIndex.init(arena);
    try types.indexCheckpointData(blob, &idx);
    const cfg = try protocol.get(t.pv, corpus_chain);
    const path = state_hash.pathFor(cfg);
    var out: state_hash.CheckpointHash = .{};
    try state_hash.accumulateCheckpoint(arena, path, blob, &idx, &out);
    var c = ctx.check(item);
    c.text("path", "v1", @tagName(path));
    c.eql("loaded_child_objects_fixed", t.fixed, cfg.feature_flags.loaded_child_objects_fixed);
    c.eql("lookup count", t.history.len, out.lookups.items.len);
    var panicked = false;
    for (out.lookups.items) |key| {
        const ans = findAnswer(t.history, key) orelse {
            c.failf("no truth answer for lookup {x}:{d}", .{ &key.id, key.version });
            break;
        };
        state_hash.applyHistory(&out, key, ans, cfg.feature_flags.loaded_child_objects_fixed) catch {
            panicked = true;
            break;
        };
    }
    c.eql("panicked (acc null)", t.acc == null, panicked);
    if (!panicked) if (t.acc) |acc_hex| {
        c.digestHex("acc", acc_hex, &out.acc.toBytes());
        c.digestHex("digest", t.digest orelse "", &out.acc.digest());
    };
    _ = c.finish();
}

/// `"<key id>:<key version>:<id>:<version>:<digest>"` or `"<key id>:<key version>:none"`.
fn findAnswer(history: []const []const u8, key: state_hash.Key) ??state_hash.ObjectRef {
    var buf: [96]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buf, "{x}:{d}:", .{ &key.id, key.version }) catch return null;
    for (history) |h| {
        if (!std.mem.startsWith(u8, h, prefix)) continue;
        const rest = h[prefix.len..];
        if (std.mem.eql(u8, rest, "none")) return @as(?state_hash.ObjectRef, null);
        var parts = std.mem.splitScalar(u8, rest, ':');
        var r: state_hash.ObjectRef = undefined;
        _ = std.fmt.hexToBytes(&r.id, parts.next() orelse return null) catch return null;
        r.version = std.fmt.parseInt(u64, parts.next() orelse return null, 10) catch return null;
        _ = std.fmt.hexToBytes(&r.digest, parts.next() orelse return null) catch return null;
        return @as(?state_hash.ObjectRef, r);
    }
    return null;
}

fn loadState(ctx: *harness.Ctx, arena: std.mem.Allocator) !State {
    const z = try ctx.corpus.readFileAlloc(ctx.io, truth_path, arena, .limited(1 << 30));
    const text = try harness.decompressZstd(arena, z, 1 << 32);
    var st: State = .{ .truth = .empty, .pv = &.{} };
    var it = harness.lines(text);
    while (it.next()) |line| {
        const k = "{\"seq\":";
        if (!std.mem.startsWith(u8, line, k)) return error.BadTruthLine;
        const end = std.mem.indexOfScalarPos(u8, line, k.len, ',') orelse return error.BadTruthLine;
        const seq = try std.fmt.parseInt(u64, line[k.len..end], 10);
        try st.truth.put(arena, seq, line);
    }
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const pv = try arena.alloc(u64, epochs.len);
    for (epochs, pv) |e, *p| p.* = e.pv;
    st.pv = pv;
    return st;
}

fn epochOf(blob: []const u8, idx: *const types.CheckpointIndex) u64 {
    return std.mem.readInt(u64, blob[idx.summary.o..][0..8], .little);
}

fn keyText(arena: std.mem.Allocator, keys: []state_hash.Key) ![]const []const u8 {
    std.mem.sort(state_hash.Key, keys, {}, state_hash.Key.lessThan);
    const out = try arena.alloc([]const u8, keys.len);
    for (keys, out) |k, *o| o.* = try std.fmt.allocPrint(arena, "{x}:{d}", .{ &k.id, k.version });
    return out;
}

fn checkFile(st: *const State, ctx: *harness.Ctx, name: []const u8) !void {
    const item = name[0 .. name.len - ".chk".len];
    const arena = ctx.scratch();
    const seq = std.fmt.parseInt(u64, item, 10) catch return ctx.fail(item, "bad name", .{});
    const line = st.truth.get(seq) orelse return ctx.fail(item, "no truth line", .{});
    const t = std.json.parseFromSliceLeaky(TruthLine, arena, line, .{}) catch |e| return ctx.fail(item, "truth: {s}", .{@errorName(e)});

    const blob = try ctx.readFile(try std.fmt.allocPrint(arena, "chk/{s}", .{name}), max_blob);
    var idx = try types.CheckpointIndex.init(arena);
    types.indexCheckpointData(blob, &idx) catch |e| return ctx.fail(item, "index: {s}", .{@errorName(e)});
    const epoch = epochOf(blob, &idx);
    if (epoch >= st.pv.len) return ctx.fail(item, "epoch {d} not in epochs.jsonl", .{epoch});
    const cfg = protocol.get(st.pv[epoch], corpus_chain) catch return ctx.fail(item, "protocol {d}", .{st.pv[epoch]});
    const path = state_hash.pathFor(cfg);

    var out: state_hash.CheckpointHash = .{};
    state_hash.accumulateCheckpoint(arena, path, blob, &idx, &out) catch |e| return ctx.fail(item, "accumulate: {s}", .{@errorName(e)});

    var c = ctx.check(item);
    c.eql("epoch", t.epoch, epoch);
    c.eql("pv", t.pv, st.pv[epoch]);
    c.text("path", t.path, @tagName(path));
    c.eql("txs", t.txs, idx.tx_count);
    const missing = try keyText(arena, out.missing.items);
    // Rust reads every modified_at key before unwrapping them, so a miss panics after the
    // whole list was read and before any history lookup.
    const lookups = if (missing.len > 0) &[_][]const u8{} else try keyText(arena, out.lookups.items);
    c.eql("missing count", t.missing.len, missing.len);
    for (t.missing, 0..) |m, i| if (i < missing.len) c.text("missing", m, missing[i]);
    c.eql("lookup count", t.lookups.len, lookups.len);
    for (t.lookups, 0..) |l, i| if (i < lookups.len) c.text("lookup", l, lookups[i]);
    if (missing.len > 0) {
        c.eql("acc is null", true, t.acc == null);
    } else if (t.acc) |acc_hex| {
        const acc = out.acc.toBytes();
        const dig = out.acc.digest();
        c.digestHex("acc", acc_hex, &acc);
        c.digestHex("digest", t.digest orelse "", &dig);
    } else c.failf("truth panicked but zui read every object", .{});
    _ = c.finish();
}

// ---------------------------------------------------------------------------------------------
// Bench: accumulate per checkpoint from indexed blobs (Rust: from decoded effects with a
// prebuilt store; decode untimed on both sides).

const BenchItem = struct { blob: []const u8, idx: types.CheckpointIndex, path: state_hash.Path };

pub fn bench(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const names = ctx.benchInputs();
    const items = try arena.alloc(BenchItem, names.len);
    var txs: u64 = 0;
    for (names, items) |n, *it| {
        it.blob = try ctx.corpus.readFileAlloc(ctx.io, n, arena, .limited(max_blob));
        var full = try types.CheckpointIndex.init(std.heap.page_allocator);
        defer full.deinit(std.heap.page_allocator);
        try types.indexCheckpointData(it.blob, &full);
        it.idx = .{
            .summary = full.summary,
            .sig = full.sig,
            .contents = full.contents,
            .tx_count = full.tx_count,
            .sig_total = full.sig_total,
            .obj_total = full.obj_total,
            .txs = try arena.dupe(types.index.Tx, full.txs[0..full.tx_count]),
            .sigs = try arena.dupe(types.index.Range, full.sigs[0..full.sig_total]),
            .objs = try arena.dupe(types.index.Range, full.objs[0..full.obj_total]),
        };
        const cfg = try protocol.get(epochs[epochOf(it.blob, &it.idx)].pv, corpus_chain);
        it.path = state_hash.pathFor(cfg);
        txs += full.tx_count;
    }
    const S = struct {
        fn pass(b: []const BenchItem) !void {
            var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer scratch.deinit();
            for (b) |*it| {
                _ = scratch.reset(.retain_capacity);
                var out: state_hash.CheckpointHash = .{};
                try state_hash.accumulateCheckpoint(scratch.allocator(), it.path, it.blob, &it.idx, &out);
                std.mem.doNotOptimizeAway(out.acc.digest());
            }
        }
    };
    try ctx.benchPasses("state-hash", "tx", txs, @as([]const BenchItem, items), S.pass);
}
