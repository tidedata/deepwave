//! Conformance suites of the exec lane (CONTRACTS.md section 3.3).
//!
//! `exec-replay`: every corpus transaction is one item. deepwave executes it against the
//! checkpoint's own input objects and compares the effects, events and every output object
//! byte-exact with the certified ones. Transactions whose execution needs the Move VM are
//! skipped with their class until move_vm and natives land; a skip counts against done.
//! While they wait, the run also replays exec's storage accounting over every metered
//! transaction with V2 effects (`storage_check.zig`) and reports it as a diagnostic.
//!
//! `exec-state-hash`: state_hash_suite.zig.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
/// The corpus these suites replay ($ZUI_CORPUS) is mainnet history.
const corpus_chain: protocol.Chain = .mainnet;
const classify = @import("classify.zig");
const replay = @import("replay.zig");
const state_hash_suite = @import("state_hash_suite.zig");
const storage_check = @import("storage_check.zig");
const inputs = @import("inputs.zig");
const packages = @import("packages.zig");
const objects = @import("objects.zig");
const ptb = @import("ptb/root.zig");
const system = @import("system/root.zig");
const system_replay = @import("system/replay.zig");
const versions = @import("versions/root.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "exec-replay",
        .lane = "exec",
        .doc = "every corpus transaction: effects, events and output objects byte-exact",
        .run = runReplay,
        .bench = replay.bench,
        .baselines = &.{
            .{ .name = "exec", .argv = &.{ "{release}/zui-truth-exec", "bench", "exec" } },
            .{ .name = "exec-move", .argv = &.{ "{release}/zui-truth-exec", "bench", "exec-move" } },
        },
    },
    .{
        .name = "exec-system",
        .lane = "exec-system",
        .doc = "exec-replay's system transactions only (settlement, randomness, authenticator, end of epoch, ChangeEpoch, genesis; CONTRACTS 6.4.2), with the system bench",
        .run = runSystem,
        .bench = system_replay.bench,
        .baselines = &.{.{ .name = "system", .argv = &.{ "{release}/zui-truth-exec-system", "bench", "system" } }},
    },
    .{
        .name = "exec-move-synth",
        .lane = "exec-move",
        .doc = "synthetic vectors from Mysten's executor for paths the corpus misses (coin deny list v2): effects, events and written objects byte-exact",
        .run = @import("ptb/synth_suite.zig").run,
    },
    .{
        .name = "exec-state-hash",
        .lane = "exec",
        .doc = "per-checkpoint GlobalStateHasher accumulator (ECMH point, digest, history lookups) equals sui-core's",
        .run = state_hash_suite.run,
        .bench = state_hash_suite.bench,
        .baselines = &.{.{ .name = "state-hash", .argv = &.{ "{release}/zui-truth-exec", "bench", "state-hash" } }},
    },
};

const max_blob = 1 << 30;

pub const Tally = struct {
    pv: []const u64 = &.{},
    /// Reference gas price and start timestamp per epoch (epochs.jsonl).
    rgp: []const u64 = &.{},
    start_ms: []const u64 = &.{},
    pkgs: packages.Store = .{},
    objs: replay.ObjectDb = .{},
    children: system_replay.Children = .{},
    /// exec-system: only the system transactions (`system.inScope`).
    only_system: bool = false,
    /// exec-history slices: `-Dfilter=cut=<Cut>[@<n>][:<substr>]` runs only the checkpoints of
    /// one cut (every n-th checkpoint with `@n`), optionally filtered by a file-name substring.
    cut: ?versions.Cut = null,
    sample: u64 = 1,
    /// `cut=<Cut>+<lo>-<hi>`: protocol versions lo..hi inclusive.
    pv_lo: u64 = 0,
    pv_hi: u64 = std.math.maxInt(u64),
    coin_skips: replay.SkipTally = .{},
    fail_shown: std.atomic.Value(u64) = .init(0),
    fail_ids: [20]?[]const u8 = @splat(null),
    total: [classify.n_classes]std.atomic.Value(u64) = @splat(.init(0)),
    passed: [classify.n_classes]std.atomic.Value(u64) = @splat(.init(0)),
    failed: [classify.n_classes]std.atomic.Value(u64) = @splat(.init(0)),
    v1: std.atomic.Value(u64) = .init(0),
    storage_ok: std.atomic.Value(u64) = .init(0),
    storage_bad: std.atomic.Value(u64) = .init(0),
    storage_na: std.atomic.Value(u64) = .init(0),
    storage_oog: std.atomic.Value(u64) = .init(0),
    storage_shown: std.atomic.Value(u64) = .init(0),
    shown: [20]?[]const u8 = @splat(null),
    inputs_ok: std.atomic.Value(u64) = .init(0),
    inputs_bad: std.atomic.Value(u64) = .init(0),
    inputs_missing: std.atomic.Value(u64) = .init(0),
    inputs_missing_by: [@typeInfo(inputs.Missing).@"enum".field_names.len]std.atomic.Value(u64) = @splat(.init(0)),
    inputs_na: std.atomic.Value(u64) = .init(0),
    inputs_shown: std.atomic.Value(u64) = .init(0),
    inputs_msgs: [20]?[]const u8 = @splat(null),

    fn print(t: *Tally, w: *std.Io.Writer) void {
        w.print("exec-replay classes (total / passed / failed / skipped):\n", .{}) catch {};
        inline for (@typeInfo(classify.Class).@"enum".field_names, 0..) |fname, i| {
            const tot = t.total[i].load(.monotonic);
            const p = t.passed[i].load(.monotonic);
            const fl = t.failed[i].load(.monotonic);
            w.print("  {s:<22} {d:>8} {d:>8} {d:>8} {d:>8}\n", .{ fname, tot, p, fl, tot - p - fl }) catch {};
        }
        t.coin_skips.print(w);
        for (t.fail_ids) |f| if (f) |text| w.print("  failed: {s} (rerun with --filter <checkpoint> for the detail)\n", .{text}) catch {};
        w.print("  effects v1 transactions: {d}\n", .{t.v1.load(.monotonic)}) catch {};
        w.print("storage-gas diagnostic (metered, effects v2): {d} match, {d} differ, {d} storage out-of-gas or bump-only (not modeled), {d} not applicable\n", .{
            t.storage_ok.load(.monotonic), t.storage_bad.load(.monotonic), t.storage_oog.load(.monotonic), t.storage_na.load(.monotonic),
        }) catch {};
        for (t.shown) |m| if (m) |text| w.print("  storage-gas {s}\n", .{text}) catch {};
        w.print("inputs diagnostic (programmable, effects v2: lamport version and dependencies): {d} match, {d} differ, {d} input object not in checkpoint, {d} not applicable\n", .{
            t.inputs_ok.load(.monotonic), t.inputs_bad.load(.monotonic), t.inputs_missing.load(.monotonic), t.inputs_na.load(.monotonic),
        }) catch {};
        inline for (@typeInfo(inputs.Missing).@"enum".field_names, 0..) |fname, i| {
            const n = t.inputs_missing_by[i].load(.monotonic);
            if (n > 0) w.print("  inputs not available: {s} {d}\n", .{ fname, n }) catch {};
        }
        for (t.inputs_msgs) |m| if (m) |text| w.print("  inputs {s}\n", .{text}) catch {};
        w.flush() catch {};
    }
};

fn runReplay(ctx: *harness.Ctx) !void {
    return runReplayWith(ctx, false);
}

fn runSystem(ctx: *harness.Ctx) !void {
    return runReplayWith(ctx, true);
}

fn runReplayWith(ctx: *harness.Ctx, only_system: bool) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const pv = try arena.alloc(u64, epochs.len);
    for (epochs, pv) |e, *p| p.* = e.pv;
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const Extra = struct { epoch: u64, rgp: ?u64 = null, start_ms: ?u64 = null };
    const rgp = try arena.alloc(u64, epochs.len);
    const start_ms = try arena.alloc(u64, epochs.len);
    @memset(rgp, 0);
    @memset(start_ms, 0);
    {
        const text = try ctx.corpus.readFileAlloc(ctx.io, "epochs.jsonl", arena, .limited(64 << 20));
        var it = harness.lines(text);
        while (it.next()) |line| {
            const x = try std.json.parseFromSliceLeaky(Extra, arena, line, .{ .ignore_unknown_fields = true });
            if (x.epoch < epochs.len) {
                rgp[x.epoch] = x.rgp orelse 0;
                start_ms[x.epoch] = x.start_ms orelse 0;
            }
        }
    }
    var tally: Tally = .{ .pv = pv, .rgp = rgp, .start_ms = start_ms, .pkgs = try packages.load(ctx, arena, last), .objs = try replay.ObjectDb.load(ctx, arena), .children = try system_replay.Children.load(ctx, arena), .only_system = only_system };
    if (try @import("perf.zig").setup(ctx.io, &tally.pkgs)) |m| ctx.stderr.print("exec-replay perf: {s}\n", .{m}) catch {};
    ctx.stderr.print("exec-replay: {d} non-system packages, {d} system package ids, {d} read-only objects from the corpus\n", .{ tally.pkgs.user.count(), tally.pkgs.system.count(), tally.objs.map.count() }) catch {};
    if (ctx.opts.filter) |f| if (std.mem.startsWith(u8, f, "cut=")) {
        var rest = f[4..];
        var sub: ?[]const u8 = null;
        if (std.mem.indexOfScalar(u8, rest, ':')) |k| {
            sub = rest[k + 1 ..];
            rest = rest[0..k];
        }
        if (std.mem.indexOfScalar(u8, rest, '+')) |k| {
            const range = rest[k + 1 ..];
            rest = rest[0..k];
            const dash = std.mem.indexOfScalar(u8, range, '-') orelse return error.BadCutRange;
            tally.pv_lo = try std.fmt.parseInt(u64, range[0..dash], 10);
            tally.pv_hi = try std.fmt.parseInt(u64, range[dash + 1 ..], 10);
        }
        if (std.mem.indexOfScalar(u8, rest, '@')) |k| {
            tally.sample = try std.fmt.parseInt(u64, rest[k + 1 ..], 10);
            rest = rest[0..k];
        }
        tally.cut = std.meta.stringToEnum(versions.Cut, rest) orelse return error.UnknownCut;
        ctx.opts.filter = sub;
    };
    try ctx.forEachFile("chk", ".chk", &tally, replayFile);
    @import("perf.zig").finish(ctx.io) catch |e| ctx.stderr.print("exec-replay perf: writing the output failed: {s}\n", .{@errorName(e)}) catch {};
    tally.print(ctx.stderr);
}

fn replayFile(tally: *Tally, ctx: *harness.Ctx, name: []const u8) !void {
    const seq_text = name[0 .. name.len - ".chk".len];
    if (tally.cut != null) {
        const seq = std.fmt.parseInt(u64, seq_text, 10) catch return;
        if (seq % tally.sample != 0) return;
    }
    const blob = ctx.readFile(try std.fmt.allocPrint(ctx.scratch(), "chk/{s}", .{name}), max_blob) catch |e| {
        ctx.fail(seq_text, "read: {s}", .{@errorName(e)});
        return;
    };
    if (blob.len == 0 or blob[0] != 1) return ctx.fail(seq_text, "bad blob tag", .{});
    const arena = ctx.scratch();
    const cp = bcs.decode(types.CheckpointData, arena, blob[1..]) catch |e| {
        ctx.fail(seq_text, "decode CheckpointData: {s}", .{@errorName(e)});
        return;
    };
    var idx = try types.CheckpointIndex.init(arena);
    types.indexCheckpointData(blob, &idx) catch |e| return ctx.fail(seq_text, "index: {s}", .{@errorName(e)});
    var table: objects.ObjectTable = .{};
    table.addCheckpoint(arena, blob, &idx) catch |e| return ctx.fail(seq_text, "object table: {s}", .{@errorName(e)});
    const summary = &cp.checkpoint_summary.data;
    const cfg = if (summary.epoch < tally.pv.len) protocol.get(tally.pv[summary.epoch], corpus_chain) catch null else null;
    if (tally.cut) |want| if (cfg == null or versions.cutOf(cfg.?) != want or cfg.?.version < tally.pv_lo or cfg.?.version > tally.pv_hi) return;
    // The Move-call executor runs on the cuts `versions.moveSupported` names (CONTRACTS 6.6b);
    // it reads runtime loads from the archive.
    const move_ok = if (cfg) |c| versions.moveSupported(c) else false;
    var arch: ?ptb.archive.Archive = null;
    var arch_objs: objects.ObjectTable = .{};
    if (move_ok) {
        var needs = false;
        for (cp.transactions) |*t| switch (classify.classify(&t.transaction.data.@"0".element().intent_message.value.V1.kind)) {
            .ptb_move_call, .ptb_make_vec, .ptb_publish => needs = true,
            else => {},
        };
        if (needs) {
            // `binpb-done/` (the converted range), `binpb-r4/` (checkpoints whose `.chk` lacks a read
            // object), `binpb-exec/` (the rest of the execution-version-4 checkpoints) or
            // `binpb-hist/` (exec-history: the rest of the earlier checkpoints with programmable
            // transactions)
            for ([_][]const u8{ "binpb-done", "binpb-r4", "binpb-exec", "binpb-hist" }) |dir| {
                const path = try std.fmt.allocPrint(arena, "{s}/{s}.binpb.zst", .{ dir, seq_text });
                const dec = ctx.readZstd(path, max_blob) catch continue;
                arch = ptb.archive.parse(arena, dec, cp.transactions.len) catch null;
                if (arch) |a| for (a.objects) |raw| {
                    const k = objects.keyOf(raw) catch continue;
                    try arch_objs.map.put(arena, k, raw);
                };
                break;
            }
        }
    }
    for (cp.transactions, 0..) |*ctx_tx, i| {
        const id = try std.fmt.allocPrint(arena, "{s}/tx[{d}]", .{ seq_text, i });
        const data = &ctx_tx.transaction.data.@"0".element().intent_message.value.V1;
        if (tally.only_system and !system.inScope(&data.kind)) continue;
        const class = classify.classify(&data.kind);
        const ci = @intFromEnum(class);
        _ = tally.total[ci].fetchAdd(1, .monotonic);
        if (ctx_tx.effects == .V1) _ = tally.v1.fetchAdd(1, .monotonic);
        if (cfg) |c| {
            const metered = data.kind == .ProgrammableTransaction;
            const res = storage_check.check(arena, c, blob, &idx, idx.txAt(i), &ctx_tx.effects, metered, data.gas_data.budget) catch |e| storage_check.Result{ .mismatch = @errorName(e) };
            switch (res) {
                .ok => _ = tally.storage_ok.fetchAdd(1, .monotonic),
                .not_applicable => _ = tally.storage_na.fetchAdd(1, .monotonic),
                .storage_oog => _ = tally.storage_oog.fetchAdd(1, .monotonic),
                .mismatch => |m| {
                    _ = tally.storage_bad.fetchAdd(1, .monotonic);
                    const k = tally.storage_shown.fetchAdd(1, .monotonic);
                    if (k < tally.shown.len) tally.shown[k] = std.fmt.allocPrint(std.heap.page_allocator, "{s}: {s}", .{ id, m }) catch null;
                },
            }
        }
        if (cfg) |c| {
            const res = inputs.check(arena, c, blob, &idx, idx.txAt(i), data, &ctx_tx.effects, &tally.pkgs, summary.epoch, &table, &tally.objs) catch |e| inputs.Result{ .mismatch = @errorName(e) };
            switch (res) {
                .ok => _ = tally.inputs_ok.fetchAdd(1, .monotonic),
                .not_applicable => _ = tally.inputs_na.fetchAdd(1, .monotonic),
                .missing_input => |m| {
                    _ = tally.inputs_missing.fetchAdd(1, .monotonic);
                    _ = tally.inputs_missing_by[@intFromEnum(m)].fetchAdd(1, .monotonic);
                },
                .mismatch => |m| {
                    _ = tally.inputs_bad.fetchAdd(1, .monotonic);
                    const k = tally.inputs_shown.fetchAdd(1, .monotonic);
                    if (k < tally.inputs_msgs.len) tally.inputs_msgs[k] = std.fmt.allocPrint(std.heap.page_allocator, "{s}: {s}", .{ id, m }) catch null;
                },
            }
        }
        const is_move = class == .ptb_move_call or class == .ptb_make_vec or class == .ptb_publish;
        const outcome = if (system.handles(&data.kind))
            system_replay.check(ctx, arena, id, cfg, summary.epoch, blob, &idx, idx.txAt(i), data, &tally.pkgs, &tally.children, &tally.coin_skips)
        else blk: {
            if (class.needsVm() and !(is_move and move_ok)) {
                if (is_move) {
                    var buf: [96]u8 = undefined;
                    const why = if (cfg) |c| std.fmt.bufPrint(&buf, "Move call on an execution version before the latest: {s}", .{versions.cutOf(c).label()}) catch unreachable else "Move call on an execution version before the latest";
                    tally.coin_skips.add(ctx.io, why);
                }
                ctx.skip(id, @tagName(class));
                continue;
            }
            const coin_first = class == .ptb_coin_transfer and move_ok;
            const mv: ?replay.MoveArgs = if (is_move or coin_first) .{
                .env = .{
                    .gpa = std.heap.smp_allocator,
                    .cfg = cfg.?,
                    .pv = tally.pv[summary.epoch],
                    .epoch = summary.epoch,
                    .epoch_start_ms = tally.start_ms[summary.epoch],
                    .rgp = tally.rgp[summary.epoch],
                    .pkgs = &tally.pkgs,
                },
                .archive_objs = if (arch != null) &arch_objs else null,
                .loaded = if (arch) |a| a.loaded[i] else null,
                .coin_first = coin_first,
            } else null;
            break :blk replay.checkTransaction(ctx, arena, id, cfg, summary.epoch, blob, &idx, idx.txAt(i), data, &table, &tally.objs, &tally.coin_skips, if (mv) |*m| m else null);
        };
        switch (outcome) {
            .pass => _ = tally.passed[ci].fetchAdd(1, .monotonic),
            .fail => {
                _ = tally.failed[ci].fetchAdd(1, .monotonic);
                const k = tally.fail_shown.fetchAdd(1, .monotonic);
                if (k < tally.fail_ids.len) tally.fail_ids[k] = std.heap.page_allocator.dupe(u8, id) catch null;
            },
            .skip => {},
        }
    }
}
