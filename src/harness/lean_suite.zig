//! Reviewer suites for the lean lane (CONTRACTS.md section 5.11). The Lean specs are oracles,
//! so these suites run the lane's executables rather than Zig code:
//!
//! `lean-bcs`
//!   - `rust/vectors`, `lean/vectors`: every vector in vectors/lean-bcs/vectors.jsonl gets the
//!     same verdict from crates.io bcs 0.1.6 (`zui-lean-truth bcs-check`) and from the proved Lean
//!     decoder, and every accepted vector re-encodes to its own bytes (`zui-spec bcs`);
//!   - `rust/edge`, `lean/edge`: the same for tools/truth/lean/edge/bcs.jsonl, whose verdicts
//!     come from Rust;
//!   - one item per corpus blob: chk/<seq>.chk decodes as `CheckpointData` in the Lean model and
//!     re-encodes byte for byte (`zui-spec bcs-chk`, run in shards on -Djobs workers).
//! `lean-gas`
//!   - `rust/vectors`, `lean/vectors`, `rust/edge`, `lean/edge`: every op script gives the same
//!     per-op results, summary, gas used and gas left in sui-types' `SuiGasStatus` and in the
//!     Lean model.
//! `lean-store`
//!   - one item per trace in vectors/lean-store: `zui-spec store-trace` accepts it.
//!
//! Needs `./zig build lean` (builds lean/.lake/build/bin/zui-spec) and the Rust checker in the
//! shared target dir (`cargo build --release --manifest-path tools/truth/lean/Cargo.toml`);
//! tools/ci.sh does both. The runner's working directory is the repo root (build.zig).
const std = @import("std");
const harness = @import("root.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "lean-bcs",
        .lane = "lean",
        .doc = "Lean BCS oracle vs bcs 0.1.6 on lean-bcs and edge vectors; every corpus blob round-trips in the Lean model",
        .run = runBcs,
    },
    .{
        .name = "lean-gas",
        .lane = "lean",
        .doc = "Lean gas model vs sui-types SuiGasStatus on lean-gas and edge op scripts",
        .run = runGas,
    },
    .{
        .name = "lean-store",
        .lane = "lean",
        .doc = "every lean-store trace passes the Lean store-recovery checker",
        .run = runStore,
    },
};

const spec_bin = "lean/.lake/build/bin/zui-spec";
const registry = "lean/data/sui-format-1.83.1.json";
const edge_dir = "tools/truth/lean/edge";
/// The Rust checker lives in the one shared cargo target dir; the shell expands it.
const truth_prefix = [_][]const u8{
    "bash", "-c", "exec \"${CARGO_TARGET_DIR:?source tools/env.sh}/release/zui-lean-truth\" \"$@\"", "zui-lean-truth",
};
/// Corpus blobs per `zui-spec bcs-chk` process.
const shard_size = 128;

fn truthArgv(a: std.mem.Allocator, args: []const []const u8) ![]const []const u8 {
    const out = try a.alloc([]const u8, truth_prefix.len + args.len);
    @memcpy(out[0..truth_prefix.len], &truth_prefix);
    @memcpy(out[truth_prefix.len..], args);
    return out;
}

fn lastLine(text: []const u8) []const u8 {
    const t = std.mem.trimEnd(u8, text, "\n");
    const at = std.mem.lastIndexOfScalar(u8, t, '\n') orelse return t;
    return t[at + 1 ..];
}

fn tail(text: []const u8, n: usize) []const u8 {
    return if (text.len > n) text[text.len - n ..] else text;
}

/// One item: the command exits 0 and its last stdout line is a summary with `"done":true`
/// (both oracles print that only when at least one item ran and none failed).
fn checkItem(ctx: *harness.Ctx, item: []const u8, argv: []const []const u8) void {
    if (!ctx.selected(item) or ctx.done()) return;
    const r = std.process.run(ctx.gpa, ctx.io, .{ .argv = argv }) catch |e| {
        ctx.fail(item, "cannot run {s}: {s} (./zig build lean; cargo build the truth tool)", .{ argv[0], @errorName(e) });
        return;
    };
    defer ctx.gpa.free(r.stdout);
    defer ctx.gpa.free(r.stderr);
    const last = lastLine(r.stdout);
    if (!r.term.success() or std.mem.indexOf(u8, last, "\"done\":true") == null) {
        ctx.fail(item, "{s}\n{s}\n{s}", .{ last, tail(r.stdout, 2000), tail(r.stderr, 2000) });
        return;
    }
    ctx.pass(item);
}

fn vectorPath(ctx: *harness.Ctx, sub: []const u8) ![]const u8 {
    return std.fmt.allocPrint(ctx.arena.allocator(), "{s}/vectors/{s}", .{ ctx.corpus_path, sub });
}

fn runPair(ctx: *harness.Ctx, kind: []const u8, spec_cmd: []const u8, with_registry: bool) !void {
    const a = ctx.arena.allocator();
    const vec = try vectorPath(ctx, try std.fmt.allocPrint(a, "lean-{s}/vectors.jsonl", .{kind}));
    const edge = try std.fmt.allocPrint(a, "{s}/{s}.jsonl", .{ edge_dir, kind });
    const rust_cmd = try std.fmt.allocPrint(a, "{s}-check", .{kind});
    for ([_]struct { name: []const u8, file: []const u8 }{
        .{ .name = "vectors", .file = vec },
        .{ .name = "edge", .file = edge },
    }) |set| {
        const rust_args = if (with_registry)
            try a.dupe([]const u8, &.{ rust_cmd, registry, set.file })
        else
            try a.dupe([]const u8, &.{ rust_cmd, set.file });
        checkItem(ctx, try std.fmt.allocPrint(a, "rust/{s}", .{set.name}), try truthArgv(a, rust_args));
        const lean_argv = if (with_registry)
            try a.dupe([]const u8, &.{ spec_bin, spec_cmd, registry, set.file })
        else
            try a.dupe([]const u8, &.{ spec_bin, spec_cmd, set.file });
        checkItem(ctx, try std.fmt.allocPrint(a, "lean/{s}", .{set.name}), lean_argv);
    }
}

const Shards = struct {
    names: []const []const u8,
    /// Blobs per shard (1 under -Dfilter, so the shard name is the blob name).
    per: usize,
};

fn shardOf(s: *const Shards, name: []const u8) []const []const u8 {
    if (s.per == 1) {
        for (s.names, 0..) |n, i| if (std.mem.eql(u8, n, name)) return s.names[i .. i + 1];
        return &.{};
    }
    const idx = std.fmt.parseInt(usize, name["shard-".len..], 10) catch return &.{};
    const lo = idx * s.per;
    return s.names[lo..@min(s.names.len, lo + s.per)];
}

fn bcsChkShard(s: *const Shards, w: *harness.Ctx, shard_name: []const u8) !void {
    const files = shardOf(s, shard_name);
    if (files.len == 0) return;
    const a = w.scratch();
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(a, &.{ spec_bin, "bcs-chk", registry, "CheckpointData" });
    for (files) |f| try argv.append(a, try std.fmt.allocPrint(a, "{s}/chk/{s}", .{ w.corpus_path, f }));
    const r = std.process.run(w.gpa, w.io, .{ .argv = argv.items }) catch |e| {
        for (files) |f| w.fail(f, "cannot run {s}: {s} (./zig build lean)", .{ spec_bin, @errorName(e) });
        return;
    };
    defer w.gpa.free(r.stdout);
    defer w.gpa.free(r.stderr);
    const last = lastLine(r.stdout);
    const summary_ok = std.mem.indexOf(u8, last, "\"check\":\"lean-bcs-chk\"") != null;
    const want_items = try std.fmt.allocPrint(a, "\"items\":{d},", .{files.len});
    for (files, argv.items[4..]) |f, path| {
        if (!summary_ok or std.mem.indexOf(u8, last, want_items) == null) {
            w.fail(f, "bcs-chk did not finish: {s}\n{s}", .{ last, tail(r.stderr, 1000) });
            continue;
        }
        const needle = try std.fmt.allocPrint(a, "FAIL {s} ", .{path});
        if (std.mem.indexOf(u8, r.stdout, needle)) |at| {
            const end = std.mem.indexOfScalarPos(u8, r.stdout, at, '\n') orelse r.stdout.len;
            w.fail(f, "{s}", .{r.stdout[at..end]});
        } else w.pass(f);
    }
    // A failing exit with no FAIL line for any of our files is still a failure.
    if (summary_ok and !r.term.success() and std.mem.indexOf(u8, r.stdout, "FAIL ") == null)
        w.fail(shard_name, "bcs-chk exited non-zero: {s}", .{last});
}

fn runBcs(ctx: *harness.Ctx) !void {
    try runPair(ctx, "bcs", "bcs", true);

    const all = try ctx.listFiles("chk", ".chk");
    defer ctx.freeNames(all);
    var picked: std.ArrayList([]const u8) = .empty;
    defer picked.deinit(ctx.gpa);
    for (all) |n| if (ctx.selected(n)) try picked.append(ctx.gpa, n);
    const per: usize = if (ctx.opts.filter != null) 1 else shard_size;
    const shards: Shards = .{ .names = picked.items, .per = per };
    var shard_names: std.ArrayList([]const u8) = .empty;
    defer {
        if (per != 1) for (shard_names.items) |n| ctx.gpa.free(n);
        shard_names.deinit(ctx.gpa);
    }
    if (per == 1) {
        try shard_names.appendSlice(ctx.gpa, picked.items);
    } else {
        var i: usize = 0;
        while (i * per < picked.items.len) : (i += 1)
            try shard_names.append(ctx.gpa, try std.fmt.allocPrint(ctx.gpa, "shard-{d}", .{i}));
    }
    try ctx.forEachName(shard_names.items, &shards, bcsChkShard);
}

fn runGas(ctx: *harness.Ctx) !void {
    try runPair(ctx, "gas", "gas", false);
}

fn storeTrace(_: void, w: *harness.Ctx, name: []const u8) !void {
    const path = try std.fmt.allocPrint(w.scratch(), "{s}/vectors/lean-store/{s}", .{ w.corpus_path, name });
    checkItemNoReset(w, name, &.{ spec_bin, "store-trace", path });
}

/// `checkItem` for forEachName workers (the pool already reset the arena and applied -Dfilter).
fn checkItemNoReset(w: *harness.Ctx, item: []const u8, argv: []const []const u8) void {
    const r = std.process.run(w.gpa, w.io, .{ .argv = argv }) catch |e| {
        w.fail(item, "cannot run {s}: {s} (./zig build lean)", .{ argv[0], @errorName(e) });
        return;
    };
    defer w.gpa.free(r.stdout);
    defer w.gpa.free(r.stderr);
    const last = lastLine(r.stdout);
    if (!r.term.success() or std.mem.indexOf(u8, last, "\"done\":true") == null) {
        w.fail(item, "{s}\n{s}", .{ tail(r.stdout, 2000), tail(r.stderr, 1000) });
        return;
    }
    w.pass(item);
}

fn runStore(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("vectors/lean-store", ".jsonl", {}, storeTrace);
}

test "lastLine" {
    try std.testing.expectEqualStrings("b", lastLine("a\nb\n"));
    try std.testing.expectEqualStrings("a", lastLine("a"));
}
