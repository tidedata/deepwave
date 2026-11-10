//! Conformance suite of the node lane (CONTRACTS.md section 6.7).
//!
//!   node-convert   every archive proto in `binpb-done/<seq>.binpb.zst` (Mysten's checkpoint
//!                  archive, the same message a node's GetCheckpoint returns with the full mask)
//!                  converted by `convert.protoToChk` equals `chk/<seq>.chk`, which
//!                  `zui-dumper convert` made with sui-types (`Checkpoint -> CheckpointData`).
//!                  One item per proto, compared byte for byte.
//!
//!   node-execute   deepwave itself (`Node`, execute mode, fresh store) over the longest
//!                  contiguous run of `binpb-done/` (Mysten's archive protos: blob plus archive
//!                  record): every checkpoint verified and applied, every transaction exec runs
//!                  compared with the certified effects, events and output objects byte for byte.
//!                  Inputs a node operator would give: `packages/` (--packages), `deny/` (exec's
//!                  deny-list state, --deny-state), system packages from `chk/` (--trust-dir).
//!                  Items are the executed transactions (an exec error is a failure). Verify-only
//!                  transactions are not items; their count and reasons are printed, and one
//!                  extra item, `coverage`, fails when they exceed `max_verify_only` (the floor this
//!                  suite last reached), so a change that quietly stops executing shows up too.
const std = @import("std");
const harness = @import("harness");
const convert = @import("convert.zig");
const node_mod = @import("node.zig");
const execute = @import("execute.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "node-convert",
        .lane = "node",
        .doc = "archive proto (sui.rpc.v2 Checkpoint) to checkpoint blob equals sui-types Checkpoint -> CheckpointData (zui-dumper convert), byte for byte",
        .run = runConvert,
        .bench = benchConvert,
        .baselines = &.{.{ .name = "convert", .argv = &.{ "{dumper}", "bench", "convert" } }},
        .inputs = .{ .dir = "binpb-done", .suffix = ".binpb.zst" },
    },
    .{
        .name = "node-execute",
        .lane = "node",
        .doc = "deepwave in execute mode over the longest contiguous binpb-done window from a fresh store: every executed transaction's effects, events and output objects equal the certified ones byte for byte; verify-only count at or under the recorded floor",
        .run = runExecute,
    },
    .{
        .name = "node-dst",
        .lane = "node",
        .doc = "deterministic simulation of the node's follow pipeline (virtual time, faulty sources and disk, crashes): never accepts a bad checkpoint, never loses a committed one, always converges, replays bit for bit",
        .run = @import("dst_conformance.zig").run,
    },
    .{ .name = "sig-order", .lane = "node", .doc = "every corpus sponsored or multi-signer transaction: V2 contents certify required_signers order (sender, gas owner), and the sweep's reorder (and the ingest overlay rule) takes exactly a permutation of the certified signatures, keeping TransactionData and the digest", .run = @import("conformance_sigorder.zig").run },
    .{ .name = "rpc-policy", .lane = "rpc-surface", .doc = "transaction-deny-config denials (Execute, Simulate), admin GET /transaction-deny-config and POST /traffic-control, and traffic-controller answers equal sui-node 1.83.1's (src/serve/vectors/rpc-surface/{deny,traffic})", .run = @import("conformance_policy.zig").run },
};

/// Verify-only transactions allowed over the full window (342446161..342456160): the floor this
/// suite reached (node round 3, 2026-11-08: 41 settlements and 1 other transaction whose
/// unchanged child object predates the window, which a store started mid-epoch without a snapshot
/// cannot hold). Lower it as exec or the node cover more; never raise it to pass.
pub const max_verify_only: u64 = 42;

const Tally = struct {
    ctx: *harness.Ctx,
    buf: [64]u8 = undefined,
    verify_only: u64 = 0,
    whys: std.StringArrayHashMapUnmanaged(u64) = .empty,
    arena: std.heap.ArenaAllocator,

    fn report(p: *anyopaque, seq: u64, tx: u32, v: execute.Verdict, why: []const u8) void {
        const t: *Tally = @ptrCast(@alignCast(p));
        const id = if (tx == std.math.maxInt(u32)) std.fmt.bufPrint(&t.buf, "{d}", .{seq}) catch "?" else std.fmt.bufPrint(&t.buf, "{d}/tx[{d}]", .{ seq, tx }) catch "?";
        if (!t.ctx.selected(id)) return;
        switch (v) {
            .match => t.ctx.pass(id),
            .mismatch => t.ctx.fail(id, "{s}", .{why}),
            .verify_only => {
                t.verify_only += 1;
                const a = t.arena.allocator();
                const gop = t.whys.getOrPut(a, why) catch return;
                if (!gop.found_existing) {
                    gop.key_ptr.* = a.dupe(u8, why) catch "?";
                    gop.value_ptr.* = 0;
                }
                gop.value_ptr.* += 1;
            },
        }
    }
};

fn runExecute(ctx: *harness.Ctx) !void {
    const a = ctx.scratch();
    // The longest contiguous run of archive protos.
    var seqs: std.ArrayList(u64) = .empty;
    var dir = try ctx.corpus.openDir(ctx.io, "binpb-done", .{ .iterate = true });
    defer dir.close(ctx.io);
    var it = dir.iterate();
    while (try it.next(ctx.io)) |e| {
        if (!std.mem.endsWith(u8, e.name, ".binpb.zst")) continue;
        try seqs.append(a, std.fmt.parseInt(u64, e.name[0 .. e.name.len - ".binpb.zst".len], 10) catch continue);
    }
    if (seqs.items.len == 0) return ctx.fail("window", "no binpb-done protos", .{});
    std.mem.sort(u64, seqs.items, {}, std.sort.asc(u64));
    var best_lo: u64 = seqs.items[0];
    var best_n: u64 = 1;
    var lo: u64 = seqs.items[0];
    var n: u64 = 1;
    for (seqs.items[1..], 0..) |q, i| {
        if (q == seqs.items[i] + 1) n += 1 else {
            lo = q;
            n = 1;
        }
        if (n > best_n) {
            best_n = n;
            best_lo = lo;
        }
    }
    // -Dlimit=N: the first N checkpoints of the window (a smoke run never counts as done).
    const count = if (ctx.opts.limit) |l| @min(best_n, @max(l, 1)) else best_n;
    const to = best_lo + count - 1;

    const tmp_root = std.c.getenv("TMPDIR");
    const tmp = if (tmp_root) |t| std.mem.trimEnd(u8, std.mem.span(t), "/") else "/tmp";
    const work = try std.fmt.allocPrint(a, "{s}/deepwave-execute-{d}", .{ tmp, std.c.getpid() });
    std.Io.Dir.cwd().deleteTree(ctx.io, work) catch {};
    defer std.Io.Dir.cwd().deleteTree(ctx.io, work) catch {};
    const cp = ctx.corpus_path;
    var tally: Tally = .{ .ctx = ctx, .arena = .init(ctx.gpa) };
    defer tally.arena.deinit();
    const cfg: node_mod.Config = .{
        .dir = work,
        .mode = .execute,
        .source = .{ .dir = try std.fmt.allocPrint(a, "{s}/binpb-done", .{cp}) },
        .trust_dir = try std.fmt.allocPrint(a, "{s}/chk", .{cp}),
        .genesis = try std.fmt.allocPrint(a, "{s}/vectors/bls-cert/upstream/genesis.blob", .{cp}),
        .epochs_index = try std.fmt.allocPrint(a, "{s}/epochs.jsonl", .{cp}),
        .start = .{ .seq = best_lo },
        .to = to,
        .halt_on_mismatch = false,
        .status_every_s = 30,
        .sync_mode = .none,
        .read_sets = false,
        .packages_dir = try std.fmt.allocPrint(a, "{s}/packages", .{cp}),
        .deny_state = try std.fmt.allocPrint(a, "{s}/deny/objects.bin.zst", .{cp}),
        .report = .{ .ctx = &tally, .f = Tally.report },
    };
    std.log.info("node-execute: checkpoints {d}..{d} ({d} of a {d}-checkpoint window) in {s}", .{ best_lo, to, count, best_n, work });
    const nd = try node_mod.Node.init(ctx.gpa, ctx.io, cfg);
    defer nd.deinit();
    nd.run() catch |e| {
        ctx.fail("run", "node stopped: {s}", .{@errorName(e)});
    };
    const applied = nd.follower.applied_next.load(.acquire);
    if (applied != to + 1) ctx.fail("run", "applied up to {d}, window ends at {d}", .{ applied -| 1, to });
    var w = ctx.stderr;
    w.print("node-execute: {d} verify-only transactions (floor {d})\n", .{ tally.verify_only, max_verify_only }) catch {};
    for (tally.whys.keys(), tally.whys.values()) |k, v| w.print("  verify-only {d}: {s}\n", .{ v, k }) catch {};
    w.flush() catch {};
    if (ctx.opts.limit == null) {
        if (tally.verify_only > max_verify_only) ctx.fail("coverage", "{d} verify-only transactions, floor {d}", .{ tally.verify_only, max_verify_only }) else ctx.pass("coverage");
    }
}

const max_blob = 1 << 30;

fn runConvert(ctx: *harness.Ctx) !void {
    try ctx.forEachFile("binpb-done", ".binpb.zst", {}, convertOne);
}

fn convertOne(_: void, ctx: *harness.Ctx, name: []const u8) !void {
    const seq_text = name[0 .. name.len - ".binpb.zst".len];
    if (!ctx.selected(seq_text)) return;
    const arena = ctx.scratch();
    const proto = ctx.readZstd(try std.fmt.allocPrint(arena, "binpb-done/{s}", .{name}), max_blob) catch |e| {
        return ctx.fail(seq_text, "read proto: {s}", .{@errorName(e)});
    };
    // The truth blob: `chk/` (the corpus checkpoint set, which the other suites iterate) or
    // `chk-extra/` (protos fetched into binpb-done outside that set, converted by `zui-dumper
    // convert`). A proto with neither is a corpus gap and fails: no truth is not a pass.
    const want = ctx.readFile(try std.fmt.allocPrint(arena, "chk/{s}.chk", .{seq_text}), max_blob) catch |e| switch (e) {
        error.FileNotFound => ctx.readFile(try std.fmt.allocPrint(arena, "chk-extra/{s}.chk", .{seq_text}), max_blob) catch |e2| {
            return ctx.fail(seq_text, "read truth (chk/ and chk-extra/): {s}", .{@errorName(e2)});
        },
        else => return ctx.fail(seq_text, "read chk: {s}", .{@errorName(e)}),
    };
    var out: std.ArrayList(u8) = .empty;
    const seq = convert.protoToChk(arena, arena, proto, &out) catch |e| {
        return ctx.fail(seq_text, "convert: {s}", .{@errorName(e)});
    };
    const name_seq = std.fmt.parseInt(u64, seq_text, 10) catch return ctx.fail(seq_text, "file name", .{});
    if (seq != name_seq) return ctx.fail(seq_text, "summary sequence {d}", .{seq});
    _ = ctx.expectBytes(seq_text, "blob", want, out.items);
}

const BenchState = struct { protos: []const []const u8, bytes: u64 };

/// Conversion throughput on the bench inputs (protos decompressed outside the timed region).
fn benchConvert(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var protos: std.ArrayList([]const u8) = .empty;
    var bytes: u64 = 0;
    for (ctx.benchInputs()) |name| {
        const z = try ctx.corpus.readFileAlloc(ctx.io, name, arena, .limited(max_blob));
        const p = try convert.unzstd(arena, z, max_blob);
        bytes += p.len;
        try protos.append(arena, p);
    }
    const S = struct {
        fn pass(st: *const BenchState) !void {
            var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer scratch.deinit();
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(std.heap.page_allocator);
            for (st.protos) |p| {
                _ = scratch.reset(.retain_capacity);
                _ = try convert.protoToChk(std.heap.page_allocator, scratch.allocator(), p, &out);
                std.mem.doNotOptimizeAway(out.items.ptr);
            }
        }
    };
    const st: BenchState = .{ .protos = protos.items, .bytes = bytes };
    try ctx.benchPasses("convert", "checkpoint", protos.items.len, &st, S.pass);
}
