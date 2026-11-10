//! Stage 3 of the validator speed bench: the commit decision. Replays the DAGs Mysten's
//! consensus-core replayed (tools/truth/val-bench/consensus/zui_val_bench.rs writes
//! `consensus/val-bench/<case>.vec` in the committer-vectors format) round by round through deepwave's
//! Core (BlockManager, DagState, pipelined UniversalCommitter, Linearizer, CommitFinalizer), times
//! each round, and checks every linearized commit (index, digest, leader, timestamp, sub-dag block
//! order) against Rust's line for the same round. Blocks are decoded before the clock starts.
const std = @import("std");
const harness = @import("harness");
const consensus = @import("consensus");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
const types = consensus.types;

pub const cases = [_][]const u8{ "n4", "n10", "n100", "n10-timeouts", "n100-timeouts" };

const Step = struct {
    blocks: []types.VerifiedBlock,
    /// Rust's commit lines for this round.
    want: []const []const u8,
};

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn parseStakes(a: Allocator, csv: ?[]const u8, n: usize) ![]u64 {
    const out = try a.alloc(u64, n);
    if (csv) |c| {
        var it = std.mem.splitScalar(u8, c, ',');
        for (out) |*o| o.* = try std.fmt.parseInt(u64, it.next() orelse return error.BadVector, 10);
    } else @memset(out, 1);
    return out;
}

fn commitLine(a: Allocator, s: *const types.CommittedSubDag) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(a);
    try w.writer.print("commit {d} {x} {d} {d} {d} {d}", .{ s.commit_ref.index, &s.commit_ref.digest, s.leader.round, s.leader.author, s.timestamp_ms, s.blocks.len });
    for (s.blocks) |b| try w.writer.print(" {x}", .{&b.digest});
    return w.written();
}

pub fn run(ctx: *harness.Ctx) anyerror!void {
    for (cases) |name| {
        if (!ctx.selected(name)) continue;
        try runCase(ctx, name);
    }
}

fn runCase(ctx: *harness.Ctx, name: []const u8) !void {
    const gpa = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const path = try std.fmt.allocPrint(a, "consensus/val-bench/{s}.vec", .{name});
    const text = ctx.corpus.readFileAlloc(ctx.io, path, a, .limited(8 << 30)) catch |e| {
        ctx.fail(name, "read {s}: {s}", .{ path, @errorName(e) });
        return;
    };

    // parse (untimed)
    var lines = std.mem.splitScalar(u8, text, '\n');
    var steps: std.ArrayList(Step) = .empty;
    var pending: std.ArrayList(types.VerifiedBlock) = .empty;
    var want: std.ArrayList([]const u8) = .empty;
    var stakes: []u64 = &.{};
    var gc_depth: u32 = 0;
    var shuffle = false;
    var leaders: usize = 1;
    var genesis: std.ArrayList([32]u8) = .empty;
    var in_step = false;
    var nblocks: usize = 0;
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "scenario")) {
            _ = it.next();
            const n = try std.fmt.parseInt(usize, it.next().?, 10);
            gc_depth = try std.fmt.parseInt(u32, it.next().?, 10);
            shuffle = (try std.fmt.parseInt(u8, it.next().?, 10)) != 0;
            leaders = try std.fmt.parseInt(usize, it.next().?, 10);
            stakes = try parseStakes(a, it.next(), n);
        } else if (std.mem.eql(u8, kind, "genesis")) {
            var g: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&g, it.next().?);
            try genesis.append(a, g);
        } else if (std.mem.eql(u8, kind, "block")) {
            if (in_step) {
                try steps.append(a, .{ .blocks = pending.items, .want = want.items });
                pending = .empty;
                want = .empty;
                in_step = false;
            }
            const bytes = try unhex(a, it.next().?);
            try pending.append(a, try consensus.digest.decodeVerifiedUnchecked(a, bytes));
            nblocks += 1;
        } else if (std.mem.eql(u8, kind, "step")) {
            in_step = true;
        } else if (std.mem.eql(u8, kind, "commit")) {
            try want.append(a, line);
        } else if (std.mem.eql(u8, kind, "end")) {
            if (in_step) try steps.append(a, .{ .blocks = pending.items, .want = want.items });
            in_step = false;
        }
    }

    const fx = try consensus.test_dag.Fixture.init(gpa, .{
        .stakes = stakes,
        .own_index = null,
        .mode = .round_robin_test,
        .protocol = .{ .gc_depth = gc_depth, .transaction_voting_enabled = true, .num_leaders_per_round = leaders, .bad_nodes_stake_threshold = 30, .shuffle_commit_blocks = shuffle },
        .parameters = .{ .skip_equivocation_validation = true },
    });
    defer fx.deinit();
    var noop: consensus.verifier.NoopTransactionVerifier = .{};
    var tracker = consensus.transaction_vote_tracker.TransactionVoteTracker.init(gpa, fx.context, fx.dag, noop.verifier());
    defer tracker.deinit();
    var fin = consensus.commit_finalizer.CommitFinalizer.init(gpa, fx.context, fx.dag, &tracker);
    defer fin.deinit();
    var rec_out: consensus.core.Output = .{};
    var core = try consensus.core.Core.recover(gpa, a, .{ .context = fx.context, .dag = fx.dag, .schedule = fx.schedule, .tracker = &tracker, .finalizer = &fin }, &rec_out);
    defer core.deinit();

    var gen_ok = genesis.items.len == fx.dag.genesis.len;
    if (gen_ok) for (fx.dag.genesis, genesis.items) |g, w| {
        gen_ok = gen_ok and std.mem.eql(u8, &g.digest, &w);
    };

    // timed replay
    const times = try a.alloc(u64, steps.items.len);
    var mine: std.Io.Writer.Allocating = .init(a);
    var commits: u64 = 0;
    var diffs: usize = 0;
    for (steps.items, times, 0..) |st, *t, k| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        var out: consensus.core.Output = .{ .record_linearized = true };
        const t0 = common.now(ctx.io);
        for (st.blocks) |*b| try tracker.addVotedBlock(b, &.{});
        try core.addBlocks(scratch.allocator(), st.blocks, &out);
        t.* = common.since(ctx.io, t0);
        defer for (out.committed.items) |*f| f.deinit();
        const got = out.linearized.items;
        commits += got.len;
        const n = @max(got.len, st.want.len);
        for (0..n) |i| {
            const g: []const u8 = if (i < got.len) try commitLine(a, &got[i]) else "<none>";
            const w: []const u8 = if (i < st.want.len) st.want[i] else "<none>";
            if (i < got.len) {
                try mine.writer.writeAll(g);
                try mine.writer.writeByte('\n');
            }
            if (!std.mem.eql(u8, g, w)) {
                diffs += 1;
                if (diffs <= 4) ctx.detail("DIFF commit {s} round-step {d}\n  rust: {s}\n  zui:  {s}\n", .{ name, k + 1, w[0..@min(w.len, 300)], g[0..@min(g.len, 300)] });
            }
        }
    }
    const wall = blk: {
        var s: u64 = 0;
        for (times) |x| s += x;
        break :blk s;
    };
    const dg = common.digestHex(mine.written());
    const extra = try std.fmt.allocPrint(a, ",\"commits\":{d},\"blocks\":{d},\"ns_per_commit\":{d:.1},\"commits_per_s\":{d:.1}", .{
        commits,                                                                  nblocks,
        @as(f64, @floatFromInt(wall)) / @as(f64, @floatFromInt(@max(commits, 1))), @as(f64, @floatFromInt(commits)) * 1e9 / @as(f64, @floatFromInt(@max(wall, 1))),
    });
    common.emit(ctx, .{ .stage = "commit", .case = name, .mode = "replay", .threads = 1, .unit = "round", .items = times, .count = steps.items.len, .wall_ns = wall, .out = &dg, .extra = extra });
    if (!gen_ok) {
        ctx.fail(name, "genesis digests differ from Rust", .{});
    } else if (diffs != 0) {
        ctx.fail(name, "{d} commit lines differ from Rust ({d} commits)", .{ diffs, commits });
    } else ctx.pass(name);
}
