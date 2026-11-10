//! Stage 3 of the validator speed bench: the commit decision. Replays the DAGs Mysten's
//! consensus-core replayed (tools/truth/val-bench/consensus/zui_val_bench.rs writes
//! `consensus/val-bench/<case>.vec` in the committer-vectors format) round by round through deepwave's
//! Core (BlockManager, DagState, pipelined UniversalCommitter, Linearizer, CommitFinalizer), times
//! each round, and checks against Rust's lines for the same round every linearized commit (index,
//! digest, leader, timestamp, sub-dag block order) and every commit the CommitFinalizer released
//! (index, digest, rejected transactions by block). Blocks are decoded before the clock starts.
//! The final lines matter: the commit lines do not depend on the finalizer at all, so a finalizer
//! that released commits late or with the wrong rejected transactions passed this stage while it
//! compared commit lines only.
const std = @import("std");
const harness = @import("harness");
const consensus = @import("consensus");
const common = @import("common.zig");

const Allocator = std.mem.Allocator;
const types = consensus.types;

pub const cases = [_][]const u8{ "n4", "n10", "n100", "n10-timeouts", "n100-timeouts" };

const Step = struct {
    blocks: []types.VerifiedBlock,
    /// Rust's commit lines for this round (the Linearizer's sub-dags).
    want: []const []const u8,
    /// Rust's final lines for this round (the commits its CommitFinalizer released, with their
    /// rejected transactions).
    want_final: []const []const u8,
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

const Vector = struct {
    steps: []Step,
    stakes: []u64,
    gc_depth: u32,
    shuffle: bool,
    leaders: usize,
    genesis: []const [32]u8,
    nblocks: usize,
};

/// Parses one case file (`scenario`, `genesis`, then per round `block`.. `step` `commit`..
/// `final`.., `end`). Everything is allocated from `a`.
fn parseVector(a: Allocator, text: []const u8) !Vector {
    var lines = std.mem.splitScalar(u8, text, '\n');
    var steps: std.ArrayList(Step) = .empty;
    var pending: std.ArrayList(types.VerifiedBlock) = .empty;
    var want: std.ArrayList([]const u8) = .empty;
    var want_final: std.ArrayList([]const u8) = .empty;
    var v: Vector = .{ .steps = &.{}, .stakes = &.{}, .gc_depth = 0, .shuffle = false, .leaders = 1, .genesis = &.{}, .nblocks = 0 };
    var genesis: std.ArrayList([32]u8) = .empty;
    var in_step = false;
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "scenario")) {
            _ = it.next();
            const n = try std.fmt.parseInt(usize, it.next() orelse return error.BadVector, 10);
            v.gc_depth = try std.fmt.parseInt(u32, it.next() orelse return error.BadVector, 10);
            v.shuffle = (try std.fmt.parseInt(u8, it.next() orelse return error.BadVector, 10)) != 0;
            v.leaders = try std.fmt.parseInt(usize, it.next() orelse return error.BadVector, 10);
            v.stakes = try parseStakes(a, it.next(), n);
        } else if (std.mem.eql(u8, kind, "genesis")) {
            var g: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&g, it.next() orelse return error.BadVector);
            try genesis.append(a, g);
        } else if (std.mem.eql(u8, kind, "block")) {
            if (in_step) {
                try steps.append(a, .{ .blocks = pending.items, .want = want.items, .want_final = want_final.items });
                pending = .empty;
                want = .empty;
                want_final = .empty;
                in_step = false;
            }
            const bytes = try unhex(a, it.next() orelse return error.BadVector);
            try pending.append(a, try consensus.digest.decodeVerifiedUnchecked(a, bytes));
            v.nblocks += 1;
        } else if (std.mem.eql(u8, kind, "step")) {
            in_step = true;
        } else if (std.mem.eql(u8, kind, "commit")) {
            try want.append(a, line);
        } else if (std.mem.eql(u8, kind, "final")) {
            try want_final.append(a, line);
        } else if (std.mem.eql(u8, kind, "end")) {
            if (in_step) try steps.append(a, .{ .blocks = pending.items, .want = want.items, .want_final = want_final.items });
            in_step = false;
        }
    }
    v.steps = steps.items;
    v.genesis = genesis.items;
    return v;
}

const Outcome = struct {
    gen_ok: bool,
    commits: u64 = 0,
    finals: u64 = 0,
    commit_diffs: usize = 0,
    final_diffs: usize = 0,
    /// Most commits the finalizer released in one round.
    max_step_finals: usize = 0,
    /// Lanes the finalizer's indirect pass ran on (1: inline).
    lanes: usize = 1,
    /// The finalizer's other switches as this run had them (the environment's, see
    /// commit_finalizer.zig `switchesFromEnv`), and the rehash-after-eviction switch.
    walk: consensus.commit_finalizer.Walk = .reference,
    share_blocks: bool = false,
    rehash: bool = false,
    /// Per-round wall time.
    times: []u64,
    /// The commit lines and the final lines deepwave wrote.
    commit_text: []const u8,
    final_text: []const u8,
};

/// Replays the rounds through a fresh Core and compares deepwave's commit and final lines with the
/// vector's, round by round. `ctx` (null in unit tests) is told the first differing lines.
fn replayVector(gpa: Allocator, a: Allocator, io: std.Io, v: *const Vector, name: []const u8, ctx: ?*harness.Ctx) !Outcome {
    const fx = try consensus.test_dag.Fixture.init(gpa, .{
        .stakes = v.stakes,
        .own_index = null,
        .mode = .round_robin_test,
        .protocol = .{ .gc_depth = v.gc_depth, .transaction_voting_enabled = true, .num_leaders_per_round = v.leaders, .bad_nodes_stake_threshold = 30, .shuffle_commit_blocks = v.shuffle },
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

    var o: Outcome = .{ .gen_ok = v.genesis.len == fx.dag.genesis.len, .times = try a.alloc(u64, v.steps.len), .commit_text = "", .final_text = "" };
    if (o.gen_ok) for (fx.dag.genesis, v.genesis) |g, w| {
        o.gen_ok = o.gen_ok and std.mem.eql(u8, &g.digest, &w);
    };
    o.lanes = fin.lanesInUse();
    o.walk = fin.sw.walk;
    o.share_blocks = fin.sw.share_blocks;
    o.rehash = consensus.store.rehashOnEvict();

    // timed replay
    var mine: std.Io.Writer.Allocating = .init(a);
    var mine_final: std.Io.Writer.Allocating = .init(a);
    for (v.steps, o.times, 0..) |st, *t, k| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        var out: consensus.core.Output = .{ .record_linearized = true };
        const t0 = common.now(io);
        for (st.blocks) |*b| try tracker.addVotedBlock(b, &.{});
        try core.addBlocks(scratch.allocator(), st.blocks, &out);
        t.* = common.since(io, t0);
        defer for (out.committed.items) |*f| f.deinit();
        const got = out.linearized.items;
        o.commits += got.len;
        for (0..@max(got.len, st.want.len)) |i| {
            const g: []const u8 = if (i < got.len) try commitLine(a, &got[i]) else "<none>";
            const w: []const u8 = if (i < st.want.len) st.want[i] else "<none>";
            if (i < got.len) {
                try mine.writer.writeAll(g);
                try mine.writer.writeByte('\n');
            }
            if (!std.mem.eql(u8, g, w)) {
                o.commit_diffs += 1;
                if (ctx) |c| if (o.commit_diffs <= 4) c.detail("DIFF commit {s} round-step {d}\n  rust: {s}\n  zui:  {s}\n", .{ name, k + 1, w[0..@min(w.len, 300)], g[0..@min(g.len, 300)] });
            }
        }
        // The commits the finalizer released in this round, against Rust's finalizer's.
        const fins = out.committed.items;
        o.finals += fins.len;
        o.max_step_finals = @max(o.max_step_finals, fins.len);
        for (0..@max(fins.len, st.want_final.len)) |i| {
            const g: []const u8 = if (i < fins.len) try finalLine(a, &fins[i].sub_dag) else "<none>";
            const w: []const u8 = if (i < st.want_final.len) st.want_final[i] else "<none>";
            if (i < fins.len) {
                try mine_final.writer.writeAll(g);
                try mine_final.writer.writeByte('\n');
            }
            if (!std.mem.eql(u8, g, w)) {
                o.final_diffs += 1;
                if (ctx) |c| if (o.final_diffs <= 4) c.detail("DIFF final {s} round-step {d}\n  rust: {s}\n  zui:  {s}\n", .{ name, k + 1, w[0..@min(w.len, 300)], g[0..@min(g.len, 300)] });
            }
        }
    }
    o.commit_text = mine.written();
    o.final_text = mine_final.written();
    return o;
}

fn finalLine(a: Allocator, s: *const types.CommittedSubDag) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(a);
    try consensus.gen_dag.finalLine(&w.writer, s);
    return w.written();
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
    const v = try parseVector(a, text);
    const o = try replayVector(gpa, a, ctx.io, &v, name, ctx);

    const wall = blk: {
        var s: u64 = 0;
        for (o.times) |x| s += x;
        break :blk s;
    };
    const dg = common.digestHex(o.commit_text);
    const extra = try rowExtra(a, &o, v.nblocks, wall);
    common.emit(ctx, .{ .stage = "commit", .case = name, .mode = "replay", .threads = 1, .unit = "round", .items = o.times, .count = v.steps.len, .wall_ns = wall, .out = &dg, .extra = extra });
    if (!o.gen_ok) {
        ctx.fail(name, "genesis digests differ from Rust", .{});
    } else if (o.commit_diffs != 0) {
        ctx.fail(name, "{d} commit lines differ from Rust ({d} commits)", .{ o.commit_diffs, o.commits });
    } else if (o.final_diffs != 0) {
        ctx.fail(name, "{d} final lines differ from Rust ({d} finalized commits)", .{ o.final_diffs, o.finals });
    } else ctx.pass(name);
}

/// The commit row's own fields. `out` stays the digest of the commit lines (what the Rust row
/// carries); the final lines have their own. `threads` stays 1, the driver thread, as in the Rust
/// row the merge pairs this one with (Rust runs its indirect pass on tokio's blocking pool under
/// the same 1); `lanes` is what the finalizer's indirect pass really ran on, and `walk`,
/// `share_blocks` and `rehash` are the other switches of the run: a row that was meant to
/// measure a switch and ran without it shows the default here.
fn rowExtra(a: Allocator, o: *const Outcome, nblocks: usize, wall: u64) ![]u8 {
    const dgf = common.digestHex(o.final_text);
    return std.fmt.allocPrint(a, ",\"commits\":{d},\"blocks\":{d},\"ns_per_commit\":{d:.1},\"commits_per_s\":{d:.1},\"finals\":{d},\"max_step_finals\":{d},\"out_final\":\"{s}\",\"lanes\":{d},\"walk\":\"{s}\",\"share_blocks\":{d},\"rehash\":{d}", .{
        o.commits,                                                                  nblocks,
        @as(f64, @floatFromInt(wall)) / @as(f64, @floatFromInt(@max(o.commits, 1))), @as(f64, @floatFromInt(o.commits)) * 1e9 / @as(f64, @floatFromInt(@max(wall, 1))),
        o.finals,                                                                   o.max_step_finals,
        &dgf,                                                                       o.lanes,
        @tagName(o.walk),                                                           @intFromBool(o.share_blocks),
        @intFromBool(o.rehash),
    });
}

test "commit row names the finalizer's switches next to lanes: walk, share_blocks, rehash" {
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var o: Outcome = .{ .gen_ok = true, .times = &.{}, .commit_text = "", .final_text = "", .commits = 10, .finals = 9 };
    const off = try rowExtra(a, &o, 40, 1000);
    try std.testing.expect(std.mem.endsWith(u8, off, ",\"lanes\":1,\"walk\":\"reference\",\"share_blocks\":0,\"rehash\":0"));
    o.lanes = 4;
    o.walk = .dense;
    o.share_blocks = true;
    o.rehash = true;
    const on = try rowExtra(a, &o, 40, 1000);
    try std.testing.expect(std.mem.endsWith(u8, on, ",\"lanes\":4,\"walk\":\"dense\",\"share_blocks\":1,\"rehash\":1"));
    // the row stays one JSON object when appended to the common fields
    const row = try std.fmt.allocPrint(a, "{{\"stage\":\"commit\"{s}}}", .{on});
    const parsed = try std.json.parseFromSliceLeaky(std.json.Value, a, row, .{});
    try std.testing.expectEqualStrings("dense", parsed.object.get("walk").?.string);
    try std.testing.expectEqual(@as(i64, 4), parsed.object.get("lanes").?.integer);
}

test "commit stage compares the final lines: a burst of 20 or more commits finalized in one round passes, a changed final line fails" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const gen_dag = consensus.gen_dag;
    // A generated n=10 DAG with timeouts in the vector format the Rust tool writes, with the
    // lines of the finalizer whose output the replay vectors prove against Mysten.
    const c = &gen_dag.cases[gen_dag.burst_case];
    const committee = try gen_dag.committeeOf(a, c);
    var stats: gen_dag.Stats = .{};
    const text = try gen_dag.vectorText(gpa, c.name, &committee, &c.gen, &stats);
    defer gpa.free(text);
    try std.testing.expect(stats.max_step_finals >= 20);
    try std.testing.expect(stats.finals_with_rejects > 0);

    const v = try parseVector(a, text);
    const o = try replayVector(gpa, a, std.testing.io, &v, c.name, null);
    try std.testing.expect(o.gen_ok);
    try std.testing.expectEqual(@as(usize, 0), o.commit_diffs);
    try std.testing.expectEqual(@as(usize, 0), o.final_diffs);
    try std.testing.expectEqual(@as(u64, stats.finals), o.finals);
    try std.testing.expect(o.max_step_finals >= 20);

    // 1. One rejected index changed in one final line of the burst round: only the final
    // comparison can see it.
    // 2. One final line moved to the next round (a commit finalized one round late).
    var burst_step: usize = 0;
    for (v.steps, 0..) |st, k| {
        if (st.want_final.len >= 20) burst_step = k;
    }
    try std.testing.expect(v.steps[burst_step].want_final.len >= 20);
    {
        const changed = try a.dupe([]const u8, v.steps[burst_step].want_final);
        var hit: ?usize = null;
        for (changed, 0..) |l, i| {
            if (std.mem.indexOfScalar(u8, l, ':') != null) hit = i;
        }
        // a final line of the burst with rejected transactions, else the first with an index added
        const i = hit orelse 0;
        const zero_ref: [40]u8 = @splat(0);
        changed[i] = if (hit != null) try std.fmt.allocPrint(a, "{s},65535", .{changed[i]}) else try std.fmt.allocPrint(a, "{s} {x}:0", .{ changed[i], &zero_ref });
        var v2 = v;
        v2.steps = try a.dupe(Step, v.steps);
        v2.steps[burst_step].want_final = changed;
        const o2 = try replayVector(gpa, a, std.testing.io, &v2, c.name, null);
        try std.testing.expectEqual(@as(usize, 0), o2.commit_diffs);
        try std.testing.expectEqual(@as(usize, 1), o2.final_diffs);
    }
    {
        try std.testing.expect(burst_step + 1 < v.steps.len);
        var v3 = v;
        v3.steps = try a.dupe(Step, v.steps);
        const here = v.steps[burst_step].want_final;
        const next = v.steps[burst_step + 1].want_final;
        v3.steps[burst_step].want_final = here[0 .. here.len - 1];
        v3.steps[burst_step + 1].want_final = try std.mem.concat(a, []const u8, &.{ here[here.len - 1 ..], next });
        const o3 = try replayVector(gpa, a, std.testing.io, &v3, c.name, null);
        try std.testing.expectEqual(@as(usize, 0), o3.commit_diffs);
        try std.testing.expect(o3.final_diffs >= 2);
    }
}
