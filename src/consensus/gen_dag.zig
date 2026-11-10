//! Test and bench support for the commit path. Three pieces:
//!
//! - `genDag`: a Zig port of the validator speed bench's DAG generator (`gen_dag` in
//!   tools/truth/val-bench/consensus/zui_val_bench.rs). Same rules (own previous block first, then
//!   random parents until a quorum of stake, the previous round's round-robin leader first with a
//!   given probability, weak links, payloads with reject votes), so the same shape: at n=100 with
//!   mainnet-like stakes commits arrive in bursts of tens per step. It is not the same DAG as
//!   Rust's: the random stream is seeded differently from `StdRng::seed_from_u64`.
//! - `replay`: pushes blocks step by step through deepwave's Core and CommitFinalizer and writes what
//!   the Rust tools write: one `commit` line per linearized sub-dag and one `final` line per
//!   finalized commit with its rejected transactions.
//! - `parseVectors`: reads the scenarios of Mysten's committer vectors (`consensus/replay.vec`,
//!   tools/truth/consensus/committer-vectors) with the commit and final lines Mysten wrote.
//!
//! What each proves. A generated DAG compares deepwave with deepwave: the finalizer with every switch off
//! (the path the replay conformance suite proves against Mysten) against the same finalizer with
//! switches on, and against outputs pinned when the lane started. The vectors compare deepwave with
//! Mysten, final lines included, under any switch setting.
//!
//! Why final lines and why switches off first. The val-bench compared commit lines only, and a
//! change to the finalizer (e272188b, reverted on the train by 8089b88d) passed it while applying
//! the results of the indirect walk to the wrong blocks: it iterated a slice of the
//! pending-transaction list while removing emptied entries from that same list, so every result
//! after the first emptied block went to its neighbour. Commit lines do not depend on the
//! finalizer; final lines do. Every case here must therefore show (through the finalizer's
//! counters) that it ran that shape: a pass where one pending block empties and a later one still
//! has results to apply.
//! Owner lane: val-consensus-core (commit-tail work). Not part of the node.
const std = @import("std");
const types = @import("types.zig");
const config = @import("config.zig");
const digest_mod = @import("digest.zig");
const store_mod = @import("store.zig");
const rand = @import("rand.zig");
const test_dag = @import("test_dag.zig");
const verifier_mod = @import("verifier.zig");
const tracker_mod = @import("transaction_vote_tracker.zig");
const commit_finalizer = @import("commit_finalizer.zig");
const core_mod = @import("core.zig");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------- generator

/// (authority, first round, last round), inclusive.
pub const Range = struct { authority: u32, first: types.Round, last: types.Round };

fn inRanges(r: []const Range, a: u32, round: types.Round) bool {
    for (r) |x| if (x.authority == a and round >= x.first and round <= x.last) return true;
    return false;
}

pub const Gen = struct {
    rounds: types.Round,
    seed: u64,
    leader_link_pct: u32 = 90,
    weak_link_pct: u32 = 5,
    /// No blocks from the authority in these rounds.
    offline: []const Range = &.{},
    /// Others do not link the authority's blocks of these rounds.
    ignored: []const Range = &.{},
    payload: bool = true,
    /// Transaction payload length range (Rust: 200..1200). Unit tests use short payloads.
    tx_len_min: u32 = 200,
    tx_len_max: u32 = 1200,
};

fn rngOf(seed: u64) rand.ChaCha12 {
    var s: [32]u8 = @splat(0);
    std.mem.writeInt(u64, s[0..8], seed, .little);
    s[8] = 0x5a;
    return rand.ChaCha12.fromSeed(s);
}

/// `mainnet_like_stakes`: decreasing stakes with noise, summing to 10,000.
pub fn mainnetLikeStakes(a: Allocator, n: usize) Allocator.Error![]u64 {
    var rng = rngOf(1304);
    const raw = try a.alloc(f64, n);
    defer a.free(raw);
    var total: f64 = 0;
    for (raw, 0..) |*x, i| {
        x.* = 1.0 / (1.0 + @as(f64, @floatFromInt(i)) * 0.08) + rng.nextF64() * 0.05;
        total += x.*;
    }
    const s = try a.alloc(u64, n);
    var sum: u64 = 0;
    for (s, raw) |*o, x| {
        o.* = @intFromFloat(@max(1.0, @floor(x / total * 10_000.0)));
        sum += o.*;
    }
    if (sum < 10_000) s[0] += 10_000 - sum;
    return s;
}

/// The generated DAG, one layer of blocks per round (round 1 first), allocated from `arena`.
/// `genesis` are the committee's genesis blocks in authority order.
pub fn genDag(arena: Allocator, g: *const Gen, stakes: []const u64, genesis: []const types.VerifiedBlock) ![][]types.VerifiedBlock {
    const n = stakes.len;
    var total: u64 = 0;
    for (stakes) |s| total += s;
    const quorum = total - (total - 1) / 3;
    var rng = rngOf(g.seed);

    const by_author = try arena.alloc(std.ArrayList(types.BlockRef), n);
    for (by_author, genesis) |*l, *gb| {
        l.* = .empty;
        try l.append(arena, gb.reference());
    }
    var ntx_of: std.HashMapUnmanaged(types.BlockRef, usize, store_mod.RefContext, 80) = .empty;
    const layers = try arena.alloc([]types.VerifiedBlock, g.rounds);
    const chosen = try arena.alloc(bool, n);
    const others = try arena.alloc(usize, n);
    const new_refs = try arena.alloc(?types.BlockRef, n);

    var r: types.Round = 1;
    while (r <= g.rounds) : (r += 1) {
        const leader_prev: usize = @as(usize, r - 1) % n;
        var layer: std.ArrayList(types.VerifiedBlock) = .empty;
        @memset(new_refs, null);
        for (0..n) |a| {
            if (inRanges(g.offline, @intCast(a), r)) continue;
            var anc: std.ArrayList(types.BlockRef) = .empty;
            try anc.append(arena, by_author[a].items[by_author[a].items.len - 1]);
            var stake: u64 = if (anc.items[0].round == r - 1) stakes[a] else 0;
            @memset(chosen, false);
            chosen[a] = true;
            var no: usize = 0;
            for (0..n) |x| if (x != a) {
                others[no] = x;
                no += 1;
            };
            rng.shuffle(usize, others[0..no]);
            if (leader_prev != a and rng.genRangeU32(100) < g.leader_link_pct) {
                const at = std.mem.indexOfScalar(usize, others[0..no], leader_prev).?;
                std.mem.copyBackwards(usize, others[1 .. at + 1], others[0..at]);
                others[0] = leader_prev;
            }
            for (others[0..no], 0..) |o, k| {
                if (stake >= quorum and k > 0) break;
                // one block per author and round here, so there is one candidate at most
                const list = by_author[o].items;
                var i = list.len;
                while (i > 0) {
                    i -= 1;
                    const b = list[i];
                    if (b.round < r - 1) break;
                    if (b.round == r - 1 and !inRanges(g.ignored, @intCast(o), b.round)) {
                        try anc.append(arena, b);
                        chosen[o] = true;
                        stake += stakes[o];
                        break;
                    }
                }
            }
            if (stake < quorum) return error.NoParentQuorum;
            for (0..n) |o| {
                if (chosen[o] or rng.genRangeU32(100) >= g.weak_link_pct) continue;
                const list = by_author[o].items;
                var i = list.len;
                while (i > 0) {
                    i -= 1;
                    const b = list[i];
                    if (b.round < r and !inRanges(g.ignored, @intCast(o), b.round)) {
                        try anc.append(arena, b);
                        chosen[o] = true;
                        break;
                    }
                }
            }
            const ts = @as(u64, r) * 1000 + rng.genRangeU32(1000);
            var txs: []types.Transaction = &.{};
            var votes: std.ArrayList(types.BlockTransactionVotes) = .empty;
            var cvotes: []types.CommitVote = &.{};
            if (g.payload) {
                txs = try arena.alloc(types.Transaction, rng.genRangeU32(6));
                for (txs) |*t| {
                    const len = g.tx_len_min + rng.genRangeU32(@max(1, g.tx_len_max - g.tx_len_min));
                    const data = try arena.alloc(u8, len);
                    for (data) |*x| x.* = @truncate(rng.nextU32());
                    t.* = .{ .data = data };
                }
                for (anc.items[1..]) |b| {
                    const target_txs = ntx_of.get(b) orelse 0;
                    var rejects: [2]types.TransactionIndex = undefined;
                    var nr: usize = 0;
                    if (b.author == 1 and target_txs > 0 and b.round % 4 != 0) {
                        rejects[nr] = 0;
                        nr += 1;
                    }
                    if (target_txs > 0 and rng.genRangeU32(100) < 10) {
                        rejects[nr] = @intCast(rng.genRangeU32(@intCast(target_txs)));
                        nr += 1;
                    }
                    std.mem.sort(types.TransactionIndex, rejects[0..nr], {}, std.sort.asc(types.TransactionIndex));
                    if (nr == 2 and rejects[0] == rejects[1]) nr = 1;
                    if (nr > 0) try votes.append(arena, .{ .block_ref = b, .rejects = try arena.dupe(types.TransactionIndex, rejects[0..nr]) });
                }
                cvotes = try arena.alloc(types.CommitVote, rng.genRangeU32(2));
                for (cvotes) |*c| {
                    c.index = 1 + rng.genRangeU32(999);
                    for (&c.digest) |*x| x.* = @truncate(rng.nextU32());
                }
            }
            const block: types.Block = .{ .V2 = .{
                .epoch = 0,
                .round = r,
                .author = @intCast(a),
                .timestamp_ms = ts,
                .ancestors = anc.items,
                .transactions = txs,
                .transaction_votes = votes.items,
                .commit_votes = cvotes,
                .misbehavior_reports = &.{},
            } };
            const vb = try digest_mod.verifiedForTest(arena, block);
            try ntx_of.put(arena, vb.reference(), txs.len);
            new_refs[a] = vb.reference();
            try layer.append(arena, vb);
        }
        for (by_author, new_refs) |*l, nr| if (nr) |x| try l.append(arena, x);
        layers[r - 1] = layer.items;
    }
    return layers;
}

// ---------------------------------------------------------------- lines

/// `commit_line` of the Rust tools.
pub fn commitLine(w: *std.Io.Writer, s: *const types.CommittedSubDag) std.Io.Writer.Error!void {
    try w.print("commit {d} {x} {d} {d} {d} {d}", .{ s.commit_ref.index, &s.commit_ref.digest, s.leader.round, s.leader.author, s.timestamp_ms, s.blocks.len });
    for (s.blocks) |b| try w.print(" {x}", .{&b.digest});
}

/// `final_line` of the Rust tools: `final <index> <commit digest>` then, per block with rejected
/// transactions in block-ref order, ` <hex BCS(BlockRef)>:<indices csv>`.
pub fn finalLine(w: *std.Io.Writer, s: *const types.CommittedSubDag) std.Io.Writer.Error!void {
    try w.print("final {d} {x}", .{ s.commit_ref.index, &s.commit_ref.digest });
    for (s.rejected_transactions_by_block) |rj| {
        // BCS of BlockRef { round: u32, author: AuthorityIndex(u32), digest: [u8; 32] }
        var ref: [40]u8 = undefined;
        std.mem.writeInt(u32, ref[0..4], rj.block.round, .little);
        std.mem.writeInt(u32, ref[4..8], rj.block.author, .little);
        ref[8..40].* = rj.block.digest;
        try w.print(" {x}:", .{&ref});
        for (rj.indices, 0..) |i, k| try w.print("{s}{d}", .{ if (k > 0) "," else "", i });
    }
}

/// The lines one step produced, in the order the Rust tools write them: `step`, the step's commit
/// lines, then its final lines.
pub fn stepLines(w: *std.Io.Writer, linearized: []const types.CommittedSubDag, finalized: []const commit_finalizer.Finalized) std.Io.Writer.Error!void {
    try w.writeAll("step\n");
    for (linearized) |*s| {
        try commitLine(w, s);
        try w.writeByte('\n');
    }
    for (finalized) |*f| {
        try finalLine(w, &f.sub_dag);
        try w.writeByte('\n');
    }
}

/// 1-based number and text of the first line where `want` and `got` differ, or null when equal.
pub const LineDiff = struct { line: usize, want: []const u8, got: []const u8 };
pub fn firstDiff(want: []const u8, got: []const u8) ?LineDiff {
    if (std.mem.eql(u8, want, got)) return null;
    var wi = std.mem.splitScalar(u8, want, '\n');
    var gi = std.mem.splitScalar(u8, got, '\n');
    var n: usize = 1;
    while (true) : (n += 1) {
        const w = wi.next();
        const g = gi.next();
        if (w == null and g == null) return .{ .line = n, .want = "<end>", .got = "<end>" };
        if (w == null or g == null or !std.mem.eql(u8, w.?, g.?)) return .{ .line = n, .want = w orelse "<end>", .got = g orelse "<end>" };
    }
}

pub fn digestHex(text: []const u8) [64]u8 {
    const d = digest_mod.blake2b(text);
    var out: [64]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{&d}) catch unreachable;
    return out;
}

// ---------------------------------------------------------------- replay

pub const Committee = struct {
    stakes: []const u64,
    gc_depth: u32 = 60,
    shuffle: bool = true,
    leaders: usize = 1,
    /// DagState cached rounds (null: the default, 500).
    cached_rounds: ?u32 = null,
};

pub const Stats = struct {
    steps: usize = 0,
    blocks: usize = 0,
    commits: usize = 0,
    finals: usize = 0,
    /// Finalized commits that carry rejected transactions, and how many transactions.
    finals_with_rejects: usize = 0,
    rejected_transactions: usize = 0,
    /// Most commits linearized in one step and most commits finalized in one step.
    max_step_commits: usize = 0,
    max_step_finals: usize = 0,
    /// Commits still held by the finalizer after the last step.
    pending_at_end: usize = 0,
    /// The finalizer's own counters after the last step.
    fin: commit_finalizer.Counters = .{},
};

pub const Run = struct {
    /// `step`, `commit` and `final` lines of every step.
    lines: []u8,
    stats: Stats,
    /// Per-step wall time in ns when a clock was given, else empty.
    times: []u64,
    /// Rehashes of the DAG window, the vote tracker's map and the finalizer's block map.
    rehashes: [3]u64 = .{ 0, 0, 0 },
    /// Lanes the finalizer's pool has (1: inline) and the indirect passes that ran on it.
    lanes: usize = 1,
    lane_passes: u64 = 0,

    pub fn deinit(self: *Run, gpa: Allocator) void {
        gpa.free(self.lines);
        gpa.free(self.times);
    }
};

pub const Pipeline = struct {
    fx: *test_dag.Fixture,
    tracker: *tracker_mod.TransactionVoteTracker,
    fin: *commit_finalizer.CommitFinalizer,
};

pub const Options = struct {
    /// The finalizer's switches, set on the fresh pipeline before the first step. The default is
    /// every switch off, whatever the environment asks for.
    sw: commit_finalizer.Switches = .{},
    /// The rehash-after-eviction switch (store.zig `Churn`) for the length of the run.
    rehash: bool = false,
    /// Called after the last step (state inspection by tests).
    inspect: ?*const fn (p: Pipeline) anyerror!void = null,
    /// Monotonic ns clock for per-step timing (null: no timing).
    clock_ns: ?*const fn () u64 = null,
};

fn fixtureOf(gpa: Allocator, c: *const Committee) !*test_dag.Fixture {
    var params: config.Parameters = .{ .skip_equivocation_validation = true };
    if (c.cached_rounds) |x| params.dag_state_cached_rounds = x;
    // The same settings as the replay conformance suite and the val-bench.
    return test_dag.Fixture.init(gpa, .{
        .stakes = c.stakes,
        .own_index = null,
        .mode = .round_robin_test,
        .protocol = .{ .gc_depth = c.gc_depth, .transaction_voting_enabled = true, .num_leaders_per_round = c.leaders, .bad_nodes_stake_threshold = 30, .shuffle_commit_blocks = c.shuffle },
        .parameters = params,
    });
}

/// Replays `steps` (the blocks of each step) through a fresh Core: per step the blocks are
/// registered with the vote tracker and added to the Core, as the replay conformance suite, the
/// val-bench and the Rust tools do.
pub fn replay(gpa: Allocator, c: *const Committee, steps: []const []const types.VerifiedBlock, opts: Options) !Run {
    const fx = try fixtureOf(gpa, c);
    defer fx.deinit();
    return replayOn(gpa, fx, steps, opts);
}

fn replayOn(gpa: Allocator, fx: *test_dag.Fixture, steps: []const []const types.VerifiedBlock, opts: Options) !Run {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var noop: verifier_mod.NoopTransactionVerifier = .{};
    var tracker = tracker_mod.TransactionVoteTracker.init(gpa, fx.context, fx.dag, noop.verifier());
    defer tracker.deinit();
    var fin = commit_finalizer.CommitFinalizer.init(gpa, fx.context, fx.dag, &tracker);
    defer fin.deinit();
    const pipeline: Pipeline = .{ .fx = fx, .tracker = &tracker, .fin = &fin };
    try fin.setSwitches(opts.sw);
    // put back afterwards: the tests after this run keep the switch the environment asked for
    const rehash_was = store_mod.swapRehashOnEvict(opts.rehash);
    defer store_mod.setRehashOnEvict(rehash_was);
    var rec_out: core_mod.Output = .{};
    var core = try core_mod.Core.recover(gpa, arena_state.allocator(), .{ .context = fx.context, .dag = fx.dag, .schedule = fx.schedule, .tracker = &tracker, .finalizer = &fin }, &rec_out);
    defer core.deinit();

    var lines: std.Io.Writer.Allocating = .init(gpa);
    defer lines.deinit();
    const times = try gpa.alloc(u64, if (opts.clock_ns != null) steps.len else 0);
    errdefer gpa.free(times);
    var stats: Stats = .{};

    for (steps, 0..) |blocks, k| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        var out: core_mod.Output = .{ .record_linearized = true };
        const t0: u64 = if (opts.clock_ns) |clk| clk() else 0;
        for (blocks) |*b| try tracker.addVotedBlock(b, &.{});
        try core.addBlocks(scratch.allocator(), blocks, &out);
        if (opts.clock_ns) |clk| times[k] = clk() - t0;
        defer for (out.committed.items) |*f| f.deinit();
        if (out.missing.len != 0) return error.MissingAncestors;

        try stepLines(&lines.writer, out.linearized.items, out.committed.items);
        for (out.committed.items) |*f| {
            if (f.sub_dag.rejected_transactions_by_block.len > 0) stats.finals_with_rejects += 1;
            for (f.sub_dag.rejected_transactions_by_block) |rj| stats.rejected_transactions += rj.indices.len;
        }
        stats.steps += 1;
        stats.blocks += blocks.len;
        stats.commits += out.linearized.items.len;
        stats.finals += out.committed.items.len;
        stats.max_step_commits = @max(stats.max_step_commits, out.linearized.items.len);
        stats.max_step_finals = @max(stats.max_step_finals, out.committed.items.len);
    }
    stats.pending_at_end = fin.pending_commits.items.len;
    stats.fin = fin.counters;
    if (opts.inspect) |f| try f(pipeline);
    return .{
        .lines = try lines.toOwnedSlice(),
        .stats = stats,
        .times = times,
        .rehashes = .{ fx.dag.recent_churn.rehashes, tracker.churn.rehashes, fin.blocks_churn.rehashes },
        .lanes = fin.lanesInUse(),
        .lane_passes = fin.lane_passes,
    };
}

/// Generates the DAG of `g` for the committee and replays it.
pub fn run(gpa: Allocator, c: *const Committee, g: *const Gen, opts: Options) !Run {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const fx = try fixtureOf(gpa, c);
    defer fx.deinit();
    const layers = try genDag(arena_state.allocator(), g, c.stakes, fx.dag.genesis);
    return replayOn(gpa, fx, layers, opts);
}

/// A vector file in the Rust tools' format (`scenario`, `genesis`, `block`, `step`, `commit`,
/// `final`, `end`) for the generated DAG of `g`, with the commit and final lines deepwave's finalizer
/// wrote: what the val-bench reads as `consensus/val-bench/<case>.vec`. For tests of the readers.
pub fn vectorText(gpa: Allocator, name: []const u8, c: *const Committee, g: *const Gen, stats: ?*Stats) ![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const fx = try fixtureOf(gpa, c);
    defer fx.deinit();
    const layers = try genDag(arena_state.allocator(), g, c.stakes, fx.dag.genesis);
    var w: std.Io.Writer.Allocating = .init(gpa);
    errdefer w.deinit();
    try w.writer.print("scenario {s} {d} {d} {d} {d} ", .{ name, c.stakes.len, c.gc_depth, @intFromBool(c.shuffle), c.leaders });
    for (c.stakes, 0..) |s, i| try w.writer.print("{s}{d}", .{ if (i > 0) "," else "", s });
    try w.writer.writeByte('\n');
    for (fx.dag.genesis) |gb| try w.writer.print("genesis {x}\n", .{&gb.digest});
    var r = try replayOn(gpa, fx, layers, .{});
    defer r.deinit(gpa);
    if (stats) |o| o.* = r.stats;
    var k: usize = 0;
    var it = std.mem.tokenizeScalar(u8, r.lines, '\n');
    while (it.next()) |line| {
        if (std.mem.eql(u8, line, "step")) {
            for (layers[k]) |b| try w.writer.print("block {x}\n", .{b.serialized});
            k += 1;
        }
        try w.writer.writeAll(line);
        try w.writer.writeByte('\n');
    }
    try w.writer.writeAll("end\n");
    return w.toOwnedSlice();
}

// ---------------------------------------------------------------- Mysten's vectors

pub const VectorScenario = struct {
    name: []const u8,
    committee: Committee,
    genesis: []const [32]u8,
    steps: []const []const types.VerifiedBlock,
    /// The `step`, `commit` and `final` lines Mysten wrote for this scenario.
    want: []const u8,
    commits: usize,
    finals: usize,
};

/// Parses the scenarios of a committer-vectors file (`scenario`, `genesis`, `block`, `step`,
/// `commit`, `final`, `end` lines; other lines are skipped). Everything is allocated from `arena`.
pub fn parseVectors(arena: Allocator, text: []const u8) ![]VectorScenario {
    var out: std.ArrayList(VectorScenario) = .empty;
    var cur: ?VectorScenario = null;
    var genesis: std.ArrayList([32]u8) = .empty;
    var steps: std.ArrayList([]const types.VerifiedBlock) = .empty;
    var pending: std.ArrayList(types.VerifiedBlock) = .empty;
    var want: std.ArrayList(u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = it.next() orelse continue;
        if (std.mem.eql(u8, kind, "scenario")) {
            if (cur != null) return error.BadVector;
            const name = it.next() orelse return error.BadVector;
            const n = try std.fmt.parseInt(usize, it.next() orelse return error.BadVector, 10);
            const gc_depth = try std.fmt.parseInt(u32, it.next() orelse return error.BadVector, 10);
            const shuffle = (try std.fmt.parseInt(u8, it.next() orelse return error.BadVector, 10)) != 0;
            const leaders = try std.fmt.parseInt(usize, it.next() orelse return error.BadVector, 10);
            const stakes = try arena.alloc(u64, n);
            if (it.next()) |csv| {
                var ci = std.mem.splitScalar(u8, csv, ',');
                for (stakes) |*s| s.* = try std.fmt.parseInt(u64, ci.next() orelse return error.BadVector, 10);
            } else @memset(stakes, 1);
            cur = .{ .name = name, .committee = .{ .stakes = stakes, .gc_depth = gc_depth, .shuffle = shuffle, .leaders = leaders }, .genesis = &.{}, .steps = &.{}, .want = "", .commits = 0, .finals = 0 };
            genesis = .empty;
            steps = .empty;
            pending = .empty;
            want = .empty;
        } else if (cur == null) {
            continue;
        } else if (std.mem.eql(u8, kind, "genesis")) {
            var g: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&g, it.next() orelse return error.BadVector);
            try genesis.append(arena, g);
        } else if (std.mem.eql(u8, kind, "block")) {
            const hex = it.next() orelse return error.BadVector;
            const bytes = try arena.alloc(u8, hex.len / 2);
            _ = try std.fmt.hexToBytes(bytes, hex);
            try pending.append(arena, try digest_mod.decodeVerifiedUnchecked(arena, bytes));
        } else if (std.mem.eql(u8, kind, "step")) {
            try steps.append(arena, pending.items);
            pending = .empty;
            try want.appendSlice(arena, "step\n");
        } else if (std.mem.eql(u8, kind, "commit") or std.mem.eql(u8, kind, "final")) {
            if (kind[0] == 'c') cur.?.commits += 1 else cur.?.finals += 1;
            try want.appendSlice(arena, line);
            try want.append(arena, '\n');
        } else if (std.mem.eql(u8, kind, "end")) {
            if (pending.items.len != 0) return error.BadVector;
            var sc = cur.?;
            sc.genesis = genesis.items;
            sc.steps = steps.items;
            sc.want = want.items;
            try out.append(arena, sc);
            cur = null;
        }
    }
    if (cur != null) return error.BadVector;
    return out.items;
}

/// Replays one of Mysten's scenarios and compares every commit and final line with Mysten's.
/// Returns the first differing line, or null when all are equal (genesis digests included).
pub fn checkVectorScenario(gpa: Allocator, sc: *const VectorScenario, opts: Options) !?LineDiff {
    const fx = try fixtureOf(gpa, &sc.committee);
    defer fx.deinit();
    if (fx.dag.genesis.len != sc.genesis.len) return .{ .line = 0, .want = "genesis count", .got = "differs" };
    for (fx.dag.genesis, sc.genesis) |g, w| {
        if (!std.mem.eql(u8, &g.digest, &w)) return .{ .line = 0, .want = "genesis digest", .got = "differs" };
    }
    var r = try replayOn(gpa, fx, sc.steps, opts);
    defer r.deinit(gpa);
    const d = firstDiff(sc.want, r.lines) orelse return null;
    // the texts die with this call: report the line number only
    return .{ .line = d.line, .want = "see the scenario's line", .got = "differs" };
}

// ---------------------------------------------------------------- the exactness cases

const ones4: [4]u64 = @splat(1);
const ones10: [10]u64 = @splat(1);

/// Ten authorities (5, 15, .. 95) offline in overlapping stretches of rounds: the shape of the
/// Rust tool's n100-timeouts case on fewer rounds.
const offline100: [10]Range = blk: {
    var o: [10]Range = undefined;
    for (&o, 0..) |*x, i| x.* = .{ .authority = @intCast(i * 10 + 5), .first = @intCast(8 + i * 3), .last = @intCast(20 + i * 4) };
    break :blk o;
};

pub const Case = struct {
    name: []const u8,
    /// Equal stakes of this size, or mainnet-like stakes when `mainnet` is set.
    n: usize,
    mainnet: bool = false,
    gc_depth: u32 = 60,
    cached_rounds: ?u32 = null,
    gen: Gen,
    /// Only with `ZUI_COMMIT_TAIL=full` (slow in a debug build).
    full_only: bool = false,
    /// Blake2b-256 of the lines the finalizer wrote for this case when the lane started (every
    /// switch off, the path the replay conformance suite proves against Mysten).
    golden: []const u8,
};

/// The val-bench shapes on fewer rounds and short payloads, plus small GC windows so DAG
/// eviction, the vote tracker's GC and the walk's GC cut all run.
pub const cases = [_]Case{
    .{ .name = "n4", .n = 4, .gen = .{ .rounds = 400, .seed = 41, .leader_link_pct = 90, .weak_link_pct = 5, .tx_len_min = 8, .tx_len_max = 40 }, .golden = "c70e3baa69b3172b835e5572976ac28758b99924a4955b115d38245199dc066d" },
    .{ .name = "n10", .n = 10, .gen = .{ .rounds = 300, .seed = 101, .leader_link_pct = 90, .weak_link_pct = 5, .tx_len_min = 8, .tx_len_max = 40 }, .golden = "b207b6a83f9ec70617c7f353792b8732aa19e9d12b68615c75995047fb9b1afd" },
    .{ .name = "n10-timeouts", .n = 10, .gen = .{
        .rounds = 400,
        .seed = 102,
        .leader_link_pct = 60,
        .weak_link_pct = 10,
        .offline = &.{ .{ .authority = 3, .first = 60, .last = 160 }, .{ .authority = 7, .first = 220, .last = 250 }, .{ .authority = 2, .first = 300, .last = 312 }, .{ .authority = 5, .first = 300, .last = 312 } },
        .ignored = &.{.{ .authority = 8, .first = 330, .last = 360 }},
        .tx_len_min = 8,
        .tx_len_max = 40,
    }, .golden = "b42fd916ccbb0e0ab627253a8542589f94a1575dbbf790b716b96240c1a9825f" },
    .{ .name = "n10-gc", .n = 10, .gc_depth = 8, .cached_rounds = 4, .gen = .{
        .rounds = 400,
        .seed = 103,
        .leader_link_pct = 55,
        .weak_link_pct = 20,
        .offline = &.{ .{ .authority = 4, .first = 50, .last = 120 }, .{ .authority = 9, .first = 200, .last = 230 } },
        .ignored = &.{.{ .authority = 6, .first = 260, .last = 300 }},
        .tx_len_min = 8,
        .tx_len_max = 40,
    }, .golden = "c83b5311e083f9ec4930348e7c754f201095ffbfae2173afd04ef2a7c8e26076" },
    .{ .name = "n100", .n = 100, .mainnet = true, .gen = .{ .rounds = 52, .seed = 1001, .leader_link_pct = 90, .weak_link_pct = 3, .tx_len_min = 8, .tx_len_max = 40 }, .golden = "cd5f755f342db5b8e6c073bd8353e1412388f11d0cc94171dfcf1a828fd718d2" },
    .{ .name = "n100-timeouts", .n = 100, .mainnet = true, .full_only = true, .gen = .{
        .rounds = 64,
        .seed = 1003,
        .leader_link_pct = 90,
        .weak_link_pct = 3,
        .offline = &offline100,
        .ignored = &.{ .{ .authority = 1, .first = 30, .last = 40 }, .{ .authority = 2, .first = 44, .last = 50 } },
        .tx_len_min = 8,
        .tx_len_max = 40,
    }, .golden = "23cf5897c52612dcfbfcd45545946cd8800a3bed96fb80e28cf17498cf5597d0" },
    .{ .name = "n100-gc", .n = 100, .mainnet = true, .full_only = true, .gc_depth = 10, .cached_rounds = 4, .gen = .{ .rounds = 64, .seed = 1004, .leader_link_pct = 90, .weak_link_pct = 3, .tx_len_min = 8, .tx_len_max = 40 }, .golden = "150902a5648c2b90b5131ffcd5ff7ce85b3116a80b8b5b80299b09de635dd994" },
};

pub fn committeeOf(a: Allocator, c: *const Case) !Committee {
    const stakes = if (c.mainnet) try mainnetLikeStakes(a, c.n) else blk: {
        const s = try a.alloc(u64, c.n);
        @memset(s, 1);
        break :blk s;
    };
    return .{ .stakes = stakes, .gc_depth = c.gc_depth, .cached_rounds = c.cached_rounds };
}

/// `ZUI_COMMIT_TAIL=full` turns on the slow cases and the replay of Mysten's vectors under every
/// switch setting (the lane's gate; needs `$ZUI_CORPUS/consensus/replay.vec`).
fn fullRun() bool {
    const v = std.testing.environ.getPosix("ZUI_COMMIT_TAIL") orelse return false;
    return std.mem.eql(u8, v, "full");
}

/// The switch settings under test. Each commit of the lane that adds a switch adds rows; the
/// first row is always "every switch off". `heavy` rows run on the n=100 cases only with
/// `ZUI_COMMIT_TAIL=full` (a debug build walks slowly); the last row, everything on, always runs.
pub const Variant = struct { name: []const u8, sw: commit_finalizer.Switches, rehash: bool = false, heavy: bool = true };
pub const variants = [_]Variant{
    .{ .name = "default", .sw = .{} },
    .{ .name = "sets", .sw = .{ .walk = .sets, .cross_check = true } },
    .{ .name = "dense-checked", .sw = .{ .walk = .dense, .cross_check = true } },
    .{ .name = "dense", .sw = .{ .walk = .dense } },
    .{ .name = "lanes", .sw = .{ .lanes = 3 } },
    .{ .name = "lanes-1", .sw = .{ .lanes = 3, .blocks_per_task = 1 } },
    .{ .name = "sets-lanes", .sw = .{ .walk = .sets, .lanes = 3, .blocks_per_task = 2 } },
    .{ .name = "dense-lanes-checked", .sw = .{ .walk = .dense, .lanes = 4, .blocks_per_task = 1, .cross_check = true } },
    // the smallest pool (the caller and one worker) and the largest (MAX_LANES)
    .{ .name = "lanes-2", .sw = .{ .lanes = 2, .blocks_per_task = 1 } },
    .{ .name = "dense-lanes-8", .sw = .{ .walk = .dense, .lanes = 8, .blocks_per_task = 1 } },
    .{ .name = "rehash", .sw = .{}, .rehash = true },
    .{ .name = "share", .sw = .{ .share_blocks = true } },
    .{ .name = "all-on", .sw = .{ .walk = .dense, .lanes = 3, .share_blocks = true }, .rehash = true, .heavy = false },
};

/// Index in `cases` of the n=10 case whose DAG finalizes 20 or more commits in one step (the
/// val-bench unit test replays it as a vector file).
pub const burst_case: usize = 2;
/// Index in `cases` of the small-GC-window case: the DAG window, the vote tracker and the
/// finalizer evict throughout, so the rehash switch must fire in all three.
pub const gc_case: usize = 3;

test "generated DAG: deterministic, own block first, a quorum of parents; mainnet-like stakes sum to 10,000" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const stakes = try mainnetLikeStakes(a, 100);
    var sum: u64 = 0;
    for (stakes) |s| sum += s;
    try std.testing.expectEqual(@as(u64, 10_000), sum);

    const g: Gen = .{ .rounds = 12, .seed = 7, .tx_len_min = 8, .tx_len_max = 40 };
    const fx = try test_dag.Fixture.init(gpa, .{ .stakes = &ones10, .own_index = null });
    defer fx.deinit();
    const l1 = try genDag(a, &g, &ones10, fx.dag.genesis);
    const l2 = try genDag(a, &g, &ones10, fx.dag.genesis);
    try std.testing.expectEqual(@as(usize, 12), l1.len);
    for (l1, l2) |x, y| {
        try std.testing.expectEqual(@as(usize, 10), x.len);
        for (x, y) |bx, by| {
            try std.testing.expectEqualSlices(u8, bx.serialized, by.serialized);
            const anc = bx.block.inner.ancestors();
            try std.testing.expect(anc.len >= 7);
            try std.testing.expectEqual(bx.block.inner.author(), anc[0].author);
        }
    }
}

test "final line: BCS block ref and indices as the Rust tools write them" {
    const gpa = std.testing.allocator;
    var w: std.Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    const rej = [_]types.RejectedInBlock{
        .{ .block = .{ .round = 0x0102, .author = 3, .digest = @splat(0xab) }, .indices = &.{ 0, 7, 300 } },
        .{ .block = .{ .round = 0x0103, .author = 0, .digest = @splat(0x01) }, .indices = &.{5} },
    };
    const s: types.CommittedSubDag = .{ .leader = types.BlockRef.MIN, .blocks = &.{}, .timestamp_ms = 0, .commit_ref = .{ .index = 9, .digest = @splat(0xcd) }, .decided_with_local_blocks = true, .recovered_rejected_transactions = false, .rejected_transactions_by_block = &rej };
    try finalLine(&w.writer, &s);
    const cd: [32]u8 = @splat(0xcd);
    const ab: [32]u8 = @splat(0xab);
    const one: [32]u8 = @splat(0x01);
    var want: std.Io.Writer.Allocating = .init(gpa);
    defer want.deinit();
    try want.writer.print("final 9 {x} 0201000003000000{x}:0,7,300 0301000000000000{x}:5", .{ &cd, &ab, &one });
    try std.testing.expectEqualStrings(want.written(), w.written());
    try std.testing.expect(firstDiff("a\nb\n", "a\nb\n") == null);
    try std.testing.expectEqual(@as(usize, 2), firstDiff("a\nb\n", "a\nc\n").?.line);
    try std.testing.expectEqual(@as(usize, 3), firstDiff("a\nb\n", "a\nb\nc\n").?.line);
}

test "vector text of a generated DAG parses back to the same steps and lines" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const committee: Committee = .{ .stakes = &ones4 };
    const g: Gen = .{ .rounds = 40, .seed = 41, .tx_len_min = 8, .tx_len_max = 40 };
    var stats: Stats = .{};
    const text = try vectorText(gpa, "t4", &committee, &g, &stats);
    defer gpa.free(text);
    const scs = try parseVectors(arena_state.allocator(), text);
    try std.testing.expectEqual(@as(usize, 1), scs.len);
    try std.testing.expectEqualStrings("t4", scs[0].name);
    try std.testing.expectEqual(@as(usize, 40), scs[0].steps.len);
    try std.testing.expectEqual(stats.commits, scs[0].commits);
    try std.testing.expectEqual(stats.finals, scs[0].finals);
    try std.testing.expect(stats.finals > 0);
    try std.testing.expect((try checkVectorScenario(gpa, &scs[0], .{})) == null);
}

test "a run leaves the rehash switch as it found it, on or off" {
    const gpa = std.testing.allocator;
    const at_start = store_mod.rehashOnEvict();
    defer store_mod.setRehashOnEvict(at_start);
    const committee: Committee = .{ .stakes = &ones4 };
    const g: Gen = .{ .rounds = 12, .seed = 41, .tx_len_min = 8, .tx_len_max = 40 };
    for ([_]bool{ true, false }) |outer| {
        for ([_]bool{ false, true }) |inner| {
            store_mod.setRehashOnEvict(outer);
            var r = try run(gpa, &committee, &g, .{ .rehash = inner });
            r.deinit(gpa);
            // with the switch on in the environment, a run with it off used to leave it off
            try std.testing.expectEqual(outer, store_mod.rehashOnEvict());
        }
    }
}

fn printStats(name: []const u8, dg: []const u8, st: *const Stats) void {
    std.debug.print("commit-tail {s}: output {s} steps {d} blocks {d} commits {d} finals {d} with-rejects {d} rejected-txs {d} max-step-commits {d} max-step-finals {d} pending-at-end {d} passes {d} multi-block {d} emptied-then-later {d} indirect-finalized {d} late-rejected {d} indirect-rejected {d}\n", .{
        name,                   dg,                         st.steps,                  st.blocks,                 st.commits,            st.finals,
        st.finals_with_rejects, st.rejected_transactions,   st.max_step_commits,       st.max_step_finals,        st.pending_at_end,     st.fin.indirect_passes,
        st.fin.multi_block_passes, st.fin.emptied_then_later, st.fin.indirect_finalized, st.fin.late_rejected, st.fin.indirect_rejected,
    });
}

test "commit tail exactness: every switch setting against the unswitched finalizer and the pinned output, generated DAGs at n=4, 10 and 100 with timeouts, GC and bursts" {
    const gpa = std.testing.allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const full = fullRun();
    const show = std.testing.environ.getPosix("ZUI_COMMIT_TAIL_STATS") != null;
    var bad: usize = 0;
    var best_burst_10: usize = 0;
    var best_burst_100: usize = 0;
    for (&cases) |*c| {
        if (c.full_only and !full) continue;
        const committee = try committeeOf(arena_state.allocator(), c);
        var base = try run(gpa, &committee, &c.gen, .{ .sw = variants[0].sw });
        defer base.deinit(gpa);
        const st = &base.stats;
        const dg = digestHex(base.lines);
        if (show) printStats(c.name, &dg, st);
        // The case must exercise what it is for: commits, finals with rejected transactions, and
        // indirect passes over several pending blocks where one block empties and a later one
        // still has results to apply (the apply order), indirect finalization and indirect reject.
        if (st.commits == 0 or st.finals == 0 or st.finals_with_rejects == 0 or st.fin.multi_block_passes == 0 or
            st.fin.emptied_then_later == 0 or st.fin.indirect_finalized == 0 or st.fin.indirect_rejected == 0)
        {
            bad += 1;
            std.debug.print("commit-tail {s}: the case does not exercise the finalizer\n", .{c.name});
            if (!show) printStats(c.name, &dg, st);
        }
        if (c.n == 10) best_burst_10 = @max(best_burst_10, st.max_step_finals);
        if (c.n == 100) best_burst_100 = @max(best_burst_100, st.max_step_finals);
        if (!std.mem.eql(u8, &dg, c.golden)) {
            bad += 1;
            std.debug.print("commit-tail {s}: the output is not the pinned one\n", .{c.name});
            if (!show) printStats(c.name, &dg, st);
        }
        for (variants[1..]) |v| {
            if (v.heavy and c.n == 100 and !full) continue;
            var got = try run(gpa, &committee, &c.gen, .{ .sw = v.sw, .rehash = v.rehash });
            defer got.deinit(gpa);
            if (v.rehash and c == &cases[gc_case]) {
                for (got.rehashes) |n| try std.testing.expect(n > 0);
            } else if (!v.rehash) {
                for (got.rehashes) |n| try std.testing.expectEqual(@as(u64, 0), n);
            }
            if (firstDiff(base.lines, got.lines)) |d| {
                bad += 1;
                std.debug.print("commit-tail {s}: variant {s} differs at line {d}\n  off: {s}\n  on:  {s}\n", .{ c.name, v.name, d.line, d.want[0..@min(d.want.len, 240)], d.got[0..@min(d.got.len, 240)] });
            }
            // A lane row must have run on its lanes: the pool has the row's lane count, and with
            // one pending block per task every pass over two or more pending blocks (each case
            // has some, checked above) went to the pool.
            if (v.sw.lanes > 1) {
                try std.testing.expectEqual(v.sw.lanes, got.lanes);
                if (v.sw.blocks_per_task == 1) try std.testing.expect(got.lane_passes > 0);
            } else if (v.sw.lanes == 1) try std.testing.expectEqual(@as(u64, 0), got.lane_passes);
            try std.testing.expectEqual(base.stats, got.stats);
        }
    }
    // Bursts: one step that finalizes 20 or more commits, at n=10 and at n=100.
    try std.testing.expect(best_burst_10 >= 20);
    try std.testing.expect(best_burst_100 >= 20);
    try std.testing.expectEqual(@as(usize, 0), bad);
}

test "commit tail gate (ZUI_COMMIT_TAIL=full): Mysten's replay vectors, every commit and final line, under every switch setting" {
    if (!fullRun()) return error.SkipZigTest;
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    // Asked for explicitly, so a missing corpus fails instead of skipping.
    const root = std.testing.environ.getPosix("ZUI_CORPUS") orelse return error.CorpusNotSet;
    var dir = try std.Io.Dir.openDirAbsolute(io, root, .{});
    defer dir.close(io);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const text = try dir.readFileAlloc(io, "consensus/replay.vec", a, .limited(1 << 31));
    const scenarios = try parseVectors(a, text);
    try std.testing.expect(scenarios.len >= 16);
    var bad: usize = 0;
    var commits: usize = 0;
    var finals: usize = 0;
    for (scenarios) |*sc| {
        commits += sc.commits;
        finals += sc.finals;
        for (&variants) |v| {
            if (try checkVectorScenario(gpa, sc, .{ .sw = v.sw, .rehash = v.rehash })) |d| {
                bad += 1;
                std.debug.print("commit-tail vectors {s}: variant {s} differs from Mysten at line {d} of the scenario's step/commit/final lines\n", .{ sc.name, v.name, d.line });
            }
        }
    }
    std.debug.print("commit-tail vectors: {d} scenarios, {d} commit lines and {d} final lines, {d} switch settings, {d} differ\n", .{ scenarios.len, commits, finals, variants.len, bad });
    try std.testing.expect(finals > 3000);
    try std.testing.expectEqual(@as(usize, 0), bad);
}

// ---------------------------------------------------------------- out of memory in the Core's call arena

const dag_mod = @import("dag_state.zig");
const ls_mod = @import("leader_schedule.zig");

const oom_gen: Gen = .{ .rounds = 10, .seed = 41, .tx_len_min = 8, .tx_len_max = 40 };

test "out of memory in the Core's call arena in a step that finalizes commits: the finalized commits and their block holds are freed, at every allocation of the step" {
    const gpa = std.testing.allocator;
    const committee: Committee = .{ .stakes = &ones4 };
    var target: ?usize = null; // the first step that finalizes commits (found by the first pass)
    var fail_at: usize = 0;
    var failures: usize = 0;
    sweep: while (true) {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const fx = try fixtureOf(gpa, &committee);
        defer fx.deinit();
        const layers = try genDag(a, &oom_gen, committee.stakes, fx.dag.genesis);
        var noop: verifier_mod.NoopTransactionVerifier = .{};
        var tracker = tracker_mod.TransactionVoteTracker.init(gpa, fx.context, fx.dag, noop.verifier());
        defer tracker.deinit();
        var fin = commit_finalizer.CommitFinalizer.init(gpa, fx.context, fx.dag, &tracker);
        defer fin.deinit();
        try fin.setSwitches(.{ .share_blocks = true });
        var rec_out: core_mod.Output = .{};
        var core = try core_mod.Core.recover(gpa, a, .{ .context = fx.context, .dag = fx.dag, .schedule = fx.schedule, .tracker = &tracker, .finalizer = &fin }, &rec_out);
        defer core.deinit();
        for (layers, 0..) |blocks, k| {
            var scratch: std.heap.ArenaAllocator = .init(gpa);
            defer scratch.deinit();
            var failing = std.testing.FailingAllocator.init(scratch.allocator(), .{});
            if (target) |tk| {
                if (k == tk) failing.fail_index = fail_at;
            }
            var out: core_mod.Output = .{};
            // The driver frees what it was handed, also after a failed call. What the Core took
            // from the finalizer and could not hand over is the Core's to free.
            defer for (out.committed.items) |*f| f.deinit();
            for (blocks) |*b| try tracker.addVotedBlock(b, &.{});
            core.addBlocks(failing.allocator(), blocks, &out) catch {
                try std.testing.expect(failing.has_induced_failure);
                failures += 1;
                fail_at += 1;
                continue :sweep;
            };
            if (target == null) {
                if (out.committed.items.len == 0) continue;
                // every block of a finalized commit is shared, so holds are at stake
                for (out.committed.items) |f| try std.testing.expectEqual(f.sub_dag.blocks.len, f.boxes.len);
                target = k;
                continue :sweep;
            }
            // the step ran through: its allocations are used up
            if (k == target.?) break :sweep;
        }
        return error.NoStepFinalizes;
    }
    try std.testing.expect(failures > 20);
    // A finalized commit that was not freed, or a block it still held, is reported by
    // std.testing.allocator when the test ends.
}

test "out of memory in the Core's call arena while recovery replays the stored commits through the finalizer: the finalized commits are freed, at every allocation of the recovery" {
    const gpa = std.testing.allocator;
    const committee: Committee = .{ .stakes = &ones4 };
    var fail_at: usize = 0;
    var failures: usize = 0;
    var replayed: usize = 0;
    while (true) : (fail_at += 1) {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        // First life: the DAG runs, the store ends with commits, their blocks and the finalized
        // records.
        const fx = try fixtureOf(gpa, &committee);
        defer fx.deinit();
        const layers = try genDag(a, &oom_gen, committee.stakes, fx.dag.genesis);
        {
            var r = try replayOn(gpa, fx, layers, .{});
            defer r.deinit(gpa);
            try std.testing.expect(r.stats.finals > 0);
            try fx.dag.flush();
        }
        // Second life, as after a restart whose consumer processed nothing: a new DagState over
        // the same store, and a Core that replays every stored commit through a new finalizer.
        const dag = try dag_mod.DagState.init(gpa, fx.context, fx.mem.store());
        defer dag.deinit();
        var schedule = try ls_mod.LeaderSchedule.fromStore(gpa, fx.context, dag);
        defer schedule.deinit();
        schedule.mode = fx.schedule.mode;
        var noop: verifier_mod.NoopTransactionVerifier = .{};
        var tracker = tracker_mod.TransactionVoteTracker.init(gpa, fx.context, dag, noop.verifier());
        defer tracker.deinit();
        var fin = commit_finalizer.CommitFinalizer.init(gpa, fx.context, dag, &tracker);
        defer fin.deinit();
        try fin.setSwitches(.{ .share_blocks = true });
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        var failing = std.testing.FailingAllocator.init(scratch.allocator(), .{ .fail_index = fail_at });
        var out: core_mod.Output = .{};
        defer for (out.committed.items) |*f| f.deinit();
        var core = core_mod.Core.recover(gpa, failing.allocator(), .{ .context = fx.context, .dag = dag, .schedule = &schedule, .tracker = &tracker, .finalizer = &fin, .replay_after_commit_index = 0 }, &out) catch {
            try std.testing.expect(failing.has_induced_failure);
            failures += 1;
            continue;
        };
        core.deinit();
        replayed = out.committed.items.len;
        break;
    }
    try std.testing.expect(replayed > 0);
    try std.testing.expect(failures > 20);
}

// ---------------------------------------------------------------- local microbench

var bench_t0: ?std.Io.Timestamp = null;
fn benchClock() u64 {
    const now = std.Io.Timestamp.now(std.testing.io, .awake);
    if (bench_t0 == null) bench_t0 = now;
    return @intCast(bench_t0.?.durationTo(now).nanoseconds);
}

/// The Rust tool's n100-timeouts outages (twenty authorities offline in overlapping stretches).
const offline_bench: [20]Range = blk: {
    var o: [20]Range = undefined;
    for (&o, 0..) |*x, i| x.* = .{ .authority = @intCast(i * 5), .first = @intCast(50 + i * 7), .last = @intCast(120 + i * 9) };
    break :blk o;
};

/// The val-bench's two n=100 shapes at its length (400 rounds, payloads of 200 to 1200 bytes),
/// both on mainnet-like stakes: with 100 equal stakes this generator's DAG never commits. The
/// outage case keeps the 90% leader link rate too: at the Rust tool's 80% no block of this
/// generator's DAG has a quorum of votes among its parents, nothing commits, and the case would
/// time the committer only (the microbench refuses a case that does not commit).
const bench_cases = [_]Case{
    .{ .name = "n100", .n = 100, .mainnet = true, .gen = .{ .rounds = 400, .seed = 1001, .leader_link_pct = 90, .weak_link_pct = 3 }, .golden = "" },
    .{ .name = "n100-timeouts", .n = 100, .mainnet = true, .gen = .{
        .rounds = 400,
        .seed = 1002,
        .leader_link_pct = 90,
        .weak_link_pct = 3,
        .offline = &offline_bench,
        .ignored = &.{ .{ .authority = 1, .first = 200, .last = 260 }, .{ .authority = 2, .first = 300, .last = 330 } },
    }, .golden = "" },
};

test "commit tail microbench (ZUI_COMMIT_TAIL_BENCH=1, build with -Doptimize=ReleaseFast): per-step p50, p99 and max at n=100 under each switch setting" {
    if (std.testing.environ.getPosix("ZUI_COMMIT_TAIL_BENCH") == null) return error.SkipZigTest;
    const gpa = std.heap.smp_allocator;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const settings = [_]Variant{
        .{ .name = "default", .sw = .{} },
        .{ .name = "sets", .sw = .{ .walk = .sets } },
        .{ .name = "dense", .sw = .{ .walk = .dense } },
        .{ .name = "lanes-auto", .sw = .{ .lanes = 0 } },
        .{ .name = "dense+lanes-auto", .sw = .{ .walk = .dense, .lanes = 0 } },
        .{ .name = "dense+lanes-auto+rehash", .sw = .{ .walk = .dense, .lanes = 0 }, .rehash = true },
        .{ .name = "share", .sw = .{ .share_blocks = true } },
        .{ .name = "all-on", .sw = .{ .walk = .dense, .lanes = 0, .share_blocks = true }, .rehash = true },
    };
    for (&bench_cases) |*c| {
        const committee = try committeeOf(arena_state.allocator(), c);
        var base_digest: [64]u8 = undefined;
        for (settings, 0..) |v, k| {
            // three runs, the fastest total: the Mac is shared with other builds
            var best: ?Run = null;
            defer if (best) |*b| b.deinit(gpa);
            for (0..3) |_| {
                var r = try run(gpa, &committee, &c.gen, .{ .sw = v.sw, .rehash = v.rehash, .clock_ns = benchClock });
                var total: u64 = 0;
                for (r.times) |t| total += t;
                var best_total: u64 = std.math.maxInt(u64);
                if (best) |b| {
                    best_total = 0;
                    for (b.times) |t| best_total += t;
                }
                if (total < best_total) {
                    if (best) |*b| b.deinit(gpa);
                    best = r;
                } else r.deinit(gpa);
            }
            const r = &best.?;
            // a DAG that never commits measures nothing of the finalizer
            try std.testing.expect(r.stats.commits > 0 and r.stats.finals > 0);
            const dg = digestHex(r.lines);
            if (k == 0) base_digest = dg;
            var total: u64 = 0;
            for (r.times) |t| total += t;
            std.mem.sort(u64, r.times, {}, std.sort.asc(u64));
            const n = r.times.len;
            const p99 = r.times[@min(n - 1, (n * 99 + 99) / 100 - 1)];
            std.debug.print("commit-tail-bench {s} {s}: steps {d} commits {d} finals {d} max-step-finals {d} p50 {d:.3} ms p99 {d:.3} ms max {d:.3} ms total {d:.1} ms output {s}\n", .{
                c.name,                                            v.name,                                   n,                                                         r.stats.commits,                            r.stats.finals, r.stats.max_step_finals,
                @as(f64, @floatFromInt(r.times[n / 2])) / 1e6, @as(f64, @floatFromInt(p99)) / 1e6, @as(f64, @floatFromInt(r.times[n - 1])) / 1e6, @as(f64, @floatFromInt(total)) / 1e6, if (std.mem.eql(u8, &dg, &base_digest)) "same" else "DIFFERENT",
            });
            try std.testing.expectEqualSlices(u8, &base_digest, &dg);
        }
    }
}
