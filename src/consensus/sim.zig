//! Deterministic in-process simulation of N Mysticeti cores: a seeded network
//! with per-message drops and delays, crashes of the delivery to a node, and the invariants the
//! protocol promises: every honest core emits the same commit sequence, and no core signs two
//! blocks for one round. Owner lane: val-consensus-core. Used by `zig build test -Dlane=consensus`
//! (small seeds) and by the long DST runs (many seeds).
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const iface = @import("iface.zig");
const digest_mod = @import("digest.zig");
const test_dag = @import("test_dag.zig");
const core_mod = @import("core.zig");
const commit_finalizer = @import("commit_finalizer.zig");
const verifier_mod = @import("verifier.zig");
const tracker_mod = @import("transaction_vote_tracker.zig");

const Allocator = std.mem.Allocator;

/// A BlockSigner that never signs two blocks of one round, returns a recognizable fake signature.
pub const WatermarkSigner = struct {
    last_round: types.Round = 0,
    signed: u64 = 0,

    pub fn signer(self: *WatermarkSigner) iface.BlockSigner {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: iface.BlockSigner.VTable = .{ .sign_block = sign };
    fn sign(ctx: *anyopaque, epoch: types.Epoch, round: types.Round, message: []const u8) iface.BlockSigner.SignError![64]u8 {
        _ = .{ epoch, message };
        const self: *WatermarkSigner = @ptrCast(@alignCast(ctx));
        if (round <= self.last_round) return error.AlreadySigned;
        self.last_round = round;
        self.signed += 1;
        return @splat(0xAB);
    }
};

/// Hands out two small transactions per proposal.
pub const TwoTxSource = struct {
    counter: u64 = 0,
    bufs: [2][8]u8 = undefined,

    pub fn source(self: *TwoTxSource) iface.TransactionSource {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: iface.TransactionSource.VTable = .{ .next = next, .ack = ack };
    fn next(ctx: *anyopaque, out: []types.Transaction, max_bytes: u64) usize {
        _ = max_bytes;
        const self: *TwoTxSource = @ptrCast(@alignCast(ctx));
        const n = @min(out.len, 2);
        for (out[0..n], 0..) |*t, i| {
            std.mem.writeInt(u64, &self.bufs[i], self.counter, .little);
            self.counter += 1;
            t.* = .{ .data = &self.bufs[i] };
        }
        return n;
    }
    fn ack(_: *anyopaque, _: types.BlockRef) void {}
};

const Node = struct {
    fx: *test_dag.Fixture,
    noop: verifier_mod.NoopTransactionVerifier = .{},
    tracker: tracker_mod.TransactionVoteTracker,
    fin: commit_finalizer.CommitFinalizer,
    signer: WatermarkSigner = .{},
    txs: TwoTxSource = .{},
    core: core_mod.Core,
    /// Commit refs in the order the CommitSink would see them.
    commits: std.ArrayList(types.CommitRef) = .empty,
    rejected_total: usize = 0,
};

pub const Config = struct {
    n: usize = 4,
    seed: u64 = 1,
    /// Simulated milliseconds to run.
    run_ms: u64 = 6_000,
    /// Probability (permille) a block delivery to a node is dropped (it is re-sent later by the
    /// periodic sync, as the Synchronizer does).
    drop_permille: u32 = 0,
    /// Max extra delivery delay in ticks.
    max_delay_ticks: u32 = 0,
};

pub const Result = struct {
    min_commits: usize,
    max_commits: usize,
    total_blocks: usize,
};

const Pending = struct { deliver_at: u64, to: usize, block: types.VerifiedBlock };

/// Runs the simulation. Returns an error on any invariant violation.
pub fn run(gpa: Allocator, cfg: Config) !Result {
    var prng = std.Random.DefaultPrng.init(cfg.seed);
    const rnd = prng.random();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const stakes = try arena.alloc(u64, cfg.n);
    @memset(stakes, 1);
    const nodes = try arena.alloc(*Node, cfg.n);
    for (nodes, 0..) |*np, i| {
        const node = try arena.create(Node);
        node.fx = try test_dag.Fixture.init(gpa, .{ .stakes = stakes, .own_index = @intCast(i), .mode = .stake_based });
        node.noop = .{};
        node.tracker = tracker_mod.TransactionVoteTracker.init(gpa, node.fx.context, node.fx.dag, node.noop.verifier());
        node.fin = commit_finalizer.CommitFinalizer.init(gpa, node.fx.context, node.fx.dag, &node.tracker);
        node.signer = .{};
        node.txs = .{};
        node.commits = .empty;
        node.rejected_total = 0;
        np.* = node;
    }
    defer for (nodes) |node| {
        node.core.deinit();
        node.fin.deinit();
        node.tracker.deinit();
        node.commits.deinit(gpa);
        node.fx.deinit();
    };

    // Boot all cores (recover proposes round 1).
    var queue: std.ArrayList(Pending) = .empty;
    defer queue.deinit(gpa);
    var tick: u64 = 0;
    for (nodes, 0..) |node, i| {
        var out: core_mod.Output = .{};
        node.core = try core_mod.Core.recover(gpa, arena, .{
            .context = node.fx.context,
            .dag = node.fx.dag,
            .schedule = node.fx.schedule,
            .tracker = &node.tracker,
            .finalizer = &node.fin,
            .signer = node.signer.signer(),
            .tx_source = node.txs.source(),
            .sync_last_known_own_block = false,
        }, &out);
        try collect(gpa, arena, nodes, &queue, i, &out, tick, rnd, cfg);
    }

    const tick_ms: u64 = 60;
    const ticks = cfg.run_ms / tick_ms;
    var total_blocks: usize = 0;
    while (tick < ticks) : (tick += 1) {
        for (nodes) |node| {
            node.fx.clock.now_ms = tick * tick_ms;
            node.fx.clock.mono_ns = tick * tick_ms * std.time.ns_per_ms;
        }
        // Deliver due messages.
        var i: usize = 0;
        while (i < queue.items.len) {
            if (queue.items[i].deliver_at <= tick) {
                const p = queue.swapRemove(i);
                var out: core_mod.Output = .{};
                const node = nodes[p.to];
                // The verify tile votes (SignedBlockVerifier + TransactionVerifier) and registers the
                // block with the vote tracker before the core sees it (authority_service.rs).
                try node.tracker.addVotedBlock(&p.block, &.{});
                try node.core.addBlocks(arena, &.{p.block}, &out);
                try collect(gpa, arena, nodes, &queue, p.to, &out, tick, rnd, cfg);
            } else i += 1;
        }
        // Timers: every node tries to propose on its clock round (the min-delay and leader checks apply).
        for (nodes, 0..) |node, k| {
            var out: core_mod.Output = .{};
            try node.core.newBlock(arena, node.fx.dag.thresholdClockRound(), false, &out);
            try collect(gpa, arena, nodes, &queue, k, &out, tick, rnd, cfg);
        }
        // Periodic sync: resend a lagging node the blocks it is missing (drops are repaired).
        if (cfg.drop_permille > 0 and tick % 5 == 0) {
            for (nodes, 0..) |node, k| {
                for (nodes, 0..) |other, o| {
                    if (o == k) continue;
                    var r: types.Round = 1;
                    const hi = other.fx.dag.highestAcceptedRound();
                    while (r <= hi) : (r += 1) {
                        const bs = other.fx.dag.getCachedBlocks(arena, @intCast(o), r) catch continue;
                        for (bs) |b| {
                            if (b.block.inner.round() != r) continue;
                            if (node.fx.dag.containsBlock(b.reference()) catch true) continue;
                            try queue.append(gpa, .{ .deliver_at = tick + 1, .to = k, .block = try digest_mod.cloneVerified(arena, b) });
                        }
                    }
                }
            }
        }
    }

    // Invariants.
    var min_c: usize = std.math.maxInt(usize);
    var max_c: usize = 0;
    for (nodes) |node| {
        min_c = @min(min_c, node.commits.items.len);
        max_c = @max(max_c, node.commits.items.len);
        total_blocks += node.signer.signed;
        // One block per round per author: the signer refuses otherwise, and the DAG rejects own equivocation.
    }
    // All commit sequences are prefixes of one another.
    const ref_seq = nodes[0].commits.items;
    for (nodes[1..]) |node| {
        const m = @min(ref_seq.len, node.commits.items.len);
        for (ref_seq[0..m], node.commits.items[0..m]) |a, b| {
            if (a.index != b.index or !std.mem.eql(u8, &a.digest, &b.digest)) return error.CommitSequenceDiverged;
        }
    }
    return .{ .min_commits = min_c, .max_commits = max_c, .total_blocks = total_blocks };
}

fn collect(gpa: Allocator, arena: Allocator, nodes: []*Node, queue: *std.ArrayList(Pending), from: usize, out: *core_mod.Output, tick: u64, rnd: std.Random, cfg: Config) !void {
    const node = nodes[from];
    for (out.committed.items) |*f| {
        try node.commits.append(gpa, f.sub_dag.commit_ref);
        node.rejected_total += f.sub_dag.rejected_transactions_by_block.len;
        f.deinit();
    }
    for (out.proposed.items) |eb| {
        for (nodes, 0..) |_, to| {
            if (to == from) continue;
            if (cfg.drop_permille > 0 and rnd.uintLessThan(u32, 1000) < cfg.drop_permille) continue;
            const delay: u64 = if (cfg.max_delay_ticks > 0) rnd.uintLessThan(u32, cfg.max_delay_ticks + 1) else 0;
            try queue.append(gpa, .{ .deliver_at = tick + 1 + delay, .to = to, .block = try digest_mod.cloneVerified(arena, &eb.block) });
        }
    }
}

test "four cores commit the same sequence (no faults)" {
    const r = try run(std.testing.allocator, .{ .seed = 7, .run_ms = 5_000 });
    try std.testing.expect(r.min_commits >= 10);
}

test "four cores agree under drops and delays, across seeds" {
    for ([_]u64{ 1, 2, 3 }) |seed| {
        const r = try run(std.testing.allocator, .{ .seed = seed, .run_ms = 8_000, .drop_permille = 150, .max_delay_ticks = 3 });
        try std.testing.expect(r.max_commits >= 5);
    }
}

test "sim: seven cores, many seeds, drops and delays" {
    var seed: u64 = 100;
    while (seed < 108) : (seed += 1) {
        const r = try run(std.testing.allocator, .{ .n = 7, .seed = seed, .run_ms = 5_000, .drop_permille = 100, .max_delay_ticks = 2 });
        try std.testing.expect(r.max_commits >= 3);
    }
}
