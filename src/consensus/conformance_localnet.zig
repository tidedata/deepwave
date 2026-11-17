//! Suite `consensus-localnet` (val-truth): a real consensus history from Mysten's own validators,
//! replayed through deepwave's consensus core.
//!
//! The history is a Mysten localnet capture (tools/truth/consensus/capture.sh): four unchanged
//! sui-node 1.83.1 validators under transaction load for several epochs. tools/truth/consensus/dump
//! writes, per epoch, every block and commit the validators stored (`epoch-N.vec`, the union of the
//! four RocksDB stores, equal where they overlap), and committees.py writes the consensus Context each
//! validator started that epoch with (`epoch-N.meta`: protocol version, epoch start time, committee
//! stakes and keys, from sui-node's own log lines). Files: `$ZUI_CORPUS/consensus/localnet/`.
//!
//! Per epoch, deepwave builds the Context (`ProtocolConfig.fromProtocol(version, .unknown)`, the
//! committee, stake-based leader election as on a real chain), then feeds the blocks round by round:
//! - every block goes through deepwave's SignedBlockVerifier (signature against the committee's
//!   protocol key, ancestors, limits) and must be accepted with the digest Mysten stored, and its
//!   round-1 genesis ancestors must be deepwave's genesis blocks for that epoch (item `.../block/R/A`);
//! - the accepted blocks go through Core as an observer (BlockManager, DagState, pipelined
//!   UniversalCommitter, Linearizer, leader schedule updates from reputation scores, the
//!   TransactionVoteTracker and CommitFinalizer); every commit deepwave decides must equal Mysten's
//!   commit at that index: digest (so the bytes: the digest is Blake2b256 of the Commit), leader,
//!   timestamp and the ordered block list (`.../commit/I`). deepwave must reach every commit Mysten stored;
//!   commits past Mysten's last one (blocks of the union no single validator committed before it
//!   stopped) are counted, not compared;
//! - every commit Mysten finalized carries the same rejected transactions in deepwave (`.../final/I`);
//! - each leader schedule update's reputation scores and commit range equal Mysten's CommitInfo
//!   (`.../scores/I`).
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types.zig");
const digest_mod = @import("digest.zig");
const test_dag = @import("test_dag.zig");
const core_mod = @import("core.zig");
const verifier_mod = @import("verifier.zig");
const tracker_mod = @import("transaction_vote_tracker.zig");
const commit_finalizer = @import("commit_finalizer.zig");
const config = @import("config.zig");

const Allocator = std.mem.Allocator;
const dir = "consensus/localnet";

pub const suites = [_]harness.Suite{
    .{ .name = "consensus-localnet", .lane = "val-truth", .doc = "Mysten localnet consensus history (4 sui-node 1.83.1, several epochs) through zui's verifier and Core: every block accepted, every commit, finalization and leader schedule update equal", .run = run },
};

const Meta = struct {
    epoch: u64,
    protocol: u64,
    start_ms: u64,
    stakes: []u64,
    keys: [][32]u8,
};

fn parseMeta(a: Allocator, text: []const u8) !Meta {
    var m: Meta = .{ .epoch = 0, .protocol = 0, .start_ms = 0, .stakes = &.{}, .keys = &.{} };
    var stakes: std.ArrayList(u64) = .empty;
    var keys: std.ArrayList([32]u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const k = it.next() orelse continue;
        if (std.mem.eql(u8, k, "epoch")) m.epoch = try std.fmt.parseInt(u64, it.next().?, 10);
        if (std.mem.eql(u8, k, "protocol")) m.protocol = try std.fmt.parseInt(u64, it.next().?, 10);
        if (std.mem.eql(u8, k, "start_ms")) m.start_ms = try std.fmt.parseInt(u64, it.next().?, 10);
        if (std.mem.eql(u8, k, "authority")) {
            const idx = try std.fmt.parseInt(usize, it.next().?, 10);
            if (idx != stakes.items.len) return error.BadVector;
            try stakes.append(a, try std.fmt.parseInt(u64, it.next().?, 10));
            var key: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&key, it.next().?);
            try keys.append(a, key);
        }
    }
    m.stakes = stakes.items;
    m.keys = keys.items;
    if (m.stakes.len == 0) return error.BadVector;
    return m;
}

fn hex32(s: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

const RustCommit = struct { digest: [32]u8, commit: types.CommitV1 };
const RustFinal = struct { digest: [32]u8, line: []const u8 };
const RustInfo = struct { digest: [32]u8, scores: []const u8, start: u32, end: u32 };

fn run(ctx: *harness.Ctx) anyerror!void {
    const metas = ctx.listFiles(dir, ".meta") catch |e| {
        ctx.skip(dir, @errorName(e));
        return;
    };
    defer ctx.freeNames(metas);
    if (metas.len == 0) {
        ctx.skip(dir, "no epoch-N.meta files (tools/truth/consensus/capture.sh)");
        return;
    }
    // Numeric epoch order.
    std.mem.sort([]const u8, metas, {}, struct {
        fn lt(_: void, x: []const u8, y: []const u8) bool {
            return epochOf(x) < epochOf(y);
        }
    }.lt);
    for (metas) |name| {
        if (ctx.done()) break;
        try runEpoch(ctx, name);
    }
}

fn epochOf(name: []const u8) u64 {
    const base = if (std.mem.lastIndexOfScalar(u8, name, '/')) |i| name[i + 1 ..] else name;
    const s = std.mem.trimEnd(u8, std.mem.trimStart(u8, base, "epoch-"), ".meta");
    return std.fmt.parseInt(u64, s, 10) catch std.math.maxInt(u64);
}

fn runEpoch(ctx: *harness.Ctx, meta_name: []const u8) !void {
    const gpa = ctx.gpa;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const epoch_no = epochOf(meta_name);
    const meta_path = try std.fmt.allocPrint(a, "{s}/epoch-{d}.meta", .{ dir, epoch_no });
    const vec_path = try std.fmt.allocPrint(a, "{s}/epoch-{d}.vec", .{ dir, epoch_no });
    const label = try std.fmt.allocPrint(a, "epoch{d}", .{epoch_no});
    const meta_text = ctx.corpus.readFileAlloc(ctx.io, meta_path, a, .limited(1 << 20)) catch |e| {
        ctx.skip(meta_path, @errorName(e));
        return;
    };
    const vec_text = ctx.corpus.readFileAlloc(ctx.io, vec_path, a, .limited(1 << 34)) catch |e| {
        ctx.skip(vec_path, @errorName(e));
        return;
    };
    const meta = try parseMeta(a, meta_text);

    // Rust's record of the epoch.
    var blocks: std.ArrayList(struct { round: u32, author: u32, digest: [32]u8, bytes: []const u8 }) = .empty;
    var commits: std.AutoArrayHashMapUnmanaged(u32, RustCommit) = .empty;
    var finals: std.AutoArrayHashMapUnmanaged(u32, RustFinal) = .empty;
    var infos: std.ArrayList(RustInfo) = .empty;
    var max_commit: u32 = 0;
    {
        var lines = std.mem.splitScalar(u8, vec_text, '\n');
        while (lines.next()) |line| {
            var it = std.mem.tokenizeScalar(u8, line, ' ');
            const k = it.next() orelse continue;
            if (std.mem.eql(u8, k, "block")) {
                const round = try std.fmt.parseInt(u32, it.next().?, 10);
                const author = try std.fmt.parseInt(u32, it.next().?, 10);
                const d = try hex32(it.next().?);
                try blocks.append(a, .{ .round = round, .author = author, .digest = d, .bytes = try unhex(a, it.next().?) });
            } else if (std.mem.eql(u8, k, "commit")) {
                const index = try std.fmt.parseInt(u32, it.next().?, 10);
                const d = try hex32(it.next().?);
                const bytes = try unhex(a, it.next().?);
                const c = try bcs.decode(types.Commit, a, bytes);
                try commits.put(a, index, .{ .digest = d, .commit = c.V1 });
                max_commit = @max(max_commit, index);
            } else if (std.mem.eql(u8, k, "final")) {
                const index = try std.fmt.parseInt(u32, it.next().?, 10);
                const d = try hex32(it.next().?);
                try finals.put(a, index, .{ .digest = d, .line = it.rest() });
            } else if (std.mem.eql(u8, k, "info")) {
                _ = it.next(); // index
                const d = try hex32(it.next().?);
                _ = it.next(); // committed rounds
                const scores = it.next().?;
                const start = try std.fmt.parseInt(u32, it.next().?, 10);
                const end = try std.fmt.parseInt(u32, it.next().?, 10);
                try infos.append(a, .{ .digest = d, .scores = scores, .start = start, .end = end });
            }
        }
    }

    // deepwave's consensus for that epoch: the Context sui-node started with, observer, stake-based
    // leader election (the production path; the committer vectors use Rust's cfg(test) one).
    const pc = config.ProtocolConfig.fromProtocol(meta.protocol, .unknown) catch {
        ctx.skip(label, "protocol version unsupported by zui's protocol tables");
        return;
    };
    const fx = try test_dag.Fixture.init(gpa, .{
        .stakes = meta.stakes,
        .epoch = meta.epoch,
        .epoch_start_ms = meta.start_ms,
        .protocol = pc,
        .own_index = null,
        .mode = .stake_based,
    });
    defer fx.deinit();
    for (fx.authorities, meta.keys) |*au, key| au.protocol_key = key;
    var noop: verifier_mod.NoopTransactionVerifier = .{};
    var tracker = tracker_mod.TransactionVoteTracker.init(gpa, fx.context, fx.dag, noop.verifier());
    defer tracker.deinit();
    var fin = commit_finalizer.CommitFinalizer.init(gpa, fx.context, fx.dag, &tracker);
    defer fin.deinit();
    var core = blk: {
        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        var out: core_mod.Output = .{};
        break :blk try core_mod.Core.recover(gpa, scratch.allocator(), .{
            .context = fx.context,
            .dag = fx.dag,
            .schedule = fx.schedule,
            .tracker = &tracker,
            .finalizer = &fin,
        }, &out);
    };
    defer core.deinit();
    const genesis = fx.genesisRefs();
    const verifier = verifier_mod.SignedBlockVerifier.init(fx.context, noop.verifier(), genesis);
    const votes = try a.alloc(types.TransactionIndex, 1 << 16);

    var zui_commits: u32 = 0;
    var extra: u32 = 0;
    var finalized_seen: usize = 0;
    var finalized_zui_only: usize = 0;
    var rejected_blocks: usize = 0;
    var last_range: types.CommitRange = .{ .start = 0, .end_exclusive = 0 };
    var score_updates: usize = 0;
    var score_matched: usize = 0;
    var batch: std.ArrayList(types.VerifiedBlock) = .empty;

    var i: usize = 0;
    while (i < blocks.items.len) {
        if (ctx.done()) break;
        const round = blocks.items[i].round;
        batch.clearRetainingCapacity();
        while (i < blocks.items.len and blocks.items[i].round == round) : (i += 1) {
            const b = blocks.items[i];
            var nb: [128]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "{s}/block/{d}/{d}", .{ label, b.round, b.author }) catch "block";
            ctx.nextItem();
            var out_block: types.VerifiedBlock = undefined;
            var nv: usize = 0;
            const verdict = try verifier.verifyAndVote(a, b.bytes, &out_block, votes, &nv);
            var c = ctx.check(item);
            switch (verdict) {
                .ok => {
                    c.bytes("block digest", &b.digest, &out_block.digest);
                    c.eql("block round", b.round, out_block.block.inner.round());
                    c.eql("block author", b.author, out_block.block.inner.author());
                    const re = try digest_mod.serializeSignedBlock(ctx.scratch(), &out_block.block);
                    c.bytes("re-encoded block", b.bytes, re);
                },
                .reject => |r| c.failf("zui rejects a block Mysten accepted: {any}", .{r}),
            }
            if (c.finish()) {
                try batch.append(a, out_block);
            } else rejected_blocks += 1;
        }
        for (batch.items) |*vb| try tracker.addVotedBlock(vb, &.{});
        var scratch = std.heap.ArenaAllocator.init(gpa);
        defer scratch.deinit();
        var out: core_mod.Output = .{ .record_linearized = true };
        try core.addBlocks(scratch.allocator(), batch.items, &out);
        defer for (out.committed.items) |*f| f.deinit();

        for (out.linearized.items) |*sd| {
            zui_commits += 1;
            const index = sd.commit_ref.index;
            const want = commits.get(index) orelse {
                if (index > max_commit) {
                    extra += 1;
                    continue;
                }
                ctx.fail(label, "zui commit {d} has no Mysten commit at that index", .{index});
                continue;
            };
            var nb: [128]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "{s}/commit/{d}", .{ label, index }) catch "commit";
            ctx.nextItem();
            var c = ctx.check(item);
            c.eql("commit index", @as(u32, @intCast(zui_commits)), index);
            c.bytes("commit digest", &want.digest, &sd.commit_ref.digest);
            c.eql("leader", true, want.commit.leader.eql(sd.leader));
            c.eql("timestamp", want.commit.timestamp_ms, sd.timestamp_ms);
            c.eql("sub-dag block count", want.commit.blocks.len, sd.blocks.len);
            for (want.commit.blocks, 0..) |r, k| {
                if (k >= sd.blocks.len) break;
                if (!r.eql(sd.blocks[k].reference())) {
                    c.failf("sub-dag block {d}: Mysten {d}/{d}, zui {d}/{d}", .{ k, r.round, r.author, sd.blocks[k].reference().round, sd.blocks[k].reference().author });
                    break;
                }
            }
            _ = c.finish();
        }
        for (out.committed.items) |*f| {
            const sd = &f.sub_dag;
            const want = finals.get(sd.commit_ref.index) orelse {
                finalized_zui_only += 1;
                continue;
            };
            finalized_seen += 1;
            var nb: [128]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "{s}/final/{d}", .{ label, sd.commit_ref.index }) catch "final";
            ctx.nextItem();
            var c = ctx.check(item);
            c.bytes("finalized commit digest", &want.digest, &sd.commit_ref.digest);
            const got = try finalLine(ctx.scratch(), sd);
            c.text("rejected transactions", want.line, got);
            _ = c.finish();
        }
        // Leader schedule updates: compare with Mysten's CommitInfo for the same commit range.
        const rs = fx.schedule.swap_table.reputation_scores;
        if (rs.commit_range.end_exclusive != last_range.end_exclusive and rs.scores_per_authority.len > 0) {
            last_range = rs.commit_range;
            score_updates += 1;
            const end_incl = rs.commit_range.end_exclusive - 1;
            for (infos.items) |inf| {
                if (inf.start != rs.commit_range.start or inf.end != end_incl) continue;
                score_matched += 1;
                var nb: [128]u8 = undefined;
                const item = std.fmt.bufPrint(&nb, "{s}/scores/{d}-{d}", .{ label, inf.start, inf.end }) catch "scores";
                ctx.nextItem();
                var c = ctx.check(item);
                var sb: std.ArrayList(u8) = .empty;
                for (rs.scores_per_authority, 0..) |s, k| {
                    if (k > 0) try sb.append(ctx.scratch(), ',');
                    try sb.print(ctx.scratch(), "{d}", .{s});
                }
                c.text("reputation scores", inf.scores, sb.items);
                _ = c.finish();
            }
        }
    }

    // Epoch totals: deepwave reached every commit Mysten stored, every finalized one, every update.
    {
        var nb: [128]u8 = undefined;
        const item = std.fmt.bufPrint(&nb, "{s}/totals", .{label}) catch "totals";
        ctx.nextItem();
        var c = ctx.check(item);
        c.eql("blocks rejected by zui", @as(usize, 0), rejected_blocks);
        c.eql("Mysten commits zui reached", max_commit, @min(zui_commits, max_commit));
        c.eql("Mysten finalized commits zui finalized", finals.count(), finalized_seen);
        c.eql("Mysten schedule updates zui matched", infos.items.len, score_matched);
        _ = c.finish();
        ctx.detail("INFO consensus-localnet {s}: {d} blocks, {d} Mysten commits, zui {d} commits ({d} past Mysten's last), {d} finalized ({d} only in zui), {d} schedule updates ({d} in Mysten's CommitInfo)\n", .{ label, blocks.items.len, max_commit, zui_commits, extra, finalized_seen, finalized_zui_only, score_updates, infos.items.len });
    }
}

/// The `final` line body zui_consensus_dump.rs writes: `<n> [<round>,<author>,<digest>=<csv|->]...`.
fn finalLine(a: Allocator, sd: *const types.CommittedSubDag) ![]const u8 {
    var s: std.ArrayList(u8) = .empty;
    try s.print(a, "{d}", .{sd.rejected_transactions_by_block.len});
    for (sd.rejected_transactions_by_block) |r| {
        try s.print(a, " {d},{d},{x}=", .{ r.block.round, r.block.author, &r.block.digest });
        if (r.indices.len == 0) try s.append(a, '-');
        for (r.indices, 0..) |t, k| {
            if (k > 0) try s.append(a, ',');
            try s.print(a, "{d}", .{t});
        }
    }
    return s.items;
}
