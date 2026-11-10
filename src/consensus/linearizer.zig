//! consensus_core::linearizer::Linearizer at mainnet-v1.83.1 (`consensus_linearize_subdag_v2`):
//! turns committed leaders into CommittedSubDags: the leader's causal history not yet committed
//! and above the GC round (stack walk from the leader), sorted by (round, authority) or, with
//! `shuffle_commit_blocks`, by (round, Blake2b256(leader-digest-seed ++ block digest)); then a Commit
//! with timestamp = max(stake-weighted median of the leader's parents' timestamps, previous commit
//! timestamp) (`consensus_median_based_commit_timestamp`) and the previous commit's digest, added
//! to the DagState. Owner lane: val-consensus-core.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types.zig");
const err = @import("error.zig");
const digest_mod = @import("digest.zig");
const dag_mod = @import("dag_state.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;
const Block = *const types.VerifiedBlock;

pub const Linearizer = struct {
    context: *const Context,
    dag: *dag_mod.DagState,

    /// `handle_commit`: one CommittedSubDag per leader, in order; each also records its Commit in
    /// the DagState (so the next leader's linearization sees the committed set). Everything returned
    /// (blocks included, deep copies) is allocated from `arena` and outlives DAG eviction.
    pub fn handleCommit(self: *Linearizer, arena: Allocator, leaders: []const Block) err.Error![]types.CommittedSubDag {
        const out = arena.alloc(types.CommittedSubDag, leaders.len) catch return error.OutOfMemory;
        for (leaders, out) |leader, *o| o.* = try self.collectSubDagAndCommit(arena, leader);
        return out;
    }

    fn collectSubDagAndCommit(self: *Linearizer, arena: Allocator, leader: Block) err.Error!types.CommittedSubDag {
        const dag = self.dag;
        const last_index = dag.lastCommitIndex();
        const last_digest = dag.lastCommitDigest();
        const last_ts = dag.lastCommitTimestampMs();

        const to_commit = try linearizeSubDag(arena, leader, dag, self.context.protocol_config.shuffle_commit_blocks);
        const ts = try calculateCommitTimestamp(self.context, dag, leader, last_ts);

        const refs = arena.alloc(types.BlockRef, to_commit.len) catch return error.OutOfMemory;
        for (refs, to_commit) |*r, b| r.* = b.reference();
        const commit: types.Commit = .{ .V1 = .{
            .index = last_index + 1,
            .previous_digest = last_digest,
            .timestamp_ms = ts,
            .leader = leader.reference(),
            .blocks = refs,
        } };
        const ser = bcs.encodeAlloc(types.Commit, arena, &commit) catch return error.OutOfMemory;
        const trusted: types.TrustedCommit = .{ .commit = commit, .serialized = ser, .digest = digest_mod.commitDigest(ser) };
        try dag.addCommit(trusted);

        // Deep copies so the sub-dag outlives DagState eviction.
        const blocks = arena.alloc(types.VerifiedBlock, to_commit.len) catch return error.OutOfMemory;
        for (blocks, to_commit) |*o, b| o.* = try digest_mod.cloneVerified(arena, b);
        return .{
            .leader = leader.reference(),
            .blocks = blocks,
            .timestamp_ms = ts,
            .commit_ref = trusted.reference(),
            .decided_with_local_blocks = true,
            .recovered_rejected_transactions = false,
            .rejected_transactions_by_block = &.{},
        };
    }
};

/// `linearize_sub_dag`: marks the leader and its uncommitted ancestors above the GC round as
/// committed and returns them in commit order (pointers into the DAG).
pub fn linearizeSubDag(arena: Allocator, leader: Block, dag: *dag_mod.DagState, shuffle_blocks: bool) err.Error![]Block {
    const gc = dag.gcRound();
    const leader_ref = leader.reference();
    if (!try dag.setCommitted(leader_ref)) return error.Invariant; // leader committed twice

    var buffer: std.ArrayList(Block) = .empty;
    var to_commit: std.ArrayList(Block) = .empty;
    buffer.append(arena, leader) catch return error.OutOfMemory;
    while (buffer.pop()) |x| {
        to_commit.append(arena, x) catch return error.OutOfMemory;
        for (x.block.inner.ancestors()) |anc| {
            if (anc.round <= gc) continue;
            if (try dag.isCommitted(anc)) continue;
            const b = dag.getBlock(anc) orelse return error.MissingBlock;
            buffer.append(arena, b) catch return error.OutOfMemory;
            if (!try dag.setCommitted(anc)) return error.Invariant;
        }
    }
    for (to_commit.items) |b| if (b.block.inner.round() <= gc) return error.Invariant;

    if (shuffle_blocks) {
        const seed = digest_mod.blake2b(&leader.digest);
        const Key = struct { round: types.Round, hash: [32]u8, block: Block };
        const keys = arena.alloc(Key, to_commit.items.len) catch return error.OutOfMemory;
        for (keys, to_commit.items) |*k, b| {
            const r = b.reference();
            var h = @import("hash").Blake2b256.init();
            h.update(&seed);
            h.update(&r.digest);
            var d: [32]u8 = undefined;
            h.final(&d);
            k.* = .{ .round = r.round, .hash = d, .block = b };
        }
        std.sort.block(Key, keys, {}, struct {
            fn lt(_: void, a: Key, b: Key) bool {
                if (a.round != b.round) return a.round < b.round;
                return std.mem.order(u8, &a.hash, &b.hash) == .lt;
            }
        }.lt);
        for (to_commit.items, keys) |*o, k| o.* = k.block;
    } else {
        std.sort.block(Block, to_commit.items, {}, struct {
            fn lt(_: void, a: Block, b: Block) bool {
                const ar = a.block.inner.round();
                const br = b.block.inner.round();
                if (ar != br) return ar < br;
                return a.block.inner.author() < b.block.inner.author();
            }
        }.lt);
    }
    return to_commit.items;
}

/// `calculate_commit_timestamp`.
pub fn calculateCommitTimestamp(context: *const Context, dag: *const dag_mod.DagState, leader: Block, last_commit_timestamp_ms: types.BlockTimestampMs) err.Error!types.BlockTimestampMs {
    const lr = leader.block.inner.round();
    const Entry = struct { ts: types.BlockTimestampMs, stake: types.Stake };
    // One parent per authority at most (the verifier rejects duplicate authors), so the committee
    // bound suffices; Rust has no cap at all.
    var buf: [@import("committee.zig").max_committee_size]Entry = undefined;
    var n: usize = 0;
    var total: types.Stake = 0;
    for (leader.block.inner.ancestors()) |a| {
        if (a.round != lr -% 1) continue;
        const b = dag.getBlock(a) orelse return error.MissingBlock;
        if (n >= buf.len) return error.Invariant;
        const stake = context.committee.stake(b.block.inner.author());
        buf[n] = .{ .ts = b.block.inner.timestampMs(), .stake = stake };
        n += 1;
        total += stake;
    }
    if (n == 0 or total < context.committee.quorum_threshold) return error.Invariant;
    return @max(medianByStake(Entry, buf[0..n], total), last_commit_timestamp_ms);
}

fn medianByStake(comptime Entry: type, entries: []Entry, total: types.Stake) types.BlockTimestampMs {
    std.sort.block(Entry, entries, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return a.ts < b.ts;
        }
    }.lt);
    var cumulative: types.Stake = 0;
    for (entries) |e| {
        cumulative += e.stake;
        if (cumulative > total / 2) return e.ts;
    }
    return entries[entries.len - 1].ts;
}

test "median timestamp by stake" {
    const E = struct { ts: u64, stake: u64 };
    var a = [_]E{ .{ .ts = 30, .stake = 1 }, .{ .ts = 10, .stake = 1 }, .{ .ts = 20, .stake = 1 }, .{ .ts = 40, .stake = 1 } };
    // total 4, half 2: cumulative 1,2,3 -> third entry (30).
    try std.testing.expectEqual(@as(u64, 30), medianByStake(E, &a, 4));
}

test "commit timestamp of a leader with more than 256 parents (committee of 300)" {
    const test_dag = @import("test_dag.zig");
    const gpa = std.testing.allocator;
    const stakes = try gpa.alloc(u64, 300);
    defer gpa.free(stakes);
    @memset(stakes, 1);
    const f = try test_dag.Fixture.init(gpa, .{ .stakes = stakes });
    defer f.deinit();
    const r1 = try f.fullLayers(1, 1, f.genesisRefs());
    // The leader's own block first, then every other round-1 block: 300 parents.
    const anc = try f.arena().alloc(types.BlockRef, r1.len);
    anc[0] = r1[7];
    var k: usize = 1;
    for (r1) |r| if (r.author != 7) {
        anc[k] = r;
        k += 1;
    };
    const leader_ref = try f.addBlock(2, 7, anc, null);
    const leader = f.dag.getBlock(leader_ref).?;
    // Parent timestamps 1000 + author, equal stakes: Rust's median is the 151st smallest.
    try std.testing.expectEqual(@as(u64, 1150), try calculateCommitTimestamp(f.context, f.dag, leader, 0));
    try std.testing.expectEqual(@as(u64, 5000), try calculateCommitTimestamp(f.context, f.dag, leader, 5000));
}
