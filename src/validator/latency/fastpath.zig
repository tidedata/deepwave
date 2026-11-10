//! The owned-object fast path at mainnet-v1.83.1, and what is measurable around it
//! (docs/VALIDATOR-DESIGN.md 10.6).
//!
//! What the protocol allows. Mainnet protocol 141 has `mysticeti_fastpath: true` and
//! `disable_preconsensus_locking: true`: owned-object transactions go through consensus like
//! every other transaction, are voted on inside blocks (reject lists, `BlockTransactionVotes`),
//! and are executed once their commit is finalized by `CommitFinalizer`. There is no
//! pre-consensus certificate and no execution before commit in 1.83.1, so deepwave cannot (and does
//! not) execute earlier: the "fast path" is the finalization rule in `commit_finalizer.rs`.
//! That rule is implemented here as `finalizeBlock` (pure, byte-for-byte the direct-finalize
//! branch of `try_direct_finalize_commit`) and `VoteTracker` (the reject-vote aggregation of
//! `transaction_vote_tracker.rs`), so the shadow can compare every outcome with the Rust one.
//!
//! What deepwave adds, measurement only. `Observer` watches the DAG and records, for every block,
//! how long after receipt a quorum of later blocks had it as an ancestor (the "DAG certificate",
//! which is when a transaction without reject votes is already safe) and how much earlier that
//! was than the commit that finalizes it. That lead time is the ceiling of any future fast path
//! and the number to bring to Mysten. The Observer never changes what the node does: it signs
//! nothing, executes nothing, and `Flags.experimental_fast_path` (an active early-execution
//! path) is refused, because the protocol has none to follow.
const std = @import("std");
const consensus = @import("consensus");
const hist = @import("hist.zig");

const types = consensus.types;
const Committee = consensus.committee.Committee;

pub const max_authorities = 256;
pub const Voters = std.StaticBitSet(max_authorities);

pub const Error = error{ CommitteeTooLarge, OutOfMemory, ExperimentalRefused };

// ------------------------------------------------------------------ vote tracker

const TxKey = struct { block: types.BlockRef, index: types.TransactionIndex };

const RejectAgg = struct {
    voters: Voters = .empty,
    stake: types.Stake = 0,
};

/// consensus_core::transaction_vote_tracker::VoteTrackerState: per (block, transaction) the stake
/// of the authorities that rejected it, each counted once. Votes may arrive before the block.
/// Like Rust, every voting block gets an entry of its own (`known`), so `finalizeBlock` can tell
/// "no reject votes" from "no vote information".
pub const VoteTracker = struct {
    gpa: std.mem.Allocator,
    committee: *const Committee,
    rejects: std.AutoHashMap(TxKey, RejectAgg),
    /// Blocks passed to `addVotingBlock` (Rust creates a `votes` entry for each).
    known: std.AutoHashMap(types.BlockRef, void),
    gc_round: types.Round = 0,
    max_entries: usize,
    /// Highest round of a target block whose reject votes were dropped because the tracker was
    /// full (0 = nothing dropped). Blocks at or below it may have incomplete votes, so
    /// `finalizeBlock` reports them pending. Cleared by `gc` once the GC round passes it.
    incomplete_round: types.Round = 0,
    /// Reject entries dropped for lack of room (diagnostic).
    dropped: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, committee: *const Committee, max_entries: usize) Error!VoteTracker {
        if (committee.size() > max_authorities) return error.CommitteeTooLarge;
        return .{ .gpa = gpa, .committee = committee, .rejects = .init(gpa), .known = .init(gpa), .max_entries = max_entries };
    }

    pub fn deinit(v: *VoteTracker) void {
        v.rejects.deinit();
        v.known.deinit();
    }

    /// Adds the reject votes `block` carries and registers `ref` (the block's own reference) as
    /// a block with vote information. Votes on blocks at or below the GC round are ignored.
    /// Past `max_entries` new entries are not stored: the loss is recorded in `incomplete_round`
    /// (never silent) and affected blocks finalize as pending.
    pub fn addVotingBlock(v: *VoteTracker, ref: types.BlockRef, block: *const types.Block) Error!void {
        const author = block.author();
        if (author >= v.committee.size()) return;
        if (ref.round > v.gc_round and !v.known.contains(ref)) {
            if (v.known.count() >= v.max_entries) {
                // The block has no entry: finalizeBlock reports NoVoteInfo for it.
                v.dropped += 1;
            } else {
                try v.known.put(ref, {});
            }
        }
        for (block.transactionVotes()) |bv| {
            if (bv.block_ref.round <= v.gc_round) continue;
            for (bv.rejects) |idx| {
                const key: TxKey = .{ .block = bv.block_ref, .index = idx };
                const gop = try v.rejects.getOrPut(key);
                if (!gop.found_existing) {
                    if (v.rejects.count() > v.max_entries) {
                        _ = v.rejects.remove(key);
                        v.dropped += 1;
                        v.incomplete_round = @max(v.incomplete_round, bv.block_ref.round);
                        continue;
                    }
                    gop.value_ptr.* = .{};
                }
                if (!gop.value_ptr.voters.isSet(author)) {
                    gop.value_ptr.voters.set(author);
                    gop.value_ptr.stake += v.committee.stake(author);
                }
            }
        }
    }

    pub fn rejectStake(v: *const VoteTracker, ref: types.BlockRef, idx: types.TransactionIndex) types.Stake {
        return if (v.rejects.get(.{ .block = ref, .index = idx })) |a| a.stake else 0;
    }

    /// True when the tracker holds vote information for `ref` (it saw the block as a voter, and
    /// it is above the GC round).
    pub fn hasInfo(v: *const VoteTracker, ref: types.BlockRef) bool {
        return ref.round > v.gc_round and v.known.contains(ref);
    }

    pub fn gc(v: *VoteTracker, round: types.Round) void {
        v.gc_round = @max(v.gc_round, round);
        if (v.incomplete_round <= v.gc_round) v.incomplete_round = 0;
        var doomed: std.ArrayList(TxKey) = .empty;
        defer doomed.deinit(v.gpa);
        var it = v.rejects.keyIterator();
        while (it.next()) |k| {
            if (k.block.round <= v.gc_round) doomed.append(v.gpa, k.*) catch break;
        }
        for (doomed.items) |k| _ = v.rejects.remove(k);
        var doomed_blocks: std.ArrayList(types.BlockRef) = .empty;
        defer doomed_blocks.deinit(v.gpa);
        var bit = v.known.keyIterator();
        while (bit.next()) |k| {
            if (k.round <= v.gc_round) doomed_blocks.append(v.gpa, k.*) catch break;
        }
        for (doomed_blocks.items) |k| _ = v.known.remove(k);
    }
};

pub const Outcome = enum { finalized, rejected, pending };

pub const FinalizeError = error{
    /// The tracker has no vote information for the block (never seen, dropped, or already
    /// garbage collected). Rust panics here ("incorrectly gc'ed"); deepwave reports it so a shadow
    /// comparison can flag it instead of calling the transactions finalized.
    NoVoteInfo,
};

/// The direct-finalize decision for the transactions of one committed block
/// (`try_direct_finalize_commit`): with no reject votes a transaction is finalized, with a
/// quorum of reject stake it is rejected, in between it stays pending for indirect finalization.
/// `vote_gc_round` is `dag_state.calculate_gc_round(leader.round + 3)`: transactions of a block
/// at or below it are all pending (the voting blocks may have discarded them). Writes one
/// outcome per transaction into `out` (len = number of transactions).
///
/// This is only the per-block direct rule. The commit-level prerequisite is `commitReady`, and
/// Rust's result after indirect finalization (`INDIRECT_REJECT_DEPTH`) is not modelled: compare
/// against the direct labels only (`finalizer_transaction_status`), not the final pending set.
pub fn finalizeBlock(
    votes: *const VoteTracker,
    ref: types.BlockRef,
    vote_gc_round: types.Round,
    out: []Outcome,
) FinalizeError!void {
    if (ref.round <= vote_gc_round) {
        @memset(out, .pending);
        return;
    }
    if (!votes.hasInfo(ref)) return error.NoVoteInfo;
    // Votes for this block may have been dropped for lack of room: do not claim finalized.
    if (ref.round <= votes.incomplete_round) {
        @memset(out, .pending);
        return;
    }
    for (out, 0..) |*o, i| {
        const s = votes.rejectStake(ref, @intCast(i));
        o.* = if (s == 0) .finalized else if (s >= votes.committee.quorum_threshold) .rejected else .pending;
    }
}

/// Waves a remote-decided commit waits before `process_commit` finalizes it (leader round + 3).
pub const commit_wave_length: types.Round = 3;

/// The `process_commit` gate: a commit decided with local blocks is finalized right away; one
/// decided without them waits until a commit at `leader_round + commit_wave_length` exists
/// (`highest_commit_leader_round`).
pub fn commitReady(decided_with_local_blocks: bool, leader_round: types.Round, highest_commit_leader_round: types.Round) bool {
    return decided_with_local_blocks or highest_commit_leader_round >= leader_round +| commit_wave_length;
}

// ------------------------------------------------------------------ observer

const BlockInfo = struct {
    first_seen_ns: u64,
    voters: Voters = .empty,
    stake: types.Stake = 0,
    cert_ns: u64 = 0,
    round: types.Round,
    num_txs: u16,
};

pub const Observer = struct {
    gpa: std.mem.Allocator,
    committee: *const Committee,
    blocks: std.AutoHashMap(types.BlockRef, BlockInfo),
    votes: VoteTracker,
    max_blocks: usize,
    /// Received to DAG-certified (a quorum of later blocks include the block), us.
    receive_to_cert: hist.Hist = .{},
    /// DAG-certified to committed: the lead of the certificate over the commit, us.
    cert_to_commit: hist.Hist = .{},
    /// Received to committed, us (reference for the two above).
    receive_to_commit: hist.Hist = .{},
    committed_before_cert: std.atomic.Value(u64) = .init(0),
    untracked: std.atomic.Value(u64) = .init(0),

    pub fn init(gpa: std.mem.Allocator, committee: *const Committee, max_blocks: usize) Error!Observer {
        return .{
            .gpa = gpa,
            .committee = committee,
            .blocks = .init(gpa),
            .votes = try VoteTracker.init(gpa, committee, max_blocks * 4),
            .max_blocks = max_blocks,
        };
    }

    pub fn deinit(o: *Observer) void {
        o.blocks.deinit();
        o.votes.deinit();
    }

    /// `Flags.experimental_fast_path` has nothing to enable at 1.83.1 (see the file comment).
    pub fn refuseExperimental(enabled: bool) Error!void {
        if (enabled) return error.ExperimentalRefused;
    }

    /// A block entered the DAG (accepted). Counts it as an acceptor of its ancestors and folds in
    /// its reject votes.
    pub fn onBlock(o: *Observer, vb: *const types.VerifiedBlock, now_ns: u64) Error!void {
        const blk = &vb.block.inner;
        const ref = vb.reference();
        if (blk.author() >= o.committee.size()) return;
        try o.votes.addVotingBlock(ref, blk);
        if (o.blocks.count() >= o.max_blocks and !o.blocks.contains(ref)) {
            _ = o.untracked.fetchAdd(1, .monotonic);
        } else {
            const gop = try o.blocks.getOrPut(ref);
            if (!gop.found_existing) gop.value_ptr.* = .{ .first_seen_ns = now_ns, .round = ref.round, .num_txs = @intCast(@min(blk.transactions().len, std.math.maxInt(u16))) };
        }
        const author = blk.author();
        for (blk.ancestors()) |anc| {
            if (anc.round >= ref.round) continue;
            const info = o.blocks.getPtr(anc) orelse continue;
            if (info.voters.isSet(author)) continue;
            info.voters.set(author);
            info.stake += o.committee.stake(author);
            if (info.cert_ns == 0 and o.committee.reachedQuorum(info.stake)) {
                info.cert_ns = now_ns;
                o.receive_to_cert.record(now_ns -| info.first_seen_ns);
            }
        }
    }

    /// The commit finalizing `refs` (the sub-dag's blocks) happened at `now_ns`.
    pub fn onCommit(o: *Observer, refs: []const types.BlockRef, now_ns: u64) void {
        for (refs) |r| {
            const info = o.blocks.getPtr(r) orelse continue;
            o.receive_to_commit.record(now_ns -| info.first_seen_ns);
            if (info.cert_ns != 0) {
                o.cert_to_commit.record(now_ns -| info.cert_ns);
            } else {
                _ = o.committed_before_cert.fetchAdd(1, .monotonic);
            }
            _ = o.blocks.remove(r);
        }
    }

    pub fn gc(o: *Observer, round: types.Round) void {
        o.votes.gc(round);
        var doomed: std.ArrayList(types.BlockRef) = .empty;
        defer doomed.deinit(o.gpa);
        var it = o.blocks.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.round <= round) doomed.append(o.gpa, e.key_ptr.*) catch break;
        }
        for (doomed.items) |k| _ = o.blocks.remove(k);
    }

    pub fn render(o: *const Observer, out: *std.ArrayList(u8), gpa: std.mem.Allocator) !void {
        try out.appendSlice(gpa, "fast path observer (DAG certificate vs commit, ms)\n");
        const rows = [_]struct { n: []const u8, h: *const hist.Hist }{
            .{ .n = "received_to_certified", .h = &o.receive_to_cert },
            .{ .n = "certified_to_committed", .h = &o.cert_to_commit },
            .{ .n = "received_to_committed", .h = &o.receive_to_commit },
        };
        for (rows) |r| {
            try out.print(gpa, "  {s:<24}{d:>8}  p50 {d}.{d:0>3}  p99 {d}.{d:0>3}\n", .{
                r.n,                              r.h.count(),
                r.h.percentileUs(0.5) / 1000,     r.h.percentileUs(0.5) % 1000,
                r.h.percentileUs(0.99) / 1000,    r.h.percentileUs(0.99) % 1000,
            });
        }
        try out.print(gpa, "  committed before certified {d}, untracked {d}\n", .{ o.committed_before_cert.load(.monotonic), o.untracked.load(.monotonic) });
    }
};

// ------------------------------------------------------------------ tests

fn testCommittee(auths: []consensus.committee.Authority) !Committee {
    for (auths, 0..) |*a, i| a.* = .{ .stake = (&[_]u64{ 1, 2, 3, 4 })[i], .address = "", .hostname = "", .authority_name = "", .protocol_key = @as([32]u8, @splat(0)), .network_key = @as([32]u8, @splat(0)) };
    return Committee.init(0, auths);
}

fn mkBlock(round: types.Round, author: u32, anc: []const types.BlockRef, votes: []const types.BlockTransactionVotes) types.Block {
    return .{ .V2 = .{
        .epoch = 0,
        .round = round,
        .author = author,
        .timestamp_ms = 0,
        .ancestors = anc,
        .transactions = &.{},
        .transaction_votes = votes,
        .commit_votes = &.{},
        .misbehavior_reports = &.{},
    } };
}

test "vote tracker aggregates reject stake once per author and finalizeBlock follows the Rust rule" {
    var auths: [4]consensus.committee.Authority = undefined;
    const c = try testCommittee(&auths);
    var vt = try VoteTracker.init(std.testing.allocator, &c, 1000);
    defer vt.deinit();
    const target: types.BlockRef = .{ .round = 1, .author = 0, .digest = @as([32]u8, @splat(1)) };
    // stakes [1,2,3,4], total 10: f = 3, quorum = 7
    const rej0 = [_]types.BlockTransactionVotes{.{ .block_ref = target, .rejects = &.{ 0, 1 } }};
    const rej1 = [_]types.BlockTransactionVotes{.{ .block_ref = target, .rejects = &.{1} }};
    const b3 = mkBlock(2, 3, &.{}, &rej0); // author 3, stake 4
    const b2 = mkBlock(2, 2, &.{}, &rej1); // author 2, stake 3
    const tb = mkBlock(1, 0, &.{}, &.{});
    const r3: types.BlockRef = .{ .round = 2, .author = 3, .digest = @as([32]u8, @splat(3)) };
    const r2: types.BlockRef = .{ .round = 2, .author = 2, .digest = @as([32]u8, @splat(2)) };
    try vt.addVotingBlock(target, &tb); // the committed block itself has vote info
    try vt.addVotingBlock(r3, &b3);
    try vt.addVotingBlock(r3, &b3); // duplicate: counted once
    try vt.addVotingBlock(r2, &b2);
    try std.testing.expectEqual(@as(u64, 4), vt.rejectStake(target, 0));
    try std.testing.expectEqual(@as(u64, 7), vt.rejectStake(target, 1));
    var out: [3]Outcome = undefined;
    try finalizeBlock(&vt, target, 0, &out);
    try std.testing.expectEqual(Outcome.pending, out[0]); // 4 < 7
    try std.testing.expectEqual(Outcome.rejected, out[1]); // 7 >= 7
    try std.testing.expectEqual(Outcome.finalized, out[2]);
    try finalizeBlock(&vt, target, 1, &out); // block round 1 <= vote gc round 1: all pending
    try std.testing.expectEqual(Outcome.pending, out[2]);
    vt.gc(1);
    try std.testing.expectEqual(@as(u64, 0), vt.rejectStake(target, 1));
    // GC'd block: no vote information, not "finalized"
    try std.testing.expectError(error.NoVoteInfo, finalizeBlock(&vt, target, 0, &out));
    // a block the tracker never saw
    const other: types.BlockRef = .{ .round = 5, .author = 1, .digest = @as([32]u8, @splat(9)) };
    try std.testing.expectError(error.NoVoteInfo, finalizeBlock(&vt, other, 0, &out));
}

test "tracker overflow is recorded and makes affected blocks pending, never finalized" {
    var auths: [4]consensus.committee.Authority = undefined;
    const c = try testCommittee(&auths);
    var vt = try VoteTracker.init(std.testing.allocator, &c, 1);
    defer vt.deinit();
    const t1: types.BlockRef = .{ .round = 3, .author = 0, .digest = @as([32]u8, @splat(1)) };
    const t2: types.BlockRef = .{ .round = 4, .author = 1, .digest = @as([32]u8, @splat(2)) };
    const rv = [_]types.BlockTransactionVotes{ .{ .block_ref = t1, .rejects = &.{0} }, .{ .block_ref = t2, .rejects = &.{0} } };
    const vb = mkBlock(5, 3, &.{}, &rv);
    const vref: types.BlockRef = .{ .round = 5, .author = 3, .digest = @as([32]u8, @splat(5)) };
    try vt.addVotingBlock(vref, &vb);
    try std.testing.expect(vt.dropped > 0);
    try std.testing.expectEqual(@as(types.Round, 4), vt.incomplete_round);
    // register the committed blocks so only the overflow decides
    vt.max_entries = 100;
    try vt.addVotingBlock(t2, &mkBlock(4, 1, &.{}, &.{}));
    var out: [1]Outcome = undefined;
    try finalizeBlock(&vt, t2, 0, &out);
    try std.testing.expectEqual(Outcome.pending, out[0]);
    try std.testing.expect(commitReady(true, 10, 0));
    try std.testing.expect(!commitReady(false, 10, 12));
    try std.testing.expect(commitReady(false, 10, 13));
}

test "observer measures certificate lead over commit" {
    var auths: [4]consensus.committee.Authority = undefined;
    const c = try testCommittee(&auths);
    var o = try Observer.init(std.testing.allocator, &c, 100);
    defer o.deinit();
    const dg = @as([32]u8, @splat(0));
    var r1: types.BlockRef = .{ .round = 1, .author = 0, .digest = dg };
    r1.digest[0] = 1;
    const b1: types.VerifiedBlock = .{ .block = .{ .inner = mkBlock(1, 0, &.{}, &.{}), .signature = "" }, .serialized = "", .digest = r1.digest };
    try o.onBlock(&b1, 1_000_000);
    // authors 3 and 2 (stake 7 = quorum) include it at round 2
    const anc = [_]types.BlockRef{r1};
    var d3 = dg;
    d3[0] = 3;
    var d2 = dg;
    d2[0] = 2;
    const v3: types.VerifiedBlock = .{ .block = .{ .inner = mkBlock(2, 3, &anc, &.{}), .signature = "" }, .serialized = "", .digest = d3 };
    const v2: types.VerifiedBlock = .{ .block = .{ .inner = mkBlock(2, 2, &anc, &.{}), .signature = "" }, .serialized = "", .digest = d2 };
    try o.onBlock(&v3, 11_000_000);
    try std.testing.expectEqual(@as(u64, 0), o.receive_to_cert.count());
    try o.onBlock(&v2, 21_000_000); // quorum reached, 20 ms after receipt
    try std.testing.expectEqual(@as(u64, 1), o.receive_to_cert.count());
    try std.testing.expect(o.receive_to_cert.percentileUs(0.5) >= 18_000);
    o.onCommit(&.{r1}, 71_000_000); // committed 50 ms after the certificate
    try std.testing.expectEqual(@as(u64, 1), o.cert_to_commit.count());
    const lead = o.cert_to_commit.percentileUs(0.5);
    try std.testing.expect(lead >= 46_000 and lead <= 54_000);
    var txt: std.ArrayList(u8) = .empty;
    defer txt.deinit(std.testing.allocator);
    try o.render(&txt, std.testing.allocator);
    try std.testing.expect(txt.items.len > 0);
    try std.testing.expectError(error.ExperimentalRefused, Observer.refuseExperimental(true));
}
