//! `round_tracker.rs` and `commit_vote_monitor.rs` at mainnet-v1.83.1: what peers have received
//! and accepted (for the propagation delay that stops proposing) and the highest commit index a
//! quorum has voted for (for the commit syncer). Thread-safe (one monitor lock each); sizes are
//! fixed at creation from the committee. Owner lane: val-consensus-net.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const consensus = @import("consensus");
const types = consensus.types;
const Committee = consensus.Committee;
const Monitor = @import("mon.zig").Monitor;

pub const QuorumRound = struct { low: types.Round, high: types.Round };

pub const RoundTracker = struct {
    gpa: Allocator,
    mu: Monitor,
    n: usize,
    own_index: types.AuthorityIndex,
    /// [author][target]: highest accepted round per target seen from blocks of `author`.
    block_accepted: []types.Round,
    probed_accepted: []types.Round,
    probed_received: []types.Round,
    local_highest_received: []types.Round,

    pub fn init(gpa: Allocator, io: Io, committee: *const Committee, own_index: types.AuthorityIndex) Allocator.Error!RoundTracker {
        const n = committee.size();
        const m = try gpa.alloc(types.Round, 3 * n * n + n);
        @memset(m, 0);
        return .{
            .gpa = gpa,
            .mu = Monitor.init(io),
            .n = n,
            .own_index = own_index,
            .block_accepted = m[0 .. n * n],
            .probed_accepted = m[n * n .. 2 * n * n],
            .probed_received = m[2 * n * n .. 3 * n * n],
            .local_highest_received = m[3 * n * n ..],
        };
    }

    pub fn deinit(t: *RoundTracker) void {
        t.gpa.free(t.block_accepted.ptr[0 .. 3 * t.n * t.n + t.n]);
    }

    fn at(t: *const RoundTracker, v: []types.Round, row: usize, col: usize) *types.Round {
        return &@constCast(v)[row * t.n + col];
    }

    /// `update_from_verified_block`: a block (ours or a peer's) and the ancestors it excluded.
    pub fn updateFromVerifiedBlock(t: *RoundTracker, author: types.AuthorityIndex, round: types.Round, ancestors: []const types.BlockRef, excluded: []const types.BlockRef) void {
        if (author >= t.n) return;
        t.mu.lock();
        defer t.mu.unlock();
        t.local_highest_received[author] = @max(t.local_highest_received[author], round);
        const a = t.at(t.block_accepted, author, author);
        a.* = @max(a.*, round);
        for (ancestors) |anc| {
            if (anc.author >= t.n) continue;
            const p = t.at(t.block_accepted, author, anc.author);
            p.* = @max(p.*, anc.round);
        }
        for (excluded) |anc| {
            if (anc.author >= t.n) continue;
            const p = t.at(t.block_accepted, author, anc.author);
            p.* = @max(p.*, anc.round);
        }
    }

    /// `update_from_probe`: row `peer` of each matrix replaced by what the peer reported.
    pub fn updateFromProbe(t: *RoundTracker, peer: types.AuthorityIndex, received: ?[]const types.Round, accepted: ?[]const types.Round) void {
        if (peer >= t.n) return;
        t.mu.lock();
        defer t.mu.unlock();
        if (received) |r| if (r.len == t.n) @memcpy(t.probed_received[peer * t.n ..][0..t.n], r);
        if (accepted) |a| if (a.len == t.n) @memcpy(t.probed_accepted[peer * t.n ..][0..t.n], a);
    }

    /// The probe results for a failed or absent peer count as zeros (Rust: a fresh matrix per probe).
    pub fn resetProbe(t: *RoundTracker) void {
        t.mu.lock();
        defer t.mu.unlock();
        @memset(t.probed_received, 0);
        @memset(t.probed_accepted, 0);
    }

    pub fn setLocalAccepted(t: *RoundTracker, own_accepted: []const types.Round, last_proposed: types.Round) void {
        t.mu.lock();
        defer t.mu.unlock();
        if (own_accepted.len == t.n) @memcpy(t.probed_accepted[t.own_index * t.n ..][0..t.n], own_accepted);
        @memcpy(t.probed_received[t.own_index * t.n ..][0..t.n], t.local_highest_received);
        t.probed_accepted[t.own_index * t.n + t.own_index] = last_proposed;
        t.probed_received[t.own_index * t.n + t.own_index] = last_proposed;
    }

    /// Copies the locally tracked highest received rounds (GetLatestRounds, `highest_received`).
    pub fn localHighestReceived(t: *RoundTracker, out: []types.Round) void {
        t.mu.lock();
        defer t.mu.unlock();
        @memcpy(out[0..t.n], t.local_highest_received);
    }

    /// `compute_quorum_round` for one target over a matrix [reporter][target]; stake from `committee`.
    fn quorumRound(t: *const RoundTracker, committee: *const Committee, matrix: []const types.Round, target: usize, scratch: []struct { types.Round, u64 }) QuorumRound {
        for (0..t.n) |r| scratch[r] = .{ matrix[r * t.n + target], committee.authorities[r].stake };
        std.mem.sort(struct { types.Round, u64 }, scratch[0..t.n], {}, struct {
            fn lt(_: void, a: struct { types.Round, u64 }, b: struct { types.Round, u64 }) bool {
                if (a[0] != b[0]) return a[0] < b[0];
                return a[1] < b[1];
            }
        }.lt);
        var total: u64 = 0;
        var low: types.Round = 0;
        var i: usize = t.n;
        while (i > 0) {
            i -= 1;
            total += scratch[i][1];
            if (total >= committee.quorum_threshold) {
                low = scratch[i][0];
                break;
            }
        }
        total = 0;
        var high: types.Round = 0;
        for (scratch[0..t.n]) |e| {
            total += e[1];
            if (total >= committee.quorum_threshold) {
                high = e[0];
                break;
            }
        }
        return .{ .low = low, .high = high };
    }

    /// `calculate_propagation_delay(last_proposed_round)`: the lower of the received-based and the
    /// accepted-based gap between our last proposal and the quorum round of our own blocks.
    pub fn propagationDelay(t: *RoundTracker, committee: *const Committee, last_proposed: types.Round) types.Round {
        const gpa = t.gpa;
        const scratch = gpa.alloc(struct { types.Round, u64 }, t.n) catch return 0;
        defer gpa.free(scratch);
        const merged = gpa.alloc(types.Round, t.n * t.n) catch return 0;
        defer gpa.free(merged);
        t.mu.lock();
        for (merged, 0..) |*m, i| m.* = @max(t.probed_accepted[i], t.block_accepted[i]);
        const recv = t.quorumRound(committee, t.probed_received, t.own_index, scratch);
        const acc = t.quorumRound(committee, merged, t.own_index, scratch);
        t.mu.unlock();
        return @min(last_proposed -| recv.low, last_proposed -| acc.low);
    }
};

pub const GENESIS_COMMIT_INDEX: types.CommitIndex = 0;
/// commit_vote_monitor.rs COMMIT_LAG_MULTIPLIER
pub const commit_lag_multiplier: u32 = 5;

pub fn isCommitLagging(commit_sync_batch_size: u32, local_commit_index: types.CommitIndex, quorum_commit_index: types.CommitIndex) bool {
    return @as(u64, local_commit_index) + @as(u64, commit_sync_batch_size) * commit_lag_multiplier < quorum_commit_index;
}

pub const CommitVoteMonitor = struct {
    gpa: Allocator,
    mu: Monitor,
    highest_voted: []types.CommitIndex,

    pub fn init(gpa: Allocator, io: Io, committee_size: usize) Allocator.Error!CommitVoteMonitor {
        const h = try gpa.alloc(types.CommitIndex, committee_size);
        @memset(h, 0);
        return .{ .gpa = gpa, .mu = Monitor.init(io), .highest_voted = h };
    }

    pub fn deinit(m: *CommitVoteMonitor) void {
        m.gpa.free(m.highest_voted);
    }

    /// `observe_block`: the highest commit index each authority has voted for.
    pub fn observeBlock(m: *CommitVoteMonitor, author: types.AuthorityIndex, votes: []const types.CommitVote) void {
        if (author >= m.highest_voted.len) return;
        m.mu.lock();
        defer m.mu.unlock();
        for (votes) |v| if (v.index > m.highest_voted[author]) {
            m.highest_voted[author] = v.index;
        };
    }

    /// The highest commit index certified by a quorum: sort (index, stake) descending and take the
    /// index where the accumulated stake reaches the quorum.
    pub fn quorumCommitIndex(m: *CommitVoteMonitor, committee: *const Committee) types.CommitIndex {
        const Pair = struct { types.CommitIndex, u64 };
        const buf = m.gpa.alloc(Pair, m.highest_voted.len) catch return GENESIS_COMMIT_INDEX;
        defer m.gpa.free(buf);
        m.mu.lock();
        for (m.highest_voted, 0..) |h, i| buf[i] = .{ h, committee.authorities[i].stake };
        m.mu.unlock();
        std.mem.sort(Pair, buf, {}, struct {
            fn gt(_: void, a: Pair, b: Pair) bool {
                if (a[0] != b[0]) return a[0] > b[0];
                return a[1] > b[1];
            }
        }.gt);
        var total: u64 = 0;
        for (buf) |p| {
            total += p[1];
            if (total >= committee.quorum_threshold) return p[0];
        }
        return GENESIS_COMMIT_INDEX;
    }
};

fn testCommittee(n: usize, stakes: []const u64) !struct { auths: []consensus.committee.Authority, c: Committee } {
    const a = try std.testing.allocator.alloc(consensus.committee.Authority, n);
    for (a, 0..) |*x, i| x.* = .{ .stake = stakes[i], .address = "", .hostname = "", .authority_name = "", .protocol_key = @splat(0), .network_key = @splat(0) };
    return .{ .auths = a, .c = try Committee.init(0, a) };
}

test "commit vote monitor: quorum commit index (Rust test_commit_vote_monitor)" {
    const gpa = std.testing.allocator;
    const t = try testCommittee(4, &.{ 1, 1, 1, 1 });
    defer gpa.free(t.auths);
    var m = try CommitVoteMonitor.init(gpa, std.testing.io, 4);
    defer m.deinit();
    for (0..4) |i| m.observeBlock(@intCast(i), &.{.{ .index = @intCast(5 + i), .digest = @splat(0) }});
    try std.testing.expectEqual(@as(types.CommitIndex, 6), m.quorumCommitIndex(&t.c));
    m.observeBlock(0, &.{.{ .index = 6, .digest = @splat(0) }});
    m.observeBlock(1, &.{.{ .index = 7, .digest = @splat(0) }});
    try std.testing.expectEqual(@as(types.CommitIndex, 7), m.quorumCommitIndex(&t.c));
}

test "commit lagging" {
    try std.testing.expect(!isCommitLagging(100, 0, 500));
    try std.testing.expect(isCommitLagging(100, 0, 501));
}

test "round tracker: propagation delay from probed quorum rounds" {
    const gpa = std.testing.allocator;
    const t = try testCommittee(4, &.{ 1, 1, 1, 1 });
    defer gpa.free(t.auths);
    var rt = try RoundTracker.init(gpa, std.testing.io, &t.c, 0);
    defer rt.deinit();
    // Peers 1..3 report having received our block up to rounds 100, 100, 90; we are at 110.
    rt.updateFromProbe(1, &.{ 100, 0, 0, 0 }, &.{ 100, 0, 0, 0 });
    rt.updateFromProbe(2, &.{ 100, 0, 0, 0 }, &.{ 100, 0, 0, 0 });
    rt.updateFromProbe(3, &.{ 90, 0, 0, 0 }, &.{ 90, 0, 0, 0 });
    rt.setLocalAccepted(&.{ 110, 0, 0, 0 }, 110);
    // Reports (low to high): 90, 100, 100, 110; quorum 3: low bound is 100.
    try std.testing.expectEqual(@as(types.Round, 10), rt.propagationDelay(&t.c, 110));
    // A block from peer 3 whose ancestors show it accepted our round 108 lowers the delay of
    // the accepted view, and the delay is the minimum of both views.
    rt.updateFromVerifiedBlock(3, 120, &.{.{ .round = 108, .author = 0, .digest = @splat(0) }}, &.{});
    rt.updateFromVerifiedBlock(2, 120, &.{.{ .round = 108, .author = 0, .digest = @splat(0) }}, &.{});
    try std.testing.expectEqual(@as(types.Round, 2), rt.propagationDelay(&t.c, 110));
}
