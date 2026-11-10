//! Test support and conformance helper: a fixture (committee, context, MemStore, DagState,
//! LeaderSchedule) and a DAG builder that creates real V2 blocks (BCS bytes, Blake2b digests) the way
//! Rust's `DagBuilder` does. Used by unit tests, the replay conformance suite and the simulator.
//! Owner lane: val-consensus-core. Not part of the node.
const std = @import("std");
const types = @import("types.zig");
const err = @import("error.zig");
const digest_mod = @import("digest.zig");
const committee_mod = @import("committee.zig");
const config = @import("config.zig");
const iface = @import("iface.zig");
const store_mod = @import("store.zig");
const dag_mod = @import("dag_state.zig");
const ls_mod = @import("leader_schedule.zig");
const committer_mod = @import("committer.zig");
const linearizer_mod = @import("linearizer.zig");
const Context = @import("context.zig").Context;

const Allocator = std.mem.Allocator;

/// A deterministic clock the tests advance by hand.
pub const FakeClock = struct {
    now_ms: u64 = 0,
    mono_ns: u64 = 0,

    pub fn clock(self: *FakeClock) iface.Clock {
        return .{ .ctx = self, .vtable = &vtable };
    }
    const vtable: iface.Clock.VTable = .{ .now_ms = nowMs, .mono_ns = monoNs };
    fn nowMs(ctx: *anyopaque) u64 {
        const s: *FakeClock = @ptrCast(@alignCast(ctx));
        return s.now_ms;
    }
    fn monoNs(ctx: *anyopaque) u64 {
        const s: *FakeClock = @ptrCast(@alignCast(ctx));
        return s.mono_ns;
    }
};

pub const Fixture = struct {
    gpa: Allocator,
    arena_state: std.heap.ArenaAllocator,
    authorities: []committee_mod.Authority,
    clock: *FakeClock,
    context: *Context,
    mem: *store_mod.MemStore,
    dag: *dag_mod.DagState,
    schedule: *ls_mod.LeaderSchedule,

    pub const Options = struct {
        /// Stake per authority; the length is the committee size.
        stakes: []const u64,
        epoch: u64 = 0,
        epoch_start_ms: u64 = 0,
        protocol: config.ProtocolConfig = .{ .gc_depth = 60, .transaction_voting_enabled = true, .num_leaders_per_round = 1, .bad_nodes_stake_threshold = 30 },
        parameters: config.Parameters = .{},
        own_index: ?u32 = 0,
        mode: ls_mod.ElectionMode = .round_robin_test,
    };

    pub fn equalStakes(comptime n: usize) [n]u64 {
        return @splat(1);
    }

    pub fn init(gpa: Allocator, o: Options) err.Error!*Fixture {
        const self = gpa.create(Fixture) catch return error.OutOfMemory;
        errdefer gpa.destroy(self);
        self.gpa = gpa;
        self.arena_state = std.heap.ArenaAllocator.init(gpa);
        errdefer self.arena_state.deinit();
        const a = self.arena_state.allocator();
        self.authorities = a.alloc(committee_mod.Authority, o.stakes.len) catch return error.OutOfMemory;
        for (self.authorities, o.stakes, 0..) |*x, s, i| {
            const host = std.fmt.allocPrint(a, "host{d}", .{i}) catch return error.OutOfMemory;
            x.* = .{ .stake = s, .address = "", .hostname = host, .authority_name = "", .protocol_key = @splat(0), .network_key = @splat(0) };
        }
        self.clock = a.create(FakeClock) catch return error.OutOfMemory;
        self.clock.* = .{};
        self.context = a.create(Context) catch return error.OutOfMemory;
        self.context.* = .{
            .epoch_start_timestamp_ms = o.epoch_start_ms,
            .own_index = o.own_index,
            .committee = committee_mod.Committee.init(o.epoch, self.authorities) catch return error.Invariant,
            .parameters = o.parameters,
            .protocol_config = o.protocol,
            .clock = self.clock.clock(),
        };
        self.mem = gpa.create(store_mod.MemStore) catch return error.OutOfMemory;
        errdefer gpa.destroy(self.mem);
        self.mem.* = store_mod.MemStore.init(gpa);
        errdefer self.mem.deinit();
        self.dag = try dag_mod.DagState.init(gpa, self.context, self.mem.store());
        errdefer self.dag.deinit();
        self.schedule = gpa.create(ls_mod.LeaderSchedule) catch return error.OutOfMemory;
        self.schedule.* = ls_mod.LeaderSchedule.init(gpa, self.context, .{});
        self.schedule.mode = o.mode;
        return self;
    }

    pub fn deinit(self: *Fixture) void {
        const gpa = self.gpa;
        self.schedule.deinit();
        gpa.destroy(self.schedule);
        self.dag.deinit();
        self.mem.deinit();
        gpa.destroy(self.mem);
        self.arena_state.deinit();
        gpa.destroy(self);
    }

    pub fn arena(self: *Fixture) Allocator {
        return self.arena_state.allocator();
    }

    pub fn genesisRefs(self: *Fixture) []types.BlockRef {
        const g = self.dag.genesis;
        const out = self.arena().alloc(types.BlockRef, g.len) catch unreachable;
        for (out, g) |*o, b| o.* = b.reference();
        return out;
    }

    /// Creates a V2 block, accepts it into the DAG and returns its ref. `timestamp_ms` defaults to
    /// round * 1000 + author when null.
    pub fn addBlock(self: *Fixture, round: types.Round, author: types.AuthorityIndex, ancestors: []const types.BlockRef, timestamp_ms: ?u64) err.Error!types.BlockRef {
        const a = self.arena();
        const anc = a.dupe(types.BlockRef, ancestors) catch return error.OutOfMemory;
        const block: types.Block = .{ .V2 = .{
            .epoch = self.context.committee.epoch,
            .round = round,
            .author = author,
            .timestamp_ms = timestamp_ms orelse (@as(u64, round) * 1000 + author),
            .ancestors = anc,
            .transactions = &.{},
            .transaction_votes = &.{},
            .commit_votes = &.{},
            .misbehavior_reports = &.{},
        } };
        const vb = try digest_mod.verifiedForTest(a, block);
        try self.dag.acceptBlock(&vb);
        return vb.reference();
    }

    /// Adds one block per author in `authors` at `round`, each referencing every block of `prev`
    /// except those whose author is in `exclude`. Returns the new refs in author order.
    pub fn layer(self: *Fixture, round: types.Round, authors: []const types.AuthorityIndex, prev: []const types.BlockRef, exclude: []const types.AuthorityIndex) err.Error![]types.BlockRef {
        const a = self.arena();
        var anc: std.ArrayList(types.BlockRef) = .empty;
        for (prev) |p| {
            if (std.mem.indexOfScalar(types.AuthorityIndex, exclude, p.author) == null) anc.append(a, p) catch return error.OutOfMemory;
        }
        const out = a.alloc(types.BlockRef, authors.len) catch return error.OutOfMemory;
        for (authors, out) |au, *o| o.* = try self.addBlock(round, au, anc.items, null);
        return out;
    }

    /// Full layers from `from` to `to` inclusive over all authorities, starting from `prev`.
    pub fn fullLayers(self: *Fixture, from: types.Round, to: types.Round, prev_in: []const types.BlockRef) err.Error![]const types.BlockRef {
        const n = self.context.committee.size();
        const all = self.arena().alloc(types.AuthorityIndex, n) catch return error.OutOfMemory;
        for (all, 0..) |*x, i| x.* = @intCast(i);
        var prev = prev_in;
        var r = from;
        while (r <= to) : (r += 1) prev = try self.layer(r, all, prev, &.{});
        return prev;
    }

    pub fn committer(self: *Fixture) err.Error!committer_mod.UniversalCommitter {
        return committer_mod.UniversalCommitter.fromProtocol(self.context, self.dag, self.schedule);
    }
    pub fn linearizer(self: *Fixture) linearizer_mod.Linearizer {
        return .{ .context = self.context, .dag = self.dag };
    }
};

test "full DAG: direct commits for rounds 1..3, then linearized sub-dags" {
    const gpa = std.testing.allocator;
    var stakes = Fixture.equalStakes(4);
    const f = try Fixture.init(gpa, .{ .stakes = &stakes });
    defer f.deinit();
    _ = try f.fullLayers(1, 5, f.genesisRefs());

    const c = try f.committer();
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const decided = try c.tryDecide(scratch.allocator(), f.dag.lastCommitLeader());
    try std.testing.expectEqual(@as(usize, 3), decided.len);
    for (decided, 1..) |d, round| {
        try std.testing.expect(d == .commit);
        try std.testing.expect(d.commit.direct);
        try std.testing.expectEqual(@as(types.Round, @intCast(round)), d.commit.block.block.inner.round());
        // round-robin test election: (round + 0) % 4
        try std.testing.expectEqual(@as(types.AuthorityIndex, @intCast(round % 4)), d.commit.block.block.inner.author());
    }

    var leaders: [3]*const types.VerifiedBlock = undefined;
    for (decided, &leaders) |d, *l| l.* = d.commit.block;
    var lin = f.linearizer();
    const subs = try lin.handleCommit(scratch.allocator(), &leaders);
    try std.testing.expectEqual(@as(usize, 3), subs.len);
    try std.testing.expectEqual(@as(usize, 1), subs[0].blocks.len); // round-1 leader only (genesis is below)
    try std.testing.expectEqual(@as(usize, 4), subs[1].blocks.len); // 3 other round-1 blocks + round-2 leader
    try std.testing.expectEqual(@as(types.CommitIndex, 1), subs[0].commit_ref.index);
    try std.testing.expectEqual(@as(types.CommitIndex, 3), f.dag.lastCommitIndex());
    // commit chain: previous digest of commit 2 is the digest of commit 1
    try std.testing.expectEqual(subs[2].commit_ref.digest, f.dag.lastCommitDigest());
    // Nothing more to decide immediately afterwards.
    var scratch2 = std.heap.ArenaAllocator.init(gpa);
    defer scratch2.deinit();
    const again = try c.tryDecide(scratch2.allocator(), f.dag.lastCommitLeader());
    try std.testing.expectEqual(@as(usize, 0), again.len);
    try f.dag.flush();
}

test "missing leader block in round 1 is skipped on 2f+1 blames" {
    const gpa = std.testing.allocator;
    var stakes = Fixture.equalStakes(4);
    const f = try Fixture.init(gpa, .{ .stakes = &stakes });
    defer f.deinit();
    // Round 1: authorities 0, 2, 3 only (the round-1 leader is authority 1).
    const r1 = try f.layer(1, &.{ 0, 2, 3 }, f.genesisRefs(), &.{});
    const all = [_]types.AuthorityIndex{ 0, 1, 2, 3 };
    var prev = try f.layer(2, &all, r1, &.{});
    prev = try f.layer(3, &all, prev, &.{});
    prev = try f.layer(4, &all, prev, &.{});
    _ = try f.layer(5, &all, prev, &.{});
    const c = try f.committer();
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const decided = try c.tryDecide(scratch.allocator(), f.dag.lastCommitLeader());
    try std.testing.expect(decided.len >= 1);
    try std.testing.expect(decided[0] == .skip);
    try std.testing.expectEqual(@as(types.Round, 1), decided[0].skip.round);
    try std.testing.expectEqual(@as(types.AuthorityIndex, 1), decided[0].skip.authority);
}
