//! Support for consensus_net's tests and the local test committee: a thread-safe in-memory
//! `consensus.store.Store`, block building (BCS SignedBlock + Blake2b digest), generated
//! committees with Ed25519 keys, a real clock. Used by unit tests and `localnet.zig`; nothing
//! here is on the production path. Owner lane: val-consensus-net.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const hash = @import("hash");
const consensus = @import("consensus");
const types = consensus.types;
const store_mod = consensus.store;
const mon = @import("mon.zig");
const Ed25519 = std.crypto.sign.Ed25519;

pub fn blockDigest(serialized: []const u8) types.BlockDigest {
    return hash.blake2b256(&.{serialized});
}

pub const BlockSpec = struct {
    epoch: types.Epoch = 0,
    round: types.Round,
    author: types.AuthorityIndex,
    timestamp_ms: u64 = 0,
    ancestors: []const types.BlockRef = &.{},
    transactions: []const types.Transaction = &.{},
    commit_votes: []const types.CommitVote = &.{},
    /// Ed25519 protocol-key seed: the signature is over the consensus block signing message.
    sign_seed: ?[32]u8 = null,
};

/// A V1 SignedBlock (serialized, owned by `gpa`) and its ref.
pub fn buildBlock(gpa: Allocator, spec: BlockSpec) !struct { bytes: []u8, ref: types.BlockRef } {
    const inner: types.Block = .{ .V1 = .{
        .epoch = spec.epoch,
        .round = spec.round,
        .author = spec.author,
        .timestamp_ms = spec.timestamp_ms,
        .ancestors = spec.ancestors,
        .transactions = spec.transactions,
        .commit_votes = spec.commit_votes,
        .misbehavior_reports = &.{},
    } };
    var sig: [64]u8 = @splat(0);
    if (spec.sign_seed) |seed| {
        const inner_bytes = try bcs.encodeAlloc(types.Block, gpa, &inner);
        defer gpa.free(inner_bytes);
        const inner_digest = hash.blake2b256(&.{inner_bytes});
        const msg = consensus.digest.signingMessage(&inner_digest);
        const kp = try Ed25519.KeyPair.generateDeterministic(seed);
        sig = (try kp.sign(&msg, null)).toBytes();
    }
    const sb: types.SignedBlock = .{ .inner = inner, .signature = &sig };
    const bytes = try bcs.encodeAlloc(types.SignedBlock, gpa, &sb);
    return .{ .bytes = bytes, .ref = .{ .round = spec.round, .author = spec.author, .digest = blockDigest(bytes) } };
}

pub fn decodeBlock(arena: Allocator, serialized: []const u8) !types.VerifiedBlock {
    const sb = try bcs.decode(types.SignedBlock, arena, serialized);
    return .{ .block = sb, .serialized = serialized, .digest = blockDigest(serialized) };
}

pub fn buildCommit(gpa: Allocator, index: types.CommitIndex, previous: types.CommitDigest, leader: types.BlockRef, blocks: []const types.BlockRef) !struct { bytes: []u8, digest: types.CommitDigest } {
    const c: types.Commit = .{ .V1 = .{ .index = index, .previous_digest = previous, .timestamp_ms = 0, .leader = leader, .blocks = blocks } };
    const bytes = try bcs.encodeAlloc(types.Commit, gpa, &c);
    return .{ .bytes = bytes, .digest = hash.blake2b256(&.{bytes}) };
}

// ---------------------------------------------------------------- generated committee

pub const max_test_authorities = 16;

pub const TestCommittee = struct {
    gpa: Allocator,
    n: usize,
    protocol_seeds: [max_test_authorities][32]u8,
    network_seeds: [max_test_authorities][32]u8,
    ports: [max_test_authorities]u16,
    authorities: []consensus.committee.Authority,
    addresses: [][]u8,
    committee: consensus.Committee,

    /// `n` equal-stake authorities with keys derived from `seed` (generated keys only; the
    /// validator safety gate treats such committees as local tests) on loopback ports starting at
    /// `base_port` (0: pick free ones).
    pub fn init(gpa: Allocator, io: Io, n: usize, seed: u64, base_port: u16, epoch: types.Epoch) !*TestCommittee {
        std.debug.assert(n >= 1 and n <= max_test_authorities);
        const tc = try gpa.create(TestCommittee);
        errdefer gpa.destroy(tc);
        tc.* = .{ .gpa = gpa, .n = n, .protocol_seeds = undefined, .network_seeds = undefined, .ports = undefined, .authorities = try gpa.alloc(consensus.committee.Authority, n), .addresses = try gpa.alloc([]u8, n), .committee = undefined };
        var prng = std.Random.DefaultPrng.init(seed);
        for (0..n) |i| {
            prng.random().bytes(&tc.protocol_seeds[i]);
            prng.random().bytes(&tc.network_seeds[i]);
            tc.ports[i] = if (base_port != 0) base_port + @as(u16, @intCast(i)) else try freePort(io);
            tc.addresses[i] = try std.fmt.allocPrint(gpa, "/ip4/127.0.0.1/udp/{d}", .{tc.ports[i]});
            const pk = try Ed25519.KeyPair.generateDeterministic(tc.protocol_seeds[i]);
            const nk = try Ed25519.KeyPair.generateDeterministic(tc.network_seeds[i]);
            tc.authorities[i] = .{ .stake = 1, .address = tc.addresses[i], .hostname = "localhost", .authority_name = "", .protocol_key = pk.public_key.toBytes(), .network_key = nk.public_key.toBytes() };
        }
        tc.committee = try consensus.Committee.init(epoch, tc.authorities);
        return tc;
    }

    pub fn deinit(tc: *TestCommittee) void {
        for (tc.addresses) |a| tc.gpa.free(a);
        tc.gpa.free(tc.addresses);
        tc.gpa.free(tc.authorities);
        tc.gpa.destroy(tc);
    }
};

/// A currently free loopback port (bind to 0, read it back, close).
pub fn freePort(io: Io) !u16 {
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var l = try any.listen(io, .{ .reuse_address = true });
    defer l.deinit(io);
    return l.socket.address.ip4.port;
}

// ---------------------------------------------------------------- clock

pub const RealClock = struct {
    io: Io,

    pub fn clock(c: *RealClock) consensus.iface.Clock {
        return .{ .ctx = c, .vtable = &vt };
    }
    const vt: consensus.iface.Clock.VTable = .{ .now_ms = nowMs, .mono_ns = monoNs };
    fn nowMs(ctx: *anyopaque) u64 {
        const c: *RealClock = @ptrCast(@alignCast(ctx));
        return @intCast(@divTrunc(Io.Clock.real.now(c.io).toNanoseconds(), std.time.ns_per_ms));
    }
    fn monoNs(ctx: *anyopaque) u64 {
        const c: *RealClock = @ptrCast(@alignCast(ctx));
        return mon.monoNs(c.io);
    }
};

// ---------------------------------------------------------------- in-memory store

/// A thread-safe in-memory Store for tests: blocks by ref, commits by index, commit votes.
pub const FakeStore = struct {
    gpa: Allocator,
    mu: mon.Monitor,
    blocks: std.ArrayList(Entry) = .empty,
    commits: std.ArrayList(CommitEntry) = .empty,
    votes: std.AutoHashMapUnmanaged(types.CommitIndex, []types.BlockRef) = .empty,
    /// Store-owned memory of decoded reads (`read_blocks` has no caller arena); freed by `deinit`.
    read_arena: std.heap.ArenaAllocator,

    const Entry = struct { ref: types.BlockRef, bytes: []u8 };
    const CommitEntry = struct { index: types.CommitIndex, digest: types.CommitDigest, bytes: []u8 };

    pub fn init(gpa: Allocator, io: Io) FakeStore {
        return .{ .gpa = gpa, .mu = mon.Monitor.init(io), .read_arena = std.heap.ArenaAllocator.init(gpa) };
    }

    pub fn deinit(s: *FakeStore) void {
        for (s.blocks.items) |e| s.gpa.free(e.bytes);
        s.blocks.deinit(s.gpa);
        for (s.commits.items) |e| s.gpa.free(e.bytes);
        s.commits.deinit(s.gpa);
        var it = s.votes.valueIterator();
        while (it.next()) |v| s.gpa.free(v.*);
        s.votes.deinit(s.gpa);
        s.read_arena.deinit();
    }

    pub fn addBlock(s: *FakeStore, bytes: []const u8, ref: types.BlockRef) !void {
        s.mu.lock();
        defer s.mu.unlock();
        for (s.blocks.items) |e| if (e.ref.eql(ref)) return;
        try s.blocks.append(s.gpa, .{ .ref = ref, .bytes = try s.gpa.dupe(u8, bytes) });
    }

    pub fn addCommit(s: *FakeStore, index: types.CommitIndex, digest: types.CommitDigest, bytes: []const u8, votes: []const types.BlockRef) !void {
        s.mu.lock();
        defer s.mu.unlock();
        for (s.commits.items) |c| if (c.index == index) return;
        try s.commits.append(s.gpa, .{ .index = index, .digest = digest, .bytes = try s.gpa.dupe(u8, bytes) });
        if (!s.votes.contains(index)) try s.votes.put(s.gpa, index, try s.gpa.dupe(types.BlockRef, votes));
    }

    /// Records that the block `voter` carried a commit vote for `index`.
    pub fn addVote(s: *FakeStore, index: types.CommitIndex, voter: types.BlockRef) !void {
        s.mu.lock();
        defer s.mu.unlock();
        const old = s.votes.get(index) orelse &[_]types.BlockRef{};
        for (old) |v| if (v.eql(voter)) return;
        const grown = try s.gpa.alloc(types.BlockRef, old.len + 1);
        @memcpy(grown[0..old.len], old);
        grown[old.len] = voter;
        if (s.votes.get(index)) |o| s.gpa.free(o);
        try s.votes.put(s.gpa, index, grown);
    }

    pub fn store(s: *FakeStore) store_mod.Store {
        return .{ .ctx = s, .vtable = &vt };
    }

    const E = consensus.errors.Error;
    const vt: store_mod.Store.VTable = .{
        .write = write,
        .read_blocks = readBlocks,
        .contains_blocks = containsBlocks,
        .scan_blocks_by_author = scanByAuthor,
        .scan_last_blocks_by_author = scanLast,
        .read_last_commit = readLastCommit,
        .scan_commits = scanCommits,
        .read_commit_votes = readCommitVotes,
        .read_last_commit_info = readLastCommitInfo,
        .read_last_finalized_commit = readLastFinalized,
        .read_rejected_transactions = readRejected,
    };

    fn self(ctx: *anyopaque) *FakeStore {
        return @ptrCast(@alignCast(ctx));
    }

    fn write(ctx: *anyopaque, batch: *const store_mod.WriteBatch) E!void {
        const s = self(ctx);
        for (batch.blocks) |b| s.addBlock(b.serialized, b.reference()) catch return error.OutOfMemory;
        for (batch.commits) |c| s.addCommit(c.commit.index(), c.digest, c.serialized, &.{}) catch return error.OutOfMemory;
    }

    fn decode(arena: Allocator, e: Entry) E!types.VerifiedBlock {
        const bytes = arena.dupe(u8, e.bytes) catch return error.OutOfMemory;
        return decodeBlock(arena, bytes) catch return error.SerializationFailure;
    }

    fn readBlocks(ctx: *anyopaque, refs: []const types.BlockRef, out: []?types.VerifiedBlock) E!void {
        const s = self(ctx);
        s.mu.lock();
        defer s.mu.unlock();
        const arena = s.read_arena.allocator();
        for (refs, 0..) |r, i| {
            out[i] = null;
            for (s.blocks.items) |e| if (e.ref.eql(r)) {
                out[i] = try decode(arena, e);
                break;
            };
        }
    }

    fn containsBlocks(ctx: *anyopaque, refs: []const types.BlockRef, out: []bool) E!void {
        const s = self(ctx);
        s.mu.lock();
        defer s.mu.unlock();
        for (refs, 0..) |r, i| {
            out[i] = false;
            for (s.blocks.items) |e| if (e.ref.eql(r)) {
                out[i] = true;
            };
        }
    }

    fn scanByAuthor(ctx: *anyopaque, arena: Allocator, author: types.AuthorityIndex, start: types.Round, end: types.Round, limit: usize) E![]types.VerifiedBlock {
        const s = self(ctx);
        s.mu.lock();
        defer s.mu.unlock();
        var list: std.ArrayList(Entry) = .empty;
        defer list.deinit(arena);
        for (s.blocks.items) |e| if (e.ref.author == author and e.ref.round >= start and e.ref.round < end) list.append(arena, e) catch return error.OutOfMemory;
        std.mem.sort(Entry, list.items, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                return a.ref.order(b.ref) == .lt;
            }
        }.lt);
        const n = @min(limit, list.items.len);
        const out = arena.alloc(types.VerifiedBlock, n) catch return error.OutOfMemory;
        for (list.items[0..n], 0..) |e, i| out[i] = try decode(arena, e);
        return out;
    }

    fn scanLast(ctx: *anyopaque, arena: Allocator, author: types.AuthorityIndex, num: u64, before: ?types.Round) E![]types.VerifiedBlock {
        const s = self(ctx);
        s.mu.lock();
        defer s.mu.unlock();
        var list: std.ArrayList(Entry) = .empty;
        defer list.deinit(arena);
        for (s.blocks.items) |e| if (e.ref.author == author and (before == null or e.ref.round < before.?)) list.append(arena, e) catch return error.OutOfMemory;
        std.mem.sort(Entry, list.items, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                return a.ref.order(b.ref) == .lt;
            }
        }.lt);
        const n: usize = @intCast(@min(num, list.items.len));
        const tail = list.items[list.items.len - n ..];
        const out = arena.alloc(types.VerifiedBlock, n) catch return error.OutOfMemory;
        for (tail, 0..) |e, i| out[i] = try decode(arena, e);
        return out;
    }

    fn readLastCommit(ctx: *anyopaque) E!?types.TrustedCommit {
        _ = ctx;
        return null;
    }

    fn scanCommits(ctx: *anyopaque, arena: Allocator, range: types.CommitRange) E![]types.TrustedCommit {
        const s = self(ctx);
        s.mu.lock();
        defer s.mu.unlock();
        var list: std.ArrayList(types.TrustedCommit) = .empty;
        for (s.commits.items) |e| if (e.index >= range.start and e.index < range.end_exclusive) {
            const bytes = arena.dupe(u8, e.bytes) catch return error.OutOfMemory;
            const c = bcs.decode(types.Commit, arena, bytes) catch return error.SerializationFailure;
            list.append(arena, .{ .commit = c, .serialized = bytes, .digest = e.digest }) catch return error.OutOfMemory;
        };
        std.mem.sort(types.TrustedCommit, list.items, {}, struct {
            fn lt(_: void, a: types.TrustedCommit, b: types.TrustedCommit) bool {
                return a.commit.index() < b.commit.index();
            }
        }.lt);
        return list.items;
    }

    fn readCommitVotes(ctx: *anyopaque, arena: Allocator, index: types.CommitIndex) E![]types.BlockRef {
        const s = self(ctx);
        s.mu.lock();
        defer s.mu.unlock();
        const v = s.votes.get(index) orelse return &.{};
        return arena.dupe(types.BlockRef, v) catch return error.OutOfMemory;
    }

    fn readLastCommitInfo(ctx: *anyopaque) E!?store_mod.CommitInfoEntry {
        _ = ctx;
        return null;
    }
    fn readLastFinalized(ctx: *anyopaque) E!?types.CommitRef {
        _ = ctx;
        return null;
    }
    fn readRejected(ctx: *anyopaque, commit: types.CommitRef) E!?[]const types.RejectedInBlock {
        _ = .{ ctx, commit };
        return null;
    }
};

/// A Context for tests: committee from `tc`, default parameters, default protocol config.
pub fn makeContext(tc: *const TestCommittee, own: ?types.AuthorityIndex, clock: consensus.iface.Clock) consensus.Context {
    return .{
        .epoch_start_timestamp_ms = 0,
        .own_index = own,
        .committee = tc.committee,
        .parameters = .{},
        .protocol_config = .{ .max_transactions_in_block_bytes = 512 * 1024 },
        .clock = clock,
    };
}

test "buildBlock round trips through the fake store" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const b = try buildBlock(gpa, .{ .round = 3, .author = 1, .ancestors = &.{.{ .round = 2, .author = 0, .digest = @splat(1) }}, .sign_seed = @as([32]u8, @splat(5)) });
    defer gpa.free(b.bytes);
    var fs = FakeStore.init(gpa, io);
    defer fs.deinit();
    try fs.addBlock(b.bytes, b.ref);
    const st = fs.store();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const out = try arena_state.allocator().alloc(?types.VerifiedBlock, 1);
    try st.vtable.read_blocks(st.ctx, &.{b.ref}, out);
    try std.testing.expect(out[0] != null);
    try std.testing.expectEqual(@as(types.Round, 3), out[0].?.block.inner.round());
    try std.testing.expect(out[0].?.reference().eql(b.ref));
}
