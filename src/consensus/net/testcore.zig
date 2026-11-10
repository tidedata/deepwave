//! A toy consensus core for exercising the network side end to end, plus the test signer,
//! verifier, sink and transaction source. NOT Mysticeti: it proposes round r+1 once every
//! authority's round r block is accepted (or a quorum, with `wait_all` off), commits the leader
//! of round R (author R mod n) once round R+1 is complete, and keeps the commit chain and the
//! commit votes in the store, which is enough to drive SubscribeBlocks, FetchBlocks,
//! FetchCommits, the commit syncer and the verify path with real signatures. Owner lane:
//! val-consensus-net. Generated test keys only.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const hash = @import("hash");
const consensus = @import("consensus");
const types = consensus.types;
const iface = consensus.iface;
const testkit = @import("testkit.zig");
const mon = @import("mon.zig");
const node = @import("authority_node.zig");
const shared_mod = @import("shared.zig");
const Ed25519 = std.crypto.sign.Ed25519;

// ---------------------------------------------------------------- signer (generated keys)

/// Signs blocks with a generated Ed25519 key, refusing a second signature for a round (the same
/// rule the validator's signer enforces).
pub const TestSigner = struct {
    kp: Ed25519.KeyPair,
    mu: std.atomic.Mutex = .unlocked,
    last_round: types.Round = 0,
    signed_any: bool = false,

    pub fn init(seed: *const [32]u8) !TestSigner {
        return .{ .kp = try Ed25519.KeyPair.generateDeterministic(seed.*) };
    }

    pub fn blockSigner(t: *TestSigner) iface.BlockSigner {
        return .{ .ctx = t, .vtable = &vt };
    }
    const vt: iface.BlockSigner.VTable = .{ .sign_block = signBlock };

    fn signBlock(ctx: *anyopaque, epoch: types.Epoch, round: types.Round, message: []const u8) iface.BlockSigner.SignError![64]u8 {
        _ = epoch;
        const t: *TestSigner = @ptrCast(@alignCast(ctx));
        while (!t.mu.tryLock()) std.atomic.spinLoopHint();
        defer t.mu.unlock();
        if (t.signed_any and round <= t.last_round) return error.AlreadySigned;
        const sig = t.kp.sign(message, null) catch return error.Refused;
        t.signed_any = true;
        t.last_round = round;
        return sig.toBytes();
    }
};

// ---------------------------------------------------------------- verifier

pub const ToyVerifier = struct {
    context: *const consensus.Context,

    pub fn hook(v: *ToyVerifier) shared_mod.VerifierHook {
        return .{ .ctx = v, .verify = verify };
    }

    fn verify(ctx: *anyopaque, arena: Allocator, serialized: []const u8, out: *types.VerifiedBlock, votes: []types.TransactionIndex, nrej: *usize) consensus.errors.Error!consensus.errors.BlockVerdict {
        _ = votes;
        const v: *ToyVerifier = @ptrCast(@alignCast(ctx));
        nrej.* = 0;
        const sb = bcs.decode(types.SignedBlock, arena, serialized) catch return .{ .reject = .malformed_block };
        const b = sb.inner;
        if (b.epoch() != v.context.committee.epoch) return .{ .reject = .{ .wrong_epoch = .{ .expected = v.context.committee.epoch, .actual = b.epoch() } } };
        if (!v.context.committee.isValidIndex(b.author())) return .{ .reject = .{ .invalid_authority_index = b.author() } };
        if (b.round() == 0) return .{ .reject = .genesis_block };
        if (sb.signature.len != 64) return .{ .reject = .malformed_signature };
        const inner_bytes = bcs.encodeAlloc(types.Block, arena, &b) catch return error.OutOfMemory;
        const digest = hash.blake2b256(&.{inner_bytes});
        const msg = consensus.digest.signingMessage(&digest);
        const pk = Ed25519.PublicKey.fromBytes(v.context.committee.authorities[b.author()].protocol_key) catch return .{ .reject = .signature_verification_failure };
        const sig = Ed25519.Signature.fromBytes(sb.signature[0..64].*);
        sig.verify(&msg, pk) catch return .{ .reject = .signature_verification_failure };
        out.* = .{ .block = sb, .serialized = serialized, .digest = testkit.blockDigest(serialized) };
        return .ok;
    }
};

// ---------------------------------------------------------------- sink and source

pub const TestSink = struct {
    gpa: Allocator,
    mu: mon.Monitor,
    /// (commit index, leader ref) in arrival order.
    commits: std.ArrayList(struct { index: types.CommitIndex, leader: types.BlockRef }) = .empty,
    full_every: u32 = 0,
    calls: u32 = 0,

    pub fn init(gpa: Allocator, io: std.Io) TestSink {
        return .{ .gpa = gpa, .mu = mon.Monitor.init(io) };
    }
    pub fn deinit(s: *TestSink) void {
        s.commits.deinit(s.gpa);
    }
    pub fn commitSink(s: *TestSink) iface.CommitSink {
        return .{ .ctx = s, .vtable = &vt };
    }
    const vt: iface.CommitSink.VTable = .{ .push = push, .processed_through = processed };
    fn push(ctx: *anyopaque, sd: *const types.CommittedSubDag) bool {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        s.mu.lock();
        defer s.mu.unlock();
        s.calls += 1;
        // Exercise the full-sink retry path: refuse every `full_every`th call once.
        if (s.full_every != 0 and s.calls % s.full_every == 0) return false;
        s.commits.append(s.gpa, .{ .index = sd.commit_ref.index, .leader = sd.leader }) catch return false;
        return true;
    }
    fn processed(ctx: *anyopaque) types.CommitIndex {
        const s: *TestSink = @ptrCast(@alignCast(ctx));
        s.mu.lock();
        defer s.mu.unlock();
        return if (s.commits.items.len == 0) 0 else s.commits.items[s.commits.items.len - 1].index;
    }
    pub fn count(s: *TestSink) usize {
        s.mu.lock();
        defer s.mu.unlock();
        return s.commits.items.len;
    }
};

pub const TestSource = struct {
    counter: std.atomic.Value(u64) = .init(0),
    acked: std.atomic.Value(u32) = .init(0),
    buf: [8]u8 = undefined,

    pub fn txSource(t: *TestSource) iface.TransactionSource {
        return .{ .ctx = t, .vtable = &vt };
    }
    const vt: iface.TransactionSource.VTable = .{ .next = next, .ack = ack };
    fn next(ctx: *anyopaque, out: []types.Transaction, max_bytes: u64) usize {
        const t: *TestSource = @ptrCast(@alignCast(ctx));
        if (out.len == 0 or max_bytes < 8) return 0;
        std.mem.writeInt(u64, &t.buf, t.counter.fetchAdd(1, .monotonic), .little);
        out[0] = .{ .data = &t.buf };
        return 1;
    }
    fn ack(ctx: *anyopaque, _: types.BlockRef) void {
        const t: *TestSource = @ptrCast(@alignCast(ctx));
        _ = t.acked.fetchAdd(1, .monotonic);
    }
};

pub const AcceptAllTxs = struct {
    pub fn verifier(self: *AcceptAllTxs) iface.TransactionVerifier {
        return .{ .ctx = self, .vtable = &vt };
    }
    const vt: iface.TransactionVerifier.VTable = .{ .verify_batch = verifyBatch, .verify_and_vote_batch = vote };
    fn verifyBatch(_: *anyopaque, _: types.BlockRef, _: []const types.Transaction) iface.TransactionVerifier.VerifyError!void {}
    fn vote(_: *anyopaque, _: types.BlockRef, _: []const types.Transaction, _: []types.TransactionIndex) iface.TransactionVerifier.VerifyError!usize {
        return 0;
    }
};

// ---------------------------------------------------------------- the toy core

pub const ToyCore = struct {
    gpa: Allocator,
    context: *const consensus.Context,
    fs: *testkit.FakeStore,
    signer: iface.BlockSigner,
    tx_source: iface.TransactionSource,
    /// Advance only when every authority's block of the round is accepted.
    wait_all: bool = true,
    n: usize,
    rounds: std.ArrayList([]?types.BlockRef) = .empty,
    accepted: std.AutoHashMapUnmanaged(types.BlockRef, void) = .empty,
    suspended: std.ArrayList(Suspended) = .empty,
    highest_by_author: []types.Round,
    last_proposed: types.Round = 0,
    highest_complete: types.Round = 0,
    commit_index: types.CommitIndex = 0,
    last_commit_digest: types.CommitDigest = @splat(0),
    next_leader_round: types.Round = 1,
    own_may_propose: bool = false,

    const Suspended = struct { ref: types.BlockRef, bytes: []u8, ancestors: []types.BlockRef };
    const E = consensus.errors.Error;

    pub fn create(gpa: Allocator, context: *const consensus.Context, fs: *testkit.FakeStore, signer: iface.BlockSigner, tx_source: iface.TransactionSource, wait_all: bool) !*ToyCore {
        const t = try gpa.create(ToyCore);
        const n = context.committee.size();
        t.* = .{ .gpa = gpa, .context = context, .fs = fs, .signer = signer, .tx_source = tx_source, .wait_all = wait_all, .n = n, .highest_by_author = try gpa.alloc(types.Round, n) };
        @memset(t.highest_by_author, 0);
        try t.ensureRound(0);
        for (0..n) |a| {
            const g: types.BlockRef = .{ .round = 0, .author = @intCast(a), .digest = @splat(0) };
            t.rounds.items[0][a] = g;
            try t.accepted.put(gpa, g, {});
        }
        return t;
    }

    pub fn driver(t: *ToyCore) node.CoreDriver {
        return .{ .ctx = t, .vtable = &vt };
    }

    const vt: node.CoreDriver.VTable = .{
        .recover = recover,
        .add_blocks = addBlocks,
        .add_certified_commits = addCommits,
        .try_propose = tryPropose,
        .set_last_known_proposed_round = setLast,
        .flush = flush,
        .snapshot = snapshot,
        .missing_blocks = missingBlocks,
        .deinit = deinit,
    };

    fn self(ctx: *anyopaque) *ToyCore {
        return @ptrCast(@alignCast(ctx));
    }

    fn ensureRound(t: *ToyCore, r: types.Round) !void {
        while (t.rounds.items.len <= r) {
            const row = try t.gpa.alloc(?types.BlockRef, t.n);
            @memset(row, null);
            try t.rounds.append(t.gpa, row);
        }
    }

    fn threshold(t: *const ToyCore) usize {
        return if (t.wait_all) t.n else @intCast(t.context.committee.quorum_threshold);
    }

    fn recover(ctx: *anyopaque, arena: Allocator, out: *consensus.core.Output) E!void {
        _ = .{ ctx, arena, out };
    }

    fn accept(t: *ToyCore, bytes: []const u8, ref: types.BlockRef, commit_votes: []const types.CommitVote) E!void {
        if (t.accepted.contains(ref)) return;
        t.accepted.put(t.gpa, ref, {}) catch return error.OutOfMemory;
        t.ensureRound(ref.round) catch return error.OutOfMemory;
        t.rounds.items[ref.round][ref.author] = ref;
        t.fs.addBlock(bytes, ref) catch return error.OutOfMemory;
        for (commit_votes) |v| t.fs.addVote(v.index, ref) catch return error.OutOfMemory;
        t.highest_by_author[ref.author] = @max(t.highest_by_author[ref.author], ref.round);
        // advance the highest complete round
        while (true) {
            const r = t.highest_complete + 1;
            if (r >= t.rounds.items.len) break;
            var cnt: usize = 0;
            for (t.rounds.items[r]) |x| if (x != null) {
                cnt += 1;
            };
            if (cnt >= t.threshold()) t.highest_complete = r else break;
        }
    }

    fn ancestorsAccepted(t: *ToyCore, ancestors: []const types.BlockRef) bool {
        for (ancestors) |a| if (!t.accepted.contains(a)) return false;
        return true;
    }

    fn addBlocks(ctx: *anyopaque, arena: Allocator, blocks: []const types.VerifiedBlock, rejects: []const []const types.TransactionIndex, out: *consensus.core.Output) E!void {
        _ = rejects;
        const t = self(ctx);
        for (blocks) |b| {
            const ref = b.reference();
            if (t.accepted.contains(ref)) continue;
            const anc = b.block.inner.ancestors();
            if (t.ancestorsAccepted(anc)) {
                try t.accept(b.serialized, ref, b.block.inner.commitVotes());
            } else {
                t.suspended.append(t.gpa, .{ .ref = ref, .bytes = t.gpa.dupe(u8, b.serialized) catch return error.OutOfMemory, .ancestors = t.gpa.dupe(types.BlockRef, anc) catch return error.OutOfMemory }) catch return error.OutOfMemory;
            }
        }
        // accept suspended blocks whose ancestors arrived
        var progress = true;
        while (progress) {
            progress = false;
            var i: usize = 0;
            while (i < t.suspended.items.len) {
                const s = t.suspended.items[i];
                if (t.ancestorsAccepted(s.ancestors)) {
                    const decoded = testkit.decodeBlock(arena, s.bytes) catch return error.SerializationFailure;
                    try t.accept(s.bytes, s.ref, decoded.block.inner.commitVotes());
                    t.gpa.free(s.bytes);
                    t.gpa.free(s.ancestors);
                    _ = t.suspended.swapRemove(i);
                    progress = true;
                } else i += 1;
            }
        }
        var missing: std.ArrayList(types.BlockRef) = .empty;
        for (t.suspended.items) |s| for (s.ancestors) |a| if (!t.accepted.contains(a)) {
            missing.append(arena, a) catch return error.OutOfMemory;
        };
        out.missing = missing.items;
        try t.evaluateCommits(arena, out);
    }

    fn emitCommit(t: *ToyCore, arena: Allocator, out: *consensus.core.Output, index: types.CommitIndex, leader: types.BlockRef, commit_bytes: []const u8, digest: types.CommitDigest, leader_block: types.VerifiedBlock) E!void {
        t.fs.addCommit(index, digest, commit_bytes, &.{}) catch return error.OutOfMemory;
        t.commit_index = index;
        t.last_commit_digest = digest;
        t.next_leader_round = leader.round + 1;
        // Like the real core's Finalized: the sub-dag owns its memory (its own arena).
        var fa = std.heap.ArenaAllocator.init(t.gpa);
        errdefer fa.deinit();
        const fal = fa.allocator();
        const blocks = fal.alloc(types.VerifiedBlock, 1) catch return error.OutOfMemory;
        blocks[0] = try consensus.digest.cloneVerified(fal, &leader_block);
        const sub_dag: types.CommittedSubDag = .{ .leader = leader, .blocks = blocks, .timestamp_ms = 0, .commit_ref = .{ .index = index, .digest = digest }, .decided_with_local_blocks = true, .recovered_rejected_transactions = false, .rejected_transactions_by_block = &.{} };
        out.committed.append(arena, .{ .arena = fa, .sub_dag = sub_dag, .already_finalized = false }) catch return error.OutOfMemory;
    }

    fn evaluateCommits(t: *ToyCore, arena: Allocator, out: *consensus.core.Output) E!void {
        while (t.next_leader_round + 1 <= t.highest_complete) {
            const r = t.next_leader_round;
            const leader = t.rounds.items[r][r % t.n] orelse {
                // An authority that proposes nothing (down or observing) has no leader block: skip
                // its round once two later rounds are complete.
                if (!t.wait_all and t.highest_complete >= r + 2) {
                    t.next_leader_round += 1;
                    continue;
                }
                break;
            };
            const c = testkit.buildCommit(t.gpa, t.commit_index + 1, t.last_commit_digest, leader, &.{leader}) catch return error.OutOfMemory;
            defer t.gpa.free(c.bytes);
            var res: [1]?types.VerifiedBlock = undefined;
            t.fs.store().vtable.read_blocks(t.fs.store().ctx, &.{leader}, &res) catch return error.StoreCorrupt;
            try t.emitCommit(arena, out, t.commit_index + 1, leader, c.bytes, c.digest, res[0] orelse return error.StoreCorrupt);
        }
    }

    fn addCommits(ctx: *anyopaque, arena: Allocator, commits: []const types.TrustedCommit, blocks: []const types.VerifiedBlock, _: []const []const types.TransactionIndex, out: *consensus.core.Output) E!void {
        const t = self(ctx);
        for (blocks) |b| try t.accept(b.serialized, b.reference(), b.block.inner.commitVotes());
        for (commits) |c| {
            if (c.commit.index() != t.commit_index + 1) continue;
            const leader = c.commit.leader();
            var found: ?types.VerifiedBlock = null;
            for (blocks) |b| if (b.reference().eql(leader)) {
                found = b;
            };
            try t.emitCommit(arena, out, c.commit.index(), leader, c.serialized, c.digest, found orelse return error.StoreCorrupt);
        }
        try t.evaluateCommits(arena, out);
    }

    fn tryPropose(ctx: *anyopaque, arena: Allocator, force: bool, signals: consensus.core.Signals, out: *consensus.core.Output) E!void {
        _ = .{ force, signals };
        const t = self(ctx);
        const own = t.context.own_index orelse return;
        if (!t.own_may_propose) return;
        const target = t.highest_complete;
        if (target + 1 <= t.last_proposed) return;
        const round = target + 1;
        var ancestors: std.ArrayList(types.BlockRef) = .empty;
        if (t.rounds.items[target][own]) |r| ancestors.append(arena, r) catch return error.OutOfMemory;
        for (t.rounds.items[target], 0..) |x, a| if (x) |r| if (a != own) ancestors.append(arena, r) catch return error.OutOfMemory;
        var txs: [1]types.Transaction = undefined;
        const ntx = t.tx_source.next(&txs, 1024);
        const votes: []const types.CommitVote = if (t.commit_index > 0) arena.dupe(types.CommitVote, &.{.{ .index = t.commit_index, .digest = t.last_commit_digest }}) catch return error.OutOfMemory else &.{};
        const tx_copy: []const types.Transaction = if (ntx > 0) arena.dupe(types.Transaction, &.{.{ .data = arena.dupe(u8, txs[0].data) catch return error.OutOfMemory }}) catch return error.OutOfMemory else &.{};
        const inner: types.Block = .{ .V1 = .{
            .epoch = t.context.committee.epoch,
            .round = round,
            .author = own,
            .timestamp_ms = t.context.clock.nowMs(),
            .ancestors = ancestors.items,
            .transactions = tx_copy,
            .commit_votes = votes,
            .misbehavior_reports = &.{},
        } };
        const inner_bytes = bcs.encodeAlloc(types.Block, arena, &inner) catch return error.OutOfMemory;
        const digest = hash.blake2b256(&.{inner_bytes});
        const msg = consensus.digest.signingMessage(&digest);
        const sig = t.signer.signBlock(t.context.committee.epoch, round, &msg) catch return error.Shutdown;
        const sb: types.SignedBlock = .{ .inner = inner, .signature = &sig };
        const bytes = bcs.encodeAlloc(types.SignedBlock, arena, &sb) catch return error.OutOfMemory;
        const vb = testkit.decodeBlock(arena, bytes) catch return error.SerializationFailure;
        try t.accept(bytes, vb.reference(), votes);
        t.last_proposed = round;
        out.proposed.append(arena, .{ .block = vb, .excluded_ancestors = &.{} }) catch return error.OutOfMemory;
        try t.evaluateCommits(arena, out);
    }

    fn setLast(ctx: *anyopaque, round: types.Round) void {
        const t = self(ctx);
        t.last_proposed = @max(t.last_proposed, round);
        t.own_may_propose = true;
    }

    fn flush(ctx: *anyopaque) E!void {
        _ = ctx;
    }

    fn snapshot(ctx: *anyopaque, accepted: []types.Round, last_proposed: *types.Round, commit_index: *types.CommitIndex) void {
        const t = self(ctx);
        for (accepted, 0..) |*a, i| a.* = t.highest_by_author[i];
        last_proposed.* = t.last_proposed;
        commit_index.* = t.commit_index;
    }

    fn missingBlocks(ctx: *anyopaque, out: []types.BlockRef) usize {
        const t = self(ctx);
        var n: usize = 0;
        for (t.suspended.items) |s| for (s.ancestors) |a| {
            if (!t.accepted.contains(a) and n < out.len) {
                out[n] = a;
                n += 1;
            }
        };
        return n;
    }

    fn deinit(ctx: *anyopaque) void {
        const t = self(ctx);
        for (t.rounds.items) |r| t.gpa.free(r);
        t.rounds.deinit(t.gpa);
        t.accepted.deinit(t.gpa);
        for (t.suspended.items) |s| {
            t.gpa.free(s.bytes);
            t.gpa.free(s.ancestors);
        }
        t.suspended.deinit(t.gpa);
        t.gpa.free(t.highest_by_author);
        t.gpa.destroy(t);
    }
};
