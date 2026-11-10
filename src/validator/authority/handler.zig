//! The consensus handler (consensus_handler.rs `handle_consensus_commit`, mainnet-v1.83.1): turns
//! one committed sub-dag into the executable order and writes everything the commit decided in
//! one durable group. Implements `consensus.iface.CommitSink`.
//!
//! Per commit, in Rust's order:
//!   1. commit info: timestamp (not before epoch start), the commit-interval ring and the
//!      additional state digest, the rejected transactions digest;
//!   2. parse every block's transactions (fast-path rejects from the sub-dag);
//!   3. filter (`filter_consensus_txns`): drop rejected; at epoch end drop user and most system
//!      kinds; drop user transactions from a proposer that sent EndOfPublish; take owned-object
//!      locks post-consensus: the first transaction in consensus order wins every ObjectRef, a
//!      later conflicting one is dropped (and its competitor deferred when the protocol says so);
//!   4. dedup by consensus transaction key (processed in an earlier commit, or earlier in this one);
//!   5. system transactions go to their owners through `Router` (checkpoint signatures, DKG, JWK
//!      votes, capabilities, deny config, execution time observations);
//!   6. schedule: deferred transactions due, reorder by gas price, then per transaction defer
//!      (unpaid amplification, double spend, randomness not ready, congestion) or cancel
//!      (congestion beyond the deferral limit, DKG failed) or schedule, with the congestion
//!      tracker bumping object costs;
//!   7. epoch close state machine (EndOfPublish quorum or the epoch's end time);
//!   8. consensus commit prologue V4 (version assignments of cancelled transactions plus the
//!      additional state digest), authenticator state update, randomness state update, and the
//!      accumulator settlement per checkpoint chunk;
//!   9. shared-object version assignment, checkpoint queue (chunks of
//!      `max_transactions_per_checkpoint`, flush by `min_checkpoint_interval_ms`);
//!  10. one durable group (state.commit), then: executor enqueue, pending checkpoints to the
//!      builder, the adapter learns what was sequenced.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const consensus = @import("consensus");
const iface = @import("../iface.zig");
const messages = @import("../messages.zig");
const codec = @import("codec.zig");
const tx_mod = @import("tx.zig");
const state_mod = @import("state.zig");
const versions = @import("versions.zig");
const jwk_aggregator = @import("../jwk/aggregator.zig");
const deferral = @import("deferral.zig");
const congestion = @import("congestion.zig");
const env_mod = @import("env.zig");
const exec_bridge = @import("exec_bridge.zig");
const adapter_mod = @import("adapter.zig");
const status_mod = @import("status.zig");
const locks_mod = @import("locks.zig");
const tx_validator = @import("tx_validator.zig");

const Allocator = std.mem.Allocator;
pub const Id = tx_mod.Id;
const Key = versions.Assignable.Key;
const EpochState = state_mod.EpochState;
const Batch = state_mod.Batch;
const DeferralKey = deferral.DeferralKey;

pub const Error = error{ Corrupt, Io, Unsupported, OutOfMemory };

/// Where non-user consensus transactions go (every hook optional so a partial validator runs).
pub const Router = struct {
    checkpoint_signature: ?iface.CheckpointSignatureSink = null,
    randomness: ?iface.RandomnessHooks = null,
    jwk: ?iface.JwkHooks = null,
    epoch: ?iface.EpochHooks = null,
};

/// JWKs that became active in `round` (`get_new_jwks`), supplied by the JWK lane.
pub const JwkSource = struct {
    ctx: *anyopaque,
    get: *const fn (ctx: *anyopaque, arena: Allocator, round: u64) []const types.ActiveJwk,
};

/// The durable log the batch is appended to.
pub const DurableLog = struct {
    ctx: *anyopaque,
    append: *const fn (ctx: *anyopaque, group: []const u8) @import("epoch_log.zig").Error!void,

    pub fn appendGroup(l: DurableLog, group: []const u8) @import("epoch_log.zig").Error!void {
        return l.append(l.ctx, group);
    }
    pub fn fromMem(m: *@import("epoch_log.zig").MemLog) DurableLog {
        const T = struct {
            fn f(ctx: *anyopaque, g: []const u8) @import("epoch_log.zig").Error!void {
                const l: *@import("epoch_log.zig").MemLog = @ptrCast(@alignCast(ctx));
                return l.appendGroup(g);
            }
        };
        return .{ .ctx = m, .append = T.f };
    }
    pub fn fromFile(m: *@import("epoch_log.zig").FileLog) DurableLog {
        const T = struct {
            fn f(ctx: *anyopaque, g: []const u8) @import("epoch_log.zig").Error!void {
                const l: *@import("epoch_log.zig").FileLog = @ptrCast(@alignCast(ctx));
                return l.appendGroup(g);
            }
        };
        return .{ .ctx = m, .append = T.f };
    }
};

pub const Deps = struct {
    params: env_mod.Params,
    /// Committee in consensus AuthorityIndex order.
    committee: []const iface.AuthorityName,
    state: *EpochState,
    log: DurableLog,
    epoch_ctl: env_mod.EpochControl,
    router: Router = .{},
    exec: *exec_bridge.Bridge,
    reader: versions.ObjectReader,
    estimator: *congestion.Estimator,
    pending_sink: ?iface.PendingCheckpointSink = null,
    jwks: ?JwkSource = null,
    adapter: ?*adapter_mod.Adapter = null,
    statuses: ?*status_mod.StatusCache = null,
    reasons: ?*tx_validator.ReasonCache = null,
    tracer: iface.Tracer = .{},
};

const CommitInfo = struct {
    round: u64,
    timestamp: u64,
    leader_author: u32,
    commit_ref: state_mod.CommitRef,
    rejected_digest: [32]u8,
    period_us: u64,
    additional_digest: [32]u8,
};

const Parsed = struct {
    tx: messages.ConsensusTransaction,
    rejected: bool,
    author: u32,
    pos: status_mod.Position,
    /// Set for UserTransactionV2 that decoded and passed the input checks (never for vote-rejected ones).
    user: ?tx_mod.UserTx,
    is_user: bool = false,
    /// UserTransactionV2 whose input checks failed (Rust: owned_object_refs_to_lock is None): digest + reason.
    bad_inputs: bool = false,
    bad_digest: [32]u8 = @splat(0),
    bad_reason: []const u8 = "",
    raw_hash: [32]u8,
};

const Conflict = struct { winner_author: u32 = 0, gas: u32 = 0, non_gas: u32 = 0 };

/// A transaction ready to schedule: the decoded user transaction.
const Item = *const tx_mod.UserTx;

pub const Stats = struct {
    commits: u64 = 0,
    user_scheduled: u64 = 0,
    deferred: u64 = 0,
    cancelled: u64 = 0,
    dropped_lock_conflict: u64 = 0,
    rejected_by_vote: u64 = 0,
    skipped_duplicates: u64 = 0,
    pending_checkpoints: u64 = 0,
};

pub const Handler = struct {
    gpa: Allocator,
    d: Deps,
    committee_index: std.AutoHashMapUnmanaged([96]u8, u32) = .empty,
    /// Highest commit index handled (durable or skipped at epoch end): `processed_through`.
    last_handled: std.atomic.Value(u32) = .init(0),
    /// Set when a commit failed to apply: nothing further is processed until a restart.
    failed: std.atomic.Value(bool) = .init(false),
    stats: Stats = .{},
    /// Bounded input ring for the CommitSink.
    inbox: std.ArrayList(*Input) = .empty,
    inbox_lock: adapter_mod.Spin = .{},
    inbox_cap: usize = 1024,
    /// Acknowledgements waiting for the next durable group: executed items (their assigned
    /// versions are no longer needed), checkpointed user signatures, built pending checkpoints.
    ack_lock: adapter_mod.Spin = .{},
    ack_assigned: std.ArrayList(Key) = .empty,
    ack_sigs: std.ArrayList([32]u8) = .empty,
    ack_pending: ?u64 = null,

    pub const InitError = Allocator.Error || error{MissingEpochStart};

    /// Epoch start values the handler cannot default: Rust `expect()`s them.
    fn checkParams(p: env_mod.Params, d: Deps) error{MissingEpochStart}!void {
        if (p.randomness_state_enabled and p.randomness_isv == null) return error.MissingEpochStart;
        if (p.accumulators_enabled and p.implicit.accumulator_root == null) return error.MissingEpochStart;
        if (d.jwks != null and p.authenticator_isv == null) return error.MissingEpochStart;
    }

    pub fn init(gpa: Allocator, d: Deps) InitError!Handler {
        try checkParams(d.params, d);
        var h: Handler = .{ .gpa = gpa, .d = d };
        errdefer h.committee_index.deinit(gpa);
        for (d.committee, 0..) |name, i| try h.committee_index.put(gpa, name.@"0", @intCast(i));
        h.last_handled.store(@intCast(@min(d.state.indices.sub_dag_index, std.math.maxInt(u32))), .release);
        return h;
    }

    pub fn deinit(h: *Handler) void {
        h.ack_assigned.deinit(h.gpa);
        h.ack_sigs.deinit(h.gpa);
        for (h.inbox.items) |i| i.destroy(h.gpa);
        h.inbox.deinit(h.gpa);
        h.committee_index.deinit(h.gpa);
    }

    /// Rebuilds the execution time estimator from the observations in the epoch state (restart):
    /// the estimator is a pure function of the sequenced observations (`ExecutionTimeEstimator::new`
    /// over the stored observations).
    pub fn restoreEstimator(h: *Handler, arena: Allocator) Error!void {
        for (h.d.state.observations.items) |o| {
            const Est = []const struct { types.ExecutionTimeObservationKey, types.Duration };
            const ests = bcs.decode(Est, arena, o.estimates_bcs) catch return error.Corrupt;
            for (ests) |e| {
                const key = try obsKeyBytes(arena, &e.@"0");
                const ns = e.@"1".secs *| 1_000_000_000 +| e.@"1".nanos;
                try h.d.estimator.processObservation(arena, o.authority, o.generation, key, ns, false);
            }
        }
    }

    /// Executor callback: `key` ran, so its assigned versions can be forgotten at the next commit.
    pub fn noteExecuted(h: *Handler, key: Key) void {
        h.ack_lock.lock();
        defer h.ack_lock.unlock();
        h.ack_assigned.append(h.gpa, key) catch {};
    }
    fn noteExecutedCb(ctx: *anyopaque, key: Key) void {
        const h: *Handler = @ptrCast(@alignCast(ctx));
        h.noteExecuted(key);
    }
    /// Wires the executor's completion callback to `noteExecuted`. `h` must not move afterwards.
    pub fn attachBridge(h: *Handler, b: *exec_bridge.Bridge) void {
        b.on_done = .{ .ctx = h, .f = noteExecutedCb };
    }

    /// The checkpoint builder consumed the signatures of `digest`.
    pub fn ackSigs(h: *Handler, digest: [32]u8) void {
        h.ack_lock.lock();
        defer h.ack_lock.unlock();
        h.ack_sigs.append(h.gpa, digest) catch {};
    }

    /// The checkpoint builder built pending checkpoints up to and including `seq`.
    pub fn ackPendingThrough(h: *Handler, seq: u64) void {
        h.ack_lock.lock();
        defer h.ack_lock.unlock();
        h.ack_pending = @max(h.ack_pending orelse 0, seq);
    }

    fn drainAcks(h: *Handler, arena: Allocator, batch: *Batch) Allocator.Error!void {
        h.ack_lock.lock();
        defer h.ack_lock.unlock();
        try batch.assigned_acked.appendSlice(arena, h.ack_assigned.items);
        try batch.sigs_acked.appendSlice(arena, h.ack_sigs.items);
        if (h.ack_pending) |q| batch.pending_acked = q;
        h.ack_assigned.clearRetainingCapacity();
        h.ack_sigs.clearRetainingCapacity();
        h.ack_pending = null;
    }

    /// Seeds the estimator with the observations stored at the end of the previous epoch
    /// (`get_stored_execution_time_observations`, generation None), before this epoch's own
    /// observations are replayed. `chunks` are the BCS `StoredExecutionTimeObservations` values
    /// of the system state's chunk dynamic fields, in chunk order (merge_sorted_chunks); a
    /// non-chunked epoch passes none. Names are mapped to the current committee's indices;
    /// unknown validators are skipped as Rust's `authority_index` lookup does.
    pub fn seedEstimator(h: *Handler, arena: Allocator, chunks: []const []const u8) Error!void {
        for (chunks) |cb| {
            const stored = bcs.decode(types.StoredExecutionTimeObservations, arena, cb) catch return error.Corrupt;
            switch (stored) {
                .V1 => |entries| for (entries) |ent| {
                    const key = try obsKeyBytes(arena, &ent.@"0");
                    for (ent.@"1") |src| {
                        const idx = h.committee_index.get(src.@"0".@"0") orelse continue;
                        const ns = src.@"1".secs *| 1_000_000_000 +| src.@"1".nanos;
                        try h.d.estimator.processObservation(arena, idx, null, key, ns, true);
                    }
                },
            }
        }
        h.d.estimator.recomputeAll();
    }

    // ------------------------------------------------------------------ CommitSink

    const Input = struct {
        arena: std.heap.ArenaAllocator,
        sub: consensus.types.CommittedSubDag,
        fn destroy(i: *Input, gpa: Allocator) void {
            i.arena.deinit();
            gpa.destroy(i);
        }
    };

    fn cloneSub(h: *Handler, src: *const consensus.types.CommittedSubDag) Allocator.Error!*Input {
        const inp = try h.gpa.create(Input);
        errdefer h.gpa.destroy(inp);
        inp.arena = .init(h.gpa);
        errdefer inp.arena.deinit();
        const a = inp.arena.allocator();
        const blocks = try a.alloc(consensus.types.VerifiedBlock, src.blocks.len);
        for (src.blocks, blocks) |sb, *db| {
            // only what the handler reads: the block reference, round, author and each transaction's bytes
            var blk = sb.block;
            const txs = sb.block.inner.transactions();
            const copy = try a.alloc(consensus.types.Transaction, txs.len);
            for (txs, copy) |t, *c| c.* = .{ .data = try a.dupe(u8, t.data) };
            switch (blk.inner) {
                inline .V1, .V2, .V3 => |*v| v.transactions = copy,
            }
            db.* = .{ .block = blk, .serialized = &.{}, .digest = sb.digest };
        }
        const rej = try a.alloc(consensus.types.RejectedInBlock, src.rejected_transactions_by_block.len);
        for (src.rejected_transactions_by_block, rej) |r, *o| o.* = .{ .block = r.block, .indices = try a.dupe(consensus.types.TransactionIndex, r.indices) };
        inp.sub = src.*;
        inp.sub.blocks = blocks;
        inp.sub.rejected_transactions_by_block = rej;
        return inp;
    }

    fn sinkPush(ctx: *anyopaque, sub: *const consensus.types.CommittedSubDag) bool {
        const h: *Handler = @ptrCast(@alignCast(ctx));
        h.inbox_lock.lock();
        defer h.inbox_lock.unlock();
        if (h.inbox.items.len >= h.inbox_cap) return false;
        const inp = h.cloneSub(sub) catch return false;
        h.inbox.append(h.gpa, inp) catch {
            inp.destroy(h.gpa);
            return false;
        };
        return true;
    }
    fn sinkProcessedThrough(ctx: *anyopaque) consensus.types.CommitIndex {
        const h: *Handler = @ptrCast(@alignCast(ctx));
        return h.last_handled.load(.acquire);
    }
    const sink_vt: consensus.iface.CommitSink.VTable = .{ .push = sinkPush, .processed_through = sinkProcessedThrough };

    pub fn commitSink(h: *Handler) consensus.iface.CommitSink {
        return .{ .ctx = h, .vtable = &sink_vt };
    }

    /// Handler thread: processes every queued commit. Returns how many.
    pub fn drain(h: *Handler) Error!usize {
        var n: usize = 0;
        while (true) {
            h.inbox_lock.lock();
            const inp: ?*Input = if (h.inbox.items.len != 0) h.inbox.orderedRemove(0) else null;
            h.inbox_lock.unlock();
            const i = inp orelse break;
            var arena_state: std.heap.ArenaAllocator = .init(h.gpa);
            defer arena_state.deinit();
            h.handleCommit(arena_state.allocator(), &i.sub) catch |e| {
                // never skip a commit: put it back at the head, mark the handler failed and surface the error;
                // the owner must restart (replaying from the durable indices)
                h.failed.store(true, .release);
                h.inbox_lock.lock();
                const requeued = h.inbox.insert(h.gpa, 0, i);
                h.inbox_lock.unlock();
                if (requeued) |_| {} else |_| i.destroy(h.gpa);
                return e;
            };
            i.destroy(h.gpa);
            n += 1;
        }
        return n;
    }

    // ------------------------------------------------------------------ helpers

    fn authorityIndex(h: *const Handler, name: *const iface.AuthorityName) ?u32 {
        return h.committee_index.get(name.@"0");
    }

    /// `AuthorityCapabilities` etc. must come from the block's author.
    fn senderMatches(h: *const Handler, author: u32, name: *const iface.AuthorityName) bool {
        const idx = h.authorityIndex(name) orelse return false;
        return idx == author;
    }

    fn consensusKey(arena: Allocator, c: *const messages.ConsensusTransaction, user: ?*const tx_mod.UserTx, raw: []const u8) Allocator.Error![32]u8 {
        var b: std.ArrayList(u8) = .empty;
        switch (c.kind) {
            .UserTransactionV2 => {
                try b.append(arena, 0);
                try b.appendSlice(arena, &user.?.digest);
            },
            .CheckpointSignatureV2 => |m| {
                try b.append(arena, 1);
                try b.appendSlice(arena, &m.summary.auth_signature.authority.@"0");
                var n: [8]u8 = undefined;
                std.mem.writeInt(u64, &n, m.summary.data.sequence_number, .little);
                try b.appendSlice(arena, &n);
                const enc = try bcs.encodeAlloc(types.CheckpointSummary, arena, &m.summary.data);
                const dig = hash.blake2b256(&.{ "CheckpointSummary::", enc });
                try b.appendSlice(arena, &dig);
            },
            .EndOfPublish => |a| {
                try b.append(arena, 2);
                try b.appendSlice(arena, &a.@"0");
            },
            .CapabilityNotificationV2 => |cap| {
                try b.append(arena, 3);
                try b.appendSlice(arena, &cap.authority.@"0");
                var n: [8]u8 = undefined;
                std.mem.writeInt(u64, &n, cap.generation, .little);
                try b.appendSlice(arena, &n);
            },
            .NewJWKFetched => |j| {
                try b.append(arena, 4);
                const enc = try bcs.encodeAlloc(@TypeOf(j), arena, &j);
                try b.appendSlice(arena, enc);
            },
            .RandomnessDkgMessage => |m| {
                try b.append(arena, 5);
                try b.appendSlice(arena, &m.@"0".@"0");
            },
            .RandomnessDkgConfirmation => |m| {
                try b.append(arena, 6);
                try b.appendSlice(arena, &m.@"0".@"0");
            },
            .ExecutionTimeObservation => |o| {
                try b.append(arena, 7);
                try b.appendSlice(arena, &o.authority.@"0");
                var n: [8]u8 = undefined;
                std.mem.writeInt(u64, &n, o.generation, .little);
                try b.appendSlice(arena, &n);
            },
            .UpdateTransactionDenyConfig => |m| switch (m) {
                .V1 => |v| {
                    try b.append(arena, 8);
                    try b.appendSlice(arena, &v.authority.@"0");
                    var n: [8]u8 = undefined;
                    std.mem.writeInt(u64, &n, v.generation, .little);
                    try b.appendSlice(arena, &n);
                },
            },
            else => {
                try b.append(arena, 255);
                try b.appendSlice(arena, raw);
            },
        }
        return hash.blake2b256(&.{b.items});
    }

    fn rejectedDigest(arena: Allocator, rej: []const consensus.types.RejectedInBlock) Allocator.Error![32]u8 {
        // BCS Vec<(BlockRef, Vec<TransactionIndex>)>: ULEB len; BlockRef = round u32, author u32,
        // digest 32 bytes; Vec<u16> = ULEB len then u16 LE each.
        var w = codec.Writer.init(arena);
        try uleb(&w, rej.len);
        for (rej) |r| {
            try w.u32_(r.block.round);
            try w.u32_(r.block.author);
            try w.raw(&r.block.digest);
            try uleb(&w, r.indices.len);
            for (r.indices) |i| {
                var b: [2]u8 = undefined;
                std.mem.writeInt(u16, &b, i, .little);
                try w.raw(&b);
            }
        }
        return hash.blake2b256(&.{w.bytes()});
    }

    fn uleb(w: *codec.Writer, v: usize) Allocator.Error!void {
        var x = v;
        while (true) {
            const byte: u8 = @intCast(x & 0x7f);
            x >>= 7;
            if (x == 0) {
                try w.u8_(byte);
                return;
            }
            try w.u8_(byte | 0x80);
        }
    }

    fn additionalStateDigest(arena: Allocator, ring: []const u64) Allocator.Error![32]u8 {
        var w = codec.Writer.init(arena);
        try uleb(&w, ring.len);
        for (ring) |t| try w.u64_(t);
        return hash.blake2b256(&.{w.bytes()});
    }

    fn setStatus(h: *Handler, p: status_mod.Position, s: status_mod.Status) void {
        if (h.d.statuses) |c| c.set(p, s) catch {};
    }

    fn setReason(h: *Handler, p: status_mod.Position, reason: []const u8) void {
        if (h.d.reasons) |c| c.set(.{ .round = p.round, .author = p.author, .digest = p.digest, .index = p.index }, reason) catch {};
    }

    // ------------------------------------------------------------------ the commit

    pub fn handleCommit(h: *Handler, arena: Allocator, sub: *const consensus.types.CommittedSubDag) Error!void {
        const p = h.d.params;
        const st = h.d.state;
        const epoch = p.epoch;
        if (!p.record_additional_state_digest) return error.Unsupported;
        if (!p.mode_is_execution_time_estimate) return error.Unsupported;

        if (h.failed.load(.acquire)) return error.Corrupt;
        // replays after a restart re-send commits at or below the durable point: skip them
        const done = h.last_handled.load(.acquire);
        if (sub.commit_ref.index <= done and done != 0) return;
        // never process out of order: a gap would silently lose locks, versions and deferrals
        if (done != 0 and sub.commit_ref.index != done + 1) return error.Corrupt;

        const last_committed_round = st.indices.last_committed_round;

        // 1. commit info
        // commit_info.timestamp is clamped to the epoch start; the commit-interval ring
        // (`observe_commit_time`) takes the raw `commit_timestamp_ms()`
        const ts = @max(sub.timestamp_ms, p.epoch_start_ms);
        const ring = try st.ringAfter(arena, sub.timestamp_ms);
        const period_ms = state_mod.EpochState.intervalOf(ring) orelse p.min_checkpoint_interval_ms;
        const info: CommitInfo = .{
            .round = sub.leader.round,
            .timestamp = ts,
            .leader_author = sub.leader.author,
            .commit_ref = .{ .index = sub.commit_ref.index, .digest = sub.commit_ref.digest },
            .rejected_digest = try rejectedDigest(arena, sub.rejected_transactions_by_block),
            .period_us = period_ms *| 1000,
            .additional_digest = try additionalStateDigest(arena, ring),
        };
        if (info.round <= last_committed_round and last_committed_round != 0) return error.Corrupt;

        var batch = Batch.init(arena, .{ .last_committed_round = info.round, .sub_dag_index = info.commit_ref.index, .transaction_index = 0 });
        try batch.commit_times.append(arena, sub.timestamp_ms);
        if (h.d.statuses) |sc| sc.updateLastCommitted(last_committed_round);

        // 2. parse
        var parsed: std.ArrayList(Parsed) = .empty;
        for (sub.blocks) |*blk| {
            const ref = blk.reference();
            const rejected_idx: []const consensus.types.TransactionIndex = for (sub.rejected_transactions_by_block) |r| {
                if (std.mem.eql(u8, &r.block.digest, &ref.digest)) break r.indices;
            } else &.{};
            const txs = blk.block.inner.transactions();
            for (txs, 0..) |t, idx| {
                const c = bcs.decode(messages.ConsensusTransaction, arena, t.data) catch |e| switch (e) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.Corrupt,
                };
                const is_user = c.kind == .UserTransactionV2;
                var rejected = false;
                if (is_user) for (rejected_idx) |ri| if (ri == idx) {
                    rejected = true;
                };
                var user: ?tx_mod.UserTx = null;
                var bad = false;
                var bad_digest: [32]u8 = @splat(0);
                var bad_reason: []const u8 = "";
                if (is_user and !rejected) {
                    // payload starts after the 8 byte tracking id and the 1 byte variant
                    const raw = if (t.data.len > 9) t.data[9..] else return error.Corrupt;
                    if (tx_mod.fromDecodedWhy(arena, raw, c.kind.UserTransactionV2, &bad_reason)) |u| {
                        user = u;
                    } else |e| switch (e) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => {
                            // deterministic drop, as Rust: the digest alone keys it
                            bad = true;
                            bad_digest = try tx_mod.transactionDigest(arena, &c.kind.UserTransactionV2.tx.data.@"0".element().intent_message.value.V1);
                        },
                    }
                }
                try parsed.append(arena, .{
                    .is_user = is_user,
                    .bad_inputs = bad,
                    .bad_digest = bad_digest,
                    .bad_reason = bad_reason,
                    .tx = c,
                    .rejected = rejected,
                    .author = ref.author,
                    .pos = .{ .round = ref.round, .author = ref.author, .digest = ref.digest, .index = @intCast(idx) },
                    .user = user,
                    .raw_hash = hash.blake2b256(&.{t.data}),
                });
            }
            h.setStatus(.{ .round = ref.round, .author = ref.author, .digest = ref.digest, .index = std.math.maxInt(u16) }, .finalized);
        }

        // 3. filter
        const initial_reconfig = h.d.epoch_ctl.reconfigState();
        var kept: std.ArrayList(*Parsed) = .empty;
        var owned_locks = locks_mod.OwnedLocks.init(arena, st);
        var lock_authors: std.AutoHashMapUnmanaged(Id, u32) = .empty;
        var contested: std.AutoHashMapUnmanaged(Id, Conflict) = .empty;
        var dropped_keys: std.ArrayList([32]u8) = .empty;
        for (parsed.items) |*pt| {
            const is_user = pt.is_user;
            if (pt.rejected) {
                if (is_user) {
                    h.setStatus(pt.pos, .rejected);
                    h.stats.rejected_by_vote += 1;
                    if (h.d.adapter) |a| a.onSequenced(&pt.raw_hash);
                }
                continue;
            }
            if (!initial_reconfig.shouldAcceptConsensusCerts()) {
                switch (pt.tx.kind) {
                    .UserTransactionV2, .UserTransaction, .CertifiedTransaction, .CapabilityNotification, .CapabilityNotificationV2, .EndOfPublish, .ExecutionTimeObservation, .NewJWKFetched, .UpdateTransactionDenyConfig => {
                        if (is_user) h.setStatus(pt.pos, .dropped);
                        continue;
                    },
                    .CheckpointSignature, .CheckpointSignatureV2, .RandomnessStateUpdate, .RandomnessDkgMessage, .RandomnessDkgConfirmation => {},
                }
            }
            if (!initial_reconfig.shouldAcceptTx()) switch (pt.tx.kind) {
                .RandomnessDkgConfirmation, .RandomnessDkgMessage => continue,
                else => {},
            };
            switch (pt.tx.kind) {
                .CapabilityNotification, .RandomnessStateUpdate, .CheckpointSignature, .CertifiedTransaction, .UserTransaction => continue,
                else => {},
            }
            if (is_user and h.d.epoch_ctl.hasReceivedEndOfPublishFrom(pt.author)) {
                h.setStatus(pt.pos, .dropped);
                continue;
            }
            if (pt.bad_inputs) {
                h.setStatus(pt.pos, .dropped);
                h.setReason(pt.pos, pt.bad_reason);
                var k: std.ArrayList(u8) = .empty;
                try k.append(arena, 0);
                try k.appendSlice(arena, &pt.bad_digest);
                const bk = hash.blake2b256(&.{k.items});
                try dropped_keys.append(arena, bk);
                if (h.d.adapter) |a| {
                    a.onSequenced(&pt.raw_hash);
                    a.onConsensusKey(&bk);
                }
                continue;
            }
            if (pt.user) |*u| {
                const refs = try u.refsToLock(arena);
                const outcome = try owned_locks.tryAcquirePostConsensus(refs, &u.digest);
                if (outcome != .conflict) {
                    // new locks go to the commit batch; ones already held are not rewritten
                    if (outcome == .acquired) for (refs) |r| try batch.addLock(r, u.digest);
                    const g = try lock_authors.getOrPut(arena, u.digest);
                    if (!g.found_existing) g.value_ptr.* = pt.author;
                    h.setStatus(pt.pos, .finalized);
                } else {
                    // intra-commit contest: credit the holder of any ref locked earlier in this commit
                    for (refs) |r| if (owned_locks.holderInCommit(r)) |holder| {
                        const gop = try contested.getOrPut(arena, holder);
                        if (!gop.found_existing) gop.value_ptr.* = .{};
                        gop.value_ptr.winner_author = lock_authors.get(holder) orelse pt.author;
                        var is_gas = false;
                        for (u.data().gas_data.payment) |gp| if (std.mem.eql(u8, &gp.@"0".@"0".@"0", &r.id)) {
                            is_gas = true;
                        };
                        if (is_gas) gop.value_ptr.gas += 1 else gop.value_ptr.non_gas += 1;
                    };
                    h.stats.dropped_lock_conflict += 1;
                    h.setStatus(pt.pos, .dropped);
                    h.setReason(pt.pos, "Object is locked by another transaction");
                    const dk = try consensusKey(arena, &pt.tx, u, &.{});
                    try dropped_keys.append(arena, dk);
                    if (h.d.adapter) |a| {
                        a.onSequenced(&pt.raw_hash);
                        a.onConsensusKey(&dk);
                    }
                    continue;
                }
            }
            try kept.append(arena, pt);
        }
        for (dropped_keys.items) |k| try batch.recordProcessed(k);

        // 4. dedup (+ verify_consensus_transaction's sender checks)
        var occurrence: std.AutoHashMapUnmanaged([32]u8, u32) = .empty;
        var user_occurrence: std.AutoHashMapUnmanaged(Id, u32) = .empty;
        var txns: std.ArrayList(*Parsed) = .empty;
        var seq: u64 = 0;
        for (kept.items) |pt| {
            seq += 1;
            batch.indices.transaction_index = seq;
            if (!h.senderOk(pt)) continue;
            const key = try consensusKey(arena, &pt.tx, if (pt.user) |*u| u else null, &.{});
            // any appearance of a transaction ends tracking of our own copy
            if (h.d.adapter) |a| {
                a.onSequenced(&pt.raw_hash);
                if (pt.user != null) a.onConsensusKey(&key);
            }
            const oc = try occurrence.getOrPut(arena, key);
            if (oc.found_existing) oc.value_ptr.* += 1 else oc.value_ptr.* = 1;
            if (pt.user) |u| {
                const uo = try user_occurrence.getOrPut(arena, u.digest);
                if (uo.found_existing) uo.value_ptr.* += 1 else uo.value_ptr.* = 1;
            }
            if (oc.value_ptr.* > 1) {
                h.stats.skipped_duplicates += 1;
                continue;
            }
            if (st.isProcessed(&key)) {
                h.stats.skipped_duplicates += 1;
                continue;
            }
            try batch.recordProcessed(key);
            try txns.append(arena, pt);
        }

        // 5. randomness status for this commit round (before DKG messages), as init_randomness
        var randomness_round: ?u64 = null;
        var dkg_failed = false;
        if (p.randomness_state_enabled) if (h.d.router.randomness) |rh| {
            if (rh.vtable.begin_commit) |f| f(rh.ctx, info.round, ts);
            if (rh.vtable.dkg_failed(rh.ctx)) {
                dkg_failed = true;
            } else if (initial_reconfig.shouldAcceptTx()) {
                randomness_round = rh.vtable.reserve_next_round(rh.ctx, ts);
            }
        };

        // 6. system transactions to their owners
        var user_txs: std.ArrayList(*const tx_mod.UserTx) = .empty;
        var eop_authors: std.ArrayList(u32) = .empty;
        for (txns.items) |pt| switch (pt.tx.kind) {
            .UserTransactionV2 => try user_txs.append(arena, &pt.user.?),
            .EndOfPublish => try eop_authors.append(arena, pt.author),
            .NewJWKFetched => |j| if (h.d.router.jwk) |jh| {
                _ = jh.vtable.vote(jh.ctx, &j.@"0", &j.@"1", &j.@"2", info.round);
            },
            .CapabilityNotificationV2 => |c| if (h.d.router.epoch) |eh| eh.vtable.capabilities(eh.ctx, &c),
            .UpdateTransactionDenyConfig => |c| if (h.d.router.epoch) |eh| eh.vtable.deny_config(eh.ctx, &c),
            .ExecutionTimeObservation => |o| try h.processObservation(arena, &batch, &o),
            .CheckpointSignatureV2 => |*m| if (h.d.router.checkpoint_signature) |cs| cs.vtable.add(cs.ctx, &m.summary.auth_signature.authority, m),
            .RandomnessDkgMessage => |m| if (p.randomness_state_enabled) if (h.d.router.randomness) |rh| rh.vtable.dkg_message(rh.ctx, &m.@"0", m.@"1"),
            .RandomnessDkgConfirmation => |m| if (p.randomness_state_enabled) if (h.d.router.randomness) |rh| rh.vtable.dkg_confirmation(rh.ctx, &m.@"0", m.@"1"),
            else => {},
        };
        // process_dkg_updates: advance_dkg after the commit's DKG messages and confirmations
        if (p.randomness_state_enabled) if (h.d.router.randomness) |rh| if (rh.vtable.advance_dkg) |f| f(rh.ctx);

        // 7. authenticator state update from jwks that became active in the previous commit
        var auth_update: ?SystemTx = null;
        if (p.authenticator_isv) |isv| if (h.d.jwks) |src| {
            const new = src.get(src.ctx, arena, last_committed_round);
            if (new.len != 0) auth_update = try buildAuthenticatorUpdate(arena, epoch, info.round, new, isv);
        };

        // 8. schedule
        var cancelled: versions.Cancelled = .empty;
        var indirect = IndirectObserver.init();
        const sched = try h.collectToSchedule(arena, &batch, &indirect, &cancelled, &info, user_txs.items, &user_occurrence, &contested, randomness_round != null, dkg_failed);

        // 9. epoch close
        const close = try h.handleClose(arena, &batch, &info, eop_authors.items);
        const make_checkpoint = close.should_accept_tx or close.final_round;
        if (!make_checkpoint) {
            h.last_handled.store(info.commit_ref.index, .release);
            return;
        }

        // 10. schedulables, version assignment, queue, pending checkpoints
        try h.finishCommit(arena, &batch, &info, sched, &cancelled, &indirect, auth_update, randomness_round, dkg_failed, close.final_round);
    }

    fn senderOk(h: *const Handler, pt: *const Parsed) bool {
        return switch (pt.tx.kind) {
            .CheckpointSignatureV2 => |m| h.senderMatches(pt.author, &m.summary.auth_signature.authority),
            .EndOfPublish => |a| h.senderMatches(pt.author, &a),
            .CapabilityNotificationV2 => |c| h.senderMatches(pt.author, &c.authority),
            .NewJWKFetched => |j| h.senderMatches(pt.author, &j.@"0") and jwkSizeOk(&j.@"1", &j.@"2"),
            .RandomnessDkgMessage => |m| h.senderMatches(pt.author, &m.@"0"),
            .RandomnessDkgConfirmation => |m| h.senderMatches(pt.author, &m.@"0"),
            .ExecutionTimeObservation => |o| h.senderMatches(pt.author, &o.authority),
            else => true,
        };
    }

    fn jwkSizeOk(id: *const types.JwkId, jwk: *const types.JWK) bool {
        const n = id.iss.@"0".len + id.kid.@"0".len + jwk.kty.@"0".len + jwk.alg.@"0".len + jwk.e.@"0".len + jwk.n.@"0".len;
        return n <= messages.max_total_jwk_size;
    }

    fn processObservation(h: *Handler, arena: Allocator, batch: *Batch, o: *const messages.ExecutionTimeObservation) Error!void {
        const idx = h.authorityIndex(&o.authority) orelse return;
        for (o.estimates) |e| {
            const key = try obsKeyBytes(arena, &e.@"0");
            const ns = e.@"1".secs *| 1_000_000_000 +| e.@"1".nanos;
            try h.d.estimator.processObservation(arena, idx, o.generation, key, ns, false);
        }
        const enc = try bcs.encodeAlloc(@TypeOf(o.estimates), arena, &o.estimates);
        try batch.observations.append(arena, .{ .authority = idx, .generation = o.generation, .estimates_bcs = enc });
    }

    // ------------------------------------------------------------------ scheduling

    const Scheduled = struct {
        txns: []const *const tx_mod.UserTx,
        randomness: []const *const tx_mod.UserTx,
    };

    fn loadDebts(h: *Handler, arena: Allocator, txns: []const *const tx_mod.UserTx, round: u64, randomness: bool) Allocator.Error![]congestion.Debt {
        var ids: std.ArrayList(Id) = .empty;
        for (txns) |u| for (u.shared) |s| try ids.append(arena, s.id);
        std.mem.sort(Id, ids.items, {}, struct {
            fn less(_: void, a: Id, b: Id) bool {
                return std.mem.order(u8, &a, &b) == .lt;
            }
        }.less);
        const budget = if (randomness) h.d.params.per_commit_budget_randomness else h.d.params.per_commit_budget;
        var out: std.ArrayList(congestion.Debt) = .empty;
        var last: ?Id = null;
        for (ids.items) |id| {
            if (last) |l| if (std.mem.eql(u8, &l, &id)) continue;
            last = id;
            if (h.d.state.debtOf(randomness, &id)) |d| {
                if (round > d.round) try out.append(arena, .{ .id = id, .debt = congestion.decayedDebt(d.debt, d.round, round, budget) });
            }
        }
        return out.items;
    }

    fn deferCommon(h: *Handler, arena: Allocator, deferred: *DeferredMap, key: DeferralKey, u: *const tx_mod.UserTx) Allocator.Error!void {
        _ = h;
        const gop = try deferred.getOrPut(arena, key);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(arena, u);
    }

    const DeferredMap = std.ArrayHashMapUnmanaged(DeferralKey, std.ArrayList(*const tx_mod.UserTx), KeyCtx, false);
    const KeyCtx = struct {
        pub fn hash(_: KeyCtx, k: DeferralKey) u32 {
            var hh = std.hash.Wyhash.init(0);
            switch (k) {
                .randomness => |r| {
                    hh.update(&.{0});
                    hh.update(std.mem.asBytes(&r.deferred_from_round));
                },
                .consensus_round => |c| {
                    hh.update(&.{1});
                    hh.update(std.mem.asBytes(&c.future_round));
                    hh.update(std.mem.asBytes(&c.deferred_from_round));
                },
            }
            return @truncate(hh.final());
        }
        pub fn eql(_: KeyCtx, a: DeferralKey, b: DeferralKey, _: usize) bool {
            return DeferralKey.eql(a, b);
        }
    };

    fn collectToSchedule(
        h: *Handler,
        arena: Allocator,
        batch: *Batch,
        indirect: *IndirectObserver,
        cancelled: *versions.Cancelled,
        info: *const CommitInfo,
        user_txs: []const *const tx_mod.UserTx,
        occurrence: *std.AutoHashMapUnmanaged(Id, u32),
        contested: *std.AutoHashMapUnmanaged(Id, Conflict),
        generating_randomness: bool,
        dkg_failed: bool,
    ) Error!Scheduled {
        const p = h.d.params;
        const st = h.d.state;

        // load deferred transactions due (and record their deletion)
        var prev: congestion.PrevDeferred = .empty;
        var txns: std.ArrayList(*const tx_mod.UserTx) = .empty;
        var rtxns: std.ArrayList(*const tx_mod.UserTx) = .empty;
        var loaded_regular: std.ArrayList(*const tx_mod.UserTx) = .empty;
        for (st.deferred.items) |d| {
            if (!d.key.dueByRound(info.round)) continue;
            try batch.deferred_del.append(arena, d.key);
            for (d.txs.items) |raw| {
                const u = try arena.create(tx_mod.UserTx);
                u.* = tx_mod.parse(arena, try arena.dupe(u8, raw)) catch return error.Corrupt;
                try prev.put(arena, u.digest, d.key);
                try loaded_regular.append(arena, u);
            }
        }
        if (dkg_failed or generating_randomness) {
            for (st.deferred.items) |d| {
                if (d.key != .randomness) continue;
                try batch.deferred_del.append(arena, d.key);
                for (d.txs.items) |raw| {
                    const u = try arena.create(tx_mod.UserTx);
                    u.* = tx_mod.parse(arena, try arena.dupe(u8, raw)) catch return error.Corrupt;
                    try prev.put(arena, u.digest, d.key);
                    try rtxns.append(arena, u);
                }
            }
        }
        for (loaded_regular.items) |u| {
            if (u.uses_randomness) try rtxns.append(arena, u) else try txns.append(arena, u);
        }
        for (user_txs) |u| {
            if (u.uses_randomness) try rtxns.append(arena, u) else try txns.append(arena, u);
        }
        if (p.ordering_by_gas_price) {
            const lessFn = struct {
                fn f(_: void, a: *const tx_mod.UserTx, b: *const tx_mod.UserTx) bool {
                    return a.gas_price > b.gas_price;
                }
            }.f;
            std.mem.sort(*const tx_mod.UserTx, txns.items, {}, lessFn);
            std.mem.sort(*const tx_mod.UserTx, rtxns.items, {}, lessFn);
        }

        var tracker = try congestion.Tracker.init(arena, try h.loadDebts(arena, txns.items, info.round, false), p.congestion, false);
        var rtracker = try congestion.Tracker.init(arena, try h.loadDebts(arena, rtxns.items, info.round, true), p.congestion, true);

        var scheduled: std.ArrayList(*const tx_mod.UserTx) = .empty;
        var rscheduled: std.ArrayList(*const tx_mod.UserTx) = .empty;
        var deferred: DeferredMap = .empty;

        for (txns.items) |u| try h.deferralAndCancellation(arena, &deferred, cancelled, &scheduled, info, u, &tracker, &prev, occurrence, contested, indirect, generating_randomness, dkg_failed);
        for (rtxns.items) |u| {
            if (dkg_failed) {
                try cancelled.put(arena, u.digest, .dkg_failed);
                try rscheduled.append(arena, u);
                continue;
            }
            try h.deferralAndCancellation(arena, &deferred, cancelled, &rscheduled, info, u, &rtracker, &prev, occurrence, contested, indirect, generating_randomness, dkg_failed);
        }

        // record new deferrals (sorted by key, as a BTreeMap)
        const keys = try arena.dupe(DeferralKey, deferred.keys());
        std.mem.sort(DeferralKey, keys, {}, DeferralKey.lessThan);
        for (keys) |k| {
            const list = deferred.get(k).?;
            var raws: std.ArrayList([]const u8) = .empty;
            if (p.merge_colliding_deferrals) {
                if (st.deferredFor(k)) |existing| for (existing) |e| try raws.append(arena, e);
            }
            for (list.items) |u| try raws.append(arena, u.raw);
            try batch.deferred_set.append(arena, .{ .key = k, .txs = raws.items });
            h.stats.deferred += list.items.len;
        }

        // congestion debts
        const debts = try tracker.finishCommit(arena, info.period_us);
        for (debts) |dd| try batch.debts.append(arena, .{ .randomness = false, .id = dd.id, .round = info.round, .debt = dd.debt });
        const rdebts = try rtracker.finishCommit(arena, info.period_us);
        for (rdebts) |dd| try batch.debts.append(arena, .{ .randomness = true, .id = dd.id, .round = info.round, .debt = dd.debt });

        return .{ .txns = scheduled.items, .randomness = rscheduled.items };
    }

    fn deferralAndCancellation(
        h: *Handler,
        arena: Allocator,
        deferred: *DeferredMap,
        cancelled: *versions.Cancelled,
        scheduled: *std.ArrayList(*const tx_mod.UserTx),
        info: *const CommitInfo,
        u: *const tx_mod.UserTx,
        tracker: *congestion.Tracker,
        prev: *const congestion.PrevDeferred,
        occurrence: *std.AutoHashMapUnmanaged(Id, u32),
        contested: *std.AutoHashMapUnmanaged(Id, Conflict),
        indirect: *IndirectObserver,
        generating_randomness: bool,
        dkg_failed: bool,
    ) Error!void {
        const p = h.d.params;

        // unpaid amplification
        if (p.defer_unpaid_amplification and !u.restrictsProposers(p.epoch)) {
            const count = occurrence.get(u.digest) orelse 0;
            const allowed = tx_mod.paidProposerCount(u.gas_price, p.rgp);
            if (count > allowed) {
                const from = if (prev.get(u.digest)) |k| k.deferredFromRound() else info.round;
                const key = DeferralKey.newForConsensusRound(info.round + 1, from);
                if (deferral.withinLimit(key, p.max_deferral_rounds)) {
                    try h.deferCommon(arena, deferred, key, u);
                    return;
                }
            }
        }
        // owned-object double spend contention
        if (contested.get(u.digest) != null and p.defer_owned_object_double_spend) {
            const from = if (prev.get(u.digest)) |k| k.deferredFromRound() else info.round;
            const key = DeferralKey.newForConsensusRound(info.round + 1, from);
            if (deferral.withinLimit(key, p.max_deferral_rounds)) {
                try h.deferCommon(arena, deferred, key, u);
                return;
            }
        }

        // cost (observed into the indirect state digest) then should_defer
        const est_ns = try h.d.estimator.getEstimateNs(arena, u.data());
        const cost_us = congestion.Tracker.txCostUs(est_ns);
        indirect.observe(cost_us);

        // randomness not ready
        if (!dkg_failed and !generating_randomness and p.randomness_state_enabled and u.uses_randomness) {
            const from = if (prev.get(u.digest)) |k| k.deferredFromRound() else info.round;
            try h.deferCommon(arena, deferred, DeferralKey.newForRandomness(from), u);
            return;
        }
        if (try tracker.shouldDefer(arena, u, prev, info.round, info.period_us)) |d| {
            if (deferral.withinLimit(d.key, p.max_deferral_rounds)) {
                try h.deferCommon(arena, deferred, d.key, u);
            } else {
                try cancelled.put(arena, u.digest, .{ .congestion_on_objects = d.congested });
                h.stats.cancelled += 1;
                try scheduled.append(arena, u);
            }
            return;
        }
        try tracker.bump(arena, cost_us, u);
        try scheduled.append(arena, u);
    }

    // ------------------------------------------------------------------ epoch close

    const Close = struct { should_accept_tx: bool, final_round: bool };

    fn handleClose(h: *Handler, arena: Allocator, batch: *Batch, info: *const CommitInfo, eops: []const u32) Error!Close {
        _ = arena;
        const p = h.d.params;
        const ctl = h.d.epoch_ctl;
        const next_reconfig = ctl.nextReconfigurationTimestampMs();
        const timestamp_triggered = info.timestamp >= next_reconfig;
        const deadline_reached = if (p.epoch_close_deadline_ms) |dl| info.timestamp >= next_reconfig +| dl else false;
        var quorum = ctl.hasEndOfPublishQuorum();
        if (!quorum) for (eops) |a| {
            if (ctl.recordEndOfPublish(a)) {
                quorum = true;
                break;
            }
        };
        if (!(timestamp_triggered or quorum)) return .{ .should_accept_tx = true, .final_round = false };

        var rs = ctl.reconfigState();
        const start_reject_all_tx = rs.isRejectAllTx();
        rs.closeAllCerts();
        // Rust reads the cache before this commit's loaded keys are removed, so any deferral
        // present at the start of the commit (or created by it) postpones the final round.
        const has_deferred = h.d.state.deferred.items.len != 0 or batch.deferred_set.items.len != 0;
        const should_close = !has_deferred or deadline_reached;
        const final_round = should_close and !start_reject_all_tx;
        if (final_round) {
            if (has_deferred) {
                // abandon: nothing staged is persisted, every stored deferral is deleted
                batch.deferred_set.clearRetainingCapacity();
                for (h.d.state.deferred.items) |d| {
                    var already = false;
                    for (batch.deferred_del.items) |k| if (DeferralKey.eql(k, d.key)) {
                        already = true;
                    };
                    if (!already) try batch.deferred_del.append(batch.arena, d.key);
                }
            }
            rs.closeAllTx();
        }
        ctl.storeReconfigState(rs);
        return .{ .should_accept_tx = rs.shouldAcceptTx(), .final_round = final_round };
    }

    // ------------------------------------------------------------------ commit tail

    const SysKind = enum { prologue, authenticator, randomness, settlement };
    pub const SystemTx = struct { td_bcs: []const u8, digest: Id };

    const Sched = struct {
        key: Key,
        /// Null for randomness and settlement (built when executed).
        user: ?*const tx_mod.UserTx = null,
        system: ?SystemTx = null,
        kind: exec_bridge.ItemKind,
        shared: []const tx_mod.SharedInput,
    };

    const Chunk = struct {
        items: std.ArrayList(Sched) = .empty,
        settlement: ?Sched = null,
        height: u64,
    };

    fn userSched(arena: Allocator, u: *const tx_mod.UserTx) Sched {
        _ = arena;
        return .{ .key = .{ .digest = u.digest }, .user = u, .kind = .user, .shared = u.shared };
    }

    fn clockShared() tx_mod.SharedInput {
        var id: Id = @splat(0);
        id[31] = 6;
        return .{ .id = id, .isv = 1, .mutability = .mutable };
    }

    fn finishCommit(
        h: *Handler,
        arena: Allocator,
        batch: *Batch,
        info: *const CommitInfo,
        sched: Scheduled,
        cancelled: *const versions.Cancelled,
        indirect: *IndirectObserver,
        auth_update: ?SystemTx,
        randomness_round: ?u64,
        dkg_failed: bool,
        final_round: bool,
    ) Error!void {
        const p = h.d.params;
        const st = h.d.state;
        const epoch = p.epoch;

        // schedulables: prologue, authenticator update, scheduled transactions (+ randomness)
        const prologue_sched: Sched = .{
            .key = .{ .consensus_commit_prologue = .{ .epoch = epoch, .round = info.round, .sub_dag_index = info.commit_ref.index } },
            .kind = .consensus_commit_prologue,
            .shared = &.{clockShared()},
        };
        var regular: std.ArrayList(Sched) = .empty;
        try regular.append(arena, prologue_sched);
        if (auth_update) |au| {
            var id: Id = @splat(0);
            id[31] = 7;
            const shared = try arena.alloc(tx_mod.SharedInput, 1);
            shared[0] = .{ .id = id, .isv = p.authenticator_isv.?, .mutability = .mutable };
            try regular.append(arena, .{ .key = .{ .digest = au.digest }, .system = au, .kind = .authenticator_state_update, .shared = shared });
        }
        for (sched.txns) |u| try regular.append(arena, userSched(arena, u));

        var rand_list: std.ArrayList(Sched) = .empty;
        if (randomness_round) |rr| {
            const shared = try arena.alloc(tx_mod.SharedInput, 1);
            shared[0] = .{ .id = tx_mod.randomness_object_id, .isv = p.randomness_isv.?, .mutability = .mutable };
            try rand_list.append(arena, .{ .key = .{ .randomness_round = .{ .epoch = epoch, .round = rr } }, .kind = .randomness_state_update, .shared = shared });
        }
        for (sched.randomness) |u| try rand_list.append(arena, userSched(arena, u));
        const should_write_random_checkpoint = randomness_round != null or (dkg_failed and sched.randomness.len != 0);

        // chunk by max_transactions_per_checkpoint
        var qh = st.queue_height;
        var chunks: std.ArrayList(Chunk) = .empty;
        var rchunks: std.ArrayList(Chunk) = .empty;
        const max_tx: usize = @intCast(@max(p.max_tx_per_checkpoint, 1));
        try h.buildChunks(arena, regular.items, max_tx, &qh, &chunks);
        if (should_write_random_checkpoint) try h.buildChunks(arena, rand_list.items, max_tx, &qh, &rchunks);

        // version assignment over every schedulable in chunk order, then settlement
        var assignables: std.ArrayList(versions.Assignable) = .empty;
        var order: std.ArrayList(*const Sched) = .empty;
        for ([_]*std.ArrayList(Chunk){ &chunks, &rchunks }) |cl| for (cl.items) |*c| {
            for (c.items.items) |*s| try h.addAssignable(arena, &assignables, &order, s);
            if (c.settlement) |*s| try h.addAssignable(arena, &assignables, &order, s);
        };
        const venv: versions.Env = .{
            .implicit = p.implicit,
            .epoch_versions = .{ .ctx = st, .get = epochVersionsGet },
            .reader = h.d.reader,
        };
        const result = try versions.assignFromConsensus(arena, &venv, assignables.items, cancelled);
        {
            var it = result.next_versions.iterator();
            var ks: std.ArrayList(versions.ObjKey) = .empty;
            while (it.next()) |kv| try ks.append(arena, kv.key_ptr.*);
            std.mem.sort(versions.ObjKey, ks.items, {}, versions.ObjKey.lessThan);
            for (ks.items) |k| try batch.next_versions.append(arena, .{ .key = k, .version = result.next_versions.get(k).? });
        }

        // the real prologue transaction
        var cancelled_assign: std.ArrayList(struct { types.TransactionDigest, []const struct { struct { types.ObjectID, types.SequenceNumber }, types.SequenceNumber } }) = .empty;
        for (result.assigned) |a| {
            const d = a.key.asDigest() orelse continue;
            if (!a.anyCancelled()) continue;
            const vs = try arena.alloc(struct { struct { types.ObjectID, types.SequenceNumber }, types.SequenceNumber }, a.shared.len);
            for (a.shared, vs) |s, *o| o.* = .{ .{ oid(s.id), seqn(s.isv) }, seqn(s.version) };
            try cancelled_assign.append(arena, .{ tdigest(d), vs });
        }
        const folded = indirect.foldWith(info.additional_digest);
        const prologue = try buildPrologue(arena, epoch, info, cancelled_assign.items, folded);

        // replace the prologue's key by its digest in chunk 0 and in the assignment
        const prologue_key: Key = .{ .digest = prologue.digest };
        for (result.assigned) |*a| if (a.key.eql(prologue_sched.key)) {
            a.key = prologue_key;
        };
        chunks.items[0].items.items[0].key = prologue_key;
        chunks.items[0].items.items[0].system = prologue;

        // persist assigned versions (all schedulables), user signatures
        {
            var by_key: std.AutoHashMapUnmanaged(Key, *const Sched) = .empty;
            for ([_]*std.ArrayList(Chunk){ &chunks, &rchunks }) |cl| for (cl.items) |*c| {
                for (c.items.items) |*s| try by_key.put(arena, s.key, s);
                if (c.settlement) |*s| try by_key.put(arena, s.key, s);
            };
            for (result.assigned) |a| {
                const exec: ?state_mod.ExecPayload = if (by_key.get(a.key)) |s| blk: {
                    const pl = try execPayload(arena, s.*);
                    break :blk .{ .kind = @intFromEnum(s.kind), .td_bcs = pl.td_bcs, .digest = pl.digest, .owned = pl.owned };
                } else null;
                try batch.assigned.append(arena, .{ .key = a.key, .shared = a.shared, .system = a.system, .exec = exec });
            }
        }
        for (sched.txns) |u| try h.recordSigs(arena, batch, u);
        for (sched.randomness) |u| try h.recordSigs(arena, batch, u);

        // checkpoint queue
        var queue_pending: u64 = st.queue_pending_tx;
        var seq_no: u64 = st.queue_seq;
        var last_built = st.queue_last_built_ts;
        var qroots: std.ArrayList(state_mod.QueuedRoots) = .empty;
        // existing queued roots
        for (st.queue.items) |q| try qroots.append(arena, q);

        const assigned_map = result.assigned;
        var pending_out: std.ArrayList(state_mod.PendingCheckpoint) = .empty;
        const qctx = QueueCtx{ .h = h, .arena = arena, .batch = batch, .roots = &qroots, .pending_tx = &queue_pending, .seq = &seq_no, .last_built = &last_built, .max_tx = max_tx, .min_interval = p.min_checkpoint_interval_ms, .out = &pending_out };
        for (chunks.items) |*c| try qctx.pushChunk(c, info);
        try qctx.flush(info, info.timestamp, final_round);
        if (should_write_random_checkpoint) {
            for (rchunks.items) |*c| try qctx.pushChunk(c, info);
            if (final_round) try qctx.flush(info, info.timestamp, true);
        }
        if (final_round and pending_out.items.len != 0) {
            // mark the last flush as last_of_epoch: it is already in the batch ops, patch it
            var i = batch.queue_ops.items.len;
            while (i > 0) {
                i -= 1;
                switch (batch.queue_ops.items[i]) {
                    .flush => |*f| {
                        f.last_of_epoch = true;
                        break;
                    },
                    else => {},
                }
            }
            pending_out.items[pending_out.items.len - 1].last_of_epoch = true;
        }
        batch.queue_next_seq = seq_no;
        batch.randomness_round = randomness_round;
        try h.drainAcks(arena, batch);
        batch.queue_height = qh;
        batch.queue_drained = qroots.items.len == 0;
        _ = assigned_map;

        // durable
        state_mod.commit(st, h.d.log, batch) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            error.Io => error.Io,
            error.Corrupt => error.Corrupt,
        };
        h.last_handled.store(info.commit_ref.index, .release);
        h.stats.commits += 1;

        // 11. effects of the durable commit: executor, builder, adapter
        for (chunks.items) |c| try h.enqueueChunk(arena, c, result.assigned);
        for (rchunks.items) |c| try h.enqueueChunk(arena, c, result.assigned);
        if (h.d.pending_sink) |sink| for (pending_out.items) |pc| {
            const ipc = try toIfacePending(arena, &pc);
            sink.push(&ipc) catch {};
            h.stats.pending_checkpoints += 1;
        };
        if (h.d.adapter) |a| a.advanceTick();
    }

    fn recordSigs(h: *Handler, arena: Allocator, batch: *Batch, u: *const tx_mod.UserTx) Allocator.Error!void {
        _ = h;
        const sigs = u.signatures();
        const raw = try arena.alloc([]const u8, sigs.len);
        for (sigs, raw) |s, *o| o.* = s.@"0";
        var av: std.ArrayList(?u64) = .empty;
        // alias versions as claimed (AddressAliasesV2): one entry per required signer
        for (u.tx.claims) |c| switch (c) {
            .AddressAliasesV2 => |al| for (al) |e| try av.append(arena, if (e.@"1") |v| v.@"0" else null),
            else => {},
        };
        try batch.user_sigs.append(arena, .{ .digest = u.digest, .sigs = raw, .alias_versions = av.items });
    }

    fn epochVersionsGet(ctx: *const anyopaque, k: versions.ObjKey) ?u64 {
        const st: *const EpochState = @ptrCast(@alignCast(ctx));
        return st.nextVersion(k);
    }

    fn buildChunks(h: *Handler, arena: Allocator, list: []const Sched, max_tx: usize, qh: *u64, out: *std.ArrayList(Chunk)) Allocator.Error!void {
        var i: usize = 0;
        while (i < list.len) {
            const end = @min(i + max_tx, list.len);
            qh.* += 1;
            var c: Chunk = .{ .height = qh.* };
            try c.items.appendSlice(arena, list[i..end]);
            if (h.d.params.accumulators_enabled) {
                var acc_id: Id = @splat(0);
                acc_id[30] = 0x0a;
                acc_id[31] = 0xcc;
                const shared = try arena.alloc(tx_mod.SharedInput, 1);
                shared[0] = .{ .id = acc_id, .isv = h.d.params.implicit.accumulator_root.?, .mutability = .mutable };
                c.settlement = .{ .key = .{ .accumulator_settlement = .{ .epoch = h.d.params.epoch, .height = qh.* } }, .kind = .accumulator_settlement, .shared = shared };
            }
            try out.append(arena, c);
            i = end;
        }
    }

    fn addAssignable(h: *Handler, arena: Allocator, list: *std.ArrayList(versions.Assignable), order: *std.ArrayList(*const Sched), s: *const Sched) Allocator.Error!void {
        _ = h;
        var nsv: std.ArrayList(u64) = .empty;
        if (s.user) |u| {
            for (u.owned) |o| try nsv.append(arena, o.version);
            for (u.receiving) |o| try nsv.append(arena, o.version);
        }
        try list.append(arena, .{ .key = s.key, .shared = s.shared, .non_shared_versions = nsv.items });
        try order.append(arena, s);
    }

    fn enqueueChunk(h: *Handler, arena: Allocator, c: Chunk, assigned: []const versions.Assigned) Error!void {
        for (c.items.items) |s| try h.enqueueOne(arena, s, assigned);
        if (c.settlement) |s| try h.enqueueOne(arena, s, assigned);
    }

    const Payload = struct { td_bcs: ?[]const u8, digest: ?Id, owned: []const tx_mod.ObjRef };

    fn execPayload(arena: Allocator, s: Sched) Allocator.Error!Payload {
        var td_bcs: ?[]const u8 = null;
        var digest: ?Id = null;
        var owned: []const tx_mod.ObjRef = &.{};
        if (s.user) |u| {
            const all: types.TransactionData = .{ .V1 = u.data().* };
            td_bcs = try bcs.encodeAlloc(types.TransactionData, arena, &all);
            digest = u.digest;
            var ol: std.ArrayList(tx_mod.ObjRef) = .empty;
            try ol.appendSlice(arena, u.owned);
            try ol.appendSlice(arena, u.receiving);
            owned = ol.items;
        } else if (s.system) |sy| {
            td_bcs = sy.td_bcs;
            digest = sy.digest;
        }
        return .{ .td_bcs = td_bcs, .digest = digest, .owned = owned };
    }

    fn enqueueOne(h: *Handler, arena: Allocator, s: Sched, assigned: []const versions.Assigned) Error!void {
        var a: ?versions.Assigned = null;
        for (assigned) |x| if (x.key.eql(s.key)) {
            a = x;
            break;
        };
        const asg = a orelse return error.Corrupt;
        const pl = try execPayload(arena, s);
        h.d.exec.enqueue(.{ .key = s.key, .kind = s.kind, .td_bcs = pl.td_bcs, .digest = pl.digest, .shared = asg.shared, .system = asg.system, .owned = pl.owned }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Full => return error.Io,
        };
    }

    const QueueCtx = struct {
        h: *Handler,
        arena: Allocator,
        batch: *Batch,
        roots: *std.ArrayList(state_mod.QueuedRoots),
        pending_tx: *u64,
        seq: *u64,
        last_built: *u64,
        max_tx: usize,
        min_interval: u64,
        out: *std.ArrayList(state_mod.PendingCheckpoint),

        fn pushChunk(q: QueueCtx, c: *const Chunk, info: *const CommitInfo) Allocator.Error!void {
            const user_tx_count: u64 = c.items.items.len;
            var tx_roots: std.ArrayList(Key) = .empty;
            for (c.items.items) |s| try tx_roots.append(q.arena, s.key);
            const settle: ?Key = if (c.settlement) |s| s.key else null;
            if (q.pending_tx.* > 0 and q.pending_tx.* + user_tx_count > q.max_tx) try q.flushForced();
            const qr: state_mod.QueuedRoots = .{
                .height = c.height,
                .tx_roots = tx_roots.items,
                .settlement_root = settle,
                .timestamp = info.timestamp,
                .commit_ref = info.commit_ref,
                .rejected_digest = info.rejected_digest,
            };
            q.pending_tx.* += user_tx_count;
            try q.roots.append(q.arena, qr);
            try q.batch.queue_ops.append(q.arena, .{ .push = qr });
        }

        fn flushForced(q: QueueCtx) Allocator.Error!void {
            if (q.roots.items.len == 0) return;
            const roots = try q.arena.dupe(state_mod.QueuedRoots, q.roots.items);
            const last = roots[roots.len - 1];
            const pc: state_mod.PendingCheckpoint = .{
                .roots = roots,
                .timestamp_ms = last.timestamp,
                .last_of_epoch = false,
                .checkpoint_height = last.height,
                .commit_ref = last.commit_ref,
                .rejected_digest = last.rejected_digest,
                .checkpoint_seq = q.seq.*,
            };
            q.last_built.* = last.timestamp;
            q.pending_tx.* = 0;
            q.seq.* += 1;
            q.roots.clearRetainingCapacity();
            try q.batch.queue_ops.append(q.arena, .{ .flush = pc });
            try q.out.append(q.arena, pc);
        }

        fn flush(q: QueueCtx, info: *const CommitInfo, now: u64, force: bool) Allocator.Error!void {
            _ = info;
            if (!force and now < q.last_built.* + q.min_interval) return;
            try q.flushForced();
        }
    };

    fn toIfacePending(arena: Allocator, pc: *const state_mod.PendingCheckpoint) Allocator.Error!iface.PendingCheckpoint {
        const roots = try arena.alloc(iface.CheckpointRoots, pc.roots.len);
        for (pc.roots, roots) |q, *o| {
            const keys = try arena.alloc(iface.TransactionKey, q.tx_roots.len);
            for (q.tx_roots, keys) |k, *ko| ko.* = toIfaceKey(k);
            o.* = .{ .tx_roots = keys, .settlement_root = if (q.settlement_root) |s| toIfaceKey(s) else null, .height = q.height };
        }
        return .{ .roots = roots, .details = .{
            .timestamp_ms = pc.timestamp_ms,
            .last_of_epoch = pc.last_of_epoch,
            .checkpoint_height = pc.checkpoint_height,
            .consensus_commit_ref = .{ .index = pc.commit_ref.index, .digest = pc.commit_ref.digest },
            .rejected_transactions_digest = .{ .@"0" = pc.rejected_digest },
            .checkpoint_seq = pc.checkpoint_seq,
        } };
    }

    fn toIfaceKey(k: Key) iface.TransactionKey {
        return switch (k) {
            .digest => |d| .{ .digest = tdigest(d) },
            .randomness_round => |r| .{ .randomness_round = .{ .epoch = r.epoch, .round = r.round } },
            .accumulator_settlement => |r| .{ .accumulator_settlement = .{ .epoch = r.epoch, .height = r.height } },
            .consensus_commit_prologue => |r| .{ .consensus_commit_prologue = .{ .epoch = r.epoch, .round = r.round, .sub_dag_index = r.sub_dag_index } },
        };
    }
};

// ---------------------------------------------------------------------------- free helpers

pub fn oid(id: Id) types.ObjectID {
    return .{ .@"0" = .{ .@"0" = id } };
}
pub fn seqn(v: u64) types.SequenceNumber {
    return .{ .@"0" = v };
}
pub fn tdigest(d: Id) types.TransactionDigest {
    return .{ .@"0" = .{ .@"0" = d } };
}

/// `IndirectStateObserver`: hashes the BCS of every cost estimate observed, folded into the
/// additional state digest.
pub const IndirectObserver = struct {
    h: hash.Blake2b256,

    pub fn init() IndirectObserver {
        return .{ .h = hash.Blake2b256.init() };
    }

    /// `observe_indirect_state(&Some(estimate_us))`: BCS Option<u64> = 1 ++ u64 LE.
    pub fn observe(o: *IndirectObserver, estimate_us: u64) void {
        var b: [9]u8 = undefined;
        b[0] = 1;
        std.mem.writeInt(u64, b[1..9], estimate_us, .little);
        o.h.update(&b);
    }

    /// `fold_with(d1)`: blake2b(BCS(d1) ++ BCS(d2)), each digest as 0x20 ++ 32 bytes.
    pub fn foldWith(o: *IndirectObserver, d1: [32]u8) [32]u8 {
        var d2: [32]u8 = undefined;
        o.h.final(&d2);
        var buf: [66]u8 = undefined;
        buf[0] = 32;
        buf[1..33].* = d1;
        buf[33] = 32;
        buf[34..66].* = d2;
        return hash.blake2b256(&.{&buf});
    }
};

/// Canonical observation key bytes (see congestion.keyOfCommand): tag, then for a Move entry
/// point package, module, function and the BCS type arguments.
pub fn obsKeyBytes(arena: Allocator, k: *const types.ExecutionTimeObservationKey) Allocator.Error![]const u8 {
    var b: std.ArrayList(u8) = .empty;
    switch (k.*) {
        .MoveEntryPoint => |m| {
            try b.append(arena, 0);
            try b.appendSlice(arena, &m.package.@"0".@"0");
            var l: [4]u8 = undefined;
            std.mem.writeInt(u32, &l, @intCast(m.module.@"0".len), .little);
            try b.appendSlice(arena, &l);
            try b.appendSlice(arena, m.module.@"0");
            std.mem.writeInt(u32, &l, @intCast(m.function.@"0".len), .little);
            try b.appendSlice(arena, &l);
            try b.appendSlice(arena, m.function.@"0");
            const ta = try bcs.encodeAlloc([]const types.TypeInput, arena, &m.type_arguments);
            try b.appendSlice(arena, ta);
        },
        .TransferObjects => try b.append(arena, 1),
        .SplitCoins => try b.append(arena, 2),
        .MergeCoins => try b.append(arena, 3),
        .Publish => try b.append(arena, 4),
        .MakeMoveVec => try b.append(arena, 5),
        .Upgrade => try b.append(arena, 6),
    }
    return b.items;
}

fn systemTransactionData(arena: Allocator, kind: types.TransactionKind) Allocator.Error!Handler.SystemTx {
    const zero: Id = @splat(0);
    const td: types.TransactionDataV1 = .{
        .kind = kind,
        .sender = .{ .@"0" = zero },
        .gas_data = .{
            .payment = &.{.{ oid(zero), seqn(0), .{ .@"0" = .{ .@"0" = zero } } }},
            .owner = .{ .@"0" = zero },
            .price = 1,
            .budget = 0,
        },
        .expiration = .None,
    };
    const all: types.TransactionData = .{ .V1 = td };
    const enc = try bcs.encodeAlloc(types.TransactionData, arena, &all);
    return .{ .td_bcs = enc, .digest = hash.blake2b256(&.{ "TransactionData::", enc }) };
}

/// `VerifiedTransaction::new_consensus_commit_prologue_v4` (sub_dag_index is None).
fn buildPrologue(arena: Allocator, epoch: u64, info: *const CommitInfo, cancelled: anytype, additional: [32]u8) Allocator.Error!Handler.SystemTx {
    return systemTransactionData(arena, .{ .ConsensusCommitPrologueV4 = .{
        .epoch = epoch,
        .round = info.round,
        .sub_dag_index = null,
        .commit_timestamp_ms = info.timestamp,
        .consensus_commit_digest = .{ .@"0" = .{ .@"0" = info.commit_ref.digest } },
        .consensus_determined_version_assignments = .{ .CancelledTransactionsV2 = cancelled },
        .additional_state_digest = .{ .@"0" = .{ .@"0" = additional } },
    } });
}

/// `authenticator_state_update_transaction`: new active jwks sorted.
fn buildAuthenticatorUpdate(arena: Allocator, epoch: u64, round: u64, jwks: []const types.ActiveJwk, isv: u64) Allocator.Error!Handler.SystemTx {
    const sorted = try arena.dupe(types.ActiveJwk, jwks);
    // `new_active_jwks.sort()`: ActiveJwk's Ord is NOT derived; it is `jwk_ord` (sui-types
    // authenticator_state.rs, matching jwk_lt in authenticator_state.move): field by field, each
    // string compared by length first, then bytes; epoch ignored. Stable like Vec::sort.
    std.mem.sort(types.ActiveJwk, sorted, {}, struct {
        fn less(_: void, a: types.ActiveJwk, b: types.ActiveJwk) bool {
            return jwk_aggregator.activeJwkOrder(a, b) == .lt;
        }
    }.less);
    return systemTransactionData(arena, .{ .AuthenticatorStateUpdate = .{
        .epoch = epoch,
        .round = round,
        .new_active_jwks = sorted,
        .authenticator_obj_initial_shared_version = seqn(isv),
    } });
}

test "authenticator state update sorts new jwks in ActiveJwk order (length first) like Rust" {
    // A lexicographic sort puts "https://b.example" (17 bytes) after "https://aa.example" (18);
    // jwk_ord compares lengths first, so it goes first. The expected bytes are those of
    // jwk/state_update.authenticatorStateUpdate, which jwk-vectors pins to Rust's
    // new_authenticator_state_update (asu-1).
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const mk = struct {
        fn f(iss: []const u8, kid: []const u8, n: []const u8) types.ActiveJwk {
            return .{ .jwk_id = .{ .iss = .{ .@"0" = iss }, .kid = .{ .@"0" = kid } }, .jwk = .{ .kty = .{ .@"0" = "RSA" }, .e = .{ .@"0" = "AQAB" }, .n = .{ .@"0" = n }, .alg = .{ .@"0" = "RS256" } }, .epoch = 5 };
        }
    }.f;
    const jwks = [_]types.ActiveJwk{ mk("https://aa.example", "k", "n"), mk("https://b.example", "kid2", "n"), mk("https://b.example", "k9", "zz"), mk("https://b.example", "k9", "z") };
    const got = try buildAuthenticatorUpdate(arena, 5, 77, &jwks, 11);
    var want = try @import("../jwk/state_update.zig").authenticatorStateUpdate(std.testing.allocator, 5, 77, &jwks, 11);
    defer want.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, want.data, got.td_bcs);
    try std.testing.expectEqualSlices(u8, &want.digest, &got.digest);
    const td = try bcs.decode(types.TransactionData, arena, got.td_bcs);
    const order = td.V1.kind.AuthenticatorStateUpdate.new_active_jwks;
    try std.testing.expectEqualStrings("https://b.example", order[0].jwk_id.iss.@"0");
    try std.testing.expectEqualStrings("k9", order[0].jwk_id.kid.@"0");
    try std.testing.expectEqualStrings("z", order[0].jwk.n.@"0");
    try std.testing.expectEqualStrings("zz", order[1].jwk.n.@"0");
    try std.testing.expectEqualStrings("kid2", order[2].jwk_id.kid.@"0");
    try std.testing.expectEqualStrings("https://aa.example", order[3].jwk_id.iss.@"0");
}
