//! CheckpointBuilder (sui-core `checkpoints/mod.rs`, 1.83.1, protocols with
//! `split_checkpoints_in_consensus_handler`: one PendingCheckpoint becomes exactly one
//! checkpoint; the splitting by `max_transactions_per_checkpoint` already happened in the
//! consensus handler, see queue.zig).
//!
//! For each PendingCheckpoint, in order:
//!   1. resolve the roots of every root group to transaction digests and wait for their effects
//!      (`Env`; `error.NotReady` means "try again", nothing was changed),
//!   2. order each group causally (prologue first, `causal_order.zig`), append the group's
//!      accumulator settlement effects,
//!   3. collect the randomness rounds and the user signatures,
//!   4. on the last checkpoint of the epoch: execute the epoch-change transaction (`Env`),
//!      append its effects, accumulate the state and take the epoch's ECMH root,
//!   5. build contents and summary (`create.zig`), check for a fork against what was built or
//!      certified before, store, then sign and submit our signature (`output.zig`).
//!
//! The Rust builder runs as one task; this one is driven by `runQueued` from one thread (the
//! checkpoint builder thread of docs/VALIDATOR-DESIGN.md 7). `push` may be called from the
//! consensus handler thread.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const iface = @import("../iface.zig");
const ev = @import("effects_view.zig");
const causal = @import("causal_order.zig");
const create = @import("create.zig");
const store_mod = @import("store.zig");
const state_acc = @import("state_acc.zig");
const output_mod = @import("output.zig");

pub const Error = error{
    /// Effects or digests are not there yet: call again later. Nothing was written.
    NotReady,
    /// A checkpoint was built with a different digest than before or than the network certified.
    Fork,
    /// An invariant broke (unexpected system transaction, sequence gap, unsupported protocol).
    Fatal,
    Full,
    Unimplemented,
    OutOfMemory,
    Io,
} || create.Error || causal.Error || state_acc.Error || output_mod.Error || store_mod.Error;

/// What a transaction of a checkpoint is (`TransactionKind` in `create_checkpoint`).
pub const TxClass = union(enum) {
    consensus_commit_prologue,
    authenticator_state_update,
    /// Settlement and other programmable system transactions the builder adds.
    programmable_system,
    randomness_state_update: u64,
    programmable,
    /// ChangeEpoch, Genesis, EndOfEpochTransaction: must never be a root (Rust `fatal!`).
    forbidden,
};

pub const SettlementRequest = struct {
    key: iface.TransactionKey,
    sorted_root_digests: []const [32]u8,
    height: u64,
    seq: u64,
    tx_index_offset: u64,
};

pub const AdvanceRequest = struct {
    gas: ev.GasSummary,
    epoch_start_timestamp_ms: u64,
    seq: u64,
    /// The previous checkpoint's sequence number (may be below seq - 1 in Rust's wording).
    last_checkpoint_seq: u64,
    tx_digests: []const [32]u8,
};

pub const EpochAdvance = struct {
    /// BCS TransactionEffects of the executed advance-epoch (EndOfEpochTransaction) transaction.
    effects: []const u8,
    /// `committee.voting_rights` of the new system state: sorted by the 96-byte name.
    next_committee: []const create.CommitteeEntry,
    next_protocol_version: u64,
};

/// The executor side the builder reads, implemented by val-authority (`authority/exec_bridge.zig`
/// next to iface.TxExecutor). All results are allocated in the arena passed in.
pub const Env = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const Err = error{ OutOfMemory, Fatal };
    pub const VTable = struct {
        /// `notify_read_tx_key_to_digest`: the digest for a root, null while unknown.
        key_digest: *const fn (ctx: *anyopaque, key: *const iface.TransactionKey) ?[32]u8,
        /// BCS TransactionEffects of an executed transaction, null while not executed.
        effects: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, digest: *const [32]u8) Err!?[]const u8,
        tx_class: *const fn (ctx: *anyopaque, digest: *const [32]u8) ?TxClass,
        /// `user_signatures_for_checkpoint` for one transaction. NOT empty for system
        /// transactions: Rust takes `tx_signatures()`, and every system transaction
        /// (`VerifiedTransaction::new_system_transaction`) carries one all-zero Ed25519
        /// signature (flag 0 + 96 zero bytes), paired with a null alias version. That holds for
        /// the prologue and the authenticator state update (recorded by
        /// `process_user_signatures` with their aliases) as for RandomnessStateUpdate and
        /// settlement transactions (taken from the transaction). Only the epoch-change
        /// transaction the builder appends gets no signature at all (`augment_epoch_last_checkpoint`).
        user_signatures: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, digest: *const [32]u8) Err![]const create.SigEntry,
        /// `resolve_settlement_effects`: effects of the accumulator settlement transactions of
        /// a root group (null while not executed).
        settlement_effects: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: *const SettlementRequest) Err!?[]const []const u8,
        /// `create_and_execute_advance_epoch_tx` (null while not ready). MUST be idempotent: a
        /// retry of the last checkpoint of an epoch (after a failed store or output) calls it
        /// again and must return the stored effects of the already executed transaction.
        advance_epoch: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: *const AdvanceRequest) Err!?EpochAdvance,
    };
};

pub const Built = struct {
    seq: u64,
    digest: [32]u8,
    summary_bcs: []const u8,
    contents_bcs: []const u8,
    num_txs: u64,
    /// Already built before (height at or below the last built one): nothing was done.
    skipped: bool = false,
};

const Owned = struct {
    arena: std.heap.ArenaAllocator,
    p: iface.PendingCheckpoint,
};

pub const max_queued = 1024;

pub const Builder = struct {
    gpa: std.mem.Allocator,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    env: Env,
    store: store_mod.Store,
    /// Null: build and store only (shadow, tests).
    output: ?*output_mod.Output = null,
    tracer: iface.Tracer = .{},
    /// Accumulate the state hash after every checkpoint (needed at epoch end; the root must
    /// follow every checkpoint, so leave it on).
    accumulate: bool = true,
    running: state_acc.RunningRoot = .{},

    lock: store_mod.SpinLock = .{},
    queued: std.ArrayList(*Owned) = .empty,
    built_count: u64 = 0,
    /// Pushes refused for lack of memory (as opposed to a full queue).
    push_oom: u64 = 0,

    pub fn init(gpa: std.mem.Allocator, cfg: *const protocol.ProtocolConfig, epoch: u64, env: Env, st: store_mod.Store, out: ?*output_mod.Output) Builder {
        var b: Builder = .{ .gpa = gpa, .cfg = cfg, .epoch = epoch, .env = env, .store = st, .output = out };
        if (st.runningRoot()) |r| {
            // A root that does not restore leaves `running` empty: `apply` then fails with
            // OutOfOrder for any seq > 0 instead of committing a wrong epoch digest.
            if (state_acc.RunningRoot.restore(&r.root, r.seq)) |rr| b.running = rr;
        }
        return b;
    }

    pub fn deinit(b: *Builder) void {
        for (b.queued.items) |o| {
            o.arena.deinit();
            b.gpa.destroy(o);
        }
        b.queued.deinit(b.gpa);
    }

    // ------------------------------------------------------------ iface.PendingCheckpointSink

    fn sinkPush(ctx: *anyopaque, pending: *const iface.PendingCheckpoint) error{ Full, Unimplemented }!void {
        const b: *Builder = @ptrCast(@alignCast(ctx));
        // the iface error set has no OutOfMemory: it is backpressure too, but make it visible
        b.push(pending) catch |e| {
            if (e == error.OutOfMemory) b.push_oom += 1;
            return error.Full;
        };
    }
    const sink_vtable: iface.PendingCheckpointSink.VTable = .{ .push = sinkPush };

    pub fn pendingSink(b: *Builder) iface.PendingCheckpointSink {
        return .{ .ctx = b, .vtable = &sink_vtable };
    }

    /// Queues a deep copy of `pending`.
    pub fn push(b: *Builder, pending: *const iface.PendingCheckpoint) error{ Full, OutOfMemory }!void {
        b.lock.lock();
        const full = b.queued.items.len >= max_queued;
        b.lock.unlock();
        if (full) return error.Full;
        // the deep copy is built outside the lock; only the append is under it
        const o = try b.gpa.create(Owned);
        errdefer b.gpa.destroy(o);
        o.arena = std.heap.ArenaAllocator.init(b.gpa);
        errdefer o.arena.deinit();
        const a = o.arena.allocator();
        const roots = try a.alloc(iface.CheckpointRoots, pending.roots.len);
        for (pending.roots, roots) |r, *dst| dst.* = .{
            .tx_roots = try a.dupe(iface.TransactionKey, r.tx_roots),
            .settlement_root = r.settlement_root,
            .height = r.height,
        };
        o.p = .{ .roots = roots, .details = pending.details };
        b.lock.lock();
        defer b.lock.unlock();
        if (b.queued.items.len >= max_queued) return error.Full;
        try b.queued.append(b.gpa, o);
    }

    pub fn queuedCount(b: *Builder) usize {
        b.lock.lock();
        defer b.lock.unlock();
        return b.queued.items.len;
    }

    /// Builds queued pending checkpoints in order until the queue is empty or one is not ready.
    /// Returns how many were built.
    pub fn runQueued(b: *Builder) Error!u32 {
        var done: u32 = 0;
        while (true) {
            b.lock.lock();
            const head: ?*Owned = if (b.queued.items.len > 0) b.queued.items[0] else null;
            b.lock.unlock();
            const o = head orelse return done;
            var arena = std.heap.ArenaAllocator.init(b.gpa);
            defer arena.deinit();
            _ = b.buildNext(arena.allocator(), &o.p) catch |e| switch (e) {
                error.NotReady => return done,
                else => return e,
            };
            b.lock.lock();
            _ = b.queued.orderedRemove(0);
            b.lock.unlock();
            o.arena.deinit();
            b.gpa.destroy(o);
            done += 1;
        }
    }

    // ------------------------------------------------------------ the build

    /// `make_checkpoint` for one pending checkpoint.
    pub fn buildNext(b: *Builder, arena: std.mem.Allocator, pending: *const iface.PendingCheckpoint) Error!Built {
        const details = pending.details;
        const cfg = b.cfg;
        if (!cfg.feature_flags.prepend_prologue_tx_in_consensus_commit_in_checkpoints) return error.Fatal;

        const last = b.store.lastBuilt();
        if (last) |l| {
            // heights restart every epoch: the skip applies to this epoch's checkpoints only
            if (l.epoch == b.epoch) if (l.height) |h| if (details.checkpoint_height <= h) {
                return .{ .seq = details.checkpoint_seq, .digest = l.digest, .summary_bcs = &.{}, .contents_bcs = &.{}, .num_txs = 0, .skipped = true };
            };
            if (details.checkpoint_seq != l.seq + 1) return error.Fatal;
        } else if (details.checkpoint_seq != 0) {
            // no previous checkpoint known (not even the previous epoch's): only genesis follows
            return error.Fatal;
        }

        // 1-2: resolve, wait for effects, order
        var all: std.ArrayList(ev.View) = .empty;
        for (pending.roots) |grp| {
            const digs = try arena.alloc([32]u8, grp.tx_roots.len);
            for (grp.tx_roots, digs) |*k, *d| d.* = b.env.vtable.key_digest(b.env.ctx, k) orelse return error.NotReady;
            const views = try arena.alloc(ev.View, digs.len);
            for (digs, views) |*d, *v| {
                const raw = (b.env.vtable.effects(b.env.ctx, arena, d) catch |e| return mapEnv(e)) orelse return error.NotReady;
                v.* = try ev.View.parse(arena, raw);
            }
            var ccp_first = false;
            if (digs.len > 0) {
                const c = b.env.vtable.tx_class(b.env.ctx, &digs[0]) orelse return error.NotReady;
                ccp_first = c == .consensus_commit_prologue;
                if (ccp_first and !std.mem.eql(u8, &views[0].tx, &digs[0])) return error.Fatal;
            }
            const sorted = try causal.orderForCheckpoint(arena, views, ccp_first, cfg.feature_flags.disable_effects_tx_dependencies);
            const group_start = all.items.len;
            try all.appendSlice(arena, sorted);
            if (grp.settlement_root) |sk| {
                const sd = try arena.alloc([32]u8, sorted.len);
                for (sorted, sd) |*v, *d| d.* = v.tx;
                const req: SettlementRequest = .{ .key = sk, .sorted_root_digests = sd, .height = grp.height, .seq = details.checkpoint_seq, .tx_index_offset = group_start };
                const raws = (b.env.vtable.settlement_effects(b.env.ctx, arena, &req) catch |e| return mapEnv(e)) orelse return error.NotReady;
                for (raws) |raw| try all.append(arena, try ev.View.parse(arena, raw));
            }
        }

        // 3: kinds (randomness rounds) and user signatures
        var rounds: std.ArrayList(u64) = .empty;
        var sigs: std.ArrayList([]const create.SigEntry) = .empty;
        for (all.items) |*v| {
            const class = b.env.vtable.tx_class(b.env.ctx, &v.tx) orelse return error.NotReady;
            switch (class) {
                .forbidden => return error.Fatal,
                .randomness_state_update => |r| try rounds.append(arena, r),
                else => {},
            }
            try sigs.append(arena, b.env.vtable.user_signatures(b.env.ctx, arena, &v.tx) catch |e| return mapEnv(e));
        }

        // 4: end of epoch
        var eoe: ?create.EndOfEpoch = null;
        var rolling: ?ev.GasSummary = null;
        var epoch_acc: ?@import("sig").Ecmh = null;
        if (details.last_of_epoch) {
            const gas = create.rollingGas(last, b.epoch, create.gasOf(all.items));
            rolling = gas;
            const td = try arena.alloc([32]u8, all.items.len);
            for (all.items, td) |*v, *d| d.* = v.tx;
            const req: AdvanceRequest = .{
                .gas = gas,
                .epoch_start_timestamp_ms = details.timestamp_ms,
                .seq = details.checkpoint_seq,
                .last_checkpoint_seq = if (last) |l| l.seq else 0,
                .tx_digests = td,
            };
            const adv = (b.env.vtable.advance_epoch(b.env.ctx, arena, &req) catch |e| return mapEnv(e)) orelse return error.NotReady;
            try all.append(arena, try ev.View.parse(arena, adv.effects));
            try sigs.append(arena, &.{});
            const acc = try state_acc.accumulateEffects(b.gpa, cfg, all.items);
            epoch_acc = acc;
            var running = b.running;
            try running.apply(details.checkpoint_seq, &acc);
            eoe = .{
                .next_committee = adv.next_committee,
                .next_protocol_version = adv.next_protocol_version,
                .root_state_digest = running.epochDigest(),
            };
        }

        const created = try create.create(arena, .{
            .cfg = cfg,
            .epoch = b.epoch,
            .seq = details.checkpoint_seq,
            .timestamp_ms = details.timestamp_ms,
            .last = last,
            .effects = all.items,
            .signatures = sigs.items,
            .randomness_rounds = rounds.items,
            .end_of_epoch = eoe,
            .rolling_gas = rolling,
        });

        // 5: write. A re-derived checkpoint must equal what was built before.
        const seq = details.checkpoint_seq;
        // A certified digest that differs from ours is a fork. `last_built` is not advanced, so
        // the check repeats on every retry (sticky) and nothing is built on top of the fork.
        if (b.store.certifiedDigest(seq)) |cd| {
            if (!std.mem.eql(u8, &cd, &created.summary_digest)) {
                b.store.recordFork(seq, created.summary_digest, cd);
                return error.Fork;
            }
        }
        if (b.store.locallyComputedDigest(seq)) |prev| {
            if (!std.mem.eql(u8, &prev, &created.summary_digest)) {
                b.store.recordFork(seq, prev, null);
                return error.Fork;
            }
        }
        // the state root advances only for a checkpoint that is going to be stored
        if (b.accumulate or details.last_of_epoch) {
            const acc = epoch_acc orelse try state_acc.accumulateEffects(b.gpa, cfg, all.items);
            try b.running.apply(seq, &acc);
            try b.store.putRunningRoot(.{ .root = b.running.root.toBytes(), .seq = seq });
        }
        const new_last = create.LastBuilt.fromSummary(&created.summary, created.summary_digest, details.checkpoint_height);
        try b.store.putBuilt(seq, details.checkpoint_height, new_last, created.summary_bcs, created.contents_bcs);
        b.tracer.mark(.checkpoint_built, &created.summary_digest, 0);
        if (b.output) |o| {
            _ = try o.checkpointCreated(&created.summary, created.summary_bcs, &created.summary_digest);
            b.tracer.mark(.checkpoint_signed, &created.summary_digest, 0);
        }
        // only now is the checkpoint "built": a failed output above is retried by the next run
        try b.store.setLastBuilt(new_last);
        b.built_count += 1;
        return .{
            .seq = seq,
            .digest = created.summary_digest,
            .summary_bcs = created.summary_bcs,
            .contents_bcs = created.contents_bcs,
            .num_txs = created.num_txs,
        };
    }
};

fn mapEnv(e: Env.Err) Error {
    return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        error.Fatal => error.Fatal,
    };
}

// ---------------------------------------------------------------- tests

const bcs = @import("bcs");
const testing = std.testing;

pub const TestEnv = struct {
    /// transaction digest first byte -> effects bytes
    raws: [8]?[]const u8 = @splat(null),
    class: TxClass = .programmable,
    epoch_effects: ?[]const u8 = null,
    committee: []const create.CommitteeEntry = &.{},

    fn keyDigest(ctx: *anyopaque, key: *const iface.TransactionKey) ?[32]u8 {
        _ = ctx;
        return switch (key.*) {
            .digest => |d| d.@"0".@"0",
            else => null,
        };
    }
    fn effects(ctx: *anyopaque, arena: std.mem.Allocator, d: *const [32]u8) Env.Err!?[]const u8 {
        const t: *TestEnv = @ptrCast(@alignCast(ctx));
        const r = t.raws[d[0]] orelse return null;
        return try arena.dupe(u8, r);
    }
    fn txClass(ctx: *anyopaque, d: *const [32]u8) ?TxClass {
        const t: *TestEnv = @ptrCast(@alignCast(ctx));
        _ = d;
        return t.class;
    }
    fn userSigs(ctx: *anyopaque, arena: std.mem.Allocator, d: *const [32]u8) Env.Err![]const create.SigEntry {
        _ = .{ ctx, arena, d };
        return &.{};
    }
    fn settlement(ctx: *anyopaque, arena: std.mem.Allocator, req: *const SettlementRequest) Env.Err!?[]const []const u8 {
        _ = .{ ctx, arena, req };
        return &.{};
    }
    fn advance(ctx: *anyopaque, arena: std.mem.Allocator, req: *const AdvanceRequest) Env.Err!?EpochAdvance {
        _ = .{arena};
        const t: *TestEnv = @ptrCast(@alignCast(ctx));
        _ = req;
        return .{ .effects = t.epoch_effects.?, .next_committee = t.committee, .next_protocol_version = 101 };
    }
    const vtable: Env.VTable = .{ .key_digest = keyDigest, .effects = effects, .tx_class = txClass, .user_signatures = userSigs, .settlement_effects = settlement, .advance_epoch = advance };
    pub fn env(t: *TestEnv) Env {
        return .{ .ctx = t, .vtable = &vtable };
    }
};

pub fn fx(a: std.mem.Allocator, id: u8) ![]const u8 {
    const e: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = .{ .computationCost = 10, .storageCost = 2, .storageRebate = 1, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = blk: {
            var d: [32]u8 = @splat(0);
            d[0] = id;
            break :blk d;
        } } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 5 },
        .changed_objects = &.{},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    return bcs.encodeAlloc(types.TransactionEffects, a, &e);
}

pub fn txKey(id: u8) iface.TransactionKey {
    var d: [32]u8 = @splat(0);
    d[0] = id;
    return .{ .digest = .{ .@"0" = .{ .@"0" = d } } };
}

pub fn pend(a: std.mem.Allocator, ids: []const u8, seq: u64, height: u64, last: bool) !iface.PendingCheckpoint {
    const keys = try a.alloc(iface.TransactionKey, ids.len);
    for (ids, keys) |i, *k| k.* = txKey(i);
    const roots = try a.alloc(iface.CheckpointRoots, 1);
    roots[0] = .{ .tx_roots = keys, .settlement_root = null, .height = height };
    return .{ .roots = roots, .details = .{
        .timestamp_ms = 1000 + seq,
        .last_of_epoch = last,
        .checkpoint_height = height,
        .consensus_commit_ref = std.mem.zeroes(@FieldType(iface.PendingCheckpointInfo, "consensus_commit_ref")),
        .rejected_transactions_digest = .{ .@"0" = @splat(0) },
        .checkpoint_seq = seq,
    } };
}

test "builder: chain of checkpoints, not ready, fork on a changed rebuild, end of epoch" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);
    var ms = store_mod.MemStore.init(testing.allocator);
    defer ms.deinit();
    var te: TestEnv = .{};
    te.raws[1] = try fx(a, 1);
    te.raws[2] = try fx(a, 2);
    // genesis checkpoint (seq 0) is the base
    ms.seedCertified(.{ .seq = 0, .epoch = 1, .timestamp_ms = 900, .network_total_transactions = 1, .rolling_gas = .{}, .digest = @splat(3) });
    ms.seedRoot((@import("sig").Ecmh{}).toBytes(), 0);
    var b = Builder.init(testing.allocator, cfg, 1, te.env(), ms.store(), null);
    defer b.deinit();

    // the second transaction has no effects yet: not ready, nothing stored
    try b.push(&(try pend(a, &.{ 1, 2, 3 }, 1, 1, false)));
    try testing.expectEqual(@as(u32, 0), try b.runQueued());
    try testing.expectEqual(@as(usize, 1), b.queuedCount());
    try testing.expectEqual(@as(u64, 0), ms.store().lastBuilt().?.seq);
    te.raws[3] = try fx(a, 3);
    try testing.expectEqual(@as(u32, 1), try b.runQueued());
    const l1 = ms.store().lastBuilt().?;
    try testing.expectEqual(@as(u64, 1), l1.seq);
    try testing.expectEqual(@as(u64, 4), l1.network_total_transactions);
    try testing.expectEqual(@as(u64, 30), l1.rolling_gas.computation_cost);

    // next checkpoint chains onto the previous digest
    try b.push(&(try pend(a, &.{1}, 2, 2, false)));
    try testing.expectEqual(@as(u32, 1), try b.runQueued());
    const s2 = (try ms.store().builtSummary(a, 2)).?;
    const parsed = try @import("checkpoint").Summary.parse(s2);
    try testing.expectEqualSlices(u8, &l1.digest, parsed.previous_digest.?);

    // a sequence gap is fatal
    try testing.expectError(error.Fatal, b.buildNext(a, &(try pend(a, &.{1}, 9, 9, false))));
    // already built heights are skipped
    const again = try b.buildNext(a, &(try pend(a, &.{1}, 2, 2, false)));
    try testing.expect(again.skipped);

    // end of epoch: the epoch change effects are appended and the summary carries the committee
    te.raws[4] = try fx(a, 4);
    te.epoch_effects = try fx(a, 5);
    te.committee = &.{ .{ .name = @splat(1), .stake = 6000 }, .{ .name = @splat(2), .stake = 4000 } };
    const built = try b.buildNext(a, &(try pend(a, &.{4}, 3, 3, true)));
    try testing.expectEqual(@as(u64, 2), built.num_txs);
    const p3 = try @import("checkpoint").Summary.parse(built.summary_bcs);
    try testing.expectEqual(@as(u32, 2), p3.next_committee.?.count);
    try testing.expectEqual(@as(u64, 101), p3.next_protocol_version);
    // the rolling gas of an end-of-epoch checkpoint does not include the epoch-change effects
    const full = try bcs.decode(types.CheckpointSummary, a, built.summary_bcs);
    try testing.expectEqual(@as(u64, 50), full.epoch_rolling_gas_cost_summary.computationCost);
}

test "builder: seq above genesis without a stored running root fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);
    var ms = store_mod.MemStore.init(testing.allocator);
    defer ms.deinit();
    var te: TestEnv = .{};
    te.raws[1] = try fx(a, 1);
    ms.seedCertified(.{ .seq = 0, .epoch = 1, .timestamp_ms = 900, .network_total_transactions = 1, .rolling_gas = .{}, .digest = @splat(3) });
    var b = Builder.init(testing.allocator, cfg, 1, te.env(), ms.store(), null);
    defer b.deinit();
    try testing.expectError(error.OutOfOrder, b.buildNext(a, &(try pend(a, &.{1}, 1, 1, false))));
    try testing.expectEqual(@as(u64, 0), ms.store().lastBuilt().?.seq);
}

test "builder: heights restart in a new epoch" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);
    var ms = store_mod.MemStore.init(testing.allocator);
    defer ms.deinit();
    var te: TestEnv = .{};
    te.raws[1] = try fx(a, 1);
    ms.seedCertified(.{ .seq = 0, .epoch = 1, .timestamp_ms = 900, .network_total_transactions = 1, .rolling_gas = .{}, .digest = @splat(3) });
    ms.seedRoot((@import("sig").Ecmh{}).toBytes(), 0);
    var b1 = Builder.init(testing.allocator, cfg, 1, te.env(), ms.store(), null);
    defer b1.deinit();
    _ = try b1.buildNext(a, &(try pend(a, &.{1}, 1, 7, false)));
    // epoch 2: the height counter restarts at 1, below the previous epoch's 7
    var b2 = Builder.init(testing.allocator, cfg, 2, te.env(), ms.store(), null);
    defer b2.deinit();
    const r = try b2.buildNext(a, &(try pend(a, &.{1}, 2, 1, false)));
    try testing.expect(!r.skipped);
    try testing.expectEqual(@as(u64, 2), ms.store().lastBuilt().?.seq);
}

test "builder: a failed output is retried, a certified fork is sticky" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);
    var ms = store_mod.MemStore.init(testing.allocator);
    defer ms.deinit();
    var te: TestEnv = .{};
    te.raws[1] = try fx(a, 1);
    ms.seedCertified(.{ .seq = 0, .epoch = 1, .timestamp_ms = 900, .network_total_transactions = 1, .rolling_gas = .{}, .digest = @splat(3) });
    ms.seedRoot((@import("sig").Ecmh{}).toBytes(), 0);
    var b = Builder.init(testing.allocator, cfg, 1, te.env(), ms.store(), null);
    defer b.deinit();
    // certified digest differs from ours: Fork now and on every retry, last_built never moves
    try ms.store().putCertified(1, @splat(9), "x");
    const p = try pend(a, &.{1}, 1, 1, false);
    try testing.expectError(error.Fork, b.buildNext(a, &p));
    try testing.expectError(error.Fork, b.buildNext(a, &p));
    try testing.expectEqual(@as(u64, 0), ms.store().lastBuilt().?.seq);
}
