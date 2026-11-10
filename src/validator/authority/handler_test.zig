//! End-to-end unit tests of the consensus handler on an in-memory rig: a four validator
//! committee, MemLog, LocalEpochControl and the MemRunner executor. They check the protocol
//! facts the handler must get right: first-in-order wins an owned object, conflicting
//! transactions are dropped (and persisted so a replay cannot flip the winner), shared versions
//! are assigned in order with the lamport rule, the prologue goes first, deferral by congestion,
//! pending checkpoints, and crash recovery from the log.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const consensus = @import("consensus");
const messages = @import("../messages.zig");
const iface = @import("../iface.zig");
const handler_mod = @import("handler.zig");
const state_mod = @import("state.zig");
const epoch_log = @import("epoch_log.zig");
const env_mod = @import("env.zig");
const congestion = @import("congestion.zig");
const exec_bridge = @import("exec_bridge.zig");
const versions = @import("versions.zig");
const status_mod = @import("status.zig");
const tx_mod = @import("tx.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

fn id1(b: u8) Id {
    var a: Id = @splat(0);
    a[31] = b;
    return a;
}

fn oidOf(id: Id) types.ObjectID {
    return handler_mod.oid(id);
}

/// A user transaction: sender `sender`, one owned input, gas coin `gas`, optional shared input.
fn userTxBytes(arena: Allocator, sender: u8, owned: ?tx_mod.ObjRef, gas: tx_mod.ObjRef, shared: ?tx_mod.SharedInput, price: u64) ![]const u8 {
    var inputs: std.ArrayList(types.CallArg) = .empty;
    if (owned) |o| try inputs.append(arena, .{ .Object = .{ .ImmOrOwnedObject = .{ oidOf(o.id), handler_mod.seqn(o.version), .{ .@"0" = .{ .@"0" = o.digest } } } } });
    if (shared) |s| try inputs.append(arena, .{ .Object = .{ .SharedObject = .{ .id = oidOf(s.id), .initial_shared_version = handler_mod.seqn(s.isv), .mutability = switch (s.mutability) {
        .mutable => .Mutable,
        .immutable => .Immutable,
        .non_exclusive_write => .NonExclusiveWrite,
    } } } });
    const cmds = try arena.alloc(types.Command, 1);
    cmds[0] = .{ .TransferObjects = .{ &.{.{ .Input = 0 }}, .{ .Input = 0 } } };
    const addr: types.SuiAddress = .{ .@"0" = id1(sender) };
    const td: types.TransactionData = .{ .V1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs.items, .commands = cmds } },
        .sender = addr,
        .gas_data = .{ .payment = &.{.{ oidOf(gas.id), handler_mod.seqn(gas.version), .{ .@"0" = .{ .@"0" = gas.digest } } }}, .owner = addr, .price = price, .budget = 1_000_000 },
        .expiration = .None,
    } };
    const sst: @FieldType(types.SenderSignedData, "0") = .{ .items = try arena.dupe(types.SenderSignedTransaction, &.{.{
        .intent_message = .{ .intent = types.Intent.sui(.transaction_data), .value = td },
        .tx_signatures = &.{},
    }}) };
    const ssd: types.SenderSignedData = .{ .@"0" = sst };
    const claims = try arena.dupe(messages.TransactionClaim, &.{.{ .AddressAliasesV2 = &.{.{ 0, null }} }});
    const ct: messages.ConsensusTransaction = .{ .tracking_id = @splat(1), .kind = .{ .UserTransactionV2 = .{ .tx = .{ .data = ssd, .auth_signature = .{} }, .claims = claims } } };
    return bcs.encodeAlloc(messages.ConsensusTransaction, arena, &ct);
}

fn block(arena: Allocator, round: u32, author: u32, digest_byte: u8, txs: []const []const u8) !consensus.types.VerifiedBlock {
    const ts = try arena.alloc(consensus.types.Transaction, txs.len);
    for (txs, ts) |t, *o| o.* = .{ .data = t };
    const blk: consensus.types.SignedBlock = .{ .inner = .{ .V1 = .{
        .epoch = 1,
        .round = round,
        .author = author,
        .timestamp_ms = 0,
        .ancestors = &.{},
        .transactions = ts,
        .commit_votes = &.{},
        .misbehavior_reports = &.{},
    } }, .signature = &.{} };
    return .{ .block = blk, .serialized = &.{}, .digest = @splat(digest_byte) };
}

const Rig = struct {
    gpa: Allocator,
    log: epoch_log.MemLog,
    st: state_mod.EpochState,
    ctl: env_mod.LocalEpochControl,
    mem: exec_bridge.MemRunner,
    bridge: exec_bridge.Bridge,
    est: congestion.Estimator,
    statuses: status_mod.StatusCache,
    committee: [4]iface.AuthorityName,
    stakes: [4]u64,
    h: handler_mod.Handler,
    pending_count: usize = 0,
    pending_seqs: [16]u64 = undefined,

    fn pendingPush(ctx: *anyopaque, p: *const iface.PendingCheckpoint) error{ Full, Unimplemented }!void {
        const r: *Rig = @ptrCast(@alignCast(ctx));
        if (r.pending_count < r.pending_seqs.len) r.pending_seqs[r.pending_count] = p.details.checkpoint_seq;
        r.pending_count += 1;
    }
    const sink_vt: iface.PendingCheckpointSink.VTable = .{ .push = pendingPush };

    fn noObject(_: *anyopaque, _: *const Id) ?versions.ObjectReader.Current {
        return null;
    }
    const reader_vt: versions.ObjectReader.VTable = .{ .current = noObject };

    fn init(gpa: Allocator, rig: *Rig, params: env_mod.Params) !void {
        rig.gpa = gpa;
        rig.log = epoch_log.MemLog.init(gpa);
        rig.st = state_mod.EpochState.init(gpa);
        rig.stakes = .{ 2500, 2500, 2500, 2500 };
        rig.ctl = try env_mod.LocalEpochControl.init(gpa, &rig.stakes);
        rig.mem = .{ .gpa = gpa };
        rig.bridge = exec_bridge.Bridge.init(gpa, rig.mem.runner());
        rig.est = congestion.Estimator.init(gpa, &rig.stakes, params.congestion);
        rig.statuses = .{ .gpa = gpa };
        for (&rig.committee, 0..) |*c, i| c.* = .{ .@"0" = @splat(@intCast(i + 1)) };
        rig.pending_count = 0;
        rig.st.window = 3;
        rig.h = try handler_mod.Handler.init(gpa, .{
            .params = params,
            .committee = &rig.committee,
            .state = &rig.st,
            .log = handler_mod.DurableLog.fromMem(&rig.log),
            .epoch_ctl = rig.ctl.control(),
            .exec = &rig.bridge,
            .reader = .{ .ctx = rig, .vtable = &reader_vt },
            .estimator = &rig.est,
            .pending_sink = .{ .ctx = rig, .vtable = &sink_vt },
            .statuses = &rig.statuses,
        });
    }

    fn deinit(r: *Rig) void {
        r.h.deinit();
        r.statuses.deinit();
        r.est.deinit();
        r.bridge.deinit();
        r.mem.deinit();
        r.ctl.deinit();
        r.st.deinit();
        r.log.deinit();
    }
};

fn testParams() env_mod.Params {
    return .{
        .epoch = 1,
        .epoch_start_ms = 1000,
        .rgp = 1000,
        .ordering_by_gas_price = true,
        .defer_owned_object_double_spend = true,
        .max_deferral_rounds = 10,
        .congestion = .{ .target_utilization = 50, .allowed_txn_cost_overage_burst_limit_us = 0, .max_estimate_us = 1_000_000 },
        .record_additional_state_digest = true,
        .commit_rate_window = 3,
        .max_tx_per_checkpoint = 100,
        .min_checkpoint_interval_ms = 250,
    };
}

fn subDag(arena: Allocator, index: u32, ts: u64, blocks: []const consensus.types.VerifiedBlock) !consensus.types.CommittedSubDag {
    return .{
        .leader = blocks[0].reference(),
        .blocks = try arena.dupe(consensus.types.VerifiedBlock, blocks),
        .timestamp_ms = ts,
        .commit_ref = .{ .index = index, .digest = @splat(@intCast(index)) },
        .decided_with_local_blocks = true,
        .recovered_rejected_transactions = false,
        .rejected_transactions_by_block = &.{},
    };
}

test "first transaction in order wins an owned object; the loser is dropped and stays dropped" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try Rig.init(gpa, &rig, testParams());
    defer rig.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();

    const coin: tx_mod.ObjRef = .{ .id = id1(0x20), .version = 5, .digest = id1(0x21) };
    const gas1: tx_mod.ObjRef = .{ .id = id1(0x30), .version = 3, .digest = id1(0x31) };
    const gas2: tx_mod.ObjRef = .{ .id = id1(0x32), .version = 3, .digest = id1(0x33) };
    const t1 = try userTxBytes(a, 0xa1, coin, gas1, null, 1000);
    const t2 = try userTxBytes(a, 0xa2, coin, gas2, null, 1000); // same coin: conflict
    const b1 = try block(a, 10, 0, 1, &.{t1});
    const b2 = try block(a, 10, 1, 2, &.{t2});
    const sd = try subDag(a, 1, 2000, &.{ b1, b2 });
    try rig.h.handleCommit(a, &sd);

    try std.testing.expectEqual(@as(u64, 1), rig.h.stats.commits);
    try std.testing.expectEqual(@as(u64, 1), rig.h.stats.dropped_lock_conflict);
    // the coin is locked to the first transaction
    const holder = rig.st.lockHolder(.{ .id = coin.id, .version = 5, .digest = coin.digest }).?;
    const ux1 = try tx_mod.parse(a, t1[9..]);
    try std.testing.expectEqualSlices(u8, &ux1.digest, &holder);
    // statuses
    try std.testing.expect(rig.statuses.get(.{ .round = 10, .author = 0, .digest = @splat(1), .index = 0 }) == .finalized);
    try std.testing.expect(rig.statuses.get(.{ .round = 10, .author = 1, .digest = @splat(2), .index = 0 }) == .dropped);
    // defer_owned_object_double_spend: the contested winner waits one round; only the prologue ran
    try std.testing.expectEqual(@as(usize, 1), rig.bridge.pending());
    try std.testing.expectEqual(@as(usize, 1), rig.st.deferred.items.len);
    try std.testing.expectEqual(@as(u64, 1), rig.h.stats.deferred);
    // a pending checkpoint was cut (min interval 0)
    try std.testing.expectEqual(@as(usize, 1), rig.pending_count);

    // a later commit carrying the loser again cannot win: the lock is durable
    const b3 = try block(a, 11, 2, 3, &.{t2});
    const sd2 = try subDag(a, 2, 2200, &.{b3});
    try rig.h.handleCommit(a, &sd2);
    try std.testing.expectEqual(@as(u64, 2), rig.h.stats.dropped_lock_conflict);
    // ... and the deferred winner is scheduled now (prologue of commit 1 and 2, plus the winner)
    try std.testing.expectEqual(@as(usize, 0), rig.st.deferred.items.len);
    try std.testing.expectEqual(@as(usize, 3), rig.bridge.pending());

    // restart: rebuild state from the log; the lock survives and the commit is not redone
    var st2 = state_mod.EpochState.init(gpa);
    defer st2.deinit();
    try rig.log.replay(state_mod.Replay{ .state = &st2 }, state_mod.Replay.visit);
    try std.testing.expectEqualSlices(u8, &ux1.digest, &st2.lockHolder(.{ .id = coin.id, .version = 5, .digest = coin.digest }).?);
    try std.testing.expectEqual(@as(u64, 2), st2.indices.sub_dag_index);
}

test "shared versions assigned in order, lamport rule, duplicates skipped" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try Rig.init(gpa, &rig, testParams());
    defer rig.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();

    const shared: tx_mod.SharedInput = .{ .id = id1(0x50), .isv = 4, .mutability = .mutable };
    const g1: tx_mod.ObjRef = .{ .id = id1(0x61), .version = 9, .digest = id1(0x71) };
    const g2: tx_mod.ObjRef = .{ .id = id1(0x62), .version = 2, .digest = id1(0x72) };
    const t1 = try userTxBytes(a, 0xb1, null, g1, shared, 1000);
    const t2 = try userTxBytes(a, 0xb2, null, g2, shared, 1000);
    // t1 appears twice in the same commit (two proposers): processed once
    const sd = try subDag(a, 1, 2000, &.{
        try block(a, 10, 0, 1, &.{t1}),
        try block(a, 10, 1, 2, &.{ t1, t2 }),
    });
    try rig.h.handleCommit(a, &sd);
    try std.testing.expectEqual(@as(u64, 1), rig.h.stats.skipped_duplicates);
    // absent object: the first read is at its initial shared version 4. t1 (gas version 9) moves
    // it to max(9, 4) + 1 = 10; t2 (gas version 2) reads 10 and moves it to max(2, 10) + 1 = 11.
    try std.testing.expectEqual(@as(?u64, 11), rig.st.nextVersion(.{ .id = shared.id, .isv = 4 }));
    // the assigned versions are kept for execution
    const ux1 = try tx_mod.parse(a, t1[9..]);
    const ux2 = try tx_mod.parse(a, t2[9..]);
    const as1 = rig.st.assignedFor(.{ .digest = ux1.digest }).?;
    const as2 = rig.st.assignedFor(.{ .digest = ux2.digest }).?;
    try std.testing.expectEqual(@as(u64, 4), as1.shared[0].version);
    try std.testing.expectEqual(@as(u64, 10), as2.shared[0].version);
    // a replay of the same commit index does nothing
    try rig.h.handleCommit(a, &sd);
    try std.testing.expectEqual(@as(u64, 1), rig.h.stats.commits);
}

test "congestion beyond the deferral limit cancels with the sentinel version" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    var p = testParams();
    // no deferral rounds allowed: a congested transaction is cancelled at once
    p.max_deferral_rounds = 0;
    p.defer_owned_object_double_spend = false;
    p.congestion = .{ .target_utilization = 0, .allowed_txn_cost_overage_burst_limit_us = 0, .max_estimate_us = 1_000_000 };
    try Rig.init(gpa, &rig, p);
    defer rig.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();

    const shared: tx_mod.SharedInput = .{ .id = id1(0x50), .isv = 4, .mutability = .mutable };
    const g1: tx_mod.ObjRef = .{ .id = id1(0x61), .version = 9, .digest = id1(0x71) };
    const g2: tx_mod.ObjRef = .{ .id = id1(0x62), .version = 2, .digest = id1(0x72) };
    const t1 = try userTxBytes(a, 0xb1, null, g1, shared, 2000);
    const t2 = try userTxBytes(a, 0xb2, null, g2, shared, 1000);
    const sd = try subDag(a, 1, 2000, &.{try block(a, 10, 0, 1, &.{ t1, t2 })});
    try rig.h.handleCommit(a, &sd);
    // gas price ordering: t1 (2000) first and runs; t2 starts after t1's cost: over the budget
    const ux1 = try tx_mod.parse(a, t1[9..]);
    const ux2 = try tx_mod.parse(a, t2[9..]);
    try std.testing.expectEqual(@as(u64, 4), rig.st.assignedFor(.{ .digest = ux1.digest }).?.shared[0].version);
    try std.testing.expectEqual(versions.congested, rig.st.assignedFor(.{ .digest = ux2.digest }).?.shared[0].version);
    try std.testing.expectEqual(@as(u64, 1), rig.h.stats.cancelled);
    // the cancelled transaction did not move the object: only t1's lamport bump is recorded
    try std.testing.expectEqual(@as(?u64, 10), rig.st.nextVersion(.{ .id = shared.id, .isv = 4 }));
    // and the object kept a debt for the next commits
    try std.testing.expect(rig.st.debtOf(false, &shared.id) != null);
}

test "end of publish quorum closes the epoch and cuts the last checkpoint" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try Rig.init(gpa, &rig, testParams());
    defer rig.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();

    // three of four validators send EndOfPublish in one commit
    var eops: [3][]const u8 = undefined;
    for (&eops, 0..) |*e, i| {
        const ct: messages.ConsensusTransaction = .{ .tracking_id = @splat(2), .kind = .{ .EndOfPublish = rig.committee[i] } };
        e.* = try bcs.encodeAlloc(messages.ConsensusTransaction, a, &ct);
    }
    const sd = try subDag(a, 1, 2000, &.{
        try block(a, 10, 0, 1, &.{eops[0]}),
        try block(a, 10, 1, 2, &.{eops[1]}),
        try block(a, 10, 2, 3, &.{eops[2]}),
    });
    try rig.h.handleCommit(a, &sd);
    try std.testing.expect(rig.ctl.state.isRejectAllTx());
    // a final pending checkpoint was cut
    try std.testing.expect(rig.pending_count >= 1);
    var last_of_epoch = false;
    for (rig.st.pending.items) |pc| last_of_epoch = last_of_epoch or pc.last_of_epoch;
    try std.testing.expect(last_of_epoch);

    // a user transaction in the next commit is ignored (epoch over)
    const coin: tx_mod.ObjRef = .{ .id = id1(0x20), .version = 5, .digest = id1(0x21) };
    const gas1: tx_mod.ObjRef = .{ .id = id1(0x30), .version = 3, .digest = id1(0x31) };
    const t1 = try userTxBytes(a, 0xa1, coin, gas1, null, 1000);
    const sd2 = try subDag(a, 2, 2300, &.{try block(a, 11, 0, 4, &.{t1})});
    try rig.h.handleCommit(a, &sd2);
    try std.testing.expect(rig.statuses.get(.{ .round = 11, .author = 0, .digest = @splat(4), .index = 0 }) == .dropped);
    // the epoch's final commit did not schedule it, and no lock was taken
    try std.testing.expect(rig.st.lockHolder(.{ .id = coin.id, .version = 5, .digest = coin.digest }) == null);
}

test "params from the mainnet protocol config" {
    const cfg = try protocol.get(141, .mainnet);
    const p = env_mod.Params.fromProtocol(cfg, 1, 0, 1000);
    try std.testing.expect(p.ordering_by_gas_price);
    try std.testing.expect(p.record_additional_state_digest);
    try std.testing.expect(p.mode_is_execution_time_estimate);
    try std.testing.expectEqual(@as(u64, 50), p.congestion.target_utilization);
    try std.testing.expect(p.max_tx_per_checkpoint > 0);
}

test "params at protocol 141 match the Mysten 1.83.1 snapshot values" {
    // sui-protocol-config snapshots sui_protocol_config__test__Mainnet_version_141.snap
    const cfg = try protocol.get(141, .mainnet);
    const p = env_mod.Params.fromProtocol(cfg, 1, 0, 1000);
    const c = p.congestion;
    try std.testing.expectEqual(@as(u64, 50), c.target_utilization);
    try std.testing.expectEqual(@as(u64, 500_000), c.allowed_txn_cost_overage_burst_limit_us);
    try std.testing.expectEqual(@as(u64, 20), c.randomness_scalar);
    try std.testing.expectEqual(@as(u64, 1_500_000), c.max_estimate_us);
    try std.testing.expectEqual(@as(u64, 10), c.stored_observations_num_included_checkpoints);
    try std.testing.expectEqual(@as(u64, 180), c.stored_observations_limit);
    try std.testing.expectEqual(@as(u64, 3334), c.stake_weighted_median_threshold);
    try std.testing.expect(c.default_none_duration_for_new_keys);
    try std.testing.expectEqual(@as(?u64, 18), c.observations_chunk_size);
    try std.testing.expectEqual(@as(u64, 37_000_000), p.per_commit_budget);
    try std.testing.expectEqual(@as(u64, 7_400_000), p.per_commit_budget_randomness);
    try std.testing.expectEqual(@as(u64, 10), p.max_deferral_rounds);
    try std.testing.expectEqual(@as(u64, 20_000), p.max_tx_per_checkpoint);
    try std.testing.expectEqual(@as(u64, 200), p.min_checkpoint_interval_ms);
    try std.testing.expectEqual(@as(u32, 10), p.commit_rate_window);
    try std.testing.expectEqual(@as(u64, 1024), p.max_programmable_tx_commands);
    try std.testing.expectEqual(@as(?u64, 120_000), p.epoch_close_deadline_ms);
    try std.testing.expect(p.ordering_by_gas_price);
    try std.testing.expect(p.merge_colliding_deferrals);
    try std.testing.expect(p.allowed_proposers);
    try std.testing.expect(p.accumulators_enabled);
    try std.testing.expect(p.randomness_state_enabled);
    // devnet-only / disabled everywhere at 141
    try std.testing.expect(!p.defer_owned_object_double_spend);
    try std.testing.expect(!p.defer_unpaid_amplification);
    try std.testing.expect(cfg.feature_flags.disable_preconsensus_locking);
    try std.testing.expect(cfg.feature_flags.include_cancelled_randomness_txns_in_prologue);
}

test "the commit-interval ring takes the raw commit timestamp, the prologue the clamped one" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    // epoch starts at 1000 ms
    try Rig.init(gpa, &rig, testParams());
    defer rig.deinit();
    var ar: std.heap.ArenaAllocator = .init(gpa);
    defer ar.deinit();
    const a = ar.allocator();
    // two commits stamped before the epoch start, then one after
    try rig.h.handleCommit(a, &(try subDag(a, 1, 400, &.{try block(a, 10, 0, 1, &.{})})));
    try rig.h.handleCommit(a, &(try subDag(a, 2, 700, &.{try block(a, 11, 0, 2, &.{})})));
    try rig.h.handleCommit(a, &(try subDag(a, 3, 1600, &.{try block(a, 12, 0, 3, &.{})})));
    // Rust observe_commit_time(commit_timestamp_ms()): 400, 700, 1600 (window 3), not 1000, 1000, 1600
    try std.testing.expectEqualSlices(u64, &.{ 400, 700, 1600 }, rig.st.commit_times.items);
    // commit_interval_estimate = (1600 - 400) div_ceil 3 = 400 ms
    try std.testing.expectEqual(@as(?u64, 400), state_mod.EpochState.intervalOf(rig.st.commit_times.items));
}
