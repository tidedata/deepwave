//! `CheckpointBuilder::create_checkpoint` minus the I/O (sui-core `checkpoints/mod.rs`, 1.83.1):
//! from the causally ordered effects of one pending checkpoint, build the CheckpointContents and
//! the CheckpointSummary, byte for byte as Rust serializes them.
//!
//! This is a pure function of its inputs so it can be replayed against recorded checkpoints
//! (suite `checkpoint-build`).
//!
//!   contents          V2 (`address_aliases`) or V1: ExecutionDigests plus the user signatures
//!   network total     previous total + number of transactions
//!   rolling gas       previous epoch rolling gas + this checkpoint's gas, or just this
//!                     checkpoint's when the previous checkpoint is of an earlier epoch
//!   commitments       [CheckpointArtifactsDigest] when `include_checkpoint_artifacts_digest_in_summary`
//!   version data      `checkpoint_summary_version_specific_data` 1: BCS(V1{randomness_rounds})
//!   end of epoch      next committee, next protocol version, [ECMHLiveObjectSetDigest] when
//!                     `commit_root_state_digest`
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const ev = @import("effects_view.zig");
const artifacts = @import("artifacts.zig");

pub const Error = error{ BadVersionSpecificData, LengthMismatch } || artifacts.Error;

pub const SigEntry = std.meta.Child(@FieldType(types.CheckpointTransactionContents, "user_signatures"));
pub const CommitteeEntry = struct { name: [96]u8, stake: u64 };

/// The checkpoint the builder built last, as the next one needs it.
pub const LastBuilt = struct {
    seq: u64,
    epoch: u64,
    timestamp_ms: u64,
    network_total_transactions: u64,
    rolling_gas: ev.GasSummary,
    digest: [32]u8,
    /// Consensus commit height the checkpoint was built from (null: not from this epoch's queue,
    /// e.g. the last checkpoint of the previous epoch).
    height: ?u64 = null,

    pub fn fromSummary(s: *const types.CheckpointSummary, digest: [32]u8, height: ?u64) LastBuilt {
        const g = s.epoch_rolling_gas_cost_summary;
        return .{
            .seq = s.sequence_number,
            .epoch = s.epoch,
            .timestamp_ms = s.timestamp_ms,
            .network_total_transactions = s.network_total_transactions,
            .rolling_gas = .{
                .computation_cost = g.computationCost,
                .storage_cost = g.storageCost,
                .storage_rebate = g.storageRebate,
                .non_refundable_storage_fee = g.nonRefundableStorageFee,
            },
            .digest = digest,
            .height = height,
        };
    }
};

pub const EndOfEpoch = struct {
    next_committee: []const CommitteeEntry,
    next_protocol_version: u64,
    /// `RunningRoot.epochDigest()` after this checkpoint's effects were accumulated.
    root_state_digest: [32]u8,
};

pub const Params = struct {
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    seq: u64,
    timestamp_ms: u64,
    last: ?LastBuilt,
    /// Final checkpoint order, the epoch-change transaction included on an end-of-epoch checkpoint.
    effects: []const ev.View,
    /// One entry per effects: the user signatures (and alias versions) of the transaction.
    signatures: []const []const SigEntry,
    /// RandomnessStateUpdate rounds of the checkpoint's transactions, in checkpoint order.
    randomness_rounds: []const u64,
    end_of_epoch: ?EndOfEpoch = null,
    /// The epoch rolling gas of the summary when it is not the sum of `effects`: on an
    /// end-of-epoch checkpoint Rust computes it before the epoch-change transaction is added.
    rolling_gas: ?ev.GasSummary = null,
};

pub const Created = struct {
    summary: types.CheckpointSummary,
    summary_bcs: []u8,
    summary_digest: [32]u8,
    contents_bcs: []u8,
    contents_digest: [32]u8,
    num_txs: u64,
};

/// Sums effects' gas the way `GasCostSummary::new_from_txn_effects` does (wrapping: sui-node is
/// built without overflow checks).
pub fn gasOf(effects: []const ev.View) ev.GasSummary {
    var g: ev.GasSummary = .{};
    for (effects) |*e| {
        const x = e.gas();
        g.computation_cost +%= x.computation_cost;
        g.storage_cost +%= x.storage_cost;
        g.storage_rebate +%= x.storage_rebate;
        g.non_refundable_storage_fee +%= x.non_refundable_storage_fee;
    }
    return g;
}

/// `get_epoch_total_gas_cost`.
pub fn rollingGas(last: ?LastBuilt, epoch: u64, cur: ev.GasSummary) ev.GasSummary {
    const l = last orelse return cur;
    if (l.epoch != epoch) return cur;
    return .{
        .computation_cost = l.rolling_gas.computation_cost +% cur.computation_cost,
        .storage_cost = l.rolling_gas.storage_cost +% cur.storage_cost,
        .storage_rebate = l.rolling_gas.storage_rebate +% cur.storage_rebate,
        .non_refundable_storage_fee = l.rolling_gas.non_refundable_storage_fee +% cur.non_refundable_storage_fee,
    };
}

fn digestOf(d: [32]u8) types.hand.Digest {
    return .{ .@"0" = d };
}

/// BCS(CheckpointVersionSpecificData::V1 { randomness_rounds }).
pub fn versionSpecificData(arena: std.mem.Allocator, cfg: *const protocol.ProtocolConfig, rounds: []const u64) Error![]const u8 {
    const v = cfg.checkpoint_summary_version_specific_data orelse return &.{};
    switch (v) {
        0 => return &.{},
        1 => {
            var out: std.ArrayList(u8) = .empty;
            try out.append(arena, 0); // enum variant V1
            try appendUleb(arena, &out, rounds.len);
            for (rounds) |r| {
                var b: [8]u8 = undefined;
                std.mem.writeInt(u64, &b, r, .little);
                try out.appendSlice(arena, &b);
            }
            return out.items;
        },
        else => return error.BadVersionSpecificData,
    }
}

fn appendUleb(arena: std.mem.Allocator, out: *std.ArrayList(u8), n: usize) !void {
    var v = n;
    while (true) {
        const b: u8 = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) {
            try out.append(arena, b);
            return;
        }
        try out.append(arena, b | 0x80);
    }
}

pub fn create(arena: std.mem.Allocator, p: Params) Error!Created {
    if (p.signatures.len != p.effects.len) return error.LengthMismatch;
    const cfg = p.cfg;

    // contents
    const n = p.effects.len;
    const contents: types.CheckpointContents = blk: {
        if (cfg.feature_flags.address_aliases) {
            const txs = try arena.alloc(types.CheckpointTransactionContents, n);
            for (p.effects, p.signatures, txs) |*e, s, *t| t.* = .{
                .digest = .{ .transaction = .{ .@"0" = digestOf(e.tx) }, .effects = .{ .@"0" = digestOf(e.digest) } },
                .user_signatures = s,
            };
            break :blk .{ .V2 = .{ .transactions = txs } };
        }
        const txs = try arena.alloc(types.ExecutionDigests, n);
        const sigs = try arena.alloc([]const types.hand.GenericSignature, n);
        for (p.effects, p.signatures, txs, sigs) |*e, s, *t, *o| {
            t.* = .{ .transaction = .{ .@"0" = digestOf(e.tx) }, .effects = .{ .@"0" = digestOf(e.digest) } };
            const plain = try arena.alloc(types.hand.GenericSignature, s.len);
            for (s, plain) |x, *y| y.* = x[0];
            o.* = plain;
        }
        break :blk .{ .V1 = .{ .transactions = txs, .user_signatures = sigs } };
    };
    const contents_bcs = try bcs.encodeAlloc(types.CheckpointContents, arena, &contents);
    const contents_digest = types.digest.checkpointContentsDigest(contents_bcs);

    const num_txns: u64 = n;
    const network_total = if (p.last) |l| l.network_total_transactions + num_txns else num_txns;
    const gas = p.rolling_gas orelse rollingGas(p.last, p.epoch, gasOf(p.effects));

    const commitments: []const types.CheckpointCommitment = if (cfg.feature_flags.include_checkpoint_artifacts_digest_in_summary) blk: {
        const d = try artifacts.artifactsDigest(arena, p.effects);
        const one = try arena.alloc(types.CheckpointCommitment, 1);
        one[0] = .{ .CheckpointArtifactsDigest = .{ .@"0" = digestOf(d) } };
        break :blk one;
    } else &.{};

    var eoe: ?types.EndOfEpochData = null;
    if (p.end_of_epoch) |e| {
        const committee = try arena.alloc(@typeInfo(@FieldType(types.EndOfEpochData, "nextEpochCommittee")).pointer.child, e.next_committee.len);
        for (e.next_committee, committee) |m, *o| o.* = .{ .{ .@"0" = m.name }, m.stake };
        var ec: []const types.CheckpointCommitment = &.{};
        if (cfg.feature_flags.commit_root_state_digest) {
            const one = try arena.alloc(types.CheckpointCommitment, 1);
            one[0] = .{ .ECMHLiveObjectSetDigest = .{ .digest = digestOf(e.root_state_digest) } };
            ec = one;
        }
        eoe = .{
            .nextEpochCommittee = committee,
            .nextEpochProtocolVersion = .{ .@"0" = e.next_protocol_version },
            .epochCommitments = ec,
        };
    }

    const summary: types.CheckpointSummary = .{
        .epoch = p.epoch,
        .sequence_number = p.seq,
        .network_total_transactions = network_total,
        .content_digest = .{ .@"0" = digestOf(contents_digest) },
        .previous_digest = if (p.last) |l| .{ .@"0" = digestOf(l.digest) } else null,
        .epoch_rolling_gas_cost_summary = .{
            .computationCost = gas.computation_cost,
            .storageCost = gas.storage_cost,
            .storageRebate = gas.storage_rebate,
            .nonRefundableStorageFee = gas.non_refundable_storage_fee,
        },
        .timestamp_ms = p.timestamp_ms,
        .checkpoint_commitments = commitments,
        .end_of_epoch_data = eoe,
        .version_specific_data = try versionSpecificData(arena, cfg, p.randomness_rounds),
    };
    const summary_bcs = try bcs.encodeAlloc(types.CheckpointSummary, arena, &summary);
    return .{
        .summary = summary,
        .summary_bcs = summary_bcs,
        .summary_digest = types.digest.checkpointSummaryDigest(summary_bcs),
        .contents_bcs = contents_bcs,
        .contents_digest = contents_digest,
        .num_txs = num_txns,
    };
}

/// The message a validator BLS-signs for a summary: Intent(CheckpointSummary, v0, Sui) ++
/// BCS(summary) ++ BCS(epoch) (`AuthoritySignInfo::new` -> `new_secure`).
pub fn signingMessage(arena: std.mem.Allocator, summary_bcs: []const u8, epoch: u64) std.mem.Allocator.Error![]u8 {
    const m = try arena.alloc(u8, summary_bcs.len + 11);
    m[0..3].* = .{ 2, 0, 0 };
    @memcpy(m[3..][0..summary_bcs.len], summary_bcs);
    std.mem.writeInt(u64, m[3 + summary_bcs.len ..][0..8], epoch, .little);
    return m;
}

// ---------------------------------------------------------------- tests

const testing = std.testing;

fn emptyEffects(a: std.mem.Allocator, id: u8, gas_c: u64) !ev.View {
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = 1,
        .gas_used = .{ .computationCost = gas_c, .storageCost = 2, .storageRebate = 1, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(id) } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 5 },
        .changed_objects = &.{},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    const raw = try bcs.encodeAlloc(types.TransactionEffects, a, &fx);
    return ev.View.parse(a, raw);
}

test "create: summary and contents are consistent and chain" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);
    const e1 = try emptyEffects(a, 1, 10);
    const e2 = try emptyEffects(a, 2, 20);
    const no_sigs: []const SigEntry = &.{};
    const c0 = try create(a, .{
        .cfg = cfg,
        .epoch = 1,
        .seq = 7,
        .timestamp_ms = 1000,
        .last = null,
        .effects = &.{ e1, e2 },
        .signatures = &.{ no_sigs, no_sigs },
        .randomness_rounds = &.{4},
    });
    try testing.expectEqual(@as(u64, 2), c0.summary.network_total_transactions);
    try testing.expectEqual(@as(u64, 30), c0.summary.epoch_rolling_gas_cost_summary.computationCost);
    try testing.expectEqualSlices(u8, &c0.contents_digest, &c0.summary.content_digest.@"0".@"0");
    // the next checkpoint of the same epoch rolls the gas and chains the digest
    const last = LastBuilt.fromSummary(&c0.summary, c0.summary_digest, 3);
    const c1 = try create(a, .{
        .cfg = cfg,
        .epoch = 1,
        .seq = 8,
        .timestamp_ms = 1100,
        .last = last,
        .effects = &.{e1},
        .signatures = &.{no_sigs},
        .randomness_rounds = &.{},
    });
    try testing.expectEqual(@as(u64, 3), c1.summary.network_total_transactions);
    try testing.expectEqual(@as(u64, 40), c1.summary.epoch_rolling_gas_cost_summary.computationCost);
    try testing.expectEqualSlices(u8, &c0.summary_digest, &c1.summary.previous_digest.?.@"0".@"0");
    // a new epoch restarts the rolling gas
    const c2 = try create(a, .{
        .cfg = cfg,
        .epoch = 2,
        .seq = 9,
        .timestamp_ms = 1200,
        .last = LastBuilt.fromSummary(&c1.summary, c1.summary_digest, 4),
        .effects = &.{e2},
        .signatures = &.{no_sigs},
        .randomness_rounds = &.{},
    });
    try testing.expectEqual(@as(u64, 20), c2.summary.epoch_rolling_gas_cost_summary.computationCost);
    // the checkpoint crate's reader parses what we wrote
    const parsed = try @import("checkpoint").Summary.parse(c0.summary_bcs);
    try testing.expectEqual(@as(u64, 7), parsed.sequence_number);
    try testing.expectEqual(@as(u64, 2), parsed.network_total_transactions);
}

test "create: end of epoch data carries the committee and the state root" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cfg = try protocol.get(100, .mainnet);
    const e1 = try emptyEffects(a, 1, 10);
    const no_sigs: []const SigEntry = &.{};
    const c = try create(a, .{
        .cfg = cfg,
        .epoch = 1,
        .seq = 7,
        .timestamp_ms = 1000,
        .last = null,
        .effects = &.{e1},
        .signatures = &.{no_sigs},
        .randomness_rounds = &.{},
        .end_of_epoch = .{
            .next_committee = &.{ .{ .name = @splat(1), .stake = 6000 }, .{ .name = @splat(2), .stake = 4000 } },
            .next_protocol_version = 101,
            .root_state_digest = @splat(9),
        },
    });
    const eoe = c.summary.end_of_epoch_data.?;
    try testing.expectEqual(@as(usize, 2), eoe.nextEpochCommittee.len);
    try testing.expectEqual(@as(u64, 101), eoe.nextEpochProtocolVersion.@"0");
    try testing.expectEqual(@as(usize, 1), eoe.epochCommitments.len);
    const parsed = try @import("checkpoint").Summary.parse(c.summary_bcs);
    try testing.expectEqual(@as(u32, 2), parsed.next_committee.?.count);
    try testing.expectEqual(@as(u64, 101), parsed.next_protocol_version);
}
