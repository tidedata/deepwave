//! Replays a recorded mainnet checkpoint (a `.chk` corpus blob: CheckpointData = summary,
//! certificate, contents and every transaction with its effects, made by Mysten's validators)
//! through deepwave's checkpoint builder and compares the result byte for byte:
//!
//!   - contents: BCS(CheckpointContents) built from the effects' digests and the user signatures
//!   - summary: BCS(CheckpointSummary) built from the previous summary, the effects, the
//!     randomness rounds of the RandomnessStateUpdate transactions, the artifacts digest, and on
//!     an end-of-epoch checkpoint the next committee and the ECMH root (taken from the recorded
//!     summary: the root itself is proven by the `state-hash` suite of the exec lane)
//!   - order: the transactions of every consensus commit group, fed in reverse, come back in the
//!     recorded order from `causal_order` (protocols that still sort causally only)
//!
//! This is the offline half of the goal "every built checkpoint summary and contents is byte
//! equal to the Rust validator's" (docs/VALIDATOR-DESIGN.md 5.4). The commit-by-commit half needs
//! the localnet capture (tools/truth/consensus).
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const ev = @import("effects_view.zig");
const causal = @import("causal_order.zig");
const create = @import("create.zig");
const builder = @import("builder.zig");

pub const Result = union(enum) {
    ok,
    /// Not comparable (reason).
    skipped: []const u8,
    /// A difference (what).
    mismatch: []const u8,
};

pub fn classOf(kind: *const types.TransactionKind) builder.TxClass {
    return switch (kind.*) {
        .ConsensusCommitPrologue, .ConsensusCommitPrologueV2, .ConsensusCommitPrologueV3, .ConsensusCommitPrologueV4 => .consensus_commit_prologue,
        .AuthenticatorStateUpdate => .authenticator_state_update,
        .ProgrammableSystemTransaction => .programmable_system,
        .RandomnessStateUpdate => |r| .{ .randomness_state_update = r.randomness_round.@"0" },
        .ProgrammableTransaction => .programmable,
        .ChangeEpoch, .Genesis, .EndOfEpochTransaction => .forbidden,
    };
}

fn kindOf(t: *const types.CheckpointTransaction) *const types.TransactionKind {
    const st = t.transaction.data.@"0".element();
    return switch (st.intent_message.value) {
        .V1 => |*v| &v.kind,
    };
}

/// The last transaction of an end-of-epoch checkpoint (the epoch-change transaction).
fn eoe_tx(summary: *const types.CheckpointSummary, i: usize, n: usize) bool {
    return summary.end_of_epoch_data != null and i + 1 == n;
}

/// `[(GenericSignature(0x00 ++ 64 zero ++ 32 zero), None)]`.
pub fn isSystemSignature(s: []const create.SigEntry) bool {
    if (s.len != 1 or s[0][1] != null) return false;
    const b = s[0][0].@"0";
    if (b.len != 97) return false;
    for (b) |x| if (x != 0) return false;
    return true;
}

/// `blob` is a corpus `.chk` (tag byte 1, then CheckpointData); `prev_summary_bcs` the previous
/// checkpoint's BCS CheckpointSummary.
pub fn replay(arena: std.mem.Allocator, cfg: *const protocol.ProtocolConfig, blob: []const u8, prev_summary_bcs: []const u8) !Result {
    if (blob.len == 0 or blob[0] != 1) return .{ .mismatch = "bad blob tag" };
    if (!cfg.feature_flags.prepend_prologue_tx_in_consensus_commit_in_checkpoints) return .{ .skipped = "protocol before the consensus commit prologue prepend" };
    const cp = try bcs.decode(types.CheckpointData, arena, blob[1..]);
    const summary = &cp.checkpoint_summary.data;
    const prev = try bcs.decode(types.CheckpointSummary, arena, prev_summary_bcs);
    if (prev.sequence_number + 1 != summary.sequence_number) return .{ .skipped = "previous checkpoint is not seq - 1" };
    const eoe = summary.end_of_epoch_data;
    const n = cp.transactions.len;

    // effects, classes, signatures
    const views = try arena.alloc(ev.View, n);
    const classes = try arena.alloc(builder.TxClass, n);
    for (cp.transactions, views, classes) |*t, *v, *c| {
        const raw = try bcs.encodeAlloc(types.TransactionEffects, arena, &t.effects);
        v.* = try ev.View.parse(arena, raw);
        c.* = classOf(kindOf(t));
    }
    // the recorded effects digests must be what contents say (guards a bad re-encode)
    const sigs = try arena.alloc([]const create.SigEntry, n);
    switch (cp.checkpoint_contents) {
        .V1 => |c| {
            if (c.transactions.len != n) return .{ .mismatch = "contents length" };
            for (c.transactions, c.user_signatures, views, sigs) |d, s, *v, *o| {
                if (!std.mem.eql(u8, &d.effects.@"0".@"0", &v.digest)) return .{ .skipped = "effects re-encode differs from recorded digest" };
                const l = try arena.alloc(create.SigEntry, s.len);
                for (s, l) |x, *y| y.* = .{ x, null };
                o.* = l;
            }
        },
        .V2 => |c| {
            if (c.transactions.len != n) return .{ .mismatch = "contents length" };
            for (c.transactions, views, sigs) |t, *v, *o| {
                if (!std.mem.eql(u8, &t.digest.effects.@"0".@"0", &v.digest)) return .{ .skipped = "effects re-encode differs from recorded digest" };
                o.* = t.user_signatures;
            }
        },
    }

    // what `builder.Env.user_signatures` must return for system transactions: the one all-zero
    // Ed25519 signature of `new_system_transaction` with no alias version; nothing for the
    // epoch-change transaction the builder appends at the end of an epoch
    for (classes, sigs, 0..) |c, s, i| {
        if (c == .programmable) continue;
        if (eoe_tx(summary, i, n)) {
            if (s.len != 0) return .{ .mismatch = "epoch-change transaction carries signatures" };
            continue;
        }
        if (!isSystemSignature(s)) return .{ .mismatch = "system transaction signatures" };
    }

    // randomness rounds, in checkpoint order
    var rounds: std.ArrayList(u64) = .empty;
    var has_random = false;
    var has_settlement = false;
    for (classes) |c| switch (c) {
        .randomness_state_update => |r| {
            try rounds.append(arena, r);
            has_random = true;
        },
        .programmable_system => has_settlement = true,
        else => {},
    };

    // end of epoch input from the recorded summary
    var eoe_in: ?create.EndOfEpoch = null;
    var rolling: ?ev.GasSummary = null;
    const last = create.LastBuilt.fromSummary(&prev, types.digest.checkpointSummaryDigest(prev_summary_bcs), null);
    if (eoe) |e| {
        if (n == 0) return .{ .mismatch = "end of epoch checkpoint without transactions" };
        const committee = try arena.alloc(create.CommitteeEntry, e.nextEpochCommittee.len);
        for (e.nextEpochCommittee, committee) |m, *o| o.* = .{ .name = m[0].@"0", .stake = m[1] };
        var root: [32]u8 = @splat(0);
        for (e.epochCommitments) |c| switch (c) {
            .ECMHLiveObjectSetDigest => |d| root = d.digest.@"0",
            else => {},
        };
        eoe_in = .{ .next_committee = committee, .next_protocol_version = e.nextEpochProtocolVersion.@"0", .root_state_digest = root };
        rolling = create.rollingGas(last, summary.epoch, create.gasOf(views[0 .. n - 1]));
    }

    const created = try create.create(arena, .{
        .cfg = cfg,
        .epoch = summary.epoch,
        .seq = summary.sequence_number,
        .timestamp_ms = summary.timestamp_ms,
        .last = last,
        .effects = views,
        .signatures = sigs,
        .randomness_rounds = rounds.items,
        .end_of_epoch = eoe_in,
        .rolling_gas = rolling,
    });
    const want_contents = try bcs.encodeAlloc(types.CheckpointContents, arena, &cp.checkpoint_contents);
    if (!std.mem.eql(u8, want_contents, created.contents_bcs)) return .{ .mismatch = "contents bytes" };
    const want_summary = try bcs.encodeAlloc(types.CheckpointSummary, arena, summary);
    if (!std.mem.eql(u8, want_summary, created.summary_bcs)) return .{ .mismatch = "summary bytes" };

    // causal order, per commit group
    if (cfg.feature_flags.disable_effects_tx_dependencies) return .ok;
    if (has_random and !has_settlement) return .ok; // randomness chunks are separate root groups: boundaries unknown
    const body_end = if (eoe != null) n - 1 else n;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= body_end) : (i += 1) {
        const boundary = i == body_end or (i > start and classes[i] == .consensus_commit_prologue);
        if (!boundary) continue;
        if (i > start) {
            // settlement effects close the group and are not sorted
            var end = i;
            while (end > start and classes[end - 1] == .programmable_system) end -= 1;
            const group = views[start..end];
            const ccp_first = group.len > 0 and classes[start] == .consensus_commit_prologue;
            // feed it reversed, the prologue (always the first root) kept first
            const rev = try arena.alloc(ev.View, group.len);
            const keep: usize = if (ccp_first) 1 else 0;
            if (ccp_first) rev[0] = group[0];
            for (group[keep..], 0..) |g, k| rev[group.len - 1 - k] = g;
            const got = try causal.orderForCheckpoint(arena, rev, ccp_first, false);
            for (got, group) |g, w| {
                if (!std.mem.eql(u8, &g.tx, &w.tx)) return .{ .mismatch = "causal order" };
            }
        }
        start = i;
    }
    return .ok;
}
