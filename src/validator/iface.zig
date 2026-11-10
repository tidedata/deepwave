//! Interfaces between the validator lanes (docs/VALIDATOR-DESIGN.md section 4.4). validator-base
//! owns this file: a lane implements the side it owns and codes against the other sides through
//! these declarations only, so all lanes build in parallel against fakes.
//!
//! Ownership of each implementation:
//!   ConsensusSubmit, CommitHandler, SystemTxRouter, TxExecutor ........ val-authority
//!   PendingCheckpointSink, CheckpointSignatureSink, CertifiedSink ...... val-checkpoints
//!   RandomnessHooks, JwkHooks ........................................ val-randomness-jwk
//!   EpochHooks, EpochView ............................................ val-epoch-api-keys
//!   Tracer ........................................................... val-fast-finality
const std = @import("std");
const types = @import("types");
const consensus = @import("consensus");
const messages = @import("messages.zig");

pub const AuthorityName = messages.AuthorityName;

// ------------------------------------------------------------------ into consensus

/// sui-core consensus_adapter: queue ConsensusTransactions for this validator's next blocks.
/// Implemented by val-authority (`authority/adapter.zig`), which also implements
/// consensus.iface.TransactionSource for the core.
pub const ConsensusSubmit = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const Priority = enum { system, user, soft_bundle };
    pub const Error = error{ Overloaded, EpochEnding, Unimplemented };
    pub const VTable = struct {
        /// `txs` are BCS ConsensusTransactions (copied). System messages (checkpoint signatures,
        /// DKG, JWK, EndOfPublish, capabilities) are never shed under load.
        submit: *const fn (ctx: *anyopaque, txs: []const []const u8, priority: Priority) Error!void,
    };
    pub fn submit(s: ConsensusSubmit, txs: []const []const u8, priority: Priority) Error!void {
        return s.vtable.submit(s.ctx, txs, priority);
    }
};

// ------------------------------------------------------------------ out of consensus

/// One committed ConsensusTransaction, decoded, with its position.
pub const Sequenced = struct {
    commit: consensus.types.CommitRef,
    block: consensus.types.BlockRef,
    index: consensus.types.TransactionIndex,
    tx: *const messages.ConsensusTransaction,
    /// Fast-path verdict for user transactions (rejected by a quorum: never executed).
    rejected: bool,
};

/// The consensus handler (sui-core `consensus_handler.rs`) hands every non-user consensus
/// transaction to its owner through this router, in commit order, on the handler thread.
/// Handlers must not block; they record into the epoch store's pending batch for this commit
/// (one atomic write per commit, val-epoch-api-keys).
pub const SystemTxRouter = struct {
    checkpoint_signature: CheckpointSignatureSink,
    randomness: RandomnessHooks,
    jwk: JwkHooks,
    epoch: EpochHooks,
};

// ------------------------------------------------------------------ checkpoints

/// sui-core checkpoints::CheckpointRoots / PendingCheckpoint (the consensus handler splits
/// commits into these, `split_checkpoints_in_consensus_handler` on mainnet 141).
pub const TransactionKey = union(enum) {
    digest: types.TransactionDigest,
    /// Randomness round whose RandomnessStateUpdate digest is not known yet.
    randomness_round: struct { epoch: u64, round: u64 },
    /// Accumulator settlement placeholder (epoch, checkpoint height).
    accumulator_settlement: struct { epoch: u64, height: u64 },
    consensus_commit_prologue: struct { epoch: u64, round: u64, sub_dag_index: u32 },
};

pub const CheckpointRoots = struct {
    tx_roots: []const TransactionKey,
    settlement_root: ?TransactionKey,
    height: u64,
};

pub const PendingCheckpointInfo = struct {
    timestamp_ms: u64,
    last_of_epoch: bool,
    checkpoint_height: u64,
    consensus_commit_ref: consensus.types.CommitRef,
    rejected_transactions_digest: types.Digest,
    checkpoint_seq: u64,
};

pub const PendingCheckpoint = struct {
    roots: []const CheckpointRoots,
    details: PendingCheckpointInfo,
};

/// Implemented by val-checkpoints' builder. Called by the consensus handler after the commit's
/// epoch-store batch is durable.
pub const PendingCheckpointSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        push: *const fn (ctx: *anyopaque, pending: *const PendingCheckpoint) error{ Full, Unimplemented }!void,
    };
    pub fn push(s: PendingCheckpointSink, pending: *const PendingCheckpoint) error{ Full, Unimplemented }!void {
        return s.vtable.push(s.ctx, pending);
    }
};

/// Implemented by val-checkpoints' aggregator: a sequenced CheckpointSignatureV2 from a peer.
pub const CheckpointSignatureSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        add: *const fn (ctx: *anyopaque, from: *const AuthorityName, msg: *const messages.CheckpointSignatureMessage) void,
    };
    pub fn add(s: CheckpointSignatureSink, from: *const AuthorityName, msg: *const messages.CheckpointSignatureMessage) void {
        s.vtable.add(s.ctx, from, msg);
    }
};

/// Where certified checkpoints this validator built go: the node's store and state sync (the
/// same path a full node's verified checkpoints take), plus epoch end detection.
pub const CertifiedSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// `summary_bcs` is BCS(CertifiedCheckpointSummary); `contents_bcs` BCS(CheckpointContents).
        certified: *const fn (ctx: *anyopaque, seq: u64, summary_bcs: []const u8, contents_bcs: []const u8) error{ Io, Unimplemented }!void,
    };
    pub fn certified(s: CertifiedSink, seq: u64, summary_bcs: []const u8, contents_bcs: []const u8) error{ Io, Unimplemented }!void {
        return s.vtable.certified(s.ctx, seq, summary_bcs, contents_bcs);
    }
};

// ------------------------------------------------------------------ randomness and JWK

pub const RandomnessHooks = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        dkg_message: *const fn (ctx: *anyopaque, from: *const AuthorityName, versioned_msg: []const u8) void,
        dkg_confirmation: *const fn (ctx: *anyopaque, from: *const AuthorityName, versioned_conf: []const u8) void,
        /// Called by the consensus handler once per commit: reserves the next randomness round
        /// if `commit_timestamp_ms` is at least random_beacon_min_round_interval_ms after the
        /// last one and DKG has completed. Returns the round to schedule, if any.
        reserve_next_round: *const fn (ctx: *anyopaque, commit_timestamp_ms: u64) ?u64,
        /// DKG failed or timed out (random_beacon_dkg_timeout_round): randomness transactions are
        /// cancelled for the epoch.
        dkg_failed: *const fn (ctx: *anyopaque) bool,
        /// After a restart: the last round reserved by a DURABLE commit; the next reservation
        /// must be `last + 1`. Reservations made by a commit that did not become durable are
        /// forgotten (the replayed commit reserves the same round again).
        restore_last_round: ?*const fn (ctx: *anyopaque, last: u64) void = null,
        /// Start of a commit, before `dkg_failed` / `reserve_next_round`: the commit's consensus
        /// round (the DKG timeout compares against it) and timestamp.
        begin_commit: ?*const fn (ctx: *anyopaque, round: u64, timestamp_ms: u64) void = null,
        /// After the commit's RandomnessDkgMessage / Confirmation were fed in: `advance_dkg` when
        /// Rust would run it (the hooks decide). May submit this validator's Confirmation.
        advance_dkg: ?*const fn (ctx: *anyopaque) void = null,
    };
};

pub const JwkHooks = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// A sequenced NewJWKFetched vote (`max_jwk_votes_per_validator_per_epoch` enforced
        /// here). Returns true when the JWK just reached validity stake and becomes active at
        /// this commit (the handler then schedules an AuthenticatorStateUpdate).
        vote: *const fn (ctx: *anyopaque, from: *const AuthorityName, id: *const types.JwkId, jwk: *const types.JWK, round: u64) bool,
    };
};

// ------------------------------------------------------------------ epoch

pub const EpochHooks = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        end_of_publish: *const fn (ctx: *anyopaque, from: *const AuthorityName) void,
        capabilities: *const fn (ctx: *anyopaque, caps: *const messages.AuthorityCapabilitiesV2) void,
        deny_config: *const fn (ctx: *anyopaque, cfg: *const messages.SharedTransactionDenyConfig) void,
    };
};

/// Read-only view of the current epoch every lane gets.
pub const EpochView = struct {
    epoch: u64,
    protocol_version: u64,
    chain_id: [8]u8,
    epoch_start_timestamp_ms: u64,
    /// Sui committee: (AuthorityName, voting power) in consensus AuthorityIndex order.
    committee: []const struct { AuthorityName, u64 },
    /// This validator's AuthorityIndex, or null when not in the committee (shadow).
    own_index: ?u32,
};

// ------------------------------------------------------------------ execution

/// Execution of sequenced transactions with consensus-assigned shared-object versions, backed by
/// the node's exec module. Implemented by val-authority (`authority/exec_bridge.zig`).
pub const TxExecutor = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const SharedVersion = struct { id: types.ObjectID, initial_shared_version: types.SequenceNumber, assigned: types.SequenceNumber };
    pub const VTable = struct {
        /// `tx_bcs`: BCS SenderSignedData or a system TransactionKind wrapped as Rust's
        /// VerifiedExecutableTransaction. Execution order follows the version DAG.
        enqueue: *const fn (ctx: *anyopaque, tx_bcs: []const u8, shared: []const SharedVersion) error{ Full, Unimplemented }!void,
        /// Effects digest once executed (null while pending).
        effects_digest: *const fn (ctx: *anyopaque, digest: *const types.TransactionDigest) ?types.Digest,
    };
};

// ------------------------------------------------------------------ latency

/// End-to-end stages for val-fast-finality's per-stage budget (docs/VALIDATOR-DESIGN.md 10).
pub const Stage = enum(u8) {
    tx_received,
    tx_validated,
    tx_submitted,
    tx_in_proposed_block,
    block_received,
    block_verified,
    leader_committed,
    sub_dag_finalized,
    tx_sequenced,
    tx_executed,
    checkpoint_built,
    checkpoint_signed,
    checkpoint_certified,
    effects_served,
};

pub const Tracer = struct {
    ctx: ?*anyopaque = null,
    vtable: ?*const VTable = null,
    pub const VTable = struct {
        mark: *const fn (ctx: *anyopaque, stage: Stage, key: *const [32]u8, mono_ns: u64) void,
    };
    pub fn mark(t: Tracer, stage: Stage, key: *const [32]u8, mono_ns: u64) void {
        if (t.vtable) |v| v.mark(t.ctx.?, stage, key, mono_ns);
    }
};

test {
    std.testing.refAllDecls(@This());
}
