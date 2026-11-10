//! The seams between consensus and the rest of the validator (docs/VALIDATOR-DESIGN.md 4.3).
//! Reviewer/validator-base owned: lanes implement these, they do not change them alone.
//!
//! All are small vtables so the core stays sans-I/O and testable with fakes, and so the
//! validator can hand in the gate-checked signer without consensus ever touching key bytes.
const std = @import("std");
const types = @import("types.zig");

/// consensus_core::TransactionVerifier, implemented by the validator (val-authority,
/// `authority/tx_validator.zig`, after sui-core `consensus_validator.rs` SuiTxValidator).
/// Called on every peer block's transactions before the block is accepted.
pub const TransactionVerifier = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Whole-batch checks (sizes, decodable ConsensusTransactions, allowed kinds for the
        /// epoch, allowed proposers against `block.author`). An error rejects the whole block
        /// (ValidationError in Rust). Rust `verify_batch(&BlockRef, ...)`.
        verify_batch: *const fn (ctx: *anyopaque, block: types.BlockRef, txs: []const types.Transaction) VerifyError!void,
        /// Fast-path votes: indices of transactions this validator rejects (owned-object
        /// conflicts, invalid signatures, deny list). Writes into `out`, returns the count.
        verify_and_vote_batch: *const fn (ctx: *anyopaque, block: types.BlockRef, txs: []const types.Transaction, out: []types.TransactionIndex) VerifyError!usize,
    };

    pub const VerifyError = error{ InvalidTransaction, Unimplemented };

    pub fn verifyBatch(v: TransactionVerifier, block: types.BlockRef, txs: []const types.Transaction) VerifyError!void {
        return v.vtable.verify_batch(v.ctx, block, txs);
    }
    pub fn verifyAndVoteBatch(v: TransactionVerifier, block: types.BlockRef, txs: []const types.Transaction, out: []types.TransactionIndex) VerifyError!usize {
        return v.vtable.verify_and_vote_batch(v.ctx, block, txs, out);
    }
};

/// Signs this authority's blocks. Implemented by `validator/signer.zig` (the only holder of the
/// protocol key). The signer persists the (epoch, round) watermark before it returns, and refuses
/// a second signature for a round it already signed: equivocation is impossible by construction.
pub const BlockSigner = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// `message` is BCS(IntentMessage(Intent{ConsensusBlock, V0, Consensus}, InnerBlockDigest)).
        sign_block: *const fn (ctx: *anyopaque, epoch: types.Epoch, round: types.Round, message: []const u8) SignError![64]u8,
    };
    pub const SignError = error{ AlreadySigned, Refused, Io, Unimplemented };

    pub fn signBlock(s: BlockSigner, epoch: types.Epoch, round: types.Round, message: []const u8) SignError![64]u8 {
        return s.vtable.sign_block(s.ctx, epoch, round, message);
    }
};

/// Where committed sub-dags go: consensus_core::CommitConsumer. The validator's consensus
/// handler (val-authority) implements it. Called on the core thread in commit index order;
/// must not block (push to a ring and return). Returns false when the ring is full, and the core
/// retries on its next tick (backpressure, as Rust's bounded channel).
pub const CommitSink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        push: *const fn (ctx: *anyopaque, sub_dag: *const types.CommittedSubDag) bool,
        /// Highest commit index the consumer has fully processed (for replay after restart:
        /// consensus re-sends commits after this index).
        processed_through: *const fn (ctx: *anyopaque) types.CommitIndex,
    };

    pub fn push(s: CommitSink, sub_dag: *const types.CommittedSubDag) bool {
        return s.vtable.push(s.ctx, sub_dag);
    }
    pub fn processedThrough(s: CommitSink) types.CommitIndex {
        return s.vtable.processed_through(s.ctx);
    }
};

/// Pulls transactions for the next proposal: consensus_core::TransactionClient /
/// TransactionConsumer. The validator's consensus adapter (val-authority) fills it.
pub const TransactionSource = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Copies up to `max_count` transactions totalling at most `max_bytes` into `out`
        /// (slices stay valid until `ack`). Returns the count.
        next: *const fn (ctx: *anyopaque, out: []types.Transaction, max_bytes: u64) usize,
        /// The proposal that carried the last `next` batch was included in `block`.
        ack: *const fn (ctx: *anyopaque, block: types.BlockRef) void,
    };

    pub fn next(s: TransactionSource, out: []types.Transaction, max_bytes: u64) usize {
        return s.vtable.next(s.ctx, out, max_bytes);
    }
    pub fn ack(s: TransactionSource, block: types.BlockRef) void {
        s.vtable.ack(s.ctx, block);
    }
};

/// Monotonic and wall clocks, injected so the core can run under deterministic simulation.
pub const Clock = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        now_ms: *const fn (ctx: *anyopaque) u64,
        mono_ns: *const fn (ctx: *anyopaque) u64,
    };
    pub fn nowMs(c: Clock) u64 {
        return c.vtable.now_ms(c.ctx);
    }
    pub fn monoNs(c: Clock) u64 {
        return c.vtable.mono_ns(c.ctx);
    }
};

/// Per-stage latency marks (val-fast-finality's tracer). A null tracer costs one branch.
pub const Tracer = struct {
    ctx: ?*anyopaque = null,
    vtable: ?*const VTable = null,

    pub const Stage = enum(u8) {
        block_received,
        block_verified,
        block_accepted,
        block_proposed,
        leader_committed,
        sub_dag_emitted,
    };
    pub const VTable = struct {
        mark: *const fn (ctx: *anyopaque, stage: Stage, ref: types.BlockRef, mono_ns: u64) void,
    };
    pub fn mark(t: Tracer, stage: Stage, ref: types.BlockRef, mono_ns: u64) void {
        if (t.vtable) |v| v.mark(t.ctx.?, stage, ref, mono_ns);
    }
};

test {
    std.testing.refAllDecls(@This());
}
