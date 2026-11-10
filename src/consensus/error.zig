//! consensus_core::error::ConsensusError at mainnet-v1.83.1, the subset the core and network
//! act on. Protocol-visible verdicts on peer input (an invalid block) are values
//! (`BlockVerdict`), never Zig errors; Zig errors mean "cannot proceed". Owner: val-consensus-core.
const types = @import("types.zig");

/// Why a peer block is rejected (BlockVerifier). Mirrors the ConsensusError variants
/// `block_verifier.rs` returns, in the same order of checks.
pub const BlockReject = union(enum) {
    wrong_epoch: struct { expected: types.Epoch, actual: types.Epoch },
    genesis_block,
    invalid_authority_index: types.AuthorityIndex,
    malformed_signature,
    signature_verification_failure,
    too_many_ancestors: usize,
    insufficient_parent_stake,
    invalid_ancestor_position,
    invalid_ancestor_round,
    duplicated_ancestors_authority: types.AuthorityIndex,
    invalid_genesis_ancestor,
    transaction_too_large,
    too_many_transactions,
    too_many_transaction_bytes,
    invalid_transaction,
    invalid_transaction_votes,
    too_many_commit_votes,
    invalid_misbehavior_report,
    malformed_block,
    unexpected_block_version,
    invalid_transaction_votes_cutoff,
};

pub const BlockVerdict = union(enum) {
    ok,
    reject: BlockReject,
};

/// Errors that stop an operation (not verdicts).
pub const Error = error{
    Unimplemented,
    /// A block the DAG must hold (above the GC round) is not in memory or the store.
    MissingBlock,
    /// An invariant Rust asserts (and would panic on) does not hold. The caller stops consensus.
    Invariant,
    /// Protocol features deepwave does not implement (V3 consensus).
    Unsupported,
    /// A certified commit does not directly follow the last local commit.
    CommitIndexGap,
    /// The BlockSigner refused (watermark: this round was already signed) or failed.
    SignRefused,
    OutOfMemory,
    StoreCorrupt,
    StoreIo,
    Shutdown,
    SerializationFailure,
};
