//! Mysticeti wire and storage types, equal to Mysten's consensus crates at mainnet-v1.83.1
//! (`consensus/types/src/block.rs`, `consensus/core/src/block.rs`, `consensus/core/src/commit.rs`,
//! `consensus/config/src/committee.rs`). Field order and enum variant order are the serde order,
//! so `bcs.encode` / `bcs.decode` of these types give Rust's bytes. Owner lane: val-consensus-core.
//!
//! Shapes declared here are the contract every validator lane codes against
//! (docs/VALIDATOR-DESIGN.md section 4). Change them only together with the design doc.
const std = @import("std");
const core = @import("core");

/// consensus_types::block::Round
pub const Round = u32;
/// consensus_types::block::BlockTimestampMs
pub const BlockTimestampMs = u64;
/// consensus_types::block::TransactionIndex
pub const TransactionIndex = u16;
/// consensus_config::AuthorityIndex(u32): a serde newtype, so plain u32 on the wire.
pub const AuthorityIndex = u32;
/// consensus_config::Epoch / Stake
pub const Epoch = u64;
pub const Stake = u64;
/// consensus_core::CommitIndex. First commit after genesis is 1.
pub const CommitIndex = u32;

pub const GENESIS_ROUND: Round = 0;
/// consensus_types::block::NUM_RESERVED_TRANSACTION_INDICES
pub const NUM_RESERVED_TRANSACTION_INDICES: TransactionIndex = 8;
/// consensus_types::block::PING_TRANSACTION_INDEX
pub const PING_TRANSACTION_INDEX: TransactionIndex = std.math.maxInt(TransactionIndex);
/// consensus_core::commit::MINIMUM_WAVE_LENGTH
pub const MINIMUM_WAVE_LENGTH: Round = 3;
/// consensus_config::DIGEST_LENGTH (Blake2b256)
pub const DIGEST_LENGTH = 32;

/// consensus_types::block::BlockDigest: Blake2b256 over the BCS bytes of the SignedBlock.
pub const BlockDigest = [DIGEST_LENGTH]u8;
/// consensus_core::commit::CommitDigest: Blake2b256 over the BCS bytes of the Commit.
pub const CommitDigest = [DIGEST_LENGTH]u8;

pub const block_digest_min: BlockDigest = @splat(0);
pub const block_digest_max: BlockDigest = @splat(0xff);

/// consensus_types::block::BlockRef. Ordered by (round, author, digest), the derived Ord.
pub const BlockRef = struct {
    round: Round,
    author: AuthorityIndex,
    digest: BlockDigest,

    pub const MIN: BlockRef = .{ .round = 0, .author = 0, .digest = block_digest_min };
    pub const MAX: BlockRef = .{ .round = std.math.maxInt(Round), .author = std.math.maxInt(AuthorityIndex), .digest = block_digest_max };

    pub fn order(a: BlockRef, b: BlockRef) std.math.Order {
        if (a.round != b.round) return std.math.order(a.round, b.round);
        if (a.author != b.author) return std.math.order(a.author, b.author);
        return std.mem.order(u8, &a.digest, &b.digest);
    }
    pub fn eql(a: BlockRef, b: BlockRef) bool {
        return a.round == b.round and a.author == b.author and std.mem.eql(u8, &a.digest, &b.digest);
    }
};

/// consensus_core::block::Slot (not serialized): one (round, authority) position in the DAG.
pub const Slot = struct {
    round: Round,
    authority: AuthorityIndex,
};

/// consensus_core::block::Transaction { data: Bytes }. An opaque, BCS-encoded
/// sui_types::messages_consensus::ConsensusTransaction to the validator.
pub const Transaction = struct {
    data: []const u8,
};

/// consensus_core::block::BlockTransactionVotes: the fast-path reject votes one block casts on
/// the transactions of an earlier block.
pub const BlockTransactionVotes = struct {
    block_ref: BlockRef,
    rejects: []const TransactionIndex,
};

/// consensus_core::commit::CommitRef. `CommitVote` is the same type.
pub const CommitRef = struct {
    index: CommitIndex,
    digest: CommitDigest,
};
pub const CommitVote = CommitRef;

/// consensus_core::block::MisbehaviorProof
pub const MisbehaviorProof = union(enum) {
    InvalidBlock: BlockRef,
};

/// consensus_core::block::MisbehaviorReport
pub const MisbehaviorReport = struct {
    target: AuthorityIndex,
    proof: MisbehaviorProof,
};

/// consensus_core::block::BlockV1
pub const BlockV1 = struct {
    epoch: Epoch,
    round: Round,
    author: AuthorityIndex,
    timestamp_ms: BlockTimestampMs,
    ancestors: []const BlockRef,
    transactions: []const Transaction,
    commit_votes: []const CommitVote,
    misbehavior_reports: []const MisbehaviorReport,
};

/// consensus_core::block::BlockV2 (mainnet at protocol 141: transaction voting is on, V3 is not).
pub const BlockV2 = struct {
    epoch: Epoch,
    round: Round,
    author: AuthorityIndex,
    timestamp_ms: BlockTimestampMs,
    ancestors: []const BlockRef,
    transactions: []const Transaction,
    transaction_votes: []const BlockTransactionVotes,
    commit_votes: []const CommitVote,
    misbehavior_reports: []const MisbehaviorReport,
};

/// consensus_core::block::BlockV3
pub const BlockV3 = struct {
    epoch: Epoch,
    round: Round,
    author: AuthorityIndex,
    timestamp_ms: BlockTimestampMs,
    ancestors: []const BlockRef,
    transactions: []const Transaction,
    transaction_votes: []const BlockTransactionVotes,
    transaction_votes_cutoff_round: Round,
    commit_votes: []const CommitVote,
    misbehavior_reports: []const MisbehaviorReport,
};

/// consensus_core::block::Block. Rust's BlockAPI accessors are the methods below.
pub const Block = union(enum) {
    V1: BlockV1,
    V2: BlockV2,
    V3: BlockV3,

    pub fn epoch(b: *const Block) Epoch {
        return switch (b.*) {
            inline else => |v| v.epoch,
        };
    }
    pub fn round(b: *const Block) Round {
        return switch (b.*) {
            inline else => |v| v.round,
        };
    }
    pub fn author(b: *const Block) AuthorityIndex {
        return switch (b.*) {
            inline else => |v| v.author,
        };
    }
    pub fn slot(b: *const Block) Slot {
        return .{ .round = b.round(), .authority = b.author() };
    }
    pub fn timestampMs(b: *const Block) BlockTimestampMs {
        return switch (b.*) {
            inline else => |v| v.timestamp_ms,
        };
    }
    pub fn ancestors(b: *const Block) []const BlockRef {
        return switch (b.*) {
            inline else => |v| v.ancestors,
        };
    }
    pub fn transactions(b: *const Block) []const Transaction {
        return switch (b.*) {
            inline else => |v| v.transactions,
        };
    }
    pub fn transactionVotes(b: *const Block) []const BlockTransactionVotes {
        return switch (b.*) {
            .V1 => &.{},
            inline .V2, .V3 => |v| v.transaction_votes,
        };
    }
    pub fn transactionVotesCutoffRound(b: *const Block) Round {
        return switch (b.*) {
            .V1, .V2 => GENESIS_ROUND,
            .V3 => |v| v.transaction_votes_cutoff_round,
        };
    }
    pub fn commitVotes(b: *const Block) []const CommitVote {
        return switch (b.*) {
            inline else => |v| v.commit_votes,
        };
    }
    pub fn misbehaviorReports(b: *const Block) []const MisbehaviorReport {
        return switch (b.*) {
            inline else => |v| v.misbehavior_reports,
        };
    }
};

/// consensus_core::block::SignedBlock { inner: Block, signature: Bytes }. The signature is the
/// author's Ed25519 protocol-key signature over
/// BCS(IntentMessage(Intent{ConsensusBlock=8, V0, Consensus=2}, InnerBlockDigest)), where
/// InnerBlockDigest = Blake2b256(BCS(Block)). Genesis blocks carry an empty signature.
pub const SignedBlock = struct {
    inner: Block,
    signature: []const u8,
};

/// consensus_core::block::VerifiedBlock (not serialized): a SignedBlock that passed the
/// BlockVerifier, with its serialized bytes and digest = Blake2b256(serialized). Borrowed bytes:
/// `serialized` is the exact wire/storage form and `block` is decoded from it in an arena.
pub const VerifiedBlock = struct {
    block: SignedBlock,
    serialized: []const u8,
    digest: BlockDigest,

    pub fn reference(v: *const VerifiedBlock) BlockRef {
        return .{ .round = v.block.inner.round(), .author = v.block.inner.author(), .digest = v.digest };
    }
};

/// consensus_core::block::ExtendedBlock: a verified block and the ancestors the proposer
/// excluded (sent to subscribers so they can track ancestor scoring).
pub const ExtendedBlock = struct {
    block: VerifiedBlock,
    excluded_ancestors: []const BlockRef,
};

/// consensus_core::commit::CommitV1
pub const CommitV1 = struct {
    index: CommitIndex,
    previous_digest: CommitDigest,
    timestamp_ms: BlockTimestampMs,
    leader: BlockRef,
    blocks: []const BlockRef,
};

/// consensus_core::commit::Commit
pub const Commit = union(enum) {
    V1: CommitV1,

    pub fn index(c: *const Commit) CommitIndex {
        return c.V1.index;
    }
    pub fn round(c: *const Commit) Round {
        return c.V1.leader.round;
    }
    pub fn leader(c: *const Commit) BlockRef {
        return c.V1.leader;
    }
};

/// consensus_core::commit::TrustedCommit (not serialized): a commit produced locally or certified
/// by a quorum, with its serialized bytes and digest = Blake2b256(serialized).
pub const TrustedCommit = struct {
    commit: Commit,
    serialized: []const u8,
    digest: CommitDigest,

    pub fn reference(t: *const TrustedCommit) CommitRef {
        return .{ .index = t.commit.index(), .digest = t.digest };
    }
};

/// consensus_core::leader_scoring::ReputationScores (stored inside CommitInfo).
pub const ReputationScores = struct {
    scores_per_authority: []const u64,
    commit_range: CommitRange,
};

/// consensus_core::commit::CommitRange: serialized as Rust's `Range<u32>` {start, end}, with an
/// exclusive end on the wire; the API is inclusive (`start()`, `end() = wire_end - 1`).
pub const CommitRange = struct {
    start: CommitIndex,
    end_exclusive: CommitIndex,

    pub fn inclusive(first: CommitIndex, last_index: CommitIndex) CommitRange {
        return .{ .start = first, .end_exclusive = last_index +| 1 };
    }
    pub fn last(r: CommitRange) CommitIndex {
        return r.end_exclusive -| 1;
    }
    pub fn size(r: CommitRange) usize {
        return r.end_exclusive - r.start;
    }
};

/// consensus_core::commit::CommitInfo (stored, recovery only).
pub const CommitInfo = struct {
    committed_rounds: []const Round,
    reputation_scores: ReputationScores,
};

/// consensus_core::commit::DecidedLeader (not serialized): the committer's decision for one
/// leader slot.
pub const DecidedLeader = union(enum) {
    /// The leader block and whether it was decided directly.
    commit: struct { block: *const VerifiedBlock, direct: bool },
    skip: Slot,
};

/// consensus_core::commit::CertifiedCommit (not serialized): a synced commit certified by a quorum,
/// with its blocks in commit order (the leader is last).
pub const CertifiedCommit = struct {
    commit: TrustedCommit,
    blocks: []const VerifiedBlock,
};

/// consensus_core::commit::CommittedSubDag (not serialized): the output of consensus to the
/// validator, one per commit, in commit index order.
pub const CommittedSubDag = struct {
    leader: BlockRef,
    /// Linearized blocks of the sub-dag, in commit order.
    blocks: []const VerifiedBlock,
    timestamp_ms: BlockTimestampMs,
    commit_ref: CommitRef,
    decided_with_local_blocks: bool,
    recovered_rejected_transactions: bool,
    /// Fast-path rejected transactions per block (block ref, indices), sorted by block ref.
    rejected_transactions_by_block: []const RejectedInBlock,
};

pub const RejectedInBlock = struct {
    block: BlockRef,
    indices: []const TransactionIndex,
};

test "BlockRef order matches the derived Rust Ord" {
    const a: BlockRef = .{ .round = 1, .author = 2, .digest = @splat(0) };
    const b: BlockRef = .{ .round = 1, .author = 3, .digest = @splat(0) };
    try std.testing.expect(a.order(b) == .lt);
    try std.testing.expect(BlockRef.MIN.order(BlockRef.MAX) == .lt);
    _ = core;
}

test "CommitRange keeps Rust's exclusive wire end" {
    const r = CommitRange.inclusive(5, 9);
    try std.testing.expectEqual(@as(CommitIndex, 10), r.end_exclusive);
    try std.testing.expectEqual(@as(CommitIndex, 9), r.last());
    try std.testing.expectEqual(@as(usize, 5), r.size());
}
