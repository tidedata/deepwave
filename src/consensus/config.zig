//! Consensus configuration at mainnet-v1.83.1. Owner lane: val-consensus-core.
//!
//! `ProtocolConfig` mirrors consensus_config::ConsensusProtocolConfig
//! (`consensus/config/src/consensus_protocol_config.rs`), filled from deepwave's `protocol` module by
//! the validator (`fromProtocol`), so the consensus module never imports the Move VM side.
//! `Parameters` mirrors consensus_config::Parameters (`parameters.rs`), the validator.yaml
//! `consensus-config.parameters` block; defaults are the non-test Rust defaults.
const std = @import("std");
const protocol = @import("protocol");

pub const ChainType = enum { unknown, mainnet, testnet };

pub const ProtocolConfig = struct {
    protocol_version: u64 = 0,
    chain: ChainType = .unknown,
    max_transaction_size_bytes: u64 = 256 * 1024,
    max_transactions_in_block_bytes: u64 = 512 * 1024,
    max_num_transactions_in_block: u64 = 512,
    /// consensus_gc_depth (mainnet 141: 60).
    gc_depth: u32 = 0,
    slim_block_propagation_enabled: bool = false,
    /// mysticeti_fastpath (mainnet 141: true) -> Block::V2.
    transaction_voting_enabled: bool = false,
    /// mysticeti_num_leaders_per_round (mainnet 141: 1).
    num_leaders_per_round: ?usize = null,
    /// consensus_bad_nodes_stake_threshold (mainnet 141: 30).
    bad_nodes_stake_threshold: u64 = 0,
    /// -> Block::V3, LeaderScheduleV3, FlexCommitter (off on mainnet 141).
    enable_v3: bool = false,
    leader_schedule_window_size: u32 = 600,
    leader_schedule_update_interval: u32 = 60,
    shuffle_commit_blocks: bool = false,

    /// `to_consensus_protocol_config` (sui-core/src/consensus_manager/mod.rs): transaction voting is
    /// always on, V3 off, leader schedule window 300 / interval 12 (V3 only, unused here), the rest
    /// from the protocol config at `protocol_version` on `chain`.
    pub fn fromProtocol(protocol_version: u64, chain: ChainType) error{UnsupportedVersion}!ProtocolConfig {
        const pchain: protocol.Chain = switch (chain) {
            .mainnet => .mainnet,
            .testnet => .testnet,
            .unknown => .unknown,
        };
        const cfg = try protocol.get(protocol_version, pchain);
        return .{
            .protocol_version = protocol_version,
            .chain = chain,
            .max_transaction_size_bytes = protocol.derived.maxTransactionSizeBytes(cfg),
            .max_transactions_in_block_bytes = protocol.derived.maxTransactionsInBlockBytes(cfg),
            .max_num_transactions_in_block = protocol.derived.maxNumTransactionsInBlock(cfg),
            .gc_depth = protocol.derived.gcDepth(cfg),
            .slim_block_propagation_enabled = cfg.feature_flags.consensus_slim_block_propagation,
            .transaction_voting_enabled = true,
            .num_leaders_per_round = protocol.derived.mysticetiNumLeadersPerRound(cfg),
            .bad_nodes_stake_threshold = cfg.consensus_bad_nodes_stake_threshold orelse 0,
            .enable_v3 = false,
            .leader_schedule_window_size = 300,
            .leader_schedule_update_interval = 12,
            .shuffle_commit_blocks = cfg.feature_flags.shuffle_consensus_commit_blocks,
        };
    }
};

/// Durations are nanoseconds.
pub const Parameters = struct {
    db_path: []const u8 = "",
    leader_timeout_ns: u64 = 200 * std.time.ns_per_ms,
    min_round_delay_ns: u64 = 50 * std.time.ns_per_ms,
    max_forward_time_drift_ns: u64 = 500 * std.time.ns_per_ms,
    max_blocks_per_sync: usize = 32,
    max_blocks_per_fetch: usize = 1000,
    sync_last_known_own_block_timeout_ns: u64 = 5 * std.time.ns_per_s,
    round_prober_interval_ms: u64 = 5_000,
    round_prober_request_timeout_ms: u64 = 4_000,
    propagation_delay_stop_proposal_threshold: u32 = 5,
    dag_state_cached_rounds: u32 = 500,
    commit_sync_parallel_fetches: usize = 8,
    commit_sync_batch_size: u32 = 100,
    commit_sync_batches_ahead: usize = 32,
    commit_sync_request_timeout_ns: u64 = 10 * std.time.ns_per_s,
    commit_sync_probe_timeout_ns: u64 = 2 * std.time.ns_per_s,
    tonic: Tonic = .{},
    /// Rust `parameters.internal.skip_equivocation_validation`: tests with equivocators only.
    skip_equivocation_validation: bool = false,

    pub const Tonic = struct {
        keepalive_interval_ns: u64 = 10 * std.time.ns_per_s,
        connection_buffer_size: usize = 32 << 20,
        excessive_message_size: usize = 16 << 20,
        message_size_limit: usize = 64 << 20,
    };
};

test "mainnet 141 maps to the consensus config the design lists" {
    const c = try ProtocolConfig.fromProtocol(141, .mainnet);
    try std.testing.expectEqual(@as(u32, 60), c.gc_depth);
    try std.testing.expect(c.transaction_voting_enabled);
    try std.testing.expectEqual(@as(?usize, 1), c.num_leaders_per_round);
    try std.testing.expectEqual(@as(u64, 30), c.bad_nodes_stake_threshold);
    try std.testing.expectEqual(@as(u64, 128), c.max_num_transactions_in_block);
    try std.testing.expectEqual(@as(u64, 294912), c.max_transactions_in_block_bytes);
    try std.testing.expectEqual(@as(u64, 262144), c.max_transaction_size_bytes);
    try std.testing.expect(!c.enable_v3);
}

test "shuffle_commit_blocks follows the chain at 141 (off on mainnet and testnet, on for localnets)" {
    // sui-protocol-config 1.83.1, version 140: shuffle_consensus_commit_blocks only when the chain
    // is neither Mainnet nor Testnet. Localnets (Chain::Unknown) linearize with the shuffle.
    try std.testing.expect(!(try ProtocolConfig.fromProtocol(141, .mainnet)).shuffle_commit_blocks);
    try std.testing.expect(!(try ProtocolConfig.fromProtocol(141, .testnet)).shuffle_commit_blocks);
    const local = try ProtocolConfig.fromProtocol(141, .unknown);
    try std.testing.expect(local.shuffle_commit_blocks);
    try std.testing.expect(!local.slim_block_propagation_enabled);
    try std.testing.expectEqual(@as(u32, 60), local.gc_depth);
    try std.testing.expect(!(try ProtocolConfig.fromProtocol(139, .unknown)).shuffle_commit_blocks);
}
