//! val-authority: validator transaction handling at mainnet-v1.83.1 (docs/VALIDATOR-DESIGN.md
//! 5.3). Sources: sui-core `authority_server.rs` (SubmitTransaction, WaitForEffects),
//! `consensus_adapter.rs`, `consensus_validator.rs` (SuiTxValidator: block transaction checks
//! and fast-path reject votes), `consensus_handler.rs` (commit -> sequenced transactions,
//! dedup, deferral, congestion control, cancellation, consensus commit prologue, randomness
//! scheduling, PendingCheckpoint split), `authority_per_epoch_store.rs`
//! (`try_acquire_owned_object_locks_post_consensus`: one lock per owned ObjectRef per epoch,
//! taken after sequencing, `disable_preconsensus_locking` on mainnet 141),
//! `shared_object_version_manager.rs`, `shared_object_congestion_tracker.rs`,
//! `transaction_deferral.rs`, `execution_time_estimator.rs`, `post_consensus_tx_reorder.rs`.
const std = @import("std");

pub const codec = @import("codec.zig");
pub const usertx = @import("tx.zig");
pub const epoch_log = @import("epoch_log.zig");
pub const state = @import("state.zig");
pub const versions = @import("versions.zig");
pub const deferral = @import("deferral.zig");
pub const congestion = @import("congestion.zig");
pub const env = @import("env.zig");
pub const exec_bridge = @import("exec_bridge.zig");
pub const checker = @import("checker.zig");
pub const tx_validator = @import("tx_validator.zig");
pub const adapter = @import("adapter.zig");
pub const status = @import("status.zig");
pub const handler = @import("handler.zig");
pub const submit = @import("submit.zig");
pub const preverify = @import("preverify.zig");
pub const presteps = @import("presteps.zig");
pub const preverify_fixture = @import("preverify_fixture.zig");
pub const locks = @import("locks.zig");
pub const sim_runner = @import("sim_runner.zig");
pub const authority = @import("authority.zig");

/// Skeleton names kept for the other lanes (docs/VALIDATOR-DESIGN.md 5.3).
/// SubmitTransaction / WaitForEffects (`authority_server.rs`).
pub const Submit = submit.Submit;
pub const WaitForEffects = submit.WaitForEffects;
/// consensus_adapter: `iface.ConsensusSubmit` + `consensus.iface.TransactionSource`.
pub const Adapter = adapter.Adapter;
/// consensus_validator::SuiTxValidator: `consensus.iface.TransactionVerifier`.
pub const TxValidator = tx_validator.TxValidator;
/// consensus_handler::ConsensusHandler: `consensus.iface.CommitSink`.
pub const Handler = handler.Handler;
/// The composition root of one epoch (`authority.Authority`).
pub const Authority = authority.Authority;
/// Owned-object locks for one commit over the epoch state.
pub const OwnedLocks = locks.OwnedLocks;
/// exec_bridge: `iface.TxExecutor` over the node's executor.
pub const ExecBridge = exec_bridge.Bridge;

test {
    std.testing.refAllDecls(@This());
    _ = codec;
    _ = usertx;
    _ = epoch_log;
    _ = state;
    _ = versions;
    _ = deferral;
    _ = congestion;
    _ = env;
    _ = exec_bridge;
    _ = checker;
    _ = tx_validator;
    _ = adapter;
    _ = status;
    _ = handler;
    _ = submit;
    _ = preverify;
    _ = presteps;
    _ = locks;
    _ = sim_runner;
    _ = authority;
    _ = @import("handler_test.zig");
    _ = @import("tx_validator_test.zig");
    _ = @import("preverify_test.zig");
    _ = @import("consensus_vectors_test.zig");
}
