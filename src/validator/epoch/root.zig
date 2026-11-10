//! val-epoch-api-keys, part 1: the validator epoch lifecycle at mainnet-v1.83.1
//! (docs/VALIDATOR-DESIGN.md 5.6). Sources: sui-core `authority/authority_per_epoch_store.rs`
//! (per-epoch tables; atomic per-commit consensus output batches as `consensus_quarantine.rs`),
//! `epoch/reconfiguration.rs` (ReconfigState: AcceptAllCerts -> RejectUserCerts ->
//! RejectAllCerts -> RejectAllTx), `consensus_handler.rs` (`handle_close_epoch`,
//! `advance_end_of_epoch_state_machine`), `authority.rs` `create_and_execute_advance_epoch_tx`
//! and `choose_protocol_version_and_system_packages_v2`, sui-node `lib.rs`
//! `monitor_reconfiguration` / `reconfigure_state`.
//!
//!   store.zig       per-epoch table store, one atomic checksummed record per consensus commit
//!   reconfig.zig    ReconfigState, EndOfPublish quorum, capabilities, close-epoch state machine,
//!                   protocol version vote
//!   endofepoch.zig  EndOfEpochTransaction / ChangeEpoch construction
//!   manager.zig     committee switch, epoch store close/open, safe mode, component restart
//!   capabilities.zig  this validator's CapabilityNotificationV2 (versions with digests)
//!   hooks.zig       iface.EpochHooks over an EpochState
//!   driver.zig      iface.CertifiedSink that switches epochs on the last checkpoint of an epoch
const store = @import("store.zig");
pub const reconfig = @import("reconfig.zig");
pub const endofepoch = @import("endofepoch.zig");
pub const capabilities = @import("capabilities.zig");
pub const manager = @import("manager.zig");
pub const hooks = @import("hooks.zig");
pub const driver = @import("driver.zig");
pub const announce = @import("announce.zig");
pub const vectors = @import("vectors.zig");
pub const Table = store.Table;
pub const Batch = store.Batch;
pub const TableStore = store.Store;
pub const ReconfigState = reconfig.ReconfigState;
pub const EpochState = reconfig.EpochState;
/// Name of the skeleton's type; open() now takes an `EpochInfo`.
pub const EpochStore = reconfig.EpochState;
pub const EpochInfo = reconfig.EpochInfo;
pub const EpochManager = manager.EpochManager;

pub const Error = reconfig.Error || endofepoch.Error;

test {
    @import("std").testing.refAllDecls(@This());
    _ = store;
}
