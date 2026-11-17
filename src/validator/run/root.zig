//! `deepwave-validator run`: the integrated validator (docs/VALIDATOR-STATUS.md). Composes every lane
//! around one epoch at a time:
//!
//!   consensus (core + net) -> authority (TxValidator votes, adapter, handler) -> execution
//!   (runner over the exec store) -> checkpoints (builder, signer, aggregator) -> epoch driver,
//!   with randomness (DKG through consensus, partial signatures over anemo) and JWK beside it.
//!
//! Files (one owner each while the integration lanes run in parallel; docs/VALIDATOR-STATUS.md):
//!   genesis.zig, exec_store.zig, runner.zig, objects.zig, zklogin.zig,
//!   ckpt_env.zig, ckpt_store.zig ............ execution side (exec store, runner, builder Env)
//!   p2p.zig ................................. the seat's anemo endpoint (one per p2p address)
//!   state_sync.zig, catchup.zig ............. sui.StateSync + sui.Discovery served, catch-up client
//!   randomness_net.zig ...................... sui.Randomness/SendSignatures over anemo
//!   load.zig, signcheck.zig ................. load generator and the double-sign audit
//!   runtime.zig ............................. per-epoch composition and threads
const std = @import("std");

// --- modules (each lane adds its own line here) ---
pub const epoch_control = @import("epoch_control.zig");
pub const load = @import("load.zig");
pub const signcheck = @import("signcheck.zig");
pub const randomness_net = @import("randomness_net.zig");
pub const catchup = @import("catchup.zig");
pub const p2p = @import("p2p.zig");
pub const state_sync = @import("state_sync.zig");
pub const genesis = @import("genesis.zig");
pub const exec_store = @import("exec_store.zig");
pub const objects = @import("objects.zig");
pub const zklogin = @import("zklogin.zig");
pub const runner = @import("runner.zig");
pub const ckpt_env = @import("ckpt_env.zig");
pub const ckpt_store = @import("ckpt_store.zig");
pub const exec_e2e_test = @import("exec_e2e_test.zig");
pub const settle_vectors_test = @import("settle_vectors_test.zig");
pub const runtime = @import("runtime.zig");

test {
    std.testing.refAllDecls(@This());
}
