//! rpc_exec (lane rpc-exec, Wave C, CONTRACTS 6.7): sui.rpc.v2 TransactionExecutionService.
//! SimulateTransaction runs a transaction against a pre-state without committing anything;
//! ExecuteTransaction submits a signed transaction to validators and returns certified effects.
const std = @import("std");
const protocol = @import("protocol");
const store = @import("store");

pub const conformance = @import("conformance.zig");
pub const state = @import("state.zig");
pub const simulate = @import("simulate.zig");
pub const resolve = @import("resolve.zig");
pub const remote = @import("remote.zig");
pub const epoch_env = @import("epoch_env.zig");
pub const congestion = @import("congestion.zig");
pub const checks = @import("checks.zig");
pub const render = @import("render.zig");
pub const failure = @import("failure.zig");
pub const pool = @import("pool.zig");
pub const deny = @import("deny.zig");
pub const txdeny = @import("txdeny.zig");
pub const service = @import("service.zig");
pub const driver = @import("driver/root.zig");
pub const live = @import("live/root.zig");
pub const reply = @import("reply.zig");
pub const Reply = reply.Reply;
pub const RpcError = reply.RpcError;

pub const State = state.State;

/// What the handler reads from the epoch store and the system state.
pub const EpochEnv = struct {
    /// Digest of checkpoint 0 (the chain identifier).
    chain_id: [32]u8,
    epoch: u64,
    pv: u64,
    cfg: *const protocol.ProtocolConfig,
    rgp: u64,
    epoch_start_ms: u64,
    committee_size: u32,
};

test {
    std.testing.refAllDecls(@This());
    _ = live;
}
