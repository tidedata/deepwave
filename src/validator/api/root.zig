//! val-epoch-api-keys, part 2: the `sui.validator.Validator` gRPC service at mainnet-v1.83.1
//! (docs/VALIDATOR-DESIGN.md 5.6). Sources: sui-network `build.rs` (package sui.validator,
//! service Validator; methods SubmitTransaction, WaitForEffects, ObjectInfo, TransactionInfo,
//! Checkpoint, CheckpointV2, GetSystemStateObject, ValidatorHealth; BcsCodec except where
//! `use_prost`), sui-types `messages_grpc.rs`, sui-core `authority_server.rs` (ValidatorService,
//! traffic control, load shedding), `overload_monitor.rs`.
//!
//!   server.zig        the h2c server, method dispatch, `/metrics` endpoint
//!   wire.zig          request decoders and BCS response framing (driver wire is the prost truth)
//!   backend.zig       the Backend interface (val-authority and the node store implement it)
//!   node_backend.zig  store-backed ObjectInfo, TransactionInfo, Checkpoint(V2), system state
//!   overload.zig      overload protection (monitor math, per-transaction shedding, queue checks)
//!   metrics.zig       validator metric names and Prometheus rendering
//! The handlers for SubmitTransaction/WaitForEffects are val-authority's (`backend.Authority`).
pub const server = @import("server.zig");
pub const wire = @import("wire.zig");
pub const backend = @import("backend.zig");
pub const node_backend = @import("node_backend.zig");
pub const overload = @import("overload.zig");
pub const metrics = @import("metrics.zig");

pub const service_path = server.service_path;
pub const Method = server.Method;
pub const Error = server.Error;
pub const Server = server.Server;
pub const MetricsServer = server.MetricsServer;
pub const Backend = backend.Backend;
pub const NodeBackend = node_backend.NodeBackend;

test {
    @import("std").testing.refAllDecls(@This());
    _ = @import("server_test.zig");
}
