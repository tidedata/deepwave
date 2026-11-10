//! What the Validator gRPC server calls. The server (server.zig) owns framing, request decoding,
//! limits, overload protection, metrics and error rendering; a `Backend` owns the data:
//!
//!   - `submit` and `wait_for_effects` are val-authority's (`authority.Submit`): transaction
//!     validation, consensus submission, position tracking, effects waiting;
//!   - `object_info`, `transaction_info`, `checkpoint`, `checkpoint_v2` and `system_state` answer
//!     from the node's store and this validator's own checkpoint builder (`node_backend.zig` is the
//!     store-backed default for the first, second and last, and for certified checkpoints);
//!   - `health` reports the numbers `validator_health_impl` reports.
//!
//! Every reply is a value: `ok` or the `SuiErrorKind` the Rust server would put into the gRPC
//! status (code INTERNAL, message = Display, details = BCS of the error).
const std = @import("std");
const rpc_exec = @import("rpc_exec");
const wire = @import("wire.zig");

pub const sui_error = rpc_exec.driver.sui_error;
pub const SuiErrorKind = sui_error.SuiErrorKind;

pub fn Result(comptime T: type) type {
    return union(enum) {
        ok: T,
        err: SuiErrorKind,
    };
}

pub const SubmitRequest = struct {
    /// BCS Transactions (empty with `ping`).
    transactions: []const []const u8,
    ping: bool,
    soft_bundle: bool,
    /// Peer address text for traffic accounting (null when unknown).
    client: ?[]const u8,
    /// A `submit_type` that is not Default, Ping or SoftBundle. The backend answers
    /// ValidatorHaltedAtEpochEnd first when it is halted, otherwise
    /// GrpcMessageDeserializeError("unknown enumeration value N") (authority_server.rs order).
    invalid_submit_type: ?i32 = null,
};

pub const WaitRequest = struct {
    transaction_digest: ?[32]u8,
    /// BCS ConsensusPosition, as sent.
    consensus_position: ?[]const u8,
    include_details: bool,
    ping: bool,
    /// How long the handler may wait (sui-node: 20 s for effects, 10 s for pings).
    deadline_ms: u64 = 20_000,
};

pub const CheckpointQuery = struct {
    sequence_number: ?u64,
    request_content: bool,
    certified: bool,
};

pub const Backend = struct {
    ctx: *anyopaque,
    vt: *const VTable,

    pub const VTable = struct {
        submit: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: SubmitRequest) Result([]const wire.driver_wire.RawSubmitResult),
        wait_for_effects: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: WaitRequest) Result(wire.driver_wire.RawWaitResponse),
        /// BCS ObjectInfoResponse.
        object_info: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: wire.ObjectInfoRequest) Result([]const u8),
        /// BCS TransactionInfoResponse.
        transaction_info: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, digest: *const [32]u8) Result([]const u8),
        /// BCS CheckpointResponse (`v2 = false`) or CheckpointResponseV2.
        checkpoint: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, q: CheckpointQuery, v2: bool) Result([]const u8),
        /// BCS SuiSystemState.
        system_state: *const fn (ctx: *anyopaque, arena: std.mem.Allocator) Result([]const u8),
        health: *const fn (ctx: *anyopaque) wire.Health,
    };

    pub fn submit(b: Backend, arena: std.mem.Allocator, req: SubmitRequest) Result([]const wire.driver_wire.RawSubmitResult) {
        return b.vt.submit(b.ctx, arena, req);
    }
    pub fn waitForEffects(b: Backend, arena: std.mem.Allocator, req: WaitRequest) Result(wire.driver_wire.RawWaitResponse) {
        return b.vt.wait_for_effects(b.ctx, arena, req);
    }
    pub fn objectInfo(b: Backend, arena: std.mem.Allocator, req: wire.ObjectInfoRequest) Result([]const u8) {
        return b.vt.object_info(b.ctx, arena, req);
    }
    pub fn transactionInfo(b: Backend, arena: std.mem.Allocator, digest: *const [32]u8) Result([]const u8) {
        return b.vt.transaction_info(b.ctx, arena, digest);
    }
    pub fn checkpoint(b: Backend, arena: std.mem.Allocator, q: CheckpointQuery, v2: bool) Result([]const u8) {
        return b.vt.checkpoint(b.ctx, arena, q, v2);
    }
    pub fn systemState(b: Backend, arena: std.mem.Allocator) Result([]const u8) {
        return b.vt.system_state(b.ctx, arena);
    }
    pub fn health(b: Backend) wire.Health {
        return b.vt.health(b.ctx);
    }
};

/// The part of val-authority that serves SubmitTransaction and WaitForEffects. `NodeBackend`
/// forwards to it; null answers with an explicit "not attached" error.
pub const Authority = struct {
    ctx: *anyopaque,
    submit: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: SubmitRequest) Result([]const wire.driver_wire.RawSubmitResult),
    wait_for_effects: *const fn (ctx: *anyopaque, arena: std.mem.Allocator, req: WaitRequest) Result(wire.driver_wire.RawWaitResponse),
    health: *const fn (ctx: *anyopaque) wire.Health,
};

pub fn unsupported(comptime what: []const u8) SuiErrorKind {
    return .{ .UnsupportedFeatureError = .{ .@"error" = .{ .@"0" = what } } };
}

pub fn objectNotFound(id: *const [32]u8, version: ?u64) SuiErrorKind {
    return .{ .UserInputError = .{ .@"error" = .{ .ObjectNotFound = .{
        .object_id = .{ .@"0" = .{ .@"0" = id.* } },
        .version = if (version) |v| .{ .@"0" = v } else null,
    } } } };
}

pub fn storageError(text: []const u8) SuiErrorKind {
    return .{ .Storage = .{ .@"0" = text } };
}
