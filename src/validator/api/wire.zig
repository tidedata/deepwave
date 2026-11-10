//! Request decoders and BCS framing for `sui.validator.Validator` (server side). Truth:
//! sui-types `messages_grpc.rs` (prost `Raw*` messages for SubmitTransaction, WaitForEffects and
//! ValidatorHealth; BcsCodec for ObjectInfo, TransactionInfo, Checkpoint, CheckpointV2,
//! GetSystemStateObject) and `messages_checkpoint.rs`. The response encoders of the two
//! SubmitTransaction/WaitForEffects messages are the driver's (`rpc_exec.driver.wire`), which is the
//! byte truth the client side already tests against.
//!
//! prost rules on decode: unknown fields are skipped, a scalar given twice takes the last value,
//! repeated bytes append. BCS rules: the whole body must be consumed (`bcs::from_bytes` rejects
//! trailing bytes), and BcsCodec has no length prefix of its own beyond the gRPC frame.
const std = @import("std");
const serve = @import("serve");
const rpc_exec = @import("rpc_exec");
const proto = serve.proto;
pub const driver_wire = rpc_exec.driver.wire;

pub const Malformed = error{Malformed};

// ------------------------------------------------------------------ prost requests

pub const submit_type_default: i32 = 0;
pub const submit_type_ping: i32 = 1;
pub const submit_type_soft_bundle: i32 = 2;

pub const SubmitTxRequest = struct {
    transactions: []const []const u8,
    submit_type: i32 = submit_type_default,
};

/// `RawSubmitTxRequest`. Unknown `submit_type` values stay as given (the handler rejects them).
pub fn decodeSubmitTxRequest(arena: std.mem.Allocator, body: []const u8) (Malformed || error{OutOfMemory})!SubmitTxRequest {
    var txs: std.ArrayList([]const u8) = .empty;
    var out: SubmitTxRequest = .{ .transactions = &.{} };
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => try txs.append(arena, proto.Reader.bytesOf(f) catch return error.Malformed),
        2 => out.submit_type = @truncate(@as(i64, @bitCast(proto.Reader.varintOf(f) catch return error.Malformed))),
        else => {},
    };
    out.transactions = txs.items;
    return out;
}

pub const WaitForEffectsRequest = struct {
    transaction_digest: ?[]const u8 = null,
    consensus_position: ?[]const u8 = null,
    include_details: bool = false,
    /// `PingType` as sent (0 = Consensus).
    ping_type: ?i32 = null,
};

pub fn decodeWaitForEffectsRequest(body: []const u8) Malformed!WaitForEffectsRequest {
    var out: WaitForEffectsRequest = .{};
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => out.transaction_digest = proto.Reader.bytesOf(f) catch return error.Malformed,
        2 => out.consensus_position = proto.Reader.bytesOf(f) catch return error.Malformed,
        3 => out.include_details = (proto.Reader.varintOf(f) catch return error.Malformed) != 0,
        4 => out.ping_type = @truncate(@as(i64, @bitCast(proto.Reader.varintOf(f) catch return error.Malformed))),
        else => {},
    };
    return out;
}

/// `RawValidatorHealthResponse`: every field is `optional`, so a present value is always written.
pub fn writeHealthResponse(w: *proto.Writer, h: Health) proto.Error!void {
    try w.uint(1, h.pending_certificates);
    try w.uint(2, h.inflight_consensus_messages);
    try w.uint(3, h.consensus_round);
    try w.uint(4, h.checkpoint_sequence);
}

/// What the typed `ValidatorHealthResponse` converts into (messages_grpc.rs `TryFrom`):
/// `pending_certificates = num_inflight_execution_transactions`,
/// `inflight_consensus_messages = num_inflight_consensus_transactions`,
/// `consensus_round = last_committed_leader_round`, `checkpoint_sequence = last_locally_built_checkpoint`.
pub const Health = struct {
    pending_certificates: u64 = 0,
    inflight_consensus_messages: u64 = 0,
    consensus_round: u64 = 0,
    checkpoint_sequence: u64 = 0,
};

pub fn healthResponse(arena: std.mem.Allocator, h: Health) std.mem.Allocator.Error![]const u8 {
    return driver_wire.encodeAlloc(arena, 32, h, writeHealthResponse);
}

// ------------------------------------------------------------------ BCS requests

/// `ObjectInfoRequest { object_id, generate_layout: LayoutGenerationOption, request_kind }`.
pub const ObjectInfoRequest = struct {
    object_id: [32]u8,
    /// `LayoutGenerationOption::Generate`.
    generate_layout: bool,
    /// `PastObjectInfoDebug(version)`; null is `LatestObjectInfo`.
    version: ?u64,
};

pub fn decodeObjectInfoRequest(b: []const u8) Malformed!ObjectInfoRequest {
    if (b.len < 32 + 2) return error.Malformed;
    var out: ObjectInfoRequest = .{ .object_id = b[0..32].*, .generate_layout = false, .version = null };
    out.generate_layout = switch (b[32]) {
        0 => true, // Generate
        1 => false, // None
        else => return error.Malformed,
    };
    switch (b[33]) {
        0 => if (b.len != 34) return error.Malformed,
        1 => {
            if (b.len != 34 + 8) return error.Malformed;
            out.version = std.mem.readInt(u64, b[34..42], .little);
        },
        else => return error.Malformed,
    }
    return out;
}

/// `TransactionInfoRequest { transaction_digest }`: a Digest is BCS bytes (length 32, then the bytes).
pub fn decodeTransactionInfoRequest(b: []const u8) Malformed![32]u8 {
    if (b.len != 33 or b[0] != 32) return error.Malformed;
    return b[1..33].*;
}

pub const CheckpointRequest = struct {
    sequence_number: ?u64,
    request_content: bool,
    /// V2 only: certified (true) or the locally computed pending checkpoint.
    certified: bool = true,
};

fn readOptU64(b: []const u8, at: *usize) Malformed!?u64 {
    if (at.* >= b.len) return error.Malformed;
    const tag = b[at.*];
    at.* += 1;
    switch (tag) {
        0 => return null,
        1 => {
            if (at.* + 8 > b.len) return error.Malformed;
            const v = std.mem.readInt(u64, b[at.*..][0..8], .little);
            at.* += 8;
            return v;
        },
        else => return error.Malformed,
    }
}

fn readBool(b: []const u8, at: *usize) Malformed!bool {
    if (at.* >= b.len) return error.Malformed;
    const v = b[at.*];
    at.* += 1;
    if (v > 1) return error.Malformed;
    return v == 1;
}

pub fn decodeCheckpointRequest(b: []const u8, v2: bool) Malformed!CheckpointRequest {
    var at: usize = 0;
    const seq = try readOptU64(b, &at);
    const content = try readBool(b, &at);
    var certified = true;
    if (v2) certified = try readBool(b, &at);
    if (at != b.len) return error.Malformed;
    return .{ .sequence_number = seq, .request_content = content, .certified = certified };
}

/// `SystemStateRequest { _unused: bool }`.
pub fn decodeSystemStateRequest(b: []const u8) Malformed!void {
    if (b.len != 1 or b[0] > 1) return error.Malformed;
}

// ------------------------------------------------------------------ BCS responses

/// `ObjectInfoResponse { object, layout: None, lock_for_debugging: None }` around raw object BCS.
pub fn objectInfoResponse(arena: std.mem.Allocator, object_bcs: []const u8) std.mem.Allocator.Error![]const u8 {
    const out = try arena.alloc(u8, object_bcs.len + 2);
    @memcpy(out[0..object_bcs.len], object_bcs);
    out[object_bcs.len] = 0; // layout: None
    out[object_bcs.len + 1] = 0; // lock_for_debugging: None
    return out;
}

/// `CheckpointResponse { checkpoint: Option<CertifiedCheckpointSummary>, contents: Option<CheckpointContents> }`.
pub fn checkpointResponse(arena: std.mem.Allocator, summary_cert: ?[]const u8, contents: ?[]const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try appendOpt(arena, &out, summary_cert);
    try appendOpt(arena, &out, contents);
    return out.items;
}

pub const SummaryKind = enum(u8) { certified = 0, pending = 1 };

/// `CheckpointResponseV2 { checkpoint: Option<CheckpointSummaryResponse>, contents }`, where the
/// summary response is the enum `Certified(CertifiedCheckpointSummary) | Pending(CheckpointSummary)`.
pub fn checkpointResponseV2(arena: std.mem.Allocator, summary: ?struct { kind: SummaryKind, bcs: []const u8 }, contents: ?[]const u8) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    if (summary) |s| {
        try out.append(arena, 1);
        try out.append(arena, @intFromEnum(s.kind));
        try out.appendSlice(arena, s.bcs);
    } else try out.append(arena, 0);
    try appendOpt(arena, &out, contents);
    return out.items;
}

fn appendOpt(arena: std.mem.Allocator, out: *std.ArrayList(u8), v: ?[]const u8) std.mem.Allocator.Error!void {
    if (v) |b| {
        try out.append(arena, 1);
        try out.appendSlice(arena, b);
    } else try out.append(arena, 0);
}

/// `TransactionInfoResponse { transaction, status: Executed(None, SignedTransactionEffects, events) }`:
/// the stored SenderSignedData bytes, variant 1 (Executed), no certificate signature, the effects
/// with this validator's `AuthoritySignInfo { epoch, authority, signature }` and the events.
pub fn transactionInfoExecuted(
    arena: std.mem.Allocator,
    sender_signed_data: []const u8,
    effects: []const u8,
    epoch: u64,
    authority: *const [96]u8,
    signature: *const [48]u8,
    events: ?[]const u8,
) std.mem.Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, sender_signed_data);
    try out.append(arena, 1); // TransactionStatus::Executed
    try out.append(arena, 0); // Option<AuthorityStrongQuorumSignInfo>: None
    try out.appendSlice(arena, effects);
    var e: [8]u8 = undefined;
    std.mem.writeInt(u64, &e, epoch, .little);
    try out.appendSlice(arena, &e);
    try out.append(arena, 96); // AuthorityName: serde_as Bytes, ULEB length 96
    try out.appendSlice(arena, authority);
    try out.appendSlice(arena, signature); // fixed 48 bytes, no length
    if (events) |ev| try out.appendSlice(arena, ev) else try out.append(arena, 0); // TransactionEvents::default
    return out.items;
}

/// BCS of `SuiSystemState` from the inner struct: the enum variant (V1 = 0, V2 = 1) then the inner bytes.
pub fn systemStateResponse(arena: std.mem.Allocator, wrapper_version: u64, inner: []const u8) (Malformed || error{OutOfMemory})![]const u8 {
    if (wrapper_version != 1 and wrapper_version != 2) return error.Malformed;
    const out = try arena.alloc(u8, 1 + inner.len);
    out[0] = @intCast(wrapper_version - 1);
    @memcpy(out[1..], inner);
    return out;
}

test "ObjectInfoRequest decodes both kinds and rejects trailing bytes" {
    var b: [42]u8 = @splat(0);
    b[0] = 7;
    b[32] = 1; // layout None
    b[33] = 0; // latest
    const latest = try decodeObjectInfoRequest(b[0..34]);
    try std.testing.expect(!latest.generate_layout and latest.version == null and latest.object_id[0] == 7);
    b[32] = 0;
    b[33] = 1;
    std.mem.writeInt(u64, b[34..42], 99, .little);
    const past = try decodeObjectInfoRequest(&b);
    try std.testing.expect(past.generate_layout);
    try std.testing.expectEqual(@as(u64, 99), past.version.?);
    try std.testing.expectError(error.Malformed, decodeObjectInfoRequest(b[0..41]));
    try std.testing.expectError(error.Malformed, decodeObjectInfoRequest(b[0..35]));
    b[32] = 2;
    try std.testing.expectError(error.Malformed, decodeObjectInfoRequest(&b));
}

test "checkpoint requests" {
    const a = try decodeCheckpointRequest(&.{ 1, 5, 0, 0, 0, 0, 0, 0, 0, 1 }, false);
    try std.testing.expectEqual(@as(u64, 5), a.sequence_number.?);
    try std.testing.expect(a.request_content);
    const b = try decodeCheckpointRequest(&.{ 0, 0, 1 }, true);
    try std.testing.expect(b.sequence_number == null and !b.request_content and b.certified);
    try std.testing.expectError(error.Malformed, decodeCheckpointRequest(&.{ 0, 0, 1, 0 }, true));
    try std.testing.expectError(error.Malformed, decodeCheckpointRequest(&.{ 0, 0 }, true));
}

test "transaction info request is a length-prefixed digest" {
    var b: [33]u8 = @splat(9);
    b[0] = 32;
    try std.testing.expectEqual(@as(u8, 9), (try decodeTransactionInfoRequest(&b))[0]);
    try std.testing.expectError(error.Malformed, decodeTransactionInfoRequest(b[0..32]));
}

test "submit and wait requests follow prost" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // two transactions then submit_type 2, plus an unknown field 9
    const body = [_]u8{ 0x0a, 2, 'a', 'b', 0x0a, 1, 'c', 0x10, 2, 0x48, 1 };
    const req = try decodeSubmitTxRequest(arena, &body);
    try std.testing.expectEqual(@as(usize, 2), req.transactions.len);
    try std.testing.expectEqualStrings("ab", req.transactions[0]);
    try std.testing.expectEqual(submit_type_soft_bundle, req.submit_type);
    const w = try decodeWaitForEffectsRequest(&.{ 0x0a, 1, 7, 0x18, 1, 0x20, 0 });
    try std.testing.expect(w.include_details and w.ping_type.? == 0 and w.transaction_digest.?[0] == 7);
    try std.testing.expectError(error.Malformed, decodeWaitForEffectsRequest(&.{ 0x0a, 9, 1 }));
}

test "health response writes all four optional fields" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const b = try healthResponse(arena_state.allocator(), .{ .pending_certificates = 0, .inflight_consensus_messages = 3, .consensus_round = 4, .checkpoint_sequence = 5 });
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0, 0x10, 3, 0x18, 4, 0x20, 5 }, b);
}

test "checkpoint response framing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, try checkpointResponse(a, null, null));
    try std.testing.expectEqualSlices(u8, &.{ 1, 'x', 1, 'y' }, try checkpointResponse(a, "x", "y"));
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 'x', 0 }, try checkpointResponseV2(a, .{ .kind = .pending, .bcs = "x" }, null));
    try std.testing.expectEqualSlices(u8, &.{ 0, 0 }, try checkpointResponseV2(a, null, null));
}
