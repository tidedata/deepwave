//! Validator gRPC wire messages of `sui.validator.Validator` (SubmitTransaction, WaitForEffects):
//! the prost `Raw*` messages of sui-types `messages_grpc.rs` and the typed values the client side
//! (`authority_client.rs`, `TryFrom<Raw*>`) turns them into, with the BCS payloads inside
//! (Transaction envelope, ConsensusPosition, effects digest, ExecutedData, SuiError).
//!
//! Encoders write prost's bytes: fields in tag order, proto3 scalars only when not default,
//! `optional` fields when present, oneof members always, repeated `bytes` element by element.
//! Decoders follow prost's merge rules (last scalar wins, repeated fields append) and then the
//! `TryFrom` conversions, whose failures are `SuiErrorKind::GrpcMessageDeserializeError` values
//! with Rust's `type_info` strings.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const serve = @import("serve");
const proto = serve.proto;
const se = @import("sui_error.zig");

pub const SuiErrorKind = se.SuiErrorKind;

// ------------------------------------------------------------------------------------------
// BCS payloads

/// consensus-types `BlockRef { round: u32, author: AuthorityIndex(u32), digest: BlockDigest([u8; 32]) }`.
pub const BlockRef = struct { round: u32, author: u32, digest: [32]u8 };

/// sui-types `ConsensusPosition { epoch, block, index: TransactionIndex(u16) }`.
pub const ConsensusPosition = struct {
    epoch: u64,
    block: BlockRef,
    index: u16,

    pub const ping_index: u16 = std.math.maxInt(u16);
    pub const bcs_len = 8 + 4 + 4 + 32 + 2;

    pub fn encode(p: ConsensusPosition) [bcs_len]u8 {
        var out: [bcs_len]u8 = undefined;
        var w = bcs.Writer.init(&out);
        bcs.encode(ConsensusPosition, &p, &w) catch unreachable;
        return out;
    }
};

/// sui-types `ExecutedData` with every part kept as raw BCS (validated on decode).
pub const ExecutedData = struct {
    effects: []const u8,
    events: ?[]const u8 = null,
    input_objects: []const []const u8 = &.{},
    output_objects: []const []const u8 = &.{},
};

/// `SubmitTxResult`.
pub const SubmitTxResult = union(enum) {
    Submitted: struct { position: ConsensusPosition, raw: []const u8 },
    Executed: struct { effects_digest: [32]u8, details: ?ExecutedData },
    Rejected: SuiErrorKind,
};

/// `WaitForEffectsResponse`.
pub const WaitForEffectsResponse = union(enum) {
    Executed: struct { effects_digest: [32]u8, details: ?ExecutedData },
    /// The validator's reject vote reason; null when it cast none.
    Rejected: ?SuiErrorKind,
    Expired: struct { epoch: u64, round: ?u32 },
};

/// `RawWaitForEffectsRequest` fields as the driver builds them.
pub const WaitForEffectsRequest = struct {
    /// Null only for pings.
    transaction_digest: ?[32]u8,
    consensus_position: ?ConsensusPosition = null,
    include_details: bool = false,
    /// `PingType::Consensus` (0) for pings.
    ping: bool = false,
};

// ------------------------------------------------------------------------------------------
// Encoding

/// Grows a buffer until `f(*Writer, ctx)` fits; returns the encoded bytes in `arena`.
pub fn encodeAlloc(arena: Allocator, hint: usize, ctx: anytype, comptime f: anytype) Allocator.Error![]const u8 {
    var cap: usize = @max(hint, 64);
    while (true) : (cap *= 2) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        f(&w, ctx) catch {
            arena.free(buf);
            continue;
        };
        return w.bytesWritten();
    }
}

fn digestBcs(d: *const [32]u8) [33]u8 {
    var out: [33]u8 = undefined;
    out[0] = 32;
    @memcpy(out[1..], d);
    return out;
}

/// `SubmitTxRequest::new_transaction(tx).into_raw()`: `transactions = [bcs(Transaction)]`,
/// `submit_type = Default` (0, not written). `tx_bcs` is the BCS signed transaction envelope.
pub fn writeSubmitTxRequest(w: *proto.Writer, tx_bcs: ?[]const u8) proto.Error!void {
    if (tx_bcs) |t| try w.bytes(1, t) else try w.uint(2, 1); // ping: no transaction, submit_type Ping
}

pub fn submitTxRequest(arena: Allocator, tx_bcs: ?[]const u8) ![]const u8 {
    return encodeAlloc(arena, if (tx_bcs) |t| t.len + 8 else 4, tx_bcs, writeSubmitTxRequest);
}

pub fn writeWaitForEffectsRequest(w: *proto.Writer, r: WaitForEffectsRequest) proto.Error!void {
    if (r.transaction_digest) |d| {
        const b = digestBcs(&d);
        try w.bytes(1, &b);
    }
    if (r.consensus_position) |p| {
        const b = p.encode();
        try w.bytes(2, &b);
    }
    if (r.include_details) try w.uint(3, 1);
    if (r.ping) try w.uint(4, 0);
}

pub fn waitForEffectsRequest(arena: Allocator, r: WaitForEffectsRequest) ![]const u8 {
    return encodeAlloc(arena, 128, r, writeWaitForEffectsRequest);
}

fn writeExecutedData(w: *proto.Writer, field: u32, d: ExecutedData) proto.Error!void {
    var hint = d.effects.len + 16;
    if (d.events) |e| hint += e.len + 4;
    for (d.input_objects) |o| hint += o.len + 4;
    for (d.output_objects) |o| hint += o.len + 4;
    const m = try w.begin(field, hint);
    if (d.effects.len > 0) try w.bytes(1, d.effects);
    if (d.events) |e| try w.bytes(2, e);
    for (d.input_objects) |o| try w.bytes(3, o);
    for (d.output_objects) |o| try w.bytes(4, o);
    try w.end(m);
}

fn writeExecutedStatus(w: *proto.Writer, field: u32, digest: *const [32]u8, details: ?ExecutedData) proto.Error!void {
    const m = try w.begin(field, 64);
    const b = digestBcs(digest);
    try w.bytes(1, &b);
    if (details) |d| try writeExecutedData(w, 2, d);
    try w.end(m);
}

fn writeRejected(w: *proto.Writer, field: u32, err_bcs: ?[]const u8) proto.Error!void {
    const m = try w.begin(field, if (err_bcs) |e| e.len + 4 else 0);
    if (err_bcs) |e| try w.bytes(1, e);
    try w.end(m);
}

/// One `RawSubmitTxResult` to encode; `Rejected` carries the BCS SuiError.
pub const RawSubmitResult = union(enum) {
    Submitted: []const u8,
    Executed: struct { effects_digest: [32]u8, details: ?ExecutedData },
    Rejected: []const u8,
};

/// `RawSubmitTxResponse { results }`.
pub fn writeSubmitTxResponse(w: *proto.Writer, results: []const RawSubmitResult) proto.Error!void {
    for (results) |r| {
        const m = try w.begin(1, 64);
        switch (r) {
            .Submitted => |b| try w.bytes(1, b),
            .Executed => |e| try writeExecutedStatus(w, 2, &e.effects_digest, e.details),
            .Rejected => |b| try writeRejected(w, 3, b),
        }
        try w.end(m);
    }
}

pub fn submitTxResponse(arena: Allocator, results: []const RawSubmitResult) ![]const u8 {
    return encodeAlloc(arena, 256, results, writeSubmitTxResponse);
}

/// One `RawWaitForEffectsResponse` to encode; `Rejected` carries the optional BCS SuiError.
pub const RawWaitResponse = union(enum) {
    Executed: struct { effects_digest: [32]u8, details: ?ExecutedData },
    Rejected: ?[]const u8,
    Expired: struct { epoch: u64, round: ?u32 },
};

pub fn writeWaitForEffectsResponse(w: *proto.Writer, r: RawWaitResponse) proto.Error!void {
    switch (r) {
        .Executed => |e| try writeExecutedStatus(w, 1, &e.effects_digest, e.details),
        .Rejected => |b| try writeRejected(w, 2, b),
        .Expired => |e| {
            const m = try w.begin(3, 16);
            if (e.epoch != 0) try w.uint(1, e.epoch);
            if (e.round) |x| try w.uint(2, x);
            try w.end(m);
        },
    }
}

pub fn waitForEffectsResponse(arena: Allocator, r: RawWaitResponse) ![]const u8 {
    return encodeAlloc(arena, 256, r, writeWaitForEffectsResponse);
}

/// BCS of a SuiError value.
pub fn suiErrorBcs(arena: Allocator, e: *const SuiErrorKind) ![]const u8 {
    return bcs.encodeAlloc(SuiErrorKind, arena, e);
}

// ------------------------------------------------------------------------------------------
// Decoding (client side)

/// A response that cannot be used: the error the Rust client returns for it (as a SuiError
/// value, which the driver then wraps like any other `Err` of the RPC).
pub const DecodeFailure = SuiErrorKind;

fn deserializeError(arena: Allocator, type_info: []const u8, err: anyerror) Allocator.Error!SuiErrorKind {
    _ = arena;
    return .{ .GrpcMessageDeserializeError = .{ .type_info = .{ .@"0" = type_info }, .@"error" = .{ .@"0" = se.bcsErrorText(err) } } };
}

fn protoFailure() SuiErrorKind {
    // tonic's codec rejects a body prost cannot decode: Status::internal("failed to decode
    // Protobuf message: ..."), which `From<Status>` turns into an RpcError (no details).
    return .{ .RpcError = .{ .{ .@"0" = "failed to decode Protobuf message" }, .{ .@"0" = se.codeDescription(13) } } };
}

pub fn Decoded(comptime T: type) type {
    return union(enum) { ok: T, err: SuiErrorKind };
}

fn decodeDigest(arena: Allocator, bytes: []const u8, type_info: []const u8) Allocator.Error!union(enum) { ok: [32]u8, err: SuiErrorKind } {
    const d = bcs.decode(types.Digest, arena, bytes) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = try deserializeError(arena, type_info, e) },
    };
    return .{ .ok = d.@"0" };
}

const RawExecutedData = struct {
    effects: []const u8 = &.{},
    events: ?[]const u8 = null,
    input_objects: std.ArrayList([]const u8) = .empty,
    output_objects: std.ArrayList([]const u8) = .empty,
};

fn mergeExecutedData(arena: Allocator, d: *RawExecutedData, body: []const u8) !void {
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => d.effects = try proto.Reader.bytesOf(f),
        2 => d.events = try proto.Reader.bytesOf(f),
        3 => try d.input_objects.append(arena, try proto.Reader.bytesOf(f)),
        4 => try d.output_objects.append(arena, try proto.Reader.bytesOf(f)),
        else => {},
    };
}

const RawExecuted = struct { effects_digest: []const u8 = &.{}, details: ?RawExecutedData = null };

fn mergeExecuted(arena: Allocator, e: *RawExecuted, body: []const u8) !void {
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => e.effects_digest = try proto.Reader.bytesOf(f),
        2 => {
            if (e.details == null) e.details = .{};
            try mergeExecutedData(arena, &e.details.?, try proto.Reader.bytesOf(f));
        },
        else => {},
    };
}

fn mergeRejected(body: []const u8, err: *?[]const u8) !void {
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => err.* = try proto.Reader.bytesOf(f),
        else => {},
    };
}

/// `TryFrom<RawExecutedData> for ExecutedData`: every part must decode as its BCS type.
fn convertExecutedData(arena: Allocator, d: RawExecutedData) Allocator.Error!Decoded(ExecutedData) {
    _ = bcs.decode(types.TransactionEffects, arena, d.effects) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = try deserializeError(arena, "RawExecutedData.effects", e) },
    };
    if (d.events) |ev| _ = bcs.decode(types.TransactionEvents, arena, ev) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = try deserializeError(arena, "RawExecutedData.events", e) },
    };
    for (d.input_objects.items) |o| _ = bcs.decode(types.Object, arena, o) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = try deserializeError(arena, "RawExecutedData.input_objects", e) },
    };
    for (d.output_objects.items) |o| _ = bcs.decode(types.Object, arena, o) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = try deserializeError(arena, "RawExecutedData.output_objects", e) },
    };
    return .{ .ok = .{ .effects = d.effects, .events = d.events, .input_objects = d.input_objects.items, .output_objects = d.output_objects.items } };
}

const ExecutedOut = struct { effects_digest: [32]u8, details: ?ExecutedData };

fn convertExecuted(arena: Allocator, e: RawExecuted) Allocator.Error!Decoded(ExecutedOut) {
    const dg = switch (try decodeDigest(arena, e.effects_digest, "RawWaitForEffectsResponse.effects_digest")) {
        .ok => |d| d,
        .err => |x| return .{ .err = x },
    };
    var details: ?ExecutedData = null;
    if (e.details) |d| switch (try convertExecutedData(arena, d)) {
        .ok => |x| details = x,
        .err => |x| return .{ .err = x },
    };
    return .{ .ok = .{ .effects_digest = dg, .details = details } };
}

fn convertRejected(arena: Allocator, err: ?[]const u8) Allocator.Error!Decoded(?SuiErrorKind) {
    const b = err orelse return .{ .ok = null };
    const e = se.decode(arena, b) catch |x| switch (x) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .err = try deserializeError(arena, "RawWaitForEffectsResponse.rejected.reason", x) },
    };
    return .{ .ok = e };
}

/// `RawSubmitTxResponse` -> `SubmitTxResponse` (exactly one result) -> its `SubmitTxResult`.
pub fn decodeSubmitTxResponse(arena: Allocator, body: []const u8) Allocator.Error!Decoded(SubmitTxResult) {
    return decodeSubmitInner(arena, body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => return .{ .err = protoFailure() },
    };
}

const RawResult = union(enum) { none, submitted: []const u8, executed: RawExecuted, rejected: ?[]const u8 };

fn decodeSubmitInner(arena: Allocator, body: []const u8) (Allocator.Error || error{Malformed})!Decoded(SubmitTxResult) {
    var results: std.ArrayList(RawResult) = .empty;
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => {
            var res: RawResult = .none;
            var rr = proto.Reader.init(try proto.Reader.bytesOf(f));
            while (try rr.next()) |g| switch (g.number) {
                1 => res = .{ .submitted = try proto.Reader.bytesOf(g) },
                2 => {
                    var ex: RawExecuted = if (res == .executed) res.executed else .{};
                    try mergeExecuted(arena, &ex, try proto.Reader.bytesOf(g));
                    res = .{ .executed = ex };
                },
                3 => {
                    var er: ?[]const u8 = if (res == .rejected) res.rejected else null;
                    try mergeRejected(try proto.Reader.bytesOf(g), &er);
                    res = .{ .rejected = er };
                },
                else => {},
            };
            try results.append(arena, res);
        },
        else => {},
    };
    if (results.items.len != 1) {
        const msg = try std.fmt.allocPrint(arena, "Expected exactly 1 result, got {d}", .{results.items.len});
        return .{ .err = .{ .GrpcMessageDeserializeError = .{ .type_info = .{ .@"0" = "RawSubmitTxResponse.results" }, .@"error" = .{ .@"0" = msg } } } };
    }
    switch (results.items[0]) {
        .none => return .{ .err = .{ .GrpcMessageDeserializeError = .{ .type_info = .{ .@"0" = "RawSubmitTxResult.inner" }, .@"error" = .{ .@"0" = "RawSubmitTxResult.inner is None" } } } },
        .submitted => |b| {
            const p = bcs.decode(ConsensusPosition, arena, b) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .{ .err = try deserializeError(arena, "ConsensusPosition", e) },
            };
            return .{ .ok = .{ .Submitted = .{ .position = p, .raw = b } } };
        },
        .executed => |ex| switch (try convertExecuted(arena, ex)) {
            .ok => |o| return .{ .ok = .{ .Executed = .{ .effects_digest = o.effects_digest, .details = o.details } } },
            .err => |x| return .{ .err = x },
        },
        .rejected => |er| switch (try convertRejected(arena, er)) {
            .ok => |e| return .{ .ok = .{ .Rejected = e orelse .{ .GrpcMessageDeserializeError = .{ .type_info = .{ .@"0" = "RawSubmitTxResult.inner.Error" }, .@"error" = .{ .@"0" = "RawSubmitTxResult.inner.Error is None" } } } } },
            .err => |x| return .{ .err = x },
        },
    }
}

/// `RawWaitForEffectsResponse` -> `WaitForEffectsResponse`.
pub fn decodeWaitForEffectsResponse(arena: Allocator, body: []const u8) Allocator.Error!Decoded(WaitForEffectsResponse) {
    return decodeWaitInner(arena, body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => return .{ .err = protoFailure() },
    };
}

const RawWait = union(enum) { none, executed: RawExecuted, rejected: ?[]const u8, expired: struct { epoch: u64 = 0, round: ?u32 = null } };

fn decodeWaitInner(arena: Allocator, body: []const u8) (Allocator.Error || error{Malformed})!Decoded(WaitForEffectsResponse) {
    var res: RawWait = .none;
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => {
            var ex: RawExecuted = if (res == .executed) res.executed else .{};
            try mergeExecuted(arena, &ex, try proto.Reader.bytesOf(f));
            res = .{ .executed = ex };
        },
        2 => {
            var er: ?[]const u8 = if (res == .rejected) res.rejected else null;
            try mergeRejected(try proto.Reader.bytesOf(f), &er);
            res = .{ .rejected = er };
        },
        3 => {
            var x: @FieldType(RawWait, "expired") = if (res == .expired) res.expired else .{};
            var rr = proto.Reader.init(try proto.Reader.bytesOf(f));
            while (try rr.next()) |g| switch (g.number) {
                1 => x.epoch = try proto.Reader.varintOf(g),
                2 => x.round = @truncate(try proto.Reader.varintOf(g)),
                else => {},
            };
            res = .{ .expired = x };
        },
        else => {},
    };
    switch (res) {
        .none => return .{ .err = .{ .GrpcMessageDeserializeError = .{ .type_info = .{ .@"0" = "RawWaitForEffectsResponse.inner" }, .@"error" = .{ .@"0" = "RawWaitForEffectsResponse.inner is None" } } } },
        .executed => |ex| switch (try convertExecuted(arena, ex)) {
            .ok => |o| return .{ .ok = .{ .Executed = .{ .effects_digest = o.effects_digest, .details = o.details } } },
            .err => |x| return .{ .err = x },
        },
        .rejected => |er| switch (try convertRejected(arena, er)) {
            .ok => |e| return .{ .ok = .{ .Rejected = e } },
            .err => |x| return .{ .err = x },
        },
        .expired => |x| return .{ .ok = .{ .Expired = .{ .epoch = x.epoch, .round = x.round } } },
    }
}

// ------------------------------------------------------------------------------------------
// Decoding (server side, for fake validators and the h2 loopback)

pub const SubmitTxRequestView = struct { transactions: []const []const u8, submit_type: u64 };

pub fn decodeSubmitTxRequest(arena: Allocator, body: []const u8) !SubmitTxRequestView {
    var txs: std.ArrayList([]const u8) = .empty;
    var st: u64 = 0;
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => try txs.append(arena, try proto.Reader.bytesOf(f)),
        2 => st = try proto.Reader.varintOf(f),
        else => {},
    };
    return .{ .transactions = txs.items, .submit_type = st };
}

pub fn decodeWaitForEffectsRequest(arena: Allocator, body: []const u8) !WaitForEffectsRequest {
    var out: WaitForEffectsRequest = .{ .transaction_digest = null };
    var r = proto.Reader.init(body);
    while (try r.next()) |f| switch (f.number) {
        1 => out.transaction_digest = (try bcs.decode(types.Digest, arena, try proto.Reader.bytesOf(f))).@"0",
        2 => out.consensus_position = try bcs.decode(ConsensusPosition, arena, try proto.Reader.bytesOf(f)),
        3 => out.include_details = (try proto.Reader.varintOf(f)) != 0,
        4 => out.ping = true,
        else => {},
    };
    return out;
}

const testing = std.testing;

test "wait for effects request round trip and prost shape" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const pos: ConsensusPosition = .{ .epoch = 7, .block = .{ .round = 9, .author = 2, .digest = @splat(5) }, .index = 3 };
    const req = try waitForEffectsRequest(arena, .{ .transaction_digest = @splat(1), .consensus_position = pos, .include_details = true });
    // field 1: 33 bytes (bcs digest), field 2: 50 bytes, field 3: true
    try testing.expectEqual(@as(u8, 0x0a), req[0]);
    try testing.expectEqual(@as(u8, 33), req[1]);
    try testing.expectEqual(@as(u8, 32), req[2]);
    const back = try decodeWaitForEffectsRequest(arena, req);
    try testing.expectEqual(pos, back.consensus_position.?);
    try testing.expect(back.include_details and !back.ping);
    const ping = try waitForEffectsRequest(arena, .{ .transaction_digest = null, .ping = true });
    try testing.expectEqualSlices(u8, &.{ 0x20, 0x00 }, ping);
}

test "responses: expired, rejected none, bad inner" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const ex = try waitForEffectsResponse(arena, .{ .Expired = .{ .epoch = 5, .round = 0 } });
    const d = try decodeWaitForEffectsResponse(arena, ex);
    try testing.expectEqual(@as(u64, 5), d.ok.Expired.epoch);
    try testing.expectEqual(@as(?u32, 0), d.ok.Expired.round);
    const rj = try waitForEffectsResponse(arena, .{ .Rejected = null });
    try testing.expectEqualSlices(u8, &.{ 0x12, 0x00 }, rj);
    try testing.expect((try decodeWaitForEffectsResponse(arena, rj)).ok.Rejected == null);
    const none = try decodeWaitForEffectsResponse(arena, "");
    try testing.expectEqualStrings("Failed to deserialize RawWaitForEffectsResponse.inner, error: RawWaitForEffectsResponse.inner is None", try none.err.text(arena));
    const two = try submitTxResponse(arena, &.{ .{ .Rejected = "" }, .{ .Rejected = "" } });
    try testing.expectEqualStrings("Failed to deserialize RawSubmitTxResponse.results, error: Expected exactly 1 result, got 2", try (try decodeSubmitTxResponse(arena, two)).err.text(arena));
}
