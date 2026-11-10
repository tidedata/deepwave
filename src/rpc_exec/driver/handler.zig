//! `TransactionExecutionService.ExecuteTransaction` as `sui-rpc-api`
//! (`grpc/v2/transaction_execution_service/mod.rs` `execute_transaction`): request validation
//! with the exact `FieldViolation` replies, the read mask (default `effects`), the executor (the
//! orchestrator plus the transaction driver in a node, a fake in tests), then the
//! `ExecutedTransaction` rendered with serve's renderers.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const serve = @import("serve");
const proto = serve.proto;
const mask = serve.mask;
const status = serve.status;
const reply = @import("../reply.zig");
const se = @import("sui_error.zig");
const errors = @import("errors.zig");
const drv = @import("driver.zig");
const sdk_sig = @import("sdk_sig.zig");
const drv_committee = @import("committee.zig");

pub const Reply = reply.Reply;
pub const RpcError = reply.RpcError;

/// `EXECUTE_TRANSACTION_READ_MASK_DEFAULT`.
pub const default_read_mask = "effects";
/// `MAX_NUMBER_OF_SIGNATURES`: the sender and an optional sponsor.
pub const max_signatures = 2;

/// `ExecuteTransactionRequestV3` as the executor sees it.
pub const ExecuteRequest = struct {
    /// BCS `Transaction` (SenderSignedData with one transaction): what validators receive.
    envelope: []const u8,
    /// BCS `TransactionData` and its decoded value.
    data_bcs: []const u8,
    data: *const types.TransactionData,
    digest: [32]u8,
    /// Raw `GenericSignature` bytes.
    signatures: []const []const u8,
    include_events: bool,
    include_input_objects: bool,
    include_output_objects: bool,

    /// The driver's view of this request.
    pub fn driverRequest(r: *const ExecuteRequest) drv.Request {
        return drv.Request.fromData(r.envelope, r.data_bcs, r.data);
    }
};

/// A render context for one response (`json` of events): `objects` are the transaction's own
/// objects (a package it published resolves from them first). Null: no `json`.
pub const RenderHook = struct {
    ctx: *anyopaque,
    make: *const fn (ctx: *anyopaque, arena: Allocator, objects: []const []const u8) ?*const serve.render_object.Ctx,
};

/// `TransactionExecutor::execute_transaction`: the orchestrator in a node. Its `ok` response is
/// filtered by the include flags like `TransactionOrchestrator` does (events only when asked,
/// objects only when asked and non-empty).
pub const Executor = struct {
    ctx: *anyopaque,
    executeFn: *const fn (ctx: *anyopaque, arena: Allocator, req: *const ExecuteRequest) Allocator.Error!drv.Outcome,
    /// Event `json` (sui-node renders it with the node's package store); null leaves it out.
    render: ?RenderHook = null,

    pub fn execute(e: Executor, arena: Allocator, req: *const ExecuteRequest) Allocator.Error!drv.Outcome {
        return e.executeFn(e.ctx, arena, req);
    }
};

/// ExecuteTransaction: `body` is the `ExecuteTransactionRequest` message, the reply is the
/// `ExecuteTransactionResponse` message or the gRPC error tonic sends.
pub fn executeTransaction(arena: Allocator, executor: Executor, body: []const u8) Allocator.Error!Reply {
    const req = parseRequest(arena, body) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Malformed => return .{ .err = try plainError(arena, 13, "failed to decode Protobuf message") },
    };

    // transaction
    const tx = req.transaction orelse return .{ .err = try violation(arena, "transaction", "", .field_missing) };
    const data_bcs: []const u8 = blk: {
        if (tx.bcs) |b| {
            const value = b.value orelse "";
            _ = bcs.decode(types.TransactionData, arena, value) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    const text = try std.fmt.allocPrint(arena, "invalid transaction: error converting from protobuf: field: bcs reason: FIELD_INVALID description: {s}", .{se.bcsErrorText(e)});
                    return .{ .err = try violation(arena, "transaction", text, .field_invalid) };
                },
            };
            break :blk value;
        }
        if (tx.version != 1) {
            const v = if (tx.version) |x| try std.fmt.allocPrint(arena, "Some({d})", .{x}) else "None";
            const text = try std.fmt.allocPrint(arena, "invalid transaction: error converting from protobuf: field: version reason: FIELD_INVALID description: unknown Transaction version {s}", .{v});
            return .{ .err = try violation(arena, "transaction", text, .field_invalid) };
        }
        return .{ .err = try plainError(arena, 12, "transaction resolution from structured Transaction fields is not supported; send transaction.bcs") };
    };
    const data = try arena.create(types.TransactionData);
    data.* = bcs.decode(types.TransactionData, arena, data_bcs) catch return error.OutOfMemory;

    // signatures
    if (req.signatures.len > max_signatures) {
        const text = try std.fmt.allocPrint(arena, "{d} provided signatures exceeds the maximum allowed of {d}", .{ req.signatures.len, max_signatures });
        return .{ .err = try violation(arena, "signatures", text, .field_invalid) };
    }
    const sigs = try arena.alloc([]const u8, req.signatures.len);
    for (req.signatures, sigs, 0..) |s, *out, i| {
        out.* = switch (try parseUserSignature(arena, s)) {
            .ok => |b| b,
            .err => |why| {
                const field = try std.fmt.allocPrint(arena, "signatures[{d}]", .{i});
                const text = try std.fmt.allocPrint(arena, "invalid signature: {s}", .{why});
                return .{ .err = try violation(arena, field, text, .field_invalid) };
            },
            .unsupported => return .{ .err = try plainError(arena, 12, "structured UserSignature fields are not supported; send signature bcs") },
        };
    }

    // read_mask
    var tree = if (req.mask_parts.items.len == 0)
        try mask.Tree.parse(arena, default_read_mask)
    else blk: {
        var paths: std.ArrayList([]const u8) = .empty;
        for (req.mask_parts.items) |part| {
            var r = proto.Reader.init(part);
            while (r.next() catch return .{ .err = try plainError(arena, 13, "failed to decode Protobuf message") }) |f| {
                if (f.number == 1) try paths.append(arena, proto.Reader.stringOf(f) catch return .{ .err = try plainError(arena, 13, "failed to decode Protobuf message") });
            }
        }
        if (status.invalidPath(comptime serve.schema.index("ExecutedTransaction"), paths.items)) |p| {
            const text = try std.fmt.allocPrint(arena, "invalid read_mask path: {s}", .{p});
            return .{ .err = try violation(arena, "read_mask", text, .field_invalid) };
        }
        break :blk try mask.Tree.fromPaths(arena, paths.items);
    };
    const m = tree.mask();
    _ = &tree;

    const objects_wanted = m.contains("balance_changes") or m.contains("objects") or m.contains("effects");
    const exec_req: ExecuteRequest = .{
        .envelope = try envelope(arena, data_bcs, sigs),
        .data_bcs = data_bcs,
        .data = data,
        .digest = types.digest.transactionDataDigest(data_bcs),
        .signatures = sigs,
        .include_events = m.contains("events"),
        .include_input_objects = objects_wanted,
        .include_output_objects = objects_wanted,
    };
    const q = switch (try executor.execute(arena, &exec_req)) {
        .err => |e| return .{ .err = try e.toRpcError(arena) },
        .ok => |q| q,
    };
    const rctx: ?*const serve.render_object.Ctx = if (executor.render) |h| h.make(h.ctx, arena, q.output_objects orelse &.{}) else null;
    return .{ .ok = try renderWith(arena, m, &exec_req, q, rctx) };
}

/// The `ExecuteTransactionResponse` for a finalized transaction.
pub fn render(arena: Allocator, m: mask.Mask, req: *const ExecuteRequest, q: drv.QuorumResponse) Allocator.Error![]const u8 {
    return renderWith(arena, m, req, q, null);
}

pub fn renderWith(arena: Allocator, m: mask.Mask, req: *const ExecuteRequest, q: drv.QuorumResponse, rctx: ?*const serve.render_object.Ctx) Allocator.Error![]const u8 {
    const ins = if (req.include_input_objects) q.input_objects orelse &.{} else &.{};
    const outs = if (req.include_output_objects) q.output_objects orelse &.{} else &.{};
    const raws = try arena.alloc([]const u8, ins.len + outs.len);
    @memcpy(raws[0..ins.len], ins);
    @memcpy(raws[ins.len..], outs);
    const Ctx = struct { arena: Allocator, m: mask.Mask, req: *const ExecuteRequest, q: drv.QuorumResponse, raws: []const []const u8, rctx: ?*const serve.render_object.Ctx };
    const ctx: Ctx = .{ .arena = arena, .m = m, .req = req, .q = q, .raws = raws, .rctx = rctx };
    var cap: usize = 1024 + q.effects.len * 4 + req.data_bcs.len * 2;
    for (raws) |r| cap += r.len * 2;
    if (q.events) |e| cap += e.len * 2;
    while (true) : (cap *= 2) {
        const buf = try arena.alloc(u8, cap);
        var w = proto.Writer.init(buf);
        writeResponse(&w, ctx) catch |e| switch (e) {
            error.NoSpace => continue,
            error.OutOfMemory => return error.OutOfMemory,
            // the effects and objects came from 2f+1 validators and decoded on the way in
            else => return error.OutOfMemory,
        };
        return w.bytesWritten();
    }
}

fn writeResponse(w: *proto.Writer, ctx: anytype) !void {
    const arena = ctx.arena;
    const m = ctx.m;
    const t = try w.begin(1, ctx.q.effects.len + 256);
    var set = try serve.objset.ObjSet.build(arena, ctx.raws);
    const eff = try bcs.decode(types.TransactionEffects, arena, ctx.q.effects);
    try writeExecuted(arena, w, m, .{
        .transaction = ctx.req.data_bcs,
        .signatures = ctx.req.signatures,
        .effects = ctx.q.effects,
        .events = if (ctx.req.include_events) ctx.q.events else null,
        .objects = &set,
        .effects_digest = &ctx.q.effects_digest,
        .decoded_effects = eff,
        .render = ctx.rctx,
    });
    if (m.contains("balance_changes")) {
        for (try serve.balance.derive(arena, eff, &set.map)) |c| try serve.balance.write(w, 8, c);
    }
    // `read_mask.subtree("objects.objects")`: one walk, so a bare `objects` leaf selects nothing
    if (m.subtreeDyn("objects.objects") != null) try serve.ledger.writeObjectSetAt(arena, w, 9, m, ctx.raws);
    try w.end(t);
}

/// serve's `render_tx.writeExecuted` with the signatures rendered as sui-sdk-types parsed them.
fn writeExecuted(arena: Allocator, w: *proto.Writer, m: mask.Mask, in: serve.render_tx.Input) !void {
    const td = try bcs.decode(types.TransactionData, arena, in.transaction);
    const eff = in.decoded_effects.?;
    const tx_digest: [32]u8 = switch (eff) {
        inline else => |v| v.transaction_digest.@"0".@"0",
    };
    const ev_digest: ?[32]u8 = switch (eff) {
        inline else => |v| if (v.events_digest) |d| d.@"0".@"0" else null,
    };
    if (m.contains("digest")) {
        var buf: [serve.b58.max_len_32]u8 = undefined;
        try w.string(1, serve.b58.encode32(&buf, &tx_digest));
    }
    if (m.subtree("transaction")) |sm| try serve.render_tx.writeTransaction(arena, w, 2, sm, in.transaction, td, &tx_digest);
    if (m.subtree("signatures")) |sm| for (in.signatures) |sg| try sdk_sig.writeUserSignature(w, 3, arena, sm, sg);
    if (m.subtree("effects")) |sm| try serve.render_tx.writeEffects(arena, w, 4, sm, in.effects, eff, &in);
    if (m.subtree("events")) |sm| if (in.events) |eb| {
        const ev = try bcs.decode(types.TransactionEvents, arena, eb);
        try serve.render_tx.writeEventsCtx(arena, w, 5, sm, eb, ev, if (ev_digest) |*d| d else null, in.render);
    };
}

/// BCS `Transaction` = `Envelope<SenderSignedData>`: one `SenderSignedTransaction` with the
/// default intent (0, 0, 0), the data and the signatures as byte strings.
pub fn envelope(arena: Allocator, data_bcs: []const u8, sigs: []const []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, &.{ 1, 0, 0, 0 });
    try out.appendSlice(arena, data_bcs);
    try uleb(arena, &out, sigs.len);
    for (sigs) |s| {
        try uleb(arena, &out, s.len);
        try out.appendSlice(arena, s);
    }
    return out.items;
}

fn uleb(arena: Allocator, out: *std.ArrayList(u8), v0: usize) Allocator.Error!void {
    var v = v0;
    while (v >= 0x80) : (v >>= 7) try out.append(arena, @as(u8, @truncate(v)) | 0x80);
    try out.append(arena, @truncate(v));
}

fn plainError(arena: Allocator, code: u8, message: []const u8) Allocator.Error!RpcError {
    return .{ .code = code, .message = message, .details = try errors.statusDetails(arena, code, message) };
}

/// `RpcError::from(FieldViolation)`: INVALID_ARGUMENT, message = description, details = BadRequest.
fn violation(arena: Allocator, field: []const u8, description: []const u8, reason: status.Reason) Allocator.Error!RpcError {
    const details = status.badRequest(arena, 3, field, description, reason) catch return error.OutOfMemory;
    return .{ .code = 3, .message = description, .details = details };
}

// ------------------------------------------------------------------------------------------
// request

const BcsMsg = struct { value: ?[]const u8 = null };
const TxMsg = struct { bcs: ?BcsMsg = null, version: ?u64 = null };
const SigMsg = struct { bcs: ?BcsMsg = null, scheme: ?u64 = null };
const Parsed = struct {
    transaction: ?TxMsg = null,
    signatures: []const SigMsg = &.{},
    mask_parts: std.ArrayList([]const u8) = .empty,
};

const PErr = error{ Malformed, OutOfMemory };

/// prost decode of `ExecuteTransactionRequest`, keeping what the handler reads (message fields
/// seen twice merge, scalars: last wins).
fn parseRequest(arena: Allocator, body: []const u8) PErr!Parsed {
    var p: Parsed = .{};
    var sigs: std.ArrayList(SigMsg) = .empty;
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => {
            var t = p.transaction orelse TxMsg{};
            try mergeTx(&t, try bytesOf(f));
            p.transaction = t;
        },
        2 => {
            var s: SigMsg = .{};
            try mergeSig(&s, try bytesOf(f));
            try sigs.append(arena, s);
        },
        3 => try p.mask_parts.append(arena, try bytesOf(f)),
        else => {},
    };
    p.signatures = sigs.items;
    return p;
}

fn bytesOf(f: proto.Reader.Field) PErr![]const u8 {
    return proto.Reader.bytesOf(f) catch error.Malformed;
}

fn mergeBcs(b: *BcsMsg, body: []const u8) PErr!void {
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        2 => b.value = try bytesOf(f),
        else => {},
    };
}

fn mergeTx(t: *TxMsg, body: []const u8) PErr!void {
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => {
            var b = t.bcs orelse BcsMsg{};
            try mergeBcs(&b, try bytesOf(f));
            t.bcs = b;
        },
        3 => t.version = proto.Reader.varintOf(f) catch return error.Malformed,
        else => {},
    };
}

fn mergeSig(s: *SigMsg, body: []const u8) PErr!void {
    var r = proto.Reader.init(body);
    while (r.next() catch return error.Malformed) |f| switch (f.number) {
        1 => {
            var b = s.bcs orelse BcsMsg{};
            try mergeBcs(&b, try bytesOf(f));
            s.bcs = b;
        },
        2 => s.scheme = proto.Reader.varintOf(f) catch return error.Malformed,
        else => {},
    };
}

const SigResult = union(enum) { ok: []const u8, err: []const u8, unsupported };

/// `sui_sdk_types::UserSignature::try_from(&proto::UserSignature)`: `from_bytes` of the bcs
/// value, else the value read as BCS (a length-prefixed byte string holding the same form).
fn parseUserSignature(arena: Allocator, s: SigMsg) Allocator.Error!SigResult {
    const b = s.bcs orelse {
        if (s.scheme == null) return .{ .err = "error converting from protobuf: field: scheme reason: FIELD_MISSING" };
        return .unsupported;
    };
    const value = b.value orelse "";
    if (try serializedError(arena, value) == null) return .{ .ok = value };
    // bcs path
    var r = bcs.Reader.init(value);
    const len = r.length() catch |e| return .{ .err = try invalidBcs(arena, se.bcsErrorText(e)) };
    const inner = r.bytes(len) catch |e| return .{ .err = try invalidBcs(arena, se.bcsErrorText(e)) };
    if (try serializedError(arena, inner)) |why| return .{ .err = try invalidBcs(arena, why) };
    if (r.pos() != value.len) return .{ .err = try invalidBcs(arena, "remaining input") };
    return .{ .ok = inner };
}

fn invalidBcs(arena: Allocator, why: []const u8) Allocator.Error![]const u8 {
    return std.fmt.allocPrint(arena, "error converting from protobuf: field: bcs reason: FIELD_INVALID description: {s}", .{why});
}

/// `UserSignature::from_serialized_bytes`: null when the bytes form a signature.
fn serializedError(arena: Allocator, bytes: []const u8) Allocator.Error!?[]const u8 {
    if (bytes.len > 0 and bytes[0] == 5) return switch (try sdk_sig.parseZkLogin(arena, bytes)) {
        .ok => null,
        .err => |e| e,
    };
    // multisig and passkey: sui-sdk-types' own BCS forms and checks (verifysig's parser)
    if (bytes.len > 1 and (bytes[0] == 3 or bytes[0] == 6)) return serve.verifysig.serializedUserSigError(arena, bytes);
    return checkSerialized(bytes);
}

fn checkSerialized(bytes: []const u8) ?[]const u8 {
    if (bytes.len == 0) return "missing signature scheme flag";
    return switch (bytes[0]) {
        0 => if (bytes.len == 1 + 64 + 32) null else "invalid ed25519 signature",
        1 => if (bytes.len == 1 + 64 + 33) null else "invalid secp25k1 signature",
        2 => if (bytes.len == 1 + 64 + 33) null else "invalid secp25r1 signature",
        4 => "bls not supported for user signatures",
        // multisig and passkey: their own BCS forms (not re-checked here)
        3, 5, 6 => if (bytes.len > 1) null else "unexpected end of input",
        else => schemeText(bytes[0]),
    };
}

fn schemeText(flag: u8) []const u8 {
    const texts = comptime blk: {
        @setEvalBranchQuota(2_000_000);
        var t: [256][]const u8 = undefined;
        for (&t, 0..) |*x, i| x.* = std.fmt.comptimePrint("invalid signature scheme: {x:0>2}", .{i});
        break :blk t;
    };
    return texts[flag];
}

// ------------------------------------------------------------------------------------------
// executors

/// An executor that answers every request with a fixed outcome, filtered like the
/// orchestrator (the truth tool's fake `TransactionExecutor`).
pub const FixedExecutor = struct {
    outcome: drv.Outcome,

    pub fn executor(self: *FixedExecutor) Executor {
        return .{ .ctx = self, .executeFn = run };
    }

    fn run(ctx: *anyopaque, arena: Allocator, req: *const ExecuteRequest) Allocator.Error!drv.Outcome {
        _ = arena;
        const self: *FixedExecutor = @ptrCast(@alignCast(ctx));
        return filtered(self.outcome, req);
    }
};

/// The node's executor: one `drv.Driver` per request over a transport, run to its outcome with
/// a blocking `Waiter`. The transport hands answers to the driver passed to `Waiter.waitFn`.
/// Not here (the orchestrator's work before the driver): user signature verification
/// (`InvalidUserSignature`), the local effects cache and `notify_read_executed_effects`.
pub const DriverExecutor = struct {
    committee: *const drv_committee.Committee,
    transport: drv.Transport,
    clock: drv.Clock,
    waiter: drv.Waiter,
    options: drv.Options,

    pub fn executor(self: *DriverExecutor) Executor {
        return .{ .ctx = self, .executeFn = run };
    }

    fn run(ctx: *anyopaque, arena: Allocator, req: *const ExecuteRequest) Allocator.Error!drv.Outcome {
        const self: *DriverExecutor = @ptrCast(@alignCast(ctx));
        var d = try drv.Driver.init(arena, self.committee, self.transport, self.clock, req.driverRequest(), self.options);
        const o = drv.runBlocking(&d, self.waiter) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => drv.Outcome{ .err = .{ .TransactionDriverInternalError = .{ .Unknown = .{ .@"0" = @errorName(e) } } } },
        };
        return filtered(o, req);
    }
};

/// `TransactionOrchestrator::execute_transaction_block`'s filtering of a driver response.
pub fn filtered(o: drv.Outcome, req: *const ExecuteRequest) drv.Outcome {
    var q = switch (o) {
        .err => return o,
        .ok => |q| q,
    };
    if (!req.include_events) q.events = null;
    if (!req.include_input_objects) q.input_objects = null;
    if (!req.include_output_objects) q.output_objects = null;
    return .{ .ok = q };
}
