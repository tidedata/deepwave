//! Truth vectors of `tools/truth/rpc-exec-driver` (`$ZUI_CORPUS/vectors/rpc-execute/`, formats in
//! its README) checked against the driver: validator wire messages byte for byte, SuiError texts
//! and categories, tonic `Status` to SuiError, driver error texts and their gRPC replies, and
//! the ExecuteTransaction handler's replies. Used by the `rpc-execute` conformance suite and by
//! the unit tests (`vectors_test.zig`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const se = @import("sui_error.zig");
const wire = @import("wire.zig");
const errors = @import("errors.zig");
const drv = @import("driver.zig");
const handler = @import("handler.zig");

pub const dir = "vectors/rpc-execute";

/// Where item results go.
pub const Sink = struct {
    ctx: *anyopaque,
    passFn: *const fn (ctx: *anyopaque, item: []const u8) void,
    failFn: *const fn (ctx: *anyopaque, item: []const u8, why: []const u8) void,

    fn pass(s: Sink, item: []const u8) void {
        s.passFn(s.ctx, item);
    }
    fn fail(s: Sink, item: []const u8, why: []const u8) void {
        s.failFn(s.ctx, item, why);
    }
};

const Rd = struct {
    b: []const u8,
    p: usize = 0,

    fn int(r: *Rd, comptime T: type) !T {
        const n = @sizeOf(T);
        if (r.p + n > r.b.len) return error.Truncated;
        defer r.p += n;
        return std.mem.readInt(T, r.b[r.p..][0..n], .little);
    }
    fn take(r: *Rd, n: usize) ![]const u8 {
        if (r.p + n > r.b.len) return error.Truncated;
        defer r.p += n;
        return r.b[r.p..][0..n];
    }
    fn blob(r: *Rd) ![]const u8 {
        return r.take(try r.int(u32));
    }
    fn objects(r: *Rd, arena: Allocator) ![]const []const u8 {
        const n = try r.int(u32);
        const out = try arena.alloc([]const u8, n);
        for (out) |*o| o.* = try r.blob();
        return out;
    }
    fn done(r: *const Rd) bool {
        return r.p >= r.b.len;
    }
};

/// Collects the differences of one item.
const Diff = struct {
    arena: Allocator,
    msgs: std.ArrayList(u8) = .empty,

    fn bytes(d: *Diff, what: []const u8, want: []const u8, got: []const u8) void {
        if (std.mem.eql(u8, want, got)) return;
        const at = std.mem.indexOfDiff(u8, want, got) orelse 0;
        d.msgs.print(d.arena, "{s}: differ at byte {d} (want {d} bytes, got {d}); ", .{ what, at, want.len, got.len }) catch {};
    }
    fn text(d: *Diff, what: []const u8, want: []const u8, got: []const u8) void {
        if (std.mem.eql(u8, want, got)) return;
        d.msgs.print(d.arena, "{s}:\n  want {s}\n  got  {s}\n", .{ what, want, got }) catch {};
    }
    fn eq(d: *Diff, what: []const u8, want: anytype, got: @TypeOf(want)) void {
        if (want == got) return;
        d.msgs.print(d.arena, "{s}: want {any} got {any}; ", .{ what, want, got }) catch {};
    }
    fn note(d: *Diff, comptime fmt: []const u8, args: anytype) void {
        d.msgs.print(d.arena, fmt ++ "; ", args) catch {};
    }
    fn finish(d: *Diff, sink: Sink, item: []const u8) void {
        if (d.msgs.items.len == 0) sink.pass(item) else sink.fail(item, d.msgs.items);
    }
};

fn optEq(a: ?[]const u8, b: ?[]const u8) bool {
    if (a == null or b == null) return a == null and b == null;
    return std.mem.eql(u8, a.?, b.?);
}

fn listEq(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!std.mem.eql(u8, x, y)) return false;
    return true;
}

// ------------------------------------------------------------------------------------------
// wire/<seq>.rec.zst

/// One decompressed `wire/<seq>.rec.zst`.
pub fn checkWire(arena: Allocator, sink: Sink, seq: []const u8, data: []const u8) !void {
    var r: Rd = .{ .b = data };
    while (!r.done()) {
        const tx_index = try r.int(u32);
        const count = try r.int(u8);
        var blobs: [21][]const u8 = undefined;
        if (count != 21) return error.BadRecord;
        for (&blobs) |*b| b.* = try r.blob();
        const item = try std.fmt.allocPrint(arena, "wire/{s}/{d}", .{ seq, tx_index });
        var d: Diff = .{ .arena = arena };
        try checkWireRecord(arena, &d, &blobs);
        d.finish(sink, item);
    }
}

fn checkWireRecord(arena: Allocator, d: *Diff, b: *const [21][]const u8) !void {
    const tx = b[0];
    const digest: [32]u8 = b[20][0..32].*;
    var r7: Rd = .{ .b = b[7] };
    var r8: Rd = .{ .b = b[8] };
    const ins = try r7.objects(arena);
    const outs = try r8.objects(arena);
    const events: ?[]const u8 = if (b[6].len == 0) null else b[6];
    const details: wire.ExecutedData = .{ .effects = b[5], .events = events, .input_objects = ins, .output_objects = outs };

    // requests (client side) and their server-side decode
    d.bytes("1 SubmitTxRequest", b[1], try wire.submitTxRequest(arena, tx));
    d.bytes("2 SubmitTxRequest ping", b[2], try wire.submitTxRequest(arena, null));
    const sub = try wire.decodeSubmitTxRequest(arena, b[1]);
    if (sub.transactions.len != 1 or !std.mem.eql(u8, sub.transactions[0], tx) or sub.submit_type != 0) d.note("1 decode: wrong transactions or type", .{});
    const ping = try wire.decodeSubmitTxRequest(arena, b[2]);
    if (ping.transactions.len != 0 or ping.submit_type != 1) d.note("2 decode: wrong ping", .{});

    const pos = bcs.decode(wire.ConsensusPosition, arena, b[3]) catch {
        d.note("3 ConsensusPosition does not decode", .{});
        return;
    };
    d.bytes("3 ConsensusPosition", b[3], &pos.encode());

    d.bytes("11 WaitForEffectsRequest", b[11], try wire.waitForEffectsRequest(arena, .{ .transaction_digest = digestOfTx(arena, tx), .consensus_position = pos, .include_details = true }));
    d.bytes("12 WaitForEffectsRequest", b[12], try wire.waitForEffectsRequest(arena, .{ .transaction_digest = digestOfTx(arena, tx) }));
    d.bytes("13 WaitForEffectsRequest ping", b[13], try wire.waitForEffectsRequest(arena, .{ .transaction_digest = null, .consensus_position = pos, .ping = true }));
    for ([_]struct { []const u8, wire.WaitForEffectsRequest }{
        .{ b[11], .{ .transaction_digest = digestOfTx(arena, tx), .consensus_position = pos, .include_details = true } },
        .{ b[12], .{ .transaction_digest = digestOfTx(arena, tx) } },
        .{ b[13], .{ .transaction_digest = null, .consensus_position = pos, .ping = true } },
    }, 11..) |c, i| {
        const got = try wire.decodeWaitForEffectsRequest(arena, c[0]);
        if (!std.meta.eql(got, c[1])) d.note("{d} WaitForEffectsRequest decode differs", .{i});
    }

    // submit responses
    d.bytes("4 Submitted", b[4], try wire.submitTxResponse(arena, &.{.{ .Submitted = b[3] }}));
    switch (try wire.decodeSubmitTxResponse(arena, b[4])) {
        .ok => |res| if (res != .Submitted or !std.meta.eql(res.Submitted.position, pos)) d.note("4 decode: not Submitted(position)", .{}),
        .err => d.note("4 decode failed", .{}),
    }
    d.bytes("9 Executed", b[9], try wire.submitTxResponse(arena, &.{.{ .Executed = .{ .effects_digest = digest, .details = details } }}));
    switch (try wire.decodeSubmitTxResponse(arena, b[9])) {
        .ok => |res| switch (res) {
            .Executed => |e| {
                if (!std.mem.eql(u8, &e.effects_digest, &digest)) d.note("9 decode: digest", .{});
                checkDetails(d, "9", e.details, details);
            },
            else => d.note("9 decode: not Executed", .{}),
        },
        .err => |e| d.note("9 decode failed: {f}", .{&e}),
    }
    switch (try wire.decodeSubmitTxResponse(arena, b[10])) {
        .ok => |res| switch (res) {
            .Rejected => |e| {
                if (e != .UserInputError or e.UserInputError.@"error" != .ObjectVersionUnavailableForConsumption) d.note("10 decode: wrong error", .{});
                d.bytes("10 Rejected", b[10], try wire.submitTxResponse(arena, &.{.{ .Rejected = try wire.suiErrorBcs(arena, &e) }}));
            },
            else => d.note("10 decode: not Rejected", .{}),
        },
        .err => |e| d.note("10 decode failed: {f}", .{&e}),
    }

    // wait responses
    d.bytes("14 Executed", b[14], try wire.waitForEffectsResponse(arena, .{ .Executed = .{ .effects_digest = digest, .details = null } }));
    d.bytes("15 Executed details", b[15], try wire.waitForEffectsResponse(arena, .{ .Executed = .{ .effects_digest = digest, .details = details } }));
    d.bytes("17 Rejected None", b[17], try wire.waitForEffectsResponse(arena, .{ .Rejected = null }));
    d.bytes("18 Expired", b[18], try wire.waitForEffectsResponse(arena, .{ .Expired = .{ .epoch = pos.epoch, .round = pos.block.round } }));
    d.bytes("19 Expired None", b[19], try wire.waitForEffectsResponse(arena, .{ .Expired = .{ .epoch = pos.epoch, .round = null } }));
    switch (try wire.decodeWaitForEffectsResponse(arena, b[15])) {
        .ok => |res| switch (res) {
            .Executed => |e| {
                checkDetails(d, "15", e.details, details);
                // honest data passes SafeClient's checks
                const name: [96]u8 = @splat(1);
                if (e.details) |det| if (try drv.verifyExecutedData(arena, &name, det)) |bad| d.note("15 verify_executed_data rejects honest data: {f}", .{&bad});
            },
            else => d.note("15 decode: not Executed", .{}),
        },
        .err => |e| d.note("15 decode failed: {f}", .{&e}),
    }
    switch (try wire.decodeWaitForEffectsResponse(arena, b[16])) {
        .ok => |res| switch (res) {
            .Rejected => |maybe| if (maybe) |e| {
                if (e != .ObjectLockConflict) d.note("16 decode: wrong error", .{});
                d.bytes("16 Rejected", b[16], try wire.waitForEffectsResponse(arena, .{ .Rejected = try wire.suiErrorBcs(arena, &e) }));
            } else d.note("16 decode: no error", .{}),
            else => d.note("16 decode: not Rejected", .{}),
        },
        .err => |e| d.note("16 decode failed: {f}", .{&e}),
    }
    for ([_]usize{ 14, 17, 18, 19 }) |i| switch (try wire.decodeWaitForEffectsResponse(arena, b[i])) {
        .ok => |res| switch (i) {
            14 => if (res != .Executed or res.Executed.details != null) d.note("14 decode", .{}),
            17 => if (res != .Rejected or res.Rejected != null) d.note("17 decode", .{}),
            18 => if (res != .Expired or res.Expired.round != pos.block.round) d.note("18 decode", .{}),
            else => if (res != .Expired or res.Expired.round != null) d.note("19 decode", .{}),
        },
        .err => |e| d.note("{d} decode failed: {f}", .{ i, &e }),
    };
    if (!std.mem.eql(u8, &types.digest.effectsDigest(b[5]), &digest)) d.note("20 effects digest", .{});
}

fn summary(d: *Diff, what: []const u8, body: []const u8) void {
    const proto = @import("serve").proto;
    var r = proto.Reader.init(body);
    const top = (r.next() catch return) orelse return;
    var rr = proto.Reader.init(proto.Reader.bytesOf(top) catch return);
    d.note("{s}:", .{what});
    while (rr.next() catch return) |f| {
        d.note(" f{d} len {d}", .{ f.number, f.data.len });
        if (f.number == 9 or f.number == 3) {
            var r3 = proto.Reader.init(f.data);
            while (r3.next() catch return) |g| {
                d.note("   g{d} len {d}", .{ g.number, g.data.len });
                var r4 = proto.Reader.init(g.data);
                while (r4.next() catch return) |h| d.note("     h{d} len {d} v{d}", .{ h.number, h.data.len, h.varint });
            }
        }
    }
}

fn checkDetails(d: *Diff, what: []const u8, got: ?wire.ExecutedData, want: wire.ExecutedData) void {
    const g = got orelse return d.note("{s} decode: no details", .{what});
    if (!std.mem.eql(u8, g.effects, want.effects) or !optEq(g.events, want.events) or
        !listEq(g.input_objects, want.input_objects) or !listEq(g.output_objects, want.output_objects))
        d.note("{s} decode: details differ", .{what});
}

/// The transaction digest of a `Transaction` envelope (blob 0).
fn digestOfTx(arena: Allocator, envelope: []const u8) [32]u8 {
    const parts = @import("serve").service.splitEnvelope(arena, envelope) catch return @splat(0);
    return types.digest.transactionDataDigest(parts.data);
}

// ------------------------------------------------------------------------------------------
// handler/<seq>.rec.zst

/// The executor errors of cases 20 and up (`fake_error` in the truth tool).
pub fn executorError(arena: Allocator, case: u8, names: []const [96]u8) !errors.SubmissionError {
    const failed = struct {
        fn f(c: se.ErrorCategory, details: []const u8) errors.SubmissionError {
            return .{ .TransactionFailed = .{ .category = c, .details = details } };
        }
    }.f;
    return switch (case) {
        20 => failed(.InvalidTransaction, "d-invalid"),
        21 => .TimeoutBeforeFinality,
        22 => .{ .TimeoutBeforeFinalityWithErrors = .{ .last_error = "last", .attempts = 3, .timeout_ns = 90 * std.time.ns_per_s } },
        23 => failed(.Aborted, "d-aborted"),
        24 => failed(.LockConflict, "d-lock"),
        25 => failed(.ValidatorOverloaded, "d-overload"),
        26 => failed(.Unavailable, "d-unavail"),
        27 => failed(.Internal, "d-internal"),
        28 => .{ .InvalidUserSignature = .{ .UserInputError = .{ .@"error" = .{ .IncorrectUserSignature = .{ .@"error" = .{ .@"0" = "bad sig" } } } } } },
        29 => .{ .InvalidUserSignature = .{ .InvalidSignature = .{ .@"error" = .{ .@"0" = "nope" } } } },
        30 => .TxAlreadyFinalizedWithDifferentUserSignatures,
        31 => .{ .SystemOverload = .{ .overloaded_stake = 5000, .errors = &.{} } },
        32 => .{ .TransactionDriverInternalError = .{ .Unknown = .{ .@"0" = "boom" } } },
        33 => .{ .SystemOverloadRetryAfter = .{ .overload_stake = 3400, .errors = &.{}, .retry_after_secs = 7 } },
        34 => .{ .FailedWithTransientErrorAfterMaximumAttempts = 5 },
        35 => blk: {
            const pairs = try arena.alloc(@typeInfo(@FieldType(errors.Conflict, "pairs")).pointer.child, 2);
            pairs[0] = .{ .name = &names[0], .obj_ref = oref(3) };
            pairs[1] = .{ .name = &names[1], .obj_ref = oref(4) };
            const c = try arena.alloc(errors.Conflict, 1);
            c[0] = .{ .digest = @splat(7), .pairs = pairs, .stake = 5000 };
            break :blk .{ .ObjectsDoubleUsed = c };
        },
        36 => blk: {
            const g = try arena.alloc(errors.GroupedError, 3);
            g[0] = .{ .err = .TimeoutError, .stake = 2500, .names = &.{} };
            g[1] = .{ .err = .{ .UserInputError = .{ .@"error" = .{ .GasBudgetTooHigh = .{ .gas_budget = 9, .max_budget = 5 } } } }, .stake = 5000, .names = &.{} };
            g[2] = .{ .err = .{ .InvalidSignature = .{ .@"error" = .{ .@"0" = "sig" } } }, .stake = 2500, .names = &.{} };
            break :blk .{ .NonRecoverableTransactionError = g };
        },
        else => error.UnknownCase,
    };
}

fn bytes32(n: u8) [32]u8 {
    var b: [32]u8 = undefined;
    for (&b, 0..) |*x, i| x.* = (n *% 31 +% @as(u8, @truncate(i)) *% 17) ^ 0x5a;
    return b;
}

fn oref(n: u8) se.ObjectRef {
    return .{ .{ .@"0" = .{ .@"0" = bytes32(n) } }, .{ .@"0" = @as(u64, n) * 7 + 1 }, .{ .@"0" = .{ .@"0" = bytes32(n +% 100) } } };
}

/// One decompressed `handler/<seq>.rec.zst`. `names`: committee.txt.
pub fn checkHandler(arena: Allocator, sink: Sink, seq: []const u8, data: []const u8, names: []const [96]u8) !void {
    var r: Rd = .{ .b = data };
    while (!r.done()) {
        const tx_index = try r.int(u32);
        _ = try r.blob(); // TransactionData (inside every request)
        const nsig = try r.int(u32);
        for (0..nsig) |_| _ = try r.blob();
        const effects = try r.blob();
        const events = try r.blob();
        const ins = try r.objects(arena);
        const outs = try r.objects(arena);
        const ok: drv.QuorumResponse = .{
            .effects_digest = types.digest.effectsDigest(effects),
            .effects = effects,
            .events = if (events.len == 0) null else events,
            .input_objects = if (ins.len == 0) null else ins,
            .output_objects = if (outs.len == 0) null else outs,
            .source = 0,
        };
        const cases = try r.int(u8);
        for (0..cases) |_| {
            const case = try r.int(u8);
            const req = try r.blob();
            const code = try r.int(u8);
            const msg = try r.blob();
            const details = try r.blob();
            const resp = try r.blob();
            const item = try std.fmt.allocPrint(arena, "handler/{s}/{d}/case{d}", .{ seq, tx_index, case });
            var fixed: handler.FixedExecutor = .{ .outcome = if (case >= 20) .{ .err = try executorError(arena, case, names) } else .{ .ok = ok } };
            const got = try handler.executeTransaction(arena, fixed.executor(), req);
            var d: Diff = .{ .arena = arena };
            switch (got) {
                .ok => |body| {
                    if (code != 0) d.note("want code {d} ({s}), got a response", .{ code, msg });
                    d.bytes("response", resp, body);
                    if (!std.mem.eql(u8, resp, body)) {
                        summary(&d, "want", resp);
                        summary(&d, "got", body);
                    }
                },
                .err => |e| {
                    d.eq("code", code, e.code);
                    d.text("message", msg, e.message);
                    d.bytes("details", details, e.details);
                },
            }
            d.finish(sink, item);
        }
    }
}

// ------------------------------------------------------------------------------------------
// errors

pub fn checkSuiErrors(arena: Allocator, sink: Sink, data: []const u8) !void {
    var r: Rd = .{ .b = data };
    var n: usize = 0;
    while (!r.done()) : (n += 1) {
        const raw = try r.blob();
        const display = try r.blob();
        const request_text = try r.blob();
        const category = try r.int(u8);
        const retryable = try r.int(u8);
        const categorized = try r.int(u8);
        const item = try std.fmt.allocPrint(arena, "sui_errors/{d}", .{n});
        var d: Diff = .{ .arena = arena };
        const e = se.decode(arena, raw) catch |err| {
            sink.fail(item, @errorName(err));
            continue;
        };
        d.bytes("bcs", raw, try wire.suiErrorBcs(arena, &e));
        d.text("Display", display, try e.text(arena));
        d.text("request error text", request_text, try e.requestErrorText(arena));
        d.eq("category", category, @intFromEnum(e.categorize()));
        const rt = e.isRetryable();
        d.eq("retryable", retryable, @intFromBool(rt.retryable));
        d.eq("categorized", categorized, @intFromBool(rt.categorized));
        d.finish(sink, item);
    }
}

pub fn checkStatus(arena: Allocator, sink: Sink, data: []const u8) !void {
    var r: Rd = .{ .b = data };
    var n: usize = 0;
    while (!r.done()) : (n += 1) {
        const code = try r.int(u8);
        const msg = try r.blob();
        const details = try r.blob();
        const result = try r.blob();
        const display = try r.blob();
        const category = try r.int(u8);
        const item = try std.fmt.allocPrint(arena, "status/{d}", .{n});
        var d: Diff = .{ .arena = arena };
        const e = try se.fromStatus(arena, code, msg, details);
        d.bytes("SuiError bcs", result, try wire.suiErrorBcs(arena, &e));
        d.text("Display", display, try e.text(arena));
        d.eq("category", category, @intFromEnum(e.categorize()));
        d.finish(sink, item);
    }
}

fn readAgg(arena: Allocator, r: *Rd) !errors.AggregatedRequestErrors {
    const n = try r.int(u32);
    const groups = try arena.alloc(errors.ErrorGroup, n);
    for (groups) |*g| {
        const text = try r.blob();
        const m = try r.int(u32);
        const names = try arena.alloc(errors.Name, m);
        for (names) |*x| x.* = (try r.take(96))[0..96];
        const stake = try r.int(u64);
        const cat = try r.int(u8);
        g.* = .{ .text = text, .names = names, .stake = stake, .category = @enumFromInt(cat) };
    }
    return .{ .errors = groups, .total_stake = try r.int(u64) };
}

fn readDigs(arena: Allocator, r: *Rd) !errors.AggregatedEffectsDigests {
    const n = try r.int(u32);
    const groups = try arena.alloc(errors.DigestGroup, n);
    for (groups) |*g| {
        const digest = (try r.take(32))[0..32].*;
        const m = try r.int(u32);
        const names = try arena.alloc(errors.Name, m);
        for (names) |*x| x.* = (try r.take(96))[0..96];
        g.* = .{ .digest = digest, .names = names, .stake = try r.int(u64) };
    }
    return .{ .digests = groups };
}

fn readSpec(arena: Allocator, r: *Rd) !errors.DriverError {
    return switch (try r.int(u8)) {
        0 => .{ .ClientInternal = try r.blob() },
        1 => .{ .ValidationFailed = try r.blob() },
        2 => .{ .Aborted = .{ .non_retriable = try readAgg(arena, r), .retriable = try readAgg(arena, r), .observed = try readDigs(arena, r) } },
        3 => .{ .RejectedByValidators = .{ .non_retriable = try readAgg(arena, r), .retriable = try readAgg(arena, r) } },
        4 => .{ .ForkedExecution = .{ .observed = try readDigs(arena, r), .non_retriable = try readAgg(arena, r), .retriable = try readAgg(arena, r) } },
        5 => blk: {
            const last: ?*const errors.DriverError = if (try r.int(u8) != 0) last: {
                const p = try arena.create(errors.DriverError);
                p.* = try readSpec(arena, r);
                break :last p;
            } else null;
            break :blk .{ .TimeoutWithLastRetriableError = .{ .last_error = last, .attempts = try r.int(u32), .timeout_ns = try r.int(u64) } };
        },
        else => error.BadRecord,
    };
}

pub fn checkDriverErrors(arena: Allocator, sink: Sink, data: []const u8) !void {
    var r: Rd = .{ .b = data };
    var n: usize = 0;
    while (!r.done()) : (n += 1) {
        const e = try readSpec(arena, &r);
        const display = try r.blob();
        const category = try r.int(u8);
        const retriable = try r.int(u8);
        const code = try r.int(u8);
        const msg = try r.blob();
        const details = try r.blob();
        const item = try std.fmt.allocPrint(arena, "driver_errors/{d}", .{n});
        var d: Diff = .{ .arena = arena };
        d.text("Display", display, try e.text(arena));
        d.eq("category", category, @intFromEnum(e.categorize()));
        d.eq("retriable", retriable, @intFromBool(e.isSubmissionRetriable()));
        const sub = try e.toSubmissionError(arena);
        const rpc = try sub.toRpcError(arena);
        d.eq("grpc code", code, rpc.code);
        d.text("grpc message", msg, rpc.message);
        d.bytes("grpc details", details, rpc.details);
        d.finish(sink, item);
    }
}

/// committee.txt: `<index>\t<hex name>` lines.
pub fn parseCommittee(arena: Allocator, text: []const u8) ![]const [96]u8 {
    var out: std.ArrayList([96]u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, text, '\n');
    while (it.next()) |line| {
        const tab = std.mem.indexOfScalar(u8, line, '\t') orelse return error.BadCommittee;
        var name: [96]u8 = undefined;
        _ = std.fmt.hexToBytes(&name, std.mem.trim(u8, line[tab + 1 ..], " \r")) catch return error.BadCommittee;
        try out.append(arena, name);
    }
    return out.items;
}

/// Runs every vector file under `root` (the corpus directory). `per_file` limits the wire and
/// handler files read (null: all of them).
pub fn runAll(gpa: Allocator, io: std.Io, root: std.Io.Dir, sink: Sink, per_file: ?usize) !void {
    const harness = @import("harness");
    var fixed_state = std.heap.ArenaAllocator.init(gpa);
    defer fixed_state.deinit();
    const arena = fixed_state.allocator();
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const read = struct {
        fn f(a: Allocator, i: std.Io, r: std.Io.Dir, sub: []const u8) ![]u8 {
            return r.readFileAlloc(i, sub, a, .limited(1 << 30));
        }
    }.f;
    const names = try parseCommittee(arena, try read(arena, io, root, dir ++ "/committee.txt"));
    try checkSuiErrors(arena, sink, try read(arena, io, root, dir ++ "/sui_errors.rec"));
    try checkStatus(arena, sink, try read(arena, io, root, dir ++ "/status.rec"));
    try checkDriverErrors(arena, sink, try read(arena, io, root, dir ++ "/driver_errors.rec"));
    for ([_][]const u8{ "wire", "handler" }) |kind| {
        const sub = try std.fmt.allocPrint(arena, dir ++ "/{s}", .{kind});
        const files = try harness.listFilesIn(gpa, io, root, sub, ".rec.zst");
        defer {
            for (files) |f| gpa.free(f);
            gpa.free(files);
        }
        if (files.len == 0) return error.NoVectors;
        for (files, 0..) |f, i| {
            if (per_file) |lim| if (i >= lim) break;
            _ = arena_state.reset(.retain_capacity);
            const a = arena_state.allocator();
            const z = try read(a, io, root, try std.fmt.allocPrint(a, "{s}/{s}", .{ sub, f }));
            const data = try harness.decompressZstd(a, z, 1 << 30);
            const seq = f[0 .. f.len - ".rec.zst".len];
            if (std.mem.eql(u8, kind, "wire")) try checkWire(a, sink, seq, data) else try checkHandler(a, sink, seq, data, names);
        }
    }
}
