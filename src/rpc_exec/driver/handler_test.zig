//! Handler tests without the corpus: validation replies, and ExecuteTransaction end to end
//! through the driver and in-process fake validators.
const std = @import("std");
const testing = std.testing;
const bcs = @import("bcs");
const types = @import("types");
const serve = @import("serve");
const proto = serve.proto;
const se = @import("sui_error.zig");
const drv = @import("driver.zig");
const fake = @import("fake.zig");
const handler = @import("handler.zig");

const ns_per_s = std.time.ns_per_s;

fn txData(arena: std.mem.Allocator, price: u64) ![]const u8 {
    const v: types.TransactionData = .{ .V1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = &.{}, .commands = &.{} } },
        .sender = .{ .@"0" = @splat(1) },
        .gas_data = .{ .payment = &.{}, .owner = .{ .@"0" = @splat(1) }, .price = price, .budget = 5_000_000 },
        .expiration = .None,
    } };
    return bcs.encodeAlloc(types.TransactionData, arena, &v);
}

/// ExecuteTransactionRequest { transaction { bcs { value } }, signatures [{ bcs { value } }], read_mask? }
fn requestBody(arena: std.mem.Allocator, data: []const u8, sigs: []const []const u8, mask_paths: ?[]const []const u8) ![]const u8 {
    const buf = try arena.alloc(u8, data.len + 4096);
    var w = proto.Writer.init(buf);
    const t = try w.begin(1, data.len + 16);
    const b = try w.begin(1, data.len + 8);
    try w.bytes(2, data);
    try w.end(b);
    try w.end(t);
    for (sigs) |s| {
        const sm = try w.begin(2, s.len + 16);
        const bm = try w.begin(1, s.len + 8);
        try w.bytes(2, s);
        try w.end(bm);
        try w.end(sm);
    }
    if (mask_paths) |ps| {
        const mm = try w.begin(3, 256);
        for (ps) |p| try w.string(1, p);
        try w.end(mm);
    }
    return w.bytesWritten();
}

const ed25519_sig: [97]u8 = [_]u8{0} ++ @as([96]u8, @splat(0));

const E2E = struct {
    arena_state: std.heap.ArenaAllocator,
    committee: @import("committee.zig").Committee = undefined,
    net: fake.Net = undefined,
    exec: handler.DriverExecutor = undefined,

    fn init(self: *E2E) !void {
        const arena = self.arena_state.allocator();
        self.committee = try fake.committee(arena, &.{ 2500, 2500, 2500, 2500 });
        self.net = try fake.Net.init(arena, 4, @splat(9));
        self.exec = .{
            .committee = &self.committee,
            .transport = self.net.transport(),
            .clock = self.net.clock(),
            .waiter = self.net.waiter(),
            .options = .{ .reference_gas_price = 750, .seed = 1 },
        };
    }
};

test "ExecuteTransaction end to end: handler, driver, fake validators" {
    var e: E2E = .{ .arena_state = .init(testing.allocator) };
    defer e.arena_state.deinit();
    try e.init();
    const arena = e.arena_state.allocator();
    const data = try txData(arena, 1000);
    // default mask: effects only
    const reply = try handler.executeTransaction(arena, e.exec.executor(), try requestBody(arena, data, &.{&ed25519_sig}, null));
    const body = reply.ok;
    try testing.expect(std.mem.indexOf(u8, body, e.net.honest_effects) != null);
    try testing.expectEqual(@as(usize, 1), e.net.calls(.submit_transaction, null));
    // the validators got the signed envelope
    const sub = try @import("wire.zig").decodeSubmitTxRequest(arena, blk: {
        break :blk (try @import("wire.zig").submitTxRequest(arena, try handler.envelope(arena, data, &.{&ed25519_sig})));
    });
    const split = try serve.service.splitEnvelope(arena, sub.transactions[0]);
    try testing.expectEqualSlices(u8, data, split.data);
    try testing.expectEqualSlices(u8, &ed25519_sig, split.sigs[0]);
}

test "ExecuteTransaction end to end: rejected by validators" {
    var e: E2E = .{ .arena_state = .init(testing.allocator) };
    defer e.arena_state.deinit();
    try e.init();
    const arena = e.arena_state.allocator();
    for (e.net.validators) |*v| v.submit = .{ .rejected = .{ .UserInputError = .{ .@"error" = .MissingGasPayment } } };
    const reply = try handler.executeTransaction(arena, e.exec.executor(), try requestBody(arena, try txData(arena, 1000), &.{&ed25519_sig}, &.{"digest"}));
    try testing.expectEqual(@as(u8, 3), reply.err.code);
    try testing.expect(std.mem.endsWith(u8, reply.err.message, "} with 5000 stake]."));
    try testing.expect(std.mem.startsWith(u8, reply.err.message, "Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable). Non-retriable errors: [Transaction gas payment missing { k#"));
}

test "ExecuteTransaction end to end: gas price under RGP" {
    var e: E2E = .{ .arena_state = .init(testing.allocator) };
    defer e.arena_state.deinit();
    try e.init();
    const arena = e.arena_state.allocator();
    const reply = try handler.executeTransaction(arena, e.exec.executor(), try requestBody(arena, try txData(arena, 10), &.{&ed25519_sig}, null));
    try testing.expectEqual(@as(u8, 3), reply.err.code);
    try testing.expectEqualStrings("Transaction failed validation: Gas price 10 under reference gas price (RGP) 750", reply.err.message);
    try testing.expectEqual(@as(usize, 0), e.net.log.items.len);
}

test "ExecuteTransaction validation replies" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var fixed: handler.FixedExecutor = .{ .outcome = .{ .err = .TimeoutBeforeFinality } };
    const ex = fixed.executor();
    const data = try txData(arena, 1000);
    {
        const r = try handler.executeTransaction(arena, ex, "");
        try testing.expectEqual(@as(u8, 3), r.err.code);
        try testing.expectEqualStrings("", r.err.message);
    }
    {
        const r = try handler.executeTransaction(arena, ex, try requestBody(arena, data[0 .. data.len - 1], &.{}, null));
        try testing.expectEqualStrings("invalid transaction: error converting from protobuf: field: bcs reason: FIELD_INVALID description: unexpected end of input", r.err.message);
    }
    {
        const r = try handler.executeTransaction(arena, ex, try requestBody(arena, data, &.{ &ed25519_sig, &ed25519_sig, &ed25519_sig }, null));
        try testing.expectEqualStrings("3 provided signatures exceeds the maximum allowed of 2", r.err.message);
    }
    {
        const r = try handler.executeTransaction(arena, ex, try requestBody(arena, data, &.{&[_]u8{ 0x09, 0, 0 }}, null));
        try testing.expectEqualStrings("invalid signature: error converting from protobuf: field: bcs reason: FIELD_INVALID description: unexpected end of input", r.err.message);
    }
    {
        const r = try handler.executeTransaction(arena, ex, try requestBody(arena, data, &.{&ed25519_sig}, &.{"effects.nope"}));
        try testing.expectEqualStrings("invalid read_mask path: effects.nope", r.err.message);
    }
    {
        const r = try handler.executeTransaction(arena, ex, try requestBody(arena, data, &.{&ed25519_sig}, null));
        try testing.expectEqual(@as(u8, 14), r.err.code);
        try testing.expectEqualStrings("timed-out before finality could be reached", r.err.message);
    }
}

test "ExecuteTransaction never sets checkpoint or timestamp, whatever the read mask asks" {
    // sui-rpc-api `execute_transaction` fills digest, transaction, signatures, effects, events,
    // balance_changes and objects only: the transaction is quorum-executed, not yet in a
    // checkpoint (clients wait for that with GetTransaction / SubscribeCheckpoints)
    var e: E2E = .{ .arena_state = .init(testing.allocator) };
    defer e.arena_state.deinit();
    try e.init();
    const arena = e.arena_state.allocator();
    const data = try txData(arena, 1000);
    const reply = try handler.executeTransaction(arena, e.exec.executor(), try requestBody(arena, data, &.{&ed25519_sig}, &.{ "digest", "checkpoint", "timestamp", "effects.status" }));
    var r = proto.Reader.init(reply.ok);
    const f = (try r.next()).?;
    try testing.expectEqual(@as(u32, 1), f.number);
    var seen: [16]bool = @splat(false);
    var tr = proto.Reader.init(try proto.Reader.bytesOf(f));
    while (try tr.next()) |g| seen[@min(g.number, 15)] = true;
    try testing.expect(seen[1] and seen[4]);
    try testing.expect(!seen[6] and !seen[7]);
    try testing.expect((try r.next()) == null);
    // only checkpoint and timestamp: an empty ExecutedTransaction (prost writes the empty message)
    const only = try handler.executeTransaction(arena, e.exec.executor(), try requestBody(arena, data, &.{&ed25519_sig}, &.{ "checkpoint", "timestamp" }));
    try testing.expectEqualSlices(u8, &.{ 0x0a, 0x00 }, only.ok);
}
