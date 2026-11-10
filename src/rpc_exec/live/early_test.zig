//! `early.head`: what answers an Execute before any submission. sui-node 1.83.1 skips an early
//! rejection for a transaction it already executed and answers that transaction's local effects
//! (truth: rpc-surface deny/cases.jsonl `deny-user/execute/transfer-a-already-executed`, OK with
//! effects, while `deny-user/execute/transfer-a` before the execution and the Simulate of the same
//! transaction afterwards are both denied).
const std = @import("std");
const types = @import("types");
const early = @import("early.zig");
const local = @import("local.zig");
const txdeny = @import("../txdeny.zig");
const handler = @import("../driver/handler.zig");
const drv = @import("../driver/driver.zig");

const testing = std.testing;
const Allocator = std.mem.Allocator;

const user_denied = "Error checking transaction input objects: Transaction is denied: Transaction signing is temporarily disabled";

fn tid(b: u8) [32]u8 {
    return @splat(b);
}

/// A transfer-shaped PTB: one owned input (0x11 at version 3) and one gas coin (0x99 at 3).
fn txData(arena: Allocator) !*types.TransactionData {
    const td = try arena.create(types.TransactionData);
    const Ref = @typeInfo(@TypeOf(td.V1.gas_data.payment)).pointer.child;
    const pay = try arena.alloc(Ref, 1);
    pay[0] = .{ .{ .@"0" = .{ .@"0" = tid(0x99) } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = tid(0xdd) } } };
    const inputs = try arena.alloc(types.CallArg, 1);
    inputs[0] = .{ .Object = .{ .ImmOrOwnedObject = .{ .{ .@"0" = .{ .@"0" = tid(0x11) } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = tid(0xee) } } } } };
    td.* = .{ .V1 = .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = &.{} } },
        .sender = .{ .@"0" = tid(0xa1) },
        .gas_data = .{ .payment = pay, .owner = .{ .@"0" = tid(0xa1) }, .price = 1000, .budget = 5_000_000 },
        .expiration = .None,
    } };
    return td;
}

fn request(data: *const types.TransactionData, include_events: bool) handler.ExecuteRequest {
    return .{ .envelope = "", .data_bcs = "", .data = data, .digest = tid(0x77), .signatures = &.{}, .include_events = include_events, .include_input_objects = false, .include_output_objects = false };
}

/// Live versions: 0x11 is at version `input_version` (null: unknown here).
const Objects = struct {
    input_version: ?u64 = null,

    fn live(o: *Objects) early.LiveObjects {
        return .{ .ctx = o, .get = get, .at = at };
    }
    fn get(ctx: *anyopaque, _: Allocator, id: *const [32]u8) ?early.Live {
        const o: *Objects = @ptrCast(@alignCast(ctx));
        if (!std.mem.eql(u8, id, &tid(0x11))) return null;
        const v = o.input_version orelse return null;
        return .{ .version = v, .digest = tid(0xee), .immutable = false };
    }
    fn at(_: *anyopaque, _: Allocator, _: *const [32]u8, _: u64) ?[]const u8 {
        return null;
    }
};

/// The node's executed set: one digest with fixed effects bytes.
const Executed = struct {
    digest: ?[32]u8 = null,
    lookups: usize = 0,

    fn effects(e: *Executed) local.LocalEffects {
        return .{ .ctx = e, .get = get };
    }
    fn get(ctx: *anyopaque, _: Allocator, req: *const handler.ExecuteRequest) ?drv.QuorumResponse {
        const e: *Executed = @ptrCast(@alignCast(ctx));
        e.lookups += 1;
        const d = e.digest orelse return null;
        if (!std.mem.eql(u8, &d, &req.digest)) return null;
        return .{ .effects_digest = tid(0xef), .effects = "effects", .events = "events", .input_objects = null, .output_objects = null, .source = 0 };
    }
};

fn installUserDisabled(arena: Allocator) !void {
    txdeny.install(try txdeny.parseItems(arena, &.{"user-transaction-disabled=true"}));
}

test "early.head: a denied transaction not executed here is rejected with the deny text" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    try installUserDisabled(a);
    defer txdeny.install(.{});
    var objs: Objects = .{};
    var ex: Executed = .{};
    const data = try txData(a);
    const req = request(data, false);
    const h = try early.head(a, objs.live(), ex.effects(), &req, false);
    try testing.expect(h == .reject);
    const re = try h.reject.toRpcError(a);
    try testing.expectEqual(@as(u8, 3), re.code);
    try testing.expectEqualStrings(user_denied, re.message);
}

test "early.head: an executed transaction answers its local effects past the deny config" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    try installUserDisabled(a);
    defer txdeny.install(.{});
    var objs: Objects = .{};
    var ex: Executed = .{ .digest = tid(0x77) };
    const data = try txData(a);
    const req = request(data, false);
    const h = try early.head(a, objs.live(), ex.effects(), &req, false);
    try testing.expect(h == .local);
    try testing.expectEqualStrings("effects", h.local.effects);
    // filtered to the read mask: no events asked for
    try testing.expect(h.local.events == null);
    const with_events = request(data, true);
    const h2 = try early.head(a, objs.live(), ex.effects(), &with_events, false);
    try testing.expectEqualStrings("events", h2.local.events.?);
}

test "early.head: an executed transaction answers its local effects past a stale input" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    // 0x11 moved on to version 4 (this transaction consumed version 3)
    var objs: Objects = .{ .input_version = 4 };
    var none: Executed = .{};
    const data = try txData(a);
    const req = request(data, false);
    const stale = try early.head(a, objs.live(), none.effects(), &req, false);
    try testing.expect(stale == .reject);
    const re = try stale.reject.toRpcError(a);
    try testing.expectEqual(@as(u8, 3), re.code);
    try testing.expect(std.mem.indexOf(u8, re.message, "unavailable for consumption") != null);
    var ex: Executed = .{ .digest = tid(0x77) };
    try testing.expect((try early.head(a, objs.live(), ex.effects(), &req, false)) == .local);
}

test "early.head: nothing to reject and not executed submits; the local lookup runs either way" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    var objs: Objects = .{ .input_version = 3 };
    var ex: Executed = .{ .digest = tid(0x55) };
    const data = try txData(a);
    const req = request(data, false);
    try testing.expect((try early.head(a, objs.live(), ex.effects(), &req, false)) == .submit);
    try testing.expectEqual(@as(usize, 1), ex.lookups);
    // no live objects and no local store: submit
    try testing.expect((try early.head(a, null, null, &req, false)) == .submit);
}

test "early.head: early validation off skips the deny config (validators do not apply it)" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    try installUserDisabled(a);
    defer txdeny.install(.{});
    early.enabled.store(false, .monotonic);
    defer early.enabled.store(true, .monotonic);
    var objs: Objects = .{ .input_version = 4 };
    var none: Executed = .{};
    const data = try txData(a);
    const req = request(data, false);
    try testing.expect((try early.head(a, objs.live(), none.effects(), &req, false)) == .submit);
    var ex: Executed = .{ .digest = tid(0x77) };
    try testing.expect((try early.head(a, objs.live(), ex.effects(), &req, false)) == .local);
}

test "early.head: a dynamic predicate alone (every rule empty) still denies" {
    var ar = std.heap.ArenaAllocator.init(testing.allocator);
    defer ar.deinit();
    const a = ar.allocator();
    // truth: deny-dyn-false/execute/transfer-a
    txdeny.install(try txdeny.parseItems(a, &.{"dynamic-transaction-checks=False"}));
    defer txdeny.install(.{});
    try testing.expect(txdeny.current().rules.isEmpty());
    var objs: Objects = .{};
    var none: Executed = .{};
    const data = try txData(a);
    const req = request(data, false);
    const h = try early.head(a, objs.live(), none.effects(), &req, false);
    try testing.expect(h == .reject);
    const re = try h.reject.toRpcError(a);
    try testing.expectEqualStrings("Error checking transaction input objects: Transaction is denied: Dynamic transaction predicate failed", re.message);
    // `True` passes
    txdeny.install(try txdeny.parseItems(a, &.{"dynamic-transaction-checks=True"}));
    try testing.expect((try early.head(a, objs.live(), none.effects(), &req, false)) == .submit);
}
