//! In-process fake validators for the driver's loopback tests: a virtual clock, a transport that
//! answers every call from per-validator behaviour (after a per-validator latency), and a runner
//! that advances time to the next answer or driver timer. Nothing here touches a network.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const se = @import("sui_error.zig");
const wire = @import("wire.zig");
const cm = @import("committee.zig");
const drv = @import("driver.zig");

const ns_per_ms = std.time.ns_per_ms;

/// A small but valid `TransactionEffects::V2` for `digest`; `epoch` varies the bytes (a forked
/// execution is the same transaction with other effects).
pub fn effects(arena: Allocator, tx_digest: [32]u8, epoch: u64) ![]const u8 {
    const v: types.TransactionEffects = .{ .V2 = .{
        .status = .Success,
        .executed_epoch = epoch,
        .gas_used = .{ .computationCost = 1000, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
        .transaction_digest = .{ .@"0" = .{ .@"0" = tx_digest } },
        .gas_object_index = null,
        .events_digest = null,
        .dependencies = &.{},
        .lamport_version = .{ .@"0" = 1 },
        .changed_objects = &.{},
        .unchanged_consensus_objects = &.{},
        .aux_data_digest = null,
    } };
    return bcs.encodeAlloc(types.TransactionEffects, arena, &v);
}

pub const SubmitBehavior = union(enum) {
    submitted,
    executed,
    executed_with_details,
    rejected: se.SuiErrorKind,
    status: drv.Status,
    silent,
};

pub const WaitBehavior = union(enum) {
    /// Executed with this validator's effects (details when asked).
    executed,
    /// Executed, but without details even when asked.
    executed_no_details,
    rejected: ?se.SuiErrorKind,
    expired,
    status: drv.Status,
    silent,
};

pub const Validator = struct {
    submit: SubmitBehavior = .submitted,
    /// Acknowledgments (include_details = false).
    ack: WaitBehavior = .executed,
    /// Full effects requests (include_details = true).
    full: WaitBehavior = .executed,
    latency: u64 = 1 * ns_per_ms,
    /// This validator's effects; null: the honest ones.
    effects: ?[]const u8 = null,
    /// The first N WaitForEffects calls answer UNAVAILABLE (an `RpcError`, retried by acks).
    unavailable_first: u32 = 0,
    /// The first N acknowledgment calls answer Expired.
    expired_first: u32 = 0,
    // counters
    wait_calls: u32 = 0,
    ack_calls: u32 = 0,
};

pub const Entry = struct { call: drv.CallId, validator: u32, method: drv.Method, details: bool, at: u64 };

pub const Net = struct {
    arena: Allocator,
    now_ns: u64 = 0,
    validators: []Validator,
    honest_effects: []const u8,
    pending: std.ArrayList(struct { call: drv.CallId, at: u64, result: drv.RpcResult, cancelled: bool = false }) = .empty,
    log: std.ArrayList(Entry) = .empty,
    cancelled: std.ArrayList(drv.CallId) = .empty,
    driver: ?*drv.Driver = null,
    steps: usize = 0,

    pub fn init(arena: Allocator, n: usize, tx_digest: [32]u8) !Net {
        const vs = try arena.alloc(Validator, n);
        @memset(vs, .{});
        return .{ .arena = arena, .validators = vs, .honest_effects = try effects(arena, tx_digest, 7) };
    }

    pub fn transport(net: *Net) drv.Transport {
        return .{ .ctx = net, .vtable = &.{ .start = start, .cancel = cancel } };
    }

    pub fn clock(net: *Net) drv.Clock {
        return .{ .ctx = net, .nowFn = now };
    }

    fn now(ctx: *anyopaque) u64 {
        const net: *Net = @ptrCast(@alignCast(ctx));
        return net.now_ns;
    }

    fn cancel(ctx: *anyopaque, call: drv.CallId) void {
        const net: *Net = @ptrCast(@alignCast(ctx));
        for (net.pending.items) |*p| if (p.call == call) {
            p.cancelled = true;
        };
        net.cancelled.append(net.arena, call) catch @panic("oom");
    }

    fn start(ctx: *anyopaque, call: drv.CallId, validator: u32, method: drv.Method, body: []const u8) void {
        const net: *Net = @ptrCast(@alignCast(ctx));
        net.startInner(call, validator, method, body) catch @panic("fake transport failed");
    }

    fn startInner(net: *Net, call: drv.CallId, validator: u32, method: drv.Method, body: []const u8) !void {
        const v = &net.validators[validator];
        const eff = v.effects orelse net.honest_effects;
        const digest = types.digest.effectsDigest(eff);
        var details = false;
        const result: ?drv.RpcResult = switch (method) {
            .submit_transaction => blk: {
                const req = try wire.decodeSubmitTxRequest(net.arena, body);
                std.debug.assert(req.transactions.len <= 1);
                break :blk switch (v.submit) {
                    .silent => null,
                    .status => |s| .{ .status = s },
                    .submitted => .{ .ok = try wire.submitTxResponse(net.arena, &.{.{ .Submitted = &positionBcs(call) }}) },
                    .executed => .{ .ok = try wire.submitTxResponse(net.arena, &.{.{ .Executed = .{ .effects_digest = digest, .details = null } }}) },
                    .executed_with_details => .{ .ok = try wire.submitTxResponse(net.arena, &.{.{ .Executed = .{ .effects_digest = digest, .details = .{ .effects = eff } } }}) },
                    .rejected => |e| .{ .ok = try wire.submitTxResponse(net.arena, &.{.{ .Rejected = try wire.suiErrorBcs(net.arena, &e) }}) },
                };
            },
            .wait_for_effects => blk: {
                const req = try wire.decodeWaitForEffectsRequest(net.arena, body);
                details = req.include_details;
                v.wait_calls += 1;
                if (!details) v.ack_calls += 1;
                if (v.wait_calls <= v.unavailable_first) break :blk .{ .status = .{ .code = 14, .message = "connection refused" } };
                if (!details and v.ack_calls <= v.expired_first) break :blk .{ .ok = try wire.waitForEffectsResponse(net.arena, .{ .Expired = .{ .epoch = 1, .round = null } }) };
                const b = if (details) v.full else v.ack;
                break :blk switch (b) {
                    .silent => null,
                    .status => |s| .{ .status = s },
                    .executed => .{ .ok = try wire.waitForEffectsResponse(net.arena, .{ .Executed = .{ .effects_digest = digest, .details = if (details) .{ .effects = eff } else null } }) },
                    .executed_no_details => .{ .ok = try wire.waitForEffectsResponse(net.arena, .{ .Executed = .{ .effects_digest = digest, .details = null } }) },
                    .rejected => |maybe| .{ .ok = try wire.waitForEffectsResponse(net.arena, .{ .Rejected = if (maybe) |e| try wire.suiErrorBcs(net.arena, &e) else null }) },
                    .expired => .{ .ok = try wire.waitForEffectsResponse(net.arena, .{ .Expired = .{ .epoch = 1, .round = 5 } }) },
                };
            },
        };
        try net.log.append(net.arena, .{ .call = call, .validator = validator, .method = method, .details = details, .at = net.now_ns });
        if (result) |r| try net.pending.append(net.arena, .{ .call = call, .at = net.now_ns + v.latency, .result = r });
    }

    fn positionBcs(call: drv.CallId) [50]u8 {
        const p: wire.ConsensusPosition = .{ .epoch = 1, .block = .{ .round = call, .author = 0, .digest = @splat(3) }, .index = 0 };
        return p.encode();
    }

    /// Polls the driver to the end, moving the clock to the next answer or timer.
    pub fn run(net: *Net, d: *drv.Driver) !drv.Outcome {
        return drv.runBlocking(d, net.waiter());
    }

    /// A `Waiter` on the virtual clock: jumps to the next answer or the deadline.
    pub fn waiter(net: *Net) drv.Waiter {
        return .{ .ctx = net, .waitFn = wait };
    }

    fn wait(ctx: *anyopaque, d: *drv.Driver, deadline: ?u64) anyerror!void {
        const net: *Net = @ptrCast(@alignCast(ctx));
        net.driver = d;
        net.steps += 1;
        if (net.steps > 1_000_000) return error.Runaway;
        var next: ?u64 = deadline;
        for (net.pending.items) |p| if (!p.cancelled) {
            if (next == null or p.at < next.?) next = p.at;
        };
        const t = next orelse return error.Stuck;
        if (t > net.now_ns) net.now_ns = t;
        var i: usize = 0;
        while (i < net.pending.items.len) {
            const p = net.pending.items[i];
            if (p.at <= net.now_ns) {
                _ = net.pending.orderedRemove(i);
                if (!p.cancelled) try d.onResponse(p.call, p.result);
            } else i += 1;
        }
    }

    /// Calls started for `method` (and full-effects or not, for WaitForEffects).
    pub fn calls(net: *const Net, method: drv.Method, details: ?bool) usize {
        var n: usize = 0;
        for (net.log.items) |e| if (e.method == method and (details == null or e.details == details.?)) {
            n += 1;
        };
        return n;
    }

    pub fn nth(net: *const Net, method: drv.Method, details: ?bool, k: usize) ?Entry {
        var n: usize = 0;
        for (net.log.items) |e| if (e.method == method and (details == null or e.details == details.?)) {
            if (n == k) return e;
            n += 1;
        };
        return null;
    }
};

/// A committee with deterministic names `[i+1; 96]` and the given stakes.
pub fn committee(arena: Allocator, stakes: []const u64) !cm.Committee {
    const ms = try arena.alloc(cm.Member, stakes.len);
    for (ms, stakes, 0..) |*m, s, i| m.* = .{ .name = @splat(@intCast(i + 1)), .stake = s };
    return cm.Committee.init(arena, 1, ms);
}
