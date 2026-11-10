//! Loopback tests of the driver against in-process fake validators (fake.zig).
const std = @import("std");
const testing = std.testing;
const types = @import("types");
const se = @import("sui_error.zig");
const errors = @import("errors.zig");
const drv = @import("driver.zig");
const fake = @import("fake.zig");

const ns_per_ms = std.time.ns_per_ms;
const ns_per_s = std.time.ns_per_s;
const tx_digest: [32]u8 = @splat(9);
const rgp: u64 = 750;

const Setup = struct {
    arena_state: std.heap.ArenaAllocator,
    committee: @import("committee.zig").Committee = undefined,
    net: fake.Net = undefined,
    driver: drv.Driver = undefined,

    fn arena(s: *Setup) std.mem.Allocator {
        return s.arena_state.allocator();
    }

    fn deinit(s: *Setup) void {
        s.arena_state.deinit();
    }
};

fn setup(stakes: []const u64) !*Setup {
    const s = try testing.allocator.create(Setup);
    s.* = .{ .arena_state = .init(testing.allocator) };
    s.committee = try fake.committee(s.arena(), stakes);
    s.net = try fake.Net.init(s.arena(), stakes.len, tx_digest);
    return s;
}

fn destroy(s: *Setup) void {
    s.deinit();
    testing.allocator.destroy(s);
}

fn request(gas_price: u64) drv.Request {
    return .{ .transaction = "signed transaction bytes", .digest = tx_digest, .gas_price = gas_price };
}

fn drive(s: *Setup, req: drv.Request, opts: drv.Options) !drv.Outcome {
    s.driver = try drv.Driver.init(s.arena(), &s.committee, s.net.transport(), s.net.clock(), req, opts);
    return s.net.run(&s.driver);
}

fn rpcOf(s: *Setup, o: drv.Outcome) !@import("../reply.zig").RpcError {
    return switch (o) {
        .ok => error.UnexpectedSuccess,
        .err => |e| e.toRpcError(s.arena()),
    };
}

const even4 = [_]u64{ 2500, 2500, 2500, 2500 };

test "committee of 4, all honest: certified effects" {
    for (0..8) |seed| {
        const s = try setup(&even4);
        defer destroy(s);
        const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = seed });
        const q = o.ok;
        try testing.expectEqualSlices(u8, s.net.honest_effects, q.effects);
        try testing.expectEqual(types.digest.effectsDigest(s.net.honest_effects), q.effects_digest);
        try testing.expect(q.input_objects == null and q.output_objects == null and q.events == null);
        // one submission (amplification 1), an ack request to every member
        try testing.expectEqual(@as(usize, 1), s.net.calls(.submit_transaction, null));
        try testing.expectEqual(@as(usize, 4), s.net.calls(.wait_for_effects, false));
        try testing.expectEqual(@as(u32, 0), s.driver.attempts);
    }
}

test "uneven stake committee, all honest" {
    const stakes = [_]u64{ 4000, 3000, 2000, 1000 };
    for (0..8) |seed| {
        const s = try setup(&stakes);
        defer destroy(s);
        // the 4000 member is slow: 3000 + 2000 + 1000 = 6000 < 6667 cannot certify without it
        s.net.validators[0].latency = 50 * ns_per_ms;
        const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = seed });
        try testing.expectEqual(types.digest.effectsDigest(s.net.honest_effects), o.ok.effects_digest);
        try testing.expect(s.net.now_ns >= 50 * ns_per_ms);
    }
}

test "amplification: gas price 3x RGP submits to 3 validators at once" {
    const s = try setup(&even4);
    defer destroy(s);
    _ = (try drive(s, request(3 * rgp), .{ .reference_gas_price = rgp, .seed = 3 })).ok;
    try testing.expectEqual(@as(usize, 3), s.net.calls(.submit_transaction, null));
    for (0..3) |k| try testing.expectEqual(@as(u64, 0), s.net.nth(.submit_transaction, null, k).?.at);
}

test "gas price under RGP fails validation without any call" {
    const s = try setup(&even4);
    defer destroy(s);
    const o = try drive(s, request(500), .{ .reference_gas_price = rgp });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 3), e.code);
    try testing.expectEqualStrings("Transaction failed validation: Gas price 500 under reference gas price (RGP) 750", e.message);
    try testing.expectEqual(@as(usize, 0), s.net.log.items.len);
}

test "gasless transaction and ping use amplification 1" {
    const s = try setup(&even4);
    defer destroy(s);
    var req = request(0);
    req.gasless = true;
    _ = (try drive(s, req, .{ .reference_gas_price = rgp })).ok;
    const p = try setup(&even4);
    defer destroy(p);
    _ = (try drive(p, .{ .transaction = null }, .{ .reference_gas_price = rgp })).ok;
    try testing.expectEqual(@as(usize, 1), p.net.calls(.submit_transaction, null));
}

test "one byzantine effects digest: certified by the honest 3, full effects from an honest one" {
    var saw_byzantine_full = false;
    for (0..16) |seed| {
        const s = try setup(&even4);
        defer destroy(s);
        s.net.validators[2].effects = try fake.effects(s.arena(), tx_digest, 8);
        const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = seed });
        try testing.expectEqual(types.digest.effectsDigest(s.net.honest_effects), o.ok.effects_digest);
        try testing.expect(o.ok.source != 2);
        if (s.net.nth(.wait_for_effects, true, 0).?.validator == 2) {
            saw_byzantine_full = true;
            // mismatch: the next ranked validator is asked, no new attempt
            try testing.expect(s.net.calls(.wait_for_effects, true) >= 2);
        }
        try testing.expectEqual(@as(u32, 0), s.driver.attempts);
    }
    try testing.expect(saw_byzantine_full);
}

test "forked execution: two digests with 5000 stake each" {
    const s = try setup(&even4);
    defer destroy(s);
    const other = try fake.effects(s.arena(), tx_digest, 8);
    s.net.validators[2].effects = other;
    s.net.validators[3].effects = other;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 1 });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 13), e.code);
    try testing.expect(std.mem.startsWith(u8, e.message, "Transaction execution observed forked outputs (non-retriable). Observed effects digests: ["));
    try testing.expect(std.mem.indexOf(u8, e.message, "{ k#01010101.., k#02020202.. } with 5000 stake") != null);
    try testing.expect(std.mem.indexOf(u8, e.message, "{ k#03030303.., k#04040404.. } with 5000 stake") != null);
    try testing.expect(s.driver.driver_error.? == .ForkedExecution);
}

test "uneven stake: a 4000 member alone on its digest forks the 6000 rest" {
    const s = try setup(&.{ 4000, 3000, 2000, 1000 });
    defer destroy(s);
    s.net.validators[0].effects = try fake.effects(s.arena(), tx_digest, 8);
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 5 });
    _ = try rpcOf(s, o);
    try testing.expect(s.driver.driver_error.? == .ForkedExecution);
}

const lock_conflict = se.UserInputError{ .ObjectVersionUnavailableForConsumption = .{
    .provided_obj_ref = .{ .{ .@"0" = .{ .@"0" = @splat(5) } }, .{ .@"0" = 3 }, .{ .@"0" = .{ .@"0" = @splat(6) } } },
    .current_version = .{ .@"0" = 4 },
} };

test "f+1 non-retriable rejections at submission: rejected by validators" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.submit = .{ .rejected = .{ .UserInputError = .{ .@"error" = lock_conflict } } };
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 2 });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 3), e.code);
    // two rejections (5000 >= 3334) end it; the names are the first two targets
    try testing.expectEqual(@as(usize, 2), s.net.calls(.submit_transaction, null));
    const a = s.net.nth(.submit_transaction, null, 0).?.validator;
    const b = s.net.nth(.submit_transaction, null, 1).?.validator;
    var buf: [64]u8 = undefined;
    const lo: u8 = @intCast(@min(a, b) + 1);
    const hi: u8 = @intCast(@max(a, b) + 1);
    const names = try std.fmt.bufPrint(&buf, "{{ k#{x:0>2}{x:0>2}{x:0>2}{x:0>2}.., k#{x:0>2}{x:0>2}{x:0>2}{x:0>2}.. }} with 5000 stake].", .{ lo, lo, lo, lo, hi, hi, hi, hi });
    try testing.expect(std.mem.endsWith(u8, e.message, names));
    try testing.expect(std.mem.startsWith(u8, e.message, "Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable). Non-retriable errors: [Transaction needs to be rebuilt because object 0x0505"));
    try testing.expectEqual(e.code, e.details[1]);
}

test "f+1 non-retriable rejections at acknowledgment" {
    const s = try setup(&even4);
    defer destroy(s);
    const rej: se.SuiErrorKind = .{ .UserInputError = .{ .@"error" = lock_conflict } };
    s.net.validators[0].ack = .{ .rejected = rej };
    s.net.validators[1].ack = .{ .rejected = rej };
    s.net.validators[2].latency = 5 * ns_per_ms;
    s.net.validators[3].latency = 5 * ns_per_ms;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 4 });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 3), e.code);
    try testing.expect(s.driver.driver_error.? == .RejectedByValidators);
    try testing.expect(std.mem.indexOf(u8, e.message, "{ k#01010101.., k#02020202.. } with 5000 stake") != null);
}

test "submission timeout: backup request to another validator after 1s" {
    const s = try setup(&even4);
    defer destroy(s);
    // whichever validator is asked first stays silent; every other one answers
    const probe = try setup(&even4);
    defer destroy(probe);
    for (probe.net.validators) |*v| v.submit = .silent;
    probe.driver = try drv.Driver.init(probe.arena(), &probe.committee, probe.net.transport(), probe.net.clock(), request(rgp), .{ .reference_gas_price = rgp, .seed = 11 });
    _ = try probe.driver.poll();
    const first = probe.net.nth(.submit_transaction, null, 0).?.validator;
    for (s.net.validators, 0..) |*v, i| v.submit = if (i == first) .silent else .submitted;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 11 });
    _ = o.ok;
    try testing.expectEqual(first, s.net.nth(.submit_transaction, null, 0).?.validator);
    const second = s.net.nth(.submit_transaction, null, 1).?;
    try testing.expect(second.validator != first);
    try testing.expectEqual(@as(u64, 1 * ns_per_s), second.at);
    // the silent call was cancelled when the backup succeeded
    try testing.expect(std.mem.indexOfScalar(drv.CallId, s.net.cancelled.items, s.net.nth(.submit_transaction, null, 0).?.call) != null);
}

test "submission error: retried at once at the next validator" {
    const s = try setup(&even4);
    defer destroy(s);
    const probe = try setup(&even4);
    defer destroy(probe);
    probe.driver = try drv.Driver.init(probe.arena(), &probe.committee, probe.net.transport(), probe.net.clock(), request(rgp), .{ .reference_gas_price = rgp, .seed = 12 });
    _ = try probe.driver.poll();
    const first = probe.net.nth(.submit_transaction, null, 0).?.validator;
    s.net.validators[first].submit = .{ .status = .{ .code = 14, .message = "unavailable" } };
    _ = (try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 12 })).ok;
    const second = s.net.nth(.submit_transaction, null, 1).?;
    try testing.expect(second.validator != first);
    try testing.expectEqual(@as(u64, 1 * ns_per_ms), second.at); // right after the error came back
}

test "every validator silent: the orchestrator's 90s finality timeout" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.submit = .silent;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 14), e.code);
    try testing.expectEqualStrings("timed-out before finality could be reached", e.message);
    try testing.expectEqual(@as(u64, 90 * ns_per_s), s.net.now_ns);
}

test "drive timeout keeps the last retriable error" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.submit = .{ .status = .{ .code = 14, .message = "down" } };
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .finality_timeout = null, .drive_timeout = 5 * ns_per_s });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 14), e.code);
    const prefix = "Transaction timed out before finality could be reached. Attempts: ";
    try testing.expect(std.mem.startsWith(u8, e.message, prefix));
    try testing.expect(std.mem.indexOf(u8, e.message, " & timeout: 5s. Last error: Transaction processing aborted (retriable with another submission). Retriable errors: [The service is currently unavailable - down { k#01010101.., k#02020202.., k#03030303.., k#04040404.. } with 10000 stake].") != null);
    try testing.expect(s.driver.attempts > 3);
}

test "expired at every validator once, then certified on the next attempt" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.expired_first = 1;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 6 });
    _ = o.ok;
    try testing.expectEqual(@as(u32, 1), s.driver.attempts);
    try testing.expectEqual(@as(usize, 2), s.net.calls(.submit_transaction, null));
    // the second attempt waited for the first backoff delay (100ms) after the abort
    try testing.expect(s.net.nth(.submit_transaction, null, 1).?.at >= 100 * ns_per_ms);
}

test "expired forever: aborted attempts until the drive timeout" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.ack = .expired;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .finality_timeout = null, .drive_timeout = 3 * ns_per_s, .seed = 7 });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 14), e.code);
    try testing.expect(std.mem.indexOf(u8, e.message, "Retriable errors: [Transaction status expired {") != null);
    try testing.expect(std.mem.indexOf(u8, e.message, " with 7500 stake].") != null);
}

test "acknowledgment RPC errors are retried with backoff" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.unavailable_first = 2;
    // full effects requests also start with UNAVAILABLE; they are not retried in place
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 8 });
    _ = o.ok;
    try testing.expect(s.net.now_ns >= 100 * ns_per_ms);
}

test "full effects fall back to another acknowledging validator after 200ms" {
    for (0..4) |seed| {
        const s = try setup(&even4);
        defer destroy(s);
        for (s.net.validators) |*v| v.full = .silent;
        // exactly one validator answers full effects: the fallback must find it
        const probe = try setup(&even4);
        defer destroy(probe);
        probe.driver = try drv.Driver.init(probe.arena(), &probe.committee, probe.net.transport(), probe.net.clock(), request(rgp), .{ .reference_gas_price = rgp, .seed = seed });
        _ = try probe.net.run(&probe.driver);
        const initial = probe.net.nth(.wait_for_effects, true, 0).?.validator;
        const helper: u32 = (initial + 1) % 4;
        s.net.validators[helper].full = .executed;
        const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = seed });
        try testing.expectEqual(helper, o.ok.source);
        // ticks every 200ms from the start of certification (the submission took 1ms)
        const fb = s.net.nth(.wait_for_effects, true, 1).?;
        try testing.expect(fb.validator != initial);
        try testing.expect((fb.at - 1 * ns_per_ms) % (200 * ns_per_ms) == 0 and fb.at >= 201 * ns_per_ms);
    }
}

test "executed with details at submission: no full effects request" {
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| v.submit = .executed_with_details;
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp });
    try testing.expectEqual(s.net.nth(.submit_transaction, null, 0).?.validator, o.ok.source);
    try testing.expectEqual(@as(usize, 0), s.net.calls(.wait_for_effects, true));
}

test "full effects without details: next validator, sequentially" {
    var failed: usize = 0;
    for (0..12) |seed| {
        const s = try setup(&even4);
        defer destroy(s);
        // "Execution data not found" is ValidatorInternal: Internal, non-retriable
        s.net.validators[0].full = .executed_no_details;
        _ = (try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = seed })).ok;
        const t = try setup(&even4);
        defer destroy(t);
        t.net.validators[0].full = .executed_no_details;
        t.net.validators[1].full = .executed_no_details;
        const o = try drive(t, request(rgp), .{ .reference_gas_price = rgp, .seed = seed });
        switch (o) {
            .ok => |q| try testing.expect(q.source >= 2),
            .err => {
                // both were asked before a good one: f+1 stake of non-retriable errors
                failed += 1;
                const e = try rpcOf(t, o);
                try testing.expectEqual(@as(u8, 13), e.code);
                try testing.expectEqualStrings("Transaction is rejected as invalid by more than 1/3 of validators by stake (non-retriable). Non-retriable errors: [Execution data not found { k#01010101.., k#02020202.. } with 5000 stake].", e.message);
            },
        }
    }
    try testing.expect(failed > 0 and failed < 12);
}

test "allowed and blocked validators" {
    {
        const s = try setup(&even4);
        defer destroy(s);
        const name = s.committee.displayName(2);
        _ = (try drive(s, request(3 * rgp), .{ .reference_gas_price = rgp, .allowed_validators = &.{ name, "unknown" } })).ok;
        try testing.expectEqual(@as(usize, 1), s.net.calls(.submit_transaction, null));
        try testing.expectEqual(@as(u32, 2), s.net.nth(.submit_transaction, null, 0).?.validator);
    }
    {
        const s = try setup(&even4);
        defer destroy(s);
        const blocked = [_][]const u8{ s.committee.displayName(0), s.committee.displayName(1), s.committee.displayName(3) };
        for (0..4) |seed| {
            s.net.log.clearRetainingCapacity();
            _ = (try drive(s, request(rgp), .{ .reference_gas_price = rgp, .blocked_validators = &blocked, .seed = seed })).ok;
            try testing.expectEqual(@as(u32, 2), s.net.nth(.submit_transaction, null, 0).?.validator);
        }
    }
    {
        // nobody allowed: every attempt aborts with no errors, until the drive timeout
        const s = try setup(&even4);
        defer destroy(s);
        const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .allowed_validators = &.{"nobody"}, .finality_timeout = null, .drive_timeout = 2 * ns_per_s });
        const e = try rpcOf(s, o);
        try testing.expectEqual(@as(u8, 14), e.code);
        try testing.expect(std.mem.endsWith(u8, e.message, "Last error: Transaction processing aborted (retriable with another submission)."));
        try testing.expectEqual(@as(usize, 0), s.net.log.items.len);
    }
}

test "allowed proposers of the current epoch restrict submission targets" {
    const s = try setup(&even4);
    defer destroy(s);
    var req = request(4 * rgp);
    req.allowed_proposers = .{ .epoch = 1, .proposers = &.{ 1, 3 } };
    _ = (try drive(s, req, .{ .reference_gas_price = rgp })).ok;
    try testing.expectEqual(@as(usize, 2), s.net.calls(.submit_transaction, null));
    for (0..2) |k| {
        const v = s.net.nth(.submit_transaction, null, k).?.validator;
        try testing.expect(v == 1 or v == 3);
    }
    // another epoch's proposers do not apply
    const t = try setup(&even4);
    defer destroy(t);
    req.allowed_proposers = .{ .epoch = 0, .proposers = &.{1} };
    _ = (try drive(t, req, .{ .reference_gas_price = rgp })).ok;
    try testing.expectEqual(@as(usize, 4), t.net.calls(.submit_transaction, null));
}

test "overloaded validators add 10s to the backoff" {
    const s = try setup(&even4);
    defer destroy(s);
    const overload: se.SuiErrorKind = .{ .TooManyTransactionsPendingConsensus = {} };
    for (s.net.validators) |*v| v.submit = .{ .rejected = overload };
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .finality_timeout = null, .drive_timeout = 15 * ns_per_s });
    const e = try rpcOf(s, o);
    try testing.expectEqual(@as(u8, 14), e.code);
    // attempt 0 at 0s, attempt 1 after ~10.1s, then the 15s timeout
    try testing.expectEqual(@as(u32, 1), s.driver.attempts);
    try testing.expect(std.mem.indexOf(u8, e.message, "Attempts: 1 & timeout: 15s.") != null);
}

test "zui: min_amplification submits to that many validators at once" {
    const s = try setup(&even4);
    defer destroy(s);
    const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = 3, .min_amplification = 3 });
    try testing.expectEqualSlices(u8, s.net.honest_effects, o.ok.effects);
    try testing.expectEqual(@as(usize, 3), s.net.calls(.submit_transaction, null));
}

test "zui: certified effects from a detail acknowledgment, the feedback sees each step" {
    const Fb = struct {
        submit: u32 = 0,
        effects: u32 = 0,
        finality: u32 = 0,
        fn f(ctx: *anyopaque, _: u32, op: drv.Op, lat: ?u64, _: bool) void {
            const x: *@This() = @ptrCast(@alignCast(ctx));
            if (lat == null) return;
            switch (op) {
                .submit => x.submit += 1,
                .effects => x.effects += 1,
                .finality => x.finality += 1,
            }
        }
    };
    for (0..4) |seed| {
        const s = try setup(&even4);
        defer destroy(s);
        var fb: Fb = .{};
        const detail = [_]u32{ 0, 1, 2, 3 };
        const o = try drive(s, request(rgp), .{ .reference_gas_price = rgp, .seed = seed, .detail_acks = &detail, .feedback = .{ .ctx = &fb, .f = Fb.f } });
        try testing.expectEqualSlices(u8, s.net.honest_effects, o.ok.effects);
        try testing.expectEqual(@as(u32, 1), fb.submit);
        try testing.expectEqual(@as(u32, 1), fb.finality);
        try testing.expect(fb.effects >= 3);
    }
}

test "local effects that appear during a drive answer it (notify_read_executed_effects)" {
    // every validator accepts the submission but never acknowledges: without the local arm the
    // drive would wait for finality
    const s = try setup(&even4);
    defer destroy(s);
    for (s.net.validators) |*v| {
        v.ack = .silent;
        v.full = .silent;
    }
    const L = struct {
        net: *fake.Net,
        at_ns: u64,
        asked: u32 = 0,
        q: drv.QuorumResponse,
        fn get(ctx: *anyopaque) ?drv.QuorumResponse {
            const l: *@This() = @ptrCast(@alignCast(ctx));
            l.asked += 1;
            return if (l.net.now_ns >= l.at_ns) l.q else null;
        }
    };
    const eff = try fake.effects(s.arena(), tx_digest, 0);
    var l: L = .{ .net = &s.net, .at_ns = s.net.now_ns + 700 * std.time.ns_per_ms, .q = .{ .effects_digest = @splat(0), .effects = eff, .events = null, .input_objects = null, .output_objects = null, .source = 0 } };
    s.driver = try drv.Driver.init(s.arena(), &s.committee, s.net.transport(), s.net.clock(), request(1000), .{ .reference_gas_price = 1000, .seed = 3 });
    const r = try drv.runRacing(&s.driver, s.net.waiter(), .{ .ctx = &l, .get = L.get, .every_ns = 50 * std.time.ns_per_ms });
    try std.testing.expect(r.local);
    try std.testing.expect(r.outcome == .ok);
    try std.testing.expectEqualSlices(u8, eff, r.outcome.ok.effects);
    // answered within one poll interval of the local execution, long before any timeout
    try std.testing.expect(s.net.now_ns <= l.at_ns + 50 * std.time.ns_per_ms);
    try std.testing.expect(l.asked >= 2);
}

test "a drive that finishes first is not replaced by local effects" {
    const s = try setup(&even4);
    defer destroy(s);
    const L = struct {
        fn get(_: *anyopaque) ?drv.QuorumResponse {
            return null;
        }
    };
    var dummy: u8 = 0;
    s.driver = try drv.Driver.init(s.arena(), &s.committee, s.net.transport(), s.net.clock(), request(1000), .{ .reference_gas_price = 1000, .seed = 4 });
    const r = try drv.runRacing(&s.driver, s.net.waiter(), .{ .ctx = &dummy, .get = L.get, .every_ns = 50 * std.time.ns_per_ms });
    try std.testing.expect(!r.local);
    try std.testing.expect(r.outcome == .ok);
}
