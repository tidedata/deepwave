//! Coin deny list v2 reads during execution (`check_coin_deny_list_v2_during_execution`): Rust
//! reads the per-type config and its settings through the tracking store, so they show up in
//! `unchanged_loaded_runtime_objects`. exec-move charges for the check and, without the store's
//! latest objects, assumes it passes; this makes the reads against the pre-state and reports a
//! pause or a denied owner (the effects would differ).
//!
//! The check itself is exec's (`exec.ptb.deny.check`, the one the Move-call and coin executors
//! run): one implementation of the read order and of the setting decode. Here it runs over the
//! simulation's pre-state, and every object it finds is recorded.
const std = @import("std");
const bcs = @import("bcs");
const types = @import("types");
const exec = @import("exec");

const state_mod = @import("state.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const ObjectView = exec.objects.ObjectView;
const State = state_mod.State;
pub const Ref = struct { id: Id, version: u64 };

/// (coin type, owner) pairs that received funds: exec-move's `Output.deny_pairs` (written
/// `Coin<T>` objects and `Balance<T>` accumulator events of context::finish, SUI excluded).
pub const Pairs = struct {
    items: std.ArrayList(struct { ty: types.TypeTag, owner: Id }) = .empty,
};

pub fn fromPtb(arena: Allocator, list: []const exec.ptb.run.DenyPair) !Pairs {
    var p: Pairs = .{};
    for (list) |x| try p.items.append(arena, .{ .ty = try bcs.decode(types.TypeTag, arena, x.t), .owner = x.o });
    return p;
}

pub const Outcome = union(enum) {
    ok,
    /// A paused coin type or a denied owner: the execution would fail (not modelled).
    denied: []const u8,
};

/// The pre-state as the check's store: every object a lookup finds is a read.
const Recorder = struct {
    state: State,
    arena: Allocator,
    reads: *std.ArrayList(Ref),
    oom: bool = false,

    fn get(p: *const anyopaque, id: *const Id) ?[]const u8 {
        const r: *Recorder = @ptrCast(@alignCast(@constCast(p)));
        const raw = r.state.latest(id) orelse return null;
        const v = ObjectView.parse(raw) catch return null;
        r.reads.append(r.arena, .{ .id = id.*, .version = v.version }) catch {
            r.oom = true;
        };
        return raw;
    }
};

/// Makes the reads for `pairs` (any order, duplicates allowed) and appends each object read to
/// `reads`, in read order. The lookups are Rust's, in Rust's order: the per-type config field
/// of every coin type in canonical type string order (`get_per_type_coin_deny_list_v2`, the
/// `filter_map` collected into `regulated_coin_owners`); then, for each type that has a config,
/// in the same order, the global pause setting and each owner's setting in address order
/// (`check_new_regulated_coin_owners`), up to the first setting that reads true at `epoch`
/// (`read_value(Some(epoch))`: the newer value when `epoch > newer_value_epoch`, else the older).
pub fn check(arena: Allocator, state: State, epoch: u64, pairs: *const Pairs, reads: *std.ArrayList(Ref)) !Outcome {
    if (pairs.items.items.len == 0) return .ok;
    var list: std.ArrayList(exec.ptb.deny.Pair) = .empty;
    for (pairs.items.items) |*pr| try exec.ptb.deny.addPair(arena, &list, try exec.ptb.deny.canonical(arena, &pr.ty), pr.owner, pr.ty);
    var rec: Recorder = .{ .state = state, .arena = arena, .reads = reads };
    const denied = try exec.ptb.deny.check(arena, .{ .ctx = &rec, .get = Recorder.get }, epoch, list.items);
    if (rec.oom) return error.OutOfMemory;
    const d = denied orelse return .ok;
    return .{ .denied = switch (d) {
        .pause => |ty| try std.fmt.allocPrint(arena, "coin type {s} is globally paused", .{ty}),
        .address => |x| try std.fmt.allocPrint(arena, "address denied for coin type {s}", .{x.coin_type}),
    } };
}

// The lookups of `check` against Mysten's executor: the vectors of exec's
// `testdata/deny_order.jsonl` carry every store read of
// `check_coin_deny_list_v2_during_execution` in call order. The pairs are handed over in
// reverse command order, so the order of the lookups is the check's own.
test "the simulation check makes Rust's deny list reads in Rust's order (Rust-made vectors)" {
    const vectors = exec.ptb.deny_order_vectors;
    const TestState = struct {
        arena: Allocator,
        latest: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,
        /// Every `latest` call, in call order.
        log: std.ArrayList(Id) = .empty,

        fn getLatest(p: *const anyopaque, id: *const Id) ?[]const u8 {
            const s: *@This() = @ptrCast(@alignCast(@constCast(p)));
            s.log.append(s.arena, id.*) catch @panic("OOM");
            return s.latest.get(id.*);
        }
        fn none(_: *const anyopaque, _: *const Id, _: u64) ?[]const u8 {
            return null;
        }
        const vtable: State.VTable = .{ .latest = getLatest, .at = none, .child_at_most = none };
    };
    var arena_state: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena_state.deinit();
    var n: usize = 0;
    var it = std.mem.tokenizeScalar(u8, vectors.text, '\n');
    while (it.next()) |line| {
        _ = arena_state.reset(.retain_capacity);
        const a = arena_state.allocator();
        const v = try std.json.parseFromSliceLeaky(vectors.Line, a, line, .{});
        // out of gas before context::finish: exec hands simulation no pairs, nothing to check
        if (std.mem.eql(u8, v.name, "out-of-gas/before-finish")) continue;
        var ts: TestState = .{ .arena = a };
        for (v.latest) |h| {
            const raw = try vectors.unhex(a, h);
            try ts.latest.put(a, (try ObjectView.parse(raw)).id, raw);
        }
        var pairs: Pairs = .{};
        const rcv = try vectors.receivers(a, &v);
        var i = rcv.len;
        while (i > 0) {
            i -= 1;
            try pairs.items.append(a, .{ .ty = rcv[i].ty, .owner = rcv[i].owner });
        }
        var reads: std.ArrayList(Ref) = .empty;
        const out = try check(a, .{ .ctx = &ts, .vtable = &TestState.vtable }, v.epoch, &pairs, &reads);

        // every lookup, hit or miss, in Rust's order
        errdefer std.debug.print("deny order vector {s}\n", .{v.name});
        try std.testing.expectEqual(v.reads.len, ts.log.items.len);
        var hits: usize = 0;
        for (v.reads, ts.log.items) |r, *got| {
            try std.testing.expectEqualSlices(u8, try vectors.unhex(a, r.id), got);
            if (!r.hit) continue;
            // the objects that exist are the reported reads, in the same order, at their version
            try std.testing.expect(hits < reads.items.len);
            try std.testing.expectEqualSlices(u8, got, &reads.items[hits].id);
            try std.testing.expectEqual((try ObjectView.parse(ts.latest.get(got.*).?)).version, reads.items[hits].version);
            hits += 1;
        }
        try std.testing.expectEqual(hits, reads.items.len);

        // the check's own result: Rust's status, or for the vectors that then run out of gas
        // at the charge (the status hides it) what the vector's name says the store held
        const fx = (try bcs.decode(types.TransactionEffects, a, try vectors.unhex(a, v.effects))).V2;
        const type_a = "0000000000000000000000000000000000000000000000000000000000000001::ascii::String";
        const want: ?[]const u8 = if (std.mem.startsWith(u8, v.name, "out-of-gas/"))
            (if (std.mem.endsWith(u8, v.name, "-denied")) "address denied for coin type " ++ type_a else if (std.mem.endsWith(u8, v.name, "-paused")) "coin type " ++ type_a ++ " is globally paused" else null)
        else switch (fx.status) {
            .Success => null,
            .Failure => |f| switch (f.@"error") {
                .CoinTypeGlobalPause => |x| try std.fmt.allocPrint(a, "coin type {s} is globally paused", .{x.coin_type.@"0"}),
                .AddressDeniedForCoin => |x| try std.fmt.allocPrint(a, "address denied for coin type {s}", .{x.coin_type.@"0"}),
                else => return error.TestUnexpectedResult,
            },
        };
        if (want) |w| {
            try std.testing.expect(out == .denied);
            try std.testing.expectEqualStrings(w, out.denied);
        } else try std.testing.expect(out == .ok);
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 29), n);
}
