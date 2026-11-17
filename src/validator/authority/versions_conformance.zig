//! Suite `authority-versions` (val-truth): shared-object version assignment against Mysten's
//! sui-core at mainnet-v1.83.1. Vectors: `$ZUI_CORPUS/vectors/authority/versions.txt`, written by
//! tools/truth/authority/versions (format in zui_version_vectors.rs): seeded schedules of user
//! transactions, randomness state updates and commit prologues over shared objects at chosen
//! versions, with congestion and DKG cancellations, run through Rust's
//! `SharedObjVerManager::assign_versions_from_consensus`.
//!
//! Per transaction (item `<scenario>/tx<k>`): deepwave's input extraction from the TransactionData BCS
//! (`rpc_exec.checks.inputKinds`, what `tx.zig` builds UserTx from) gives Rust's shared inputs (id,
//! initial shared version, mutability, in order) and Rust's non-shared input versions (owned PTB
//! inputs, gas, then receiving objects); then deepwave's `versions.assignFromConsensus` over the whole
//! schedule gives Rust's assigned versions (shared and implicitly read system objects) for every
//! schedulable, and Rust's next versions (item `<scenario>/next`).
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const checks = @import("rpc_exec").checks;
const versions = @import("versions.zig");
const tx_mod = @import("tx.zig");

const Allocator = std.mem.Allocator;
const Id = versions.Id;
const path = "vectors/authority/versions.txt";

pub const suites = [_]harness.Suite{
    .{ .name = "authority-versions", .lane = "val-truth", .doc = "shared-object version assignment (input extraction, lamport versions, cancellations, implicit system objects, next versions) vs Mysten's sui-core", .run = run },
};

fn hexId(s: []const u8) !Id {
    var out: Id = undefined;
    _ = try std.fmt.hexToBytes(&out, s);
    return out;
}

fn parseKey(s: []const u8) !versions.Assignable.Key {
    if (std.mem.startsWith(u8, s, "d:")) return .{ .digest = try hexId(s[2..]) };
    var it = std.mem.splitScalar(u8, s, ':');
    const kind = it.next().?;
    if (std.mem.eql(u8, kind, "rand")) {
        const e = try std.fmt.parseInt(u64, it.next().?, 10);
        const r = try std.fmt.parseInt(u64, it.next().?, 10);
        return .{ .randomness_round = .{ .epoch = e, .round = r } };
    }
    if (std.mem.eql(u8, kind, "ccp")) {
        const e = try std.fmt.parseInt(u64, it.next().?, 10);
        const r = try std.fmt.parseInt(u64, it.next().?, 10);
        const i = try std.fmt.parseInt(u32, it.next().?, 10);
        return .{ .consensus_commit_prologue = .{ .epoch = e, .round = r, .sub_dag_index = i } };
    }
    return error.BadVector;
}

fn parseShared(a: Allocator, s: []const u8) ![]tx_mod.SharedInput {
    var out: std.ArrayList(tx_mod.SharedInput) = .empty;
    if (std.mem.eql(u8, s, "-")) return out.items;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |p| {
        var f = std.mem.splitScalar(u8, p, ':');
        const id = try hexId(f.next().?);
        const isv = try std.fmt.parseInt(u64, f.next().?, 10);
        const m = f.next().?;
        try out.append(a, .{ .id = id, .isv = isv, .mutability = switch (m[0]) {
            'i' => .immutable,
            'm' => .mutable,
            'n' => .non_exclusive_write,
            else => return error.BadVector,
        } });
    }
    return out.items;
}

fn parseU64s(a: Allocator, s: []const u8) ![]u64 {
    var out: std.ArrayList(u64) = .empty;
    if (std.mem.eql(u8, s, "-")) return out.items;
    var it = std.mem.splitScalar(u8, s, ',');
    while (it.next()) |p| try out.append(a, try std.fmt.parseInt(u64, p, 10));
    return out.items;
}

const Obj = struct { version: u64, start: ?u64 };

const Scenario = struct {
    name: []const u8 = "",
    implicit: versions.Implicit = .{},
    objects: std.AutoHashMapUnmanaged(Id, Obj) = .empty,
    txs: std.ArrayList(Tx) = .empty,
    assigns: std.ArrayList([]const u8) = .empty,
    next: std.ArrayList([]const u8) = .empty,
};

const Tx = struct {
    key: versions.Assignable.Key,
    data: ?[]const u8,
    shared: []tx_mod.SharedInput,
    non_shared: []u64,
    cancel: ?versions.CancelReason,
};

fn curV(ctx: *anyopaque, id: *const Id) ?versions.ObjectReader.Current {
    const s: *Scenario = @ptrCast(@alignCast(ctx));
    const o = s.objects.get(id.*) orelse return null;
    return .{ .version = o.version, .start_version = o.start };
}

fn noEpochVersion(_: *const anyopaque, _: versions.ObjKey) ?u64 {
    return null;
}

fn run(ctx: *harness.Ctx) anyerror!void {
    const gpa = ctx.gpa;
    const text = ctx.corpus.readFileAlloc(ctx.io, path, gpa, .limited(1 << 30)) catch |e| {
        ctx.skip(path, @errorName(e));
        return;
    };
    defer gpa.free(text);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var sc: Scenario = .{};
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (ctx.done()) break;
        const a = arena_state.allocator();
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        const k = it.next() orelse continue;
        if (std.mem.eql(u8, k, "vscenario")) {
            _ = arena_state.reset(.retain_capacity);
            sc = .{ .name = try arena_state.allocator().dupe(u8, it.next().?) };
        } else if (std.mem.eql(u8, k, "vimplicit")) {
            const id = try hexId(it.next().?);
            const isv = try std.fmt.parseInt(u64, it.next().?, 10);
            if (std.mem.eql(u8, &id, &versions.Implicit.acc_id)) sc.implicit.accumulator_root = isv else if (std.mem.eql(u8, &id, &versions.Implicit.fwd_id)) sc.implicit.forwarding_registry = isv else return error.BadVector;
        } else if (std.mem.eql(u8, k, "vobject")) {
            const id = try hexId(it.next().?);
            const v = try std.fmt.parseInt(u64, it.next().?, 10);
            const st = it.next().?;
            try sc.objects.put(a, id, .{ .version = v, .start = if (std.mem.eql(u8, st, "-")) null else try std.fmt.parseInt(u64, st, 10) });
        } else if (std.mem.eql(u8, k, "vtx")) {
            const key = try parseKey(it.next().?);
            const data = it.next().?;
            const shared = try parseShared(a, it.next().?);
            const ns = try parseU64s(a, it.next().?);
            const cs = it.next().?;
            var cancel: ?versions.CancelReason = null;
            if (std.mem.eql(u8, cs, "dkg")) cancel = .dkg_failed else if (std.mem.startsWith(u8, cs, "congestion:")) {
                var ids: std.ArrayList(Id) = .empty;
                const rest = cs["congestion:".len..];
                if (!std.mem.eql(u8, rest, "-")) {
                    var p = std.mem.splitScalar(u8, rest, ',');
                    while (p.next()) |h| try ids.append(a, try hexId(h));
                }
                cancel = .{ .congestion_on_objects = ids.items };
            }
            try sc.txs.append(a, .{ .key = key, .data = if (std.mem.eql(u8, data, "-")) null else try unhex(a, data), .shared = shared, .non_shared = ns, .cancel = cancel });
        } else if (std.mem.eql(u8, k, "vassign")) {
            try sc.assigns.append(a, it.rest());
        } else if (std.mem.eql(u8, k, "vnext")) {
            try sc.next.append(a, it.rest());
        } else if (std.mem.eql(u8, k, "vend")) {
            try runScenario(ctx, a, &sc);
        }
    }
}

fn unhex(a: Allocator, s: []const u8) ![]u8 {
    const out = try a.alloc(u8, s.len / 2);
    _ = try std.fmt.hexToBytes(out, s);
    return out;
}

fn sharedEql(x: []const tx_mod.SharedInput, y: []const tx_mod.SharedInput) bool {
    if (x.len != y.len) return false;
    for (x, y) |p, q| if (!std.mem.eql(u8, &p.id, &q.id) or p.isv != q.isv or p.mutability != q.mutability) return false;
    return true;
}

fn runScenario(ctx: *harness.Ctx, a: Allocator, sc: *Scenario) !void {
    // 1. deepwave's extraction from the transaction bytes.
    const assignables = try a.alloc(versions.Assignable, sc.txs.items.len);
    var cancelled: versions.Cancelled = .empty;
    for (sc.txs.items, assignables, 0..) |t, *as, k| {
        var shared = t.shared;
        var ns = t.non_shared;
        if (t.data) |bytes| {
            var nb: [96]u8 = undefined;
            const item = std.fmt.bufPrint(&nb, "{s}/tx{d}/inputs", .{ sc.name, k }) catch "inputs";
            ctx.nextItem();
            var c = ctx.check(item);
            const td = bcs.decode(types.TransactionData, a, bytes) catch |e| {
                c.failf("TransactionData decode: {s}", .{@errorName(e)});
                _ = c.finish();
                as.* = .{ .key = t.key, .shared = t.shared, .non_shared_versions = t.non_shared };
                continue;
            };
            const re = try bcs.encodeAlloc(types.TransactionData, a, &td);
            c.bytes("TransactionData re-encoded", bytes, re);
            var kinds: std.ArrayList(checks.InputKind) = .empty;
            var recv: std.ArrayList(checks.Receiving) = .empty;
            if (try checks.inputKinds(a, &td.V1, &kinds, &recv)) |f| c.failf("zui refuses the inputs: {s}", .{f.message});
            var zs: std.ArrayList(tx_mod.SharedInput) = .empty;
            var zn: std.ArrayList(u64) = .empty;
            for (kinds.items) |kk| switch (kk) {
                .package => {},
                .owned => |o| try zn.append(a, o.version),
                .shared => |s| try zs.append(a, .{ .id = s.id, .isv = s.isv, .mutability = switch (s.mutability) {
                    .Immutable => .immutable,
                    .Mutable => .mutable,
                    .NonExclusiveWrite => .non_exclusive_write,
                } }),
            };
            for (recv.items) |r| try zn.append(a, r.version);
            c.eql("shared inputs equal Rust's", true, sharedEql(t.shared, zs.items));
            c.bytes("non-shared input versions", std.mem.sliceAsBytes(t.non_shared), std.mem.sliceAsBytes(zn.items));
            const digest = try tx_mod.transactionDigest(a, &td.V1);
            c.bytes("transaction digest (key)", &t.key.digest, &digest);
            _ = c.finish();
            shared = zs.items;
            ns = zn.items;
        }
        as.* = .{ .key = t.key, .shared = shared, .non_shared_versions = ns };
        if (t.cancel) |r| if (t.key.asDigest()) |d| try cancelled.put(a, d, r);
    }

    // 2. deepwave's assignment over the whole schedule.
    const vt: versions.ObjectReader.VTable = .{ .current = curV };
    const env: versions.Env = .{
        .implicit = sc.implicit,
        .epoch_versions = .{ .ctx = sc, .get = noEpochVersion },
        .reader = .{ .ctx = sc, .vtable = &vt },
    };
    const r = try versions.assignFromConsensus(a, &env, assignables, &cancelled);
    if (r.assigned.len != sc.assigns.items.len) {
        ctx.fail(sc.name, "zui assigned {d} schedulables, Rust {d}", .{ r.assigned.len, sc.assigns.items.len });
        return;
    }
    for (r.assigned, sc.assigns.items, 0..) |got, want, k| {
        var nb: [96]u8 = undefined;
        const item = std.fmt.bufPrint(&nb, "{s}/tx{d}/assigned", .{ sc.name, k }) catch "assigned";
        ctx.nextItem();
        var s: std.ArrayList(u8) = .empty;
        const sa = ctx.scratch();
        try s.print(sa, "{s} ", .{keyText(sa, got.key) catch ""});
        if (got.shared.len == 0) try s.append(sa, '-');
        for (got.shared, 0..) |v, i| {
            if (i > 0) try s.append(sa, ',');
            try s.print(sa, "{x}:{d}:{d}", .{ &v.id, v.isv, v.version });
        }
        try s.append(sa, ' ');
        if (got.system.len == 0) try s.append(sa, '-');
        for (got.system, 0..) |v, i| {
            if (i > 0) try s.append(sa, ',');
            try s.print(sa, "{x}:{d}:{d}", .{ &v.id, v.isv, v.version });
        }
        _ = ctx.expectText(item, "assigned versions", want, s.items);
    }
    // 3. next versions, sorted as Rust sorts them (by id, then initial shared version).
    {
        var nb: [96]u8 = undefined;
        const item = std.fmt.bufPrint(&nb, "{s}/next", .{sc.name}) catch "next";
        ctx.nextItem();
        const sa = ctx.scratch();
        const keys = try sa.dupe(versions.ObjKey, r.next_versions.keys());
        std.mem.sort(versions.ObjKey, keys, {}, versions.ObjKey.lessThan);
        var s: std.ArrayList(u8) = .empty;
        for (keys) |key| try s.print(sa, "{x} {d} {d}\n", .{ &key.id, key.isv, r.next_versions.get(key).? });
        var w: std.ArrayList(u8) = .empty;
        for (sc.next.items) |l| try w.print(sa, "{s}\n", .{l});
        _ = ctx.expectText(item, "next versions", w.items, s.items);
    }
}

fn keyText(a: Allocator, k: versions.Assignable.Key) ![]const u8 {
    return switch (k) {
        .digest => |d| std.fmt.allocPrint(a, "d:{x}", .{&d}),
        .randomness_round => |x| std.fmt.allocPrint(a, "rand:{d}:{d}", .{ x.epoch, x.round }),
        .accumulator_settlement => |x| std.fmt.allocPrint(a, "settle:{d}:{d}", .{ x.epoch, x.height }),
        .consensus_commit_prologue => |x| std.fmt.allocPrint(a, "ccp:{d}:{d}:{d}", .{ x.epoch, x.round, x.sub_dag_index }),
    };
}
