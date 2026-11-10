//! Stage 6 of the validator speed bench: shared-object version assignment and congestion
//! control over committed transaction sets. Every checkpoint of `bench/val-bench/versions.list`
//! is one consensus commit, in checkpoint order: its consensus commit prologue, user transactions,
//! randomness and authenticator state updates (settlements and epoch-change transactions are left
//! out on both sides). Same inputs and rules as tools/truth/val-bench `versions`:
//!
//!   assign      authority/versions.zig assignFromConsensus per commit (get-or-init from the
//!               epoch's next-version map, objects absent from the store start at their initial
//!               shared version, then assign_versions_for_certificate per schedulable), the new
//!               next versions written back. Every 97th shared-object user transaction is
//!               cancelled for congestion on its first shared input, every 211th for a failed DKG.
//!   congestion  authority/congestion.zig: Estimator.getEstimateNs (no observations: default
//!               durations), Tracker.shouldDefer (empty previously-deferred set) and bump per user
//!               transaction with shared inputs, then finishCommit's debts seed the next commit.
//!               Commit period 50 ms; parameters of the newest protocol in the list.
//!
//! The implicitly read system objects come from the Rust side's test authority (its epoch start
//! configuration), the first line of rust-versions.out.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const common = @import("common.zig");
const versions = @import("../authority/versions.zig");
const congestion = @import("../authority/congestion.zig");
const tx_mod = @import("../authority/tx.zig");
const messages = @import("../messages.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

const Commit = struct {
    seq: u64,
    assignables: []const versions.Assignable,
    cancelled: versions.Cancelled,
    /// user programmable transactions: (index into assignables, parsed tx)
    users: []const struct { usize, tx_mod.UserTx },
};

const EpochMap = std.AutoHashMapUnmanaged(versions.ObjKey, u64);

fn getV(ctx: *const anyopaque, k: versions.ObjKey) ?u64 {
    const m: *const EpochMap = @ptrCast(@alignCast(ctx));
    return m.get(k);
}
fn absent(_: *anyopaque, _: *const Id) ?versions.ObjectReader.Current {
    return null;
}
const absent_vt: versions.ObjectReader.VTable = .{ .current = absent };

fn id8(id: *const Id) [8]u8 {
    var out: [8]u8 = undefined;
    _ = std.fmt.bufPrint(&out, "{x}", .{id[0..4]}) catch unreachable;
    return out;
}

/// One commit's assignment (the timed part), then the epoch map update.
fn assignCommit(a: Allocator, gpa: Allocator, implicit: versions.Implicit, map: *EpochMap, c: *const Commit) ![]versions.Assigned {
    var dummy: u8 = 0;
    const env: versions.Env = .{
        .implicit = implicit,
        .epoch_versions = .{ .ctx = map, .get = getV },
        .reader = .{ .ctx = &dummy, .vtable = &absent_vt },
    };
    const r = try versions.assignFromConsensus(a, &env, c.assignables, &c.cancelled);
    var it = r.next_versions.iterator();
    while (it.next()) |kv| try map.put(gpa, kv.key_ptr.*, kv.value_ptr.*);
    return r.assigned;
}

fn congestionCommit(a: Allocator, est: *const congestion.Estimator, params: congestion.Params, period_us: u64, debts: []const congestion.Debt, c: *const Commit, line: ?*std.Io.Writer) ![]congestion.Debt {
    var t = try congestion.Tracker.init(a, debts, params, false);
    const prev: congestion.PrevDeferred = .empty;
    if (line) |w| try w.print("{d} cc", .{c.seq});
    for (c.users) |entry| {
        const k = entry[0];
        const u = &entry[1];
        if (u.shared.len == 0) continue;
        const cost = congestion.Tracker.txCostUs(try est.getEstimateNs(a, u.data()));
        if (try t.shouldDefer(a, u, &prev, c.seq, period_us)) |d| {
            if (line) |w| {
                try w.print(" d{d}:", .{k});
                for (d.congested, 0..) |id, j| try w.print("{s}{s}", .{ if (j == 0) "" else "+", &id8(&id) });
            }
            continue;
        }
        try t.bump(a, cost, u);
        if (line) |w| try w.print(" b{d}:{d}", .{ k, cost });
    }
    const next = try t.finishCommit(a, period_us);
    if (line) |w| {
        try w.print(" max={d} debts={d}", .{ t.maxCost(), next.len });
        for (next) |d| try w.print(" {s}:{d}", .{ &id8(&d.id), d.debt });
        try w.writeByte('\n');
    }
    return next;
}

fn parseImplicit(line: []const u8) !versions.Implicit {
    var imp: versions.Implicit = .{};
    if (!std.mem.startsWith(u8, line, "implicit")) return error.BadRustOutput;
    const rest = std.mem.trim(u8, line["implicit".len..], " ");
    var it = std.mem.tokenizeScalar(u8, rest, ',');
    while (it.next()) |e| {
        const colon = std.mem.indexOfScalar(u8, e, ':') orelse return error.BadRustOutput;
        var id: Id = undefined;
        _ = try std.fmt.hexToBytes(&id, e[0..colon]);
        const v = try std.fmt.parseInt(u64, e[colon + 1 ..], 10);
        if (std.mem.eql(u8, &id, &versions.Implicit.acc_id)) imp.accumulator_root = v else if (std.mem.eql(u8, &id, &versions.Implicit.fwd_id)) imp.forwarding_registry = v else return error.BadRustOutput;
    }
    return imp;
}

fn sysId(last: u8) Id {
    var a: Id = @splat(0);
    a[31] = last;
    return a;
}

pub fn run(ctx: *harness.Ctx) anyerror!void {
    const gpa = ctx.gpa;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const files = try common.readList(ctx, a, "versions");
    const epochs = try harness.corpus_suite.loadEpochs(ctx, a);
    const rust_out = ctx.corpus.readFileAlloc(ctx.io, common.dir ++ "/rust-versions.out", a, .limited(4 << 30)) catch |e| {
        ctx.fail("versions", "no Rust output: {s}", .{@errorName(e)});
        return;
    };
    const implicit = try parseImplicit(rust_out[0 .. std.mem.indexOfScalar(u8, rust_out, '\n') orelse rust_out.len]);

    var commits: std.ArrayList(Commit) = .empty;
    var shared_tx_counter: u64 = 0;
    var last_pv: u64 = 0;
    var nsched: usize = 0;
    for (files) |rel| {
        const seq = try common.seqOf(rel);
        const blob = try ctx.corpus.readFileAlloc(ctx.io, rel, a, .limited(1 << 31));
        const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
        last_pv = @max(last_pv, epochs[cp.checkpoint_summary.data.epoch].pv);
        var asg: std.ArrayList(versions.Assignable) = .empty;
        var users: std.ArrayList(struct { usize, tx_mod.UserTx }) = .empty;
        var cancelled: versions.Cancelled = .empty;
        for (cp.transactions) |*t| {
            const st = t.transaction.data.@"0".element();
            const td = switch (st.intent_message.value) {
                .V1 => |*v| v,
            };
            const digest = try tx_mod.transactionDigest(a, td);
            const one = struct {
                fn shared(al: Allocator, id: Id, isv: u64) ![]const versions.SharedInput {
                    const s = try al.alloc(versions.SharedInput, 1);
                    s[0] = .{ .id = id, .isv = isv, .mutability = .mutable };
                    return s;
                }
            };
            switch (td.kind) {
                .ConsensusCommitPrologue, .ConsensusCommitPrologueV2, .ConsensusCommitPrologueV3, .ConsensusCommitPrologueV4 => {
                    try asg.append(a, .{ .key = .{ .digest = digest }, .shared = try one.shared(a, sysId(6), 1) });
                },
                .RandomnessStateUpdate => |r| try asg.append(a, .{ .key = .{ .digest = digest }, .shared = try one.shared(a, sysId(8), r.randomness_obj_initial_shared_version.@"0") }),
                .AuthenticatorStateUpdate => |u| try asg.append(a, .{ .key = .{ .digest = digest }, .shared = try one.shared(a, sysId(7), u.authenticator_obj_initial_shared_version.@"0") }),
                .ProgrammableTransaction => {
                    const plain: messages.PlainTransactionWithClaims = .{ .tx = .{ .data = t.transaction.data, .auth_signature = .{} }, .claims = &.{} };
                    const u = try tx_mod.fromDecoded(a, "", plain);
                    const ns = try a.alloc(u64, u.owned.len + u.receiving.len);
                    for (u.owned, 0..) |o, k| ns[k] = o.version;
                    for (u.receiving, 0..) |o, k| ns[u.owned.len + k] = o.version;
                    if (u.shared.len != 0) {
                        shared_tx_counter += 1;
                        if (shared_tx_counter % 97 == 0) {
                            const ids = try a.alloc(Id, 1);
                            ids[0] = u.shared[0].id;
                            try cancelled.put(a, u.digest, .{ .congestion_on_objects = ids });
                        } else if (shared_tx_counter % 211 == 0) {
                            try cancelled.put(a, u.digest, .dkg_failed);
                        }
                    }
                    try users.append(a, .{ asg.items.len, u });
                    try asg.append(a, .{ .key = .{ .digest = u.digest }, .shared = u.shared, .non_shared_versions = ns });
                },
                else => continue,
            }
        }
        nsched += asg.items.len;
        try commits.append(a, .{ .seq = seq, .assignables = asg.items, .cancelled = cancelled, .users = users.items });
    }

    // reference outputs
    var outw: std.Io.Writer.Allocating = .init(a);
    const w = &outw.writer;
    try w.writeAll(rust_out[0 .. (std.mem.indexOfScalar(u8, rust_out, '\n') orelse 0) + 1]);
    var map: EpochMap = .empty;
    defer map.deinit(gpa);
    for (commits.items) |*c| {
        var scratch: std.heap.ArenaAllocator = .init(gpa);
        defer scratch.deinit();
        const got = try assignCommit(scratch.allocator(), gpa, implicit, &map, c);
        for (got, 0..) |g, i| {
            try w.print("{d} {d} {x} s=", .{ c.seq, i, &g.key.digest });
            for (g.shared, 0..) |s, k| try w.print("{s}{x}:{d}:{d}", .{ if (k == 0) "" else ",", &s.id, s.isv, s.version });
            var acc: ?versions.SystemVersion = null;
            var fwd: ?versions.SystemVersion = null;
            for (g.system) |s| {
                if (std.mem.eql(u8, &s.id, &versions.Implicit.acc_id)) acc = s;
                if (std.mem.eql(u8, &s.id, &versions.Implicit.fwd_id)) fwd = s;
            }
            if (acc) |s| try w.print(" acc={d}:{d}", .{ s.isv, s.version }) else try w.writeAll(" acc=-");
            if (fwd) |s| try w.print(" fwd={d}:{d}\n", .{ s.isv, s.version }) else try w.writeAll(" fwd=-\n");
        }
    }
    {
        const keys = try a.alloc(versions.ObjKey, map.count());
        var it = map.keyIterator();
        var k: usize = 0;
        while (it.next()) |kp| : (k += 1) keys[k] = kp.*;
        std.mem.sort(versions.ObjKey, keys, {}, versions.ObjKey.lessThan);
        for (keys) |key| try w.print("next {x}:{d} {d}\n", .{ &key.id, key.isv, map.get(key).? });
    }
    const v_len = outw.written().len;
    const v_dg = common.digestHex(outw.written()[0..v_len]);

    // timed assignment
    const best = try a.alloc(u64, commits.items.len);
    @memset(best, std.math.maxInt(u64));
    for (0..3) |_| {
        var m: EpochMap = .empty;
        defer m.deinit(gpa);
        for (commits.items, best) |*c, *b| {
            var scratch: std.heap.ArenaAllocator = .init(gpa);
            defer scratch.deinit();
            const t0 = common.now(ctx.io);
            std.mem.doNotOptimizeAway(try assignCommit(scratch.allocator(), gpa, implicit, &m, c));
            b.* = @min(b.*, common.since(ctx.io, t0));
        }
    }
    var wall: u64 = 0;
    for (best) |x| wall += x;
    common.emit(ctx, .{ .stage = "versions", .case = "all", .mode = "assign", .threads = 1, .unit = "commit", .items = best, .count = commits.items.len, .wall_ns = wall, .out = &v_dg, .extra = try std.fmt.allocPrint(a, ",\"schedulables\":{d}", .{nsched}) });

    // congestion control
    const cfg = try protocol.get(last_pv, .mainnet);
    const params: congestion.Params = switch (cfg.feature_flags.per_object_congestion_control_mode) {
        .ExecutionTimeEstimate => |e| e,
        else => return error.NotExecutionTimeEstimate,
    };
    const stakes = [_]u64{1};
    var est = congestion.Estimator.init(gpa, &stakes, params);
    defer est.deinit();
    const period_us: u64 = 50_000;
    var clw: std.Io.Writer.Allocating = .init(a);
    try clw.writer.print("params target={d} burst={d} max={d} period_us={d}\n", .{ params.target_utilization, params.allowed_txn_cost_overage_burst_limit_us, params.max_estimate_us, period_us });
    {
        var debts: []const congestion.Debt = &.{};
        for (commits.items) |*c| debts = try congestionCommit(a, &est, params, period_us, debts, c, &clw.writer);
    }
    const c_dg = common.digestHex(clw.written());
    @memset(best, std.math.maxInt(u64));
    for (0..3) |_| {
        var debts_arena: std.heap.ArenaAllocator = .init(gpa);
        defer debts_arena.deinit();
        var debts: []const congestion.Debt = &.{};
        for (commits.items, best) |*c, *b| {
            var scratch: std.heap.ArenaAllocator = .init(gpa);
            defer scratch.deinit();
            const t0 = common.now(ctx.io);
            const next = try congestionCommit(scratch.allocator(), &est, params, period_us, debts, c, null);
            b.* = @min(b.*, common.since(ctx.io, t0));
            debts = try debts_arena.allocator().dupe(congestion.Debt, next);
        }
    }
    wall = 0;
    for (best) |x| wall += x;
    common.emit(ctx, .{ .stage = "congestion", .case = "all", .mode = "commit", .threads = 1, .unit = "commit", .items = best, .count = commits.items.len, .wall_ns = wall, .out = &c_dg });

    try w.writeAll("--- congestion\n");
    try w.writeAll(clw.written());
    _ = try common.compareOut(ctx, a, "versions", outw.written());
}
