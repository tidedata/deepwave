//! `validator-funds`: the validator's certified execution path (run/runner.zig `runUser`, `enqueued`) against
//! Mysten's code.
//!
//!   funds/<scenario>/<n>   `zui-truth-exec funds-sched` (src/validator/run/testdata/funds_sched.jsonl):
//!                          runs of certified transactions withdrawing from address balances,
//!                          grouped by assigned accumulator version, decided by sui-core's own
//!                          funds withdraw scheduler (Eager) and executed by sui-execution with the
//!                          InsufficientFundsForWithdraw early error where it said so. deepwave feeds
//!                          the same transactions through the runner's scheduling hook in commit
//!                          order and runs each one; effects and events must be byte-exact.
//!   restart/<scenario>/<k> the same runs with a validator restart after the first k
//!                          transactions (new runner over the same store, the unsettled group
//!                          re-enqueued whole): the remaining effects must not change.
//!   deny/<vector>          the `exec-move-synth` coin deny list vectors (corpus,
//!                          `zui-truth-exec synth`): the same transaction run as a certified one on
//!                          a store holding its inputs and the deny list state; Rust's failure
//!                          (AddressDeniedForCoin, CoinTypeGlobalPause) or success, byte-exact.
//!
//! System packages: the corpus (newest epoch), as Rust ran with.
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const protocol = @import("protocol");
const exec = @import("exec");
const exec_bridge = @import("../authority/exec_bridge.zig");
const versions = @import("../authority/versions.zig");
const store_mod = @import("exec_store.zig");
const runner_mod = @import("runner.zig");

const Id = [32]u8;
const funds_file = @embedFile("testdata/funds_sched.jsonl");
const synth_path = "vectors/exec-move-synth/vectors.jsonl.zst";
/// `get_mainnet_chain_identifier()` (4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S), the chain the
/// funds-sched tool ran with: it keys coin reservations and ValidDuring expirations.
const mainnet_chain_id: Id = blk: {
    var out: Id = undefined;
    _ = std.fmt.hexToBytes(&out, "35834a8ac17ca48fb14ac8f99c17c98747e95dd07294ae41a46b382246a4499b") catch unreachable;
    break :blk out;
};

pub const suites = [_]harness.Suite{
    .{ .name = "validator-funds", .lane = "val-truth", .doc = "certified execution: funds withdraw scheduling (InsufficientFundsForWithdraw) and coin deny list denials through the validator runner vs sui-core's scheduler and sui-execution", .run = run },
};

const FundsLine = struct {
    name: []const u8,
    pv: u64,
    epoch: u64,
    rgp: u64,
    start_ms: u64,
    objects: []const []const u8,
    txs: []const struct { tx: []const u8, acc: u64, status: []const u8, effects: []const u8, events: ?[]const u8 },
};

const SynthLine = struct {
    name: []const u8,
    pv: u64,
    epoch: u64,
    rgp: u64,
    start_ms: u64,
    tx: []const u8,
    objects: []const []const u8,
    latest: []const []const u8,
    effects: []const u8,
    events: ?[]const u8,
    written: []const []const u8 = &.{},
    loaded: ?[]const struct { id: []const u8, version: u64 } = null,
    digest: ?[]const u8 = null,
};

fn unhex(a: std.mem.Allocator, h: []const u8) ![]u8 {
    const out = try a.alloc(u8, h.len / 2);
    _ = try std.fmt.hexToBytes(out, h);
    return out;
}

/// A runner over a fresh in-memory store holding `objs` (one record each, in order), with the
/// corpus packages.
const Rig = struct {
    store: store_mod.ExecStore,
    r: runner_mod.Runner = undefined,

    fn init(rig: *Rig, ctx: *harness.Ctx, a: std.mem.Allocator, pkgs: *const exec.packages.Store, cfg: *const protocol.ProtocolConfig, epoch: u64, start_ms: u64, rgp: u64, objs: []const []const u8) !void {
        rig.store = store_mod.ExecStore.openMem(ctx.gpa, ctx.io);
        for (objs, 0..) |raw, i| {
            var d: Id = @splat(0xee);
            std.mem.writeInt(u64, d[0..8], i, .little);
            try rig.store.commitTx(&.{ .digest = d, .td_bcs = "", .effects_bcs = "", .written = &.{raw} });
        }
        _ = a;
        rig.r.init(ctx.gpa, &rig.store, .{ .cfg = cfg, .epoch = epoch, .epoch_start_ms = start_ms, .rgp = rgp, .chain_id = mainnet_chain_id });
        rig.r.pkgs.user.deinit(ctx.gpa);
        rig.r.pkgs.system.deinit(ctx.gpa);
        rig.r.pkgs = pkgs.*;
        // packages the vector publishes (the vault) are in the store
        rig.r.pkgs.lookup = rig.store.packageLookup();
    }

    /// A validator restart: a new runner (empty funds scheduler and unsettled withdrawals) over
    /// the same store.
    fn restart(rig: *Rig, ctx: *harness.Ctx, pkgs: *const exec.packages.Store, cfg: *const protocol.ProtocolConfig, epoch: u64, start_ms: u64, rgp: u64) void {
        rig.r.pkgs = .{};
        rig.r.deinit();
        rig.r.init(ctx.gpa, &rig.store, .{ .cfg = cfg, .epoch = epoch, .epoch_start_ms = start_ms, .rgp = rgp, .chain_id = mainnet_chain_id });
        rig.r.pkgs.user.deinit(ctx.gpa);
        rig.r.pkgs.system.deinit(ctx.gpa);
        rig.r.pkgs = pkgs.*;
        // packages the vector publishes (the vault) are in the store
        rig.r.pkgs.lookup = rig.store.packageLookup();
    }

    fn deinit(rig: *Rig) void {
        // the package store belongs to the suite
        rig.r.pkgs = .{};
        rig.r.deinit();
        rig.store.close();
    }
};

fn run(ctx: *harness.Ctx) anyerror!void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const pkgs = try exec.packages.load(ctx, arena, last);

    var it = harness.lines(funds_file);
    while (it.next()) |line| {
        ctx.nextItem();
        const a = ctx.scratch();
        const v = std.json.parseFromSliceLeaky(FundsLine, a, line, .{}) catch |e| {
            ctx.fail("funds", "line: {s}", .{@errorName(e)});
            continue;
        };
        runFunds(ctx, a, &pkgs, &v) catch |e| ctx.fail(v.name, "{s}", .{@errorName(e)});
    }

    if (ctx.corpus.readFileAlloc(ctx.io, synth_path, arena, .limited(1 << 30))) |z| {
        const text = try harness.decompressZstd(arena, z, 1 << 31);
        var lines = harness.lines(text);
        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line[0..@min(line.len, 64)], "\"name\":\"deny/") == null and
                std.mem.indexOf(u8, line[0..@min(line.len, 64)], "\"name\":\"config/") == null) continue;
            ctx.nextItem();
            const a = ctx.scratch();
            const v = std.json.parseFromSliceLeaky(SynthLine, a, line, .{ .ignore_unknown_fields = true }) catch |e| {
                ctx.fail("deny", "line: {s}", .{@errorName(e)});
                continue;
            };
            const item = try std.fmt.allocPrint(a, "deny/{s}", .{v.name});
            if (ctx.selected(item)) runDeny(ctx, a, &pkgs, item, &v) catch |e| ctx.fail(item, "{s}", .{@errorName(e)});
        }
    } else |e| ctx.fail("deny", "read {s}: {s}", .{ synth_path, @errorName(e) });
}

fn runFunds(ctx: *harness.Ctx, a: std.mem.Allocator, pkgs: *const exec.packages.Store, v: *const FundsLine) !void {
    const cfg = try protocol.get(v.pv, .mainnet);
    const objs = try a.alloc([]const u8, v.objects.len);
    for (v.objects, objs) |h, *o| o.* = try unhex(a, h);
    var rig: Rig = .{ .store = undefined };
    try rig.init(ctx, a, pkgs, cfg, v.epoch, v.start_ms, v.rgp, objs);
    defer rig.deinit();
    const items = try a.alloc(exec_bridge.Item, v.txs.len);
    for (v.txs, items) |t, *item| {
        const td_bcs = try unhex(a, t.tx);
        const sys = try a.alloc(versions.SystemVersion, 1);
        sys[0] = .{ .id = runner_mod.acc_root_id, .isv = 3, .version = t.acc };
        item.* = .{ .key = .{ .digest = types.digest.transactionDataDigest(td_bcs) }, .kind = .user, .td_bcs = td_bcs, .digest = types.digest.transactionDataDigest(td_bcs), .shared = &.{}, .system = sys };
        // collect_withdraw_reservations, in commit order
        try rig.r.enqueued(item);
    }
    for (v.txs, items, 0..) |t, *item, n| {
        const name = try std.fmt.allocPrint(a, "funds/{s}/{d}", .{ v.name, n });
        if (!ctx.selected(name)) continue;
        var c = ctx.check(name);
        const e = rig.r.run(a, item) catch |err| {
            c.failf("runner: {s} ({s}; Rust status {s})", .{ @errorName(err), rig.r.lastError(), t.status });
            _ = c.finish();
            continue;
        };
        const want = try unhex(a, t.effects);
        if (!std.mem.eql(u8, want, e.effects_bcs)) c.failf("effects differ (Rust status {s}): {s}", .{ t.status, exec.replay.effectsDiff(a, e.effects_bcs, want) });
        if (t.events) |h| {
            const w = try unhex(a, h);
            if (e.events_bcs) |g| c.bytes("events", w, g) else c.failf("Rust has events, zui none", .{});
        } else if (e.events_bcs != null) c.failf("zui has events, Rust none", .{});
        _ = c.finish();
    }
    try runRestarts(ctx, a, pkgs, cfg, v, objs, items);
}

/// `restart/<scenario>/<k>`: the first k transactions execute, the validator restarts, and the
/// bridge re-enqueues the whole unsettled group in commit order (executed members held unacked
/// until their settlement, exec_bridge.zig `held`); the rest must still match Rust, which
/// decided them with the executed members' reservations and unsettled object withdrawals.
fn runRestarts(ctx: *harness.Ctx, a: std.mem.Allocator, pkgs: *const exec.packages.Store, cfg: *const protocol.ProtocolConfig, v: *const FundsLine, objs: []const []const u8, items: []const exec_bridge.Item) !void {
    var k: usize = 1;
    while (k < v.txs.len) : (k += 1) {
        const name = try std.fmt.allocPrint(a, "restart/{s}/{d}", .{ v.name, k });
        if (!ctx.selected(name)) continue;
        var c = ctx.check(name);
        var rig: Rig = .{ .store = undefined };
        try rig.init(ctx, a, pkgs, cfg, v.epoch, v.start_ms, v.rgp, objs);
        defer rig.deinit();
        for (items) |*item| try rig.r.enqueued(item);
        for (items[0..k]) |*item| {
            if (rig.r.run(a, item)) |_| {} else |_| {}
        }
        rig.restart(ctx, pkgs, cfg, v.epoch, v.start_ms, v.rgp);
        for (items) |*item| try rig.r.enqueued(item);
        for (v.txs, items, 0..) |t, *item, n| {
            const e = rig.r.run(a, item) catch |err| {
                if (n >= k) c.failf("tx {d}: runner: {s} ({s}; Rust status {s})", .{ n, @errorName(err), rig.r.lastError(), t.status });
                continue;
            };
            if (n < k) continue;
            const want = try unhex(a, t.effects);
            if (!std.mem.eql(u8, want, e.effects_bcs)) c.failf("tx {d}: effects differ (Rust status {s}): {s}", .{ n, t.status, exec.replay.effectsDiff(a, e.effects_bcs, want) });
        }
        _ = c.finish();
    }
}

fn runDeny(ctx: *harness.Ctx, a: std.mem.Allocator, pkgs: *const exec.packages.Store, item_name: []const u8, v: *const SynthLine) !void {
    const cfg = try protocol.get(v.pv, .mainnet);
    var objs: std.ArrayList([]const u8) = .empty;
    for (v.objects) |h| try objs.append(a, try unhex(a, h));
    for (v.latest) |h| try objs.append(a, try unhex(a, h));
    var rig: Rig = .{ .store = undefined };
    try rig.init(ctx, a, pkgs, cfg, v.epoch, v.start_ms, v.rgp, objs.items);
    defer rig.deinit();
    const td_bcs = try unhex(a, v.tx);
    const td = (try bcs.decode(types.TransactionData, a, td_bcs)).V1;
    const want = try unhex(a, v.effects);
    const fx = (try bcs.decode(types.TransactionEffects, a, want)).V2;
    // shared inputs at the versions Rust's effects name (consensus assigned them)
    var shared: std.ArrayList(versions.SharedVersion) = .empty;
    for (fx.changed_objects) |*ch| switch (ch[1].input_state) {
        .Exist => |x| if (x[1] == .Shared) try shared.append(a, .{ .id = ch[0].@"0".@"0", .isv = 0, .version = x[0][0].@"0" }),
        else => {},
    };
    for (fx.unchanged_consensus_objects) |*u| switch (u[1]) {
        .ReadOnlyRoot => |vd| try shared.append(a, .{ .id = u[0].@"0".@"0", .isv = 0, .version = vd[0].@"0" }),
        else => {},
    };
    var digest = types.digest.transactionDataDigest(td_bcs);
    if (v.digest) |h| _ = try std.fmt.hexToBytes(&digest, h);
    _ = td;
    const item: exec_bridge.Item = .{ .key = .{ .digest = digest }, .kind = .user, .td_bcs = td_bcs, .digest = digest, .shared = shared.items, .system = &.{} };
    const e = rig.r.run(a, &item) catch |err| {
        var c = ctx.check(item_name);
        // a vector crafted past the signing checks (`out-of-gas`: a budget below
        // `base_tx_cost_fixed * price`, which Rust's executor ran unchecked): sui-core's
        // `check_certificate_input` -> `check_gas` refuses it (`ExecutionOutput::Fatal`, no
        // effects), and so must the runner
        const refused = err == error.Failed and std.mem.endsWith(u8, v.name, "out-of-gas") and std.mem.indexOf(u8, rig.r.lastError(), "is lower than min") != null;
        if (!refused) c.failf("runner: {s} ({s})", .{ @errorName(err), rig.r.lastError() });
        _ = c.finish();
        return;
    };
    var c = ctx.check(item_name);
    if (!std.mem.eql(u8, want, e.effects_bcs)) c.failf("effects differ: {s}", .{exec.replay.effectsDiff(a, e.effects_bcs, want)});
    if (v.events) |h| {
        const w = try unhex(a, h);
        if (e.events_bcs) |g| c.bytes("events", w, g) else c.failf("Rust has events, zui none", .{});
    } else if (e.events_bcs != null) c.failf("zui has events, Rust none", .{});
    _ = c.finish();
}
