//! Gas profiler on real traffic: picks the newest mainnet transactions that call
//! a package from the store, re-runs each on deepwave's simulation engine against the store's current
//! state with the VM's per-instruction gas attribution on (src/move/vm/profile.zig), and reports
//! gas per function, per instruction and per opcode.
//!
//! The re-run uses the transaction as recorded, in dev-inspect mode (no replay or ownership checks) with
//! owned inputs and gas coins rebased to their current versions (liveOverrides hands the engine the
//! live objects so its rebase runs; an input that no longer exists stays at its recorded ref and
//! the run is likely rejected, which is counted and printed), so a transaction whose shared objects changed
//! since may take another path or abort: such runs are listed, and `--checks` runs the engine's
//! full simulate mode instead. The recorded computation cost is printed next to the replayed
//! one for calibration.
const std = @import("std");
const common = @import("common.zig");
const bcs = @import("bcs");
const types = @import("types");
const node = @import("node");
const exec = @import("exec");
const protocol = @import("protocol");
const rpc_exec = @import("rpc_exec");
const simulate = @import("simulate");
const vm = @import("move_vm");

const Allocator = std.mem.Allocator;
const Id = common.Id;
const store = node.store;
const ff = common.ff;

/// Package bytes for the simulation engine, read from the store's live set (immutable per id
/// except system packages, which the store holds at the current epoch's version).
pub const Substitute = struct { id: Id, raw: []const u8 };

pub const PkgLookup = struct {
    gpa: Allocator,
    st: *store.Store,
    /// Served instead of the store's bytes for this package id (differential execution).
    substitute: ?Substitute = null,
    cache: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,

    pub fn get(ctx: *const anyopaque, id: *const Id, epoch: u64) ?[]const u8 {
        _ = epoch;
        const l: *PkgLookup = @ptrCast(@alignCast(@constCast(ctx)));
        if (l.substitute) |s| if (std.mem.eql(u8, &s.id, id)) return s.raw;
        if (l.cache.get(id.*)) |b| return b;
        var snap = l.st.snapshot();
        defer snap.release();
        const live = snap.liveObject(id) orelse return null;
        const v = exec.objects.ObjectView.parse(live.bytes) catch return null;
        if (!v.is_package) return null;
        const owned = l.gpa.dupe(u8, live.bytes) catch return null;
        l.cache.put(l.gpa, id.*, owned) catch return null;
        return owned;
    }
};

/// The engine over a stopped node directory's store. Fields point into each other: init in place.
pub const Sim = struct {
    lookup: PkgLookup,
    pkgs: exec.packages.Store,
    env: rpc_exec.epoch_env.Cache,
    engine: simulate.api.Engine,

    pub fn init(s: *Sim, gpa: Allocator, io: std.Io, st: *store.Store, substitute: ?Substitute) !void {
        s.lookup = .{ .gpa = gpa, .st = st, .substitute = substitute };
        s.pkgs = .{ .loaded = true };
        s.pkgs.lookup = .{ .ctx = &s.lookup, .get = PkgLookup.get };
        s.env = .{ .gpa = gpa, .io = io, .st = st, .chain_id = node.node.mainnet_chain_id, .layout_cfg = try protocol.get(protocol.max_protocol_version, .mainnet) };
        s.engine = .{
            .core = .{ .gpa = gpa, .pkgs = &s.pkgs, .io = io },
            .tip = .{ .store = st, .env = s.env.source() },
        };
    }
};

/// The live objects of the transaction's owned and receiving inputs and gas coins, as simulate
/// overrides: the engine rebases those refs to the live (version, digest). Empty when the
/// transaction does not decode.
pub fn liveOverrides(arena: Allocator, snap: *const store.Snapshot, tx: []const u8) ![]const []const u8 {
    const all = bcs.decode(types.TransactionData, arena, tx) catch return &.{};
    const td = switch (all) {
        .V1 => |v| v,
    };
    var out: std.ArrayList([]const u8) = .empty;
    switch (td.kind) {
        .ProgrammableTransaction => |pt| for (pt.inputs) |in| {
            const obj = switch (in) {
                .Object => |o| o,
                else => continue,
            };
            const ref = switch (obj) {
                .ImmOrOwnedObject => |r| r,
                .Receiving => |r| r,
                .SharedObject => continue,
            };
            if (snap.liveObject(&ref[0].@"0".@"0")) |l| try out.append(arena, try arena.dupe(u8, l.bytes));
        },
        else => {},
    }
    for (td.gas_data.payment) |r| {
        if (snap.liveObject(&r[0].@"0".@"0")) |l| try out.append(arena, try arena.dupe(u8, l.bytes));
    }
    return out.items;
}

pub const Recorded = struct { digest: Id, checkpoint: u64, tx: []const u8, computation: u64 };

/// The newest transactions calling `target` (original package id), newest first.
pub fn collectCalls(gpa: Allocator, arena: Allocator, snap: *const store.Snapshot, target: Id, exact: ?Id, module: ?[]const u8, function: ?[]const u8, scan_checkpoints: u64, limit: usize) ![]Recorded {
    const tip = snap.highestCommitted() orelse return &.{};
    const low = snap.lowestAvailable() orelse 0;
    var oc: common.OriginCache = .{ .arena = arena, .snap = snap };
    var out: std.ArrayList(Recorded) = .empty;
    var tmp: std.heap.ArenaAllocator = .init(gpa);
    defer tmp.deinit();
    var seq = tip;
    var scanned: u64 = 0;
    while (scanned < scan_checkpoints and out.items.len < limit) : (scanned += 1) {
        defer {
            if (seq == 0) scanned = scan_checkpoints else seq -= 1;
        }
        if (seq < low) break;
        _ = tmp.reset(.retain_capacity);
        const a = tmp.allocator();
        const rec = (snap.checkpointChecked(seq) catch continue) orelse continue;
        const contents = bcs.decode(types.CheckpointContents, a, rec.contents) catch continue;
        const n = switch (contents) {
            .V1 => |v| v.transactions.len,
            .V2 => |v| v.transactions.len,
        };
        var i = n;
        while (i > 0 and out.items.len < limit) {
            i -= 1;
            const dg: *const Id = switch (contents) {
                .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
                .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
            };
            const t = (snap.transactionChecked(dg) catch continue) orelse continue;
            const td = bcs.decode(types.TransactionData, a, t.tx) catch continue;
            const ptb = switch (td.V1.kind) {
                .ProgrammableTransaction => |p| p,
                else => continue,
            };
            var hit = false;
            for (ptb.commands) |c| switch (c) {
                .MoveCall => |mc| {
                    if (module) |m| if (!std.mem.eql(u8, m, mc.module.@"0")) continue;
                    if (function) |f| if (!std.mem.eql(u8, f, mc.function.@"0")) continue;
                    if (exact) |x| {
                        if (!std.mem.eql(u8, &x, &mc.package.@"0".@"0")) continue;
                    }
                    const orig = oc.original(&mc.package.@"0".@"0");
                    if (std.mem.eql(u8, &orig, &target)) hit = true;
                },
                else => {},
            };
            if (!hit) continue;
            var comp: u64 = 0;
            if (bcs.decode(types.TransactionEffects, a, t.effects)) |e| {
                comp = switch (e) {
                    .V1 => |x| x.gas_used.computationCost,
                    .V2 => |x| x.gas_used.computationCost,
                };
            } else |_| {}
            try out.append(arena, .{ .digest = dg.*, .checkpoint = t.checkpoint, .tx = try arena.dupe(u8, t.tx), .computation = comp });
        }
    }
    return out.items;
}

const RunRow = struct { digest: Id, checkpoint: u64, recorded: u64, replayed: u64, status: []const u8, gas_units_internal: u64, instructions: u64 };

fn lessCell(_: void, a: vm.profile.FnInfo, b: vm.profile.FnInfo) bool {
    return a.cell.exclusive > b.cell.exclusive;
}

const HotRow = struct { fn_id: u32, pc: u16, op: u8, gas: u64, count: u64 };
fn lessHot(_: void, a: HotRow, b: HotRow) bool {
    return a.gas > b.gas;
}
const OpRow = struct { op: u8, gas: u64, count: u64 };
fn lessOp(_: void, a: OpRow, b: OpRow) bool {
    return a.gas > b.gas;
}

fn units(g: u64) f64 {
    return @as(f64, @floatFromInt(g)) / 1000.0;
}

pub fn run(ctx: *common.Ctx) !u8 {
    const arena = ctx.arena;
    const dir = ctx.opts.get("--dir") orelse return error.MissingDir;
    const pid = try common.parseId(ctx.opts.get("--package") orelse return error.MissingPackage);
    const scan_n = try ctx.opts.num("--checkpoints", 500);
    const limit: usize = @intCast(try ctx.opts.num("--limit", 50));
    const top: usize = @intCast(try ctx.opts.num("--top", 40));
    var o = try common.openNode(ctx.gpa, ctx.io, arena, dir);
    defer o.close();
    var snap = o.st.snapshot();
    defer snap.release();

    var oc: common.OriginCache = .{ .arena = arena, .snap = &snap };
    const target = oc.original(&pid);
    const calls = try collectCalls(ctx.gpa, arena, &snap, target, null, ctx.opts.get("--module"), ctx.opts.get("--function"), scan_n, limit);

    const sim = try arena.create(Sim);
    try sim.init(ctx.gpa, ctx.io, o.st, null);
    var prof = vm.profile.Profiler.init(ctx.gpa);
    defer prof.deinit();
    const mode: simulate.api.Mode = if (ctx.opts.flag("--checks")) .simulate else .dev_inspect;

    var rows: std.ArrayList(RunRow) = .empty;
    var rejected: u64 = 0;
    var failed: u64 = 0;
    for (calls) |c| {
        var run_arena: std.heap.ArenaAllocator = .init(ctx.gpa);
        defer run_arena.deinit();
        const before_gas = prof.total_gas;
        const before_ins = prof.instructions;
        vm.profile.activate(&prof);
        const res = sim.engine.simulate(run_arena.allocator(), &snap, .{ .tx = .{ .data = c.tx }, .mode = mode, .overrides = .{ .objects = try liveOverrides(run_arena.allocator(), &snap, c.tx) } }) catch |e| {
            vm.profile.activate(null);
            prof.endTransaction();
            rejected += 1;
            try rows.append(arena, .{ .digest = c.digest, .checkpoint = c.checkpoint, .recorded = c.computation, .replayed = 0, .status = try std.fmt.allocPrint(arena, "error: {s}", .{@errorName(e)}), .gas_units_internal = 0, .instructions = 0 });
            continue;
        };
        vm.profile.activate(null);
        prof.endTransaction();
        switch (res) {
            .rejected => |r| {
                rejected += 1;
                try rows.append(arena, .{ .digest = c.digest, .checkpoint = c.checkpoint, .recorded = c.computation, .replayed = 0, .status = try std.fmt.allocPrint(arena, "rejected: {s}", .{r.message}), .gas_units_internal = 0, .instructions = 0 });
            },
            .executed => |x| {
                var st: []const u8 = "success";
                switch (x.status) {
                    .success => {},
                    .failure => |f| {
                        failed += 1;
                        st = try std.fmt.allocPrint(arena, "failure: {s}", .{f.name});
                    },
                }
                try rows.append(arena, .{ .digest = c.digest, .checkpoint = c.checkpoint, .recorded = c.computation, .replayed = x.gas.computation, .status = st, .gas_units_internal = prof.total_gas - before_gas, .instructions = prof.instructions - before_ins });
            },
        }
    }

    // aggregate
    const fns = try arena.dupe(vm.profile.FnInfo, prof.fns.items);
    std.mem.sort(vm.profile.FnInfo, fns, {}, lessCell);
    var hot: std.ArrayList(HotRow) = .empty;
    var it = prof.cells.iterator();
    while (it.next()) |e| try hot.append(arena, .{ .fn_id = e.key_ptr.fn_id, .pc = e.key_ptr.pc, .op = e.value_ptr.op, .gas = e.value_ptr.gas, .count = e.value_ptr.count });
    std.mem.sort(HotRow, hot.items, {}, lessHot);
    var ops: std.ArrayList(OpRow) = .empty;
    for (prof.by_op, 0..) |c, op| if (c.count > 0 or c.gas > 0) try ops.append(arena, .{ .op = @intCast(op), .gas = c.gas, .count = c.count });
    std.mem.sort(OpRow, ops.items, {}, lessOp);

    var j: common.Json = .{ .w = ctx.w };
    try j.beginObj();
    try j.str("package", try common.hexId(arena, &target));
    try j.str("mode", @tagName(mode));
    try j.int("transactions_selected", calls.len);
    try j.int("rejected", rejected);
    try j.int("failed_runs", failed);
    try j.int("instructions", prof.instructions);
    try j.float("total_gas_units", units(prof.total_gas));
    try j.arrIn("functions");
    for (fns[0..@min(top, fns.len)]) |f| {
        try j.beginObj();
        try j.str("address", try common.hexId(arena, &f.addr));
        try j.str("module", f.module);
        try j.str("function", f.name);
        try j.boolean("native", f.cell.native);
        try j.int("calls", f.cell.calls);
        try j.float("exclusive_gas_units", units(f.cell.exclusive));
        try j.float("inclusive_gas_units", units(f.cell.inclusive));
        try j.float("exclusive_share", if (prof.total_gas == 0) 0 else @as(f64, @floatFromInt(f.cell.exclusive)) / @as(f64, @floatFromInt(prof.total_gas)));
        try j.endObj();
    }
    try j.endArr();
    try j.arrIn("hot_instructions");
    for (hot.items[0..@min(top, hot.items.len)]) |h| {
        const f = prof.fns.items[h.fn_id];
        try j.beginObj();
        try j.str("module", f.module);
        try j.str("function", f.name);
        try j.int("pc", h.pc);
        try j.str("op", std.enums.tagName(ff.Opcode, @enumFromInt(h.op)) orelse "?");
        try j.int("executions", h.count);
        try j.float("gas_units", units(h.gas));
        try j.float("gas_units_per_execution", if (h.count == 0) 0 else units(h.gas) / @as(f64, @floatFromInt(h.count)));
        try j.endObj();
    }
    try j.endArr();
    try j.arrIn("opcodes");
    for (ops.items) |r| {
        try j.beginObj();
        try j.str("op", std.enums.tagName(ff.Opcode, @enumFromInt(r.op)) orelse "?");
        try j.int("executions", r.count);
        try j.float("gas_units", units(r.gas));
        try j.endObj();
    }
    try j.endArr();
    try j.arrIn("runs");
    for (rows.items) |r| {
        try j.beginObj();
        try j.str("digest", try b58(arena, &r.digest));
        try j.int("checkpoint", r.checkpoint);
        try j.str("status", r.status);
        try j.int("recorded_computation_mist", r.recorded);
        try j.int("replayed_computation_mist", r.replayed);
        try j.float("profiled_gas_units", units(r.gas_units_internal));
        try j.int("instructions", r.instructions);
        try j.endObj();
    }
    try j.endArr();
    try j.endObj();
    try ctx.w.writeByte('\n');
    return 0;
}

fn b58(arena: Allocator, id: *const Id) ![]const u8 {
    const serve = @import("serve");
    const buf = try arena.alloc(u8, serve.b58.max_len_32);
    return try arena.dupe(u8, serve.b58.encode32(buf[0..serve.b58.max_len_32], id));
}
