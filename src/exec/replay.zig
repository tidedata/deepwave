//! Replay of one corpus transaction against its checkpoint's input objects (plus the corpus
//! read-only objects of `vectors/exec-replay/objects.bin.zst`) and comparison of the result with
//! the certified effects, events and output objects, byte for byte.
const std = @import("std");
const harness = @import("harness");
const types = @import("types");
const bcs = @import("bcs");
const protocol = @import("protocol");
/// The corpus these suites replay ($ZUI_CORPUS) is mainnet history.
const corpus_chain: protocol.Chain = .mainnet;
const objects = @import("objects.zig");
const coin_ptb = @import("coin_ptb.zig");
const ccp = @import("ccp.zig");
const inputs = @import("inputs.zig");
const ptb = @import("ptb/root.zig");
const packages = @import("packages.zig");
const classify = @import("classify.zig");

pub const Outcome = enum { pass, fail, skip };

/// Skip reasons of the executor, counted per reason (digits stripped) for the run summary.
pub const SkipTally = struct {
    lock: std.Io.Mutex = .init,
    reasons: [64]?[]const u8 = @splat(null),
    counts: [64]u64 = @splat(0),
    /// The first item skipped for each reason (for `--filter`).
    examples: [64]?[]const u8 = @splat(null),

    pub fn add(t: *SkipTally, io: std.Io, reason: []const u8) void {
        t.addAt(io, reason, null);
    }

    pub fn addAt(t: *SkipTally, io: std.Io, reason: []const u8, item: ?[]const u8) void {
        var buf: [160]u8 = undefined;
        var n: usize = 0;
        for (reason) |ch| {
            if (n == buf.len) break;
            if (std.ascii.isDigit(ch)) {
                if (n > 0 and buf[n - 1] == '#') continue;
                buf[n] = '#';
            } else buf[n] = ch;
            n += 1;
        }
        const key = buf[0..n];
        t.lock.lockUncancelable(io);
        defer t.lock.unlock(io);
        for (&t.reasons, &t.counts, &t.examples) |*r, *c, *x| {
            if (r.*) |have| {
                if (std.mem.eql(u8, have, key)) {
                    c.* += 1;
                    return;
                }
            } else {
                r.* = std.heap.page_allocator.dupe(u8, key) catch return;
                c.* = 1;
                if (item) |it| x.* = std.heap.page_allocator.dupe(u8, it) catch null;
                return;
            }
        }
    }

    pub fn print(t: *const SkipTally, w: *std.Io.Writer) void {
        for (t.reasons, t.counts, t.examples) |r, c, x| if (r) |text| if (x) |e| w.print("  executor skipped {d}: {s} (e.g. {s})\n", .{ c, text, e }) catch {} else w.print("  executor skipped {d}: {s}\n", .{ c, text }) catch {};
    }
};

pub const ObjectDb = objects.ObjectDb;

/// The checkpoint's objects (every transaction's inputs and outputs), then the corpus
/// read-only objects.
const Lookup = struct {
    table: *const objects.ObjectTable,
    db: *const ObjectDb,
    /// The archive's object set of the checkpoint (runtime-loaded objects), when loaded.
    archive: ?*const objects.ObjectTable = null,
    /// The executing epoch (deny-list reads).
    epoch: u64 = 0,

    fn get(p: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        const l: *const Lookup = @ptrCast(@alignCast(p));
        const k: objects.Key = .{ .id = id.*, .version = version };
        return l.table.get(k) orelse (if (l.archive) |a| a.get(k) else null) orelse l.db.get(k);
    }

    fn unstable(p: *const anyopaque, id: *const [32]u8) bool {
        const l: *const Lookup = @ptrCast(@alignCast(p));
        return l.db.deny.writtenIn(id, l.epoch);
    }

    /// The store's latest object: only the deny-list objects, from the corpus snapshot.
    fn latest(p: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const l: *const Lookup = @ptrCast(@alignCast(p));
        return l.db.deny.get(id, l.epoch);
    }

    fn objectLookup(l: *const Lookup) coin_ptb.ObjectLookup {
        return .{ .ctx = l, .get = get, .latest = if (l.db.deny.loaded) latest else null, .latest_unstable = unstable };
    }
};

/// What the Move-call executor needs beyond the checkpoint (ptb/root.zig).
pub const MoveArgs = struct {
    env: ptb.Env,
    archive_objs: ?*const objects.ObjectTable,
    /// `unchanged_loaded_runtime_objects` of this transaction (null: no archive record).
    loaded: ?[]const ptb.Ref,
    /// A coin-only PTB: the coin executor first, this one for what it does not model.
    coin_first: bool = false,
};

const MoveRun = union(enum) { out: coin_ptb.Output, fail, skip };

/// The checkpoint's transactions before this one: their object-balance withdrawals since the
/// last accumulator root settlement are the scheduler's unsettled withdrawals.
const Unsettled = struct {
    blob: []const u8,
    txs: []const types.index.Tx,

    fn get(p: *const anyopaque, arena: std.mem.Allocator, field: *const [32]u8) anyerror!u128 {
        const u: *const Unsettled = @ptrCast(@alignCast(p));
        var root: [32]u8 = @splat(0);
        root[30] = 0x0a;
        root[31] = 0xcc;
        var sum: u128 = 0;
        for (u.txs) |*t| {
            const fx = switch (try bcs.decode(types.TransactionEffects, arena, t.effects.slice(u.blob))) {
                .V2 => |v| v,
                .V1 => continue,
            };
            for (fx.changed_objects) |*c| {
                if (std.mem.eql(u8, &c[0].@"0".@"0", &root) and c[1].output_state == .ObjectWrite) sum = 0;
                if (!std.mem.eql(u8, &c[0].@"0".@"0", field)) continue;
                switch (c[1].output_state) {
                    .AccumulatorWriteV1 => |*w| if (w.operation == .Split) switch (w.value) {
                        .Integer => |v| sum += v,
                        else => return error.Unsupported,
                    },
                    else => {},
                }
            }
        }
        return sum;
    }
};

/// The Move-call executor (ptb/root.zig) on one transaction.
fn runMove(ctx: *harness.Ctx, arena: std.mem.Allocator, id: []const u8, blob: []const u8, idx: *const types.CheckpointIndex, tx: *const types.index.Tx, data: *const types.TransactionDataV1, lookup: *const Lookup, skips: *SkipTally, m: *const MoveArgs, out_events: *?[]const u8) MoveRun {
    const fx_all = arena.create(types.TransactionEffects) catch return .skip;
    fx_all.* = bcs.decode(types.TransactionEffects, arena, tx.effects.slice(blob)) catch {
        ctx.fail(id, "certified effects do not decode", .{});
        return .fail;
    };
    const fx = switch (fx_all.*) {
        .V2 => |*v| v,
        // exec-history: protocols before 33 (execution versions 0..2) certify V1 effects; the
        // driver reads them through a V2 view and writes V1 itself
        .V1 => |*v| ptb.v2View(arena, v) catch return .skip,
    };
    const tx_pos = (@intFromPtr(tx) - @intFromPtr(idx.txs.ptr)) / @sizeOf(types.index.Tx);
    const unsettled_ctx: Unsettled = .{ .blob = blob, .txs = idx.txs[0..tx_pos] };
    const res = ptb.execute(arena, m.env, tx.data.slice(blob), data, .{
        .objs = lookup.objectLookup(),
        .effects = fx,
        .unchanged_loaded = m.loaded,
        .unsettled = .{ .ctx = &unsettled_ctx, .get = Unsettled.get },
        .insufficient_funds = fx.status == .Failure and fx.status.Failure.@"error" == .InsufficientFundsForWithdraw and fx.status.Failure.command == null,
    }) catch |e| {
        ctx.fail(id, "ptb: {s}", .{@errorName(e)});
        return .fail;
    };
    switch (res) {
        .unsupported => |why| {
            skips.addAt(ctx.io, why, id);
            ctx.skip(id, why);
            return .skip;
        },
        .done => |o| {
            out_events.* = o.events;
            return .{ .out = .{ .effects = o.effects, .written = o.written } };
        },
    }
}

pub fn checkTransaction(
    ctx: *harness.Ctx,
    arena: std.mem.Allocator,
    id: []const u8,
    cfg: ?*const protocol.ProtocolConfig,
    epoch: u64,
    blob: []const u8,
    idx: *const types.CheckpointIndex,
    tx: *const types.index.Tx,
    data: *const types.TransactionDataV1,
    table: *const objects.ObjectTable,
    db: *const ObjectDb,
    skips: *SkipTally,
    mv: ?*const MoveArgs,
) Outcome {
    const c = cfg orelse {
        ctx.skip(id, "no protocol config for the epoch");
        return .skip;
    };
    const lookup: Lookup = .{ .table = table, .db = db, .archive = if (mv) |m| m.archive_objs else null, .epoch = epoch };
    var out_events: ?[]const u8 = null;
    const out: coin_ptb.Output = if (mv != null and !mv.?.coin_first) switch (runMove(ctx, arena, id, blob, idx, tx, data, &lookup, skips, mv.?, &out_events)) {
        .out => |o| o,
        .fail => return .fail,
        .skip => return .skip,
    } else if (ccp.timestampOf(&data.kind) != null) blk: {
        const ins = arena.alloc([]const u8, tx.in_count) catch return .skip;
        for (idx.objs[tx.in_first..][0..tx.in_count], ins) |r, *o| o.* = r.slice(blob);
        const res = ccp.execute(arena, c, epoch, tx.data.slice(blob), data, ins) catch |e| {
            ctx.fail(id, "ccp: {s}", .{@errorName(e)});
            return .fail;
        };
        switch (res) {
            .unsupported => |why| {
                skips.add(ctx.io, why);
                ctx.skip(id, why);
                return .skip;
            },
            .done => |o| break :blk o,
        }
    } else blk: {
        // Shared inputs at the versions consensus assigned (from the certified effects here).
        const assigned = inputs.assignedFromEffects(arena, data, tx.effects.slice(blob)) catch {
            ctx.fail(id, "certified effects do not decode", .{});
            return .fail;
        };
        var objs = lookup.objectLookup();
        objs.assigned = assigned;
        const res = coin_ptb.execute(arena, c, epoch, 0, tx.data.slice(blob), data, objs) catch |e| {
            ctx.fail(id, "coin_ptb: {s}", .{@errorName(e)});
            return .fail;
        };
        switch (res) {
            .unsupported => |why| {
                if (mv) |m| switch (runMove(ctx, arena, id, blob, idx, tx, data, &lookup, skips, m, &out_events)) {
                    .out => |o| break :blk o,
                    .fail => return .fail,
                    .skip => return .skip,
                };
                skips.add(ctx.io, why);
                ctx.skip(id, why);
                return .skip;
            },
            .done => |o| break :blk o,
        }
    };
    const want_fx = tx.effects.slice(blob);
    if (!std.mem.eql(u8, want_fx, out.effects)) {
        ctx.fail(id, "effects differ (zui {d} bytes, certified {d} bytes): {s}", .{ out.effects.len, want_fx.len, effectsDiff(arena, out.effects, want_fx) });
        return .fail;
    }
    if (tx.events) |ev| {
        const want_ev = ev.slice(blob);
        const got_ev = out_events orelse {
            ctx.fail(id, "certified transaction has events", .{});
            return .fail;
        };
        if (!std.mem.eql(u8, want_ev, got_ev)) {
            ctx.fail(id, "events differ (zui {d} bytes, certified {d} bytes)", .{ got_ev.len, want_ev.len });
            return .fail;
        }
    } else if (out_events != null) {
        ctx.fail(id, "zui emitted events, certified none", .{});
        return .fail;
    }
    if (out.written.len != tx.out_count) {
        ctx.fail(id, "{d} output objects, certified {d}", .{ out.written.len, tx.out_count });
        return .fail;
    }
    for (idx.objs[tx.out_first..][0..tx.out_count]) |r| {
        const want = r.slice(blob);
        const k = objects.keyOf(want) catch {
            ctx.fail(id, "certified output object does not parse", .{});
            return .fail;
        };
        const got = for (out.written) |w| {
            if (std.mem.eql(u8, &w.id, &k.id)) break w.bytes;
        } else {
            ctx.fail(id, "output object missing", .{});
            return .fail;
        };
        if (!std.mem.eql(u8, got, want)) {
            ctx.fail(id, "output object bytes differ", .{});
            return .fail;
        }
    }
    ctx.pass(id);
    return .pass;
}

/// The first differing effects field, for failure details.
pub fn effectsDiff(arena: std.mem.Allocator, got_raw: []const u8, want_raw: []const u8) []const u8 {
    const got = bcs.decode(types.TransactionEffects, arena, got_raw) catch return "zui effects do not decode";
    const want = bcs.decode(types.TransactionEffects, arena, want_raw) catch return "certified effects do not decode";
    if (got == .V1 and want == .V1) return effectsDiffV1(arena, &got.V1, &want.V1);
    if (got != .V2 or want != .V2) return "effects version";
    const g = &got.V2;
    const w = &want.V2;
    const p = std.fmt.allocPrint;
    if (!std.meta.eql(g.status, w.status) or g.status == .Failure) {
        const gs = if (g.status == .Failure) @tagName(g.status.Failure.@"error") else "Success";
        const ws = if (w.status == .Failure) @tagName(w.status.Failure.@"error") else "Success";
        if (!std.mem.eql(u8, gs, ws)) {
            if (g.status == .Failure and g.status.Failure.@"error" == .MoveAbort) {
                const ga = g.status.Failure.@"error".MoveAbort;
                return p(arena, "status zui abort {x}::{s} f{d} pc{d} {?s} code {d} (command {?d}), certified {s}", .{
                    ga[0].module.address.@"0", ga[0].module.name.@"0", ga[0].function, ga[0].instruction, if (ga[0].function_name) |fnm| fnm.@"0" else null, ga[1], g.status.Failure.command, ws,
                }) catch "status";
            }
            return p(arena, "status zui {any}, certified {any}", .{ g.status, w.status }) catch "status";
        }
    }
    {
        const ge = bcs.encodeAlloc(types.ExecutionStatus, arena, &g.status) catch return "status encode";
        const we = bcs.encodeAlloc(types.ExecutionStatus, arena, &w.status) catch return "status encode";
        if (!std.mem.eql(u8, ge, we)) {
            if (g.status == .Failure and w.status == .Failure and g.status.Failure.@"error" == .MoveAbort and w.status.Failure.@"error" == .MoveAbort) {
                const ga = g.status.Failure.@"error".MoveAbort;
                const wa = w.status.Failure.@"error".MoveAbort;
                return p(arena, "abort zui {x}::{s} f{d} pc{d} {?s} code {d}, certified {x}::{s} f{d} pc{d} {?s} code {d}", .{
                    ga[0].module.address.@"0", ga[0].module.name.@"0", ga[0].function, ga[0].instruction, if (ga[0].function_name) |fnm| fnm.@"0" else null, ga[1],
                    wa[0].module.address.@"0", wa[0].module.name.@"0", wa[0].function, wa[0].instruction, if (wa[0].function_name) |fnm| fnm.@"0" else null, wa[1],
                }) catch "abort";
            }
            return p(arena, "status detail zui {any}, certified {any}", .{ g.status, w.status }) catch "status detail";
        }
    }
    if (g.lamport_version.@"0" != w.lamport_version.@"0") return "lamport version";
    if (g.dependencies.len != w.dependencies.len) return "dependency count";
    if (!std.meta.eql(g.gas_object_index, w.gas_object_index)) return "gas object index";
    // (exec-history: object diffs before the gas diff; they usually explain it)
    const n = @min(g.changed_objects.len, w.changed_objects.len);
    for (g.changed_objects[0..n], w.changed_objects[0..n], 0..) |a, b, i| {
        const hx = std.fmt.bytesToHex(b[0].@"0".@"0", .lower);
        if (!std.meta.eql(a[0], b[0])) return p(arena, "changed object {d} id: zui {x}, certified {s} ({d} vs {d} changed)", .{ i, a[0].@"0".@"0", hx, g.changed_objects.len, w.changed_objects.len }) catch "id";
        if (!std.meta.eql(a[1].input_state, b[1].input_state)) return p(arena, "changed object {d} ({s}) input state", .{ i, hx }) catch "in";
        if (std.meta.activeTag(a[1].output_state) != std.meta.activeTag(b[1].output_state)) return p(arena, "changed object {d} ({s}) output kind zui {s}, certified {s}", .{ i, hx, @tagName(a[1].output_state), @tagName(b[1].output_state) }) catch "out";
        if (!std.meta.eql(a[1].id_operation, b[1].id_operation)) return p(arena, "changed object {d} ({s}) id operation", .{ i, hx }) catch "op";
    }
    for (g.changed_objects[0..n], w.changed_objects[0..n], 0..) |a, b, i| {
        // (bytes, not std.meta.eql: an accumulator write's type tag holds slices)
        const OS = @TypeOf(a[1].output_state);
        const ao = bcs.encodeAlloc(OS, arena, &a[1].output_state) catch return "output state encode";
        const bo = bcs.encodeAlloc(OS, arena, &b[1].output_state) catch return "output state encode";
        if (!std.mem.eql(u8, ao, bo)) return p(arena, "changed object {d} ({x}) output state: zui {any}, certified {any}", .{ i, b[0].@"0".@"0", a[1].output_state, b[1].output_state }) catch "output";
    }
    if (g.changed_objects.len != w.changed_objects.len) return p(arena, "{d} changed objects, certified {d}", .{ g.changed_objects.len, w.changed_objects.len }) catch "changed objects";
    if (!std.meta.eql(g.gas_used, w.gas_used)) return p(arena, "gas zui {any}, certified {any}", .{ g.gas_used, w.gas_used }) catch "gas";
    for (g.dependencies, w.dependencies, 0..) |a, b, i| if (!std.meta.eql(a, b)) return p(arena, "dependency {d}: zui {x}, certified {x}", .{ i, a.@"0".@"0", b.@"0".@"0" }) catch "dependency";
    for (g.unchanged_consensus_objects, w.unchanged_consensus_objects, 0..) |a, b, i| if (!std.meta.eql(a, b)) return p(arena, "unchanged consensus object {d}: zui {any}, certified {any}", .{ i, a, b }) catch "unchanged";
    if (g.unchanged_consensus_objects.len != w.unchanged_consensus_objects.len) return p(arena, "{d} unchanged consensus objects, certified {d}", .{ g.unchanged_consensus_objects.len, w.unchanged_consensus_objects.len }) catch "unchanged";
    if (!std.meta.eql(g.events_digest, w.events_digest)) return "events digest";
    if (!std.meta.eql(g.aux_data_digest, w.aux_data_digest)) return "aux data digest";
    return "output object digests or other bytes";
}

/// exec-history: the first differing TransactionEffectsV1 field (protocols before 33).
fn effectsDiffV1(arena: std.mem.Allocator, g: *const types.TransactionEffectsV1, w: *const types.TransactionEffectsV1) []const u8 {
    const p = std.fmt.allocPrint;
    if (!std.meta.eql(g.status, w.status) or g.status == .Failure) {
        const ge = bcs.encodeAlloc(types.ExecutionStatus, arena, &g.status) catch return "status encode";
        const we = bcs.encodeAlloc(types.ExecutionStatus, arena, &w.status) catch return "status encode";
        if (!std.mem.eql(u8, ge, we)) return p(arena, "V1 status zui {any}, certified {any}", .{ g.status, w.status }) catch "status";
    }
    inline for (.{ "modified_at_versions", "created", "mutated", "unwrapped", "deleted", "unwrapped_then_deleted", "wrapped", "shared_objects", "dependencies" }) |f| {
        const a = @field(g, f);
        const b = @field(w, f);
        const n = @min(a.len, b.len);
        for (a[0..n], b[0..n], 0..) |x, y, i| {
            const ex = bcs.encodeAlloc(@TypeOf(x), arena, &x) catch return f;
            const ey = bcs.encodeAlloc(@TypeOf(y), arena, &y) catch return f;
            if (!std.mem.eql(u8, ex, ey)) return p(arena, "V1 " ++ f ++ "[{d}] (of {d} vs {d}): zui {x}, certified {x}", .{ i, a.len, b.len, ex[0..@min(ex.len, 48)], ey[0..@min(ey.len, 48)] }) catch f;
        }
        if (a.len != b.len) {
            const extra = if (a.len > b.len) a[n] else b[n];
            const ee = bcs.encodeAlloc(@TypeOf(extra), arena, &extra) catch return f;
            return p(arena, "V1 " ++ f ++ ": zui {d}, certified {d}; first extra ({s}) {x}", .{ a.len, b.len, if (a.len > b.len) "zui" else "certified", ee[0..@min(ee.len, 48)] }) catch f;
        }
    }
    if (!std.meta.eql(g.gas_used, w.gas_used)) return p(arena, "V1 gas zui {any}, certified {any}", .{ g.gas_used, w.gas_used }) catch "gas";
    {
        const ex = bcs.encodeAlloc(@TypeOf(g.gas_object), arena, &g.gas_object) catch return "gas object";
        const ey = bcs.encodeAlloc(@TypeOf(w.gas_object), arena, &w.gas_object) catch return "gas object";
        if (!std.mem.eql(u8, ex, ey)) return "V1 gas object";
    }
    if (!std.meta.eql(g.events_digest, w.events_digest)) return "V1 events digest";
    return "V1 other bytes";
}

const BenchTx = struct {
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    tx_raw: []const u8,
    data: *const types.TransactionDataV1,
    ccp_inputs: []const []const u8,
    lookup: *const Lookup,
};

/// Same selection as `zui-truth-exec bench exec`: coin-only programmable transactions and
/// consensus commit prologues of the bench checkpoints whose inputs the checkpoint carries
/// (no coin reservations, no address-balance gas). Timed: execution to effects bytes and
/// written object bytes (deepwave) and `execute_transaction_to_effects` (Rust), inputs prepared
/// outside the timed region on both sides.
pub fn bench(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const db = try arena.create(ObjectDb);
    db.* = .{};
    var list: std.ArrayList(BenchTx) = .empty;
    for (ctx.benchInputs()) |name| {
        const blob = try ctx.corpus.readFileAlloc(ctx.io, name, arena, .limited(1 << 30));
        const cp = try bcs.decode(types.CheckpointData, arena, blob[1..]);
        var full = try types.CheckpointIndex.init(std.heap.page_allocator);
        defer full.deinit(std.heap.page_allocator);
        try types.indexCheckpointData(blob, &full);
        const idx = try arena.create(types.CheckpointIndex);
        idx.* = full;
        idx.txs = try arena.dupe(types.index.Tx, full.txs[0..full.tx_count]);
        idx.sigs = try arena.dupe(types.index.Range, full.sigs[0..full.sig_total]);
        idx.objs = try arena.dupe(types.index.Range, full.objs[0..full.obj_total]);
        const table = try arena.create(objects.ObjectTable);
        table.* = .{};
        try table.addCheckpoint(arena, blob, idx);
        const lookup = try arena.create(Lookup);
        const epoch = cp.checkpoint_summary.data.epoch;
        lookup.* = .{ .table = table, .db = db, .epoch = epoch };
        const cfg = try protocol.get(epochs[epoch].pv, corpus_chain);
        for (cp.transactions, 0..) |*t, i| {
            const data = &t.transaction.data.@"0".element().intent_message.value.V1;
            const tx = &idx.txs[i];
            const is_ccp = ccp.timestampOf(&data.kind) != null;
            if (!is_ccp and !benchCoin(data, blob, idx, tx)) continue;
            const ins = try arena.alloc([]const u8, tx.in_count);
            for (idx.objs[tx.in_first..][0..tx.in_count], ins) |r, *o| o.* = r.slice(blob);
            try list.append(arena, .{ .cfg = cfg, .epoch = epoch, .tx_raw = tx.data.slice(blob), .data = data, .ccp_inputs = if (is_ccp) ins else &.{}, .lookup = lookup });
        }
    }
    const S = struct {
        fn pass(txs: []const BenchTx) !void {
            var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer scratch.deinit();
            for (txs) |*b| {
                _ = scratch.reset(.retain_capacity);
                const a = scratch.allocator();
                if (b.ccp_inputs.len > 0) {
                    const r = try ccp.execute(a, b.cfg, b.epoch, b.tx_raw, b.data, b.ccp_inputs);
                    std.mem.doNotOptimizeAway(r);
                } else {
                    const r = try coin_ptb.execute(a, b.cfg, b.epoch, 0, b.tx_raw, b.data, b.lookup.objectLookup());
                    std.mem.doNotOptimizeAway(r);
                }
            }
        }
    };
    try ctx.benchPasses("exec", "tx", list.items.len, @as([]const BenchTx, list.items), S.pass);
    // the Move-call bench reads the coin deny list v2 snapshot (regulated coin transfers)
    if (ctx.corpus.readFileAlloc(ctx.io, ptb.deny.Snapshot.path, arena, .limited(1 << 30))) |dz| {
        db.deny = try .parse(arena, try harness.decompressZstd(arena, dz, 1 << 32));
    } else |_| {}
    try benchMove(ctx, arena, epochs, db);
}

const MoveTx = struct {
    env: ptb.Env,
    tx_raw: []const u8,
    data: *const types.TransactionDataV1,
    fx: *const types.TransactionEffectsV2,
    lookup: *const Lookup,
    loaded: ?[]const ptb.Ref,
};

/// Programmable transactions with a MoveCall (no Publish/Upgrade, no funds withdrawals, no
/// receiving or coin-reservation inputs) on execution version 4 whose effects deepwave reproduces
/// byte for byte, executed from the checkpoint, its archive record and the corpus packages.
/// The objects each one reads beyond the checkpoint's input objects (read-only shared inputs,
/// read-only runtime loads, immutable inputs) go to `$ZUI_CORPUS/bench/exec-move.pack`, which
/// `zui-truth-exec bench exec-move` reads, so Rust executes the same transactions from the same
/// objects. Pack record: tx digest (32), u32 count, then u32 length + BCS `Object` per object.
fn benchMove(ctx: *harness.Ctx, arena: std.mem.Allocator, epochs: []const harness.corpus_suite.Epoch, db: *const ObjectDb) !void {
    const last = try arena.alloc(?u64, epochs.len);
    for (epochs, last) |e, *l| l.* = e.last;
    const rgp = try arena.alloc(u64, epochs.len);
    const start_ms = try arena.alloc(u64, epochs.len);
    @memset(rgp, 0);
    @memset(start_ms, 0);
    {
        const Extra = struct { epoch: u64, rgp: ?u64 = null, start_ms: ?u64 = null };
        const text = try ctx.corpus.readFileAlloc(ctx.io, "epochs.jsonl", arena, .limited(64 << 20));
        var it = harness.lines(text);
        while (it.next()) |line| {
            const x = try std.json.parseFromSliceLeaky(Extra, arena, line, .{ .ignore_unknown_fields = true });
            if (x.epoch < epochs.len) {
                rgp[x.epoch] = x.rgp orelse 0;
                start_ms[x.epoch] = x.start_ms orelse 0;
            }
        }
    }
    const store = try arena.create(packages.Store);
    store.* = try packages.load(ctx, arena, last);
    var list: std.ArrayList(MoveTx) = .empty;
    var selected: usize = 0;
    var pack: std.ArrayList(u8) = .empty;
    var scratch: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch.deinit();
    var tally: SkipTally = .{};
    for (ctx.benchInputs()) |name| {
        const blob = try ctx.corpus.readFileAlloc(ctx.io, name, arena, .limited(1 << 30));
        const cp = try bcs.decode(types.CheckpointData, arena, blob[1..]);
        const epoch = cp.checkpoint_summary.data.epoch;
        const cfg = try protocol.get(epochs[epoch].pv, corpus_chain);
        if ((cfg.getOpt("execution_version") orelse 0) != 4) continue;
        var full = try types.CheckpointIndex.init(std.heap.page_allocator);
        defer full.deinit(std.heap.page_allocator);
        try types.indexCheckpointData(blob, &full);
        const idx = try arena.create(types.CheckpointIndex);
        idx.* = full;
        idx.txs = try arena.dupe(types.index.Tx, full.txs[0..full.tx_count]);
        idx.sigs = try arena.dupe(types.index.Range, full.sigs[0..full.sig_total]);
        idx.objs = try arena.dupe(types.index.Range, full.objs[0..full.obj_total]);
        const table = try arena.create(objects.ObjectTable);
        table.* = .{};
        try table.addCheckpoint(arena, blob, idx);
        const seq_text = std.fs.path.stem(name);
        var arch: ?ptb.archive.Archive = null;
        const arch_objs = try arena.create(objects.ObjectTable);
        arch_objs.* = .{};
        for ([_][]const u8{ "binpb-done", "binpb-r4", "binpb-exec" }) |dir| {
            const path = try std.fmt.allocPrint(arena, "{s}/{s}.binpb.zst", .{ dir, seq_text });
            const dec = ctx.readZstd(path, 1 << 30) catch continue;
            arch = ptb.archive.parse(arena, dec, cp.transactions.len) catch null;
            if (arch) |a| for (a.objects) |raw| {
                const k = objects.keyOf(raw) catch continue;
                try arch_objs.map.put(arena, k, raw);
            };
            break;
        }
        const a = arch orelse continue;
        const lookup = try arena.create(Lookup);
        lookup.* = .{ .table = table, .db = db, .archive = arch_objs, .epoch = cp.checkpoint_summary.data.epoch };
        for (cp.transactions, 0..) |*t, i| {
            const data = &t.transaction.data.@"0".element().intent_message.value.V1;
            if (classify.classify(&data.kind) != .ptb_move_call) continue;
            const tx = &idx.txs[i];
            if (!moveBenchInputs(data)) continue;
            const fx = switch (t.effects) {
                .V2 => |*v| v,
                .V1 => continue,
            };
            selected += 1;
            const b: MoveTx = .{
                .env = .{ .gpa = std.heap.smp_allocator, .cfg = cfg, .pv = epochs[epoch].pv, .epoch = epoch, .epoch_start_ms = start_ms[epoch], .rgp = rgp[epoch], .pkgs = store },
                .tx_raw = tx.data.slice(blob),
                .data = data,
                .fx = fx,
                .lookup = lookup,
                .loaded = a.loaded[i],
            };
            _ = scratch.reset(.retain_capacity);
            const r = ptb.execute(scratch.allocator(), b.env, b.tx_raw, data, .{ .objs = lookup.objectLookup(), .effects = fx, .unchanged_loaded = b.loaded }) catch continue;
            switch (r) {
                .done => |o| if (std.mem.eql(u8, o.effects, tx.effects.slice(blob))) {
                    try list.append(arena, b);
                    try packTx(arena, &pack, b);
                } else tally.add(ctx.io, "effects differ in the bench lookup"),
                .unsupported => |why| tally.add(ctx.io, why),
            }
        }
    }
    ctx.stderr.print("exec-move bench: {d} selected, {d} reproduced\n", .{ selected, list.items.len }) catch {};
    tally.print(ctx.stderr);
    try ctx.corpus.createDirPath(ctx.io, "bench");
    try ctx.corpus.writeFile(ctx.io, .{ .sub_path = "bench/exec-move.pack", .data = pack.items });
    const S = struct {
        fn pass(txs: []const MoveTx) !void {
            var sc: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
            defer sc.deinit();
            for (txs) |*b| {
                _ = sc.reset(.retain_capacity);
                const r = try ptb.execute(sc.allocator(), b.env, b.tx_raw, b.data, .{ .objs = b.lookup.objectLookup(), .effects = b.fx, .unchanged_loaded = b.loaded });
                std.mem.doNotOptimizeAway(r);
            }
        }
    };
    try ctx.benchPasses("exec-move", "tx", list.items.len, @as([]const MoveTx, list.items), S.pass);
    // per-stage profile: 5 more passes with the stage clocks on (not part of the timed median)
    var stages: [8]u64 = @splat(0);
    ptb.profile = &stages;
    for (0..5) |_| try S.pass(list.items);
    ptb.profile = null;
    var total: u64 = 0;
    for (stages) |x| total += x;
    const n: u64 = 5 * @max(1, list.items.len);
    for (stages, ptb.stage_names) |x, name| if (x > 0)
        ctx.stderr.print("exec-move stage {s}: {d} ns/tx ({d:.1}%)\n", .{ name, x / n, 100.0 * @as(f64, @floatFromInt(x)) / @as(f64, @floatFromInt(@max(1, total))) }) catch {};
}

fn benchCoin(data: *const types.TransactionDataV1, blob: []const u8, idx: *const types.CheckpointIndex, tx: *const types.index.Tx) bool {
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return false,
    };
    for (pt.commands) |cmd| switch (cmd) {
        .SplitCoins, .MergeCoins, .TransferObjects => {},
        else => return false,
    };
    return benchInputsHeld(data, blob, idx, tx);
}

/// One `exec-move.pack` record: the objects `b` reads that the checkpoint's input objects lack.
fn packTx(arena: std.mem.Allocator, pack: *std.ArrayList(u8), b: MoveTx) !void {
    var objs: std.ArrayList([]const u8) = .empty;
    const Add = struct {
        fn add(al: std.mem.Allocator, l: *const Lookup, list: *std.ArrayList([]const u8), id: *const [32]u8, version: u64) !void {
            if (Lookup.get(l, id, version)) |raw| try list.append(al, raw);
        }
    };
    if (b.loaded) |ls| for (ls) |r| try Add.add(arena, b.lookup, &objs, &r.id, r.version);
    for (b.fx.unchanged_consensus_objects) |*u| switch (u[1]) {
        .ReadOnlyRoot => |v| try Add.add(arena, b.lookup, &objs, &u[0].@"0".@"0", v[0].@"0"),
        else => {},
    };
    const pt = &b.data.kind.ProgrammableTransaction;
    for (pt.inputs) |*arg| switch (arg.*) {
        .Object => |*oa| switch (oa.*) {
            .ImmOrOwnedObject => |r| try Add.add(arena, b.lookup, &objs, &r[0].@"0".@"0", r[1].@"0"),
            else => {},
        },
        else => {},
    };
    try pack.appendSlice(arena, &types.digest.transactionDataDigest(b.tx_raw));
    try pack.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u32, @intCast(objs.items.len))));
    for (objs.items) |raw| {
        try pack.appendSlice(arena, std.mem.asBytes(&std.mem.nativeToLittle(u32, @intCast(raw.len))));
        try pack.appendSlice(arena, raw);
    }
}

/// Gas coins, no coin reservations, no funds withdrawals, no receiving inputs (the Rust side
/// serves objects by id from the checkpoint and the pack).
fn moveBenchInputs(data: *const types.TransactionDataV1) bool {
    const pt = &data.kind.ProgrammableTransaction;
    if (data.gas_data.payment.len == 0) return false;
    for (data.gas_data.payment) |r| if (inputs.isCoinReservation(&r[2].@"0".@"0")) return false;
    for (pt.inputs) |*arg| switch (arg.*) {
        .Pure => {},
        .FundsWithdrawal => return false,
        .Object => |*oa| switch (oa.*) {
            .ImmOrOwnedObject => |r| if (inputs.isCoinReservation(&r[2].@"0".@"0")) return false,
            .SharedObject => {},
            .Receiving => return false,
        },
    };
    return true;
}

/// Gas coins and object inputs the checkpoint carries (owned at the signed version), no coin
/// reservations, no funds withdrawals, no receiving inputs.
fn benchInputsHeld(data: *const types.TransactionDataV1, blob: []const u8, idx: *const types.CheckpointIndex, tx: *const types.index.Tx) bool {
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return false,
    };
    if (data.gas_data.payment.len == 0) return false;
    const In = struct {
        fn has(b: []const u8, ix: *const types.CheckpointIndex, t: *const types.index.Tx, id: *const [32]u8, version: ?u64) bool {
            for (ix.objs[t.in_first..][0..t.in_count]) |r| {
                const k = objects.keyOf(r.slice(b)) catch continue;
                if (std.mem.eql(u8, &k.id, id) and (version == null or version.? == k.version)) return true;
            }
            return false;
        }
    };
    for (data.gas_data.payment) |r| {
        if (inputs.isCoinReservation(&r[2].@"0".@"0")) return false;
        if (!In.has(blob, idx, tx, &r[0].@"0".@"0", r[1].@"0")) return false;
    }
    for (pt.inputs) |*arg| switch (arg.*) {
        .Pure => {},
        .FundsWithdrawal => return false,
        .Object => |*oa| switch (oa.*) {
            .ImmOrOwnedObject => |r| {
                if (inputs.isCoinReservation(&r[2].@"0".@"0")) return false;
                if (!In.has(blob, idx, tx, &r[0].@"0".@"0", r[1].@"0")) return false;
            },
            .SharedObject => |sh| if (!In.has(blob, idx, tx, &sh.id.@"0".@"0", null)) return false,
            .Receiving => return false,
        },
    };
    return true;
}
