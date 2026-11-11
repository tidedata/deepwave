//! Differential tests of the untraced interpreter loop (`Session.stepRun`).
//!
//! The reference is `Session.step`, one instruction at a time: with a tracer it is the traced
//! loop the move-vm-trace suite checks against Rust event for event, and without one (`ref_loop`)
//! it is the same code minus the tracer hooks. Every comparison here runs one call twice with the
//! same starting state and requires the same outcome (status, sub status, module, function and
//! code offset), the same whole `Meter` (gas left, instruction count, stack height and size with
//! their high-water marks, tier state, native calls), the same operand stack (height and values,
//! deep), the same call depth, the same values behind the reference arguments and the same
//! object runtime results (every write, event, loaded child, created and deleted id, in bytes).
//!
//! Per call: the call's own budget on all three loops, then the reference against `stepRun` at
//! every remaining-gas value from 0 to what the call uses (every instruction of the call runs
//! out of gas once), or at both ends and a random sample for long calls; the three counters
//! placed just below each tier start; an unmetered meter (unless the call only ends by running
//! out of gas); other gas model versions; the v0..v3 interpreter rules. A sample of the budgets
//! also runs traced, which ties the tracer-less reference to the traced loop. Every comparison of `stepRun` runs it a second time with block
//! gas charging on (`Session.block_gas`), against the same reference: so at every budget of the
//! sweep, which ends the gas at every instruction of every block the call runs (the meter then
//! refuses the block and charges it instruction by instruction), and for every fault inside a
//! block that was charged at once (the meter is put back before the failing instruction). The
//! tallies count both, and the tests require them.
//!
//! Unit tests run this over calls into the embedded framework and over synthetic modules (no
//! verifier, so type-confused operands reach every fallback). The `move-vm-diff` suite runs it
//! over every call of the move-vm-gas corpus.
const std = @import("std");
const harness = @import("harness");
const protocol = @import("protocol");
const move_format = @import("move_format");
const natives = @import("natives");
const types_mod = @import("types");
const loader = @import("loader.zig");
const value = @import("value.zig");
const types = @import("types.zig");
const gas = @import("gas.zig");
const interp = @import("interp.zig");
const trace = @import("trace.zig");
const host = @import("host.zig");
const conf = @import("conformance.zig");

const Allocator = std.mem.Allocator;
const Value = value.Value;
const ff = move_format.file_format;
const Call = conf.Call;

/// `fast`: `stepRun` as it runs by default. `block`: `stepRun` with block gas charging on.
pub const Mode = enum { traced, ref, fast, block };

/// A counter placed `below` units under the start of tier `tier + 1` before the run.
pub const Pre = struct { tier: u8 = 0, below: u64 };

pub const Opts = struct {
    mode: Mode = .ref,
    /// Remaining gas in internal units (null: the call's budget, as the truth tool sets it).
    gas_left: ?u64 = null,
    unmetered: bool = false,
    /// Gas model version of the meter (null: the call's protocol version's).
    gm: ?u64 = null,
    pre_instructions: ?Pre = null,
    pre_size: ?Pre = null,
    pre_height: ?Pre = null,
    /// The v0..v3 interpreter rules (`cuts.Rules.legacyVm`).
    legacy: bool = false,
};

pub const Snap = struct {
    /// A failure that is not a VM error (a missing native, a load error).
    fail: ?anyerror = null,
    ok: bool = false,
    err: interp.VmError = .{ .major = .EXECUTED },
    meter: gas.Meter,
    /// The called function is a native (the traced loop does not run those as the entry).
    entry_native: bool = false,
    /// Block gas (not part of the comparison): blocks charged at once, refused by the meter,
    /// undone inside, undone at an instruction that then failed; and where in its function's
    /// block tables the run's error is.
    blocks_charged: u64 = 0,
    blocks_refused: u64 = 0,
    blocks_undone: u64 = 0,
    blocks_faulted: u64 = 0,
    stop: interp.Blocks.Pos = .outside,
    /// Operand stack height, call depth, stack values, values behind reference arguments, the
    /// object runtime's results.
    state: []const u8 = "",
};

fn dumpValue(out: *std.ArrayList(u8), a: Allocator, v: Value, depth: u32) Allocator.Error!void {
    const raw: u8 = @as(*const u8, @ptrCast(&v)).*;
    try out.append(a, raw);
    if (raw > @intFromEnum(value.Tag.ref_elem) or depth > 48) return;
    switch (v.tag) {
        .invalid => {},
        .u8, .u16, .u32, .u64, .bool => try out.appendSlice(a, std.mem.asBytes(&v.a)),
        .u128 => {
            try out.appendSlice(a, std.mem.asBytes(&v.a));
            try out.appendSlice(a, std.mem.asBytes(&v.b));
        },
        .u256, .address => try out.appendSlice(a, v.box()),
        .container => try dumpContainer(out, a, v.cont(), depth),
        .ref_slot => try dumpValue(out, a, v.slot().*, depth + 1),
        .ref_elem => {
            try out.appendSlice(a, std.mem.asBytes(&v.b));
            const c = v.cont();
            const w = c.kind.width();
            if (c.kind.isPrimVec() and v.b < c.len) try out.appendSlice(a, c.data[v.b * w ..][0..w]);
        },
    }
}

fn dumpContainer(out: *std.ArrayList(u8), a: Allocator, c: *const value.Container, depth: u32) Allocator.Error!void {
    try out.append(a, @intFromEnum(c.kind));
    try out.appendSlice(a, std.mem.asBytes(&c.tag));
    try out.appendSlice(a, std.mem.asBytes(&c.len));
    if (c.kind.isPrimVec()) {
        try out.appendSlice(a, c.bytes());
    } else for (c.values()) |f| try dumpValue(out, a, f, depth + 1);
}

/// The start of tier `k + 1` of a counter (null: the table has no such tier).
fn tierStart(comptime which: enum { instructions, size, height }, table: *const protocol.gas.CostTable, k: u8) ?u64 {
    var at: u64 = 0;
    var i: u8 = 0;
    while (true) : (i += 1) {
        const t = switch (which) {
            .instructions => table.instructionTier(at),
            .size => table.stackSizeTier(at),
            .height => table.stackHeightTier(at),
        };
        const next = t[1] orelse return null;
        if (i == k) return next;
        at = next + 1;
    }
}

fn applyPre(m: *gas.Meter, o: Opts) void {
    if (o.pre_instructions) |p| if (tierStart(.instructions, m.table, p.tier)) |n| {
        m.instructions_executed = n -| p.below;
        const t = m.table.instructionTier(m.instructions_executed);
        m.instructions_current_tier_mult = t[0];
        m.instructions_next_tier_start = t[1];
    };
    if (o.pre_size) |p| if (tierStart(.size, m.table, p.tier)) |n| {
        m.stack_size_current = n -| p.below;
        m.stack_size_high_water_mark = m.stack_size_current;
        const t = m.table.stackSizeTier(m.stack_size_current);
        m.stack_size_current_tier_mult = t[0];
        m.stack_size_next_tier_start = t[1];
    };
    if (o.pre_height) |p| if (tierStart(.height, m.table, p.tier)) |n| {
        m.stack_height_current = n -| p.below;
        m.stack_height_high_water_mark = m.stack_height_current;
        const t = m.table.stackHeightTier(m.stack_height_current);
        m.stack_height_current_tier_mult = t[0];
        m.stack_height_next_tier_start = t[1];
    };
}

/// Runs call `c` once (as `conformance.runCallWith` does) on the loop and starting state `o`
/// names. `arena` holds the run; the snapshot's bytes go to `keep`.
pub fn runOne(arena: Allocator, keep: Allocator, rt: *loader.Runtime, cache: *interp.LinkCache, c: *const Call, o: Opts) !Snap {
    const cfg = try protocol.get(c.pv, .mainnet);
    const root = rt.package(&c.root) orelse return error.RootMissing;
    const entry = try cache.get(rt, root);
    if (entry.fail != null) return error.LinkageRefused;
    const link = &entry.link;
    const func = try link.function(&c.module_addr, c.module_name, c.func);
    const ty_args = try arena.alloc(*const loader.Type, c.tys.len);
    for (c.tys, ty_args) |t, *d| d.* = try types.fromTagBytes(arena, rt, t);
    if (c.args.len != func.params.len) return error.ArgCount;
    const heap = value.Heap{ .arena = arena };
    const args = try arena.alloc(Value, c.args.len);
    const ptys = try types.instantiateAll(arena, func.module, func.params, ty_args);
    const slots = try arena.alloc(?*Value, c.args.len);
    var bad_arg = false;
    for (c.args, args, ptys, slots) |a, *v, pt, *slot| {
        slot.* = null;
        const x = (try types.deserializeArg(heap, pt, a.bytes)) orelse {
            bad_arg = true;
            break;
        };
        if (a.kind == .val) {
            v.* = x;
        } else {
            const s = try arena.create(Value);
            s.* = x;
            v.* = Value.refSlot(s);
            slot.* = s;
        }
    }
    const gm = o.gm orelse try cfg.get("gas_model_version");
    var snap: Snap = .{ .meter = if (o.unmetered) gas.Meter.unmetered() else gas.Meter.init(gm, c.budget, 1), .entry_native = func.is_native };
    const meter = &snap.meter;
    if (o.gas_left) |g| {
        meter.gas_left = g;
        meter.initial_budget = g;
    }
    applyPre(meter, o);
    var ecfg = try interp.ExecConfig.fromProtocolAnyCut(cfg);
    if (o.legacy) ecfg.rules.execution_version = 3;
    var sess = try interp.Session.init(arena, link, meter, ecfg);
    const h = try arena.create(host.Host);
    h.* = .{ .cfg = cfg, .tx = conf.DEFAULT_TX };
    h.rt.resolver = .{ .ctx = undefined, .vtable = &conf.truth_world };
    const table = try arena.create(interp.NativeTable);
    table.* = h.table();
    sess.natives = table;
    sess.ext = h;
    sess.tracer = null;
    sess.ref_loop = o.mode == .ref;
    sess.block_gas = o.mode == .block;
    if (o.mode == .traced) {
        const t = try arena.create(trace.Tracer);
        t.* = trace.Tracer.init(arena, ecfg);
        sess.tracer = t;
    }
    var out: std.ArrayList(u8) = .empty;
    const outcome: interp.Outcome = if (bad_arg) .{ .err = .{ .major = .FAILED_TO_DESERIALIZE_ARGUMENT } } else sess.run(func, ty_args, args) catch |e| {
        if (e == error.OutOfMemory) return e;
        snap.fail = e;
        return snap;
    };
    switch (outcome) {
        .ok => snap.ok = true,
        .err => |e| snap.err = e,
    }
    snap.blocks_charged = sess.blocks_charged;
    snap.blocks_refused = sess.blocks_refused;
    snap.blocks_undone = sess.blocks_undone;
    snap.blocks_faulted = sess.blocks_faulted;
    if (o.mode == .block and !snap.ok and interp.Blocks.covers(meter.gas_model_version)) if (snap.err.module) |m| if (snap.err.off) |at| {
        for (m.functions) |*fx| if (fx.def_idx == at.fdef) {
            snap.stop = interp.Blocks.posOf(fx, at.pc);
        };
    };
    try out.appendSlice(keep, std.mem.asBytes(&@as(u64, sess.sp)));
    try out.appendSlice(keep, std.mem.asBytes(&@as(u64, if (bad_arg) 0 else sess.frames.items.len)));
    for (sess.stack[0..sess.sp]) |v| try dumpValue(&out, keep, v, 0);
    for (slots) |s| if (s) |sl| try dumpValue(&out, keep, sl.*, 0);
    const fin = try h.finish(arena);
    switch (fin) {
        .ok => |r| {
            try out.append(keep, 1);
            inline for (.{ r.writes.len, r.events.len, r.acc_events.len, r.loaded.len, r.created.len, r.deleted.len }) |n| try out.appendSlice(keep, std.mem.asBytes(&@as(u64, n)));
            try dumpResults(&out, keep, arena, &r);
        },
        .err => |e| {
            try out.append(keep, 0);
            try out.append(keep, @intFromEnum(e));
        },
    }
    snap.state = out.items;
    return snap;
}

/// The object runtime's results in full: every write (id, owner, type, value bytes), event,
/// accumulator event, loaded child, created and deleted id, and the settlement amounts.
fn dumpResults(out: *std.ArrayList(u8), keep: Allocator, a: Allocator, r: *const natives.abi.ObjectRuntime.Results) Allocator.Error!void {
    const objrt = natives.abi.objrt;
    for (r.writes) |*w| {
        try out.appendSlice(keep, &w.id);
        try dumpBytes(out, keep, try w.owner.encode(a));
        try dumpBytes(out, keep, try objrt.tagBcs(a, w.ty));
        try dumpBytes(out, keep, try types_mod.layout.encodeAlloc(a, &w.value));
    }
    for (r.events) |*e| {
        try dumpBytes(out, keep, try objrt.tagBcs(a, e.ty));
        try dumpBytes(out, keep, try types_mod.layout.encodeAlloc(a, &e.value));
    }
    for (r.acc_events) |*e| {
        try out.appendSlice(keep, &e.accumulator_id);
        try out.append(keep, @intFromEnum(e.action));
        try out.appendSlice(keep, &e.target_addr);
        try dumpBytes(out, keep, try objrt.tagBcs(a, e.target_ty));
        const kind: u8, const n: u64 = switch (e.value) {
            .u64 => |x| .{ 0, x },
            .event_ref => |x| .{ 1, x },
        };
        try out.append(keep, kind);
        try out.appendSlice(keep, std.mem.asBytes(&n));
    }
    for (r.loaded) |*l| {
        try out.appendSlice(keep, &l.id);
        try out.appendSlice(keep, std.mem.asBytes(&l.version));
        try out.append(keep, @intFromBool(l.modified));
    }
    for (r.created) |*id| try out.appendSlice(keep, id);
    for (r.deleted) |*id| try out.appendSlice(keep, id);
    try out.appendSlice(keep, std.mem.asBytes(&r.settlement_input_sui));
    try out.appendSlice(keep, std.mem.asBytes(&r.settlement_output_sui));
}

fn dumpBytes(out: *std.ArrayList(u8), keep: Allocator, b: []const u8) Allocator.Error!void {
    try out.appendSlice(keep, std.mem.asBytes(&@as(u64, b.len)));
    try out.appendSlice(keep, b);
}

fn sameErr(a: interp.VmError, b: interp.VmError) bool {
    if (a.major != b.major or a.sub != b.sub or a.module != b.module) return false;
    if ((a.off == null) != (b.off == null)) return false;
    if (a.off) |x| return x.fdef == b.off.?.fdef and x.pc == b.off.?.pc;
    return true;
}

pub fn same(a: *const Snap, b: *const Snap) bool {
    if (a.fail != b.fail or a.ok != b.ok) return false;
    if (!a.ok and !sameErr(a.err, b.err)) return false;
    if (!std.meta.eql(a.meter, b.meter)) return false;
    return std.mem.eql(u8, a.state, b.state);
}

fn describeSnap(w: *std.ArrayList(u8), a: Allocator, name: []const u8, s: *const Snap) !void {
    try w.print(a, "  {s}: ", .{name});
    if (s.fail) |e| try w.print(a, "error {s}", .{@errorName(e)}) else if (s.ok) try w.appendSlice(a, "ok") else {
        try w.print(a, "{s} sub {?d}", .{ @tagName(s.err.major), s.err.sub });
        if (s.err.module) |m| try w.print(a, " in {s}", .{m.name});
        if (s.err.off) |o| try w.print(a, " fn {d} pc {d}", .{ o.fdef, o.pc });
    }
    const m = &s.meter;
    try w.print(a, "; gas_left {d} ins {d} h {d}/{d} s {d}/{d} natives {d} tiers i {d}/{?d} s {d}/{?d} h {d}/{?d} err {s}; state {d} bytes\n", .{
        m.gas_left,                          m.instructions_executed,          m.stack_height_current,
        m.stack_height_high_water_mark,      m.stack_size_current,             m.stack_size_high_water_mark,
        m.num_native_calls,                  m.instructions_current_tier_mult, m.instructions_next_tier_start,
        m.stack_size_current_tier_mult,      m.stack_size_next_tier_start,     m.stack_height_current_tier_mult,
        m.stack_height_next_tier_start,      @tagName(m.err),                  s.state.len,
    });
}

fn describe(gpa: Allocator, o: Opts, an: []const u8, a: *const Snap, bn: []const u8, b: *const Snap) ![]u8 {
    var w: std.ArrayList(u8) = .empty;
    errdefer w.deinit(gpa);
    try w.print(gpa, "{s} and {s} differ (gas_left {?d}, unmetered {}, gm {?d}, legacy {}", .{ an, bn, o.gas_left, o.unmetered, o.gm, o.legacy });
    if (o.pre_instructions) |p| try w.print(gpa, ", instructions {d} below tier {d}", .{ p.below, p.tier + 1 });
    if (o.pre_size) |p| try w.print(gpa, ", stack size {d} below tier {d}", .{ p.below, p.tier + 1 });
    if (o.pre_height) |p| try w.print(gpa, ", stack height {d} below tier {d}", .{ p.below, p.tier + 1 });
    try w.appendSlice(gpa, ")\n");
    try describeSnap(&w, gpa, an, a);
    try describeSnap(&w, gpa, bn, b);
    if (!std.mem.eql(u8, a.state, b.state)) {
        var d: usize = 0;
        while (d < a.state.len and d < b.state.len and a.state[d] == b.state[d]) d += 1;
        try w.print(gpa, "  state differs at byte {d} (0..8 stack height, 8..16 call depth, then values)\n", .{d});
    }
    return w.toOwnedSlice(gpa);
}

pub const Plan = struct {
    /// Every remaining-gas value when the call uses at most this many internal units.
    exhaustive_cap: u64 = 6000,
    /// Longer calls: this many random budgets, and every budget within `edge` of both ends.
    samples: u32 = 24,
    edge: u64 = 48,
    /// One budget in this many also runs traced (0: only the call's own budget; 1: the traced
    /// loop itself at every budget, beside the reference).
    traced_every: u32 = 16,
    /// The traced loop at all (synthetic modules with type-confused operands skip it).
    traced: bool = true,
    /// Calls that run more instructions than this, or leave more than 64 KiB of values, are
    /// not traced: a trace holds a snapshot per effect, gigabytes for the corpus's long calls.
    traced_max_ins: u64 = 20_000,
    /// Random tier placements.
    presets: u32 = 8,
    /// Other gas model versions: covered by block gas (11 and later) and older ones.
    gms: []const u64 = &.{ 13, 11, 10, 9, 7, 5, 4, 1 },
    /// Random budgets per gas model version and for the legacy rules.
    gm_samples: u32 = 4,
    legacy: bool = true,
    unmetered: bool = true,
    /// A call that runs more instructions than this is a loop, and each of its runs costs as
    /// much as thousands of ordinary calls (the corpus's 120 longest hold 98% of its
    /// instructions): it gets `long_n` of every list above instead (budgets at each end, random
    /// budgets, tier placements, budgets per gas model version and for the legacy rules).
    long_ins: u64 = 100_000,
    long_n: u32 = 6,
    /// A call that ends by running out of gas at its own budget is a loop with no other end
    /// (92 of the corpus's 120 longest calls). It never runs unmetered (that run would not
    /// end), and on another gas model version, where the same budget buys up to a thousand
    /// million instructions, it gets at most this many internal units.
    oog_gas_cap: u64 = 250_000,
};

pub const Tally = struct {
    calls: u64 = 0,
    runs: u64 = 0,
    compared: u64 = 0,
    exhaustive_calls: u64 = 0,
    /// Calls over `Plan.long_ins` instructions (the short lists), and calls that end by
    /// running out of gas at their own budget (never unmetered, capped on other gas models).
    long_calls: u64 = 0,
    oog_calls: u64 = 0,
    traced_runs: u64 = 0,
    /// Comparisons whose reference outcome was an error / out of gas.
    errors: u64 = 0,
    oog: u64 = 0,
    /// Block gas runs: blocks charged at once, refused by the meter and undone inside; runs
    /// that ended in an error after charging at least one block; runs that ran out of gas at
    /// the first instruction of a block and at a later one (the budget ends inside the block);
    /// runs that failed at an instruction inside a block that had been charged at once.
    blocks_charged: u64 = 0,
    blocks_refused: u64 = 0,
    blocks_undone: u64 = 0,
    block_error_runs: u64 = 0,
    block_oog_first: u64 = 0,
    block_oog_inside: u64 = 0,
    block_fault_runs: u64 = 0,
};

const Driver = struct {
    gpa: Allocator,
    run_arena: std.heap.ArenaAllocator,
    keep_arena: std.heap.ArenaAllocator,
    rt: *loader.Runtime,
    cache: *interp.LinkCache,
    c: *const Call,
    tally: *Tally,
    /// The loop under test (`fast`, and then `block` as well; `ref` only in the harness's own
    /// self test).
    subject: Mode = .fast,

    fn one(d: *Driver, o: Opts) !Snap {
        _ = d.run_arena.reset(.retain_capacity);
        d.tally.runs += 1;
        return runOne(d.run_arena.allocator(), d.keep_arena.allocator(), d.rt, d.cache, d.c, o);
    }

    /// Reference against the subject (and the traced loop when `traced`) from the starting
    /// state `o`. Returns a description of the first difference, or null.
    fn pair(d: *Driver, o_in: Opts, traced: bool, ref_out: ?*Snap) !?[]u8 {
        _ = d.keep_arena.reset(.retain_capacity);
        var o = o_in;
        o.mode = .ref;
        const r = try d.one(o);
        if (ref_out) |p| p.* = r;
        o.mode = d.subject;
        const f = try d.one(o);
        d.tally.compared += 1;
        if (!r.ok and r.fail == null) {
            d.tally.errors += 1;
            if (r.err.major == .OUT_OF_GAS) d.tally.oog += 1;
        }
        if (!same(&r, &f)) return try describe(d.gpa, o, "reference", &r, @tagName(d.subject), &f);
        if (d.subject == .fast) {
            // the same loop with block gas charging on
            o.mode = .block;
            const b = try d.one(o);
            d.tally.compared += 1;
            d.tally.blocks_charged += b.blocks_charged;
            d.tally.blocks_refused += b.blocks_refused;
            d.tally.blocks_undone += b.blocks_undone;
            if (!b.ok and b.fail == null) {
                if (b.blocks_charged != 0) d.tally.block_error_runs += 1;
                if (b.err.major == .OUT_OF_GAS) switch (b.stop) {
                    .first => d.tally.block_oog_first += 1,
                    .inside => d.tally.block_oog_inside += 1,
                    .outside => {},
                };
                if (b.blocks_faulted != 0) d.tally.block_fault_runs += 1;
            }
            if (!same(&r, &b)) return try describe(d.gpa, o, "reference", &r, "block", &b);
        }
        if (traced) {
            o.mode = .traced;
            const t = try d.one(o);
            d.tally.traced_runs += 1;
            d.tally.compared += 1;
            if (!same(&r, &t)) return try describe(d.gpa, o, "reference", &r, "traced", &t);
        }
        return null;
    }
};

/// Compares the loops on call `c` under `plan`. Returns null when every run agreed, else a
/// description of the first difference (owned by `gpa`).
pub fn diffCall(gpa: Allocator, rt: *loader.Runtime, cache: *interp.LinkCache, c: *const Call, plan: Plan, tally: *Tally, seed: u64) !?[]u8 {
    return diffCallSubject(gpa, rt, cache, c, plan, tally, seed, .fast);
}

fn diffCallSubject(gpa: Allocator, rt: *loader.Runtime, cache: *interp.LinkCache, c: *const Call, plan: Plan, tally: *Tally, seed: u64, subject: Mode) !?[]u8 {
    var d: Driver = .{
        .gpa = gpa,
        .run_arena = std.heap.ArenaAllocator.init(gpa),
        .keep_arena = std.heap.ArenaAllocator.init(gpa),
        .rt = rt,
        .cache = cache,
        .c = c,
        .tally = tally,
        .subject = subject,
    };
    defer d.run_arena.deinit();
    defer d.keep_arena.deinit();
    tally.calls += 1;
    var prng = std.Random.DefaultPrng.init(seed ^ 0x9e37_79b9_7f4a_7c15);
    const rnd = prng.random();

    // The call's own budget, on all three loops.
    var base: Snap = undefined;
    if (try d.pair(.{}, false, &base)) |m| return m;
    const bm = base.meter;
    if (base.fail != null) return null;
    const used: u64 = if (bm.initial_budget >= bm.gas_left) bm.initial_budget - bm.gas_left else bm.initial_budget;
    const n_ins = bm.instructions_executed;
    const traced = plan.traced and !base.entry_native and n_ins <= plan.traced_max_ins and base.state.len <= 64 << 10;
    const long = n_ins > plan.long_ins;
    const edge: u64 = if (long) @min(plan.edge, plan.long_n) else plan.edge;
    const samples: u32 = if (long) @min(plan.samples, plan.long_n) else plan.samples;
    const presets: u32 = if (long) @min(plan.presets, plan.long_n / 2) else plan.presets;
    const gm_samples: u32 = if (long) @min(plan.gm_samples, 1) else plan.gm_samples;
    if (long) tally.long_calls += 1;
    const oog = !base.ok and base.err.major == .OUT_OF_GAS;
    if (oog) tally.oog_calls += 1;
    if (traced) if (try d.pair(.{}, true, null)) |m| return m;

    // Every budget (or both ends and a sample): each one stops the call at another instruction.
    if (used <= plan.exhaustive_cap) {
        tally.exhaustive_calls += 1;
        var g: u64 = 0;
        while (g <= used) : (g += 1) {
            const tr = traced and plan.traced_every != 0 and g % plan.traced_every == 0;
            if (try d.pair(.{ .gas_left = g }, tr, null)) |m| return m;
        }
    } else {
        var g: u64 = 0;
        const edge_traced = traced and plan.traced_every == 1;
        while (g <= edge) : (g += 1) {
            if (try d.pair(.{ .gas_left = g }, edge_traced, null)) |m| return m;
            if (try d.pair(.{ .gas_left = used - g }, edge_traced, null)) |m| return m;
        }
        var k: u32 = 0;
        while (k < samples) : (k += 1) {
            const tr = traced and plan.traced_every != 0 and k % plan.traced_every == 0;
            if (try d.pair(.{ .gas_left = rnd.uintLessThan(u64, used) }, tr, null)) |m| return m;
        }
    }

    // Counters just below a tier start, so the call crosses it at a random instruction.
    var k: u32 = 0;
    while (k < presets) : (k += 1) {
        var o: Opts = .{};
        const pick = 1 + rnd.uintLessThan(u8, 7);
        if (pick & 1 != 0) o.pre_instructions = .{ .tier = rnd.uintLessThan(u8, 3), .below = rnd.uintLessThan(u64, n_ins + 2) };
        if (pick & 2 != 0) o.pre_size = .{ .tier = rnd.uintLessThan(u8, 3), .below = rnd.uintLessThan(u64, bm.stack_size_current + 2) };
        if (pick & 4 != 0) o.pre_height = .{ .tier = rnd.uintLessThan(u8, 2), .below = rnd.uintLessThan(u64, bm.stack_height_high_water_mark + 2) };
        if (rnd.boolean()) o.gas_left = rnd.uintLessThan(u64, (used + 1) *| @as(u64, if (oog) 1 else 8));
        if (try d.pair(o, false, null)) |m| return m;
    }

    if (plan.unmetered and !oog) if (try d.pair(.{ .unmetered = true }, false, null)) |m| return m;

    for (plan.gms) |gm| {
        var b: Snap = undefined;
        if (try d.pair(.{ .gm = gm, .gas_left = if (oog) @min(bm.initial_budget, plan.oog_gas_cap) else null }, false, &b)) |m| return m;
        const u: u64 = if (b.meter.initial_budget >= b.meter.gas_left) b.meter.initial_budget - b.meter.gas_left else 0;
        var j: u32 = 0;
        while (j < gm_samples) : (j += 1) {
            if (try d.pair(.{ .gm = gm, .gas_left = rnd.uintLessThan(u64, u + 1) }, false, null)) |m| return m;
        }
    }

    if (plan.legacy) {
        if (try d.pair(.{ .legacy = true }, false, null)) |m| return m;
        var j: u32 = 0;
        while (j < gm_samples) : (j += 1) {
            if (try d.pair(.{ .legacy = true, .gas_left = rnd.uintLessThan(u64, used + 1) }, false, null)) |m| return m;
        }
    }
    return null;
}

// ---------------------------------------------------------------------------------------------
// The move-vm-diff suite: the plan above over the move-vm-gas corpus.

/// Every call runs the light plan (every budget when it uses at most 1,500 gas units); one
/// call in `DEEP_EVERY` runs the deep one (every budget up to 12,000 units: a run per unit,
/// so the cost grows with the square of the call's length).
const DEEP_EVERY: u64 = 32;
const light_plan: Plan = .{ .exhaustive_cap = 1500, .samples = 12, .edge = 24, .traced_every = 0, .presets = 4, .gms = &.{ 13, 10, 7 }, .gm_samples = 2 };
const deep_plan: Plan = .{ .exhaustive_cap = 12_000, .samples = 64, .edge = 96, .traced_every = 64, .presets = 12 };

/// One worker of the suite: its own runtime, link cache and scratch (a Runtime belongs to one
/// thread). Workers take the corpus's calls one at a time off a shared counter.
const SuiteWorker = struct {
    ctx: harness.Ctx,
    next: *std.atomic.Value(u64),
    tally: Tally = .{},
    err: ?anyerror = null,

    fn run(w: *SuiteWorker) void {
        w.work() catch |e| {
            w.err = e;
        };
    }

    fn work(w: *SuiteWorker) !void {
        const ctx = &w.ctx;
        var vec = try conf.loadVectors(ctx);
        defer vec.deinit(ctx.gpa);
        var cache = interp.LinkCache.init(ctx.gpa);
        defer cache.deinit();
        var it = harness.lines(vec.calls_text);
        var name_buf: [512]u8 = undefined;
        var taken: u64 = 0; // lines read from `it`
        while (!ctx.done()) {
            const n = w.next.fetchAdd(1, .monotonic);
            var line: []const u8 = undefined;
            while (taken <= n) : (taken += 1) line = it.next() orelse return;
            ctx.nextItem();
            const arena = ctx.scratch();
            const c = try Call.parse(arena, line);
            const item = try std.fmt.bufPrint(&name_buf, "{d}/{s}::{s}", .{ c.id, c.module_name, c.func });
            if (!ctx.selected(item)) continue;
            const plan = if (n % DEEP_EVERY == 0) deep_plan else light_plan;
            const msg = diffCall(ctx.gpa, vec.rt, &cache, &c, plan, &w.tally, c.id) catch |e| {
                ctx.fail(item, "could not run the call: {s}", .{@errorName(e)});
                continue;
            };
            if (msg) |m| {
                defer ctx.gpa.free(m);
                ctx.fail(item, "{s}", .{m});
            } else ctx.pass(item);
        }
    }
};

pub fn runSuite(ctx: *harness.Ctx) !void {
    const jobs: usize = @max(1, ctx.opts.jobs);
    var next: std.atomic.Value(u64) = .init(0);
    const workers = try ctx.gpa.alloc(SuiteWorker, jobs);
    defer ctx.gpa.free(workers);
    const arenas = try ctx.gpa.alloc(std.heap.ArenaAllocator, jobs);
    defer ctx.gpa.free(arenas);
    const threads = try ctx.gpa.alloc(std.Thread, jobs);
    defer ctx.gpa.free(threads);
    for (workers, arenas) |*w, *a| {
        a.* = .init(std.heap.page_allocator);
        w.* = .{ .ctx = ctx.*, .next = &next };
        w.ctx.arena = a;
        w.ctx.stats = .{};
    }
    defer for (arenas) |*a| a.deinit();
    var spawned: usize = 0;
    for (threads[1..], workers[1..]) |*t, *w| {
        t.* = std.Thread.spawn(.{ .stack_size = 64 << 20 }, SuiteWorker.run, .{w}) catch break;
        spawned += 1;
    }
    workers[0].run(); // this thread is a worker too
    for (threads[1..][0..spawned]) |t| t.join();
    var tally: Tally = .{};
    var first_err: ?anyerror = null;
    for (workers[0 .. spawned + 1]) |*w| {
        ctx.stats.add(w.ctx.stats);
        inline for (@typeInfo(Tally).@"struct".field_names) |f| @field(tally, f) += @field(w.tally, f);
        if (first_err == null) first_err = w.err;
    }
    ctx.detail("move-vm-diff: {d} calls ({d} at every budget, {d} long, {d} ending out of gas), {d} runs, {d} comparisons ({d} traced), {d} ended in an error ({d} out of gas)\n", .{ tally.calls, tally.exhaustive_calls, tally.long_calls, tally.oog_calls, tally.runs, tally.compared, tally.traced_runs, tally.errors, tally.oog });
    ctx.detail("move-vm-diff block gas: {d} blocks charged at once, {d} refused by the meter, {d} undone inside; {d} runs ended in an error after a charged block, {d} ran out of gas at the first instruction of a block and {d} inside one, {d} failed inside a charged block\n", .{ tally.blocks_charged, tally.blocks_refused, tally.blocks_undone, tally.block_error_runs, tally.block_oog_first, tally.block_oog_inside, tally.block_fault_runs });
    if (first_err) |e| return e;
}

// ---------------------------------------------------------------------------------------------
// Unit tests: the embedded framework.

/// BCS bytes for test arguments.
const B = struct {
    a: Allocator,

    fn uleb(b: B, out: *std.ArrayList(u8), n: usize) !void {
        var x = n;
        while (true) {
            const byte: u8 = @intCast(x & 0x7f);
            x >>= 7;
            if (x == 0) {
                try out.append(b.a, byte);
                return;
            }
            try out.append(b.a, byte | 0x80);
        }
    }
    fn int(b: B, comptime T: type, x: T) ![]const u8 {
        const o = try b.a.alloc(u8, @sizeOf(T));
        std.mem.writeInt(T, o[0..@sizeOf(T)], x, .little);
        return o;
    }
    fn u256_(b: B, x: u256) ![]const u8 {
        const o = try b.a.alloc(u8, 32);
        std.mem.writeInt(u256, o[0..32], x, .little);
        return o;
    }
    fn addr(b: B, last: u8) ![]const u8 {
        const o = try b.a.alloc(u8, 32);
        @memset(o, 0);
        o[31] = last;
        o[0] = last ^ 0x5c;
        return o;
    }
    /// vector<u8> (also a String, a BCS, an ascii String).
    fn bytes(b: B, s: []const u8) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try b.uleb(&out, s.len);
        try out.appendSlice(b.a, s);
        return out.items;
    }
    /// 0, 1, 2, .. as a vector<u8> of `n` bytes.
    fn iota(b: B, n: usize) ![]const u8 {
        const s = try b.a.alloc(u8, n);
        for (s, 0..) |*x, i| x.* = @truncate(i *% 7 +% 3);
        return b.bytes(s);
    }
    /// A vector of fixed-width elements (or any already encoded elements).
    fn vec(b: B, elems: []const []const u8) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try b.uleb(&out, elems.len);
        for (elems) |e| try out.appendSlice(b.a, e);
        return out.items;
    }
    fn vecInt(b: B, comptime T: type, xs: []const T) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try b.uleb(&out, xs.len);
        for (xs) |x| try out.appendSlice(b.a, try b.int(T, x));
        return out.items;
    }
    /// A `sui::bcs::BCS` positioned at the start of `payload` (it keeps its bytes reversed).
    fn bcsOf(b: B, payload: []const u8) ![]const u8 {
        const r = try b.a.dupe(u8, payload);
        std.mem.reverse(u8, r);
        return b.bytes(r);
    }
    /// The argument list, kept in the arena (a literal with runtime elements is a temporary).
    fn args(b: B, list: []const A) ![]const A {
        return b.a.dupe(A, list);
    }
    fn cat(b: B, parts: []const []const u8) ![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        for (parts) |p| try out.appendSlice(b.a, p);
        return out.items;
    }
};

const ty_u8 = [_]u8{1};
const ty_u16 = [_]u8{8};
const ty_u64 = [_]u8{2};
const ty_u128 = [_]u8{3};
const ty_u256 = [_]u8{10};
const ty_addr = [_]u8{4};
const ty_vec_u8 = [_]u8{ 6, 1 };

const A = Call.Arg;
fn val(bytes: []const u8) A {
    return .{ .kind = .val, .bytes = bytes };
}
fn ref(bytes: []const u8) A {
    return .{ .kind = .ref, .bytes = bytes };
}
fn mut(bytes: []const u8) A {
    return .{ .kind = .mut, .bytes = bytes };
}

const FwCall = struct { pkg: u8, module: []const u8, func: []const u8, tys: []const []const u8 = &.{}, args: []const A = &.{} };

fn frameworkCalls(b: B) ![]const FwCall {
    const u64s = [_]u64{ 5, 9, 1, 7, 3, 11, 2, 40, 13, 8 };
    const u64v = try b.vecInt(u64, &u64s);
    const addrs = try b.vec(&.{ try b.addr(1), try b.addr(2), try b.addr(3) });
    const nested = try b.vec(&.{ try b.bytes(&.{ 1, 2 }), try b.bytes(&.{3}), try b.bytes(&.{}) });
    const hello = try b.bytes("hello, w\xc3\xb6rld");
    const bitvec = try b.cat(&.{ try b.int(u64, 24), try b.vec(&.{ &.{1}, &.{0}, &.{1}, &.{1}, &.{1}, &.{0}, &.{0}, &.{1}, &.{1}, &.{1}, &.{1}, &.{0}, &.{1}, &.{0}, &.{0}, &.{0}, &.{1}, &.{1}, &.{0}, &.{1}, &.{0}, &.{1}, &.{1}, &.{1} }) });
    // priority_queue::Entry<u64> { priority, value } x 9, and a PriorityQueue of them
    var ent: std.ArrayList(u8) = .empty;
    try b.uleb(&ent, 9);
    for ([_]u64{ 4, 8, 15, 16, 23, 42, 7, 1, 30 }) |p| {
        try ent.appendSlice(b.a, try b.int(u64, p));
        try ent.appendSlice(b.a, try b.int(u64, p * 3));
    }
    // vec_map::VecMap<u64, vector<u8>> { contents: vector<Entry { key, value }> }
    var vm: std.ArrayList(u8) = .empty;
    try b.uleb(&vm, 4);
    for ([_]u64{ 10, 20, 30, 40 }) |k| {
        try vm.appendSlice(b.a, try b.int(u64, k));
        try vm.appendSlice(b.a, try b.bytes(&.{ @truncate(k), 1, 2 }));
    }
    const bcs_bytes = try b.cat(&.{ try b.int(u64, 0x1122334455667788), try b.iota(9), try b.u256_(1 << 200), try b.addr(9), try b.vecInt(u64, &.{ 1, 2, 3 }), nested, &.{ 1, 7, 0, 0, 0, 0, 0, 0, 0 } });
    const type_name = try b.bytes("0000000000000000000000000000000000000000000000000000000000000002::coin::Coin<0000000000000000000000000000000000000000000000000000000000000002::sui::SUI>");
    const list = [_]FwCall{
        // vector loops
        .{ .pkg = 1, .module = "vector", .func = "reverse", .tys = &.{&ty_u8}, .args = try b.args(&.{mut(try b.iota(21))}) },
        .{ .pkg = 1, .module = "vector", .func = "reverse", .tys = &.{&ty_u8}, .args = try b.args(&.{mut(try b.iota(0))}) },
        .{ .pkg = 1, .module = "vector", .func = "reverse", .tys = &.{&ty_u64}, .args = try b.args(&.{mut(u64v)}) },
        .{ .pkg = 1, .module = "vector", .func = "reverse", .tys = &.{&ty_addr}, .args = try b.args(&.{mut(addrs)}) },
        .{ .pkg = 1, .module = "vector", .func = "reverse", .tys = &.{&ty_vec_u8}, .args = try b.args(&.{mut(nested)}) },
        .{ .pkg = 1, .module = "vector", .func = "append", .tys = &.{&ty_u8}, .args = try b.args(&.{ mut(try b.iota(3)), val(try b.iota(9)) }) },
        .{ .pkg = 1, .module = "vector", .func = "append", .tys = &.{&ty_u256}, .args = try b.args(&.{ mut(try b.vec(&.{try b.u256_(7)})), val(try b.vec(&.{ try b.u256_(1 << 255), try b.u256_(3) })) }) },
        .{ .pkg = 1, .module = "vector", .func = "append", .tys = &.{&ty_vec_u8}, .args = try b.args(&.{ mut(nested), val(nested) }) },
        .{ .pkg = 1, .module = "vector", .func = "remove", .tys = &.{&ty_u64}, .args = try b.args(&.{ mut(u64v), val(try b.int(u64, 3)) }) },
        .{ .pkg = 1, .module = "vector", .func = "remove", .tys = &.{&ty_u64}, .args = try b.args(&.{ mut(u64v), val(try b.int(u64, 10)) }) },
        .{ .pkg = 1, .module = "vector", .func = "remove", .tys = &.{&ty_vec_u8}, .args = try b.args(&.{ mut(nested), val(try b.int(u64, 0)) }) },
        .{ .pkg = 1, .module = "vector", .func = "contains", .tys = &.{&ty_u8}, .args = try b.args(&.{ ref(try b.iota(30)), ref(&.{250}) }) },
        .{ .pkg = 1, .module = "vector", .func = "contains", .tys = &.{&ty_addr}, .args = try b.args(&.{ ref(addrs), ref(try b.addr(3)) }) },
        .{ .pkg = 1, .module = "vector", .func = "contains", .tys = &.{&ty_vec_u8}, .args = try b.args(&.{ ref(nested), ref(try b.bytes(&.{3})) }) },
        .{ .pkg = 1, .module = "vector", .func = "index_of", .tys = &.{&ty_u64}, .args = try b.args(&.{ ref(u64v), ref(try b.int(u64, 13)) }) },
        .{ .pkg = 1, .module = "vector", .func = "insert", .tys = &.{&ty_u8}, .args = try b.args(&.{ mut(try b.iota(10)), val(&.{77}), val(try b.int(u64, 4)) }) },
        .{ .pkg = 1, .module = "vector", .func = "insert", .tys = &.{&ty_u8}, .args = try b.args(&.{ mut(try b.iota(2)), val(&.{77}), val(try b.int(u64, 3)) }) },
        .{ .pkg = 1, .module = "vector", .func = "swap_remove", .tys = &.{&ty_u16}, .args = try b.args(&.{ mut(try b.vecInt(u16, &.{ 1, 2, 3, 4, 5 })), val(try b.int(u64, 1)) }) },
        .{ .pkg = 1, .module = "vector", .func = "swap_remove", .tys = &.{&ty_u16}, .args = try b.args(&.{ mut(try b.vecInt(u16, &.{})), val(try b.int(u64, 0)) }) },
        .{ .pkg = 1, .module = "vector", .func = "singleton", .tys = &.{&ty_u128}, .args = try b.args(&.{val(try b.int(u128, 1 << 100))}) },
        // strings (natives and loops over bytes)
        .{ .pkg = 1, .module = "string", .func = "utf8", .args = try b.args(&.{val(hello)}) },
        .{ .pkg = 1, .module = "string", .func = "utf8", .args = try b.args(&.{val(try b.bytes(&.{ 0xff, 0xfe }))}) },
        .{ .pkg = 1, .module = "string", .func = "append", .args = try b.args(&.{ mut(hello), val(hello) }) },
        .{ .pkg = 1, .module = "string", .func = "sub_string", .args = try b.args(&.{ ref(hello), val(try b.int(u64, 2)), val(try b.int(u64, 7)) }) },
        .{ .pkg = 1, .module = "string", .func = "index_of", .args = try b.args(&.{ ref(hello), ref(try b.bytes("rld")) }) },
        .{ .pkg = 1, .module = "ascii", .func = "string", .args = try b.args(&.{val(try b.bytes("plain ascii text"))}) },
        .{ .pkg = 1, .module = "ascii", .func = "string", .args = try b.args(&.{val(try b.bytes("bad \xff"))}) },
        .{ .pkg = 1, .module = "ascii", .func = "try_string", .args = try b.args(&.{val(try b.bytes("ok\x80"))}) },
        .{ .pkg = 1, .module = "ascii", .func = "all_characters_printable", .args = try b.args(&.{ref(try b.bytes("printable?\n"))}) },
        .{ .pkg = 1, .module = "ascii", .func = "to_uppercase", .args = try b.args(&.{ref(try b.bytes("mixed Case 123"))}) },
        .{ .pkg = 1, .module = "ascii", .func = "index_of", .args = try b.args(&.{ ref(try b.bytes("needle in a haystack")), ref(try b.bytes("hay")) }) },
        // integers
        .{ .pkg = 1, .module = "u64", .func = "sqrt", .args = try b.args(&.{val(try b.int(u64, (1 << 40) + 12345))}) },
        .{ .pkg = 1, .module = "u64", .func = "pow", .args = try b.args(&.{ val(try b.int(u64, 3)), val(&.{30}) }) },
        .{ .pkg = 1, .module = "u64", .func = "pow", .args = try b.args(&.{ val(try b.int(u64, 10)), val(&.{25}) }) },
        .{ .pkg = 1, .module = "u64", .func = "to_string", .args = try b.args(&.{val(try b.int(u64, std.math.maxInt(u64)))}) },
        .{ .pkg = 1, .module = "u64", .func = "divide_and_round_up", .args = try b.args(&.{ val(try b.int(u64, 100)), val(try b.int(u64, 7)) }) },
        .{ .pkg = 1, .module = "u64", .func = "divide_and_round_up", .args = try b.args(&.{ val(try b.int(u64, 1)), val(try b.int(u64, 0)) }) },
        .{ .pkg = 1, .module = "u128", .func = "sqrt", .args = try b.args(&.{val(try b.int(u128, (1 << 100) + 99))}) },
        .{ .pkg = 1, .module = "u128", .func = "pow", .args = try b.args(&.{ val(try b.int(u128, 7)), val(&.{40}) }) },
        .{ .pkg = 1, .module = "u128", .func = "to_string", .args = try b.args(&.{val(try b.int(u128, 1 << 90))}) },
        .{ .pkg = 1, .module = "u256", .func = "pow", .args = try b.args(&.{ val(try b.u256_(3)), val(&.{100}) }) },
        .{ .pkg = 1, .module = "u256", .func = "to_string", .args = try b.args(&.{val(try b.u256_(1 << 130))}) },
        .{ .pkg = 1, .module = "u256", .func = "divide_and_round_up", .args = try b.args(&.{ val(try b.u256_(1 << 200)), val(try b.u256_(12345)) }) },
        // structs, field borrows, loops over bools
        .{ .pkg = 1, .module = "bit_vector", .func = "new", .args = try b.args(&.{val(try b.int(u64, 70))}) },
        .{ .pkg = 1, .module = "bit_vector", .func = "new", .args = try b.args(&.{val(try b.int(u64, 0))}) },
        .{ .pkg = 1, .module = "bit_vector", .func = "set", .args = try b.args(&.{ mut(bitvec), val(try b.int(u64, 5)) }) },
        .{ .pkg = 1, .module = "bit_vector", .func = "set", .args = try b.args(&.{ mut(bitvec), val(try b.int(u64, 24)) }) },
        .{ .pkg = 1, .module = "bit_vector", .func = "shift_left", .args = try b.args(&.{ mut(bitvec), val(try b.int(u64, 7)) }) },
        .{ .pkg = 1, .module = "bit_vector", .func = "longest_set_sequence_starting_at", .args = try b.args(&.{ ref(bitvec), val(try b.int(u64, 7)) }) },
        .{ .pkg = 1, .module = "fixed_point32", .func = "create_from_rational", .args = try b.args(&.{ val(try b.int(u64, 7)), val(try b.int(u64, 3)) }) },
        .{ .pkg = 1, .module = "fixed_point32", .func = "create_from_rational", .args = try b.args(&.{ val(try b.int(u64, 1)), val(try b.int(u64, 0)) }) },
        .{ .pkg = 1, .module = "fixed_point32", .func = "multiply_u64", .args = try b.args(&.{ val(try b.int(u64, 1000)), val(try b.int(u64, 3 << 31)) }) },
        .{ .pkg = 1, .module = "fixed_point32", .func = "divide_u64", .args = try b.args(&.{ val(try b.int(u64, 1000)), val(try b.int(u64, 3 << 31)) }) },
        // options (generic calls that pass the type argument through)
        .{ .pkg = 1, .module = "option", .func = "some", .tys = &.{&ty_u64}, .args = try b.args(&.{val(try b.int(u64, 5))}) },
        .{ .pkg = 1, .module = "option", .func = "destroy_with_default", .tys = &.{&ty_u64}, .args = try b.args(&.{ val(try b.vecInt(u64, &.{})), val(try b.int(u64, 9)) }) },
        .{ .pkg = 1, .module = "option", .func = "get_with_default", .tys = &.{&ty_addr}, .args = try b.args(&.{ ref(try b.vec(&.{try b.addr(4)})), val(try b.addr(5)) }) },
        .{ .pkg = 1, .module = "option", .func = "swap_or_fill", .tys = &.{&ty_u64}, .args = try b.args(&.{ mut(try b.vecInt(u64, &.{3})), val(try b.int(u64, 4)) }) },
        .{ .pkg = 1, .module = "option", .func = "extract", .tys = &.{&ty_u64}, .args = try b.args(&.{mut(try b.vecInt(u64, &.{}))}) },
        .{ .pkg = 1, .module = "option", .func = "to_vec", .tys = &.{&ty_vec_u8}, .args = try b.args(&.{val(try b.vec(&.{try b.iota(4)}))}) },
        .{ .pkg = 1, .module = "type_name", .func = "get", .tys = &.{&ty_vec_u8} },
        .{ .pkg = 1, .module = "type_name", .func = "get_address", .args = try b.args(&.{ref(type_name)}) },
        .{ .pkg = 1, .module = "type_name", .func = "get_module", .args = try b.args(&.{ref(type_name)}) },
        // sui framework
        .{ .pkg = 2, .module = "hex", .func = "encode", .args = try b.args(&.{val(try b.iota(20))}) },
        .{ .pkg = 2, .module = "hex", .func = "decode", .args = try b.args(&.{val(try b.bytes("deadBEEF0042"))}) },
        .{ .pkg = 2, .module = "hex", .func = "decode", .args = try b.args(&.{val(try b.bytes("xz"))}) },
        .{ .pkg = 2, .module = "address", .func = "to_string", .args = try b.args(&.{val(try b.addr(0xab))}) },
        .{ .pkg = 2, .module = "address", .func = "to_bytes", .args = try b.args(&.{val(try b.addr(0xab))}) },
        .{ .pkg = 2, .module = "address", .func = "from_ascii_bytes", .args = try b.args(&.{ref(try b.bytes("00000000000000000000000000000000000000000000000000000000000000ff"))}) },
        .{ .pkg = 2, .module = "address", .func = "from_ascii_bytes", .args = try b.args(&.{ref(try b.bytes("00"))}) },
        .{ .pkg = 2, .module = "bcs", .func = "new", .args = try b.args(&.{val(try b.iota(12))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_u64", .args = try b.args(&.{mut(try b.bcsOf(bcs_bytes))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_u64", .args = try b.args(&.{mut(try b.bytes(&.{ 1, 2, 3 }))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_vec_u8", .args = try b.args(&.{mut(try b.bcsOf(try b.iota(9)))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_u256", .args = try b.args(&.{mut(try b.bcsOf(try b.u256_(1 << 200)))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_address", .args = try b.args(&.{mut(try b.bcsOf(try b.addr(9)))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_vec_u64", .args = try b.args(&.{mut(try b.bcsOf(try b.vecInt(u64, &.{ 1, 2, 3 })))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_vec_vec_u8", .args = try b.args(&.{mut(try b.bcsOf(nested))}) },
        .{ .pkg = 2, .module = "bcs", .func = "peel_option_u64", .args = try b.args(&.{mut(try b.bcsOf(&.{ 1, 7, 0, 0, 0, 0, 0, 0, 0 }))}) },
        .{ .pkg = 2, .module = "priority_queue", .func = "create_entries", .tys = &.{&ty_u64}, .args = try b.args(&.{ val(u64v), val(u64v) }) },
        .{ .pkg = 2, .module = "priority_queue", .func = "new", .tys = &.{&ty_u64}, .args = try b.args(&.{val(ent.items)}) },
        .{ .pkg = 2, .module = "priority_queue", .func = "pop_max", .tys = &.{&ty_u64}, .args = try b.args(&.{mut(ent.items)}) },
        .{ .pkg = 2, .module = "priority_queue", .func = "insert", .tys = &.{&ty_u64}, .args = try b.args(&.{ mut(ent.items), val(try b.int(u64, 50)), val(try b.int(u64, 9)) }) },
        .{ .pkg = 2, .module = "vec_set", .func = "from_keys", .tys = &.{&ty_u64}, .args = try b.args(&.{val(u64v)}) },
        .{ .pkg = 2, .module = "vec_set", .func = "from_keys", .tys = &.{&ty_u64}, .args = try b.args(&.{val(try b.vecInt(u64, &.{ 1, 2, 1 }))}) },
        .{ .pkg = 2, .module = "vec_set", .func = "contains", .tys = &.{&ty_addr}, .args = try b.args(&.{ ref(addrs), ref(try b.addr(2)) }) },
        .{ .pkg = 2, .module = "vec_set", .func = "insert", .tys = &.{&ty_u64}, .args = try b.args(&.{ mut(u64v), val(try b.int(u64, 99)) }) },
        .{ .pkg = 2, .module = "vec_set", .func = "remove", .tys = &.{&ty_u64}, .args = try b.args(&.{ mut(u64v), ref(try b.int(u64, 7)) }) },
        .{ .pkg = 2, .module = "vec_map", .func = "from_keys_values", .tys = &.{ &ty_u64, &ty_u8 }, .args = try b.args(&.{ val(try b.vecInt(u64, &.{ 1, 2, 3 })), val(try b.iota(3)) }) },
        .{ .pkg = 2, .module = "vec_map", .func = "get", .tys = &.{ &ty_u64, &ty_vec_u8 }, .args = try b.args(&.{ ref(vm.items), ref(try b.int(u64, 30)) }) },
        .{ .pkg = 2, .module = "vec_map", .func = "get", .tys = &.{ &ty_u64, &ty_vec_u8 }, .args = try b.args(&.{ ref(vm.items), ref(try b.int(u64, 31)) }) },
        .{ .pkg = 2, .module = "vec_map", .func = "get_idx", .tys = &.{ &ty_u64, &ty_vec_u8 }, .args = try b.args(&.{ ref(vm.items), ref(try b.int(u64, 40)) }) },
        .{ .pkg = 2, .module = "vec_map", .func = "remove", .tys = &.{ &ty_u64, &ty_vec_u8 }, .args = try b.args(&.{ mut(vm.items), ref(try b.int(u64, 20)) }) },
        .{ .pkg = 2, .module = "vec_map", .func = "insert", .tys = &.{ &ty_u64, &ty_vec_u8 }, .args = try b.args(&.{ mut(vm.items), val(try b.int(u64, 25)), val(try b.iota(2)) }) },
    };
    return b.a.dupe(FwCall, &list);
}

fn fwCall(f: FwCall, gm: u64) Call {
    var id: loader.Address = @splat(0);
    id[31] = f.pkg;
    var two: loader.Address = @splat(0);
    two[31] = 2;
    return .{
        .id = 0,
        .pv = 141,
        .gm = gm,
        .root = two,
        .module_addr = id,
        .module_name = f.module,
        .func = f.func,
        .tys = f.tys,
        .args = f.args,
        .budget = 1_000_000,
        .truth = .null,
    };
}

/// The plan of the unit tests (Debug build): every budget for calls of ordinary size.
const unit_plan: Plan = .{ .exhaustive_cap = 2500, .samples = 40, .edge = 40, .traced_every = 32, .presets = 6, .gms = &.{ 13, 11, 10, 9, 5, 1 }, .gm_samples = 3 };

fn expectAgree(msg: ?[]u8, what: []const u8, func: []const u8) !void {
    if (msg) |m| {
        defer std.testing.allocator.free(m);
        std.debug.print("\n{s}::{s}: {s}\n", .{ what, func, m });
        return error.LoopsDiffer;
    }
}

test "stepRun equals the reference and the traced loop on framework calls, at every budget" {
    const gpa = std.testing.allocator;
    const rt = try conf.frameworkRuntime(gpa);
    defer {
        rt.deinit();
        gpa.destroy(rt);
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const calls = try frameworkCalls(.{ .a = arena_state.allocator() });
    const gm = try (try protocol.get(141, .mainnet)).get("gas_model_version");
    var cache = interp.LinkCache.init(gpa);
    defer cache.deinit();
    var tally: Tally = .{};
    var ok_calls: usize = 0;
    var every_budget_traced: usize = 0;
    for (calls, 0..) |f, i| {
        const c = fwCall(f, gm);
        // The call itself must run: a wrong name or argument encoding would test nothing.
        var a2 = std.heap.ArenaAllocator.init(gpa);
        defer a2.deinit();
        const s0 = try runOne(a2.allocator(), a2.allocator(), rt, &cache, &c, .{ .mode = .ref });
        if (s0.ok) ok_calls += 1;
        if (s0.fail != null or !(s0.ok or s0.err.major == .ABORTED or s0.err.major == .ARITHMETIC_ERROR)) {
            std.debug.print("\ncall {d} {s}::{s}: fail {?}, status {s}\n", .{ i, f.module, f.func, s0.fail, @tagName(s0.err.major) });
            return error.TestCallDidNotRun;
        }
        // One call in four: the traced loop itself at every budget, beside the reference.
        var plan = unit_plan;
        if (i % 4 == 0) {
            plan.traced_every = 1;
            every_budget_traced += 1;
        }
        try expectAgree(try diffCall(gpa, rt, &cache, &c, plan, &tally, i), f.module, f.func);
    }
    // Most calls succeed, some abort, and the sweep really ran out of gas all over them.
    try std.testing.expect(ok_calls * 4 >= calls.len * 3 and ok_calls < calls.len);
    try std.testing.expect(tally.exhaustive_calls * 2 >= calls.len);
    try std.testing.expect(tally.oog > 20_000);
    try std.testing.expect(every_budget_traced >= 20);
    try std.testing.expect(tally.traced_runs > 4_000);
    // block gas really charged blocks, undid some inside, and ended in errors after charging
    if (tally.blocks_charged < 10_000 or tally.blocks_undone < 100 or tally.block_error_runs < 1_000 or
        tally.blocks_refused < 10_000 or tally.block_oog_inside < 2_000 or tally.block_oog_first < 200 or tally.block_fault_runs < 1)
    {
        std.debug.print("\nblock gas over the framework calls: {any}\n", .{tally});
        return error.BlockGasNotExercised;
    }
}

test "the differential harness reports a difference" {
    // The same call from two different starting budgets is a real difference in gas; and the
    // harness, pointed at the reference as its own subject, agrees with itself.
    const gpa = std.testing.allocator;
    const rt = try conf.frameworkRuntime(gpa);
    defer {
        rt.deinit();
        gpa.destroy(rt);
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const b: B = .{ .a = a };
    const gm = try (try protocol.get(141, .mainnet)).get("gas_model_version");
    var cache = interp.LinkCache.init(gpa);
    defer cache.deinit();
    const c = fwCall(.{ .pkg = 2, .module = "hex", .func = "encode", .args = try b.args(&.{val(try b.iota(6))}) }, gm);
    const full = try runOne(a, a, rt, &cache, &c, .{ .mode = .fast });
    try std.testing.expect(full.ok and full.meter.instructions_executed > 30);
    const used = full.meter.initial_budget - full.meter.gas_left;
    const exact = try runOne(a, a, rt, &cache, &c, .{ .mode = .fast, .gas_left = used });
    try std.testing.expect(exact.ok and exact.meter.gas_left == 0);
    try std.testing.expect(!same(&full, &exact)); // gas left differs
    const short = try runOne(a, a, rt, &cache, &c, .{ .mode = .fast, .gas_left = used - 1 });
    try std.testing.expect(!short.ok and short.err.major == .OUT_OF_GAS);
    try std.testing.expect(!same(&exact, &short));
    // one instruction earlier: another code offset, another instruction count
    const shorter = try runOne(a, a, rt, &cache, &c, .{ .mode = .fast, .gas_left = used / 2 });
    try std.testing.expect(!shorter.ok and !same(&short, &shorter));
    try std.testing.expect(shorter.meter.instructions_executed < short.meter.instructions_executed);
    // a value on the stack differs
    const c2 = fwCall(.{ .pkg = 1, .module = "u64", .func = "diff", .args = try b.args(&.{ val(try b.int(u64, 10)), val(try b.int(u64, 3)) }) }, gm);
    const c3 = fwCall(.{ .pkg = 1, .module = "u64", .func = "diff", .args = try b.args(&.{ val(try b.int(u64, 10)), val(try b.int(u64, 4)) }) }, gm);
    const r2 = try runOne(a, a, rt, &cache, &c2, .{ .mode = .fast });
    const r3 = try runOne(a, a, rt, &cache, &c3, .{ .mode = .fast });
    try std.testing.expect(r2.ok and r3.ok and std.meta.eql(r2.meter, r3.meter) and !same(&r2, &r3));
    // tier placement changes the charge
    const pre = try runOne(a, a, rt, &cache, &c, .{ .mode = .fast, .pre_instructions = .{ .below = 3 } });
    try std.testing.expect(pre.ok and pre.meter.instructions_current_tier_mult > full.meter.instructions_current_tier_mult);
    var tally: Tally = .{};
    try expectAgree(try diffCallSubject(gpa, rt, &cache, &c, unit_plan, &tally, 1, .ref), "self", "encode");
    try std.testing.expect(tally.compared > 100);
}

// ---------------------------------------------------------------------------------------------
// Unit tests: synthetic modules (deserialized and bounds checked, not verified).

const SynFn = struct {
    name: []const u8,
    /// Indices into `syn_sigs`.
    params: u16 = 0,
    ret: u16 = 0,
    locals: u16 = 0,
    tps: u8 = 0,
    code: []const ff.Instr,
};

const n_u64 = [_]ff.Node{.{ .tag = .U64 }};
const n_u8 = [_]ff.Node{.{ .tag = .U8 }};
const n_u128 = [_]ff.Node{.{ .tag = .U128 }};
const n_u256 = [_]ff.Node{.{ .tag = .U256 }};
const n_bool = [_]ff.Node{.{ .tag = .Bool }};
const n_addr = [_]ff.Node{.{ .tag = .Address }};
const n_t0 = [_]ff.Node{.{ .tag = .TypeParameter, .idx = 0 }};
const n_t1 = [_]ff.Node{.{ .tag = .TypeParameter, .idx = 1 }};
const n_vec_t0 = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .TypeParameter, .idx = 0 } };
const n_vec_u64 = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .U64 } };
const n_vec_u8 = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .U8 } };
const n_s = [_]ff.Node{.{ .tag = .Datatype, .idx = 0 }};
const n_vec_s = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .Datatype, .idx = 0 } };
const n_ref_u64 = [_]ff.Node{ .{ .tag = .Reference }, .{ .tag = .U64 } };
const n_vec_vec_u8 = [_]ff.Node{ .{ .tag = .Vector }, .{ .tag = .Vector }, .{ .tag = .U8 } };

/// The signature table of every synthetic module. Vector instructions name the signature whose
/// first token is the element type.
const SIG_NONE = 0;
const SIG_U64 = 1;
const SIG_T0 = 2;
const SIG_VEC_T0 = 3;
const SIG_T1_T0 = 4;
const SIG_U64_U64 = 5;
const SIG_VEC_U64 = 6;
const SIG_U8 = 7;
const SIG_S = 8;
const SIG_VEC_U8 = 9;
const SIG_T0_T1 = 10;
const SIG_LOCALS4 = 11; // u64, vector<u8>, S, u64
const SIG_U128 = 12;
const SIG_U256 = 13;
const SIG_VEC_S = 14;
const SIG_ADDR = 15;
const SIG_VEC_VEC_U8 = 16;
const SIG_LOCALS_MIX = 17; // u64, u64, u64, u64, u64, u64 (six untyped scratch locals)
const syn_sigs = [_][]const ff.Token{
    &.{},
    &.{&n_u64},
    &.{&n_t0},
    &.{&n_vec_t0},
    &.{ &n_t1, &n_t0 },
    &.{ &n_u64, &n_u64 },
    &.{&n_vec_u64},
    &.{&n_u8},
    &.{&n_s},
    &.{&n_vec_u8},
    &.{ &n_t0, &n_t1 },
    &.{ &n_u64, &n_vec_u8, &n_s, &n_u64 },
    &.{&n_u128},
    &.{&n_u256},
    &.{&n_vec_s},
    &.{&n_addr},
    &.{&n_vec_vec_u8},
    &.{ &n_u64, &n_u64, &n_u64, &n_u64, &n_u64, &n_u64 },
};

const Syn = struct {
    rt: loader.Runtime,
    id: loader.Address,

    /// Module `M` at 0x0707..: struct `S { a: u64, b: vector<u8> }` (datatype 0, fields 0 and 1),
    /// functions `fns` (function handle i is function i) and the generic call sites `insts`.
    fn init(s: *Syn, gpa: Allocator, a: Allocator, fns: []const SynFn, insts: []const ff.FunctionInstantiation) !void {
        var idents: std.ArrayList([]const u8) = .empty;
        try idents.appendSlice(a, &.{ "M", "S", "a", "b" });
        const fhs = try a.alloc(ff.FunctionHandle, fns.len);
        const fds = try a.alloc(ff.FunctionDefinition, fns.len);
        const both = [_]ff.AbilitySet{ ff.AbilitySet.ALL, ff.AbilitySet.ALL };
        for (fns, fhs, fds, 0..) |f, *fh, *fd, i| {
            try idents.append(a, f.name);
            fh.* = .{ .module = 0, .name = @intCast(idents.items.len - 1), .parameters = f.params, .return_ = f.ret, .type_parameters = both[0..f.tps] };
            fd.* = .{ .function = @intCast(i), .visibility = .Public, .is_entry = false, .acquires = &.{}, .code = .{ .locals = f.locals, .code = f.code, .jump_tables = &.{} } };
        }
        const addrs = [_][32]u8{@splat(7)};
        const mhs = [_]ff.ModuleHandle{.{ .address = 0, .name = 0 }};
        const dhs = [_]ff.DatatypeHandle{.{ .module = 0, .name = 1, .abilities = ff.AbilitySet.ALL, .type_parameters = &.{} }};
        const fields = [_]ff.FieldDefinition{ .{ .name = 2, .signature = &n_u64 }, .{ .name = 3, .signature = &n_vec_u8 } };
        const sds = [_]ff.StructDefinition{.{ .struct_handle = 0, .native = false, .fields = &fields }};
        const fhd = [_]ff.FieldHandle{ .{ .owner = 0, .field = 0 }, .{ .owner = 0, .field = 1 } };
        var wide = [_][32]u8{@splat(0)};
        wide[0][0] = 5;
        wide[0][9] = 1;
        const cm: ff.CompiledModule = .{
            .version = 6,
            .module_handles = &mhs,
            .datatype_handles = &dhs,
            .function_handles = fhs,
            .field_handles = &fhd,
            .function_instantiations = insts,
            .signatures = &syn_sigs,
            .identifiers = idents.items,
            .address_identifiers = &addrs,
            .struct_defs = &sds,
            .function_defs = fds,
            .wide = &wide,
        };
        const bytes = try move_format.serializeAlloc(a, &cm, 6);
        s.rt = loader.Runtime.init(gpa, try conf.binaryConfig(protocol.max_protocol_version));
        errdefer s.rt.deinit();
        s.rt.jit_limits = false;
        s.id = @splat(7);
        const mods = [_]loader.NamedModule{.{ .name = "M", .bytes = bytes }};
        const link = [_][2]loader.Address{.{ s.id, s.id }};
        const p = try s.rt.addPackage(.{ .version_id = s.id, .original_id = s.id, .version = 1, .linkage = &link, .type_origins = &.{}, .modules = &mods });
        if (p.refused != null) return error.Refused;
    }

    fn call(s: *const Syn, func: []const u8, tys: []const []const u8, args: []const A, gm: u64) Call {
        return .{
            .id = 0,
            .pv = protocol.max_protocol_version,
            .gm = gm,
            .root = s.id,
            .module_addr = s.id,
            .module_name = "M",
            .func = func,
            .tys = tys,
            .args = args,
            .budget = 2_000_000,
            .truth = .null,
        };
    }
};

fn mk(op: ff.Opcode, idx: u16, imm: u64) ff.Instr {
    return .{ .op = op, .idx = idx, .imm = imm };
}
fn op0(op: ff.Opcode) ff.Instr {
    return .{ .op = op };
}
fn ix(op: ff.Opcode, idx: u16) ff.Instr {
    return .{ .op = op, .idx = idx };
}
fn ld(x: u64) ff.Instr {
    return .{ .op = .LdU64, .imm = x };
}

const SynCase = struct { func: []const u8, tys: []const []const u8 = &.{}, args: []const A = &.{} };

/// Loads the module, runs every case through the differential plan and returns the reference
/// outcome of each case at its own budget (status code; 0 when it succeeded).
fn runSyn(fns: []const SynFn, insts: []const ff.FunctionInstantiation, cases: []const SynCase, plan: Plan, outcomes: []u64, min_undone: u64) !void {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var syn: Syn = undefined;
    try syn.init(gpa, a, fns, insts);
    defer syn.rt.deinit();
    const gm = try (try protocol.get(protocol.max_protocol_version, .mainnet)).get("gas_model_version");
    var cache = interp.LinkCache.init(gpa);
    defer cache.deinit();
    var tally: Tally = .{};
    for (cases, 0..) |cs, i| {
        const c = syn.call(cs.func, cs.tys, cs.args, gm);
        const s0 = try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .ref });
        try std.testing.expect(s0.fail == null);
        if (i < outcomes.len) outcomes[i] = if (s0.ok) 0 else @intFromEnum(s0.err.major);
        try expectAgree(try diffCall(gpa, &syn.rt, &cache, &c, plan, &tally, i), "M", cs.func);
    }
    // block gas ran in these programs: blocks charged at once, and undone inside where the
    // test says so (type-confused operands, arithmetic errors)
    if (tally.blocks_charged < 100 or tally.blocks_undone < min_undone or tally.block_fault_runs * 10 < min_undone) {
        std.debug.print("\nblock gas over the synthetic cases: {any}\n", .{tally});
        return error.BlockGasNotExercised;
    }
}

const syn_plan: Plan = .{ .exhaustive_cap = 1200, .samples = 30, .edge = 30, .traced_every = 0, .traced = false, .presets = 6, .gms = &.{ 14, 11, 10, 9, 1 }, .gm_samples = 3 };

fn status(c: move_format.StatusCode) u64 {
    return @intFromEnum(c);
}

test "stepRun equals the reference: locals, references, structs, vectors, casts, comparisons" {
    const fns = [_]SynFn{
        // 0: locals of every kind stored over each other, copied and popped
        .{ .name = "locals", .ret = SIG_U64, .locals = SIG_LOCALS4, .code = &.{
            ld(7),                   ix(.StLoc, 0),           ix(.ImmBorrowLoc, 0),    ix(.StLoc, 3), // local 3 holds a reference
            ix(.CopyLoc, 3),         ix(.CopyLoc, 3),         op0(.Pop),                op0(.ReadRef),
            ix(.StLoc, 0),           ld(1),                   ix(.StLoc, 3), // store over a reference
            mk(.LdU8, 0, 1),         mk(.LdU8, 0, 2),         mk(.VecPack, SIG_U8, 2), ix(.StLoc, 1),
            ix(.CopyLoc, 1),         ix(.StLoc, 1), // store over a vector (the old one is dropped)
            ix(.CopyLoc, 1),         op0(.Pop), // pop of a container
            ld(3),                   ix(.MoveLoc, 1),         ix(.Pack, 0),            ix(.StLoc, 2),
            ix(.CopyLoc, 2),         ix(.StLoc, 2), // store over a struct
            ix(.MutBorrowLoc, 2),    ix(.MutBorrowField, 0),  op0(.ReadRef),            ix(.MoveLoc, 0),
            op0(.Add),                ix(.MoveLoc, 2),         ix(.Unpack, 0),          op0(.Pop),
            op0(.Add),                op0(.Ret),
        } },
        // 1: field borrows, ReadRef and WriteRef through slots and through vector elements
        .{ .name = "refs", .ret = SIG_U64, .locals = SIG_LOCALS4, .code = &.{
            ld(5),                       mk(.LdU8, 0, 9),             mk(.VecPack, SIG_U8, 1),     ix(.Pack, 0),
            ix(.StLoc, 2),               ld(11),                      ix(.MutBorrowLoc, 2),        ix(.MutBorrowField, 0),
            op0(.WriteRef),               mk(.LdU8, 0, 200),           ix(.MutBorrowLoc, 2),        ix(.MutBorrowField, 1),
            ld(0),                       ix(.VecMutBorrow, SIG_U8),   op0(.WriteRef), // write through an element reference
            ix(.ImmBorrowLoc, 2),        ix(.ImmBorrowField, 1),      ld(0),                       ix(.VecImmBorrow, SIG_U8),
            op0(.ReadRef),                op0(.CastU64),                ix(.ImmBorrowLoc, 2),        ix(.ImmBorrowField, 0),
            op0(.ReadRef),                op0(.Add),                    ix(.ImmBorrowLoc, 2),        op0(.ReadRef), // read a whole struct
            ix(.Unpack, 0),              op0(.Pop),                    op0(.Pop),                    op0(.Nop),
            ix(.ImmBorrowLoc, 2),        op0(.FreezeRef),              ix(.ImmBorrowField, 1),      op0(.ReadRef), // read a vector
            ix(.StLoc, 1),               ix(.MutBorrowLoc, 1),        ix(.VecPopBack, SIG_U8),     op0(.CastU64),
            op0(.Add),                    mk(.LdU8, 0, 4),             mk(.VecPack, SIG_U8, 1),     ix(.MutBorrowLoc, 1),
            op0(.WriteRef), // write a vector over a vector
            ix(.MoveLoc, 2),             ix(.MutBorrowLoc, 2),        op0(.Pop),                    ix(.Unpack, 0),
            op0(.Pop),                    op0(.Add),                    op0(.Ret),
        } },
        // 2: vector<u64>: pack, push, swap, borrow, pop to empty, then one pop too many
        .{ .name = "vecs", .params = SIG_U64, .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{
            ld(1),                       ld(2),                       ld(3),                       mk(.VecPack, SIG_U64, 3),
            ix(.StLoc, 1),               ix(.MutBorrowLoc, 1),        ld(4),                       ix(.VecPushBack, SIG_U64),
            ix(.MutBorrowLoc, 1),        ld(0),                       ld(3),                       ix(.VecSwap, SIG_U64),
            ix(.MutBorrowLoc, 1),        ld(2),                       ld(2),                       ix(.VecSwap, SIG_U64),
            ix(.ImmBorrowLoc, 1),        ix(.VecLen, SIG_U64),        ix(.ImmBorrowLoc, 1),        ix(.CopyLoc, 0),
            ld(7),                       op0(.BitAnd),                 ix(.VecImmBorrow, SIG_U64),  op0(.ReadRef),
            op0(.Add),                    ix(.StLoc, 2),
            ix(.MutBorrowLoc, 1),        ix(.VecPopBack, SIG_U64),    op0(.Pop),                    ix(.MutBorrowLoc, 1),
            ix(.VecPopBack, SIG_U64),    op0(.Pop),                    ix(.MutBorrowLoc, 1),        ix(.VecPopBack, SIG_U64),
            op0(.Pop),                    ix(.MutBorrowLoc, 1),        ix(.VecPopBack, SIG_U64),    op0(.Pop),
            ix(.CopyLoc, 0),             ld(9),                       op0(.Eq),                     mk(.BrFalse, 46, 0),
            ix(.MutBorrowLoc, 1),        ix(.VecPopBack, SIG_U64),    op0(.Pop),                    op0(.Nop),
            ix(.MoveLoc, 1),             mk(.VecUnpack, SIG_U64, 0),  ix(.MoveLoc, 2),             op0(.Ret),
        } },
        // 3: vector<S> and vector<vector<u8>>: element references are slots, swap moves values
        .{ .name = "vec_structs", .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{
            ld(1),                           mk(.VecPack, SIG_U8, 0),         ix(.Pack, 0),                    ld(2),
            mk(.LdU8, 0, 5),                 mk(.VecPack, SIG_U8, 1),         ix(.Pack, 0),                    mk(.VecPack, SIG_S, 2),
            ix(.StLoc, 0),                   ix(.MutBorrowLoc, 0),            ld(0),                           ld(1),
            ix(.VecSwap, SIG_S),             ix(.MutBorrowLoc, 0),            ld(0),                           ix(.VecMutBorrow, SIG_S),
            ix(.MutBorrowField, 1),          mk(.LdU8, 0, 6),                 ix(.VecPushBack, SIG_U8),        ix(.ImmBorrowLoc, 0),
            ld(0),                           ix(.VecImmBorrow, SIG_S),        ix(.ImmBorrowField, 1),          ix(.VecLen, SIG_U8),
            ix(.MutBorrowLoc, 0),            ix(.VecPopBack, SIG_S),          ix(.Unpack, 0),                  op0(.Pop),
            op0(.Add),                        ix(.ImmBorrowLoc, 0),            ix(.ImmBorrowLoc, 0),            op0(.Eq),
            op0(.Pop),                        ix(.CopyLoc, 0),                 ix(.CopyLoc, 0),                 op0(.Neq),
            op0(.Pop),                        mk(.VecPack, SIG_VEC_U8, 0),     ix(.StLoc, 1),                   ix(.MutBorrowLoc, 1),
            mk(.LdU8, 0, 1),                 mk(.VecPack, SIG_U8, 1),         ix(.VecPushBack, SIG_VEC_U8),    ix(.ImmBorrowLoc, 1),
            ld(0),                           ix(.VecImmBorrow, SIG_VEC_U8),   ix(.VecLen, SIG_U8),             op0(.Add),
            op0(.Ret),
        } },
        // 4: casts in every direction, shifts, boolean and comparison operators on every width
        .{ .name = "casts", .params = SIG_U64, .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{
            ix(.CopyLoc, 0),         op0(.CastU8),             op0(.CastU16),            op0(.CastU32),
            op0(.CastU64),            op0(.CastU128),           op0(.CastU256),           op0(.CastU128),
            op0(.CastU64),            op0(.CastU32),            op0(.CastU16),            op0(.CastU8),
            mk(.LdU8, 0, 3),         op0(.Shl),                mk(.LdU8, 0, 1),         op0(.Shr),
            op0(.CastU64),            ix(.CopyLoc, 0),         op0(.Eq),                 ix(.CopyLoc, 0),
            ld(200),                 op0(.Neq),                op0(.Or),                 op0(.LdTrue),
            op0(.And),                op0(.Not),                op0(.Pop),                mk(.LdU128, 0, 0),
            mk(.LdU128, 0, 0),       op0(.Eq),                 op0(.Pop),                mk(.LdU256, 0, 0),
            mk(.LdU256, 0, 0),       op0(.Neq),                op0(.Pop),                mk(.LdU16, 0, 200),
            op0(.CastU8),             op0(.Pop),                ix(.CopyLoc, 0),         op0(.Ret),
        } },
        // 5: type-confused operands: every inline handler must hand them to the full path
        .{ .name = "confused", .params = SIG_U64, .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{
            ix(.CopyLoc, 0),             mk(.BrTrue, 0, 0), // u64 where a bool is expected
        } },
        .{ .name = "confused_readref", .ret = SIG_U64, .code = &.{ ld(1), op0(.ReadRef), op0(.Ret) } },
        .{ .name = "confused_field", .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{ ld(1), ix(.StLoc, 0), ix(.ImmBorrowLoc, 0), ix(.ImmBorrowField, 0), op0(.ReadRef), op0(.Ret) } },
        .{ .name = "confused_veclen", .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{ ld(1), ix(.StLoc, 0), ix(.ImmBorrowLoc, 0), ix(.VecLen, SIG_U64), op0(.Ret) } },
        .{ .name = "confused_eq", .ret = SIG_U64, .code = &.{ ld(1), mk(.LdU8, 0, 1), op0(.Eq), op0(.Pop), ld(1), op0(.LdTrue), op0(.Neq), op0(.Pop), ld(0), op0(.Ret) } },
        .{ .name = "confused_cast", .ret = SIG_U64, .code = &.{ op0(.LdTrue), op0(.CastU64), op0(.Ret) } },
        .{ .name = "confused_writeref", .ret = SIG_U64, .code = &.{ ld(1), ld(2), op0(.WriteRef), ld(0), op0(.Ret) } },
        .{ .name = "empty_stack_ops", .params = SIG_U64, .ret = SIG_U64, .code = &.{
            // one instruction on an empty stack, picked by the argument
            ix(.CopyLoc, 0), ld(0),                    op0(.Eq), mk(.BrFalse, 6, 0), op0(.ReadRef),              op0(.Ret),
            ix(.CopyLoc, 0), ld(1),                    op0(.Eq), mk(.BrFalse, 12, 0), ix(.VecLen, SIG_U64),      op0(.Ret),
            ix(.CopyLoc, 0), ld(2),                    op0(.Eq), mk(.BrFalse, 18, 0), op0(.CastU8),               op0(.Ret),
            ix(.CopyLoc, 0), ld(3),                    op0(.Eq), mk(.BrFalse, 24, 0), ix(.ImmBorrowField, 0),    op0(.Ret),
            ix(.CopyLoc, 0), ld(4),                    op0(.Eq), mk(.BrFalse, 30, 0), op0(.WriteRef),             op0(.Ret),
            ix(.CopyLoc, 0), ld(5),                    op0(.Eq), mk(.BrFalse, 36, 0), ix(.VecPopBack, SIG_U64),  op0(.Ret),
            ix(.CopyLoc, 0), ld(6),                    op0(.Eq), mk(.BrFalse, 42, 0), ix(.VecSwap, SIG_U64),     op0(.Ret),
            ix(.CopyLoc, 0), ld(7),                    op0(.Eq), mk(.BrFalse, 48, 0), op0(.Eq),                   op0(.Ret),
            ix(.CopyLoc, 0), ld(8),                    op0(.Eq), mk(.BrFalse, 54, 0), ix(.VecImmBorrow, SIG_U64), op0(.Ret),
            ix(.CopyLoc, 0), ld(9),                    op0(.Eq), mk(.BrFalse, 60, 0), ix(.VecPushBack, SIG_U64), op0(.Ret),
            ld(0),           op0(.Abort),
        } },
        // operand stack limit through the pushing handlers
        .{ .name = "overflow_ref", .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{ ld(1), ix(.StLoc, 0), ix(.ImmBorrowLoc, 0), ix(.StLoc, 1), ix(.CopyLoc, 1), mk(.Branch, 4, 0) } },
        .{ .name = "overflow_borrow", .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{ ld(1), ix(.StLoc, 0), ix(.MutBorrowLoc, 0), mk(.Branch, 2, 0) } },
        // a function that runs off its end, and a vector index out of range
        .{ .name = "off_end", .ret = SIG_U64, .code = &.{ ld(1), op0(.Pop) } },
        .{ .name = "oob", .params = SIG_U64, .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{
            ld(1),                       mk(.VecPack, SIG_U64, 1),    ix(.StLoc, 1),               ix(.ImmBorrowLoc, 1),
            ix(.CopyLoc, 0),             ix(.VecImmBorrow, SIG_U64),  op0(.ReadRef),                op0(.Ret),
        } },
        .{ .name = "swap_oob", .params = SIG_U64, .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{
            ld(1),                       ld(2),                       mk(.VecPack, SIG_U64, 2),    ix(.StLoc, 1),
            ix(.MutBorrowLoc, 1),        ld(1),                       ix(.CopyLoc, 0),             ix(.VecSwap, SIG_U64),
            ld(0),                       op0(.Ret),
        } },
    };
    var args_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer args_arena.deinit();
    const ba: B = .{ .a = args_arena.allocator() };
    var cases: std.ArrayList(SynCase) = .empty;
    defer cases.deinit(std.testing.allocator);
    const one = try ba.int(u64, 1);
    try cases.appendSlice(std.testing.allocator, &.{
        .{ .func = "locals" },
        .{ .func = "refs" },
        .{ .func = "vecs", .args = try ba.args(&.{val(one)}) },
        .{ .func = "vecs", .args = try ba.args(&.{val(try ba.int(u64, 9))}) }, // pops the empty vector
        .{ .func = "vecs", .args = try ba.args(&.{val(try ba.int(u64, 4))}) }, // index out of range
        .{ .func = "vec_structs" },
        .{ .func = "casts", .args = try ba.args(&.{val(try ba.int(u64, 20))}) },
        .{ .func = "casts", .args = try ba.args(&.{val(try ba.int(u64, 300))}) }, // CastU8 overflows
        .{ .func = "casts", .args = try ba.args(&.{val(try ba.int(u64, 100))}) }, // Shl result needs the mask
        .{ .func = "confused", .args = try ba.args(&.{val(one)}) },
        .{ .func = "confused_readref" },
        .{ .func = "confused_field" },
        .{ .func = "confused_veclen" },
        .{ .func = "confused_eq" },
        .{ .func = "confused_cast" },
        .{ .func = "confused_writeref" },
        .{ .func = "overflow_ref" },
        .{ .func = "overflow_borrow" },
        .{ .func = "off_end" },
        .{ .func = "oob", .args = try ba.args(&.{val(try ba.int(u64, 0))}) },
        .{ .func = "oob", .args = try ba.args(&.{val(one)}) },
        .{ .func = "swap_oob", .args = try ba.args(&.{val(one)}) },
        .{ .func = "swap_oob", .args = try ba.args(&.{val(try ba.int(u64, 2))}) },
    });
    var k: u64 = 0;
    while (k <= 10) : (k += 1) try cases.append(std.testing.allocator, .{ .func = "empty_stack_ops", .args = try ba.args(&.{val(try ba.int(u64, k))}) });
    var out: [23]u64 = undefined;
    try runSyn(&fns, &.{}, cases.items, syn_plan, &out, 100);
    // The programs do what their comments say (so the comparisons above covered those paths).
    try std.testing.expectEqual(@as(u64, 0), out[0]);
    try std.testing.expectEqual(@as(u64, 0), out[1]);
    try std.testing.expectEqual(@as(u64, 0), out[2]);
    try std.testing.expectEqual(status(.VECTOR_OPERATION_ERROR), out[3]);
    try std.testing.expectEqual(status(.VECTOR_OPERATION_ERROR), out[4]);
    try std.testing.expectEqual(@as(u64, 0), out[5]);
    try std.testing.expectEqual(@as(u64, 0), out[6]);
    try std.testing.expectEqual(status(.ARITHMETIC_ERROR), out[7]);
    try std.testing.expectEqual(@as(u64, 0), out[8]);
    try std.testing.expectEqual(status(.INTERNAL_TYPE_ERROR), out[10]);
    try std.testing.expectEqual(status(.EXECUTION_STACK_OVERFLOW), out[16]);
    try std.testing.expectEqual(status(.EXECUTION_STACK_OVERFLOW), out[17]);
    try std.testing.expectEqual(status(.PC_OVERFLOW), out[18]);
    try std.testing.expectEqual(@as(u64, 0), out[19]);
    try std.testing.expectEqual(status(.VECTOR_OPERATION_ERROR), out[20]);
    try std.testing.expectEqual(@as(u64, 0), out[21]);
    try std.testing.expectEqual(status(.VECTOR_OPERATION_ERROR), out[22]);
}

/// `k` Nops, then 1 / 0 and four more instructions: one block of `k + 6` instructions (the Ret
/// is not part of it) whose instruction `k + 2` fails.
fn faultCode(comptime k: usize) []const ff.Instr {
    const code = comptime blk: {
        var c: [k + 7]ff.Instr = undefined;
        for (0..k) |i| c[i] = op0(.Nop);
        c[k] = ld(1);
        c[k + 1] = ld(0);
        c[k + 2] = op0(.Div);
        c[k + 3] = ld(2);
        c[k + 4] = op0(.Pop);
        c[k + 5] = ld(9);
        c[k + 6] = op0(.Ret);
        break :blk c;
    };
    return &code;
}

test "block gas equals the reference: a fault at every position of a charged block, every budget that ends inside one" {
    const K = 12;
    const fns = comptime blk: {
        var f: [K + 3]SynFn = undefined;
        for (0..K) |k| f[k] = .{ .name = std.fmt.comptimePrint("fault_{d}", .{k}), .ret = SIG_U64, .code = faultCode(k) };
        // the first instruction of a charged block fails (a u256 where Not wants a bool;
        // LdU256 is charged on its own, so the block starts at the Not)
        f[K] = .{ .name = "fault_first", .ret = SIG_U64, .code = &.{ mk(.LdU256, 0, 0), op0(.Not), ld(1), op0(.Pop), ld(0), op0(.Ret) } };
        // a block the meter refuses whatever the budget: it pops below an empty stack
        f[K + 1] = .{ .name = "low_stack", .ret = SIG_U64, .code = &.{ op0(.Nop), op0(.Nop), op0(.Pop), ld(1), op0(.Ret) } };
        // a block that runs through
        f[K + 2] = .{ .name = "straight", .ret = SIG_U64, .code = &.{ ld(6), ld(7), op0(.Mul), ld(2), op0(.Sub), mk(.LdU8, 0, 3), op0(.Shl), ld(5), op0(.Lt), op0(.Not), op0(.Pop), ld(4), op0(.Ret) } };
        break :blk f;
    };
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var syn: Syn = undefined;
    try syn.init(gpa, a, &fns, &.{});
    defer syn.rt.deinit();
    const gm = try (try protocol.get(protocol.max_protocol_version, .mainnet)).get("gas_model_version");
    var cache = interp.LinkCache.init(gpa);
    defer cache.deinit();
    var tally: Tally = .{};
    for (fns, 0..) |f, i| {
        const c = syn.call(f.name, &.{}, &.{}, gm);
        // at the call's own budget, with block gas on: what the block did
        const b = try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .block });
        try std.testing.expect(b.fail == null);
        if (i < K) {
            // charged at once, given back at the failing instruction, which then failed there
            try std.testing.expect(!b.ok and b.err.major == .ARITHMETIC_ERROR);
            try std.testing.expectEqual(@as(u16, @intCast(i + 2)), b.err.off.?.pc);
            try std.testing.expectEqual(interp.Blocks.Pos.inside, b.stop);
            try std.testing.expectEqual([4]u64{ 1, 0, 1, 1 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
            // the meter is at the instructions before the failing one plus that one's own
            // charge: i Nops, two loads and the Div
            try std.testing.expectEqual(@as(u64, i + 3), b.meter.instructions_executed);
        } else if (i == K) {
            try std.testing.expect(!b.ok and b.err.major == .INTERNAL_TYPE_ERROR);
            try std.testing.expectEqual(@as(u16, 1), b.err.off.?.pc);
            try std.testing.expectEqual(interp.Blocks.Pos.first, b.stop);
            try std.testing.expectEqual([4]u64{ 1, 0, 1, 1 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
        } else if (i == K + 1) {
            try std.testing.expect(!b.ok and b.err.major == .EMPTY_VALUE_STACK);
            try std.testing.expectEqual([4]u64{ 0, 1, 0, 0 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
        } else {
            try std.testing.expect(b.ok);
            try std.testing.expectEqual([4]u64{ 1, 0, 0, 0 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
        }
        // and the same as the reference at every budget: each budget below the call's use
        // stops at another instruction of the block
        try expectAgree(try diffCall(gpa, &syn.rt, &cache, &c, syn_plan, &tally, i), "M", f.name);
    }
    try std.testing.expectEqual(@as(u64, fns.len), tally.exhaustive_calls);
    // fault_k has k + 2 instructions after its first that a budget can end on
    if (tally.block_oog_inside < 12 * 2 + 66 or tally.block_oog_first < fns.len or tally.block_fault_runs < 4 * (K + 1) or tally.blocks_refused < 150) {
        std.debug.print("\nblock gas over the fault cases: {any}\n", .{tally});
        return error.BlockGasNotExercised;
    }
}

/// The TypeTag of `vector<vector<..<u8>>>`, `depth` vectors deep (`depth + 1` type nodes).
fn nestedVecTag(a: Allocator, depth: usize) ![]const u8 {
    const t = try a.alloc(u8, depth + 1);
    @memset(t[0..depth], 6);
    t[depth] = 1;
    return t;
}

test "stepRun equals the reference: calls, returns, call depth, generic calls" {
    // function handles: 0 rec, 1 forever, 2 pass, 3 grow, 4 swap, 5 concrete, 6 leaf, 7 args,
    // 8 calls_leaf
    const insts = [_]ff.FunctionInstantiation{
        .{ .handle = 2, .type_parameters = SIG_T0 }, // 0: pass<T0>
        .{ .handle = 3, .type_parameters = SIG_VEC_T0 }, // 1: grow<vector<T0>>
        .{ .handle = 4, .type_parameters = SIG_T1_T0 }, // 2: swap<T1, T0>
        .{ .handle = 2, .type_parameters = SIG_U64 }, // 3: pass<u64>
        .{ .handle = 4, .type_parameters = SIG_T0_T1 }, // 4: swap<T0, T1> (in order)
        .{ .handle = 2, .type_parameters = SIG_VEC_U64 }, // 5: pass<vector<u64>>
    };
    const fns = [_]SynFn{
        // rec(n): n more frames below this one
        .{ .name = "rec", .params = SIG_U64, .ret = SIG_U64, .code = &.{
            ix(.CopyLoc, 0), ld(0), op0(.Eq), mk(.BrFalse, 6, 0), ld(42), op0(.Ret),
            ix(.MoveLoc, 0), ld(1), op0(.Sub), ix(.Call, 0),      ld(1),  op0(.Add),
            op0(.Ret),
        } },
        .{ .name = "forever", .code = &.{ ix(.Call, 1), op0(.Ret) } },
        // pass<T>(n): calls itself with its own type argument
        .{ .name = "pass", .params = SIG_U64, .ret = SIG_U64, .tps = 1, .code = &.{
            ix(.CopyLoc, 0), ld(0),            op0(.Eq), mk(.BrFalse, 6, 0), ld(7), op0(.Ret),
            ix(.MoveLoc, 0), ld(1),            op0(.Sub), ix(.CallGeneric, 0), op0(.Ret),
        } },
        // grow<T>(n): calls grow<vector<T>>: one more type node per frame, until the limit
        .{ .name = "grow", .params = SIG_U64, .ret = SIG_U64, .tps = 1, .code = &.{
            ix(.CopyLoc, 0), ld(0),            op0(.Eq), mk(.BrFalse, 6, 0), ld(7), op0(.Ret),
            ix(.MoveLoc, 0), ld(1),            op0(.Sub), ix(.CallGeneric, 1), op0(.Ret),
        } },
        // swap<A, B>(n): calls swap<B, A>, then swap<A, B>
        .{ .name = "swap", .params = SIG_U64, .ret = SIG_U64, .tps = 2, .code = &.{
            ix(.CopyLoc, 0), ld(0),            op0(.Eq), mk(.BrFalse, 6, 0), ld(7),            op0(.Ret),
            ix(.CopyLoc, 0), ld(1),            op0(.Sub), ix(.CallGeneric, 2), op0(.Pop),       ix(.MoveLoc, 0),
            ld(1),           op0(.Sub),         ix(.CallGeneric, 4), op0(.Ret),
        } },
        // concrete(n): call sites whose type arguments are fixed, in a loop
        .{ .name = "concrete", .params = SIG_U64, .ret = SIG_U64, .code = &.{
            ix(.CopyLoc, 0), ld(0),            op0(.Eq), mk(.BrTrue, 15, 0), ld(2), ix(.CallGeneric, 3),
            op0(.Pop),        ld(1),            ix(.CallGeneric, 5), op0(.Pop), ix(.MoveLoc, 0), ld(1),
            op0(.Sub),        ix(.StLoc, 0),    mk(.Branch, 0, 0), ld(3),     op0(.Ret),
        } },
        // leaf(a, b) -> (b, a): locals that own memory are dropped at Ret
        .{ .name = "leaf", .params = SIG_U64_U64, .ret = SIG_U64_U64, .locals = SIG_LOCALS4, .code = &.{
            mk(.LdU8, 0, 1),  mk(.VecPack, SIG_U8, 1), ix(.StLoc, 3),   ld(1),             mk(.VecPack, SIG_U8, 0), ix(.Pack, 0),
            ix(.StLoc, 4),    mk(.LdU256, 0, 0),       ix(.StLoc, 5),   ix(.MoveLoc, 1),   ix(.MoveLoc, 0),         op0(.Ret),
        } },
        // args(n): a call with too few values on the stack when n == 0
        .{ .name = "args", .params = SIG_U64, .ret = SIG_U64, .code = &.{
            ix(.CopyLoc, 0), ld(0), op0(.Eq), mk(.BrFalse, 6, 0), ld(1),        ix(.Call, 6),
            ld(1),           ld(2), ix(.Call, 6), op0(.Add),      op0(.Ret),
        } },
        // calls_leaf(n): n calls in a loop, the returned values popped
        .{ .name = "calls_leaf", .params = SIG_U64, .ret = SIG_U64, .code = &.{
            ix(.CopyLoc, 0), ld(0),             op0(.Eq),  mk(.BrTrue, 14, 0), ld(5), ix(.CopyLoc, 0),
            ix(.Call, 6),    op0(.Pop),          op0(.Pop), ix(.MoveLoc, 0),    ld(1), op0(.Sub),
            ix(.StLoc, 0),   mk(.Branch, 0, 0), ld(9),    op0(.Ret),
        } },
    };
    var args_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer args_arena.deinit();
    const a = args_arena.allocator();
    const ba: B = .{ .a = a };
    var cases: std.ArrayList(SynCase) = .empty;
    defer cases.deinit(std.testing.allocator);
    // call depth: 1024 frames below the first is the limit
    for ([_]u64{ 0, 1, 5, 1022, 1023, 1024, 1025 }) |n| try cases.append(std.testing.allocator, .{ .func = "rec", .args = try ba.args(&.{val(try ba.int(u64, n))}) });
    try cases.append(std.testing.allocator, .{ .func = "forever" });
    // pass-through generic calls with type arguments of 1, 63, 64, 65, 127 and 128 nodes
    for ([_]usize{ 0, 62, 63, 64, 126, 127 }) |depth| {
        const tag = try nestedVecTag(a, depth);
        const tys = try a.dupe([]const u8, &.{tag});
        try cases.append(std.testing.allocator, .{ .func = "pass", .tys = tys, .args = try ba.args(&.{val(try ba.int(u64, 3))}) });
    }
    try cases.append(std.testing.allocator, .{ .func = "pass", .tys = &.{&ty_u64}, .args = try ba.args(&.{val(try ba.int(u64, 1030))}) });
    try cases.append(std.testing.allocator, .{ .func = "grow", .tys = &.{&ty_u8}, .args = try ba.args(&.{val(try ba.int(u64, 5))}) });
    try cases.append(std.testing.allocator, .{ .func = "grow", .tys = &.{&ty_u8}, .args = try ba.args(&.{val(try ba.int(u64, 200))}) });
    try cases.append(std.testing.allocator, .{ .func = "swap", .tys = &.{ &ty_u8, &ty_vec_u8 }, .args = try ba.args(&.{val(try ba.int(u64, 6))}) });
    {
        const t62 = try nestedVecTag(a, 61);
        const tys = try a.dupe([]const u8, &.{ t62, &ty_u8 });
        try cases.append(std.testing.allocator, .{ .func = "swap", .tys = tys, .args = try ba.args(&.{val(try ba.int(u64, 3))}) });
        const tys2 = try a.dupe([]const u8, &.{ t62, &ty_vec_u8 });
        try cases.append(std.testing.allocator, .{ .func = "swap", .tys = tys2, .args = try ba.args(&.{val(try ba.int(u64, 3))}) });
    }
    try cases.append(std.testing.allocator, .{ .func = "concrete", .args = try ba.args(&.{val(try ba.int(u64, 4))}) });
    try cases.append(std.testing.allocator, .{ .func = "leaf", .args = try ba.args(&.{ val(try ba.int(u64, 1)), val(try ba.int(u64, 2)) }) });
    try cases.append(std.testing.allocator, .{ .func = "args", .args = try ba.args(&.{val(try ba.int(u64, 0))}) });
    try cases.append(std.testing.allocator, .{ .func = "args", .args = try ba.args(&.{val(try ba.int(u64, 1))}) });
    try cases.append(std.testing.allocator, .{ .func = "calls_leaf", .args = try ba.args(&.{val(try ba.int(u64, 6))}) });
    var out: [26]u64 = undefined;
    try runSyn(&fns, &insts, cases.items, syn_plan, &out, 0);
    try std.testing.expectEqual(@as(u64, 0), out[0]);
    try std.testing.expectEqual(@as(u64, 0), out[4]); // 1023 more frames
    try std.testing.expectEqual(@as(u64, 0), out[5]); // 1024 more frames: the last one allowed
    try std.testing.expectEqual(status(.CALL_STACK_OVERFLOW), out[6]);
    try std.testing.expectEqual(status(.CALL_STACK_OVERFLOW), out[7]);
    try std.testing.expectEqual(@as(u64, 0), out[8]); // pass<u8>
    try std.testing.expectEqual(@as(u64, 0), out[9]); // 63 nodes: 1 + 2 * 63 fits
    try std.testing.expectEqual(status(.VM_MAX_TYPE_NODES_REACHED), out[10]); // 64 nodes
    try std.testing.expectEqual(status(.CALL_STACK_OVERFLOW), out[14]);
    try std.testing.expectEqual(@as(u64, 0), out[15]);
    try std.testing.expectEqual(status(.VM_MAX_TYPE_NODES_REACHED), out[16]);
    try std.testing.expectEqual(@as(u64, 0), out[17]);
    try std.testing.expectEqual(@as(u64, 0), out[20]);
    try std.testing.expectEqual(@as(u64, 0), out[21]);
    try std.testing.expectEqual(status(.EMPTY_VALUE_STACK), out[22]);
    try std.testing.expectEqual(@as(u64, 0), out[23]);
    try std.testing.expectEqual(@as(u64, 0), out[24]);
}

/// Instruction `BAD_AT` is `op` on local 0 (the test puts a local index past the frame's locals
/// there once the module is loaded). The four instructions before it are static, so with block
/// gas on it sits inside a block that was charged at once (a CopyLoc of a local that does not
/// exist has no static charge: the block ends before it).
const BAD_AT = 4;
fn badLocalCode(comptime op: ff.Opcode) []const ff.Instr {
    const code = comptime [_]ff.Instr{ ld(1), ix(.StLoc, 0), ld(2), ld(3), ix(op, 0), ld(4), op0(.Pop), ld(0), op0(.Ret) };
    return &code;
}

test "a local index past the frame's locals: stepRun leaves it to op, and every loop reports op's error" {
    // The bounds checker refuses such an index and the loader makes modules no other way, so
    // the loaded code is changed by hand: this is the frame builder that does not exist yet.
    const ops = [_]ff.Opcode{ .CopyLoc, .MoveLoc, .StLoc, .ImmBorrowLoc, .MutBorrowLoc };
    const N_LOCALS = 6; // SIG_LOCALS_MIX
    // the first index outside, the next one, the largest one
    const bads = [_]u16{ N_LOCALS, N_LOCALS + 1, 0xffff };
    const fns = comptime blk: {
        var f: [ops.len * bads.len + 1]SynFn = undefined;
        for (ops, 0..) |o, i| for (0..bads.len) |j| {
            f[i * bads.len + j] = .{ .name = std.fmt.comptimePrint("{s}_{d}", .{ @tagName(o), j }), .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = badLocalCode(o) };
        };
        // StLoc on an empty stack: the missing operand is reported first, as `op` has it
        f[ops.len * bads.len] = .{ .name = "st_empty", .ret = SIG_U64, .locals = SIG_LOCALS_MIX, .code = &.{ op0(.Nop), op0(.Nop), op0(.Nop), op0(.Nop), ix(.StLoc, 0), ld(0), op0(.Ret) } };
        break :blk f;
    };
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var syn: Syn = undefined;
    try syn.init(gpa, a, &fns, &.{});
    defer syn.rt.deinit();
    const gm = try (try protocol.get(protocol.max_protocol_version, .mainnet)).get("gas_model_version");
    var cache = interp.LinkCache.init(gpa);
    defer cache.deinit();
    const link = &(try cache.get(&syn.rt, syn.rt.package(&syn.id).?)).link;
    for (fns, 0..) |f, i| {
        const func = try link.function(&syn.id, "M", f.name);
        try std.testing.expectEqual(@as(u16, N_LOCALS), func.n_locals);
        const code = try a.dupe(ff.Instr, func.code);
        try std.testing.expect(code[BAD_AT].op == f.code[BAD_AT].op and code[BAD_AT].idx == 0);
        code[BAD_AT].idx = if (i < ops.len * bads.len) bads[i % bads.len] else 0xffff;
        func.code = code;
    }
    var tally: Tally = .{};
    for (fns, 0..) |f, i| {
        const c = syn.call(f.name, &.{}, &.{}, gm);
        const opc = f.code[BAD_AT].op;
        const borrow = opc == .ImmBorrowLoc or opc == .MutBorrowLoc;
        const empty = i == ops.len * bads.len;
        // the reference loop: `op`'s error at the instruction, charged as Rust orders it
        // (CopyLoc and MoveLoc read the local before the charge, the others after it)
        const r = try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .ref });
        try std.testing.expect(r.fail == null and !r.ok);
        try std.testing.expectEqual(if (empty) move_format.StatusCode.EMPTY_VALUE_STACK else move_format.StatusCode.INTERNAL_TYPE_ERROR, r.err.major);
        try std.testing.expectEqual(@as(u16, BAD_AT), r.err.off.?.pc);
        try std.testing.expectEqual(@as(u64, if (empty or opc == .CopyLoc or opc == .MoveLoc) BAD_AT else BAD_AT + 1), r.meter.instructions_executed);
        // `stepRun`: the same outcome, meter and state, so its handler read nothing and left
        // the instruction to `op` (no handler raises this status itself)
        const fast = try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .fast });
        try std.testing.expect(same(&r, &fast));
        // with block gas the hand-over shows: the charged block is given back at the instruction
        const b = try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .block });
        try std.testing.expect(same(&r, &b));
        if (empty) {
            // the block pops below an empty stack: the meter refuses it
            try std.testing.expectEqual([4]u64{ 0, 1, 0, 0 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
        } else if (opc == .CopyLoc) {
            try std.testing.expectEqual([4]u64{ 1, 0, 0, 0 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
            try std.testing.expectEqual(interp.Blocks.Pos.outside, b.stop);
        } else {
            try std.testing.expectEqual([4]u64{ 1, 0, 1, 1 }, [4]u64{ b.blocks_charged, b.blocks_refused, b.blocks_undone, b.blocks_faulted });
            try std.testing.expectEqual(interp.Blocks.Pos.inside, b.stop);
        }
        // the v0..v3 rules have their own statuses
        const lr = try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .ref, .legacy = true });
        const want: move_format.StatusCode = if (empty) .EMPTY_VALUE_STACK else if (borrow) .UNKNOWN_INVARIANT_VIOLATION_ERROR else .VERIFIER_INVARIANT_VIOLATION;
        try std.testing.expect(lr.fail == null and !lr.ok);
        try std.testing.expectEqual(want, lr.err.major);
        try std.testing.expect(same(&lr, &(try runOne(a, a, &syn.rt, &cache, &c, .{ .mode = .fast, .legacy = true }))));
        // and the whole plan: every budget, tier placements, unmetered, the other gas models
        try expectAgree(try diffCall(gpa, &syn.rt, &cache, &c, syn_plan, &tally, i), "M", f.name);
    }
    try std.testing.expectEqual(@as(u64, fns.len), tally.exhaustive_calls);
    try std.testing.expect(tally.compared > 1000 and tally.blocks_undone >= 12);
}
