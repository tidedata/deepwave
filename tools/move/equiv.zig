//! Equivalence checking of an optimized module against the original:
//!   1. the Move and Sui verifiers accept the optimized module;
//!   2. the public interface is unchanged (same function signatures, visibility and entry flags,
//!      same datatypes and fields), so every caller and every stored object keeps working;
//!   3. differential execution: the newest recorded mainnet calls of the module are replayed twice
//!      on deepwave's simulation engine against the store's current state, once with the original
//!      package and once with the optimized module substituted, and compared on status, events and
//!      every written object (the gas coin aside). Computation gas of both is reported.
//! Abort locations (function index, offset) are not compared: optimization moves them (see
//! normalizeFailure). The run exits nonzero when fewer than --min-runs (default 1) calls replayed
//! identically, so a run where everything was rejected is not a pass.
//! Divergences are listed with their reason; a clean run is evidence, not a proof: the corpus of
//! calls decides how much, and `superopt` windows carry their own exhaustive or sampled proofs.
const std = @import("std");
const common = @import("common.zig");
const rw = @import("rewrite.zig");
const profile = @import("profile.zig");
const mf = @import("move_format");
const bcs = @import("bcs");
const types = @import("types");
const simulate = @import("simulate");

const Allocator = std.mem.Allocator;
const ff = common.ff;
const Id = common.Id;

fn sigEql(a: *const ff.CompiledModule, ai: u16, b: *const ff.CompiledModule, bi: u16) bool {
    const sa = a.signatureAt(ai);
    const sb = b.signatureAt(bi);
    if (sa.len != sb.len) return false;
    for (sa, sb) |x, y| if (!ff.tokenEql(x, y)) return false;
    return true;
}

/// Null when the interfaces agree, else why not.
pub fn sameInterface(a: *const ff.CompiledModule, b: *const ff.CompiledModule) ?[]const u8 {
    if (a.function_defs.len != b.function_defs.len) return "function count differs";
    if (a.struct_defs.len != b.struct_defs.len) return "struct count differs";
    if (a.enum_defs.len != b.enum_defs.len) return "enum count differs";
    if (a.datatype_handles.len != b.datatype_handles.len) return "datatype handles differ";
    if (a.function_handles.len != b.function_handles.len) return "function handles differ";
    if (a.constant_pool.len != b.constant_pool.len) return "constant pool differs";
    for (a.constant_pool, b.constant_pool) |x, y| {
        if (!ff.tokenEql(x.type_, y.type_) or !std.mem.eql(u8, x.data, y.data)) return "constant differs";
    }
    for (a.function_defs, b.function_defs) |x, y| {
        if (x.visibility != y.visibility or x.is_entry != y.is_entry or (x.code == null) != (y.code == null)) return "function visibility, entry flag or native-ness differs";
        const fa = a.functionHandleAt(x.function);
        const fb = b.functionHandleAt(y.function);
        if (!std.mem.eql(u8, a.identifierAt(fa.name), b.identifierAt(fb.name))) return "function order or name differs";
        if (!sigEql(a, fa.parameters, b, fb.parameters) or !sigEql(a, fa.return_, b, fb.return_)) return "function signature differs";
        if (fa.type_parameters.len != fb.type_parameters.len) return "function type parameters differ";
        for (fa.type_parameters, fb.type_parameters) |p, q| if (!p.eql(q)) return "function type parameter abilities differ";
    }
    for (a.datatype_handles, b.datatype_handles) |x, y| {
        if (!x.abilities.eql(y.abilities) or x.type_parameters.len != y.type_parameters.len) return "datatype abilities differ";
        if (!std.mem.eql(u8, a.identifierAt(x.name), b.identifierAt(y.name))) return "datatype name differs";
    }
    for (a.struct_defs, b.struct_defs) |x, y| {
        if (x.native != y.native or x.fields.len != y.fields.len) return "struct layout differs";
        for (x.fields, y.fields) |f, g| {
            if (!std.mem.eql(u8, a.identifierAt(f.name), b.identifierAt(g.name)) or !ff.tokenEql(f.signature, g.signature)) return "struct field differs";
        }
    }
    return null;
}

const Divergence = struct { digest: Id, reason: []const u8 };

/// Failure texts carry "Location: <addr>::<module>::<function> (function index N) at offset M" (or
/// "<addr>::<module> in function definition N at offset M"). Optimizer passes and inlining move
/// instructions and abort sites, so only the module part of every location is kept; the failure
/// kind, abort code and command stay in the comparison.
pub fn normalizeFailure(arena: Allocator, msg: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var rest = msg;
    const marker = "Location: ";
    while (std.mem.indexOf(u8, rest, marker)) |i| {
        try out.appendSlice(arena, rest[0 .. i + marker.len]);
        rest = rest[i + marker.len ..];
        const at = std.mem.indexOf(u8, rest, " at offset ") orelse break;
        const loc = rest[0..at];
        // keep "<addr>::<module>"
        var keep = loc.len;
        if (std.mem.indexOf(u8, loc, "::")) |c1| {
            if (std.mem.indexOfPos(u8, loc, c1 + 2, "::")) |c2| keep = c2;
        }
        if (std.mem.indexOf(u8, loc[0..keep], " in function definition")) |k| keep = k;
        try out.appendSlice(arena, loc[0..keep]);
        var j = at + " at offset ".len;
        while (j < rest.len and std.ascii.isDigit(rest[j])) j += 1;
        rest = rest[j..];
    }
    try out.appendSlice(arena, rest);
    return out.items;
}

fn statusKey(arena: Allocator, x: simulate.api.Executed) ![]const u8 {
    return switch (x.status) {
        .success => "success",
        .failure => |f| try std.fmt.allocPrint(arena, "failure {s} {s}", .{ f.name, try normalizeFailure(arena, f.message) }),
    };
}

/// Why two executions differ, or null. `gas_id` is skipped (its balance carries the gas charge).
fn compare(arena: Allocator, a: simulate.api.Executed, b: simulate.api.Executed, gas_id: ?Id) !?[]const u8 {
    const sa = try statusKey(arena, a);
    const sb = try statusKey(arena, b);
    if (!std.mem.eql(u8, sa, sb)) return try std.fmt.allocPrint(arena, "status differs: {s} vs {s}", .{ sa, sb });
    const ea = a.events orelse &.{};
    const eb = b.events orelse &.{};
    if (!std.mem.eql(u8, ea, eb)) return "events differ";
    var ia: usize = 0;
    var ib: usize = 0;
    while (true) {
        while (ia < a.object_changes.len and gas_id != null and std.mem.eql(u8, &a.object_changes[ia].id, &gas_id.?)) ia += 1;
        while (ib < b.object_changes.len and gas_id != null and std.mem.eql(u8, &b.object_changes[ib].id, &gas_id.?)) ib += 1;
        if (ia >= a.object_changes.len or ib >= b.object_changes.len) break;
        const x = a.object_changes[ia];
        const y = b.object_changes[ib];
        if (x.kind != y.kind or !std.mem.eql(u8, &x.id, &y.id)) return "object changes differ in kind or id";
        const ox = x.object orelse &.{};
        const oy = y.object orelse &.{};
        if (!std.mem.eql(u8, ox, oy)) return try std.fmt.allocPrint(arena, "object 0x{x} differs after the transaction", .{&x.id});
        ia += 1;
        ib += 1;
    }
    if (ia < a.object_changes.len or ib < b.object_changes.len) return "object change counts differ";
    return null;
}

pub fn run(ctx: *common.Ctx) !u8 {
    const arena = ctx.arena;
    const dir = ctx.opts.get("--dir") orelse return error.MissingDir;
    const pid = try common.parseId(ctx.opts.get("--package") orelse return error.MissingPackage);
    const mod = ctx.opts.get("--module") orelse return error.MissingModule;
    const opt_path = ctx.opts.get("--optimized") orelse return error.MissingOptimized;
    const scan_n = try ctx.opts.num("--checkpoints", 1000);
    const limit: usize = @intCast(try ctx.opts.num("--limit", 100));

    var o = try common.openNode(ctx.gpa, ctx.io, arena, dir);
    defer o.close();
    var snap = o.st.snapshot();
    defer snap.release();
    const pkg = try common.loadPackage(arena, &snap, &pid);
    const lm = common.moduleByName(&pkg, mod) orelse return error.ModuleNotFound;

    const opt_raw = try std.Io.Dir.cwd().readFileAlloc(ctx.io, opt_path, arena, .limited(16 << 20));
    const opt_cm = switch (try mf.deserialize(arena, opt_raw, &.{})) {
        .ok => |m| m,
        .err => return error.BadOptimizedModule,
    };

    var j: common.Json = .{ .w = ctx.w };
    try j.beginObj();
    try j.str("package", try common.hexId(arena, &pid));
    try j.str("module", mod);

    // 1. verifiers
    const v = try rw.Verifier.init(try common.protocolOpt(ctx.opts));
    const vo = try v.check(arena, &opt_cm);
    try j.objIn("verifier");
    switch (vo) {
        .ok => try j.boolean("ok", true),
        .move => |m| {
            try j.boolean("ok", false);
            try j.str("move_verifier", m);
        },
        .sui => |m| {
            try j.boolean("ok", false);
            try j.str("sui_verifier", m);
        },
    }
    try j.endObj();

    // 2. interface
    const iface = sameInterface(&lm.cm, &opt_cm);
    try j.objIn("interface");
    try j.boolean("unchanged", iface == null);
    if (iface) |why| try j.str("difference", why);
    try j.endObj();

    var exit: u8 = 0;
    if (vo != .ok or iface != null) {
        try j.int("differential_runs", 0);
        try j.endObj();
        try ctx.w.writeByte('\n');
        return 1;
    }

    // 3. differential execution
    const new_pkg = try common.rebuildPackage(arena, pkg.object, mod, opt_raw);
    var oc: common.OriginCache = .{ .arena = arena, .snap = &snap };
    const target = oc.original(&pid);
    const calls = try profile.collectCalls(ctx.gpa, arena, &snap, target, pid, mod, ctx.opts.get("--function"), scan_n, limit);

    const base = try arena.create(profile.Sim);
    try base.init(ctx.gpa, ctx.io, o.st, null);
    const alt = try arena.create(profile.Sim);
    try alt.init(ctx.gpa, ctx.io, o.st, .{ .id = pid, .raw = new_pkg });
    const mode: simulate.api.Mode = if (ctx.opts.flag("--checks")) .simulate else .dev_inspect;

    var equal: u64 = 0;
    var both_rejected: u64 = 0;
    var baseline_rejected: u64 = 0;
    var gas_before: u128 = 0;
    var gas_after: u128 = 0;
    var divs: std.ArrayList(Divergence) = .empty;
    for (calls) |c| {
        var ra: std.heap.ArenaAllocator = .init(ctx.gpa);
        defer ra.deinit();
        var rb: std.heap.ArenaAllocator = .init(ctx.gpa);
        defer rb.deinit();
        const req: simulate.api.Request = .{ .tx = .{ .data = c.tx }, .mode = mode, .overrides = .{ .objects = try profile.liveOverrides(ra.allocator(), &snap, c.tx) } };
        const resA = base.engine.simulate(ra.allocator(), &snap, req) catch |e| {
            try divs.append(arena, .{ .digest = c.digest, .reason = try std.fmt.allocPrint(arena, "baseline error {s}", .{@errorName(e)}) });
            continue;
        };
        const resB = alt.engine.simulate(rb.allocator(), &snap, req) catch |e| {
            try divs.append(arena, .{ .digest = c.digest, .reason = try std.fmt.allocPrint(arena, "optimized error {s}", .{@errorName(e)}) });
            continue;
        };
        switch (resA) {
            .rejected => {
                switch (resB) {
                    .rejected => both_rejected += 1,
                    // not compared: the baseline could not run it, so there is nothing to agree with
                    .executed => baseline_rejected += 1,
                }
                continue;
            },
            .executed => |xa| switch (resB) {
                .rejected => |r| try divs.append(arena, .{ .digest = c.digest, .reason = try std.fmt.allocPrint(arena, "optimized rejected: {s}", .{r.message}) }),
                .executed => |xb| {
                    const gas_id: ?Id = if (xa.td.gas_data.payment.len > 0) xa.td.gas_data.payment[0][0].@"0".@"0" else null;
                    if (try compare(arena, xa, xb, gas_id)) |why| {
                        try divs.append(arena, .{ .digest = c.digest, .reason = why });
                    } else {
                        equal += 1;
                        gas_before += xa.gas.computation;
                        gas_after += xb.gas.computation;
                    }
                },
            },
        }
    }

    try j.int("recorded_calls", calls.len);
    try j.int("identical_results", equal);
    try j.int("both_rejected", both_rejected);
    try j.int("baseline_rejected_not_compared", baseline_rejected);
    const min_runs = try ctx.opts.num("--min-runs", 1);
    try j.int("min_runs", min_runs);
    try j.boolean("enough_evidence", equal >= min_runs);
    if (equal < min_runs) try j.str("no_evidence", "fewer identical replays than --min-runs: recorded calls were rejected by the engine (old owned versions, pruned history) or none were found; this run proves nothing");
    try j.int("diverged", divs.items.len);
    try j.int("computation_mist_before", gas_before);
    try j.int("computation_mist_after", gas_after);
    try j.float("computation_saved_percent", if (gas_before == 0) 0 else 100.0 * (@as(f64, @floatFromInt(gas_before)) - @as(f64, @floatFromInt(gas_after))) / @as(f64, @floatFromInt(gas_before)));
    try j.arrIn("divergences");
    for (divs.items) |d| {
        try j.beginObj();
        try j.str("digest", try hexDigest(arena, &d.digest));
        try j.str("reason", d.reason);
        try j.endObj();
    }
    try j.endArr();
    try j.endObj();
    try ctx.w.writeByte('\n');
    if (divs.items.len > 0 or equal < min_runs) exit = 1;
    return exit;
}

fn hexDigest(arena: Allocator, id: *const Id) ![]const u8 {
    const serve = @import("serve");
    const buf = try arena.alloc(u8, serve.b58.max_len_32);
    return try arena.dupe(u8, serve.b58.encode32(buf[0..serve.b58.max_len_32], id));
}

test "normalizeFailure drops offsets and function names" {
    var st: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer st.deinit();
    const a = st.allocator();
    const n = try normalizeFailure(a, "Transaction fails: Move Runtime Abort. Location: 0xab::m::f (function index 3) at offset 17, Abort Code: 5 in command 0");
    try std.testing.expectEqualStrings("Transaction fails: Move Runtime Abort. Location: 0xab::m, Abort Code: 5 in command 0", n);
}
