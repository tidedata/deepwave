//! What Sui's adapter runs on one module at publish (execution path): the Move bytecode verifier
//! (`verify_module_with_config_metered`), function signatures by name, the native check, then
//! `sui_verify_module_metered` with the same meter (1.83.1).
const std = @import("std");
const ff = @import("../file_format.zig");
const c = @import("common.zig");
const cfgm = @import("cfg.zig");
const mc = @import("module_checks.zig");
const cp = @import("code_passes.zig");
const rs = @import("refsafety.zig");
const sui = @import("sui.zig");
const check_bounds = @import("../check_bounds.zig");

const Allocator = std.mem.Allocator;
const CompiledModule = ff.CompiledModule;

pub const Config = c.Config;
pub const Meter = c.Meter;
pub const SuiError = sui.SuiError;

/// Native functions the VM links, as "addr64::module::function".
pub const Natives = std.StringHashMapUnmanaged(void);

pub const MoveError = struct { err: ff.PartialVmError, loc: ff.Location };

pub const Result = struct {
    move: ?MoveError = null,
    /// Only meaningful when `move` is null.
    sui: ?SuiError = null,
    meter: Meter = .{},
};

/// `arena` holds module-lifetime data (ability cache, messages); `scratch` is reset per function.
pub fn verifyModule(arena: Allocator, scratch: *std.heap.ArenaAllocator, cfg: *const Config, m: *const CompiledModule, natives: ?*const Natives) Allocator.Error!Result {
    var r: Result = .{};
    r.meter.enterScope(.Module);
    if (try check_bounds.verifyModule(arena, m, cfg.deprecate_global_storage_ops)) |e| {
        r.move = .{ .err = e, .loc = .undefined };
        return r;
    }
    // only index the module once the bounds check has passed (a caller may hand in a module
    // from deserializeNoCheckBounds)
    const self_name = m.identifiers[m.module_handles[m.self_module_handle_idx].name];
    var ctx: c.Ctx = .{};
    moveVerify(&ctx, arena, scratch, cfg, m, natives, &r.meter) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Vm => {
            r.move = .{ .err = ctx.err, .loc = .{ .module = self_name } };
            return r;
        },
    };
    r.sui = sui.verify(arena, scratch, &ctx, cfg, m, &r.meter) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        // A Rust panic/unwrap path (or a meter limit): report as an invariant violation.
        error.Vm => SuiError{ .kind = .InvariantViolation, .msg = "zui: unexpected verifier state" },
    };
    return r;
}

fn moveVerify(ctx: *c.Ctx, arena: Allocator, scratch: *std.heap.ArenaAllocator, cfg: *const Config, m: *const CompiledModule, natives: ?*const Natives, meter: *Meter) c.E!void {
    var cache = c.AbilityCache.init(arena, m);
    try mc.limits(ctx, arena, cfg, m);
    try mc.duplication(ctx, arena, m);
    try mc.signatures(ctx, arena, m, &cache, meter);
    try mc.instructionConsistency(ctx, cfg, m);
    try mc.constants(ctx, m);
    try mc.friends(ctx, m);
    try mc.abilityFieldRequirements(ctx, m, &cache, meter);
    try mc.recursiveDataDefs(ctx, arena, m);
    try mc.instantiationLoops(ctx, arena, m);
    try codeUnits(ctx, arena, scratch, cfg, m, &cache, meter);
    // verify_module_function_signature_by_name for every function: only entry functions of
    // modules below VERSION_5 have checks (legacy_script_signature_checks). Binary configs up to
    // protocol 44 deserialize those versions.
    if (m.version < ff.VERSION_5) try legacyScriptSignatures(ctx, m);
    if (natives) |n| try checkNatives(ctx, arena, m, n);
}

fn codeUnits(ctx: *c.Ctx, arena: Allocator, scratch: *std.heap.ArenaAllocator, cfg: *const Config, m: *const CompiledModule, cache: *c.AbilityCache, meter: *Meter) c.E!void {
    var name_def: std.AutoHashMapUnmanaged(u16, u16) = .empty;
    for (m.function_defs, 0..) |fd, i| try name_def.put(arena, m.function_handles[fd.function].name, @intCast(i));
    var total_back_edges: usize = 0;
    for (m.function_defs, 0..) |*fd, i| {
        const fidx: u16 = @intCast(i);
        total_back_edges += verifyFunction(ctx, scratch, cfg, m, fidx, fd, cache, &name_def, meter) catch |e| {
            if (e == error.Vm) ctx.atIndex(.FunctionDefinition, fidx);
            return e;
        };
    }
    if (cfg.max_back_edges_per_module) |lim| if (total_back_edges > lim) return ctx.status(.TOO_MANY_BACK_EDGES);
}

fn verifyFunction(ctx: *c.Ctx, scratch: *std.heap.ArenaAllocator, cfg: *const Config, m: *const CompiledModule, fidx: u16, fd: *const ff.FunctionDefinition, cache: *c.AbilityCache, name_def: *const std.AutoHashMapUnmanaged(u16, u16), meter: *Meter) c.E!usize {
    meter.enterScope(.Function);
    const code = &(fd.code orelse return 0);
    _ = scratch.reset(.retain_capacity);
    const a = scratch.allocator();
    if (m.version <= ff.VERSION_5) {
        try cfgm.verifyV5(ctx, a, cfg, fidx, code.code);
    } else {
        try cfgm.verifyFallthrough(ctx, fidx, code.code);
    }
    const g = try cfgm.Cfg.init(a, code.code, code.jump_tables);
    if (m.version > ff.VERSION_5) try cfgm.verifyReducibility(ctx, a, cfg, fidx, &g);
    if (cfg.max_basic_blocks) |lim| if (g.numBlocks() > lim)
        return ctx.fail(ff.PartialVmError.new(.TOO_MANY_BASIC_BLOCKS).atCodeOffset(fidx, 0));
    if (cfg.max_back_edges_per_function) |lim| if (g.num_back_edges > lim)
        return ctx.fail(ff.PartialVmError.new(.TOO_MANY_BACK_EDGES).atCodeOffset(fidx, 0));
    const fh = &m.function_handles[fd.function];
    const f: cp.Fn = .{
        .m = m,
        .fidx = fidx,
        .code = code,
        .params = m.signatures[fh.parameters],
        .ret = m.signatures[fh.return_],
        .locals = m.signatures[code.locals],
        .tparams = fh.type_parameters,
        .g = &g,
    };
    try cp.stackUsage(ctx, cfg, &f);
    try cp.typeSafety(ctx, a, cfg, &f, cache, meter);
    try cp.localsSafety(ctx, a, &f, cache, meter);
    if (cfg.disallow_jump_orphans) try cp.jumpTableUsage(ctx, a, &f);
    if (cfg.switch_to_regex_reference_safety) return ctx.invariant(); // not used by any Sui config
    try rs.verify(ctx, a, cfg, &f, name_def, meter);
    try cp.acquires(ctx, a, cfg, m, fidx);
    try meter.transfer(ctx, .Function, .Module, 1.0);
    return g.num_back_edges;
}

/// move-bytecode-verifier `legacy_script_signature_checks` on every entry function (modules
/// below VERSION_5): `signer` (`&signer` at VERSION_1) arguments first, the rest valid constant
/// types, no return values.
fn legacyScriptSignatures(ctx: *c.Ctx, m: *const CompiledModule) c.E!void {
    for (m.function_defs, 0..) |fd, i| {
        if (!fd.is_entry) continue;
        const fh = m.function_handles[fd.function];
        const params = m.signatures[fh.parameters];
        var k: usize = 0;
        while (k < params.len) : (k += 1) {
            const t = params[k];
            const lead = if (m.version <= ff.VERSION_1)
                t.len == 2 and t[0].tag == .Reference and t[1].tag == .Signer
            else
                t[0].tag == .Signer;
            if (!lead) break;
        }
        var ok = m.signatures[fh.return_].len == 0;
        for (params[k..]) |t| if (!mc.validForConstant(t)) {
            ok = false;
        };
        if (!ok) return ctx.fail(ff.PartialVmError.new(.INVALID_MAIN_FUNCTION_SIGNATURE).atIndex(.FunctionDefinition, @intCast(i)));
    }
}

/// move-vm-runtime `check_natives` against Sui's native function table.
fn checkNatives(ctx: *c.Ctx, arena: Allocator, m: *const CompiledModule, natives: *const Natives) c.E!void {
    var buf: std.ArrayList(u8) = .empty;
    var n: u16 = 0;
    for (m.function_defs) |fd| {
        if (fd.code != null) continue;
        const fh = m.function_handles[fd.function];
        const mh = m.module_handles[fh.module];
        buf.clearRetainingCapacity();
        try buf.print(arena, "{x}::{s}::{s}", .{ &m.address_identifiers[mh.address], m.identifiers[mh.name], m.identifiers[fh.name] });
        if (!natives.contains(buf.items)) return ctx.fail(ff.verificationError(.MISSING_DEPENDENCY, .FunctionHandle, n));
        n += 1;
    }
    for (m.struct_defs, 0..) |sd, i| if (sd.native) return ctx.fail(ff.verificationError(.MISSING_DEPENDENCY, .FunctionHandle, @intCast(i)));
}

test {
    std.testing.refAllDecls(@This());
}
