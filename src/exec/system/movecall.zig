//! One system Move call, as `execution_engine` runs the system transactions that are a single
//! MoveCall on the framework (randomness and authenticator state updates):
//! `programmable_transactions::execution::execute::<execution_mode::System>` of a PTB with one
//! MoveCall, unmetered, then `Context::finish` (mutable inputs written back, object runtime
//! results: child writes, loaded children, deletions, events) into the system `Store`.
//!
//! Execution versions 4 and 3 (see `run`). The VM runtime for a
//! framework snapshot is cached per thread, keyed by the (id, version) of every package of the
//! call's linkage (an object version names one object, so the key is exact).
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const vm = @import("move_vm");
const natives = @import("natives");
const move_format = @import("move_format");
const protocol = @import("protocol");
const objects = @import("../objects.zig");
const store_mod = @import("store.zig");
const sys = @import("root.zig");

const Allocator = std.mem.Allocator;
const loader = vm.loader;
const Type = loader.Type;
const Value = vm.Value;
const objrt = natives.objrt;
const ff = move_format.file_format;

pub const Arg = union(enum) {
    /// An input object of the store (shared or owned), by id.
    object: [32]u8,
    /// BCS of a pure argument.
    pure: []const u8,
};

pub const Call = struct {
    package: [32]u8,
    module: []const u8,
    function: []const u8,
    args: []const Arg,
};

const framework_id: [32]u8 = addr(2);

fn addr(n: u16) [32]u8 {
    var a: [32]u8 = @splat(0);
    std.mem.writeInt(u16, a[30..32], n, .big);
    return a;
}

// ---- VM runtime per framework snapshot ------------------------------------------------------

const IdVer = struct { id: [32]u8, version: u64 };

const Vm = struct {
    /// The root packages, then their linkage, at the versions loaded.
    pkgs: []const IdVer,
    n_roots: usize,
    rt: *loader.Runtime,
    links: vm.interp.LinkCache,
    /// The protocol's binary config the packages were loaded under (part of the key: the same
    /// package versions can be live under protocols that deserialize differently).
    bin: move_format.BinaryConfig,
    /// Last use (least recently used is replaced).
    used: u64 = 0,
};

/// Framework snapshots kept per thread (a few MB each; one per system package upgrade).
/// Replacement is least recently used, so the snapshot of a run of transactions from one
/// epoch stays while snapshots of other epochs come and go.
const cache_slots = 16;
threadlocal var tl_cache: [cache_slots]?*Vm = @splat(null);
threadlocal var tl_tick: u64 = 0;

/// Frees this thread's framework snapshots. For worker threads that exit while the process lives
/// on (the node's simulate pool); the snapshots are smp_allocator-owned.
pub fn releaseThreadCaches() void {
    const gpa = std.heap.smp_allocator;
    for (&tl_cache) |*slot| if (slot.*) |old| {
        old.links.deinit();
        old.rt.deinit();
        gpa.destroy(old.rt);
        gpa.destroy(old);
        slot.* = null;
    };
}

pub fn binaryConfig(cfg: *const protocol.ProtocolConfig) !move_format.BinaryConfig {
    const b = try protocol.derived.binaryConfig(cfg, null);
    var out: move_format.BinaryConfig = .{
        .max_binary_format_version = b.max_binary_format_version,
        .min_binary_format_version = b.min_binary_format_version,
        .check_no_extraneous_bytes = b.check_no_extraneous_bytes,
        .deprecate_global_storage_ops = b.deprecate_global_storage_ops,
        .type_parameter_index_max = b.type_parameter_index_max,
        .table_config = undefined,
    };
    inline for (@typeInfo(@TypeOf(b.table_config)).@"struct".field_names) |f| {
        @field(out.table_config, f) = @field(b.table_config, f);
    }
    return out;
}

const PkgObj = struct { raw: []const u8, pkg: types.MovePackage };

fn decodePackage(a: Allocator, raw: []const u8) !PkgObj {
    const o = bcs.decode(types.Object, a, raw) catch return error.BadPackage;
    return switch (o.data) {
        .Package => |p| .{ .raw = raw, .pkg = p },
        else => error.BadPackage,
    };
}

fn packageInput(a: Allocator, p: *const types.MovePackage) !loader.PackageInput {
    const vid = p.id.@"0".@"0";
    const info = objrt.packageInfo(a, p) catch return error.BadPackage;
    const link = try a.alloc([2]loader.Address, p.linkage_table.entries.len + 1);
    link[0] = .{ info.original_id, vid };
    for (p.linkage_table.entries, link[1..]) |e, *l| l.* = .{ e.key.@"0".@"0", e.value.upgraded_id.@"0".@"0" };
    const origins = try a.alloc(loader.TypeOrigin, p.type_origin_table.len);
    for (p.type_origin_table, origins) |t, *o| o.* = .{ .module = t.module_name.@"0", .name = t.datatype_name.@"0", .defining = t.package.@"0".@"0" };
    const mods = try a.alloc(loader.NamedModule, p.module_map.entries.len);
    for (p.module_map.entries, mods) |e, *m| m.* = .{ .name = e.key.@"0", .bytes = e.value };
    return .{ .version_id = vid, .original_id = info.original_id, .version = p.version.@"0", .linkage = link, .type_origins = origins, .modules = mods };
}

/// (id, version) of a package object from its first bytes (`Data::Package`: tag 1, id, version).
fn packageIdVer(raw: []const u8) ?IdVer {
    if (raw.len < 41 or raw[0] != 1) return null;
    return .{ .id = raw[1..33].*, .version = std.mem.readInt(u64, raw[33..41], .little) };
}

/// The VM runtime holding `root` and its linkage at the versions `src` serves. A cached
/// runtime is reused when the root and every package of its linkage are at the same versions.
fn vmFor(scratch: Allocator, cfg: *const protocol.ProtocolConfig, src: sys.Source, roots: []const [32]u8) !?*Vm {
    // The packages: every root, then each root's linkage, deduplicated (one runtime, so the
    // values one command returns are the types the next command takes).
    var ivs: std.ArrayList(IdVer) = .empty;
    var raws: std.ArrayList([]const u8) = .empty;
    for (roots) |*r| {
        const raw = src.package(src.ctx, r) orelse return null;
        const iv = packageIdVer(raw) orelse return error.BadPackage;
        try ivs.append(scratch, iv);
        try raws.append(scratch, raw);
    }
    const bin = try binaryConfig(cfg);
    tl_tick += 1;
    cached: for (tl_cache) |slot| if (slot) |v| {
        if (v.n_roots != roots.len) continue;
        if (!std.meta.eql(v.bin, bin)) continue;
        for (v.pkgs[0..roots.len], ivs.items) |c, iv| if (!std.mem.eql(u8, &c.id, &iv.id) or c.version != iv.version) continue :cached;
        for (v.pkgs[roots.len..]) |d| {
            const raw = src.package(src.ctx, &d.id) orelse continue :cached;
            const iv = packageIdVer(raw) orelse continue :cached;
            if (iv.version != d.version) continue :cached;
        }
        v.used = tl_tick;
        return v;
    };
    var objs: std.ArrayList(PkgObj) = .empty;
    for (raws.items) |raw| try objs.append(scratch, try decodePackage(scratch, raw));
    for (0..roots.len) |ri| {
        for (objs.items[ri].pkg.linkage_table.entries) |e| {
            const id = e.value.upgraded_id.@"0".@"0";
            const seen = for (ivs.items) |x| {
                if (std.mem.eql(u8, &x.id, &id)) break true;
            } else false;
            if (seen) continue;
            // (System packages record version 0 in their linkage tables; the id names the
            // package the epoch loads.)
            const raw = src.package(src.ctx, &id) orelse return null;
            const d = try decodePackage(scratch, raw);
            try ivs.append(scratch, .{ .id = id, .version = d.pkg.version.@"0" });
            try objs.append(scratch, d);
        }
    }

    // Build a runtime that owns copies of the package bytes (the cache outlives `src`).
    const gpa = std.heap.smp_allocator;
    const rt = try gpa.create(loader.Runtime);
    rt.* = loader.Runtime.init(gpa, bin);
    errdefer {
        rt.deinit();
        gpa.destroy(rt);
    }
    const ra = rt.arena_state.allocator();
    var k = objs.items.len;
    while (k > 0) {
        k -= 1;
        const own = try decodePackage(ra, try ra.dupe(u8, objs.items[k].raw));
        const p = try rt.addPackage(try packageInput(ra, &own.pkg));
        if (p.refused != null) return error.FrameworkRefused;
    }
    const v = try gpa.create(Vm);
    v.* = .{ .pkgs = try ra.dupe(IdVer, ivs.items), .n_roots = roots.len, .rt = rt, .links = vm.interp.LinkCache.init(gpa), .bin = bin, .used = tl_tick };
    var at: usize = 0;
    for (tl_cache, 0..) |slot, i| {
        const s_used = if (slot) |x| x.used else 0;
        const best = if (tl_cache[at]) |x| x.used else 0;
        if (slot == null) {
            at = i;
            break;
        }
        if (s_used < best) at = i;
    }
    if (tl_cache[at]) |old| {
        old.links.deinit();
        old.rt.deinit();
        gpa.destroy(old.rt);
        gpa.destroy(old);
    }
    tl_cache[at] = v;
    return v;
}

/// The value layout (plain and annotated) of a Move object of type `tag`, from the VM runtime of
/// `roots` (and their linkage) at the versions `src` serves. Null: a package is not available.
pub const Layouts = struct { plain: *const types.layout.MoveTypeLayout, annotated: *const objrt.ALayout };
pub fn objectLayouts(arena: Allocator, cfg: *const protocol.ProtocolConfig, src: sys.Source, roots: []const [32]u8, tag: *const types.TypeTag) !?Layouts {
    const v = (try vmFor(arena, cfg, src, roots)) orelse return null;
    const tb = try bcs.encodeAlloc(types.TypeTag, arena, tag);
    const ty = vm.types.fromTagBytes(arena, v.rt, tb) catch return error.TypeNotLoaded;
    const plain = (try vm.host.layoutLimited(arena, ty, .none)) orelse return error.InvariantViolation;
    const annotated = (try vm.host.annotatedLimited(arena, ty, .none)) orelse return error.InvariantViolation;
    return .{ .plain = plain, .annotated = annotated };
}

// ---- object conversions ---------------------------------------------------------------------

fn st(a: Allocator, address: [32]u8, module: []const u8, name: []const u8, args: []const types.TypeTag) !types.TypeTag {
    _ = a;
    return .{ .@"struct" = .{ .address = .{ .@"0" = address }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = args } };
}

fn one(a: Allocator, t: types.TypeTag) ![]const types.TypeTag {
    const s = try a.alloc(types.TypeTag, 1);
    s[0] = t;
    return s;
}

/// `StructTag::from(MoveObjectType)`.
pub fn objectTypeTag(a: Allocator, t: *const types.MoveObjectType) !*const types.TypeTag {
    const out = try a.create(types.TypeTag);
    const sui = try st(a, framework_id, "sui", "SUI", &.{});
    out.* = switch (t.@"0") {
        .Other => |s| .{ .@"struct" = s },
        .GasCoin => try st(a, framework_id, "coin", "Coin", try one(a, sui)),
        .StakedSui => try st(a, addr(3), "staking_pool", "StakedSui", &.{}),
        .Coin => |c| try st(a, framework_id, "coin", "Coin", try one(a, c)),
        .SuiBalanceAccumulatorField => try balanceField(a, sui),
        .BalanceAccumulatorField => |b| try balanceField(a, b),
    };
    return out;
}

fn balanceField(a: Allocator, t: types.TypeTag) !types.TypeTag {
    const bal = try st(a, framework_id, "balance", "Balance", try one(a, t));
    const key = try st(a, framework_id, "accumulator", "Key", try one(a, bal));
    const val = try st(a, framework_id, "accumulator", "U128", &.{});
    const args = try a.alloc(types.TypeTag, 2);
    args[0] = key;
    args[1] = val;
    return st(a, framework_id, "dynamic_field", "Field", args);
}

fn isStruct(t: *const types.TypeTag, address: *const [32]u8, module: []const u8, name: []const u8, n: usize) ?*const types.StructTag {
    if (t.* != .@"struct") return null;
    const s = &t.@"struct";
    if (!std.mem.eql(u8, &s.address.@"0", address) or !std.mem.eql(u8, s.module.@"0", module) or !std.mem.eql(u8, s.name.@"0", name) or s.type_args.len != n) return null;
    return s;
}

/// `MoveObjectType::from(StructTag)`.
fn moveObjectType(t: *const types.TypeTag) !types.MoveObjectType {
    const s = &t.@"struct";
    if (isStruct(t, &framework_id, "coin", "Coin", 1)) |c| {
        if (isStruct(&c.type_args[0], &framework_id, "sui", "SUI", 0) != null) return .{ .@"0" = .GasCoin };
        return .{ .@"0" = .{ .Coin = c.type_args[0] } };
    }
    if (isStruct(t, &addr(3), "staking_pool", "StakedSui", 0) != null) return .{ .@"0" = .StakedSui };
    if (isStruct(t, &framework_id, "dynamic_field", "Field", 2)) |f| {
        if (isStruct(&f.type_args[0], &framework_id, "accumulator", "Key", 1)) |k| if (isStruct(&f.type_args[1], &framework_id, "accumulator", "U128", 0) != null) {
            if (isStruct(&k.type_args[0], &framework_id, "balance", "Balance", 1)) |b| {
                if (isStruct(&b.type_args[0], &framework_id, "sui", "SUI", 0) != null) return .{ .@"0" = .SuiBalanceAccumulatorField };
                return .{ .@"0" = .{ .BalanceAccumulatorField = b.type_args[0] } };
            }
        };
    }
    return .{ .@"0" = .{ .Other = s.* } };
}

/// Abilities of an instantiated type: has `store` (`has_public_transfer` of a written object).
fn hasStore(t: *const Type) bool {
    return switch (t.*) {
        .bool, .u8, .u16, .u32, .u64, .u128, .u256, .address => true,
        .vector => |e| hasStore(e),
        .signer, .ref, .mut_ref, .param => false,
        .datatype => |d| blk: {
            const cm = &d.dt.module.cm;
            const h = if (d.dt.is_enum) cm.enum_defs[d.dt.def_idx].enum_handle else cm.struct_defs[d.dt.def_idx].struct_handle;
            const dh = cm.datatype_handles[h];
            if (!dh.abilities.hasStore()) break :blk false;
            for (dh.type_parameters, d.args) |p, arg| if (!p.is_phantom and !hasStore(arg)) break :blk false;
            break :blk true;
        },
    };
}

/// `Data::Move` bytes up to the version for a written object of type `tag`.
fn header(a: Allocator, rt: *loader.Runtime, tag: *const types.TypeTag) ![]const u8 {
    if (tag.* != .@"struct") return error.NotAStruct;
    const tag_bytes = try bcs.encodeAlloc(types.TypeTag, a, tag);
    const ty = vm.types.fromTagBytes(a, rt, tag_bytes) catch return error.TypeNotLoaded;
    const mot = try moveObjectType(tag);
    var out: std.ArrayList(u8) = .empty;
    try out.append(a, 0);
    try out.appendSlice(a, try bcs.encodeAlloc(types.MoveObjectType, a, &mot));
    try out.append(a, @intFromBool(hasStore(ty)));
    return out.items;
}

// ---- storage for the object runtime ---------------------------------------------------------

const Resolver = struct {
    a: Allocator,
    src: sys.Source,
    /// Every child object read, as stored (for `loaded_runtime_objects`).
    read: std.AutoArrayHashMapUnmanaged([32]u8, []const u8) = .empty,
    missing: bool = false,
    bad: bool = false,

    const vtable: objrt.Resolver.VTable = .{ .read_child = readChild, .received_at = receivedAt, .package_at = packageAt, .available_balance = availableBalance };

    fn stored(r: *Resolver, raw: []const u8) !*const objrt.StoredObject {
        const o = try bcs.decode(types.Object, r.a, raw);
        const v = try objects.ObjectView.parse(raw);
        const out = try r.a.create(objrt.StoredObject);
        out.* = .{
            .id = v.id,
            .owner = try objrt.Owner.fromTypes(r.a, &o.owner),
            .version = v.version,
            .previous_transaction = o.previous_transaction.@"0".@"0",
            .storage_rebate = o.storage_rebate,
            .digest = v.digest(),
            .move = switch (o.data) {
                .Move => |m| .{ .type_ = try objectTypeTag(r.a, &m.type_), .contents = m.contents },
                .Package => null,
            },
        };
        return out;
    }

    var miss_warns: std.atomic.Value(u32) = .init(0);

    fn readChild(ctx: *anyopaque, parent: *const objrt.Id, child: *const objrt.Id, upper: u64) objrt.ResolveError!?*const objrt.StoredObject {
        const r: *Resolver = @ptrCast(@alignCast(ctx));
        const raw = (r.src.child(r.src.ctx, parent, child, upper) catch {
            if (miss_warns.fetchAdd(1, .monotonic) < 20) std.log.warn("system call: child {x} of {x} at or below {d} not available", .{ child.*, parent.*, upper });
            r.missing = true;
            return error.Storage;
        }) orelse return null;
        r.read.put(r.a, child.*, raw) catch {
            r.bad = true;
            return error.Storage;
        };
        return r.stored(raw) catch {
            r.bad = true;
            return error.Storage;
        };
    }

    fn receivedAt(ctx: *anyopaque, _: *const objrt.Id, _: *const objrt.Id, _: u64, _: u64) objrt.ResolveError!?*const objrt.StoredObject {
        const r: *Resolver = @ptrCast(@alignCast(ctx));
        r.missing = true;
        return error.Storage;
    }

    fn packageAt(ctx: *anyopaque, id: *const objrt.Id, version: u64) ?objrt.PackageInfo {
        const r: *Resolver = @ptrCast(@alignCast(ctx));
        const raw = r.src.package(r.src.ctx, id) orelse return null;
        const p = decodePackage(r.a, raw) catch return null;
        if (p.pkg.version.@"0" != version) {
            if (miss_warns.fetchAdd(1, .monotonic) < 20) std.log.warn("system call: package {x} at version {d} not available (have {d})", .{ id.*, version, p.pkg.version.@"0" });
            r.missing = true;
            return null;
        }
        return objrt.packageInfo(r.a, &p.pkg) catch null;
    }

    fn availableBalance(ctx: *anyopaque, _: *const objrt.Id, _: *const objrt.TypeTag) objrt.ResolveError!u128 {
        const r: *Resolver = @ptrCast(@alignCast(ctx));
        r.missing = true;
        return error.Storage;
    }
};

// ---- the call -------------------------------------------------------------------------------

fn isTxContext(t: *const Type) bool {
    const inner = switch (t.*) {
        .ref, .mut_ref => |x| x,
        else => t,
    };
    if (inner.* != .datatype) return false;
    const dt = inner.datatype.dt;
    return std.mem.eql(u8, &dt.module.pkg.original_id, &framework_id) and std.mem.eql(u8, dt.module.name, "tx_context") and std.mem.eql(u8, dt.name, "TxContext");
}

/// A PTB argument of a system command.
pub const PArg = union(enum) { input: u16, result: u16, nested: [2]u16 };

/// One MoveCall of a system PTB (`ProgrammableTransactionBuilder::programmable_move_call`).
pub const Command = struct {
    package: [32]u8,
    module: []const u8,
    function: []const u8,
    type_args: []const types.TypeTag = &.{},
    args: []const PArg,
};

pub const Ptb = struct { inputs: []const Arg, commands: []const Command };

/// Runs one MoveCall as a one-command system PTB and finishes the transaction (effects V2).
pub fn run(arena: Allocator, s: *store_mod.Store, env: *const sys.Env, src: sys.Source, sender: *const [32]u8, gas: *const types.GasData, call: *const Call) !sys.Outcome {
    const pargs = try arena.alloc(PArg, call.args.len);
    for (pargs, 0..) |*x, i| x.* = .{ .input = @intCast(i) };
    const ptb: Ptb = .{ .inputs = call.args, .commands = &.{.{ .package = call.package, .module = call.module, .function = call.function, .args = pargs }} };
    const events = switch (try exec(arena, s, env, src, sender, gas, &ptb)) {
        .ok => |e| e,
        .unsupported => |why| return .{ .unsupported = why },
        .aborted => |ab| {
            const status = (try abortStatus(arena, ab)) orelse return .{ .unsupported = "system Move call failed with a VM error other than an abort" };
            return .{ .done = s.intoFailure(status) catch |e| switch (e) {
                error.Unsupported => return .{ .unsupported = s.why },
                else => |x| return x,
            } };
        },
    };
    return finish(s, events);
}

/// `ExecutionStatus::Failure` of a Move abort (`convert_vm_error` for ABORTED): `MoveAbort` at
/// the aborting module's runtime id, function definition index, code offset and function name,
/// with the command index. Null for any other VM error (not modeled here).
pub fn abortStatus(a: Allocator, ab: Abort) !?types.ExecutionStatus {
    if (ab.err.major != .ABORTED) return null;
    const m = ab.err.module orelse return null;
    const off = ab.err.off orelse return null;
    // ABORTED without a code is VMInvariantViolation in Rust (not modeled here).
    const code = ab.err.sub orelse return null;
    const fname = m.cm.identifiers[m.cm.function_handles[m.cm.function_defs[off.fdef].function].name];
    _ = a;
    return .{ .Failure = .{
        .@"error" = .{ .MoveAbort = .{ .{
            .module = .{ .address = .{ .@"0" = m.cm.selfAddress().* }, .name = .{ .@"0" = m.cm.selfName() } },
            .function = off.fdef,
            .instruction = off.pc,
            .function_name = .{ .@"0" = fname },
        }, code } },
        .command = ab.command,
    } };
}

/// `Store.intoEffects` with an unsupported store reason as an outcome.
pub fn finish(s: *store_mod.Store, events: ?[]const u8) !sys.Outcome {
    return .{ .done = s.intoEffects(events) catch |e| switch (e) {
        error.Unsupported => return .{ .unsupported = s.why },
        else => |x| return x,
    } };
}

/// `aborted`: a command failed in the VM (abort or runtime error). Nothing was written to the
/// store: `exec` applies results only after every command succeeded, so the caller sees the
/// state Rust has after `drop_writes`.
pub const Abort = struct { command: u16, err: vm.interp.VmError };
pub const Exec = union(enum) { ok: ?[]const u8, unsupported: []const u8, aborted: Abort };

/// `SPT::execute::<System>` of a PTB of MoveCalls into the store: every command on one VM
/// runtime and one object runtime, mutable input objects written back, then the object
/// runtime's results (child writes, loaded children, deletions). Returns the events (BCS
/// `TransactionEvents`, null when none). The caller finishes the effects.
pub fn exec(arena: Allocator, s: *store_mod.Store, env: *const sys.Env, src: sys.Source, sender: *const [32]u8, gas: *const types.GasData, ptb: *const Ptb) !Exec {
    const cfg = env.cfg;
    const ev = cfg.execution_version orelse 0;
    // Execution version 3 (protocol 38 to 118) runs the same framework calls through the v3
    // adapter and the previous Move VM; for successful unmetered system calls the results
    // are the same (exec-replay checks every one byte for byte). The VM limits come from the
    // same protocol fields.
    const ecfg: vm.ExecConfig = switch (ev) {
        4 => vm.ExecConfig.fromProtocol(cfg) catch return .{ .unsupported = "protocol config" },
        0...3 => .{
            .vector_len_max = cfg.getOpt("max_move_vector_len") orelse 256 * 1024,
            .max_value_depth = cfg.getOpt("max_move_value_depth"),
            .max_type_nodes = cfg.getOpt("max_type_to_layout_nodes") orelse 256,
            .ld_const_abstract_size = cfg.feature_flags.charge_ld_const_abstract_size,
        },
        else => return .{ .unsupported = "execution version after 4" },
    };
    var roots: std.ArrayList([32]u8) = .empty;
    for (ptb.commands) |*c| {
        const seen = for (roots.items) |r| {
            if (std.mem.eql(u8, &r, &c.package)) break true;
        } else false;
        if (!seen) try roots.append(arena, c.package);
    }
    const v = (try vmFor(arena, cfg, src, roots.items)) orelse return .{ .unsupported = "framework package not available" };

    const heap: vm.value.Heap = .{ .arena = arena };
    const h = try arena.create(vm.Host);
    h.* = .{
        .cfg = cfg,
        .tx = .{
            .sender = sender.*,
            .digest = s.tx_digest,
            .epoch = env.epoch,
            .epoch_timestamp_ms = env.epoch_start_ms,
            .rgp = env.rgp,
            .gas_price = gas.price,
            .gas_budget = gas.budget,
            .sponsor = null,
        },
        .tx_arena = arena,
    };
    var res: Resolver = .{ .a = arena, .src = src };
    h.rt.is_metered = false;
    h.rt.epoch = env.epoch;
    h.rt.resolver = .{ .ctx = &res, .vtable = &Resolver.vtable };
    const table = try arena.create(vm.NativeTable);
    table.* = h.table();

    // Locals shared by every command: one slot per input object (created at first use), the
    // TxContext, and the results.
    const ObjSlot = struct { slot: *Value, ty: *const Type, mutable: bool };
    const obj_slots = try arena.alloc(?ObjSlot, ptb.inputs.len);
    @memset(obj_slots, null);
    var ctx_slot: ?*Value = null;
    const Res = struct { vals: []Value, tys: []const *const Type, slots: []?*Value };
    var results: std.ArrayList(Res) = .empty;

    var meter = vm.Meter.unmetered();
    var ev_ends: std.ArrayList(usize) = .empty;
    for (ptb.commands) |*c| {
        var root: ?*loader.Package = null;
        for (v.pkgs[0..v.n_roots]) |iv| if (std.mem.eql(u8, &iv.id, &c.package)) {
            root = v.rt.package(&iv.id);
        };
        const entry = try v.links.get(v.rt, root orelse return error.InvariantViolation);
        if (entry.fail != null) return .{ .unsupported = "framework linkage refused" };
        const link = &entry.link;
        const func = link.function(&c.package, c.module, c.function) catch return .{ .unsupported = "system function not found" };
        const ty_args = try arena.alloc(*const Type, c.type_args.len);
        for (c.type_args, ty_args) |*t, *o| {
            const tb = try bcs.encodeAlloc(types.TypeTag, arena, t);
            o.* = vm.types.fromTagBytes(arena, v.rt, tb) catch return .{ .unsupported = "type argument not loaded" };
        }
        const ptys = try vm.types.instantiateAll(arena, func.module, func.params, ty_args);
        const args = try arena.alloc(Value, ptys.len);
        var ai: usize = 0;
        for (ptys, args) |pt, *out| {
            const inner = switch (pt.*) {
                .ref, .mut_ref => |x| x,
                else => pt,
            };
            if (isTxContext(pt)) {
                if (ctx_slot == null) {
                    // v4 `Value::new_tx_context`: sender 0x0, the digest, zeros (the
                    // tx_context natives read the host's). v3 `to_bcs_legacy_context`: the
                    // framework reads the fields (sender, digest, epoch, epoch start, ids).
                    var b: std.ArrayList(u8) = .empty;
                    try b.appendSlice(arena, if (ev == 4) &@as([32]u8, @splat(0)) else sender);
                    try b.append(arena, 32);
                    try b.appendSlice(arena, &s.tx_digest);
                    var w: [8]u8 = undefined;
                    std.mem.writeInt(u64, &w, if (ev == 4) 0 else env.epoch, .little);
                    try b.appendSlice(arena, &w);
                    std.mem.writeInt(u64, &w, if (ev == 4) 0 else env.epoch_start_ms, .little);
                    try b.appendSlice(arena, &w);
                    try b.appendNTimes(arena, 0, 8);
                    var sl: ?*Value = null;
                    _ = try refTo(arena, heap, pt, b.items, &sl);
                    ctx_slot = sl orelse return error.InvariantViolation;
                }
                out.* = Value.refSlot(ctx_slot.?);
                continue;
            }
            if (ai >= c.args.len) return .{ .unsupported = "system call argument count" };
            const pa = c.args[ai];
            ai += 1;
            switch (pa) {
                .input => |ii| switch (ptb.inputs[ii]) {
                    .pure => |bytes| out.* = try refTo(arena, heap, pt, bytes, null),
                    .object => |id| {
                        if (inner == pt) return .{ .unsupported = "system call takes an object by value" };
                        if (obj_slots[ii] == null) {
                            const view = s.input(&id) orelse return error.InvariantViolation;
                            // ObjectRuntime input: owner and every UID the object holds.
                            const lay = (try vm.host.layoutLimited(arena, inner, .none)) orelse return error.InvariantViolation;
                            const lv = types.layout.decodePacked(arena, lay, view.contents()) catch return error.InvariantViolation;
                            const alay = (try vm.host.annotatedLimited(arena, inner, .none)) orelse return error.InvariantViolation;
                            const uids = try objrt.allUids(arena, &lv, alay);
                            const owner = try bcs.decode(types.Owner, arena, view.ownerBytes());
                            try h.rt.addInput(arena, .{ .id = id, .version = view.version, .owner = try objrt.Owner.fromTypes(arena, &owner), .contained_uids = uids });
                            var sl: ?*Value = null;
                            _ = try refTo(arena, heap, pt, view.contents(), &sl);
                            obj_slots[ii] = .{ .slot = sl.?, .ty = inner, .mutable = false };
                        }
                        if (pt.* == .mut_ref) obj_slots[ii].?.mutable = true;
                        out.* = Value.refSlot(obj_slots[ii].?.slot);
                    },
                },
                .result, .nested => {
                    const ci: u16, const k: u16 = switch (pa) {
                        .result => |r| .{ r, 0 },
                        .nested => |n| .{ n[0], n[1] },
                        else => unreachable,
                    };
                    if (ci >= results.items.len) return error.InvariantViolation;
                    const r = &results.items[ci];
                    if (pa == .result and r.vals.len != 1) return error.InvariantViolation;
                    if (k >= r.vals.len) return error.InvariantViolation;
                    if (inner == pt) {
                        out.* = r.vals[k]; // moved
                    } else {
                        if (r.slots[k] == null) {
                            const sl = try arena.create(Value);
                            sl.* = r.vals[k];
                            r.slots[k] = sl;
                        }
                        out.* = Value.refSlot(r.slots[k].?);
                    }
                },
            }
        }
        if (ai != c.args.len) return .{ .unsupported = "system call argument count" };

        var sess = try vm.Session.init(arena, link, &meter, ecfg);
        sess.natives = table;
        sess.ext = h;
        const outcome = sess.run(func, ty_args, args) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |x| return .{ .unsupported = try std.fmt.allocPrint(arena, "system Move call: VM {s}", .{@errorName(x)}) },
        };
        if (res.missing) return .{ .unsupported = "child object not available" };
        if (res.bad) return error.InvariantViolation;
        const vals = switch (outcome) {
            .ok => |x| x,
            .err => |e| return .{ .aborted = .{ .command = @intCast(results.items.len), .err = e } },
        };
        // The events this command emitted are its own (`take_user_events` per command).
        try ev_ends.append(arena, h.rt.events.items.len);
        const rtys = try vm.types.instantiateAll(arena, func.module, func.returns, ty_args);
        const slots = try arena.alloc(?*Value, vals.len);
        @memset(slots, null);
        try results.append(arena, .{ .vals = try arena.dupe(Value, vals), .tys = rtys, .slots = slots });
    }

    // Mutable inputs used by mutable reference are written back (same type, owner).
    for (ptb.inputs, obj_slots) |in, os| if (os) |o| if (o.mutable) {
        const id = in.object;
        var bytes: std.ArrayList(u8) = .empty;
        try vm.types.serialize(arena, o.ty, o.slot.*, &bytes);
        var w = store_mod.Store.inputAsWrite(s.input(&id).?);
        w.contents = bytes.items;
        try s.write(w, .modified);
    };

    // Before `minimize_child_object_mutations` (protocol 76) the object runtime reports a child
    // borrowed mutably as written even when its value did not change (ChildObjectEffectV0, the
    // VM's dirty flag); the fingerprint rule below the flag is the one `finish` implements.
    var dirty: std.ArrayList([32]u8) = .empty;
    if (!cfg.feature_flags.minimize_child_object_mutations) {
        for (h.rt.store.keys(), h.rt.store.values()) |id, co| if (co.exists) {
            if (h.shadows.get(&co.value)) |sh| if (sh.mutable) try dirty.append(arena, id);
        };
    }
    const fin = try h.finish(arena);
    const r = switch (fin) {
        .ok => |x| x,
        .err => return .{ .unsupported = "object runtime finish error" },
    };
    for (dirty.items) |id| {
        const written = for (r.writes) |w| {
            if (std.mem.eql(u8, &w.id, &id)) break true;
        } else false;
        if (written) continue;
        const co = h.rt.store.get(id).?;
        try s.write(.{
            .id = id,
            .header = header(arena, v.rt, co.ty) catch return .{ .unsupported = "written object type" },
            .contents = try types.layout.encodeAlloc(arena, &co.value),
            .owner = try (objrt.Owner{ .object = co.owner }).encode(arena),
        }, .modified);
    }
    if (r.acc_events.len != 0) return .{ .unsupported = "accumulator events from a system call" };
    for (r.loaded) |l| {
        const raw = res.read.get(l.id) orelse return error.InvariantViolation;
        try s.loadedChild(raw);
    }
    // Write kinds (`WriteKind` in execution versions 0 to 2; the same split decides the
    // IDOperation of effects V2): an id that existed before (input or loaded child) is
    // mutated, a new id is created, any other id was wrapped before and is unwrapped.
    for (r.writes) |w| {
        const existed = s.input(&w.id) != null or res.read.contains(w.id);
        const is_new = for (r.created) |c| {
            if (std.mem.eql(u8, &c, &w.id)) break true;
        } else false;
        try s.write(.{
            .id = w.id,
            .header = header(arena, v.rt, w.ty) catch return .{ .unsupported = "written object type" },
            .contents = try types.layout.encodeAlloc(arena, &w.value),
            .owner = try w.owner.encode(arena),
        }, if (existed) .modified else if (is_new) .created else .unwrapped);
    }
    // `created_object_ids`: every new id that is still alive, written or wrapped.
    for (r.created) |id| if (!s.written.contains(id)) try s.created.put(arena, id, {});
    for (r.deleted) |id| {
        if (s.input(&id) != null or res.read.contains(id)) {
            try s.delete(id);
        } else {
            // DeleteKind::UnwrapThenDelete: an object that was wrapped before.
            if (!cfg.feature_flags.simplified_unwrap_then_delete) return .{ .unsupported = "unwrap then delete before simplified_unwrap_then_delete (tombstone lookup)" };
            try s.unwrapDelete(id);
        }
    }
    // A loaded child the transaction changed that is neither written nor deleted was wrapped
    // (moved out of its parent into a value).
    for (r.loaded) |l| if (l.modified and !s.written.contains(l.id) and !s.deleted.contains(l.id)) {
        try s.wrap(l.id);
    };

    if (r.events.len == 0) return .{ .ok = null };
    const evs = try arena.alloc(types.Event, r.events.len);
    var ci: usize = 0;
    for (r.events, evs, 0..) |e, *o, i| {
        while (ci < ev_ends.items.len and i >= ev_ends.items[ci]) ci += 1;
        if (ci >= ptb.commands.len or e.ty.* != .@"struct") return error.InvariantViolation;
        const c = &ptb.commands[ci];
        o.* = .{
            .package_id = .{ .@"0" = .{ .@"0" = c.package } },
            .transaction_module = .{ .@"0" = c.module },
            .sender = .{ .@"0" = sender.* },
            .type_ = e.ty.@"struct",
            .contents = try types.layout.encodeAlloc(arena, &e.value),
        };
    }
    const te: types.TransactionEvents = .{ .data = evs };
    return .{ .ok = try bcs.encodeAlloc(types.TransactionEvents, arena, &te) };
}

/// A VM argument of parameter type `pt` from `bytes`: by value, or a reference to a slot.
fn refTo(arena: Allocator, heap: vm.value.Heap, pt: *const Type, bytes: []const u8, slot_out: ?*?*Value) !Value {
    const inner = switch (pt.*) {
        .ref, .mut_ref => |x| x,
        else => pt,
    };
    var rd = loader.Reader{ .bytes = bytes };
    const x = vm.types.deserialize(heap, inner, &rd, 0) catch return error.InvariantViolation;
    if (rd.pos != bytes.len) return error.InvariantViolation;
    if (inner == pt) return x;
    const sl = try arena.create(Value);
    sl.* = x;
    if (slot_out) |o| o.* = sl;
    return Value.refSlot(sl);
}
