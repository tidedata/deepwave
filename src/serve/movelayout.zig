//! Annotated Move type layouts for RPC rendering (`json`, `display`): the port of
//! `TypeLayoutResolver::get_annotated_layout` (sui-adapter latest) as sui-node 1.83.1 reaches it
//! from `get_struct_layout_with_overlay`.
//!
//! Rust builds a type linkage from every address in the struct tag (each package and its linkage
//! table, "at least" each version), loads the type in a VM with that linkage and converts it with
//! `type_to_fully_annotated_layout` under `TypeSize::from_vm_config_for_value_depth` (depth
//! `max_move_value_depth`, nodes `max_type_to_layout_nodes`). A datatype's fields and their types
//! never change across compatible upgrades, and neither does its defining id, so any package
//! version that contains the datatype gives the same layout. This resolver therefore loads:
//! the struct tag's own address (a defining id, so that version holds the type), and for a
//! datatype handle inside a module either the module's own package or the version its linkage
//! table names (the version it was compiled against, which holds the type). Framework packages
//! not listed in a linkage table are loaded at their own address.
//!
//! Failures where Rust's resolver errors (package or type missing, limits) give `null`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const mf = @import("move_format");
const ff = mf.file_format;

pub const Layout = union(enum) {
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    u256,
    address,
    signer,
    vector: *const Layout,
    @"struct": *const Struct,
    @"enum": *const Enum,
};

/// `MoveStructLayout`: `type_` carries defining ids, as the VM's annotated layout does.
pub const Struct = struct { type_: types.StructTag, fields: []const Field };
pub const Field = struct { name: []const u8, layout: Layout };
/// `MoveEnumLayout`: variants in tag order (`variants[i].tag == i`).
pub const Enum = struct { type_: types.StructTag, variants: []const Variant };
pub const Variant = struct { name: []const u8, tag: u16, fields: []const Field };

pub const Limits = struct {
    max_depth: u64 = 128, // max_move_value_depth
    max_nodes: u64 = 512, // max_type_to_layout_nodes
};

/// Where package objects come from: BCS(Object) of the package stored at `id`, or null.
pub const PackageSource = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, id: *const [32]u8) ?[]const u8,
};

pub const Error = Allocator.Error;

const LinkEntry = struct { original: [32]u8, upgraded: [32]u8 };
const Origin = struct { module: []const u8, name: []const u8, package: [32]u8 };

const Pkg = struct {
    id: [32]u8,
    modules: []const struct { name: []const u8, bytes: []const u8 },
    origins: []const Origin,
    linkage: []const LinkEntry,
    parsed: std.StringHashMapUnmanaged(?*const ff.CompiledModule) = .empty,
};

/// One resolver per request (single thread); packages and modules parse once per resolver.
pub const Resolver = struct {
    arena: Allocator,
    src: PackageSource,
    limits: Limits = .{},
    pkgs: std.AutoHashMapUnmanaged([32]u8, ?*Pkg) = .empty,

    pub fn init(arena: Allocator, src: PackageSource) Resolver {
        return .{ .arena = arena, .src = src };
    }

    fn package(r: *Resolver, id: *const [32]u8) Error!?*Pkg {
        if (r.pkgs.get(id.*)) |p| return p;
        const p = try r.loadPackage(id);
        try r.pkgs.put(r.arena, id.*, p);
        return p;
    }

    fn loadPackage(r: *Resolver, id: *const [32]u8) Error!?*Pkg {
        const raw = r.src.get(r.src.ctx, id) orelse return null;
        const obj = bcs.decode(types.Object, r.arena, raw) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        const mp = switch (obj.data) {
            .Package => |p| p,
            .Move => return null,
        };
        const p = try r.arena.create(Pkg);
        const mods = try r.arena.alloc(@typeInfo(@TypeOf(p.modules)).pointer.child, mp.module_map.entries.len);
        for (mp.module_map.entries, mods) |e, *m| m.* = .{ .name = e.key.@"0", .bytes = e.value };
        const origins = try r.arena.alloc(Origin, mp.type_origin_table.len);
        for (mp.type_origin_table, origins) |t, *o| o.* = .{ .module = t.module_name.@"0", .name = t.datatype_name.@"0", .package = t.package.@"0".@"0" };
        const links = try r.arena.alloc(LinkEntry, mp.linkage_table.entries.len);
        for (mp.linkage_table.entries, links) |e, *l| l.* = .{ .original = e.key.@"0".@"0", .upgraded = e.value.upgraded_id.@"0".@"0" };
        p.* = .{ .id = id.*, .modules = mods, .origins = origins, .linkage = links };
        return p;
    }

    fn module(r: *Resolver, p: *Pkg, name: []const u8) Error!?*const ff.CompiledModule {
        if (p.parsed.get(name)) |m| return m;
        var found: ?*const ff.CompiledModule = null;
        for (p.modules) |m| if (std.mem.eql(u8, m.name, name)) {
            const cfg: mf.BinaryConfig = .{};
            switch (try mf.deserialize(r.arena, m.bytes, &cfg)) {
                .ok => |cm| {
                    const c = try r.arena.create(ff.CompiledModule);
                    c.* = cm;
                    found = c;
                },
                .err => {},
            }
            break;
        };
        try p.parsed.put(r.arena, name, found);
        return found;
    }

    /// Layout of `tag` (the object or event type). Null where Rust's resolver fails.
    pub fn structLayout(r: *Resolver, tag: *const types.StructTag) Error!?Layout {
        const args = try r.arena.alloc(*const RType, tag.type_args.len);
        for (tag.type_args, args) |*a, *o| o.* = (try r.fromTag(a)) orelse return null;
        const dt = (try r.datatypeAt(&tag.address.@"0", tag.module.@"0", tag.name.@"0", args)) orelse return null;
        var z: TypeSize = .{ .lim = r.limits };
        const t: RType = .{ .datatype = dt };
        return r.layoutOf(&t, &z) catch |e| switch (e) {
            error.Limit, error.Unresolved => null,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    /// Layout of any type tag (primitives included).
    pub fn typeLayout(r: *Resolver, tag: *const types.TypeTag) Error!?Layout {
        const t = (try r.fromTag(tag)) orelse return null;
        var z: TypeSize = .{ .lim = r.limits };
        return r.layoutOf(t, &z) catch |e| switch (e) {
            error.Limit, error.Unresolved => null,
            error.OutOfMemory => error.OutOfMemory,
        };
    }

    // ---- resolved types ----

    const Datatype = struct {
        pkg: *Pkg,
        cm: *const ff.CompiledModule,
        module: []const u8,
        name: []const u8,
        is_enum: bool,
        def: u16,
        args: []const *const RType,
    };

    const RType = union(enum) {
        bool,
        u8,
        u16,
        u32,
        u64,
        u128,
        u256,
        address,
        signer,
        vector: *const RType,
        datatype: Datatype,
    };

    fn fromTag(r: *Resolver, tag: *const types.TypeTag) Error!?*const RType {
        const out = try r.arena.create(RType);
        out.* = switch (tag.*) {
            .bool => .bool,
            .u8 => .u8,
            .u16 => .u16,
            .u32 => .u32,
            .u64 => .u64,
            .u128 => .u128,
            .u256 => .u256,
            .address => .address,
            .signer => .signer,
            .vector => |e| .{ .vector = (try r.fromTag(e)) orelse return null },
            .@"struct" => |*s| blk: {
                const args = try r.arena.alloc(*const RType, s.type_args.len);
                for (s.type_args, args) |*a, *o| o.* = (try r.fromTag(a)) orelse return null;
                break :blk .{ .datatype = (try r.datatypeAt(&s.address.@"0", s.module.@"0", s.name.@"0", args)) orelse return null };
            },
        };
        return out;
    }

    /// The datatype `module::name` in the package stored at `pkg_id`.
    fn datatypeAt(r: *Resolver, pkg_id: *const [32]u8, mname: []const u8, name: []const u8, args: []const *const RType) Error!?Datatype {
        const p = (try r.package(pkg_id)) orelse return null;
        const cm = (try r.module(p, mname)) orelse return null;
        for (cm.struct_defs, 0..) |d, i| {
            const h = cm.datatypeHandleAt(d.struct_handle);
            if (std.mem.eql(u8, cm.identifierAt(h.name), name)) {
                if (h.type_parameters.len != args.len) return null;
                return .{ .pkg = p, .cm = cm, .module = mname, .name = name, .is_enum = false, .def = @intCast(i), .args = args };
            }
        }
        for (cm.enum_defs, 0..) |d, i| {
            const h = cm.datatypeHandleAt(d.enum_handle);
            if (std.mem.eql(u8, cm.identifierAt(h.name), name)) {
                if (h.type_parameters.len != args.len) return null;
                return .{ .pkg = p, .cm = cm, .module = mname, .name = name, .is_enum = true, .def = @intCast(i), .args = args };
            }
        }
        return null;
    }

    /// The package version a module of `p` links `original` against.
    fn linked(p: *const Pkg, self_addr: *const [32]u8, original: *const [32]u8) [32]u8 {
        if (std.mem.eql(u8, self_addr, original)) return p.id;
        for (p.linkage) |l| if (std.mem.eql(u8, &l.original, original)) return l.upgraded;
        return original.*;
    }

    const LayoutError = Allocator.Error || error{ Limit, Unresolved };

    /// A field's signature token instantiated with the enclosing datatype's arguments.
    fn fromToken(r: *Resolver, d: *const Datatype, t: ff.Token) LayoutError!*const RType {
        const n = t[0];
        const out = try r.arena.create(RType);
        out.* = switch (n.tag) {
            .Bool => .bool,
            .U8 => .u8,
            .U16 => .u16,
            .U32 => .u32,
            .U64 => .u64,
            .U128 => .u128,
            .U256 => .u256,
            .Address => .address,
            .Signer => .signer,
            .Vector => .{ .vector = try r.fromToken(d, t[1..]) },
            .TypeParameter => return if (n.idx < d.args.len) d.args[n.idx] else error.Unresolved,
            .Datatype, .DatatypeInstantiation => blk: {
                const cm = d.cm;
                const h = cm.datatypeHandleAt(n.idx);
                const mh = cm.moduleHandleAt(h.module);
                const addr = &cm.address_identifiers[mh.address];
                const target = linked(d.pkg, cm.selfAddress(), addr);
                var args: []*const RType = &.{};
                if (n.tag == .DatatypeInstantiation) {
                    args = try r.arena.alloc(*const RType, n.arity);
                    var it = ff.ArgIter.init(t);
                    for (args) |*a| a.* = try r.fromToken(d, it.next().?);
                }
                const dt = (try r.datatypeAt(&target, cm.identifierAt(mh.name), cm.identifierAt(h.name), args)) orelse return error.Unresolved;
                break :blk .{ .datatype = dt };
            },
            .Reference, .MutableReference => return error.Unresolved,
        };
        return out;
    }

    fn definingId(d: *const Datatype) [32]u8 {
        for (d.pkg.origins) |o| if (std.mem.eql(u8, o.module, d.module) and std.mem.eql(u8, o.name, d.name)) return o.package;
        return d.pkg.id;
    }

    fn tagOf(r: *Resolver, t: *const RType) Allocator.Error!types.TypeTag {
        return switch (t.*) {
            .bool => .bool,
            .u8 => .u8,
            .u16 => .u16,
            .u32 => .u32,
            .u64 => .u64,
            .u128 => .u128,
            .u256 => .u256,
            .address => .address,
            .signer => .signer,
            .vector => |e| blk: {
                const x = try r.arena.create(types.TypeTag);
                x.* = try r.tagOf(e);
                break :blk .{ .vector = x };
            },
            .datatype => |*d| .{ .@"struct" = try r.structTagOf(d) },
        };
    }

    fn structTagOf(r: *Resolver, d: *const Datatype) Allocator.Error!types.StructTag {
        const args = try r.arena.alloc(types.TypeTag, d.args.len);
        for (d.args, args) |a, *o| o.* = try r.tagOf(a);
        return .{ .address = .{ .@"0" = definingId(d) }, .module = .{ .@"0" = d.module }, .name = .{ .@"0" = d.name }, .type_args = args };
    }

    /// `type_to_fully_annotated_layout_impl` with the VM's `TypeSize` accounting.
    fn layoutOf(r: *Resolver, t: *const RType, z: *TypeSize) LayoutError!Layout {
        try z.enter();
        const out: Layout = switch (t.*) {
            .bool => .bool,
            .u8 => .u8,
            .u16 => .u16,
            .u32 => .u32,
            .u64 => .u64,
            .u128 => .u128,
            .u256 => .u256,
            .address => .address,
            .signer => .signer,
            .vector => |e| blk: {
                const el = try r.arena.create(Layout);
                el.* = try r.layoutOf(e, z);
                break :blk .{ .vector = el };
            },
            .datatype => |*d| blk: {
                try z.check();
                const tag = try r.structTagOf(d);
                const cm = d.cm;
                if (d.is_enum) {
                    const def = &cm.enum_defs[d.def];
                    const vs = try r.arena.alloc(Variant, def.variants.len);
                    for (def.variants, vs, 0..) |vd, *o, vi| {
                        try z.incrNodes();
                        const fs = try r.arena.alloc(Field, vd.fields.len);
                        for (vd.fields, fs) |fd, *fo| fo.* = .{ .name = cm.identifierAt(fd.name), .layout = try r.layoutOf(try r.fromToken(d, fd.signature), z) };
                        o.* = .{ .name = cm.identifierAt(vd.variant_name), .tag = @intCast(vi), .fields = fs };
                    }
                    try z.check();
                    const e = try r.arena.create(Enum);
                    e.* = .{ .type_ = tag, .variants = vs };
                    break :blk .{ .@"enum" = e };
                }
                const def = &cm.struct_defs[d.def];
                if (def.native) return error.Unresolved;
                const fs = try r.arena.alloc(Field, def.fields.len);
                for (def.fields, fs) |fd, *fo| fo.* = .{ .name = cm.identifierAt(fd.name), .layout = try r.layoutOf(try r.fromToken(d, fd.signature), z) };
                try z.check();
                const s = try r.arena.create(Struct);
                s.* = .{ .type_ = tag, .fields = fs };
                break :blk .{ .@"struct" = s };
            },
        };
        try z.check();
        z.depth -= 1;
        return out;
    }
};

/// move-vm-runtime `TypeSize` (as src/move/vm/host.zig ports it).
const TypeSize = struct {
    lim: Limits,
    depth: u64 = 0,
    nodes: u64 = 0,
    fn check(z: *const TypeSize) error{Limit}!void {
        if (z.depth > z.lim.max_depth or z.nodes > z.lim.max_nodes) return error.Limit;
    }
    fn enter(z: *TypeSize) error{Limit}!void {
        z.depth += 1;
        z.nodes += 1;
        try z.check();
    }
    fn incrNodes(z: *TypeSize) error{Limit}!void {
        z.nodes += 1;
        if (z.nodes > z.lim.max_nodes) return error.Limit;
    }
};

/// `StructTag::from(MoveObjectType)` without allocation for the common cases.
pub fn objectStructTag(arena: Allocator, t: types.MoveObjectType) Allocator.Error!types.StructTag {
    const two: [32]u8 = comptime blk: {
        var a: [32]u8 = @splat(0);
        a[31] = 2;
        break :blk a;
    };
    const three: [32]u8 = comptime blk: {
        var a: [32]u8 = @splat(0);
        a[31] = 3;
        break :blk a;
    };
    const sui_tag: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "sui" }, .name = .{ .@"0" = "SUI" }, .type_args = &.{} } };
    const S = struct {
        fn st(addr: [32]u8, m: []const u8, n: []const u8, args: []const types.TypeTag) types.StructTag {
            return .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = m }, .name = .{ .@"0" = n }, .type_args = args };
        }
    };
    return switch (t.@"0") {
        .Other => |s| s,
        .GasCoin => S.st(two, "coin", "Coin", try arena.dupe(types.TypeTag, &.{sui_tag})),
        .StakedSui => S.st(three, "staking_pool", "StakedSui", &.{}),
        .Coin => |c| S.st(two, "coin", "Coin", try arena.dupe(types.TypeTag, &.{c})),
        .SuiBalanceAccumulatorField, .BalanceAccumulatorField => blk: {
            const inner: types.TypeTag = switch (t.@"0") {
                .BalanceAccumulatorField => |b| b,
                else => sui_tag,
            };
            const bal: types.TypeTag = .{ .@"struct" = S.st(two, "balance", "Balance", try arena.dupe(types.TypeTag, &.{inner})) };
            const key: types.TypeTag = .{ .@"struct" = S.st(two, "accumulator", "Key", try arena.dupe(types.TypeTag, &.{bal})) };
            const val: types.TypeTag = .{ .@"struct" = S.st(two, "accumulator", "U128", &.{}) };
            break :blk S.st(two, "dynamic_field", "Field", try arena.dupe(types.TypeTag, &.{ key, val }));
        },
    };
}
