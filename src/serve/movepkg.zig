//! MovePackageService on a package object: `sui_package_resolver::Package::read_from_package`
//! (module index, type origins, open signatures) and sui-rpc-api's `move_package_service`
//! conversions (`convert_module`, `convert_datatype`, `convert_function`), written as prost bytes.
//! The resolver walks BTreeMaps keyed by `String`, i.e. byte-lexicographic order; the BCS map the
//! object carries is in serialized-key order, so names are re-sorted here.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const mf = @import("move_format");
const proto = @import("proto.zig");
const typestr = @import("typestr.zig");

const ff = mf.file_format;

/// `error.Resolver`: `Package.message` holds the INTERNAL text (sui-package-resolver's Display).
pub const Error = error{ Resolver, NotAPackage } || proto.Error || bcs.DecodeError || Allocator.Error;

const Named = struct { name: []const u8, defining: [32]u8 = @splat(0), idx: u16 };

const Mod = struct {
    name: []const u8,
    cm: ff.CompiledModule,
    structs: []const Named, // sorted by name
    enums: []const Named,
    funcs: []const Named, // sorted by name; later definitions of a name win
};

pub const Package = struct {
    id: [32]u8,
    version: u64,
    original_id: [32]u8,
    mods: []const Mod, // sorted by name
    message: []const u8 = "",
};

fn lessName(_: void, a: Named, b: Named) bool {
    return std.mem.order(u8, a.name, b.name) == .lt;
}
fn lessEntry(comptime E: type) fn (void, E, E) bool {
    return struct {
        fn lt(_: void, a: E, b: E) bool {
            return std.mem.order(u8, a.key.@"0", b.key.@"0") == .lt;
        }
    }.lt;
}

fn hexId(arena: Allocator, a: *const [32]u8) Allocator.Error![]const u8 {
    const buf = try arena.alloc(u8, 66);
    var o: typestr.Out = .{ .buf = buf };
    o.address(a) catch unreachable;
    return o.str();
}

/// Parses BCS(Object) and indexes the package like `Package::read_from_package`.
///
/// The result owns everything it points at: `raw` is copied into `arena` first, because the BCS
/// decode and the module deserializer borrow names, identifiers and signatures from their input.
/// A Package lives in the service's package cache past the request whose snapshot read `raw`;
/// with borrowed bytes, a retention prune that swept the package's segment left every later
/// GetPackage rendering from an unmapped segment (SIGSEGV in writePackage, train/4 shadow rig).
pub fn read(arena: Allocator, raw: []const u8, out: *Package) Error!void {
    const own = try arena.dupe(u8, raw);
    const obj = try bcs.decode(types.Object, arena, own);
    const mp = switch (obj.data) {
        .Package => |p| p,
        .Move => return error.NotAPackage,
    };
    const id = mp.id.@"0".@"0";
    // module_map as a BTreeMap<String, _>: byte order of the names
    const Ent = @TypeOf(mp.module_map.entries[0]);
    const sorted = try arena.dupe(Ent, mp.module_map.entries);
    std.mem.sort(Ent, sorted, {}, lessEntry(Ent));
    // Module::read takes each datatype's origin out of the module's map (`origins.remove`): a
    // second struct or enum of the same name (deserializable, never verified) is NoTypeOrigin.
    var origins: std.StringHashMapUnmanaged([32]u8) = .empty;
    for (mp.type_origin_table) |t| {
        const key = try std.fmt.allocPrint(arena, "{s}\x00{s}", .{ t.module_name.@"0", t.datatype_name.@"0" });
        try origins.put(arena, key, t.package.@"0".@"0");
    }
    out.* = .{ .id = id, .version = mp.version.@"0", .original_id = id, .mods = &.{} };
    const pkg = out;
    var mods = try std.ArrayList(Mod).initCapacity(arena, sorted.len);
    for (sorted) |e| {
        const cfg: mf.BinaryConfig = .{};
        const res = try mf.deserialize(arena, e.value, &cfg);
        const cm = switch (res) {
            .ok => |m| m,
            .err => {
                pkg.message = "deserialization error";
                return error.Resolver;
            },
        };
        const mname = e.key.@"0";
        var structs = try std.ArrayList(Named).initCapacity(arena, cm.struct_defs.len);
        for (cm.struct_defs, 0..) |d, i| {
            const name = cm.identifierAt(cm.datatypeHandleAt(d.struct_handle).name);
            const key = try std.fmt.allocPrint(arena, "{s}\x00{s}", .{ mname, name });
            const def = (origins.fetchRemove(key) orelse return noOrigin(arena, pkg, mname, name)).value;
            try structs.append(arena, .{ .name = name, .defining = def, .idx = @intCast(i) });
        }
        var enums = try std.ArrayList(Named).initCapacity(arena, cm.enum_defs.len);
        for (cm.enum_defs, 0..) |d, i| {
            const name = cm.identifierAt(cm.datatypeHandleAt(d.enum_handle).name);
            const key = try std.fmt.allocPrint(arena, "{s}\x00{s}", .{ mname, name });
            const def = (origins.fetchRemove(key) orelse return noOrigin(arena, pkg, mname, name)).value;
            try enums.append(arena, .{ .name = name, .defining = def, .idx = @intCast(i) });
        }
        var funcs = try std.ArrayList(Named).initCapacity(arena, cm.function_defs.len);
        for (cm.function_defs, 0..) |d, i| {
            const name = cm.identifierAt(cm.functionHandleAt(d.function).name);
            funcs.appendAssumeCapacity(.{ .name = name, .idx = @intCast(i) });
        }
        std.mem.sort(Named, structs.items, {}, lessName);
        std.mem.sort(Named, enums.items, {}, lessName);
        // BTreeMap insert: a repeated name replaces the earlier index. A stable sort keeps
        // definition order within a name; the last of each run wins (O(n log n), not O(n^2)).
        std.sort.block(Named, funcs.items, {}, lessName);
        var nf: usize = 0;
        for (funcs.items, 0..) |f, i| {
            if (i + 1 < funcs.items.len and std.mem.eql(u8, funcs.items[i + 1].name, f.name)) continue;
            funcs.items[nf] = f;
            nf += 1;
        }
        funcs.items.len = nf;
        try mods.append(arena, .{ .name = mname, .cm = cm, .structs = structs.items, .enums = enums.items, .funcs = funcs.items });
    }
    if (mods.items.len == 0) {
        pkg.message = try std.fmt.allocPrint(arena, "Package has no modules: {s}", .{try hexId(arena, &id)});
        return error.Resolver;
    }
    pkg.mods = mods.items;
    pkg.original_id = if (pkg.version == 1) id else mods.items[0].cm.selfAddress().*;
}

fn noOrigin(arena: Allocator, pkg: *Package, mod_name: []const u8, name: []const u8) Error {
    pkg.message = std.fmt.allocPrint(arena, "No origin package found for {s}::{s}::{s}", .{ try hexId(arena, &pkg.id), mod_name, name }) catch return error.OutOfMemory;
    return error.Resolver;
}

// ---- message writers (field numbers: sui/rpc/v2/move_package.proto) ----

fn abilityList(set: ff.AbilitySet, buf: *[4]u64) []const u64 {
    var n: usize = 0;
    inline for (.{ .{ ff.Ability.Copy, 1 }, .{ ff.Ability.Drop, 2 }, .{ ff.Ability.Store, 3 }, .{ ff.Ability.Key, 4 } }) |p| {
        if (set.has(p[0])) {
            buf[n] = p[1];
            n += 1;
        }
    }
    return buf[0..n];
}

fn writeTypeParam(w: *proto.Writer, field: u32, constraints: ff.AbilitySet, phantom: ?bool) proto.Error!void {
    const m = try w.begin(field, 8);
    var ab: [4]u64 = undefined;
    try w.packedUints(1, abilityList(constraints, &ab));
    if (phantom) |p| try w.uint(2, @intFromBool(p));
    try w.end(m);
}

/// OpenSignatureBody.read + convert_open_signature_body.
fn writeBody(arena: Allocator, w: *proto.Writer, field: u32, cm: *const ff.CompiledModule, t: ff.Token, pkg: *Package) Error!void {
    const m = try w.begin(field, 48);
    const n = t[0];
    switch (n.tag) {
        .Signer => {
            pkg.message = "Unexpected type: 'signer'.";
            return error.Resolver;
        },
        .Reference, .MutableReference => {
            pkg.message = "Unexpected reference type.";
            return error.Resolver;
        },
        .Address => try w.uint(1, 1),
        .Bool => try w.uint(1, 2),
        .U8 => try w.uint(1, 3),
        .U16 => try w.uint(1, 4),
        .U32 => try w.uint(1, 5),
        .U64 => try w.uint(1, 6),
        .U128 => try w.uint(1, 7),
        .U256 => try w.uint(1, 8),
        .Vector => {
            try w.uint(1, 9);
            try writeBody(arena, w, 3, cm, ff.inner(t), pkg);
        },
        .Datatype, .DatatypeInstantiation => {
            try w.uint(1, 10);
            const sh = cm.datatypeHandleAt(n.idx);
            const mh = cm.moduleHandleAt(sh.module);
            const buf = try arena.alloc(u8, 66 + cm.identifierAt(mh.name).len + cm.identifierAt(sh.name).len + 4);
            var o: typestr.Out = .{ .buf = buf };
            o.address(&cm.address_identifiers[mh.address]) catch unreachable;
            const tail = std.fmt.bufPrint(buf[o.len..], "::{s}::{s}", .{ cm.identifierAt(mh.name), cm.identifierAt(sh.name) }) catch unreachable;
            try w.string(2, buf[0 .. o.len + tail.len]);
            if (n.tag == .DatatypeInstantiation) {
                var it = ff.ArgIter.init(t);
                while (it.next()) |a| try writeBody(arena, w, 3, cm, a, pkg);
            }
        },
        .TypeParameter => {
            try w.uint(1, 11);
            try w.uint(4, n.idx);
        },
    }
    try w.end(m);
}

fn writeOpenSig(arena: Allocator, w: *proto.Writer, field: u32, cm: *const ff.CompiledModule, t: ff.Token, pkg: *Package) Error!void {
    const m = try w.begin(field, 48);
    switch (t[0].tag) {
        .Reference => {
            try w.uint(1, 1);
            try writeBody(arena, w, 2, cm, ff.inner(t), pkg);
        },
        .MutableReference => {
            try w.uint(1, 2);
            try writeBody(arena, w, 2, cm, ff.inner(t), pkg);
        },
        else => try writeBody(arena, w, 2, cm, t, pkg),
    }
    try w.end(m);
}

fn writeField(arena: Allocator, w: *proto.Writer, field: u32, cm: *const ff.CompiledModule, f: ff.FieldDefinition, pos: usize, pkg: *Package) Error!void {
    const m = try w.begin(field, 64);
    try w.string(1, cm.identifierAt(f.name));
    try w.uint(2, pos);
    try writeBody(arena, w, 3, cm, f.signature, pkg);
    try w.end(m);
}

fn find(list: []const Named, name: []const u8) ?Named {
    var lo: usize = 0;
    var hi: usize = list.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        switch (std.mem.order(u8, list[mid].name, name)) {
            .eq => return list[mid],
            .lt => lo = mid + 1,
            .gt => hi = mid,
        }
    }
    return null;
}

/// convert_datatype (data_def of struct `s` or enum `e`).
fn writeDatatype(arena: Allocator, w: *proto.Writer, field: u32, pkg: *Package, md: *const Mod, d: Named, is_enum: bool) Error!void {
    const cm = &md.cm;
    const m = try w.begin(field, 256);
    const handle = if (is_enum) cm.datatypeHandleAt(cm.enum_defs[d.idx].enum_handle) else cm.datatypeHandleAt(cm.struct_defs[d.idx].struct_handle);
    const pid = try hexId(arena, &pkg.id);
    try w.string(1, try std.fmt.allocPrint(arena, "{s}::{s}::{s}", .{ pid, md.name, d.name }));
    try w.string(2, try hexId(arena, &d.defining));
    try w.string(3, md.name);
    try w.string(4, d.name);
    var ab: [4]u64 = undefined;
    try w.packedUints(5, abilityList(handle.abilities, &ab));
    for (handle.type_parameters) |tp| try writeTypeParam(w, 6, tp.constraints, tp.is_phantom);
    try w.uint(7, if (is_enum) 2 else 1);
    if (is_enum) {
        for (cm.enum_defs[d.idx].variants, 0..) |v, vi| {
            const vm = try w.begin(9, 64);
            try w.string(1, cm.identifierAt(v.variant_name));
            try w.uint(2, vi);
            for (v.fields, 0..) |f, fi| try writeField(arena, w, 3, cm, f, fi, pkg);
            try w.end(vm);
        }
    } else {
        const sd = cm.struct_defs[d.idx];
        if (!sd.native) for (sd.fields, 0..) |f, fi| try writeField(arena, w, 8, cm, f, fi, pkg);
    }
    try w.end(m);
}

/// convert_function (function_def of the definition `d`).
fn writeFunction(arena: Allocator, w: *proto.Writer, field: u32, pkg: *Package, md: *const Mod, d: Named) Error!void {
    const cm = &md.cm;
    const fd = cm.function_defs[d.idx];
    const fh = cm.functionHandleAt(fd.function);
    const m = try w.begin(field, 128);
    try w.string(1, d.name);
    try w.uint(5, switch (fd.visibility) {
        .Private => 1,
        .Public => 2,
        .Friend => 3,
    });
    try w.uint(6, @intFromBool(fd.is_entry));
    for (fh.type_parameters) |c| try writeTypeParam(w, 7, c, null);
    for (cm.signatureAt(fh.parameters)) |t| try writeOpenSig(arena, w, 8, cm, t, pkg);
    for (cm.signatureAt(fh.return_)) |t| try writeOpenSig(arena, w, 9, cm, t, pkg);
    try w.end(m);
}

const Item = struct { Named, bool };

fn datatypeNames(arena: Allocator, md: *const Mod) Allocator.Error![]const Item {
    const all = try arena.alloc(Item, md.structs.len + md.enums.len);
    for (md.structs, 0..) |s, i| all[i] = .{ s, false };
    for (md.enums, 0..) |e, i| all[md.structs.len + i] = .{ e, true };
    std.mem.sort(Item, all, {}, struct {
        fn lt(_: void, a: Item, b: Item) bool {
            return std.mem.order(u8, a[0].name, b[0].name) == .lt;
        }
    }.lt);
    return all;
}

/// `GetPackageResponse { package = 1 }`.
pub fn writePackage(arena: Allocator, w: *proto.Writer, pkg: *Package) Error!void {
    const outer = try w.begin(1, 1024);
    try w.string(1, try hexId(arena, &pkg.id));
    try w.string(2, try hexId(arena, &pkg.original_id));
    try w.uint(3, pkg.version);
    for (pkg.mods) |*md| {
        const mm = try w.begin(4, 512);
        try w.string(1, md.name);
        for (try datatypeNames(arena, md)) |d| try writeDatatype(arena, w, 3, pkg, md, d[0], d[1]);
        for (md.funcs) |f| try writeFunction(arena, w, 4, pkg, md, f);
        try w.end(mm);
    }
    try w.end(outer);
}

fn module(arena: Allocator, pkg: *Package, name: []const u8) Error!*const Mod {
    for (pkg.mods) |*md| if (std.mem.eql(u8, md.name, name)) return md;
    pkg.message = try std.fmt.allocPrint(arena, "Module not found: {s}::{s}", .{ try hexId(arena, &pkg.id), name });
    return error.Resolver;
}

/// `GetDatatypeResponse { datatype = 1 }`.
pub fn writeDatatypeResponse(arena: Allocator, w: *proto.Writer, pkg: *Package, module_name: []const u8, name: []const u8) Error!void {
    const md = try module(arena, pkg, module_name);
    const found: ?Item = if (find(md.structs, name)) |s| .{ s, false } else if (find(md.enums, name)) |e| .{ e, true } else null;
    const d = found orelse {
        pkg.message = try std.fmt.allocPrint(arena, "Datatype '{s}' not found", .{name});
        return error.Resolver;
    };
    try writeDatatype(arena, w, 1, pkg, md, d[0], d[1]);
}

/// `GetFunctionResponse { function = 1 }`.
pub fn writeFunctionResponse(arena: Allocator, w: *proto.Writer, pkg: *Package, module_name: []const u8, name: []const u8) Error!void {
    const md = try module(arena, pkg, module_name);
    const f = find(md.funcs, name) orelse {
        pkg.message = try std.fmt.allocPrint(arena, "Function not found: {s}", .{name});
        return error.Resolver;
    };
    try writeFunction(arena, w, 1, pkg, md, f);
}
