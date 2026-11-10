//! Storage-layout advisor: from a package's bytecode, the size of every struct
//! (fixed bytes and which fields are variable), and advice about smaller fields, inline versus
//! dynamic fields, and deletes that earn the storage rebate.
//!
//! Everything here is static and exact where sizes are fixed (BCS has no padding). Advice that
//! rests on a name heuristic says so (`heuristic: true`). Measured on-chain sizes come from
//! `deepwave-move gas-report --table types` (avg/max size per type).
const std = @import("std");
const common = @import("common.zig");
const mf = @import("move_format");

const Allocator = std.mem.Allocator;
const ff = common.ff;
const Id = common.Id;

/// Sui's storage price: 76 MIST per unit, 100 units per byte (protocol config `storage_gas_price`, `obj_data_cost_refundable`).
pub const mist_per_byte: u64 = 7600;

pub const Size = struct {
    fixed: u64 = 0,
    /// Some part has a size that depends on the value (vectors, strings, tables' contents do not count: they live in dynamic fields).
    variable: bool = false,
};

pub const Finding = struct {
    kind: []const u8,
    severity: []const u8,
    module: []const u8,
    datatype: []const u8 = "",
    field: []const u8 = "",
    message: []const u8,
    /// Bytes saved per object instance, 0 when it depends on the data.
    saves_bytes: u64 = 0,
    heuristic: bool = false,
};

pub const FieldInfo = struct { name: []const u8, ty: []const u8, size: Size };

pub const StructInfo = struct {
    module: []const u8,
    name: []const u8,
    abilities: u8,
    fields: []const FieldInfo,
    size: Size,
    /// key structs: bytes of the stored object besides the contents (type tag, version, owner, previous tx, rebate).
    object_overhead: u64 = 0,
    has_unpack: bool = false,
};

pub const ModuleInfo = struct {
    name: []const u8,
    bytes: u64,
    functions: u32,
    code_bytes: u64,
    constant_bytes: u64,
    df_adds: u32 = 0,
    df_removes: u32 = 0,
};

pub const Analysis = struct {
    modules: std.ArrayList(ModuleInfo) = .empty,
    structs: std.ArrayList(StructInfo) = .empty,
    findings: std.ArrayList(Finding) = .empty,
};

fn isFramework(a: *const Id, n: u8) bool {
    for (a[0..31]) |b| if (b != 0) return false;
    return a[31] == n;
}

const Qualified = struct { addr: *const Id, module: []const u8, name: []const u8 };

fn datatypeName(cm: *const ff.CompiledModule, h: u16) Qualified {
    const dh = cm.datatypeHandleAt(h);
    const mh = cm.moduleHandleAt(dh.module);
    return .{ .addr = &cm.address_identifiers[mh.address], .module = cm.identifierAt(mh.name), .name = cm.identifierAt(dh.name) };
}

const SizeCtx = struct { cm: *const ff.CompiledModule, depth: u32 = 0 };

fn tokenSize(c: SizeCtx, tok: ff.Token) Size {
    if (c.depth > 8) return .{ .variable = true };
    const n = tok[0];
    switch (n.tag) {
        .Bool, .U8 => return .{ .fixed = 1 },
        .U16 => return .{ .fixed = 2 },
        .U32 => return .{ .fixed = 4 },
        .U64 => return .{ .fixed = 8 },
        .U128 => return .{ .fixed = 16 },
        .U256, .Address, .Signer => return .{ .fixed = 32 },
        .Vector => return .{ .fixed = 1, .variable = true },
        .Reference, .MutableReference, .TypeParameter => return .{ .variable = true },
        .Datatype, .DatatypeInstantiation => {
            const q = datatypeName(c.cm, n.idx);
            if (isFramework(q.addr, 2)) {
                const eq = std.mem.eql;
                if (eq(u8, q.module, "object") and (eq(u8, q.name, "UID") or eq(u8, q.name, "ID"))) return .{ .fixed = 32 };
                if (eq(u8, q.module, "balance") and eq(u8, q.name, "Balance")) return .{ .fixed = 8 };
                if (eq(u8, q.module, "coin") and eq(u8, q.name, "Coin")) return .{ .fixed = 40 };
                // Table family: UID + size
                if ((eq(u8, q.module, "table") or eq(u8, q.module, "object_table") or eq(u8, q.module, "bag") or eq(u8, q.module, "object_bag") or eq(u8, q.module, "linked_table"))) {
                    if (eq(u8, q.module, "linked_table")) return .{ .fixed = 32 + 8 + 2, .variable = true }; // UID + size + head/tail options
                    return .{ .fixed = 40 };
                }
                if (eq(u8, q.module, "table_vec") and eq(u8, q.name, "TableVec")) return .{ .fixed = 40 };
                if (eq(u8, q.module, "versioned") and eq(u8, q.name, "Versioned")) return .{ .fixed = 40 };
                if (eq(u8, q.module, "vec_map") or eq(u8, q.module, "vec_set") or eq(u8, q.module, "url")) return .{ .fixed = 1, .variable = true };
            }
            if (isFramework(q.addr, 1)) {
                if (std.mem.eql(u8, q.module, "string") or std.mem.eql(u8, q.module, "ascii")) return .{ .fixed = 1, .variable = true };
                if (std.mem.eql(u8, q.module, "option") and std.mem.eql(u8, q.name, "Option")) {
                    return .{ .fixed = 1, .variable = true };
                }
            }
            // a struct of this module: sum of its fields
            const dh = c.cm.datatypeHandleAt(n.idx);
            if (c.cm.isSelfHandle(dh.module)) {
                for (c.cm.struct_defs) |sd| {
                    if (sd.struct_handle == n.idx) {
                        var total: Size = .{};
                        for (sd.fields) |f| {
                            const fs = tokenSize(.{ .cm = c.cm, .depth = c.depth + 1 }, f.signature);
                            total.fixed += fs.fixed;
                            total.variable = total.variable or fs.variable;
                        }
                        return total;
                    }
                }
                for (c.cm.enum_defs) |ed| if (ed.enum_handle == n.idx) return .{ .fixed = 1, .variable = true };
            }
            return .{ .variable = true };
        },
    }
}

fn tokenText(arena: Allocator, cm: *const ff.CompiledModule, tok: ff.Token, out: *std.ArrayList(u8)) Allocator.Error!void {
    const n = tok[0];
    switch (n.tag) {
        .Bool => try out.appendSlice(arena, "bool"),
        .U8 => try out.appendSlice(arena, "u8"),
        .U16 => try out.appendSlice(arena, "u16"),
        .U32 => try out.appendSlice(arena, "u32"),
        .U64 => try out.appendSlice(arena, "u64"),
        .U128 => try out.appendSlice(arena, "u128"),
        .U256 => try out.appendSlice(arena, "u256"),
        .Address => try out.appendSlice(arena, "address"),
        .Signer => try out.appendSlice(arena, "signer"),
        .Vector => {
            try out.appendSlice(arena, "vector<");
            try tokenText(arena, cm, ff.inner(tok), out);
            try out.append(arena, '>');
        },
        .Reference, .MutableReference => {
            try out.appendSlice(arena, if (n.tag == .Reference) "&" else "&mut ");
            try tokenText(arena, cm, ff.inner(tok), out);
        },
        .TypeParameter => try out.print(arena, "T{d}", .{n.idx}),
        .Datatype, .DatatypeInstantiation => {
            const q = datatypeName(cm, n.idx);
            if (isFramework(q.addr, 1) or isFramework(q.addr, 2)) {
                try out.print(arena, "0x{x}::{s}::{s}", .{ q.addr[31], q.module, q.name });
            } else {
                try out.print(arena, "{s}::{s}", .{ q.module, q.name });
            }
            if (n.tag == .DatatypeInstantiation) {
                try out.append(arena, '<');
                var it = ff.ArgIter.init(tok);
                var first = true;
                while (it.next()) |a| {
                    if (!first) try out.appendSlice(arena, ", ");
                    first = false;
                    try tokenText(arena, cm, a, out);
                }
                try out.append(arena, '>');
            }
        },
    }
}

fn containsAny(name: []const u8, needles: []const []const u8) bool {
    for (needles) |n| if (std.ascii.findIgnoreCase(name, n) != null) return true;
    return false;
}

const small_names = [_][]const u8{ "bps", "decimals", "percent", "level", "kind", "status", "tier", "flag", "version", "precision", "fee_rate", "rarity", "type_id", "state" };

const CallTarget = struct { addr: *const Id, module: []const u8, name: []const u8 };

fn callTarget(cm: *const ff.CompiledModule, ins: ff.Instr) ?CallTarget {
    const fh_idx: u16 = switch (ins.op) {
        .Call => ins.idx,
        .CallGeneric => cm.function_instantiations[ins.idx].handle,
        else => return null,
    };
    const fh = cm.functionHandleAt(fh_idx);
    const mh = cm.moduleHandleAt(fh.module);
    return .{ .addr = &cm.address_identifiers[mh.address], .module = cm.identifierAt(mh.name), .name = cm.identifierAt(fh.name) };
}

const container_modules = [_][]const u8{ "dynamic_field", "dynamic_object_field", "table", "object_table", "bag", "object_bag", "linked_table", "table_vec" };
const add_fns = [_][]const u8{ "add", "push_back", "push_front" };
const remove_fns = [_][]const u8{ "remove", "pop_back", "pop_front", "destroy_empty", "remove_if_exists" };

fn isIn(list: []const []const u8, s: []const u8) bool {
    for (list) |x| if (std.mem.eql(u8, x, s)) return true;
    return false;
}

/// Analyses one module into `a`. All strings live in `arena`.
pub fn analyzeModule(arena: Allocator, a: *Analysis, name: []const u8, cm: *const ff.CompiledModule, raw_len: usize) !void {
    var mi: ModuleInfo = .{ .name = name, .bytes = raw_len, .functions = @intCast(cm.function_defs.len), .code_bytes = 0, .constant_bytes = 0 };
    for (cm.constant_pool) |c| mi.constant_bytes += c.data.len;
    // unpack inventory and call-site inventory
    var unpacked = try arena.alloc(bool, cm.struct_defs.len);
    @memset(unpacked, false);
    var deletes_uid = false;
    for (cm.function_defs) |fd| {
        const cu = fd.code orelse continue;
        mi.code_bytes += cu.code.len * 2; // rough: average 2 bytes per instruction in the binary
        for (cu.code) |ins| {
            switch (ins.op) {
                .Unpack => if (ins.idx < unpacked.len) {
                    unpacked[ins.idx] = true;
                },
                .UnpackGeneric => if (ins.idx < cm.struct_def_instantiations.len) {
                    const d = cm.struct_def_instantiations[ins.idx].def;
                    if (d < unpacked.len) unpacked[d] = true;
                },
                else => {},
            }
            if (callTarget(cm, ins)) |t| {
                if (isFramework(t.addr, 2)) {
                    if (std.mem.eql(u8, t.module, "object") and std.mem.eql(u8, t.name, "delete")) deletes_uid = true;
                    if (isIn(&container_modules, t.module)) {
                        if (isIn(&add_fns, t.name)) mi.df_adds += 1;
                        if (isIn(&remove_fns, t.name)) mi.df_removes += 1;
                    }
                }
            }
        }
    }
    try a.modules.append(arena, mi);

    if (mi.df_adds > 0 and mi.df_removes == 0) {
        try a.findings.append(arena, .{
            .kind = "dynamic-field-never-removed",
            .severity = "warn",
            .module = name,
            .message = try std.fmt.allocPrint(arena, "{d} call site(s) add dynamic fields or table entries and none removes one: every entry keeps paying storage forever and never earns the rebate; add a remove path or a removal-by-owner function", .{mi.df_adds}),
        });
    }

    for (cm.struct_defs, 0..) |sd, si| {
        const dh = cm.datatypeHandleAt(sd.struct_handle);
        const sname = cm.identifierAt(dh.name);
        if (sd.native) continue;
        var fields: std.ArrayList(FieldInfo) = .empty;
        var total: Size = .{};
        var n_bool: u32 = 0;
        const is_key = dh.abilities.hasKey();
        for (sd.fields) |f| {
            const fs = tokenSize(.{ .cm = cm }, f.signature);
            total.fixed += fs.fixed;
            total.variable = total.variable or fs.variable;
            var tt: std.ArrayList(u8) = .empty;
            try tokenText(arena, cm, f.signature, &tt);
            const fname = cm.identifierAt(f.name);
            try fields.append(arena, .{ .name = fname, .ty = tt.items, .size = fs });
            const t0 = f.signature[0];
            if (t0.tag == .Bool) n_bool += 1;

            // field-level advice
            if (t0.tag == .U64 or t0.tag == .U128 or t0.tag == .U256) {
                if (containsAny(fname, &small_names)) {
                    const cur: u64 = fs.fixed;
                    const to: u64 = if (containsAny(fname, &.{ "bps", "decimals", "percent", "level", "kind", "status", "tier", "flag", "state", "rarity" })) 1 else 4;
                    try a.findings.append(arena, .{ .kind = "narrow-integer", .severity = "info", .module = name, .datatype = sname, .field = fname, .heuristic = true, .saves_bytes = cur - to, .message = try std.fmt.allocPrint(arena, "field name suggests a small range; a {s} costs {d} byte(s) instead of {d} (check the value range first)", .{ if (to == 1) "u8" else "u32", to, cur }) });
                }
            }
            if (t0.tag == .U256) {
                try a.findings.append(arena, .{ .kind = "wide-integer", .severity = "info", .module = name, .datatype = sname, .field = fname, .heuristic = true, .saves_bytes = 16, .message = "u256 takes 32 bytes; if the value fits in u128 (or u64) the field can be 16 (8) bytes" });
            }
            if (t0.tag == .Vector and is_key) {
                const inner = ff.inner(f.signature);
                const elem_fixed = tokenSize(.{ .cm = cm }, inner);
                const elem_is_u8 = inner[0].tag == .U8;
                if (!elem_is_u8) {
                    try a.findings.append(arena, .{
                        .kind = "inline-collection",
                        .severity = "warn",
                        .module = name,
                        .datatype = sname,
                        .field = fname,
                        .message = try std.fmt.allocPrint(arena, "inline vector of {s}elements on an object: the whole object is rewritten and re-priced whenever it changes, and it grows with the data; if it can grow past a few dozen entries use a Table / ObjectTable / dynamic field per entry (each entry then pays only for itself and earns its own rebate on removal)", .{if (elem_fixed.fixed > 0 and !elem_fixed.variable) "fixed-size " else ""}),
                    });
                }
            }
            if (f.signature[0].tag == .Datatype or f.signature[0].tag == .DatatypeInstantiation) {
                const q = datatypeName(cm, f.signature[0].idx);
                if (isFramework(q.addr, 2) and (std.mem.eql(u8, q.module, "vec_map") or std.mem.eql(u8, q.module, "vec_set")) and is_key) {
                    try a.findings.append(arena, .{ .kind = "inline-collection", .severity = "warn", .module = name, .datatype = sname, .field = fname, .message = "VecMap/VecSet is an inline sorted vector: lookups are linear and the object grows with it; use a Table or dynamic fields if it can grow large" });
                }
                if (isFramework(q.addr, 1) and std.mem.eql(u8, q.module, "ascii") and std.mem.eql(u8, q.name, "String")) {
                    // nothing: strings are as small as vector<u8>
                }
            }
        }
        if (n_bool >= 2) {
            try a.findings.append(arena, .{ .kind = "packable-bools", .severity = "info", .module = name, .datatype = sname, .saves_bytes = (n_bool - 1) * 1, .message = try std.fmt.allocPrint(arena, "{d} bool fields take {d} bytes; one u8 (or u16/u32 for more) bit field takes 1 ({d} bytes saved per object, at the cost of mask code)", .{ n_bool, n_bool, n_bool - 1 }) });
        }

        var overhead: u64 = 0;
        if (is_key) {
            const mh = cm.moduleHandleAt(dh.module);
            _ = mh;
            // Sui's Object::object_size_for_gas_metering: owner 40 + previous tx 32 + rebate 8 +
            // BCS type tag (enum tag 1 + address 32 + module and name strings with uleb lengths +
            // type params length 1) + has_public_transfer 1 + version 8; the contents length is not counted.
            const mname = cm.selfName();
            overhead = 40 + 32 + 8 + (1 + 32 + ulebLen(mname.len) + mname.len + ulebLen(sname.len) + sname.len + 1) + 1 + 8;
        }
        const has_unpack = si < unpacked.len and unpacked[si];
        try a.structs.append(arena, .{ .module = name, .name = sname, .abilities = dh.abilities.bits, .fields = fields.items, .size = total, .object_overhead = overhead, .has_unpack = has_unpack });

        if (is_key and !has_unpack) {
            try a.findings.append(arena, .{ .kind = "no-delete-path", .severity = "warn", .module = name, .datatype = sname, .message = "key struct is never unpacked in its module, so no function can delete an object of this type: its storage is never rebated. Add a delete function (unpack, object::delete the UID) so users can reclaim the rebate" });
        }
        if (is_key and has_unpack and !deletes_uid) {
            try a.findings.append(arena, .{ .kind = "no-object-delete", .severity = "info", .module = name, .datatype = sname, .message = "this module unpacks the type but never calls object::delete" });
        }
        if (!is_key and !dh.abilities.hasStore() and !dh.abilities.hasDrop() and !dh.abilities.hasCopy()) {
            // hot potato: nothing to advise
        }
    }
}

pub fn writeJson(w: *std.Io.Writer, a: *const Analysis, pkg_hex: []const u8) !void {
    var j: common.Json = .{ .w = w };
    try j.beginObj();
    try j.str("package", pkg_hex);
    try j.int("mist_per_byte", mist_per_byte);
    try j.arrIn("modules");
    for (a.modules.items) |m| {
        try j.beginObj();
        try j.str("name", m.name);
        try j.int("bytes", m.bytes);
        try j.int("functions", m.functions);
        try j.int("code_bytes_estimate", m.code_bytes);
        try j.int("constant_bytes", m.constant_bytes);
        try j.int("dynamic_field_adds", m.df_adds);
        try j.int("dynamic_field_removes", m.df_removes);
        try j.int("publish_storage_mist", m.bytes * mist_per_byte);
        try j.endObj();
    }
    try j.endArr();
    try j.arrIn("structs");
    for (a.structs.items) |s| {
        try j.beginObj();
        try j.str("module", s.module);
        try j.str("name", s.name);
        try j.int("abilities", s.abilities);
        try j.int("fixed_bytes", s.size.fixed);
        try j.boolean("variable", s.size.variable);
        try j.boolean("key", s.abilities & 8 != 0);
        if (s.abilities & 8 != 0) {
            try j.int("object_overhead_bytes", s.object_overhead);
            try j.int("min_storage_mist", (s.object_overhead + s.size.fixed) * mist_per_byte);
            try j.boolean("deletable", s.has_unpack);
        }
        try j.arrIn("fields");
        for (s.fields) |f| {
            try j.beginObj();
            try j.str("name", f.name);
            try j.str("type", f.ty);
            try j.int("fixed_bytes", f.size.fixed);
            try j.boolean("variable", f.size.variable);
            try j.endObj();
        }
        try j.endArr();
        try j.endObj();
    }
    try j.endArr();
    try j.arrIn("findings");
    for (a.findings.items) |f| {
        try j.beginObj();
        try j.str("kind", f.kind);
        try j.str("severity", f.severity);
        try j.str("module", f.module);
        if (f.datatype.len > 0) try j.str("struct", f.datatype);
        if (f.field.len > 0) try j.str("field", f.field);
        try j.str("message", f.message);
        if (f.saves_bytes > 0) {
            try j.int("saves_bytes_per_object", f.saves_bytes);
            try j.int("saves_mist_per_object", f.saves_bytes * mist_per_byte);
        }
        try j.boolean("heuristic", f.heuristic);
        try j.endObj();
    }
    try j.endArr();
    try j.endObj();
    try w.writeByte('\n');
}

pub fn writeText(w: *std.Io.Writer, a: *const Analysis, pkg_hex: []const u8) !void {
    try w.print("package {s}\n", .{pkg_hex});
    for (a.modules.items) |m| try w.print("  module {s}: {d} bytes ({d} MIST to publish), {d} functions, {d} constant bytes, dynamic-field adds {d} / removes {d}\n", .{ m.name, m.bytes, m.bytes * mist_per_byte, m.functions, m.constant_bytes, m.df_adds, m.df_removes });
    for (a.structs.items) |s| {
        try w.print("  struct {s}::{s}{s}: {d} fixed bytes{s}\n", .{ s.module, s.name, if (s.abilities & 8 != 0) " (key)" else "", s.size.fixed, if (s.size.variable) " + variable parts" else "" });
        for (s.fields) |f| try w.print("      {s}: {s} = {d}{s}\n", .{ f.name, f.ty, f.size.fixed, if (f.size.variable) "+" else "" });
    }
    for (a.findings.items) |f| {
        try w.print("[{s}] {s} {s}", .{ f.severity, f.kind, f.module });
        if (f.datatype.len > 0) try w.print("::{s}", .{f.datatype});
        if (f.field.len > 0) try w.print(".{s}", .{f.field});
        try w.print(": {s}", .{f.message});
        if (f.saves_bytes > 0) try w.print(" (saves {d} bytes = {d} MIST per object)", .{ f.saves_bytes, f.saves_bytes * mist_per_byte });
        try w.writeByte('\n');
    }
}

fn ulebLen(n: usize) u64 {
    var v = n;
    var l: u64 = 1;
    while (v >= 0x80) : (v >>= 7) l += 1;
    return l;
}

pub fn run(ctx: *common.Ctx) !u8 {
    const arena = ctx.arena;
    var a: Analysis = .{};
    var pkg_hex: []const u8 = "";
    const only = ctx.opts.get("--module");
    if (ctx.opts.get("--module-file")) |path| {
        const raw = try std.Io.Dir.cwd().readFileAlloc(ctx.io, path, arena, .limited(16 << 20));
        const res = try mf.deserialize(arena, raw, &.{});
        switch (res) {
            .ok => |*m| {
                const mm = m.*;
                try analyzeModule(arena, &a, mm.selfName(), &mm, raw.len);
            },
            .err => return error.BadModule,
        }
        pkg_hex = path;
    } else {
        const dir = ctx.opts.get("--dir") orelse return error.MissingDir;
        const pid = try common.parseId(ctx.opts.get("--package") orelse return error.MissingPackage);
        var o = try common.openNode(ctx.gpa, ctx.io, arena, dir);
        defer o.close();
        var snap = o.st.snapshot();
        defer snap.release();
        const pkg = try common.loadPackage(arena, &snap, &pid);
        pkg_hex = try common.hexId(arena, &pkg.id);
        for (pkg.modules) |*m| {
            if (only) |n| if (!std.mem.eql(u8, n, m.name)) continue;
            try analyzeModule(arena, &a, m.name, &m.cm, m.raw.len);
        }
    }
    const text = if (ctx.opts.get("--format")) |f| std.mem.eql(u8, f, "text") else false;
    if (text) try writeText(ctx.w, &a, pkg_hex) else try writeJson(ctx.w, &a, pkg_hex);
    return 0;
}
