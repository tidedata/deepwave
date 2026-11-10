//! Display v2 evaluation (sui-display `v2/{interpreter,value,writer}.rs`, `v2/visitor/*`):
//! chains over the root object, dynamic field / object / derived loads, literal values,
//! transforms and the structured output (a `google.protobuf.Value`, metered as Rust meters it).
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const hash = @import("hash");
const bcs = @import("bcs");
const movelayout = @import("../movelayout.zig");
const pbvalue = @import("../pbvalue.zig");
const P = @import("parse.zig");

const Layout = movelayout.Layout;
const PV = pbvalue.Value;
const VS = pbvalue.value_size;
pub const FormatError = P.FormatError;
pub const Fail = error{ Format, OutOfMemory };

/// An object the interpreter loaded: its struct layout and Move contents.
pub const Loaded = struct { layout: Layout, bytes: []const u8 };

/// Object reads (`v2::Store`); sui-node's `DisplayStore` reads the live object and its layout.
pub const Store = struct {
    ctx: *const anyopaque,
    latest: *const fn (ctx: *const anyopaque, arena: Allocator, id: *const [32]u8) Allocator.Error!?Loaded,
};

pub const Slice = struct { layout: *const Layout, bytes: []const u8, scoped: bool };
pub const Address = struct { bytes: [32]u8, scoped: bool };

pub const Value = union(enum) {
    address: Address,
    bool: bool,
    bytes: []const u8,
    @"enum": *const EnumV,
    slice: Slice,
    string: []const u8,
    @"struct": *const StructV,
    u8: u8,
    u16: u16,
    u32: u32,
    u64: u64,
    u128: u128,
    u256: u256,
    vector: *const VectorV,

    fn setScope(v: *Value, scoped: bool) void {
        switch (v.*) {
            .address => |*a| a.scoped = scoped,
            .slice => |*s| s.scoped = scoped,
            else => {},
        }
    }
};

pub const NamedV = struct { name: []const u8, value: Value };
pub const FieldsV = union(enum) { positional: []const Value, named: []const NamedV };
pub const StructV = struct { type_: *const types.StructTag, fields: FieldsV };
pub const EnumV = struct { type_: *const types.StructTag, variant_name: ?[]const u8, variant_index: u16, fields: FieldsV };
pub const VectorV = struct { type_: types.TypeTag, elements: []const Value };

pub const Accessor = union(enum) {
    field: []const u8,
    positional: u8,
    index: Value,
    df_index: Value,
    dof_index: Value,
    derived: Value,

    fn isLoad(a: Accessor) bool {
        return a == .df_index or a == .dof_index or a == .derived;
    }
};

pub const VStrand = union(enum) {
    text: []const u8,
    value: struct { offset: usize, value: Value, transform: ?P.Transform },
};

// ---------------------------------------------------------------------------------------------
// Type tags and BCS of values

fn addrN(comptime n: u8) [32]u8 {
    var a: [32]u8 = @splat(0);
    a[31] = n;
    return a;
}
const one = addrN(1);
const two = addrN(2);

fn isTag(t: *const types.StructTag, a: *const [32]u8, module: []const u8, name: []const u8) bool {
    return std.mem.eql(u8, &t.address.@"0", a) and std.mem.eql(u8, t.module.@"0", module) and std.mem.eql(u8, t.name.@"0", name);
}

fn mkTag(arena: Allocator, a: [32]u8, module: []const u8, name: []const u8, args: []const types.TypeTag) Allocator.Error!types.TypeTag {
    return .{ .@"struct" = .{ .address = .{ .@"0" = a }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = try arena.dupe(types.TypeTag, args) } };
}

fn layoutTag(arena: Allocator, l: *const Layout) Allocator.Error!types.TypeTag {
    return switch (l.*) {
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
            const inner = try arena.create(types.TypeTag);
            inner.* = try layoutTag(arena, e);
            break :blk .{ .vector = inner };
        },
        .@"struct" => |s| .{ .@"struct" = s.type_ },
        .@"enum" => |e| .{ .@"struct" = e.type_ },
    };
}

fn valueType(arena: Allocator, v: Value) Allocator.Error!types.TypeTag {
    return switch (v) {
        .address => .address,
        .bool => .bool,
        .bytes => blk: {
            const inner = try arena.create(types.TypeTag);
            inner.* = .u8;
            break :blk .{ .vector = inner };
        },
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .@"enum" => |e| .{ .@"struct" = e.type_.* },
        .@"struct" => |s| .{ .@"struct" = s.type_.* },
        .slice => |s| try layoutTag(arena, s.layout),
        .string => try mkTag(arena, one, "string", "String", &.{}),
        .vector => |vv| blk: {
            const inner = try arena.create(types.TypeTag);
            inner.* = vv.type_;
            break :blk .{ .vector = inner };
        },
    };
}

pub fn eqlTypeTag(a: types.TypeTag, b: types.TypeTag) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .vector => |x| eqlTypeTag(x.*, b.vector.*),
        .@"struct" => |x| blk: {
            const y = b.@"struct";
            if (!isTag(&y, &x.address.@"0", x.module.@"0", x.name.@"0")) break :blk false;
            if (x.type_args.len != y.type_args.len) break :blk false;
            for (x.type_args, y.type_args) |p, q| if (!eqlTypeTag(p, q)) break :blk false;
            break :blk true;
        },
        else => true,
    };
}

fn uleb(out: *std.ArrayList(u8), arena: Allocator, n: u64) Allocator.Error!void {
    var v = n;
    while (true) {
        const b: u8 = @intCast(v & 0x7f);
        v >>= 7;
        if (v == 0) return out.append(arena, b);
        try out.append(arena, b | 0x80);
    }
}

fn intLe(out: *std.ArrayList(u8), arena: Allocator, comptime T: type, v: T) Allocator.Error!void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    try out.appendSlice(arena, &b);
}

/// `bcs::to_bytes(&Value)` (value.rs `Serialize`).
fn bcsValue(out: *std.ArrayList(u8), arena: Allocator, v: Value) Allocator.Error!void {
    switch (v) {
        .address => |a| try out.appendSlice(arena, &a.bytes),
        .bool => |b| try out.append(arena, @intFromBool(b)),
        .bytes, .string => |s| {
            try uleb(out, arena, s.len);
            try out.appendSlice(arena, s);
        },
        .slice => |s| try out.appendSlice(arena, s.bytes),
        .u8 => |n| try out.append(arena, n),
        .u16 => |n| try intLe(out, arena, u16, n),
        .u32 => |n| try intLe(out, arena, u32, n),
        .u64 => |n| try intLe(out, arena, u64, n),
        .u128 => |n| try intLe(out, arena, u128, n),
        .u256 => |n| try intLe(out, arena, u256, n),
        .vector => |vv| {
            try uleb(out, arena, vv.elements.len);
            for (vv.elements) |e| try bcsValue(out, arena, e);
        },
        .@"struct" => |s| try bcsFields(out, arena, s.fields, true),
        .@"enum" => |e| {
            try uleb(out, arena, e.variant_index);
            try bcsFields(out, arena, e.fields, false);
        },
    }
}

fn bcsFields(out: *std.ArrayList(u8), arena: Allocator, f: FieldsV, empty_is_false: bool) Allocator.Error!void {
    switch (f) {
        .positional => |vs| {
            if (vs.len == 0 and empty_is_false) return out.append(arena, 0);
            for (vs) |x| try bcsValue(out, arena, x);
        },
        .named => |ns| {
            if (ns.len == 0 and empty_is_false) return out.append(arena, 0);
            for (ns) |x| try bcsValue(out, arena, x.value);
        },
    }
}

fn toBcs(arena: Allocator, v: Value) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try bcsValue(&out, arena, v);
    return out.items;
}

/// `derive_dynamic_field_id(parent, key_type, key_bytes)`.
pub fn dynamicFieldId(arena: Allocator, parent: *const [32]u8, key_tag: types.TypeTag, key_bytes: []const u8) Allocator.Error![32]u8 {
    const tag = try bcs.encodeAlloc(types.TypeTag, arena, &key_tag);
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, key_bytes.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &len_le, key_bytes, tag });
}

pub fn derivedObjectId(arena: Allocator, parent: *const [32]u8, key_tag: types.TypeTag, key_bytes: []const u8) Allocator.Error![32]u8 {
    return dynamicFieldId(arena, parent, try mkTag(arena, two, "derived_object", "DerivedObjectKey", &.{key_tag}), key_bytes);
}

// ---------------------------------------------------------------------------------------------
// Byte cursor shared by the visitors (annotated_visitor's errors)

const Cursor = struct {
    b: []const u8,
    pos: usize = 0,
};

// ---------------------------------------------------------------------------------------------
// Output meter (writer.rs `Meter`): one counter for the whole Display

pub const OutMeter = struct {
    used: *usize,
    max: usize,
    depth: usize,

    fn nest(m: OutMeter, it: *Interp) Fail!OutMeter {
        if (m.depth == 0) return it.fail(.too_deep);
        return .{ .used = m.used, .max = m.max, .depth = m.depth - 1 };
    }
    /// `charge`: the counter grows even when the charge fails (`fetch_add`).
    pub fn charge(m: OutMeter, n: usize) bool {
        m.used.* +|= n;
        return m.used.* <= m.max;
    }
    fn chargeOr(m: OutMeter, it: *Interp, n: usize) Fail!void {
        if (!m.charge(n)) return it.fail(.too_big);
    }
};

// ---------------------------------------------------------------------------------------------
// Interpreter

pub const Interp = struct {
    arena: Allocator,
    store: Store,
    root: Slice,
    cache: std.AutoHashMapUnmanaged([32]u8, ?*const Loaded) = .empty,
    err: FormatError = .too_big,

    pub fn fail(it: *Interp, e: FormatError) error{Format} {
        it.err = e;
        return error.Format;
    }

    fn visitorErr(it: *Interp, msg: []const u8) error{Format} {
        return it.fail(.{ .visitor = msg });
    }
    fn bcsErr(it: *Interp, msg: []const u8) error{Format} {
        return it.fail(.{ .bcs = msg });
    }

    pub fn evalStrands(it: *Interp, strands: []const P.Strand) Fail!?[]const VStrand {
        const out = try it.arena.alloc(VStrand, strands.len);
        for (strands, out) |s, *o| switch (s) {
            .text => |t| o.* = .{ .text = t },
            .expr => |e| {
                const v = (try it.evalAlts(e.alternates)) orelse return null;
                o.* = .{ .value = .{ .offset = e.offset, .value = v, .transform = e.transform } };
            },
        };
        return out;
    }

    fn evalAlts(it: *Interp, alts: []const P.Chain) Fail!?Value {
        for (alts) |c| if (try it.evalChain(c)) |v| return v;
        return null;
    }

    fn evalChain(it: *Interp, chain: P.Chain) Fail!?Value {
        var root: Value = if (chain.root) |lit|
            (try it.evalLiteral(lit)) orelse return null
        else
            .{ .slice = it.root };
        // the path is a stack: its last element is the next accessor
        var path: std.ArrayList(Accessor) = .empty;
        const accs = try it.arena.alloc(Accessor, chain.accessors.len);
        for (chain.accessors, accs) |a, *o| o.* = (try it.evalAccessor(a)) orelse return null;
        var k = accs.len;
        while (k > 0) {
            k -= 1;
            try path.append(it.arena, accs[k]);
        }

        while (path.items.len > 0) {
            const acc = path.items[path.items.len - 1];
            switch (root) {
                .address => |a| switch (acc) {
                    .df_index => |i| {
                        const id = try dynamicFieldId(it.arena, &a.bytes, try valueType(it.arena, i), try toBcs(it.arena, i));
                        const s = (try it.fetch(&id, a.scoped)) orelse return null;
                        const f = (try it.fieldVisit(s)) orelse return null;
                        if (f.dof) return null;
                        _ = path.pop();
                        root = .{ .slice = .{ .bytes = f.value_bytes, .layout = f.value_layout, .scoped = s.scoped } };
                    },
                    .dof_index => |i| {
                        const wrapped = try mkTag(it.arena, two, "dynamic_object_field", "Wrapper", &.{try valueType(it.arena, i)});
                        const id = try dynamicFieldId(it.arena, &a.bytes, wrapped, try toBcs(it.arena, i));
                        const s = (try it.fetch(&id, a.scoped)) orelse return null;
                        const f = (try it.fieldVisit(s)) orelse return null;
                        if (!f.dof) return null;
                        if (f.value_bytes.len != 32) return null;
                        const vs = (try it.fetch(f.value_bytes[0..32], a.scoped)) orelse return null;
                        _ = path.pop();
                        root = .{ .slice = vs };
                    },
                    .derived => |i| {
                        const id = try derivedObjectId(it.arena, &a.bytes, try valueType(it.arena, i), try toBcs(it.arena, i));
                        const s = (try it.fetch(&id, a.scoped)) orelse return null;
                        _ = path.pop();
                        root = .{ .slice = s };
                    },
                    else => return null,
                },
                .bytes => |bs| {
                    const i = asNumericIndex(acc) orelse return null;
                    if (i >= bs.len) return null;
                    _ = path.pop();
                    root = .{ .u8 = bs[@intCast(i)] };
                },
                .string => |s| {
                    if (acc == .field and std.mem.eql(u8, acc.field, "bytes")) {
                        _ = path.pop();
                        root = .{ .bytes = s };
                    } else return null;
                },
                .vector => |vv| {
                    const i = asNumericIndex(acc) orelse return null;
                    _ = path.pop();
                    if (i >= vv.elements.len) return null;
                    root = vv.elements[@intCast(i)];
                },
                .@"struct" => |s| {
                    root = fieldsGet(s.fields, acc) orelse return null;
                    _ = path.pop();
                },
                .@"enum" => |e| {
                    root = fieldsGet(e.fields, acc) orelse return null;
                    _ = path.pop();
                },
                .slice => |s| {
                    var v = (try it.extractSlice(s, &path)) orelse return null;
                    v.setScope(s.scoped);
                    root = v;
                },
                .bool, .u8, .u16, .u32, .u64, .u128, .u256 => return null,
            }
        }
        return root;
    }

    fn evalAccessor(it: *Interp, a: P.Accessor) Fail!?Accessor {
        return switch (a) {
            .field => |f| .{ .field = f },
            .positional => |i| .{ .positional = i },
            .index => |c| if (try it.evalChain(c)) |v| .{ .index = v } else null,
            .df_index => |c| if (try it.evalChain(c)) |v| .{ .df_index = v } else null,
            .dof_index => |c| if (try it.evalChain(c)) |v| .{ .dof_index = v } else null,
            .derived => |c| if (try it.evalChain(c)) |v| .{ .derived = v } else null,
        };
    }

    fn evalChains(it: *Interp, chains: []const P.Chain) Fail!?[]const Value {
        const out = try it.arena.alloc(Value, chains.len);
        for (chains, out) |c, *o| o.* = (try it.evalChain(c)) orelse return null;
        return out;
    }

    fn evalFields(it: *Interp, f: P.Fields) Fail!?FieldsV {
        switch (f) {
            .positional => |cs| return .{ .positional = (try it.evalChains(cs)) orelse return null },
            .named => |ns| {
                const out = try it.arena.alloc(NamedV, ns.len);
                for (ns, out) |n, *o| o.* = .{ .name = n.name, .value = (try it.evalChain(n.chain)) orelse return null };
                return .{ .named = out };
            },
        }
    }

    fn evalLiteral(it: *Interp, lit: *const P.Literal) Fail!?Value {
        return switch (lit.*) {
            .self_ => .{ .slice = it.root },
            .address => |a| .{ .address = .{ .bytes = a, .scoped = false } },
            .bool => |b| .{ .bool = b },
            .u8 => |n| .{ .u8 = n },
            .u16 => |n| .{ .u16 = n },
            .u32 => |n| .{ .u32 = n },
            .u64 => |n| .{ .u64 = n },
            .u128 => |n| .{ .u128 = n },
            .u256 => |n| .{ .u256 = n },
            .byte_array => |b| .{ .bytes = b },
            .string => |s| .{ .string = s },
            .vector => |*v| blk: {
                const elements = (try it.evalChains(v.elements)) orelse break :blk null;
                const t: types.TypeTag = if (v.type_) |t|
                    t
                else if (elements.len > 0)
                    try valueType(it.arena, elements[0])
                else
                    return it.fail(.vector_no_type);
                for (elements) |e| {
                    const et = try valueType(it.arena, e);
                    if (!eqlTypeTag(et, t)) return it.fail(.{ .vector_type_mismatch = .{ .offset = v.offset, .this = t, .that = et } });
                }
                const vv = try it.arena.create(VectorV);
                vv.* = .{ .type_ = t, .elements = elements };
                break :blk .{ .vector = vv };
            },
            .@"struct" => |*s| blk: {
                const f = (try it.evalFields(s.fields)) orelse break :blk null;
                const sv = try it.arena.create(StructV);
                sv.* = .{ .type_ = &s.type_, .fields = f };
                break :blk .{ .@"struct" = sv };
            },
            .@"enum" => |*e| blk: {
                const f = (try it.evalFields(e.fields)) orelse break :blk null;
                const ev = try it.arena.create(EnumV);
                ev.* = .{ .type_ = &e.type_, .variant_name = e.variant_name, .variant_index = e.variant_index, .fields = f };
                break :blk .{ .@"enum" = ev };
            },
        };
    }

    fn fetch(it: *Interp, id: *const [32]u8, scoped: bool) Fail!?Slice {
        const gop = try it.cache.getOrPut(it.arena, id.*);
        if (!gop.found_existing) {
            const l = try it.store.latest(it.store.ctx, it.arena, id);
            gop.value_ptr.* = if (l) |x| blk: {
                const p = try it.arena.create(Loaded);
                p.* = x;
                break :blk p;
            } else null;
        }
        const l = gop.value_ptr.* orelse return null;
        return .{ .layout = &l.layout, .bytes = l.bytes, .scoped = scoped };
    }

    // --- dynamic field visitor (sui-types dynamic_field/visitor.rs)

    const DField = struct { dof: bool, value_bytes: []const u8, value_layout: *const Layout };

    /// `FieldVisitor::deserialize`: null for "not a dynamic field", error for bad bytes.
    fn fieldVisit(it: *Interp, s: Slice) Fail!?DField {
        const st = switch (s.layout.*) {
            .@"struct" => |x| x,
            else => {
                // other layouts still have to deserialize for the visitor errors
                var c: Cursor = .{ .b = s.bytes };
                try it.skip(&c, s.layout);
                if (c.pos != c.b.len) return it.trailing(c);
                return null;
            },
        };
        var c: Cursor = .{ .b = s.bytes };
        if (!isTag(&st.type_, &two, "dynamic_field", "Field")) {
            try it.skip(&c, s.layout);
            if (c.pos != c.b.len) return it.trailing(c);
            return null;
        }
        var have_id = false;
        var name: ?bool = null;
        var value: ?DField = null;
        for (st.fields) |*f| {
            const lo = c.pos;
            try it.skip(&c, &f.layout);
            const hi = c.pos;
            if (std.mem.eql(u8, f.name, "id")) {
                if (!isUidLayout(&f.layout) or hi - lo != 32) return null;
                have_id = true;
            } else if (std.mem.eql(u8, f.name, "name")) {
                name = switch (f.layout) {
                    .@"struct" => |ns| if (isTag(&ns.type_, &two, "dynamic_object_field", "Wrapper")) blk: {
                        if (ns.fields.len != 1 or !std.mem.eql(u8, ns.fields[0].name, "name")) return null;
                        break :blk true;
                    } else false,
                    else => false,
                };
            } else if (std.mem.eql(u8, f.name, "value")) {
                value = .{ .dof = false, .value_bytes = c.b[lo..hi], .value_layout = &f.layout };
            } else return null;
        }
        if (c.pos != c.b.len) return it.trailing(c);
        if (!have_id or name == null or value == null) return null;
        var v = value.?;
        v.dof = name.?;
        return v;
    }

    fn trailing(it: *Interp, c: Cursor) error{Format} {
        return it.visitorErr(std.fmt.allocPrint(it.arena, "trailing {d} byte(s) at the end of input", .{c.b.len - c.pos}) catch "trailing bytes");
    }

    // --- reading primitives

    fn take(it: *Interp, c: *Cursor, n: usize) Fail![]const u8 {
        if (c.b.len - c.pos < n) return it.visitorErr("unexpected end of input");
        const s = c.b[c.pos..][0..n];
        c.pos += n;
        return s;
    }
    fn readUleb(it: *Interp, c: *Cursor) Fail!u64 {
        var v: u64 = 0;
        var shift: u32 = 0;
        while (true) {
            const byte = (try it.take(c, 1))[0];
            if (shift == 63 and byte > 1) return it.visitorErr("unexpected end of input");
            v |= @as(u64, byte & 0x7f) << @intCast(shift);
            if (byte & 0x80 == 0) return v;
            shift += 7;
            if (shift > 63) return it.visitorErr("unexpected end of input");
        }
    }
    fn readInt(it: *Interp, c: *Cursor, comptime T: type) Fail!T {
        return std.mem.readInt(T, (try it.take(c, @sizeOf(T)))[0..@sizeOf(T)], .little);
    }
    fn readBool(it: *Interp, c: *Cursor) Fail!bool {
        const b = (try it.take(c, 1))[0];
        if (b > 1) return it.visitorErr(std.fmt.allocPrint(it.arena, "unexpected byte: {d}", .{b}) catch "unexpected byte");
        return b == 1;
    }
    fn readTag(it: *Interp, c: *Cursor, e: *const movelayout.Enum) Fail!*const movelayout.Variant {
        const tag = (try it.take(c, 1))[0];
        if (tag > 127 or tag >= e.variants.len) return it.visitorErr(std.fmt.allocPrint(it.arena, "invalid variant tag: {d}", .{tag}) catch "invalid variant tag");
        return &e.variants[tag];
    }

    fn skip(it: *Interp, c: *Cursor, l: *const Layout) Fail!void {
        switch (l.*) {
            .bool => _ = try it.readBool(c),
            .u8 => _ = try it.take(c, 1),
            .u16 => _ = try it.take(c, 2),
            .u32 => _ = try it.take(c, 4),
            .u64 => _ = try it.take(c, 8),
            .u128 => _ = try it.take(c, 16),
            .u256, .address, .signer => _ = try it.take(c, 32),
            .vector => |el| {
                const n = try it.readUleb(c);
                var i: u64 = 0;
                while (i < n) : (i += 1) try it.skip(c, el);
            },
            .@"struct" => |s| for (s.fields) |*f| try it.skip(c, &f.layout),
            .@"enum" => |e| {
                const v = try it.readTag(c, e);
                for (v.fields) |*f| try it.skip(c, &f.layout);
            },
        }
    }

    // --- Extractor (visitor/extractor.rs)

    fn extractSlice(it: *Interp, s: Slice, path: *std.ArrayList(Accessor)) Fail!?Value {
        var c: Cursor = .{ .b = s.bytes };
        const v = try it.extract(&c, s.layout, path);
        if (c.pos != c.b.len) return it.trailing(c);
        return v;
    }

    fn sliceOf(c: *const Cursor, l: *const Layout, start: usize) Value {
        return .{ .slice = .{ .layout = l, .bytes = c.b[start..c.pos], .scoped = false } };
    }

    fn extract(it: *Interp, c: *Cursor, l: *const Layout, path: *std.ArrayList(Accessor)) Fail!?Value {
        const start = c.pos;
        const empty = path.items.len == 0;
        switch (l.*) {
            .u8 => {
                const v = try it.readInt(c, u8);
                return if (empty) .{ .u8 = v } else null;
            },
            .u16 => {
                const v = try it.readInt(c, u16);
                return if (empty) .{ .u16 = v } else null;
            },
            .u32 => {
                const v = try it.readInt(c, u32);
                return if (empty) .{ .u32 = v } else null;
            },
            .u64 => {
                const v = try it.readInt(c, u64);
                return if (empty) .{ .u64 = v } else null;
            },
            .u128 => {
                const v = try it.readInt(c, u128);
                return if (empty) .{ .u128 = v } else null;
            },
            .u256 => {
                const v = try it.readInt(c, u256);
                return if (empty) .{ .u256 = v } else null;
            },
            .bool => {
                const v = try it.readBool(c);
                return if (empty) .{ .bool = v } else null;
            },
            .address => {
                const a = (try it.take(c, 32))[0..32].*;
                if (empty) return .{ .address = .{ .bytes = a, .scoped = true } };
                if (path.items[path.items.len - 1].isLoad()) return .{ .address = .{ .bytes = a, .scoped = false } };
                return null;
            },
            .signer => {
                _ = try it.take(c, 32);
                return null;
            },
            .vector => |el| {
                const n = try it.readUleb(c);
                const acc = path.pop() orelse {
                    var i: u64 = 0;
                    while (i < n) : (i += 1) try it.skip(c, el);
                    return sliceOf(c, l, start);
                };
                var result: ?Value = null;
                const want = asNumericIndex(acc);
                var i: u64 = 0;
                while (i < n) : (i += 1) {
                    if (want != null and i == want.?) {
                        result = try it.extract(c, el, path);
                    } else try it.skip(c, el);
                }
                return result;
            },
            .@"struct" => |s| return it.extractStruct(c, l, s, path, start),
            .@"enum" => |e| {
                const v = try it.readTag(c, e);
                const acc = path.pop() orelse {
                    for (v.fields) |*f| try it.skip(c, &f.layout);
                    return sliceOf(c, l, start);
                };
                return it.extractNamedField(c, v.fields, acc, path);
            },
        }
    }

    /// Walks all `fields`, extracting the one `acc` names (the driver skips the rest).
    fn extractNamedField(it: *Interp, c: *Cursor, fields: []const movelayout.Field, acc: Accessor, path: *std.ArrayList(Accessor)) Fail!?Value {
        var nb: [8]u8 = undefined;
        const name: ?[]const u8 = switch (acc) {
            .field => |f| f,
            .positional => |i| std.fmt.bufPrint(&nb, "pos{d}", .{i}) catch unreachable,
            else => null,
        };
        var result: ?Value = null;
        var found = false;
        for (fields) |*f| {
            if (!found and name != null and std.mem.eql(u8, f.name, name.?)) {
                found = true;
                result = try it.extract(c, &f.layout, path);
            } else try it.skip(c, &f.layout);
        }
        return result;
    }

    fn extractStruct(it: *Interp, c: *Cursor, l: *const Layout, s: *const movelayout.Struct, path: *std.ArrayList(Accessor), start: usize) Fail!?Value {
        if (isTag(&s.type_, &one, "option", "Option")) {
            // OptionVisitor: transparent, the path is not consumed
            if (!isOptionLayout(s)) return it.bcsErr("expected option type");
            const el = s.fields[0].layout.vector;
            const n = try it.readUleb(c);
            return switch (n) {
                0 => null,
                1 => try it.extract(c, el, path),
                else => it.bcsErr("expected option type"),
            };
        }
        if (path.items.len == 0) {
            for (s.fields) |*f| try it.skip(c, &f.layout);
            return sliceOf(c, l, start);
        }
        const acc = path.items[path.items.len - 1];
        if (acc.isLoad()) {
            // AddressExtractor
            var addr: ?[32]u8 = null;
            const is_id = isUidLayout(l) or isIdLayout(l);
            const first_uid = s.fields.len > 0 and std.mem.eql(u8, s.fields[0].name, "id") and isUidLayout(&s.fields[0].layout);
            for (s.fields, 0..) |*f, i| {
                const lo = c.pos;
                try it.skip(c, &f.layout);
                if (i == 0 and (is_id or first_uid)) {
                    if (c.pos - lo != 32) return it.bcsErr("unexpected end of input");
                    addr = c.b[lo..][0..32].*;
                }
            }
            return if (addr) |a| .{ .address = .{ .bytes = a, .scoped = false } } else null;
        }
        if (acc == .index) {
            if (!(isTag(&s.type_, &two, "vec_map", "VecMap") and s.type_.type_args.len == 2) or
                s.fields.len == 0 or !std.mem.eql(u8, s.fields[0].name, "contents"))
            {
                for (s.fields) |*f| try it.skip(c, &f.layout);
                return null;
            }
            const key = try toBcs(it.arena, acc.index);
            _ = path.pop();
            const v = try it.vecMapVisit(c, &s.fields[0].layout, key, path);
            for (s.fields[1..]) |*f| try it.skip(c, &f.layout);
            return v;
        }
        if (acc != .field and acc != .positional) {
            for (s.fields) |*f| try it.skip(c, &f.layout);
            return null;
        }
        _ = path.pop();
        return it.extractNamedField(c, s.fields, acc, path);
    }

    /// `VecMapVisitor`: the value of the first entry whose key bytes equal `key`.
    fn vecMapVisit(it: *Interp, c: *Cursor, l: *const Layout, key: []const u8, path: *std.ArrayList(Accessor)) Fail!?Value {
        switch (l.*) {
            .vector => |el| {
                const n = try it.readUleb(c);
                var result: ?Value = null;
                var i: u64 = 0;
                while (i < n) : (i += 1) {
                    if (result == null) {
                        result = try it.vecMapVisit(c, el, key, path);
                    } else try it.skip(c, el);
                }
                return result;
            },
            .@"struct" => |s| {
                if (!(isTag(&s.type_, &two, "vec_map", "Entry") and s.type_.type_args.len == 2) or s.fields.len == 0 or
                    !std.mem.eql(u8, s.fields[0].name, "key"))
                {
                    for (s.fields) |*f| try it.skip(c, &f.layout);
                    return null;
                }
                const lo = c.pos;
                try it.skip(c, &s.fields[0].layout);
                if (!std.mem.eql(u8, key, c.b[lo..c.pos]) or s.fields.len < 2 or !std.mem.eql(u8, s.fields[1].name, "value")) {
                    for (s.fields[1..]) |*f| try it.skip(c, &f.layout);
                    return null;
                }
                const v = try it.extract(c, &s.fields[1].layout, path);
                for (s.fields[2..]) |*f| try it.skip(c, &f.layout);
                if (s.fields.len > 2) return null;
                return v;
            },
            else => {
                try it.skip(c, l);
                return null;
            },
        }
    }
};

fn isOptionLayout(s: *const movelayout.Struct) bool {
    if (s.type_.type_args.len != 1 or s.fields.len != 1) return false;
    if (!std.mem.eql(u8, s.fields[0].name, "vec") or s.fields[0].layout != .vector) return false;
    return true;
}

fn isUidLayout(l: *const Layout) bool {
    return switch (l.*) {
        .@"struct" => |s| isTag(&s.type_, &two, "object", "UID") and s.fields.len == 1 and isIdLayout(&s.fields[0].layout),
        else => false,
    };
}

fn isIdLayout(l: *const Layout) bool {
    return switch (l.*) {
        .@"struct" => |s| isTag(&s.type_, &two, "object", "ID") and s.fields.len == 1 and s.fields[0].layout == .address,
        else => false,
    };
}

fn isStringLayout(s: *const movelayout.Struct) bool {
    if (s.type_.type_args.len != 0) return false;
    return isTag(&s.type_, &one, "ascii", "String") or isTag(&s.type_, &one, "string", "String") or
        isTag(&s.type_, &one, "type_name", "TypeName") or isTag(&s.type_, &two, "url", "Url");
}

fn asU64(v: Value) ?u64 {
    return switch (v) {
        .u8 => |n| n,
        .u16 => |n| n,
        .u32 => |n| n,
        .u64 => |n| n,
        .u128 => |n| std.math.cast(u64, n),
        .u256 => |n| std.math.cast(u64, n),
        .slice => |s| switch (s.layout.*) {
            .u8 => if (s.bytes.len == 1) s.bytes[0] else null,
            .u16 => if (s.bytes.len == 2) std.mem.readInt(u16, s.bytes[0..2], .little) else null,
            .u32 => if (s.bytes.len == 4) std.mem.readInt(u32, s.bytes[0..4], .little) else null,
            .u64 => if (s.bytes.len == 8) std.mem.readInt(u64, s.bytes[0..8], .little) else null,
            .u128 => if (s.bytes.len == 16) std.math.cast(u64, std.mem.readInt(u128, s.bytes[0..16], .little)) else null,
            .u256 => if (s.bytes.len == 32) std.math.cast(u64, std.mem.readInt(u256, s.bytes[0..32], .little)) else null,
            else => null,
        },
        else => null,
    };
}

fn asNumericIndex(a: Accessor) ?u64 {
    return switch (a) {
        .index => |v| asU64(v),
        else => null,
    };
}

fn fieldsGet(f: FieldsV, a: Accessor) ?Value {
    switch (f) {
        .positional => |vs| if (a == .positional) {
            if (a.positional < vs.len) return vs[a.positional];
        },
        .named => |ns| if (a == .field) {
            for (ns) |n| if (std.mem.eql(u8, n.name, a.field)) return n.value;
        },
    }
    return null;
}

// ---------------------------------------------------------------------------------------------
// Atoms and transforms (value.rs)

const Atom = union(enum) {
    address: [32]u8,
    bool: bool,
    bytes: []const u8,
    u8: u8,
    u16: u16,
    u32: u32,
    u64: u64,
    u128: u128,
    u256: u256,
};

fn bcsExact(it: *Interp, b: []const u8, n: usize) Fail![]const u8 {
    if (b.len < n) return it.bcsErr("unexpected end of input");
    if (b.len > n) return it.bcsErr("remaining input");
    return b;
}

/// `bcs::from_bytes::<Vec<u8>>` / `&[u8]`.
fn bcsBytes(it: *Interp, b: []const u8) Fail![]const u8 {
    var v: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        if (i >= b.len) return it.bcsErr("unexpected end of input");
        const byte = b[i];
        v |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) {
            if (byte == 0 and i > 0) return it.bcsErr("ULEB128 encoding was not minimal in size");
            break;
        }
        if (i == 4) return it.bcsErr("ULEB128 encoding was not minimal in size");
        shift += 7;
    }
    if (v > std.math.maxInt(u31)) return it.bcsErr("exceeded max sequence length");
    const rest = b[i + 1 ..];
    if (rest.len < v) return it.bcsErr("unexpected end of input");
    if (rest.len > v) return it.bcsErr("remaining input");
    return rest;
}

fn atomOf(it: *Interp, v: Value) Fail!Atom {
    return switch (v) {
        .address => |a| .{ .address = a.bytes },
        .bool => |b| .{ .bool = b },
        .u8 => |n| .{ .u8 = n },
        .u16 => |n| .{ .u16 = n },
        .u32 => |n| .{ .u32 = n },
        .u64 => |n| .{ .u64 = n },
        .u128 => |n| .{ .u128 = n },
        .u256 => |n| .{ .u256 = n },
        .bytes, .string => |b| .{ .bytes = b },
        .@"enum" => it.fail(.{ .transform_invalid = "unexpected enum" }),
        .@"struct" => it.fail(.{ .transform_invalid = "unexpected struct" }),
        .vector => |vv| blk: {
            if (vv.type_ != .u8) return it.fail(.{ .transform_invalid = "unexpected vector" });
            const out = try it.arena.alloc(u8, vv.elements.len);
            for (vv.elements, out) |e, *o| o.* = switch (e) {
                .u8 => |b| b,
                .slice => |s| if (s.layout.* == .u8) (try bcsExact(it, s.bytes, 1))[0] else return it.fail(.{ .transform_invalid = "unexpected vector" }),
                else => return it.fail(.{ .transform_invalid = "unexpected vector" }),
            };
            break :blk .{ .bytes = out };
        },
        .slice => |s| switch (s.layout.*) {
            .address => .{ .address = (try bcsExact(it, s.bytes, 32))[0..32].* },
            .bool => blk: {
                const b = (try bcsExact(it, s.bytes, 1))[0];
                if (b > 1) return it.bcsErr("expected boolean");
                break :blk .{ .bool = b == 1 };
            },
            .u8 => .{ .u8 = (try bcsExact(it, s.bytes, 1))[0] },
            .u16 => .{ .u16 = std.mem.readInt(u16, (try bcsExact(it, s.bytes, 2))[0..2], .little) },
            .u32 => .{ .u32 = std.mem.readInt(u32, (try bcsExact(it, s.bytes, 4))[0..4], .little) },
            .u64 => .{ .u64 = std.mem.readInt(u64, (try bcsExact(it, s.bytes, 8))[0..8], .little) },
            .u128 => .{ .u128 = std.mem.readInt(u128, (try bcsExact(it, s.bytes, 16))[0..16], .little) },
            .u256 => .{ .u256 = std.mem.readInt(u256, (try bcsExact(it, s.bytes, 32))[0..32], .little) },
            .vector => |el| if (el.* == .u8) .{ .bytes = try bcsBytes(it, s.bytes) } else it.fail(.{ .transform_invalid = "unexpected vector" }),
            .@"struct" => |st| if (isStringLayout(st))
                .{ .bytes = try bcsBytes(it, s.bytes) }
            else if (isUidLayout(s.layout) or isIdLayout(s.layout))
                .{ .address = (try bcsExact(it, s.bytes, 32))[0..32].* }
            else
                it.fail(.{ .transform_invalid = "unexpected struct" }),
            .signer => it.fail(.{ .transform_invalid = "unexpected signer" }),
            .@"enum" => it.fail(.{ .transform_invalid = "unexpected enum" }),
        },
    };
}

/// String output with the shared output meter (writer.rs `StringWriter`).
const SW = struct {
    out: std.ArrayList(u8) = .empty,
    meter: OutMeter,
    arena: Allocator,

    fn write(w: *SW, it: *Interp, s: []const u8) Fail!void {
        if (!w.meter.charge(s.len)) return it.fail(.too_much_output);
        try w.out.appendSlice(w.arena, s);
    }
    fn print(w: *SW, it: *Interp, comptime f: []const u8, args: anytype) Fail!void {
        try w.write(it, try std.fmt.allocPrint(w.arena, f, args));
    }
};

fn hexAddr(buf: *[66]u8, a: *const [32]u8) []const u8 {
    buf[0] = '0';
    buf[1] = 'x';
    _ = std.fmt.bufPrint(buf[2..], "{x}", .{a}) catch unreachable;
    return buf;
}

fn formatAsStr(it: *Interp, a: Atom, w: *SW) Fail!void {
    var ab: [66]u8 = undefined;
    switch (a) {
        .address => |x| try w.write(it, hexAddr(&ab, &x)),
        .bool => |b| try w.write(it, if (b) "true" else "false"),
        .u8 => |n| try w.print(it, "{d}", .{n}),
        .u16 => |n| try w.print(it, "{d}", .{n}),
        .u32 => |n| try w.print(it, "{d}", .{n}),
        .u64 => |n| try w.print(it, "{d}", .{n}),
        .u128 => |n| try w.print(it, "{d}", .{n}),
        .u256 => |n| try w.print(it, "{d}", .{n}),
        .bytes => |b| {
            if (!std.unicode.utf8ValidateSlice(b)) return it.fail(.{ .transform_invalid = "expected utf8 bytes" });
            try w.write(it, b);
        },
    }
}

fn formatAsHex(it: *Interp, a: Atom, w: *SW) Fail!void {
    switch (a) {
        .bool => |b| try w.print(it, "{x:0>2}", .{@intFromBool(b)}),
        .u8 => |n| try w.print(it, "{x:0>2}", .{n}),
        .u16 => |n| try w.print(it, "{x:0>4}", .{n}),
        .u32 => |n| try w.print(it, "{x:0>8}", .{n}),
        .u64 => |n| try w.print(it, "{x:0>16}", .{n}),
        .u128 => |n| try w.print(it, "{x:0>32}", .{n}),
        .u256 => |n| try w.print(it, "{x:0>64}", .{n}),
        .address => |x| try w.print(it, "{x}", .{&x}),
        .bytes => |b| try w.print(it, "{x}", .{b}),
    }
}

fn formatAsUrl(it: *Interp, a: Atom, w: *SW) Fail!void {
    switch (a) {
        .bytes => |b| {
            var out: std.ArrayList(u8) = .empty;
            for (b) |c| switch (c) {
                'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => try out.append(it.arena, c),
                else => try out.print(it.arena, "%{X:0>2}", .{c}),
            };
            try w.write(it, out.items);
        },
        else => try formatAsStr(it, a, w),
    }
}

fn b64(arena: Allocator, m: P.Base64Mod, raw: []const u8) Allocator.Error![]const u8 {
    const enc = if (m.url and m.nopad) std.base64.url_safe_no_pad.Encoder else if (m.url) std.base64.url_safe.Encoder else if (m.nopad) std.base64.standard_no_pad.Encoder else std.base64.standard.Encoder;
    const out = try arena.alloc(u8, enc.calcSize(raw.len));
    _ = enc.encode(out, raw);
    return out;
}

fn atomLe(arena: Allocator, a: Atom) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    switch (a) {
        .address => |x| try out.appendSlice(arena, &x),
        .bool => |b| try out.append(arena, @intFromBool(b)),
        .u8 => |n| try out.append(arena, n),
        .u16 => |n| try intLe(&out, arena, u16, n),
        .u32 => |n| try intLe(&out, arena, u32, n),
        .u64 => |n| try intLe(&out, arena, u64, n),
        .u128 => |n| try intLe(&out, arena, u128, n),
        .u256 => |n| try intLe(&out, arena, u256, n),
        .bytes => |b| return b,
    }
    return out.items;
}

/// chrono `DateTime<Utc>` Debug of a millisecond timestamp.
fn formatAsTimestamp(it: *Interp, a: Atom, w: *SW) Fail!void {
    const ms: i64 = switch (a) {
        .u8 => |n| n,
        .u16 => |n| n,
        .u32 => |n| n,
        .u64 => |n| std.math.cast(i64, n) orelse return it.fail(.{ .transform_invalid = "expected unix timestamp in milliseconds" }),
        .u128 => |n| std.math.cast(i64, n) orelse return it.fail(.{ .transform_invalid = "expected unix timestamp in milliseconds" }),
        .u256 => |n| std.math.cast(i64, n) orelse return it.fail(.{ .transform_invalid = "expected unix timestamp in milliseconds" }),
        else => return it.fail(.{ .transform_invalid = "expected unix timestamp in milliseconds" }),
    };
    const secs = @divFloor(ms, 1000);
    const milli: u32 = @intCast(@mod(ms, 1000));
    const days = @divFloor(secs, 86400);
    const sod: u32 = @intCast(@mod(secs, 86400));
    // civil from days (Howard Hinnant)
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    var y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    if (m <= 2) y += 1;
    if (y > 262142) return it.fail(.{ .transform_invalid = "expected unix timestamp in milliseconds" });
    var out: std.ArrayList(u8) = .empty;
    if (y > 9999) try out.print(it.arena, "+{d}", .{@as(u64, @intCast(y))}) else try out.print(it.arena, "{d:0>4}", .{@as(u64, @intCast(y))});
    try out.print(it.arena, "-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{ @as(u64, @intCast(m)), @as(u64, @intCast(d)), sod / 3600, sod / 60 % 60, sod % 60 });
    if (milli != 0) try out.print(it.arena, ".{d:0>3}", .{milli});
    try out.append(it.arena, 'Z');
    try w.write(it, out.items);
}

fn formatValue(it: *Interp, v: Value, t: P.Transform, w: *SW) Fail!void {
    switch (t) {
        .base64 => |m| try w.write(it, try b64(it.arena, m, try atomLe(it.arena, try atomOf(it, v)))),
        .bcs => |m| try w.write(it, try b64(it.arena, m, try toBcs(it.arena, v))),
        .hex => try formatAsHex(it, try atomOf(it, v), w),
        .json => return it.fail(.{ .transform_invalid = "unexpected 'json' in string" }),
        .str => try formatAsStr(it, try atomOf(it, v), w),
        .timestamp => try formatAsTimestamp(it, try atomOf(it, v), w),
        .url => try formatAsUrl(it, try atomOf(it, v), w),
    }
}

// ---------------------------------------------------------------------------------------------
// Structured output (value.rs `format_json`, rpc_visitor `RpcVisitor<prost Value, Meter>`)

fn jStr(it: *Interp, m: OutMeter, s: []const u8) Fail!PV {
    try m.chargeOr(it, VS + s.len);
    return .{ .string = s };
}
fn jNum(it: *Interp, m: OutMeter, n: u32) Fail!PV {
    try m.chargeOr(it, VS);
    return .{ .number = @floatFromInt(n) };
}
fn jDec(it: *Interp, m: OutMeter, comptime T: type, n: T) Fail!PV {
    return jStr(it, m, try std.fmt.allocPrint(it.arena, "{d}", .{n}));
}
fn jAddr(it: *Interp, m: OutMeter, a: *const [32]u8) Fail!PV {
    const buf = try it.arena.alloc(u8, 66);
    return jStr(it, m, hexAddr(buf[0..66], a));
}

fn formatJson(it: *Interp, v: Value, m: OutMeter) Fail!PV {
    switch (v) {
        .address => |a| return jAddr(it, m, &a.bytes),
        .bool => |b| {
            try m.chargeOr(it, VS);
            return .{ .bool = b };
        },
        .u8 => |n| return jNum(it, m, n),
        .u16 => |n| return jNum(it, m, n),
        .u32 => |n| return jNum(it, m, n),
        .u64 => |n| return jDec(it, m, u64, n),
        .u128 => |n| return jDec(it, m, u128, n),
        .u256 => |n| return jDec(it, m, u256, n),
        .bytes => |b| return jStr(it, m, try b64(it.arena, .{}, b)),
        .string => |s| {
            if (!std.unicode.utf8ValidateSlice(s)) return it.fail(.{ .transform_invalid = "expected utf8 bytes" });
            return jStr(it, m, s);
        },
        .@"struct" => |s| {
            var map: pbvalue.StructBuilder = .{};
            const nested = try m.nest(it);
            try fieldsJson(it, s.fields, nested, &map);
            try m.chargeOr(it, VS);
            return .{ .@"struct" = map.finish() };
        },
        .@"enum" => |e| {
            var map: pbvalue.StructBuilder = .{};
            const nested = try m.nest(it);
            const name = if (e.variant_name) |n| try jStr(it, nested, n) else try jNum(it, nested, e.variant_index);
            try nested.chargeOr(it, "@variant".len);
            try map.put(it.arena, "@variant", name);
            try fieldsJson(it, e.fields, nested, &map);
            try m.chargeOr(it, VS);
            return .{ .@"struct" = map.finish() };
        },
        .vector => |vv| {
            const items = try it.arena.alloc(PV, vv.elements.len);
            const nested = try m.nest(it);
            for (vv.elements, items) |e, *o| o.* = try formatJson(it, e, nested);
            try m.chargeOr(it, VS);
            return .{ .list = items };
        },
        .slice => |s| {
            var c: Cursor = .{ .b = s.bytes };
            const out = try InterpRpc.value(it, &c, s.layout, m);
            if (c.pos != c.b.len) return it.trailing(c);
            return out;
        },
    }
}

fn fieldsJson(it: *Interp, f: FieldsV, m: OutMeter, map: *pbvalue.StructBuilder) Fail!void {
    switch (f) {
        .positional => |vs| for (vs, 0..) |x, i| {
            const j = try formatJson(it, x, m);
            const key = try std.fmt.allocPrint(it.arena, "pos{d}", .{i});
            try m.chargeOr(it, key.len);
            try map.put(it.arena, key, j);
        },
        .named => |ns| for (ns) |x| {
            const j = try formatJson(it, x.value, m);
            try m.chargeOr(it, x.name.len);
            try map.put(it.arena, x.name, j);
        },
    }
}

/// The first field of a string-like struct, read as a BCS `String` (RpcVisitor).
fn rpcStringField(it: *Interp, c: *Cursor, s: *const movelayout.Struct) Fail![]const u8 {
    if (s.fields.len == 0) return it.bcsErr("unexpected type");
    const lo = c.pos;
    try it.skip(c, &s.fields[0].layout);
    const raw = c.b[lo..c.pos];
    for (s.fields[1..]) |*f| try it.skip(c, &f.layout);
    // `bcs::from_bytes::<String>` failures are `UnexpectedType`
    const text = bcsBytes(it, raw) catch |e| switch (e) {
        error.Format => return it.bcsErr("unexpected type"),
        else => return e,
    };
    if (!std.unicode.utf8ValidateSlice(text)) return it.bcsErr("unexpected type");
    return text;
}

fn isBalanceLayout(s: *const movelayout.Struct) bool {
    return isTag(&s.type_, &two, "balance", "Balance") and s.type_.type_args.len == 1 and s.fields.len == 1 and
        std.mem.eql(u8, s.fields[0].name, "value") and s.fields[0].layout == .u64;
}

const InterpRpc = struct {
    fn value(it: *Interp, c: *Cursor, l: *const Layout, m: OutMeter) Fail!PV {
        switch (l.*) {
            .bool => {
                const b = try it.readBool(c);
                try m.chargeOr(it, VS);
                return .{ .bool = b };
            },
            .u8 => return jNum(it, m, try it.readInt(c, u8)),
            .u16 => return jNum(it, m, try it.readInt(c, u16)),
            .u32 => return jNum(it, m, try it.readInt(c, u32)),
            .u64 => return jDec(it, m, u64, try it.readInt(c, u64)),
            .u128 => return jDec(it, m, u128, try it.readInt(c, u128)),
            .u256 => return jDec(it, m, u256, try it.readInt(c, u256)),
            .address, .signer => return jAddr(it, m, (try it.take(c, 32))[0..32]),
            .vector => |el| {
                const n = try it.readUleb(c);
                if (el.* == .u8) {
                    if (c.b.len - c.pos < n) return it.visitorErr("unexpected end of input");
                    const raw = try it.take(c, @intCast(n));
                    return jStr(it, m, try b64(it.arena, .{}, raw));
                }
                const nested = try m.nest(it);
                var items: std.ArrayList(PV) = .empty;
                var i: u64 = 0;
                while (i < n) : (i += 1) try items.append(it.arena, try value(it, c, el, nested));
                try m.chargeOr(it, VS);
                return .{ .list = items.items };
            },
            .@"struct" => |s| {
                if (isStringLayout(s)) return jStr(it, m, try rpcStringField(it, c, s));
                if (isUidLayout(l) or isIdLayout(l)) {
                    const lo = c.pos;
                    try it.skip(c, &s.fields[0].layout);
                    if (c.pos - lo != 32) return it.bcsErr("unexpected type");
                    return jAddr(it, m, c.b[lo..][0..32]);
                }
                if (isTag(&s.type_, &one, "option", "Option")) {
                    if (!isOptionLayout(s)) return it.bcsErr("expected option type");
                    const n = try it.readUleb(c);
                    return switch (n) {
                        0 => blk: {
                            try m.chargeOr(it, VS);
                            break :blk .null;
                        },
                        1 => try value(it, c, s.fields[0].layout.vector, m),
                        else => it.bcsErr("expected option type"),
                    };
                }
                if (isBalanceLayout(s)) return jDec(it, m, u64, try it.readInt(c, u64));
                var map: pbvalue.StructBuilder = .{};
                const nested = try m.nest(it);
                for (s.fields) |*f| {
                    const v = try value(it, c, &f.layout, nested);
                    try nested.chargeOr(it, f.name.len);
                    try map.put(it.arena, f.name, v);
                }
                try m.chargeOr(it, VS);
                return .{ .@"struct" = map.finish() };
            },
            .@"enum" => |e| {
                const v = try it.readTag(c, e);
                var map: pbvalue.StructBuilder = .{};
                const nested = try m.nest(it);
                const name = try jStr(it, nested, v.name);
                try nested.chargeOr(it, "@variant".len);
                try map.put(it.arena, "@variant", name);
                for (v.fields) |*f| {
                    const x = try value(it, c, &f.layout, nested);
                    try nested.chargeOr(it, f.name.len);
                    try map.put(it.arena, f.name, x);
                }
                try m.chargeOr(it, VS);
                return .{ .@"struct" = map.finish() };
            },
        }
    }
};

/// writer.rs `write`: one bare or `:json` expression gives a structured value (atoms as their
/// string), anything else a string.
pub fn write(it: *Interp, m: OutMeter, strands: []const VStrand) Fail!PV {
    if (strands.len == 1 and strands[0] == .value and (strands[0].value.transform == null or strands[0].value.transform.? == .json)) {
        const s = strands[0].value;
        if (s.transform == null) {
            const save = it.err;
            if (atomOf(it, s.value)) |a| {
                var w: SW = .{ .meter = m, .arena = it.arena };
                formatAsStr(it, a, &w) catch |e| {
                    if (e == error.Format) it.err = it.err.forExprAtOffset(s.offset);
                    return e;
                };
                return .{ .string = w.out.items };
            } else |e| switch (e) {
                error.OutOfMemory => return e,
                error.Format => it.err = save,
            }
        }
        return formatJson(it, s.value, m) catch |e| {
            if (e == error.Format) it.err = it.err.forExprAtOffset(s.offset);
            return e;
        };
    }
    var w: SW = .{ .meter = m, .arena = it.arena };
    for (strands) |s| switch (s) {
        .text => |t| try w.write(it, t),
        .value => |v| formatValue(it, v.value, v.transform orelse .str, &w) catch |e| {
            if (e == error.Format) it.err = it.err.forExprAtOffset(v.offset);
            return e;
        },
    };
    return .{ .string = w.out.items };
}

