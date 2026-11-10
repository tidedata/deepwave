//! Dynamic-field rendering for ListDynamicFields: the port of sui-rpc-api 1.83.1
//! `list_dynamic_fields::{get_dynamic_field, load_dynamic_field}` with
//! `sui_types::dynamic_field::visitor::FieldVisitor` (split a `0x2::dynamic_field::Field<Name,
//! Value>` object's contents into the name and value bytes with the Move layout of the field type).
//!
//! The layout comes from `serve.movelayout` (the render lane's port of the annotated layout
//! resolver), fed by the store's live packages. Rust answers None for the entry (it is skipped)
//! whenever the layout or the field visit fails; so does `writeField`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const hash = @import("hash");
const proto = serve.proto;
const typestr = serve.typestr;
const render_object = serve.render_object;
const movelayout = serve.movelayout;
const Layout = movelayout.Layout;
const Mask = serve.mask.Mask;

const sui_framework: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    break :blk a;
};

/// `derive_dynamic_field_id`: blake2b256(0xf0 || parent || u64le(len(key)) || key || bcs(key type)).
pub fn dynamicFieldId(arena: Allocator, parent: *const [32]u8, key_type: types.TypeTag, key_bcs: []const u8) ![32]u8 {
    const tb = try bcs.encodeAlloc(types.TypeTag, arena, &key_type);
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, key_bcs.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &len_le, key_bcs, tb });
}

/// One request's state: the layout resolver (packages and modules parse once per request).
pub const Session = struct {
    arena: Allocator,
    snap: *const store.Snapshot,
    resolver: movelayout.Resolver,
    /// Layouts by BCS(StructTag) of the field object type (null: unresolvable).
    layouts: std.StringHashMapUnmanaged(?Layout) = .empty,
    /// `json`/`display` for `field_object` and `child_object` (null: left out).
    render: ?*const render_object.Ctx = null,

    pub fn init(arena: Allocator, snap: *const store.Snapshot) Session {
        return .{ .arena = arena, .snap = snap, .resolver = movelayout.Resolver.init(arena, .{ .ctx = snap, .get = getPackage }) };
    }

    fn getPackage(ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 {
        const snap: *const store.Snapshot = @ptrCast(@alignCast(ctx));
        const o = snap.liveObject(id) orelse return null;
        return o.bytes;
    }

    fn fieldLayout(s: *Session, tag: *const types.StructTag) !?Layout {
        const key = try bcs.encodeAlloc(types.StructTag, s.arena, tag);
        const gop = try s.layouts.getOrPut(s.arena, key);
        if (gop.found_existing) return gop.value_ptr.*;
        gop.value_ptr.* = null;
        const l = try s.resolver.structLayout(tag);
        gop.value_ptr.* = l;
        return l;
    }
};

pub fn shouldLoad(m: Mask) bool {
    @setEvalBranchQuota(20000);
    return m.contains("kind") or m.contains("name") or m.contains("value_type") or m.contains("child_id") or
        m.contains("child_object") or m.contains("field_object");
}

fn isStruct(t: *const types.StructTag, addr: *const [32]u8, module: []const u8, name: []const u8) bool {
    return std.mem.eql(u8, &t.address.@"0", addr) and std.mem.eql(u8, t.module.@"0", module) and std.mem.eql(u8, t.name.@"0", name);
}

/// Skips one value of `l` (BCS). Errors on truncated input or bad lengths/tags.
pub fn skipValue(r: *bcs.Reader, l: Layout) !void {
    switch (l) {
        .bool => {
            const b = try r.int(u8);
            if (b > 1) return error.InvalidValue;
        },
        .u8 => _ = try r.bytes(1),
        .u16 => _ = try r.bytes(2),
        .u32 => _ = try r.bytes(4),
        .u64 => _ = try r.bytes(8),
        .u128 => _ = try r.bytes(16),
        .u256 => _ = try r.bytes(32),
        .address, .signer => _ = try r.bytes(32),
        .vector => |inner| {
            const n = try r.length();
            switch (inner.*) {
                .u8 => _ = try r.bytes(n),
                .u16 => _ = try r.bytes(n * 2),
                .u32 => _ = try r.bytes(n * 4),
                .u64 => _ = try r.bytes(n * 8),
                .u128 => _ = try r.bytes(n * 16),
                .u256, .address, .signer => _ = try r.bytes(n * 32),
                else => for (0..n) |_| try skipValue(r, inner.*),
            }
        },
        .@"struct" => |s| for (s.fields) |f| try skipValue(r, f.layout),
        .@"enum" => |e| {
            const tag = try r.uleb32();
            if (tag >= e.variants.len) return error.InvalidValue;
            for (e.variants[tag].fields) |f| try skipValue(r, f.layout);
        },
    }
}

fn canonical(arena: Allocator, t: types.TypeTag) ![]const u8 {
    var cap: usize = 256;
    while (true) : (cap *= 4) {
        const buf = try arena.alloc(u8, cap);
        var o: typestr.Out = .{ .buf = buf };
        typestr.typeTag(&o, t) catch continue;
        return o.str();
    }
}

fn writeBcs(w: *proto.Writer, field: u32, name: []const u8, value: []const u8) !void {
    const mark = try w.begin(field, name.len + value.len + 8);
    try w.string(1, name);
    try w.bytes(2, value);
    try w.end(mark);
}

const Split = struct {
    dof: bool,
    name_type: types.TypeTag,
    name_bytes: []const u8,
    value_type: types.TypeTag,
    value_bytes: []const u8,
};

/// `FieldVisitor::deserialize` over `Field<Name, Value>` contents. Null where Rust errors.
fn split(s: *Session, ty: *const types.StructTag, contents: []const u8) !?Split {
    const layout = (try s.fieldLayout(ty)) orelse return null;
    const st = switch (layout) {
        .@"struct" => |x| x,
        else => return null,
    };
    if (st.fields.len != 3) return null;
    var r = bcs.Reader.init(contents);
    skipValue(&r, st.fields[0].layout) catch return null; // id: UID
    const ns = r.pos();
    skipValue(&r, st.fields[1].layout) catch return null;
    const ne = r.pos();
    skipValue(&r, st.fields[2].layout) catch return null;
    const ve = r.pos();
    r.finish() catch return null;
    const name_t = ty.type_args[0];
    const value_t = ty.type_args[1];
    // DynamicObject when the name is `0x2::dynamic_object_field::Wrapper<T>`; the name is then T
    // (Wrapper { name: T } has T's bytes) and the value an ID.
    if (name_t == .@"struct") {
        const nt = name_t.@"struct";
        if (isStruct(&nt, &sui_framework, "dynamic_object_field", "Wrapper") and nt.type_args.len == 1) {
            if (ve - ne != 32) return null;
            return .{ .dof = true, .name_type = nt.type_args[0], .name_bytes = contents[ns..ne], .value_type = value_t, .value_bytes = contents[ne..ve] };
        }
    }
    return .{ .dof = false, .name_type = name_t, .name_bytes = contents[ns..ne], .value_type = value_t, .value_bytes = contents[ne..ve] };
}

/// Writes one DynamicField message body (fields in number order, as prost encodes). Returns false
/// when sui-node skips the entry (`get_dynamic_field` returning None).
pub fn writeField(s: *Session, w: *proto.Writer, m: Mask, parent: *const [32]u8, field_id: *const [32]u8) !bool {
    @setEvalBranchQuota(20000);
    const a = s.arena;
    if (!shouldLoad(m)) {
        if (m.contains("parent")) try render_object.addrStr(w, 2, parent);
        if (m.contains("field_id")) try render_object.addrStr(w, 3, field_id);
        return true;
    }
    const plain = struct {
        fn f(w2: *proto.Writer, m2: Mask, p: *const [32]u8, fid: *const [32]u8) !bool {
            @setEvalBranchQuota(20000);
            if (m2.contains("parent")) try render_object.addrStr(w2, 2, p);
            if (m2.contains("field_id")) try render_object.addrStr(w2, 3, fid);
            return true;
        }
    }.f;
    const fo = s.snap.liveObject(field_id) orelse return plain(w, m, parent, field_id);
    const obj = bcs.decode(types.Object, a, fo.bytes) catch return false;
    const mo = switch (obj.data) {
        .Move => |x| x,
        .Package => return plain(w, m, parent, field_id),
    };
    const ty = try movelayout.objectStructTag(a, mo.type_);
    if (!isStruct(&ty, &sui_framework, "dynamic_field", "Field") or ty.type_args.len != 2) return plain(w, m, parent, field_id);
    const sp = (try split(s, &ty, mo.contents)) orelse return false;

    // DynamicObject: the child is needed for value_type and child_object.
    var child_raw: ?[]const u8 = null;
    var child_type: ?[]const u8 = null;
    if (sp.dof and (m.contains("value_type") or m.contains("child_object"))) {
        const cid: *const [32]u8 = sp.value_bytes[0..32];
        const co = s.snap.liveObject(cid) orelse return false;
        const cobj = bcs.decode(types.Object, a, co.bytes) catch return false;
        const cmo = switch (cobj.data) {
            .Move => |x| x,
            .Package => return false,
        };
        child_raw = co.bytes;
        child_type = try canonical(a, .{ .@"struct" = try movelayout.objectStructTag(a, cmo.type_) });
    }

    if (m.contains("kind")) try w.uint(1, if (sp.dof) 2 else 1);
    if (m.contains("parent")) try render_object.addrStr(w, 2, parent);
    if (m.contains("field_id")) try render_object.addrStr(w, 3, field_id);
    if (m.subtree("field_object")) |sub| {
        const mark = try w.begin(4, fo.bytes.len + 256);
        try render_object.writeObjectCtx(a, w, sub, fo.bytes, s.render);
        try w.end(mark);
    }
    if (m.contains("name")) try writeBcs(w, 5, try canonical(a, sp.name_type), sp.name_bytes);
    if (m.contains("value")) try writeBcs(w, 6, try canonical(a, sp.value_type), sp.value_bytes);
    if (sp.dof) {
        if (m.contains("value_type")) try w.string(7, child_type.?);
        if (m.contains("child_id")) try render_object.addrStr(w, 8, sp.value_bytes[0..32]);
        if (m.subtree("child_object")) |sub| {
            const mark = try w.begin(9, child_raw.?.len + 256);
            try render_object.writeObjectCtx(a, w, sub, child_raw.?, s.render);
            try w.end(mark);
        }
    } else if (m.contains("value_type")) try w.string(7, try canonical(a, sp.value_type));
    return true;
}

test "dynamicFieldId of a u64 key" {
    // derive_dynamic_field_id(0x5, u64, bcs(7u64)) matches the formula's byte layout.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    var parent: [32]u8 = @splat(0);
    parent[31] = 5;
    const key = [_]u8{ 7, 0, 0, 0, 0, 0, 0, 0 };
    const id = try dynamicFieldId(arena_state.allocator(), &parent, .u64, &key);
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, 8, .little);
    const want = hash.blake2b256(&.{ &[_]u8{0xf0}, &parent, &len_le, &key, &[_]u8{2} });
    try std.testing.expectEqualSlices(u8, &want, &id);
}
