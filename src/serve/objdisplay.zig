//! `display` for an object (render.rs `render_object_display`): the Display v2 object of the
//! object's type is the live object at `display_object_id(type)` (a derived object of the
//! display registry 0xd keyed by `DisplayKey<T>`), its templates are rendered by `display/`
//! over the object's annotated layout; the interpreter loads further objects through the same
//! object source. No Display object, undecodable Display, no layout or an unparsable template
//! leave the field out (Rust `None`).
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const hash = @import("hash");
const proto = @import("proto.zig");
const movelayout = @import("movelayout.zig");
const render_object = @import("render_object.zig");
const display = @import("display/root.zig");

pub const Error = render_object.Error;

const registry: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 0xd;
    break :blk a;
};
const two: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    break :blk a;
};

/// `derive_dynamic_field_id(parent, key_type_tag, key_bytes)`.
pub fn dynamicFieldId(arena: Allocator, parent: *const [32]u8, key_tag: *const types.TypeTag, key_bytes: []const u8) Allocator.Error![32]u8 {
    const tag = try bcs.encodeAlloc(types.TypeTag, arena, key_tag);
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, key_bytes.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &len_le, key_bytes, tag });
}

/// `display_registry::display_object_id(T)`.
pub fn displayObjectId(arena: Allocator, t: *const types.StructTag) Allocator.Error![32]u8 {
    const inner = try arena.alloc(types.TypeTag, 1);
    inner[0] = .{ .@"struct" = t.* };
    const key = try arena.alloc(types.TypeTag, 1);
    key[0] = .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "display_registry" }, .name = .{ .@"0" = "DisplayKey" }, .type_args = inner } };
    const wrapper: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "derived_object" }, .name = .{ .@"0" = "DerivedObjectKey" }, .type_args = key } };
    return dynamicFieldId(arena, &registry, &wrapper, &.{0});
}

/// `sui_types::display_registry::Display { id: UID, fields: VecMap<String, String>, cap_id: Option<ID> }`.
const DisplayV2 = struct {
    id: [32]u8,
    fields: []const struct { key: bcs.String, value: bcs.String },
    cap_id: ?[32]u8,
};

/// The live-object view the display interpreter and the hook share.
pub const Hook = struct {
    src: movelayout.PackageSource,
    limits: display.Limits = .{},

    pub fn ctxDisplay(h: *const Hook) render_object.Ctx.Display {
        return .{ .ctx = h, .write = write };
    }

    /// A hook over `src` allocated in `arena` (one per request).
    pub fn create(arena: Allocator, src: movelayout.PackageSource) Allocator.Error!render_object.Ctx.Display {
        const h = try arena.create(Hook);
        h.* = .{ .src = src };
        return h.ctxDisplay();
    }

    const StoreCtx = struct { src: movelayout.PackageSource, resolver: *movelayout.Resolver };

    fn latest(ctx: *const anyopaque, arena: Allocator, id: *const [32]u8) Allocator.Error!?display.Loaded {
        const s: *const StoreCtx = @ptrCast(@alignCast(ctx));
        const raw = s.src.get(s.src.ctx, id) orelse return null;
        const obj = bcs.decode(types.Object, arena, raw) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        const mo = switch (obj.data) {
            .Move => |m| m,
            .Package => return null,
        };
        const tag = try movelayout.objectStructTag(arena, mo.type_);
        const l = (try s.resolver.structLayout(&tag)) orelse return null;
        return .{ .layout = l, .bytes = mo.contents };
    }

    fn write(ctx: *const anyopaque, arena: Allocator, w: *proto.Writer, field: u32, tag: *const types.StructTag, contents: []const u8, resolver: *movelayout.Resolver) Error!void {
        const h: *const Hook = @ptrCast(@alignCast(ctx));
        const did = try displayObjectId(arena, tag);
        const raw = h.src.get(h.src.ctx, &did) orelse return;
        const obj = bcs.decode(types.Object, arena, raw) catch return;
        const mo = switch (obj.data) {
            .Move => |m| m,
            .Package => return,
        };
        const d = bcs.decode(DisplayV2, arena, mo.contents) catch return;
        const fields = try arena.alloc([2][]const u8, d.fields.len);
        for (d.fields, fields) |f, *o| o.* = .{ f.key.@"0", f.value.@"0" };
        const root = (try resolver.structLayout(tag)) orelse return;
        const sc = try arena.create(StoreCtx);
        sc.* = .{ .src = h.src, .resolver = resolver };
        const store: display.Store = .{ .ctx = sc, .latest = latest };
        _ = try display.render(arena, w, field, fields, &root, contents, store, h.limits);
    }
};

test {
    std.testing.refAllDecls(@This());
}
