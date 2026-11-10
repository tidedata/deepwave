//! sui.rpc.v2 `Object` rendering from BCS(Object), byte-equal to `Merge<&Object> for Object` in
//! sui-types `rpc_proto_conversions.rs` (1983-2150). Note the Rust quirk kept here: the Move
//! object / package merges set `object_id` and `version` regardless of the mask.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const proto = @import("proto.zig");
const mask = @import("mask.zig");
const b58 = @import("b58.zig");
const typestr = @import("typestr.zig");
const movelayout = @import("movelayout.zig");
const render_json = @import("render_json.zig");
const pbvalue = @import("pbvalue.zig");

const Mask = mask.Mask;
pub const Error = proto.Error || bcs.DecodeError || Allocator.Error || error{ InvalidValue, Unsupported };

pub fn str32(w: *proto.Writer, field: u32, d: *const [32]u8) proto.Error!void {
    var buf: [b58.max_len_32]u8 = undefined;
    try w.string(field, b58.encode32Cached(&buf, d));
}

/// "0x" + 64 hex, the form of `ObjectID::to_canonical_string(true)` and `SuiAddress` Display.
pub fn addrStr(w: *proto.Writer, field: u32, a: *const [32]u8) proto.Error!void {
    var buf: [66]u8 = undefined;
    var o: typestr.Out = .{ .buf = &buf };
    o.address(a) catch unreachable;
    try w.string(field, o.str());
}

pub fn writeOwner(w: *proto.Writer, field: u32, o: types.Owner) Error!void {
    const m = try w.begin(field, 80);
    switch (o) {
        .AddressOwner => |a| {
            try w.uint(1, 1);
            try addrStr(w, 2, &a.@"0");
        },
        .ObjectOwner => |a| {
            try w.uint(1, 2);
            try addrStr(w, 2, &a.@"0");
        },
        .Shared => |s| {
            try w.uint(1, 3);
            try w.uint(3, s.initial_shared_version.@"0");
        },
        .Immutable => try w.uint(1, 4),
        .ConsensusAddressOwner => |c| {
            try w.uint(1, 5);
            try addrStr(w, 2, &c.owner.@"0");
            try w.uint(3, c.start_version.@"0");
        },
        .Party => return error.Unsupported, // `todo!("Party WIP")` panics in Rust 1.83.1
    }
    try w.end(m);
}

/// What `json` and `display` need (render.rs `render_object_to_proto`): the package resolver
/// (with the request's overlay), an optional shared JSON budget (null: each value gets
/// `max_json_move_value_size`), and the Display v2 renderer.
pub const Ctx = struct {
    resolver: *movelayout.Resolver,
    json_budget: ?*usize = null,
    display: ?Display = null,
    /// False leaves `json` out (test harnesses whose truth was recorded without packages).
    json_on: bool = true,

    pub const Display = struct {
        ctx: *const anyopaque,
        /// Writes field `field` (sui.rpc.v2 Display) for a Move object, or nothing (Rust `None`).
        write: *const fn (ctx: *const anyopaque, arena: Allocator, w: *proto.Writer, field: u32, tag: *const types.StructTag, contents: []const u8, resolver: *movelayout.Resolver) Error!void,
    };

    /// `render_json_with_budget` for a value of struct type `tag`; null where Rust gives `None`.
    pub fn json(c: *const Ctx, arena: Allocator, tag: *const types.StructTag, contents: []const u8) Allocator.Error!?pbvalue.Value {
        if (!c.json_on) return null;
        var fresh: usize = render_json.default_value_budget;
        const budget = c.json_budget orelse &fresh;
        return render_json.renderTyped(arena, c.resolver, tag, contents, budget);
    }
};

/// Object message body for mask `m`. `raw` is BCS(Object); `obj` its decoded form.
pub fn writeObjectBody(arena: Allocator, w: *proto.Writer, m: Mask, raw: []const u8, obj: types.Object) Error!void {
    return writeObjectBodyCtx(arena, w, m, raw, obj, null);
}

/// As `writeObjectBody`, rendering `json` and `display` when `ctx` is given (they are left out
/// without one).
pub fn writeObjectBodyCtx(arena: Allocator, w: *proto.Writer, m: Mask, raw: []const u8, obj: types.Object, ctx: ?*const Ctx) Error!void {
    if (m.contains("bcs")) {
        const mm = try w.begin(1, raw.len + 16);
        try w.string(1, "Object");
        try w.bytes(2, raw);
        try w.end(mm);
    }
    const id = switch (obj.data) {
        .Move => |mo| objectIdOf(mo.contents),
        .Package => |p| p.id.@"0".@"0",
    };
    const version = switch (obj.data) {
        .Move => |mo| mo.version.@"0",
        .Package => |p| p.version.@"0",
    };
    // field 2 (object_id) and 3 (version) are always written by the data merge
    try addrStr(w, 2, &id);
    try w.uint(3, version);
    if (m.contains("digest")) try str32(w, 4, &types.digest.objectDigest(raw));
    if (m.contains("owner")) try writeOwner(w, 5, obj.owner);
    switch (obj.data) {
        .Move => |mo| {
            if (m.contains("object_type")) {
                var o = typestr.scratch();
                try typestr.moveObjectType(&o, mo.type_);
                try w.string(6, o.str());
            }
            if (m.contains("has_public_transfer")) try w.uint(7, @intFromBool(mo.has_public_transfer));
            if (m.contains("contents")) {
                var o = typestr.scratch();
                try typestr.moveObjectType(&o, mo.type_);
                const mm = try w.begin(8, mo.contents.len + o.len + 8);
                try w.string(1, o.str());
                try w.bytes(2, mo.contents);
                try w.end(mm);
            }
        },
        .Package => |p| {
            if (m.contains("object_type")) try w.string(6, "package");
            if (m.contains("package")) try writePackage(arena, w, 9, p);
        },
    }
    if (m.contains("previous_transaction")) try str32(w, 10, &obj.previous_transaction.@"0".@"0");
    if (m.contains("storage_rebate")) try w.uint(11, obj.storage_rebate);
    var tag: ?types.StructTag = null;
    if (ctx != null) switch (obj.data) {
        .Move => |mo| tag = try movelayout.objectStructTag(arena, mo.type_),
        .Package => {},
    };
    if (m.contains("json")) if (ctx) |c| if (tag) |*t| {
        if (try c.json(arena, t, obj.data.Move.contents)) |v| try pbvalue.write(w, 100, &v);
    };
    if (m.contains("balance")) switch (obj.data) {
        .Move => |mo| if (coinBalance(mo)) |b| try w.uint(101, b),
        .Package => {},
    };
    if (m.contains("display")) if (ctx) |c| if (c.display) |d| if (tag) |*t| {
        try d.write(d.ctx, arena, w, 102, t, obj.data.Move.contents, c.resolver);
    };
}

fn objectIdOf(contents: []const u8) [32]u8 {
    return contents[0..32].*;
}

fn coinBalance(mo: types.MoveObject) ?u64 {
    switch (mo.type_.@"0") {
        .GasCoin, .Coin => {},
        else => return null,
    }
    // Coin { id: UID, balance: Balance } = 32 + 8 bytes
    if (mo.contents.len != 40) return null;
    return std.mem.readInt(u64, mo.contents[32..40], .little);
}

fn writePackage(arena: Allocator, w: *proto.Writer, field: u32, p: types.MovePackage) Error!void {
    const m = try w.begin(field, 1024);
    // BCS maps are ordered by serialized key (length first); Rust's BTreeMap<String, _> iterates
    // by string content, which is what the proto lists.
    const Entry = @TypeOf(p.module_map.entries[0]);
    const sorted = try arena.dupe(Entry, p.module_map.entries);
    std.mem.sort(Entry, sorted, {}, struct {
        fn lt(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.key.@"0", b.key.@"0");
        }
    }.lt);
    for (sorted) |e| {
        const mm = try w.begin(4, e.value.len + e.key.@"0".len + 16);
        try w.string(1, e.key.@"0");
        try w.bytes(2, e.value);
        try w.end(mm);
    }
    for (p.type_origin_table) |t| {
        const mm = try w.begin(5, 128);
        try w.string(1, t.module_name.@"0");
        try w.string(2, t.datatype_name.@"0");
        try addrStr(w, 3, &t.package.@"0".@"0");
        try w.end(mm);
    }
    for (p.linkage_table.entries) |e| {
        const mm = try w.begin(6, 150);
        try addrStr(w, 1, &e.key.@"0".@"0");
        try addrStr(w, 2, &e.value.upgraded_id.@"0".@"0");
        try w.uint(3, e.value.upgraded_version.@"0");
        try w.end(mm);
    }
    try w.end(m);
}

/// Parses BCS(Object) and writes the message body for `m`.
pub fn writeObject(arena: Allocator, w: *proto.Writer, m: Mask, raw: []const u8) Error!void {
    return writeObjectCtx(arena, w, m, raw, null);
}

/// `render_object_to_proto`: as `writeObject`, with `json`/`display` from `ctx`.
pub fn writeObjectCtx(arena: Allocator, w: *proto.Writer, m: Mask, raw: []const u8, ctx: ?*const Ctx) Error!void {
    const obj = try bcs.decode(types.Object, arena, raw);
    try writeObjectBodyCtx(arena, w, m, raw, obj, ctx);
}
