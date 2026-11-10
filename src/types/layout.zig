//! Move runtime layouts and values (move-core-types 1.83.1 `runtime_value`): `MoveTypeLayout`
//! and friends with their serde/BCS form, and layout-driven decode/encode of a `Value`
//! (`MoveValue::simple_deserialize` / `bcs::to_bytes(&MoveValue)`). This is the bridge the
//! Move VM uses between BCS bytes and values.
//!
//! Depth: the layout types are named serde containers, so a layout nests at most 500 deep like
//! any bcs value. Values are read with `deserialize_seq`/`deserialize_tuple`, which bcs does not
//! count, so Rust has no value depth limit (it overflows its stack instead); deepwave stops at
//! `max_value_depth` with `DepthExceeded` to stay stack safe. The other intended difference: a
//! vector of more than 2^20 zero-width elements (empty struct layouts, which Move never makes)
//! is refused rather than materialized.
const std = @import("std");
const bcs = @import("bcs");
const Allocator = std.mem.Allocator;
const Reader = bcs.Reader;

pub const max_value_depth: usize = 4096;
/// move-core-types VARIANT_TAG_MAX_VALUE.
pub const variant_tag_max: u8 = 127;

pub const MoveTypeLayout = union(enum) {
    @"bool": void,
    @"u8": void,
    @"u64": void,
    @"u128": void,
    address: void,
    vector: *const MoveTypeLayout,
    @"struct": *const MoveStructLayout,
    signer: void,
    @"u16": void,
    @"u32": void,
    @"u256": void,
    @"enum": *const MoveEnumLayout,
};
pub const MoveStructLayout = struct { @"0": []const MoveTypeLayout };
pub const MoveEnumLayout = struct { @"0": []const []const MoveTypeLayout };
pub const MoveDatatypeLayout = union(enum) {
    @"struct": *const MoveStructLayout,
    @"enum": *const MoveEnumLayout,
};

pub const Value = union(enum) {
    bool: bool,
    u8: u8,
    u16: u16,
    u32: u32,
    u64: u64,
    u128: u128,
    u256: u256,
    address: [32]u8,
    signer: [32]u8,
    vector: []const Value,
    @"struct": []const Value,
    variant: Variant,
    /// A `vector<u8>` held packed (one byte per element, not one `Value`). Only the packed
    /// producers make it (`decodePacked`, the VM host's `toLayout`, natives' `bytesValue`); every
    /// reader of a `vector<u8>` from those paths accepts both forms (`byteSlice`, `vecLen`).
    bytes: []const u8,

    pub const Variant = struct { tag: u8, fields: []const Value };

    /// Elements of a vector value; a packed `vector<u8>` is expanded into `arena`.
    pub fn items(v: Value, arena: Allocator) Allocator.Error![]const Value {
        return switch (v) {
            .vector => |xs| xs,
            .bytes => |b| blk: {
                const out = try arena.alloc(Value, b.len);
                for (out, b) |*o, x| o.* = .{ .u8 = x };
                break :blk out;
            },
            else => unreachable,
        };
    }

    /// Number of elements of a vector value (either form).
    pub fn vecLen(v: Value) usize {
        return switch (v) {
            .vector => |xs| xs.len,
            .bytes => |b| b.len,
            else => unreachable,
        };
    }

    /// Value equality across the two `vector<u8>` forms.
    pub fn eql(a: *const Value, b: *const Value) bool {
        if (a.* == .bytes or b.* == .bytes) {
            if (a.* == .bytes and b.* == .bytes) return std.mem.eql(u8, a.bytes, b.bytes);
            const pb, const pv = if (a.* == .bytes) .{ a.bytes, b } else .{ b.bytes, a };
            if (pv.* != .vector or pv.vector.len != pb.len) return false;
            for (pv.vector, pb) |e, x| if (e != .u8 or e.u8 != x) return false;
            return true;
        }
        if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
        return switch (a.*) {
            .bool => |x| x == b.bool,
            .u8 => |x| x == b.u8,
            .u16 => |x| x == b.u16,
            .u32 => |x| x == b.u32,
            .u64 => |x| x == b.u64,
            .u128 => |x| x == b.u128,
            .u256 => |x| x == b.u256,
            .address => |x| std.mem.eql(u8, &x, &b.address),
            .signer => |x| std.mem.eql(u8, &x, &b.signer),
            .vector => |xs| sliceEql(xs, b.vector),
            .@"struct" => |xs| sliceEql(xs, b.@"struct"),
            .variant => |va| va.tag == b.variant.tag and sliceEql(va.fields, b.variant.fields),
            .bytes => unreachable,
        };
    }

    fn sliceEql(xs: []const Value, ys: []const Value) bool {
        if (xs.len != ys.len) return false;
        for (xs, ys) |*x, *y| if (!eql(x, y)) return false;
        return true;
    }
};

/// The bytes of a `vector<u8>` value in either form: the packed slice itself, or the elements
/// copied into `arena`.
pub fn byteSlice(arena: Allocator, v: Value) Allocator.Error![]const u8 {
    return switch (v) {
        .bytes => |b| b,
        .vector => |xs| blk: {
            const out = try arena.alloc(u8, xs.len);
            for (out, xs) |*o, it| o.* = it.u8;
            break :blk out;
        },
        else => unreachable,
    };
}

pub const Error = bcs.DecodeError;

/// `MoveValue::simple_deserialize`: the whole of `bytes` must be exactly one value of `layout`.
pub fn decode(arena: Allocator, layout: *const MoveTypeLayout, bytes: []const u8) Error!Value {
    var r = Reader.init(bytes);
    const v = try decodeFrom(arena, layout, &r, 0);
    try r.finish();
    return v;
}

/// `decode`, with every `vector<u8>` as `.bytes` (copied out of `bytes` into `arena`).
pub fn decodePacked(arena: Allocator, layout: *const MoveTypeLayout, bytes: []const u8) Error!Value {
    var r = Reader.init(bytes);
    const v = try decodeImpl(true, arena, layout, &r, 0);
    try r.finish();
    return v;
}

pub fn decodeFrom(arena: Allocator, layout: *const MoveTypeLayout, r: *Reader, depth: usize) Error!Value {
    return decodeImpl(false, arena, layout, r, depth);
}

pub fn decodePackedFrom(arena: Allocator, layout: *const MoveTypeLayout, r: *Reader, depth: usize) Error!Value {
    return decodeImpl(true, arena, layout, r, depth);
}

fn decodeImpl(comptime packed_bytes: bool, arena: Allocator, layout: *const MoveTypeLayout, r: *Reader, depth: usize) Error!Value {
    if (depth > max_value_depth) return error.DepthExceeded;
    switch (layout.*) {
        .bool => return .{ .bool = try r.boolean() },
        .u8 => return .{ .u8 = try r.int(u8) },
        .u16 => return .{ .u16 = try r.int(u16) },
        .u32 => return .{ .u32 = try r.int(u32) },
        .u64 => return .{ .u64 = try r.int(u64) },
        .u128 => return .{ .u128 = try r.int(u128) },
        .u256 => return .{ .u256 = try r.int(u256) },
        .address => return .{ .address = (try r.bytes(32))[0..32].* },
        .signer => return .{ .signer = (try r.bytes(32))[0..32].* },
        .vector => |elem| {
            const n = try r.length();
            if (packed_bytes and elem.* == .u8) return .{ .bytes = try arena.dupe(u8, try r.bytes(n)) };
            // Never trust the length for the allocation: every element is at least 0 bytes in
            // theory (empty struct), so grow as elements are read.
            var list: std.ArrayList(Value) = .empty;
            var i: usize = 0;
            while (i < n) : (i += 1) {
                const before = r.at;
                try list.append(arena, try decodeImpl(packed_bytes, arena, elem, r, depth + 1));
                // Zero-width elements (an empty struct layout) consume no input, so a huge
                // length would only burn memory: Rust accepts it, deepwave refuses beyond the cap.
                if (r.at == before and n > 1 << 20) return error.LengthTooLarge;
            }
            return .{ .vector = list.items };
        },
        .@"struct" => |sl| return .{ .@"struct" = try decodeFields(packed_bytes, arena, sl.@"0", r, depth) },
        .@"enum" => |el| {
            const tag = try r.int(u8);
            if (tag > variant_tag_max) return error.InvalidEnumTag;
            if (tag >= el.@"0".len) return error.InvalidEnumTag;
            return .{ .variant = .{ .tag = tag, .fields = try decodeFields(packed_bytes, arena, el.@"0"[tag], r, depth) } };
        },
    }
}

fn decodeFields(comptime packed_bytes: bool, arena: Allocator, layouts: []const MoveTypeLayout, r: *Reader, depth: usize) Error![]const Value {
    const out = try arena.alloc(Value, layouts.len);
    for (layouts, out) |*l, *o| o.* = try decodeImpl(packed_bytes, arena, l, r, depth + 1);
    return out;
}

/// `bcs::to_bytes(&MoveValue)`.
pub fn encode(v: *const Value, w: anytype) bcs.EncodeError!void {
    switch (v.*) {
        .bool => |b| try w.int(u8, @intFromBool(b)),
        .u8 => |x| try w.int(u8, x),
        .u16 => |x| try w.int(u16, x),
        .u32 => |x| try w.int(u32, x),
        .u64 => |x| try w.int(u64, x),
        .u128 => |x| try w.int(u128, x),
        .u256 => |x| try w.int(u256, x),
        .address, .signer => |a| try w.bytes(&a),
        .vector => |items| {
            try w.uleb32(@intCast(items.len));
            for (items) |*e| try encode(e, w);
        },
        .bytes => |b| {
            try w.uleb32(@intCast(b.len));
            try w.bytes(b);
        },
        .@"struct" => |fields| for (fields) |*e| try encode(e, w),
        .variant => |va| {
            try w.int(u8, va.tag);
            for (va.fields) |*e| try encode(e, w);
        },
    }
}

pub fn encodeAlloc(a: Allocator, v: *const Value) Allocator.Error![]u8 {
    var cw: bcs.CountingWriter = .{};
    encode(v, &cw) catch unreachable;
    const buf = try a.alloc(u8, cw.n);
    var w = bcs.Writer.init(buf);
    encode(v, &w) catch unreachable;
    return buf;
}

test "layout value round trip" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const u8l: MoveTypeLayout = .@"u8";
    const fields = [_]MoveTypeLayout{ .@"bool", .{ .vector = &u8l } };
    const sl: MoveStructLayout = .{ .@"0" = &fields };
    const layout: MoveTypeLayout = .{ .@"struct" = &sl };
    const bytes = [_]u8{ 1, 3, 7, 8, 9 };
    const v = try decode(a, &layout, &bytes);
    try std.testing.expectEqualSlices(u8, &bytes, try encodeAlloc(a, &v));
    try std.testing.expectError(error.TrailingBytes, decode(a, &layout, &(bytes ++ [_]u8{0})));
    try std.testing.expectError(error.InvalidBool, decode(a, &layout, &[_]u8{ 2, 0 }));
}
