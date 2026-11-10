//! Comptime BCS codec: decode, validate-and-skip, encode and measure any Zig type that follows
//! the mapping in CONTRACTS.md section 2.3. One comptime walk per type, no runtime type info.
//!
//! Type shapes:
//!   bool, u8..u64, u128, u256, i8..i64      fixed width little endian
//!   void                                    nothing
//!   [N]T                                    N items, no length (u8 items: N raw bytes)
//!   []const T                               ULEB128 length + items (u8: borrowed from the input)
//!   ?T                                      tag byte 0/1 + value
//!   *const T                                Box<T>: transparent, allocated in the decode arena
//!   struct { .. }                           fields in order; counts as a container for depth
//!   struct { A, B } (tuple)                 items in order; no depth
//!   struct { @"0": T, bcs_newtype = true }  as T; counts as a container for depth
//!   union(enum)                             ULEB128 variant index + payload; counts for depth
//!   types with hooks                        `bcsDecode`, `bcsSkip`, `bcsEncode`, `bcsTree` (see Map, String)
const std = @import("std");
const Allocator = std.mem.Allocator;
const io = @import("io.zig");
const meta = @import("meta.zig");
pub const Reader = io.Reader;
pub const Writer = io.Writer;
pub const Error = io.Error;

pub const DecodeError = Error || Allocator.Error;
pub const EncodeError = error{NoSpace};

pub fn isNewtype(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "bcs_newtype");
}

/// Structs that are not containers for the depth limit: tuples, and the anonymous payload
/// structs of struct variants (bcs reads those with deserialize_tuple).
pub fn noDepth(comptime T: type) bool {
    return @typeInfo(T).@"struct".is_tuple or @hasDecl(T, "bcs_no_depth");
}

pub fn hasHooks(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union" => @hasDecl(T, "bcsDecode"),
        else => false,
    };
}

/// Lower bound of the wire size of one T in bytes (never recurses through unions or pointers).
pub fn minWire(comptime T: type) usize {
    if (hasHooks(T)) return if (@hasDecl(T, "bcs_min_wire")) T.bcs_min_wire else 0;
    return switch (@typeInfo(T)) {
        .bool => 1,
        .int => @sizeOf(T),
        .@"enum" => |e| @sizeOf(e.tag_type),
        .void => 0,
        .array => |a| a.len * minWire(a.child),
        .pointer => |p| if (p.size == .slice) 1 else 0,
        .optional => 1,
        .@"struct" => blk: {
            var n: usize = 0;
            for (meta.types(T)) |ft| n += minWire(ft);
            break :blk n;
        },
        .@"union" => 1,
        else => @compileError("bcs: unsupported type " ++ @typeName(T)),
    };
}

// ---------------------------------------------------------------- decode

/// Decodes a whole input. Slices of bytes borrow from `bytes`; other slices and boxes are
/// allocated from `arena`. Fails with TrailingBytes if input remains.
pub fn decode(comptime T: type, arena: Allocator, bytes: []const u8) DecodeError!T {
    var r = Reader.init(bytes);
    const v = try decodeFrom(T, arena, &r);
    try r.finish();
    return v;
}

pub fn decodeFrom(comptime T: type, arena: Allocator, r: *Reader) DecodeError!T {
    if (comptime hasHooks(T)) return T.bcsDecode(arena, r);
    switch (@typeInfo(T)) {
        .bool => return r.boolean(),
        .int => return r.int(T),
        .void => return {},
        .@"enum" => |e| return std.enums.fromInt(T, try r.int(e.tag_type)) orelse error.InvalidEnumTag,
        .array => |a| {
            if (a.child == u8) {
                return (try r.bytes(a.len))[0..a.len].*;
            }
            var out: T = undefined;
            for (&out) |*slot| slot.* = try decodeFrom(a.child, arena, r);
            return out;
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                const E = p.child;
                const n = try r.length();
                if (E == u8) return r.bytes(n);
                const min = comptime minWire(E);
                if (min > 0 and n > r.remaining() / min) {
                    // Cannot fit: replay as skips so the error is the one bcs reports first.
                    var i: usize = 0;
                    while (i < n) : (i += 1) try skip(E, r);
                    return error.EndOfInput;
                }
                const out = try arena.alloc(E, n);
                for (out) |*slot| slot.* = try decodeFrom(E, arena, r);
                return out;
            },
            .one => {
                const out = try arena.create(p.child);
                out.* = try decodeFrom(p.child, arena, r);
                return out;
            },
            else => @compileError("bcs: unsupported pointer " ++ @typeName(T)),
        },
        .optional => |o| {
            const tag = try r.int(u8);
            return switch (tag) {
                0 => null,
                1 => try decodeFrom(o.child, arena, r),
                else => error.InvalidEnumTag,
            };
        },
        .@"struct" => |s| {
            if (comptime noDepth(T)) {
                var out: T = undefined;
                inline for (s.field_names, s.field_types) |name, ft| @field(out, name) = try decodeFrom(ft, arena, r);
                return out;
            }
            try r.enter();
            var out: T = undefined;
            inline for (s.field_names, s.field_types) |name, ft| @field(out, name) = try decodeFrom(ft, arena, r);
            r.leave();
            return out;
        },
        .@"union" => |u| {
            try r.enter();
            const tag = try r.uleb32();
            switch (tag) {
                inline 0...u.field_names.len - 1 => |i| {
                    const payload = try decodeFrom(u.field_types[i], arena, r);
                    r.leave();
                    return @unionInit(T, u.field_names[i], payload);
                },
                else => return error.InvalidEnumTag,
            }
        },
        else => @compileError("bcs: unsupported type " ++ @typeName(T)),
    }
}

/// Validates one T at the cursor and skips it. Does not allocate.
pub fn skip(comptime T: type, r: *Reader) Error!void {
    if (comptime hasHooks(T)) return T.bcsSkip(r);
    switch (@typeInfo(T)) {
        .bool => _ = try r.boolean(),
        .int => _ = try r.bytes(@sizeOf(T)),
        .void => {},
        .@"enum" => |e| {
            if (std.enums.fromInt(T, try r.int(e.tag_type)) == null) return error.InvalidEnumTag;
        },
        .array => |a| {
            if (a.child == u8) {
                _ = try r.bytes(a.len);
            } else {
                var i: usize = 0;
                while (i < a.len) : (i += 1) try skip(a.child, r);
            }
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                const n = try r.length();
                if (p.child == u8) {
                    _ = try r.bytes(n);
                } else {
                    var i: usize = 0;
                    while (i < n) : (i += 1) try skip(p.child, r);
                }
            },
            .one => try skip(p.child, r),
            else => @compileError("bcs: unsupported pointer " ++ @typeName(T)),
        },
        .optional => |o| {
            const tag = try r.int(u8);
            switch (tag) {
                0 => {},
                1 => try skip(o.child, r),
                else => return error.InvalidEnumTag,
            }
        },
        .@"struct" => |s| {
            if (comptime noDepth(T)) {
                inline for (s.field_types) |ft| try skip(ft, r);
            } else {
                try r.enter();
                inline for (s.field_types) |ft| try skip(ft, r);
                r.leave();
            }
        },
        .@"union" => |u| {
            try r.enter();
            const tag = try r.uleb32();
            switch (tag) {
                inline 0...u.field_names.len - 1 => |i| try skip(u.field_types[i], r),
                else => return error.InvalidEnumTag,
            }
            r.leave();
        },
        else => @compileError("bcs: unsupported type " ++ @typeName(T)),
    }
}

/// Skips one T that was already validated (by `skip`, `View.init` or `View.take`): no bounds,
/// tag, UTF-8 or ordering checks, so it is the cheap path for walking to a field. Behaviour on
/// bytes that were not validated is undefined (it may read out of bounds in a release build).
pub fn skipTrusted(comptime T: type, r: *Reader) void {
    if (comptime hasHooks(T)) return T.bcsSkip(r) catch unreachable;
    switch (@typeInfo(T)) {
        .bool => r.at += 1,
        .int => r.at += @sizeOf(T),
        .void => {},
        .@"enum" => |e| r.at += @sizeOf(e.tag_type),
        .array => |a| {
            if (a.child == u8) {
                r.at += a.len;
            } else {
                var i: usize = 0;
                while (i < a.len) : (i += 1) skipTrusted(a.child, r);
            }
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                const n = r.uleb32() catch unreachable;
                if (p.child == u8) {
                    r.at += n;
                } else if (comptime fixedWire(p.child)) |w| {
                    r.at += @as(usize, n) * w;
                } else {
                    var i: usize = 0;
                    while (i < n) : (i += 1) skipTrusted(p.child, r);
                }
            },
            .one => skipTrusted(p.child, r),
            else => @compileError("bcs: unsupported pointer " ++ @typeName(T)),
        },
        .optional => |o| {
            const tag = r.buf[r.at];
            r.at += 1;
            if (tag == 1) skipTrusted(o.child, r);
        },
        .@"struct" => |s| {
            if (comptime fixedWire(T)) |w| {
                r.at += w;
            } else inline for (s.field_types) |ft| skipTrusted(ft, r);
        },
        .@"union" => |u| {
            const tag = r.uleb32() catch unreachable;
            switch (tag) {
                inline 0...u.field_names.len - 1 => |i| skipTrusted(u.field_types[i], r),
                else => unreachable,
            }
        },
        else => @compileError("bcs: unsupported type " ++ @typeName(T)),
    }
}

/// Wire size when it is the same for every value of T (no hooks, no variable parts), else null.
pub fn fixedWire(comptime T: type) ?usize {
    if (comptime hasHooks(T)) return null;
    return switch (@typeInfo(T)) {
        .bool => 1,
        .int => @sizeOf(T),
        .void => 0,
        .@"enum" => |e| @sizeOf(e.tag_type),
        .array => |a| if (fixedWire(a.child)) |w| w * a.len else null,
        .@"struct" => |s| blk: {
            var total: usize = 0;
            inline for (s.field_types) |ft| {
                total += fixedWire(ft) orelse break :blk null;
            }
            break :blk total;
        },
        else => null,
    };
}

// ---------------------------------------------------------------- encode

/// Encodes `v` into `w` (a `Writer` or `CountingWriter`).
pub fn encode(comptime T: type, v: *const T, w: anytype) EncodeError!void {
    if (comptime hasHooks(T)) return v.bcsEncode(w);
    switch (@typeInfo(T)) {
        .bool => try w.int(u8, @intFromBool(v.*)),
        .int => try w.int(T, v.*),
        .void => {},
        .@"enum" => |e| try w.int(e.tag_type, @intFromEnum(v.*)),
        .array => |a| {
            if (a.child == u8) {
                try w.bytes(&v.*);
            } else {
                for (v) |*e| try encode(a.child, e, w);
            }
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                try w.uleb32(@intCast(v.len));
                if (p.child == u8) {
                    try w.bytes(v.*);
                } else {
                    for (v.*) |*e| try encode(p.child, e, w);
                }
            },
            .one => try encode(p.child, v.*, w),
            else => @compileError("bcs: unsupported pointer " ++ @typeName(T)),
        },
        .optional => |o| {
            if (v.*) |*x| {
                try w.int(u8, 1);
                try encode(o.child, x, w);
            } else try w.int(u8, 0);
        },
        .@"struct" => |s| {
            inline for (s.field_names, s.field_types) |name, ft| try encode(ft, &@field(v.*, name), w);
        },
        .@"union" => |u| {
            const active = std.meta.activeTag(v.*);
            inline for (u.field_names, u.field_types, 0..) |name, ft, i| {
                if (active == @field(std.meta.Tag(T), name)) {
                    try w.uleb32(i);
                    try encode(ft, &@field(v.*, name), w);
                    return;
                }
            }
            unreachable;
        },
        else => @compileError("bcs: unsupported type " ++ @typeName(T)),
    }
}

/// Exact encoded size of `v`. Does not allocate.
pub fn encodedLen(comptime T: type, v: *const T) usize {
    var c: io.CountingWriter = .{};
    encode(T, v, &c) catch unreachable;
    return c.n;
}

/// Encodes into a freshly allocated buffer of the exact size.
pub fn encodeAlloc(comptime T: type, gpa: Allocator, v: *const T) Allocator.Error![]u8 {
    const buf = try gpa.alloc(u8, encodedLen(T, v));
    var w = Writer.init(buf);
    encode(T, v, &w) catch unreachable;
    return buf;
}
