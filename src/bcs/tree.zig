//! Canonical tree text (docs/CONFORMANCE.md, tools/dumper/src/tree.rs), rendered straight from
//! the Zig value by comptime reflection. Compact JSON, byte-for-byte what Rust writes.
const std = @import("std");
const codec = @import("codec.zig");
const wire = @import("wire.zig");
const Writer = std.Io.Writer;

pub const Error = Writer.Error;

const hex_digits = "0123456789abcdef";

pub fn writeHex(w: *Writer, b: []const u8) Error!void {
    try w.writeAll("\"0x");
    var buf: [512]u8 = undefined;
    var i: usize = 0;
    while (i < b.len) {
        const n: usize = @min(@as(usize, 256), b.len - i);
        for (b[i..][0..n], 0..) |x, j| {
            buf[2 * j] = hex_digits[x >> 4];
            buf[2 * j + 1] = hex_digits[x & 15];
        }
        try w.writeAll(buf[0 .. 2 * n]);
        i += n;
    }
    try w.writeByte('"');
}

/// serde_json-compatible string escaping as `push_json_str` in the dumper.
pub fn writeJsonStr(w: *Writer, s: []const u8) Error!void {
    try w.writeByte('"');
    var start: usize = 0;
    for (s, 0..) |c, i| {
        const esc: ?[]const u8 = switch (c) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            else => null,
        };
        if (esc != null or c < 0x20) {
            try w.writeAll(s[start..i]);
            if (esc) |e| {
                try w.writeAll(e);
            } else {
                try w.writeAll("\\u00");
                try w.writeByte(hex_digits[c >> 4]);
                try w.writeByte(hex_digits[c & 15]);
            }
            start = i + 1;
        }
    }
    try w.writeAll(s[start..]);
    try w.writeByte('"');
}

/// True when a value of type T renders as a single byte (u8 or a transparent wrapper of one).
pub fn isByteLike(comptime T: type) bool {
    if (codec.hasHooks(T)) return false;
    return switch (@typeInfo(T)) {
        .int => T == u8,
        .@"struct" => |s| codec.isNewtype(T) and isByteLike(s.field_types[0]),
        else => false,
    };
}

fn tupleAllBytes(comptime T: type) bool {
    const s = @typeInfo(T).@"struct";
    if (!s.is_tuple or s.field_types.len == 0) return false;
    inline for (s.field_types) |ft| if (!isByteLike(ft)) return false;
    return true;
}

fn byteOf(v: anytype) u8 {
    const T = @TypeOf(v.*);
    if (T == u8) return v.*;
    return byteOf(&v.@"0");
}

pub fn render(comptime T: type, v: *const T, w: *Writer) Error!void {
    if (comptime codec.hasHooks(T)) {
        if (comptime @hasDecl(T, "bcsTree")) return v.bcsTree(w);
        if (comptime @hasDecl(T, "bcs_string")) return writeJsonStr(w, v.@"0");
        if (comptime @hasDecl(T, "bcs_map")) {
            // serde walks a BTreeMap in key order (Rust Ord), not wire order.
            const E = @TypeOf(v.entries[0]);
            const n = v.entries.len;
            var stack: [256]u32 = undefined;
            const order: []u32 = if (n <= stack.len) stack[0..n] else std.heap.page_allocator.alloc(u32, n) catch return error.WriteFailed;
            defer if (n > stack.len) std.heap.page_allocator.free(order);
            for (order, 0..) |*o, i| o.* = @intCast(i);
            const Ctx = struct {
                entries: []const E,
                fn less(c: @This(), x: u32, y: u32) bool {
                    return wire.keyLess(@TypeOf(c.entries[0].key), &c.entries[x].key, &c.entries[y].key);
                }
            };
            std.mem.sort(u32, order, Ctx{ .entries = v.entries }, Ctx.less);
            try w.writeByte('[');
            for (order, 0..) |oi, i| {
                const e = &v.entries[oi];
                if (i > 0) try w.writeByte(',');
                try w.writeByte('[');
                try render(@TypeOf(e.key), &e.key, w);
                try w.writeByte(',');
                try render(@TypeOf(e.value), &e.value, w);
                try w.writeByte(']');
            }
            try w.writeByte(']');
            return;
        }
        @compileError("bcs.tree: type with hooks needs bcsTree: " ++ @typeName(T));
    }
    switch (@typeInfo(T)) {
        .bool => try w.writeAll(if (v.*) "true" else "false"),
        .int => |i| {
            if (i.bits > 64) {
                try w.print("\"{d}\"", .{v.*});
            } else try w.print("{d}", .{v.*});
        },
        .void => try w.writeAll("null"),
        .@"enum" => try w.print("{d}", .{@intFromEnum(v.*)}),
        .array => |a| {
            if (a.child == u8 or isByteLike(a.child)) {
                if (a.len == 0) return w.writeAll("[]");
                if (a.child == u8) return writeHex(w, &v.*);
                var tmp: [a.len]u8 = undefined;
                for (v, 0..) |*e, i| tmp[i] = byteOf(e);
                return writeHex(w, &tmp);
            }
            try w.writeByte('[');
            for (v, 0..) |*e, i| {
                if (i > 0) try w.writeByte(',');
                try render(a.child, e, w);
            }
            try w.writeByte(']');
        },
        .pointer => |p| switch (p.size) {
            .slice => {
                if (v.len == 0) return w.writeAll("[]");
                if (p.child == u8) return writeHex(w, v.*);
                if (comptime isByteLike(p.child)) {
                    try w.writeAll("\"0x");
                    for (v.*) |*e| {
                        const b = byteOf(e);
                        try w.writeByte(hex_digits[b >> 4]);
                        try w.writeByte(hex_digits[b & 15]);
                    }
                    return w.writeByte('"');
                }
                try w.writeByte('[');
                for (v.*, 0..) |*e, i| {
                    if (i > 0) try w.writeByte(',');
                    try render(p.child, e, w);
                }
                try w.writeByte(']');
            },
            .one => try render(p.child, v.*, w),
            else => @compileError("bcs.tree: unsupported pointer"),
        },
        .optional => |o| {
            if (v.*) |*x| try render(o.child, x, w) else try w.writeAll("null");
        },
        .@"struct" => |s| {
            if (comptime codec.isNewtype(T)) return render(s.field_types[0], &v.@"0", w);
            if (s.is_tuple) {
                if (comptime tupleAllBytes(T)) {
                    var tmp: [s.field_names.len]u8 = undefined;
                    inline for (s.field_names, 0..) |name, i| tmp[i] = byteOf(&@field(v.*, name));
                    return writeHex(w, &tmp);
                }
                try w.writeByte('[');
                inline for (s.field_names, s.field_types, 0..) |name, ft, i| {
                    if (i > 0) try w.writeByte(',');
                    try render(ft, &@field(v.*, name), w);
                }
                try w.writeByte(']');
                return;
            }
            try w.writeByte('{');
            inline for (s.field_names, s.field_types, 0..) |name, ft, i| {
                if (i > 0) try w.writeByte(',');
                try writeJsonStr(w, name);
                try w.writeByte(':');
                try render(ft, &@field(v.*, name), w);
            }
            try w.writeByte('}');
        },
        .@"union" => |u| {
            const active = std.meta.activeTag(v.*);
            inline for (u.field_names, u.field_types) |name, ft| {
                if (active == @field(std.meta.Tag(T), name)) {
                    try w.writeByte('{');
                    try writeJsonStr(w, name);
                    try w.writeByte(':');
                    try render(ft, &@field(v.*, name), w);
                    try w.writeByte('}');
                    return;
                }
            }
            unreachable;
        },
        else => @compileError("bcs.tree: unsupported type " ++ @typeName(T)),
    }
}

/// Renders into a freshly allocated string.
pub fn renderAlloc(comptime T: type, gpa: std.mem.Allocator, v: *const T) ![]u8 {
    var aw: Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try render(T, v, &aw.writer);
    return aw.toOwnedSlice();
}
