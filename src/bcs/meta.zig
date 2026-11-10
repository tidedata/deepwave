//! Field reflection helpers (Zig 0.17 reports struct and union fields as parallel arrays).
pub fn names(comptime T: type) []const [:0]const u8 {
    return switch (@typeInfo(T)) {
        .@"struct" => |s| s.field_names,
        .@"union" => |u| u.field_names,
        else => @compileError("meta.names: not a struct or union"),
    };
}

pub fn types(comptime T: type) []const type {
    return switch (@typeInfo(T)) {
        .@"struct" => |s| s.field_types,
        .@"union" => |u| u.field_types,
        else => @compileError("meta.types: not a struct or union"),
    };
}

pub fn count(comptime T: type) usize {
    return names(T).len;
}

pub fn fieldType(comptime T: type, comptime name: []const u8) type {
    inline for (names(T), types(T)) |n, t| {
        if (comptime std.mem.eql(u8, n, name)) return t;
    }
    @compileError("no field " ++ name ++ " in " ++ @typeName(T));
}

const std = @import("std");
