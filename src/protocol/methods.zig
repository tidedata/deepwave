//! Accessors shared by the generated config structs.
const std = @import("std");

/// The value type of an `Option<T>` config field.
pub fn FieldType(comptime S: type, comptime field: []const u8) type {
    const t = @FieldType(S, field);
    return switch (@typeInfo(t)) {
        .optional => |o| o.child,
        else => t,
    };
}

pub fn get(comptime S: type, self: *const S, comptime field: []const u8) error{ProtocolConfigMissing}!FieldType(S, field) {
    const v = @field(self, field);
    return switch (@typeInfo(@TypeOf(v))) {
        .optional => v orelse error.ProtocolConfigMissing,
        else => v,
    };
}
