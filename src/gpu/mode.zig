//! ZUI_GPU environment parsing, shared by the root and the conformance suite.
const std = @import("std");
const ops = @import("ops.zig");

/// ZUI_GPU=off|auto|metal|cuda (unset or unknown: off).
pub fn fromEnv() ops.Mode {
    const v = std.c.getenv("ZUI_GPU") orelse return .off;
    return ops.Mode.parse(std.mem.span(v)) orelse .off;
}
