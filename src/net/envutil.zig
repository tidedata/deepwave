//! Environment lookup for tests and tools. Libraries never read the environment; suites and the
//! live probe do, and only where libc is linked (the harness has no environment handle yet).
const std = @import("std");
const builtin = @import("builtin");

pub fn get(name: [:0]const u8) ?[]const u8 {
    if (!builtin.link_libc) return null;
    const p = std.c.getenv(name.ptr) orelse return null;
    return std.mem.span(p);
}
