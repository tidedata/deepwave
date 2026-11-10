//! Monotonic nanoseconds without an `std.Io` (for reports and benches; never on a hot path).
const std = @import("std");
const builtin = @import("builtin");

pub fn now() u64 {
    var ts: std.posix.timespec = undefined;
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Sleeps `ns` nanoseconds (the store's commit pacing; no `std.Io` there).
pub fn sleep(ns: u64) void {
    var ts: std.posix.timespec = .{ .sec = @intCast(ns / std.time.ns_per_s), .nsec = @intCast(ns % std.time.ns_per_s) };
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.nanosleep(&ts, &ts);
    } else {
        _ = std.c.nanosleep(&ts, &ts);
    }
}

test "monotonic" {
    const a = now();
    const b = now();
    try std.testing.expect(b >= a and a > 0);
}
