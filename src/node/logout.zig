//! Log output as telemetry-subscribers sets it up from the environment (lane ops-metrics):
//!
//!   RUST_LOG_JSON (set, any value)  newline-delimited JSON, tracing-subscriber's `fmt().json()`
//!                                   layout: {"timestamp":"2026-11-09T15:04:05.123456Z",
//!                                   "level":"INFO","fields":{"message":"..."},"target":"..."}
//!                                   (sui-node adds `filename` and `line_number`; std.log has no
//!                                   source location, so those keys are absent, as tracing omits
//!                                   them for an event without one).
//!   RUST_LOG_FILE=PREFIX            write to `PREFIX.YYYY-MM-DD` (UTC day, appended, a new file
//!                                   each day: tracing_appender::rolling::daily("", PREFIX))
//!                                   instead of stderr, text or JSON.
//!
//! The target is `zui_node` for unscoped lines and `zui_node::<scope>` for a std.log scope
//! (RUST_LOG directives still name the scope). Each line is one write(2) of a stack buffer.
const std = @import("std");
const Atomic = std.atomic.Value;

pub var json: bool = false;
var prefix: ?[]const u8 = null;
var fd: Atomic(i32) = .init(2);
var fd_day: Atomic(i64) = .init(-1);
var lock: Atomic(u32) = .init(0);

/// Reads RUST_LOG_JSON and RUST_LOG_FILE (call once, before the first log line).
pub fn init() void {
    json = std.c.getenv("RUST_LOG_JSON") != null;
    if (std.c.getenv("RUST_LOG_FILE")) |p| {
        const s = std.mem.span(p);
        if (s.len > 0) prefix = s;
    }
}

/// Where lines go now: stderr, or today's file (opened, or reopened after midnight UTC).
fn target(now_s: i64) i32 {
    const p = prefix orelse return 2;
    const day = @divFloor(now_s, 86400);
    if (fd_day.load(.acquire) == day) return fd.load(.acquire);
    while (lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer lock.store(0, .release);
    if (fd_day.load(.acquire) == day) return fd.load(.acquire);
    var nb: [std.fs.max_path_bytes]u8 = undefined;
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(now_s) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const path = std.fmt.bufPrintSentinel(&nb, "{s}.{d:0>4}-{d:0>2}-{d:0>2}", .{ p, yd.year, md.month.numeric(), @as(u32, md.day_index) + 1 }, 0) catch return 2;
    const flags: std.c.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true };
    const nfd = std.c.open(path.ptr, flags, @as(std.c.mode_t, 0o644));
    if (nfd < 0) return 2;
    const old = fd.swap(nfd, .acq_rel);
    fd_day.store(day, .release);
    if (old != 2) _ = std.c.close(old);
    return nfd;
}

pub fn write(bytes: []const u8) void {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    const f = target(@intCast(ts.sec));
    _ = std.c.write(f, bytes.ptr, bytes.len);
}

/// tracing's level words.
pub fn levelWord(level: std.log.Level) []const u8 {
    return switch (level) {
        .err => "ERROR",
        .warn => "WARN",
        .info => "INFO",
        .debug => "DEBUG",
    };
}

/// One JSON line (with its newline) into `buf`; the message is cut to fit.
pub fn jsonLine(buf: []u8, level: std.log.Level, scope: []const u8, msg: []const u8, sec: i64, nsec: i64) []const u8 {
    var w = std.Io.Writer.fixed(buf);
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(sec) };
    const ds = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const tail_max = 96; // `"},"target":"zui_node::<scope>"}\n`
    w.print("{{\"timestamp\":\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>6}Z\",\"level\":\"{s}\",\"fields\":{{\"message\":\"", .{
        yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(), @as(u64, @intCast(nsec)) / 1000, levelWord(level),
    }) catch return buf[0..0];
    for (msg) |c| {
        if (w.end + tail_max + 6 > buf.len) break;
        switch (c) {
            '"' => w.writeAll("\\\"") catch break,
            '\\' => w.writeAll("\\\\") catch break,
            '\n' => w.writeAll("\\n") catch break,
            '\r' => w.writeAll("\\r") catch break,
            '\t' => w.writeAll("\\t") catch break,
            0...8, 11, 12, 14...0x1f => w.print("\\u{x:0>4}", .{c}) catch break,
            else => w.writeByte(c) catch break,
        }
    }
    const sc = scope[0..@min(scope.len, 48)];
    if (std.mem.eql(u8, sc, "default"))
        w.writeAll("\"},\"target\":\"zui_node\"}\n") catch return buf[0..0]
    else
        w.print("\"}},\"target\":\"zui_node::{s}\"}}\n", .{sc}) catch return buf[0..0];
    return w.buffered();
}

test "json log line: tracing-subscriber layout, escaped message" {
    var buf: [512]u8 = undefined;
    const line = jsonLine(&buf, .warn, "default", "a \"quoted\"\nline\\", 1794125265, 123456789);
    try std.testing.expectEqualStrings("{\"timestamp\":\"2026-11-08T08:07:45.123456Z\",\"level\":\"WARN\",\"fields\":{\"message\":\"a \\\"quoted\\\"\\nline\\\\\"},\"target\":\"zui_node\"}\n", line);
    var buf2: [512]u8 = undefined;
    const l2 = jsonLine(&buf2, .err, "serve", "x", 0, 0);
    try std.testing.expectEqualStrings("{\"timestamp\":\"1970-01-01T00:00:00.000000Z\",\"level\":\"ERROR\",\"fields\":{\"message\":\"x\"},\"target\":\"zui_node::serve\"}\n", l2);
    // parses as JSON
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, line, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("WARN", parsed.value.object.get("level").?.string);
    // a long message is cut, the line stays valid JSON
    var big: [600]u8 = @splat('a');
    var buf3: [512]u8 = undefined;
    const l3 = jsonLine(&buf3, .info, "default", &big, 0, 0);
    const p3 = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, l3, .{});
    defer p3.deinit();
}
