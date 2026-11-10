//! Runtime log filter (sui-node's `RUST_LOG` env filter, reloadable through the admin port's
//! `POST /logging`). Text form: comma-separated directives, `LEVEL` or `TARGET=LEVEL`; levels
//! `off`, `error`, `warn`, `info`, `debug`, `trace` (deepwave logs nothing finer than debug, so trace
//! acts as debug). A target names a std.log scope (`default` for unscoped logs); a directive for
//! a target deepwave does not have (`sui_node=debug`) is kept and has no effect. The last bare level
//! is the default; with none, `error`, as tracing's `EnvFilter`.
//!
//! `enabled` is called for every log line: one atomic load decides anything below the highest
//! level of any directive, the rest reads the directive table under a spin lock.
//!
//! The trace filter (`setTrace`, `resetTrace`) is sui-node's second filter, telemetry-subscribers'
//! `TracingHandle.trace`: the admin port's `POST /enable-tracing?filter=F&duration=D` sets it and
//! resets it after D, `POST /reset-tracing` resets it now; reset means the `TRACE_FILTER`
//! environment variable, or `off` when it is unset (as `update_trace_filter`/`reset_trace` do).
//! sui-node exports the spans that pass it over OTLP; deepwave has no exporter and logs instead: a
//! line passes when the log filter or the trace filter enables it. `GET /logging` shows the log
//! filter only, as sui-node's `get_log`. The trace filter is off at start (deepwave does not turn
//! TRACE_FILTER into extra log lines unless an admin reset asks for it). Its syntax is the log
//! filter's, plus EnvFilter's bare target (`sui_core` = `sui_core=trace`); a span or field
//! directive (`target[span]=level`) is kept and has no effect.
const std = @import("std");
const Level = std.log.Level;
const Atomic = std.atomic.Value;

pub const default_text = "info";
const max_directives = 16;
const max_text = 512;

const Directive = struct { target: [64]u8 = undefined, target_len: u8 = 0, level: ?Level };

const Filter = struct {
    text: [max_text]u8 = undefined,
    text_len: usize = 0,
    default: ?Level = .info,
    dirs: [max_directives]Directive = undefined,
    n: usize = 0,
};

var lock: Atomic(u32) = .init(0);
var current: Filter = init: {
    var f: Filter = .{};
    @memcpy(f.text[0..default_text.len], default_text);
    f.text_len = default_text.len;
    break :init f;
};
/// Highest level any directive enables (`Level` as u8, err = 0 .. debug = 3); 255 = nothing.
var max_level: Atomic(u8) = .init(@intFromEnum(Level.info));

fn acquire() void {
    while (lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
}
fn release() void {
    lock.store(0, .release);
}

pub const ParseError = error{ BadLevel, BadDirective, TooLong, TooMany };

fn parseLevel(s: []const u8) ParseError!?Level {
    const eql = std.ascii.eqlIgnoreCase;
    if (eql(s, "off")) return null;
    if (eql(s, "error")) return .err;
    if (eql(s, "warn")) return .warn;
    if (eql(s, "info")) return .info;
    if (eql(s, "debug") or eql(s, "trace")) return .debug;
    return error.BadLevel;
}

fn parse(text: []const u8) ParseError!Filter {
    return parseMode(text, false);
}

/// `lenient`: EnvFilter's bare target (`sui_core`: every level of that target) and span or field
/// directives (`a[b]=debug`, kept without effect) are accepted.
fn parseMode(text: []const u8, lenient: bool) ParseError!Filter {
    const t = std.mem.trim(u8, text, " \t\r\n");
    if (t.len > max_text) return error.TooLong;
    var f: Filter = .{ .default = .err };
    @memcpy(f.text[0..t.len], t);
    f.text_len = t.len;
    var it = std.mem.splitScalar(u8, t, ',');
    while (it.next()) |raw| {
        const d = std.mem.trim(u8, raw, " \t");
        if (d.len == 0) continue;
        if (lenient and std.mem.indexOfAny(u8, d, "[{") != null) continue;
        if (lenient and std.mem.indexOfScalar(u8, d, '=') == null and (parseLevel(d) catch null) == null and !std.ascii.eqlIgnoreCase(d, "off")) {
            if (d.len > 64) return error.BadDirective;
            if (f.n == max_directives) return error.TooMany;
            var dir: Directive = .{ .level = .debug };
            @memcpy(dir.target[0..d.len], d);
            dir.target_len = @intCast(d.len);
            f.dirs[f.n] = dir;
            f.n += 1;
            continue;
        }
        if (std.mem.indexOfScalar(u8, d, '=')) |eq| {
            const target = std.mem.trim(u8, d[0..eq], " ");
            if (target.len == 0 or target.len > 64) return error.BadDirective;
            if (f.n == max_directives) return error.TooMany;
            var dir: Directive = .{ .level = try parseLevel(std.mem.trim(u8, d[eq + 1 ..], " ")) };
            @memcpy(dir.target[0..target.len], target);
            dir.target_len = @intCast(target.len);
            f.dirs[f.n] = dir;
            f.n += 1;
        } else {
            f.default = try parseLevel(d);
        }
    }
    return f;
}

fn maxOf(f: *const Filter) u8 {
    var m: u8 = 255;
    if (f.default) |l| m = @intFromEnum(l);
    for (f.dirs[0..f.n]) |d| if (d.level) |l| {
        if (m == 255 or @intFromEnum(l) > m) m = @intFromEnum(l);
    };
    return m;
}

/// Replaces the filter; on a parse error the old one stays.
pub fn set(text: []const u8) ParseError!void {
    const f = try parse(text);
    acquire();
    current = f;
    max_level.store(maxOf(&f), .release);
    release();
}

/// The filter text (`GET /logging`), copied into `buf`.
pub fn get(buf: []u8) []const u8 {
    acquire();
    defer release();
    const n = @min(buf.len, current.text_len);
    @memcpy(buf[0..n], current.text[0..n]);
    return buf[0..n];
}

pub fn enabled(level: Level, scope: []const u8) bool {
    const m = max_level.load(.acquire);
    const tm = trace_max.load(.acquire);
    const in_log = m != 255 and @intFromEnum(level) <= m;
    const in_trace = tm != 255 and @intFromEnum(level) <= tm;
    if (!in_log and !in_trace) return false;
    acquire();
    defer release();
    if (in_log and enabledIn(&current, level, scope)) return true;
    return in_trace and enabledIn(&trace_cur, level, scope);
}

fn enabledIn(f: *const Filter, level: Level, scope: []const u8) bool {
    for (f.dirs[0..f.n]) |d| if (std.mem.eql(u8, d.target[0..d.target_len], scope)) {
        const l = d.level orelse return false;
        return @intFromEnum(level) <= @intFromEnum(l);
    };
    const l = f.default orelse return false;
    return @intFromEnum(level) <= @intFromEnum(l);
}

// ------------------------------------------------------------------ trace filter

var trace_cur: Filter = init: {
    var f: Filter = .{ .default = null };
    @memcpy(f.text[0..3], "off");
    f.text_len = 3;
    break :init f;
};
var trace_max: Atomic(u8) = .init(255);
/// Bumped by every set or reset (tests, and a timer that only resets its own filter if asked).
pub var trace_gen: Atomic(u64) = .init(0);

/// Replaces the trace filter (`TracingHandle::update_trace_filter`'s filter part); on a parse
/// error the old one stays.
pub fn setTrace(text: []const u8) ParseError!void {
    const f = try parseMode(text, true);
    acquire();
    trace_cur = f;
    trace_max.store(maxOf(&f), .release);
    _ = trace_gen.fetchAdd(1, .monotonic);
    release();
}

/// `reset_trace`: the trace filter becomes `TRACE_FILTER`, or `off` when it is unset (or deepwave
/// cannot read it).
pub fn resetTrace() void {
    setTrace(traceEnv() orelse "off") catch setTrace("off") catch unreachable;
}

/// The `TRACE_FILTER` environment variable (null when unset or without libc).
pub fn traceEnv() ?[]const u8 {
    if (!@import("builtin").link_libc) return null;
    const p = std.c.getenv("TRACE_FILTER") orelse return null;
    return std.mem.span(p);
}

/// The trace filter text, copied into `buf`.
pub fn getTrace(buf: []u8) []const u8 {
    acquire();
    defer release();
    const n = @min(buf.len, trace_cur.text_len);
    @memcpy(buf[0..n], trace_cur.text[0..n]);
    return buf[0..n];
}

test "log filter: the trace filter adds lines and resets" {
    defer set(default_text) catch unreachable;
    defer setTrace("off") catch unreachable;
    try set("info");
    try std.testing.expect(!enabled(.debug, "serve"));
    try setTrace("serve");
    try std.testing.expect(enabled(.debug, "serve"));
    try std.testing.expect(!enabled(.debug, "default"));
    try std.testing.expect(enabled(.info, "default"));
    try setTrace("serve[conn{id=1}]=debug,warn");
    try std.testing.expect(!enabled(.debug, "serve"));
    try std.testing.expectError(error.BadLevel, setTrace("a=loud"));
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("serve[conn{id=1}]=debug,warn", getTrace(&buf));
    try setTrace("off");
    try std.testing.expect(!enabled(.debug, "serve"));
    try std.testing.expect(enabled(.info, "default"));
}

test "log filter: levels, targets, reload, bad text keeps the old filter" {
    defer set(default_text) catch unreachable;
    try set("info");
    try std.testing.expect(enabled(.info, "default"));
    try std.testing.expect(!enabled(.debug, "default"));
    try set("debug");
    try std.testing.expect(enabled(.debug, "default"));
    try set("warn,sui_node=debug,default=error");
    try std.testing.expect(!enabled(.warn, "default"));
    try std.testing.expect(enabled(.err, "default"));
    try std.testing.expect(enabled(.warn, "serve"));
    try std.testing.expect(!enabled(.info, "serve"));
    var buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("warn,sui_node=debug,default=error", get(&buf));
    try std.testing.expectError(error.BadLevel, set("loud"));
    try std.testing.expectEqualStrings("warn,sui_node=debug,default=error", get(&buf));
    try set("off");
    try std.testing.expect(!enabled(.err, "default"));
    // EnvFilter: directives without a bare level leave the default at error
    try set("serve=debug");
    try std.testing.expect(enabled(.err, "default"));
    try std.testing.expect(!enabled(.warn, "default"));
    try std.testing.expect(enabled(.debug, "serve"));
}
