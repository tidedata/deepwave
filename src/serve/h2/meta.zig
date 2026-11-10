//! Response metadata sui-node 1.83.1 adds to every reply on :9000, in its order (captured in
//! `vectors/`): sui-rpc-api `append_info_headers` (x-sui-*, server), then tower-http's permissive
//! CORS layer (vary, access-control-*), then sui-node's `server-timing`, then hyper's framing
//! headers and `date`. Also the `grpc-timeout` parser of sui-http.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Tip = struct { epoch: u64, height: u64, timestamp_ms: u64 };

/// What the node reports in the x-sui-* headers. Filled by the router's info source.
pub const Info = struct {
    /// base58 of the chain identifier (checkpoint 0 digest).
    chain_id: []const u8 = "",
    chain: []const u8 = "",
    tip: ?Tip = null,
    lowest: ?u64 = null,
    server: []const u8 = "",
};

/// Appends the x-sui-*, server, CORS and server-timing headers. Values are allocated in `arena`.
pub fn common(list: *std.ArrayList(Header), arena: Allocator, info: ?*const Info, dur_ms: u64) !void {
    if (info) |i| {
        if (i.chain_id.len > 0) try list.append(arena, .{ .name = "x-sui-chain-id", .value = i.chain_id });
        if (i.chain.len > 0) try list.append(arena, .{ .name = "x-sui-chain", .value = i.chain });
        if (i.tip) |t| {
            try list.append(arena, .{ .name = "x-sui-epoch", .value = try num(arena, t.epoch) });
            try list.append(arena, .{ .name = "x-sui-checkpoint-height", .value = try num(arena, t.height) });
            try list.append(arena, .{ .name = "x-sui-timestamp-ms", .value = try num(arena, t.timestamp_ms) });
            const buf = try arena.alloc(u8, 40);
            try list.append(arena, .{ .name = "x-sui-timestamp", .value = timestampText(buf, t.timestamp_ms) });
        }
        if (i.lowest) |l| {
            const v = try num(arena, l);
            try list.append(arena, .{ .name = "x-sui-lowest-available-checkpoint", .value = v });
            try list.append(arena, .{ .name = "x-sui-lowest-available-checkpoint-objects", .value = v });
        }
        if (i.server.len > 0) try list.append(arena, .{ .name = "server", .value = i.server });
    }
    try cors(list, arena);
    try list.append(arena, .{ .name = "server-timing", .value = try std.fmt.allocPrint(arena, "finish_request;dur={d}", .{dur_ms}) });
}

pub fn cors(list: *std.ArrayList(Header), arena: Allocator) !void {
    try list.append(arena, .{ .name = "vary", .value = vary });
    try list.append(arena, .{ .name = "access-control-allow-origin", .value = "*" });
    try list.append(arena, .{ .name = "access-control-expose-headers", .value = "*" });
}

pub const vary = "origin, access-control-request-method, access-control-request-headers";

/// tower-http 0.6 permissive CORS answers every OPTIONS request as a preflight, on any path and
/// whatever its headers (vectors h1-options-bare, h1-options-unknown, h2-options-bare). On
/// sui-node's axum `/health` route the method router adds `allow: GET,HEAD` after
/// server-timing (h1-options-health, h2-options-health).
pub fn preflight(list: *std.ArrayList(Header), arena: Allocator, dur_ms: u64, health_route: bool) !void {
    try list.append(arena, .{ .name = "vary", .value = vary });
    try list.append(arena, .{ .name = "access-control-allow-methods", .value = "GET,POST" });
    try list.append(arena, .{ .name = "access-control-allow-headers", .value = "*" });
    try list.append(arena, .{ .name = "access-control-allow-origin", .value = "*" });
    try list.append(arena, .{ .name = "server-timing", .value = try std.fmt.allocPrint(arena, "finish_request;dur={d}", .{dur_ms}) });
    if (health_route) try list.append(arena, .{ .name = "allow", .value = "GET,HEAD" });
}

/// The path without its query.
pub fn pathOnly(path: []const u8) []const u8 {
    return if (std.mem.indexOfScalar(u8, path, '?')) |q| path[0..q] else path;
}

/// `threshold_seconds` of `GET /health?threshold_seconds=N`.
pub fn healthThreshold(path: []const u8) ?u32 {
    const q = std.mem.indexOfScalar(u8, path, '?') orelse return null;
    var it = std.mem.splitScalar(u8, path[q + 1 ..], '&');
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "threshold_seconds=")) return std.fmt.parseInt(u32, kv["threshold_seconds=".len..], 10) catch null;
    }
    return null;
}

fn num(arena: Allocator, v: u64) ![]const u8 {
    return std.fmt.allocPrint(arena, "{d}", .{v});
}

/// prost-types `Timestamp` Display (RFC 3339, UTC, 0/3/6/9 fraction digits).
pub fn timestampText(buf: []u8, ms: u64) []const u8 {
    const secs = ms / 1000;
    const nanos = (ms % 1000) * 1_000_000;
    const es: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const ds = es.getDaySeconds();
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const head = std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}", .{ yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() }) catch unreachable;
    var n = head.len;
    if (nanos != 0) {
        const frac = if (nanos % 1_000_000 == 0)
            std.fmt.bufPrint(buf[n..], ".{d:0>3}", .{nanos / 1_000_000}) catch unreachable
        else if (nanos % 1000 == 0)
            std.fmt.bufPrint(buf[n..], ".{d:0>6}", .{nanos / 1000}) catch unreachable
        else
            std.fmt.bufPrint(buf[n..], ".{d:0>9}", .{nanos}) catch unreachable;
        n += frac.len;
    }
    buf[n] = 'Z';
    return buf[0 .. n + 1];
}

/// IMF-fixdate, as hyper writes `date`: `Sun, 08 Nov 2026 08:07:10 GMT`.
pub fn httpDate(buf: *[29]u8, unix_s: u64) []const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = unix_s };
    const ds = es.getDaySeconds();
    const day = es.getEpochDay();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();
    const wdays = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" }; // 1970-01-01 was a Thursday
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{ wdays[day.day % 7], @as(u32, md.day_index) + 1, months[md.month.numeric() - 1], yd.year, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() }) catch unreachable;
}

pub fn monoNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn unixS() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// sui-http `try_parse_grpc_timeout`: up to 8 digits and a unit H M S m u n. Null when absent or
/// invalid (an invalid header is ignored, as in sui-node).
/// `x-sui-client-protocol-version` as sui-rpc-api reads it (`to_str()?.parse::<u64>()`):
/// an optional `+`, then decimal digits that fit a u64; anything else is no version.
pub fn parseClientProtocolVersion(value: []const u8) ?u64 {
    const digits = if (value.len > 0 and value[0] == '+') value[1..] else value;
    if (digits.len == 0) return null;
    var v: u64 = 0;
    for (digits) |ch| {
        if (ch < '0' or ch > '9') return null;
        v = std.math.mul(u64, v, 10) catch return null;
        v = std.math.add(u64, v, ch - '0') catch return null;
    }
    return v;
}

test "client protocol version header parses like Rust u64::from_str" {
    try std.testing.expectEqual(@as(?u64, 138), parseClientProtocolVersion("138"));
    try std.testing.expectEqual(@as(?u64, 7), parseClientProtocolVersion("+7"));
    try std.testing.expectEqual(@as(?u64, null), parseClientProtocolVersion(""));
    try std.testing.expectEqual(@as(?u64, null), parseClientProtocolVersion("+"));
    try std.testing.expectEqual(@as(?u64, null), parseClientProtocolVersion("-1"));
    try std.testing.expectEqual(@as(?u64, null), parseClientProtocolVersion("1_000"));
    try std.testing.expectEqual(@as(?u64, null), parseClientProtocolVersion(" 1"));
    try std.testing.expectEqual(@as(?u64, null), parseClientProtocolVersion("18446744073709551616"));
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), parseClientProtocolVersion("18446744073709551615"));
}

pub fn parseTimeout(value: []const u8) ?u64 {
    if (value.len < 2) return null;
    const digits = value[0 .. value.len - 1];
    if (digits.len > 8) return null;
    for (digits) |c| if (c < '0' or c > '9') return null;
    const v = std.fmt.parseInt(u64, digits, 10) catch return null;
    const mul: u64 = switch (value[value.len - 1]) {
        'H' => 3600 * std.time.ns_per_s,
        'M' => 60 * std.time.ns_per_s,
        'S' => std.time.ns_per_s,
        'm' => std.time.ns_per_ms,
        'u' => std.time.ns_per_us,
        'n' => 1,
        else => return null,
    };
    return v *| mul; // 99999999H is past u64 nanoseconds: clamp (the callers add with +|)
}

test "timestamp, date and timeout text" {
    var b: [40]u8 = undefined;
    try std.testing.expectEqualStrings("2026-11-08T08:07:10.029Z", timestampText(&b, 1794125230029));
    try std.testing.expectEqualStrings("2026-11-08T08:07:10Z", timestampText(&b, 1794125230000));
    var d: [29]u8 = undefined;
    try std.testing.expectEqualStrings("Sun, 08 Nov 2026 08:07:10 GMT", httpDate(&d, 1794125230));
    try std.testing.expectEqual(@as(?u64, 30 * std.time.ns_per_s), parseTimeout("30000m"));
    try std.testing.expectEqual(@as(?u64, null), parseTimeout("abc"));
    try std.testing.expectEqual(@as(?u64, null), parseTimeout("123456789S"));
    try std.testing.expectEqual(@as(?u64, std.math.maxInt(u64)), parseTimeout("99999999H")); // no overflow
}
