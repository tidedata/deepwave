//! hello (method 0x00, docs/NATIVE-PROTOCOL.md 3.3, 4.1 and 8): what a client may require of the
//! node it reached, and the record of who connects with which zui/1 minor.
//!
//! A minor 0 client sends `client`, `minor` and `token` and nothing else; it is answered as it
//! always was. From minor 1 a client may append three fields: the chain it expects, the lowest
//! minor it can work with, and the feature bits it cannot do without. A node that cannot satisfy
//! them answers a distinct error (WRONG_CHAIN, MINOR_UNSUPPORTED, FEATURE_MISSING) instead of an
//! OK the client would have to second-guess.
const std = @import("std");
const Atomic = std.atomic.Value;
const proto = @import("proto.zig");

/// The optional tail of a HelloReq.
pub const Want = struct {
    chain_id: ?[32]u8 = null,
    /// 0: any.
    min_minor: u16 = 0,
    /// 0: none.
    features: u64 = 0,

    /// What follows `token`: nothing (every minor 0 client), or all three fields.
    pub fn read(r: *proto.R) proto.R.Error!?Want {
        if (r.p == r.b.len) return null;
        var w: Want = .{};
        if (try r.option()) w.chain_id = (try r.fixed(32)).*;
        w.min_minor = try r.int(u16);
        w.features = try r.int(u64);
        return w;
    }
};

pub const Refusal = struct {
    code: proto.Code,
    message: []const u8,
    buf: [32]u8 = undefined,
    len: u8 = 0,

    /// ErrorBody.detail: what the node has instead (its chain id, its minor, the missing bits).
    pub fn detail(r: *const Refusal) []const u8 {
        return r.buf[0..r.len];
    }
};

/// Why a node on `chain_id` that speaks `proto.server_minor` and serves `features` cannot serve
/// a client that wants `w`; null when it can. The first failing check answers: chain, minor,
/// features.
pub fn refuse(w: Want, chain_id: *const [32]u8, features: u64) ?Refusal {
    if (w.chain_id) |want| if (!std.mem.eql(u8, &want, chain_id)) {
        var r: Refusal = .{ .code = .wrong_chain, .message = "this node serves another chain (detail: its chain id)", .len = 32 };
        r.buf = chain_id.*;
        return r;
    };
    if (w.min_minor > proto.server_minor) {
        var r: Refusal = .{ .code = .minor_unsupported, .message = "this node does not speak the zui/1 minor the client needs (detail: its minor)", .len = 2 };
        std.mem.writeInt(u16, r.buf[0..2], proto.server_minor, .little);
        return r;
    }
    const missing = w.features & ~features;
    if (missing != 0) {
        var r: Refusal = .{ .code = .feature_missing, .message = "this node does not serve a feature the client requires (detail: the missing feature bits)", .len = 8 };
        std.mem.writeInt(u64, r.buf[0..8], missing, .little);
        return r;
    }
    return null;
}

/// Hellos are counted by the client's minor: 0, 1, 2, and 3 or more.
pub const minor_buckets = 4;
pub const minor_labels = [minor_buckets][]const u8{ "0", "1", "2", "3+" };

/// Log lines about hellos per window; the rest are counted and summed up when the next window
/// opens.
pub const log_burst: u32 = 10;
pub const log_window_ms: i64 = 60_000;

pub const Stats = struct {
    by_minor: [minor_buckets]Atomic(u64) = @splat(.init(0)),
    wrong_chain: Atomic(u64) = .init(0),
    minor_unsupported: Atomic(u64) = .init(0),
    feature_missing: Atomic(u64) = .init(0),
    window_start_ms: Atomic(i64) = .init(std.math.minInt(i64)),
    in_window: Atomic(u32) = .init(0),
    suppressed: Atomic(u64) = .init(0),

    /// Counts one hello and logs it unless this window's lines are used up. Any thread. True
    /// when a line was logged.
    pub fn record(s: *Stats, client: []const u8, minor: u16, refused: ?proto.Code, now_ms: i64) bool {
        _ = s.by_minor[@min(minor, minor_buckets - 1)].fetchAdd(1, .monotonic);
        if (refused) |c| switch (c) {
            .wrong_chain => _ = s.wrong_chain.fetchAdd(1, .monotonic),
            .minor_unsupported => _ = s.minor_unsupported.fetchAdd(1, .monotonic),
            .feature_missing => _ = s.feature_missing.fetchAdd(1, .monotonic),
            else => {},
        };
        const start = s.window_start_ms.load(.acquire);
        if (start == std.math.minInt(i64) or now_ms - start >= log_window_ms) {
            // one thread opens the window; a loser of the race logs within the new one
            if (s.window_start_ms.cmpxchgStrong(start, now_ms, .acq_rel, .acquire) == null) {
                s.in_window.store(0, .release);
                const skipped = s.suppressed.swap(0, .acq_rel);
                if (skipped != 0) std.log.info("zui/1 hello: {d} more not logged in the last window", .{skipped});
            }
        }
        if (s.in_window.fetchAdd(1, .acq_rel) >= log_burst) {
            _ = s.suppressed.fetchAdd(1, .monotonic);
            return false;
        }
        var nb: [client_log_max]u8 = undefined;
        const name = printable(&nb, client);
        if (refused) |c| {
            std.log.info("zui/1 hello: client \"{s}\" minor {d}: refused ({s})", .{ name, minor, @tagName(c) });
        } else {
            std.log.info("zui/1 hello: client \"{s}\" minor {d}", .{ name, minor });
        }
        return true;
    }
};

pub const client_log_max = 64;

/// `s` for a log line: at most 64 bytes, anything but plain printable ASCII as `?` (the client
/// string is the client's to choose).
pub fn printable(buf: *[client_log_max]u8, s: []const u8) []const u8 {
    const n = @min(s.len, buf.len);
    for (buf[0..n], s[0..n]) |*o, c| o.* = if (c >= 0x20 and c < 0x7f and c != '"' and c != '\\') c else '?';
    return buf[0..n];
}

/// Milliseconds on the monotonic clock.
pub fn monoMs() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

test "hello: the optional requirement fields, and each refusal" {
    // nothing after the token: an old client
    var r0: proto.R = .{ .b = "" };
    try std.testing.expectEqual(@as(?Want, null), try Want.read(&r0));
    // all three
    var body: [1 + 32 + 2 + 8]u8 = undefined;
    body[0] = 1;
    @memset(body[1..33], 0x5a);
    std.mem.writeInt(u16, body[33..35], 1, .little);
    std.mem.writeInt(u64, body[35..43], 0x21, .little);
    var r1: proto.R = .{ .b = &body };
    const w = (try Want.read(&r1)).?;
    try r1.done();
    try std.testing.expectEqual(@as([32]u8, @splat(0x5a)), w.chain_id.?);
    try std.testing.expectEqual(@as(u16, 1), w.min_minor);
    try std.testing.expectEqual(@as(u64, 0x21), w.features);
    // no chain stated
    var r2: proto.R = .{ .b = &@as([11]u8, @splat(0)) };
    const w2 = (try Want.read(&r2)).?;
    try r2.done();
    try std.testing.expect(w2.chain_id == null and w2.min_minor == 0 and w2.features == 0);
    // a tail that stops short is malformed
    var r3: proto.R = .{ .b = body[0..40] };
    try std.testing.expectError(error.Malformed, Want.read(&r3));

    const chain: [32]u8 = @splat(0x5a);
    const served: u64 = 0x1f63;
    try std.testing.expect(refuse(w, &chain, served) == null);
    try std.testing.expect(refuse(.{}, &chain, served) == null);
    const wc = refuse(.{ .chain_id = @splat(0x11), .min_minor = 9, .features = 1 << 40 }, &chain, served).?;
    try std.testing.expectEqual(proto.Code.wrong_chain, wc.code);
    try std.testing.expectEqualSlices(u8, &chain, wc.detail());
    const mu = refuse(.{ .chain_id = chain, .min_minor = proto.server_minor + 1, .features = 1 << 40 }, &chain, served).?;
    try std.testing.expectEqual(proto.Code.minor_unsupported, mu.code);
    try std.testing.expectEqual(proto.server_minor, std.mem.readInt(u16, mu.detail()[0..2], .little));
    const fm = refuse(.{ .chain_id = chain, .min_minor = proto.server_minor, .features = (1 << 40) | (1 << 2) | 1 }, &chain, served).?;
    try std.testing.expectEqual(proto.Code.feature_missing, fm.code);
    try std.testing.expectEqual(@as(u64, (1 << 40) | (1 << 2)), std.mem.readInt(u64, fm.detail()[0..8], .little));
}

test "hello: counted by minor, logged at most log_burst times per window, client strings made printable" {
    var s: Stats = .{};
    var logged: u32 = 0;
    for (0..25) |i| {
        if (s.record("zui-sdk-ts/0.1", if (i < 20) 0 else 1, null, 1000 + @as(i64, @intCast(i)))) logged += 1;
    }
    try std.testing.expectEqual(log_burst, logged);
    try std.testing.expectEqual(@as(u64, 20), s.by_minor[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 5), s.by_minor[1].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 15), s.suppressed.load(.monotonic));
    // the next window logs again
    try std.testing.expect(s.record("x", 7, .wrong_chain, 1000 + log_window_ms));
    try std.testing.expectEqual(@as(u64, 1), s.by_minor[3].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), s.wrong_chain.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), s.suppressed.load(.monotonic));
    _ = s.record("y", 2, .feature_missing, 1001 + log_window_ms);
    _ = s.record("z", 65535, .minor_unsupported, 1002 + log_window_ms);
    try std.testing.expectEqual(@as(u64, 1), s.by_minor[2].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), s.by_minor[3].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), s.feature_missing.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), s.minor_unsupported.load(.monotonic));

    var b: [client_log_max]u8 = undefined;
    try std.testing.expectEqualStrings("ok/1.0 ??? ?x?", printable(&b, "ok/1.0 \n\x1b\xff \"x\\"));
    try std.testing.expectEqual(@as(usize, client_log_max), printable(&b, &@as([300]u8, @splat('a'))).len);
}
