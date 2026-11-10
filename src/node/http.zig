//! Mysten's public checkpoint bucket, `https://checkpoints.mainnet.sui.io/<seq>.binpb.zst`: the
//! same archive protos as the S3 bucket, served by Google Cloud Storage behind Google's front end.
//! No credentials and no per-request cost to us. Measured 2026-11-08: objects are kept 30 days
//! (`x-goog-expiration`), hits are cached at the edge (`cache-control: public, max-age=3600`),
//! a 404 is not cached (`private, max-age=0`), so polling the tip sees a new object at once.
//! Round trip on a warm connection: a hit 45 to 60 ms TTFB, a 404 100 to 140 ms (from two
//! regions alike).
//!
//! Untrusted like every source: the follower verifies everything fetched.
//!
//! Fallback: with an S3 bucket configured, a request that fails (network, 5xx) or a 404 well below
//! the highest sequence number seen here (older than the 30-day window, or a hole) goes to S3.
//! A 404 near the tip never does: that is the normal "not there yet" of tip polling.
const std = @import("std");
const Io = std.Io;
const s3 = @import("s3.zig");
const netguard = @import("netguard.zig");
const Atomic = std.atomic.Value;

pub const mainnet_base = "https://checkpoints.mainnet.sui.io";

/// A 404 this far below the highest sequence number served here is treated as missing from the
/// public bucket (retention or a hole), not as the tip, and goes to the fallback.
pub const fallback_margin: u64 = 1000;

pub const Stats = struct {
    gets: Atomic(u64) = .init(0),
    hits: Atomic(u64) = .init(0),
    misses: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
    /// Requests canceled at `Public.timeout_ms` (a connection that went silent).
    timeouts: Atomic(u64) = .init(0),
    /// Requests answered by the S3 fallback instead.
    fallback: Atomic(u64) = .init(0),
    /// Attempts retried after a transient error (each on a fresh connection).
    retries: Atomic(u64) = .init(0),
};

pub const Result = enum { ok, missing };

pub const Public = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Base URL without a trailing slash.
    base: []const u8 = mainnet_base,
    /// Client pool: a request takes a free slot for its duration, so each std.http.Client (and
    /// its keep-alive connections and TLS clock) is used by one thread at a time and its clock can
    /// be refreshed without racing a handshake (netguard.Client).
    slots: [max_clients]Slot,
    fallback: ?*s3.Bucket = null,
    /// Highest sequence number this source has served (the tip as far as it knows).
    highest: Atomic(u64) = .init(0),
    stats: Stats = .{},
    /// One GET (connect, TLS, request, whole body) must finish within this, or it is canceled and
    /// fails with error.Timeout (the fetcher retries): a hung connection never holds a thread.
    timeout_ms: u64 = 15_000,
    /// Set at shutdown: requests in flight end within ~100 ms (error.Stopped).
    stopping: Atomic(bool) = .init(false),

    /// More than the fetcher's threads plus the main thread and stream-check.
    pub const max_clients = 16;

    const Slot = struct {
        busy: Atomic(bool) = .init(false),
        client: netguard.Client,
    };

    pub fn init(gpa: std.mem.Allocator, io: Io, base: []const u8) Public {
        var p: Public = .{ .gpa = gpa, .io = io, .base = std.mem.trimEnd(u8, base, "/"), .slots = undefined };
        for (&p.slots) |*sl| {
            sl.* = .{ .client = netguard.Client.init(gpa, io) };
            // A few idle keep-alive connections per slot.
            sl.client.http.connection_pool.free_size = 4;
        }
        return p;
    }

    pub fn deinit(p: *Public) void {
        for (&p.slots) |*sl| sl.client.deinit();
    }

    fn acquire(p: *Public) *Slot {
        while (true) {
            for (&p.slots) |*sl| {
                if (sl.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return sl;
            }
            p.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    /// GETs checkpoint `seq` into `out` (cleared first). Thread-safe.
    pub fn get(p: *Public, seq: u64, out: *std.ArrayList(u8)) !Result {
        return p.request(seq, out, false);
    }

    /// Does checkpoint `seq` exist? A one-byte ranged GET. Thread-safe.
    pub fn exists(p: *Public, seq: u64) !bool {
        var tmp: std.ArrayList(u8) = .empty;
        defer tmp.deinit(p.gpa);
        return (try p.request(seq, &tmp, true)) == .ok;
    }

    fn request(p: *Public, seq: u64, out: *std.ArrayList(u8), first_byte: bool) !Result {
        const r = p.requestHttp(seq, out, first_byte) catch |e| {
            const b = p.fallback orelse return e;
            _ = p.stats.fallback.fetchAdd(1, .monotonic);
            std.log.warn("public bucket {d}: {s}; trying S3", .{ seq, @errorName(e) });
            return p.viaS3(b, seq, out, first_byte);
        };
        switch (r) {
            .ok => {
                var hi = p.highest.load(.monotonic);
                while (seq > hi) hi = p.highest.cmpxchgWeak(hi, seq, .monotonic, .monotonic) orelse break;
                return .ok;
            },
            .missing => {
                const b = p.fallback orelse return .missing;
                if (seq + fallback_margin > p.highest.load(.monotonic)) return .missing;
                _ = p.stats.fallback.fetchAdd(1, .monotonic);
                return p.viaS3(b, seq, out, first_byte);
            },
        }
    }

    fn viaS3(p: *Public, b: *s3.Bucket, seq: u64, out: *std.ArrayList(u8), first_byte: bool) !Result {
        _ = p;
        var nb: [48]u8 = undefined;
        const key = std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq}) catch unreachable;
        if (first_byte) return if (try b.exists(key)) .ok else .missing;
        return switch (try b.get(key, out)) {
            .ok => .ok,
            .missing => .missing,
        };
    }

    fn requestHttp(p: *Public, seq: u64, out: *std.ArrayList(u8), first_byte: bool) !Result {
        var url_buf: [256]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "{s}/{d}.binpb.zst", .{ p.base, seq });
        var hdrs: [1]std.http.Header = undefined;
        var nh: usize = 0;
        if (first_byte) {
            hdrs[0] = .{ .name = "range", .value = "bytes=0-0" };
            nh = 1;
        }
        _ = p.stats.gets.fetchAdd(1, .monotonic);
        var aw: std.Io.Writer.Allocating = .fromArrayList(p.gpa, out);
        defer out.* = aw.toArrayList();
        const sl = p.acquire();
        defer sl.busy.store(false, .release);
        // Idle pooled connections older than `idle_ms` are dropped here (netguard.Client).
        sl.client.prepare(netguard.wallMs());
        defer sl.client.done(netguard.wallMs());
        var ab: netguard.Abort = .{};
        // A pooled keep-alive connection the server closed fails on first use: retry at once on a
        // fresh one (GET is idempotent), as s3.zig does. Each attempt is bounded by `timeout_ms`.
        // The retry drops the slot's pool first: std.http puts a connection whose write failed
        // back in the pool (netguard.dropIdle), and fetchOnce marks its own as closing.
        var attempt: u32 = 0;
        const res = while (true) : (attempt += 1) {
            aw.writer.end = 0;
            ab.reset();
            break netguard.timed(p.io, p.timeout_ms, &p.stopping, &ab, fetchOnce, .{ &sl.client.http, url, hdrs[0..nh], &aw.writer, &ab }) catch |e| {
                sl.client.noteError(e, netguard.wallMs());
                if (attempt < 4 and transient(@errorName(e))) {
                    sl.client.dropPool();
                    _ = p.stats.retries.fetchAdd(1, .monotonic);
                    continue;
                }
                if (e == error.Timeout) _ = p.stats.timeouts.fetchAdd(1, .monotonic);
                _ = p.stats.errors.fetchAdd(1, .monotonic);
                return e;
            };
        };
        _ = p.stats.bytes.fetchAdd(aw.writer.end, .monotonic);
        switch (res) {
            .ok => {
                _ = p.stats.hits.fetchAdd(1, .monotonic);
                return .ok;
            },
            .partial_content => {
                if (!first_byte) return error.HttpStatus;
                _ = p.stats.hits.fetchAdd(1, .monotonic);
                return .ok;
            },
            .not_found => {
                _ = p.stats.misses.fetchAdd(1, .monotonic);
                aw.writer.end = 0;
                return .missing;
            },
            else => {
                _ = p.stats.errors.fetchAdd(1, .monotonic);
                const body = aw.writer.buffered();
                std.log.warn("public bucket GET {d}: HTTP {d} {s}", .{ seq, @intFromEnum(res), body[0..@min(body.len, 200)] });
                aw.writer.end = 0;
                return error.HttpStatus;
            },
        }
    }
};

/// One GET into `w`: std.http.Client.fetch's steps (no redirects, no content encoding: the
/// bucket serves the object's bytes), with the connection's socket registered in `abort` from the
/// moment it exists until it goes back to the pool.
fn fetchOnce(c: *std.http.Client, url: []const u8, hdrs: []const std.http.Header, w: *std.Io.Writer, abort: *netguard.Abort) !std.http.Status {
    const uri = try std.Uri.parse(url);
    var req = try c.request(.GET, uri, .{
        .redirect_behavior = .unhandled,
        .headers = .{ .accept_encoding = .omit },
        .extra_headers = hdrs,
    });
    defer req.deinit();
    // Any failure from here on: the connection is not reused (std returns one whose request
    // failed before the response head to the pool as healthy). Runs before `req.deinit`.
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try abort.arm(netguard.socketOf(req.connection.?));
    defer abort.disarm();
    try req.sendBodiless();
    var response = try req.receiveHead(&.{});
    if (response.head.content_encoding != .identity) return error.UnsupportedCompressionMethod;
    const reader = response.reader(&.{});
    _ = reader.streamRemaining(w) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
        else => |e| return e,
    };
    return response.head.status;
}

fn transient(name: []const u8) bool {
    const names = [_][]const u8{ "HttpConnectionClosing", "ConnectionResetByPeer", "BrokenPipe", "HttpRequestTruncated", "ReadFailed", "WriteFailed", "EndOfStream", "ConnectionTimedOut" };
    for (names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

test "public bucket: a GET from a server that never answers fails at the timeout" {
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, null);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var p = Public.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer p.deinit();
    p.timeout_ms = 300;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    const t0 = netguard.wallMs();
    try std.testing.expectError(error.Timeout, p.get(5, &out));
    try std.testing.expect(netguard.wallMs() - t0 < 3000);
    try std.testing.expectEqual(@as(u64, 1), p.stats.timeouts.load(.monotonic));
    // A stop in flight ends the request at once.
    p.timeout_ms = 60_000;
    p.stopping.store(true, .release);
    try std.testing.expectError(error.Stopped, p.get(6, &out));
}

test "public bucket: a 404 and a hit through the slot pool" {
    var srv404: netguard.TestServer = undefined;
    try srv404.start(std.testing.io, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    defer srv404.stop();
    var ub: [64]u8 = undefined;
    var p = Public.init(std.testing.allocator, std.testing.io, srv404.url(&ub));
    defer p.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqual(Result.missing, try p.get(7, &out));
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, "HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nabc");
    defer srv.stop();
    var p2 = Public.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer p2.deinit();
    try std.testing.expectEqual(Result.ok, try p2.get(8, &out));
    try std.testing.expectEqualStrings("abc", out.items);
}

const keep_alive_reply = "HTTP/1.1 200 OK\r\ncontent-length: 3\r\n\r\nabc";

fn napMs(ms: u64) void {
    std.testing.io.sleep(.fromMilliseconds(@intCast(ms)), .awake) catch {};
}

test "public bucket: a keep-alive connection the server reset while idle is never reused" {
    // The train/4 rehearsal: pooled connections idle through a 107-minute restore, the front end
    // closed them, and every attempt wrote into the same dead socket (WriteFailed) because std
    // put it back in the pool. Idle limit off, so only the failed-write handling is tested.
    var srv: netguard.TestServer = undefined;
    try srv.startKeepAlive(std.testing.io, keep_alive_reply, 150);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var p = Public.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer p.deinit();
    for (&p.slots) |*sl| sl.client.idle_ms = 0;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqual(Result.ok, try p.get(1, &out));
    try std.testing.expectEqual(Result.ok, try p.get(2, &out));
    try std.testing.expectEqual(@as(u32, 1), srv.accepts.load(.acquire)); // reused while fresh
    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        napMs(400); // past the server's idle cut: the pooled connection is reset
        try std.testing.expectEqual(Result.ok, try p.get(3 + round, &out));
        try std.testing.expectEqualStrings("abc", out.items);
    }
    try std.testing.expectEqual(@as(u32, 3), srv.resets.load(.acquire));
    try std.testing.expectEqual(@as(u32, 4), srv.accepts.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), p.stats.errors.load(.monotonic));
}

test "public bucket: pooled connections idle past idle_ms are dropped before the request" {
    var srv: netguard.TestServer = undefined;
    try srv.startKeepAlive(std.testing.io, keep_alive_reply, 60_000);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var p = Public.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer p.deinit();
    for (&p.slots) |*sl| sl.client.idle_ms = 200;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    try std.testing.expectEqual(Result.ok, try p.get(1, &out));
    try std.testing.expectEqual(Result.ok, try p.get(2, &out));
    try std.testing.expectEqual(@as(u32, 1), srv.accepts.load(.acquire));
    napMs(400);
    try std.testing.expectEqual(Result.ok, try p.get(3, &out));
    // A fresh connection, no failed attempt.
    try std.testing.expectEqual(@as(u32, 2), srv.accepts.load(.acquire));
    try std.testing.expectEqual(@as(u64, 0), p.stats.retries.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), p.slots[0].client.drops);
}

// Live check against checkpoints.mainnet.sui.io (skipped unless ZUI_LIVE_IDLE_S and
// ZUI_LIVE_SEQ are set): GET, idle, GET on the same client, once with the idle limit and once
// without it (the server's own idle cut, when it comes within the gap, then exercises the retry).
test "public bucket live: a GET after an idle gap succeeds" {
    const idle_s = std.fmt.parseInt(u64, std.mem.span(std.c.getenv("ZUI_LIVE_IDLE_S") orelse return error.SkipZigTest), 10) catch return error.SkipZigTest;
    const seq = std.fmt.parseInt(u64, std.mem.span(std.c.getenv("ZUI_LIVE_SEQ") orelse return error.SkipZigTest), 10) catch return error.SkipZigTest;
    const Run = struct {
        fn one(idle_ms: u64, idle: u64, s: u64, ok: *bool) void {
            var p = Public.init(std.heap.c_allocator, std.testing.io, mainnet_base);
            defer p.deinit();
            for (&p.slots) |*sl| sl.client.idle_ms = idle_ms;
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(std.heap.c_allocator);
            const a = p.get(s, &out) catch |e| return std.debug.print("live idle_ms={d}: first GET: {s}\n", .{ idle_ms, @errorName(e) });
            const n1 = out.items.len;
            std.testing.io.sleep(.fromSeconds(@intCast(idle)), .awake) catch {};
            const t0 = netguard.wallMs();
            const b = p.get(s + 1, &out) catch |e| return std.debug.print("live idle_ms={d}: GET after {d} s idle: {s}\n", .{ idle_ms, idle, @errorName(e) });
            std.debug.print("live idle_ms={d}: {d} ({s}, {d} bytes), {d} s idle, {d} ({s}, {d} bytes) in {d} ms; retries {d}, pool drops {d}, errors {d}\n", .{ idle_ms, s, @tagName(a), n1, idle, s + 1, @tagName(b), out.items.len, netguard.wallMs() - t0, p.stats.retries.load(.monotonic), p.slots[0].client.drops, p.stats.errors.load(.monotonic) });
            ok.* = a == .ok and b == .ok;
        }
    };
    var ok_a = false;
    var ok_b = false;
    const ta = try std.Thread.spawn(.{}, Run.one, .{ netguard.Client.default_idle_ms, idle_s, seq, &ok_a });
    const tb = try std.Thread.spawn(.{}, Run.one, .{ 0, idle_s, seq + 2, &ok_b });
    ta.join();
    tb.join();
    try std.testing.expect(ok_a and ok_b);
}
