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

/// One byte-rate limit for every download this process makes (`--net-max-mbps N`, in MiB per
/// second; 0, the default, is no limit and nothing here does anything). A token bucket in its
/// GCRA form: one word, `tat`, holds the time at which every byte booked so far is paid for at
/// `rate`. A reader books the bytes it just received and sleeps until they are due, so it stops
/// reading, the socket's window fills, and TCP slows the sender. Lock-free: any number of
/// threads share it, and together they get `rate`, not `rate` each.
///
/// Who books: the public bucket's body loop below (every 64 KiB read), and after the fact (the
/// whole object once it is in, which caps the average but lets one object arrive at link
/// speed) the S3 fallback here, the S3 source in source.zig and the snapshot files in
/// snapshot.zig, whose clients cannot be paced inside a body. Not capped: zui/1 edge feeds,
/// p2p, the live stream, RPC serving.
pub const ByteBucket = struct {
    /// Bytes per second; 0: unlimited.
    rate: Atomic(u64) = .init(0),
    /// Monotonic ns at which everything booked so far is paid for.
    tat: Atomic(u64) = .init(0),
    /// How far `tat` may be ahead of the clock before a reader waits: the burst, as time at
    /// `rate` (100 ms: at 80 MiB/s, 8 MiB may pass at once after an idle spell).
    burst_ns: u64 = 100 * std.time.ns_per_ms,
    /// Set at shutdown: sleepers return at once.
    stopping: Atomic(bool) = .init(false),
    /// Bytes booked and time slept (diagnostics, tests).
    bytes: Atomic(u64) = .init(0),
    waited_ns: Atomic(u64) = .init(0),

    /// Sets the cap in MiB per second (0: none) and clears a previous stop.
    pub fn configure(b: *ByteBucket, mib_per_s: u32) void {
        b.rate.store(@as(u64, mib_per_s) << 20, .release);
        b.stopping.store(false, .release);
    }

    pub fn on(b: *const ByteBucket) bool {
        return b.rate.load(.monotonic) != 0;
    }

    /// Books `n` bytes at `now` (monotonic ns). Returns the time until which the caller should
    /// not read again (at or before `now`: no wait). Never blocks.
    pub fn reserve(b: *ByteBucket, n: u64, now: u64) u64 {
        const r = b.rate.load(.monotonic);
        if (r == 0 or n == 0) return now;
        const cost: u64 = @intCast(@min(@as(u128, n) * std.time.ns_per_s / r, std.math.maxInt(u64) / 4));
        _ = b.bytes.fetchAdd(n, .monotonic);
        var cur = b.tat.load(.monotonic);
        while (true) {
            // An idle spell earns nothing beyond the burst: the schedule restarts at `now`.
            const next = @max(cur, now) + cost;
            cur = b.tat.cmpxchgWeak(cur, next, .monotonic, .monotonic) orelse return next -| b.burst_ns;
        }
    }

    /// Sleeps the calling thread until `due` (from `reserve`), in steps that notice a stop.
    pub fn sleepUntil(b: *ByteBucket, io: Io, due: u64) void {
        while (!b.stopping.load(.acquire)) {
            const now = monoNs();
            if (now >= due) return;
            const step = @min(due - now, 100 * std.time.ns_per_ms);
            io.sleep(.fromNanoseconds(@intCast(step)), .awake) catch return;
            _ = b.waited_ns.fetchAdd(step, .monotonic);
        }
    }

    /// Books `n` bytes that were just received and waits until they are due.
    pub fn charge(b: *ByteBucket, io: Io, n: u64) void {
        if (!b.on() or n == 0) return;
        b.sleepUntil(io, b.reserve(n, monoNs()));
    }
};

/// The process's download cap (`ByteBucket`); the node sets it from `--net-max-mbps` at start.
pub var net_cap: ByteBucket = .{};

/// Bytes read from a paced body between two bookings.
const pace_chunk: usize = 64 << 10;

/// One request's bookings. The body loop sleeps inside the request for at most `budget_ns` in
/// total, and `Public.requestHttp` adds exactly that to the request's timeout, so the limiter's
/// sleep never counts against the time a GET has for the network. What is still owed when the
/// budget is spent is slept after the request, outside its timeout (`due`).
const Paced = struct {
    bucket: *ByteBucket,
    io: Io,
    budget_ns: u64,
    due: u64 = 0,

    fn charge(pc: *Paced, n: usize) void {
        if (n == 0) return;
        const now = monoNs();
        pc.due = pc.bucket.reserve(n, now);
        if (pc.due <= now) return;
        const s = @min(pc.due - now, pc.budget_ns);
        if (s == 0) return;
        pc.budget_ns -= s;
        pc.io.sleep(.fromNanoseconds(@intCast(s)), .awake) catch return;
        _ = pc.bucket.waited_ns.fetchAdd(s, .monotonic);
    }
};

fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const Result = enum { ok, missing };

pub const Public = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Base URL without a trailing slash.
    base: []const u8 = mainnet_base,
    /// Client pool: a request takes a free slot for its duration, so each std.http.Client (and
    /// its keep-alive connections and TLS clock) is used by one thread at a time and its clock can
    /// be refreshed without racing a handshake (netguard.Client). The first `limit` slots are in
    /// use; the rest stay untouched (a client that never made a request holds no memory).
    slots: [max_clients]Slot,
    /// Requests in flight at once, at most: `default_clients` until `setConcurrency`.
    limit: Atomic(u32) = .init(default_clients),
    fallback: ?*s3.Bucket = null,
    /// Highest sequence number this source has served (the tip as far as it knows).
    highest: Atomic(u64) = .init(0),
    stats: Stats = .{},
    /// One GET (connect, TLS, request, whole body) must finish within this, or it is canceled and
    /// fails with error.Timeout (the fetcher retries): a hung connection never holds a thread.
    timeout_ms: u64 = 15_000,
    /// Set at shutdown: requests in flight end within ~100 ms (error.Stopped).
    stopping: Atomic(bool) = .init(false),

    /// The pool with the default `--fetchers 8` (and the whole pool until lane tip-cheap, when
    /// `--fetchers 64` on the public bucket was silently 16 in flight): the fetch threads, the
    /// trust walk's 16 parallel requests, the main thread and stream-check.
    pub const default_clients = 16;
    /// Slots beside the fetch threads' own: the main thread's tip search and stream-check.
    pub const spare_clients = 2;
    /// The most requests this client ever has in flight at the bucket, whatever `--fetchers`
    /// says: 62 fetch threads and the two spare. More fetch threads than that still start; the
    /// extra ones wait for a slot. Each request in flight is a download at the link's speed, so
    /// on a shared box raise `--fetchers` together with `--net-max-mbps`.
    pub const max_clients = 64;

    /// Pool size for `fetchers` fetch threads: theirs plus the spare, never under the default
    /// (so nothing changes at or below 14 fetchers) and never over `max_clients`.
    pub fn clientsFor(fetchers: u32) u32 {
        return std.math.clamp(fetchers +| spare_clients, default_clients, max_clients);
    }

    /// Sizes the pool for `fetchers` fetch threads (before they start). Returns how many of
    /// them can have a request in flight at once.
    pub fn setConcurrency(p: *Public, fetchers: u32) u32 {
        const n = clientsFor(fetchers);
        p.limit.store(n, .release);
        return @min(fetchers, n);
    }

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

    fn tryAcquire(p: *Public) ?*Slot {
        for (p.slots[0..p.limit.load(.acquire)]) |*sl| {
            if (sl.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return sl;
        }
        return null;
    }

    fn acquire(p: *Public) *Slot {
        while (true) {
            if (p.tryAcquire()) |sl| return sl;
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
            // a request the stop ended is not a reason to ask S3 (and wait for it)
            if (p.stopping.load(.acquire)) return e;
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
        var nb: [48]u8 = undefined;
        const key = std.fmt.bufPrint(&nb, "{d}.binpb.zst", .{seq}) catch unreachable;
        if (first_byte) return if (try b.exists(key)) .ok else .missing;
        const r = try b.get(key, out);
        // s3.zig cannot pace inside a body: the object is booked once it is in.
        if (r == .ok) net_cap.charge(p.io, out.items.len);
        return switch (r) {
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
        // With a download cap (`net_cap`): the body is read in chunks, each booked. The request
        // may sleep for the limiter up to `timeout_ms` in total and gets that much more time,
        // so the network still has its full `timeout_ms`; the rest is slept once the slot is
        // free again (this defer runs last).
        const capped = net_cap.on();
        const budget_ms: u64 = if (capped) p.timeout_ms else 0;
        var paced: Paced = .{ .bucket = &net_cap, .io = p.io, .budget_ns = 0 };
        defer if (capped) net_cap.sleepUntil(p.io, paced.due);
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
            paced.budget_ns = budget_ms * std.time.ns_per_ms;
            break netguard.timed(p.io, p.timeout_ms + budget_ms, &p.stopping, &ab, fetchOnce, .{ &sl.client.http, url, hdrs[0..nh], &aw.writer, &ab, if (capped) &paced else null }) catch |e| {
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
/// With `pace` the body is read `pace_chunk` bytes at a time and each read is booked on the
/// download cap before the next (the reader sleeps, the sender slows down).
fn fetchOnce(c: *std.http.Client, url: []const u8, hdrs: []const std.http.Header, w: *std.Io.Writer, abort: *netguard.Abort, pace: ?*Paced) !std.http.Status {
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
    if (pace) |pc| {
        while (true) {
            const n = reader.stream(w, .limited(pace_chunk)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
                else => |e| return e,
            };
            pc.charge(n);
        }
        return response.head.status;
    }
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

test "public bucket: the request pool follows the fetcher count, 16 by default and 64 at most" {
    try std.testing.expectEqual(@as(u32, 16), Public.clientsFor(0));
    try std.testing.expectEqual(@as(u32, 16), Public.clientsFor(8)); // the default: as before
    try std.testing.expectEqual(@as(u32, 16), Public.clientsFor(14));
    try std.testing.expectEqual(@as(u32, 18), Public.clientsFor(16));
    try std.testing.expectEqual(@as(u32, 34), Public.clientsFor(32));
    try std.testing.expectEqual(@as(u32, 64), Public.clientsFor(62));
    try std.testing.expectEqual(@as(u32, 64), Public.clientsFor(64));
    try std.testing.expectEqual(@as(u32, 64), Public.clientsFor(4096));
    // A server that accepts and never answers: every request stays in flight.
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, null);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var p = Public.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer p.deinit();
    p.timeout_ms = 60_000;
    try std.testing.expectEqual(@as(u32, 16), p.limit.load(.acquire));
    try std.testing.expectEqual(@as(u32, 8), p.setConcurrency(8));
    try std.testing.expectEqual(@as(u32, 16), p.limit.load(.acquire));
    try std.testing.expectEqual(@as(u32, 64), p.setConcurrency(100)); // the documented maximum
    try std.testing.expectEqual(@as(u32, Public.max_clients), p.limit.load(.acquire));
    const fetchers = 32;
    try std.testing.expectEqual(@as(u32, fetchers), p.setConcurrency(fetchers));
    const Get = struct {
        fn run(pp: *Public, seq: u64, stopped: *Atomic(u32)) void {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(pp.gpa);
            if (pp.get(seq, &out)) |_| {} else |e| {
                if (e == error.Stopped) _ = stopped.fetchAdd(1, .acq_rel);
            }
        }
    };
    var stopped: Atomic(u32) = .init(0);
    var threads: [fetchers]std.Thread = undefined;
    var made: usize = 0;
    defer {
        p.stopping.store(true, .release);
        for (threads[0..made]) |t| t.join();
    }
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, Get.run, .{ &p, 1000 + i, &stopped });
        made += 1;
    }
    // All 32 are in flight at once. With the fixed pool of 16 the server saw 16 connections
    // and the other 16 threads slept in acquire() until a request timed out.
    var waited: u32 = 0;
    while (srv.accepts.load(.acquire) < fetchers and waited < 10_000) : (waited += 5) napMs(5);
    try std.testing.expectEqual(@as(u32, fetchers), srv.accepts.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), stopped.load(.acquire));
    p.stopping.store(true, .release);
    for (threads[0..made]) |t| t.join();
    made = 0;
    try std.testing.expectEqual(@as(u32, fetchers), stopped.load(.acquire));
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

test "byte bucket: the rate over a simulated clock is the configured one within 10%, for one reader and for many" {
    const mib: u64 = 1 << 20;
    // One reader, 64 KiB reads that arrive at once (a link far faster than the cap).
    {
        var b: ByteBucket = .{};
        b.configure(8);
        const t0: u64 = 5 * std.time.ns_per_s;
        var now = t0;
        var total: u64 = 0;
        while (now - t0 < 20 * std.time.ns_per_s) {
            const due = b.reserve(64 << 10, now);
            total += 64 << 10;
            now = @max(now, due) + 20_000; // the read itself
        }
        const rate = @as(u128, total) * std.time.ns_per_s / (now - t0);
        try std.testing.expect(rate >= 8 * mib * 90 / 100 and rate <= 8 * mib * 110 / 100);
        try std.testing.expectEqual(total, b.bytes.load(.monotonic));
    }
    // 48 readers sharing it, uneven read sizes (4 KiB to 256 KiB): together they get the rate,
    // not the rate each.
    {
        var b: ByteBucket = .{};
        b.configure(25);
        const t0: u64 = 1000;
        var ready: [48]u64 = @splat(t0);
        var total: u64 = 0;
        var now: u64 = t0;
        var rng = std.Random.DefaultPrng.init(7);
        while (now - t0 < 30 * std.time.ns_per_s) {
            var who: usize = 0;
            for (ready, 0..) |r, i| {
                if (r < ready[who]) who = i;
            }
            now = @max(now, ready[who]);
            const n: u64 = @as(u64, 4 << 10) << rng.random().uintLessThan(u6, 7);
            const due = b.reserve(n, now);
            total += n;
            ready[who] = @max(now, due) + 50_000 + rng.random().uintLessThan(u64, 200_000);
        }
        const rate = @as(u128, total) * std.time.ns_per_s / (now - t0);
        try std.testing.expect(rate >= 25 * mib * 90 / 100 and rate <= 25 * mib * 110 / 100);
    }
    // A link slower than the cap is never delayed.
    {
        var b: ByteBucket = .{};
        b.configure(8);
        var now: u64 = 1000;
        for (0..1000) |_| {
            try std.testing.expect(b.reserve(64 << 10, now) <= now);
            now += 16 * std.time.ns_per_ms; // 4 MiB/s
        }
    }
    // After an idle minute only the burst (100 ms of rate) passes at once, not a minute's worth.
    {
        var b: ByteBucket = .{};
        b.configure(8);
        _ = b.reserve(64 << 10, 1000);
        const now: u64 = 60 * std.time.ns_per_s;
        var passed: u64 = 0;
        while (b.reserve(64 << 10, now) <= now) passed += 64 << 10;
        try std.testing.expect(passed <= 8 * mib / 10 and passed >= 8 * mib / 10 - (128 << 10));
    }
    // No cap (the default): nothing is booked or delayed.
    {
        var b: ByteBucket = .{};
        try std.testing.expect(!b.on());
        try std.testing.expectEqual(@as(u64, 77), b.reserve(1 << 30, 77));
        try std.testing.expectEqual(@as(u64, 0), b.tat.load(.monotonic));
        try std.testing.expectEqual(@as(u64, 0), b.bytes.load(.monotonic));
    }
}

test "public bucket: a GET under the download cap takes the capped time, keeps its bytes and does not time out" {
    const gpa = std.testing.allocator;
    const body_len: usize = 1 << 20;
    const head = "HTTP/1.1 200 OK\r\ncontent-length: 1048576\r\nconnection: close\r\n\r\n";
    const reply = try gpa.alloc(u8, head.len + body_len);
    defer gpa.free(reply);
    @memcpy(reply[0..head.len], head);
    for (reply[head.len..], 0..) |*c, i| c.* = @truncate(i *% 31 +% (i >> 8));
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var ub: [64]u8 = undefined;
    defer net_cap = .{};
    // No cap: at once.
    {
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, reply);
        defer srv.stop();
        var p = Public.init(gpa, std.testing.io, srv.url(&ub));
        defer p.deinit();
        try std.testing.expectEqual(Result.ok, try p.get(1, &out));
        try std.testing.expectEqualSlices(u8, reply[head.len..], out.items);
        try std.testing.expectEqual(@as(u64, 0), net_cap.bytes.load(.monotonic));
    }
    // 2 MiB/s: 1 MiB less the 100 ms burst is 0.4 s. The request's timeout is 250 ms, less than
    // the limiter's sleep: the sleep does not count against it.
    {
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, reply);
        defer srv.stop();
        var p = Public.init(gpa, std.testing.io, srv.url(&ub));
        defer p.deinit();
        p.timeout_ms = 250;
        net_cap = .{};
        net_cap.configure(2);
        const t0 = netguard.wallMs();
        try std.testing.expectEqual(Result.ok, try p.get(2, &out));
        const ms = netguard.wallMs() - t0;
        try std.testing.expectEqualSlices(u8, reply[head.len..], out.items);
        try std.testing.expectEqual(@as(u64, body_len), net_cap.bytes.load(.monotonic));
        try std.testing.expect(ms >= 350);
        try std.testing.expect(ms < 10_000);
        try std.testing.expectEqual(@as(u64, 0), p.stats.timeouts.load(.monotonic));
        try std.testing.expectEqual(@as(u64, 0), p.stats.errors.load(.monotonic));
    }
    // A stop ends a limiter sleep at once.
    {
        net_cap = .{};
        net_cap.configure(1);
        net_cap.stopping.store(true, .release);
        const t0 = netguard.wallMs();
        net_cap.sleepUntil(std.testing.io, monoNs() + 60 * std.time.ns_per_s);
        try std.testing.expect(netguard.wallMs() - t0 < 1000);
    }
}
