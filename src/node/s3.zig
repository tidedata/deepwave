//! Mysten's checkpoint archive on S3 (`s3://mysten-mainnet-checkpoints`, us-west-2, requester
//! pays) over HTTPS with AWS Signature Version 4, in Zig (std.http.Client + std.crypto).
//!
//! Every key `<seq>.binpb.zst` exists from genesis to the tip (the archive lags the tip by under
//! a second, measured 2026-11-07). The archive is untrusted: everything fetched is verified by
//! the follower (BLS certificate, digests, objects against effects) before it is stored.
//!
//! Cost (requester pays): about $0.0004 per 1,000 GETs plus $0.09/GB out of us-west-2. Every
//! request and byte is counted in `Stats`; the node logs the spend when it stops.
//!
//! Credentials come from an AWS shared credentials file (`[profile]` with aws_access_key_id,
//! aws_secret_access_key, optional aws_session_token). They are never printed.
const std = @import("std");
const netguard = @import("netguard.zig");
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const default_bucket = "mysten-mainnet-checkpoints";
pub const default_region = "us-west-2";
pub const usd_per_get = 0.0004 / 1000.0;
pub const usd_per_byte = 0.09 / 1073741824.0;

pub const Credentials = struct {
    access_key: []const u8,
    secret_key: []const u8,
    session_token: ?[]const u8 = null,

    /// Reads `[profile]` from an AWS shared credentials file. Strings live in `arena`.
    pub fn load(arena: std.mem.Allocator, io: Io, path: []const u8, profile: []const u8) !Credentials {
        const text = try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20));
        var section: []const u8 = "";
        var c: Credentials = .{ .access_key = "", .secret_key = "" };
        var it = std.mem.splitScalar(u8, text, '\n');
        while (it.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
            if (line[0] == '[') {
                section = std.mem.trim(u8, line[1 .. std.mem.indexOfScalar(u8, line, ']') orelse line.len], " ");
                continue;
            }
            if (!std.mem.eql(u8, section, profile)) continue;
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const k = std.mem.trim(u8, line[0..eq], " \t");
            const v = std.mem.trim(u8, line[eq + 1 ..], " \t");
            if (std.mem.eql(u8, k, "aws_access_key_id")) c.access_key = v;
            if (std.mem.eql(u8, k, "aws_secret_access_key")) c.secret_key = v;
            if (std.mem.eql(u8, k, "aws_session_token")) c.session_token = v;
        }
        if (c.access_key.len == 0 or c.secret_key.len == 0) return error.NoCredentials;
        return c;
    }
};

pub const Stats = struct {
    gets: std.atomic.Value(u64) = .init(0),
    misses: std.atomic.Value(u64) = .init(0),
    errors: std.atomic.Value(u64) = .init(0),
    bytes: std.atomic.Value(u64) = .init(0),

    pub fn usd(s: *const Stats) f64 {
        const g: f64 = @floatFromInt(s.gets.load(.monotonic));
        const b: f64 = @floatFromInt(s.bytes.load(.monotonic));
        return g * usd_per_get + b * usd_per_byte;
    }
};

pub const Bucket = struct {
    gpa: std.mem.Allocator,
    io: Io,
    creds: Credentials,
    bucket: []const u8 = default_bucket,
    region: []const u8 = default_region,
    client: std.http.Client,
    stats: Stats = .{},
    /// Hard stop: no more requests once the estimated spend reaches this (USD).
    budget_usd: f64 = 5.0,

    pub fn init(gpa: std.mem.Allocator, io: Io, creds: Credentials) Bucket {
        return .{ .gpa = gpa, .io = io, .creds = creds, .client = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(b: *Bucket) void {
        b.client.deinit();
    }

    pub const Result = enum { ok, missing };

    /// GETs `key` into `out` (cleared first). Thread-safe.
    pub fn get(b: *Bucket, key: []const u8, out: *std.ArrayList(u8)) !Result {
        return b.request(.GET, key, out);
    }

    /// Does `key` exist? A one-byte ranged GET (206 or 404), not a HEAD: std.http's fetch of a
    /// HEAD either writes to the constant `Reader.ending_instance` (no response writer, a segfault
    /// on Linux: bench-rig run 1, `--from tip`) or waits for a Content-Length body that never comes
    /// (with one). Same request price as a HEAD. Thread-safe.
    pub fn exists(b: *Bucket, key: []const u8) !bool {
        return (try b.requestOpts(key, null, true)) == .ok;
    }

    fn request(b: *Bucket, method: std.http.Method, key: []const u8, out: ?*std.ArrayList(u8)) !Result {
        std.debug.assert(method == .GET);
        return b.requestOpts(key, out, false);
    }

    fn requestOpts(b: *Bucket, key: []const u8, out: ?*std.ArrayList(u8), first_byte: bool) !Result {
        const method: std.http.Method = .GET;
        if (b.stats.usd() >= b.budget_usd) return error.BudgetExhausted;
        var host_buf: [128]u8 = undefined;
        const host = try std.fmt.bufPrint(&host_buf, "{s}.s3.{s}.amazonaws.com", .{ b.bucket, b.region });
        var url_buf: [256]u8 = undefined;
        const url = try std.fmt.bufPrint(&url_buf, "https://{s}/{s}", .{ host, key });

        const now_s: i64 = Io.Clock.real.now(b.io).toSeconds();
        var amz_date: [16]u8 = undefined;
        var day: [8]u8 = undefined;
        formatDate(now_s, &amz_date, &day);
        const empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        var sig_hex: [64]u8 = undefined;
        // Room for an instance-role session token (often over 1 KiB; it is in the canonical request).
        var canon_buf: [8192]u8 = undefined;
        const signed_headers = if (b.creds.session_token != null)
            "host;x-amz-content-sha256;x-amz-date;x-amz-request-payer;x-amz-security-token"
        else
            "host;x-amz-content-sha256;x-amz-date;x-amz-request-payer";
        {
            var cw = std.Io.Writer.fixed(&canon_buf);
            try cw.print("{s}\n/{s}\n\nhost:{s}\nx-amz-content-sha256:{s}\nx-amz-date:{s}\nx-amz-request-payer:requester\n", .{ @tagName(method), key, host, empty_hash, &amz_date });
            if (b.creds.session_token) |t| try cw.print("x-amz-security-token:{s}\n", .{t});
            try cw.print("\n{s}\n{s}", .{ signed_headers, empty_hash });
            var ch: [32]u8 = undefined;
            Sha256.hash(cw.buffered(), &ch, .{});
            var sts_buf: [256]u8 = undefined;
            const sts = try std.fmt.bufPrint(&sts_buf, "AWS4-HMAC-SHA256\n{s}\n{s}/{s}/s3/aws4_request\n{x}", .{ &amz_date, &day, b.region, &ch });
            var k: [32]u8 = undefined;
            var kbuf: [128]u8 = undefined;
            const ksecret = try std.fmt.bufPrint(&kbuf, "AWS4{s}", .{b.creds.secret_key});
            HmacSha256.create(&k, &day, ksecret);
            std.crypto.secureZero(u8, &kbuf);
            HmacSha256.create(&k, b.region, &k);
            HmacSha256.create(&k, "s3", &k);
            HmacSha256.create(&k, "aws4_request", &k);
            var sig: [32]u8 = undefined;
            HmacSha256.create(&sig, sts, &k);
            std.crypto.secureZero(u8, &k);
            _ = try std.fmt.bufPrint(&sig_hex, "{x}", .{&sig});
        }
        var auth_buf: [512]u8 = undefined;
        const auth = try std.fmt.bufPrint(&auth_buf, "AWS4-HMAC-SHA256 Credential={s}/{s}/{s}/s3/aws4_request, SignedHeaders={s}, Signature={s}", .{ b.creds.access_key, &day, b.region, signed_headers, &sig_hex });
        var hdrs: [5]std.http.Header = undefined;
        var nh: usize = 0;
        hdrs[nh] = .{ .name = "x-amz-content-sha256", .value = empty_hash };
        nh += 1;
        hdrs[nh] = .{ .name = "x-amz-date", .value = &amz_date };
        nh += 1;
        hdrs[nh] = .{ .name = "x-amz-request-payer", .value = "requester" };
        nh += 1;
        if (b.creds.session_token) |t| {
            hdrs[nh] = .{ .name = "x-amz-security-token", .value = t };
            nh += 1;
        }
        // Unsigned (SigV4 only requires host and x-amz-* headers to be signed).
        if (first_byte) {
            hdrs[nh] = .{ .name = "range", .value = "bytes=0-0" };
            nh += 1;
        }

        _ = b.stats.gets.fetchAdd(1, .monotonic);
        var aw: std.Io.Writer.Allocating = if (out) |o| .fromArrayList(b.gpa, o) else .init(b.gpa);
        defer if (out) |o| {
            o.* = aw.toArrayList();
        } else aw.deinit();
        if (out) |_| aw.writer.end = 0;
        // A pooled keep-alive connection the server has closed fails on first use; S3 closes idle
        // connections, so retry at once on a fresh one (the request is idempotent).
        var attempt: u32 = 0;
        const res = while (true) : (attempt += 1) {
            if (out) |_| aw.writer.end = 0;
            break fetchOnce(b, url, method, hdrs[0..nh], auth, &aw.writer) catch |e| {
                if (attempt < 32 and transient(@errorName(e))) {
                    // std.http may have put the failed connection back in the pool: never
                    // retry on it (netguard.dropIdle).
                    netguard.dropIdle(&b.client);
                    continue;
                }
                _ = b.stats.errors.fetchAdd(1, .monotonic);
                return e;
            };
        };
        _ = b.stats.bytes.fetchAdd(aw.writer.end, .monotonic);
        switch (res.status) {
            .ok => return .ok,
            .partial_content => return if (first_byte) .ok else error.HttpStatus,
            .not_found => {
                _ = b.stats.misses.fetchAdd(1, .monotonic);
                return .missing;
            },
            else => {
                _ = b.stats.errors.fetchAdd(1, .monotonic);
                const body = if (out) |_| aw.writer.buffered() else "";
                std.log.warn("s3 {s} {s}: HTTP {d} {s}", .{ @tagName(method), key, @intFromEnum(res.status), body[0..@min(body.len, 300)] });
                return error.HttpStatus;
            },
        }
    }
};

fn transient(name: []const u8) bool {
    const names = [_][]const u8{ "HttpConnectionClosing", "ConnectionResetByPeer", "BrokenPipe", "HttpRequestTruncated", "ReadFailed", "WriteFailed", "EndOfStream", "ConnectionTimedOut" };
    for (names) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

fn fetchOnce(b: *Bucket, url: []const u8, method: std.http.Method, hdrs: []const std.http.Header, auth: []const u8, w: *std.Io.Writer) !std.http.Client.FetchResult {
    return b.client.fetch(.{
        .location = .{ .url = url },
        .method = method,
        .extra_headers = hdrs,
        .response_writer = w,
        // (std.http sends `privileged_headers` nowhere; the authorization header goes here.)
        .headers = .{ .accept_encoding = .omit, .authorization = .{ .override = auth } },
    });
}

/// `YYYYMMDDTHHMMSSZ` and `YYYYMMDD` (UTC) for SigV4.
fn formatDate(unix_s: i64, amz: *[16]u8, day: *[8]u8) void {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(unix_s) };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    _ = std.fmt.bufPrint(amz, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", .{
        yd.year, md.month.numeric(), @as(u32, md.day_index) + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    }) catch unreachable;
    @memcpy(day, amz[0..8]);
}

test "sigv4 date" {
    var a: [16]u8 = undefined;
    var d: [8]u8 = undefined;
    formatDate(1794088373, &a, &d);
    try std.testing.expectEqualStrings("20261107T215253Z", &a);
    try std.testing.expectEqualStrings("20261107", &d);
}

// AWS's published SigV4 example (GET object, s3 docs "Example: GET Object"), checks the
// signing chain with fixed inputs.
test "sigv4 signing key chain" {
    var k: [32]u8 = undefined;
    HmacSha256.create(&k, "20130524", "AWS4wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    HmacSha256.create(&k, "us-east-1", &k);
    HmacSha256.create(&k, "s3", &k);
    HmacSha256.create(&k, "aws4_request", &k);
    const canon = "GET\n/test.txt\n\nhost:examplebucket.s3.amazonaws.com\nrange:bytes=0-9\nx-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\nx-amz-date:20130524T000000Z\n\nhost;range;x-amz-content-sha256;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    var ch: [32]u8 = undefined;
    Sha256.hash(canon, &ch, .{});
    var sts_buf: [256]u8 = undefined;
    const sts = try std.fmt.bufPrint(&sts_buf, "AWS4-HMAC-SHA256\n20130524T000000Z\n20130524/us-east-1/s3/aws4_request\n{x}", .{&ch});
    var sig: [32]u8 = undefined;
    HmacSha256.create(&sig, sts, &k);
    var hex: [64]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "{x}", .{&sig});
    try std.testing.expectEqualStrings("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", &hex);
}
