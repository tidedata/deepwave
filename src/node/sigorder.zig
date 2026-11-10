//! Sponsored and multi-signer transactions: the submitted signature order for checkpoints the
//! bucket fills.
//!
//! sui-node 1.83.1 answers a transaction's `signatures` (GetTransaction, BatchGetTransactions,
//! GetCheckpoint transactions, subscriptions) from its stored transaction, in the order the
//! submitter sent. Checkpoint contents certify the same signatures in signer order (sender, then
//! sponsor), and Mysten's bucket protos carry only the contents, so a checkpoint converted from
//! the bucket stores e.g. [sender, sponsor] where sui-node has [sponsor, sender]. No digest covers
//! the order: it has to come from a node that has it.
//!
//! The live stream and p2p already carry it (convert.txSignatures, p2p_exec.samePermutation). For
//! a checkpoint the bucket wins (a stream reconnect gap, catch-up) whose contents hold a list of
//! two or more signatures, the fetcher asks the stream's full node for
//! `GetCheckpoint { sequence_number, read_mask: transactions.signatures.bcs }` over gRPC-web and
//! converts with that overlay (convert.Options.sig_overlay). The overlay is untrusted like every
//! source: a list is taken only when it is exactly the certified signatures as a multiset, else
//! the contents order stays.
//!
//! Bounded so a catch-up never floods the public node: a request budget (`rps`, default 20 a
//! second, a burst of the same size); over budget, or when the node does not answer within
//! `timeout_ms` or does not hold the checkpoint (NOT_FOUND), the checkpoint keeps the contents
//! order and the miss is counted (`zui_sig_order_*`).
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const netguard = @import("netguard.zig");
const stream = @import("stream.zig");

/// The fields asked of the full node: enough to align and to take each transaction's list.
pub const read_mask = [_][]const u8{ "sequence_number", "transactions.signatures.bcs" };

pub const path = "/sui.rpc.v2.LedgerService/GetCheckpoint";

pub const Stats = struct {
    /// Bucket checkpoints whose contents certify a 2+ signature list (an overlay was wanted).
    wanted: Atomic(u64) = .init(0),
    requests: Atomic(u64) = .init(0),
    /// Overlays received and handed to the conversion.
    served: Atomic(u64) = .init(0),
    /// The full node does not hold the checkpoint (pruned, or ahead of it).
    not_found: Atomic(u64) = .init(0),
    /// Over the request budget: contents order kept.
    throttled: Atomic(u64) = .init(0),
    timeouts: Atomic(u64) = .init(0),
    errors: Atomic(u64) = .init(0),
    bytes: Atomic(u64) = .init(0),
};

/// A request budget: `burst` requests at once, then one per `interval_ns` (GCRA). Lock-free.
pub const Pace = struct {
    /// 0: no limit.
    interval_ns: u64,
    burst: u64,
    /// Theoretical arrival time of the next request (monotonic ns).
    tat: Atomic(u64) = .init(0),

    pub fn perSecond(rps: u32) Pace {
        if (rps == 0) return .{ .interval_ns = 0, .burst = 1 };
        return .{ .interval_ns = std.time.ns_per_s / rps, .burst = rps };
    }

    /// Takes one request at `now_ns`; false when the budget is spent.
    pub fn take(p: *Pace, now_ns: u64) bool {
        if (p.interval_ns == 0) return true;
        const slack = (p.burst -| 1) * p.interval_ns;
        var cur = p.tat.load(.monotonic);
        while (true) {
            const t = @max(cur, now_ns);
            if (t - now_ns > slack) return false;
            cur = p.tat.cmpxchgWeak(cur, t + p.interval_ns, .monotonic, .monotonic) orelse return true;
        }
    }
};

/// The grpc-web request body: one uncompressed frame of
/// `GetCheckpointRequest { sequence_number = 1: seq, read_mask = 3: { paths = 1 } }`.
pub fn requestBody(a: std.mem.Allocator, seq: u64) ![]u8 {
    var mask: std.ArrayList(u8) = .empty;
    for (read_mask) |p| try putLen(a, &mask, 1, p);
    var msg: std.ArrayList(u8) = .empty;
    try putVarint(a, &msg, 1 << 3);
    try putVarint(a, &msg, seq);
    try putLen(a, &msg, 3, mask.items);
    const out = try a.alloc(u8, 5 + msg.items.len);
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(msg.items.len), .big);
    @memcpy(out[5..], msg.items);
    return out;
}

fn putLen(a: std.mem.Allocator, out: *std.ArrayList(u8), field: u32, bytes: []const u8) !void {
    try putVarint(a, out, (field << 3) | 2);
    try putVarint(a, out, bytes.len);
    try out.appendSlice(a, bytes);
}

fn putVarint(a: std.mem.Allocator, out: *std.ArrayList(u8), v_in: u64) !void {
    var v = v_in;
    while (v >= 0x80) : (v >>= 7) try out.append(a, @as(u8, @truncate(v)) | 0x80);
    try out.append(a, @truncate(v));
}

fn varint(b: []const u8, i: *usize) !u64 {
    var r: u64 = 0;
    var shift: u6 = 0;
    while (i.* < b.len) {
        const x = b[i.*];
        i.* += 1;
        r |= @as(u64, x & 0x7f) << shift;
        if (x < 0x80) return r;
        if (shift >= 63) return error.Malformed;
        shift += 7;
    }
    return error.Malformed;
}

pub const Unary = union(enum) {
    /// `GetCheckpointResponse.checkpoint` (a `Checkpoint` proto; empty if absent).
    checkpoint: []const u8,
    not_found,
};

/// A grpc-web unary response body (data frames, then a trailers frame) to the checkpoint it
/// carries. grpc-status 5 is `not_found`; any other non-zero status is `error.GrpcStatus`.
pub fn parseUnary(body: []const u8) !Unary {
    var msg: ?[]const u8 = null;
    var i: usize = 0;
    while (i < body.len) {
        if (body.len - i < 5) return error.Malformed;
        const flags = body[i];
        const n = std.mem.readInt(u32, body[i + 1 ..][0..4], .big);
        i += 5;
        if (n > body.len - i) return error.Malformed;
        const payload = body[i..][0..n];
        i += n;
        if (flags & 0x80 != 0) {
            const code = trailerStatus(payload) orelse return error.Malformed;
            if (code == 5) return .not_found;
            if (code != 0) return error.GrpcStatus;
            break;
        }
        if (flags & 1 != 0) return error.CompressedFrame; // never asked for
        msg = payload;
    }
    const m = msg orelse return error.Malformed;
    // GetCheckpointResponse { checkpoint = 1 }
    var cp: []const u8 = &.{};
    var j: usize = 0;
    while (j < m.len) {
        const key = try varint(m, &j);
        switch (key & 7) {
            0 => _ = try varint(m, &j),
            1 => j += 8,
            5 => j += 4,
            2 => {
                const n = try varint(m, &j);
                if (n > m.len - j) return error.Malformed;
                if (key >> 3 == 1) cp = m[j..][0..n];
                j += n;
            },
            else => return error.Malformed,
        }
        if (j > m.len) return error.Malformed;
    }
    return .{ .checkpoint = cp };
}

/// `grpc-status` in a grpc-web trailers block (`name:value` lines).
fn trailerStatus(t: []const u8) ?u32 {
    var it = std.mem.tokenizeAny(u8, t, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), "grpc-status")) continue;
        return std.fmt.parseInt(u32, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch null;
    }
    return null;
}

/// What one call came back with: a body to parse, or a trailers-only NOT_FOUND.
const Answer = enum { body, not_found };

/// One POST into `w`, with the connection's socket registered in `abort` while it exists.
fn callOnce(c: *std.http.Client, url: []const u8, body: []u8, w: *std.Io.Writer, abort: *netguard.Abort) !Answer {
    const uri = try std.Uri.parse(url);
    var req = try c.request(.POST, uri, .{
        .redirect_behavior = .unhandled,
        .headers = .{ .content_type = .{ .override = "application/grpc-web+proto" }, .accept_encoding = .omit, .user_agent = .{ .override = "deepwave" } },
        .extra_headers = &.{
            .{ .name = "x-grpc-web", .value = "1" },
            .{ .name = "accept", .value = "application/grpc-web+proto" },
        },
    });
    defer req.deinit();
    // Any failure: the connection is not reused (see http.zig fetchOnce).
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try abort.arm(netguard.socketOf(req.connection.?));
    defer abort.disarm();
    try req.sendBodyComplete(body);
    var res = try req.receiveHead(&.{});
    if (res.head.status != .ok) return error.HttpStatus;
    if (stream.headStatus(res.head)) |st| {
        // Trailers-only: no body to drain; do not reuse the connection anyway.
        if (req.connection) |conn| conn.closing = true;
        if (st.code == 5) return .not_found;
        return error.GrpcStatus;
    }
    if (res.head.content_encoding != .identity) return error.UnsupportedCompressionMethod;
    const reader = res.reader(&.{});
    // Bounded while reading, not checked after: a node streaming without end would otherwise
    // grow the arena for the whole timeout. A failed socket read leaves `bodyErr` null (std sets
    // it only for chunk framing errors), so it is not unwrapped.
    var left: usize = Overlay.max_answer + 1;
    while (left > 0) {
        left -= reader.stream(w, .limited(left)) catch |err| switch (err) {
            error.EndOfStream => return .body,
            error.ReadFailed => return res.bodyErr() orelse error.ReadFailed,
            error.WriteFailed => return error.WriteFailed,
        };
    }
    return error.AnswerTooLarge;
}

/// A stale keep-alive connection's failure (worth one retry on a fresh connection).
fn retryable(e: anyerror) bool {
    return switch (e) {
        error.HttpConnectionClosing, error.ConnectionResetByPeer, error.BrokenPipe, error.HttpRequestTruncated, error.ReadFailed, error.WriteFailed, error.EndOfStream => true,
        else => false,
    };
}

/// Request budget for a remote node (a public full node).
pub const default_rps: u32 = 20;
/// For a node on this host (the local sui-node in the shadow phase): enough for a catch-up.
pub const loopback_rps: u32 = 200;

/// Whether `url` names a node on this host.
pub fn isLoopback(url: []const u8) bool {
    const rest = if (std.mem.indexOf(u8, url, "://")) |k| url[k + 3 ..] else url;
    const host_end = std.mem.indexOfAny(u8, rest, ":/") orelse rest.len;
    const host = if (rest.len > 0 and rest[0] == '[') blk: {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse break :blk rest;
        break :blk rest[1..close];
    } else rest[0..host_end];
    return std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1") or std.mem.startsWith(u8, host, "127.");
}

/// The overlay node from the `--stream` list (`A,B,...`): the first loopback URL (the local
/// sui-node standby: the very order the drop-in is compared with, and no public limits), else the
/// first URL. Trimmed of spaces and a trailing slash; null for an empty list.
pub fn pickBase(urls: []const u8) ?[]const u8 {
    var first: ?[]const u8 = null;
    var it = std.mem.tokenizeScalar(u8, urls, ',');
    while (it.next()) |raw| {
        const u = std.mem.trimEnd(u8, std.mem.trim(u8, raw, " "), "/");
        if (u.len == 0) continue;
        if (isLoopback(u)) return u;
        if (first == null) first = u;
    }
    return first;
}

/// The overlay client: one per node, shared by the fetch threads.
pub const Overlay = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// The full node's base URL (the first `--stream` URL), no trailing slash.
    base: []const u8,
    pace: Pace,
    /// Requests a second (`pace`), for the logs and the config echo.
    rps: u32,
    /// One attempt (connect, TLS, request, whole answer) must finish within this; past it the
    /// checkpoint keeps the contents order. A stale keep-alive failure gets one more attempt, so
    /// a fetch thread is held at most twice this (plus a wait for a free client).
    timeout_ms: u64 = 3_000,
    /// Set at shutdown: calls in flight end within ~100 ms.
    stopping: Atomic(bool) = .init(false),
    slots: [max_clients]Slot,
    stats: Stats = .{},
    warned_ms: Atomic(u64) = .init(0),

    pub const max_clients = 4;
    /// Largest answer read (signatures only: a few hundred KB at most).
    pub const max_answer: usize = 64 << 20;

    const Slot = struct {
        busy: Atomic(bool) = .init(false),
        client: netguard.Client,
    };

    pub fn init(gpa: std.mem.Allocator, io: Io, base: []const u8, rps: u32) Overlay {
        var o: Overlay = .{ .gpa = gpa, .io = io, .base = std.mem.trimEnd(u8, base, "/"), .pace = .perSecond(rps), .rps = rps, .slots = undefined };
        for (&o.slots) |*sl| {
            sl.* = .{ .client = netguard.Client.init(gpa, io) };
            sl.client.http.connection_pool.free_size = 2;
        }
        return o;
    }

    pub fn deinit(o: *Overlay) void {
        for (&o.slots) |*sl| sl.client.deinit();
    }

    fn acquire(o: *Overlay) *Slot {
        while (true) {
            for (&o.slots) |*sl| {
                if (sl.busy.cmpxchgStrong(false, true, .acquire, .monotonic) == null) return sl;
            }
            o.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    fn warn(o: *Overlay, seq: u64, why: []const u8) void {
        const now = netguard.wallMs();
        const last = o.warned_ms.load(.monotonic);
        if (now -| last > 60_000 and o.warned_ms.cmpxchgStrong(last, now, .monotonic, .monotonic) == null)
            std.log.warn("signature order {d} from {s}: {s}; the contents order is kept (logged once a minute)", .{ seq, o.base, why });
    }

    /// The overlay `Checkpoint` proto for `seq`, allocated in `arena`, or null (over budget, not
    /// held by the node, or failed: the caller converts with the contents order). Thread-safe.
    pub fn get(o: *Overlay, arena: std.mem.Allocator, seq: u64) ?[]const u8 {
        _ = o.stats.wanted.fetchAdd(1, .monotonic);
        if (o.stopping.load(.acquire)) return null;
        if (!o.pace.take(@import("source.zig").nowNs())) {
            _ = o.stats.throttled.fetchAdd(1, .monotonic);
            return null;
        }
        _ = o.stats.requests.fetchAdd(1, .monotonic);
        var ub: [256]u8 = undefined;
        const url = std.fmt.bufPrint(&ub, "{s}" ++ path, .{o.base}) catch {
            _ = o.stats.errors.fetchAdd(1, .monotonic);
            return null;
        };
        const body = requestBody(arena, seq) catch return null;
        var out: std.ArrayList(u8) = .empty;
        var aw: std.Io.Writer.Allocating = .fromArrayList(arena, &out);
        const sl = o.acquire();
        defer sl.busy.store(false, .release);
        sl.client.prepare(netguard.wallMs());
        defer sl.client.done(netguard.wallMs());
        var ab: netguard.Abort = .{};
        // A pooled keep-alive connection the server closed fails on first use: one retry on a
        // fresh connection (the call only reads). Each attempt is bounded by `timeout_ms`.
        var attempt: u32 = 0;
        const ans = while (true) : (attempt += 1) {
            aw.writer.end = 0;
            ab.reset();
            break netguard.timed(o.io, o.timeout_ms, &o.stopping, &ab, callOnce, .{ &sl.client.http, url, body, &aw.writer, &ab }) catch |e| {
                sl.client.noteError(e, netguard.wallMs());
                sl.client.dropPool();
                if (e == error.Stopped) return null;
                if (attempt == 0 and retryable(e)) continue;
                _ = (if (e == error.Timeout) &o.stats.timeouts else &o.stats.errors).fetchAdd(1, .monotonic);
                o.warn(seq, @errorName(e));
                return null;
            };
        };
        if (ans == .not_found) {
            _ = o.stats.not_found.fetchAdd(1, .monotonic);
            return null;
        }
        const got = aw.writer.buffered();
        _ = o.stats.bytes.fetchAdd(got.len, .monotonic);
        if (got.len > max_answer) {
            _ = o.stats.errors.fetchAdd(1, .monotonic);
            return null;
        }
        const u = parseUnary(got) catch |e| {
            _ = o.stats.errors.fetchAdd(1, .monotonic);
            o.warn(seq, @errorName(e));
            return null;
        };
        switch (u) {
            .not_found => {
                _ = o.stats.not_found.fetchAdd(1, .monotonic);
                return null;
            },
            .checkpoint => |cp| {
                _ = o.stats.served.fetchAdd(1, .monotonic);
                return cp;
            },
        }
    }
};

test "sigorder: request body is a framed GetCheckpointRequest with the signatures mask" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const b = try requestBody(a, 343111673);
    try std.testing.expectEqual(@as(u8, 0), b[0]);
    try std.testing.expectEqual(@as(usize, b.len - 5), std.mem.readInt(u32, b[1..5], .big));
    // sequence_number = 1 (varint) first.
    try std.testing.expectEqual(@as(u8, 0x08), b[5]);
    var i: usize = 6;
    try std.testing.expectEqual(@as(u64, 343111673), try varint(b, &i));
    // read_mask = 3 (len).
    try std.testing.expectEqual(@as(u8, 0x1a), b[i]);
    try std.testing.expect(std.mem.indexOf(u8, b, "transactions.signatures.bcs") != null);
    try std.testing.expect(std.mem.indexOf(u8, b, "sequence_number") != null);
}

fn frame(a: std.mem.Allocator, out: *std.ArrayList(u8), flags: u8, payload: []const u8) !void {
    var h: [5]u8 = undefined;
    h[0] = flags;
    std.mem.writeInt(u32, h[1..5], @intCast(payload.len), .big);
    try out.appendSlice(a, &h);
    try out.appendSlice(a, payload);
}

test "sigorder: unary grpc-web answers (checkpoint, NOT_FOUND trailer, error, malformed)" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // GetCheckpointResponse { checkpoint = 1: { sequence_number = 1: 7 } }
    const cp = [_]u8{ 0x08, 0x07 };
    var msg: std.ArrayList(u8) = .empty;
    try putLen(a, &msg, 1, &cp);
    var ok: std.ArrayList(u8) = .empty;
    try frame(a, &ok, 0, msg.items);
    try frame(a, &ok, 0x80, "grpc-status:0\r\ngrpc-message:\r\n");
    const u = try parseUnary(ok.items);
    try std.testing.expectEqualSlices(u8, &cp, u.checkpoint);

    var nf: std.ArrayList(u8) = .empty;
    try frame(a, &nf, 0x80, "grpc-status: 5\r\ngrpc-message: checkpoint 9 not found\r\n");
    try std.testing.expect((try parseUnary(nf.items)) == .not_found);

    var bad: std.ArrayList(u8) = .empty;
    try frame(a, &bad, 0x80, "grpc-status:14\r\n");
    try std.testing.expectError(error.GrpcStatus, parseUnary(bad.items));

    try std.testing.expectError(error.Malformed, parseUnary(&.{ 0, 0, 0, 0, 9, 1 }));
    try std.testing.expectError(error.Malformed, parseUnary(&.{}));
    var comp: std.ArrayList(u8) = .empty;
    try frame(a, &comp, 1, msg.items);
    try std.testing.expectError(error.CompressedFrame, parseUnary(comp.items));
}

test "sigorder: the request budget allows a burst, then one per interval" {
    var p: Pace = .perSecond(20); // 50 ms, burst 20
    var n: u32 = 0;
    for (0..100) |_| n += @intFromBool(p.take(1_000_000_000));
    try std.testing.expectEqual(@as(u32, 20), n);
    // 50 ms later: one more.
    try std.testing.expect(p.take(1_050_000_000));
    try std.testing.expect(!p.take(1_050_000_000));
    // A second idle: a full burst again.
    n = 0;
    for (0..100) |_| n += @intFromBool(p.take(3_000_000_000));
    try std.testing.expectEqual(@as(u32, 20), n);
    var off: Pace = .perSecond(0);
    for (0..1000) |_| try std.testing.expect(off.take(5));
}

test "sigorder: a NOT_FOUND head and a silent node both leave the contents order, bounded" {
    {
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ngrpc-status: 5\r\ngrpc-message: not found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        defer srv.stop();
        var ub: [64]u8 = undefined;
        var o = Overlay.init(std.testing.allocator, std.testing.io, srv.url(&ub), 20);
        defer o.deinit();
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        try std.testing.expect(o.get(arena.allocator(), 9) == null);
        try std.testing.expectEqual(@as(u64, 1), o.stats.not_found.load(.monotonic));
    }
    {
        var srv: netguard.TestServer = undefined;
        try srv.start(std.testing.io, null);
        defer srv.stop();
        var ub: [64]u8 = undefined;
        var o = Overlay.init(std.testing.allocator, std.testing.io, srv.url(&ub), 20);
        defer o.deinit();
        o.timeout_ms = 300;
        var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
        defer arena.deinit();
        const t0 = netguard.wallMs();
        try std.testing.expect(o.get(arena.allocator(), 9) == null);
        try std.testing.expect(netguard.wallMs() - t0 < 3000);
        try std.testing.expectEqual(@as(u64, 1), o.stats.timeouts.load(.monotonic));
    }
}

test "sigorder: a served answer comes back as the checkpoint proto" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cp = [_]u8{ 0x08, 0x09 };
    var msg: std.ArrayList(u8) = .empty;
    try putLen(a, &msg, 1, &cp);
    var body: std.ArrayList(u8) = .empty;
    try frame(a, &body, 0, msg.items);
    try frame(a, &body, 0x80, "grpc-status:0\r\n");
    const reply = try std.fmt.allocPrint(a, "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n{s}", .{ body.items.len, body.items });
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, reply);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var o = Overlay.init(std.testing.allocator, std.testing.io, srv.url(&ub), 20);
    defer o.deinit();
    const got = o.get(a, 9) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, &cp, got);
    try std.testing.expectEqual(@as(u64, 1), o.stats.served.load(.monotonic));
}

test "sigorder: the overlay node prefers a loopback stream URL" {
    try std.testing.expect(isLoopback("http://127.0.0.1:9000"));
    try std.testing.expect(isLoopback("http://localhost:9000/"));
    try std.testing.expect(isLoopback("http://[::1]:9000"));
    try std.testing.expect(!isLoopback("https://fullnode.mainnet.sui.io"));
    try std.testing.expect(!isLoopback("https://127example.com"));
    try std.testing.expectEqualStrings("http://127.0.0.1:9000", pickBase("https://fullnode.mainnet.sui.io,http://127.0.0.1:9000/").?);
    try std.testing.expectEqualStrings("https://fullnode.mainnet.sui.io", pickBase(" https://fullnode.mainnet.sui.io/ ,https://other.example").?);
    try std.testing.expect(pickBase(" , ") == null);
}
