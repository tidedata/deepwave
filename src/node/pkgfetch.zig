//! Execute mode's last resort for a package the node has not seen (`--packages-from URL`): one
//! unary `sui.rpc.v2.LedgerService/GetObject` (read_mask `bcs`) over gRPC-web on HTTP/1.1 to a
//! full node, paced to at most 20 requests a second. A node that starts at the tip without a
//! snapshot (testnet, the activation gate) holds no package published before its first checkpoint.
//!
//! Untrusted like every source: the answer must be a package object with the requested id, and a
//! wrong package can only make the transaction's effects differ from the certified ones (a counted
//! mismatch, never stored). Fetched packages are written to `--packages DIR` as `<id hex>.obj`
//! when that is set, so later runs read them locally.
//!
//! Every request is bounded by `timeout_ms` (netguard.timed: std.http has no read timeout). The
//! caller is execute mode's ordered step, which every later checkpoint waits on, so a full node
//! that accepts the connection and never answers must not hold it.
const std = @import("std");
const Io = std.Io;
const netguard = @import("netguard.zig");

pub const Fetcher = struct {
    gpa: std.mem.Allocator,
    io: Io,
    /// Full node base URL without a trailing slash (gRPC-web), e.g. https://fullnode.testnet.sui.io.
    base: []const u8,
    client: std.http.Client,
    /// Earliest wall clock (ms) for the next request: 50 ms spacing (20 req/s).
    next_ms: u64 = 0,
    gets: u64 = 0,
    hits: u64 = 0,
    /// Requests the node did not answer: not reachable, an HTTP error, or cut at `timeout_ms`
    /// (those also count in `timeouts`). An answer without the object is not one.
    errors: u64 = 0,
    timeouts: u64 = 0,
    /// One request (connect, TLS, request, whole body) must finish within this, or it is cut.
    timeout_ms: u64 = 5_000,

    pub const spacing_ms: u64 = 50;

    pub fn init(gpa: std.mem.Allocator, io: Io, base: []const u8) Fetcher {
        return .{ .gpa = gpa, .io = io, .base = std.mem.trimEnd(u8, base, "/"), .client = .{ .allocator = gpa, .io = io } };
    }

    pub fn deinit(f: *Fetcher) void {
        f.client.deinit();
    }

    /// The object's BCS (sui `Object`), in `arena`, or null (not found, not reachable, malformed).
    pub fn get(f: *Fetcher, arena: std.mem.Allocator, id: *const [32]u8) ?[]const u8 {
        const now = wallMs();
        if (now < f.next_ms) f.io.sleep(.fromMilliseconds(@intCast(f.next_ms - now)), .awake) catch {};
        f.next_ms = wallMs() + spacing_ms;
        f.gets += 1;
        const body = requestBody(arena, id) catch return null;
        var ab: netguard.Abort = .{};
        const resp = netguard.timed(f.io, f.timeout_ms, null, &ab, post, .{ f, arena, body, &ab }) catch |e| {
            f.errors += 1;
            if (e == error.Timeout) f.timeouts += 1;
            return null;
        };
        const got = objectBcs(resp) orelse return null;
        f.hits += 1;
        return got;
    }

    fn post(f: *Fetcher, arena: std.mem.Allocator, body: []u8, abort: *netguard.Abort) ![]const u8 {
        var ub: [256]u8 = undefined;
        const url = try std.fmt.bufPrint(&ub, "{s}/sui.rpc.v2.LedgerService/GetObject", .{f.base});
        var req = try f.client.request(.POST, try std.Uri.parse(url), .{
            .redirect_behavior = .unhandled,
            .headers = .{ .content_type = .{ .override = "application/grpc-web+proto" }, .accept_encoding = .omit, .user_agent = .{ .override = "deepwave" } },
            .extra_headers = &.{
                .{ .name = "x-grpc-web", .value = "1" },
                .{ .name = "accept", .value = "application/grpc-web+proto" },
            },
        });
        defer req.deinit();
        // A request that failed or was cut is not reused (std returns one that failed before the
        // response head to the pool as healthy). Runs before `req.deinit`.
        errdefer if (req.connection) |conn| {
            conn.closing = true;
        };
        // The wait's expiry shuts this socket down, so a read blocked on a silent peer returns.
        try abort.arm(netguard.socketOf(req.connection.?));
        defer abort.disarm();
        try req.sendBodyComplete(body);
        var res = try req.receiveHead(&.{});
        if (res.head.status != .ok) return error.HttpStatus;
        var aw: std.Io.Writer.Allocating = .init(arena);
        const reader = res.reader(&.{});
        _ = reader.streamRemaining(&aw.writer) catch |err| switch (err) {
            error.ReadFailed => return res.bodyErr() orelse error.ReadFailed,
            else => |e| return e,
        };
        return aw.written();
    }
};

fn wallMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

/// gRPC-web frame of `GetObjectRequest{ object_id: "0x<hex>" (1), read_mask: { paths: ["bcs"] } (3) }`.
pub fn requestBody(a: std.mem.Allocator, id: *const [32]u8) ![]u8 {
    var hex: [66]u8 = undefined;
    _ = try std.fmt.bufPrint(&hex, "0x{x}", .{id});
    const mask = [_]u8{ 0x0a, 3, 'b', 'c', 's' };
    const msg_len = 2 + hex.len + 2 + mask.len;
    const out = try a.alloc(u8, 5 + msg_len);
    out[0] = 0;
    std.mem.writeInt(u32, out[1..5], @intCast(msg_len), .big);
    var i: usize = 5;
    out[i] = 0x0a;
    out[i + 1] = hex.len;
    @memcpy(out[i + 2 ..][0..hex.len], &hex);
    i += 2 + hex.len;
    out[i] = 0x1a;
    out[i + 1] = mask.len;
    @memcpy(out[i + 2 ..][0..mask.len], &mask);
    return out;
}

/// `GetObjectResponse.object (1).bcs (1).value (2)` from a gRPC-web body (first data frame).
pub fn objectBcs(body: []const u8) ?[]const u8 {
    if (body.len < 5 or body[0] != 0) return null;
    const n = std.mem.readInt(u32, body[1..5], .big);
    if (body.len < 5 + n) return null;
    const obj = field(body[5..][0..n], 1) orelse return null;
    const bcs = field(obj, 1) orelse return null;
    return field(bcs, 2);
}

/// The first length-delimited `num` of a proto message.
fn field(b: []const u8, num: u64) ?[]const u8 {
    var i: usize = 0;
    while (i < b.len) {
        const key = varint(b, &i) orelse return null;
        switch (key & 7) {
            0 => _ = varint(b, &i) orelse return null,
            1 => i += 8,
            5 => i += 4,
            2 => {
                const n = varint(b, &i) orelse return null;
                if (n > b.len - i) return null;
                if (key >> 3 == num) return b[i..][0..n];
                i += n;
            },
            else => return null,
        }
    }
    return null;
}

fn varint(b: []const u8, i: *usize) ?u64 {
    var r: u64 = 0;
    var shift: u6 = 0;
    while (i.* < b.len) {
        const x = b[i.*];
        i.* += 1;
        r |= @as(u64, x & 0x7f) << shift;
        if (x < 0x80) return r;
        if (shift >= 63) return null;
        shift += 7;
    }
    return null;
}

test "pkgfetch: request frame and response parse" {
    const a = std.testing.allocator;
    var id: [32]u8 = @splat(0);
    id[31] = 2;
    const body = try requestBody(a, &id);
    defer a.free(body);
    try std.testing.expectEqual(@as(usize, 5 + 2 + 66 + 2 + 5), body.len);
    try std.testing.expectEqualStrings("0x0000000000000000000000000000000000000000000000000000000000000002", body[7..][0..66]);
    // object { bcs { name: "Object" value: 01 02 03 } }
    const bcs_msg = [_]u8{ 0x0a, 6, 'O', 'b', 'j', 'e', 'c', 't', 0x12, 3, 1, 2, 3 };
    const obj = [_]u8{ 0x0a, bcs_msg.len } ++ bcs_msg;
    const resp = [_]u8{ 0x0a, obj.len } ++ obj;
    const frame = [_]u8{ 0, 0, 0, 0, resp.len } ++ resp ++ [_]u8{ 0x80, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, objectBcs(&frame).?);
    try std.testing.expect(objectBcs(&[_]u8{ 0x80, 0, 0, 0, 0 }) == null);
}

test "pkgfetch: a full node that never answers is cut at the timeout" {
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, null);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var f = Fetcher.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer f.deinit();
    f.timeout_ms = 300;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const id: [32]u8 = @splat(7);
    const t0 = netguard.wallMs();
    try std.testing.expect(f.get(arena.allocator(), &id) == null);
    try std.testing.expect(netguard.wallMs() - t0 < 3000);
    try std.testing.expectEqual(@as(u64, 1), f.errors);
    try std.testing.expectEqual(@as(u64, 1), f.timeouts);
    // The next request is on a fresh connection and is cut as well (the first is not reused).
    try std.testing.expect(f.get(arena.allocator(), &id) == null);
    try std.testing.expectEqual(@as(u64, 2), f.timeouts);
    try std.testing.expectEqual(@as(u32, 2), srv.accepts.load(.acquire));
}

test "pkgfetch: an answer comes back through the bounded request" {
    // object { bcs { value: 01 02 03 } } in one gRPC-web data frame.
    const reply = "HTTP/1.1 200 OK\r\ncontent-type: application/grpc-web+proto\r\ncontent-length: 14\r\nconnection: close\r\n\r\n" ++
        [_]u8{ 0, 0, 0, 0, 9, 0x0a, 7, 0x0a, 5, 0x12, 3, 1, 2, 3 };
    var srv: netguard.TestServer = undefined;
    try srv.start(std.testing.io, reply);
    defer srv.stop();
    var ub: [64]u8 = undefined;
    var f = Fetcher.init(std.testing.allocator, std.testing.io, srv.url(&ub));
    defer f.deinit();
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const id: [32]u8 = @splat(7);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, f.get(arena.allocator(), &id).?);
    try std.testing.expectEqual(@as(u64, 0), f.errors);
    try std.testing.expectEqual(@as(u64, 1), f.hits);
}
