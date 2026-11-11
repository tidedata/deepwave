//! hello through the dispatcher and over a connection (hello.zig, NATIVE-PROTOCOL.md 3.3, 4.1, 8):
//! clients that send what they always sent get the bytes they always got, and a client that
//! states requirements the node cannot meet gets a distinct error.
const std = @import("std");
const Io = std.Io;
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const listener = @import("listener.zig");
const hello = @import("hello.zig");
const certs_test = @import("certs_test.zig");
const Rig = certs_test.Rig;

/// What a node from before minor 1 answered a hello on a test `Rig`'s store (chain id
/// 5a..5a, no checkpoints, no index, no simulator): captured from that code, not derived from
/// the new one. server "zui/0.1", minor 0, features 0x1f63, limits 128/16/131072/1000.
const old_hello_ok = "0000077a75692f302e310000" ++ rep("5a", 32) ++ rep("00", 24) ++
    "631f000000000000" ++ "80000000" ++ "10000000" ++ "00000200" ++ "e8030000" ++ rep("00", 8) ++ "00" ++ rep("00", 8) ++ "00";

fn rep(comptime s: []const u8, comptime n: usize) [s.len * n]u8 {
    var out: [s.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(out[i * s.len ..][0..s.len], s);
    return out;
}
/// And what it answered a hello with bytes after the token: BAD_REQUEST "Malformed".
const old_hello_malformed = "010001000000094d616c666f726d656400";

fn hex(comptime h: []const u8) [h.len / 2]u8 {
    var out: [h.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, h) catch unreachable;
    return out;
}

/// HelloReq: `client`, `minor`, no token, then `tail`.
fn helloBody(a: std.mem.Allocator, client: []const u8, minor: u16, tail: []const u8) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    const w: proto.W = .{ .gpa = a, .out = &b };
    try w.str(client);
    try w.int(u16, minor);
    try w.u8_(0);
    try w.fixed(tail);
    return b.items;
}

/// The optional fields of minor 1.
fn wantTail(a: std.mem.Allocator, chain: ?[32]u8, min_minor: u16, features: u64) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    const w: proto.W = .{ .gpa = a, .out = &b };
    if (chain) |c| {
        try w.u8_(1);
        try w.fixed(&c);
    } else try w.u8_(0);
    try w.int(u16, min_minor);
    try w.int(u64, features);
    return b.items;
}

const ErrorBody = struct { code: u32, message: []const u8, detail: []const u8 };

fn errorBody(resp: []const u8) !ErrorBody {
    const r0 = proto.parseResponse(resp) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 0), r0.flags);
    var r: proto.R = .{ .b = r0.body };
    const code = try r.int(u32);
    try std.testing.expectEqual(@as(u32, r0.status), code);
    const message = try r.str();
    const detail = try r.bytes();
    try r.done();
    return .{ .code = code, .message = message, .detail = detail };
}

test "hello: clients that send minor 0 and no new fields are answered byte for byte as before" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    // (a node sets its software version; old clients must not see it)
    rig.disp.software = "9.9.9-abcdef0";
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const want_ok = hex(old_hello_ok);
    const bodies = [_][]const u8{
        &.{ 0, 0, 0, 0 }, // client "", minor 0, no token
        "\x10zui-sdk-ts/0.1.0\x00\x00\x00", // the SDK as deployed
        "\x10zui-sdk-ts/0.1.0\x00\x00\x01\x03abc", // with a token (no key file: anonymous)
        "\x0czui-edge/0.1\x00\x00\x00", // src/edge's client
    };
    for (bodies) |b| {
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = b }, null, &out);
        try std.testing.expectEqualSlices(u8, &want_ok, out.items);
    }
    try std.testing.expectEqual(@as(u64, bodies.len), rig.disp.hello.by_minor[0].load(.monotonic));
    // what was malformed before still is: an empty body, and bytes after the token that are
    // not the whole of the new fields
    for ([_][]const u8{ "", "\x10zui-sdk-ts/0.1.0\x00\x00\x00\x00", "\x01x\x00\x00\x00\x01" ++ rep("\x5a", 20) }) |b| {
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = b }, null, &out);
        try std.testing.expectEqualSlices(u8, &hex(old_hello_malformed), out.items);
    }
    // src/edge's client still states the minor it always stated
    try std.testing.expectEqual(@as(u16, 0), proto.minor);
}

test "hello: minor 1 clients get the node's minor, version, chain and features; unmet requirements are distinct errors" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    rig.disp.software = "9.9.9-abcdef0";
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const chain: [32]u8 = @splat(0x5a);
    const served: u64 = 0x1f63;
    const Case = struct { minor: u16, tail: []const u8 };
    // answered OK: no requirements, and requirements this node meets
    const ok_cases = [_]Case{
        .{ .minor = 1, .tail = "" },
        .{ .minor = 1, .tail = try wantTail(a, chain, 1, 0x21) },
        .{ .minor = 1, .tail = try wantTail(a, null, 0, 0) },
        .{ .minor = 7, .tail = try wantTail(a, chain, 0, served) }, // a client from the future
        .{ .minor = 0, .tail = try wantTail(a, chain, 0, 1) }, // the fields count, whatever the minor says
    };
    for (ok_cases) |case| {
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "zui-sdk-ts/0.2.0", case.minor, case.tail) }, null, &out);
        const resp = proto.parseResponse(out.items).?;
        try std.testing.expectEqual(@as(u8, 0), resp.status);
        var r: proto.R = .{ .b = resp.body };
        const server = try r.str();
        const minor = try r.int(u16);
        // the lower of the two minors; the software version from minor 1 on
        try std.testing.expectEqual(@min(case.minor, proto.server_minor), minor);
        try std.testing.expectEqualStrings(if (case.minor >= 1) "zui/9.9.9-abcdef0" else "zui/0.1", server);
        try std.testing.expectEqualSlices(u8, &chain, try r.fixed(32));
        _ = try r.int(u64);
        _ = try r.int(u64);
        _ = try r.int(u64);
        try std.testing.expectEqual(served, try r.int(u64));
        // the rest is the layout of minor 0, unchanged
        try std.testing.expectEqualSlices(u8, hex(old_hello_ok)[12 + 32 + 24 + 8 ..], r.b[r.p..]);
    }
    try std.testing.expectEqual(@as(u16, 1), proto.server_minor);

    // refused: each with its own code, and what the node has instead in `detail`
    const other: [32]u8 = @splat(0x11);
    {
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "app", 1, try wantTail(a, other, 0, 0)) }, null, &out);
        const e = try errorBody(out.items);
        try std.testing.expectEqual(@as(u32, 15), e.code);
        try std.testing.expectEqual(@intFromEnum(proto.Code.wrong_chain), e.code);
        try std.testing.expectEqualSlices(u8, &chain, e.detail);
        try std.testing.expect(e.message.len > 0);
    }
    {
        // a minimum minor newer than the node's
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "app", 2, try wantTail(a, chain, 2, 0)) }, null, &out);
        const e = try errorBody(out.items);
        try std.testing.expectEqual(@as(u32, 16), e.code);
        try std.testing.expectEqual(@intFromEnum(proto.Code.minor_unsupported), e.code);
        try std.testing.expectEqual(proto.server_minor, std.mem.readInt(u16, e.detail[0..2], .little));
        try std.testing.expectEqual(@as(usize, 2), e.detail.len);
    }
    {
        // features this node lacks: dry_run (bit 3: no simulator here), the index (bit 2) and
        // a bit nobody serves yet; bit 0 it has
        const need: u64 = (1 << 3) | (1 << 2) | (1 << 40) | 1;
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "app", 1, try wantTail(a, chain, 1, need)) }, null, &out);
        const e = try errorBody(out.items);
        try std.testing.expectEqual(@as(u32, 17), e.code);
        try std.testing.expectEqual(@intFromEnum(proto.Code.feature_missing), e.code);
        try std.testing.expectEqual(@as(u64, (1 << 3) | (1 << 2) | (1 << 40)), std.mem.readInt(u64, e.detail[0..8], .little));
    }
    {
        // several things wrong: the chain is named first
        var out: std.ArrayList(u8) = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "app", 9, try wantTail(a, other, 9, 1 << 40)) }, null, &out);
        try std.testing.expectEqual(@as(u32, 15), (try errorBody(out.items)).code);
    }
    // counted: by minor (0, 1, 2, 3 or more), and the refusals by reason
    const hs = &rig.disp.hello;
    try std.testing.expectEqual(@as(u64, 1), hs.by_minor[0].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 5), hs.by_minor[1].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), hs.by_minor[2].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), hs.by_minor[3].load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), hs.wrong_chain.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), hs.minor_unsupported.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), hs.feature_missing.load(.monotonic));
    // a tail that is cut short is a bad request, not a guess
    {
        var out: std.ArrayList(u8) = .empty;
        const whole = try wantTail(a, chain, 1, 1);
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "app", 1, whole[0 .. whole.len - 1]) }, null, &out);
        try std.testing.expectEqual(@as(u32, 1), (try errorBody(out.items)).code);
        out = .empty;
        rig.disp.handle(a, .{ .method = .hello, .flags = 0, .body = try helloBody(a, "app", 1, try std.mem.concat(a, u8, &.{ whole, "x" })) }, null, &out);
        try std.testing.expectEqual(@as(u32, 1), (try errorBody(out.items)).code);
    }
}

test "hello over a connection: an old client's answer is unchanged, a wrong chain is refused on the wire, and the connection stays usable" {
    const gpa = std.testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const id_seed: [32]u8 = @splat(9);
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed }, &rig.disp);
    defer l.stop();
    var seed: [64]u8 = @splat(7);
    seed[0] = 1;
    var c = try certs_test.Client.open(gpa, io, l.address(), .{
        .server_name = "zui",
        .identity_seed = @splat(4),
        .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
        .seed = seed,
        .now_unix = 1_800_000_000,
        .alpn = &.{proto.alpn},
        .keep_alive_ms = 0,
    });
    defer c.close(gpa);
    try std.testing.expect(try c.handshake());
    {
        const resp = try c.request(gpa, .hello, "\x10zui-sdk-ts/0.1.0\x00\x00\x00");
        defer gpa.free(resp);
        try std.testing.expectEqualSlices(u8, &hex(old_hello_ok), resp);
    }
    {
        const resp = try c.request(gpa, .hello, try helloBody(a, "app", 1, try wantTail(a, @as([32]u8, @splat(0x11)), 0, 0)));
        defer gpa.free(resp);
        try std.testing.expectEqual(@as(u8, 15), resp[0]);
        const e = try errorBody(resp);
        try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x5a)), e.detail);
    }
    {
        // the refusal ends the request, not the connection: the client can ask again
        const resp = try c.request(gpa, .hello, try helloBody(a, "app", 1, try wantTail(a, @as([32]u8, @splat(0x5a)), 1, 1)));
        defer gpa.free(resp);
        try std.testing.expectEqual(@as(u8, 0), resp[0]);
    }
}
