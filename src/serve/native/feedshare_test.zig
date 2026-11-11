//! The feed queue's shares over real connections (listener.zig `feedClient`, jobs.zig, fairq.zig;
//! docs/EDGE.md section 4): who counts as one client, what a refused client reads, and what a
//! closed connection gives back. The order of service is tested in jobs.zig and fairq.zig, where
//! a test decides when a job ends; here the pool has no workers, so the queue only fills.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const listener = @import("listener.zig");
const cert_mod = @import("cert.zig");
const certs_test = @import("certs_test.zig");
const Rig = certs_test.Rig;
const Client = certs_test.Client;

const id_seed: [32]u8 = @splat(9);

/// API keys "g" and "t".
fn check(_: *anyopaque, token: []const u8) ?dispatch.Principal {
    if (std.mem.eql(u8, token, "g")) return .{ .id = 1, .tier = 0 };
    if (std.mem.eql(u8, token, "t")) return .{ .id = 2, .tier = 0 };
    return null;
}

/// A raw zui/1 connection that has said hello, with `token` when given.
fn connect(gpa: std.mem.Allocator, io: Io, l: *listener.Listener, salt: u8, token: ?[]const u8) !Client {
    var seed: [64]u8 = @splat(salt);
    seed[1] = 0x17;
    var cl = try Client.open(gpa, io, l.address(), .{
        .server_name = "zui",
        .identity_seed = @splat(4),
        .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
        .seed = seed,
        .now_unix = 1_800_000_000,
        .alpn = &.{proto.alpn},
        .max_streams_uni = 16,
        .max_streams_bidi = 64,
        .keep_alive_ms = 0,
    });
    errdefer cl.close(gpa);
    if (!try cl.handshake()) return error.TestUnexpectedResult;
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);
    const w: proto.W = .{ .gpa = gpa, .out = &b };
    try w.str("feedshare-test");
    try w.int(u16, 0);
    if (token) |t| {
        try w.u8_(1);
        try w.bytes(t);
    } else try w.u8_(0);
    const resp = try cl.request(gpa, .hello, b.items);
    defer gpa.free(resp);
    // hello's last byte: the connection is authenticated
    try testing.expect(resp.len > 0 and resp[0] == 0);
    try testing.expectEqual(@as(u8, @intFromBool(token != null)), resp[resp.len - 1]);
    return cl;
}

/// Sends `get_checkpoint_feed` for `seq` on a new stream and returns the stream.
fn ask(gpa: std.mem.Allocator, cl: *Client, seq: u64) !u64 {
    var rounds: usize = 0;
    const id = while (true) : (rounds += 1) {
        if (cl.c.openBidi()) |id| break id else |_| {}
        if (rounds > 2000) return error.TestUnexpectedResult;
        cl.pump();
    };
    var body: [12]u8 = @splat(0);
    std.mem.writeInt(u64, body[0..8], seq, .little);
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    try proto.encodeRequest(&req, gpa, .get_checkpoint_feed, 0, &body);
    try cl.c.streamWrite(id, req.items, true);
    return id;
}

/// The whole answer on `id` if it has come.
fn answered(cl: *Client, id: u64) ?[]const u8 {
    const st = cl.c.stream(id) orelse return null;
    return if (st.recv.complete()) st.recv.contiguous() else null;
}

/// Pumps every client until `done` says so; at most about 20 s.
fn until(clients: []const *Client, ctx: anytype, comptime done: fn (@TypeOf(ctx)) bool) !void {
    var rounds: usize = 0;
    while (!done(ctx)) : (rounds += 1) {
        if (rounds > 1000) return error.TestUnexpectedResult;
        for (clients) |c| c.pump();
    }
}

const Depth = struct {
    l: *listener.Listener,
    depth: u64,
    clients: u64,
    fn reached(d: Depth) bool {
        return d.l.feed_stats.depth.load(.monotonic) == d.depth and d.l.feed_stats.clients.load(.monotonic) == d.clients;
    }
};

const Answer = struct {
    cl: *Client,
    id: u64,
    fn here(a: Answer) bool {
        return answered(a.cl, a.id) != null;
    }
};

test "feed queue: an edge's connections are one client; the one over its share is refused, and a closed connection gives its places back" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    rig.disp.hooks.auth = .{ .ctx = &rig, .check = check };
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const cert = cert_mod.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui");
    // no feed workers: what is queued stays queued, so every count below is exact
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = &cert, .feed_workers = 0 }, &rig.disp);
    defer l.stop();
    const stats = &l.feed_stats;

    // one edge with two connections (the same key), a second edge, and a client with no key
    var a = try connect(gpa, io, l, 1, "g");
    defer a.close(gpa);
    var b = try connect(gpa, io, l, 2, "g");
    defer b.close(gpa);
    var t = try connect(gpa, io, l, 3, "t");
    defer t.close(gpa);
    var n = try connect(gpa, io, l, 4, null);
    defer n.close(gpa);
    const all = [_]*Client{ &a, &b, &t, &n };

    var refusal: std.ArrayList(u8) = .empty;
    defer refusal.deinit(gpa);
    try proto.errorResponse(&refusal, gpa, .rate_limited, "too many feed requests in flight", &.{ 0, 0, 0, 0 });

    // the first edge pipelines 64 requests over its two connections: all queued, as one client
    for (0..32) |i| _ = try ask(gpa, &a, i);
    try until(&all, Depth{ .l = l, .depth = 32, .clients = 1 }, Depth.reached);
    var on_b: [31]u64 = undefined;
    for (&on_b, 0..) |*id, i| id.* = try ask(gpa, &b, 100 + i);
    try until(&all, Depth{ .l = l, .depth = 63, .clients = 1 }, Depth.reached);
    const newest = try ask(gpa, &b, 200);
    try until(&all, Depth{ .l = l, .depth = 64, .clients = 1 }, Depth.reached);
    try testing.expectEqual(@as(u64, 64), stats.client_depth_max.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), stats.clients_waiting.load(.monotonic));

    // alone it is refused at 64, with the bytes it always got
    const over = try ask(gpa, &a, 300);
    try until(&all, Answer{ .cl = &a, .id = over }, Answer.here);
    try testing.expectEqualSlices(u8, refusal.items, answered(&a, over).?);
    try testing.expectEqual(@as(u64, 1), stats.refused_full.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), stats.refused_over_share.load(.monotonic));

    // the second edge asks for one checkpoint: it is queued, and the first edge's newest
    // request is refused in its place, with the same bytes
    const tip = try ask(gpa, &t, 400);
    try until(&all, Depth{ .l = l, .depth = 64, .clients = 2 }, Depth.reached);
    try until(&all, Answer{ .cl = &b, .id = newest }, Answer.here);
    try testing.expectEqualSlices(u8, refusal.items, answered(&b, newest).?);
    try testing.expectEqual(@as(u64, 1), stats.refused_over_share.load(.monotonic));
    try testing.expectEqual(@as(u64, 63), stats.client_depth_max.load(.monotonic));

    // a client without a key is known by its address: a third client, let in the same way
    const anon = try ask(gpa, &n, 500);
    try until(&all, Depth{ .l = l, .depth = 64, .clients = 3 }, Depth.reached);
    try testing.expectEqual(@as(u64, 2), stats.refused_over_share.load(.monotonic));
    try testing.expectEqual(@as(u64, 62), stats.client_depth_max.load(.monotonic));
    try testing.expectEqual(@as(u64, 3), stats.clients_waiting.load(.monotonic));
    // neither of the two was refused, and nothing else of the first edge's was
    for (0..20) |_| for (all) |c| c.pump();
    try testing.expect(answered(&t, tip) == null and answered(&n, anon) == null);
    var refused_on_b: usize = 0;
    for (on_b) |id| refused_on_b += @intFromBool(answered(&b, id) != null);
    try testing.expectEqual(@as(usize, 1), refused_on_b);
    try testing.expectEqual(@as(u64, 1), stats.refused_full.load(.monotonic));

    // the first edge's connection `a` closes: its 32 queued requests leave the queue
    a.c.closeApp(0);
    try until(&all, Depth{ .l = l, .depth = 32, .clients = 3 }, Depth.reached);
    try testing.expectEqual(@as(u64, 30), stats.client_depth_max.load(.monotonic));
    // and its other connection: the edge is gone from the queue
    b.c.closeApp(0);
    try until(&all, Depth{ .l = l, .depth = 2, .clients = 2 }, Depth.reached);
    try testing.expectEqual(@as(u64, 1), stats.client_depth_max.load(.monotonic));
    // (the listener stops with two requests still queued: the testing allocator sees them freed)
}

test "feed queue: requests of several clients go through the workers and are answered" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(gpa);
    defer rig.deinit();
    const io = rig.io();
    rig.disp.hooks.auth = .{ .ctx = &rig, .check = check };
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const cert = cert_mod.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui");
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = &cert }, &rig.disp);
    defer l.stop();
    var a = try connect(gpa, io, l, 1, "g");
    defer a.close(gpa);
    var t = try connect(gpa, io, l, 3, "t");
    defer t.close(gpa);
    var n = try connect(gpa, io, l, 4, null);
    defer n.close(gpa);
    const all = [_]*Client{ &a, &t, &n };
    // this node has no feed (`--edge-feed` off): every request is answered UNIMPLEMENTED by a
    // feed worker, none is refused
    var ids: [3][8]u64 = undefined;
    for (0..8) |i| for (all, 0..) |c, k| {
        ids[k][i] = try ask(gpa, c, i);
    };
    for (all, 0..) |c, k| for (ids[k]) |id| {
        try until(&all, Answer{ .cl = c, .id = id }, Answer.here);
        try testing.expectEqual(@as(u8, @intFromEnum(proto.Code.unimplemented)), answered(c, id).?[0]);
    };
    try until(&all, Depth{ .l = l, .depth = 0, .clients = 0 }, Depth.reached);
    try testing.expectEqual(@as(u64, 0), l.feed_stats.refused_full.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), l.feed_stats.refused_over_share.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), l.feed_stats.client_depth_max.load(.monotonic));
}

test "feed queue: a client is the API key, else the address without the port (IPv6: the /64)" {
    const fc = listener.Listener.feedClient;
    const v4a: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 40001 } };
    const v4b: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 7 }, .port = 40002 } };
    const v4c: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 8 }, .port = 40001 } };
    // an edge's connections differ in the port only
    try testing.expectEqual(fc(null, &v4a), fc(null, &v4b));
    try testing.expect(fc(null, &v4a) != fc(null, &v4c));
    // the same IPv4 client on a dual-stack socket
    var mapped: Io.net.IpAddress = .{ .ip6 = .{ .port = 5, .bytes = @splat(0) } };
    mapped.ip6.bytes[10] = 0xff;
    mapped.ip6.bytes[11] = 0xff;
    mapped.ip6.bytes[12..16].* = .{ 203, 0, 113, 7 };
    try testing.expectEqual(fc(null, &v4a), fc(null, &mapped));
    // IPv6: one /64 is one client
    var v6a: Io.net.IpAddress = .{ .ip6 = .{ .port = 1, .bytes = @splat(0) } };
    v6a.ip6.bytes[0..8].* = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2 };
    v6a.ip6.bytes[15] = 1;
    var v6b = v6a;
    v6b.ip6.bytes[15] = 2;
    v6b.ip6.port = 9;
    var v6c = v6a;
    v6c.ip6.bytes[7] = 3;
    try testing.expectEqual(fc(null, &v6a), fc(null, &v6b));
    try testing.expect(fc(null, &v6a) != fc(null, &v6c));
    try testing.expect(fc(null, &v6a) != fc(null, &v4a));
    // a key is the client wherever it connects from, and never the same as an address
    const k1: dispatch.Principal = .{ .id = 1, .tier = 0 };
    const k2: dispatch.Principal = .{ .id = 2, .tier = 3 };
    try testing.expectEqual(fc(k1, &v4a), fc(k1, &v6c));
    try testing.expect(fc(k1, &v4a) != fc(k2, &v4a));
    try testing.expect(fc(k1, &v4a) != fc(null, &v4a));
    const low: Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 1 }, .port = 1 } };
    try testing.expect(fc(k1, &low) != fc(null, &low));
}
