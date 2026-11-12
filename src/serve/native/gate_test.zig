//! The zui/1 listener with an access-gate hook (gate.zig): a scripted hook stands in for the
//! gate, a raw QUIC client speaks zui/1 over loopback.
const std = @import("std");
const Io = std.Io;
const net = @import("net");
const udpio = net.udpio;
const conn_mod = net.conn;
const store = @import("store");
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const cert_mod = @import("cert.zig");
const gate = @import("gate.zig");
const listener = @import("listener.zig");
const testing = std.testing;

/// What the scripted gate knows: `good` is a valid key, `revoked` is refused at hello, `slow`
/// is "being looked up" for the first few asks, anything else is an unknown key.
const Script = struct {
    hellos: u32 = 0,
    admits: u32 = 0,
    waits: u32 = 0,
    settled_ok: u32 = 0,
    settled_failed: u32 = 0,
    last_key: [64]u8 = undefined,
    last_key_len: usize = 0,
    last_method: proto.Method = .hello,
    last_peer_loopback: bool = false,
    limit_next: bool = false,
    /// `slow` answers `.wait` this many times before it is known.
    slow_left: u32 = 3,
    saw_no_wait: bool = false,
    frames: u32 = 0,
    closed: u32 = 0,
    end_stream: bool = false,

    fn remember(s: *Script, key: []const u8) void {
        s.last_key_len = @min(key.len, s.last_key.len);
        @memcpy(s.last_key[0..s.last_key_len], key[0..s.last_key_len]);
    }
    fn hello(ctx: *anyopaque, key: []const u8, peer: Io.net.IpAddress, may_wait: bool) gate.Hello {
        const s: *Script = @ptrCast(@alignCast(ctx));
        s.hellos += 1;
        s.remember(key);
        s.last_peer_loopback = peer == .ip4 and peer.ip4.bytes[0] == 127;
        if (std.mem.eql(u8, key, "revoked")) return .{ .deny = .{ .code = .permission_denied, .message = "key revoked" } };
        if (std.mem.eql(u8, key, "unknown")) return .{ .deny = .{ .code = .unauthenticated, .message = "invalid API key" } };
        if (std.mem.eql(u8, key, "slow")) {
            if (!may_wait) {
                s.saw_no_wait = true;
                return .ok;
            }
            if (s.slow_left > 0) {
                s.slow_left -= 1;
                s.waits += 1;
                return .wait;
            }
        }
        return .ok;
    }
    fn admit(ctx: *anyopaque, key: []const u8, _: Io.net.IpAddress, method: proto.Method, _: []const u8, _: bool) gate.Verdict {
        const s: *Script = @ptrCast(@alignCast(ctx));
        s.admits += 1;
        s.remember(key);
        s.last_method = method;
        if (s.limit_next) {
            s.limit_next = false;
            return .{ .deny = .{ .code = .rate_limited, .message = "rate limit exceeded", .retry_after_ms = 40 } };
        }
        var t: gate.Ticket = .{};
        t.bytes[0] = 0x5a;
        return .{ .allow = t };
    }
    fn settle(ctx: *anyopaque, t: *const gate.Ticket, ok: bool) void {
        const s: *Script = @ptrCast(@alignCast(ctx));
        std.debug.assert(t.bytes[0] == 0x5a);
        if (ok) s.settled_ok += 1 else s.settled_failed += 1;
    }
    fn streamFrames(ctx: *anyopaque, _: *gate.Ticket, _: []const u8, n: u32) ?gate.Refusal {
        const s: *Script = @ptrCast(@alignCast(ctx));
        s.frames += n;
        if (s.end_stream) return .{ .code = .rate_limited, .message = "out of credits" };
        return null;
    }
    fn streamClose(ctx: *anyopaque, _: *gate.Ticket) void {
        const s: *Script = @ptrCast(@alignCast(ctx));
        s.closed += 1;
    }
    fn hook(s: *Script) gate.Hook {
        return .{ .ctx = s, .hello = hello, .admit = admit, .settle = settle, .stream_frames = streamFrames, .stream_close = streamClose };
    }
};

const Client = struct {
    io: Io,
    sock: Io.net.Socket,
    us: udpio.Sock,
    to: Io.net.IpAddress,
    c: *conn_mod.Connection,
    tx: udpio.TxBatch = .{},
    rx: udpio.RxBatch = .{},

    fn pump(t: *Client) void {
        var now: u64 = @intCast(Io.Clock.awake.now(t.io).toNanoseconds());
        while (t.c.pollTransmit(now, t.tx.slot())) |n| {
            t.tx.commit(n, &t.to);
            if (t.tx.full()) t.tx.flush(&t.us);
        }
        t.tx.flush(&t.us);
        t.us.setWait(5 * std.time.ns_per_ms);
        const n = t.rx.recv(&t.us, true);
        now = @intCast(Io.Clock.awake.now(t.io).toNanoseconds());
        for (0..n) |i| t.c.handleDatagram(now, t.rx.data(i));
        if (t.c.nextTimeout()) |d| if (now >= d) t.c.onTimeout(now);
    }

    /// One request, its whole response (copied into `out`).
    fn request(t: *Client, gpa: std.mem.Allocator, method: proto.Method, body: []const u8, out: *std.ArrayList(u8)) !proto.Response {
        var rounds: usize = 0;
        const id = while (true) : (rounds += 1) {
            if (t.c.openBidi()) |id| break id else |_| {}
            if (rounds > 2000) return error.TestUnexpectedResult;
            t.pump();
        };
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        try proto.encodeRequest(&req, gpa, method, 0, body);
        try t.c.streamWrite(id, req.items, true);
        rounds = 0;
        while (!(t.c.stream(id).?.recv.complete())) : (rounds += 1) {
            if (rounds > 2000) return error.TestUnexpectedResult;
            t.pump();
        }
        out.clearRetainingCapacity();
        try out.appendSlice(gpa, t.c.stream(id).?.recv.contiguous());
        t.c.streamFree(id);
        return proto.parseResponse(out.items) orelse error.TestUnexpectedResult;
    }
};

fn helloBody(out: *std.ArrayList(u8), gpa: std.mem.Allocator, token: ?[]const u8) !void {
    out.clearRetainingCapacity();
    const w: proto.W = .{ .gpa = gpa, .out = out };
    try w.str("gate-test/1");
    try w.int(u16, 0);
    try w.optBytes(token);
}

fn errorOf(resp: proto.Response) !struct { code: u32, message: []const u8, detail: []const u8 } {
    var r: proto.R = .{ .b = resp.body };
    const code = try r.int(u32);
    const message = try r.str();
    return .{ .code = code, .message = message, .detail = try r.bytes() };
}

test "zui/1 with a gate: the hello token is the key; refused at hello, limited per request, counted when answered" {
    const gpa = testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var cfg: store.Config = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 11, .max_transactions = 1 << 10, .max_checkpoints = 16, .max_batch_bytes = 16 << 20, .max_batch_objects = 1 << 10, .max_segments = 16, .segment_reserve = 4 << 20, .seed = 5 };
    const sim = try store.SimIo.init(gpa, 11, .{}, 32 << 20);
    defer sim.deinit();
    const st = try store.Store.open(gpa, .{ .sim = sim }, &cfg);
    defer st.deinit();
    var svc: @import("serve").service.Service = .{ .gpa = gpa, .store = st, .chain_id = @splat(0) };
    defer svc.deinit();
    var disp: dispatch.Dispatcher = .{ .svc = &svc };
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const cert = cert_mod.generate(try P256.KeyPair.generateDeterministic(@splat(6)), @splat(1), 1_800_000_000, 14, "zui");
    const id_seed: [32]u8 = @splat(9);
    var script: Script = .{};
    const l = try listener.Listener.start(gpa, io, .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(0) }, .identity_seed = id_seed, .cert = &cert, .gate = script.hook() }, &disp);
    defer l.stop();

    var lo: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    const sock = try Io.net.IpAddress.bind(&lo, io, .{ .mode = .dgram });
    defer sock.close(io);
    const now0: u64 = @intCast(Io.Clock.awake.now(io).toNanoseconds());
    const c = try conn_mod.Connection.init(gpa, .{
        .server_name = "zui",
        .identity_seed = @splat(4),
        .expected_peer = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(id_seed)).public_key.toBytes(),
        .seed = @splat(2),
        .now_unix = 1_800_000_000,
        .alpn = &.{proto.alpn},
        .max_streams_uni = 16,
        .max_streams_bidi = 64,
        .keep_alive_ms = 0,
    }, now0);
    defer c.deinit();
    var cl: Client = .{ .io = io, .sock = sock, .us = .init(sock.handle), .to = l.address(), .c = c };
    var rounds: usize = 0;
    while (!c.isEstablished()) : (rounds += 1) {
        if (rounds > 1000 or c.isClosed()) return error.TestUnexpectedResult;
        cl.pump();
    }
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const key_obj: [33]u8 = @splat(0); // get_object: an id and "no version"

    // no hello yet: a request is put to the gate without a key, answered, and settled
    var resp = try cl.request(gpa, .get_object, &key_obj, &out);
    try testing.expectEqual(@as(u32, 1), script.admits);
    try testing.expectEqual(@as(usize, 0), script.last_key_len);
    try testing.expectEqual(proto.Method.get_object, script.last_method);
    try testing.expectEqual(@as(u32, 1), script.settled_ok + script.settled_failed);

    // a hello without a token does not ask the gate; hello is never charged
    try helloBody(&body, gpa, null);
    resp = try cl.request(gpa, .hello, body.items, &out);
    try testing.expectEqual(@as(u8, 0), resp.status);
    try testing.expectEqual(@as(u32, 0), script.hellos);
    try testing.expectEqual(@as(u32, 1), script.admits);

    // a revoked key: the hello itself is refused, with the gate's text
    try helloBody(&body, gpa, "revoked");
    resp = try cl.request(gpa, .hello, body.items, &out);
    try testing.expectEqual(@as(u8, @intFromEnum(proto.Code.permission_denied)), resp.status);
    const refused = try errorOf(resp);
    try testing.expectEqual(@as(u32, 8), refused.code);
    try testing.expectEqualStrings("key revoked", refused.message);
    try testing.expect(script.last_peer_loopback);
    // a key nobody knows: UNAUTHENTICATED (code 7), a distinct code of the protocol
    try helloBody(&body, gpa, "unknown");
    resp = try cl.request(gpa, .hello, body.items, &out);
    try testing.expectEqual(@as(u8, @intFromEnum(proto.Code.unauthenticated)), resp.status);
    const unknown = try errorOf(resp);
    try testing.expectEqual(@as(u32, 7), unknown.code);
    try testing.expectEqualStrings("invalid API key", unknown.message);
    // and the connection did not take that key
    resp = try cl.request(gpa, .get_object, &key_obj, &out);
    try testing.expectEqual(@as(usize, 0), script.last_key_len);

    // a good key: hello passes and every later request carries it
    try helloBody(&body, gpa, "good");
    resp = try cl.request(gpa, .hello, body.items, &out);
    try testing.expectEqual(@as(u8, 0), resp.status);
    resp = try cl.request(gpa, .get_object, &key_obj, &out);
    try testing.expectEqualStrings("good", script.last_key[0..script.last_key_len]);

    // over the limit: RATE_LIMITED with the retry time as its detail, and nothing to settle
    const settled = script.settled_ok + script.settled_failed;
    script.limit_next = true;
    resp = try cl.request(gpa, .get_object, &key_obj, &out);
    try testing.expectEqual(@as(u8, @intFromEnum(proto.Code.rate_limited)), resp.status);
    const limited = try errorOf(resp);
    try testing.expectEqualStrings("rate limit exceeded", limited.message);
    try testing.expectEqualSlices(u8, &.{ 40, 0, 0, 0 }, limited.detail);
    try testing.expectEqual(settled, script.settled_ok + script.settled_failed);

    // a request that fails in the service is settled as failed (it costs nothing)
    const failed0 = script.settled_failed;
    resp = try cl.request(gpa, .get_object, "short", &out);
    try testing.expect(resp.status != 0);
    try testing.expectEqual(failed0 + 1, script.settled_failed);

    // a key that is being looked up: the hello waits (the I/O thread does not), then passes
    try helloBody(&body, gpa, "slow");
    resp = try cl.request(gpa, .hello, body.items, &out);
    try testing.expectEqual(@as(u8, 0), resp.status);
    try testing.expectEqual(@as(u32, 3), script.waits);
    resp = try cl.request(gpa, .get_object, &key_obj, &out);
    try testing.expectEqualStrings("slow", script.last_key[0..script.last_key_len]);
    // a lookup that never ends: after `wait_ms` the listener stops waiting
    script.slow_left = 1_000_000;
    try helloBody(&body, gpa, "slow");
    const t0 = Io.Clock.awake.now(io).toNanoseconds();
    resp = try cl.request(gpa, .hello, body.items, &out);
    const took_ms = @divTrunc(Io.Clock.awake.now(io).toNanoseconds() - t0, std.time.ns_per_ms);
    try testing.expectEqual(@as(u8, 0), resp.status);
    try testing.expect(script.saw_no_wait);
    try testing.expect(took_ms >= 100 and took_ms < 2000);
}

test "zui/1 without a gate: the hook is null and a hello token is not put to anyone" {
    const o: listener.Options = .{ .listen = .{ .ip4 = Io.net.Ip4Address.loopback(1) }, .identity_seed = @splat(0), .cert = undefined };
    try testing.expect(o.gate == null);
}
