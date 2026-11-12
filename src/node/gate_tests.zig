//! `--gate` end to end on loopback: the node's real HTTP client against the mock gate service
//! (edge.gate.mock.Server), and the gate in front of a sui.rpc.v2-shaped handler on the real
//! h2 / gRPC-web runtime. Nothing here leaves the machine.
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const testing = std.testing;
const edge = @import("edge");
const serve = @import("serve");
const native = @import("native");
const gate = @import("gate.zig");
const netguard = @import("netguard.zig");
const g = edge.gate;
const h2 = serve.h2;

const token = "test-token-0123456789abcdef-xyz";

/// Stands in for the service: echoes, fails, or streams three messages.
const Inner = struct {
    calls: Atomic(u32) = .init(0),

    fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const s: *Inner = @ptrCast(@alignCast(ctx));
        _ = s.calls.fetchAdd(1, .monotonic);
        if (std.mem.endsWith(u8, req.path, "/SubscribeCheckpoints")) {
            if (!h2.attach(req.stream_id, .{ .ctx = s, .run = run, .wake = wake })) return .unimplemented;
            return .deferred;
        }
        if (std.mem.endsWith(u8, req.path, "/GetEpoch")) {
            rs.setMessage("no such epoch");
            return .not_found;
        }
        rs.message(req.body) catch return .internal;
        return .ok;
    }
    fn run(_: *anyopaque, link: *h2.Link) void {
        var i: u8 = 0;
        while (i < 3) : (i += 1) link.send(&.{ 'm', '0' + i }) catch return;
        link.finish(.ok, "");
    }
    fn wake(_: *anyopaque) void {}
    fn known(_: *anyopaque, _: []const u8) bool {
        return true;
    }
    fn handler(s: *Inner) h2.Handler {
        return .{ .ctx = s, .call = call, .known = known };
    }
};

/// A server thread that serves connections with `handler` as the node would.
const Front = struct {
    server: Io.net.Server,
    port: u16,
    handler: h2.Handler,
    stopping: Atomic(bool) = .init(false),
    thread: std.Thread = undefined,
    conns: [8]?std.Thread = @splat(null),
    n: usize = 0,

    fn start(f: *Front, handler: h2.Handler) !void {
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        f.* = .{ .server = try addr.listen(testing.io, .{ .reuse_address = true }), .port = 0, .handler = handler };
        f.port = f.server.socket.address.getPort();
        f.thread = try std.Thread.spawn(.{}, loop, .{f});
    }
    fn loop(f: *Front) void {
        while (f.n < f.conns.len) {
            const st = f.server.accept(testing.io) catch return;
            if (f.stopping.load(.acquire)) {
                st.close(testing.io);
                return;
            }
            f.conns[f.n] = std.Thread.spawn(.{}, one, .{ f, st }) catch null;
            f.n += 1;
        }
    }
    fn one(f: *Front, st: Io.net.Stream) void {
        h2.server.serveStreamOpts(testing.allocator, testing.io, st, .{ .inline_unary = true }, f.handler);
    }
    fn stop(f: *Front) void {
        f.stopping.store(true, .release);
        var addr = Io.net.IpAddress.parseIp4("127.0.0.1", f.port) catch unreachable;
        if (addr.connect(testing.io, .{ .mode = .stream })) |c| c.close(testing.io) else |_| {}
        f.thread.join();
        for (f.conns) |t| if (t) |th| th.join();
        f.server.deinit(testing.io);
    }
};

const Client = struct {
    stream: Io.net.Stream,

    fn connect(port: u16) !Client {
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", port);
        return .{ .stream = try addr.connect(testing.io, .{ .mode = .stream }) };
    }
    fn close(c: *Client) void {
        c.stream.shutdown(testing.io, .both) catch {};
        c.stream.close(testing.io);
    }
    /// One gRPC-web call (binary). The whole HTTP response is left in `out`.
    fn call(c: *Client, path: []const u8, key: ?[]const u8, out: *std.ArrayList(u8)) !void {
        const gpa = testing.allocator;
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        try req.print(gpa, "POST {s} HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\n", .{path});
        if (key) |k| try req.print(gpa, "x-api-key: {s}\r\n", .{k});
        try req.appendSlice(gpa, "content-length: 6\r\n\r\n\x00\x00\x00\x00\x01x");
        var wbuf: [256]u8 = undefined;
        var w = c.stream.writer(testing.io, &wbuf);
        try w.interface.writeAll(req.items);
        try w.interface.flush();
        out.clearRetainingCapacity();
        var rbuf: [4096]u8 = undefined;
        while (!done(out.items)) {
            var iov = [_][]u8{&rbuf};
            const n = try c.stream.read(testing.io, &iov);
            if (n == 0) break;
            try out.appendSlice(gpa, rbuf[0..n]);
        }
    }
    fn done(b: []const u8) bool {
        return std.mem.endsWith(u8, b, "\r\n0\r\n\r\n") or (std.mem.indexOf(u8, b, "content-length: 0\r\n") != null and std.mem.endsWith(u8, b, "\r\n\r\n"));
    }
};

fn has(b: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, b, needle) != null;
}

fn waitFor(comptime what: []const u8, ctx: anytype, comptime pred: fn (@TypeOf(ctx)) bool, timeout_ms: u32) !void {
    var waited: u32 = 0;
    while (waited < timeout_ms) : (waited += 5) {
        if (pred(ctx)) return;
        testing.io.sleep(.fromMilliseconds(5), .awake) catch {};
    }
    std.debug.print("timed out waiting for: {s}\n", .{what});
    return error.TestTimedOut;
}

const Rig = struct {
    tmp: testing.TmpDir,
    mock: *g.mock.MockGate,
    srv: *g.mock.Server,
    dir_buf: [std.fs.max_path_bytes]u8 = undefined,
    tok_buf: [std.fs.max_path_bytes]u8 = undefined,
    url_buf: [128]u8 = undefined,
    settings: gate.Settings = undefined,

    fn init(r: *Rig, token_text: []const u8) !void {
        const gpa = testing.allocator;
        const io = testing.io;
        r.tmp = testing.tmpDir(.{});
        r.mock = try gpa.create(g.mock.MockGate);
        r.mock.* = .{ .gpa = gpa, .token = token, .io = io, .free_json = "{\"rps_per_ip\":5,\"burst\":10,\"max_streams\":1,\"ttl_s\":300}" };
        r.srv = try gpa.create(g.mock.Server);
        try r.srv.start(io, r.mock);
        try r.tmp.dir.writeFile(io, .{ .sub_path = "gate.token", .data = token_text });
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const base = pb[0..try r.tmp.dir.realPath(io, &pb)];
        r.settings = .{
            // the base carries a path of its own, as a real gate's does
            .url = r.srv.url(&r.url_buf, "/v1/gate/"),
            .token_file = try std.fmt.bufPrint(&r.tok_buf, "{s}/gate.token", .{base}),
            .edge_id = "e1",
            .dir = try std.fmt.bufPrint(&r.dir_buf, "{s}/gate-state", .{base}),
        };
    }
    fn deinit(r: *Rig) void {
        const gpa = testing.allocator;
        r.srv.stop();
        r.mock.deinit();
        gpa.destroy(r.srv);
        gpa.destroy(r.mock);
        r.tmp.cleanup();
    }
};

test "gate over HTTP: keys, the free tier, refusals with their statuses, streams, usage, a restart" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(token ++ "\n");
    defer rig.deinit();
    try rig.mock.setKey("key-valid-0001", "{\"key_id\":\"kid_valid\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"max_streams\":1,\"ttl_s\":60,\"lease_units\":null,\"weights\":{\"default\":1,\"sui.rpc.v2.LedgerService/GetObject\":2}}");
    try rig.mock.setKey("key-revoked-0001", "{\"key_id\":\"kid_revoked\",\"status\":\"suspended\",\"ttl_s\":300,\"message\":\"This key was revoked.\"}");

    var inner: Inner = .{};
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    {
        const ng = try gate.NodeGate.start(gpa, testing.io, rig.settings, null);
        defer ng.deinit();
        ng.core.cfg.cut_ns = 0; // a usage window every second, so the test need not wait five
        const Ready = struct {
            fn free(n: *gate.NodeGate) bool {
                return n.core.free_known.load(.monotonic);
            }
        };
        try waitFor("the free tier from the mock gate", ng, Ready.free, 5000);
        var front: Front = undefined;
        try front.start(ng.handler(inner.handler()));
        defer front.stop();
        var c = try Client.connect(front.port);
        defer c.close();

        // a valid key: resolved over HTTP with the bearer token, then served
        for (0..5) |_| {
            try c.call("/sui.rpc.v2.LedgerService/GetObject", "key-valid-0001", &got);
            try testing.expect(has(got.items, "HTTP/1.1 200 OK") and has(got.items, "grpc-status:0"));
        }
        try testing.expectEqual(@as(u32, 5), inner.calls.load(.monotonic));
        try testing.expectEqual(@as(u32, 1), rig.mock.resolves);
        try testing.expectEqual(@as(u32, 0), rig.mock.unauthorized);
        try testing.expectEqualStrings("key-valid-0001", rig.mock.asked.items[0]);
        // a call that fails in the service: answered as the service says, counted, not charged
        try c.call("/sui.rpc.v2.LedgerService/GetEpoch", "key-valid-0001", &got);
        try testing.expect(has(got.items, "grpc-status: 5\r\n"));

        // a revoked key and an unknown key: PERMISSION_DENIED, the service never runs
        const before = inner.calls.load(.monotonic);
        try c.call("/sui.rpc.v2.LedgerService/GetObject", "key-revoked-0001", &got);
        try testing.expect(has(got.items, "grpc-status: 7\r\ngrpc-message: This%20key%20was%20revoked.\r\n"));
        try c.call("/sui.rpc.v2.LedgerService/GetObject", "key-unknown-0001", &got);
        // (a key nobody knows is UNAUTHENTICATED, a revoked one PERMISSION_DENIED)
        try testing.expect(has(got.items, "grpc-status: 16\r\ngrpc-message: invalid%20API%20key\r\n"));
        try testing.expect(!has(got.items, "retry-after-ms"));
        try testing.expectEqual(before, inner.calls.load(.monotonic));

        // health checks, reflection and service info pass whatever the key or the rate
        for (0..30) |_| {
            try c.call("/sui.rpc.v2.LedgerService/GetServiceInfo", "key-revoked-0001", &got);
            try testing.expect(has(got.items, "grpc-status:0"));
        }

        // no key: the free tier per address (5 a second, burst 10), then RESOURCE_EXHAUSTED
        // with a retry time
        var passed: u32 = 0;
        var limited: u32 = 0;
        for (0..14) |_| {
            try c.call("/sui.rpc.v2.LedgerService/GetTransaction", null, &got);
            if (has(got.items, "grpc-status:0")) {
                passed += 1;
            } else {
                limited += 1;
                try testing.expect(has(got.items, "grpc-status: 8\r\ngrpc-message: rate%20limit%20exceeded\r\nretry-after-ms: "));
            }
        }
        try testing.expect(passed >= 10 and passed <= 11);
        try testing.expectEqual(@as(u32, 14), passed + limited);

        // a server stream: its messages are counted, its slot is given back when it ends
        try c.call("/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", "key-valid-0001", &got);
        try testing.expect(has(got.items, "m0") and has(got.items, "m2") and has(got.items, "grpc-status:0"));
        const Slots = struct {
            fn free(n: *gate.NodeGate) bool {
                return n.streams.load(.monotonic) == 0;
            }
        };
        try waitFor("the stream's slot", ng, Slots.free, 2000);
        try c.call("/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", "key-valid-0001", &got);
        try testing.expect(has(got.items, "m2")); // max_streams is 1: the slot was free again

        // the usage reaches the gate: by key id and by prefix, never by key
        const Sent = struct {
            m: *g.mock.MockGate,
            fn all(x: @This()) bool {
                return x.m.row("kkid_valid", "sui.rpc.v2.SubscriptionService/SubscribeCheckpoints").stream_msgs == 6;
            }
        };
        try waitFor("the usage rows at the mock gate", Sent{ .m = rig.mock }, Sent.all, 8000);
        try testing.expectEqual(g.contract.Counters{ .local = 5, .units = 10 }, rig.mock.row("kkid_valid", "sui.rpc.v2.LedgerService/GetObject"));
        try testing.expectEqual(g.contract.Counters{ .local = 1, .units = 0 }, rig.mock.row("kkid_valid", "sui.rpc.v2.LedgerService/GetEpoch"));
        try testing.expectEqual(@as(u64, 2), rig.mock.row("kkid_valid", "sui.rpc.v2.SubscriptionService/SubscribeCheckpoints").local);
        // a call refused for its key is in no usage row: not under the key, not under the prefix
        try testing.expectEqual(g.contract.Counters{}, rig.mock.row("kkid_revoked", "sui.rpc.v2.LedgerService/GetObject"));
        const keyless = rig.mock.row("i127.0.0.0/24", "sui.rpc.v2.LedgerService/GetTransaction");
        try testing.expectEqual(@as(u64, passed), keyless.local);
        try testing.expectEqual(@as(u64, limited), keyless.limited);
        try testing.expectEqual(g.contract.Counters{}, rig.mock.row("i127.0.0.0/24", "sui.rpc.v2.LedgerService/GetObject"));
        try testing.expectEqual(@as(u64, 1), ng.core.m.denied[@intFromEnum(g.gate.Reason.invalid)].load(.monotonic));
        try testing.expectEqual(@as(u64, 1), ng.core.m.denied[@intFromEnum(g.gate.Reason.suspended)].load(.monotonic));
        for (rig.mock.batches.values()) |body| {
            try testing.expect(!has(body, "key-valid-0001") and !has(body, "key-revoked-0001") and !has(body, token));
        }
        try testing.expectEqual(@as(u32, 0), rig.mock.duplicates_differ);
        // metrics are part of the node's page
        var metrics: Io.Writer.Allocating = .init(gpa);
        defer metrics.deinit();
        try ng.renderMetrics(&metrics.writer);
        try testing.expect(has(metrics.writer.buffered(), "zui_gate_allowed{plan=\"developer\",method=\"sui.rpc.v2.LedgerService/GetObject\"} 5\n"));
        try testing.expect(has(metrics.writer.buffered(), "zui_gate_reachable 1\n"));

        // the gate goes away: calls go on, usage waits in the spool
        rig.mock.down = true;
        for (0..3) |_| {
            try c.call("/sui.rpc.v2.LedgerService/GetObject", "key-valid-0001", &got);
            try testing.expect(has(got.items, "grpc-status:0"));
        }
        const t0 = netguard.wallMs();
        ng.stop();
        try testing.expect(netguard.wallMs() - t0 < 5000);
    }
    // the spool on disk never holds a key or the credential
    {
        var d = try Io.Dir.cwd().openDir(testing.io, rig.settings.dir, .{});
        defer d.close(testing.io);
        const spool = try d.readFileAlloc(testing.io, g.spool.file_name, gpa, .unlimited);
        defer gpa.free(spool);
        try testing.expect(has(spool, "kid_valid"));
        try testing.expect(!has(spool, "key-valid-0001") and !has(spool, token));
    }
    // a restart sends what the outage held back
    rig.mock.down = false;
    {
        const ng = try gate.NodeGate.start(gpa, testing.io, rig.settings, null);
        defer ng.deinit();
        ng.core.cfg.cut_ns = 0;
        const Sent = struct {
            m: *g.mock.MockGate,
            fn all(x: @This()) bool {
                return x.m.row("kkid_valid", "sui.rpc.v2.LedgerService/GetObject").local == 8;
            }
        };
        try waitFor("the held-back usage after the restart", Sent{ .m = rig.mock }, Sent.all, 8000);
        try testing.expectEqual(@as(u64, 16), rig.mock.row("kkid_valid", "sui.rpc.v2.LedgerService/GetObject").units);
    }
}

test "gate over HTTP: a wrong credential is a configuration error and the node falls back to the free tier" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init("another-token-of-enough-length-000\n");
    defer rig.deinit();
    try rig.mock.setKey("key-valid-0001", "{\"key_id\":\"kid_valid\",\"status\":\"ok\",\"rps\":1000,\"burst\":1000,\"ttl_s\":60,\"lease_units\":null}");
    // the gate says so once, as an error: read here instead of failing the test run
    const Said = struct {
        errors: Atomic(u32) = .init(0),
        token_seen: Atomic(bool) = .init(false),
        fn write(ctx: *anyopaque, err: bool, line: []const u8) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            if (err) _ = s.errors.fetchAdd(1, .monotonic);
            if (has(line, "another-token")) s.token_seen.store(true, .release);
        }
    };
    var said: Said = .{};
    rig.settings.log = .{ .ctx = &said, .write = Said.write };
    const ng = try gate.NodeGate.start(gpa, testing.io, rig.settings, null);
    defer ng.deinit();
    const Refused = struct {
        fn seen(n: *gate.NodeGate) bool {
            return n.core.m.config_errors.load(.monotonic) >= 1;
        }
    };
    try waitFor("the gate's 401", ng, Refused.seen, 5000);
    try testing.expect(rig.mock.unauthorized >= 1);
    try testing.expect(!ng.core.reachable.load(.monotonic));
    try testing.expect(!ng.core.free_known.load(.monotonic));
    // a key cannot be checked: the built-in floor (2 a second, burst 4), not a free pass
    var inner: Inner = .{};
    const handler = ng.handler(inner.handler());
    var passed: u32 = 0;
    const Sink = struct {
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
        const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };
    var sink: u8 = 0;
    for (0..40) |_| {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        const req: h2.Request = .{ .path = "/sui.rpc.v2.LedgerService/GetObject", .authority = "", .body = "x", .stream_id = 1, .api_key = "key-valid-0001", .peer = "198.51.100.9:1" };
        const st = handler.call(handler.ctx, &req, &rs);
        if (st == .ok) passed += 1 else {
            try testing.expectEqual(h2.Status.resource_exhausted, st);
            try testing.expect(rs.retry_after_ms != null);
        }
    }
    try testing.expect(passed >= 4 and passed <= 6);
    try testing.expectEqual(@as(u32, 1), said.errors.load(.monotonic));
    try testing.expect(!said.token_seen.load(.acquire));
}

test "gate at a forwarder's seam: denied before routing, counted local or forwarded with the multiplier, failures free" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(token ++ "\n");
    defer rig.deinit();
    try rig.mock.setKey("key-valid-0001", "{\"key_id\":\"kid_valid\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"max_streams\":1,\"ttl_s\":60,\"lease_units\":null,\"forward_weight_mult\":3,\"weights\":{\"default\":1,\"sui.rpc.v2.LedgerService/GetObject\":2}}");
    const ng = try gate.NodeGate.start(gpa, testing.io, rig.settings, null);
    defer ng.deinit();
    ng.core.cfg.cut_ns = 0;
    const gh = ng.forwardHook();
    const mh = ng.meterHook();
    const Sink = struct {
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
        const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };
    var sink: u8 = 0;
    // one call through the seam, as edge/forward.zig makes it: begin, the policy's gate, the
    // meter with the routing outcome, end with the status the client got
    const Seam = struct {
        fn call(g1: edge.forward.GateHook, m1: edge.forward.MeterHook, rs: *h2.ResponseStream, path: []const u8, key: []const u8, outcome: edge.forward.Outcome, status: h2.Status) ?edge.route.Deny {
            const req: h2.Request = .{ .path = path, .authority = "", .body = "x", .stream_id = 1, .api_key = key, .peer = "198.51.100.9:4000" };
            var caller: edge.route.Caller = .{ .api_key = req.api_key, .peer = req.peer };
            var scope: edge.forward.GateScope = .{};
            g1.begin(g1.ctx, &req, rs, &caller, &scope);
            const deny = edge.route.gate(&caller, edge.route.methodOf(path));
            const st: h2.Status = if (deny) |d| @enumFromInt(d.code) else status;
            const m: edge.forward.Metered = .{ .method = edge.route.methodOf(path), .outcome = if (deny != null) .denied else outcome, .code = @intFromEnum(st), .caller = caller, .elapsed_ns = 0 };
            m1.f(m1.ctx, &m);
            g1.end(g1.ctx, &scope, st);
            return deny;
        }
    };
    const get = "/sui.rpc.v2.LedgerService/GetObject";
    for (0..4) |_| {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        // (the first call waits for the key's resolve inside begin)
        try testing.expect(Seam.call(gh, mh, &rs, get, "key-valid-0001", .local, .ok) == null);
    }
    for (0..3) |_| {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        try testing.expect(Seam.call(gh, mh, &rs, get, "key-valid-0001", .forwarded, .ok) == null);
    }
    {
        // forwarded and failed at the core: counted as forwarded, no units
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        try testing.expect(Seam.call(gh, mh, &rs, get, "key-valid-0001", .forwarded, .unavailable) == null);
    }
    {
        // an unknown key: UNAUTHENTICATED through the policy's deny
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        const d = Seam.call(gh, mh, &rs, get, "key-unknown-0001", .local, .ok).?;
        try testing.expectEqual(@as(u8, 16), d.code);
        try testing.expectEqualStrings("invalid API key", d.message);
        try testing.expect(rs.retry_after_ms == null);
    }
    // keyless past the floor's burst (the mock's free tier may not be in yet: 4 or 10 pass):
    // RESOURCE_EXHAUSTED with a retry time
    var limited: u32 = 0;
    for (0..14) |_| {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        if (Seam.call(gh, mh, &rs, get, "", .local, .ok)) |d| {
            limited += 1;
            try testing.expectEqual(@as(u8, 8), d.code);
            try testing.expect(rs.retry_after_ms != null);
        }
    }
    try testing.expect(limited >= 3);
    // health checks are not the gate's business
    {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        try testing.expect(Seam.call(gh, mh, &rs, "/grpc.health.v1.Health/Check", "key-unknown-0001", .local, .ok) == null);
    }
    const Sent = struct {
        m: *g.mock.MockGate,
        fn all(x: @This()) bool {
            const r = x.m.row("kkid_valid", "sui.rpc.v2.LedgerService/GetObject");
            return r.local == 4 and r.forwarded == 4;
        }
    };
    try waitFor("the usage rows at the mock gate", Sent{ .m = rig.mock }, Sent.all, 8000);
    // 4 local at weight 2, 3 forwarded at 2 x 3, 1 forwarded that failed at 0
    try testing.expectEqual(g.contract.Counters{ .local = 4, .forwarded = 4, .units = 4 * 2 + 3 * 6 }, rig.mock.row("kkid_valid", "sui.rpc.v2.LedgerService/GetObject"));
}

test "weights by full method path: simulate and execute are reported and charged under their gRPC paths, on every way in" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(token ++ "\n");
    defer rig.deinit();
    const sim = "sui.rpc.v2.TransactionExecutionService/SimulateTransaction";
    const exe = "sui.rpc.v2.TransactionExecutionService/ExecuteTransaction";
    // the weights of the service's contract text: 5 for simulate, 10 for execute, 1 for the rest
    try rig.mock.setKey("key-valid-0001", "{\"key_id\":\"kid_valid\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"max_streams\":1,\"ttl_s\":60,\"lease_units\":null,\"forward_weight_mult\":1," ++
        "\"weights\":{\"default\":1,\"" ++ sim ++ "\":5,\"" ++ exe ++ "\":10}}");
    const ng = try gate.NodeGate.start(gpa, testing.io, rig.settings, null);
    defer ng.deinit();
    ng.core.cfg.cut_ns = 0;
    var inner: Inner = .{};
    const handler = ng.handler(inner.handler());
    const Sink = struct {
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
        const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };
    var sink: u8 = 0;
    // 1. gRPC over h2: the handler as the h2 runtime calls it (the path with its leading slash)
    inline for (.{ "/" ++ sim, "/" ++ exe }) |path| {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        const req: h2.Request = .{ .path = path, .authority = "", .body = "x", .stream_id = 1, .api_key = "key-valid-0001", .peer = "198.51.100.9:1" };
        try testing.expectEqual(h2.Status.ok, handler.call(handler.ctx, &req, &rs));
    }
    // 2. gRPC-web over HTTP/1.1, through the real runtime
    {
        var front: Front = undefined;
        try front.start(handler);
        defer front.stop();
        var c = try Client.connect(front.port);
        defer c.close();
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(gpa);
        inline for (.{ "/" ++ sim, "/" ++ exe }) |path| {
            try c.call(path, "key-valid-0001", &got);
            try testing.expect(has(got.items, "grpc-status:0"));
        }
    }
    // 3. an edge that forwards: the forwarder's seam, the call sent on to the core
    {
        const gh = ng.forwardHook();
        const mh = ng.meterHook();
        inline for (.{ "/" ++ sim, "/" ++ exe }) |path| {
            var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
            defer rs.release();
            const req: h2.Request = .{ .path = path, .authority = "", .body = "x", .stream_id = 1, .api_key = "key-valid-0001", .peer = "198.51.100.9:1" };
            var caller: edge.route.Caller = .{ .api_key = req.api_key, .peer = req.peer };
            var scope: edge.forward.GateScope = .{};
            gh.begin(gh.ctx, &req, &rs, &caller, &scope);
            try testing.expect(edge.route.gate(&caller, edge.route.methodOf(path)) == null);
            const m: edge.forward.Metered = .{ .method = edge.route.methodOf(path), .outcome = .forwarded, .code = 0, .caller = caller, .elapsed_ns = 0 };
            mh.f(mh.ctx, &m);
            gh.end(gh.ctx, &scope, .ok);
        }
        // and a forwarded execute the core refused: counted, charged nothing
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        const req: h2.Request = .{ .path = "/" ++ exe, .authority = "", .body = "x", .stream_id = 1, .api_key = "key-valid-0001", .peer = "198.51.100.9:1" };
        var caller: edge.route.Caller = .{ .api_key = req.api_key, .peer = req.peer };
        var scope: edge.forward.GateScope = .{};
        gh.begin(gh.ctx, &req, &rs, &caller, &scope);
        const m: edge.forward.Metered = .{ .method = .execute_transaction, .outcome = .forwarded, .code = 3, .caller = caller, .elapsed_ns = 0 };
        mh.f(mh.ctx, &m);
        gh.end(gh.ctx, &scope, .invalid_argument);
    }
    const Sent = struct {
        m: *g.mock.MockGate,
        fn all(x: @This()) bool {
            return x.m.row("kkid_valid", exe).forwarded == 2;
        }
    };
    try waitFor("the usage rows at the mock gate", Sent{ .m = rig.mock }, Sent.all, 8000);
    // two local and one forwarded at 5; two local and one forwarded at 10, one failed at 0
    try testing.expectEqual(g.contract.Counters{ .local = 2, .forwarded = 1, .units = 15 }, rig.mock.row("kkid_valid", sim));
    try testing.expectEqual(g.contract.Counters{ .local = 2, .forwarded = 2, .units = 30 }, rig.mock.row("kkid_valid", exe));
    // every row the gate got names its method by the full path, and nothing fell to "other"
    try testing.expectEqual(@as(usize, 2), rig.mock.rows.count());
    for (rig.mock.rows.keys()) |k| {
        const method = k[std.mem.indexOfScalar(u8, k, 0).? + 1 ..];
        try testing.expect(std.mem.startsWith(u8, method, "sui.rpc.v2.TransactionExecutionService/"));
    }
    for (rig.mock.batches.values()) |body| {
        try testing.expect(has(body, "\"method\":\"" ++ sim ++ "\"") or has(body, "\"method\":\"" ++ exe ++ "\""));
        try testing.expect(!has(body, "\"method\":\"other\"") and !has(body, "\"method\":\"/"));
    }
}

test "gate stop: with the gate service silent (requests never answered), the stop ends the resolver, the sender and the tick at once and the spool holds everything" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(token ++ "\n");
    defer rig.deinit();
    // a peer that takes the request and never sends a byte back
    var silent: netguard.TestServer = undefined;
    try silent.start(testing.io, null);
    defer silent.stop();
    var ub: [96]u8 = undefined;
    var s = rig.settings;
    s.url = try std.fmt.bufPrint(&ub, "http://127.0.0.1:{d}/v1/gate", .{silent.port});
    const Quiet = struct {
        fn write(_: *anyopaque, _: bool, _: []const u8) void {}
    };
    var nothing: u8 = 0;
    s.log = .{ .ctx = &nothing, .write = Quiet.write };
    const ng = try gate.NodeGate.start(gpa, testing.io, s, null);
    defer ng.deinit();
    ng.core.cfg.cut_ns = 0;
    const get = ng.methods.id("/sui.rpc.v2.LedgerService/GetObject");
    const peer: g.Ip = .{ .v4 = .{ 198, 51, 100, 9 } };
    // a keyed call: its resolve hangs too, so it is served under the floor after the wait
    const first = ng.core.admitWait(&.{ .key = "key-valid-0001", .peer = peer, .method = get });
    try testing.expect(first == .allow and first.allow.kind == .ip);
    ng.core.settle(&first.allow, .local, true, 1);
    for (0..2) |_| {
        const d = ng.core.admitWait(&.{ .peer = peer, .method = get });
        try testing.expect(d == .allow);
        ng.core.settle(&d.allow, .local, true, 1);
    }
    // wait until a usage batch is sealed and its post is on the wire (the free-tier request,
    // which also hangs, comes first and takes its 2 s timeout)
    const Sealed = struct {
        fn now(n: *gate.NodeGate) bool {
            n.core.spool_mu.lockUncancelable(testing.io);
            defer n.core.spool_mu.unlock(testing.io);
            return n.core.spool.sealed != null;
        }
    };
    try waitFor("a usage batch being posted", ng, Sealed.now, 10_000);
    testing.io.sleep(.fromMilliseconds(150), .awake) catch {};
    const t0 = netguard.wallMs();
    ng.stop();
    const took = netguard.wallMs() - t0;
    // (the usage post alone would wait 10 s for its answer, a resolve 2 s)
    try testing.expect(took < 1500);
    try testing.expect(silent.accepts.load(.acquire) >= 2);
    // flushed: the batch and its rows are on disk for the next start
    var d = try Io.Dir.cwd().openDir(testing.io, s.dir, .{});
    defer d.close(testing.io);
    var sp = try g.spool.Spool.open(gpa, testing.io, d, g.spool.default_cap);
    defer sp.deinit();
    try testing.expect(sp.sealed != null);
    try testing.expect(has(sp.sealed.?.body, "\"ip_prefix\":\"198.51.100.0/24\",\"method\":\"sui.rpc.v2.LedgerService/GetObject\",\"local\":3"));
    try testing.expectEqual(@as(u64, 0), sp.stats.torn_bytes);
}

test "gate at a forwarder's seam: a call answered here after the way to the core failed is charged as local; the forward multiplier is for calls the core answered" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(token ++ "\n");
    defer rig.deinit();
    try rig.mock.setKey("key-valid-0001", "{\"key_id\":\"kid_valid\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"ttl_s\":60,\"lease_units\":1000,\"forward_weight_mult\":3,\"weights\":{\"default\":1,\"sui.rpc.v2.LedgerService/GetCheckpoint\":2}}");
    const ng = try gate.NodeGate.start(gpa, testing.io, rig.settings, null);
    defer ng.deinit();
    ng.core.cfg.cut_ns = 0;
    const gh = ng.forwardHook();
    const mh = ng.meterHook();
    const Sink = struct {
        fn write(_: *anyopaque, _: *const [5]u8, _: []const u8) anyerror!void {}
        fn cancelled(_: *anyopaque) bool {
            return false;
        }
        const vt: h2.ResponseStream.VTable = .{ .write = write, .cancelled = cancelled };
    };
    var sink: u8 = 0;
    const path = "/sui.rpc.v2.LedgerService/GetCheckpoint";
    const Case = struct { outcome: edge.forward.Outcome, upstream_error: bool, status: h2.Status };
    const cases = [_]Case{
        // tried the core for a marked certificate, no core answered, served with the held one
        .{ .outcome = .local, .upstream_error = true, .status = .ok },
        // answered here after a read-after-write wait
        .{ .outcome = .local, .upstream_error = false, .status = .ok },
        // the core answered
        .{ .outcome = .forwarded, .upstream_error = false, .status = .ok },
        // passed on, and no core answered
        .{ .outcome = .forwarded, .upstream_error = true, .status = .unavailable },
    };
    for (cases) |c| {
        var rs: h2.ResponseStream = .{ .gpa = gpa, .impl = &sink, .vt = &Sink.vt };
        defer rs.release();
        const req: h2.Request = .{ .path = path, .authority = "", .body = "x", .stream_id = 1, .api_key = "key-valid-0001", .peer = "198.51.100.9:4000" };
        var caller: edge.route.Caller = .{ .api_key = req.api_key, .peer = req.peer };
        var scope: edge.forward.GateScope = .{};
        gh.begin(gh.ctx, &req, &rs, &caller, &scope);
        try testing.expect(caller.deny == null);
        const m: edge.forward.Metered = .{ .method = .get_checkpoint, .outcome = c.outcome, .reason = .foreign_cert, .code = @intFromEnum(c.status), .caller = caller, .elapsed_ns = 0, .upstream_error = c.upstream_error };
        mh.f(mh.ctx, &m);
        gh.end(gh.ctx, &scope, c.status);
    }
    const Sent = struct {
        m: *g.mock.MockGate,
        fn all(x: @This()) bool {
            return x.m.row("kkid_valid", "sui.rpc.v2.LedgerService/GetCheckpoint").forwarded == 2;
        }
    };
    try waitFor("the usage rows at the mock gate", Sent{ .m = rig.mock }, Sent.all, 8000);
    // two local at the plain weight 2, one forwarded at 2 x 3, one forwarded that failed at 0
    try testing.expectEqual(g.contract.Counters{ .local = 2, .forwarded = 2, .units = 2 + 2 + 6 }, rig.mock.row("kkid_valid", "sui.rpc.v2.LedgerService/GetCheckpoint"));
    // the lease saw the same units: 1000 - 10
    const f = ng.core.keys.find(ng.core.keyHash("key-valid-0001")).?;
    try testing.expectEqual(@as(i64, 990), ng.core.keys.entries[f.idx].lease_left.load(.monotonic));
}

test "gate start: a credential shorter than 24 characters, or none, stops the start" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init("short-token\n");
    defer rig.deinit();
    try testing.expectError(error.GateTokenTooShort, gate.NodeGate.start(gpa, testing.io, rig.settings, null));
    // the same mistakes are caught before the node opens anything, with the flag's name
    try testing.expect(has(gate.preflight(gpa, testing.io, &rig.settings).?, "--gate-token-file"));
    try testing.expect(has(gate.preflight(gpa, testing.io, &rig.settings).?, "24 characters"));
    var s = rig.settings;
    s.token_file = "/nonexistent/gate.token";
    try testing.expectError(error.GateTokenFile, gate.NodeGate.start(gpa, testing.io, s, null));
    // plain http is for a gate on this machine only: any other host needs https
    s = rig.settings;
    s.url = "http://gate.example/v1/gate";
    try testing.expectError(error.GateUrl, gate.NodeGate.start(gpa, testing.io, s, null));
    s.url = "http://192.0.2.10:8080/v1/gate";
    try testing.expectError(error.GateUrl, gate.NodeGate.start(gpa, testing.io, s, null));
    try testing.expect(gate.loopbackHttp(rig.settings.url));
    // a CA file that is named and cannot be used stops the start too
    s = rig.settings;
    s.ca_file = "/nonexistent/ca.pem";
    try testing.expectError(error.GateCaFile, gate.NodeGate.start(gpa, testing.io, s, null));
    // (with a good credential the preflight names the CA flag)
    try rig.tmp.dir.writeFile(testing.io, .{ .sub_path = "gate.token", .data = token ++ "\n" });
    try testing.expect(has(gate.preflight(gpa, testing.io, &s).?, "--gate-ca-file"));
    s.ca_file = null;
    try testing.expect(gate.preflight(gpa, testing.io, &s) == null);
    s.url = "http://gate.example/v1/gate";
    try testing.expect(has(gate.preflight(gpa, testing.io, &s).?, "--gate URL"));
    s = rig.settings;
    s.ca_file = "/nonexistent/ca.pem";
    try rig.tmp.dir.writeFile(testing.io, .{ .sub_path = "gate.token", .data = "short-token\n" });
    try rig.tmp.dir.writeFile(testing.io, .{ .sub_path = "empty.pem", .data = "not a certificate\n" });
    var eb: [std.fs.max_path_bytes]u8 = undefined;
    var bb: [std.fs.max_path_bytes]u8 = undefined;
    const base = bb[0..try rig.tmp.dir.realPath(testing.io, &bb)];
    s.ca_file = try std.fmt.bufPrint(&eb, "{s}/empty.pem", .{base});
    // (the file is there and readable: it is refused for holding no certificate)
    try testing.expectError(error.NoCertificateInFile, gate.Http.checkCaFile(gpa, testing.io, s.ca_file.?));
    try testing.expectError(error.GateCaFile, gate.NodeGate.start(gpa, testing.io, s, null));
    try testing.expectEqual(@as(u32, 0), rig.srv.requests.load(.monotonic));
}

/// The mock gate behind TLS 1.3 with a self-signed certificate for `localhost` (its own
/// authority): what a gate behind a private CA looks like to the node.
const TlsGate = struct {
    tls: native.tcptls.Server,
    listener: Io.net.Server,
    port: u16,
    mock: *g.mock.MockGate,
    stopping: Atomic(bool) = .init(false),
    thread: std.Thread = undefined,
    handshakes: Atomic(u32) = .init(0),
    served: Atomic(u32) = .init(0),

    const sock = h2.sock;

    fn start(t: *TlsGate, mock: *g.mock.MockGate, seed: u8) !void {
        const io = testing.io;
        const kp = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(seed));
        var serial: [16]u8 = @splat(seed);
        serial[0] = 1;
        const now_unix: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).toNanoseconds(), std.time.ns_per_s));
        var addr = try Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        t.* = .{ .tls = native.tcptls.Server.init(testing.allocator, io, native.cert.generate(kp, serial, now_unix, 13, "localhost")), .listener = try addr.listen(io, .{ .reuse_address = true }), .port = 0, .mock = mock };
        t.port = t.listener.socket.address.getPort();
        t.thread = try std.Thread.spawn(.{}, loop, .{t});
    }

    /// The certificate as a PEM file's text.
    fn pem(t: *const TlsGate, a: std.mem.Allocator) ![]u8 {
        const der = t.tls.cert.bytes();
        const enc = std.base64.standard.Encoder;
        const b64 = try a.alloc(u8, enc.calcSize(der.len));
        defer a.free(b64);
        _ = enc.encode(b64, der);
        return std.fmt.allocPrint(a, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{b64});
    }

    fn stop(t: *TlsGate) void {
        t.stopping.store(true, .release);
        var addr = Io.net.IpAddress.parseIp4("127.0.0.1", t.port) catch unreachable;
        if (addr.connect(testing.io, .{ .mode = .stream })) |c| c.close(testing.io) else |_| {}
        t.thread.join();
        t.listener.deinit(testing.io);
        t.tls.deinit();
    }

    fn loop(t: *TlsGate) void {
        while (true) {
            const st = t.listener.accept(testing.io) catch return;
            const fd = st.socket.handle;
            if (t.stopping.load(.acquire)) {
                sock.close(fd);
                return;
            }
            const acc = t.tls.acceptor();
            const sess = acc.accept(acc.ctx, fd) orelse {
                sock.close(fd);
                continue;
            };
            if (!sock.attach(fd, sess)) {
                sess.vt.deinit(sess.ctx);
                sock.close(fd);
                continue;
            }
            t.one(fd) catch {};
            sock.close(fd);
        }
    }

    fn one(t: *TlsGate, fd: std.c.fd_t) !void {
        const gpa = testing.allocator;
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        var head_end: ?usize = null;
        var want: usize = 0;
        while (true) {
            var chunk: [4096]u8 = undefined;
            const k = sock.read(fd, &chunk) catch return;
            if (k == 0) return;
            if (buf.items.len == 0) _ = t.handshakes.fetchAdd(1, .monotonic);
            try buf.appendSlice(gpa, chunk[0..k]);
            if (head_end == null) if (std.mem.indexOf(u8, buf.items, "\r\n\r\n")) |e| {
                head_end = e + 4;
                var it = std.mem.splitSequence(u8, buf.items[0..e], "\r\n");
                while (it.next()) |line| {
                    const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                    if (std.ascii.eqlIgnoreCase(line[0..colon], "content-length"))
                        want = std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " "), 10) catch 0;
                }
            };
            if (head_end) |e| if (buf.items.len >= e + want) break;
        }
        const head = buf.items[0 .. head_end.? - 4];
        const body = buf.items[head_end.?..][0..want];
        var lines = std.mem.splitSequence(u8, head, "\r\n");
        var parts = std.mem.splitScalar(u8, lines.next() orelse return, ' ');
        const method = parts.next() orelse return;
        const path = parts.next() orelse return;
        var tok: []const u8 = "";
        while (lines.next()) |line| {
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            if (!std.ascii.eqlIgnoreCase(line[0..colon], "authorization")) continue;
            const v = std.mem.trim(u8, line[colon + 1 ..], " ");
            if (std.mem.startsWith(u8, v, "Bearer ")) tok = v[7..];
        }
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        const status = t.mock.handle(std.mem.eql(u8, method, "POST"), path, tok, body, &out, gpa) catch 500;
        var resp: std.ArrayList(u8) = .empty;
        defer resp.deinit(gpa);
        try resp.print(gpa, "HTTP/1.1 {d} X\r\ncontent-type: application/json\r\ncontent-length: {d}\r\nconnection: close\r\n\r\n", .{ status, out.items.len });
        try resp.appendSlice(gpa, out.items);
        sock.writeAll(fd, resp.items) catch return;
        _ = t.served.fetchAdd(1, .monotonic);
    }
};

test "gate behind a private CA: trusted with --gate-ca-file, refused without it or with another one (and then never unlimited)" {
    const gpa = testing.allocator;
    var rig: Rig = undefined;
    try rig.init(token ++ "\n");
    defer rig.deinit();
    try rig.mock.setKey("key-valid-0001", "{\"key_id\":\"kid_valid\",\"status\":\"ok\",\"plan\":\"developer\",\"rps\":1000,\"burst\":1000,\"ttl_s\":60,\"lease_units\":null}");
    var tg: TlsGate = undefined;
    try tg.start(rig.mock, 21);
    defer tg.stop();
    // the gate's own authority, and one that has nothing to do with it
    var other: TlsGate = undefined;
    try other.start(rig.mock, 22);
    defer other.stop();
    var pb: [std.fs.max_path_bytes]u8 = undefined;
    const base = pb[0..try rig.tmp.dir.realPath(testing.io, &pb)];
    const good_pem = try tg.pem(gpa);
    defer gpa.free(good_pem);
    const other_pem = try other.pem(gpa);
    defer gpa.free(other_pem);
    try rig.tmp.dir.writeFile(testing.io, .{ .sub_path = "ca.pem", .data = good_pem });
    try rig.tmp.dir.writeFile(testing.io, .{ .sub_path = "other.pem", .data = other_pem });
    var ub: [96]u8 = undefined;
    var good_path: [std.fs.max_path_bytes]u8 = undefined;
    var other_path: [std.fs.max_path_bytes]u8 = undefined;
    var s = rig.settings;
    s.url = try std.fmt.bufPrint(&ub, "https://localhost:{d}/v1/gate", .{tg.port});
    const Said = struct {
        lines: Atomic(u32) = .init(0),
        fn write(ctx: *anyopaque, _: bool, _: []const u8) void {
            const x: *@This() = @ptrCast(@alignCast(ctx));
            _ = x.lines.fetchAdd(1, .monotonic);
        }
    };
    var said: Said = .{};
    s.log = .{ .ctx = &said, .write = Said.write };
    const peer: g.Ip = .{ .v4 = .{ 198, 51, 100, 9 } };
    const Probe = struct {
        /// How many of 40 calls with the key pass, and as what.
        fn run(ng: *gate.NodeGate, p: g.Ip) struct { keyed: u32, keyless: u32 } {
            var keyed: u32 = 0;
            var keyless: u32 = 0;
            for (0..40) |_| {
                switch (ng.core.admitWait(&.{ .key = "key-valid-0001", .peer = p, .method = ng.methods.id("/sui.rpc.v2.LedgerService/GetObject") })) {
                    .allow => |t| if (t.kind == .key) {
                        keyed += 1;
                    } else {
                        keyless += 1;
                    },
                    else => {},
                }
            }
            return .{ .keyed = keyed, .keyless = keyless };
        }
    };
    {
        // trusted: the key resolves over TLS and is served as a key
        s.ca_file = try std.fmt.bufPrint(&good_path, "{s}/ca.pem", .{base});
        const ng = try gate.NodeGate.start(gpa, testing.io, s, null);
        defer ng.deinit();
        const Ready = struct {
            fn free(n: *gate.NodeGate) bool {
                return n.core.free_known.load(.monotonic);
            }
        };
        try waitFor("the free tier over TLS", ng, Ready.free, 8000);
        const got = Probe.run(ng, peer);
        try testing.expectEqual(@as(u32, 40), got.keyed);
        try testing.expect(ng.core.reachable.load(.monotonic));
        try testing.expect(tg.served.load(.monotonic) >= 2);
    }
    const served = tg.served.load(.monotonic);
    for ([_]?[]const u8{ "other.pem", null }) |file| {
        // another authority, or none but the system's: the gate's certificate is refused, the
        // gate counts as unreachable, and the key gets the built-in floor (2 a second, burst 4)
        s.ca_file = if (file) |f| try std.fmt.bufPrint(&other_path, "{s}/{s}", .{ base, f }) else null;
        // (a directory of its own: no free tier kept by the run above)
        var db: [std.fs.max_path_bytes]u8 = undefined;
        s.dir = try std.fmt.bufPrint(&db, "{s}/gate-state-untrusted", .{base});
        const ng = try gate.NodeGate.start(gpa, testing.io, s, null);
        defer ng.deinit();
        const Down = struct {
            fn seen(n: *gate.NodeGate) bool {
                return n.core.m.free_errors.load(.monotonic) >= 1;
            }
        };
        try waitFor("the refused certificate", ng, Down.seen, 8000);
        const got = Probe.run(ng, peer);
        try testing.expectEqual(@as(u32, 0), got.keyed);
        try testing.expect(got.keyless >= 4 and got.keyless <= 6);
        try testing.expect(!ng.core.reachable.load(.monotonic));
        try testing.expect(!ng.core.free_known.load(.monotonic));
    }
    // nothing got through to the gate without a certificate the node trusts
    try testing.expectEqual(served, tg.served.load(.monotonic));
    try testing.expect(said.lines.load(.monotonic) >= 1);
}
