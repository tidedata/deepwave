//! The :9000 transport against sui-node 1.83.1 captures (h2/vectors, taken from a production node
//! through an SSH tunnel on 2026-11-08): each captured request is replayed over a real socket
//! to the deepwave runtime with the router's predicates, reflection and health, and the reply must
//! have sui-node's status line, header names in sui-node's order, the same values for every
//! header that does not carry the tip or the time, the same connection behaviour (closed or
//! kept), and the same body framing.
const std = @import("std");
const testing = std.testing;
const h2 = @import("h2/root.zig");
const hpack = h2.hpack;
const reflection = @import("reflection.zig");
const router = @import("router.zig");
const lh_service = @import("lh_service.zig");

const svcinfo_path = "/sui.rpc.v2.LedgerService/GetServiceInfo";

const H = struct {
    var dummy: u8 = 0;
    // a GetServiceInfo-shaped reply (chain id, chain); the vectors' values differ (tip)
    const canned = "\x0a\x2c4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S\x12\x07mainnet";
    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const p = req.path;
        if (std.mem.startsWith(u8, p, reflection.health_path)) return reflection.healthCall(req, rs);
        if (std.mem.startsWith(u8, p, reflection.v1_path)) return reflection.call(testing.allocator, .v1, req, rs);
        if (std.mem.startsWith(u8, p, reflection.v1alpha_path)) return reflection.call(testing.allocator, .v1alpha, req, rs);
        if (std.mem.eql(u8, p, svcinfo_path)) {
            rs.message(canned) catch return .internal;
            return .ok;
        }
        return .unimplemented;
    }
    fn info(_: *anyopaque, out: *h2.meta.Info) void {
        out.* = .{ .chain_id = "4btiuiMPvEENsttpZC7CZ53DruC3MAgfznDbASZ7DR6S", .chain = "mainnet", .tip = .{ .epoch = 1305, .height = 342960193, .timestamp_ms = 1794131786665 }, .lowest = 342420333, .server = "sui-node/1.83.1-6a567faf6de1" };
    }
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call, .known = router.known, .compress = router.compress, .info = info, .bidi = router.bidi, .method = router.method };
};

/// Values that carry the tip or the clock: compared by name only.
fn volatileHeader(name: []const u8) bool {
    return std.mem.startsWith(u8, name, "x-sui-") or std.mem.eql(u8, name, "date") or std.mem.eql(u8, name, "server-timing");
}

const Server = struct {
    server: std.Io.net.Server,
    t: std.Thread,
    port: u16,
    opts: h2.ServerOptions,
    stopping: std.atomic.Value(bool) = .init(false),

    /// Serves `conns` connections, one after the other.
    fn start(opts: h2.ServerOptions, conns: usize) !*Server {
        const s = try testing.allocator.create(Server);
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        s.server = try addr.listen(testing.io, .{ .reuse_address = true });
        s.port = s.server.socket.address.getPort();
        s.opts = opts;
        s.stopping = .init(false);
        s.t = try std.Thread.spawn(.{}, run, .{ s, conns });
        return s;
    }
    fn run(s: *Server, conns: usize) void {
        var i: usize = 0;
        while (i < conns) : (i += 1) {
            const st = s.server.accept(testing.io) catch return;
            if (s.stopping.load(.acquire)) {
                st.close(testing.io);
                return;
            }
            h2.server.serveStreamOpts(testing.allocator, testing.io, st, s.opts, H.handler);
        }
    }
    /// Joins the server thread; a test that failed early leaves it in accept, so wake it.
    fn stop(s: *Server) void {
        s.stopping.store(true, .release);
        if (s.connect()) |c| c.close(testing.io) else |_| {}
        s.t.join();
        s.server.deinit(testing.io);
        testing.allocator.destroy(s);
    }
    fn connect(s: *Server) !std.Io.net.Stream {
        var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", s.port);
        return caddr.connect(testing.io, .{ .mode = .stream });
    }
};

fn writeAll(st: std.Io.net.Stream, bytes: []const u8) !void {
    var wbuf: [512]u8 = undefined;
    var w = st.writer(testing.io, &wbuf);
    try w.interface.writeAll(bytes);
    try w.interface.flush();
}

/// Reads one byte batch; 0 at EOF.
fn readSome(st: std.Io.net.Stream, buf: []u8) !usize {
    var iov = [_][]u8{buf};
    return st.read(testing.io, &iov) catch |e| switch (e) {
        error.ConnectionResetByPeer => 0,
        else => e,
    };
}

/// True when the peer closes within `ms` (false: still open, nothing more arrived).
fn closesWithin(st: std.Io.net.Stream, ms: i32) bool {
    var p = [_]std.c.pollfd{.{ .fd = st.socket.handle, .events = std.c.POLL.IN, .revents = 0 }};
    if (std.c.poll(&p, 1, ms) <= 0) return false;
    var b: [64]u8 = undefined;
    const n = readSome(st, &b) catch return true;
    return n == 0;
}

// ---------------------------------------------------------------- HTTP/1.x

const H1 = struct {
    status: []const u8,
    headers: std.ArrayList([2][]const u8) = .empty,
    body: []const u8,
    closed: bool,
};

fn parseH1(a: std.mem.Allocator, raw0: []const u8) !H1 {
    var raw = raw0;
    var closed = false;
    if (std.mem.endsWith(u8, raw, "<<CLOSED>>")) {
        raw = raw[0 .. raw.len - "<<CLOSED>>".len];
        closed = true;
    }
    const he = (std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.Bad) + 4;
    var lines = std.mem.splitSequence(u8, raw[0 .. he - 4], "\r\n");
    var r: H1 = .{ .status = lines.next().?, .body = raw[he..], .closed = closed };
    while (lines.next()) |l| {
        const c = std.mem.indexOf(u8, l, ": ") orelse return error.Bad;
        try r.headers.append(a, .{ l[0..c], l[c + 2 ..] });
    }
    return r;
}

fn header(r: *const H1, name: []const u8) ?[]const u8 {
    for (r.headers.items) |kv| if (std.mem.eql(u8, kv[0], name)) return kv[1];
    return null;
}

/// gRPC-web frames of a body (de-chunked when chunked; base64 is not decoded).
fn webFrames(a: std.mem.Allocator, r: *const H1) ![]const u8 {
    if (header(r, "transfer-encoding") == null) return r.body;
    var out: std.ArrayList(u8) = .empty;
    var p: usize = 0;
    while (true) {
        const e = std.mem.indexOfPos(u8, r.body, p, "\r\n") orelse return error.Bad;
        const n = try std.fmt.parseInt(usize, r.body[p..e], 16);
        if (n == 0) break;
        try out.appendSlice(a, r.body[e + 2 ..][0..n]);
        p = e + 2 + n + 2;
    }
    return out.items;
}

/// Same body: byte-equal, except a message frame (flag 0/1) whose payload carries the tip;
/// those are compared by flag, and the frames after them byte for byte.
fn expectSameBody(a: std.mem.Allocator, name: []const u8, want: *const H1, got: *const H1) !void {
    const w = try webFrames(a, want);
    const g = try webFrames(a, got);
    const ct = header(want, "content-type") orelse "";
    if (!std.mem.startsWith(u8, ct, "application/grpc-web") or std.mem.indexOf(u8, ct, "text") != null) {
        if (!std.mem.eql(u8, w, g)) {
            std.debug.print("{s}: body differs\n want {any}\n got  {any}\n", .{ name, w, g });
            return error.TestUnexpectedResult;
        }
        return;
    }
    var wi: usize = 0;
    var gi: usize = 0;
    while (wi + 5 <= w.len and gi + 5 <= g.len) {
        const wn = std.mem.readInt(u32, w[wi + 1 ..][0..4], .big);
        const gn = std.mem.readInt(u32, g[gi + 1 ..][0..4], .big);
        try testing.expectEqual(w[wi], g[gi]);
        if (w[wi] & 0x80 != 0) try testing.expectEqualStrings(w[wi + 5 ..][0..wn], g[gi + 5 ..][0..gn]);
        wi += 5 + wn;
        gi += 5 + gn;
    }
    try testing.expectEqual(w.len - wi, g.len - gi);
}

fn expectSameH1(a: std.mem.Allocator, name: []const u8, want: *const H1, got: *const H1) !void {
    errdefer std.debug.print("vector {s}:\n--- sui-node\n{s}\n{any}\n--- zui\n{s}\n{any}\n", .{ name, want.status, want.headers.items, got.status, got.headers.items });
    try testing.expectEqualStrings(want.status, got.status);
    try testing.expectEqual(want.headers.items.len, got.headers.items.len);
    for (want.headers.items, got.headers.items) |w, g| {
        try testing.expectEqualStrings(w[0], g[0]);
        if (!volatileHeader(w[0])) try testing.expectEqualStrings(w[1], g[1]);
    }
    try expectSameBody(a, name, want, got);
    try testing.expectEqual(want.closed, got.closed);
}

/// Sends a captured request on a fresh connection; reads the reply (to EOF when the server
/// closes, or until it is complete and the connection stays open).
fn h1Exchange(a: std.mem.Allocator, srv: *Server, req: []const u8, head_req: bool) ![]const u8 {
    const st = try srv.connect();
    defer st.close(testing.io);
    try writeAll(st, req);
    var got: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        if (std.mem.indexOf(u8, got.items, "\r\n\r\n")) |he| {
            const head = got.items[0..he];
            const body = got.items[he + 4 ..];
            const complete = if (head_req)
                true
            else if (std.ascii.findIgnoreCase(head, "transfer-encoding: chunked") != null)
                std.mem.endsWith(u8, body, "\r\n0\r\n\r\n") or std.mem.eql(u8, body, "0\r\n\r\n")
            else if (std.ascii.findIgnoreCase(head, "content-length: ")) |i| blk: {
                const v = head[i + "content-length: ".len ..];
                const e = std.mem.indexOf(u8, v, "\r\n") orelse v.len;
                break :blk body.len >= try std.fmt.parseInt(usize, v[0..e], 10);
            } else false; // close-delimited
            if (complete) {
                if (closesWithin(st, 150)) try got.appendSlice(a, "<<CLOSED>>");
                return got.items;
            }
        }
        const n = try readSome(st, &buf);
        if (n == 0) {
            try got.appendSlice(a, "<<CLOSED>>");
            return got.items;
        }
        try got.appendSlice(a, buf[0..n]);
    }
}

const h1_vectors = [_][]const u8{
    // connection framing (hyper): connection: close / keep-alive, HTTP/1.0
    "h1-health-close",          "h1-health-10",           "h1-health-10-ka",          "h1-svcinfo-close",
    "h1-svcinfo-10",            "h1-10-ka-svcinfo",       "h1-10-unknown",            "h1-10-empty-body",
    "h1-close-empty-body",      "h1-close-unknown",       "h1-close-get-grpc",        "h1-options-close",
    // methods: CORS on any OPTIONS, axum /health, tonic-web 405
    "h1-options-bare",          "h1-options-origin-only", "h1-options-health",        "h1-options-unknown",
    "h1-options-grpcweb-ct",    "h1-options",             "h1-get-grpcweb-ct",        "h1-put-grpcweb-ct",
    "h1-get-health-grpcweb-ct", "h1-get-unknown-grpcweb-ct", "h1-post-health",        "h1-head-health",
    "h1-get-health",            "h1-get-health-thresh",   "h1-get-root",              "h1-get-grpc-path",
    // gRPC-web content types and accept, exact match
    "h1-ct-json",               "h1-ct-charset",          "h1-ct-upper",              "h1-accept-multi",
    "h1-svcinfo-bin",           "h1-svcinfo-grpc-h1",
    "h1-svcinfo-origin",        "h1-svcinfo-grpcweb-plain",
    // no message; health Watch of an unknown service; reflection errors
    "h1-empty-body",            "h1-watch-unknown",       "h1-health-check",          "h1-health-check-unknown",
    "h1-refl-ext",              "h1-refl-bad",            "h1-refl-short",            "h1-unknown-service",
    "h1-unimpl-method",         "h1-req-short",           "h1-req-flag-noenc",        "h1-req-gzip",
};

test "HTTP/1.x replies equal sui-node's captures (connection framing, methods, gRPC-web types, errors)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const srv = try Server.start(.{}, h1_vectors.len);
    defer srv.stop();
    inline for (h1_vectors) |name| {
        const req = @embedFile("h2/vectors/" ++ name ++ ".req");
        const want_raw = @embedFile("h2/vectors/" ++ name ++ ".resp");
        const got_raw = try h1Exchange(a, srv, req, std.mem.startsWith(u8, req, "HEAD "));
        var want = try parseH1(a, want_raw);
        // older captures did not mark closes: only the new ones say whether the node closed
        const marks = std.mem.endsWith(u8, want_raw, "<<CLOSED>>") or isNewCapture(name);
        var got = try parseH1(a, got_raw);
        if (!marks) {
            want.closed = got.closed;
        }
        try expectSameH1(a, name, &want, &got);
    }
}

/// Vectors captured with the close marker (2026-11-08 09:56 PST and later).
fn isNewCapture(name: []const u8) bool {
    const new = [_][]const u8{ "h1-health-10-ka", "h1-options-bare", "h1-options-origin-only", "h1-options-health", "h1-options-unknown", "h1-get-grpcweb-ct", "h1-put-grpcweb-ct", "h1-get-health-grpcweb-ct", "h1-get-unknown-grpcweb-ct", "h1-ct-json", "h1-ct-charset", "h1-ct-upper", "h1-accept-multi", "h1-empty-body", "h1-watch-unknown", "h1-refl-ext", "h1-refl-bad", "h1-refl-short", "h1-post-health", "h1-head-health", "h1-options-grpcweb-ct" };
    for (new) |n| if (std.mem.eql(u8, n, name)) return true;
    return false;
}

// ---------------------------------------------------------------- h2c

const H2Reply = struct {
    status: []const u8 = "",
    headers: std.ArrayList([2][]const u8) = .empty,
    trailers: std.ArrayList([2][]const u8) = .empty,
    data: std.ArrayList(u8) = .empty,
};

const Collect = struct {
    a: std.mem.Allocator,
    list: *std.ArrayList([2][]const u8),
    status: *[]const u8,
    fn push(c: *Collect, name: []const u8, value: []const u8) hpack.Error!void {
        if (std.mem.eql(u8, name, ":status")) {
            c.status.* = c.a.dupe(u8, value) catch return error.OutOfMemory;
            return;
        }
        c.list.append(c.a, .{ c.a.dupe(u8, name) catch return error.OutOfMemory, c.a.dupe(u8, value) catch return error.OutOfMemory }) catch return error.OutOfMemory;
    }
};

fn h2Frame(out: *std.ArrayList(u8), a: std.mem.Allocator, t: u8, flags: u8, sid: u32, payload: []const u8) !void {
    try out.appendSlice(a, &.{ @intCast(payload.len >> 16), @intCast((payload.len >> 8) & 0xff), @intCast(payload.len & 0xff), t, flags });
    var s: [4]u8 = undefined;
    std.mem.writeInt(u32, &s, sid, .big);
    try out.appendSlice(a, &s);
    try out.appendSlice(a, payload);
}

const H2Req = struct {
    name: []const u8,
    method: []const u8,
    path: []const u8,
    headers: []const [2][]const u8 = &.{},
    /// Send the vector's `.req` bytes as the body.
    body: bool = false,
};

const grpc_hdrs = [_][2][]const u8{ .{ "content-type", "application/grpc" }, .{ "te", "trailers" } };

const h2_vectors = [_]H2Req{
    .{ .name = "h2-get-health", .method = "GET", .path = "/health" },
    .{ .name = "h2-get-health-thresh", .method = "GET", .path = "/health?threshold_seconds=5" },
    .{ .name = "h2-head-health", .method = "HEAD", .path = "/health" },
    .{ .name = "h2-post-health", .method = "POST", .path = "/health" },
    .{ .name = "h2-options-preflight", .method = "OPTIONS", .path = svcinfo_path, .headers = &.{ .{ "origin", "https://example.com" }, .{ "access-control-request-method", "POST" } } },
    .{ .name = "h2-options-bare", .method = "OPTIONS", .path = svcinfo_path },
    .{ .name = "h2-options-health", .method = "OPTIONS", .path = "/health" },
    .{ .name = "h2-options-unknown", .method = "OPTIONS", .path = "/nope" },
    .{ .name = "h2-empty-body", .method = "POST", .path = svcinfo_path, .headers = &grpc_hdrs },
    .{ .name = "h2-get-grpc-path", .method = "GET", .path = svcinfo_path },
    .{ .name = "h2-get-grpcweb-ct", .method = "GET", .path = svcinfo_path, .headers = &.{.{ "content-type", "application/grpc-web+proto" }} },
    .{ .name = "h2-get-unknown", .method = "GET", .path = "/nope" },
    .{ .name = "h2-post-unknown", .method = "POST", .path = "/sui.nope.Svc/X", .headers = &grpc_hdrs, .body = true },
    .{ .name = "h2-post-json-ct", .method = "POST", .path = svcinfo_path, .headers = &.{.{ "content-type", "application/json" }}, .body = true },
    .{ .name = "h2-post-grpcweb", .method = "POST", .path = svcinfo_path, .headers = &.{.{ "content-type", "application/grpc-web+proto" }}, .body = true },
    .{ .name = "h2-watch-unknown", .method = "POST", .path = "/grpc.health.v1.Health/Watch", .headers = &grpc_hdrs, .body = true },
    .{ .name = "h2-refl-ext", .method = "POST", .path = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", .headers = &grpc_hdrs, .body = true },
    .{ .name = "h2-refl-bad", .method = "POST", .path = "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", .headers = &grpc_hdrs, .body = true },
};

/// One request on a fresh h2c connection; reads until the stream ends.
fn h2Exchange(a: std.mem.Allocator, srv: *Server, r: H2Req, body: []const u8) !H2Reply {
    const st = try srv.connect();
    defer st.close(testing.io);
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, h2.conn.preface);
    try h2Frame(&out, a, 4, 0, 0, &.{});
    var hb: std.ArrayList(u8) = .empty;
    try hpack.encodeLiteral(&hb, a, ":method", r.method);
    try hpack.encodeLiteral(&hb, a, ":scheme", "http");
    try hpack.encodeLiteral(&hb, a, ":path", r.path);
    try hpack.encodeLiteral(&hb, a, ":authority", "127.0.0.1:19000");
    for (r.headers) |kv| try hpack.encodeLiteral(&hb, a, kv[0], kv[1]);
    try h2Frame(&out, a, 1, if (body.len == 0) 5 else 4, 1, hb.items);
    if (body.len > 0) try h2Frame(&out, a, 0, 1, 1, body);
    try writeAll(st, out.items);
    var dec = hpack.Decoder.init(testing.allocator);
    defer dec.deinit();
    var rep: H2Reply = .{};
    var in: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    var blocks: u32 = 0;
    while (true) {
        var pos: usize = 0;
        while (in.items.len - pos >= 9) {
            const h = in.items[pos..][0..9];
            const len = (@as(usize, h[0]) << 16) | (@as(usize, h[1]) << 8) | h[2];
            if (in.items.len - pos < 9 + len) break;
            const payload = in.items[pos + 9 ..][0..len];
            const sid = std.mem.readInt(u32, h[5..9], .big) & 0x7fffffff;
            pos += 9 + len;
            if (sid != 1) continue;
            const end = h[4] & 1 != 0;
            switch (h[3]) {
                1 => {
                    var c: Collect = .{ .a = a, .list = if (blocks == 0) &rep.headers else &rep.trailers, .status = &rep.status };
                    try dec.decode(a, payload, &c, Collect.push);
                    blocks += 1;
                },
                0 => try rep.data.appendSlice(a, payload),
                3 => return error.StreamReset,
                else => {},
            }
            if (end) return rep;
        }
        const n = try readSome(st, &buf);
        if (n == 0) return error.Closed;
        try in.appendSlice(a, buf[0..n]);
    }
}

/// curl `-D -` output: `HTTP/2 <status> `, header lines, a blank line, trailer lines.
fn parseHdr(a: std.mem.Allocator, raw: []const u8) !H2Reply {
    var rep: H2Reply = .{};
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    const first = lines.next().?;
    rep.status = std.mem.trim(u8, first["HTTP/2 ".len..], " ");
    var in_trailers = false;
    while (lines.next()) |l| {
        if (l.len == 0) {
            in_trailers = true;
            continue;
        }
        const c = std.mem.indexOf(u8, l, ": ") orelse return error.Bad;
        try (if (in_trailers) &rep.trailers else &rep.headers).append(a, .{ l[0..c], l[c + 2 ..] });
    }
    return rep;
}

fn expectSameList(want: []const [2][]const u8, got: []const [2][]const u8) !void {
    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| {
        try testing.expectEqualStrings(w[0], g[0]);
        if (!volatileHeader(w[0])) try testing.expectEqualStrings(w[1], g[1]);
    }
}

test "h2c replies equal sui-node's captures (/health, CORS on any OPTIONS, 404/405, missing message, Watch, reflection errors)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const srv = try Server.start(.{}, h2_vectors.len);
    defer srv.stop();
    inline for (h2_vectors) |r| {
        const want = try parseHdr(a, @embedFile("h2/vectors/" ++ r.name ++ ".hdr"));
        const body: []const u8 = if (r.body) @embedFile("h2/vectors/" ++ r.name ++ ".req") else "";
        const got = try h2Exchange(a, srv, r, body);
        errdefer std.debug.print("vector {s}:\n--- sui-node {s}\n{any}\n{any}\n--- zui {s}\n{any}\n{any}\n", .{ r.name, want.status, want.headers.items, want.trailers.items, got.status, got.headers.items, got.trailers.items });
        try testing.expectEqualStrings(want.status, got.status);
        try expectSameList(want.headers.items, got.headers.items);
        try expectSameList(want.trailers.items, got.trailers.items);
        if (comptime std.mem.eql(u8, r.name, "h2-post-grpcweb")) {
            // gRPC-web over h2: the message, then the trailers frame in the body
            try testing.expectEqual(@as(u8, 0), got.data.items[0]);
            try testing.expect(std.mem.endsWith(u8, got.data.items, "\x80\x00\x00\x00\x0fgrpc-status:0\r\n"));
            try testing.expect(std.mem.endsWith(u8, @embedFile("h2/vectors/h2-post-grpcweb.body"), "\x80\x00\x00\x00\x0fgrpc-status:0\r\n"));
        } else if (comptime !std.mem.eql(u8, r.name, "h2-post-json-ct") and !std.mem.eql(u8, r.name, "h2-head-health")) {
            try testing.expectEqualSlices(u8, @embedFile("h2/vectors/" ++ r.name ++ ".body"), got.data.items);
        }
    }
}

// ---------------------------------------------------------------- runtime

test "grpc.health Watch holds the stream without a thread; the status message first" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const srv = try Server.start(.{}, 1);
    defer srv.stop();
    const st = try srv.connect();
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, h2.conn.preface);
    try h2Frame(&out, a, 4, 0, 0, &.{});
    var hb: std.ArrayList(u8) = .empty;
    try hpack.encodeLiteral(&hb, a, ":method", "POST");
    try hpack.encodeLiteral(&hb, a, ":path", "/grpc.health.v1.Health/Watch");
    try hpack.encodeLiteral(&hb, a, "content-type", "application/grpc");
    try h2Frame(&out, a, 1, 4, 1, hb.items);
    try h2Frame(&out, a, 0, 1, 1, "\x00\x00\x00\x00\x00");
    const pumps0 = h2.server.stats.pumps.load(.acquire);
    try writeAll(st, out.items);
    // read until the SERVING message (DATA on stream 1)
    var in: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    const data = outer: while (true) {
        const n = try readSome(st, &buf);
        try testing.expect(n > 0);
        try in.appendSlice(a, buf[0..n]);
        var pos: usize = 0;
        while (in.items.len - pos >= 9) {
            const len = (@as(usize, in.items[pos]) << 16) | (@as(usize, in.items[pos + 1]) << 8) | in.items[pos + 2];
            if (in.items.len - pos < 9 + len) break;
            if (in.items[pos + 3] == 0 and in.items[pos + 8] == 1) break :outer in.items[pos + 9 ..][0..len];
            try testing.expect(in.items[pos + 3] != 1 or in.items[pos + 4] & 1 == 0); // no END_STREAM
            pos += 9 + len;
        }
    };
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00\x02\x08\x01", data);
    // still open, and no pump thread holds it
    try testing.expectEqual(pumps0, h2.server.stats.pumps.load(.acquire));
    try testing.expect(!closesWithin(st, 200));
    st.close(testing.io);
}

const Slow = struct {
    var dummy: u8 = 0;
    var concurrent: std.atomic.Value(u32) = .init(0);
    var peak: std.atomic.Value(u32) = .init(0);
    fn call(_: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const now = concurrent.fetchAdd(1, .acq_rel) + 1;
        _ = peak.fetchMax(now, .acq_rel);
        h2.sock.sleepMs(150);
        _ = concurrent.fetchSub(1, .acq_rel);
        rs.message(req.body) catch return .internal;
        return .ok;
    }
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call };
};

test "h2c: 32 concurrent unary streams on one connection run in parallel (worker pool), small client window" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var server = blk: {
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        break :blk try addr.listen(testing.io, .{ .reuse_address = true });
    };
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server) void {
            const st = s.accept(testing.io) catch return;
            h2.server.serveStreamOpts(testing.allocator, testing.io, st, .{}, Slow.handler);
        }
    }.run, .{&server});
    defer t.join();
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const st = try caddr.connect(testing.io, .{ .mode = .stream });
    defer st.close(testing.io);

    const streams = 32;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, h2.conn.preface);
    // SETTINGS: INITIAL_WINDOW_SIZE 64 bytes per stream (replies wait for window updates)
    try h2Frame(&out, a, 4, 0, 0, &.{ 0, 4, 0, 0, 0, 64 });
    const msg = "\x00\x00\x00\x00\x50" ++ @as([80]u8, @splat('z'));
    var sid: u32 = 1;
    while (sid < 2 * streams) : (sid += 2) {
        var hb: std.ArrayList(u8) = .empty;
        try hpack.encodeLiteral(&hb, a, ":method", "POST");
        try hpack.encodeLiteral(&hb, a, ":path", "/t.S/Slow");
        try hpack.encodeLiteral(&hb, a, "content-type", "application/grpc");
        try h2Frame(&out, a, 1, 4, sid, hb.items);
        try h2Frame(&out, a, 0, 1, sid, msg);
    }
    const t0 = h2.meta.monoNs();
    try writeAll(st, out.items);
    var in: std.ArrayList(u8) = .empty;
    var buf: [16384]u8 = undefined;
    var ended: u32 = 0;
    var data_bytes: usize = 0;
    var pos: usize = 0;
    while (ended < streams) {
        const n = try readSome(st, &buf);
        try testing.expect(n > 0);
        try in.appendSlice(a, buf[0..n]);
        while (in.items.len - pos >= 9) {
            const h = in.items[pos..][0..9];
            const len = (@as(usize, h[0]) << 16) | (@as(usize, h[1]) << 8) | h[2];
            if (in.items.len - pos < 9 + len) break;
            const fsid = std.mem.readInt(u32, h[5..9], .big) & 0x7fffffff;
            if (h[3] == 0 and fsid != 0) {
                data_bytes += len;
                // give the stream its window back as the data arrives
                var inc: [4]u8 = undefined;
                std.mem.writeInt(u32, &inc, @intCast(@max(len, 1)), .big);
                var wu: std.ArrayList(u8) = .empty;
                try h2Frame(&wu, a, 8, 0, fsid, &inc);
                try writeAll(st, wu.items);
            }
            if (h[3] == 1 and h[4] & 1 != 0) ended += 1;
            pos += 9 + len;
        }
    }
    const ms = (h2.meta.monoNs() - t0) / std.time.ns_per_ms;
    try testing.expectEqual(@as(usize, streams * msg.len), data_bytes);
    // serial would take 32 x 150 ms = 4.8 s
    try testing.expect(Slow.peak.load(.acquire) >= 8);
    try testing.expect(ms < 2500);
}

const Pumped = struct {
    var dummy: u8 = 0;
    var runs: std.atomic.Value(u32) = .init(0);
    var dones: std.atomic.Value(u32) = .init(0);
    var fail_after_attach = false;
    fn call(_: *anyopaque, req: *const h2.Request, _: *h2.ResponseStream) h2.Status {
        if (!h2.attach(req.stream_id, .{ .ctx = &dummy, .run = run, .wake = wake, .done = done })) return .unimplemented;
        return if (fail_after_attach) .internal else .deferred;
    }
    fn run(_: *anyopaque, link: *h2.Link) void {
        _ = runs.fetchAdd(1, .acq_rel);
        link.send("x") catch return;
        link.finish(.ok, "");
    }
    fn wake(_: *anyopaque) void {}
    fn done(_: *anyopaque) void {
        _ = dones.fetchAdd(1, .acq_rel);
    }
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call };
};

fn pumpedCall(opts: h2.ServerOptions, h2c: bool) ![]u8 {
    var server = blk: {
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        break :blk try addr.listen(testing.io, .{ .reuse_address = true });
    };
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    const T = struct {
        fn run(s: *std.Io.net.Server, o: h2.ServerOptions) void {
            const st = s.accept(testing.io) catch return;
            h2.server.serveStreamOpts(testing.allocator, testing.io, st, o, Pumped.handler);
        }
    };
    const t = try std.Thread.spawn(.{}, T.run, .{ &server, opts });
    defer t.join();
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const st = try caddr.connect(testing.io, .{ .mode = .stream });
    defer st.close(testing.io);
    const gpa = testing.allocator;
    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    if (h2c) {
        try req.appendSlice(gpa, h2.conn.preface);
        try h2Frame(&req, gpa, 4, 0, 0, &.{});
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(gpa);
        try hpack.encodeLiteral(&hb, gpa, ":method", "POST");
        try hpack.encodeLiteral(&hb, gpa, ":path", "/t.S/Stream");
        try h2Frame(&req, gpa, 1, 4, 1, hb.items);
        try h2Frame(&req, gpa, 0, 1, 1, "\x00\x00\x00\x00\x00");
    } else {
        try req.appendSlice(gpa, "POST /t.S/Stream HTTP/1.1\r\nhost: x\r\ncontent-type: application/grpc-web+proto\r\nconnection: close\r\ncontent-length: 5\r\n\r\n\x00\x00\x00\x00\x00");
    }
    try writeAll(st, req.items);
    var got: std.ArrayList(u8) = .empty;
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try readSome(st, &buf);
        if (n == 0) break;
        try got.appendSlice(gpa, buf[0..n]);
        if (h2c and h2DoneOn1(got.items)) break;
    }
    return got.toOwnedSlice(gpa);
}

fn h2DoneOn1(b: []const u8) bool {
    var pos: usize = 0;
    while (pos + 9 <= b.len) {
        const len = (@as(usize, b[pos]) << 16) | (@as(usize, b[pos + 1]) << 8) | b[pos + 2];
        if (pos + 9 + len > b.len) return false;
        if (b[pos + 3] == 1 and b[pos + 4] & 1 != 0) return true;
        pos += 9 + len;
    }
    return false;
}

fn waitFor(v: *std.atomic.Value(u32), want: u32) !void {
    var i: u32 = 0;
    while (v.load(.acquire) < want and i < 2000) : (i += 1) h2.sock.sleepMs(1);
    try testing.expectEqual(want, v.load(.acquire));
}

test "Pump.done runs exactly once: after run, or in place of run when the stream cannot start" {
    Pumped.fail_after_attach = false;
    Pumped.runs.store(0, .release);
    Pumped.dones.store(0, .release);
    // h2c, normal: run then done
    const a1 = try pumpedCall(.{}, true);
    defer testing.allocator.free(a1);
    try waitFor(&Pumped.dones, 1);
    try testing.expectEqual(@as(u32, 1), Pumped.runs.load(.acquire));
    // h2c over max_pumps: RESOURCE_EXHAUSTED, done without run
    const a2 = try pumpedCall(.{ .max_pumps = 0 }, true);
    defer testing.allocator.free(a2);
    try testing.expect(std.mem.indexOf(u8, a2, "grpc-status\x018") != null);
    try waitFor(&Pumped.dones, 2);
    try testing.expectEqual(@as(u32, 1), Pumped.runs.load(.acquire));
    // h2c, inline dispatch over max_pumps (the connection-thread attach path)
    const a3 = try pumpedCall(.{ .max_pumps = 0, .inline_unary = true }, true);
    defer testing.allocator.free(a3);
    try waitFor(&Pumped.dones, 3);
    try testing.expectEqual(@as(u32, 1), Pumped.runs.load(.acquire));
    // gRPC-web, normal: run then done
    const b1 = try pumpedCall(.{}, false);
    defer testing.allocator.free(b1);
    try testing.expect(std.mem.indexOf(u8, b1, "grpc-status:0") != null);
    try waitFor(&Pumped.dones, 4);
    try testing.expectEqual(@as(u32, 2), Pumped.runs.load(.acquire));
    // the handler fails after attaching: done without run, on both transports
    Pumped.fail_after_attach = true;
    defer Pumped.fail_after_attach = false;
    const b2 = try pumpedCall(.{}, false);
    defer testing.allocator.free(b2);
    try waitFor(&Pumped.dones, 5);
    const a4 = try pumpedCall(.{}, true);
    defer testing.allocator.free(a4);
    try waitFor(&Pumped.dones, 6);
    try testing.expectEqual(@as(u32, 2), Pumped.runs.load(.acquire));
}

test "gRPC-web text over h2c: base64 request, base64 frames out when accept asks for text" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const srv = try Server.start(.{}, 1);
    defer srv.stop();
    const r: H2Req = .{ .name = "web-text", .method = "POST", .path = svcinfo_path, .headers = &.{ .{ "content-type", "application/grpc-web-text" }, .{ "accept", "application/grpc-web-text" } } };
    const got = try h2Exchange(a, srv, r, "AAAAAAA=");
    try testing.expectEqualStrings("200", got.status);
    try testing.expectEqualStrings("content-type", got.headers.items[0][0]);
    try testing.expectEqualStrings("application/grpc-web-text+proto", got.headers.items[0][1]);
    try testing.expectEqual(@as(usize, 0), got.trailers.items.len);
    try testing.expect(std.mem.endsWith(u8, got.data.items, "gAAAAA9ncnBjLXN0YXR1czowDQo="));
    const d = std.base64.standard.Decoder;
    const first_len = got.data.items.len - "gAAAAA9ncnBjLXN0YXR1czowDQo=".len;
    const raw = try a.alloc(u8, try d.calcSizeForSlice(got.data.items[0..first_len]));
    try d.decode(raw, got.data.items[0..first_len]);
    try testing.expectEqualSlices(u8, "\x00\x00\x00\x00" ++ [_]u8{H.canned.len} ++ H.canned, raw);
}

/// A List*-sized stream through `lh_service.ListPump` (the writer every List* call uses on the
/// transport runtime) to a client that reads slowly and returns window only for what it read.
const Huge = struct {
    var dummy: u8 = 0;
    const msg_len = 32 * 1024;
    const messages = 256; // 8 MiB
    /// Bytes (framed) the pump's writes returned for so far.
    var produced: std.atomic.Value(usize) = .init(0);
    fn call(_: *anyopaque, req: *const h2.Request, _: *h2.ResponseStream) h2.Status {
        if (!lh_service.ListPump.attachTest(req.stream_id, req.body, answer)) return .unimplemented;
        return .deferred;
    }
    fn answer(_: *lh_service.ListPump, arena: std.mem.Allocator, rs: *h2.ResponseStream) h2.Status {
        const payload = arena.alloc(u8, msg_len) catch return .internal;
        @memset(payload, 'q');
        for (0..messages) |_| {
            rs.message(payload) catch return .cancelled;
            _ = produced.fetchAdd(msg_len + 5, .acq_rel);
        }
        return .ok;
    }
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call };
};

test "List* stream: 8 MiB to a slow reader is sent under flow control, never buffered whole" {
    const gpa = testing.allocator;
    Huge.produced.store(0, .release);
    var server = blk: {
        var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        break :blk try addr.listen(testing.io, .{ .reuse_address = true });
    };
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    const t = try std.Thread.spawn(.{}, struct {
        fn run(s: *std.Io.net.Server) void {
            const st = s.accept(testing.io) catch return;
            h2.server.serveStreamOpts(testing.allocator, testing.io, st, .{}, Huge.handler);
        }
    }.run, .{&server});
    defer t.join();
    var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const st = try caddr.connect(testing.io, .{ .mode = .stream });
    defer st.close(testing.io);

    var req: std.ArrayList(u8) = .empty;
    defer req.deinit(gpa);
    try req.appendSlice(gpa, h2.conn.preface);
    try h2Frame(&req, gpa, 4, 0, 0, &.{}); // default windows: 65,535 per stream and connection
    var hb: std.ArrayList(u8) = .empty;
    defer hb.deinit(gpa);
    try hpack.encodeLiteral(&hb, gpa, ":method", "POST");
    try hpack.encodeLiteral(&hb, gpa, ":path", "/sui.rpc.v2.LedgerService/ListEvents");
    try hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
    try h2Frame(&req, gpa, 1, 4, 1, hb.items);
    try h2Frame(&req, gpa, 0, 1, 1, "\x00\x00\x00\x00\x00");
    try writeAll(st, req.items);

    var in: std.ArrayList(u8) = .empty;
    defer in.deinit(gpa);
    var buf: [16384]u8 = undefined;
    var pos: usize = 0;
    var received: usize = 0;
    var peak: usize = 0;
    var ended = false;
    var status: ?[]const u8 = null;
    while (!ended) {
        const n = try readSome(st, &buf);
        try testing.expect(n > 0);
        try in.appendSlice(gpa, buf[0..n]);
        var credit: usize = 0;
        while (in.items.len - pos >= 9) {
            const h = in.items[pos..][0..9];
            const len = (@as(usize, h[0]) << 16) | (@as(usize, h[1]) << 8) | h[2];
            if (in.items.len - pos < 9 + len) break;
            const fsid = std.mem.readInt(u32, h[5..9], .big) & 0x7fffffff;
            if (h[3] == 0 and fsid == 1) {
                received += len;
                credit += len;
            }
            if (h[3] == 1 and fsid == 1 and h[4] & 1 != 0) {
                ended = true;
                // trailers: grpc-status is a literal in the block; find "0" after its name
                const blk = in.items[pos + 9 ..][0..len];
                if (std.mem.indexOf(u8, blk, "grpc-status")) |i| status = blk[i + 11 ..][1..2];
            }
            pos += 9 + len;
        }
        const ahead = Huge.produced.load(.acquire) -| received;
        peak = @max(peak, ahead);
        // the slow reader: give back only what it read, a little later
        h2.sock.sleepMs(1);
        if (credit > 0) {
            var inc: [4]u8 = undefined;
            std.mem.writeInt(u32, &inc, @intCast(credit), .big);
            var wu: std.ArrayList(u8) = .empty;
            defer wu.deinit(gpa);
            try h2Frame(&wu, gpa, 8, 0, 0, &inc);
            try h2Frame(&wu, gpa, 8, 0, 1, &inc);
            try writeAll(st, wu.items);
        }
    }
    try testing.expectEqual(@as(usize, Huge.messages * (Huge.msg_len + 5)), received);
    try testing.expectEqualStrings("0", status orelse "?");
    // What the server held ahead of the client: the window (65,535), one message queued
    // behind it, and one partly read frame. A buffered answer would be the whole 8 MiB.
    try testing.expect(peak <= 65535 + (Huge.msg_len + 5) + 16384 + 9);
}

/// List* streams that end on their own, by client cancel (RST_STREAM) and with short
/// `grpc-timeout`s, while the client keeps the connection thread reading (PING, WINDOW_UPDATE):
/// every read ends in `wakeAll`, which must never reach a `ListPump` its `done` already freed
/// (ListPump.wakeFn SIGSEGV seen replaying sui-node List* traffic, 2026-11-09).
const Racy = struct {
    var dummy: u8 = 0;
    var runs: std.atomic.Value(u32) = .init(0);
    var calls: std.atomic.Value(u32) = .init(0);
    var unattached: std.atomic.Value(u32) = .init(0);
    var bytes_in: std.atomic.Value(u64) = .init(0);
    fn call(_: *anyopaque, req: *const h2.Request, _: *h2.ResponseStream) h2.Status {
        _ = calls.fetchAdd(1, .monotonic);
        if (!lh_service.ListPump.attachTest(req.stream_id, req.body, answer)) {
            _ = unattached.fetchAdd(1, .monotonic);
            return .unimplemented;
        }
        return .deferred;
    }
    fn answer(j: *lh_service.ListPump, _: std.mem.Allocator, rs: *h2.ResponseStream) h2.Status {
        _ = runs.fetchAdd(1, .acq_rel);
        const b = j.requestBody();
        const k: u8 = if (b.len > 5) b[5] else 0;
        if (k % 3 == 1) h2.sock.sleepMs(1);
        for (0..k % 4) |_| rs.message("\x08\x01") catch return .cancelled;
        return .ok;
    }
    const handler: h2.Handler = .{ .ctx = &dummy, .call = call };
};

fn stressMs() u64 {
    const v = std.c.getenv("ZUI_LISTPUMP_STRESS_MS") orelse return 1500;
    return std.fmt.parseInt(u64, std.mem.span(v), 10) catch 1500;
}

/// One client: connections one after the other until `until_ns`, each with up to 150 streams.
fn racyClient(until_ns: u64, streams_done: *std.atomic.Value(u32), failed: *std.atomic.Value(u32)) void {
    racyClientInner(until_ns, streams_done) catch |err| {
        std.debug.print("listpump stress client: {s}\n", .{@errorName(err)});
        _ = failed.fetchAdd(1, .acq_rel);
    };
}

/// The stress client opens and resets streams far faster than any real peer. On a loaded box the
/// connection thread reads them in large batches, and more than `max_pending_resets` (20) resets
/// of streams opened in one `feed` pass close the connection with GOAWAY(ENHANCE_YOUR_CALM), the
/// rapid reset guard: the client's next write fails (WriteFailed, as many as `reset_closes`;
/// 2026-11-10 on a test machine: 1 to 6 per run, every run). This test is about late
/// pump wakes, not that guard (h2/test_limits.zig covers it), so its server takes every reset.
const racy_opts: h2.server.Options = .{ .h2 = .{ .max_pending_resets = std.math.maxInt(u32) } };

fn racyClientInner(until_ns: u64, streams_done: *std.atomic.Value(u32)) !void {
    const gpa = std.heap.smp_allocator;
    var round: u32 = 0;
    while (h2.meta.monoNs() < until_ns) : (round += 1) {
        var server = blk: {
            var addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
            break :blk try addr.listen(testing.io, .{ .reuse_address = true });
        };
        defer server.deinit(testing.io);
        const port = server.socket.address.getPort();
        const t = try std.Thread.spawn(.{}, struct {
            fn run(s: *std.Io.net.Server) void {
                const st = s.accept(testing.io) catch return;
                h2.server.serveStreamOpts(std.heap.smp_allocator, testing.io, st, racy_opts, Racy.handler);
            }
        }.run, .{&server});
        defer t.join();
        var caddr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
        const st = try caddr.connect(testing.io, .{ .mode = .stream });
        defer st.close(testing.io);
        // a reader that drops everything (the server must never stall on a full socket)
        const rd = try std.Thread.spawn(.{}, struct {
            fn run(s: std.Io.net.Stream) void {
                var buf: [16384]u8 = undefined;
                while (true) {
                    const n = readSome(s, &buf) catch return;
                    if (n == 0) return;
                    _ = Racy.bytes_in.fetchAdd(n, .monotonic);
                }
            }
        }.run, .{st});
        defer rd.join();
        defer st.shutdown(testing.io, .both) catch {};
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try out.appendSlice(gpa, h2.conn.preface);
        try h2Frame(&out, gpa, 4, 0, 0, &.{});
        var hb: std.ArrayList(u8) = .empty;
        defer hb.deinit(gpa);
        const timeouts = [_][]const u8{ "2m", "20m", "100m", "5S" };
        var sid: u32 = 1;
        while (sid < 300 and h2.meta.monoNs() < until_ns) : (sid += 2) {
            hb.clearRetainingCapacity();
            try hpack.encodeLiteral(&hb, gpa, ":method", "POST");
            try hpack.encodeLiteral(&hb, gpa, ":path", "/t.S/List");
            try hpack.encodeLiteral(&hb, gpa, "content-type", "application/grpc");
            try hpack.encodeLiteral(&hb, gpa, "grpc-timeout", timeouts[(sid / 2) % timeouts.len]);
            try h2Frame(&out, gpa, 1, 4, sid, hb.items);
            const kind: u8 = @intCast((sid / 2 + round) % 251);
            try h2Frame(&out, gpa, 0, 1, sid, &.{ 0, 0, 0, 0, 1, kind });
            // a third of the calls: the client cancels at once, or a little later
            if (sid % 3 == 0) try h2Frame(&out, gpa, 3, 0, sid, &.{ 0, 0, 0, 8 });
            if (sid % 7 == 0 and sid > 8) try h2Frame(&out, gpa, 3, 0, sid - 8, &.{ 0, 0, 0, 8 });
            try writeAll(st, out.items);
            out.clearRetainingCapacity();
            // keep the connection thread reading (and so waking every pump) while pumps end
            for (0..8) |i| {
                try h2Frame(&out, gpa, 8, 0, 0, &.{ 0, 0, 0, 1 });
                var ping: [8]u8 = undefined;
                std.mem.writeInt(u64, &ping, (@as(u64, sid) << 8) | i, .big);
                try h2Frame(&out, gpa, 6, 0, 0, &ping);
                try writeAll(st, out.items);
                out.clearRetainingCapacity();
            }
            _ = streams_done.fetchAdd(1, .monotonic);
            // let the workers keep up (a fast client otherwise closes before any pump starts)
            if (sid % 16 == 15) h2.sock.sleepMs(1);
        }
        // pumps end while the connection thread keeps reading; the rest race the close
        for (0..20) |i| {
            try h2Frame(&out, gpa, 8, 0, 0, &.{ 0, 0, 0, 1 });
            var ping: [8]u8 = undefined;
            std.mem.writeInt(u64, &ping, 0xffff_0000 | i, .big);
            try h2Frame(&out, gpa, 6, 0, 0, &ping);
            try writeAll(st, out.items);
            out.clearRetainingCapacity();
            h2.sock.sleepMs(1);
        }
        try h2Frame(&out, gpa, 7, 0, 0, &.{ 0, 0, 0, 0, 0, 0, 0, 0 });
        writeAll(st, out.items) catch {};
    }
}

test "List* pumps: late wakes never reach a freed ListPump (cancels, deadlines, stream ends, closes)" {
    Racy.runs.store(0, .release);
    const until = h2.meta.monoNs() + stressMs() * std.time.ns_per_ms;
    var streams = std.atomic.Value(u32).init(0);
    var failed = std.atomic.Value(u32).init(0);
    // half the time: stall each pump thread right after `done` freed its ListPump
    const flip = try std.Thread.spawn(.{}, struct {
        fn run(u: u64) void {
            var on = false;
            while (h2.meta.monoNs() < u) {
                on = !on;
                h2.server.test_stall_after_done_ms.store(if (on) 1 else 0, .monotonic);
                h2.sock.sleepMs(50);
            }
            h2.server.test_stall_after_done_ms.store(0, .monotonic);
        }
    }.run, .{until});
    var clients: [8]std.Thread = undefined;
    for (&clients) |*c| c.* = try std.Thread.spawn(.{}, racyClient, .{ until, &streams, &failed });
    for (clients) |c| c.join();
    flip.join();
    std.debug.print("listpump stress: {d} streams sent, {d} handler calls ({d} not attached), {d} pumps ran, {d} refused, {d} bytes in, {d} client errors\n", .{ streams.load(.acquire), Racy.calls.load(.acquire), Racy.unattached.load(.acquire), Racy.runs.load(.acquire), h2.server.stats.pumps_refused.load(.acquire), Racy.bytes_in.load(.acquire), failed.load(.acquire) });
    try testing.expectEqual(@as(u32, 0), failed.load(.acquire));
    // enough calls must reach a running pump, or the race this test is for never happens. An
    // absolute floor, not a share of the streams: the share depends on the box's load (6% with
    // four gate shards on a test machine's 32 cores, 963 of 16068); the unpaced client ran 7 of 565k.
    try testing.expect(Racy.runs.load(.acquire) >= 100);
}
