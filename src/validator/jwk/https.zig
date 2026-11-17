//! The real JWK `Transport`: an HTTPS GET with std.http through the node's netguard client (TLS
//! clock refresh, bounded by a hard timeout so a silent server never holds the updater). Cold
//! path (one request per provider per hour); never used by local test committees. Up to 10 redirects are followed
//! (a redirect to plain http is refused), any status is accepted like Rust, and the body is capped at `max_body` bytes.
const std = @import("std");
const node = @import("node");
const updater = @import("updater.zig");
const netguard = node.netguard;

pub const Https = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    client: netguard.Client,
    timeout_ms: u64 = 15_000,
    max_body: usize = 1 << 20,
    /// `https_proxy` / `HTTPS_PROXY` (an `http://host:port` CONNECT proxy), as reqwest honours
    /// them (localnets whose namespaces reach the providers only through a proxy).
    proxy_host: [256]u8 = undefined,
    proxy_len: usize = 0,
    proxy_port: u16 = 0,

    /// In place (the proxy host lives in the struct).
    pub fn init(h: *Https, gpa: std.mem.Allocator, io: std.Io) void {
        h.* = .{ .gpa = gpa, .io = io, .client = netguard.Client.init(gpa, io) };
        if (envProxy()) |p| h.setProxy(p.host, p.port);
    }

    pub fn setProxy(h: *Https, host: []const u8, port: u16) void {
        if (host.len > h.proxy_host.len) return;
        @memcpy(h.proxy_host[0..host.len], host);
        h.proxy_len = host.len;
        h.proxy_port = port;
    }

    pub fn deinit(h: *Https) void {
        h.client.deinit();
    }

    pub fn transport(h: *Https) updater.Transport {
        return .{ .ctx = h, .get = get };
    }

    fn get(ctx: *anyopaque, arena: std.mem.Allocator, url: []const u8) anyerror![]const u8 {
        const h: *Https = @ptrCast(@alignCast(ctx));
        const buf = try h.gpa.alloc(u8, h.max_body);
        defer h.gpa.free(buf);
        var w: std.Io.Writer = .fixed(buf);
        h.client.prepare(netguard.wallMs());
        defer h.client.done(netguard.wallMs());
        var abort: netguard.Abort = .{};
        var tun: Tunnel = .{ .io = h.io, .proxy_host = h.proxy_host[0..h.proxy_len], .proxy_port = h.proxy_port, .timeout_ms = h.timeout_ms };
        defer tun.join();
        const t: ?*Tunnel = if (h.proxy_len != 0) &tun else null;
        const status = netguard.timed(h.io, h.timeout_ms, null, &abort, fetchOnce, .{ &h.client.http, url, &w, &abort, t }) catch |e| {
            h.client.noteError(e, netguard.wallMs());
            return e;
        };
        _ = status; // Rust's fetch_jwks does not check the status; parse_jwks rejects non-JWKS bodies
        return arena.dupe(u8, w.buffered());
    }
};

const HostPort = struct { host: []const u8, port: u16 };

/// `http://host:port` (or `host:port`) from https_proxy / HTTPS_PROXY; null when unset or not
/// in that form.
fn envProxy() ?HostPort {
    const raw = std.c.getenv("https_proxy") orelse std.c.getenv("HTTPS_PROXY") orelse return null;
    return parseProxy(std.mem.span(raw));
}

pub fn parseProxy(v: []const u8) ?HostPort {
    var s = v;
    if (std.mem.startsWith(u8, s, "http://")) s = s["http://".len..];
    s = std.mem.trimEnd(u8, s, "/");
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    if (colon == 0) return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    return .{ .host = s[0..colon], .port = port };
}

test "proxy from the environment's form" {
    const p = parseProxy("http://192.0.2.10:3128").?;
    try std.testing.expectEqualStrings("192.0.2.10", p.host);
    try std.testing.expectEqual(@as(u16, 3128), p.port);
    try std.testing.expect(parseProxy("http://nohost") == null);
    try std.testing.expectEqualStrings("proxy.local", parseProxy("proxy.local:8080/").?.host);
}

fn fetchOnce(c: *std.http.Client, url: []const u8, w: *std.Io.Writer, abort: *netguard.Abort, tun: ?*Tunnel) !std.http.Status {
    const uri = try std.Uri.parse(url);
    var hbuf: [std.Io.net.HostName.max_len]u8 = undefined;
    const tunnel_conn: ?*std.http.Client.Connection = if (tun) |t| blk: {
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.InsecureRedirect;
        const host = try std.Io.net.HostName.fromUri(uri, &hbuf);
        break :blk try t.open(c, host.bytes, uri.port orelse 443);
    } else null;
    var req = try c.request(.GET, uri, .{
        .redirect_behavior = .init(10), // reqwest default: up to 10 redirects
        .headers = .{ .accept_encoding = .omit },
        // through the proxy: the request owns the tunnel connection, closed after the response
        .connection = tunnel_conn,
        .keep_alive = tunnel_conn == null,
    });
    defer req.deinit();
    errdefer if (req.connection) |conn| {
        conn.closing = true;
    };
    try abort.arm(netguard.socketOf(req.connection.?));
    defer abort.disarm();
    try req.sendBodiless();
    var redirect_buf: [8192]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);
    if (!std.ascii.eqlIgnoreCase(req.uri.scheme, "https")) return error.InsecureRedirect;
    if (response.head.content_encoding != .identity) return error.UnsupportedCompressionMethod;
    const reader = response.reader(&.{});
    _ = reader.streamRemaining(w) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr() orelse error.ReadFailed,
        error.WriteFailed => return error.BodyTooLarge,
        else => |e| return e,
    };
    return response.head.status;
}

/// HTTPS through a CONNECT proxy. std.http.Client (zig 0.17.1) opens the CONNECT tunnel but then
/// speaks plain HTTP inside it (`connectProxied` hands the tunnel back as a `.plain` connection),
/// so the TLS connection is made here: `connectTcpOptions` dials a loopback forwarder (TLS host
/// and certificate checks against the provider's name) whose other side has already sent CONNECT
/// to the proxy. The forwarder thread copies bytes both ways and ends when either side closes or
/// goes quiet for `timeout_ms`.
const Tunnel = struct {
    io: std.Io,
    proxy_host: []const u8,
    proxy_port: u16,
    timeout_ms: u64,
    thread: ?std.Thread = null,

    fn open(t: *Tunnel, c: *std.http.Client, host: []const u8, port: u16) !*std.http.Client.Connection {
        const io = t.io;
        try tlsClock(c);
        const ph: std.Io.net.HostName = .{ .bytes = t.proxy_host };
        var up = try ph.connect(io, t.proxy_port, .{ .mode = .stream });
        var up_owned = true;
        defer if (up_owned) up.close(io);
        try connectHandshake(up.socket.handle, host, port, t.timeout_ms);
        const lo = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
        var srv = try lo.listen(io, .{});
        const lport = srv.socket.address.getPort();
        t.thread = std.Thread.spawn(.{}, forward, .{ io, srv, up, t.timeout_ms }) catch |e| {
            srv.deinit(io);
            return e;
        };
        up_owned = false; // the forwarder closes both
        return c.connectTcpOptions(.{
            .host = .{ .bytes = "127.0.0.1" },
            .port = lport,
            .protocol = .tls,
            .proxied_host = .{ .bytes = host },
            .proxied_port = port,
        });
    }

    fn join(t: *Tunnel) void {
        if (t.thread) |th| th.join();
        t.thread = null;
    }
};

/// What `request` does before its first TLS connection: the CA bundle and the clock it checks
/// certificates against.
fn tlsClock(c: *std.http.Client) !void {
    const io = c.io;
    if (c.now != null) return;
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(c.allocator);
    const now = std.Io.Clock.real.now(io);
    bundle.rescan(c.allocator, io, now) catch return error.CertificateBundleLoadFailure;
    try c.ca_bundle_lock.lock(io);
    defer c.ca_bundle_lock.unlock(io);
    c.now = now;
    std.mem.swap(std.crypto.Certificate.Bundle, &c.ca_bundle, &bundle);
}

fn waitReadable(fd: std.posix.socket_t, timeout_ms: u64) bool {
    var fds = [1]std.c.pollfd{.{ .fd = fd, .events = std.c.POLL.IN, .revents = 0 }};
    return std.c.poll(&fds, 1, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) > 0;
}

fn writeAllFd(fd: std.posix.socket_t, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(fd, bytes[off..].ptr, bytes.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}

/// `CONNECT host:port`; the proxy's answer must be a 200.
fn connectHandshake(fd: std.posix.socket_t, host: []const u8, port: u16, timeout_ms: u64) !void {
    var req: [600]u8 = undefined;
    try writeAllFd(fd, try std.fmt.bufPrint(&req, "CONNECT {s}:{d} HTTP/1.1\r\nHost: {s}:{d}\r\n\r\n", .{ host, port, host, port }));
    var buf: [4096]u8 = undefined;
    var n: usize = 0;
    while (std.mem.indexOf(u8, buf[0..n], "\r\n\r\n") == null) {
        if (n == buf.len or !waitReadable(fd, timeout_ms)) return error.ProxyHandshake;
        const r = std.c.read(fd, buf[n..].ptr, buf.len - n);
        if (r <= 0) return error.ProxyHandshake;
        n += @intCast(r);
    }
    if (n < 12 or !std.mem.startsWith(u8, buf[0..n], "HTTP/1.") or !std.mem.eql(u8, buf[9..12], "200")) return error.ProxyRefused;
}

fn forward(io: std.Io, srv_in: std.Io.net.Server, up_in: std.Io.net.Stream, timeout_ms: u64) void {
    var srv = srv_in;
    defer srv.deinit(io);
    var up = up_in;
    defer up.close(io);
    if (!waitReadable(srv.socket.handle, timeout_ms)) return;
    var down = srv.accept(io) catch return;
    defer down.close(io);
    var fds = [2]std.c.pollfd{
        .{ .fd = down.socket.handle, .events = std.c.POLL.IN, .revents = 0 },
        .{ .fd = up.socket.handle, .events = std.c.POLL.IN, .revents = 0 },
    };
    var buf: [16 << 10]u8 = undefined;
    while (true) {
        if (std.c.poll(&fds, 2, @intCast(@min(timeout_ms, std.math.maxInt(i32)))) <= 0) return;
        for (0..2) |i| {
            if (fds[i].revents == 0) continue;
            const r = std.c.read(fds[i].fd, &buf, buf.len);
            if (r <= 0) return;
            writeAllFd(fds[1 - i].fd, buf[0..@intCast(r)]) catch return;
        }
    }
}
