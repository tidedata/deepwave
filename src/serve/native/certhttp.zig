//! `GET /native/cert-hash` (NATIVE-PROTOCOL.md 1.3): the WebTransport certificate's SHA-256 as 64
//! lowercase hex characters, no newline, with `access-control-allow-origin: *` (dapps fetch it
//! cross-origin before `new WebTransport(url, { serverCertificateHashes })`). Plain HTTP/1.1 on
//! TCP at the native listen address (same host and port number as the UDP listener). One tiny
//! thread; every other path is 404. Dev only: prod uses a WebPKI certificate and needs no hash.
//! The certificate rotates (certs.zig): the hash is read per request, and
//! `GET /native/cert-hashes` lists the current and the next one, a line each:
//! `<sha256 hex> <from> <until>` (the unix seconds between which the node presents it).
//! With `--native-cert` there is no hash to pin and both answer 204 with no body: a page that
//! still fetches the hash then gets an empty string and connects without
//! `serverCertificateHashes`, which is right for a WebPKI certificate. (The real certificate's
//! hash would make Chrome apply its pinned-certificate rules, at most 14 days of validity, and
//! refuse it; a 404 would fail deployed pages at the fetch.)
//!
//! With an rpc dispatcher (`--native-http-rpc`, docs/EDGE.md section 7) the same listener also
//! answers `POST /zui1/rpc`: the body is one zui/1 request exactly as a stream carries it (varint
//! method, varint flags, body), the response body is the zui/1 response bytes. That is how
//! Cloudflare Workers and plain `fetch` callers reach verified mode (they cannot open QUIC):
//! plain HTTP/1.1 behind the operator's TLS terminator, one thread per connection (at most
//! `max_conns` at once), only the methods that never block for long (no dry_run, submit,
//! subscribe, pair_relay or edge feed).
const std = @import("std");
const c = std.c;
const Atomic = std.atomic.Value;
const dispatch = @import("dispatch.zig");
const proto = @import("proto.zig");
const certs_mod = @import("certs.zig");

pub const max_conns = 64;
const max_body = 128 << 10;
/// One connection gets this long, in total, for its head, its body and its answer: a client that
/// trickles bytes cannot hold a thread (and one of the `max_conns` slots) for longer.
const conn_budget_ms: i64 = 10_000;

fn monoMs() i64 {
    var ts: c.timespec = undefined;
    _ = c.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

/// Milliseconds left until `deadline` (0 or less: out of time).
fn leftMs(deadline: i64) i32 {
    return @intCast(@min(@max(deadline - monoMs(), 0), conn_budget_ms));
}

/// Waits for `fd` to become readable until `deadline`; false on timeout or error.
fn waitReadable(fd: c.fd_t, deadline: i64) bool {
    const left = leftMs(deadline);
    if (left <= 0) return false;
    var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    return (std.posix.poll(&fds, left) catch 0) != 0;
}

fn setTimeouts(fd: c.fd_t) void {
    const tv: c.timeval = .{ .sec = @intCast(@divTrunc(conn_budget_ms, 1000)), .usec = 0 };
    _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(c.timeval));
    _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(c.timeval));
}

/// `Content-Length` of an HTTP/1.1 request head (case-insensitive), or null.
fn contentLength(head: []const u8) ?usize {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next();
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], "content-length")) continue;
        return std.fmt.parseInt(usize, std.mem.trim(u8, line[colon + 1 ..], " \t"), 10) catch null;
    }
    return null;
}

fn writeAll(fd: c.fd_t, b: []const u8) void {
    var off: usize = 0;
    while (off < b.len) {
        const k = c.write(fd, b[off..].ptr, b.len - off);
        if (k <= 0) return;
        off += @intCast(k);
    }
}

pub const Server = struct {
    fd: c.fd_t,
    hash_hex: [64]u8,
    /// The rotating certificate; null: `hash_hex`, fixed at start.
    certs: ?*certs_mod.Certs = null,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    gpa: std.mem.Allocator = undefined,
    rpc: ?*dispatch.Dispatcher = null,
    live: Atomic(u32) = .init(0),
    /// The fds of live connection threads (-1: free slot), so `stop` can cut them off.
    open_fds: [max_conns]Atomic(c.fd_t) = @splat(.init(-1)),

    /// `ip4` in network order bytes, `port` host order.
    pub fn start(gpa: std.mem.Allocator, ip4: [4]u8, port: u16, hash: [32]u8) !*Server {
        return startRpc(gpa, ip4, port, hash, null);
    }

    pub fn startRpc(gpa: std.mem.Allocator, ip4: [4]u8, port: u16, hash: [32]u8, rpc: ?*dispatch.Dispatcher) !*Server {
        return startInner(gpa, ip4, port, hash, null, rpc);
    }

    /// As `startRpc`, with the hashes read from `cs` at every request (they change at a rotation).
    pub fn startCerts(gpa: std.mem.Allocator, ip4: [4]u8, port: u16, cs: *certs_mod.Certs, rpc: ?*dispatch.Dispatcher) !*Server {
        return startInner(gpa, ip4, port, @splat(0), cs, rpc);
    }

    fn startInner(gpa: std.mem.Allocator, ip4: [4]u8, port: u16, hash: [32]u8, cs: ?*certs_mod.Certs, rpc: ?*dispatch.Dispatcher) !*Server {
        const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
        if (fd < 0) return error.Socket;
        errdefer _ = c.close(fd);
        const one: c_int = 1;
        _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(c_int));
        var sa: c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(ip4) };
        if (c.bind(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)) != 0) return error.Bind;
        if (c.listen(fd, 64) != 0) return error.Listen;
        const s = try gpa.create(Server);
        s.* = .{ .fd = fd, .hash_hex = std.fmt.bytesToHex(hash, .lower), .certs = cs, .gpa = gpa, .rpc = rpc };
        s.thread = try std.Thread.spawn(.{}, loop, .{s});
        return s;
    }

    /// The TCP port bound (tests bind port 0).
    pub fn boundPort(s: *const Server) u16 {
        var sa: c.sockaddr.in = undefined;
        var len: c.socklen_t = @sizeOf(c.sockaddr.in);
        if (c.getsockname(s.fd, @ptrCast(&sa), &len) != 0) return 0;
        return std.mem.bigToNative(u16, sa.port);
    }

    pub fn stop(s: *Server, gpa: std.mem.Allocator) void {
        s.stop_flag.store(true, .release);
        _ = c.shutdown(s.fd, 2);
        if (s.thread) |t| t.join();
        _ = c.close(s.fd);
        gpa.destroy(s);
    }

    fn loop(s: *Server) void {
        while (!s.stop_flag.load(.acquire)) {
            var fds = [1]std.posix.pollfd{.{ .fd = s.fd, .events = std.posix.POLL.IN, .revents = 0 }};
            const r = std.posix.poll(&fds, 200) catch 0;
            if (r == 0) continue;
            const cfd = c.accept(s.fd, null, null);
            if (cfd < 0) continue;
            if (s.rpc == null) {
                setTimeouts(cfd);
                s.serveOne(cfd, monoMs() + 2000);
                _ = c.close(cfd);
                continue;
            }
            if (s.live.load(.acquire) >= max_conns) {
                _ = c.close(cfd);
                continue;
            }
            _ = s.live.fetchAdd(1, .acq_rel);
            const t = std.Thread.spawn(.{}, connThread, .{ s, cfd }) catch {
                _ = s.live.fetchSub(1, .acq_rel);
                _ = c.close(cfd);
                continue;
            };
            t.detach();
        }
        // let the connection threads finish before the server memory goes
        // shutting a socket down wakes its blocked reads and writes at once
        while (s.live.load(.acquire) != 0) {
            for (&s.open_fds) |*slot| {
                const f = slot.load(.acquire);
                if (f >= 0) _ = c.shutdown(f, 2);
            }
            _ = std.posix.poll(&.{}, 10) catch 0;
        }
    }

    fn connThread(s: *Server, fd: c.fd_t) void {
        var mine: ?*Atomic(c.fd_t) = null;
        for (&s.open_fds) |*slot| {
            if (slot.cmpxchgStrong(-1, fd, .acq_rel, .monotonic) == null) {
                mine = slot;
                break;
            }
        }
        defer {
            if (mine) |m| m.store(-1, .release);
            _ = c.close(fd);
            _ = s.live.fetchSub(1, .acq_rel);
        }
        setTimeouts(fd);
        s.serveOne(fd, monoMs() + conn_budget_ms);
    }

    /// `POST /zui1/rpc`: `head` holds `n` bytes already read (the head and maybe a body prefix).
    fn serveRpc(s: *Server, fd: c.fd_t, head: []u8, n: usize, cors: []const u8, deadline: i64) void {
        const d = s.rpc.?;
        const end = (std.mem.indexOf(u8, head[0..n], "\r\n\r\n") orelse return) + 4;
        const want = contentLength(head[0..end]) orelse return httpError(fd, "411 Length Required", cors);
        if (want == 0 or want > max_body) return httpError(fd, "413 Payload Too Large", cors);
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        const body = a.alloc(u8, want) catch return httpError(fd, "503 Service Unavailable", cors);
        const have = @min(n - end, want);
        @memcpy(body[0..have], head[end..][0..have]);
        var got = have;
        while (got < want) {
            if (!waitReadable(fd, deadline)) return;
            const k = c.read(fd, body[got..].ptr, want - got);
            if (k <= 0) return;
            got += @intCast(k);
        }
        const req = proto.parseRequest(body) orelse return httpError(fd, "400 Bad Request", cors);
        // long-running methods belong to the QUIC listener's worker threads
        if (dispatch.slowMethod(req.method) or dispatch.feedMethod(req.method) or req.method == .subscribe or req.method == .pair_relay)
            return httpError(fd, "403 Forbidden", cors);
        var out: std.ArrayList(u8) = .empty;
        d.handle(a, req, null, &out);
        var hb: [256]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncache-control: no-store\r\n{s}content-length: {d}\r\nconnection: close\r\n\r\n", .{ cors, out.items.len }) catch return;
        writeAll(fd, h);
        writeAll(fd, out.items);
    }

    fn httpError(fd: c.fd_t, status: []const u8, cors: []const u8) void {
        var hb: [256]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "HTTP/1.1 {s}\r\n{s}content-length: 0\r\nconnection: close\r\n\r\n", .{ status, cors }) catch return;
        writeAll(fd, h);
    }

    /// The body of `/native/cert-hash` (64 hex characters, no newline: deployed pages pass the
    /// whole body as one hash) or, with `all`, of `/native/cert-hashes`. Empty: there is no
    /// hash to pin (`--native-cert`).
    fn hashBody(s: *Server, buf: *[256]u8, all: bool) []const u8 {
        const v: certs_mod.View = if (s.certs) |cs| cs.view() else {
            if (!all) return &s.hash_hex;
            return std.fmt.bufPrint(buf, "{s}\n", .{&s.hash_hex}) catch unreachable;
        };
        if (v.n == 0) return "";
        if (!all) return std.fmt.bufPrint(buf, "{x}", .{&v.sha256[0]}) catch unreachable;
        var n: usize = 0;
        for (0..v.n) |i| n += (std.fmt.bufPrint(buf[n..], "{x} {d} {d}\n", .{ &v.sha256[i], v.from[i], v.until[i] }) catch unreachable).len;
        return buf[0..n];
    }

    fn serveOne(s: *Server, fd: c.fd_t, deadline: i64) void {
        var buf: [4096]u8 = undefined;
        var n: usize = 0;
        while (n < buf.len) {
            if (!waitReadable(fd, deadline)) return;
            const k = c.read(fd, buf[n..].ptr, buf.len - n);
            if (k <= 0) return;
            n += @intCast(k);
            if (std.mem.indexOf(u8, buf[0..n], "\r\n\r\n") != null) break;
        }
        const req = buf[0..n];
        const line_end = std.mem.indexOf(u8, req, "\r\n") orelse return;
        var parts = std.mem.splitScalar(u8, req[0..line_end], ' ');
        const method = parts.next() orelse return;
        const target = parts.next() orelse return;
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
        const cors = "access-control-allow-origin: *\r\naccess-control-allow-methods: GET, POST, OPTIONS\r\naccess-control-allow-headers: *\r\n";
        if (s.rpc != null and std.mem.eql(u8, method, "POST") and std.mem.eql(u8, path, "/zui1/rpc")) return s.serveRpc(fd, buf[0..], n, cors, deadline);
        var out: [1024]u8 = undefined;
        const get = std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD");
        var body_buf: [256]u8 = undefined;
        const resp = if (std.mem.eql(u8, method, "OPTIONS"))
            std.fmt.bufPrint(&out, "HTTP/1.1 204 No Content\r\n{s}content-length: 0\r\nconnection: close\r\n\r\n", .{cors}) catch return
        else if (get and (std.mem.eql(u8, path, "/native/cert-hash") or std.mem.eql(u8, path, "/native/cert-hashes"))) blk: {
            const body = s.hashBody(&body_buf, path.len == "/native/cert-hashes".len);
            if (body.len == 0) break :blk std.fmt.bufPrint(&out, "HTTP/1.1 204 No Content\r\ncache-control: no-store\r\n{s}content-length: 0\r\nconnection: close\r\n\r\n", .{cors}) catch return;
            break :blk std.fmt.bufPrint(&out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncache-control: no-store\r\n{s}content-length: {d}\r\nconnection: close\r\n\r\n{s}", .{ cors, body.len, if (method[0] == 'H') "" else body }) catch return;
        } else
            std.fmt.bufPrint(&out, "HTTP/1.1 404 Not Found\r\n{s}content-length: 0\r\nconnection: close\r\n\r\n", .{cors}) catch return;
        _ = c.write(fd, resp.ptr, resp.len);
    }
};
