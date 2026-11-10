//! `GET /native/cert-hash` (NATIVE-PROTOCOL.md 1.3): the WebTransport certificate's SHA-256 as 64
//! lowercase hex characters, no newline, with `access-control-allow-origin: *` (dapps fetch it
//! cross-origin before `new WebTransport(url, { serverCertificateHashes })`). Plain HTTP/1.1 on
//! TCP at the native listen address (same host and port number as the UDP listener). One tiny
//! thread; every other path is 404. Dev only: prod uses a WebPKI certificate and needs no hash.
const std = @import("std");
const c = std.c;
const Atomic = std.atomic.Value;

pub const Server = struct {
    fd: c.fd_t,
    hash_hex: [64]u8,
    stop_flag: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,

    /// `ip4` in network order bytes, `port` host order.
    pub fn start(gpa: std.mem.Allocator, ip4: [4]u8, port: u16, hash: [32]u8) !*Server {
        const fd = c.socket(c.AF.INET, c.SOCK.STREAM, 0);
        if (fd < 0) return error.Socket;
        errdefer _ = c.close(fd);
        const one: c_int = 1;
        _ = c.setsockopt(fd, c.SOL.SOCKET, c.SO.REUSEADDR, std.mem.asBytes(&one), @sizeOf(c_int));
        var sa: c.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = @bitCast(ip4) };
        if (c.bind(fd, @ptrCast(&sa), @sizeOf(c.sockaddr.in)) != 0) return error.Bind;
        if (c.listen(fd, 64) != 0) return error.Listen;
        const s = try gpa.create(Server);
        s.* = .{ .fd = fd, .hash_hex = std.fmt.bytesToHex(hash, .lower) };
        s.thread = try std.Thread.spawn(.{}, loop, .{s});
        return s;
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
            s.serveOne(cfd);
            _ = c.close(cfd);
        }
    }

    fn serveOne(s: *Server, fd: c.fd_t) void {
        var buf: [4096]u8 = undefined;
        var n: usize = 0;
        while (n < buf.len) {
            var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
            if ((std.posix.poll(&fds, 2000) catch 0) == 0) return;
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
        const cors = "access-control-allow-origin: *\r\naccess-control-allow-methods: GET, OPTIONS\r\naccess-control-allow-headers: *\r\n";
        var out: [512]u8 = undefined;
        const resp = if (std.mem.eql(u8, method, "OPTIONS"))
            std.fmt.bufPrint(&out, "HTTP/1.1 204 No Content\r\n{s}content-length: 0\r\nconnection: close\r\n\r\n", .{cors}) catch return
        else if (std.mem.eql(u8, path, "/native/cert-hash") and (std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD")))
            std.fmt.bufPrint(&out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncache-control: no-store\r\n{s}content-length: 64\r\nconnection: close\r\n\r\n{s}", .{ cors, if (method[0] == 'H') "" else &s.hash_hex }) catch return
        else
            std.fmt.bufPrint(&out, "HTTP/1.1 404 Not Found\r\n{s}content-length: 0\r\nconnection: close\r\n\r\n", .{cors}) catch return;
        _ = c.write(fd, resp.ptr, resp.len);
    }
};
