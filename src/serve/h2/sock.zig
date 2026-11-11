//! Blocking socket helpers on a raw fd (libc): poll with a timeout, read, write-all without
//! SIGPIPE, TCP_NODELAY, peer-closed probe.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;

pub const Error = error{ Closed, Timeout, Io };

/// TCP_NODELAY, no SIGPIPE, and a 5 s send timeout so a write to a peer that stopped reading
/// returns to `writeAll`, which gives up after `write_stall_limit` such timeouts in a row.
pub fn tune(fd: c.fd_t) void {
    const one: c_int = 1;
    _ = c.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&one), @sizeOf(c_int));
    if (comptime builtin.os.tag.isDarwin()) {
        _ = c.setsockopt(fd, std.posix.SOL.SOCKET, 0x1022, std.mem.asBytes(&one), @sizeOf(c_int)); // SO_NOSIGPIPE
        // `rawWriteSome`: the socket polls writable only with room for one whole chunk.
        const lowat: c_int = darwin_chunk;
        _ = c.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDLOWAT, std.mem.asBytes(&lowat), @sizeOf(c_int));
    }
    const tv: c.timeval = .{ .sec = 5, .usec = 0 };
    _ = c.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&tv), @sizeOf(c.timeval));
}


/// A byte-stream session layered on an accepted fd (TLS 1.3 for `--serve-tls`): once attached,
/// `read`, `writeAll`, `writeSome`, `waitReadable`, `waitConn` and `close` on that fd go through
/// it, so the h2c and HTTP/1.1 paths serve TLS connections unchanged. The record layer itself
/// lives outside this module (native/tcptls.zig); the raw I/O below is what it uses.
pub const Session = struct {
    ctx: *anyopaque,
    vt: *const VTable,
    pub const VTable = struct {
        /// Plaintext into `buf`: blocks until at least one byte (0: closed).
        read: *const fn (ctx: *anyopaque, buf: []u8) Error!usize,
        /// Encrypts and writes all of `bytes` (after what a `write_some` left unsent).
        write: *const fn (ctx: *anyopaque, bytes: []const u8) Error!void,
        /// Never waits for the peer: sends what an earlier call left, then encrypts a first part
        /// of `bytes` and sends what the socket takes now. Returns how many bytes of `bytes` it
        /// took (they are the session's from then on, sent or not); 0 with nothing taken means
        /// the socket is full. An empty `bytes` only sends what was left. Null: `write` is used,
        /// which waits.
        write_some: ?*const fn (ctx: *anyopaque, bytes: []const u8) Error!usize = null,
        /// Bytes `write_some` took and has not sent yet.
        unsent: ?*const fn (ctx: *anyopaque) usize = null,
        /// Plaintext (or a whole record) is buffered: a read would not block.
        buffered: *const fn (ctx: *anyopaque) bool,
        /// Frees the session (the fd is closed by `close`).
        deinit: *const fn (ctx: *anyopaque) void,
    };
};

/// Makes a session for a freshly accepted fd (the TLS handshake runs here, blocking on the
/// connection thread); null refuses the connection.
pub const Acceptor = struct {
    ctx: *anyopaque,
    accept: *const fn (ctx: *anyopaque, fd: c.fd_t) ?*const Session,
};

/// fds with a session; fds past the table are never given one (`attach` fails).
const max_session_fd = 65536;
var sessions: [max_session_fd]std.atomic.Value(?*const Session) = @splat(.init(null));

pub fn attach(fd: c.fd_t, s: *const Session) bool {
    if (fd < 0 or fd >= max_session_fd) return false;
    sessions[@intCast(fd)].store(s, .release);
    return true;
}

inline fn sessionOf(fd: c.fd_t) ?*const Session {
    if (fd < 0 or fd >= max_session_fd) return null;
    return sessions[@intCast(fd)].load(.acquire);
}

fn buffered(fd: c.fd_t) bool {
    const s = sessionOf(fd) orelse return false;
    return s.vt.buffered(s.ctx);
}

/// 5 s send timeouts in a row before a write fails (a peer that reads nothing for 2 min).
pub const write_stall_limit = 24;

/// Waits until `fd` is readable (or hung up). False on timeout.
pub fn waitReadable(fd: c.fd_t, timeout_ms: i32) Error!bool {
    if (buffered(fd)) return true;
    return waitReadableRaw(fd, timeout_ms);
}

/// `waitReadable` on the socket itself (a session's own buffer not counted).
pub fn waitReadableRaw(fd: c.fd_t, timeout_ms: i32) Error!bool {
    var p = [_]c.pollfd{.{ .fd = fd, .events = c.POLL.IN, .revents = 0 }};
    while (true) {
        const r = c.poll(&p, 1, timeout_ms);
        if (r < 0) {
            if (c.errno(r) == .INTR) continue;
            return error.Io;
        }
        return r > 0;
    }
}

/// Reads what is available (blocks if nothing is). 0 means the peer closed.
pub fn read(fd: c.fd_t, buf: []u8) Error!usize {
    if (sessionOf(fd)) |s| return s.vt.read(s.ctx, buf);
    return rawRead(fd, buf);
}

/// `read` without a session.
pub fn rawRead(fd: c.fd_t, buf: []u8) Error!usize {
    while (true) {
        const r = c.read(fd, buf.ptr, buf.len);
        if (r < 0) switch (c.errno(r)) {
            .INTR => continue,
            .AGAIN => return error.Timeout,
            .CONNRESET, .PIPE, .TIMEDOUT => return 0,
            else => return error.Io,
        };
        return @intCast(r);
    }
}

pub fn writeAll(fd: c.fd_t, bytes: []const u8) Error!void {
    if (sessionOf(fd)) |s| return s.vt.write(s.ctx, bytes);
    return rawWriteAll(fd, bytes);
}

/// `writeAll` without a session.
pub fn rawWriteAll(fd: c.fd_t, bytes: []const u8) Error!void {
    const flags: u32 = if (comptime builtin.os.tag == .linux) 0x4000 else 0; // MSG_NOSIGNAL
    var off: usize = 0;
    var stalls: u32 = 0;
    while (off < bytes.len) {
        const r = c.send(fd, bytes[off..].ptr, bytes.len - off, flags);
        if (r < 0) switch (c.errno(r)) {
            .INTR => continue,
            .AGAIN => {
                stalls += 1;
                if (stalls >= write_stall_limit) return error.Closed;
                var p = [_]c.pollfd{.{ .fd = fd, .events = c.POLL.OUT, .revents = 0 }};
                _ = c.poll(&p, 1, 1000);
                continue;
            },
            else => return error.Closed,
        };
        if (r > 0) stalls = 0;
        off += @intCast(r);
    }
}

/// Writes what the socket takes now without waiting; 0 when its send buffer is full.
pub fn writeSome(fd: c.fd_t, bytes: []const u8) Error!usize {
    if (sessionOf(fd)) |s| {
        if (s.vt.write_some) |f| return f(s.ctx, bytes);
        // A session without a non-blocking write takes everything, waiting for the peer.
        try s.vt.write(s.ctx, bytes);
        return bytes.len;
    }
    return rawWriteSome(fd, bytes);
}

/// Bytes a session took in `writeSome` and has not sent yet (a later `writeSome`, also an empty
/// one, sends them).
pub fn unsent(fd: c.fd_t) usize {
    const s = sessionOf(fd) orelse return 0;
    const f = s.vt.unsent orelse return 0;
    return f(s.ctx);
}

/// Largest single send of `rawWriteSome` on Darwin, and the socket's send low-water mark there
/// (`tune`).
const darwin_chunk = 32 << 10;

/// `writeSome` without a session.
pub fn rawWriteSome(fd: c.fd_t, bytes: []const u8) Error!usize {
    if (bytes.len == 0) return 0;
    const nosig: u32 = if (comptime builtin.os.tag == .linux) 0x4000 else 0; // MSG_NOSIGNAL
    const flags: u32 = nosig | @as(u32, std.posix.MSG.DONTWAIT);
    var len = bytes.len;
    if (comptime builtin.os.tag.isDarwin()) {
        // Darwin's MSG_DONTWAIT only refuses a send that finds no room at all: one that fits in
        // part sends that part and then waits for the rest, up to the send timeout (measured: a
        // 256 KiB send into a nearly full buffer returned after the 5 s SO_SNDTIMEO). So send
        // only what is known to fit: the socket polls writable once it has room for its
        // low-water mark, which `tune` set to one chunk (2,048 bytes on a socket it never saw).
        var p = [_]c.pollfd{.{ .fd = fd, .events = c.POLL.OUT, .revents = 0 }};
        const pr = c.poll(&p, 1, 0);
        if (pr < 0) return if (c.errno(pr) == .INTR) 0 else error.Closed;
        if (pr == 0) return 0;
        if (p[0].revents & c.POLL.OUT == 0) return if (p[0].revents & (c.POLL.ERR | c.POLL.HUP | c.POLL.NVAL) != 0) error.Closed else 0;
        var lowat: c_int = 0;
        var sz: c.socklen_t = @sizeOf(c_int);
        if (c.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDLOWAT, std.mem.asBytes(&lowat), &sz) != 0 or lowat <= 0) lowat = 2048;
        len = @min(len, @as(usize, @intCast(lowat)));
    }
    while (true) {
        const r = c.send(fd, bytes.ptr, len, flags);
        if (r < 0) switch (c.errno(r)) {
            .INTR => continue,
            .AGAIN => return 0,
            else => return error.Closed,
        };
        return @intCast(r);
    }
}

/// True when the peer has closed or reset (a pending EOF or error); data waiting to be read does
/// not count (a pipelined next request).
pub fn peerClosed(fd: c.fd_t) bool {
    var p = [_]c.pollfd{.{ .fd = fd, .events = c.POLL.IN, .revents = 0 }};
    const r = c.poll(&p, 1, 0);
    if (r <= 0) return false;
    if (p[0].revents & (c.POLL.ERR | c.POLL.HUP | c.POLL.NVAL) != 0) return true;
    var b: [1]u8 = undefined;
    const n = c.recv(fd, &b, 1, std.posix.MSG.PEEK | std.posix.MSG.DONTWAIT);
    return n == 0;
}

pub fn shutdown(fd: c.fd_t) void {
    _ = c.shutdown(fd, 2); // SHUT_RDWR
}

pub fn close(fd: c.fd_t) void {
    if (sessionOf(fd)) |s| {
        sessions[@intCast(fd)].store(null, .release);
        s.vt.deinit(s.ctx);
    }
    _ = c.close(fd);
}

pub fn sleepMs(ms: u64) void {
    var ts: c.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = c.nanosleep(&ts, &ts);
}

/// A wake-up fd pair for a thread that waits in `waitConn`: eventfd on Linux (one fd), a
/// non-blocking pipe elsewhere. `r` is polled, `w` is written. Null when the system is out of fds
/// (the caller then falls back to short poll timeouts).
pub const Wake = struct {
    r: c.fd_t,
    w: c.fd_t,

    pub fn open() ?Wake {
        if (comptime builtin.os.tag == .linux) {
            const fd = c.eventfd(0, 0x800 | 0x80000); // EFD_NONBLOCK | EFD_CLOEXEC
            if (fd < 0) return null;
            return .{ .r = fd, .w = fd };
        }
        var fds: [2]c.fd_t = undefined;
        if (c.pipe(&fds) != 0) return null;
        for (fds) |fd| {
            const fl = c.fcntl(fd, c.F.GETFL);
            _ = c.fcntl(fd, c.F.SETFL, fl | @as(c_int, @bitCast(c.O{ .NONBLOCK = true })));
            _ = c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC));
        }
        return .{ .r = fds[0], .w = fds[1] };
    }

    pub fn close(k: Wake) void {
        _ = c.close(k.r);
        if (k.w != k.r) _ = c.close(k.w);
    }

    /// Wakes the waiter (never blocks; a full pipe already means "woken").
    pub fn signal(k: Wake) void {
        const one: u64 = 1;
        const n: usize = if (comptime builtin.os.tag == .linux) 8 else 1;
        _ = c.write(k.w, std.mem.asBytes(&one).ptr, n);
    }

    /// Clears pending wake-ups.
    pub fn clear(k: Wake) void {
        var b: [64]u8 = undefined;
        while (c.read(k.r, &b, b.len) > 0) {}
    }
};

pub const Ready = struct { readable: bool = false, writable: bool = false, woken: bool = false };

/// Waits until `fd` is readable when `want_in` (a hang-up or an error always reports readable),
/// writable when `want_out`, or `wake` fires.
pub fn waitConn(fd: c.fd_t, want_in: bool, want_out: bool, wake: ?Wake, timeout_ms: i32) Error!Ready {
    if (want_in and buffered(fd)) return .{ .readable = true };
    var ev: i16 = 0;
    if (want_in) ev |= c.POLL.IN;
    if (want_out) ev |= c.POLL.OUT;
    var p = [_]c.pollfd{
        .{ .fd = fd, .events = ev, .revents = 0 },
        .{ .fd = if (wake) |k| k.r else -1, .events = c.POLL.IN, .revents = 0 },
    };
    const n: c_uint = if (wake != null) 2 else 1;
    while (true) {
        const r = c.poll(&p, n, timeout_ms);
        if (r < 0) {
            if (c.errno(r) == .INTR) continue;
            return error.Io;
        }
        const bad = c.POLL.ERR | c.POLL.HUP | c.POLL.NVAL;
        return .{
            .readable = p[0].revents & (c.POLL.IN | bad) != 0,
            .writable = p[0].revents & c.POLL.OUT != 0,
            .woken = n == 2 and p[1].revents & c.POLL.IN != 0,
        };
    }
}

/// The address of the socket's peer as text into `out` ("1.2.3.4:5678", "[hex groups]:5678";
/// left empty when the kernel does not say): `conn.Request.peer`.
pub fn peerText(fd: std.c.fd_t, out: *@import("conn.zig").Peer) void {
    var ss: std.c.sockaddr.storage = undefined;
    var len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);
    if (std.c.getpeername(fd, @ptrCast(&ss), &len) != 0) return;
    var b: [54]u8 = undefined;
    const sa: *const std.c.sockaddr = @ptrCast(&ss);
    if (sa.family == std.c.AF.INET) {
        const in: *const std.c.sockaddr.in = @ptrCast(@alignCast(&ss));
        const a: [4]u8 = @bitCast(in.addr);
        out.set(std.fmt.bufPrint(&b, "{d}.{d}.{d}.{d}:{d}", .{ a[0], a[1], a[2], a[3], std.mem.bigToNative(u16, in.port) }) catch return);
    } else if (sa.family == std.c.AF.INET6) {
        const in6: *const std.c.sockaddr.in6 = @ptrCast(@alignCast(&ss));
        var w: std.Io.Writer = .fixed(&b);
        w.writeByte('[') catch return;
        for (0..8) |i| {
            if (i > 0) w.writeByte(':') catch return;
            w.print("{x}", .{std.mem.readInt(u16, in6.addr[2 * i ..][0..2], .big)}) catch return;
        }
        w.print("]:{d}", .{std.mem.bigToNative(u16, in6.port)}) catch return;
        out.set(w.buffered());
    }
}
