//! Zero-downtime binary upgrade: the new deepwave takes the listening sockets and then the store
//! from the running one.
//!
//! Off unless `--handoff-sock PATH` is given. With it, every start does the same thing:
//!   1. connect to PATH. Nobody there (no such file, connection refused): a plain start.
//!   2. HELLO. The running process answers OFFER with its listening sockets (`serve`, `serve_tls`,
//!      `metrics`) as SCM_RIGHTS descriptors and keeps serving: both processes now hold the same
//!      kernel sockets, so nothing is closed or rebound. A process that is itself stopping (or has
//!      begun tearing down) answers BUSY instead: the successor then waits for its exit (the
//!      directory lock) and starts fresh.
//!   3. RELEASE. The old process starts its normal graceful stop (the SIGTERM path: drain open
//!      calls, finish the checkpoint in hand, flush and close the store), then answers RELEASED.
//!      Its close() of the listening descriptors does not close the sockets (the new process
//!      holds them) and its accept loops poll their stop flag (`Options.poll_accept`): no
//!      shutdown() (it would kill the shared socket on Linux), no wake connection, and no
//!      accept after the stop. Connections that arrive meanwhile wait in the listen queue (raised
//!      to 4096 at RELEASE) and are accepted by the new process: the gap is not zero, it is drain
//!      + store close + the new process's store open and start.
//!   4. The new process takes the directory lock (`DIR/zui.lock`, flock; the old one drops it
//!      after the store is closed), tells systemd it is the main process (MAINPID=, before the
//!      store open; the old process cancels its stop-deadline alarm once released), opens the store (clean close: nothing to replay), starts its
//!      accept loops on the inherited sockets, tells systemd the new main PID (sd_notify
//!      MAINPID=) and sends DONE. The old process exits. The follower resumes at the first
//!      checkpoint after the committed one, so no checkpoint is skipped or applied twice.
//! The directory lock is also taken without a takeover (a second node on the same directory would
//! corrupt the store); a start that finds it held exits with an error.
//!
//! SIGUSR2 on the running process starts the successor itself (nginx style): it forks and execs its
//! own command line (argv[0], or ZUI_SUCCESSOR_EXE) with the same arguments, so a binary replaced
//! on disk (mv over /usr/local/bin/deepwave) is the one that starts. Under systemd the unit needs
//! NotifyAccess=all so MAINPID= from the child is accepted.
//! Not handed over: QUIC/UDP sockets (zui/1 native, anemo p2p listener; they rebind in the new
//! process, peers reconnect) and the admin port.
const std = @import("std");
const builtin = @import("builtin");
const Atomic = std.atomic.Value;

const is_linux = builtin.os.tag == .linux;

pub const max_fds = 8;
const proto_version = 1;

// ------------------------------------------------------------------------------------ libc

const Iovec = extern struct { base: [*]u8, len: usize };

const Msghdr = if (is_linux) extern struct {
    name: ?*anyopaque = null,
    namelen: u32 = 0,
    iov: [*]Iovec,
    iovlen: usize,
    control: ?*anyopaque = null,
    controllen: usize = 0,
    flags: c_int = 0,
} else extern struct {
    name: ?*anyopaque = null,
    namelen: u32 = 0,
    iov: [*]Iovec,
    iovlen: c_int,
    control: ?*anyopaque = null,
    controllen: u32 = 0,
    flags: c_int = 0,
};

const Pollfd = extern struct { fd: c_int, events: i16, revents: i16 };
const Nfds = if (is_linux) c_ulong else c_uint;

const sys = struct {
    extern "c" fn socket(domain: c_int, ty: c_int, proto: c_int) c_int;
    extern "c" fn socketpair(domain: c_int, ty: c_int, proto: c_int, sv: *[2]c_int) c_int;
    extern "c" fn bind(fd: c_int, addr: *const anyopaque, len: u32) c_int;
    extern "c" fn listen(fd: c_int, backlog: c_int) c_int;
    extern "c" fn accept(fd: c_int, addr: ?*anyopaque, len: ?*u32) c_int;
    extern "c" fn connect(fd: c_int, addr: *const anyopaque, len: u32) c_int;
    extern "c" fn sendmsg(fd: c_int, msg: *const Msghdr, flags: c_int) isize;
    extern "c" fn recvmsg(fd: c_int, msg: *Msghdr, flags: c_int) isize;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
    extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
    extern "c" fn poll(fds: [*]Pollfd, n: Nfds, timeout: c_int) c_int;
    extern "c" fn unlink(path: [*:0]const u8) c_int;
    extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
    extern "c" fn mkdir(path: [*:0]const u8, mode: c_uint) c_int;
    extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
    extern "c" fn fcntl(fd: c_int, cmd: c_int, ...) c_int;
    extern "c" fn flock(fd: c_int, op: c_int) c_int;
    extern "c" fn getsockopt(fd: c_int, level: c_int, name: c_int, val: *anyopaque, len: *u32) c_int;
    extern "c" fn geteuid() c_uint;
    extern "c" fn getpid() c_int;
    extern "c" fn fork() c_int;
    extern "c" fn execv(path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
    extern "c" fn _exit(code: c_int) noreturn;
    extern "c" fn waitpid(pid: c_int, status: ?*c_int, options: c_int) c_int;
    extern "c" fn access(path: [*:0]const u8, mode: c_int) c_int;
    extern "c" fn alarm(seconds: c_uint) c_uint;
};

const AF_UNIX = 1;
const SOCK_STREAM = 1;
const SOCK_DGRAM = 2;
const SOL_SOCKET: c_int = if (is_linux) 1 else 0xffff;
const SCM_RIGHTS: c_int = 1;
const SO_PEERCRED = 17;
const MSG_NOSIGNAL: c_int = if (is_linux) 0x4000 else 0;
const F_SETFD = 2;
const FD_CLOEXEC = 1;
const LOCK_EX = 2;
const LOCK_NB = 4;
const POLLIN: i16 = 1;
const POLLHUP: i16 = 0x10;
const O_RDWR = 2;
const O_CREAT: c_int = if (is_linux) 0o100 else 0x200;
const O_CLOEXEC: c_int = if (is_linux) 0o2000000 else 0x1000000;
const WNOHANG = 1;

const hdr_len: usize = if (is_linux) 16 else 12;
fn cmsgAlign(n: usize) usize {
    return if (is_linux) (n + 7) & ~@as(usize, 7) else (n + 3) & ~@as(usize, 3);
}

fn monoMs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

fn sleepMs(ms: u64) void {
    var ts: std.c.timespec = .{ .sec = @intCast(ms / 1000), .nsec = @intCast((ms % 1000) * std.time.ns_per_ms) };
    _ = std.c.nanosleep(&ts, &ts);
}

pub const Error = error{
    Socket,
    PathTooLong,
    Connect,
    Bind,
    Send,
    Recv,
    Timeout,
    BadMessage,
    TooManyFds,
    Locked,
    Refused,
    PeerClosed,
    Spawn,
};

// ------------------------------------------------------------------------------- unix sockets

fn unixAddr(buf: *[128]u8, path: []const u8) Error!u32 {
    const off: usize = if (is_linux) 2 else 2;
    if (path.len + 1 > 100) return error.PathTooLong;
    @memset(buf, 0);
    if (is_linux) {
        std.mem.writeInt(u16, buf[0..2], AF_UNIX, .little);
    } else {
        buf[0] = @intCast(off + path.len + 1);
        buf[1] = AF_UNIX;
    }
    @memcpy(buf[off..][0..path.len], path);
    return @intCast(off + path.len + 1);
}

fn setCloexec(fd: c_int) void {
    _ = sys.fcntl(fd, F_SETFD, @as(c_int, FD_CLOEXEC));
}

/// A listening unix stream socket at `path` (an old file there is replaced), mode 0600.
pub fn listenUnix(path: []const u8) Error!c_int {
    var pz: [128]u8 = undefined;
    if (path.len >= pz.len) return error.PathTooLong;
    @memcpy(pz[0..path.len], path);
    pz[path.len] = 0;
    var ab: [128]u8 = undefined;
    const alen = try unixAddr(&ab, path);
    const fd = sys.socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return error.Socket;
    setCloexec(fd);
    _ = sys.unlink(@ptrCast(&pz));
    if (sys.bind(fd, &ab, alen) != 0) {
        _ = sys.close(fd);
        return error.Bind;
    }
    _ = sys.chmod(@ptrCast(&pz), 0o600);
    if (sys.listen(fd, 4) != 0) {
        _ = sys.close(fd);
        return error.Bind;
    }
    return fd;
}

/// Connects to the unix stream socket at `path`: error.Connect when nobody listens there.
pub fn connectUnix(path: []const u8) Error!c_int {
    var ab: [128]u8 = undefined;
    const alen = try unixAddr(&ab, path);
    const fd = sys.socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return error.Socket;
    setCloexec(fd);
    if (sys.connect(fd, &ab, alen) != 0) {
        _ = sys.close(fd);
        return error.Connect;
    }
    return fd;
}

/// Sends `data` with `fds` attached as one SCM_RIGHTS message.
pub fn sendFds(sock: c_int, data: []const u8, fds: []const c_int) Error!void {
    if (fds.len > max_fds) return error.TooManyFds;
    var iov = [1]Iovec{.{ .base = @constCast(data.ptr), .len = data.len }};
    var ctl: [256]u8 align(8) = undefined;
    var msg: Msghdr = .{ .iov = &iov, .iovlen = 1 };
    if (fds.len > 0) {
        const dlen = fds.len * @sizeOf(c_int);
        const total = cmsgAlign(hdr_len) + cmsgAlign(dlen);
        @memset(ctl[0..total], 0);
        const clen = cmsgAlign(hdr_len) + dlen;
        if (is_linux) {
            std.mem.writeInt(u64, ctl[0..8], clen, .little);
            std.mem.writeInt(i32, ctl[8..12], SOL_SOCKET, .little);
            std.mem.writeInt(i32, ctl[12..16], SCM_RIGHTS, .little);
        } else {
            std.mem.writeInt(u32, ctl[0..4], @intCast(clen), .little);
            std.mem.writeInt(i32, ctl[4..8], SOL_SOCKET, .little);
            std.mem.writeInt(i32, ctl[8..12], SCM_RIGHTS, .little);
        }
        for (fds, 0..) |fd, i| std.mem.writeInt(i32, ctl[cmsgAlign(hdr_len) + i * 4 ..][0..4], fd, .little);
        msg.control = &ctl;
        msg.controllen = @intCast(total);
    }
    const n = sys.sendmsg(sock, &msg, MSG_NOSIGNAL);
    if (n < 0 or @as(usize, @intCast(n)) != data.len) return error.Send;
}

pub const Received = struct { len: usize, nfds: usize, fds: [max_fds]c_int };

/// Receives one message into `buf` and the descriptors attached to it.
pub fn recvFds(sock: c_int, buf: []u8) Error!Received {
    var iov = [1]Iovec{.{ .base = buf.ptr, .len = buf.len }};
    var ctl: [256]u8 align(8) = undefined;
    var msg: Msghdr = .{ .iov = &iov, .iovlen = 1, .control = &ctl, .controllen = ctl.len };
    const n = sys.recvmsg(sock, &msg, 0);
    if (n < 0) return error.Recv;
    var out: Received = .{ .len = @intCast(n), .nfds = 0, .fds = undefined };
    const clen: usize = @intCast(msg.controllen);
    var off: usize = 0;
    while (off + hdr_len <= clen) {
        var len: usize = undefined;
        var level: i32 = undefined;
        var ty: i32 = undefined;
        if (is_linux) {
            len = @intCast(std.mem.readInt(u64, ctl[off..][0..8], .little));
            level = std.mem.readInt(i32, ctl[off + 8 ..][0..4], .little);
            ty = std.mem.readInt(i32, ctl[off + 12 ..][0..4], .little);
        } else {
            len = std.mem.readInt(u32, ctl[off..][0..4], .little);
            level = std.mem.readInt(i32, ctl[off + 4 ..][0..4], .little);
            ty = std.mem.readInt(i32, ctl[off + 8 ..][0..4], .little);
        }
        if (len < hdr_len or off + len > clen) break;
        if (level == SOL_SOCKET and ty == SCM_RIGHTS) {
            const data_off = off + cmsgAlign(hdr_len);
            const cnt = (off + len - data_off) / 4;
            for (0..cnt) |i| {
                const fd = std.mem.readInt(i32, ctl[data_off + i * 4 ..][0..4], .little);
                if (out.nfds < max_fds) {
                    setCloexec(fd);
                    out.fds[out.nfds] = fd;
                    out.nfds += 1;
                } else _ = sys.close(fd);
            }
        }
        off += cmsgAlign(len);
    }
    return out;
}

/// Waits until `fd` is readable or hung up: true; false on timeout.
fn waitReadable(fd: c_int, timeout_ms: u64) bool {
    const deadline = monoMs() + timeout_ms;
    while (true) {
        const left = deadline -| monoMs();
        var p = [1]Pollfd{.{ .fd = fd, .events = POLLIN, .revents = 0 }};
        const r = sys.poll(&p, 1, @intCast(@min(left, 200)));
        if (r > 0) return true;
        if (monoMs() >= deadline) return false;
    }
}

/// One control line (without the newline) read byte by byte, so nothing past it is consumed.
fn readLine(fd: c_int, buf: []u8, timeout_ms: u64) Error![]const u8 {
    const deadline = monoMs() + timeout_ms;
    var n: usize = 0;
    while (true) {
        if (!waitReadable(fd, deadline -| monoMs())) return error.Timeout;
        var b: [1]u8 = undefined;
        const r = sys.read(fd, &b, 1);
        if (r == 0) return error.PeerClosed;
        if (r < 0) return error.Recv;
        if (b[0] == '\n') return buf[0..n];
        if (n == buf.len) return error.BadMessage;
        buf[n] = b[0];
        n += 1;
    }
}

fn writeAll(fd: c_int, data: []const u8) Error!void {
    var off: usize = 0;
    while (off < data.len) {
        const r = sys.write(fd, data[off..].ptr, data.len - off);
        if (r <= 0) return error.Send;
        off += @intCast(r);
    }
}

// ------------------------------------------------------------------------ offers and inherited

pub const Entry = struct { name: []const u8, addr: []const u8, fd: c_int };

const Inh = struct {
    name: [16]u8 = undefined,
    name_len: usize = 0,
    addr: [64]u8 = undefined,
    addr_len: usize = 0,
    fd: c_int = -1,
    taken: bool = false,
};
var inh_list: [max_fds]Inh = @splat(.{});
var inh_n: usize = 0;
/// Set once a takeover has produced descriptors (and until ready() ran).
var took_over: bool = false;
var control_fd: c_int = -1;

pub const Inherited = struct { fd: c_int, addr: []const u8 };

/// The descriptor handed over under `name`, once (null: bind it yourself).
pub fn inherited(name: []const u8) ?Inherited {
    for (inh_list[0..inh_n]) |*e| {
        if (!e.taken and std.mem.eql(u8, e.name[0..e.name_len], name)) {
            e.taken = true;
            return .{ .fd = e.fd, .addr = e.addr[0..e.addr_len] };
        }
    }
    return null;
}

/// Closes handed-over descriptors the new process did not need (its config binds fewer ports).
pub fn closeUnclaimed() void {
    for (inh_list[0..inh_n]) |*e| if (!e.taken and e.fd >= 0) {
        _ = sys.close(e.fd);
        e.fd = -1;
    };
}

fn encodeOffer(out: []u8, entries: []const Entry) Error![]const u8 {
    var w: std.Io.Writer = .fixed(out);
    w.print("OFFER {d}", .{proto_version}) catch return error.BadMessage;
    for (entries) |e| {
        if (e.name.len > 15 or e.addr.len > 63 or std.mem.indexOfAny(u8, e.name, " \n") != null or std.mem.indexOfAny(u8, e.addr, " \n") != null) return error.BadMessage;
        w.print(" {s} {s}", .{ e.name, e.addr }) catch return error.BadMessage;
    }
    w.writeAll("\n") catch return error.BadMessage;
    return w.buffered();
}

fn parseOffer(line: []const u8, fds: []const c_int) Error!void {
    var it = std.mem.tokenizeScalar(u8, std.mem.trimEnd(u8, line, "\n"), ' ');
    const tag = it.next() orelse return error.BadMessage;
    if (!std.mem.eql(u8, tag, "OFFER")) return error.BadMessage;
    const ver = it.next() orelse return error.BadMessage;
    if (!std.mem.eql(u8, ver, "1")) return error.BadMessage;
    inh_n = 0;
    var i: usize = 0;
    while (it.next()) |name| {
        const addr = it.next() orelse return error.BadMessage;
        if (i >= fds.len or i >= max_fds or name.len > 16 or addr.len > 64) return error.BadMessage;
        var e: Inh = .{ .fd = fds[i] };
        @memcpy(e.name[0..name.len], name);
        e.name_len = name.len;
        @memcpy(e.addr[0..addr.len], addr);
        e.addr_len = addr.len;
        inh_list[inh_n] = e;
        inh_n += 1;
        i += 1;
    }
    if (i != fds.len) return error.BadMessage;
}

// ------------------------------------------------------------------------------- directory lock

var lock_fd: c_int = -1;

fn lockPath(buf: []u8, dir: []const u8) ?[:0]u8 {
    return std.fmt.bufPrintSentinel(buf, "{s}/zui.lock", .{dir}, 0) catch null;
}

/// Takes `DIR/zui.lock` exclusively, waiting up to `wait_ms` (0: one try). error.Locked when another
/// process holds it. The lock is released when this process exits or `unlockDir` runs.
pub fn lockDir(dir: []const u8, wait_ms: u64) Error!void {
    if (lock_fd >= 0) return;
    var pb: [512]u8 = undefined;
    const p = lockPath(&pb, dir) orelse return error.PathTooLong;
    var db: [512]u8 = undefined;
    if (std.fmt.bufPrintSentinel(&db, "{s}", .{dir}, 0)) |dz| _ = sys.mkdir(dz.ptr, 0o750) else |_| {}
    const fd = sys.open(p.ptr, O_RDWR | O_CREAT | O_CLOEXEC, @as(c_uint, 0o640));
    if (fd < 0) return error.Locked;
    const deadline = monoMs() + wait_ms;
    while (sys.flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (monoMs() >= deadline) {
            _ = sys.close(fd);
            return error.Locked;
        }
        sleepMs(50);
    }
    lock_fd = fd;
}

pub fn unlockDir() void {
    if (lock_fd >= 0) {
        _ = sys.close(lock_fd);
        lock_fd = -1;
    }
}

// ------------------------------------------------------------------------------- new process

pub const Options = struct {
    dir: []const u8,
    sock: []const u8,
    /// Total time the old process gets to stop and release the store.
    release_timeout_ms: u64 = 300_000,
};

pub const Outcome = enum { fresh, took_over };

/// Closes every descriptor received in an OFFER (a takeover that did not happen).
fn dropInherited() void {
    for (inh_list[0..inh_n]) |*e| if (e.fd >= 0) {
        _ = sys.close(e.fd);
        e.fd = -1;
    };
    inh_n = 0;
}

/// The running process is itself stopping (or has closed its offers): no takeover. Wait for its
/// exit (the directory lock) and start fresh, binding the sockets ourselves.
fn fallbackFresh(fd: c_int, o: Options, why: []const u8) Error!Outcome {
    std.log.warn("handoff: the running deepwave refused the takeover ({s}); waiting for it to exit, then a fresh start", .{why});
    dropInherited();
    _ = sys.close(fd);
    try lockDir(o.dir, o.release_timeout_ms);
    return .fresh;
}

/// Runs before the node opens its store: takeover when a process listens on `sock`, then the
/// directory lock. See the file comment. As soon as the lock is ours the unit's main PID is
/// announced to systemd (sd_notify MAINPID=), before the store open: the old process may exit
/// any moment after RELEASED and systemd must not see that as the main process ending.
pub fn begin(o: Options) Error!Outcome {
    const fd = connectUnix(o.sock) catch {
        try lockDir(o.dir, 0);
        return .fresh;
    };
    errdefer _ = sys.close(fd);
    var hello: [64]u8 = undefined;
    const h = std.fmt.bufPrint(&hello, "HELLO {d} {d}\n", .{ proto_version, sys.getpid() }) catch return error.BadMessage;
    try writeAll(fd, h);
    if (!waitReadable(fd, 15_000)) return error.Timeout;
    var buf: [512]u8 = undefined;
    const r = try recvFds(fd, &buf);
    if (r.len == 0) return error.PeerClosed;
    if (std.mem.startsWith(u8, buf[0..r.len], "BUSY")) {
        for (r.fds[0..r.nfds]) |f| _ = sys.close(f);
        return fallbackFresh(fd, o, "stopping");
    }
    try parseOffer(buf[0..r.len], r.fds[0..r.nfds]);
    std.log.info("handoff: {d} listening sockets received from the running deepwave; asking it to release the store", .{inh_n});
    try writeAll(fd, "RELEASE\n");
    var lb: [64]u8 = undefined;
    const t0 = monoMs();
    const first = try readLine(fd, &lb, o.release_timeout_ms);
    if (std.mem.eql(u8, first, "BUSY")) return fallbackFresh(fd, o, "stopping");
    if (!std.mem.eql(u8, first, "RELEASING")) return error.Refused;
    // RELEASED, or the old process ending (its connection closes): either way the lock decides.
    const rest = readLine(fd, &lb, o.release_timeout_ms -| (monoMs() - t0));
    if (rest) |line| {
        if (!std.mem.eql(u8, line, "RELEASED")) return error.BadMessage;
    } else |e| switch (e) {
        error.PeerClosed => std.log.warn("handoff: the old process closed without RELEASED (it exited); taking the directory lock", .{}),
        else => return e,
    }
    try lockDir(o.dir, o.release_timeout_ms -| (monoMs() - t0));
    control_fd = fd;
    took_over = true;
    var b: [64]u8 = undefined;
    notify(std.fmt.bufPrint(&b, "MAINPID={d}\n", .{sys.getpid()}) catch "");
    std.log.info("handoff: store released by the old process after {d} ms (pid {d} is the unit's main process from here)", .{ monoMs() - t0, sys.getpid() });
    return .took_over;
}

/// The new process serves on the inherited sockets: sd_notify the new main PID, tell the old one
/// it may exit. A no-op when this start was not a takeover.
pub fn ready(status: []const u8) void {
    if (took_over) {
        var b: [160]u8 = undefined;
        const m = std.fmt.bufPrint(&b, "MAINPID={d}\nREADY=1\nSTATUS={s}\n", .{ sys.getpid(), status }) catch "";
        notify(m);
        var d: [48]u8 = undefined;
        if (std.fmt.bufPrint(&d, "DONE {d}\n", .{sys.getpid()})) |line| writeAll(control_fd, line) catch {} else |_| {}
        _ = sys.close(control_fd);
        control_fd = -1;
        took_over = false;
        std.log.info("handoff: pid {d} serving on the inherited sockets; the old process was told to exit", .{sys.getpid()});
    } else {
        var b: [160]u8 = undefined;
        notify(std.fmt.bufPrint(&b, "READY=1\nSTATUS={s}\n", .{status}) catch "");
    }
    closeUnclaimed();
}

/// systemd's sd_notify: one datagram to $NOTIFY_SOCKET (absent: nothing to do).
pub fn notify(msg: []const u8) void {
    const v = std.c.getenv("NOTIFY_SOCKET") orelse return;
    const path = std.mem.span(v);
    if (path.len == 0 or path.len > 100) return;
    var ab: [128]u8 = undefined;
    @memset(&ab, 0);
    var alen: u32 = undefined;
    if (is_linux) {
        std.mem.writeInt(u16, ab[0..2], AF_UNIX, .little);
        @memcpy(ab[2..][0..path.len], path);
        if (path[0] == '@') ab[2] = 0;
        alen = @intCast(2 + path.len);
    } else return;
    const fd = sys.socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) return;
    defer _ = sys.close(fd);
    var iov = [1]Iovec{.{ .base = @constCast(msg.ptr), .len = msg.len }};
    const msghdr: Msghdr = .{ .name = &ab, .namelen = alen, .iov = &iov, .iovlen = 1 };
    _ = sys.sendmsg(fd, &msghdr, MSG_NOSIGNAL);
}

// ------------------------------------------------------------------------------- old process

pub const Hooks = struct {
    ctx: *anyopaque,
    /// The listening sockets to hand over (valid while the call runs); returns the count.
    offers: *const fn (ctx: *anyopaque, out: *[max_fds]Entry) usize,
    /// The new process asked for the store: start the graceful stop. Called with the offer gate
    /// held and the node still alive (see `closeOffers`).
    release: *const fn (ctx: *anyopaque) void,
    /// The node's stop flag (a static, not part of the node): a process that is already stopping
    /// answers BUSY instead of handing over listeners it has shut down.
    stopping: *const Atomic(bool),
};

/// Serializes `offers`/`release` (which read the node) against the node's teardown: `closeOffers`
/// takes it, sets `offers_closed` and from then on the handoff thread never touches `Hooks.ctx`
/// again (the node is freed at the end of main, before `finishActive` ends the thread).
var gate: Atomic(bool) = .init(false);
var offers_closed: Atomic(bool) = .init(false);

fn gateLock() void {
    while (gate.cmpxchgWeak(false, true, .acquire, .monotonic) != null) sleepMs(1);
}
fn gateUnlock() void {
    gate.store(false, .release);
}

/// Called by the node when its stop begins and again before it frees itself: no HELLO or RELEASE
/// is served from the node after this returns (an answer in progress finishes first).
pub fn closeOffers() void {
    gateLock();
    offers_closed.store(true, .release);
    gateUnlock();
}

/// The larger accept queue the handed-over listeners get at RELEASE: connections wait in it while
/// the store closes and the successor opens it.
pub const handover_backlog: c_int = 4096;
pub fn closeFd(fd: c_int) void {
    _ = sys.close(fd);
}
pub fn raiseBacklog(fd: c_int) void {
    _ = sys.listen(fd, handover_backlog);
}

/// True from the moment a successor asked for the store: accept loops must be woken with a
/// connection, never with shutdown() (the sockets are shared).
var releasing: Atomic(bool) = .init(false);
pub fn isReleasing() bool {
    return releasing.load(.acquire);
}

/// SIGUSR2: start a successor.
var usr2: Atomic(bool) = .init(false);
fn onUsr2(_: std.posix.SIG) callconv(.c) void {
    usr2.store(true, .release);
}
pub fn installUsr2() void {
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onUsr2 }, .mask = std.posix.sigemptyset(), .flags = std.posix.SA.RESTART };
    std.posix.sigaction(.USR2, &act, null);
}

/// The command line a successor is started with (set once at startup).
var succ_argv: ?[*:null]const ?[*:0]const u8 = null;

fn dupeZ(gpa: std.mem.Allocator, s: []const u8) ![:0]u8 {
    const out = try gpa.allocSentinel(u8, s.len, 0);
    @memcpy(out, s);
    return out;
}

/// `name` looked up in $PATH as an executable file ("/dir/name"), null when not found.
fn searchPath(gpa: std.mem.Allocator, name: []const u8) ?[:0]u8 {
    const path = std.mem.span(std.c.getenv("PATH") orelse return null);
    var it = std.mem.splitScalar(u8, path, ':');
    while (it.next()) |d| {
        if (d.len == 0 or d[0] != '/') continue;
        const full = std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ d, name }, 0) catch return null;
        if (sys.access(full.ptr, 1) == 0) return full;
        gpa.free(full);
    }
    return null;
}

pub fn setSuccessorArgs(gpa: std.mem.Allocator, args: []const []const u8) !void {
    const v = try gpa.alloc(?[*:0]const u8, args.len + 1);
    for (args, 0..) |a, i| {
        if (i == 0) {
            // ZUI_SUCCESSOR_EXE, else argv[0] (a path, or a name resolved through PATH now: the
            // /proc/self/exe of a replaced binary is the old, deleted inode, and macOS has none).
            const exe: [:0]const u8 = if (std.c.getenv("ZUI_SUCCESSOR_EXE")) |e| try dupeZ(gpa, std.mem.span(e)) else if (std.mem.indexOfScalar(u8, a, '/') != null) try dupeZ(gpa, a) else if (searchPath(gpa, a)) |p| p else blk: {
                if (!is_linux) return error.SuccessorNotFound;
                std.log.warn("handoff: {s} not found in PATH; the successor would be /proc/self/exe (the OLD binary after a replace): set ZUI_SUCCESSOR_EXE", .{a});
                break :blk try dupeZ(gpa, "/proc/self/exe");
            };
            v[0] = exe.ptr;
            std.log.info("handoff: SIGUSR2 starts {s}", .{exe});
        } else v[i] = (try dupeZ(gpa, a)).ptr;
    }
    v[args.len] = null;
    succ_argv = @ptrCast(v.ptr);
}

/// The running process's server (null: off); main calls `finishActive` after the node closed.
pub var active: ?*Server = null;

/// After the store is closed: tell a waiting successor (RELEASED), wait for its DONE, end the thread.
/// A successor that vanished before DONE leaves nothing serving: exit with status 1 (an error the
/// unit and the upgrade script see), not as if the handover had worked.
pub fn finishActive() void {
    unlockDir();
    if (active) |s| {
        s.markReleased();
        const failed = s.finish();
        active = null;
        if (failed) {
            std.log.err("handoff: the successor exited during the takeover; the store is closed and nothing is serving", .{});
            std.process.exit(1);
        }
    }
}

pub const Server = struct {
    gpa: std.mem.Allocator,
    fd: c_int,
    path: []u8,
    hooks: Hooks,
    stop: Atomic(bool) = .init(false),
    released: Atomic(bool) = .init(false),
    handed_over: Atomic(bool) = .init(false),
    /// The successor ended before DONE.
    failed: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    child: Atomic(c_int) = .init(0),
    /// Tests: how long the old side waits for each peer step.
    step_timeout_ms: u64 = 300_000,

    pub fn start(gpa: std.mem.Allocator, path: []const u8, hooks: Hooks) !*Server {
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .fd = try listenUnix(path), .path = try gpa.dupe(u8, path), .hooks = hooks };
        errdefer {
            _ = sys.close(s.fd);
            gpa.free(s.path);
        }
        s.thread = try std.Thread.spawn(.{}, run, .{s});
        std.log.info("handoff: listening on {s} (SIGUSR2 starts a successor)", .{path});
        return s;
    }

    /// The store is closed and the directory lock dropped: tell the successor. The stop-deadline
    /// alarm ends here: the old process now only waits for DONE and must not _exit while the
    /// successor opens the store (under systemd that would be the "main process" dying).
    pub fn markReleased(s: *Server) void {
        unlockDir();
        if (releasing.load(.acquire)) _ = sys.alarm(0);
        s.released.store(true, .release);
    }

    /// Ends the thread (waits for the successor's DONE after a release) and frees the server. The
    /// socket path is removed only when no successor took over (it belongs to the successor then).
    /// True when the successor ended before DONE.
    pub fn finish(s: *Server) bool {
        if (!releasing.load(.acquire)) s.stop.store(true, .release);
        if (s.thread) |t| t.join();
        const failed = s.failed.load(.acquire);
        _ = sys.close(s.fd);
        if (!s.handed_over.load(.acquire) and !releasing.load(.acquire)) {
            var pz: [128]u8 = undefined;
            if (std.fmt.bufPrintSentinel(&pz, "{s}", .{s.path}, 0)) |z| _ = sys.unlink(z.ptr) else |_| {}
        }
        s.gpa.free(s.path);
        s.gpa.destroy(s);
        return failed;
    }

    fn run(s: *Server) void {
        while (!s.stop.load(.acquire)) {
            if (usr2.swap(false, .acq_rel)) s.spawnSuccessor();
            s.reapChild();
            var p = [1]Pollfd{.{ .fd = s.fd, .events = POLLIN, .revents = 0 }};
            if (sys.poll(&p, 1, 200) <= 0) continue;
            const c = sys.accept(s.fd, null, null);
            if (c < 0) continue;
            setCloexec(c);
            defer _ = sys.close(c);
            if (!peerOk(c)) {
                std.log.warn("handoff: refused a connection from another user", .{});
                continue;
            }
            if (serveClient(c, s.hooks, &s.released, &s.stop, s.step_timeout_ms)) |outcome| switch (outcome) {
                .handed_over => {
                    s.handed_over.store(true, .release);
                    return;
                },
                .aborted => {},
            } else |e| {
                std.log.warn("handoff: client ended: {s}", .{@errorName(e)});
                if (releasing.load(.acquire)) {
                    // the stop is under way: nothing to go back to
                    if (e == error.PeerClosed) s.failed.store(true, .release);
                    return;
                }
            }
        }
    }

    fn reapChild(s: *Server) void {
        const pid = s.child.load(.acquire);
        if (pid <= 0) return;
        var st: c_int = 0;
        if (sys.waitpid(pid, &st, WNOHANG) == pid) {
            s.child.store(0, .release);
            std.log.err("handoff: the successor (pid {d}) exited with status {d} before taking over; this process keeps running", .{ pid, st });
        }
    }

    fn spawnSuccessor(s: *Server) void {
        if (s.child.load(.acquire) > 0) {
            std.log.warn("handoff: SIGUSR2 ignored, a successor is already starting", .{});
            return;
        }
        const argv = succ_argv orelse {
            std.log.err("handoff: SIGUSR2 but no successor command line was set", .{});
            return;
        };
        const pid = sys.fork();
        if (pid < 0) {
            std.log.err("handoff: fork failed", .{});
            return;
        }
        if (pid == 0) {
            _ = sys.execv(argv[0].?, argv);
            _ = sys._exit(127);
        }
        s.child.store(pid, .release);
        std.log.info("handoff: successor started (pid {d}, {s})", .{ pid, argv[0].? });
    }
};

fn peerOk(c: c_int) bool {
    if (!is_linux) return true; // the socket file is 0600
    var cred: extern struct { pid: i32, uid: u32, gid: u32 } = undefined;
    var len: u32 = @sizeOf(@TypeOf(cred));
    if (sys.getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return false;
    return cred.uid == sys.geteuid() or cred.uid == 0;
}

pub const ClientOutcome = enum { handed_over, aborted };

/// The old process's side of one connection (public for the tests, which run it on a socketpair).
pub fn serveClient(c: c_int, hooks: Hooks, released: *const Atomic(bool), stop: *const Atomic(bool), step_ms: u64) Error!ClientOutcome {
    var lb: [128]u8 = undefined;
    const hello = try readLine(c, &lb, 15_000);
    if (!std.mem.startsWith(u8, hello, "HELLO 1")) return error.BadMessage;
    var entries: [max_fds]Entry = undefined;
    {
        // The offer is built and sent under the gate: the node's teardown (closeOffers) waits
        // for it, so the descriptors are still open and still ours while they are in flight.
        gateLock();
        defer gateUnlock();
        if (busy(hooks)) return refuse(c);
        const n = hooks.offers(hooks.ctx, &entries);
        var ob: [512]u8 = undefined;
        const line = try encodeOffer(&ob, entries[0..n]);
        var fds: [max_fds]c_int = undefined;
        for (entries[0..n], 0..) |e, i| fds[i] = e.fd;
        try sendFds(c, line, fds[0..n]);
    }
    // The new process may take a while to get ready; an ABORT or a closed connection ends it.
    const t0 = monoMs();
    while (true) {
        if (stop.load(.acquire)) return .aborted;
        const cmd = readLine(c, &lb, 1000) catch |e| switch (e) {
            error.Timeout => if (monoMs() - t0 > step_ms) return error.Timeout else continue,
            else => return e,
        };
        if (std.mem.eql(u8, cmd, "RELEASE")) break;
        if (std.mem.eql(u8, cmd, "ABORT")) return .aborted;
        return error.BadMessage;
    }
    {
        gateLock();
        defer gateUnlock();
        // stopping since the offer (a SIGTERM in between): the listeners are shut down, so the
        // successor must not serve on them
        if (busy(hooks)) return refuse(c);
        releasing.store(true, .release);
        hooks.release(hooks.ctx);
    }
    try writeAll(c, "RELEASING\n");
    const t1 = monoMs();
    while (!released.load(.acquire)) {
        if (monoMs() - t1 > step_ms) return error.Timeout;
        sleepMs(20);
    }
    try writeAll(c, "RELEASED\n");
    const done = readLine(c, &lb, step_ms) catch |e| switch (e) {
        // The successor ended before DONE (a failed store open, a bind error): the store is
        // closed and nothing serves. An error, not a handover (finishActive exits non-zero).
        error.PeerClosed => {
            std.log.err("handoff: successor exited during takeover (its connection closed before DONE)", .{});
            return error.PeerClosed;
        },
        // slow to open (rpc index seed, ledger history): nothing left for this process to do
        error.Timeout => {
            std.log.warn("handoff: no DONE after {d} s; exiting, the successor owns the sockets and the store", .{step_ms / 1000});
            return .handed_over;
        },
        else => return e,
    };
    if (!std.mem.startsWith(u8, done, "DONE")) return error.BadMessage;
    std.log.info("handoff: successor pid {s} is serving", .{std.mem.trim(u8, done[4..], " ")});
    return .handed_over;
}

/// Gate held: no offer may be made (the node is tearing down, or it is stopping on its own and
/// this is not the release that started it).
fn busy(hooks: Hooks) bool {
    return offers_closed.load(.acquire) or (hooks.stopping.load(.acquire) and !releasing.load(.acquire));
}

fn refuse(c: c_int) ClientOutcome {
    writeAll(c, "BUSY\n") catch {};
    return .aborted;
}

// ------------------------------------------------------------------------------------- tests

const TestCtx = struct {
    listeners: [2]c_int,
    released: Atomic(bool) = .init(false),
    release_called: Atomic(bool) = .init(false),
    stopping: Atomic(bool) = .init(false),
};

fn testOffers(ctx: *anyopaque, out: *[max_fds]Entry) usize {
    const t: *TestCtx = @ptrCast(@alignCast(ctx));
    out[0] = .{ .name = "serve", .addr = "127.0.0.1:9100", .fd = t.listeners[0] };
    out[1] = .{ .name = "metrics", .addr = "127.0.0.1:9186", .fd = t.listeners[1] };
    return 2;
}

fn testRelease(ctx: *anyopaque) void {
    const t: *TestCtx = @ptrCast(@alignCast(ctx));
    t.release_called.store(true, .release);
    // the "graceful stop" finishes a moment later
    const th = std.Thread.spawn(.{}, struct {
        fn f(tt: *TestCtx) void {
            sleepMs(100);
            tt.released.store(true, .release);
        }
    }.f, .{t}) catch return;
    th.detach();
}

fn testServer(c: c_int, t: *TestCtx, out: *?(Error!ClientOutcome)) void {
    const stop: Atomic(bool) = .init(false);
    out.* = serveClient(c, .{ .ctx = t, .offers = testOffers, .release = testRelease, .stopping = &t.stopping }, &t.released, &stop, 5000);
}

test "handoff: descriptors cross a socketpair with the offer, release and done steps" {
    // two real listening sockets stand in for serve and metrics
    var pair: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), sys.socketpair(AF_UNIX, SOCK_STREAM, 0, &pair));
    defer _ = sys.close(pair[0]);
    defer _ = sys.close(pair[1]);
    var t: TestCtx = .{ .listeners = undefined };
    var a: [2]c_int = undefined;
    var b: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), sys.socketpair(AF_UNIX, SOCK_STREAM, 0, &a));
    try std.testing.expectEqual(@as(c_int, 0), sys.socketpair(AF_UNIX, SOCK_STREAM, 0, &b));
    defer for ([_]c_int{ a[0], a[1], b[0], b[1] }) |f| {
        _ = sys.close(f);
    };
    t.listeners = .{ a[0], b[0] };
    var res: ?(Error!ClientOutcome) = null;
    const th = try std.Thread.spawn(.{}, testServer, .{ pair[0], &t, &res });
    // new process side, steps of begin() after the connect
    try writeAll(pair[1], "HELLO 1 123\n");
    var buf: [512]u8 = undefined;
    const r = try recvFds(pair[1], &buf);
    try std.testing.expectEqual(@as(usize, 2), r.nfds);
    try parseOffer(buf[0..r.len], r.fds[0..r.nfds]);
    const got = inherited("serve").?;
    try std.testing.expectEqualStrings("127.0.0.1:9100", got.addr);
    try std.testing.expect(inherited("serve") == null);
    try std.testing.expect(inherited("metrics") != null);
    // the received descriptor is the same kernel object: a byte written to the original arrives at its peer
    try writeAll(got.fd, "x");
    var one: [1]u8 = undefined;
    try std.testing.expectEqual(@as(isize, 1), sys.read(a[1], &one, 1));
    try std.testing.expectEqual(@as(u8, 'x'), one[0]);
    try writeAll(pair[1], "RELEASE\n");
    var lb: [64]u8 = undefined;
    try std.testing.expectEqualStrings("RELEASING", try readLine(pair[1], &lb, 5000));
    try std.testing.expectEqualStrings("RELEASED", try readLine(pair[1], &lb, 5000));
    try writeAll(pair[1], "DONE 123\n");
    th.join();
    try std.testing.expect(t.release_called.load(.acquire));
    try std.testing.expectEqual(ClientOutcome.handed_over, res.?  catch unreachable);
    releasing.store(false, .release);
    inh_n = 0;
}

test "handoff: directory lock is exclusive" {
    var dir_buf: [128]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/zui-handoff-test-{d}", .{sys.getpid()});
    try lockDir(dir, 0);
    // a second descriptor on the same file cannot lock while the first holds it
    var pb: [256]u8 = undefined;
    const p = lockPath(&pb, dir).?;
    const fd2 = sys.open(p.ptr, O_RDWR | O_CLOEXEC, @as(c_uint, 0));
    try std.testing.expect(fd2 >= 0);
    try std.testing.expect(sys.flock(fd2, LOCK_EX | LOCK_NB) != 0);
    unlockDir();
    try std.testing.expectEqual(@as(c_int, 0), sys.flock(fd2, LOCK_EX | LOCK_NB));
    _ = sys.close(fd2);
    _ = sys.unlink(p.ptr);
}

test "handoff: a stopping process answers BUSY and offers nothing" {
    var pair: [2]c_int = undefined;
    try std.testing.expectEqual(@as(c_int, 0), sys.socketpair(AF_UNIX, SOCK_STREAM, 0, &pair));
    defer _ = sys.close(pair[0]);
    defer _ = sys.close(pair[1]);
    var t: TestCtx = .{ .listeners = .{ -1, -1 } };
    t.stopping.store(true, .release);
    var res: ?(Error!ClientOutcome) = null;
    const th = try std.Thread.spawn(.{}, testServer, .{ pair[0], &t, &res });
    try writeAll(pair[1], "HELLO 1 123\n");
    var lb: [64]u8 = undefined;
    try std.testing.expectEqualStrings("BUSY", try readLine(pair[1], &lb, 5000));
    th.join();
    try std.testing.expectEqual(ClientOutcome.aborted, res.?  catch unreachable);
    try std.testing.expect(!t.release_called.load(.acquire));
}
