//! Batched UDP I/O on a raw socket: macOS sendmsg_x/recvmsg_x, Linux sendmmsg/recvmmsg plus UDP
//! GSO (UDP_SEGMENT), one datagram per syscall elsewhere. A QUIC endpoint writes datagrams into a
//! TxBatch in place (no copy), sends the batch with one syscall, and drains the socket with one
//! receive syscall per batch. Receives block in the kernel with SO_RCVTIMEO as the timer, so an
//! idle request/response round trip costs one receive and one send syscall per side (no poll).
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const net = std.Io.net;

pub const max_batch = 32;
/// Largest datagram either side sends (transport parameter max_udp_payload_size we advertise).
pub const max_dgram = 1500;
/// Receive slot size: a datagram over `max_dgram` arrives truncated and is dropped.
pub const rx_slot = 2048;

const is_darwin = builtin.os.tag.isDarwin();
const is_linux = builtin.os.tag == .linux;

pub const Addr = extern union {
    any: posix.sockaddr,
    in: posix.sockaddr.in,
    in6: posix.sockaddr.in6,
};

pub fn toPosix(a: *const net.IpAddress, out: *Addr) posix.socklen_t {
    switch (a.*) {
        .ip4 => |v| {
            out.in = .{ .port = std.mem.nativeToBig(u16, v.port), .addr = @bitCast(v.bytes) };
            return @sizeOf(posix.sockaddr.in);
        },
        .ip6 => |v| {
            out.in6 = .{ .port = std.mem.nativeToBig(u16, v.port), .flowinfo = v.flow, .addr = v.bytes, .scope_id = 0 };
            return @sizeOf(posix.sockaddr.in6);
        },
    }
}

pub fn fromPosix(a: *const Addr) net.IpAddress {
    if (a.any.family == posix.AF.INET6) return .{ .ip6 = .{ .port = std.mem.bigToNative(u16, a.in6.port), .bytes = a.in6.addr, .flow = a.in6.flowinfo } };
    return .{ .ip4 = .{ .port = std.mem.bigToNative(u16, a.in.port), .bytes = @bitCast(a.in.addr) } };
}

/// Darwin's batched message header (xnu bsd/sys/socket_private.h).
const msghdr_x = extern struct {
    name: ?*anyopaque,
    namelen: posix.socklen_t,
    iov: [*]posix.iovec,
    iovlen: c_int,
    control: ?*anyopaque,
    controllen: posix.socklen_t,
    flags: c_int,
    datalen: usize,
};
const darwin = struct {
    extern "c" fn recvmsg_x(s: c_int, msgp: [*]msghdr_x, cnt: c_uint, flags: c_int) isize;
    extern "c" fn sendmsg_x(s: c_int, msgp: [*]const msghdr_x, cnt: c_uint, flags: c_int) isize;
};

// The Linux paths call raw syscalls (std.os.linux), which return -errno in a usize: their result
// must go through linux.errno, never posix.errno, which reads libc's errno once libc is linked
// (the node links it) and took EAGAIN for a huge datagram count.

pub const Stats = struct {
    send_calls: u64 = 0,
    recv_calls: u64 = 0,
    sent: u64 = 0,
    received: u64 = 0,
};

/// One socket's batching state. Owns no buffers beyond its own fixed arrays.
pub const Sock = struct {
    fd: posix.fd_t,
    /// Linux UDP GSO available (probed once).
    gso: bool = false,
    /// Current SO_RCVTIMEO in ms (0: not set yet).
    rcvtimeo_ms: u32 = 0,
    stats: Stats = .{},

    pub fn init(fd: posix.fd_t) Sock {
        var s: Sock = .{ .fd = fd };
        if (is_linux) {
            var v: c_int = 0;
            var l: posix.socklen_t = @sizeOf(c_int);
            const rc = std.os.linux.getsockopt(fd, posix.IPPROTO.UDP, std.os.linux.UDP.SEGMENT, @ptrCast(&v), &l);
            s.gso = std.os.linux.errno(rc) == .SUCCESS;
        }
        return s;
    }

    /// Waits shorter than this go through `waitShort` on Linux.
    pub const coarse_ns = 10 * std.time.ns_per_ms;

    /// Linux: waits until the socket is readable or `wait_ns` have passed, on a high-resolution
    /// timer (ppoll), and returns true; the caller then receives without blocking. A socket
    /// receive timeout is counted in jiffies there and fires one to two jiffies after it was
    /// set: 4 to 8 ms at HZ=250 for a wait of 1 ms, which starved the pacer (cc.zig) and made
    /// every delayed ACK late. Returns false where SO_RCVTIMEO is exact enough (other
    /// systems), and for long waits, which stay one syscall.
    pub fn waitShort(s: *Sock, wait_ns: u64) bool {
        if (!is_linux or wait_ns >= coarse_ns) return false;
        const linux = std.os.linux;
        var fds = [_]linux.pollfd{.{ .fd = s.fd, .events = linux.POLL.IN, .revents = 0 }};
        var ts: linux.timespec = .{ .sec = 0, .nsec = @intCast(wait_ns) };
        _ = linux.ppoll(&fds, 1, &ts, null);
        return true;
    }

    /// Sets the blocking receive timeout, quantised down to a few buckets so a moving timer
    /// deadline does not cost a setsockopt per loop.
    pub fn setWait(s: *Sock, wait_ns: u64) void {
        const want_ms: u64 = @max(1, wait_ns / std.time.ns_per_ms);
        const buckets = [_]u32{ 50, 25, 10, 5, 2, 1 };
        var ms: u32 = 1;
        for (buckets) |b| if (want_ms >= b) {
            ms = b;
            break;
        };
        if (ms == s.rcvtimeo_ms) return;
        const tv: posix.timeval = .{ .sec = 0, .usec = @intCast(@as(u32, ms) * 1000) };
        posix.setsockopt(s.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&tv)) catch return;
        s.rcvtimeo_ms = ms;
    }
};

pub const TxBatch = struct {
    /// Datagrams packed back to back (a GSO run needs contiguous segments).
    buf: [max_batch * max_dgram]u8 align(16) = undefined,
    off: [max_batch + 1]u32 = @splat(0),
    addrs: [max_batch]Addr = undefined,
    alens: [max_batch]posix.socklen_t = undefined,
    n: usize = 0,

    pub fn full(b: *const TxBatch) bool {
        return b.n == max_batch;
    }

    /// Room for the next datagram (`max_dgram` bytes), written in place by the caller.
    pub fn slot(b: *TxBatch) []u8 {
        std.debug.assert(b.n < max_batch);
        return b.buf[b.off[b.n]..][0..max_dgram];
    }

    pub fn commit(b: *TxBatch, len: usize, addr: *const net.IpAddress) void {
        b.alens[b.n] = toPosix(addr, &b.addrs[b.n]);
        b.off[b.n + 1] = b.off[b.n] + @as(u32, @intCast(len));
        b.n += 1;
    }

    fn dlen(b: *const TxBatch, i: usize) usize {
        return b.off[i + 1] - b.off[i];
    }

    fn sameAddr(b: *const TxBatch, i: usize, j: usize) bool {
        return b.alens[i] == b.alens[j] and std.mem.eql(u8, std.mem.asBytes(&b.addrs[i])[0..b.alens[i]], std.mem.asBytes(&b.addrs[j])[0..b.alens[j]]);
    }

    /// Sends every queued datagram (one syscall per batch, or per GSO run on Linux) and resets.
    /// Send errors drop the datagram: QUIC recovers it as loss.
    pub fn flush(b: *TxBatch, s: *Sock) void {
        defer b.n = 0;
        if (b.n == 0) return;
        s.stats.sent += b.n;
        if (is_darwin) {
            var iov: [max_batch]posix.iovec = undefined;
            var m: [max_batch]msghdr_x = undefined;
            for (0..b.n) |i| {
                iov[i] = .{ .base = b.buf[b.off[i]..].ptr, .len = b.dlen(i) };
                m[i] = .{ .name = &b.addrs[i], .namelen = b.alens[i], .iov = iov[i..].ptr, .iovlen = 1, .control = null, .controllen = 0, .flags = 0, .datalen = 0 };
            }
            var done: usize = 0;
            while (done < b.n) {
                s.stats.send_calls += 1;
                const rc = darwin.sendmsg_x(s.fd, m[done..].ptr, @intCast(b.n - done), 0);
                if (rc <= 0) {
                    if (rc < 0 and posix.errno(rc) == .INTR) continue;
                    done += 1; // drop the head datagram (ENOBUFS and the like), try the rest
                    continue;
                }
                done += @intCast(rc);
            }
            return;
        }
        if (is_linux) return b.flushLinux(s);
        for (0..b.n) |i| {
            s.stats.send_calls += 1;
            _ = posix.system.sendto(s.fd, b.buf[b.off[i]..].ptr, b.dlen(i), 0, &b.addrs[i].any, b.alens[i]);
        }
    }

    fn flushLinux(b: *TxBatch, s: *Sock) void {
        const linux = std.os.linux;
        var iov: [max_batch]posix.iovec = undefined;
        var m: [max_batch]linux.mmsghdr = undefined;
        const Cmsg = extern struct { len: usize, level: c_int, type: c_int, seg: u16, pad: [6]u8 = @splat(0) };
        var cm: [max_batch]Cmsg = undefined;
        var nm: usize = 0;
        var i: usize = 0;
        while (i < b.n) {
            // A GSO run: same destination, equal segment size, the last one may be shorter.
            var j = i + 1;
            const seg = b.dlen(i);
            if (s.gso) {
                while (j < b.n and j - i < 64 and b.sameAddr(i, j) and b.dlen(j - 1) == seg and b.dlen(j) <= seg) : (j += 1) {}
            }
            iov[nm] = .{ .base = b.buf[b.off[i]..].ptr, .len = b.off[j] - b.off[i] };
            m[nm] = .{ .hdr = .{ .name = &b.addrs[i].any, .namelen = b.alens[i], .iov = iov[nm..].ptr, .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
            if (j - i > 1) {
                cm[nm] = .{ .len = @offsetOf(Cmsg, "seg") + 2, .level = posix.IPPROTO.UDP, .type = linux.UDP.SEGMENT, .seg = @intCast(seg) };
                m[nm].hdr.control = &cm[nm];
                m[nm].hdr.controllen = @sizeOf(Cmsg);
            }
            nm += 1;
            i = j;
        }
        var done: usize = 0;
        while (done < nm) {
            s.stats.send_calls += 1;
            const rc = linux.sendmmsg(s.fd, m[done..].ptr, @intCast(nm - done), 0);
            switch (linux.errno(rc)) {
                .SUCCESS => done += @max(1, rc),
                .INTR => {},
                .IO, .INVAL => {
                    // The device cannot segment: later batches go without GSO; this run is lost
                    // and QUIC recovery resends it.
                    if (m[done].hdr.controllen != 0) s.gso = false;
                    done += 1;
                },
                else => done += 1,
            }
        }
    }
};

pub const RxBatch = struct {
    buf: [max_batch * rx_slot]u8 align(16) = undefined,
    lens: [max_batch]usize = undefined,
    addrs: [max_batch]Addr = undefined,
    n: usize = 0,

    pub fn data(b: *RxBatch, i: usize) []u8 {
        return b.buf[i * rx_slot ..][0..b.lens[i]];
    }
    pub fn from(b: *const RxBatch, i: usize) net.IpAddress {
        return fromPosix(&b.addrs[i]);
    }

    /// `recv` that waits up to `wait_ns` for the first datagram (0: does not wait): on the
    /// socket's receive timeout, or for a short wait on Linux on a precise timer first.
    pub fn recvWait(b: *RxBatch, s: *Sock, wait_ns: u64) usize {
        if (wait_ns == 0 or s.waitShort(wait_ns)) return b.recv(s, false);
        s.setWait(wait_ns);
        return b.recv(s, true);
    }

    /// Receives up to `max_batch` datagrams in one syscall. `block`: wait up to the socket's
    /// SO_RCVTIMEO for the first. Returns the count (0 on timeout or nothing queued).
    pub fn recv(b: *RxBatch, s: *Sock, block: bool) usize {
        b.n = 0;
        if (is_darwin) {
            var iov: [max_batch]posix.iovec = undefined;
            var m: [max_batch]msghdr_x = undefined;
            for (0..max_batch) |i| {
                iov[i] = .{ .base = b.buf[i * rx_slot ..].ptr, .len = rx_slot };
                m[i] = .{ .name = &b.addrs[i], .namelen = @sizeOf(Addr), .iov = iov[i..].ptr, .iovlen = 1, .control = null, .controllen = 0, .flags = 0, .datalen = 0 };
            }
            while (true) {
                s.stats.recv_calls += 1;
                const rc = darwin.recvmsg_x(s.fd, &m, max_batch, if (block) 0 else 0x80); // MSG_DONTWAIT
                if (rc < 0 and posix.errno(rc) == .INTR) continue;
                if (rc <= 0) return 0;
                const n: usize = @intCast(rc);
                var k: usize = 0;
                for (0..n) |i| {
                    if (m[i].flags & 0x10 != 0) continue; // MSG_TRUNC
                    if (k != i) {
                        @memcpy(b.buf[k * rx_slot ..][0..m[i].datalen], b.buf[i * rx_slot ..][0..m[i].datalen]);
                        b.addrs[k] = b.addrs[i];
                    }
                    b.lens[k] = m[i].datalen;
                    k += 1;
                }
                b.n = k;
                s.stats.received += k;
                return k;
            }
        }
        if (is_linux) {
            const linux = std.os.linux;
            var iov: [max_batch]posix.iovec = undefined;
            var m: [max_batch]linux.mmsghdr = undefined;
            for (0..max_batch) |i| {
                iov[i] = .{ .base = b.buf[i * rx_slot ..].ptr, .len = rx_slot };
                m[i] = .{ .hdr = .{ .name = &b.addrs[i].any, .namelen = @sizeOf(Addr), .iov = iov[i..].ptr, .iovlen = 1, .control = null, .controllen = 0, .flags = 0 }, .len = 0 };
            }
            const flags: u32 = if (block) linux.MSG.WAITFORONE else linux.MSG.DONTWAIT;
            while (true) {
                s.stats.recv_calls += 1;
                const rc = linux.recvmmsg(s.fd, &m, max_batch, flags, null);
                switch (linux.errno(rc)) {
                    .SUCCESS => {},
                    .INTR => continue,
                    else => return 0,
                }
                var k: usize = 0;
                for (0..rc) |i| {
                    if (m[i].hdr.flags & linux.MSG.TRUNC != 0) continue;
                    if (k != i) {
                        @memcpy(b.buf[k * rx_slot ..][0..m[i].len], b.buf[i * rx_slot ..][0..m[i].len]);
                        b.addrs[k] = b.addrs[i];
                    }
                    b.lens[k] = m[i].len;
                    k += 1;
                }
                b.n = k;
                s.stats.received += k;
                return k;
            }
        }
        // Portable: one recvfrom per datagram.
        while (b.n < max_batch) {
            var al: posix.socklen_t = @sizeOf(Addr);
            s.stats.recv_calls += 1;
            const rc = posix.system.recvfrom(s.fd, b.buf[b.n * rx_slot ..].ptr, rx_slot, if (block and b.n == 0) 0 else posix.MSG.DONTWAIT, &b.addrs[b.n].any, &al);
            if (posix.errno(rc) != .SUCCESS) break;
            b.lens[b.n] = @intCast(rc);
            b.n += 1;
        }
        s.stats.received += b.n;
        return b.n;
    }
};

test "udpio: batch send and receive on loopback, address round trip" {
    const sys = posix.system;
    const fd_a: posix.fd_t = @intCast(sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0));
    defer _ = sys.close(fd_a);
    const fd_b: posix.fd_t = @intCast(sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0));
    defer _ = sys.close(fd_b);
    var bind_addr: Addr = undefined;
    const lo: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    const bl = toPosix(&lo, &bind_addr);
    try std.testing.expectEqual(@as(c_int, 0), @as(c_int, @intCast(sys.bind(fd_b, &bind_addr.any, bl))));
    var got: Addr = undefined;
    var gl: posix.socklen_t = @sizeOf(Addr);
    try std.testing.expectEqual(@as(c_int, 0), @as(c_int, @intCast(sys.getsockname(fd_b, &got.any, &gl))));
    const dest = fromPosix(&got);
    try std.testing.expect(dest.ip4.port != 0);
    var sa = Sock.init(fd_a);
    var sb = Sock.init(fd_b);
    sb.setWait(20 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 10), sb.rcvtimeo_ms);
    const tx = try std.testing.allocator.create(TxBatch);
    defer std.testing.allocator.destroy(tx);
    tx.* = .{};
    for (0..5) |i| {
        const sl = tx.slot();
        const n = 1452 - i * 100;
        @memset(sl[0..n], @intCast('a' + i));
        tx.commit(n, &dest);
    }
    tx.flush(&sa);
    try std.testing.expectEqual(@as(usize, 0), tx.n);
    const rx = try std.testing.allocator.create(RxBatch);
    defer std.testing.allocator.destroy(rx);
    rx.* = .{};
    var total: usize = 0;
    var tries: usize = 0;
    while (total < 5 and tries < 10) : (tries += 1) {
        const n = rx.recv(&sb, true);
        for (0..n) |i| {
            const d = rx.data(i);
            try std.testing.expectEqual(1452 - (total + i) * 100, d.len);
            try std.testing.expectEqual(@as(u8, @intCast('a' + total + i)), d[0]);
            try std.testing.expectEqual(@as(u8, 127), rx.from(i).ip4.bytes[0]);
        }
        total += n;
    }
    try std.testing.expectEqual(@as(usize, 5), total);
    try std.testing.expectEqual(@as(usize, 0), rx.recv(&sb, false));
}

test "udpio: a 64-datagram burst to one address leaves in batched send calls and arrives whole" {
    // The path every zui/1 and WebTransport response takes (the native listener and the anemo
    // server queue a pass's datagrams in one TxBatch): 32 datagrams per syscall on macOS
    // (sendmsg_x) and Linux (sendmmsg), and on Linux with UDP GSO one super-packet per batch.
    const sys = posix.system;
    const fd_a: posix.fd_t = @intCast(sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0));
    defer _ = sys.close(fd_a);
    const fd_b: posix.fd_t = @intCast(sys.socket(posix.AF.INET, posix.SOCK.DGRAM, 0));
    defer _ = sys.close(fd_b);
    const rcvbuf: c_int = 1 << 20;
    posix.setsockopt(fd_b, posix.SOL.SOCKET, posix.SO.RCVBUF, std.mem.asBytes(&rcvbuf)) catch {};
    var bind_addr: Addr = undefined;
    const lo: net.IpAddress = .{ .ip4 = net.Ip4Address.loopback(0) };
    const bl = toPosix(&lo, &bind_addr);
    try std.testing.expectEqual(@as(c_int, 0), @as(c_int, @intCast(sys.bind(fd_b, &bind_addr.any, bl))));
    var got: Addr = undefined;
    var gl: posix.socklen_t = @sizeOf(Addr);
    try std.testing.expectEqual(@as(c_int, 0), @as(c_int, @intCast(sys.getsockname(fd_b, &got.any, &gl))));
    const dest = fromPosix(&got);
    var sa = Sock.init(fd_a);
    var sb = Sock.init(fd_b);
    sb.setWait(20 * std.time.ns_per_ms);
    const tx = try std.testing.allocator.create(TxBatch);
    defer std.testing.allocator.destroy(tx);
    tx.* = .{};
    // a checkpoint's worth: 63 full datagrams and a short last one, as the listener's flush
    // queues them (the batch is sent when full and at the end of the pass)
    const total_dgrams = 64;
    for (0..total_dgrams) |i| {
        if (tx.full()) tx.flush(&sa);
        const sl = tx.slot();
        const n: usize = if (i == total_dgrams - 1) 700 else 1452;
        @memset(sl[0..n], @truncate(i));
        std.mem.writeInt(u16, sl[0..2], @intCast(i), .little);
        tx.commit(n, &dest);
    }
    tx.flush(&sa);
    try std.testing.expectEqual(@as(u64, total_dgrams), sa.stats.sent);
    // two calls (one per batch of 32) unless the kernel took a batch in parts
    if (is_darwin or is_linux) try std.testing.expect(sa.stats.send_calls <= 4);
    const rx = try std.testing.allocator.create(RxBatch);
    defer std.testing.allocator.destroy(rx);
    rx.* = .{};
    var seen: [total_dgrams]bool = @splat(false);
    var total: usize = 0;
    var tries: usize = 0;
    while (total < total_dgrams and tries < 50) : (tries += 1) {
        const n = rx.recv(&sb, true);
        for (0..n) |i| {
            const d = rx.data(i);
            const k = std.mem.readInt(u16, d[0..2], .little);
            try std.testing.expect(k < total_dgrams and !seen[k]);
            seen[k] = true;
            try std.testing.expectEqual(@as(usize, if (k == total_dgrams - 1) 700 else 1452), d.len);
            try std.testing.expectEqual(@as(u8, @truncate(k)), d[d.len - 1]);
        }
        total += n;
    }
    try std.testing.expectEqual(@as(usize, total_dgrams), total);
    // fewer receive calls than datagrams as well
    try std.testing.expect(sb.stats.recv_calls < total_dgrams / 2);
}
