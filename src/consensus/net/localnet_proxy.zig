//! Loopback TCP relays for the localnet's partition test: one relay per ordered pair of
//! authorities (src dials dst through relay (src, dst)), so cutting authority `p` off cuts exactly
//! the links that touch it in both directions while the rest of the committee keeps talking.
//!
//! Two ways to cut a link:
//! - `blackhole`: bytes stop moving both ways and new connections are held without being
//!   forwarded (what a real partition looks like to TCP: silence, no reset). Healing resumes the
//!   held connections where they stopped.
//! - `drop`: every live connection on the link is closed and new ones are closed at once.
//!
//! Test tooling only: loopback addresses, no keys, nothing here talks to a real validator.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const c = std.c;

pub const CutMode = enum { blackhole, drop };

/// Pump thread stack. glibc carves the static TLS block out of the thread stack and returns
/// EINVAL (which std.Thread treats as unreachable) when it does not fit; deepwave binaries carry a
/// large static TLS, so this matches the gRPC threads rather than a small relay-sized stack.
const pump_stack: usize = 8 << 20;

/// One flag per authority: a link is cut while either end is cut.
pub const Cuts = struct {
    flags: [16]std.atomic.Value(bool) = @splat(.init(false)),
    mode: CutMode = .blackhole,

    pub fn set(cu: *Cuts, i: usize, on: bool) void {
        cu.flags[i].store(on, .release);
    }
    fn link(cu: *const Cuts, src: usize, dst: usize) bool {
        return cu.flags[src].load(.acquire) or cu.flags[dst].load(.acquire);
    }
};

pub const Relay = struct {
    gpa: Allocator,
    io: Io,
    server: Io.net.Server,
    port: u16,
    target_port: u16,
    src: usize,
    dst: usize,
    cuts: *Cuts,
    stopping: std.atomic.Value(bool) = .init(false),
    accept_thread: ?std.Thread = null,
    mu: std.atomic.Mutex = .unlocked,
    pumps: std.ArrayListUnmanaged(std.Thread) = .empty,
    /// Bytes forwarded both ways (for the report).
    bytes: std.atomic.Value(u64) = .init(0),

    pub fn start(gpa: Allocator, io: Io, src: usize, dst: usize, target_port: u16, cuts: *Cuts) !*Relay {
        var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
        const server = try any.listen(io, .{ .reuse_address = true });
        const r = try gpa.create(Relay);
        r.* = .{ .gpa = gpa, .io = io, .server = server, .port = server.socket.address.ip4.port, .target_port = target_port, .src = src, .dst = dst, .cuts = cuts };
        r.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{r});
        return r;
    }

    pub fn stop(r: *Relay) void {
        r.stopping.store(true, .release);
        if (r.accept_thread) |t| t.join();
        lock(r);
        const pumps = r.pumps.items;
        r.mu.unlock();
        for (pumps) |t| t.join();
        r.pumps.deinit(r.gpa);
        r.server.deinit(r.io);
        r.gpa.destroy(r);
    }

    fn acceptLoop(r: *Relay) void {
        const lfd = r.server.socket.handle;
        while (!r.stopping.load(.acquire)) {
            if (!readable(lfd, 100)) continue;
            const st = r.server.accept(r.io) catch continue;
            const fd = st.socket.handle;
            const t = std.Thread.spawn(.{ .stack_size = pump_stack }, pump, .{ r, fd }) catch {
                _ = c.close(fd);
                continue;
            };
            lock(r);
            r.pumps.append(r.gpa, t) catch {};
            r.mu.unlock();
        }
    }

    fn cut(r: *const Relay) bool {
        return r.cuts.link(r.src, r.dst);
    }

    /// Owns `in_fd`: connects to the target once the link is up, then copies both ways.
    fn pump(r: *Relay, in_fd: c.fd_t) void {
        defer _ = c.close(in_fd);
        // Held connection: wait (blackhole) or close (drop) while the link is cut.
        while (r.cut()) {
            if (r.stopping.load(.acquire) or r.cuts.mode == .drop) return;
            sleepMs(20);
        }
        var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(r.target_port) };
        const out = addr.connect(r.io, .{ .mode = .stream }) catch return;
        const out_fd = out.socket.handle;
        defer _ = c.close(out_fd);
        var buf: [64 << 10]u8 = undefined;
        while (!r.stopping.load(.acquire)) {
            if (r.cut()) {
                if (r.cuts.mode == .drop) return;
                sleepMs(20);
                continue;
            }
            var pfd = [2]c.pollfd{
                .{ .fd = in_fd, .events = c.POLL.IN, .revents = 0 },
                .{ .fd = out_fd, .events = c.POLL.IN, .revents = 0 },
            };
            const n = c.poll(&pfd, 2, 50);
            if (n <= 0) continue;
            if (!copy(r, &pfd[0], in_fd, out_fd, &buf)) return;
            if (!copy(r, &pfd[1], out_fd, in_fd, &buf)) return;
        }
    }

    fn copy(r: *Relay, p: *const c.pollfd, from: c.fd_t, to: c.fd_t, buf: []u8) bool {
        if (p.revents == 0) return true;
        const got = c.read(from, buf.ptr, buf.len);
        if (got <= 0) return false;
        var off: usize = 0;
        const len: usize = @intCast(got);
        while (off < len) {
            const w = c.write(to, buf[off..].ptr, len - off);
            if (w <= 0) {
                if (w < 0 and c.errno(w) == .AGAIN) {
                    var wp = [1]c.pollfd{.{ .fd = to, .events = c.POLL.OUT, .revents = 0 }};
                    _ = c.poll(&wp, 1, 50);
                    continue;
                }
                return false;
            }
            off += @intCast(w);
        }
        _ = r.bytes.fetchAdd(len, .monotonic);
        return true;
    }
};

fn lock(r: *Relay) void {
    while (!r.mu.tryLock()) std.atomic.spinLoopHint();
}

const sleepMs = @import("serve").h2.sock.sleepMs;

fn readable(fd: c.fd_t, timeout_ms: c_int) bool {
    var p = [1]c.pollfd{.{ .fd = fd, .events = c.POLL.IN, .revents = 0 }};
    return c.poll(&p, 1, timeout_ms) > 0;
}

test "relay forwards and a cut blackholes then resumes" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var any: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(0) };
    var ls = try any.listen(io, .{ .reuse_address = true });
    defer ls.deinit(io);
    var cuts: Cuts = .{};
    const r = try Relay.start(gpa, io, 0, 1, ls.socket.address.ip4.port, &cuts);
    defer r.stop();
    var addr: Io.net.IpAddress = .{ .ip4 = Io.net.Ip4Address.loopback(r.port) };
    const cl = try addr.connect(io, .{ .mode = .stream });
    defer cl.close(io);
    const sv = try ls.accept(io);
    defer sv.close(io);
    _ = c.write(cl.socket.handle, "ping", 4);
    var b: [8]u8 = undefined;
    try std.testing.expect(readable(sv.socket.handle, 2000));
    try std.testing.expectEqual(@as(isize, 4), c.read(sv.socket.handle, &b, b.len));
    cuts.set(1, true);
    sleepMs(100);
    _ = c.write(cl.socket.handle, "pong", 4);
    try std.testing.expect(!readable(sv.socket.handle, 300));
    cuts.set(1, false);
    try std.testing.expect(readable(sv.socket.handle, 2000));
    try std.testing.expectEqual(@as(isize, 4), c.read(sv.socket.handle, &b, b.len));
}
