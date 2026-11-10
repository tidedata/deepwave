//! Small blocking-synchronisation helpers for consensus_net: a monitor (mutex + condition with
//! timed waits) and the monotonic clock in nanoseconds. Thread-per-connection code uses these;
//! nothing here allocates.
const std = @import("std");
const Io = std.Io;

pub fn monoNs(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

pub const Monitor = struct {
    io: Io,
    mu: Io.Mutex = .init,
    cv: Io.Condition = .init,

    pub fn init(io: Io) Monitor {
        return .{ .io = io };
    }
    pub fn lock(m: *Monitor) void {
        m.mu.lockUncancelable(m.io);
    }
    pub fn unlock(m: *Monitor) void {
        m.mu.unlock(m.io);
    }
    pub fn wait(m: *Monitor) void {
        m.cv.waitUncancelable(m.io, &m.mu);
    }
    /// Waits for a broadcast or `ns` nanoseconds (spurious wakeups possible; the caller loops).
    pub fn waitNs(m: *Monitor, ns: u64) void {
        m.cv.waitTimeout(m.io, &m.mu, .{ .duration = .{ .raw = .fromNanoseconds(@intCast(ns)), .clock = .awake } }) catch {};
    }
    pub fn broadcast(m: *Monitor) void {
        m.cv.broadcast(m.io);
    }
    pub fn signal(m: *Monitor) void {
        m.cv.signal(m.io);
    }
};

/// A bounded multi-producer multi-consumer FIFO of `T` guarded by a monitor. `push` fails when
/// full (the caller decides: drop, retry or backpressure); `pop` blocks with a timeout.
pub fn Queue(comptime T: type) type {
    return struct {
        const Self = @This();
        mon: Monitor,
        buf: []T,
        head: usize = 0,
        len: usize = 0,
        closed: bool = false,

        pub fn init(io: Io, storage: []T) Self {
            return .{ .mon = Monitor.init(io), .buf = storage };
        }
        pub fn push(q: *Self, item: T) bool {
            q.mon.lock();
            defer q.mon.unlock();
            if (q.closed or q.len == q.buf.len) return false;
            q.buf[(q.head + q.len) % q.buf.len] = item;
            q.len += 1;
            q.mon.signal();
            return true;
        }
        /// Null on timeout or when closed and drained.
        pub fn pop(q: *Self, timeout_ns: u64) ?T {
            q.mon.lock();
            defer q.mon.unlock();
            const deadline = monoNs(q.mon.io) +| timeout_ns;
            while (q.len == 0) {
                if (q.closed) return null;
                const now = monoNs(q.mon.io);
                if (now >= deadline) return null;
                q.mon.waitNs(deadline - now);
            }
            const item = q.buf[q.head];
            q.head = (q.head + 1) % q.buf.len;
            q.len -= 1;
            return item;
        }
        pub fn close(q: *Self) void {
            q.mon.lock();
            q.closed = true;
            q.mon.broadcast();
            q.mon.unlock();
        }
        pub fn count(q: *Self) usize {
            q.mon.lock();
            defer q.mon.unlock();
            return q.len;
        }
    };
}

test "queue is FIFO, bounded, closes" {
    const io = std.testing.io;
    var storage: [2]u32 = undefined;
    var q = Queue(u32).init(io, &storage);
    try std.testing.expect(q.push(1));
    try std.testing.expect(q.push(2));
    try std.testing.expect(!q.push(3));
    try std.testing.expectEqual(@as(?u32, 1), q.pop(0));
    try std.testing.expect(q.push(3));
    try std.testing.expectEqual(@as(?u32, 2), q.pop(0));
    try std.testing.expectEqual(@as(?u32, 3), q.pop(0));
    try std.testing.expectEqual(@as(?u32, null), q.pop(1_000_000));
    q.close();
    try std.testing.expect(!q.push(4));
}
