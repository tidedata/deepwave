//! Process-wide worker pool for unary gRPC calls on h2c connections.
//!
//! sui-node (tonic) runs every HTTP/2 stream as its own task, so the streams of one connection
//! are served concurrently. Here the connection thread parses frames and hands each complete
//! unary request to this pool; a worker runs the handler with no connection lock held, then
//! takes the lock only to queue the reply. A fixed set of threads (not one per stream) keeps the
//! thread count bounded whatever the clients do.
//! - `submit` never blocks; it returns false when the queue is full (the caller then runs the
//!   task inline, so a request is never dropped);
//! - workers are started once and live as long as the process (pool memory comes from the page
//!   allocator, so tests under `testing.allocator` see no leak).
const std = @import("std");
const Io = std.Io;
const Atomic = std.atomic.Value;
const hw = @import("core").hw;

pub const Task = struct {
    run: *const fn (t: *Task) void,
    next: ?*Task = null,
};

pub const Config = struct {
    /// Worker threads (0: 4 per usable CPU, between 16 and 256; `workersFor`).
    workers: u32 = 0,
    /// Tasks waiting beyond this are refused (`submit` returns false).
    max_queued: u32 = 65536,
    stack_size: usize = 8 << 20,
};

pub const Pool = struct {
    io: Io,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    head: ?*Task = null,
    tail: ?*Task = null,
    queued: u32 = 0,
    max_queued: u32,
    workers: u32 = 0,
    /// Tasks taken by a worker and not yet returned (metrics, tests).
    busy: Atomic(u32) = .init(0),

    /// Queues `t`; false when the queue is full.
    pub fn submit(p: *Pool, t: *Task) bool {
        p.mu.lockUncancelable(p.io);
        if (p.queued >= p.max_queued) {
            p.mu.unlock(p.io);
            return false;
        }
        t.next = null;
        if (p.tail) |tl| tl.next = t else p.head = t;
        p.tail = t;
        p.queued += 1;
        p.mu.unlock(p.io);
        p.cond.signal(p.io);
        return true;
    }

    fn worker(p: *Pool) void {
        while (true) {
            p.mu.lockUncancelable(p.io);
            while (p.head == null) p.cond.waitUncancelable(p.io, &p.mu);
            const t = p.head.?;
            p.head = t.next;
            if (p.head == null) p.tail = null;
            p.queued -= 1;
            p.mu.unlock(p.io);
            _ = p.busy.fetchAdd(1, .monotonic);
            t.run(t);
            _ = p.busy.fetchSub(1, .monotonic);
        }
    }

    pub fn queuedNow(p: *Pool) u32 {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        return p.queued;
    }
};

/// Two pools (lane serve-tail): point reads (GetObject, GetServiceInfo, GetBalance, ...) never
/// queue behind calls that can take milliseconds (full checkpoints, 500-id batches, List*
/// pages, Simulate, Execute). sui-node runs every stream as its own tokio task, so a burst of
/// slow calls there does not hold up point reads either.
pub const Class = enum { fast, slow };

/// The class of a gRPC path (`/sui.rpc.v2.Service/Method`).
pub fn classOf(path: []const u8) Class {
    const slow = [_][]const u8{
        "/GetCheckpoint",        "/BatchGetObjects",     "/BatchGetTransactions", "/ListDynamicFields",
        "/ListOwnedObjects",     "/ListTransactions",    "/ListEvents",           "/ListCheckpoints",
        "/SimulateTransaction",  "/ExecuteTransaction",  "/GetPackage",           "/VerifySignature",
        "/ListPackageVersions",  "/BatchGetCheckpoints",
    };
    for (slow) |m| if (std.mem.endsWith(u8, path, m)) return .slow;
    return .fast;
}

/// CPUs this process may use: the affinity mask capped by the cgroup CPU quota (core/hw.zig:
/// cgroup v2 `cpu.max` of the process's own cgroup and its parents, or v1's cfs quota). The
/// visible CPU count alone made 256 workers per class on a 64-core host under a 400% quota:
/// that many runnable threads burn a CFS period's quota in a few ms and the whole group is
/// throttled until the next period, which is a tail of tens of ms on point reads.
pub fn usableCpus() u32 {
    return @max(1, hw.detect(null).logical_cores);
}

/// Workers of one class on `cpus` usable CPUs: 4 per CPU (handlers can wait: ExecuteTransaction
/// on effects, a cold read on the disk), never under 16 (a small quota must still serve slow
/// calls side by side) and never over 256.
pub fn workersFor(cpus: u32) u32 {
    return std.math.clamp(cpus *| 4, 16, 256);
}

test "pool size follows the usable CPUs, with a floor" {
    try std.testing.expectEqual(@as(u32, 16), workersFor(1));
    try std.testing.expectEqual(@as(u32, 16), workersFor(4)); // a 400% quota: 16, not 4 x the host's cores
    try std.testing.expectEqual(@as(u32, 32), workersFor(8));
    try std.testing.expectEqual(@as(u32, 256), workersFor(64));
    try std.testing.expectEqual(@as(u32, 256), workersFor(std.math.maxInt(u32)));
    // never more than the CPUs the process can see, never zero
    const seen: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    try std.testing.expect(usableCpus() >= 1);
    try std.testing.expect(usableCpus() <= seen);
}

/// The pools, published once each and never freed.
var globals: [2]Atomic(?*Pool) = .{ .init(null), .init(null) };
/// Held only while a pool is started.
var start_lock: Io.Mutex = .init;

/// The process pool of `class`, started on first use with `cfg` (later configs are ignored).
/// Null when no worker could be started (callers then run tasks inline).
///
/// Every request of every connection comes through here, so a started pool is one atomic
/// load. It used to be a bare spin lock: a holder that lost its CPU left every other
/// connection thread spinning for its whole time slice.
pub fn getClass(io: Io, cfg: Config, class: Class) ?*Pool {
    const global = &globals[@intFromEnum(class)];
    if (global.load(.acquire)) |p| return p;
    start_lock.lockUncancelable(io);
    defer start_lock.unlock(io);
    if (global.load(.acquire)) |p| return p;
    const p = std.heap.page_allocator.create(Pool) catch return null;
    p.* = .{ .io = io, .max_queued = cfg.max_queued };
    const n: u32 = if (cfg.workers != 0) cfg.workers else workersFor(usableCpus());
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const t = std.Thread.spawn(.{ .stack_size = cfg.stack_size }, Pool.worker, .{p}) catch break;
        t.detach();
        p.workers += 1;
    }
    if (p.workers == 0) {
        std.heap.page_allocator.destroy(p);
        return null;
    }
    global.store(p, .release);
    return p;
}

/// The fast pool (tests and callers with no path).
pub fn get(io: Io, cfg: Config) ?*Pool {
    return getClass(io, cfg, .fast);
}

test "a started pool is found without taking a lock" {
    const io = std.testing.io;
    const p = get(io, .{}) orelse return error.SkipZigTest;
    // The start lock is held (another class being started, or its holder descheduled): lookups
    // of the started pool still return at once. With the spin lock they spun until it was free.
    start_lock.lockUncancelable(io);
    var unlocked = false;
    defer if (!unlocked) start_lock.unlock(io);
    const T = struct {
        fn run(i: Io, want: *Pool, hits: *Atomic(u32)) void {
            for (0..1000) |_| if (get(i, .{}) == want) {
                _ = hits.fetchAdd(1, .monotonic);
            };
        }
    };
    var hits: Atomic(u32) = .init(0);
    var ts: [4]std.Thread = undefined;
    for (&ts) |*t| t.* = try std.Thread.spawn(.{}, T.run, .{ io, p, &hits });
    var waited: u32 = 0;
    while (hits.load(.monotonic) < 4000 and waited < 5000) : (waited += 1) @import("sock.zig").sleepMs(1);
    const got = hits.load(.monotonic);
    start_lock.unlock(io);
    unlocked = true;
    for (ts) |t| t.join();
    try std.testing.expectEqual(@as(u32, 4000), got);
}

test "pool runs submitted tasks concurrently" {
    const p = get(std.testing.io, .{}) orelse return error.SkipZigTest;
    const T = struct {
        task: Task = .{ .run = run },
        gate: *Atomic(u32),
        seen: *Atomic(u32),
        fn run(t: *Task) void {
            const self: *@This() = @fieldParentPtr("task", t);
            _ = self.seen.fetchAdd(1, .acq_rel);
            // every task waits until all 8 started: only concurrent workers get there
            var spins: u32 = 0;
            while (self.seen.load(.acquire) < 8 and spins < 5000) : (spins += 1) @import("sock.zig").sleepMs(1);
            _ = self.gate.fetchAdd(1, .acq_rel);
        }
    };
    var gate: Atomic(u32) = .init(0);
    var seen: Atomic(u32) = .init(0);
    var ts: [8]T = undefined;
    for (&ts) |*t| {
        t.* = .{ .gate = &gate, .seen = &seen };
        try std.testing.expect(p.submit(&t.task));
    }
    var waited: u32 = 0;
    while (gate.load(.acquire) < 8 and waited < 5000) : (waited += 1) @import("sock.zig").sleepMs(1);
    try std.testing.expectEqual(@as(u32, 8), gate.load(.acquire));
}
