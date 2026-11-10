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

pub const Task = struct {
    run: *const fn (t: *Task) void,
    next: ?*Task = null,
};

pub const Config = struct {
    /// Worker threads (0: 4 per CPU, between 16 and 256).
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

var globals: [2]?*Pool = .{ null, null };
var global_lock: Atomic(u32) = .init(0);

/// The process pool of `class`, started on first use with `cfg` (later configs are ignored).
/// Null when no worker could be started (callers then run tasks inline).
pub fn getClass(io: Io, cfg: Config, class: Class) ?*Pool {
    while (global_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
    defer global_lock.store(0, .release);
    const global = &globals[@intFromEnum(class)];
    if (global.*) |p| return p;
    const p = std.heap.page_allocator.create(Pool) catch return null;
    p.* = .{ .io = io, .max_queued = cfg.max_queued };
    const n: u32 = if (cfg.workers != 0) cfg.workers else blk: {
        const cpus: u32 = @intCast(std.Thread.getCpuCount() catch 4);
        break :blk std.math.clamp(cpus *| 4, 16, 256);
    };
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
    global.* = p;
    return p;
}

/// The fast pool (tests and callers with no path).
pub fn get(io: Io, cfg: Config) ?*Pool {
    return getClass(io, cfg, .fast);
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
