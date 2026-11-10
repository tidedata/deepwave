//! A fixed pool of long-lived worker threads behind an h2 handler. serve's h2 server runs one
//! thread per connection; SimulateTransaction keeps per-thread package caches and Move VM
//! runtimes (exec `pkgs.cacheFor`, `movecall`'s framework snapshots), which would be rebuilt on
//! every new connection's first simulate and stay allocated after it closes. The node hands each
//! simulate to this pool instead: the caches are bounded by the worker count and stay warm. A
//! request that finds the bounded queue full answers RESOURCE_EXHAUSTED at once.
const std = @import("std");
const serve = @import("serve");

const Io = std.Io;
const h2 = serve.h2;

pub const Pool = struct {
    io: Io,
    inner: h2.Handler,
    /// Called by each worker as it exits (frees its thread-local caches).
    on_exit: ?*const fn () void = null,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    ring: []*Job,
    head: usize = 0,
    len: usize = 0,
    closed: bool = false,
    threads: []std.Thread,
    gpa: std.mem.Allocator,

    const Job = struct {
        req: *const h2.Request,
        rs: *h2.ResponseStream,
        status: h2.Status = .ok,
        done: Io.Event = .unset,
    };

    pub const Options = struct {
        /// Worker threads (0: half the cores, at least 2, at most 16).
        workers: usize = 0,
        /// Requests waiting for a worker before new ones are refused.
        queue: usize = 256,
        on_exit: ?*const fn () void = null,
    };

    /// Starts the workers. `p` must not move while they run.
    pub fn init(p: *Pool, gpa: std.mem.Allocator, io: Io, inner: h2.Handler, opts: Options) !void {
        const cpus = std.Thread.getCpuCount() catch 4;
        const n = if (opts.workers != 0) opts.workers else std.math.clamp(cpus / 2, 2, 16);
        p.* = .{ .io = io, .inner = inner, .on_exit = opts.on_exit, .ring = try gpa.alloc(*Job, @max(opts.queue, 1)), .threads = try gpa.alloc(std.Thread, n), .gpa = gpa };
        var started: usize = 0;
        errdefer {
            p.close();
            for (p.threads[0..started]) |t| t.join();
            gpa.free(p.threads);
            gpa.free(p.ring);
        }
        while (started < n) : (started += 1) p.threads[started] = try std.Thread.spawn(.{}, worker, .{p});
    }

    fn close(p: *Pool) void {
        p.mu.lockUncancelable(p.io);
        p.closed = true;
        p.mu.unlock(p.io);
        p.cond.broadcast(p.io);
    }

    /// Stops taking requests, lets the workers finish the queue, joins them.
    pub fn deinit(p: *Pool) void {
        p.close();
        for (p.threads) |t| t.join();
        p.gpa.free(p.threads);
        p.gpa.free(p.ring);
    }

    pub fn handler(p: *Pool) h2.Handler {
        return .{ .ctx = p, .call = call };
    }

    /// Runs the request on a worker; the connection thread waits for it.
    pub fn call(ctx: *anyopaque, req: *const h2.Request, rs: *h2.ResponseStream) h2.Status {
        const p: *Pool = @ptrCast(@alignCast(ctx));
        var job: Job = .{ .req = req, .rs = rs };
        {
            p.mu.lockUncancelable(p.io);
            defer p.mu.unlock(p.io);
            if (p.closed) {
                rs.setMessage("server is shutting down");
                return .unavailable;
            }
            if (p.len == p.ring.len) {
                rs.setMessage("too many simulations in flight");
                return .resource_exhausted;
            }
            p.ring[(p.head + p.len) % p.ring.len] = &job;
            p.len += 1;
        }
        p.cond.signal(p.io);
        job.done.waitUncancelable(p.io);
        return job.status;
    }

    fn worker(p: *Pool) void {
        defer if (p.on_exit) |f| f();
        while (true) {
            p.mu.lockUncancelable(p.io);
            while (p.len == 0 and !p.closed) p.cond.waitUncancelable(p.io, &p.mu);
            if (p.len == 0) {
                p.mu.unlock(p.io);
                return;
            }
            const job = p.ring[p.head];
            p.head = (p.head + 1) % p.ring.len;
            p.len -= 1;
            p.mu.unlock(p.io);
            job.status = p.inner.call(p.inner.ctx, job.req, job.rs);
            job.done.set(p.io);
        }
    }
};

test "pool runs requests on its own threads and refuses when the queue is full" {
    const io = std.testing.io;
    const Inner = struct {
        var gate: Io.Event = .unset;
        var seen: std.atomic.Value(u32) = .init(0);
        var entered: std.atomic.Value(u32) = .init(0);
        var exits: std.atomic.Value(u32) = .init(0);
        fn call(_: *anyopaque, req: *const h2.Request, _: *h2.ResponseStream) h2.Status {
            _ = entered.fetchAdd(1, .monotonic);
            if (std.mem.eql(u8, req.path, "/block")) gate.waitUncancelable(io);
            _ = seen.fetchAdd(1, .monotonic);
            return .not_found;
        }
        fn exit() void {
            _ = exits.fetchAdd(1, .monotonic);
        }
    };
    var dummy: u8 = 0;
    var p: Pool = undefined;
    try p.init(std.testing.allocator, io, .{ .ctx = &dummy, .call = Inner.call }, .{ .workers = 1, .queue = 1, .on_exit = Inner.exit });
    // a request that returns runs on the worker and carries its status back
    const req: h2.Request = .{ .path = "/x", .authority = "", .body = "", .stream_id = 1 };
    var rs: h2.ResponseStream = undefined;
    try std.testing.expectEqual(h2.Status.not_found, Pool.call(&p, &req, &rs));
    // one blocked on the worker, one queued: the third finds the queue full
    const blocked: h2.Request = .{ .path = "/block", .authority = "", .body = "", .stream_id = 3 };
    const T = struct {
        fn run(pp: *Pool, r: *const h2.Request) void {
            var s: h2.ResponseStream = undefined;
            _ = Pool.call(pp, r, &s);
        }
    };
    const t1 = try std.Thread.spawn(.{}, T.run, .{ &p, &blocked });
    // wait until the worker is inside the blocked request
    while (Inner.entered.load(.monotonic) < 2) io.sleep(.fromMilliseconds(1), .awake) catch {};
    const t2 = try std.Thread.spawn(.{}, T.run, .{ &p, &req });
    while (true) {
        p.mu.lockUncancelable(io);
        const full = p.len == 1;
        p.mu.unlock(io);
        if (full) break;
        io.sleep(.fromMilliseconds(1), .awake) catch {};
    }
    var rs3: h2.ResponseStream = undefined;
    rs3.msg_owned = null;
    rs3.msg = "";
    // setMessage copies the text with the stream's allocator
    rs3.gpa = std.testing.allocator;
    try std.testing.expectEqual(h2.Status.resource_exhausted, Pool.call(&p, &req, &rs3));
    try std.testing.expectEqualStrings("too many simulations in flight", rs3.msg);
    std.testing.allocator.free(rs3.msg_owned.?);
    Inner.gate.set(io);
    t1.join();
    t2.join();
    try std.testing.expectEqual(@as(u32, 3), Inner.seen.load(.monotonic));
    p.deinit();
    try std.testing.expectEqual(@as(u32, 1), Inner.exits.load(.monotonic));
}
