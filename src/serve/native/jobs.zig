//! Worker threads for the slow zui/1 methods (dry_run, submit_transaction): the I/O thread
//! queues the request bytes, a worker runs the dispatcher on its own arena, and the finished
//! response waits in `done` until the I/O thread picks it up for that connection. A finished job
//! calls `wake` so the I/O thread's poll returns at once. Workers start on the first job.
//!
//! The edge feed pool is a second `Jobs` with `shares` set: its queue is divided between clients
//! (fairq.zig), where the slow methods' queue is first come, first served.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");
const fairq = @import("fairq.zig");

pub const Job = struct {
    key: u64,
    stream: u64,
    principal: ?dispatch.Principal,
    /// The whole request (header and body), owned.
    req: []u8,
    /// The whole response, owned (set by the worker).
    out: []u8 = &.{},
    /// Pools with `shares`: who the job is accounted to.
    client: fairq.Key = 0,
};

pub const Wake = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque) void,
};

pub const Jobs = struct {
    gpa: Allocator,
    io: Io,
    disp: *dispatch.Dispatcher,
    wake: Wake,
    workers: usize = 4,
    /// Queued plus running jobs beyond which `push` refuses (RATE_LIMITED).
    max_inflight: usize = 256,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    queue: std.ArrayList(*Job) = .empty,
    done: std.ArrayList(*Job) = .empty,
    inflight: usize = 0,
    closed: bool = false,
    threads: std.ArrayList(std.Thread) = .empty,
    /// Called on each worker before it exits (the simulate engine's thread caches).
    on_exit: ?*const fn () void = null,
    /// The pool's queue divided between clients (fairq.zig; `pushFor` names the client). Its
    /// `cap` is the limit and its entries are the queue: `max_inflight` and `queue` are not
    /// used. Null: one first-come queue for everyone.
    shares: ?fairq.Queue(*Job) = null,
    /// With `shares`: where the queue's gauges and refusal counts go (the metrics endpoint).
    share_stats: ?*fairq.Stats = null,
    /// With `shares`: the message of the RATE_LIMITED answer to a queued job that gave its
    /// place to a client under its share (the caller's own message for a refused push).
    evict_message: []const u8 = "too many requests in flight",

    pub fn deinit(j: *Jobs) void {
        j.mu.lockUncancelable(j.io);
        j.closed = true;
        j.mu.unlock(j.io);
        j.cond.broadcast(j.io);
        for (j.threads.items) |t| t.join();
        j.threads.deinit(j.gpa);
        for (j.queue.items) |x| j.free(x);
        for (j.done.items) |x| j.free(x);
        if (j.shares) |*q| {
            for (q.entries.items) |e| j.free(e.item);
            q.deinit(j.gpa);
        }
        j.queue.deinit(j.gpa);
        j.done.deinit(j.gpa);
    }

    fn free(j: *Jobs, x: *Job) void {
        j.gpa.free(x.req);
        j.gpa.free(x.out);
        j.gpa.destroy(x);
    }

    /// Queues a request; false when the pool is full or closed (the caller answers RATE_LIMITED).
    pub fn push(j: *Jobs, key: u64, stream: u64, principal: ?dispatch.Principal, req: []const u8) bool {
        return j.pushFor(0, key, stream, principal, req);
    }

    /// `push` for a pool with `shares`: `client` is who the request is accounted to. False when
    /// that client is refused (fairq.zig: the pool is full and the client has its share). A
    /// client under its share is let in, and may take the place of another client's queued job:
    /// that job is answered RATE_LIMITED through `collect`, like any finished job.
    pub fn pushFor(j: *Jobs, client: fairq.Key, key: u64, stream: u64, principal: ?dispatch.Principal, req: []const u8) bool {
        const x = j.gpa.create(Job) catch return false;
        x.* = .{ .key = key, .stream = stream, .principal = principal, .client = client, .req = j.gpa.dupe(u8, req) catch {
            j.gpa.destroy(x);
            return false;
        } };
        var answered = false; // a job waits in `done`: wake the I/O thread, once the lock is free
        defer if (answered) j.wake.call(j.wake.ctx);
        j.mu.lockUncancelable(j.io);
        defer j.mu.unlock(j.io);
        if (j.closed or (j.shares == null and j.inflight >= j.max_inflight)) {
            j.free(x);
            return false;
        }
        if (j.threads.items.len < j.workers and j.threads.items.len <= j.inflight) {
            if (std.Thread.spawn(.{ .stack_size = 64 << 20 }, worker, .{j})) |t| {
                j.threads.append(j.gpa, t) catch t.detach();
            } else |_| if (j.threads.items.len == 0) {
                j.free(x);
                return false;
            }
        }
        if (j.shares) |*q| {
            defer j.publish(q);
            switch (q.push(j.gpa, client, x)) {
                .refused => {
                    j.free(x);
                    return false;
                },
                .queued => {},
                .evicted => |v| {
                    j.refuse(v);
                    answered = true;
                },
            }
            j.inflight = q.inflight;
            j.cond.signal(j.io);
            return true;
        }
        j.queue.append(j.gpa, x) catch {
            j.free(x);
            return false;
        };
        j.inflight += 1;
        j.cond.signal(j.io);
        return true;
    }

    /// A queued job gave its place up: its answer is the one a refused push gets.
    fn refuse(j: *Jobs, x: *Job) void {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(j.gpa);
        proto.errorResponse(&out, j.gpa, .rate_limited, j.evict_message, &.{ 0, 0, 0, 0 }) catch {};
        x.out = j.gpa.dupe(u8, out.items) catch &.{};
        j.done.append(j.gpa, x) catch j.free(x);
    }

    fn publish(j: *Jobs, q: *const fairq.Queue(*Job)) void {
        if (j.share_stats) |s| q.publish(s);
    }

    /// Connection `key` is gone: its queued jobs leave a pool with `shares` and their places are
    /// free at once. A job of its that is running ends as usual and `collect` frees it. I/O
    /// thread only.
    pub fn cancel(j: *Jobs, key: u64) void {
        j.mu.lockUncancelable(j.io);
        defer j.mu.unlock(j.io);
        const q = if (j.shares) |*s| s else return;
        var i = q.entries.items.len;
        while (i > 0) {
            i -= 1;
            if (q.entries.items[i].item.key == key) j.free(q.remove(i));
        }
        j.inflight = q.inflight;
        j.publish(q);
    }

    /// Hands every finished job of connection `key` to `f` (which writes the response), and frees
    /// finished jobs whose connection `alive` says is gone. I/O thread only.
    pub fn collect(j: *Jobs, key: u64, ctx: anytype, comptime f: fn (@TypeOf(ctx), u64, []const u8) void, alive: anytype) void {
        j.mu.lockUncancelable(j.io);
        defer j.mu.unlock(j.io);
        var i: usize = 0;
        while (i < j.done.items.len) {
            const x = j.done.items[i];
            if (x.key == key) {
                f(ctx, x.stream, x.out);
            } else if (alive.contains(x.key)) {
                i += 1;
                continue;
            }
            _ = j.done.swapRemove(i);
            j.free(x);
        }
    }

    pub fn pending(j: *Jobs) usize {
        j.mu.lockUncancelable(j.io);
        defer j.mu.unlock(j.io);
        return j.done.items.len;
    }

    /// Jobs no worker has taken yet (caller holds the lock).
    fn waiting(j: *const Jobs) usize {
        return if (j.shares) |*q| q.entries.items.len else j.queue.items.len;
    }

    fn worker(j: *Jobs) void {
        defer if (j.on_exit) |f| f();
        while (true) {
            j.mu.lockUncancelable(j.io);
            while (j.waiting() == 0 and !j.closed) j.cond.waitUncancelable(j.io, &j.mu);
            if (j.closed) {
                j.mu.unlock(j.io);
                return;
            }
            const x = if (j.shares) |*q| blk: {
                defer j.publish(q);
                break :blk q.pop().?.item;
            } else j.queue.orderedRemove(0);
            j.mu.unlock(j.io);
            j.run(x);
            j.mu.lockUncancelable(j.io);
            if (j.shares) |*q| {
                q.finish(x.client);
                j.inflight = q.inflight;
                j.publish(q);
            } else j.inflight -= 1;
            j.done.append(j.gpa, x) catch {
                j.mu.unlock(j.io);
                j.free(x);
                continue;
            };
            j.mu.unlock(j.io);
            j.wake.call(j.wake.ctx);
        }
    }

    fn run(j: *Jobs, x: *Job) void {
        var arena = std.heap.ArenaAllocator.init(j.gpa);
        defer arena.deinit();
        const a = arena.allocator();
        var out: std.ArrayList(u8) = .empty;
        // a worker may wait on a core (an edge passing a request on, dispatch.zig `Foreign`)
        dispatch.may_block = true;
        defer dispatch.may_block = false;
        if (proto.parseRequest(x.req)) |req| {
            j.disp.handle(a, req, x.principal, &out);
        } else proto.errorResponse(&out, a, .bad_request, "request header", "") catch {};
        x.out = j.gpa.dupe(u8, out.items) catch &.{};
    }
};

// ------------------------------------------------------------------ tests

const testing = std.testing;
const store = @import("store");

/// A pool over a real dispatcher whose dry_run hook is a gate: a job blocks in it until the
/// test lets that job go, so a test decides which job ends when.
const Fixture = struct {
    threaded: Io.Threaded,
    io: Io,
    cfg: store.Config,
    sim: *store.SimIo,
    st: *store.Store,
    svc: @import("serve").service.Service,
    disp: dispatch.Dispatcher,
    jobs: Jobs,
    stats: fairq.Stats = .{},
    wakes: std.atomic.Value(u32) = .init(0),
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    /// Job numbers in the order workers took them.
    started: [256]u16 = undefined,
    n_started: usize = 0,
    go: [256]bool = @splat(false),
    open: bool = false,

    fn create(workers: usize, shares: ?usize) !*Fixture {
        const gpa = testing.allocator;
        const f = try gpa.create(Fixture);
        errdefer gpa.destroy(f);
        f.* = .{ .threaded = .init(gpa, .{}), .io = undefined, .cfg = .{ .max_live_objects = 1 << 10, .max_object_versions = 1 << 11, .max_transactions = 1 << 10, .max_checkpoints = 16, .max_batch_bytes = 16 << 20, .max_batch_objects = 1 << 10, .max_segments = 16, .segment_reserve = 4 << 20, .seed = 5 }, .sim = undefined, .st = undefined, .svc = undefined, .disp = undefined, .jobs = undefined };
        f.io = f.threaded.io();
        f.sim = try store.SimIo.init(gpa, 11, .{}, 32 << 20);
        f.st = try store.Store.open(gpa, .{ .sim = f.sim }, &f.cfg);
        f.svc = .{ .gpa = gpa, .store = f.st, .chain_id = @splat(0) };
        f.disp = .{ .svc = &f.svc, .hooks = .{ .simulator = .{ .ctx = f, .simulate = gate } } };
        f.jobs = .{ .gpa = gpa, .io = f.io, .disp = &f.disp, .wake = .{ .ctx = f, .call = woke }, .workers = workers, .max_inflight = shares orelse 64 };
        if (shares) |cap| {
            f.jobs.shares = .{ .cap = cap, .workers = workers };
            f.jobs.share_stats = &f.stats;
            f.jobs.evict_message = "too many feed requests in flight";
        }
        return f;
    }

    /// Lets every job go, then joins the workers: no thread outlives a test, passed or failed.
    fn destroy(f: *Fixture) void {
        f.mu.lockUncancelable(f.io);
        f.open = true;
        f.mu.unlock(f.io);
        f.cond.broadcast(f.io);
        f.jobs.deinit();
        f.svc.deinit();
        f.st.deinit();
        f.sim.deinit();
        f.threaded.deinit();
        testing.allocator.destroy(f);
    }

    fn woke(ctx: *anyopaque) void {
        const f: *Fixture = @ptrCast(@alignCast(ctx));
        _ = f.wakes.fetchAdd(1, .monotonic);
    }

    fn gate(ctx: *anyopaque, a: Allocator, tx: []const u8, fl: u8, out: *std.ArrayList(u8)) anyerror!void {
        _ = fl;
        const f: *Fixture = @ptrCast(@alignCast(ctx));
        const n = std.mem.readInt(u16, tx[0..2], .little);
        f.mu.lockUncancelable(f.io);
        f.started[f.n_started] = n;
        f.n_started += 1;
        while (!f.open and !f.go[n]) f.cond.waitUncancelable(f.io, &f.mu);
        f.mu.unlock(f.io);
        try proto.okHeader(out, a, 0);
        try out.appendSlice(a, tx);
    }

    /// Queues job number `n` (a dry_run whose transaction bytes are the number).
    fn push(f: *Fixture, client: fairq.Key, conn: u64, n: u16) !bool {
        const gpa = testing.allocator;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        const w: proto.W = .{ .gpa = gpa, .out = &body };
        var tx: [2]u8 = undefined;
        std.mem.writeInt(u16, &tx, n, .little);
        try w.bytes(&tx);
        try w.u8_(0);
        var req: std.ArrayList(u8) = .empty;
        defer req.deinit(gpa);
        try proto.encodeRequest(&req, gpa, .dry_run, 0, body.items);
        return f.jobs.pushFor(client, conn, n, null, req.items);
    }

    /// Job `n` may end.
    fn let(f: *Fixture, n: u16) void {
        f.mu.lockUncancelable(f.io);
        f.go[n] = true;
        f.mu.unlock(f.io);
        f.cond.broadcast(f.io);
    }

    fn startedCount(f: *Fixture) usize {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        return f.n_started;
    }

    /// Waits (at most 10 s) until workers have taken `n` jobs.
    fn waitStarted(f: *Fixture, n: usize) !void {
        var ms: usize = 0;
        while (f.startedCount() < n) : (ms += 1) {
            if (ms > 10_000) return error.TestUnexpectedResult;
            f.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }

    /// Waits (at most 10 s) until `n` finished jobs wait for `collect`.
    fn waitDone(f: *Fixture, n: usize) !void {
        var ms: usize = 0;
        while (f.jobs.pending() < n) : (ms += 1) {
            if (ms > 10_000) return error.TestUnexpectedResult;
            f.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
    }
};

/// `collect` into a list of (stream, first response byte); `alive` is every connection but `dead`.
const Collected = struct {
    got: std.ArrayList([2]u64) = .empty,
    dead: u64 = 0,

    fn take(c: *Collected, stream: u64, bytes: []const u8) void {
        c.got.append(testing.allocator, .{ stream, if (bytes.len > 0) bytes[0] else 0xff }) catch {};
    }

    pub fn contains(c: *const Collected, key: u64) bool {
        return key != c.dead;
    }
};

test "feed pool: a client with the whole queue cannot keep a second one out, or make it wait" {
    const f = try Fixture.create(4, 64);
    defer f.destroy();
    const greedy: fairq.Key = 1;
    const tip: fairq.Key = 2;
    // one edge fills the queue from two of its connections: 4 run, 60 wait
    for (0..64) |n| try testing.expect(try f.push(greedy, 10 + n % 2, @intCast(n)));
    try f.waitStarted(4);
    for (f.started[0..4]) |n| try testing.expect(n < 4);
    // alone it is refused at 64, as before there were shares
    try testing.expect(!try f.push(greedy, 10, 64));
    try testing.expectEqual(@as(u64, 1), f.stats.refused_full.load(.monotonic));
    try testing.expectEqual(@as(u64, 64), f.stats.depth.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), f.stats.clients.load(.monotonic));
    try testing.expectEqual(@as(u64, 64), f.stats.client_depth_max.load(.monotonic));
    try testing.expectEqual(@as(u32, 0), f.wakes.load(.monotonic));
    // a second client asks for one checkpoint: it is not refused
    try testing.expect(try f.push(tip, 20, 100));
    try testing.expectEqual(@as(u64, 64), f.stats.depth.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), f.stats.clients.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), f.stats.clients_waiting.load(.monotonic));
    try testing.expectEqual(@as(u64, 63), f.stats.client_depth_max.load(.monotonic));
    try testing.expectEqual(@as(u64, 1), f.stats.refused_over_share.load(.monotonic));
    // the first client's newest request (63, on connection 11) is the one refused instead,
    // with the answer of a refused push, and the I/O thread was woken for it
    try testing.expectEqual(@as(u32, 1), f.wakes.load(.monotonic));
    var c11: Collected = .{};
    defer c11.got.deinit(testing.allocator);
    f.jobs.collect(11, &c11, Collected.take, &c11);
    try testing.expectEqualSlices([2]u64, &.{.{ 63, @intFromEnum(proto.Code.rate_limited) }}, c11.got.items);
    // one job ends: the free worker takes the second client's request, before the 59 queued
    // ahead of it. It waited one service time, not fifteen.
    f.let(f.started[0]);
    try f.waitStarted(5);
    try testing.expectEqual(@as(u16, 100), f.started[4]);
    try f.waitDone(1);
    // it ends; everything else runs out in the order it came
    f.let(100);
    try f.waitDone(2);
    var c20: Collected = .{};
    defer c20.got.deinit(testing.allocator);
    f.jobs.collect(20, &c20, Collected.take, &c20);
    try testing.expectEqualSlices([2]u64, &.{.{ 100, 0 }}, c20.got.items);
    try testing.expectEqual(@as(u64, 1), f.stats.clients.load(.monotonic));
    for (0..64) |n| f.let(@intCast(n));
    try f.waitStarted(64);
    try f.waitDone(63);
    try testing.expectEqual(@as(u64, 0), f.stats.depth.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), f.stats.clients.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), f.stats.client_depth_max.load(.monotonic));
}

test "feed pool: without shares the same second client is refused (the queue before)" {
    const f = try Fixture.create(4, null);
    defer f.destroy();
    for (0..64) |n| try testing.expect(try f.push(1, 10, @intCast(n)));
    try f.waitStarted(4);
    try testing.expect(!try f.push(1, 10, 64));
    try testing.expect(!try f.push(2, 20, 100));
}

test "feed pool: a connection that goes away gives its queued requests back, and nothing leaks" {
    const f = try Fixture.create(2, 16);
    defer f.destroy();
    // one client on two connections (10 and 11), another on a third (20)
    for (0..12) |n| try testing.expect(try f.push(1, 10 + n % 2, @intCast(n)));
    try f.waitStarted(2);
    for (0..4) |n| try testing.expect(try f.push(2, 20, 100 + @as(u16, @intCast(n))));
    try testing.expect(!try f.push(1, 10, 99));
    try testing.expectEqual(@as(u64, 16), f.stats.depth.load(.monotonic));
    // connection 10 closes: its 5 queued requests leave (0 is running and ends on its own)
    f.jobs.cancel(10);
    try testing.expectEqual(@as(u64, 11), f.stats.depth.load(.monotonic));
    try testing.expectEqual(@as(u64, 7), f.stats.client_depth_max.load(.monotonic));
    // the places are free at once, for the same client's other connection too
    try testing.expect(try f.push(1, 11, 98));
    // connection 11 closes as well
    f.jobs.cancel(11);
    try testing.expectEqual(@as(u64, 6), f.stats.depth.load(.monotonic));
    try testing.expectEqual(@as(u64, 2), f.stats.clients.load(.monotonic));
    // a connection with nothing queued, and a second cancel, change nothing
    f.jobs.cancel(10);
    f.jobs.cancel(77);
    try testing.expectEqual(@as(u64, 6), f.stats.depth.load(.monotonic));
    // the two running jobs of the client that left end; the other client's four run
    f.let(0);
    f.let(1);
    for (100..104) |n| f.let(@intCast(n));
    try f.waitStarted(6);
    try f.waitDone(6);
    for (f.started[2..6]) |n| try testing.expect(n >= 100);
    try testing.expectEqual(@as(u64, 0), f.stats.depth.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), f.stats.clients.load(.monotonic));
    // connection 20 collects its four; the answers for the closed connections are freed
    var c20: Collected = .{ .dead = 10 };
    defer c20.got.deinit(testing.allocator);
    f.jobs.collect(20, &c20, Collected.take, &c20);
    try testing.expectEqual(@as(usize, 4), c20.got.items.len);
    try testing.expectEqual(@as(usize, 1), f.jobs.pending());
    c20.dead = 11;
    f.jobs.collect(20, &c20, Collected.take, &c20);
    try testing.expectEqual(@as(usize, 0), f.jobs.pending());
    // jobs running and queued when the pool stops are freed with it
    for (200..205) |n| try testing.expect(try f.push(2, 20, @intCast(n)));
    try f.waitStarted(8);
}

test "feed pool: at the tip a request takes as long with shares as without" {
    // One request at a time, each from another of 16 clients, through the whole pool: queued,
    // taken by a worker, answered (a request that does not parse: no handler time), collected.
    const rounds = 3000;
    var ns: [2][rounds]u64 = undefined;
    const without = try Fixture.create(4, null);
    defer without.destroy();
    const with = try Fixture.create(4, 64);
    defer with.destroy();
    var none: Collected = .{};
    defer none.got.deinit(testing.allocator);
    for (0..rounds + 200) |i| {
        // alternate, so both see the same machine
        for ([2]*Fixture{ without, with }, 0..) |f, k| {
            const t0: u64 = @intCast(Io.Clock.awake.now(f.io).toNanoseconds());
            if (!f.jobs.pushFor(1 + i % 16, 7, i, null, "")) return error.TestUnexpectedResult;
            var spins: usize = 0;
            while (f.wakes.load(.acquire) <= i) : (spins += 1) {
                // at most 10 s for one answer
                if (spins & 0xffff == 0xffff and @as(u64, @intCast(Io.Clock.awake.now(f.io).toNanoseconds())) - t0 > 10 * std.time.ns_per_s) return error.TestUnexpectedResult;
                std.atomic.spinLoopHint();
            }
            f.jobs.collect(7, &none, Collected.take, &none);
            const t1: u64 = @intCast(Io.Clock.awake.now(f.io).toNanoseconds());
            if (i >= 200) ns[k][i - 200] = t1 - t0;
            none.got.clearRetainingCapacity();
        }
    }
    for (&ns) |*x| std.mem.sort(u64, x, {}, std.sort.asc(u64));
    const plain = ns[0][rounds / 2];
    const shared = ns[1][rounds / 2];
    if (std.c.getenv("ZUI_FEED_BENCH") != null)
        std.debug.print("feed pool, one request at the tip, push to collected: median {d} ns without shares, {d} ns with; p90 {d} and {d} ns; p99 {d} and {d} ns\n", .{ plain, shared, ns[0][rounds * 9 / 10], ns[1][rounds * 9 / 10], ns[0][rounds * 99 / 100], ns[1][rounds * 99 / 100] });
    // the same within noise; the bound only catches a queue that makes a request wait
    try testing.expect(shared < 3 * plain + 200 * std.time.ns_per_us);
}
