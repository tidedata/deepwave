//! A persistent CPU worker pool: one set of threads per process that every batch path shares
//! (Ed25519 host prep for the GPU, CPU batch verification, Groth16 and BLS batch checks,
//! validator signature pre-verification). Threads start once (`Pool.init`) and sleep on a futex
//! between jobs. `forRange` splits [0, n) into grains that lanes claim from one atomic counter,
//! so uneven items balance on their own; the calling thread is a lane too.
//!
//! One job at a time: a caller that finds the pool busy (another thread's job, or a nested call
//! from inside a job) runs its range inline on its own thread. So `forRange` never blocks on
//! another job and never deadlocks, and the result is the same either way.
//!
//! `shared()` is the process pool the node (or a tool) installs with `setShared`; with none
//! installed every `forRange` runs inline.
const std = @import("std");

const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;

pub const max_lanes = 128;

const JobFn = *const fn (ctx: *const anyopaque, lo: usize, hi: usize) void;

pub const Pool = struct {
    io: std.Io,
    gpa: Allocator,
    /// Worker threads (lanes - 1: the caller is the other lane).
    n: usize,
    threads: [max_lanes]?std.Thread = @splat(null),
    /// Futex word the workers wait on: (job sequence << 8) | workers taking part. One word, so
    /// a worker always reads the worker count of the job it woke for (a separate count could
    /// already belong to the next job: that worker then joined one job twice and the caller
    /// returned while a grain still ran). Changed for every job and for shutdown.
    gen: Atomic(u32) align(4) = .init(0),
    stop: Atomic(bool) = .init(false),
    /// Workers still inside the current job; the caller waits for 0.
    pending: Atomic(u32) align(4) = .init(0),
    busy: Atomic(bool) = .init(false),
    // the current job
    job_fn: JobFn = undefined,
    job_ctx: *const anyopaque = undefined,
    job_n: usize = 0,
    job_grain: usize = 1,
    next: Atomic(usize) = .init(0),

    /// Starts `lanes - 1` worker threads (lanes counts the caller; 0 = one lane per CPU), at
    /// most `max_lanes`. Fewer threads than asked when spawning fails; error only when not even
    /// the struct can be allocated.
    pub fn init(io: std.Io, gpa: Allocator, want_lanes: usize) Allocator.Error!*Pool {
        const want: usize = @min(max_lanes, if (want_lanes != 0) want_lanes else (std.Thread.getCpuCount() catch 1));
        const p = try gpa.create(Pool);
        p.* = .{ .io = io, .gpa = gpa, .n = 0 };
        var made: usize = 0;
        while (made + 1 < want) : (made += 1) {
            p.threads[made] = std.Thread.spawn(.{ .stack_size = 16 << 20 }, workerMain, .{ p, made }) catch break;
        }
        p.n = made;
        return p;
    }

    /// Stops and frees the pool. Not while a job runs.
    pub fn deinit(p: *Pool) void {
        p.stop.store(true, .release);
        p.gen.store(nextGen(p.gen.load(.monotonic), 0), .release);
        p.io.futexWake(u32, &p.gen.raw, std.math.maxInt(u32));
        for (p.threads[0..p.n]) |t| if (t) |th| th.join();
        p.gpa.destroy(p);
    }

    /// Lanes including the caller.
    pub fn lanes(p: *const Pool) usize {
        return p.n + 1;
    }

    fn workerMain(p: *Pool, idx: usize) void {
        var seen: u32 = 0;
        while (true) {
            // short spin first: back-to-back jobs (pipelined chunks) skip the futex round trip
            var spins: u32 = 0;
            while (p.gen.load(.acquire) == seen) {
                if (spins < 4000) {
                    std.atomic.spinLoopHint();
                    spins += 1;
                } else p.io.futexWaitUncancelable(u32, &p.gen.raw, seen);
            }
            seen = p.gen.load(.acquire);
            if (p.stop.load(.acquire)) return;
            if (idx >= (seen & 0xff)) continue;
            p.drain();
            if (p.pending.fetchSub(1, .acq_rel) == 1) p.io.futexWake(u32, &p.pending.raw, 1);
        }
    }

    fn drain(p: *Pool) void {
        const n = p.job_n;
        const g = p.job_grain;
        while (true) {
            const lo = p.next.fetchAdd(g, .acq_rel);
            if (lo >= n) return;
            p.job_fn(p.job_ctx, lo, @min(n, lo + g));
        }
    }

    /// Runs `f(ctx, lo, hi)` over [0, n) in grains of `grain` items on up to `max_lanes_used`
    /// lanes (0 = all). Returns when every grain is done. `f` must not depend on which lane
    /// runs a grain.
    pub fn forRange(p: *Pool, n: usize, grain: usize, max_lanes_used: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx), usize, usize) void) void {
        const C = @TypeOf(ctx);
        const g = @max(1, grain);
        const want_lanes = if (max_lanes_used == 0) p.lanes() else @min(max_lanes_used, p.lanes());
        const chunks = (n + g - 1) / g;
        if (n == 0) return;
        if (want_lanes <= 1 or chunks <= 1 or p.n == 0 or p.busy.cmpxchgStrong(false, true, .acquire, .monotonic) != null) {
            f(ctx, 0, n);
            return;
        }
        defer p.busy.store(false, .release);
        const Wrap = struct {
            fn run(c: *const anyopaque, lo: usize, hi: usize) void {
                const cp: *const C = @ptrCast(@alignCast(c));
                f(cp.*, lo, hi);
            }
        };
        const workers: u32 = @intCast(@min(want_lanes - 1, chunks - 1));
        p.job_fn = Wrap.run;
        p.job_ctx = @ptrCast(&ctx);
        p.job_n = n;
        p.job_grain = g;
        p.next.store(0, .release);
        p.pending.store(workers, .release);
        p.gen.store(nextGen(p.gen.load(.monotonic), workers), .release);
        // wake every sleeper: a wake for `workers` waiters could reach the ones not taking part
        p.io.futexWake(u32, &p.gen.raw, std.math.maxInt(u32));
        p.drain();
        while (true) {
            const left = p.pending.load(.acquire);
            if (left == 0) break;
            var spins: u32 = 0;
            while (spins < 2000 and p.pending.load(.acquire) == left) : (spins += 1) std.atomic.spinLoopHint();
            if (p.pending.load(.acquire) == left) p.io.futexWaitUncancelable(u32, &p.pending.raw, left);
        }
    }
};

fn nextGen(g: u32, workers: u32) u32 {
    comptime std.debug.assert(max_lanes <= 0xff);
    return ((g >> 8) +% 1) << 8 | workers;
}

/// Runs on `p` when given, inline otherwise.
pub fn forRange(p: ?*Pool, n: usize, grain: usize, max_lanes_used: usize, ctx: anytype, comptime f: fn (@TypeOf(ctx), usize, usize) void) void {
    if (p) |pp| return pp.forRange(n, grain, max_lanes_used, ctx, f);
    if (n != 0) f(ctx, 0, n);
}

var shared_pool: Atomic(?*Pool) = .init(null);

/// The process pool (null until a caller installs one).
pub fn shared() ?*Pool {
    return shared_pool.load(.acquire);
}

/// Installs the process pool (startup, before batch work); returns the previous one.
pub fn setShared(p: ?*Pool) ?*Pool {
    return shared_pool.swap(p, .acq_rel);
}

test "forRange covers every index once, nested calls run inline" {
    const io = std.testing.io;
    const p = try Pool.init(io, std.testing.allocator, 4);
    defer p.deinit();
    var hits: [10_000]Atomic(u32) = undefined;
    for (&hits) |*h| h.* = .init(0);
    const Flat = struct {
        hits: []Atomic(u32),
        fn f(c: @This(), lo: usize, hi: usize) void {
            for (lo..hi) |i| _ = c.hits[i].fetchAdd(1, .monotonic);
        }
    };
    for ([_]usize{ 1, 3, 64, 10_000 }) |grain| {
        p.forRange(hits.len, grain, 0, Flat{ .hits = &hits }, Flat.f);
    }
    for (&hits) |*h| try std.testing.expectEqual(@as(u32, 4), h.load(.monotonic));
    // inline when no pool
    forRange(null, hits.len, 100, 0, Flat{ .hits = &hits }, Flat.f);
    for (&hits) |*h| try std.testing.expectEqual(@as(u32, 5), h.load(.monotonic));
    // nested call from inside a job runs inline
    const Nest = struct {
        hits: []Atomic(u32),
        pool: *Pool,
        fn f(c: @This(), lo: usize, hi: usize) void {
            c.pool.forRange(hi - lo, 1, 0, Off{ .hits = c.hits, .base = lo }, Off.f);
        }
    };
    p.forRange(hits.len, 333, 0, Nest{ .hits = &hits, .pool = p }, Nest.f);
    for (&hits) |*h| try std.testing.expectEqual(@as(u32, 6), h.load(.monotonic));
}

test "back-to-back jobs with changing lane counts finish every grain once" {
    // Regression: a worker that skipped job g could read job g+1's worker count, join g+1 twice
    // and release the caller while another lane still ran a grain (or hang the caller).
    const io = std.testing.io;
    const p = try Pool.init(io, std.testing.allocator, 6);
    defer p.deinit();
    var hits: [64]Atomic(u32) = undefined;
    const Flat = struct {
        hits: []Atomic(u32),
        fn f(c: @This(), lo: usize, hi: usize) void {
            for (lo..hi) |i| _ = c.hits[i].fetchAdd(1, .monotonic);
        }
    };
    var prng = std.Random.DefaultPrng.init(7);
    const rng = prng.random();
    for (0..20_000) |_| {
        for (&hits) |*h| h.* = .init(0);
        const n = 1 + rng.uintLessThan(usize, hits.len);
        const grain = 1 + rng.uintLessThan(usize, 8);
        const lanes_used = rng.uintLessThan(usize, 7);
        p.forRange(n, grain, lanes_used, Flat{ .hits = &hits }, Flat.f);
        for (hits[0..n]) |*h| try std.testing.expectEqual(@as(u32, 1), h.load(.monotonic));
        for (hits[n..]) |*h| try std.testing.expectEqual(@as(u32, 0), h.load(.monotonic));
    }
}

const Off = struct {
    hits: []Atomic(u32),
    base: usize,
    fn f(c: Off, lo: usize, hi: usize) void {
        for (lo..hi) |i| _ = c.hits[c.base + i].fetchAdd(1, .monotonic);
    }
};
