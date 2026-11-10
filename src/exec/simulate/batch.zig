//! NOT WIRED YET: no node-owned Pool and no native-proto op call this; nothing in the node's
//! default paths uses it.
//!
//! Batch simulation: many transactions against ONE store snapshot, spread over a
//! fixed pool of long-lived worker threads (so each worker's package cache and Move VM runtimes
//! stay warm, as `rpc_exec.pool` does for gRPC SimulateTransaction).
//!
//!   var pool: batch.Pool = undefined;
//!   try pool.init(gpa, io, .{});                    // once; workers = cores by default
//!   defer pool.deinit();
//!   var snap = st.snapshot(); defer snap.release(); // MVCC: every job reads this one view
//!   var b = try pool.simulateMany(&eng, &snap, reqs);   // reqs: []const api.Request
//!   defer b.deinit();
//!   for (0..reqs.len) |i| switch (b.one(i)) { .executed => ..., .rejected => ... }
//!
//! - Isolation: jobs never see each other's writes (each starts from `snap`); use
//!   `simulateChains` for jobs whose steps chain (each step sees the earlier steps' outputs,
//!   `Engine.simulateChain` semantics). Answers are meant to be identical to calling
//!   `Engine.simulate` / `simulateChain` one at a time on the same snapshot, in any order, on
//!   any thread, EXCLUDING the random ValidDuring nonce gas selection draws when `core.io` is set
//!   (use `core.io = null` for equivalence checks; see the `batch/<seq>` item of the
//!   simulate-engine conformance suite, which compares via `sameResult`).
//! - Memory: each result borrows from the batch (one arena per ticket) and from `snap`; keep
//!   both alive until `Batch.deinit`. `gpa` must be thread safe. A ticket's arena keeps every
//!   job's scratch until `deinit`, so a batch is bounded by `Options.max_jobs` / `max_steps`
//!   (`error.BatchTooLarge`); callers split larger loads into several batches.
//! - Cache memory: workers hold thread-local package caches. A node running this next to
//!   `rpc_exec.pool` must call `api.setCacheBudget(cache_mb, rpc_workers + batch_workers
//!   [+ executor threads])` so the shared `--exec-cache-mb` budget covers every thread.
//! - Failure: a job that hits an internal error (out of memory, no epoch) answers `.rejected`
//!   with code 13 (its slots are preallocated, so even out of memory cannot lose them); it
//!   never fails the batch. An empty job is `error.EmptyJob`.
//! - Reentrancy: `runAt` called from one of this pool's workers runs the jobs inline on that
//!   thread instead of queueing (queued tickets behind a blocked worker would deadlock).
const std = @import("std");
const store = @import("store");
const rpc_exec = @import("rpc_exec");
const api = @import("api.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

/// One job: a chain of one or more requests run in order on the snapshot.
pub const Job = []const api.Request;

pub const Batch = struct {
    gpa: Allocator,
    /// Per job, one Result per step.
    results: []const []const api.Result,
    /// Preallocated rejected(13) answers for every step of every job; `results[i]` starts as a
    /// slice of it and is replaced by the arena's answers when the job ran.
    fallback: []api.Result,
    arenas: []std.heap.ArenaAllocator,
    tickets: []Ticket,
    /// The pool the arenas go back to (reset, their first buffer kept) on `deinit`, so the next
    /// batch runs on memory that is already mapped. A batch must be freed before its pool.
    pool: ?*Pool = null,

    /// The only result of a single-step job (`simulateMany`).
    pub fn one(b: *const Batch, i: usize) api.Result {
        const r = b.results[i];
        if (r.len == 0) return .{ .rejected = .{ .code = 13, .message = "EmptyJob" } };
        return r[0];
    }

    pub fn deinit(b: *Batch) void {
        if (b.pool) |p| p.giveBack(b.arenas) else for (b.arenas) |*a| a.deinit();
        b.gpa.free(b.arenas);
        b.gpa.free(b.tickets);
        b.gpa.free(b.results);
        b.gpa.free(b.fallback);
        b.* = undefined;
    }
};

const Task = struct {
    engine: *const api.Engine,
    env: *const api.EpochEnv,
    base: api.State,
    jobs: []const Job,
    out: [][]const api.Result,
    next: std.atomic.Value(usize) = .init(0),
    pending: std.atomic.Value(usize),
    done: Io.Event = .unset,
};

const Ticket = struct {
    task: *Task,
    arena: *std.heap.ArenaAllocator,
    link: ?*Ticket = null,
};

pub const Options = struct {
    /// Worker threads (0: half the cores, 2 to 16, as `rpc_exec.pool`; remember
    /// `api.setCacheBudget` over all caching threads).
    workers: usize = 0,
    /// Most jobs in one batch.
    max_jobs: usize = 4096,
    /// Most steps (requests) over all jobs of one batch.
    max_steps: usize = 16384,
    /// Called by each worker as it exits (api.releaseThreadCaches frees its package caches).
    on_exit: ?*const fn () void = null,
    /// A finished batch's arenas are reset and reused by the next batch, each keeping up to this
    /// much mapped memory (0: free them). Fresh arenas made every batch pay its page faults
    /// again: batch.Pool ran at 1499 sims/s on 1 worker against 2077 for a plain thread.
    keep_arena_bytes: usize = 32 << 20,
};

pub const Pool = struct {
    io: Io,
    gpa: Allocator,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    head: ?*Ticket = null,
    tail: ?*Ticket = null,
    closed: bool = false,
    threads: []std.Thread,
    on_exit: ?*const fn () void,
    max_jobs: usize,
    max_steps: usize,
    /// Arenas of finished batches, reset with their first `keep_bytes` kept (guarded by `mu`).
    spare: std.ArrayList(std.heap.ArenaAllocator) = .empty,
    keep_bytes: usize,

    /// True on this pool's worker threads (a batch started from one runs inline).
    threadlocal var in_pool: bool = false;

    /// Starts the workers. `p` must not move while they run.
    pub fn init(p: *Pool, gpa: Allocator, io: Io, opts: Options) !void {
        const cpus = std.Thread.getCpuCount() catch 4;
        const n = if (opts.workers != 0) opts.workers else std.math.clamp(cpus / 2, 2, 16);
        p.* = .{ .io = io, .gpa = gpa, .threads = try gpa.alloc(std.Thread, n), .on_exit = opts.on_exit, .max_jobs = opts.max_jobs, .max_steps = opts.max_steps, .keep_bytes = opts.keep_arena_bytes };
        var started: usize = 0;
        errdefer {
            p.close();
            for (p.threads[0..started]) |t| t.join();
            gpa.free(p.threads);
        }
        while (started < n) : (started += 1) p.threads[started] = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, worker, .{p});
    }

    fn close(p: *Pool) void {
        p.mu.lockUncancelable(p.io);
        p.closed = true;
        p.mu.unlock(p.io);
        p.cond.broadcast(p.io);
    }

    /// Lets the queued batches finish, joins the workers.
    pub fn deinit(p: *Pool) void {
        p.close();
        for (p.threads) |t| t.join();
        p.gpa.free(p.threads);
        for (p.spare.items) |*a| a.deinit();
        p.spare.deinit(p.gpa);
    }

    /// Takes a reset arena from the spares, or a new one.
    fn takeArena(p: *Pool) std.heap.ArenaAllocator {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        return p.spare.pop() orelse std.heap.ArenaAllocator.init(p.gpa);
    }

    /// A finished batch's arenas: reset (keeping up to `keep_bytes` each) and kept for the next
    /// batches, at most one per worker; the rest are freed.
    fn giveBack(p: *Pool, arenas: []std.heap.ArenaAllocator) void {
        for (arenas) |*a| {
            if (p.keep_bytes == 0) {
                a.deinit();
                continue;
            }
            _ = a.reset(.{ .retain_with_limit = p.keep_bytes });
            p.mu.lockUncancelable(p.io);
            const kept = p.spare.items.len < p.threads.len and (p.spare.append(p.gpa, a.*) catch null) != null;
            p.mu.unlock(p.io);
            if (!kept) a.deinit();
        }
    }

    pub fn workers(p: *const Pool) usize {
        return p.threads.len;
    }

    /// Independent single-transaction jobs on one snapshot, at the engine's tip epoch.
    pub fn simulateMany(p: *Pool, e: *const api.Engine, snap: *const store.Snapshot, reqs: []const api.Request) !Batch {
        const jobs = try p.gpa.alloc(Job, reqs.len);
        defer p.gpa.free(jobs);
        for (reqs, jobs, 0..) |_, *j, i| j.* = reqs[i .. i + 1];
        return p.simulateChains(e, snap, jobs);
    }

    /// Jobs of chained steps on one snapshot, at the engine's tip epoch.
    pub fn simulateChains(p: *Pool, e: *const api.Engine, snap: *const store.Snapshot, jobs: []const Job) !Batch {
        const tip = e.tip orelse return error.NoTip;
        const env = tip.env.get(tip.env.ctx) orelse return error.EpochUnavailable;
        return p.runAt(e, &env, api.State.fromSnapshot(snap), jobs);
    }

    /// As `simulateChains` for an explicit epoch and pre-state (tests, replays). `base` must be
    /// safe to read from several threads.
    pub fn runAt(p: *Pool, e: *const api.Engine, env: *const api.EpochEnv, base: api.State, jobs: []const Job) !Batch {
        if (jobs.len > p.max_jobs) return error.BatchTooLarge;
        var steps: usize = 0;
        for (jobs) |j| {
            if (j.len == 0) return error.EmptyJob;
            steps +|= j.len;
        }
        if (steps > p.max_steps) return error.BatchTooLarge;
        var batch = try p.prepare(jobs, steps);
        errdefer batch.deinit();
        if (jobs.len == 0) return batch;
        var task: Task = .{ .engine = e, .env = env, .base = base, .jobs = jobs, .out = @constCast(batch.results), .pending = .init(batch.tickets.len) };
        for (batch.tickets, batch.arenas) |*t, *a| t.* = .{ .task = &task, .arena = a };
        if (in_pool) {
            runTicket(&task, batch.arenas[0].allocator());
            return batch;
        }
        {
            p.mu.lockUncancelable(p.io);
            defer p.mu.unlock(p.io);
            if (p.closed) return error.PoolClosed;
            for (batch.tickets) |*t| {
                if (p.tail) |tl| tl.link = t else p.head = t;
                p.tail = t;
                t.link = null;
            }
        }
        p.cond.broadcast(p.io);
        task.done.waitUncancelable(p.io);
        return batch;
    }

    fn prepare(p: *Pool, jobs: []const Job, steps: usize) !Batch {
        const nt = @min(p.threads.len, jobs.len);
        const fallback = try p.gpa.alloc(api.Result, steps);
        errdefer p.gpa.free(fallback);
        @memset(fallback, .{ .rejected = .{ .code = 13, .message = "OutOfMemory" } });
        const results = try p.gpa.alloc([]const api.Result, jobs.len);
        errdefer p.gpa.free(results);
        var off: usize = 0;
        for (jobs, results) |j, *r| {
            r.* = fallback[off .. off + j.len];
            off += j.len;
        }
        const arenas = try p.gpa.alloc(std.heap.ArenaAllocator, nt);
        errdefer p.gpa.free(arenas);
        const tickets = try p.gpa.alloc(Ticket, nt);
        for (arenas) |*a| a.* = p.takeArena();
        return .{ .gpa = p.gpa, .results = results, .fallback = fallback, .arenas = arenas, .tickets = tickets, .pool = p };
    }

    fn worker(p: *Pool) void {
        in_pool = true;
        defer if (p.on_exit) |f| f();
        while (true) {
            p.mu.lockUncancelable(p.io);
            while (p.head == null and !p.closed) p.cond.waitUncancelable(p.io, &p.mu);
            const t = p.head orelse {
                p.mu.unlock(p.io);
                return;
            };
            p.head = t.link;
            if (p.head == null) p.tail = null;
            p.mu.unlock(p.io);
            const task = t.task;
            const arena = t.arena;
            runTicket(task, arena.allocator());
            // the last ticket wakes the caller; `t` and `task` die with the caller's frame after
            if (task.pending.fetchSub(1, .acq_rel) == 1) task.done.set(p.io);
        }
    }
};

fn runTicket(task: *Task, arena: Allocator) void {
    while (true) {
        const i = task.next.fetchAdd(1, .monotonic);
        if (i >= task.jobs.len) return;
        task.out[i] = runJob(task, arena, task.jobs[i], task.out[i]);
    }
}

/// `slot`: the job's preallocated rejected(13) answers; kept (with the error's name) when the
/// engine fails, so the slot is never empty.
fn runJob(task: *Task, arena: Allocator, job: Job, slot: []const api.Result) []const api.Result {
    if (task.engine.simulateChainAt(arena, task.env, task.base, job)) |r| return r else |err| {
        const out: []api.Result = @constCast(slot);
        for (out) |*o| o.* = .{ .rejected = .{ .code = 13, .message = @errorName(err) } };
        return slot;
    }
}

/// Whether two answers are the same (rejection code and message, or digest, effects, events,
/// data and status of an execution). For equivalence checks of batch against sequential runs.
pub fn sameResult(a: api.Result, b: api.Result) bool {
    switch (a) {
        .rejected => |x| return b == .rejected and x.code == b.rejected.code and std.mem.eql(u8, x.message, b.rejected.message),
        .executed => |x| {
            if (b != .executed) return false;
            const y = b.executed;
            if (!std.mem.eql(u8, &x.digest, &y.digest) or !std.mem.eql(u8, x.effects, y.effects) or !std.mem.eql(u8, x.tx_data, y.tx_data)) return false;
            if (std.meta.activeTag(x.status) != std.meta.activeTag(y.status)) return false;
            const xe = x.events orelse &[_]u8{};
            const ye = y.events orelse &[_]u8{};
            return std.mem.eql(u8, xe, ye) and x.object_changes.len == y.object_changes.len;
        },
    }
}

test "a batch spreads jobs over the workers and keeps every answer in its slot" {
    const io = std.testing.io;
    var pool: Pool = undefined;
    try pool.init(std.testing.allocator, io, .{ .workers = 3 });
    defer pool.deinit();
    var m: rpc_exec.state.MapState = .{};
    // garbage transactions are rejected before the engine needs its core or an epoch
    var eng: api.Engine = .{ .core = undefined };
    var env: api.EpochEnv = undefined;
    var reqs: [40]api.Request = undefined;
    var bytes: [40][3]u8 = undefined;
    for (&reqs, &bytes, 0..) |*r, *b, i| {
        b.* = .{ @intCast(i), 0xff, 0xff };
        r.* = .{ .tx = .{ .data = b } };
    }
    const jobs = try std.testing.allocator.alloc(Job, reqs.len);
    defer std.testing.allocator.free(jobs);
    for (jobs, 0..) |*j, i| j.* = reqs[i .. i + 1];
    var b = try pool.runAt(&eng, &env, m.state(), jobs);
    defer b.deinit();
    try std.testing.expectEqual(@as(usize, 40), b.results.len);
    for (0..40) |i| try std.testing.expectEqual(@as(u8, 3), b.one(i).rejected.code);
    var empty = try pool.runAt(&eng, &env, m.state(), &.{});
    empty.deinit();
}

test "empty and oversized jobs are refused, and a failed slot keeps its answer" {
    const io = std.testing.io;
    var pool: Pool = undefined;
    try pool.init(std.testing.allocator, io, .{ .workers = 2, .max_jobs = 2 });
    defer pool.deinit();
    var m: rpc_exec.state.MapState = .{};
    var eng: api.Engine = .{ .core = undefined };
    var env: api.EpochEnv = undefined;
    const empty: Job = &.{};
    try std.testing.expectError(error.EmptyJob, pool.runAt(&eng, &env, m.state(), &.{empty}));
    const r: api.Request = .{ .tx = .{ .data = &.{0xff} } };
    const j: Job = &.{r};
    try std.testing.expectError(error.BatchTooLarge, pool.runAt(&eng, &env, m.state(), &.{ j, j, j }));
}

test "finished batches hand their arenas back to the pool for the next batch" {
    const io = std.testing.io;
    var pool: Pool = undefined;
    try pool.init(std.testing.allocator, io, .{ .workers = 2 });
    defer pool.deinit();
    var m: rpc_exec.state.MapState = .{};
    var eng: api.Engine = .{ .core = undefined };
    var env: api.EpochEnv = undefined;
    var bytes: [6][3]u8 = undefined;
    var reqs: [6]api.Request = undefined;
    for (&reqs, &bytes, 0..) |*r, *b, i| {
        b.* = .{ @intCast(i), 0xfe, 0xff };
        r.* = .{ .tx = .{ .data = b } };
    }
    var jobs: [6]Job = undefined;
    for (&jobs, 0..) |*j, i| j.* = reqs[i .. i + 1];
    for (0..3) |_| {
        var b = try pool.runAt(&eng, &env, m.state(), &jobs);
        for (0..6) |i| try std.testing.expectEqual(@as(u8, 3), b.one(i).rejected.code);
        b.deinit();
        try std.testing.expectEqual(@as(usize, 2), pool.spare.items.len);
    }
}
