//! Threads that are started once and kept: `spawn` hands a function to a parked thread of the
//! process's cache, and starts a new thread only when none is parked. A thread whose function
//! returned parks again for the next `spawn`; none ever exits.
//!
//! Why: starting a thread maps its stack and protects its guard page, and ending it unmaps the
//! stack; each of those takes the process's mmap lock for writing. Under Linux a writer queued
//! on that lock holds up every page fault of every other thread of the process behind it, and a
//! store that faults its pages in from disk turns that into a stall of the whole node (the
//! 2026-11-12 core hang: hundreds of short-lived threads a second, one per connection, flush
//! and sort, with fault-heavy readers). Paths that started a thread per task (a connection, a
//! server stream, a flush and its writers, a parallel sort or compression) take one from here.
//!
//! The cache is as large as the most threads ever running at once. Every cached thread has the
//! same stack, `stack_size`; a caller that needs more starts its own thread.
const std = @import("std");
const Atomic = std.atomic.Value;

/// The stack of every cached thread.
pub const stack_size: usize = 16 << 20;
/// The bytes of a function's arguments a cached thread holds (checked at compile time).
pub const args_max: usize = 2048;

pub const Stats = struct {
    /// Threads started (the cache grew), and functions handed to a parked thread.
    started: Atomic(u64) = .init(0),
    reused: Atomic(u64) = .init(0),
    /// Threads in the cache, and of them those parked now.
    threads: Atomic(u64) = .init(0),
    parked: Atomic(u64) = .init(0),
};
pub var stats: Stats = .{};

const Worker = struct {
    /// The task number given (futex word the thread parks on) and the last one finished
    /// (futex word `join` waits on). Numbers only grow, so a handle of a task long finished
    /// never waits for a later task on the same thread.
    given: Atomic(u32) align(4) = .init(0),
    finished: Atomic(u32) align(4) = .init(0),
    call: *const fn (w: *Worker) void = undefined,
    args: [args_max]u8 align(16) = undefined,
    next: ?*Worker = null,
};

/// A task handed to a thread: `join` waits until its function returned, `detach` lets it go.
pub const Handle = struct {
    w: *Worker,
    task: u32,

    pub fn join(h: Handle) void {
        const io = gio();
        while (true) {
            const f = h.w.finished.load(.acquire);
            // finished numbers only grow: at or past ours means ours returned
            if (f -% h.task < (1 << 31)) return;
            io.futexWaitUncancelable(u32, &h.w.finished.raw, f);
        }
    }

    pub fn detach(h: Handle) void {
        _ = h;
    }
};

var mu: std.Io.Mutex = .init;
var parked: ?*Worker = null;

fn gio() std.Io {
    return std.Io.Threaded.global_single_threaded.io();
}

/// Runs `@call(.auto, f, args)` on a cached thread. `f` returns void, or an error union of
/// void (ignored), like `std.Thread.spawn`'s functions.
pub fn spawn(comptime f: anytype, args: anytype) std.Thread.SpawnError!Handle {
    const Args = @TypeOf(args);
    comptime std.debug.assert(@sizeOf(Args) <= args_max and @alignOf(Args) <= 16);
    const Call = struct {
        fn call(w: *Worker) void {
            const a: *const Args = @ptrCast(@alignCast(&w.args));
            const r = @call(.auto, f, a.*);
            switch (@typeInfo(@TypeOf(r))) {
                .error_union => r catch {},
                else => {},
            }
        }
    };
    const w = take() orelse try grow();
    const a: *Args = @ptrCast(@alignCast(&w.args));
    a.* = args;
    w.call = Call.call;
    const task = w.given.load(.monotonic) +% 1;
    w.given.store(task, .release);
    gio().futexWake(u32, &w.given.raw, 1);
    return .{ .w = w, .task = task };
}

fn take() ?*Worker {
    const io = gio();
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    const w = parked orelse return null;
    parked = w.next;
    w.next = null;
    _ = stats.parked.fetchSub(1, .monotonic);
    _ = stats.reused.fetchAdd(1, .monotonic);
    return w;
}

fn park(w: *Worker) void {
    const io = gio();
    mu.lockUncancelable(io);
    defer mu.unlock(io);
    w.next = parked;
    parked = w;
    _ = stats.parked.fetchAdd(1, .monotonic);
}

/// A new thread, waiting for its first task (never freed: the thread never exits).
fn grow() std.Thread.SpawnError!*Worker {
    const w = std.heap.page_allocator.create(Worker) catch return error.SystemResources;
    w.* = .{};
    const t = std.Thread.spawn(.{ .stack_size = stack_size }, main, .{w}) catch |e| {
        std.heap.page_allocator.destroy(w);
        return e;
    };
    t.detach();
    _ = stats.started.fetchAdd(1, .monotonic);
    _ = stats.threads.fetchAdd(1, .monotonic);
    return w;
}

fn main(w: *Worker) void {
    const io = gio();
    var seen: u32 = 0;
    while (true) {
        while (w.given.load(.acquire) == seen) io.futexWaitUncancelable(u32, &w.given.raw, seen);
        seen = w.given.load(.acquire);
        w.call(w);
        // parked before the joiner is woken: a caller that joins and spawns again finds this
        // thread (a fan-out of N then reuses the same N threads, not N new ones each time)
        park(w);
        w.finished.store(seen, .release);
        io.futexWake(u32, &w.finished.raw, std.math.maxInt(u32));
    }
}

// ------------------------------------------------------------------ probes

/// Tests and benches: threads of the process now (macOS and Linux; null elsewhere).
pub fn processThreads() ?usize {
    const builtin = @import("builtin");
    switch (builtin.os.tag) {
        .macos => {
            const c = std.c;
            const task = c.mach_task_self();
            var list: c.mach_port_array_t = undefined;
            var n: c.mach_msg_type_number_t = 0;
            if (c.task_threads(task, &list, &n) != 0) return null;
            for (list[0..n]) |port| _ = c.mach_port_deallocate(task, port);
            _ = c.vm_deallocate(task, @intFromPtr(list), n * @sizeOf(c.mach_port_t));
            return n;
        },
        .linux => {
            // /proc/self/stat field 20 (num_threads); fields after the ")" of the name
            const fd = std.c.open("/proc/self/stat", .{ .ACCMODE = .RDONLY });
            if (fd < 0) return null;
            defer _ = std.c.close(fd);
            var buf: [1024]u8 = undefined;
            const r = std.c.read(fd, &buf, buf.len);
            if (r <= 0) return null;
            const text = buf[0..@intCast(r)];
            const close_paren = std.mem.lastIndexOfScalar(u8, text, ')') orelse return null;
            var it = std.mem.tokenizeScalar(u8, text[close_paren + 1 ..], ' ');
            var field: usize = 3;
            while (it.next()) |f| : (field += 1) if (field == 20) return std.fmt.parseInt(usize, f, 10) catch null;
            return null;
        },
        else => return null,
    }
}

const IntroHook = *const fn (event: c_uint, thread: ?*anyopaque, addr: ?*anyopaque, size: usize) callconv(.c) void;
extern "c" fn pthread_introspection_hook_install(hook: ?IntroHook) ?IntroHook;
var intro_prev: ?IntroHook = null;
var intro_state: Atomic(u8) = .init(0);
var intro_created: Atomic(u64) = .init(0);

fn introEvent(event: c_uint, thread: ?*anyopaque, addr: ?*anyopaque, size: usize) callconv(.c) void {
    // PTHREAD_INTROSPECTION_THREAD_CREATE
    if (event == 1) _ = intro_created.fetchAdd(1, .monotonic);
    if (intro_prev) |p| p(event, thread, addr, size);
}

/// Tests and benches: threads the process has started (any way: std.Thread, a library, this
/// cache) since the first call. macOS only (pthread introspection); null elsewhere.
pub fn threadsStarted() ?u64 {
    const builtin = @import("builtin");
    if (builtin.os.tag != .macos) return null;
    if (intro_state.cmpxchgStrong(0, 1, .acq_rel, .acquire) == null) {
        intro_prev = pthread_introspection_hook_install(introEvent);
        intro_state.store(2, .release);
    }
    while (intro_state.load(.acquire) != 2) std.atomic.spinLoopHint();
    return intro_created.load(.monotonic);
}

// ------------------------------------------------------------------ tests

const testing = std.testing;

fn addTo(x: *Atomic(u64), n: u64) void {
    _ = x.fetchAdd(n, .monotonic);
}

fn failing(x: *Atomic(u64)) error{Nope}!void {
    _ = x.fetchAdd(1, .monotonic);
    return error.Nope;
}

/// Adds `n`, then waits until `x` reaches `all` (every task of a fan-out running at once).
fn addThenMeet(x: *Atomic(u64), n: u64, all: u64) void {
    _ = x.fetchAdd(n, .monotonic);
    var spins: usize = 0;
    while (x.load(.monotonic) < all and spins < 50_000_000) : (spins += 1) std.Thread.yield() catch {};
}

test "spawn runs the function; joined threads are taken again, not started again" {
    var sum: Atomic(u64) = .init(0);
    // warm: a fan-out of 4 running at once (4 threads in the cache)
    var hs: [4]Handle = undefined;
    for (&hs) |*h| h.* = try spawn(addThenMeet, .{ &sum, 1, 4 });
    for (hs) |h| h.join();
    try testing.expectEqual(@as(u64, 4), sum.load(.monotonic));
    try testing.expect(stats.threads.load(.monotonic) >= 4);
    sum.store(10, .monotonic);
    const started = stats.started.load(.monotonic);
    // the OS's count agrees (macOS: every thread the process starts; both: threads now)
    const seen = threadsStarted();
    const threads0 = processThreads();
    // 1,000 fan-outs of 4: no thread started
    for (0..1000) |_| {
        for (&hs) |*h| h.* = try spawn(addTo, .{ &sum, 1 });
        for (hs) |h| h.join();
    }
    try testing.expectEqual(@as(u64, 4010), sum.load(.monotonic));
    try testing.expectEqual(started, stats.started.load(.monotonic));
    try testing.expectEqual(seen, threadsStarted());
    if (threads0) |n| try testing.expectEqual(n, processThreads().?);
    // an error from the function is dropped like std.Thread's
    const h = try spawn(failing, .{&sum});
    h.join();
    try testing.expectEqual(@as(u64, 4011), sum.load(.monotonic));
}

test "a detached task's thread parks again" {
    var sum: Atomic(u64) = .init(0);
    (try spawn(addTo, .{ &sum, 1 })).detach();
    var spins: usize = 0;
    while (sum.load(.monotonic) != 1 or stats.parked.load(.monotonic) == 0) : (spins += 1) {
        if (spins > 50_000_000) return error.TestUnexpectedResult;
        std.Thread.yield() catch {};
    }
    const started = stats.started.load(.monotonic);
    for (0..200) |_| {
        const h = try spawn(addTo, .{ &sum, 1 });
        h.join();
    }
    try testing.expectEqual(started, stats.started.load(.monotonic));
}
