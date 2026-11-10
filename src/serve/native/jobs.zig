//! Worker threads for the slow zui/1 methods (dry_run, submit_transaction): the I/O thread
//! queues the request bytes, a worker runs the dispatcher on its own arena, and the finished
//! response waits in `done` until the I/O thread picks it up for that connection. A finished job
//! calls `wake` so the I/O thread's poll returns at once. Workers start on the first job.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");
const dispatch = @import("dispatch.zig");

pub const Job = struct {
    key: u64,
    stream: u64,
    principal: ?dispatch.Principal,
    /// The whole request (header and body), owned.
    req: []u8,
    /// The whole response, owned (set by the worker).
    out: []u8 = &.{},
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

    pub fn deinit(j: *Jobs) void {
        j.mu.lockUncancelable(j.io);
        j.closed = true;
        j.mu.unlock(j.io);
        j.cond.broadcast(j.io);
        for (j.threads.items) |t| t.join();
        j.threads.deinit(j.gpa);
        for (j.queue.items) |x| j.free(x);
        for (j.done.items) |x| j.free(x);
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
        const x = j.gpa.create(Job) catch return false;
        x.* = .{ .key = key, .stream = stream, .principal = principal, .req = j.gpa.dupe(u8, req) catch {
            j.gpa.destroy(x);
            return false;
        } };
        j.mu.lockUncancelable(j.io);
        defer j.mu.unlock(j.io);
        if (j.closed or j.inflight >= j.max_inflight) {
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
        j.queue.append(j.gpa, x) catch {
            j.free(x);
            return false;
        };
        j.inflight += 1;
        j.cond.signal(j.io);
        return true;
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

    fn worker(j: *Jobs) void {
        defer if (j.on_exit) |f| f();
        while (true) {
            j.mu.lockUncancelable(j.io);
            while (j.queue.items.len == 0 and !j.closed) j.cond.waitUncancelable(j.io, &j.mu);
            if (j.closed) {
                j.mu.unlock(j.io);
                return;
            }
            const x = j.queue.orderedRemove(0);
            j.mu.unlock(j.io);
            j.run(x);
            j.mu.lockUncancelable(j.io);
            j.inflight -= 1;
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
        if (proto.parseRequest(x.req)) |req| {
            j.disp.handle(a, req, x.principal, &out);
        } else proto.errorResponse(&out, a, .bad_request, "request header", "") catch {};
        x.out = j.gpa.dupe(u8, out.items) catch &.{};
    }
};
