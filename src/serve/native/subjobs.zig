//! Subscription frame production off the I/O thread. Building a checkpoint's frames reads the
//! store: the checkpoint record, its transactions, and for the Address and Package filters the
//! pre-state of every transaction (its loaded input objects at their old versions, sub.KeyCache).
//! On a busy core those reads fault in cold pages; done on the listener's I/O thread they stopped
//! it from reading the socket, processing ACKs and sending for as long as each fault took.
//!
//! The I/O thread decides what a subscription may receive (its credit, the room in its data
//! stream, the tip) and queues one `Work` for it; a worker produces the frames of up to that many
//! checkpoints from its own snapshot and the I/O thread writes them to the stream (`collect`).
//! One `Work` per subscription at a time, so a subscription's frames stay in checkpoint order.
const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const store = @import("store");
const sub = @import("sub.zig");
const dispatch = @import("dispatch.zig");
const jobs_mod = @import("jobs.zig");
const bufs_mod = @import("bufs.zig");

pub const Work = struct {
    /// The connection (listener slot key) and the subscription id.
    key: u64,
    sub_id: u64,
    /// First checkpoint, the highest the I/O thread saw committed, at most this many
    /// checkpoints, and the bytes after which no further checkpoint is started.
    start: u64,
    tip: u64,
    max_cps: u64,
    room: u64,
    /// The subscription's request (a copy the work owns).
    req: sub.Req,
    /// Set by the worker: the frames, the checkpoints they cover, whether any matched, and the
    /// error that stopped production at checkpoint `start + produced`.
    out: std.ArrayList(u8) = .empty,
    produced: u64 = 0,
    matched: bool = false,
    failed: ?anyerror = null,
};

pub const Stats = struct {
    /// Works queued and not yet taken by a worker, works waiting for the I/O thread.
    queued: Atomic(u64) = .init(0),
    /// Works done, time spent producing (total and longest), checkpoints produced.
    works: Atomic(u64) = .init(0),
    produce_ns: Atomic(u64) = .init(0),
    produce_max_ns: Atomic(u64) = .init(0),
    checkpoints: Atomic(u64) = .init(0),
};

pub const Pool = struct {
    gpa: Allocator,
    io: Io,
    disp: *dispatch.Dispatcher,
    keys: *sub.KeyCache,
    wake: jobs_mod.Wake,
    workers: usize = 2,
    mu: Io.Mutex = .init,
    cond: Io.Condition = .init,
    queue: std.ArrayList(*Work) = .empty,
    done: std.ArrayList(*Work) = .empty,
    running: usize = 0,
    closed: bool = false,
    threads: std.ArrayList(std.Thread) = .empty,
    /// Where the pool's gauges and counters go (the listener's, for the metrics endpoint).
    stats: *Stats,
    /// Frame buffers given back by freed works and taken by the workers (bufs.zig).
    bufs: bufs_mod.Bufs = .{},

    pub fn deinit(p: *Pool) void {
        p.mu.lockUncancelable(p.io);
        p.closed = true;
        p.mu.unlock(p.io);
        p.cond.broadcast(p.io);
        for (p.threads.items) |t| t.join();
        p.threads.deinit(p.gpa);
        for (p.queue.items) |w| p.free(w);
        for (p.done.items) |w| p.free(w);
        p.queue.deinit(p.gpa);
        p.done.deinit(p.gpa);
        p.bufs.deinit(p.gpa);
    }

    pub fn free(p: *Pool, w: *Work) void {
        p.bufs.give(p.gpa, p.io, &w.out);
        sub.deinit(p.gpa, &w.req);
        p.gpa.destroy(w);
    }

    /// Starts every worker now rather than on the first works (a fixed set, started once).
    pub fn startWorkers(p: *Pool) void {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        while (p.threads.items.len < p.workers) {
            const t = std.Thread.spawn(.{ .stack_size = 16 << 20 }, worker, .{p}) catch return;
            p.threads.append(p.gpa, t) catch return t.detach();
        }
    }

    /// Queues production for a subscription; false when it could not be queued (out of memory,
    /// closed, no thread): the I/O thread asks again on a later pass.
    pub fn push(p: *Pool, key: u64, sub_id: u64, req: *const sub.Req, start: u64, tip: u64, max_cps: u64, room: u64) bool {
        const w = p.gpa.create(Work) catch return false;
        w.* = .{ .key = key, .sub_id = sub_id, .start = start, .tip = tip, .max_cps = max_cps, .room = room, .req = sub.clone(p.gpa, req) catch {
            p.gpa.destroy(w);
            return false;
        } };
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        if (p.closed) {
            p.free(w);
            return false;
        }
        if (p.threads.items.len < p.workers and p.threads.items.len <= p.running + p.queue.items.len) {
            if (std.Thread.spawn(.{ .stack_size = 16 << 20 }, worker, .{p})) |t| {
                p.threads.append(p.gpa, t) catch t.detach();
            } else |_| if (p.threads.items.len == 0) {
                p.free(w);
                return false;
            }
        }
        p.queue.append(p.gpa, w) catch {
            p.free(w);
            return false;
        };
        p.stats.queued.store(p.queue.items.len, .monotonic);
        p.cond.signal(p.io);
        return true;
    }

    /// Works queued or running (any thread).
    pub fn busyNow(p: *Pool) usize {
        p.mu.lockUncancelable(p.io);
        defer p.mu.unlock(p.io);
        return p.queue.items.len + p.running;
    }

    /// Hands every finished work of connection `key` to `f`, then frees it; frees finished works
    /// whose connection `alive` says is gone. I/O thread only.
    pub fn collect(p: *Pool, key: u64, ctx: anytype, comptime f: fn (@TypeOf(ctx), *Work) void, alive: anytype) void {
        p.mu.lockUncancelable(p.io);
        var mine: std.ArrayList(*Work) = .empty;
        defer mine.deinit(p.gpa);
        var i: usize = 0;
        while (i < p.done.items.len) {
            const w = p.done.items[i];
            if (w.key == key) {
                mine.append(p.gpa, w) catch {
                    i += 1;
                    continue;
                };
            } else if (alive.contains(w.key)) {
                i += 1;
                continue;
            } else p.free(w);
            _ = p.done.orderedRemove(i);
        }
        p.mu.unlock(p.io);
        // outside the lock: `f` writes to streams and may queue the next work
        for (mine.items) |w| {
            f(ctx, w);
            p.free(w);
        }
    }

    fn worker(p: *Pool) void {
        // one arena per worker for its whole life (jobs.zig `worker`)
        var arena = std.heap.ArenaAllocator.init(p.gpa);
        defer arena.deinit();
        while (true) {
            p.mu.lockUncancelable(p.io);
            while (p.queue.items.len == 0 and !p.closed) p.cond.waitUncancelable(p.io, &p.mu);
            if (p.closed) {
                p.mu.unlock(p.io);
                return;
            }
            const w = p.queue.orderedRemove(0);
            p.running += 1;
            p.stats.queued.store(p.queue.items.len, .monotonic);
            p.mu.unlock(p.io);
            p.run(&arena, w);
            _ = arena.reset(.{ .retain_with_limit = jobs_mod.arena_keep });
            p.mu.lockUncancelable(p.io);
            p.running -= 1;
            p.done.append(p.gpa, w) catch {
                // the subscription would wait forever for this work: hand it back failed
                p.mu.unlock(p.io);
                p.free(w);
                continue;
            };
            p.mu.unlock(p.io);
            p.wake.call(p.wake.ctx);
        }
    }

    fn run(p: *Pool, arena: *std.heap.ArenaAllocator, w: *Work) void {
        const t0 = nowNs();
        defer {
            const dt = nowNs() -| t0;
            _ = p.stats.works.fetchAdd(1, .monotonic);
            _ = p.stats.produce_ns.fetchAdd(dt, .monotonic);
            _ = p.stats.produce_max_ns.fetchMax(dt, .monotonic);
            _ = p.stats.checkpoints.fetchAdd(w.produced, .monotonic);
        }
        var snap = p.disp.svc.store.snapshot();
        defer snap.release();
        if (w.out.capacity == 0) w.out = p.bufs.take(p.io);
        var seq = w.start;
        while (w.produced < w.max_cps and seq <= w.tip and w.out.items.len < w.room) : (seq += 1) {
            // An edge: the frames of this checkpoint would carry a certificate that is not its
            // core's (a Checkpoint frame, or the Proof of a verified match).
            if ((w.req.filter == .checkpoints or w.req.verify) and p.disp.withholdSeq(seq)) {
                w.failed = error.ForeignCertificate;
                return;
            }
            const rec = snap.checkpoint(seq) orelse return;
            _ = arena.reset(.retain_capacity);
            const before = w.out.items.len;
            const n = sub.produce(p.gpa, arena.allocator(), p.disp.svc, &snap, p.keys, &w.req, rec, &w.out) catch |e| {
                // none of the checkpoint's frames go out
                w.out.shrinkRetainingCapacity(before);
                // another worker is computing its pre-state: what is built goes out, and the
                // subscription asks again on a later pass (no wait with a snapshot held)
                if (e != error.Pending) w.failed = e;
                return;
            };
            w.produced += 1;
            if (n > 0) w.matched = true;
        }
    }
};

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}
