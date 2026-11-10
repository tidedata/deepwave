//! Read-ahead for List* items (ListCheckpoints, ListTransactions): while one thread renders a
//! chunk's items in order, worker threads read the items' transactions and object sets, many
//! reads in flight, and hand the object bytes to the renderer (`PreObjects`), which then
//! decodes and encodes only.
//!
//! Why. A ListCheckpoints page of 16 mainnet checkpoints with the full mask reads ~500
//! transactions and 7,000-20,000 object versions (index pages plus records); a ListTransactions
//! page of 50-150 with any `effects.*` or `balance_changes` path reads up to 35,000 (sui-rpc-api
//! fetches the object set for those masks). On the rendering thread each was a blocking fault,
//! queue depth 1: 5-8 s cold on box 5's EBS volume where sui-node answered in 1-3 s, and
//! 250-450 ms even with every page cached (13 us a lookup).
//!
//! How. Two levels of work shared by all workers: transactions (item order), then their object
//! keys in batches of `key_batch`. Workers take transactions first (every transaction record is
//! in flight at once), then key batches in queue order, so a transaction with thousands of
//! objects is read by every worker. Each batch writes its objects into the transaction's slot;
//! the slot is ready when its last batch lands. Workers read through the request's own snapshot
//! (reads are `*const`, safe from any thread), so the slices stay valid until the request ends,
//! exactly as if the renderer had read them. A slot with a missing object is marked failed and
//! the renderer reads that transaction itself, which produces sui-node's error text.
//!
//! `ZUI_LH_WARM` sets the workers per chunk (default 32, 0 = off); at most `max_live` run at
//! once across all requests (a request over the cap gets fewer; with none the renderer reads
//! everything itself). Workers check `stop` between units, so a cancelled or timed-out request
//! joins within one batch's reads.
//!
//! Can this be faster: the renderer's wait is now the first item's read chain (checkpoint
//! record, transaction, keys, objects: four dependent reads) plus decode and encode of what is
//! read. Below that: io_uring batches per dependency level instead of threads faulting pages
//! (store/prefetch.zig's pattern, needs the store's version-index pages and record locations as
//! read requests), and a per-checkpoint object-key list kept at commit so the keys need no
//! transaction decode.
const std = @import("std");
const Allocator = std.mem.Allocator;
const store = @import("store");
const service = @import("service.zig");
const objset = @import("objset.zig");

pub const max_per_job = 64;
const max_live = 256;
const key_batch = 16;
var live: std.atomic.Value(u32) = .init(0);
var conf: std.atomic.Value(u32) = .init(std.math.maxInt(u32));

/// Workers per chunk (ZUI_LH_WARM, read once).
pub fn workers() u32 {
    const v = conf.load(.monotonic);
    if (v != std.math.maxInt(u32)) return v;
    var n: u32 = 32;
    if (std.c.getenv("ZUI_LH_WARM")) |s| n = std.fmt.parseInt(u32, std.mem.span(s), 10) catch 32;
    n = @min(n, max_per_job);
    conf.store(n, .monotonic);
    return n;
}

const pending: u8 = 0;
const ready: u8 = 1;
const failed: u8 = 2;

const Slot = struct {
    state: std.atomic.Value(u8) = .init(pending),
    /// Batches still being read (set before they are queued).
    left: std.atomic.Value(u32) = .init(0),
    bad: std.atomic.Value(bool) = .init(false),
    vals: [][]const u8 = &.{},
    /// The transaction record's location: the hint for its object versions (Snapshot.objectNear).
    at: u64 = 0,
};

const Batch = struct { slot: u32, off: u32, keys: []const objset.Ref };

pub const Job = struct {
    svc: ?*service.Service,
    /// The request's snapshot: every worker reads through it.
    snap: ?*store.Snapshot = null,
    digests: []const [32]u8,
    /// The checkpoint holding each digest (same length), or empty: the hint for the transaction
    /// lookup (Snapshot.transactionNear).
    cps: []const u64 = &.{},
    /// Read the transaction's object set too (masks with effects, objects or balance_changes).
    objects: bool,
    /// Read the transaction's checkpoint record too (ListTransactions renders its timestamp).
    checkpoint: bool = false,
    slots: []Slot = &.{},
    next: std.atomic.Value(usize) = .init(0),
    stop: std.atomic.Value(bool) = .init(false),
    /// Workers reading a transaction (they may still queue batches).
    producing: std.atomic.Value(u32) = .init(0),
    mu: std.atomic.Mutex = .unlocked,
    queue: std.ArrayList(Batch) = .empty,
    head: usize = 0,
    /// Per-worker memory for keys and object slices, kept until `finish`.
    arenas: [max_per_job]std.heap.ArenaAllocator = undefined,
    threads: [max_per_job]std.Thread = undefined,
    n: usize = 0,
    /// Store index probes of the workers (store.ProbeStats), summed as they exit.
    probes: [5]std.atomic.Value(u64) = @splat(.init(0)),

    /// Starts up to `want` workers (fewer when the global cap is hit). `slot_mem`: the
    /// request's arena, for one slot per digest.
    pub fn start(j: *Job, slot_mem: Allocator, want: u32) !void {
        if (j.svc == null or j.snap == null or j.digests.len == 0) return;
        if (j.objects) {
            j.slots = try slot_mem.alloc(Slot, j.digests.len);
            for (j.slots) |*s| s.* = .{};
        }
        const n = @min(@as(usize, want), max_per_job, if (j.objects) max_per_job else j.digests.len);
        while (j.n < n) {
            const prev = live.fetchAdd(1, .acq_rel);
            if (prev >= max_live) {
                _ = live.fetchSub(1, .acq_rel);
                break;
            }
            j.arenas[j.n] = .init(std.heap.page_allocator);
            j.threads[j.n] = std.Thread.spawn(.{ .stack_size = 1 << 20 }, worker, .{ j, j.n }) catch {
                j.arenas[j.n].deinit();
                _ = live.fetchSub(1, .acq_rel);
                break;
            };
            j.n += 1;
        }
    }

    /// Transaction `i`'s object bytes in key order, waiting for the workers to read them; null
    /// when the caller must read them itself (no workers, another digest, a missing object).
    pub fn objectsOf(j: *Job, i: usize, digest: *const [32]u8) ?[]const []const u8 {
        if (j.n == 0 or i >= j.slots.len or !std.mem.eql(u8, &j.digests[i], digest)) return null;
        const s = &j.slots[i];
        const t0 = service.profNs();
        defer service.prof.wait_ns += service.profNs() - t0;
        var spins: u32 = 0;
        while (true) : (spins += 1) {
            switch (s.state.load(.acquire)) {
                ready => {
                    service.prof.pre_objs += s.vals.len;
                    return s.vals;
                },
                failed => return null,
                else => if (spins < 64) std.atomic.spinLoopHint() else std.Thread.yield() catch {},
            }
        }
    }

    pub fn pre(j: *Job, base: usize) service.PreObjects {
        if (j.n == 0 or j.slots.len == 0) return .{};
        return .{ .ctx = j, .base = base, .get = getFn };
    }
    fn getFn(ctx: *anyopaque, i: usize, digest: *const [32]u8) ?[]const []const u8 {
        const j: *Job = @ptrCast(@alignCast(ctx));
        return j.objectsOf(i, digest);
    }

    /// Stops the workers (between units) and joins them; the slots' slices stay valid until
    /// the request's snapshot is released, their memory is freed here.
    pub fn finish(j: *Job) void {
        j.stop.store(true, .release);
        for (j.threads[0..j.n], j.arenas[0..j.n]) |t, *a| {
            t.join();
            a.deinit();
        }
        _ = live.fetchSub(@intCast(j.n), .acq_rel);
        j.n = 0;
        service.prof.w_runs += j.probes[0].load(.monotonic);
        service.prof.w_live += j.probes[1].load(.monotonic);
        service.prof.w_hits += j.probes[2].load(.monotonic);
        service.prof.w_falls += j.probes[3].load(.monotonic);
        service.prof.w_skips += j.probes[4].load(.monotonic);
        j.queue.deinit(std.heap.page_allocator);
    }

    fn lock(j: *Job) void {
        while (!j.mu.tryLock()) std.atomic.spinLoopHint();
    }

    fn popBatch(j: *Job) ?Batch {
        j.lock();
        defer j.mu.unlock();
        if (j.head == j.queue.items.len) return null;
        j.head += 1;
        return j.queue.items[j.head - 1];
    }

    fn queueEmpty(j: *Job) bool {
        j.lock();
        defer j.mu.unlock();
        return j.head == j.queue.items.len;
    }

    fn worker(j: *Job, w: usize) void {
        var scratch = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer scratch.deinit();
        const keep = j.arenas[w].allocator();
        const snap = j.snap.?;
        const ps0 = store.probeStats().*;
        defer {
            const ps = store.probeStats().*;
            _ = j.probes[0].fetchAdd(ps.run_probes - ps0.run_probes, .monotonic);
            _ = j.probes[1].fetchAdd(ps.live_probes - ps0.live_probes, .monotonic);
            _ = j.probes[2].fetchAdd(ps.near_hits - ps0.near_hits, .monotonic);
            _ = j.probes[3].fetchAdd(ps.near_falls - ps0.near_falls, .monotonic);
            _ = j.probes[4].fetchAdd(ps.filter_skips - ps0.filter_skips, .monotonic);
        }
        while (!j.stop.load(.acquire)) {
            _ = j.producing.fetchAdd(1, .acq_rel);
            const i = j.next.fetchAdd(1, .monotonic);
            if (i < j.digests.len) {
                _ = scratch.reset(.{ .retain_with_limit = 4 << 20 });
                j.one(scratch.allocator(), keep, snap, i);
                _ = j.producing.fetchSub(1, .acq_rel);
                continue;
            }
            _ = j.producing.fetchSub(1, .acq_rel);
            if (j.popBatch()) |b| {
                j.readBatch(snap, b);
                continue;
            }
            // Done once no transaction reader can queue more batches.
            if (j.producing.load(.acquire) == 0 and j.queueEmpty()) break;
            std.Thread.yield() catch {};
        }
    }

    fn readBatch(j: *Job, snap: *store.Snapshot, b: Batch) void {
        const s = &j.slots[b.slot];
        for (b.keys, b.off..) |k, x| {
            if (s.bad.load(.monotonic)) break;
            s.vals[x] = snap.objectNear(&k.id, k.version, s.at) orelse {
                s.bad.store(true, .monotonic);
                break;
            };
        }
        if (s.left.fetchSub(1, .acq_rel) == 1) s.state.store(if (s.bad.load(.monotonic)) failed else ready, .release);
    }

    fn one(j: *Job, scratch: Allocator, keep: Allocator, snap: *store.Snapshot, i: usize) void {
        const slot: ?*Slot = if (j.objects) &j.slots[i] else null;
        var settled = false; // the slot's batches (or its ready state) are out of this function's hands
        defer if (slot) |s| if (!settled) s.state.store(failed, .release);
        const rec = (if (i < j.cps.len) snap.transactionNear(&j.digests[i], j.cps[i]) else snap.transaction(&j.digests[i])) orelse return;
        if (j.checkpoint) _ = snap.checkpoint(rec.checkpoint);
        const s = slot orelse return;
        s.at = rec.loc;
        const k0 = service.objectKeys(j.svc.?, scratch, snap, rec) catch return;
        const keys = keep.dupe(objset.Ref, k0) catch return;
        s.vals = keep.alloc([]const u8, keys.len) catch return;
        settled = true;
        if (keys.len == 0) {
            s.state.store(ready, .release);
            return;
        }
        const nb: u32 = @intCast((keys.len + key_batch - 1) / key_batch);
        s.left.store(nb, .release);
        // Queue all but the first batch, then read the first here.
        if (nb > 1) {
            j.lock();
            defer j.mu.unlock();
            var off: usize = key_batch;
            while (off < keys.len) : (off += key_batch) {
                j.queue.append(std.heap.page_allocator, .{ .slot = @intCast(i), .off = @intCast(off), .keys = keys[off..@min(keys.len, off + key_batch)] }) catch {
                    // Out of memory: read the rest here.
                    j.mu.unlock();
                    defer j.lock();
                    j.readBatch(snap, .{ .slot = @intCast(i), .off = @intCast(off), .keys = keys[off..@min(keys.len, off + key_batch)] });
                };
            }
        }
        j.readBatch(snap, .{ .slot = @intCast(i), .off = 0, .keys = keys[0..@min(keys.len, key_batch)] });
    }
};
