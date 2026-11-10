//! The follower: reads checkpoints from a source, verifies them and applies them to the store.
//!
//! Threads. `workers` threads each claim the next checkpoint sequence number, read the blob into
//! a preallocated slot, index it, run `verify.check` (digests, effects against output objects)
//! and, when the epoch's committee is known, the BLS certificate. The calling thread is the
//! ordered stage: it takes slots in sequence order, checks the chain link and the epoch rule,
//! verifies a certificate a worker could not, installs the next committee at an end-of-epoch
//! checkpoint, and commits one store batch per checkpoint (single writer). A claim is allowed only
//! `window` checkpoints ahead of the ordered stage, so memory is bounded and fixed after warm-up
//! (slot buffers, per-slot arenas and indexes keep their capacity).
//!
//! Modes. `apply` verifies and stores what the certified effects commit to; no execution. `execute`
//! needs the exec tile and is refused until exec lands.
//!
//! Catch-up reads until `to` (inclusive). Live mode (`to == null`) polls the source for the next
//! checkpoint until `stop()`.
const std = @import("std");
const Io = std.Io;
const bcs = @import("bcs");
const hash = @import("hash");
const types = @import("types");
const store_mod = @import("store");
const verify = @import("verify.zig");
const wire = @import("wire.zig");
const archive = @import("archive.zig");
const metrics_mod = @import("metrics.zig");
const Committee = @import("committee.zig").Committee;
const Metrics = metrics_mod.Metrics;
const Atomic = std.atomic.Value;

pub const Mode = enum { apply, execute };

pub const Source = union(enum) {
    archive: *archive.Archive,
};

pub const Config = struct {
    mode: Mode = .apply,
    /// 0: one per CPU minus one (at least 1).
    workers: u32 = 0,
    /// Checkpoints in flight (claimed, being checked, or checked and waiting for the ordered stage).
    window: u32 = 0,
    /// Live mode poll interval when the source has nothing new.
    poll_ms: u32 = 100,
    /// Store read-ahead (lane fast-start, `store.prefetch`): a thread reads the live-table pages
    /// and live records of the objects in the next `prefetch_ahead` checked checkpoints, this
    /// many reads in flight, before the ordered stage applies them. 0: off.
    prefetch_qd: u32 = 0,
    prefetch_ahead: u32 = 32,
};

/// Where following starts: the committee of the first checkpoint's epoch (a trusted root: the
/// genesis committee, or the committee a previous run left) and, unless it is the first
/// checkpoint of the chain, the digest of the checkpoint before it.
pub const Anchor = struct {
    committee: Committee,
    first_seq: u64,
    prev_digest: ?[32]u8 = null,
    /// True when `first_seq` is the first checkpoint of its epoch (the previous one ended an epoch).
    /// Only matters for the epoch rule of the first checkpoint, which is waived for the anchor itself.
    prev_was_eoe: bool = false,
};

pub const Observer = struct {
    ctx: *anyopaque,
    on_checkpoint: *const fn (ctx: *anyopaque, seq: u64, c: *const verify.Checked, blob: []const u8) void,
    /// Optional: called with the checkpoint's open batch, after its certified records are added and
    /// before the commit, so the observer's own records (for example historical input versions)
    /// commit in the same durable group. An error aborts the batch and stops the follower.
    on_batch: ?*const fn (ctx: *anyopaque, seq: u64, c: *const verify.Checked, blob: []const u8, b: *store_mod.Batch) anyerror!void = null,
    /// Optional: called right after checkpoint `seq`'s batch committed (store readers see it), on
    /// the ordered apply thread, before the next checkpoint's `on_checkpoint`. Derived read
    /// indexes publish here so they never run ahead of the store (lane indexes).
    on_committed: ?*const fn (ctx: *anyopaque, seq: u64) void = null,
};

pub const PrefetchMore = struct {
    ctx: *anyopaque,
    add: *const fn (ctx: *anyopaque, seq: u64, ids: *std.ArrayList([32]u8)) void,
};

pub const Failure = struct {
    seq: u64,
    verdict: verify.Verdict,
};

pub const Error = error{ BadCheckpoint, SourceMissing, ExecNotAvailable, NoAnchor, Stopped, ObserverFailed } ||
    store_mod.Error || std.mem.Allocator.Error || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError || error{ShortRead} ||
    types.index.IndexError || Committee.Error || std.Thread.SpawnError;

const Slot = struct {
    blob: std.ArrayList(u8) = .empty,
    idx: types.CheckpointIndex,
    arena: std.heap.ArenaAllocator,
    /// `seq + 1` once `result` is final; 0 when free.
    ready: Atomic(u64) = .init(0),
    result: verify.CheckResult = .{ .bad = .decode },
    /// Verdict of the certificate when a worker could check it, else null (ordered stage does it).
    cert: ?verify.Verdict = null,
    err: ?Error = null,

    fn deinit(s: *Slot, gpa: std.mem.Allocator) void {
        s.blob.deinit(gpa);
        s.idx.deinit(gpa);
        s.arena.deinit();
    }
};

/// Committees by epoch. Written by the ordered stage only; workers read lock-free. An entry is
/// reused only after `slots.len` newer epochs, which cannot happen within one window on mainnet.
const CommitteeTable = struct {
    const n = 8;
    epochs: [n]Atomic(u64) = @splat(.init(0)), // epoch + 1, 0 = empty
    ptrs: [n]?*Holder = @splat(null),

    const Holder = struct { arena: std.heap.ArenaAllocator, committee: Committee };

    fn get(t: *const CommitteeTable, epoch: u64) ?*const Committee {
        const e = t.epochs[epoch % n].load(.acquire);
        if (e != epoch + 1) return null;
        return &t.ptrs[epoch % n].?.committee;
    }

    fn install(t: *CommitteeTable, gpa: std.mem.Allocator, h: *Holder, epoch: u64) void {
        const i = epoch % n;
        const old = t.ptrs[i];
        t.epochs[i].store(0, .release);
        // A worker may still hold the old entry only if the window spans `n` epochs.
        if (old) |o| {
            o.arena.deinit();
            gpa.destroy(o);
        }
        t.ptrs[i] = h;
        t.epochs[i].store(epoch + 1, .release);
    }
};

pub const Follower = struct {
    gpa: std.mem.Allocator,
    io: Io,
    store: *store_mod.Store,
    source: Source,
    cfg: Config,
    metrics: Metrics = .{},
    /// Per-checkpoint apply plus commit time (ordered stage), for the perf gate's commit-path p99.
    commit_hist: metrics_mod.Hist = .{},
    committees: CommitteeTable = .{},
    slots: []Slot = &.{},
    // shared pipeline state
    next_claim: Atomic(u64) = .init(0),
    applied_next: Atomic(u64) = .init(0),
    last_seq: Atomic(u64) = .init(std.math.maxInt(u64)),
    stopping: Atomic(bool) = .init(false),
    /// Bumped (and woken) on every change a waiter may care about.
    tick: Atomic(u32) = .init(0),
    first_err: Atomic(u32) = .init(0),
    // ordered-stage state
    cur_epoch: u64 = 0,
    prev_digest: ?[32]u8 = null,
    prev_was_eoe: bool = false,
    failure: ?Failure = null,
    anchor_waiver: bool = true,
    /// Called by the ordered stage for every verified checkpoint just before its batch is built.
    observer: ?Observer = null,
    /// The checkpoint whose slot the read-ahead thread is reading (no worker may reuse it), or
    /// maxInt.
    pf_hold: Atomic(u64) = .init(std.math.maxInt(u64)),
    prefetcher: ?*store_mod.prefetch.Prefetcher = null,
    /// More ids for the read-ahead of a checked checkpoint (lane catchup-io): objects the apply
    /// stage's observers read that the checkpoint itself does not carry (the archive's
    /// read-only inputs, packages and runtime loads). Called on the read-ahead thread.
    prefetch_more: ?PrefetchMore = null,

    pub fn init(gpa: std.mem.Allocator, io: Io, st: *store_mod.Store, source: Source, cfg: Config, anchor: Anchor) Error!*Follower {
        if (cfg.mode == .execute) return error.ExecNotAvailable;
        const f = try gpa.create(Follower);
        errdefer gpa.destroy(f);
        f.* = .{ .gpa = gpa, .io = io, .store = st, .source = source, .cfg = cfg };
        if (f.cfg.workers == 0) {
            const cpus = std.Thread.getCpuCount() catch 2;
            f.cfg.workers = @intCast(@max(1, cpus -| 1));
        }
        if (f.cfg.window == 0) f.cfg.window = f.cfg.workers * 2 + 2;
        f.slots = try gpa.alloc(Slot, f.cfg.window);
        var made: usize = 0;
        errdefer {
            for (f.slots[0..made]) |*s| s.deinit(gpa);
            gpa.free(f.slots);
        }
        for (f.slots) |*s| {
            s.* = .{ .idx = try types.CheckpointIndex.init(gpa), .arena = std.heap.ArenaAllocator.init(gpa) };
            made += 1;
        }
        try f.installCommittee(anchor.committee);
        f.cur_epoch = anchor.committee.epoch;
        f.prev_digest = anchor.prev_digest;
        f.prev_was_eoe = anchor.prev_was_eoe;
        f.next_claim.store(anchor.first_seq, .monotonic);
        f.applied_next.store(anchor.first_seq, .monotonic);
        return f;
    }

    pub fn deinit(f: *Follower) void {
        if (f.prefetcher) |p| p.deinit();
        for (f.slots) |*s| s.deinit(f.gpa);
        f.gpa.free(f.slots);
        for (&f.committees.ptrs) |*p| if (p.*) |h| {
            h.arena.deinit();
            f.gpa.destroy(h);
        };
        f.gpa.destroy(f);
    }

    /// Copies `c` into its own arena and makes it the committee of `c.epoch`.
    fn installCommittee(f: *Follower, c: Committee) !void {
        const h = try f.gpa.create(CommitteeTable.Holder);
        errdefer f.gpa.destroy(h);
        h.arena = std.heap.ArenaAllocator.init(f.gpa);
        errdefer h.arena.deinit();
        h.committee = try Committee.init(h.arena.allocator(), c.epoch, c.keys, c.stakes);
        f.committees.install(f.gpa, h, c.epoch);
    }

    pub fn stop(f: *Follower) void {
        f.stopping.store(true, .release);
        f.wake();
    }

    fn wake(f: *Follower) void {
        _ = f.tick.fetchAdd(1, .release);
        f.io.futexWake(u32, &f.tick.raw, std.math.maxInt(u32));
    }

    fn waitFor(f: *Follower, seen: u32, ms: u32) void {
        f.io.futexWaitTimeout(u32, &f.tick.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(ms), .clock = .awake } }) catch {};
    }

    /// Follows from the anchor to `to` (inclusive), or until `stop()` when null. Returns on the first
    /// rejected checkpoint (`failure` says which and why) or source error.
    pub fn run(f: *Follower, to: ?u64) Error!void {
        f.last_seq.store(to orelse std.math.maxInt(u64), .monotonic);
        f.stopping.store(false, .monotonic);
        f.first_err.store(0, .monotonic);
        const threads = try f.gpa.alloc(std.Thread, f.cfg.workers);
        defer f.gpa.free(threads);
        var spawned: usize = 0;
        defer {
            f.stop();
            for (threads[0..spawned]) |t| t.join();
        }
        for (threads) |*t| {
            t.* = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, workerMain, .{f});
            spawned += 1;
        }
        var pf_thread: ?std.Thread = null;
        if (f.cfg.prefetch_qd > 0 and f.prefetcher == null) {
            f.prefetcher = store_mod.prefetch.Prefetcher.init(f.gpa, f.cfg.prefetch_qd) catch null;
            if (f.prefetcher == null) std.log.warn("follower: store read-ahead unavailable (no io_uring); applying without it", .{});
        }
        if (f.prefetcher != null) pf_thread = std.Thread.spawn(.{ .stack_size = 1 << 20 }, prefetchMain, .{f}) catch |e| blk: {
            std.log.warn("follower: store read-ahead thread: {s}", .{@errorName(e)});
            break :blk null;
        };
        defer if (pf_thread) |t| {
            f.stop();
            t.join();
        };
        return f.ordered(to);
    }

    // ---------------------------------------------------------------- workers

    fn claim(f: *Follower) ?u64 {
        while (true) {
            const seen = f.tick.load(.acquire);
            if (f.stopping.load(.acquire)) return null;
            const cur = f.next_claim.load(.monotonic);
            if (cur > f.last_seq.load(.monotonic)) return null;
            // A slot is reused only once its checkpoint is applied and the read-ahead thread is
            // not reading it.
            if (cur >= @min(f.applied_next.load(.seq_cst), f.pf_hold.load(.seq_cst)) + f.slots.len) {
                f.waitFor(seen, 50);
                continue;
            }
            if (f.next_claim.cmpxchgWeak(cur, cur + 1, .monotonic, .monotonic) == null) return cur;
        }
    }

    fn workerMain(f: *Follower) void {
        while (f.claim()) |seq| {
            f.process(seq) catch |e| {
                const slot = &f.slots[seq % f.slots.len];
                slot.err = e;
                slot.ready.store(seq + 1, .release);
                f.wake();
            };
        }
    }

    fn process(f: *Follower, seq: u64) Error!void {
        const slot = &f.slots[seq % f.slots.len];
        slot.err = null;
        slot.cert = null;
        // A typical checkpoint's worth, not the largest one seen (`window` slots).
        _ = slot.arena.reset(.{ .retain_with_limit = 4 << 20 });
        if (slot.blob.capacity > 8 << 20) slot.blob.clearAndFree(f.gpa);
        var t0 = now();
        // Read (live mode: wait for the source to have it).
        while (true) {
            const seen = f.tick.load(.acquire);
            const r = switch (f.source) {
                .archive => |a| try a.read(f.gpa, f.io, seq, &slot.blob),
            };
            if (r == .ok) break;
            if (f.last_seq.load(.monotonic) != std.math.maxInt(u64)) return error.SourceMissing;
            if (f.stopping.load(.acquire)) return error.Stopped;
            f.waitFor(seen, f.cfg.poll_ms);
        }
        Metrics.max(&f.metrics.highest_seen, seq);
        var t1 = now();
        Metrics.add(&f.metrics.read_ns, t1 - t0);
        Metrics.add(&f.metrics.bytes_in, slot.blob.items.len);
        t0 = t1;
        const indexed = types.indexCheckpointData(slot.blob.items, &slot.idx);
        t1 = now();
        Metrics.add(&f.metrics.index_ns, t1 - t0);
        t0 = t1;
        // A blob the strict decoder rejects is a `decode` verdict, not a follower error.
        slot.result = if (indexed) |_| try verify.check(slot.arena.allocator(), slot.blob.items, &slot.idx) else |_| .{ .bad = .decode };
        t1 = now();
        Metrics.add(&f.metrics.check_ns, t1 - t0);
        if (slot.result == .ok) {
            if (f.committees.get(slot.result.ok.epoch)) |c| {
                t0 = now();
                slot.cert = verify.checkCert(slot.arena.allocator(), c, slot.result.ok.epoch, slot.idx.summary.slice(slot.blob.items), slot.idx.sig.slice(slot.blob.items));
                Metrics.add(&f.metrics.cert_ns, now() - t0);
            }
        }
        slot.ready.store(seq + 1, .release);
        f.wake();
    }

    // ---------------------------------------------------------------- read-ahead

    const Collect = enum { ready, not_ready, gone };

    /// Appends the object ids checkpoint `seq` touches (inputs, outputs, removals) if its slot is
    /// checked and not yet applied.
    fn collect(f: *Follower, seq: u64, ids: *std.ArrayList([32]u8)) !Collect {
        f.pf_hold.store(seq, .seq_cst);
        defer f.pf_hold.store(std.math.maxInt(u64), .release);
        if (f.applied_next.load(.seq_cst) > seq) return .gone;
        const slot = &f.slots[seq % f.slots.len];
        if (slot.ready.load(.acquire) != seq + 1) return .not_ready;
        if (slot.err != null) return .gone;
        const c = switch (slot.result) {
            .ok => |c| c,
            .bad => return .gone,
        };
        const blob = slot.blob.items;
        for (c.txs, 0..) |plan, i| {
            const t = slot.idx.txAt(i);
            for (slot.idx.objs[t.in_first..][0..t.in_count]) |r| {
                const head = wire.objectHead(r.slice(blob)) catch continue;
                try ids.append(f.gpa, head.id.*);
            }
            for (plan.puts) |p| try ids.append(f.gpa, p.id.*);
            for (plan.removes) |r| try ids.append(f.gpa, r.id);
        }
        if (f.prefetch_more) |m| m.add(m.ctx, seq, ids);
        return .ready;
    }

    fn prefetchMain(f: *Follower) void {
        const pf = f.prefetcher.?;
        var ids: std.ArrayList([32]u8) = .empty;
        defer ids.deinit(f.gpa);
        var next = f.applied_next.load(.acquire);
        const max_ids = 1 << 16;
        while (!f.stopping.load(.acquire)) {
            const seen = f.tick.load(.acquire);
            const applied = f.applied_next.load(.acquire);
            if (next < applied) next = applied;
            ids.clearRetainingCapacity();
            var got: u64 = 0;
            while (next < applied + f.cfg.prefetch_ahead and ids.items.len < max_ids) {
                const r = f.collect(next, &ids) catch break;
                if (r == .not_ready) break;
                next += 1;
                if (r == .ready) got += 1;
            }
            if (got == 0) {
                f.waitFor(seen, 5);
                continue;
            }
            pf.run(f.store, ids.items);
            Metrics.add(&f.metrics.prefetched, got);
        }
    }

    // ---------------------------------------------------------------- ordered stage

    fn ordered(f: *Follower, to: ?u64) Error!void {
        var seq = f.applied_next.load(.monotonic);
        while (to == null or seq <= to.?) : (seq += 1) {
            const slot = &f.slots[seq % f.slots.len];
            const ts = now();
            while (slot.ready.load(.acquire) != seq + 1) {
                const seen = f.tick.load(.acquire);
                if (slot.ready.load(.acquire) == seq + 1) break;
                // stop() ends catch-up too: workers stop claiming, so this slot may never fill.
                if (f.stopping.load(.acquire)) return if (to == null) {} else error.Stopped;
                f.waitFor(seen, 20);
            }
            Metrics.add(&f.metrics.stall_ns, now() - ts);
            if (slot.err) |e| {
                if (e == error.Stopped) return;
                return e;
            }
            try f.applyOne(seq, slot);
            slot.ready.store(0, .monotonic);
            f.applied_next.store(seq + 1, .release);
            f.wake();
        }
    }

    fn reject(f: *Follower, seq: u64, v: verify.Verdict) Error {
        f.failure = .{ .seq = seq, .verdict = v };
        Metrics.add(&f.metrics.rejected, 1);
        return error.BadCheckpoint;
    }

    fn applyOne(f: *Follower, seq: u64, slot: *Slot) Error!void {
        const blob = slot.blob.items;
        const c = switch (slot.result) {
            .ok => |c| c,
            .bad => |v| return f.reject(seq, v),
        };
        if (c.seq != seq) return f.reject(seq, .{ .digest_mismatch = .sequence });
        // Epoch rule: same epoch, or the next one right after an end-of-epoch checkpoint.
        const first = f.anchor_waiver;
        if (c.epoch != f.cur_epoch) {
            if (!(c.epoch == f.cur_epoch + 1 and f.prev_was_eoe)) return f.reject(seq, .epoch_mismatch);
        }
        // Chain link.
        if (f.prev_digest) |p| {
            if (c.previous == null or !std.mem.eql(u8, &c.previous.?, &p)) return f.reject(seq, .chain_break);
        } else if (!first) return f.reject(seq, .chain_break);
        // Certificate.
        var cv = slot.cert;
        if (cv == null) {
            const comm = f.committees.get(c.epoch) orelse return f.reject(seq, .no_committee);
            const t0 = now();
            cv = verify.checkCert(slot.arena.allocator(), comm, c.epoch, slot.idx.summary.slice(blob), slot.idx.sig.slice(blob));
            Metrics.add(&f.metrics.cert_ns, now() - t0);
        }
        if (!cv.?.isOk()) return f.reject(seq, cv.?);

        // The next committee is derived before the batch, so a checkpoint whose end-of-epoch data
        // cannot form one is rejected without being stored.
        var next: ?*CommitteeTable.Holder = null;
        errdefer if (next) |h| {
            h.arena.deinit();
            f.gpa.destroy(h);
        };
        if (c.end_of_epoch) |eoe| {
            const h = try f.gpa.create(CommitteeTable.Holder);
            h.arena = std.heap.ArenaAllocator.init(f.gpa);
            next = h;
            h.committee = Committee.fromEndOfEpoch(h.arena.allocator(), c.epoch + 1, eoe) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return f.reject(seq, .no_committee),
            };
        }

        if (f.observer) |o| o.on_checkpoint(o.ctx, seq, &c, blob);
        const t0 = now();
        const idx = &slot.idx;
        const b = try f.store.begin(seq, c.epoch);
        errdefer f.store.abort(b);
        const sum_start = idx.summary.o;
        const sum_cert = blob[sum_start .. idx.sig.o + idx.sig.n];
        try b.checkpoint(sum_cert, idx.contents.slice(blob));
        try b.checkpointDigest(&c.digest); // checkpoint digest index (CONTRACTS 6.8)
        for (c.txs, 0..) |plan, i| {
            const t = idx.txAt(i);
            // The whole Transaction envelope (data and user signatures), as store-replay and serve expect.
            try b.transaction(plan.tx_digest, &plan.effects_digest, t.transaction.slice(blob), t.effects.slice(blob), if (t.events) |ev| ev.slice(blob) else null);
            for (plan.puts) |p| try b.putObject(p.id, p.version, &p.digest, idx.objs[p.index].slice(blob));
            for (plan.removes) |r| try b.removeObject(&r.id, r.version, if (r.kind == 1) .wrapped else .deleted);
        }
        if (f.observer) |o| if (o.on_batch) |hook| hook(o.ctx, seq, &c, blob, b) catch |e| {
            std.log.err("follower: observer batch hook at checkpoint {d}: {s}", .{ seq, @errorName(e) });
            return error.ObserverFailed;
        };
        const t1 = now();
        try f.store.commit(b);
        const t2 = now();
        if (f.observer) |o| if (o.on_committed) |hook| hook(o.ctx, seq);
        Metrics.add(&f.metrics.apply_ns, t1 - t0);
        Metrics.add(&f.metrics.commit_ns, t2 - t1);
        f.metrics.commitLatency(t2 - t1);
        store_mod.readstats.commit.observe(t2 - t1);
        f.commit_hist.record(t2 - t0);

        // State advance.
        if (next) |h| {
            next = null;
            f.committees.install(f.gpa, h, c.epoch + 1);
        }
        f.cur_epoch = c.epoch;
        f.prev_was_eoe = c.end_of_epoch != null;
        f.prev_digest = c.digest;
        f.anchor_waiver = false;
        Metrics.add(&f.metrics.checkpoints, 1);
        Metrics.add(&f.metrics.transactions, c.txs.len);
        Metrics.add(&f.metrics.objects_put, c.puts);
        Metrics.add(&f.metrics.objects_removed, c.removes);
        f.metrics.applied_seq.store(seq, .monotonic);
        f.metrics.epoch.store(c.epoch, .monotonic);
    }
};

/// Monotonic nanoseconds (stage timers only).
pub fn now() u64 {
    var ts: std.posix.timespec = undefined;
    if (@import("builtin").os.tag == .linux) {
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    } else {
        _ = std.c.clock_gettime(.MONOTONIC, &ts);
    }
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}
