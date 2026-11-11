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
const core = @import("core");
const Committee = @import("committee.zig").Committee;
const Metrics = metrics_mod.Metrics;
const Atomic = std.atomic.Value;
const bls = @import("bls");

pub const Mode = enum { apply, execute };

/// Largest certificate batch (`Config.cert_batch` is capped to it).
pub const max_cert_batch = 256;

pub const Source = union(enum) {
    archive: *archive.Archive,
};

pub const Config = struct {
    mode: Mode = .apply,
    /// 0: one per usable CPU minus one (at least 1). Usable: the affinity mask capped by the
    /// cgroup CPU quota of the process's own cgroup and its parents (`usableCpus`).
    workers: u32 = 0,
    /// Checkpoints in flight (claimed, being checked, or checked and waiting for the ordered stage).
    window: u32 = 0,
    /// Live mode: how long a worker waits for a checkpoint the source does not have yet before
    /// it looks again. A source whose writer announces arrivals (`Follower.notify`, the node's
    /// spool) wakes the workers itself, so this is only a safety net there; a source that does
    /// not (a plain directory) is polled at this interval.
    poll_ms: u32 = 100,
    /// Store read-ahead (lane fast-start, `store.prefetch`): a thread reads the live-table pages
    /// and live records of the objects in the next `prefetch_ahead` checked checkpoints, this
    /// many reads in flight, before the ordered stage applies them. 0: off.
    prefetch_qd: u32 = 0,
    prefetch_ahead: u32 = 32,
    /// Certificate batching: 0 (default) or 1, every worker verifies its checkpoint's certificate
    /// on its own (`verify.checkCert`). N >= 2: a worker does the per-certificate part
    /// (`verify.prepCert`) and queues the pairing check; the queue is decided as one randomized
    /// batch (`verify.pairingVerdicts`, on core.pool.shared()) when it holds N items (at most half
    /// the window), by the worker that filled it, or as soon as the ordered stage waits on a
    /// queued checkpoint (it is idle then). Verdicts equal `checkCert`'s.
    cert_batch: u32 = 0,
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

/// The ordered stage's admission rules, apart from the certificate: the checkpoint is the one
/// expected (sequence number), in the same epoch or the next one right after an end-of-epoch
/// checkpoint, and links to the previous digest. Pure state, so the node simulation tester
/// (src/node/dst) runs the very same rules the follower does.
pub const Admission = struct {
    cur_epoch: u64 = 0,
    prev_digest: ?[32]u8 = null,
    prev_was_eoe: bool = false,
    /// True until the first checkpoint is applied: the anchor itself needs no chain link
    /// when `prev_digest` is null.
    anchor_waiver: bool = true,

    pub fn init(anchor: Anchor) Admission {
        return .{ .cur_epoch = anchor.committee.epoch, .prev_digest = anchor.prev_digest, .prev_was_eoe = anchor.prev_was_eoe };
    }

    /// Null when admitted; else the verdict for the rejection (in the follower's order: sequence,
    /// epoch, chain link).
    pub fn check(a: *const Admission, seq: u64, c: *const verify.Checked) ?verify.Verdict {
        if (c.seq != seq) return .{ .digest_mismatch = .sequence };
        if (c.epoch != a.cur_epoch) {
            if (!(c.epoch == a.cur_epoch + 1 and a.prev_was_eoe)) return .epoch_mismatch;
        }
        if (a.prev_digest) |p| {
            if (c.previous == null or !std.mem.eql(u8, &c.previous.?, &p)) return .chain_break;
        } else if (!a.anchor_waiver) return .chain_break;
        return null;
    }

    /// After the checkpoint was committed.
    pub fn advance(a: *Admission, c: *const verify.Checked) void {
        a.cur_epoch = c.epoch;
        a.prev_was_eoe = c.end_of_epoch != null;
        a.prev_digest = c.digest;
        a.anchor_waiver = false;
    }
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
    /// Optional: called on the ordered thread once checkpoint `seq` is committed and the follower
    /// has moved past it (`applied_next` is `seq + 1`, waiters are woken), before the ordered
    /// stage looks for the next checkpoint. No batch is open. The writer thread's background
    /// work (retention, segment cleaning) belongs here and not in `on_checkpoint`, where an
    /// arriving checkpoint would wait behind it before its own commit.
    on_idle: ?*const fn (ctx: *anyopaque, seq: u64) void = null,
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
    /// Bumped (and woken) by `Follower.notify` for a checkpoint of this slot and by `stop`: the
    /// worker waiting for the source to have the slot's checkpoint blocks on this word.
    arrived: Atomic(u32) = .init(0),
    result: verify.CheckResult = .{ .bad = .decode },
    /// Verdict of the certificate when a worker could check it, else null (ordered stage does it).
    cert: ?verify.Verdict = null,
    /// `seq + 1` while the slot's pairing check waits in the certificate queue (`ready` is set
    /// once it is decided); 0 otherwise.
    queued: Atomic(u64) = .init(0),
    /// The queued pairing check (its message lives in `arena`).
    pairing: bls.sig.BatchItem = undefined,
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

    const Holder = struct {
        arena: std.heap.ArenaAllocator,
        committee: Committee,
        /// Certificate batching: 0 not yet known, 1 every key is in G2 (`verify.keysInG2`, worked
        /// out once by the first worker that needs it), 2 not (that epoch never batches).
        keys_in_g2: Atomic(u8) = .init(0),
    };

    fn get(t: *const CommitteeTable, epoch: u64) ?*const Committee {
        const h = t.getHolder(epoch) orelse return null;
        return &h.committee;
    }

    fn getHolder(t: *const CommitteeTable, epoch: u64) ?*Holder {
        const e = t.epochs[epoch % n].load(.acquire);
        if (e != epoch + 1) return null;
        return t.ptrs[epoch % n].?;
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
    /// Reads that found the checkpoint missing at the source (live mode). Before `notify`
    /// existed every worker made one every 2 ms at the tip (7,500 to 15,500 failed opens a
    /// second); now one when it claims a checkpoint that is not there yet and one per `poll_ms`.
    read_misses: Atomic(u64) = .init(0),
    first_err: Atomic(u32) = .init(0),
    // ordered-stage state
    adm: Admission = .{},
    failure: ?Failure = null,
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
    /// Queued certificate pairing checks (`Config.cert_batch`): sequence numbers of slots whose
    /// `pairing` waits. Guarded by `cq_lock`.
    cq: []u64 = &.{},
    cq_len: usize = 0,
    cq_lock: std.atomic.Mutex = .unlocked,
    /// Flush size: min(cert_batch, window / 2), 0 when batching is off.
    cq_max: usize = 0,

    pub fn init(gpa: std.mem.Allocator, io: Io, st: *store_mod.Store, source: Source, cfg: Config, anchor: Anchor) Error!*Follower {
        if (cfg.mode == .execute) return error.ExecNotAvailable;
        const f = try gpa.create(Follower);
        errdefer gpa.destroy(f);
        f.* = .{ .gpa = gpa, .io = io, .store = st, .source = source, .cfg = cfg };
        f.cfg = autoSize(cfg, usableCpus(), @intCast(std.Thread.getCpuCount() catch 2));
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
        if (f.cfg.cert_batch >= 2) {
            f.cq_max = @max(1, @min(@min(f.cfg.cert_batch, max_cert_batch), f.slots.len / 2));
            f.cq = try gpa.alloc(u64, f.slots.len);
        }
        errdefer if (f.cq.len > 0) gpa.free(f.cq);
        try f.installCommittee(anchor.committee);
        f.adm = Admission.init(anchor);
        f.next_claim.store(anchor.first_seq, .monotonic);
        f.applied_next.store(anchor.first_seq, .monotonic);
        return f;
    }

    pub fn deinit(f: *Follower) void {
        if (f.prefetcher) |p| p.deinit();
        for (f.slots) |*s| s.deinit(f.gpa);
        f.gpa.free(f.slots);
        if (f.cq.len > 0) f.gpa.free(f.cq);
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
        h.keys_in_g2 = .init(0);
        errdefer h.arena.deinit();
        h.committee = try Committee.init(h.arena.allocator(), c.epoch, c.keys, c.stakes);
        f.committees.install(f.gpa, h, c.epoch);
    }

    pub fn stop(f: *Follower) void {
        f.stopping.store(true, .release);
        f.wake();
        for (f.slots) |*sl| f.wakeSlot(sl);
    }

    /// The source now holds checkpoint `seq`: wakes the worker waiting for it, if one is (and no
    /// other worker). Any thread. The writer must call it after the checkpoint is readable (the
    /// spool's rename): a worker samples its slot's `arrived` before it looks, so an arrival
    /// between its look and its wait is never missed. A `seq` outside the window is harmless.
    pub fn notify(f: *Follower, seq: u64) void {
        f.wakeSlot(&f.slots[seq % f.slots.len]);
    }

    fn wakeSlot(f: *Follower, sl: *Slot) void {
        _ = sl.arrived.fetchAdd(1, .release);
        f.io.futexWake(u32, &sl.arrived.raw, std.math.maxInt(u32));
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
                // the window is full: decide the queued certificates here rather than leave
                // them for the ordered stage (which would then do them on the critical path)
                if (f.cq_max > 0 and f.flushAny()) continue;
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
        slot.queued.store(0, .monotonic);
        // A typical checkpoint's worth, not the largest one seen (`window` slots).
        _ = slot.arena.reset(.{ .retain_with_limit = 4 << 20 });
        if (slot.blob.capacity > 8 << 20) slot.blob.clearAndFree(f.gpa);
        var t0 = now();
        // Read (live mode: wait for the source to have it).
        while (true) {
            const seen = slot.arrived.load(.acquire);
            const r = switch (f.source) {
                .archive => |a| try a.read(f.gpa, f.io, seq, &slot.blob),
            };
            if (r == .ok) break;
            _ = f.read_misses.fetchAdd(1, .monotonic);
            if (f.last_seq.load(.monotonic) != std.math.maxInt(u64)) return error.SourceMissing;
            if (f.stopping.load(.acquire)) return error.Stopped;
            f.io.futexWaitTimeout(u32, &slot.arrived.raw, seen, .{ .duration = .{ .raw = Io.Duration.fromMilliseconds(f.cfg.poll_ms), .clock = .awake } }) catch {};
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
            if (f.committees.getHolder(slot.result.ok.epoch)) |h| {
                const c = &h.committee;
                t0 = now();
                if (f.cq_max > 0 and f.batchable(h)) {
                    const summary = slot.idx.summary.slice(slot.blob.items);
                    switch (try verify.prepCert(slot.arena.allocator(), c, slot.result.ok.epoch, summary, slot.idx.sig.slice(slot.blob.items))) {
                        .done => |v| slot.cert = v,
                        .pairing => |it| {
                            slot.pairing = it;
                            Metrics.add(&f.metrics.cert_ns, now() - t0);
                            f.enqueueCert(seq);
                            return;
                        },
                    }
                } else {
                    slot.cert = try verify.checkCert(slot.arena.allocator(), c, slot.result.ok.epoch, slot.idx.summary.slice(slot.blob.items), slot.idx.sig.slice(slot.blob.items));
                }
                Metrics.add(&f.metrics.cert_ns, now() - t0);
            }
        }
        slot.ready.store(seq + 1, .release);
        f.wake();
    }

    // ---------------------------------------------------------------- certificate batches

    fn batchable(f: *Follower, h: *CommitteeTable.Holder) bool {
        _ = f;
        switch (h.keys_in_g2.load(.acquire)) {
            1 => return true,
            2 => return false,
            else => {
                const ok = verify.keysInG2(&h.committee);
                h.keys_in_g2.store(if (ok) 1 else 2, .release);
                return ok;
            },
        }
    }

    fn lockQueue(f: *Follower) void {
        while (!f.cq_lock.tryLock()) std.atomic.spinLoopHint();
    }

    /// Queues slot `seq`'s pairing check; the worker that fills the queue decides it.
    fn enqueueCert(f: *Follower, seq: u64) void {
        const slot = &f.slots[seq % f.slots.len];
        var batch: [max_cert_batch]u64 = undefined;
        var n: usize = 0;
        f.lockQueue();
        slot.queued.store(seq + 1, .release);
        f.cq[f.cq_len] = seq;
        f.cq_len += 1;
        if (f.cq_len >= f.cq_max) n = f.takeQueueLocked(&batch);
        f.cq_lock.unlock();
        if (n > 0) f.decideCerts(batch[0..n]) else f.wake();
    }

    fn takeQueueLocked(f: *Follower, out: *[max_cert_batch]u64) usize {
        const n = @min(f.cq_len, out.len);
        @memcpy(out[0..n], f.cq[0..n]);
        // anything past the cap stays queued (only when the window is larger than the cap)
        std.mem.copyForwards(u64, f.cq[0 .. f.cq_len - n], f.cq[n..f.cq_len]);
        f.cq_len -= n;
        return n;
    }

    /// The ordered stage waits on `seq`: if its pairing check is still queued, takes the whole
    /// queue and decides it here. False when it is not queued (someone is deciding it already).
    fn flushFor(f: *Follower, seq: u64) bool {
        const slot = &f.slots[seq % f.slots.len];
        if (slot.queued.load(.acquire) != seq + 1) return false;
        var batch: [max_cert_batch]u64 = undefined;
        f.lockQueue();
        var queued = false;
        for (f.cq[0..f.cq_len]) |q| queued = queued or q == seq;
        const n = if (queued) f.takeQueueLocked(&batch) else 0;
        f.cq_lock.unlock();
        if (n == 0) return false;
        f.decideCerts(batch[0..n]);
        return true;
    }

    /// A worker with nothing to claim: takes the whole queue, if any, and decides it.
    fn flushAny(f: *Follower) bool {
        var batch: [max_cert_batch]u64 = undefined;
        f.lockQueue();
        const n = if (f.cq_len > 0) f.takeQueueLocked(&batch) else 0;
        f.cq_lock.unlock();
        if (n == 0) return false;
        f.decideCerts(batch[0..n]);
        return true;
    }

    /// One randomized batch over the queued slots `seqs`, then each slot is published.
    fn decideCerts(f: *Follower, seqs: []const u64) void {
        const t0 = now();
        var items: [max_cert_batch]bls.sig.BatchItem = undefined;
        var out: [max_cert_batch]verify.Verdict = undefined;
        for (seqs, items[0..seqs.len]) |s, *it| it.* = f.slots[s % f.slots.len].pairing;
        var seed: [32]u8 = undefined;
        f.io.random(&seed);
        var chacha = std.Random.ChaCha.init(seed);
        verify.pairingVerdicts(f.gpa, items[0..seqs.len], chacha.random(), .{ .keys_in_group = true }, out[0..seqs.len]);
        Metrics.add(&f.metrics.cert_ns, now() - t0);
        for (seqs, out[0..seqs.len]) |s, v| {
            const slot = &f.slots[s % f.slots.len];
            slot.cert = v;
            slot.queued.store(0, .monotonic);
            slot.ready.store(s + 1, .release);
        }
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
            // A stop ends the run after the checkpoint in hand. Checked checkpoints still waiting
            // in the window are left for the next start: in catch-up every slot is ready, so
            // without this the stage applied the whole window (and whatever the fetchers added
            // to it meanwhile) before it looked at the flag, each commit at the store's pace.
            if (f.stopping.load(.acquire)) return if (to == null) {} else error.Stopped;
            const slot = &f.slots[seq % f.slots.len];
            const ts = now();
            while (slot.ready.load(.acquire) != seq + 1) {
                const seen = f.tick.load(.acquire);
                if (slot.ready.load(.acquire) == seq + 1) break;
                // idle: decide the queued certificates ourselves (this one among them)
                if (f.cq_max > 0 and f.flushFor(seq)) continue;
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
            if (f.observer) |o| if (o.on_idle) |hook| hook(o.ctx, seq);
        }
    }

    /// After a rejected checkpoint whose source can be asked again (an edge with several cores):
    /// forgets the failure and the unapplied window, so `run` starts over at the first unapplied
    /// checkpoint. Only between runs (workers joined).
    pub fn rewind(f: *Follower) void {
        f.failure = null;
        f.first_err.store(0, .monotonic);
        for (f.slots) |*sl| {
            sl.ready.store(0, .monotonic);
            sl.err = null;
            sl.cert = null;
            sl.queued.store(0, .monotonic);
        }
        f.cq_len = 0;
        f.next_claim.store(f.applied_next.load(.monotonic), .monotonic);
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
        // Seq, epoch rule and chain link (Admission, shared with the node simulation tester).
        if (f.adm.check(seq, &c)) |v| return f.reject(seq, v);
        // Certificate.
        var cv = slot.cert;
        if (cv == null) {
            const comm = f.committees.get(c.epoch) orelse return f.reject(seq, .no_committee);
            const t0 = now();
            cv = try verify.checkCert(slot.arena.allocator(), comm, c.epoch, slot.idx.summary.slice(blob), slot.idx.sig.slice(blob));
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
            h.keys_in_g2 = .init(0);
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
        f.adm.advance(&c);
        Metrics.add(&f.metrics.checkpoints, 1);
        Metrics.add(&f.metrics.transactions, c.txs.len);
        Metrics.add(&f.metrics.objects_put, c.puts);
        Metrics.add(&f.metrics.objects_removed, c.removes);
        f.metrics.applied_seq.store(seq, .monotonic);
        f.metrics.epoch.store(c.epoch, .monotonic);
    }
};

/// CPUs this process can really use: the affinity mask, capped by the cgroup v2 `cpu.max` of its
/// own cgroup and every parent (core/hw.zig; a systemd unit's CPUQuota, a container limit).
/// `std.Thread.getCpuCount` is the affinity mask alone: inside a 600% quota on a 32-thread host
/// it says 32, and 31 workers plus the executor's threads then spend the group's CPU budget
/// early in each 100 ms period; the kernel stops every thread of the group for the rest of it,
/// the ordered stage included.
pub fn usableCpus() u32 {
    return @max(1, core.hw.detect(null).logical_cores);
}

/// Worker threads for `usable` CPUs: one is left for the ordered stage.
pub fn autoWorkers(usable: u32) u32 {
    return @max(1, usable -| 1);
}

/// `cfg` with the automatic worker count and window (0) filled in, on a host of `host` CPUs of
/// which the process can use `usable`. The window (checkpoints in flight, and how far the
/// store read-ahead can look) keeps the size it had before the quota was read: a quota
/// changes how many threads check, not how far ahead of the ordered stage they may work.
pub fn autoSize(cfg: Config, usable: u32, host: u32) Config {
    var c = cfg;
    if (c.workers == 0) {
        c.workers = autoWorkers(usable);
        if (c.window == 0) c.window = autoWorkers(host) * 2 + 2;
    }
    if (c.window == 0) c.window = c.workers * 2 + 2;
    return c;
}

test "follower: the automatic worker count follows the usable CPUs (cgroup quota), the window the host" {
    const t = std.testing;
    // CPUQuota=600% on a 32-thread host: 5 workers (it was 31), the window as before.
    const quota = autoSize(.{}, 6, 32);
    try t.expectEqual(@as(u32, 5), quota.workers);
    try t.expectEqual(@as(u32, 64), quota.window);
    // No quota: what it always was.
    const free = autoSize(.{}, 32, 32);
    try t.expectEqual(@as(u32, 31), free.workers);
    try t.expectEqual(@as(u32, 64), free.window);
    // Explicit values are kept, and an explicit worker count still sizes the window.
    const fixed = autoSize(.{ .workers = 8 }, 6, 32);
    try t.expectEqual(@as(u32, 8), fixed.workers);
    try t.expectEqual(@as(u32, 18), fixed.window);
    try t.expectEqual(@as(u32, 100), autoSize(.{ .window = 100 }, 6, 32).window);
    try t.expectEqual(@as(u32, 1), autoSize(.{}, 1, 1).workers);
    try t.expectEqual(@as(u32, 1), autoSize(.{}, 0, 0).workers);
    // The count the follower uses is core/hw's (affinity mask capped by the cgroup's cpu.max).
    // Inside a quota it is below the host's: run this test in `systemd-run -p CPUQuota=200%`.
    const usable = usableCpus();
    const host: u32 = @intCast(std.Thread.getCpuCount() catch 2);
    try t.expect(usable >= 1 and usable <= host);
    try t.expectEqual(core.hw.detect(null).logical_cores, usable);
}

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

// ---------------------------------------------------------------------- tests

const testing = std.testing;

/// A store in a temporary directory plus the corpus archive and the committee of `epoch`, for
/// tests that follow real checkpoints (skipped without ZUI_CORPUS).
const TestBed = struct {
    tmp: testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    store: *store_mod.Store,
    sio: *store_mod.RealIo,
    arch: archive.Archive,
    committee: Committee,

    fn init(tb: *TestBed, epoch: u64) !void {
        const gpa = testing.allocator;
        const io = testing.io;
        const corpus = std.mem.span(std.c.getenv("ZUI_CORPUS") orelse return error.SkipZigTest);
        tb.arena = std.heap.ArenaAllocator.init(gpa);
        errdefer tb.arena.deinit();
        const a = tb.arena.allocator();
        const text = Io.Dir.cwd().readFileAlloc(io, try std.fmt.allocPrint(a, "{s}/vectors/bls-cert/{d}.jsonl", .{ corpus, epoch }), a, .limited(1 << 28)) catch return error.SkipZigTest;
        tb.committee = try @import("committee.zig").fromJsonLine(a, text[0 .. std.mem.indexOfScalar(u8, text, '\n') orelse text.len]);
        tb.arch = archive.Archive.open(io, try std.fmt.allocPrint(a, "{s}/chk", .{corpus})) catch return error.SkipZigTest;
        errdefer tb.arch.close(io);
        tb.tmp = testing.tmpDir(.{});
        errdefer tb.tmp.cleanup();
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const n = try tb.tmp.dir.realPath(io, &pb);
        var cfg: store_mod.Config = .{ .max_live_objects = 1 << 16, .max_object_versions = 1 << 20 };
        cfg.dir = try a.dupe(u8, pb[0..n]);
        const h = try store_mod.openDir(gpa, io, &cfg, .{ .sync = .none });
        tb.store = h.store;
        tb.sio = h.io;
    }

    fn deinit(tb: *TestBed) void {
        tb.store.deinit();
        tb.sio.deinit();
        tb.arch.close(testing.io);
        tb.tmp.cleanup();
        tb.arena.deinit();
    }
};

/// First checkpoint of the corpus's dense window (vectors/sync-follow/dense.cp.jsonl).
const test_first: u64 = 342446161;
const test_epoch: u64 = 1303;

test "follower: on_idle runs once a checkpoint is committed and applied, never between on_checkpoint and the commit" {
    var tb: TestBed = undefined;
    try tb.init(test_epoch);
    defer tb.deinit();
    const Rec = struct {
        const Ev = struct { kind: enum { checkpoint, batch, committed, idle }, seq: u64 };
        f: *Follower = undefined,
        evs: std.ArrayList(Ev) = .empty,
        /// At each on_idle: the follower's applied position and the store's committed tip.
        applied: [8]u64 = @splat(0),
        tip: [8]u64 = @splat(0),
        idles: usize = 0,
        fn put(r: *@This(), kind: @FieldType(Ev, "kind"), seq: u64) void {
            r.evs.append(testing.allocator, .{ .kind = kind, .seq = seq }) catch @panic("OOM");
        }
        fn onCheckpoint(ctx: *anyopaque, seq: u64, _: *const verify.Checked, _: []const u8) void {
            put(@ptrCast(@alignCast(ctx)), .checkpoint, seq);
        }
        fn onBatch(ctx: *anyopaque, seq: u64, _: *const verify.Checked, _: []const u8, _: *store_mod.Batch) anyerror!void {
            put(@ptrCast(@alignCast(ctx)), .batch, seq);
        }
        fn onCommitted(ctx: *anyopaque, seq: u64) void {
            put(@ptrCast(@alignCast(ctx)), .committed, seq);
        }
        fn onIdle(ctx: *anyopaque, seq: u64) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.applied[r.idles] = r.f.applied_next.load(.acquire);
            r.tip[r.idles] = r.f.store.committed() orelse 0;
            r.idles += 1;
            r.put(.idle, seq);
        }
    };
    var rec: Rec = .{};
    defer rec.evs.deinit(testing.allocator);
    var f = try Follower.init(testing.allocator, testing.io, tb.store, .{ .archive = &tb.arch }, .{ .workers = 2 }, .{ .committee = tb.committee, .first_seq = test_first });
    defer f.deinit();
    rec.f = f;
    f.observer = .{ .ctx = &rec, .on_checkpoint = Rec.onCheckpoint, .on_batch = Rec.onBatch, .on_committed = Rec.onCommitted, .on_idle = Rec.onIdle };
    try f.run(test_first + 2);
    try testing.expectEqual(@as(usize, 12), rec.evs.items.len);
    for (0..3) |i| {
        const seq = test_first + i;
        const e = rec.evs.items[i * 4 ..][0..4];
        for (e) |x| try testing.expectEqual(seq, x.seq);
        try testing.expect(e[0].kind == .checkpoint and e[1].kind == .batch and e[2].kind == .committed and e[3].kind == .idle);
        // The checkpoint was served (store) and the follower had moved on before the hook ran.
        try testing.expectEqual(seq + 1, rec.applied[i]);
        try testing.expectEqual(seq, rec.tip[i]);
    }
}

test "follower: a stop in catch-up ends the run after the checkpoint in hand; checked checkpoints waiting in the window are not applied" {
    var tb: TestBed = undefined;
    try tb.init(test_epoch);
    defer tb.deinit();
    const Rec = struct {
        f: *Follower = undefined,
        stop_at: u64,
        /// Checked checkpoints waiting behind `stop_at` when the stop was sent.
        waiting: u64 = 0,
        applied: u64 = 0,
        timed_out: bool = false,
        fn onCheckpoint(ctx: *anyopaque, seq: u64, _: *const verify.Checked, _: []const u8) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            if (seq != r.stop_at) return;
            // Catch-up: the workers are ahead of the ordered stage. Wait until the next three
            // checkpoints are checked and waiting, then stop with this one still in hand.
            const t0 = now();
            while (r.ahead(seq) < 3) {
                if (now() - t0 > 20 * std.time.ns_per_s) {
                    r.timed_out = true;
                    break;
                }
                testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
            }
            r.waiting = r.ahead(seq);
            r.f.stop();
        }
        fn ahead(r: *@This(), seq: u64) u64 {
            var n: u64 = 0;
            while (n < r.f.slots.len - 1) : (n += 1) {
                const s = seq + 1 + n;
                if (r.f.slots[s % r.f.slots.len].ready.load(.acquire) != s + 1) break;
            }
            return n;
        }
        fn onCommitted(ctx: *anyopaque, _: u64) void {
            const r: *@This() = @ptrCast(@alignCast(ctx));
            r.applied += 1;
        }
    };
    var rec: Rec = .{ .stop_at = test_first + 2 };
    var f = try Follower.init(testing.allocator, testing.io, tb.store, .{ .archive = &tb.arch }, .{ .workers = 2, .window = 8 }, .{ .committee = tb.committee, .first_seq = test_first });
    defer f.deinit();
    rec.f = f;
    f.observer = .{ .ctx = &rec, .on_checkpoint = Rec.onCheckpoint, .on_committed = Rec.onCommitted };
    try f.run(null);
    try testing.expect(!rec.timed_out);
    try testing.expect(rec.waiting >= 3);
    // The checkpoint in hand was committed whole; none of the waiting ones was started.
    try testing.expectEqual(@as(u64, 3), rec.applied);
    try testing.expectEqual(test_first + 3, f.applied_next.load(.acquire));
    try testing.expectEqual(@as(?u64, test_first + 2), tb.store.committed());
    // The same follower goes on from there (a second run, as after the node's refetch).
    f.rewind();
    rec.stop_at = std.math.maxInt(u64);
    try f.run(test_first + 5);
    try testing.expectEqual(@as(u64, 6), rec.applied);
    try testing.expectEqual(@as(?u64, test_first + 5), tb.store.committed());
}

/// A live follower (no end) over an empty archive directory with a one-member committee (the
/// BLS12-381 G2 generator as its key): enough to test how workers wait for the source. No
/// checkpoint in these tests is valid; the first one read ends the run with a decode verdict.
const WaitBed = struct {
    tmp: testing.TmpDir,
    arena: std.heap.ArenaAllocator,
    store: *store_mod.Store,
    sio: *store_mod.RealIo,
    arch: archive.Archive,
    f: *Follower,
    thread: ?std.Thread = null,
    result: ?Error = null,
    done: Atomic(bool) = .init(false),

    const g2_generator_hex = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

    fn init(wb: *WaitBed, cfg: Config) !void {
        const gpa = testing.allocator;
        const io = testing.io;
        wb.* = .{ .tmp = testing.tmpDir(.{}), .arena = std.heap.ArenaAllocator.init(gpa), .store = undefined, .sio = undefined, .arch = undefined, .f = undefined };
        const a = wb.arena.allocator();
        var key: [96]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, g2_generator_hex);
        const committee = try Committee.init(a, 7, &.{key}, &.{10_000});
        try wb.tmp.dir.createDir(io, "arch", .default_dir);
        try wb.tmp.dir.createDir(io, "store", .default_dir);
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        const n = try wb.tmp.dir.realPath(io, &pb);
        var scfg: store_mod.Config = .{ .max_live_objects = 1 << 12, .max_object_versions = 1 << 12, .max_transactions = 1 << 12, .max_checkpoints = 1 << 12 };
        scfg.dir = try std.fmt.allocPrint(a, "{s}/store", .{pb[0..n]});
        const h = try store_mod.openDir(gpa, io, &scfg, .{ .sync = .none });
        wb.store = h.store;
        wb.sio = h.io;
        wb.arch = .{ .dir = try wb.tmp.dir.openDir(io, "arch", .{}) };
        wb.f = try Follower.init(gpa, io, wb.store, .{ .archive = &wb.arch }, cfg, .{ .committee = committee, .first_seq = 100 });
        wb.thread = try std.Thread.spawn(.{}, runMain, .{wb});
    }

    fn runMain(wb: *WaitBed) void {
        wb.f.run(null) catch |e| {
            wb.result = e;
        };
        wb.done.store(true, .release);
    }

    /// Puts bytes for checkpoint `seq` in the archive directory (temporary name, then rename).
    fn put(wb: *WaitBed, seq: u64) !void {
        var nb: [32]u8 = undefined;
        try wb.tmp.dir.writeFile(testing.io, .{ .sub_path = "arch/.tmp", .data = "not a checkpoint" });
        try wb.tmp.dir.rename("arch/.tmp", wb.tmp.dir, try std.fmt.bufPrint(&nb, "arch/{d}.chk", .{seq}), testing.io);
    }

    /// Waits up to `ms` for `cond(wb)`; true if it held.
    fn until(wb: *WaitBed, ms: u64, comptime cond: fn (*WaitBed) bool) bool {
        const t0 = now();
        while (now() - t0 < ms * std.time.ns_per_ms) {
            if (cond(wb)) return true;
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
        return cond(wb);
    }

    fn finished(wb: *WaitBed) bool {
        return wb.done.load(.acquire);
    }

    fn deinit(wb: *WaitBed) void {
        // `run` clears the stop flag when it starts: a stop sent before the thread got there
        // would be lost (the test then hangs in the join), so it is repeated until the run ends.
        while (!wb.finished()) {
            wb.f.stop();
            testing.io.sleep(.fromMilliseconds(1), .awake) catch {};
        }
        if (wb.thread) |t| t.join();
        wb.f.deinit();
        wb.store.deinit();
        wb.sio.deinit();
        wb.arch.close(testing.io);
        wb.tmp.cleanup();
        wb.arena.deinit();
    }
};

test "follower: workers waiting for the source block until notify; no polling reads, and stop wakes them" {
    var wb: WaitBed = undefined;
    // A fallback far longer than the test: only a wake can end a wait.
    try wb.init(.{ .workers = 4, .poll_ms = 60_000 });
    defer wb.deinit();
    const f = wb.f;
    // Each worker claims one checkpoint (100..103), looks once and blocks.
    try testing.expect(wb.until(5000, struct {
        fn c(w: *WaitBed) bool {
            return w.f.read_misses.load(.acquire) == 4;
        }
    }.c));
    testing.io.sleep(.fromMilliseconds(300), .awake) catch {};
    // With the 2 ms poll this was about 600 by now.
    try testing.expectEqual(@as(u64, 4), f.read_misses.load(.acquire));
    try testing.expect(!wb.finished());
    // The writer renames the file in, then announces it.
    try wb.put(100);
    const t0 = now();
    f.notify(100);
    try testing.expect(wb.until(5000, WaitBed.finished));
    // Read, rejected (not a checkpoint) and the run ended, workers joined (stop woke the three
    // still waiting): all well inside the 60 s fallback.
    try testing.expect(now() - t0 < 5 * std.time.ns_per_s);
    try testing.expectEqual(@as(?Error, error.BadCheckpoint), wb.result);
    try testing.expectEqual(@as(u64, 100), f.failure.?.seq);
    // Only the worker of 100 was woken: one more look by it for 104, and one by each worker
    // when stop woke them. The three waiting for 101..103 never looked again in between.
    try testing.expect(f.read_misses.load(.acquire) <= 4 + 1 + 4);
}

test "follower: a checkpoint nobody announced is still found at the fallback timeout" {
    var wb: WaitBed = undefined;
    try wb.init(.{ .workers = 2, .poll_ms = 40 });
    defer wb.deinit();
    try testing.expect(wb.until(5000, struct {
        fn c(w: *WaitBed) bool {
            return w.f.read_misses.load(.acquire) >= 2;
        }
    }.c));
    try wb.put(100); // no notify
    try testing.expect(wb.until(5000, WaitBed.finished));
    try testing.expectEqual(@as(?Error, error.BadCheckpoint), wb.result);
}
