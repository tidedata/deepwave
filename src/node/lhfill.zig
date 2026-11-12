//! Ledger-history backfill: a store
//! that already holds checkpoints the ledger-history index never saw (a snapshot restore plus a
//! follow before the index existed, or a follow with the index off, or an index restarted at a
//! hole) gets index rows for its whole retained window, so ListCheckpoints, ListTransactions and
//! ListEvents answer from `lowest_available_checkpoint` to the tip like sui-node's rpc_store.
//!
//! Every input the index takes per checkpoint comes from stored records (CONTRACTS 6.8): the
//! summary's sequence number and `network_total_transactions` (checkpoint record), each
//! transaction's envelope, effects and events (transaction records, in the contents' order), and
//! the objects its changed objects name at their input and output versions (object versions by
//! (id, version): outputs are the follower's object records, inputs are kept for as long as the
//! transaction by the history writer, node history.zig). The index reads those objects only for
//! their owner (affected_address) and whether they are packages (any_package_write), so the
//! rebuilt `CheckpointData` carries exactly them. A version the store cannot find is counted
//! (`missing_objects`) and its owner dimension is skipped.
//!
//! A background thread builds a fresh index over `[from, to]` (on disk in the node's staging
//! directory `<ledger-history>/backfill`, so the heap holds one open segment; in memory in tests;
//! worker threads load
//! checkpoints in parallel into a ring; the thread applies them in order), then follows the
//! store's committed tip until it is a few checkpoints behind and reports ready. The node's
//! commit path then catches it up to the checkpoint before the one it is indexing and swaps it
//! into the live index (`history.Index.adopt`); until then the live index keeps serving.
//!
//! Durability (resume): with a staging directory (the node's `<ledger-history>/backfill`) the
//! build is an on-disk index (`history.Index.openStaging`: no per-checkpoint log; durable at each
//! segment rotation and at every `saveStaging`, which the build calls every `save_every_ns` and
//! at the end). The staging index's `indexedHi` as of its last rotation is the durable watermark:
//! a restart (crash, kill -9, upgrade) reopens it there and loads from the watermark + 1 instead
//! of from the store's lowest. A staging index whose low end is above the store's lowest (the
//! store gained older history) or that does not join the requested range is deleted and built
//! again. `adopt` renames the staging generation into the live index root and switches its
//! `CURRENT`; the live index is durable when `adopt` returns (`Index.persistedGeneration`), and
//! only then does the node delete the staging directory.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const lhist = @import("history");
const nowNs = @import("source.zig").nowNs;
const fast_start = @import("fast_start.zig");
const builtin = @import("builtin");

pub const Error = error{ CheckpointNotStored, TransactionNotStored, Cancelled };

const ObjKey = struct { id: [32]u8, version: u64 };

/// Object versions the index reads for one transaction: each changed object's input and output
/// version (dims.zig `extract`, minus accumulator writes).
fn changeKeys(arena: Allocator, eff: *const types.TransactionEffects) ![]ObjKey {
    var out: std.ArrayList(ObjKey) = .empty;
    switch (eff.*) {
        .V2 => |*v| for (v.changed_objects) |*c| {
            const id = c.@"0".@"0".@"0";
            switch (c.@"1".output_state) {
                .NotExist => {},
                .ObjectWrite => try out.append(arena, .{ .id = id, .version = v.lamport_version.@"0" }),
                .PackageWrite => |p| try out.append(arena, .{ .id = id, .version = p.@"0".@"0" }),
                .AccumulatorWriteV1 => continue,
            }
            switch (c.@"1".input_state) {
                .NotExist => {},
                .Exist => |x| try out.append(arena, .{ .id = id, .version = x.@"0".@"0".@"0" }),
            }
        },
        .V1 => |*v| {
            for (v.created) |x| try out.append(arena, .{ .id = x.@"0".@"0".@"0".@"0", .version = x.@"0".@"1".@"0" });
            for (v.mutated) |x| try out.append(arena, .{ .id = x.@"0".@"0".@"0".@"0", .version = x.@"0".@"1".@"0" });
            for (v.unwrapped) |x| try out.append(arena, .{ .id = x.@"0".@"0".@"0".@"0", .version = x.@"0".@"1".@"0" });
            for (v.modified_at_versions) |m| try out.append(arena, .{ .id = m.@"0".@"0".@"0", .version = m.@"1".@"0" });
        },
    }
    return out.items;
}

pub const Counters = struct {
    checkpoints: std.atomic.Value(u64) = .init(0),
    txs: std.atomic.Value(u64) = .init(0),
    objects: std.atomic.Value(u64) = .init(0),
    missing_objects: std.atomic.Value(u64) = .init(0),
};

/// The ledger-history inputs of checkpoint `seq` rebuilt from the store (see the file header),
/// copied into `arena` (nothing points into the snapshot's mappings). Null when the store does
/// not hold the checkpoint.
pub fn load(arena: Allocator, snap: *const store.Snapshot, seq: u64, c: *Counters) !?types.CheckpointData {
    return loadCancel(arena, snap, seq, c, null);
}

/// `load` that gives up with `error.Cancelled` between two transactions once `cancel` is set:
/// a stop does not wait for the rest of a large checkpoint's reads (each transaction is a few
/// reads of the store, cold ones on a store that was just opened).
pub fn loadCancel(arena: Allocator, snap: *const store.Snapshot, seq: u64, c: *Counters, cancel: ?*const std.atomic.Value(bool)) !?types.CheckpointData {
    const rec = (try snap.checkpointChecked(seq)) orelse return null;
    const Summary = @FieldType(types.CheckpointData, "checkpoint_summary");
    const summary = try bcs.decode(Summary, arena, try arena.dupe(u8, rec.summary_cert));
    const contents = try bcs.decode(types.CheckpointContents, arena, try arena.dupe(u8, rec.contents));
    const n = switch (contents) {
        .V1 => |v| v.transactions.len,
        .V2 => |v| v.transactions.len,
    };
    const txs = try arena.alloc(types.CheckpointTransaction, n);
    const Tx = @FieldType(types.CheckpointTransaction, "transaction");
    for (txs, 0..) |*t, i| {
        if (cancel) |x| if (x.load(.acquire)) return error.Cancelled;
        const dg: *const [32]u8 = switch (contents) {
            .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
            .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
        };
        const tr = (try snap.transactionChecked(dg)) orelse return error.TransactionNotStored;
        const eff = try bcs.decode(types.TransactionEffects, arena, try arena.dupe(u8, tr.effects));
        const keys = try changeKeys(arena, &eff);
        var objs: std.ArrayList(types.Object) = try .initCapacity(arena, keys.len);
        for (keys) |k| {
            const raw = snap.objectAt(&k.id, k.version) orelse {
                _ = c.missing_objects.fetchAdd(1, .monotonic);
                continue;
            };
            objs.appendAssumeCapacity(try bcs.decode(types.Object, arena, try arena.dupe(u8, raw)));
        }
        _ = c.objects.fetchAdd(objs.items.len, .monotonic);
        t.* = .{
            .transaction = try bcs.decode(Tx, arena, try arena.dupe(u8, tr.tx)),
            .effects = eff,
            .events = if (tr.events) |e| try bcs.decode(types.TransactionEvents, arena, try arena.dupe(u8, e)) else null,
            .input_objects = &.{},
            .output_objects = objs.items,
        };
    }
    return .{ .checkpoint_summary = summary, .checkpoint_contents = contents, .transactions = txs };
}

/// Loads checkpoint `seq` from a fresh snapshot of `st` and indexes it into `ix`.
pub fn addFromStore(ix: *lhist.Index, st: *store.Store, seq: u64, arena: *std.heap.ArenaAllocator, c: *Counters) !void {
    _ = arena.reset(.retain_capacity);
    var snap = st.snapshot();
    defer snap.release();
    const cp = (try load(arena.allocator(), &snap, seq, c)) orelse return error.CheckpointNotStored;
    try ix.addData(seq, &cp);
    _ = c.checkpoints.fetchAdd(1, .monotonic);
    _ = c.txs.fetchAdd(cp.transactions.len, .monotonic);
}

pub const Status = enum(u8) { running, ready, failed };

pub const Backfill = struct {
    gpa: Allocator,
    io: std.Io,
    st: *store.Store,
    /// The low end requested (the store's lowest when started).
    lo: u64,
    /// The current round's range (`from` moves on with each round and on a resume).
    from: u64,
    to: u64,
    out: *lhist.Index,
    /// The node's live index (null: none, or tests): the build takes the checkpoints it
    /// already holds from it (`lhist.Index.copyRows`) and reads the store only for the rest.
    live: ?*lhist.Index = null,
    workers: usize,
    /// Staging persistence on (`out` has a directory).
    staged: bool = false,
    /// Where a resume picked up (the staging watermark + 1), else null.
    resumed_at: ?u64 = null,
    saves: u32 = 0,
    last_save_ns: u64 = 0,
    save_every_ns: u64 = 300 * std.time.ns_per_s,
    status_: std.atomic.Value(Status) = .init(.running),
    cancel: std.atomic.Value(bool) = .init(false),
    /// A loader found its checkpoint below the store's floor (retention moved it meanwhile):
    /// the round ends and the build goes on from the new floor (`moveUp`).
    floor_hit: std.atomic.Value(bool) = .init(false),
    /// Times the floor passed the build, and the checkpoints already built below it that were
    /// dropped for it.
    floor_moves: u32 = 0,
    dropped: u64 = 0,
    revouch: bool = false,
    /// Checkpoints taken from the live index instead of the store.
    copied: std.atomic.Value(u64) = .init(0),
    /// The last checkpoint the store is read for before the live index takes over (the first
    /// pass; `from - 1` when the live index covers `from`).
    store_to: std.atomic.Value(u64) = .init(0),
    /// Bytes the ring may hold: checkpoints loaded (decoded, with every object their
    /// transactions changed) and not yet indexed. A loader waits while the ring holds this
    /// much, unless its checkpoint is the next one to index (`Options.mem_bytes`).
    budget: u64 = default_budget,
    /// Bytes the ring holds or has reserved now, the most it ever held, and the same in slots.
    inflight: std.atomic.Value(u64) = .init(0),
    peak_bytes: std.atomic.Value(u64) = .init(0),
    held: std.atomic.Value(u32) = .init(0),
    peak_slots: std.atomic.Value(u32) = .init(0),
    /// The largest single checkpoint loaded (bytes of its arena).
    largest: std.atomic.Value(u64) = .init(0),
    /// Unix ms of the timestamp of the node's newest committed checkpoint (0: none yet), the
    /// node's own. The build waits while the node is behind the tip by it (`behindTip`).
    tip_ms: ?*const std.atomic.Value(u64) = null,
    paused: std.atomic.Value(bool) = .init(false),
    /// Times the build stopped to wait for the node, and how long in all (ms).
    pauses: std.atomic.Value(u32) = .init(0),
    paused_ms: std.atomic.Value(u64) = .init(0),
    /// Tests: stop the build right after the `n`th save (a crash at the watermark).
    stop_after_saves: ?u32 = null,
    failure: ?anyerror = null,
    thread: ?std.Thread = null,
    next: std.atomic.Value(u64) = .init(0),
    /// The next checkpoint the build thread takes from the ring: checkpoint `seq` may be loaded
    /// into its slot only while `seq < consumed + slots.len`, so the checkpoints being loaded
    /// are always one window of distinct slots. (Waiting for the slot's state to read empty is
    /// not enough: `seq` and `seq + ring` can both see the slot empty and share its arena; lane
    /// dropin-r2-lhfill c5b31d1, a SIGSEGV on the restored epoch-1304 store.)
    consumed: std.atomic.Value(u64) = .init(0),
    slots: []Slot = &.{},
    counters: Counters = .{},
    started_ns: u64 = 0,
    /// Wall time of the build up to `ready` (ns).
    build_ns: u64 = 0,
    rounds: u32 = 0,

    /// Ring slot: `state` is 0 when empty, `seq + 1` when it holds checkpoint `seq`.
    const Slot = struct {
        state: std.atomic.Value(u64) = .init(0),
        arena: std.heap.ArenaAllocator,
        data: types.CheckpointData = undefined,
        /// What this slot counts for in `inflight` while it is loaded.
        bytes: u64 = 0,
    };
    pub const default_ring = 64;
    /// 256 MiB. Until the ring had a budget it held up to `ring` checkpoints whatever their
    /// size, and every slot kept the memory of the largest checkpoint it had ever held: a
    /// stretch of large checkpoints took a live 8 GB edge from 3 GiB to 6.3 GiB of anonymous
    /// memory and all of its swap, and the node off the tip for an hour.
    pub const default_budget: u64 = 256 << 20;
    /// What a loader reserves before it knows its checkpoint's size.
    const reserve: u64 = 1 << 20;
    /// What an idle slot keeps of its arena.
    const slot_retain: usize = 256 << 10;
    /// Ready once the build is this close to the store's committed tip (the commit path indexes
    /// the rest at the swap: about 1 ms each). While the store moves faster than the serial tail,
    /// parallel rounds close the gap instead.
    const near_tip = 64;
    /// Checkpoints copied from the live index between two looks at the node and the clock.
    const copy_step: u64 = 1024;

    pub const Options = struct {
        workers: usize = 4,
        /// Staging directory for a resumable build (null: in memory only).
        staging: ?[]const u8 = null,
        save_every_ns: u64 = 300 * std.time.ns_per_s,
        /// Tests: stop after this many saves (a crash at the watermark).
        stop_after_saves: ?u32 = null,
        /// Ring slots (tests use a small one to make slot reuse frequent).
        ring: usize = default_ring,
        /// The live index, for the checkpoints it already holds.
        live: ?*lhist.Index = null,
        /// The ring's memory budget (`Backfill.budget`).
        mem_bytes: u64 = default_budget,
        /// The node's newest committed checkpoint's timestamp (`Backfill.tip_ms`); null: the
        /// build never waits for the node (tests, tools).
        tip_ms: ?*const std.atomic.Value(u64) = null,
    };

    /// Starts building checkpoints `from..=to` (then following the store's tip) on a thread.
    pub fn start(gpa: Allocator, io: std.Io, st: *store.Store, from: u64, to: u64, workers: usize) !*Backfill {
        return startOpts(gpa, io, st, from, to, .{ .workers = workers });
    }

    /// `start` with a ring of `ring` slots.
    pub fn startRing(gpa: Allocator, io: std.Io, st: *store.Store, from: u64, to: u64, workers: usize, ring: usize) !*Backfill {
        return startOpts(gpa, io, st, from, to, .{ .workers = workers, .ring = ring });
    }

    pub fn startOpts(gpa: Allocator, io: std.Io, st: *store.Store, from: u64, to: u64, o: Options) !*Backfill {
        const b = try gpa.create(Backfill);
        errdefer gpa.destroy(b);
        var resumed: ?u64 = null;
        const out = if (o.staging) |d| try openStagingFor(gpa, io, d, from, to, &resumed) else try lhist.Index.init(gpa, io, null);
        errdefer out.deinit();
        const begin = resumed orelse from;
        const slots = try gpa.alloc(Slot, @max(1, o.ring));
        for (slots) |*s| s.* = .{ .arena = std.heap.ArenaAllocator.init(std.heap.page_allocator) };
        errdefer {
            for (slots) |*s| s.arena.deinit();
            gpa.free(slots);
        }
        b.* = .{ .gpa = gpa, .io = io, .st = st, .lo = from, .from = begin, .to = to, .out = out, .live = o.live, .budget = @max(o.mem_bytes, 1), .tip_ms = o.tip_ms, .workers = @max(1, o.workers), .slots = slots, .staged = o.staging != null, .resumed_at = resumed, .save_every_ns = o.save_every_ns, .stop_after_saves = o.stop_after_saves };
        // Its low end is the store's lowest checkpoint (the caller's `from`, or an earlier
        // one for a resumed staging index): a floor the node can read back after an unclean
        // stop (`floorWitness`).
        out.vouchLow();
        b.store_to.store(b.storeEnd(begin, to), .monotonic);
        b.next.store(begin, .monotonic);
        b.started_ns = nowNs();
        b.last_save_ns = b.started_ns;
        b.thread = try std.Thread.spawn(.{}, main, .{b});
        return b;
    }

    /// Opens the staging index in `dir` (on disk: it reopens at its last rotation, the durable
    /// watermark). Usable when it starts at or below the requested low end and reaches into the
    /// range (a store pruned since keeps working: the node prunes after the swap); then
    /// `resumed` is set to the next checkpoint to load. Anything else is deleted and the
    /// staging index starts empty.
    fn openStagingFor(gpa: Allocator, io: std.Io, dir: []const u8, from: u64, to: u64, resumed: *?u64) !*lhist.Index {
        const out = try lhist.Index.openStaging(gpa, io, dir);
        const slo = out.indexedLo() orelse return out;
        const shi = out.indexedHi().?;
        if (slo <= from and shi + 1 >= from) {
            resumed.* = @max(from, shi + 1);
            return out;
        }
        std.log.info("history: backfill staging {d}..{d} does not fit {d}..{d}; building again", .{ slo, shi, from, to });
        out.deinit();
        std.Io.Dir.cwd().deleteTree(io, dir) catch {};
        const fresh = try lhist.Index.openStaging(gpa, io, dir);
        // A delete that failed leaves the old state: building over it would skip every
        // checkpoint below its tip (`addData` skips indexed ones) and adopt the wrong window.
        if (fresh.indexedLo() != null) {
            fresh.deinit();
            return error.StagingNotEmpty;
        }
        return fresh;
    }

    pub fn status(b: *const Backfill) Status {
        return b.status_.load(.acquire);
    }

    fn fail(b: *Backfill, e: anyerror) void {
        if (b.failure == null) b.failure = e;
        b.status_.store(.failed, .release);
    }

    /// The round in progress ends: a stop, a failure, or the floor passed a loader.
    fn stopped(b: *const Backfill) bool {
        return b.cancel.load(.acquire) or b.status() == .failed or b.floor_hit.load(.acquire);
    }

    /// Tells the build to stop without waiting for it (`destroy` joins it). The loaders see it
    /// between two transactions of the checkpoint they are loading.
    pub fn requestStop(b: *Backfill) void {
        b.cancel.store(true, .release);
    }

    /// The store's lowest checkpoint is above `seq` now.
    fn floorAbove(b: *Backfill, seq: u64) bool {
        var snap = b.st.snapshot();
        defer snap.release();
        const low = snap.lowestAvailable() orelse return false;
        return low > seq;
    }

    /// A loader could not load `seq`. Pruned underneath it (the checkpoint or one of its
    /// transactions is below the store's floor now) is not a failure: the build's start moves
    /// up. Anything else is.
    fn loadFailed(b: *Backfill, seq: u64, e: anyerror) void {
        if (e == error.Cancelled) return;
        if ((e == error.CheckpointNotStored or e == error.TransactionNotStored) and b.floorAbove(seq)) {
            b.floor_hit.store(true, .release);
            return;
        }
        b.fail(e);
    }

    /// After a round the floor ended: the checkpoint to go on from, the store's lowest. What
    /// was built below it cannot join it (the checkpoints between are gone), so the output
    /// starts again there (`lhist.Index` restarts at a hole); it was all below the floor, where
    /// the node would have pruned it after the swap anyway.
    fn moveUp(b: *Backfill) !u64 {
        var snap = b.st.snapshot();
        defer snap.release();
        const low = snap.lowestAvailable() orelse return error.CheckpointNotStored;
        b.floor_hit.store(false, .release);
        const was = b.out.indexedLo();
        if (b.out.indexedHi()) |hi| {
            // (the floor passed a checkpoint that was not loaded yet, so it is above the output)
            if (hi + 1 >= low) return hi + 1;
            b.dropped += hi + 1 - was.?;
        }
        b.floor_moves += 1;
        b.lo = low;
        b.revouch = true;
        if (!@import("builtin").is_test) std.log.info("history: backfill: the store's lowest checkpoint moved up to {d} under the build (retention); going on from there, {d} checkpoints built below it are dropped", .{ low, b.dropped });
        return low;
    }

    /// The last checkpoint of `from..=to` the store must be read for: up to the live index's
    /// low end when that lies in the range (the rest is copied from it), else `to`.
    fn storeEnd(b: *Backfill, from: u64, to: u64) u64 {
        const lv = b.live orelse return to;
        const lo = lv.indexedLo() orelse return to;
        const hi = lv.indexedHi() orelse return to;
        if (hi < from) return to;
        return if (lo > from) @min(to, lo - 1) else from -| 1;
    }

    fn pause(b: *const Backfill) void {
        b.io.sleep(.fromMicroseconds(50), .awake) catch {};
    }

    /// Background work: the lowest CPU priority, and on Linux the idle I/O class (honoured by
    /// the BFQ and CFQ schedulers; the budget and `yieldToNode` are what bound it elsewhere).
    fn lowPriority() void {
        if (builtin.os.tag == .linux) {
            const linux = std.os.linux;
            // PRIO_PROCESS with id 0 is the calling thread on Linux (nice is per thread)
            _ = linux.syscall3(.setpriority, 0, 0, 19);
            // IOPRIO_WHO_PROCESS = 1, this thread; class IDLE = 3, in the top 3 bits of 16
            _ = linux.syscall3(.ioprio_set, 1, 0, 3 << 13);
        }
    }

    /// The node is behind the tip: its newest committed checkpoint is older than
    /// `fast_start.catchup_lag_ms` (10 s), or was and is not back within `tip_lag_ms` (3 s),
    /// or it has committed none yet (a start: the follower catches up first). Read off the
    /// wall clock, not off commits: a node the build itself has starved commits nothing.
    fn behindTip(b: *Backfill) bool {
        const p = b.tip_ms orelse return false;
        const ts = p.load(.monotonic);
        const was = b.paused.load(.monotonic);
        const now_ms: u64 = @intCast(@max(0, @divTrunc(std.Io.Clock.real.now(b.io).toNanoseconds(), std.time.ns_per_ms)));
        const is = ts == 0 or fast_start.behind(was, now_ms -| ts);
        if (is != was) b.paused.store(is, .monotonic);
        return is;
    }

    /// Waits for as long as the node is behind the tip (or until the build is told to stop).
    /// The follower's reads and writes come first: this is what keeps a slow disk's backfill
    /// from taking the node off the tip.
    fn yieldToNode(b: *Backfill) void {
        if (!b.behindTip()) return;
        _ = b.pauses.fetchAdd(1, .monotonic);
        const t0 = nowNs();
        while (!b.cancel.load(.acquire) and b.status() != .failed and b.behindTip()) b.io.sleep(.fromMilliseconds(100), .awake) catch {};
        _ = b.paused_ms.fetchAdd((nowNs() - t0) / std.time.ns_per_ms, .monotonic);
    }

    fn noteMax(a: *std.atomic.Value(u64), v: u64) void {
        _ = a.fetchMax(v, .monotonic);
    }

    /// Takes room in the ring for checkpoint `seq` (`reserve` bytes, until its size is known).
    /// Waits while the ring is at its budget, unless nothing is held or `seq` is the next
    /// checkpoint to index (the consumer waits for it: it must load whatever the ring holds).
    /// False: the round ended.
    fn admit(b: *Backfill, seq: u64) bool {
        while (true) {
            if (b.stopped()) return false;
            const cur = b.inflight.load(.acquire);
            if (cur == 0 or cur + reserve <= b.budget or seq == b.consumed.load(.acquire)) {
                if (b.inflight.cmpxchgWeak(cur, cur + reserve, .acq_rel, .acquire) != null) continue;
                noteMax(&b.peak_bytes, cur + reserve);
                _ = b.peak_slots.fetchMax(b.held.fetchAdd(1, .acq_rel) + 1, .monotonic);
                return true;
            }
            b.pause();
        }
    }

    /// Gives back what `admit` and the load took for a slot.
    fn release(b: *Backfill, bytes: u64) void {
        _ = b.inflight.fetchSub(bytes, .acq_rel);
        _ = b.held.fetchSub(1, .acq_rel);
    }

    /// What the ring's slots keep allocated now (call with the build at rest: tests).
    pub fn ringBytes(b: *Backfill) u64 {
        var n: u64 = 0;
        for (b.slots) |*s| n += s.arena.queryCapacity();
        return n;
    }

    pub const slot_retain_bytes = slot_retain;

    /// Heap the build holds: the ring, and the open segment of the index it builds.
    pub fn memoryBytes(b: *Backfill) u64 {
        return b.inflight.load(.monotonic) + b.out.memoryBytes();
    }

    fn worker(b: *Backfill) void {
        lowPriority();
        while (!b.stopped()) {
            b.yieldToNode();
            const seq = b.next.fetchAdd(1, .monotonic);
            if (seq > b.to) return;
            const slot = &b.slots[@intCast((seq - b.from) % b.slots.len)];
            while (seq >= b.consumed.load(.acquire) + b.slots.len) {
                if (b.stopped()) return;
                b.pause();
            }
            if (!b.admit(seq)) return;
            std.debug.assert(slot.state.load(.acquire) == 0);
            _ = slot.arena.reset(.{ .retain_with_limit = slot_retain });
            var snap = b.st.snapshot();
            defer snap.release();
            const cp = loadCancel(slot.arena.allocator(), &snap, seq, &b.counters, &b.cancel) catch |e| {
                b.release(reserve);
                return b.loadFailed(seq, e);
            };
            slot.data = cp orelse {
                b.release(reserve);
                return b.loadFailed(seq, error.CheckpointNotStored);
            };
            // the reservation becomes the checkpoint's real size
            const used: u64 = slot.arena.queryCapacity();
            slot.bytes = @max(used, reserve);
            if (used > reserve) noteMax(&b.peak_bytes, b.inflight.fetchAdd(used - reserve, .acq_rel) + (used - reserve));
            noteMax(&b.largest, used);
            slot.state.store(seq + 1, .release);
        }
    }

    fn main(b: *Backfill) void {
        lowPriority();
        b.build() catch |e| return b.fail(e);
        if (b.cancel.load(.acquire) or b.status() == .failed) return;
        b.build_ns = nowNs() - b.started_ns;
        b.status_.store(.ready, .release);
    }

    /// Saves the staging state (the durable watermark); a failed save only costs progress.
    fn save(b: *Backfill) void {
        if (!b.staged) return;
        b.out.vouchLow();
        b.out.saveStaging() catch |e| {
            std.log.warn("history: backfill staging save: {s} (the build goes on; a restart resumes from the previous save)", .{@errorName(e)});
            return;
        };
        b.saves += 1;
        b.last_save_ns = nowNs();
        if (!@import("builtin").is_test) std.log.info("history: backfill saved through checkpoint {?d} ({d} checkpoints this run)", .{ b.out.indexedHi(), b.counters.checkpoints.load(.monotonic) });
        if (b.stop_after_saves) |n| if (b.saves >= n) b.cancel.store(true, .release);
    }

    /// One parallel round over `from..=to`.
    fn round(b: *Backfill, from: u64, to: u64) !void {
        if (to < from) return;
        b.rounds += 1;
        b.from = from;
        b.to = to;
        b.next.store(from, .monotonic);
        b.consumed.store(from, .release);
        // (a round that ended early may have left loaded slots: the loaders are joined)
        for (b.slots) |*s| {
            s.state.store(0, .release);
            s.bytes = 0;
            _ = s.arena.reset(.{ .retain_with_limit = slot_retain });
        }
        b.inflight.store(0, .release);
        b.held.store(0, .release);
        var threads: std.ArrayList(std.Thread) = .empty;
        defer threads.deinit(b.gpa);
        defer for (threads.items) |t| t.join();
        for (0..b.workers) |_| {
            const t = std.Thread.spawn(.{}, worker, .{b}) catch |e| {
                if (threads.items.len == 0) return e;
                break;
            };
            threads.append(b.gpa, t) catch {
                t.join();
                break;
            };
        }
        var seq = from;
        while (seq <= to) : (seq += 1) {
            const slot = &b.slots[@intCast((seq - from) % b.slots.len)];
            while (slot.state.load(.acquire) != seq + 1) {
                if (b.stopped()) return;
                b.pause();
            }
            b.out.addData(seq, &slot.data) catch |e| {
                b.fail(e);
                return e;
            };
            if (b.revouch) {
                // the output started again at the store's lowest checkpoint (`moveUp`)
                b.out.vouchLow();
                b.revouch = false;
            }
            _ = b.counters.checkpoints.fetchAdd(1, .monotonic);
            _ = b.counters.txs.fetchAdd(slot.data.transactions.len, .monotonic);
            // indexed: its memory goes back now, not when a loader next comes to the slot
            const held_bytes = slot.bytes;
            slot.bytes = 0;
            _ = slot.arena.reset(.{ .retain_with_limit = slot_retain });
            b.release(held_bytes);
            slot.state.store(0, .release);
            b.consumed.store(seq + 1, .release);
            if (b.staged and nowNs() -| b.last_save_ns >= b.save_every_ns) {
                b.save();
                if (b.stopped()) return;
            }
        }
    }

    /// The whole build. From the store: what no index holds (with a live index that covers the
    /// upper part of the window, only the checkpoints below its low end). From the live index:
    /// everything it holds from there on, read a segment at a time from its own files. Then
    /// parallel rounds from the store up to its moving tip until close to it; the commit path
    /// takes the last few at the swap.
    fn build(b: *Backfill) !void {
        var next = b.from;
        var first = true;
        while (true) {
            if (b.cancel.load(.acquire) or b.status() == .failed) return;
            // In steps, so the copy too waits for a node that is behind and saves on time.
            if (b.live) |lv| while (true) {
                b.yieldToNode();
                if (b.cancel.load(.acquire)) return;
                const got = try b.out.copyRows(lv, next, next +| (copy_step - 1), &b.cancel);
                _ = b.copied.fetchAdd(got - next, .monotonic);
                if (got != next and b.revouch) {
                    b.out.vouchLow();
                    b.revouch = false;
                }
                const done = got < next +| copy_step;
                next = got;
                if (b.cancel.load(.acquire)) return;
                if (b.staged and nowNs() -| b.last_save_ns >= b.save_every_ns) {
                    b.save();
                    if (b.cancel.load(.acquire)) return;
                }
                if (done) break;
            };
            const tip = b.st.committed() orelse break;
            // The first pass covers the range asked for, however short; after it the build
            // is ready once it is close to the tip.
            const target = if (first) b.to else tip;
            if (!first and tip < next + near_tip) break;
            const hi = b.storeEnd(next, target);
            first = false;
            if (hi < next) {
                // the live index holds `next` after all (it grew, or the copy was cut short)
                if (target < next) break;
                continue;
            }
            b.store_to.store(hi, .monotonic);
            try b.round(next, hi);
            if (b.floor_hit.load(.acquire)) {
                next = try b.moveUp();
                first = true;
                if (next > b.to) b.to = next;
                continue;
            }
            if (b.cancel.load(.acquire) or b.status() == .failed) return;
            next = hi + 1;
        }
        if (!b.stopped()) b.save();
    }

    /// Commit path, once `status() == .ready`: joins the build thread, indexes the store's
    /// checkpoints up to `upto` (committed) and returns the index for `Index.adopt`. The
    /// backfill keeps ownership (destroy it after the adopt: it then frees the old state).
    pub fn finish(b: *Backfill, upto: u64) !*lhist.Index {
        if (b.thread) |t| t.join();
        b.thread = null;
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        var s = (b.out.indexedHi() orelse b.lo -| 1) + 1;
        while (s <= upto) : (s += 1) try addFromStore(b.out, b.st, s, &arena, &b.counters);
        b.out.vouchLow();
        b.out.detachDir();
        return b.out;
    }

    /// `destroy` for a build nobody needs any more (the index covers the store without it):
    /// nothing is saved.
    pub fn discard(b: *Backfill) void {
        b.requestStop();
        if (b.thread) |t| t.join();
        b.thread = null;
        b.staged = false;
        b.destroy();
    }

    /// Stops the build (if running) and frees everything.
    pub fn destroy(b: *Backfill) void {
        b.requestStop();
        if (b.thread) |t| t.join();
        b.thread = null;
        // An interrupted build (shutdown) keeps its progress for the next start.
        if (b.staged and b.out.root != null and b.status() == .running) b.save();
        for (b.slots) |*s| s.arena.deinit();
        b.gpa.free(b.slots);
        b.out.deinit();
        b.gpa.destroy(b);
    }
};

/// The checkpoint floor the node had given its store before it stopped, as the ledger-history
/// index kept it. The store makes its floors durable with its next meta write only (a live-table
/// flush or an age-out, store.zig `setFloors`): after an unclean stop its floor, and with it its
/// lowest checkpoint, comes back lower, over checkpoints retention had already passed. The index
/// is pruned to the store's lowest checkpoint at every retention tick and that prune is durable
/// when it returns; a backfill's staging index begins at the store's lowest checkpoint. Either
/// low end is therefore a floor the store had reached (`lhist.Index.lowIsFloor`, `peekFloor`).
/// Null: nothing vouches for a floor (an index that only began where it begins, or none).
pub fn floorWitness(io: std.Io, live: *lhist.Index, staging: ?[]const u8) ?u64 {
    var w: ?u64 = if (live.lowIsFloor()) live.indexedLo() else null;
    if (staging) |d| if (lhist.Index.peekFloor(io, d)) |s| {
        w = @max(w orelse 0, s);
    };
    return w;
}

/// Gives the store the checkpoint floor `floorWitness` holds when the store's lowest checkpoint
/// `lowest` is below it (and the witness is a checkpoint the store has: not above `tip`).
/// Before the follower runs (`setFloors` is the writer's). Returns the floor restored, null
/// when there was nothing to restore. Only the checkpoint floor: the object floor has no
/// witness and retention raises it again by itself.
pub fn restoreFloor(st: *store.Store, io: std.Io, live: *lhist.Index, staging: ?[]const u8, lowest: u64, tip: u64) !?u64 {
    const w = floorWitness(io, live, staging) orelse return null;
    if (w <= lowest or w > tip) return null;
    _ = try st.setFloors(.{ .cp_pruned = w - 1 });
    return w;
}

/// What the ledger-history index lacks of the store's window `lowest..=tip`.
pub const Gap = struct {
    /// Checkpoints the store serves and the index does not hold: `from..=to` (none: `to < from`).
    from: u64,
    to: u64,

    pub fn count(g: Gap) u64 {
        return if (g.to < g.from) 0 else g.to - g.from + 1;
    }
};

/// The index's gap below its low end (an empty index: the whole window). The index never ends
/// below the store's tip (its record is durable before the store commits the checkpoint).
pub fn gapOf(live: *lhist.Index, lowest: u64, tip: u64) Gap {
    const lo = live.indexedLo() orelse return .{ .from = lowest, .to = tip };
    return .{ .from = lowest, .to = @min(tip, lo -| 1) };
}

/// The operator's switch (`--no-history-backfill`, ZUI_LH_BACKFILL=0): false means no backfill
/// is ever started. The index then serves what it holds; the node says what is not indexed.
pub fn enabled(flag: bool, env: ?[]const u8) bool {
    if (!flag) return false;
    const v = env orelse return true;
    return !(std.mem.eql(u8, v, "0") or std.mem.eql(u8, v, "off") or std.mem.eql(u8, v, "false"));
}

/// What a backfill's staging directory holds on disk.
pub const StagingUse = struct { bytes: u64 = 0, files: u64 = 0 };

/// Bytes and files under the staging directory `dir` (`CURRENT`, `g<gen>/`). Zero when there is
/// none. Reads directory entries and file sizes only.
pub fn stagingUse(io: std.Io, dir: []const u8) StagingUse {
    var u: StagingUse = .{};
    var d = std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch return u;
    defer d.close(io);
    useOf(io, d, &u, 0);
    return u;
}

fn useOf(io: std.Io, d: std.Io.Dir, u: *StagingUse, depth: u8) void {
    var it = d.iterate();
    while (it.next(io) catch return) |e| switch (e.kind) {
        .directory => if (depth < 2) {
            var sub = d.openDir(io, e.name, .{ .iterate = true }) catch continue;
            defer sub.close(io);
            useOf(io, sub, u, depth + 1);
        },
        else => {
            const st = d.statFile(io, e.name, .{ .follow_symlinks = false }) catch continue;
            u.bytes += st.size;
            u.files += 1;
        },
    };
}

pub const Removed = struct {
    bytes: u64 = 0,
    files: u64 = 0,
    /// The directory is gone (or was never there). False: `stop` ended the removal, or `err`.
    done: bool = false,
    err: ?anyerror = null,
};

/// Removes the staging directory `dir`: the state of a build nobody will resume (the index
/// covers the store without it, the backfill is switched off or gave up, or it was adopted).
/// A build that was killed or abandoned leaves up to a whole window of index files there
/// (10 GiB were found beside an 11 GiB index). `CURRENT` goes first, so a removal that does
/// not finish leaves a directory the index opens as empty and clears (`lhist.Index` drops
/// generations `CURRENT` does not name) and that is no floor witness. `stop` is looked at
/// before every file.
pub fn removeStaging(io: std.Io, dir: []const u8, stop: ?*const std.atomic.Value(bool)) Removed {
    var r: Removed = .{};
    if (stop) |x| if (x.load(.acquire)) return r;
    var d = std.Io.Dir.cwd().openDir(io, dir, .{ .iterate = true }) catch |e| {
        if (e == error.FileNotFound) r.done = true else r.err = e;
        return r;
    };
    if (d.statFile(io, "CURRENT", .{ .follow_symlinks = false })) |st| {
        d.deleteFile(io, "CURRENT") catch |e| {
            d.close(io);
            r.err = e;
            return r;
        };
        r.bytes += st.size;
        r.files += 1;
    } else |_| {}
    const emptied = removeIn(io, d, &r, stop, 0);
    d.close(io);
    if (!emptied) return r;
    std.Io.Dir.cwd().deleteDir(io, dir) catch |e| {
        r.err = e;
        return r;
    };
    r.done = true;
    return r;
}

/// True once `d` is empty.
fn removeIn(io: std.Io, d: std.Io.Dir, r: *Removed, stop: ?*const std.atomic.Value(bool), depth: u8) bool {
    // A pass deletes what it reads; a second pass sees what a first one may have skipped.
    var pass: u8 = 0;
    while (pass < 8) : (pass += 1) {
        var seen: u64 = 0;
        var it = d.iterate();
        while (it.next(io) catch |e| {
            r.err = e;
            return false;
        }) |e| {
            if (stop) |x| if (x.load(.acquire)) return false;
            seen += 1;
            if (e.kind == .directory) {
                if (depth >= 2) {
                    r.err = error.Unexpected;
                    return false;
                }
                var sub = d.openDir(io, e.name, .{ .iterate = true }) catch |err| {
                    r.err = err;
                    return false;
                };
                const ok = removeIn(io, sub, r, stop, depth + 1);
                sub.close(io);
                if (!ok) return false;
                d.deleteDir(io, e.name) catch |err| {
                    r.err = err;
                    return false;
                };
            } else {
                const size: u64 = if (d.statFile(io, e.name, .{ .follow_symlinks = false })) |st| st.size else |_| 0;
                d.deleteFile(io, e.name) catch |err| {
                    r.err = err;
                    return false;
                };
                r.bytes += size;
                r.files += 1;
            }
        }
        if (seen == 0) return true;
    }
    r.err = error.Unexpected;
    return false;
}
