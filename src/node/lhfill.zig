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

pub const Error = error{ CheckpointNotStored, TransactionNotStored };

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
    };
    pub const default_ring = 64;
    /// Ready once the build is this close to the store's committed tip (the commit path indexes
    /// the rest at the swap: about 1 ms each). While the store moves faster than the serial tail,
    /// parallel rounds close the gap instead.
    const near_tip = 64;

    pub const Options = struct {
        workers: usize = 4,
        /// Staging directory for a resumable build (null: in memory only).
        staging: ?[]const u8 = null,
        save_every_ns: u64 = 300 * std.time.ns_per_s,
        /// Tests: stop after this many saves (a crash at the watermark).
        stop_after_saves: ?u32 = null,
        /// Ring slots (tests use a small one to make slot reuse frequent).
        ring: usize = default_ring,
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
        b.* = .{ .gpa = gpa, .io = io, .st = st, .lo = from, .from = begin, .to = to, .out = out, .workers = @max(1, o.workers), .slots = slots, .staged = o.staging != null, .resumed_at = resumed, .save_every_ns = o.save_every_ns, .stop_after_saves = o.stop_after_saves };
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

    fn stopped(b: *const Backfill) bool {
        return b.cancel.load(.acquire) or b.status() == .failed;
    }

    fn pause(b: *const Backfill) void {
        b.io.sleep(.fromMicroseconds(50), .awake) catch {};
    }

    fn worker(b: *Backfill) void {
        while (!b.stopped()) {
            const seq = b.next.fetchAdd(1, .monotonic);
            if (seq > b.to) return;
            const slot = &b.slots[@intCast((seq - b.from) % b.slots.len)];
            while (seq >= b.consumed.load(.acquire) + b.slots.len) {
                if (b.stopped()) return;
                b.pause();
            }
            std.debug.assert(slot.state.load(.acquire) == 0);
            _ = slot.arena.reset(.retain_capacity);
            var snap = b.st.snapshot();
            defer snap.release();
            const cp = load(slot.arena.allocator(), &snap, seq, &b.counters) catch |e| return b.fail(e);
            slot.data = cp orelse return b.fail(error.CheckpointNotStored);
            slot.state.store(seq + 1, .release);
        }
    }

    fn main(b: *Backfill) void {
        b.build() catch |e| return b.fail(e);
        if (b.stopped()) return;
        b.build_ns = nowNs() - b.started_ns;
        b.status_.store(.ready, .release);
    }

    /// Saves the staging state (the durable watermark); a failed save only costs progress.
    fn save(b: *Backfill) void {
        if (!b.staged) return;
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
        for (b.slots) |*s| s.state.store(0, .release);
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
            _ = b.counters.checkpoints.fetchAdd(1, .monotonic);
            _ = b.counters.txs.fetchAdd(slot.data.transactions.len, .monotonic);
            slot.state.store(0, .release);
            b.consumed.store(seq + 1, .release);
            if (b.staged and nowNs() -| b.last_save_ns >= b.save_every_ns) {
                b.save();
                if (b.stopped()) return;
            }
        }
    }

    fn build(b: *Backfill) !void {
        try b.round(b.from, b.to);
        if (b.stopped()) return;
        // Parallel rounds up to the store's moving tip until close to it; the commit path takes
        // the last few at the swap.
        while (!b.stopped()) {
            const tip = b.st.committed() orelse break;
            const hi = b.out.indexedHi() orelse b.lo -| 1;
            if (tip <= hi + near_tip) break;
            try b.round(hi + 1, tip);
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
        b.out.detachDir();
        return b.out;
    }

    /// Stops the build (if running) and frees everything.
    pub fn destroy(b: *Backfill) void {
        b.cancel.store(true, .release);
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
