//! Feeding the StateService indexes (CONTRACTS 6.8 derived-index feeds):
//!
//! - restore: `onRestoredObject` has the `snapshot.RestoreOptions.on_object` signature
//!   (`f(ctx, id, version, bytes) anyerror!void`, ctx = *Feed); every live object of epoch E goes
//!   through `Index.insert`.
//! - startup over an existing store: `rebuild` walks the store's live set (`Snapshot.forEachLive`).
//! - commit path, two steps so the index trails the object store as sui-node's does (its
//!   checkpoint executor commits the outputs, then the rpc-store indexer sees the checkpoint:
//!   sui-core checkpoint_executor/mod.rs `execute_checkpoint`, `commit_transaction_outputs` before
//!   `enqueue_to_subscription_service`):
//!   - `prepare(seq, blob)` from the follower's `on_checkpoint` (before the batch commits) turns
//!     each transaction's effects into index changes, in transaction order: for every changed
//!     object, old = the input version (from the checkpoint's object set, else the store, which
//!     still holds it before the commit), new = the output version written at the lamport version.
//!     Packages and accumulator writes do not touch the indexes. The changes are copied into the
//!     Feed's own arena and held, not applied.
//!   - `publish(seq)` from the follower's `on_committed` (after the store commit) applies them.
//!   So a StateService reader never sees index rows of checkpoint N while the store is at N-1:
//!   every row's (id, version) is readable (the store serves superseded versions from its version
//!   index), and the request snapshot, taken under the index lock, is at least as new as the index.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const index = @import("root.zig");

/// Readers of a stored-checkpoint replay (`Feed.replayRange`): reads in flight against the store.
pub var replay_threads: u32 = 16;

/// A stored-checkpoint replay logs its running counts this often (`Feed.replayProgress`), so one
/// that is cut off (a stop, a kill, a failed job) has still said how far it got and how many old
/// versions it could not read.
pub var replay_log_ms: u64 = 5_000;

/// What one stored-checkpoint replay did (`Feed.replay`, `Feed.replayRange`: the old version of
/// every changed object is read from the store), from its first checkpoint to `Feed.replayEnd`.
pub const ReplayRun = struct {
    checkpoints: u64 = 0,
    first: u64 = 0,
    last: u64 = 0,
    /// Old versions the store did not give: their rows were not removed from the index.
    missing_old: u64 = 0,
    undecodable: u64 = 0,
    last_log_ms: u64 = 0,
};

/// The operator's check for an index a replay may have left stale rows in.
pub const check_hint = "deepwave-tool verify-index --dir DIR --scratch DIR (node stopped)";

pub const Feed = struct {
    gpa: Allocator,
    ix: *index.Index,
    st: *store.Store,
    cidx: ?*types.CheckpointIndex = null,
    /// Checkpoints applied, objects restored, effects that failed to decode (skipped).
    checkpoints: u64 = 0,
    restored: u64 = 0,
    undecodable: u64 = 0,
    missing_old: u64 = 0,
    /// Commits published with no prepared changes for them (the index skipped that checkpoint).
    unprepared: u64 = 0,
    /// Stored checkpoints replayed since the process started, and what those replays could not
    /// read or decode (`missing_old` and `undecodable` above also count the commit path).
    replayed: u64 = 0,
    replay_missing_old: u64 = 0,
    replay_undecodable: u64 = 0,
    /// The replay in progress (`replayEnd` logs it and starts the next one from zero).
    run: ReplayRun = .{},
    /// Changes of the checkpoint between `prepare` and `publish`, in `pending_arena`.
    pending: ?struct { seq: u64, changes: []const index.Index.Change } = null,
    pending_arena: std.heap.ArenaAllocator,

    pub fn init(gpa: Allocator, ix: *index.Index, st: *store.Store) Feed {
        return .{ .gpa = gpa, .ix = ix, .st = st, .pending_arena = .init(gpa) };
    }

    pub fn deinit(f: *Feed) void {
        f.pending_arena.deinit();
        if (f.cidx) |c| {
            c.deinit(f.gpa);
            f.gpa.destroy(c);
        }
    }

    /// The feed's counters for another thread (metrics): the writer adds with `bump`.
    pub const Counters = struct { checkpoints: u64, missing_old: u64, undecodable: u64, unprepared: u64, replayed: u64, replay_missing_old: u64, replay_undecodable: u64 };

    pub fn counters(f: *const Feed) Counters {
        return .{
            .checkpoints = @atomicLoad(u64, &f.checkpoints, .monotonic),
            .missing_old = @atomicLoad(u64, &f.missing_old, .monotonic),
            .undecodable = @atomicLoad(u64, &f.undecodable, .monotonic),
            .unprepared = @atomicLoad(u64, &f.unprepared, .monotonic),
            .replayed = @atomicLoad(u64, &f.replayed, .monotonic),
            .replay_missing_old = @atomicLoad(u64, &f.replay_missing_old, .monotonic),
            .replay_undecodable = @atomicLoad(u64, &f.replay_undecodable, .monotonic),
        };
    }

    fn bump(p: *u64, n: u64) void {
        if (n != 0) _ = @atomicRmw(u64, p, .Add, n, .monotonic);
    }

    /// One stored checkpoint was replayed with `stats`.
    fn noteReplayed(f: *Feed, seq: u64, stats: Stats) void {
        bump(&f.undecodable, stats.undecodable);
        bump(&f.missing_old, stats.missing_old);
        bump(&f.checkpoints, 1);
        bump(&f.replayed, 1);
        bump(&f.replay_missing_old, stats.missing_old);
        bump(&f.replay_undecodable, stats.undecodable);
        if (f.run.checkpoints == 0) {
            f.run.first = seq;
            f.run.last_log_ms = nowMs();
        }
        f.run.checkpoints += 1;
        f.run.last = seq;
        f.run.missing_old += stats.missing_old;
        f.run.undecodable += stats.undecodable;
    }

    /// The running counts of the replay in progress, at most once per `replay_log_ms`.
    fn replayProgress(f: *Feed) void {
        const now = nowMs();
        if (now -| f.run.last_log_ms < replay_log_ms) return;
        f.run.last_log_ms = now;
        const r = f.run;
        if (r.missing_old != 0) {
            std.log.warn("state index: replaying stored checkpoints: {d} done ({d}..{d}), missing_old {d}, undecodable {d}", .{ r.checkpoints, r.first, r.last, r.missing_old, r.undecodable });
        } else std.log.info("state index: replaying stored checkpoints: {d} done ({d}..{d}), missing_old {d}, undecodable {d}", .{ r.checkpoints, r.first, r.last, r.missing_old, r.undecodable });
    }

    /// The end of a stored-checkpoint replay (`complete`: it reached its target; false: a stop
    /// or an error cut it off). Logs one line with what it did, at WARN when an old version
    /// could not be read, and returns it; nothing when no stored checkpoint was replayed. Called
    /// by whoever drove the replay: `start` (the inline replay) and the fast-start job.
    pub fn replayEnd(f: *Feed, complete: bool) ?ReplayRun {
        const r = f.run;
        f.run = .{};
        if (r.checkpoints == 0) return null;
        const what: []const u8 = if (complete) "replayed" else "replay cut off after";
        if (r.missing_old != 0) {
            std.log.warn("state index: {s} {d} stored checkpoints ({d}..{d}): missing_old {d}, undecodable {d}. The state index may hold stale rows: {d} old object versions could not be read from the store, so their rows were not removed. Check it with {s}", .{ what, r.checkpoints, r.first, r.last, r.missing_old, r.undecodable, r.missing_old, check_hint });
        } else std.log.info("state index: {s} {d} stored checkpoints ({d}..{d}): missing_old {d}, undecodable {d}", .{ what, r.checkpoints, r.first, r.last, r.missing_old, r.undecodable });
        return r;
    }

    /// The restore's per-object hook (CONTRACTS 6.8 `on_object`). ctx is the *Feed.
    pub fn onRestoredObject(ctx: *anyopaque, id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
        _ = id;
        _ = version;
        const f: *Feed = @ptrCast(@alignCast(ctx));
        f.ix.lock.lock();
        defer f.ix.lock.unlock();
        try f.ix.insert(bytes);
        f.restored += 1;
    }

    /// Builds the indexes from the store's live set (a restart over an existing store; in-memory
    /// index).
    pub fn rebuild(f: *Feed) !void {
        var snap = f.st.snapshot();
        defer snap.release();
        f.ix.lock.lock();
        defer f.ix.lock.unlock();
        try snap.forEachLive(f, struct {
            fn each(fd: *Feed, _: *const [32]u8, _: u64, bytes: []const u8) anyerror!void {
                try fd.ix.insert(bytes);
                fd.restored += 1;
            }
        }.each);
        f.ix.setCheckpoint(snap.highestCommitted());
    }

    pub const StartReport = struct {
        built: bool = false,
        build: ?index.lsm.Builder.Report = null,
        /// Why the index was built (null: replayed from its watermark).
        reason: ?[]const u8 = null,
        watermark: ?u64 = null,
        tip: ?u64 = null,
        replayed: u64 = 0,
        ms: u64 = 0,
    };

    /// Node start with an on-disk index (before the follower runs, before readers exist): builds
    /// the base from the live set when there is no usable index (none yet, an unfinished build,
    /// or a watermark outside the store's stored checkpoints), else replays the stored
    /// checkpoints after its watermark; then starts the background flush thread.
    pub fn start(f: *Feed) !StartReport {
        const ix = f.ix;
        if (!ix.db.onDisk()) {
            try f.rebuild();
            return .{ .built = true, .reason = "memory" };
        }
        const t0 = nowMs();
        var snap = f.st.snapshot();
        defer snap.release();
        var rep: StartReport = .{ .tip = snap.highestCommitted(), .watermark = ix.db.watermark() };
        const tip = rep.tip;
        const wm = rep.watermark;
        const lo = snap.lowestAvailable() orelse std.math.maxInt(u64);
        if (ix.db.buildPending() != null) {
            rep.reason = "resume build";
        } else if (wm == null) {
            rep.reason = "no index";
        } else if (tip == null or wm.? > tip.?) {
            rep.reason = "index ahead of the store";
        } else if (wm.? + 1 < lo and wm.? < tip.?) {
            rep.reason = "watermark below the stored checkpoints";
        }
        if (rep.reason != null) {
            std.log.info("state index: building from the live set ({s}; watermark {?d}, store tip {?d})", .{ rep.reason.?, wm, tip });
            rep.build = try index.lsm.Builder.run(&ix.db, &snap, index.rowsOf);
            rep.built = true;
            ix.setCheckpoint(ix.db.watermark());
            f.restored += rep.build.?.objects;
        }
        try ix.startBackground();
        if (tip) |t| if (ix.db.watermark()) |w| if (w < t) {
            var seq = w + 1;
            while (seq <= t) {
                const to = @min(t, seq + 9_999);
                // a failed range has still said how far the replay got
                rep.replayed += f.replayRange(&snap, seq, to, replay_threads) catch |e| {
                    _ = f.replayEnd(false);
                    return e;
                };
                seq = to + 1;
            }
            _ = f.replayEnd(true);
        };
        rep.ms = nowMs() - t0;
        return rep;
    }

    /// Why node start must build the on-disk index from a live set (null: a replay from its
    /// watermark brings it level). Same rules as `start`.
    pub fn buildReason(f: *Feed, snap: *const store.Snapshot) ?[]const u8 {
        const ix = f.ix;
        if (!ix.db.onDisk()) return "memory";
        const tip = snap.highestCommitted();
        const wm = ix.db.watermark();
        const lo = snap.lowestAvailable() orelse std.math.maxInt(u64);
        if (ix.db.buildPending() != null) return "resume build";
        if (wm == null) return "no index";
        if (tip == null or wm.? > tip.?) return "index ahead of the store";
        if (wm.? + 1 < lo and wm.? < tip.?) return "watermark below the stored checkpoints";
        return null;
    }

    /// Fast start (lane fast-start), on a background thread while the follower runs and with
    /// `ix.ready` false (no reader, no commit feed): builds the base run from `src` (the restore
    /// image, watermark `src.at`), then starts the flush thread. `replayTo` and the node's
    /// handoff bring it to the tip.
    pub fn buildFrom(f: *Feed, src: index.lsm.Source) !index.lsm.Builder.Report {
        const rep = try index.lsm.Builder.runFrom(&f.ix.db, src, index.rowsOf);
        f.ix.setCheckpoint(f.ix.db.watermark());
        f.restored += rep.objects;
        try f.ix.startBackground();
        return rep;
    }

    /// Replays the stored checkpoints after the index's checkpoint up to `to` (inclusive); the
    /// number replayed. Readers of `snap` only, so it runs beside the follower.
    pub fn replayTo(f: *Feed, snap: *const store.Snapshot, to: u64) !u64 {
        var n: u64 = 0;
        var seq = (f.ix.checkpoint orelse return error.NoWatermark) + 1;
        while (seq <= to) : (seq += 1) {
            try f.replay(snap, seq);
            n += 1;
        }
        return n;
    }

    /// Replays stored checkpoints `from..to` (inclusive) with `threads` readers (lane catchup-io).
    /// A stored checkpoint's changes come from point reads of the store (every changed object's
    /// input and output version: the live table, then the version index runs), one blocking
    /// random read after another on a restored store whose table and runs are not in memory:
    /// under 8 cp/s at queue depth 1. Here up to `batch` checkpoints have their changes computed
    /// at once, one checkpoint per reader, so `threads` reads are in flight; then the batch is
    /// applied in checkpoint order exactly as `replay` would. The snapshot is quiesced after each
    /// batch (no slice of it is held), so chunks it read are not pinned. Returns the number
    /// replayed.
    pub fn replayRange(f: *Feed, snap: *store.Snapshot, from: u64, to: u64, threads_in: u32) !u64 {
        if (to < from) return 0;
        const threads: u32 = std.math.clamp(threads_in, 1, 64);
        if (threads == 1) {
            var seq = from;
            while (seq <= to) : (seq += 1) {
                try f.replay(snap, seq);
                snap.quiesce();
            }
            return to - from + 1;
        }
        const batch: u64 = @min(@as(u64, threads) * 4, 256);
        const slots = try f.gpa.alloc(ReplaySlot, batch);
        defer f.gpa.free(slots);
        for (slots) |*sl| sl.* = .{ .arena = .init(f.gpa) };
        defer for (slots) |*sl| sl.arena.deinit();
        const workers = try f.gpa.alloc(std.Thread, threads - 1);
        defer f.gpa.free(workers);
        var seq = from;
        while (seq <= to) {
            const n = @min(batch, to - seq + 1);
            var job: ReplayJob = .{ .snap = snap, .first = seq, .slots = slots[0..n] };
            var spawned: usize = 0;
            for (workers[0..@min(workers.len, n -| 1)]) |*w| {
                w.* = std.Thread.spawn(.{ .stack_size = 1 << 20 }, ReplayJob.run, .{&job}) catch break;
                spawned += 1;
            }
            job.run();
            for (workers[0..spawned]) |w| w.join();
            for (slots[0..n], 0..) |*sl, i| {
                if (sl.err) |e| return e;
                try f.ix.applyChanges(seq + i, sl.changes);
                f.noteReplayed(seq + i, sl.stats);
            }
            for (slots[0..n]) |*sl| _ = sl.arena.reset(.{ .retain_with_limit = 1 << 20 });
            snap.quiesce();
            seq += n;
            f.replayProgress();
        }
        return to - from + 1;
    }

    /// Applies stored checkpoint `seq` (the store holds it and its object versions).
    pub fn replay(f: *Feed, snap: *const store.Snapshot, seq: u64) !void {
        var tmp = std.heap.ArenaAllocator.init(f.gpa);
        defer tmp.deinit();
        var stats: Stats = .{};
        const changes = try changesFromStore(tmp.allocator(), snap, seq, &stats);
        try f.ix.applyChanges(seq, changes);
        f.noteReplayed(seq, stats);
        f.replayProgress();
    }

    /// Step 1 of one checkpoint (`CheckpointData` blob), before its batch commits: computes the
    /// index changes (old versions missing from the checkpoint come from the store, still at N-1)
    /// and holds them for `publish`. A previous prepare that was never published (its commit
    /// failed) is dropped.
    pub fn prepare(f: *Feed, seq: u64, blob: []const u8) !void {
        f.dropPending();
        if (f.cidx == null) {
            const c = try f.gpa.create(types.CheckpointIndex);
            errdefer f.gpa.destroy(c);
            c.* = try types.CheckpointIndex.init(f.gpa);
            f.cidx = c;
        }
        const ci = f.cidx.?;
        try types.index.indexCheckpointData(blob, ci);
        var tmp_state = std.heap.ArenaAllocator.init(f.gpa);
        defer tmp_state.deinit();
        var snap = f.st.snapshot();
        defer snap.release();
        var stats: Stats = .{};
        const changes = try changesOf(tmp_state.allocator(), ci, blob, &snap, &stats);
        bump(&f.undecodable, stats.undecodable);
        bump(&f.missing_old, stats.missing_old);
        try f.stage(seq, changes);
    }

    /// Holds `changes` (copied: they may point into the checkpoint blob or the store) for
    /// `publish(seq)`.
    pub fn stage(f: *Feed, seq: u64, changes: []const index.Index.Change) !void {
        f.dropPending();
        const a = f.pending_arena.allocator();
        const own = try a.alloc(index.Index.Change, changes.len);
        for (changes, own) |c, *o| o.* = .{
            .old = if (c.old) |x| try a.dupe(u8, x) else null,
            .new = if (c.new) |x| try a.dupe(u8, x) else null,
        };
        f.pending = .{ .seq = seq, .changes = own };
    }

    /// Step 2, after checkpoint `seq` committed to the store: the index moves to `seq`. A publish
    /// with nothing prepared for `seq` (prepare failed) leaves the index where it was and counts it.
    pub fn publish(f: *Feed, seq: u64) !void {
        const p = f.pending orelse {
            bump(&f.unprepared, 1);
            return;
        };
        defer f.dropPending();
        if (p.seq != seq) {
            bump(&f.unprepared, 1);
            return;
        }
        try f.ix.applyChanges(seq, p.changes);
        bump(&f.checkpoints, 1);
    }

    fn dropPending(f: *Feed) void {
        f.pending = null;
        _ = f.pending_arena.reset(.retain_capacity);
    }
};

pub const Stats = struct { undecodable: u64 = 0, missing_old: u64 = 0 };

const ReplaySlot = struct {
    arena: std.heap.ArenaAllocator,
    changes: []const index.Index.Change = &.{},
    stats: Stats = .{},
    err: ?anyerror = null,
};

/// One batch of `Feed.replayRange`: readers take checkpoints in order through `next`.
const ReplayJob = struct {
    snap: *const store.Snapshot,
    first: u64,
    slots: []ReplaySlot,
    next: std.atomic.Value(usize) = .init(0),

    fn run(j: *ReplayJob) void {
        while (true) {
            const i = j.next.fetchAdd(1, .monotonic);
            if (i >= j.slots.len) return;
            const sl = &j.slots[i];
            sl.stats = .{};
            sl.err = null;
            sl.changes = changesFromStore(sl.arena.allocator(), j.snap, j.first + i, &sl.stats) catch |e| blk: {
                sl.err = e;
                break :blk &.{};
            };
        }
    }
};

/// The index changes of one indexed checkpoint, in transaction order. Old versions missing from the
/// checkpoint's object set come from `snap` (the store before this checkpoint commits), if given.
pub fn changesOf(a: Allocator, ci: *const types.CheckpointIndex, blob: []const u8, snap: ?*const store.Snapshot, stats: *Stats) ![]index.Index.Change {
    // (id, version) -> bytes over the checkpoint's object set
    var objs: std.AutoHashMapUnmanaged(Key, []const u8) = .empty;
    try objs.ensureTotalCapacity(a, ci.obj_total);
    for (ci.objs[0..ci.obj_total]) |r| {
        const raw = r.slice(blob);
        const k = objectKey(raw) catch continue;
        objs.putAssumeCapacity(k, raw);
    }
    var changes: std.ArrayList(index.Index.Change) = .empty;
    for (0..ci.tx_count) |i| {
        const t = ci.txAt(i);
        const eff = bcs.decode(types.TransactionEffects, a, t.effects.slice(blob)) catch {
            stats.undecodable += 1;
            continue;
        };
        const v2 = switch (eff) {
            .V2 => |x| x,
            .V1 => {
                stats.undecodable += 1;
                continue;
            },
        };
        const lamport = v2.lamport_version.@"0";
        for (v2.changed_objects) |co| {
            const id: [32]u8 = co[0].@"0".@"0";
            const ch = co[1];
            var old: ?[]const u8 = null;
            switch (ch.input_state) {
                .NotExist => {},
                .Exist => |e| {
                    const ver = e[0][0].@"0";
                    old = objs.get(.{ .id = id, .version = ver }) orelse if (snap) |sp| sp.objectAt(&id, ver) else null;
                    if (old == null) stats.missing_old += 1;
                },
            }
            const new: ?[]const u8 = switch (ch.output_state) {
                .ObjectWrite => objs.get(.{ .id = id, .version = lamport }),
                else => null,
            };
            if (old == null and new == null) continue;
            try changes.append(a, .{ .old = old, .new = new });
        }
    }
    return changes.items;
}

/// The index changes of stored checkpoint `seq`, in transaction order, from the store's records:
/// old = the input version, new = the output version at the lamport version (both in the store's
/// history window). A restart replays the checkpoints after the index watermark with it.
pub fn changesFromStore(a: Allocator, snap: *const store.Snapshot, seq: u64, stats: *Stats) ![]index.Index.Change {
    const rec = (try snap.checkpointChecked(seq)) orelse return error.CheckpointNotStored;
    const contents = try bcs.decode(types.CheckpointContents, a, rec.contents);
    const n = switch (contents) {
        .V1 => |v| v.transactions.len,
        .V2 => |v| v.transactions.len,
    };
    var changes: std.ArrayList(index.Index.Change) = .empty;
    for (0..n) |i| {
        const dg: *const [32]u8 = switch (contents) {
            .V1 => |v| &v.transactions[i].transaction.@"0".@"0",
            .V2 => |v| &v.transactions[i].digest.transaction.@"0".@"0",
        };
        const t = (try snap.transactionChecked(dg)) orelse return error.TransactionNotStored;
        const eff = bcs.decode(types.TransactionEffects, a, t.effects) catch {
            stats.undecodable += 1;
            continue;
        };
        const v2 = switch (eff) {
            .V2 => |x| x,
            .V1 => {
                stats.undecodable += 1;
                continue;
            },
        };
        const lamport = v2.lamport_version.@"0";
        for (v2.changed_objects) |co| {
            const id: [32]u8 = co[0].@"0".@"0";
            const ch = co[1];
            var old: ?[]const u8 = null;
            switch (ch.input_state) {
                .NotExist => {},
                .Exist => |e| {
                    old = snap.objectAt(&id, e[0][0].@"0");
                    if (old == null) stats.missing_old += 1;
                },
            }
            const new: ?[]const u8 = switch (ch.output_state) {
                .ObjectWrite => snap.objectAt(&id, lamport),
                else => null,
            };
            if (old == null and new == null) continue;
            try changes.append(a, .{ .old = old, .new = new });
        }
    }
    return changes.items;
}

fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

const Key = struct { id: [32]u8, version: u64 };

/// Id and version of BCS(Object) without decoding the contents.
fn objectKey(raw: []const u8) !Key {
    var r = bcs.Reader.init(raw);
    switch (try r.uleb32()) {
        0 => {
            try bcs.skip(types.MoveObjectType, &r);
            _ = try r.int(u8); // has_public_transfer
            const ver = try r.int(u64);
            const n = try r.length();
            if (n < 32) return error.InvalidValue;
            return .{ .id = (try r.bytes(32))[0..32].*, .version = ver };
        },
        1 => {
            const id = (try r.bytes(32))[0..32].*;
            return .{ .id = id, .version = try r.int(u64) };
        },
        else => return error.InvalidValue,
    }
}

test "a stored-checkpoint replay keeps its counts: the run for its log line, the totals for the metrics" {
    const testing = std.testing;
    var f: Feed = .{ .gpa = testing.allocator, .ix = undefined, .st = undefined, .pending_arena = .init(testing.allocator) };
    defer f.pending_arena.deinit();
    // (the WARN line below is expected: kept out of the test output)
    const level = testing.log_level;
    testing.log_level = .err;
    defer testing.log_level = level;
    // nothing replayed: no line
    try testing.expect(f.replayEnd(true) == null);
    f.noteReplayed(100, .{});
    f.noteReplayed(101, .{ .missing_old = 2, .undecodable = 1 });
    f.noteReplayed(102, .{ .missing_old = 1 });
    // within `replay_log_ms` of the first checkpoint: no progress line, the run is untouched
    f.replayProgress();
    try testing.expectEqual(@as(u64, 3), f.run.checkpoints);
    // cut off: the line (WARN, old versions were missing) and what it said
    const r = f.replayEnd(false).?;
    try testing.expectEqual(@as(u64, 3), r.checkpoints);
    try testing.expectEqual(@as(u64, 100), r.first);
    try testing.expectEqual(@as(u64, 102), r.last);
    try testing.expectEqual(@as(u64, 3), r.missing_old);
    try testing.expectEqual(@as(u64, 1), r.undecodable);
    // the next replay starts from zero; the totals go on
    try testing.expect(f.replayEnd(true) == null);
    f.noteReplayed(103, .{});
    const r2 = f.replayEnd(true).?;
    try testing.expectEqual(@as(u64, 1), r2.checkpoints);
    try testing.expectEqual(@as(u64, 103), r2.first);
    try testing.expectEqual(@as(u64, 0), r2.missing_old);
    const c = f.counters();
    try testing.expectEqual(@as(u64, 4), c.replayed);
    try testing.expectEqual(@as(u64, 4), c.checkpoints);
    try testing.expectEqual(@as(u64, 3), c.replay_missing_old);
    try testing.expectEqual(@as(u64, 3), c.missing_old);
    try testing.expectEqual(@as(u64, 1), c.replay_undecodable);
    try testing.expectEqual(@as(u64, 1), c.undecodable);
    try testing.expectEqual(@as(u64, 0), c.unprepared);
}
