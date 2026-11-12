//! Fast start (lane fast-start, DROP-IN-STATUS gap 1): a node over a restored store serves at once
//! and builds its derived indexes in the background, instead of walking the 773M-object live set
//! (twice, one random read per object) before the first request.
//!
//! - **One pass over the restore image.** A store restored from the formal snapshot of epoch E
//!   holds the restored live set as the compact records of segment E (`store.Snapshot.
//!   forEachImageObject`): read front to back by 64 parts on every core at disk bandwidth. The
//!   StateService index's bulk build (`index.lsm.Builder.runFrom`) consumes it, and the same pass
//!   gives the rpc index its package floors (`rpcindex.onRestoredObject`, as a restore does).
//!   Parts the build skips (a resumed build) are walked again for floors only.
//! - **Catch-up beside the follower.** The image is the live set at E's last checkpoint `at`; the
//!   job then replays the stored checkpoints `at + 1 ..` into both indexes from store snapshots
//!   (readers only) while the follower commits new ones, until it is within a few of the tip.
//! - **Handoff on the follower's thread.** `onCommitted(seq)` (after checkpoint `seq` committed,
//!   before `seq + 1` is fed) replays the last few stored checkpoints up to `seq`, makes the rpc
//!   index durable at `seq`, and flips both `ready` flags; from `seq + 1` on the commit feeds run
//!   as before. Until then StateService and the package version selectors answer UNAVAILABLE
//!   ("rpc indexes are being built"); everything else (objects, checkpoints, transactions,
//!   GetPackage by id, streams, Simulate) serves from the store from the first second.
//! - **Resumable.** The state index build keeps its parts in its manifest (lane index-disk); the
//!   rpc index commits no watermark until the handoff, so a restart starts its floors and replay
//!   again. Segment cleaning and retention wait while the job reads the image.
const std = @import("std");
const store = @import("store");
const serve = @import("serve");
const index = @import("index");

fn nowNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub const Image = struct {
    /// Segment holding the restored live set.
    epoch: u64,
    /// Checkpoint that live set is at (the end of `epoch`).
    at: u64,
};

/// The restore image of a store restored from the formal snapshot of `epoch`, if its segment is
/// still there, the store holds every checkpoint after it (the catch-up replays them) and the
/// object floor has not moved past it (the replay reads the versions those checkpoints consumed).
pub fn findImage(snap: *const store.Snapshot, epoch: u64) ?Image {
    _ = snap.segmentBytes(epoch) orelse return null;
    const lo = snap.lowestCheckpoint() orelse return null;
    const rec = snap.checkpoint(lo) orelse return null;
    const at = if (rec.epoch == epoch) lo else if (rec.epoch == epoch + 1 and lo > 0) lo - 1 else return null;
    const avail = snap.lowestAvailable() orelse return null;
    if (avail > at + 1) return null;
    // The object floor too: the replay removes the rows of every version superseded since
    // `at`, and for that it reads the version. Once the object floor is past `at + 1`, versions
    // superseded below it may no longer read (and age-out may turn their records in the image
    // into holes while the job runs), yet the image still lists every record that is
    // physically there: their rows would stay (stale owner rows, balances too high). The
    // live-table scan is used then.
    const st = snap.store;
    if (st.obj_floor.load(.acquire) > at + 1 or st.obj_floor_epoch.load(.acquire) > epoch + 1) return null;
    return .{ .epoch = epoch, .at = at };
}

/// Catch-up or tip, from the age of the newest applied checkpoint (wall clock minus its
/// timestamp): at the tip up to `tip_lag_ms`, in catch-up above `catchup_lag_ms`. The one signal
/// background work paces itself on: this job's image walk (`rate`) and deferred age-out
/// (`Node.noteLag`).
pub const tip_lag_ms: u64 = 3_000;
pub const catchup_lag_ms: u64 = 10_000;

/// Whether a node that was (`was`) or was not behind is behind now, `lag_ms` behind the tip: it
/// falls behind above `catchup_lag_ms` and is back at the tip at `tip_lag_ms` or less.
pub fn behind(was: bool, lag_ms: u64) bool {
    return lag_ms > if (was) tip_lag_ms else catchup_lag_ms;
}

test "catch-up signal: behind above 10 s, at the tip again at 3 s or less" {
    try std.testing.expect(!behind(false, 0));
    try std.testing.expect(!behind(false, 10_000));
    try std.testing.expect(behind(false, 10_001));
    try std.testing.expect(behind(true, 3_001));
    try std.testing.expect(!behind(true, 3_000));
}

pub const Job = struct {
    gpa: std.mem.Allocator,
    st: *store.Store,
    image: ?Image,
    feed: ?*index.feed.Feed = null,
    /// The state index must be built (else only replayed from its watermark).
    build: bool = false,
    rpc: ?*serve.rpcindex.Index = null,
    /// The rpc index needs package floors from the image (it has no watermark).
    floors: bool = false,
    rpc_next: ?u64 = null,

    floored: [index.lsm.build_parts]std.atomic.Value(bool) = @splat(.init(false)),
    floor_lock: std.atomic.Value(u32) = .init(0),
    floor_rows: std.atomic.Value(u64) = .init(0),
    image_objects: std.atomic.Value(u64) = .init(0),
    image_bytes: std.atomic.Value(u64) = .init(0),

    thread: ?std.Thread = null,
    stop: std.atomic.Value(bool) = .init(false),
    /// A stop flag of the caller's (`buildNow` during a restore: the node's signal flag).
    signal: ?*const std.atomic.Value(bool) = null,
    /// Set by the job (its last act) when the indexes are within a few checkpoints of the tip.
    handoff: std.atomic.Value(bool) = .init(false),
    /// Both indexes are live (handoff done) or the job failed.
    done: std.atomic.Value(bool) = .init(false),
    failed: ?anyerror = null,
    /// Timestamp (ms, wall clock) of the last checkpoint the follower committed (node sets it;
    /// 0: unknown). The image walk is paced against it (`pace`).
    tip_ts_ms: std.atomic.Value(u64) = .init(0),
    /// Image read budget, bytes/s (0: none): `max_bps` while the follower is within 3 s of the
    /// network, less as its tip latency grows to 10 s, `catchup_bps` while it catches up.
    max_bps: u64 = 0,
    catchup_bps: u64 = 0,
    pace_lock: std.atomic.Value(u32) = .init(0),
    pace_vt: u64 = 0,
    paced_ns: std.atomic.Value(u64) = .init(0),
    t0_ns: u64 = 0,
    /// No restore image (lane index-fast): the live set comes from a `store.LiveScan` pinned at
    /// the store tip when the job starts (`live_at`), walked part by part beside the follower,
    /// instead of node start blocking on a live-table walk before it serves (the rpc index's
    /// package floors on a store without an image took 25 min before RPC answered).
    scan: ?*store.LiveScan = null,
    live_at: u64 = 0,
    built_ms: u64 = 0,
    ready_ms: u64 = 0,
    replayed: u64 = 0,

    fn stopped(j: *const Job) bool {
        if (j.stop.load(.acquire)) return true;
        if (j.signal) |x| return x.load(.acquire);
        return false;
    }

    pub fn active(j: *const Job) bool {
        return !j.done.load(.acquire);
    }

    fn envMBps(name: [:0]const u8, default: u64) u64 {
        const v = std.c.getenv(name) orelse return default * (1 << 20);
        return (std.fmt.parseInt(u64, std.mem.span(v), 10) catch default) * (1 << 20);
    }

    fn configure(j: *Job) void {
        j.max_bps = envMBps("ZUI_FAST_START_MBPS", 0);
        j.catchup_bps = envMBps("ZUI_FAST_START_CATCHUP_MBPS", 256);
        if (j.feed) |f| f.ix.db.build_stop = j.signal orelse &j.stop;
    }

    /// The build part only, on this thread (a restore, before its `done` marker): the state
    /// index from the image and the rpc package floors, no catch-up.
    pub fn buildNow(j: *Job) !void {
        j.t0_ns = nowNs();
        j.configure();
        try j.buildPhase();
    }

    pub fn start(j: *Job) !void {
        j.t0_ns = nowNs();
        j.configure();
        if (j.feed) |f| f.ix.ready.store(false, .release);
        if (j.rpc) |x| x.ready.store(false, .release);
        j.thread = try std.Thread.spawn(.{ .stack_size = 16 << 20 }, run, .{j});
    }

    /// Node shutdown: stops the job (a build resumes at the next start) and joins it.
    pub fn shutdown(j: *Job) void {
        j.stop.store(true, .release);
        if (j.thread) |t| t.join();
        j.thread = null;
    }

    fn msSince(j: *const Job) u64 {
        return (nowNs() - j.t0_ns) / std.time.ns_per_ms;
    }

    fn run(j: *Job) void {
        j.runInner() catch |e| {
            if (e != error.Stopped) std.log.err("fast start: index job failed: {s}; StateService and package versions stay UNAVAILABLE until a restart", .{@errorName(e)});
            // a replay cut off here has still said what it could not read
            if (j.feed) |f| _ = f.replayEnd(false);
            j.failed = e;
            j.done.store(true, .release);
        };
    }

    fn runInner(j: *Job) !void {
        try j.buildPhase();
        try j.catchUp();
    }

    /// The live-set scan of a job without an image, made once.
    fn liveScan(j: *Job) !*store.LiveScan {
        if (j.scan) |sc| return sc;
        var snap = j.st.snapshot();
        const tip = snap.highestCommitted();
        snap.release();
        const at = tip orelse return error.EmptyStore;
        const t0 = nowNs();
        const sc = try j.gpa.create(store.LiveScan);
        errdefer j.gpa.destroy(sc);
        // versions superseded after `at` must stay readable while the scan follows them
        j.st.agePause(true);
        errdefer j.st.agePause(false);
        sc.* = try store.LiveScan.init(j.gpa, j.st, at + 1);
        j.scan = sc;
        j.live_at = at;
        std.log.info("fast start: no restore image; the live set as of checkpoint {d} from the live table ({d} entries sorted in {d} ms)", .{ at, sc.total(), (nowNs() - t0) / std.time.ns_per_ms });
        // What this build adds to the node's memory, so a small box knows before it finds out:
        // the scan's locations until the rows are read, the build budget until the tables are written.
        if (j.feed) |f| std.log.info("fast start: the build from the live table holds {d} MiB for the scan (8 bytes for each of {d} live-table entries) while it reads, and up to {d} MiB of build budget (ZUI_INDEX_BUILD_MEM_MB) to its end; the scan's part is freed before the sort", .{ (sc.total() * 8) >> 20, sc.total(), f.ix.db.opts.build_mem_bytes >> 20 });
        return sc;
    }

    fn dropScan(j: *Job) void {
        if (j.scan) |sc| {
            sc.deinit();
            j.gpa.destroy(sc);
            j.st.agePause(false);
        }
        j.scan = null;
    }

    fn buildPhase(j: *Job) !void {
        defer j.dropScan();
        if (j.build) {
            const at = if (j.image) |img| img.at else (try j.liveScan()).c1 - 1;
            if (j.image) |img| {
                std.log.info("fast start: building the state index from the restore image (segment {d}, live set at {d}){s}", .{ img.epoch, img.at, if (j.floors) " with rpc package floors" else "" });
            } else std.log.info("fast start: building the state index from the live set at {d}{s}", .{ at, if (j.floors) " with rpc package floors" else "" });
            const rep = try j.feed.?.buildFrom(.{ .ctx = j, .at = at, .walk = walkBuild, .release = releaseSource });
            j.built_ms = j.msSince();
            std.log.info("fast start: state index built from {d} objects ({d} MiB read): {d} rows, {d} MiB on disk in {d} s", .{ rep.objects, j.image_bytes.load(.monotonic) >> 20, rep.entries, rep.bytes >> 20, rep.ms / 1000 });
        }
        if (j.floors) {
            // parts the build did not walk in this process (none built, or a resumed build)
            var left: u32 = 0;
            for (&j.floored) |*f| if (!f.load(.acquire)) {
                left += 1;
            };
            if (left > 0) {
                if (j.image == null) _ = try j.liveScan(); // made once, before the walkers
                try j.floorPass();
            }
            std.log.info("fast start: rpc index package floors: {d} rows", .{j.floor_rows.load(.monotonic)});
        }
        if (j.paced_ns.load(.monotonic) > 0) std.log.info("fast start: image reads paced for {d} s in all", .{j.paced_ns.load(.monotonic) / std.time.ns_per_s});
    }

    fn catchUp(j: *Job) !void {
        // The index's flush thread (no-op when buildFrom started it). A replay-only fast start
        // (an index behind the store by more than 64 checkpoints, no build) never started it
        // before lane catchup-io: frozen memtables were never written, so after `max_frozen` of
        // them applyChanges waited for the flush forever (replay stuck, StateService
        // UNAVAILABLE, the memtables held in memory, the watermark never durable).
        if (j.feed) |f| try f.ix.startBackground();
        if (j.rpc) |x| {
            var snap = j.st.snapshot();
            defer snap.release();
            j.rpc_next = x.replayFrom(&snap) orelse (snap.highestCommitted() orelse 0) + 1;
        }
        // catch up beside the follower, until a round finds only a few new checkpoints (a fresh
        // snapshot per 2,048 so retired store memory is reclaimed as the follower commits)
        var last_log: u64 = 0;
        while (true) {
            if (j.stopped()) return error.Stopped;
            var snap = j.st.snapshot();
            defer snap.release();
            const tip = snap.highestCommitted() orelse break;
            const pos = j.position() orelse tip;
            const to = @min(tip, pos + 2048);
            const n = try j.replayTo(&snap, to);
            if (j.replayed - last_log >= 20_000) {
                last_log = j.replayed;
                std.log.info("fast start: replayed {d} stored checkpoints, at {d} (store tip {d})", .{ j.replayed, to, tip });
            }
            if (to == tip and n <= 8) break;
        }
        j.handoff.store(true, .release);
    }

    /// The lowest checkpoint both indexes have (null: nothing to replay).
    fn position(j: *const Job) ?u64 {
        var p: ?u64 = null;
        if (j.feed) |f| p = f.ix.checkpoint;
        if (j.rpc != null) if (j.rpc_next) |r| {
            p = if (p) |q| @min(q, r -| 1) else r -| 1;
        };
        return p;
    }

    fn replayTo(j: *Job, snap: *store.Snapshot, tip: u64) !u64 {
        var most: u64 = 0;
        if (j.feed) |f| {
            const from = (f.ix.checkpoint orelse return error.NoWatermark) + 1;
            var seq = from;
            while (seq <= tip) {
                if (j.stopped()) return error.Stopped;
                const to = @min(tip, seq + 1023);
                _ = try f.replayRange(snap, seq, to, index.feed.replay_threads);
                seq = to + 1;
            }
            most = tip + 1 -| from;
        }
        if (j.rpc) |x| if (j.rpc_next) |from| if (from <= tip) {
            var seq = from;
            while (seq <= tip) {
                if (j.stopped()) return error.Stopped;
                const to = @min(tip, seq + 4095);
                _ = try x.replayStored(snap, seq, to);
                seq = to + 1;
            }
            j.rpc_next = tip + 1;
            most = @max(most, tip + 1 - from);
        };
        j.replayed += most;
        return most;
    }

    /// The follower's thread, after checkpoint `seq` committed: the last stored checkpoints, then
    /// both indexes go live (fed from `seq + 1` by the commit path).
    pub fn onCommitted(j: *Job, seq: u64) void {
        if (j.done.load(.acquire) or !j.handoff.load(.acquire)) return;
        if (j.thread) |t| t.join();
        j.thread = null;
        var snap = j.st.snapshot();
        defer snap.release();
        const tip = @min(seq, snap.highestCommitted() orelse seq);
        _ = j.replayTo(&snap, tip) catch |e| {
            std.log.err("fast start: handoff replay to {d}: {s}", .{ tip, @errorName(e) });
            if (j.feed) |f| _ = f.replayEnd(false);
            j.failed = e;
            j.done.store(true, .release);
            return;
        };
        // The state index's replay of stored checkpoints ends here (the catch-up rounds and the
        // handoff are one replay): one line with its missing_old, at WARN when it is not 0.
        if (j.feed) |f| _ = f.replayEnd(true);
        if (j.rpc) |x| x.finishSeed(&snap, tip) catch |e| {
            std.log.err("fast start: rpc index at {d}: {s}", .{ tip, @errorName(e) });
            j.failed = e;
            j.done.store(true, .release);
            return;
        };
        if (j.feed) |f| f.ix.ready.store(true, .release);
        j.ready_ms = j.msSince();
        j.done.store(true, .release);
        std.log.info("fast start: indexes live at checkpoint {d}, {d} s after start ({d} checkpoints replayed; state feed missing_old {d}, undecodable {d})", .{ tip, j.ready_ms / 1000, j.replayed, if (j.feed) |f| f.missing_old else 0, if (j.feed) |f| f.undecodable else 0 });
    }

    fn floorOf(j: *Job, id: *const [32]u8, version: u64, bytes: []const u8) !void {
        if (bytes.len == 0 or bytes[0] != 1) return;
        while (j.floor_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer j.floor_lock.store(0, .release);
        try j.rpc.?.onRestoredObject(id, version, bytes);
        _ = j.floor_rows.fetchAdd(1, .monotonic);
    }

    fn wallMs() u64 {
        var ts: std.posix.timespec = undefined;
        _ = std.c.clock_gettime(.REALTIME, &ts);
        return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
    }

    /// The image read budget now (bytes/s, 0: none).
    fn rate(j: *const Job) u64 {
        const ts = j.tip_ts_ms.load(.monotonic);
        if (ts == 0) return j.max_bps;
        const lag = wallMs() -| ts;
        if (lag > catchup_lag_ms) return j.catchup_bps;
        if (lag <= tip_lag_ms) return j.max_bps;
        // 3 to 10 s behind: from the full budget (or 1 GiB/s) down to a quarter of it
        const top = if (j.max_bps != 0) j.max_bps else 1 << 30;
        return @max(j.catchup_bps, top - (top * 3 / 4) * (lag - tip_lag_ms) / (catchup_lag_ms - tip_lag_ms));
    }

    /// Called per read window of the image walk: holds the walker to the budget, and stops.
    fn pace(j: *Job, bytes: u64) !void {
        if (j.stopped()) return error.Stopped;
        const r = j.rate();
        if (r == 0) return;
        while (j.pace_lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        const now = nowNs();
        // no credit for idle time beyond 100 ms
        const t = @max(j.pace_vt, now -| 100 * std.time.ns_per_ms);
        j.pace_vt = t + bytes * std.time.ns_per_s / r;
        j.pace_lock.store(0, .release);
        var cur = nowNs();
        if (t > cur) _ = j.paced_ns.fetchAdd(t - cur, .monotonic);
        while (t > cur) : (cur = nowNs()) {
            if (j.stopped()) return error.Stopped;
            const d = @min(t - cur, 50 * std.time.ns_per_ms);
            var ts: std.c.timespec = .{ .sec = 0, .nsec = @intCast(d) };
            _ = std.c.nanosleep(&ts, &ts);
        }
    }

    const PartCtx = struct {
        j: *Job,
        sink: ?index.lsm.Sink,
        floors: bool,
        n: u64 = 0,
        pub fn onWindow(c: *PartCtx, bytes: u64) anyerror!void {
            try c.j.pace(bytes);
        }
        fn each(c: *PartCtx, id: *const [32]u8, version: u64, bytes: []const u8) anyerror!void {
            c.n += 1;
            if (c.n % 256 == 0 and c.j.stopped()) return error.Stopped;
            if (c.floors) try c.j.floorOf(id, version, bytes);
            if (c.sink) |s| try s.f(s.ctx, id, version, bytes);
        }
    };

    fn walkPart(j: *Job, part: u32, parts: u32, sink: ?index.lsm.Sink, floors: bool) !void {
        const img = j.image orelse return j.walkLivePart(part, parts, sink, floors);
        var snap = j.st.snapshot();
        defer snap.release();
        var c: PartCtx = .{ .j = j, .sink = sink, .floors = floors };
        var stats: store.Snapshot.ImageStats = .{};
        try snap.forEachImageObject(img.epoch, part, parts, &stats, &c, PartCtx.each);
        _ = j.image_objects.fetchAdd(stats.objects, .monotonic);
        _ = j.image_bytes.fetchAdd(stats.bytes, .monotonic);
        if (stats.resyncs != 0) std.log.warn("fast start: image part {d}: {d} resyncs", .{ part, stats.resyncs });
    }

    fn walkLivePart(j: *Job, part: u32, parts: u32, sink: ?index.lsm.Sink, floors: bool) !void {
        const sc = try j.liveScan();
        var c: PartCtx = .{ .j = j, .sink = sink, .floors = floors };
        const Adapter = struct {
            fn each(pc: *PartCtx, o: store.LiveIter.Item) anyerror!void {
                try pc.each(&o.id, o.version, o.bytes);
            }
        };
        try sc.walkPart(part, parts, &c, Adapter.each);
        _ = j.image_objects.fetchAdd(c.n, .monotonic);
    }

    /// `index.lsm.Source.walk` over the image; floors ride along on each part's first walk.
    fn walkBuild(ctx: *anyopaque, part: u32, parts: u32, sink: index.lsm.Sink) anyerror!void {
        const j: *Job = @ptrCast(@alignCast(ctx));
        const floors = j.floors and part < j.floored.len and !j.floored[part].load(.acquire);
        try j.walkPart(part, parts, sink, floors);
        if (floors) j.floored[part].store(true, .release);
    }

    /// `index.lsm.Source.release`: the build reads the live set no more. A live-table scan's
    /// locations (8 bytes a live-table entry, 6 GiB on mainnet) go now, before the sort, not
    /// after it; unless the rpc floors still have parts to walk with the scan (a resumed
    /// build skips the parts it has, and the floors have not seen them).
    fn releaseSource(ctx: *anyopaque) void {
        const j: *Job = @ptrCast(@alignCast(ctx));
        if (j.floors) for (&j.floored) |*f| {
            if (!f.load(.acquire)) return;
        };
        j.dropScan();
    }

    fn floorPass(j: *Job) !void {
        const P = struct {
            j: *Job,
            next: std.atomic.Value(u32) = .init(0),
            err: ?anyerror = null,
            fn work(p: *@This()) void {
                while (true) {
                    const i = p.next.fetchAdd(1, .monotonic);
                    if (i >= index.lsm.build_parts) return;
                    if (p.j.floored[i].load(.acquire)) continue;
                    p.j.walkPart(i, index.lsm.build_parts, null, true) catch |e| {
                        p.err = e;
                        return;
                    };
                    p.j.floored[i].store(true, .release);
                }
            }
        };
        var p: P = .{ .j = j };
        var ts: [16]?std.Thread = @splat(null);
        const nt = @min(std.Thread.getCpuCount() catch 4, ts.len);
        for (0..nt) |i| ts[i] = std.Thread.spawn(.{}, P.work, .{&p}) catch null;
        P.work(&p);
        for (ts[0..nt]) |t| if (t) |x| x.join();
        if (p.err) |e| return e;
    }
};
