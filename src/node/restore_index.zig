//! Derived indexes built during a formal snapshot restore (lane index-fast).
//!
//! Before this lane the restore downloaded and stored the 773M-object live set, built the live
//! table, and only then walked the restored segment once more (`fast_start.Job.buildNow`, about
//! 350 s on a test machine) to emit the StateService rows and the rpc index's package floors. Here both
//! ride along with the download:
//!
//! - **State index rows on the fetch threads.** Each verified partition's objects go through
//!   `index.rowsOf` on the fetch thread that checked it (`snapshot.RestoreOptions.on_partition`),
//!   into that thread's lane of an `index.lsm.Stream`: a sort buffer spilled as a sorted temp table
//!   whenever it fills. Partitions arrive in any order; rows are keyed, so order does not matter.
//! - **Package floors** (rpc index `onRestoredObject`) on the same threads, under one lock (a few
//!   hundred thousand packages among 773M objects).
//! - **Merge beside the live-table build.** Once every partition is in and the root matched
//!   (`after_objects`), a thread spills the lanes and merges the temp tables into the base run
//!   (`Stream.finish`, one merge thread per key range) while the restore builds the live table.
//!   `finish` joins it after the table is persisted, then makes the rpc index durable at the
//!   restored checkpoint. Both indexes are level with the store before the `done` marker, so the
//!   first start serves everything at once.
//!
//! Failure here never costs the restore: `finish` reports it and the caller falls back to the
//! post-restore image walk (`Node.restoreIndexes`), or, failing that, to node start's builds.
//! `ZUI_RESTORE_STREAM=0` turns the stream off (image walk after the restore, as before).
const std = @import("std");
const store = @import("store");
const serve = @import("serve");
const index = @import("index");
const snapshot = @import("snapshot.zig");

const Atomic = std.atomic.Value;

fn nowMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

/// False with ZUI_RESTORE_STREAM=0.
pub fn enabled() bool {
    const v = std.c.getenv("ZUI_RESTORE_STREAM") orelse return true;
    return !std.mem.eql(u8, std.mem.span(v), "0");
}

pub const Options = struct {
    /// `<dir>/state-index` (null: no StateService index, `--indexes` off).
    state_dir: ?[]const u8,
    /// `<dir>/rpc` (null: no rpc index, `--serve` off).
    rpc_dir: ?[]const u8,
    committees: ?serve.rpcindex.CommitteeSource = null,
    lsm: index.lsm.Options = .{},
    /// Sort buffer per fetch thread (0: 64 MiB; ZUI_RESTORE_INDEX_CHUNK_MB).
    chunk: usize = 0,
    /// The node's signal flag: the merge stops when it is set (the restore is retried).
    signal: *const Atomic(bool),
};

pub const Build = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    st: *store.Store,
    opts: Options,
    ix: ?*index.Index = null,
    stream: ?*index.lsm.Stream = null,
    rx: ?*serve.rpcindex.Index = null,
    rx_lock: index.lsm.SpinLock = .{},
    floors: Atomic(u64) = .init(0),
    /// The first feed error (set once, under rx_lock): the stream is abandoned.
    feed_err: ?anyerror = null,
    /// Set to stop the merge (a failed restore, a signal); checked by the merge every 64k keys.
    abort: Atomic(bool) = .init(false),
    thread: ?std.Thread = null,
    merged: Atomic(bool) = .init(false),
    merge_err: ?anyerror = null,
    report: ?index.lsm.Builder.Report = null,
    at: ?u64 = null,
    t0_ms: u64 = 0,
    merge_start_ms: u64 = 0,

    /// Opens the indexes and starts an empty stream. Null when neither index is configured.
    pub fn begin(gpa: std.mem.Allocator, io: std.Io, st: *store.Store, opts: Options) !?*Build {
        if (opts.state_dir == null and opts.rpc_dir == null) return null;
        const b = try gpa.create(Build);
        b.* = .{ .gpa = gpa, .io = io, .st = st, .opts = opts, .t0_ms = nowMs() };
        errdefer b.destroy();
        if (opts.state_dir) |d| {
            b.ix = try index.Index.open(gpa, io, d, opts.lsm);
            var chunk = opts.chunk;
            if (chunk == 0) {
                chunk = 64 << 20;
                if (std.c.getenv("ZUI_RESTORE_INDEX_CHUNK_MB")) |v| chunk = (std.fmt.parseInt(usize, std.mem.span(v), 10) catch 64) << 20;
            }
            b.stream = try index.lsm.Stream.begin(&b.ix.?.db, index.rowsOf, chunk);
            b.ix.?.ready.store(false, .release);
        }
        if (opts.rpc_dir) |d| {
            b.rx = try serve.rpcindex.Index.open(gpa, io, d);
            b.rx.?.committees = opts.committees;
        }
        std.log.info("snapshot: building the derived indexes during the download ({s}{s}{s})", .{
            if (b.ix != null) "state index" else "",
            if (b.ix != null and b.rx != null) ", " else "",
            if (b.rx != null) "rpc package floors" else "",
        });
        return b;
    }

    pub fn partitionHook(b: *Build) snapshot.PartitionHook {
        return .{ .ctx = b, .f = onPartition };
    }

    pub fn doneHook(b: *Build) snapshot.DoneHook {
        return .{ .ctx = b, .f = afterObjects };
    }

    /// Never fails the restore: an index error (temp disk full, say) stops this feed and `finish`
    /// reports it, so the caller builds the indexes the old way after the restore.
    fn onPartition(ctx: *anyopaque, worker: usize, entries: []const snapshot.Entry) anyerror!void {
        const b: *Build = @ptrCast(@alignCast(ctx));
        if (b.feed_err != null) return;
        b.feed(worker, entries) catch |e| {
            b.rx_lock.lock();
            defer b.rx_lock.unlock();
            if (b.feed_err == null) {
                b.feed_err = e;
                std.log.warn("snapshot: index feed during the download: {s}; the indexes are built after the restore instead", .{@errorName(e)});
            }
        };
    }

    fn feed(b: *Build, worker: usize, entries: []const snapshot.Entry) !void {
        for (entries) |e| switch (e) {
            .object => |o| {
                if (b.stream) |s| try s.put(worker, o.bytes);
                // Data::Package is variant 1 (rpcindex.onRestoredObject's own filter, kept here
                // so the lock is taken only for packages)
                if (b.rx) |x| if (o.bytes.len > 0 and o.bytes[0] == 1) {
                    b.rx_lock.lock();
                    defer b.rx_lock.unlock();
                    try x.onRestoredObject(&o.id, o.version, o.bytes);
                    _ = b.floors.fetchAdd(1, .monotonic);
                };
            },
            .wrapped => {},
        };
    }

    /// Every partition is in (no `onPartition` runs any more) and the root matched: the merge
    /// starts beside the live-table build.
    fn afterObjects(ctx: *anyopaque, at: u64) anyerror!void {
        const b: *Build = @ptrCast(@alignCast(ctx));
        b.at = at;
        if (b.feed_err != null) return; // `finish` reports it
        if (b.stream == null) {
            b.merged.store(true, .release);
            return;
        }
        b.merge_start_ms = nowMs();
        const objs = b.stream.?.objects.load(.monotonic);
        std.log.info("snapshot: state index rows of {d} objects in {d} temp tables; merging beside the live-table build", .{ objs, b.stream.?.spills.load(.monotonic) });
        b.thread = std.Thread.spawn(.{ .stack_size = 16 << 20 }, mergeMain, .{b}) catch |e| {
            // no thread: merge in `finish` instead
            std.log.warn("snapshot: index merge thread: {s}; merging after the table", .{@errorName(e)});
            return;
        };
    }

    fn mergeMain(b: *Build) void {
        b.merge();
        b.merged.store(true, .release);
    }

    fn merge(b: *Build) void {
        const s = b.stream.?;
        b.report = s.finish(b.at.?, &b.abort) catch |e| {
            b.merge_err = e;
            return;
        };
    }

    /// After the restore stored the end-of-epoch checkpoint and persisted the table: waits for
    /// the merge (stopping it on a signal) and makes both indexes durable at the restored
    /// checkpoint. An error means the indexes are not built (the caller falls back).
    pub fn finish(b: *Build) !void {
        const at = b.at orelse return error.RestoreNotDone;
        if (b.feed_err) |e| {
            if (b.ix) |ix| ix.db.reset() catch {};
            return e;
        }
        if (b.stream != null) {
            if (b.thread) |t| {
                while (!b.merged.load(.acquire)) {
                    if (b.opts.signal.load(.acquire)) b.abort.store(true, .release);
                    var ts: std.c.timespec = .{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
                    _ = std.c.nanosleep(&ts, &ts);
                }
                t.join();
                b.thread = null;
            } else if (!b.merged.load(.acquire)) {
                b.merge();
                b.merged.store(true, .release);
            }
            if (b.merge_err) |e| {
                if (b.opts.signal.load(.acquire)) return error.Stopped;
                // the fallback builds from scratch, not from these temp tables
                b.ix.?.db.reset() catch {};
                return e;
            }
            const r = b.report.?;
            const ix = b.ix.?;
            ix.checkpoint = ix.db.watermark();
            std.log.info("snapshot: state index merged at checkpoint {d}: {d} objects, {d} rows, {d} MiB on disk, merge {d} s ({d} s after the root matched)", .{ at, r.objects, r.entries, r.bytes >> 20, r.ms / 1000, (nowMs() - b.merge_start_ms) / 1000 });
        }
        if (b.rx) |x| {
            var snap = b.st.snapshot();
            defer snap.release();
            try x.finishSeed(&snap, at);
            std.log.info("snapshot: rpc index at checkpoint {d} ({d} package floors)", .{ at, b.floors.load(.monotonic) });
        }
    }

    /// Stops and joins the merge, closes the indexes (a finished build is durable; an
    /// unfinished one resets at the next build).
    pub fn destroy(b: *Build) void {
        b.abort.store(true, .release);
        if (b.thread) |t| t.join();
        b.thread = null;
        if (b.stream) |s| s.destroy();
        if (b.ix) |x| {
            x.deinit();
            b.gpa.destroy(x);
        }
        if (b.rx) |x| x.deinit();
        b.gpa.destroy(b);
    }
};
