//! sui-node 1.83.1's checkpoint executor, state sync and pruner families (lane ops-metrics),
//! same names, types, help texts and buckets:
//!
//!   checkpoint executor (sui-core checkpoint_executor/metrics.rs)
//!     checkpoint_exec_sync_tps               gauge: tps estimate (EMA 0.9/0.1 per checkpoint)
//!     checkpoint_exec_epoch                  gauge
//!     checkpoint_contents_age                histogram LATENCY_SEC_BUCKETS, when a checkpoint is
//!                                            taken for execution (deepwave: the ordered stage)
//!     checkpoint_contents_age_ms             Mysten histogram (pct gauge + _sum + _count)
//!     last_executed_checkpoint_age           histogram LATENCY_SEC_BUCKETS, at commit
//!     last_executed_checkpoint_age_ms        Mysten histogram
//!     checkpoint_exec_errors, checkpoint_exec_inflight, checkpoint_exec_latency,
//!     checkpoint_prepare_latency, checkpoint_transaction_count,
//!     checkpoint_executor_validator_path, checkpoint_executor_validator_sync_fallback_path
//!                                            registered and never updated by a 1.83.1 full
//!                                            node: zeros here too (dashboards see the series)
//!   state sync (sui-network state_sync/metrics.rs)
//!     checkpoints_synced_from_archive        counter: checkpoints whose data came first from
//!                                            the archive (deepwave: the bucket / S3 source)
//!     checkpoint_summary_age                 histogram LATENCY_SEC_BUCKETS: age when the
//!                                            summary arrived (fetcher arrival time)
//!     checkpoint_summary_age_ms              Mysten histogram
//!     state_sync_peers_reported_for_failure  counter (deepwave reports no peers: 0)
//!   pruner (sui-core authority_store_pruner.rs, beside ops.zig's last_pruned_checkpoint)
//!     num_pruned_objects, num_pruned_tombstones            counters
//!     last_pruned_effects_checkpoint                       gauge
//!     num_epochs_to_retain_for_objects, _for_checkpoints   gauges
//!
//! Hot path: `taken` and `executed` run once per checkpoint on the ordered stage: a few atomic
//! adds and stores, no allocation.
const std = @import("std");
const prom = @import("core").prom;
const Atomic = std.atomic.Value;
const Writer = std.Io.Writer;

const LatHist = prom.Histogram(&prom.buckets.latency_sec, prom.ns);

pub const Checkpoints = struct {
    epoch: Atomic(u64) = .init(0),
    contents_age: LatHist = .{},
    contents_age_ms: prom.MystenHistogram = .{},
    executed_age: LatHist = .{},
    executed_age_ms: prom.MystenHistogram = .{},
    summary_age: LatHist = .{},
    summary_age_ms: prom.MystenHistogram = .{},
    from_archive: Atomic(u64) = .init(0),
    /// TPSEstimator (checkpoint_executor/utils.rs): one writer (the commit callback).
    tps_bits: Atomic(u64) = .init(0),
    tps_last_ns: u64 = 0,
    tps_last_count: u64 = 0,
    /// Checkpoints taken but not committed yet: (seq, timestamp ms, network total transactions).
    stash: [64]Stash = @splat(.{}),

    const Stash = struct { seq: Atomic(u64) = .init(std.math.maxInt(u64)), ts_ms: Atomic(u64) = .init(0), total_tx: Atomic(u64) = .init(0) };

    fn ageNs(now_ms: u64, ts_ms: u64) u64 {
        return (now_ms -| ts_ms) * std.time.ns_per_ms;
    }

    /// The ordered stage took checkpoint `seq` (its summary is verified, its contents are here).
    /// `arrival_ms`: when its bytes arrived (null: not recorded, the summary age is taken now).
    pub fn taken(m: *Checkpoints, seq: u64, ts_ms: u64, total_tx: u64, epoch: u64, arrival_ms: ?u64, from_archive: bool) void {
        const now = prom.wallMs();
        const arr = arrival_ms orelse now;
        m.summary_age.observe(ageNs(arr, ts_ms));
        m.summary_age_ms.report(arr -| ts_ms);
        m.contents_age.observe(ageNs(now, ts_ms));
        m.contents_age_ms.report(now -| ts_ms);
        if (from_archive) _ = m.from_archive.fetchAdd(1, .monotonic);
        m.epoch.store(epoch, .monotonic);
        const s = &m.stash[seq % m.stash.len];
        s.ts_ms.store(ts_ms, .monotonic);
        s.total_tx.store(total_tx, .monotonic);
        s.seq.store(seq, .release);
    }

    /// Checkpoint `seq` is committed (sui-node: `update_highest_executed_checkpoint`).
    pub fn executed(m: *Checkpoints, seq: u64) void {
        const s = &m.stash[seq % m.stash.len];
        if (s.seq.load(.acquire) != seq) return;
        const ts = s.ts_ms.load(.monotonic);
        const total = s.total_tx.load(.monotonic);
        const now = prom.wallMs();
        m.executed_age.observe(ageNs(now, ts));
        m.executed_age_ms.report(now -| ts);
        // TPSEstimator::update(Instant::now(), network_total_transactions)
        const t = prom.monoNs();
        var tps = @as(f64, @bitCast(m.tps_bits.load(.monotonic)));
        if (m.tps_last_ns != 0 and t > m.tps_last_ns and total >= m.tps_last_count) {
            const dt = @as(f64, @floatFromInt(t - m.tps_last_ns)) / 1e9;
            const dc = @as(f64, @floatFromInt(total - m.tps_last_count));
            tps = tps * 0.9 + (dc / dt) * 0.1;
            m.tps_bits.store(@bitCast(tps), .monotonic);
        }
        m.tps_last_ns = t;
        m.tps_last_count = total;
    }

    pub const Pruner = struct {
        objects: u64,
        tombstones: u64,
        /// The effects pruner's watermark (deepwave prunes effects with their transactions under
        /// the checkpoint floor: equal to last_pruned_checkpoint).
        last_pruned_effects: u64,
        object_epochs: u64,
        checkpoint_epochs: u64,
        /// state_sync_peers_reported_for_failure: peers the p2p follower's scoring reported.
        peers_reported: u64 = 0,
    };

    pub fn render(m: *Checkpoints, w: *Writer, p: Pruner) Writer.Error!void {
        // checkpoint executor
        const tps: f64 = @bitCast(m.tps_bits.load(.monotonic));
        try prom.scalar(w, "checkpoint_exec_sync_tps", "Checkpoint sync estimated transactions per second", "gauge", @as(i64, @intFromFloat(tps)));
        try prom.scalar(w, "checkpoint_exec_errors", "Checkpoint execution errors count", "counter", 0);
        try prom.scalar(w, "checkpoint_exec_epoch", "Current epoch number in the checkpoint executor", "gauge", m.epoch.load(.monotonic));
        try prom.scalar(w, "checkpoint_exec_inflight", "Current number of inflight checkpoints being executed", "gauge", 0);
        const zero_sub: prom.Histogram(&prom.buckets.subsecond_latency_sec, prom.ns) = .{};
        try zero_sub.render(w, "checkpoint_exec_latency", "Latency of executing a checkpoint from enqueue to all effects available");
        try zero_sub.render(w, "checkpoint_prepare_latency", "Latency of preparing a checkpoint to enqueue for execution");
        const zero_count: prom.Histogram(&prom.buckets.count, prom.one) = .{};
        try zero_count.render(w, "checkpoint_transaction_count", "Number of transactions in the checkpoint");
        try m.contents_age.render(w, "checkpoint_contents_age", "Age of checkpoints when they arrive for execution");
        try m.contents_age_ms.render(w, "checkpoint_contents_age_ms", "Age of checkpoints when they arrive for execution");
        try m.executed_age.render(w, "last_executed_checkpoint_age", "Age of the last executed checkpoint");
        try m.executed_age_ms.render(w, "last_executed_checkpoint_age_ms", "Age of the last executed checkpoint");
        try prom.scalar(w, "checkpoint_executor_validator_path", "Number of checkpoints executed using the validator path", "gauge", 0);
        try prom.scalar(w, "checkpoint_executor_validator_sync_fallback_path", "Number of checkpoints executed using the validator fallback path to synced checkpoints", "gauge", 0);
        // state sync
        try prom.scalar(w, "checkpoints_synced_from_archive", "Checkpoints synced from archive", "counter", m.from_archive.load(.monotonic));
        try prom.scalar(w, "state_sync_peers_reported_for_failure", "Peers reported due to consistent state sync failures", "counter", p.peers_reported);
        try m.summary_age.render(w, "checkpoint_summary_age", "Age of checkpoints summaries when they arrive and are verified.");
        try m.summary_age_ms.render(w, "checkpoint_summary_age_ms", "Age of checkpoints summaries when they arrive and are verified.");
        // pruner
        try prom.scalar(w, "num_pruned_objects", "Number of pruned objects", "counter", p.objects);
        try prom.scalar(w, "num_pruned_tombstones", "Number of pruned tombstones", "counter", p.tombstones);
        try prom.scalar(w, "last_pruned_effects_checkpoint", "Last pruned effects checkpoint", "gauge", p.last_pruned_effects);
        try prom.scalar(w, "num_epochs_to_retain_for_objects", "Number of epochs to retain for objects", "gauge", p.object_epochs);
        try prom.scalar(w, "num_epochs_to_retain_for_checkpoints", "Number of epochs to retain for checkpoints", "gauge", p.checkpoint_epochs);
    }
};

/// Disk bytes per data area (lane ops-metrics): typed-store's `rocksdb_total_sst_files_size`
/// and `rocksdb_total_num_files` gauges by `cf_name`, with deepwave's directories under the node
/// directory as the column families (`store/seg`, `store/index`, `state-index`, `history`,
/// ...: the first two path components under `store/`, else the first). Bytes are allocated
/// blocks (st_blocks * 512), so punched holes do not count. A scrape starts a walk on its own
/// thread at most once a minute and prints the last finished one.
pub const DiskUsage = struct {
    pub const max_areas = 32;
    pub const refresh_ms = 60_000;
    const Area = struct { name: [48]u8 = undefined, len: u8 = 0, bytes: u64 = 0, files: u64 = 0 };

    /// A walk stops after this many files (a node directory with per-checkpoint files).
    pub const max_files = 2_000_000;

    lock: Atomic(u32) = .init(0),
    areas: [max_areas]Area = @splat(.{}),
    n: usize = 0,
    last_ms: Atomic(u64) = .init(0),
    running: Atomic(bool) = .init(false),
    stopping: Atomic(bool) = .init(false),

    fn areaOf(path: []const u8) []const u8 {
        const a = std.mem.indexOfScalar(u8, path, '/') orelse return path;
        if (!std.mem.eql(u8, path[0..a], "store")) return path[0..a];
        const b = std.mem.indexOfScalarPos(u8, path, a + 1, '/') orelse return path[0..a];
        return path[0..b];
    }

    fn add(d: *DiskUsage, area: []const u8, bytes: u64) void {
        const name = area[0..@min(area.len, 48)];
        for (d.areas[0..d.n]) |*x| if (std.mem.eql(u8, x.name[0..x.len], name)) {
            x.bytes += bytes;
            x.files += 1;
            return;
        };
        if (d.n == max_areas) return;
        const x = &d.areas[d.n];
        x.* = .{ .len = @intCast(name.len), .bytes = bytes, .files = 1 };
        @memcpy(x.name[0..name.len], name);
        d.n += 1;
    }

    /// Starts a walk of `root` (the node directory) on its own thread when the last one is
    /// older than a minute and none is running; scrapes never wait for it.
    pub fn maybeRefresh(d: *DiskUsage, gpa: std.mem.Allocator, io: std.Io, root: []const u8) void {
        const now = prom.wallMs();
        if (d.last_ms.load(.monotonic) != 0 and now -| d.last_ms.load(.monotonic) < refresh_ms) return;
        if (d.running.cmpxchgStrong(false, true, .seq_cst, .monotonic) != null) return;
        if (d.stopping.load(.seq_cst)) {
            d.running.store(false, .release);
            return;
        }
        d.last_ms.store(now, .monotonic);
        const t = std.Thread.spawn(.{ .stack_size = 1 << 20 }, walkMain, .{ d, gpa, io, root }) catch {
            d.running.store(false, .release);
            return;
        };
        t.detach();
    }

    fn walkMain(d: *DiskUsage, gpa: std.mem.Allocator, io: std.Io, root: []const u8) void {
        defer d.running.store(false, .release);
        var dir = std.Io.Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return;
        defer dir.close(io);
        var w = dir.walk(gpa) catch return;
        defer w.deinit();
        var fresh: DiskUsage = .{};
        var pb: [std.fs.max_path_bytes]u8 = undefined;
        var seen: u64 = 0;
        while (w.next(io) catch null) |e| {
            if (d.stopping.load(.acquire)) return;
            if (e.kind != .file) continue;
            seen += 1;
            if (seen > max_files) break;
            const full = std.fmt.bufPrintSentinel(&pb, "{s}/{s}", .{ root, e.path }, 0) catch continue;
            fresh.add(areaOf(e.path), allocatedBytes(full) orelse continue);
        }
        while (d.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer d.lock.store(0, .release);
        d.areas = fresh.areas;
        d.n = fresh.n;
    }

    /// Bytes allocated to the file at `path` (st_blocks * 512). Linux: statx (std.c.Stat is void
    /// on linux-gnu, so the c path does not compile there); elsewhere libc stat.
    fn allocatedBytes(path: [:0]const u8) ?u64 {
        if (@import("builtin").os.tag == .linux) {
            const linux = std.os.linux;
            var sx: linux.Statx = undefined;
            if (linux.errno(linux.statx(linux.AT.FDCWD, path.ptr, 0, .{ .BLOCKS = true }, &sx)) != .SUCCESS) return null;
            return sx.blocks * 512;
        }
        var st: std.c.Stat = undefined;
        if (std.c.stat(path.ptr, &st) != 0) return null;
        return @as(u64, @intCast(@max(st.blocks, 0))) * 512;
    }

    /// Stops a running walk and waits for it (before the node's memory goes away).
    pub fn stop(d: *DiskUsage) void {
        d.stopping.store(true, .seq_cst);
        while (d.running.load(.seq_cst)) std.Thread.yield() catch {};
    }

    pub fn render(d: *DiskUsage, w: *Writer) Writer.Error!void {
        while (d.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        defer d.lock.store(0, .release);
        if (d.n == 0) return;
        const xs = d.areas[0..d.n];
        std.sort.pdq(Area, xs, {}, struct {
            fn lt(_: void, a: Area, b: Area) bool {
                return std.mem.lessThan(u8, a.name[0..a.len], b.name[0..b.len]);
            }
        }.lt);
        try prom.head(w, "rocksdb_total_num_files", "Total number of files used in the column family", "gauge");
        for (xs) |*x| try w.print("rocksdb_total_num_files{{cf_name=\"{s}\"}} {d}\n", .{ x.name[0..x.len], x.files });
        try prom.head(w, "rocksdb_total_sst_files_size", "The storage size occupied by the sst files in the column family", "gauge");
        for (xs) |*x| try w.print("rocksdb_total_sst_files_size{{cf_name=\"{s}\"}} {d}\n", .{ x.name[0..x.len], x.bytes });
    }
};

test "disk usage: areas" {
    try std.testing.expectEqualStrings("store/seg", DiskUsage.areaOf("store/seg/00001305.log"));
    try std.testing.expectEqualStrings("store", DiskUsage.areaOf("store/meta"));
    try std.testing.expectEqualStrings("state-index", DiskUsage.areaOf("state-index/run-1.sst"));
    try std.testing.expectEqualStrings("LOCK", DiskUsage.areaOf("LOCK"));
    var d: DiskUsage = .{};
    d.add("store/seg", 4096);
    d.add("store/seg", 4096);
    d.add("history", 512);
    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try d.render(&w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "rocksdb_total_sst_files_size{cf_name=\"store/seg\"} 8192\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "rocksdb_total_num_files{cf_name=\"history\"} 1\n") != null);
}

test "checkpoint families: names, types, ages and tps" {
    var m: Checkpoints = .{};
    const now = prom.wallMs();
    m.taken(10, now - 500, 1000, 1305, now - 300, true);
    m.executed(10);
    m.taken(11, now - 100, 1100, 1305, null, false);
    m.executed(11);
    m.executed(99); // never taken: ignored
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try m.render(&out.writer, .{ .objects = 7, .tombstones = 2, .last_pruned_effects = 5, .object_epochs = 1, .checkpoint_epochs = 2 });
    const t = out.writer.buffered();
    const has = struct {
        fn f(text: []const u8, s: []const u8) bool {
            return std.mem.indexOf(u8, text, s) != null;
        }
    }.f;
    try std.testing.expect(has(t, "\ncheckpoints_synced_from_archive 1\n"));
    try std.testing.expect(has(t, "# TYPE last_executed_checkpoint_age histogram\n"));
    try std.testing.expect(has(t, "last_executed_checkpoint_age_count 2\n"));
    try std.testing.expect(has(t, "# TYPE last_executed_checkpoint_age_ms gauge\n"));
    try std.testing.expect(has(t, "last_executed_checkpoint_age_ms_count 2\n"));
    try std.testing.expect(has(t, "checkpoint_summary_age_count 2\n"));
    try std.testing.expect(has(t, "checkpoint_exec_latency_bucket{le=\"0.001\"} 0\n"));
    try std.testing.expect(has(t, "checkpoint_transaction_count_bucket{le=\"10000\"} 0\n"));
    try std.testing.expect(has(t, "\ncheckpoint_exec_epoch 1305\n"));
    try std.testing.expect(has(t, "\nnum_pruned_objects 7\n"));
    try std.testing.expect(has(t, "\nnum_epochs_to_retain_for_checkpoints 2\n"));
    // the summary arrived 200 ms after the timestamp of checkpoint 10 (le 0.2 holds it)
    try std.testing.expect(has(t, "checkpoint_summary_age_bucket{le=\"0.2\"} 1\n") or has(t, "checkpoint_summary_age_bucket{le=\"0.2\"} 2\n"));
}
