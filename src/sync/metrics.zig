//! Counters of the follower: fixed u64 slots bumped with relaxed atomics on the hot path, rendered
//! as Prometheus text only when asked (ARCHITECTURE section 2, position 7).
const std = @import("std");
const Atomic = std.atomic.Value(u64);

pub const Metrics = struct {
    checkpoints: Atomic = .init(0),
    transactions: Atomic = .init(0),
    objects_put: Atomic = .init(0),
    objects_removed: Atomic = .init(0),
    bytes_in: Atomic = .init(0),
    rejected: Atomic = .init(0),
    /// Highest checkpoint sequence number applied (valid when `checkpoints` > 0), and the highest
    /// the source has offered so far; their difference is the lag.
    applied_seq: Atomic = .init(0),
    highest_seen: Atomic = .init(0),
    epoch: Atomic = .init(0),
    /// Nanoseconds summed over all threads of each stage.
    read_ns: Atomic = .init(0),
    index_ns: Atomic = .init(0),
    check_ns: Atomic = .init(0),
    cert_ns: Atomic = .init(0),
    apply_ns: Atomic = .init(0),
    commit_ns: Atomic = .init(0),
    /// Nanoseconds the ordered stage waited for a checkpoint that was not ready.
    stall_ns: Atomic = .init(0),
    /// Store commits by latency (one durable write + index apply, flush included when it runs
    /// inline): cumulative buckets, and the slowest.
    commit_le_2ms: Atomic = .init(0),
    commit_le_5ms: Atomic = .init(0),
    commit_le_10ms: Atomic = .init(0),
    commit_le_20ms: Atomic = .init(0),
    commit_le_50ms: Atomic = .init(0),
    commit_le_100ms: Atomic = .init(0),
    commit_gt_100ms: Atomic = .init(0),
    commit_max_ns: Atomic = .init(0),
    /// Checkpoints the store read-ahead warmed before the ordered stage applied them.
    prefetched: Atomic = .init(0),

    /// Counts one store commit of `ns` nanoseconds.
    pub fn commitLatency(m: *Metrics, ns: u64) void {
        const ms = ns / std.time.ns_per_ms;
        const slot = if (ms < 2) &m.commit_le_2ms else if (ms < 5) &m.commit_le_5ms else if (ms < 10) &m.commit_le_10ms else if (ms < 20) &m.commit_le_20ms else if (ms < 50) &m.commit_le_50ms else if (ms <= 100) &m.commit_le_100ms else &m.commit_gt_100ms;
        add(slot, 1);
        max(&m.commit_max_ns, ns);
    }

    /// Upper bound (ms) of the bucket holding the q-quantile of commit latency (q in 0..1).
    pub fn commitQuantileMs(m: *const Metrics, q: f64) u64 {
        const slots = [_]*const Atomic{ &m.commit_le_2ms, &m.commit_le_5ms, &m.commit_le_10ms, &m.commit_le_20ms, &m.commit_le_50ms, &m.commit_le_100ms, &m.commit_gt_100ms };
        const bounds = [_]u64{ 2, 5, 10, 20, 50, 100, m.commit_max_ns.load(.monotonic) / std.time.ns_per_ms };
        var total: u64 = 0;
        for (slots) |sl| total += sl.load(.monotonic);
        if (total == 0) return 0;
        const want: u64 = @intFromFloat(@ceil(q * @as(f64, @floatFromInt(total))));
        var acc: u64 = 0;
        for (slots, bounds) |sl, b| {
            acc += sl.load(.monotonic);
            if (acc >= want) return b;
        }
        return bounds[bounds.len - 1];
    }

    pub fn add(slot: *Atomic, n: u64) void {
        _ = slot.fetchAdd(n, .monotonic);
    }

    pub fn max(slot: *Atomic, n: u64) void {
        var cur = slot.load(.monotonic);
        while (n > cur) cur = slot.cmpxchgWeak(cur, n, .monotonic, .monotonic) orelse return;
    }

    pub fn lag(m: *const Metrics) u64 {
        return m.highest_seen.load(.monotonic) -| m.applied_seq.load(.monotonic);
    }

    /// Prometheus text exposition.
    pub fn render(m: *const Metrics, w: *std.Io.Writer) std.Io.Writer.Error!void {
        inline for (comptime std.meta.fieldNames(Metrics)) |name| {
            const v = @field(m, name).load(.monotonic);
            const kind = comptime if (std.mem.endsWith(u8, name, "_seq") or std.mem.eql(u8, name, "epoch") or std.mem.eql(u8, name, "highest_seen")) "gauge" else "counter";
            try w.print("# TYPE zui_sync_{s} {s}\nzui_sync_{s} {d}\n", .{ name, kind, name, v });
        }
        try w.print("# TYPE zui_sync_lag gauge\nzui_sync_lag {d}\n", .{m.lag()});
    }
};

test "render" {
    var m: Metrics = .{};
    Metrics.add(&m.checkpoints, 3);
    Metrics.max(&m.highest_seen, 10);
    Metrics.max(&m.applied_seq, 7);
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try m.render(&w);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "zui_sync_checkpoints 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "zui_sync_lag 3") != null);
}

/// Latency histogram for one hot-path stage (the perf gate's commit-path p99, tools/perfgate.sh):
/// 32 linear sub-buckets per power of two of nanoseconds (about 3% resolution), relaxed atomics.
pub const Hist = struct {
    const sub_bits = 5;
    const sub = 1 << sub_bits;
    buckets: [64 * sub]Atomic = @splat(.init(0)),

    fn index(ns: u64) usize {
        if (ns < sub) return @intCast(ns);
        const top: u6 = @intCast(63 - @clz(ns));
        const shift: u6 = top - sub_bits;
        const mant: u64 = (ns >> shift) & (sub - 1);
        return @as(usize, shift + 1) * sub + @as(usize, @intCast(mant));
    }

    /// Lower edge of bucket `i`.
    fn lower(i: usize) u64 {
        if (i < sub) return i;
        const shift: u6 = @intCast(i / sub - 1);
        return (@as(u64, sub) | (i % sub)) << shift;
    }

    pub fn record(h: *Hist, ns: u64) void {
        _ = h.buckets[index(ns)].fetchAdd(1, .monotonic);
    }

    /// The `q` quantile (0..1) in ns, as the lower edge of its bucket; 0 when empty.
    pub fn quantile(h: *const Hist, q: f64) u64 {
        var total: u64 = 0;
        for (&h.buckets) |*b| total += b.load(.monotonic);
        if (total == 0) return 0;
        const rank: u64 = @intFromFloat(@ceil(q * @as(f64, @floatFromInt(total))));
        var seen: u64 = 0;
        for (&h.buckets, 0..) |*b, i| {
            seen += b.load(.monotonic);
            if (seen >= @max(rank, 1)) return lower(i);
        }
        return lower(h.buckets.len - 1);
    }
};

test "hist quantiles" {
    var h: Hist = .{};
    var i: u64 = 1;
    while (i <= 1000) : (i += 1) h.record(i * 1000);
    const p50 = h.quantile(0.5);
    const p99 = h.quantile(0.99);
    try std.testing.expect(p50 >= 485_000 and p50 <= 500_000);
    try std.testing.expect(p99 >= 960_000 and p99 <= 990_000);
    try std.testing.expectEqual(@as(u64, 7), Hist.lower(Hist.index(7)));
}
