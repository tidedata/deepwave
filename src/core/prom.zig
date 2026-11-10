//! Prometheus plumbing shared by every lane (lane ops-metrics): histograms, Mysten's percentile
//! "histograms", bounded label tables and the text-format helpers, so a family keeps sui-node
//! 1.83.1's name, type, help text, labels and buckets wherever it is counted.
//!
//! Hot path: `observe` is a few relaxed atomic adds on fixed slots (a binary search over the
//! bucket bounds, no locks, no allocation). Label tables intern a name once (spin lock, one
//! allocation per new label), then hand out a slot index; lookups of known names read without
//! locking. Rendering happens only on a scrape.
//!
//! Text output follows the prometheus crate's encoder: `# HELP`, `# TYPE`, label pairs sorted
//! by name (`le` last), numbers as Rust's f64 Display prints them (`1`, `0.005`, `90`).
const std = @import("std");
const Atomic = std.atomic.Value;
const Writer = std.Io.Writer;

/// mysten-metrics bucket sets (crates/mysten-metrics/src/lib.rs) and the few crate-local ones
/// the exported families use.
pub const buckets = struct {
    /// `LATENCY_SEC_BUCKETS`.
    pub const latency_sec = [_]f64{
        0.001, 0.005, 0.01,  0.025, 0.05,  0.075, 0.1,  0.125, 0.15, 0.175, 0.2, 0.225, 0.25, 0.275, 0.3,
        0.325, 0.35,  0.375, 0.4,   0.425, 0.45,  0.475, 0.5,  0.55, 0.6,   0.65, 0.7,  0.75, 0.8,  0.85,
        0.9,   0.95,  1,     1.1,   1.2,   1.3,   1.4,  1.5,   1.6,  1.7,   1.8, 1.9,  2,    2.5,  3,
        3.5,   4,     4.5,   5,     6,     7,     8,    9,     10,   15,    20,  25,   30,   60,   90,
    };
    /// `SUBSECOND_LATENCY_SEC_BUCKETS`.
    pub const subsecond_latency_sec = [_]f64{
        0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1,  0.125, 0.15, 0.175, 0.2, 0.225, 0.25, 0.275, 0.3,
        0.325, 0.35,  0.375, 0.4,  0.425, 0.45, 0.475, 0.5, 0.55, 0.6,  0.65, 0.7, 0.75, 0.8,  0.85,
        0.9,   0.95,  1,     2,    5,     10,   20,    30,  60,   90,
    };
    /// `COARSE_LATENCY_SEC_BUCKETS`.
    pub const coarse_latency_sec = [_]f64{ 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.2, 0.3, 0.5, 0.7, 1, 2, 3, 5, 10, 20, 30, 60, 90 };
    /// `COUNT_BUCKETS`.
    pub const count = [_]f64{ 1, 2, 3, 4, 5, 7, 10, 15, 20, 25, 30, 40, 50, 75, 100, 150, 200, 500, 1000, 2000, 5000, 10000 };
    /// `BYTES_BUCKETS`.
    pub const bytes = [_]f64{ 1, 4, 16, 64, 256, 1024, 4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576, 2097152, 4194304, 8388608, 16777216, 33554432, 67108864 };
    /// transaction_driver `REQUEST_COUNT_BUCKETS`.
    pub const request_count = [_]f64{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 20, 30, 60, 90, 120, 150 };
    /// typed-store `LATENCY_SEC_BUCKETS` (crates/typed-store/src/metrics.rs).
    pub const rocksdb_latency_sec = [_]f64{ 0.00001, 0.00005, 0.0001, 0.0002, 0.0003, 0.0004, 0.0005, 0.001, 0.002, 0.003, 0.004, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10 };
};

/// Observed values are integers in the family's unit: nanoseconds for a seconds histogram
/// (`ns`), the value itself for counts and bytes (`one`).
pub const ns: f64 = 1e9;
pub const one: f64 = 1;

/// A prometheus `Histogram` with fixed `bounds` (in the exported unit) over integer
/// observations scaled by `scale` (a seconds family observes nanoseconds: scale 1e9).
pub fn Histogram(comptime bounds: []const f64, comptime scale: f64) type {
    return struct {
        const Self = @This();
        pub const limits: [bounds.len]u64 = blk: {
            var out: [bounds.len]u64 = undefined;
            for (bounds, 0..) |b, i| out[i] = @intFromFloat(b * scale);
            break :blk out;
        };

        counts: [bounds.len]Atomic(u64) = @splat(.init(0)),
        sum: Atomic(u64) = .init(0),
        n: Atomic(u64) = .init(0),

        pub fn observe(h: *Self, v: u64) void {
            var lo: usize = 0;
            var hi: usize = limits.len;
            while (lo < hi) {
                const mid = (lo + hi) / 2;
                if (v <= limits[mid]) hi = mid else lo = mid + 1;
            }
            if (lo < limits.len) _ = h.counts[lo].fetchAdd(1, .monotonic);
            _ = h.sum.fetchAdd(v, .monotonic);
            _ = h.n.fetchAdd(1, .monotonic);
        }

        pub fn count(h: *const Self) u64 {
            return h.n.load(.monotonic);
        }

        /// The series of one child: `labels` is `a="x",b="y"` (sorted by name) or empty.
        pub fn renderSeries(h: *const Self, w: *Writer, name: []const u8, labels: []const u8) Writer.Error!void {
            var cum: u64 = 0;
            const sep: []const u8 = if (labels.len > 0) "," else "";
            for (bounds, 0..) |b, i| {
                cum += h.counts[i].load(.monotonic);
                try w.print("{s}_bucket{{{s}{s}le=\"", .{ name, labels, sep });
                try writeFloat(w, b);
                try w.print("\"}} {d}\n", .{cum});
            }
            const total = h.n.load(.monotonic);
            try w.print("{s}_bucket{{{s}{s}le=\"+Inf\"}} {d}\n", .{ name, labels, sep, total });
            const sum = @as(f64, @floatFromInt(h.sum.load(.monotonic))) / scale;
            if (labels.len > 0) {
                try w.print("{s}_sum{{{s}}} ", .{ name, labels });
                try writeFloat(w, sum);
                try w.print("\n{s}_count{{{s}}} {d}\n", .{ name, labels, total });
            } else {
                try w.print("{s}_sum ", .{name});
                try writeFloat(w, sum);
                try w.print("\n{s}_count {d}\n", .{ name, total });
            }
        }

        /// A whole family with one unlabelled child (prometheus `Histogram`: present with zeros
        /// before the first observation, as sui-node registers it).
        pub fn render(h: *const Self, w: *Writer, name: []const u8, help: []const u8) Writer.Error!void {
            try head(w, name, help, "histogram");
            try h.renderSeries(w, name, "");
        }
    };
}

/// Rust's `f64` Display: integers without a fraction, otherwise the shortest round-trip decimal.
pub fn writeFloat(w: *Writer, v: f64) Writer.Error!void {
    if (v == @trunc(v) and @abs(v) < 1e15) {
        try w.print("{d}", .{@as(i64, @intFromFloat(v))});
    } else try w.print("{d}", .{v});
}

pub fn head(w: *Writer, name: []const u8, help: []const u8, kind: []const u8) Writer.Error!void {
    try w.print("# HELP {s} {s}\n# TYPE {s} {s}\n", .{ name, help, name, kind });
}

/// One unlabelled sample: `name value`, with its HELP and TYPE.
pub fn scalar(w: *Writer, name: []const u8, help: []const u8, kind: []const u8, v: anytype) Writer.Error!void {
    try head(w, name, help, kind);
    try w.print("{s} {d}\n", .{ name, v });
}

/// A label value as the text format wants it (`\`, `"` and newline escaped).
pub fn writeLabelValue(w: *Writer, v: []const u8) Writer.Error!void {
    for (v) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        '\n' => try w.writeAll("\\n"),
        else => try w.writeByte(c),
    };
}

/// mysten-metrics `Histogram` (crates/mysten-metrics/src/histogram.rs): not buckets but an
/// IntGaugeVec `<name>{pct="50"|"95"|"99"}` holding percentiles of the points of the last
/// 60 s window, plus IntCounterVecs `<name>_sum` and `<name>_count` (separate families, same
/// help). Values are integers (ms for the `*_age_ms` families).
///
/// Points go to a ring of the last `cap` (second, value) pairs: one relaxed fetchAdd and one
/// store per point. A scrape takes the points of the 60 s before it. sui-node reports a closed
/// 60 s window (it changes once a minute); this is the same window measured at the scrape.
pub const MystenHistogram = struct {
    pub const cap = 4096;
    pub const window_s = 60;
    pub const pcts = [_]u16{ 500, 950, 990 };

    ring: [cap]Atomic(u64) = @splat(.init(0)),
    next: Atomic(u64) = .init(0),
    sum: Atomic(u64) = .init(0),
    n: Atomic(u64) = .init(0),
    /// True once a point was seen (sui-node registers the gauge children lazily).
    seen: Atomic(bool) = .init(false),

    pub fn report(h: *MystenHistogram, v: u64) void {
        h.reportAt(v, wallSeconds());
    }

    pub fn reportAt(h: *MystenHistogram, v: u64, now_s: u64) void {
        const i = h.next.fetchAdd(1, .monotonic);
        const packed_v: u64 = (@as(u64, @as(u32, @truncate(now_s))) << 32) | @min(v, std.math.maxInt(u32));
        h.ring[i % cap].store(packed_v, .monotonic);
        _ = h.sum.fetchAdd(v, .monotonic);
        _ = h.n.fetchAdd(1, .monotonic);
        if (!h.seen.load(.monotonic)) h.seen.store(true, .monotonic);
    }

    /// p50, p95, p99 of the points of the 60 s before `now_s` (zeros when none: sui-node resets
    /// a label with no data in the window to 0).
    pub fn percentiles(h: *const MystenHistogram, now_s: u64) [pcts.len]u64 {
        var vals: [cap]u32 = undefined;
        var k: usize = 0;
        const total = h.next.load(.monotonic);
        const m: usize = @intCast(@min(total, cap));
        const now32: u32 = @truncate(now_s);
        for (0..m) |j| {
            const x = h.ring[(total - 1 - j) % cap].load(.monotonic);
            const ts: u32 = @truncate(x >> 32);
            if (now32 -% ts > window_s) continue;
            vals[k] = @truncate(x);
            k += 1;
        }
        var out: [pcts.len]u64 = @splat(0);
        if (k == 0) return out;
        std.sort.pdq(u32, vals[0..k], {}, std.sort.asc(u32));
        // `pct1000_index`: len * pct1000 / 1000
        for (pcts, 0..) |p, i| out[i] = vals[k * p / 1000];
        return out;
    }

    pub fn render(h: *const MystenHistogram, w: *Writer, name: []const u8, help: []const u8) Writer.Error!void {
        try h.renderAt(w, name, help, wallSeconds());
    }

    pub fn renderAt(h: *const MystenHistogram, w: *Writer, name: []const u8, help: []const u8, now_s: u64) Writer.Error!void {
        if (!h.seen.load(.monotonic)) return;
        const p = h.percentiles(now_s);
        try head(w, name, help, "gauge");
        inline for (.{ "50", "95", "99" }, 0..) |label, i| try w.print("{s}{{pct=\"" ++ label ++ "\"}} {d}\n", .{ name, p[i] });
        try w.print("# HELP {s}_count {s}\n# TYPE {s}_count counter\n{s}_count {d}\n", .{ name, help, name, name, h.n.load(.monotonic) });
        try w.print("# HELP {s}_sum {s}\n# TYPE {s}_sum counter\n{s}_sum {d}\n", .{ name, help, name, name, h.sum.load(.monotonic) });
    }
};

/// Wall clock seconds since the Unix epoch.
pub fn wallSeconds() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// Wall clock milliseconds since the Unix epoch.
pub fn wallMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / std.time.ns_per_ms;
}

/// Monotonic nanoseconds (for durations).
pub fn monoNs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// A bounded table of label values, each with a `T` of atomics. Names are interned once (spin
/// lock, one allocation each); a known name is found without locking. Past `max` labels every
/// new name maps to `overflow` (itself interned in the last slot), so a peer or client cannot
/// grow the table without bound.
pub fn Labeled(comptime T: type, comptime max: usize) type {
    return struct {
        const Self = @This();
        pub const Slot = struct { name: []const u8, v: T = .{} };

        slots: [max]?*Slot = @splat(null),
        n: Atomic(u32) = .init(0),
        lock: Atomic(u32) = .init(0),
        overflow: []const u8 = "unknown",

        fn acquire(s: *Self) void {
            while (s.lock.cmpxchgWeak(0, 1, .acquire, .monotonic) != null) std.atomic.spinLoopHint();
        }
        fn release(s: *Self) void {
            s.lock.store(0, .release);
        }

        fn find(s: *Self, from: usize, to: usize, name: []const u8) ?*T {
            for (s.slots[from..to]) |x| if (std.mem.eql(u8, x.?.name, name)) return &x.?.v;
            return null;
        }

        /// The slot of `name`, created on first use; null only when out of memory.
        pub fn get(s: *Self, name: []const u8) ?*T {
            const n = s.n.load(.acquire);
            if (s.find(0, n, name)) |v| return v;
            s.acquire();
            defer s.release();
            const n2 = s.n.load(.acquire);
            if (s.find(n, n2, name)) |v| return v;
            const use = if (n2 + 1 >= max) s.overflow else name;
            if (n2 + 1 >= max) if (s.find(0, n2, use)) |v| return v;
            if (n2 == max) return null;
            const slot = std.heap.page_allocator.create(Slot) catch return null;
            slot.* = .{ .name = std.heap.page_allocator.dupe(u8, use) catch {
                std.heap.page_allocator.destroy(slot);
                return null;
            } };
            s.slots[n2] = slot;
            s.n.store(n2 + 1, .release);
            return &slot.v;
        }

        /// The slots in name order (`buf` holds at least `max`).
        pub fn sorted(s: *Self, buf: []*Slot) []*Slot {
            const n = s.n.load(.acquire);
            for (0..n) |i| buf[i] = s.slots[i].?;
            std.sort.pdq(*Slot, buf[0..n], {}, struct {
                fn lt(_: void, a: *Slot, b: *Slot) bool {
                    return std.mem.lessThan(u8, a.name, b.name);
                }
            }.lt);
            return buf[0..n];
        }

        pub fn len(s: *const Self) usize {
            return s.n.load(.acquire);
        }
    };
}

test "histogram: buckets, sum and text as the prometheus crate prints them" {
    var h: Histogram(&buckets.coarse_latency_sec, ns) = .{};
    h.observe(3 * std.time.ns_per_ms); // 0.003 s -> le 0.005
    h.observe(250 * std.time.ns_per_ms); // -> le 0.3
    h.observe(200 * std.time.ns_per_s); // past 90 -> +Inf only
    var buf: [8192]u8 = undefined;
    var w = Writer.fixed(&buf);
    try h.render(&w, "x_latency", "X");
    const t = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, t, "# HELP x_latency X\n# TYPE x_latency histogram\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_bucket{le=\"0.005\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_bucket{le=\"0.2\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_bucket{le=\"0.3\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_bucket{le=\"90\"} 2\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_bucket{le=\"+Inf\"} 3\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_sum 200.253\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "x_latency_count 3\n") != null);
    var w2 = Writer.fixed(&buf);
    try h.renderSeries(&w2, "y", "route=\"/a\"");
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "y_bucket{route=\"/a\",le=\"0.01\"} 1\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, w2.buffered(), "y_count{route=\"/a\"} 3\n") != null);
}

test "mysten histogram: window percentiles, sum and count" {
    var h: MystenHistogram = .{};
    var buf: [2048]u8 = undefined;
    var w0 = Writer.fixed(&buf);
    try h.renderAt(&w0, "a_ms", "A", 1000);
    try std.testing.expectEqual(@as(usize, 0), w0.end);
    h.reportAt(9999, 900); // outside the window at 1000
    for (1..101) |v| h.reportAt(v, 990);
    const p = h.percentiles(1000);
    try std.testing.expectEqual(@as(u64, 51), p[0]); // vals[100*500/1000] = vals[50] = 51
    try std.testing.expectEqual(@as(u64, 96), p[1]);
    try std.testing.expectEqual(@as(u64, 100), p[2]);
    var w = Writer.fixed(&buf);
    try h.renderAt(&w, "a_ms", "A", 1000);
    const t = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, t, "a_ms{pct=\"50\"} 51\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "# TYPE a_ms_count counter\na_ms_count 101\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "a_ms_sum 15049\n") != null);
    // nothing in the window: zeros, counters keep their totals
    try std.testing.expectEqual([3]u64{ 0, 0, 0 }, h.percentiles(5000));
}

test "labeled: bounded, overflow label" {
    const T = struct { c: Atomic(u64) = .init(0) };
    var l: Labeled(T, 4) = .{};
    _ = l.get("/b").?.c.fetchAdd(1, .monotonic);
    _ = l.get("/a").?.c.fetchAdd(1, .monotonic);
    _ = l.get("/b").?.c.fetchAdd(1, .monotonic);
    _ = l.get("/c").?.c.fetchAdd(1, .monotonic);
    _ = l.get("/d").?.c.fetchAdd(1, .monotonic); // slot 3 is the last: overflow
    _ = l.get("/e").?.c.fetchAdd(1, .monotonic);
    _ = l.get("/c").?.c.fetchAdd(1, .monotonic);
    var buf: [4]*Labeled(T, 4).Slot = undefined;
    const s = l.sorted(&buf);
    try std.testing.expectEqual(@as(usize, 4), s.len);
    try std.testing.expectEqualStrings("/a", s[0].name);
    try std.testing.expectEqual(@as(u64, 2), s[1].v.c.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2), s[2].v.c.load(.monotonic));
    try std.testing.expectEqualStrings("unknown", s[3].name);
    try std.testing.expectEqual(@as(u64, 2), s[3].v.c.load(.monotonic));
}
