//! Fixed-bucket latency histogram (log-linear, 8 sub-buckets per power of two), in microseconds.
//! Plain atomics only: no allocation, no locks, safe to update from any thread and to place in
//! shared memory. Relative error of a reported percentile is at most 1/16 (6.25%).
const std = @import("std");

pub const sub_bits = 3;
pub const sub_count = 1 << sub_bits;
/// Covers 0 us .. 2^43 us (about 100 days); larger values land in the last bucket.
pub const bucket_count = 344;

pub fn bucketOf(us: u64) usize {
    if (us < sub_count) return @intCast(us);
    const msb: u6 = @intCast(63 - @clz(us));
    const shift: u6 = msb - sub_bits;
    const idx = (@as(usize, shift) + 1) * sub_count + @as(usize, @intCast((us >> shift) & (sub_count - 1)));
    return @min(idx, bucket_count - 1);
}

/// Smallest value (us) that lands in bucket `idx`.
pub fn bucketLow(idx: usize) u64 {
    if (idx < sub_count) return idx;
    const shift: u6 = @intCast(idx / sub_count - 1);
    return (@as(u64, sub_count) + (idx % sub_count)) << shift;
}

/// Width of bucket `idx` in us.
pub fn bucketWidth(idx: usize) u64 {
    if (idx < sub_count) return 1;
    const shift: u6 = @intCast(idx / sub_count - 1);
    return @as(u64, 1) << shift;
}

pub const Hist = struct {
    counts: [bucket_count]std.atomic.Value(u64) = @splat(.init(0)),
    n: std.atomic.Value(u64) = .init(0),
    sum_us: std.atomic.Value(u64) = .init(0),
    max_us: std.atomic.Value(u64) = .init(0),

    pub fn record(h: *Hist, ns: u64) void {
        const us = ns / 1000;
        _ = h.counts[bucketOf(us)].fetchAdd(1, .monotonic);
        _ = h.n.fetchAdd(1, .monotonic);
        _ = h.sum_us.fetchAdd(us, .monotonic);
        _ = h.max_us.fetchMax(us, .monotonic);
    }

    pub fn count(h: *const Hist) u64 {
        return h.n.load(.monotonic);
    }

    pub fn meanUs(h: *const Hist) u64 {
        const c = h.count();
        return if (c == 0) 0 else h.sum_us.load(.monotonic) / c;
    }

    /// Percentile in us, `q` in 0..1 (0.5, 0.99). Reports the bucket midpoint, capped by the
    /// observed maximum. 0 when empty.
    pub fn percentileUs(h: *const Hist, q: f64) u64 {
        const total = h.count();
        if (total == 0) return 0;
        const qq = std.math.clamp(q, 0.0, 1.0);
        const want: u64 = @max(1, @as(u64, @intFromFloat(@ceil(qq * @as(f64, @floatFromInt(total))))));
        var seen: u64 = 0;
        for (&h.counts, 0..) |*c, i| {
            seen += c.load(.monotonic);
            if (seen >= want) return @min(bucketLow(i) + bucketWidth(i) / 2, h.max_us.load(.monotonic));
        }
        return h.max_us.load(.monotonic);
    }

    pub fn merge(h: *Hist, other: *const Hist) void {
        for (&h.counts, &other.counts) |*a, *b| _ = a.fetchAdd(b.load(.monotonic), .monotonic);
        _ = h.n.fetchAdd(other.n.load(.monotonic), .monotonic);
        _ = h.sum_us.fetchAdd(other.sum_us.load(.monotonic), .monotonic);
        _ = h.max_us.fetchMax(other.max_us.load(.monotonic), .monotonic);
    }
};

test "bucket mapping is monotonic and bounded" {
    var prev: usize = 0;
    var v: u64 = 0;
    while (v < 5_000_000) : (v += 1 + v / 50) {
        const b = bucketOf(v);
        try std.testing.expect(b >= prev);
        try std.testing.expect(bucketLow(b) <= v and v < bucketLow(b) + bucketWidth(b));
        prev = b;
    }
    try std.testing.expect(bucketOf(std.math.maxInt(u64)) < bucket_count);
}

test "percentiles" {
    var h: Hist = .{};
    for (1..101) |i| h.record(i * 1000 * 10); // 10 us .. 1000 us
    try std.testing.expectEqual(@as(u64, 100), h.count());
    const p50 = h.percentileUs(0.5);
    try std.testing.expect(p50 >= 480 and p50 <= 540);
    const p99 = h.percentileUs(0.99);
    try std.testing.expect(p99 >= 930 and p99 <= 1000);
    try std.testing.expectEqual(@as(u64, 505), h.meanUs());
}
