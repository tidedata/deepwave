//! Sampled store read latency (lane ops-metrics): sui-node's typed-store
//! `rocksdb_get_latency_seconds{cf_name}` (histogram, typed-store LATENCY_SEC_BUCKETS, 10 us to
//! 10 s), with deepwave's tables as the column families:
//!
//!   objects          Snapshot.latest (newest version of an object)
//!   object_versions  Snapshot.objectAtChecked (an object at a version)
//!   checkpoints      Snapshot.checkpointChecked
//!   transactions     Snapshot.transactionChecked
//!
//! Also `rocksdb_write_batch_commit_latency_seconds{db_name="deepwave"}`: every store commit (one per
//! checkpoint, from the follower).
//!
//! typed-store samples its reads too; here one read in `sample_every` per thread is timed (two
//! clock reads), the others cost a thread-local increment and a branch.
const std = @import("std");
const prom = @import("core").prom;

pub const Table = enum { objects, object_versions, checkpoints, transactions };
pub const sample_every = 64;

const Hist = prom.Histogram(&prom.buckets.rocksdb_latency_sec, prom.ns);
pub var hist: [@typeInfo(Table).@"enum".field_names.len]Hist = @splat(.{});
threadlocal var tick: u32 = 0;
/// Store commits (one durable write per checkpoint).
pub var commit: Hist = .{};

/// 0: not sampled; else the start time.
pub inline fn begin() u64 {
    tick +%= 1;
    if (tick % sample_every != 0) return 0;
    return prom.monoNs();
}

pub inline fn end(t: Table, t0: u64) void {
    if (t0 != 0) hist[@intFromEnum(t)].observe(prom.monoNs() -| t0);
}

pub fn render(w: *std.Io.Writer) std.Io.Writer.Error!void {
    if (commit.count() > 0) {
        try prom.head(w, "rocksdb_write_batch_commit_latency_seconds", "Rocksdb schema batch commit latency in seconds", "histogram");
        try commit.renderSeries(w, "rocksdb_write_batch_commit_latency_seconds", "db_name=\"zui\"");
    }
    var any = false;
    for (&hist) |*h| any = any or h.count() > 0;
    if (!any) return;
    try prom.head(w, "rocksdb_get_latency_seconds", "Rocksdb get latency in seconds", "histogram");
    var lb: [64]u8 = undefined;
    for (&hist, 0..) |*h, i| if (h.count() > 0)
        try h.renderSeries(w, "rocksdb_get_latency_seconds", std.fmt.bufPrint(&lb, "cf_name=\"{s}\"", .{@tagName(@as(Table, @enumFromInt(i)))}) catch unreachable);
}

test "read latency: sampled, by table" {
    // The table is process-wide: other store tests in the same binary have read through it
    // already, so count from what is there.
    const before = hist[@intFromEnum(Table.checkpoints)].count();
    for (0..sample_every * 3) |_| {
        const t0 = begin();
        end(.checkpoints, t0);
    }
    const after = hist[@intFromEnum(Table.checkpoints)].count();
    try std.testing.expectEqual(@as(u64, 3), after - before);
    var buf: [1 << 16]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try render(&w);
    var lb: [96]u8 = undefined;
    const want = try std.fmt.bufPrint(&lb, "rocksdb_get_latency_seconds_count{{cf_name=\"checkpoints\"}} {d}\n", .{after});
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), want) != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "le=\"0.00001\"") != null);
}
