//! The budget table: renders a tracer's Budget as text, and dumps/loads it as a small binary
//! file so a separate process (the report tool, the metrics tile) can print the table for a
//! running shadow or localnet validator. `deepwave-validator budget <dump>` prints it.
const std = @import("std");
const hist = @import("hist.zig");
const tracer = @import("tracer.zig");

const Point = tracer.Point;
const Chain = tracer.Chain;
const Budget = tracer.Budget;

/// p99 target per segment in us, 0 = no target. Initial values from the design (block receive to
/// accepted in microseconds; proposal bounded by min_round_delay 50 ms; execution a few ms). They
/// are placeholders until the localnet measurements exist; the report flags a segment whose p99
/// exceeds its target.
pub const Targets = struct {
    p99_us: [Point.count]u64 = default_p99,

    const default_p99 = blk: {
        var a: [Point.count]u64 = @splat(0);
        a[@intFromEnum(Point.tx_validated)] = 2_000;
        a[@intFromEnum(Point.tx_submitted)] = 500;
        a[@intFromEnum(Point.tx_in_proposed_block)] = 60_000;
        a[@intFromEnum(Point.tx_sequenced)] = 120_000;
        a[@intFromEnum(Point.tx_executed)] = 10_000;
        a[@intFromEnum(Point.effects_served)] = 1_000;
        a[@intFromEnum(Point.block_verified)] = 1_000;
        a[@intFromEnum(Point.block_accepted)] = 500;
        a[@intFromEnum(Point.block_proposed)] = 60_000;
        a[@intFromEnum(Point.leader_committed)] = 120_000;
        a[@intFromEnum(Point.sub_dag_finalized)] = 2_000;
        break :blk a;
    };
};

/// The end-to-end goal, in us.
pub const goal_us: u64 = 200_000;

fn ms(w: *std.ArrayList(u8), gpa: std.mem.Allocator, us: u64) !void {
    try w.print(gpa, "{d}.{d:0>3}", .{ us / 1000, us % 1000 });
}

fn row(out: *std.ArrayList(u8), gpa: std.mem.Allocator, label: []const u8, h: *const hist.Hist, total_mean: u64, target: u64) !void {
    const n = h.count();
    try out.print(gpa, "  {s:<22}{d:>9}  ", .{ label, n });
    if (n == 0) {
        try out.appendSlice(gpa, "-\n");
        return;
    }
    const cols = [_]u64{ h.percentileUs(0.5), h.percentileUs(0.99), h.max_us.load(.monotonic), h.meanUs() };
    for (cols) |v| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(gpa);
        try ms(&buf, gpa, v);
        try out.print(gpa, "{s:>10} ", .{buf.items});
    }
    if (total_mean > 0) {
        const share = @as(f64, @floatFromInt(h.meanUs())) * 100.0 / @as(f64, @floatFromInt(total_mean));
        try out.print(gpa, "{d:>6.1}%", .{share});
    } else try out.appendSlice(gpa, "      -");
    if (target != 0) {
        try out.print(gpa, "  target {d}us{s}", .{ target, if (h.percentileUs(0.99) > target) "  OVER" else "" });
    }
    try out.append(gpa, '\n');
}

/// Appends the budget table to `out`. Times in ms (p50, p99, max, mean), share of the chain's
/// mean total.
pub fn render(out: *std.ArrayList(u8), gpa: std.mem.Allocator, b: *const Budget, targets: *const Targets) !void {
    try out.appendSlice(gpa, "zui validator latency budget (ms; stage = time since the previous stage of the chain)\n");
    for (0..Chain.count) |ci| {
        const c: Chain = @enumFromInt(ci);
        const total = b.total(c);
        try out.print(gpa, "\nchain {s}\n  {s:<22}{s:>9}  {s:>10} {s:>10} {s:>10} {s:>10} {s:>7}\n", .{ @tagName(c), "stage", "n", "p50", "p99", "max", "mean", "share" });
        const pts = c.points();
        for (pts[1..]) |p| try row(out, gpa, p.name(), b.segment(p), total.meanUs(), targets.p99_us[@intFromEnum(p)]);
        try row(out, gpa, "TOTAL", total, total.meanUs(), 0);
    }
    const tx_total = b.total(.tx);
    if (tx_total.count() > 0) {
        try out.appendSlice(gpa, "\ntx to effects p50 ");
        try ms(out, gpa, tx_total.percentileUs(0.5));
        try out.appendSlice(gpa, " ms, p99 ");
        try ms(out, gpa, tx_total.percentileUs(0.99));
        try out.print(gpa, " ms against the {d} ms goal: {s}\n", .{ goal_us / 1000, if (tx_total.percentileUs(0.99) <= goal_us) "within" else "over" });
    }
    try out.print(gpa, "timelines evicted {d}, duplicate marks {d}, partial (no start mark, not in totals) {d}\n", .{ b.evicted.load(.monotonic), b.duplicates.load(.monotonic), b.partial.load(.monotonic) });
}

// ------------------------------------------------------------------ dump file

pub const magic = "ZBUD1\x00";

fn putU(out: *std.ArrayList(u8), gpa: std.mem.Allocator, comptime T: type, v: T) !void {
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, v, .little);
    try out.appendSlice(gpa, &b);
}

fn putHist(out: *std.ArrayList(u8), gpa: std.mem.Allocator, h: *const hist.Hist) !void {
    try putU(out, gpa, u64, h.n.load(.monotonic));
    try putU(out, gpa, u64, h.sum_us.load(.monotonic));
    try putU(out, gpa, u64, h.max_us.load(.monotonic));
    var nz: u16 = 0;
    for (&h.counts) |*c| {
        if (c.load(.monotonic) != 0) nz += 1;
    }
    try putU(out, gpa, u16, nz);
    for (&h.counts, 0..) |*c, i| {
        const v = c.load(.monotonic);
        if (v != 0) {
            try putU(out, gpa, u16, @intCast(i));
            try putU(out, gpa, u64, v);
        }
    }
}

pub fn encode(out: *std.ArrayList(u8), gpa: std.mem.Allocator, b: *const Budget) !void {
    try out.appendSlice(gpa, magic);
    try putU(out, gpa, u8, Point.count);
    try putU(out, gpa, u8, Chain.count);
    for (&b.segments) |*h| try putHist(out, gpa, h);
    for (&b.totals) |*h| try putHist(out, gpa, h);
    try putU(out, gpa, u64, b.evicted.load(.monotonic));
    try putU(out, gpa, u64, b.duplicates.load(.monotonic));
    try putU(out, gpa, u64, b.partial.load(.monotonic));
}

pub const DecodeError = error{BadDump};

const Cursor = struct {
    b: []const u8,
    i: usize = 0,
    fn take(c: *Cursor, comptime T: type) DecodeError!T {
        if (c.i + @sizeOf(T) > c.b.len) return error.BadDump;
        defer c.i += @sizeOf(T);
        return std.mem.readInt(T, c.b[c.i..][0..@sizeOf(T)], .little);
    }
};

fn getHist(c: *Cursor, h: *hist.Hist) DecodeError!void {
    h.n.store(try c.take(u64), .monotonic);
    h.sum_us.store(try c.take(u64), .monotonic);
    h.max_us.store(try c.take(u64), .monotonic);
    const nz = try c.take(u16);
    for (0..nz) |_| {
        const idx = try c.take(u16);
        const v = try c.take(u64);
        if (idx >= hist.bucket_count) return error.BadDump;
        h.counts[idx].store(v, .monotonic);
    }
}

/// `b` must be freshly zeroed (default-initialised).
pub fn decode(bytes: []const u8, b: *Budget) DecodeError!void {
    if (bytes.len < magic.len or !std.mem.eql(u8, bytes[0..magic.len], magic)) return error.BadDump;
    var c: Cursor = .{ .b = bytes, .i = magic.len };
    if ((try c.take(u8)) != Point.count or (try c.take(u8)) != Chain.count) return error.BadDump;
    for (&b.segments) |*h| try getHist(&c, h);
    for (&b.totals) |*h| try getHist(&c, h);
    b.evicted.store(try c.take(u64), .monotonic);
    b.duplicates.store(try c.take(u64), .monotonic);
    b.partial.store(try c.take(u64), .monotonic);
}

test "dump round trip and render" {
    const gpa = std.testing.allocator;
    const t = try tracer.StageTracer.create(gpa, 64);
    defer t.destroy();
    var k: [32]u8 = @as([32]u8, @splat(9));
    t.mark(.tx_received, &k, 1_000);
    t.mark(.tx_validated, &k, 801_000);
    t.mark(.tx_submitted, &k, 901_000);
    t.mark(.tx_in_proposed_block, &k, 40_901_000);
    t.mark(.tx_sequenced, &k, 140_901_000);
    t.mark(.tx_executed, &k, 145_901_000);
    t.mark(.effects_served, &k, 146_901_000);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try encode(&buf, gpa, &t.budget);
    const b2 = try gpa.create(Budget);
    defer gpa.destroy(b2);
    b2.* = .{};
    try decode(buf.items, b2);
    try std.testing.expectEqual(t.budget.total(.tx).count(), b2.total(.tx).count());

    var txt: std.ArrayList(u8) = .empty;
    defer txt.deinit(gpa);
    const tg: Targets = .{};
    try render(&txt, gpa, b2, &tg);
    try std.testing.expect(std.mem.indexOf(u8, txt.items, "chain tx") != null);
    try std.testing.expect(std.mem.indexOf(u8, txt.items, "within") != null);
    try std.testing.expectError(error.BadDump, decode("nope", b2));
}
