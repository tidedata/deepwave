//! Conformance suites of the ledger lane (docs/DROP-IN.md G7).
//!
//! `ledger-dims`: for every `vectors/ledger-dims/<seq>.txt` (tools/truth/ledger `zui-ledger-truth
//!   dims`, sui-inverted-index 1.83.1 `for_each_transaction_dimension` / `for_each_event_dimension`
//!   over `Checkpoint::from(CheckpointData)`), the dimension keys deepwave's history index derives from
//!   `chk/<seq>.chk` are the same set, line for line (tx-space deduplicated per transaction,
//!   event-space per event index).
const std = @import("std");
const harness = @import("harness");
const bcs = @import("bcs");
const types = @import("types");
const dims = @import("dims.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "ledger-dims",
        .lane = "ledger",
        .doc = "history index dimension keys of corpus checkpoints equal sui-inverted-index's (tx and event space)",
        .run = runDims,
    },
};

const Lines = struct {
    a: std.mem.Allocator,
    first: u64,
    out: std.ArrayList([]const u8) = .empty,
    fn emit(ctx: *anyopaque, tx_off: u32, ev: ?u32, key: []const u8) std.mem.Allocator.Error!void {
        const l: *Lines = @ptrCast(@alignCast(ctx));
        const line = if (ev) |e|
            try std.fmt.allocPrint(l.a, "e {d:0>20} {d:0>5} {x}", .{ l.first + tx_off, e, key })
        else
            try std.fmt.allocPrint(l.a, "t {d:0>20} {x}", .{ l.first + tx_off, key });
        try l.out.append(l.a, line);
    }
};

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

/// Sorted, deduplicated "\n"-joined lines (the truth file's BTreeSet order).
pub fn render(a: std.mem.Allocator, blob: []const u8) ![]const u8 {
    const cp = try bcs.decode(types.CheckpointData, a, blob[1..]);
    const s = &cp.checkpoint_summary.data;
    var l: Lines = .{ .a = a, .first = s.network_total_transactions - cp.transactions.len };
    try dims.extract(a, a, &cp, .{ .ctx = &l, .emit = Lines.emit });
    std.mem.sort([]const u8, l.out.items, {}, lessStr);
    var w: std.ArrayList(u8) = .empty;
    var prev: ?[]const u8 = null;
    for (l.out.items) |line| {
        if (prev) |p| if (std.mem.eql(u8, p, line)) continue;
        try w.appendSlice(a, line);
        try w.append(a, '\n');
        prev = line;
    }
    return w.items;
}

fn runDims(ctx: *harness.Ctx) !void {
    const names = try ctx.listFiles("vectors/ledger-dims", ".txt");
    defer ctx.freeNames(names);
    for (names) |name| {
        if (ctx.done()) return;
        const seq = name[0 .. name.len - 4];
        if (!ctx.selected(seq)) continue;
        ctx.nextItem();
        const expected = try ctx.readFile(try std.fmt.allocPrint(ctx.scratch(), "vectors/ledger-dims/{s}", .{name}), 256 << 20);
        const blob = try ctx.readFile(try std.fmt.allocPrint(ctx.scratch(), "chk/{s}.chk", .{seq}), 1 << 30);
        const got = render(ctx.scratch(), blob) catch |e| {
            ctx.fail(seq, "extract: {s}", .{@errorName(e)});
            continue;
        };
        _ = ctx.expectText(seq, "dimension keys", expected, got);
    }
}
