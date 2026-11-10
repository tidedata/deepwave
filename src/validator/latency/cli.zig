//! `deepwave-validator budget ...`: the latency budget table. Needs no keys and no network, so it
//! runs before the safety gate.
//!   budget --demo [--txs N]     model run through the tracer (the pipeline shape, not measurements)
//!   budget <dump-file>          table from a dump written by report.encode on a running validator
const std = @import("std");
const tracer = @import("tracer.zig");
const report = @import("report.zig");
const sim = @import("sim.zig");

/// `args` are the arguments after "budget". Returns the exit code.
pub fn run(io: std.Io, gpa: std.mem.Allocator, args: []const []const u8) !u8 {
    var demo = false;
    var txs: usize = 2000;
    var path: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--demo")) {
            demo = true;
        } else if (std.mem.eql(u8, a, "--txs") and i + 1 < args.len) {
            i += 1;
            txs = std.fmt.parseInt(usize, args[i], 10) catch return usage();
        } else if (a.len > 0 and a[0] != '-' and path == null) {
            path = a;
        } else return usage();
    }
    if (!demo and path == null) return usage();

    const budget = try gpa.create(tracer.Budget);
    defer gpa.destroy(budget);
    budget.* = .{};
    if (demo) {
        const t = try tracer.StageTracer.create(gpa, 1 << 14);
        defer t.destroy();
        sim.run(t, .{}, txs, 1);
        try copy(budget, &t.budget);
    } else {
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path.?, gpa, .limited(4 << 20)) catch {
            std.debug.print("budget: cannot read {s}\n", .{path.?});
            return 1;
        };
        defer gpa.free(bytes);
        report.decode(bytes, budget) catch {
            std.debug.print("budget: {s} is not a budget dump\n", .{path.?});
            return 1;
        };
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    const targets: report.Targets = .{};
    try report.render(&out, gpa, budget, &targets);
    if (demo) try out.appendSlice(gpa, "\n(demo: modelled delays, not measurements)\n");
    std.debug.print("{s}", .{out.items});
    return 0;
}

fn copy(dst: *tracer.Budget, src: *const tracer.Budget) !void {
    for (&dst.segments, &src.segments) |*d, *s| d.merge(s);
    for (&dst.totals, &src.totals) |*d, *s| d.merge(s);
    dst.evicted.store(src.evicted.load(.monotonic), .monotonic);
    dst.duplicates.store(src.duplicates.load(.monotonic), .monotonic);
}

fn usage() u8 {
    std.debug.print("usage: deepwave-validator budget --demo [--txs N] | budget <dump-file>\n", .{});
    return 2;
}
