//! Conformance suite of the ExecuteTransaction driver (CONTRACTS.md section 3.3). Ground truth
//! comes from `tools/truth/rpc-exec-driver` (sui 1.83.1) under `$ZUI_CORPUS/vectors/rpc-execute`;
//! formats in tools/truth/rpc-exec-driver/README.md. Registered as `rpc-execute` in
//! src/rpc_exec/conformance.zig.
const std = @import("std");
const harness = @import("harness");
const vectors = @import("vectors.zig");

/// Declared in src/rpc_exec/conformance.zig's `suites` (build.zig routes -Dsuite by reading
/// that array's names).
pub const doc = "ExecuteTransaction: validator wire, handler replies, error texts and driver aggregation vs sui-rpc-api/sui-core 1.83.1";

fn passFn(ctx: *anyopaque, item: []const u8) void {
    const c: *harness.Ctx = @ptrCast(@alignCast(ctx));
    if (!c.selected(item) or c.done()) return;
    c.pass(item);
}

fn failFn(ctx: *anyopaque, item: []const u8, why: []const u8) void {
    const c: *harness.Ctx = @ptrCast(@alignCast(ctx));
    if (!c.selected(item) or c.done()) return;
    c.fail(item, "{s}", .{why});
}

pub fn run(ctx: *harness.Ctx) !void {
    try vectors.runAll(ctx.gpa, ctx.io, ctx.corpus, .{ .ctx = ctx, .passFn = passFn, .failFn = failFn }, null);
}
