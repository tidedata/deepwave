//! Conformance suites of val-checkpoints (docs/VALIDATOR-DESIGN.md 9).
//!
//!   checkpoint-build  every corpus checkpoint (chk/<seq>.chk, made by Mysten's validators) is
//!                     rebuilt by deepwave's checkpoint builder from its effects, signatures and the
//!                     previous summary; contents and summary bytes and the causal order of every
//!                     commit group must equal the recorded ones (replay.zig).
//!
//! Run: ./zig build test-validator-conformance -Doptimize=ReleaseFast -Dsuite=checkpoint-build -Djobs=16
const std = @import("std");
const harness = @import("harness");
const protocol = @import("protocol");
const replay = @import("replay.zig");

pub const suites = [_]harness.Suite{
    .{
        .name = "checkpoint-build",
        .lane = "val-checkpoints",
        .doc = "zui's checkpoint builder over the recorded effects of every corpus checkpoint produces the recorded contents and summary bytes and the recorded causal order",
        .run = runBuild,
    },
};

const State = struct { pv: []const u64 };

const max_blob = 1 << 30;

fn runBuild(ctx: *harness.Ctx) !void {
    var arena_state: std.heap.ArenaAllocator = .init(ctx.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const epochs = try harness.corpus_suite.loadEpochs(ctx, arena);
    const pv = try arena.alloc(u64, epochs.len);
    for (epochs, pv) |e, *p| p.* = e.pv;
    var st: State = .{ .pv = pv };
    try ctx.forEachFile("chk", ".chk", &st, buildFile);
}

fn buildFile(st: *State, ctx: *harness.Ctx, name: []const u8) !void {
    const item = name[0 .. name.len - ".chk".len];
    const seq = std.fmt.parseInt(u64, item, 10) catch return;
    if (seq == 0) return ctx.skip(item, "genesis checkpoint");
    const a = ctx.scratch();
    const blob = ctx.readFile(try std.fmt.allocPrint(a, "chk/{s}", .{name}), max_blob) catch |e| return ctx.fail(item, "read: {s}", .{@errorName(e)});
    const prev_blob = ctx.readFile(try std.fmt.allocPrint(a, "chk/{d}.chk", .{seq - 1}), max_blob) catch return ctx.skip(item, "previous checkpoint not in the corpus");
    const types = @import("types");
    const bcs = @import("bcs");
    if (blob.len == 0 or blob[0] != 1) return ctx.fail(item, "bad .chk blob (empty or unknown version)", .{});
    if (prev_blob.len == 0 or prev_blob[0] != 1) return ctx.fail(item, "bad previous .chk blob (empty or unknown version)", .{});
    const cp = bcs.decode(types.CheckpointData, a, blob[1..]) catch |e| return ctx.fail(item, "decode: {s}", .{@errorName(e)});
    const prev_cp = bcs.decode(types.CheckpointData, a, prev_blob[1..]) catch |e| return ctx.fail(item, "decode previous: {s}", .{@errorName(e)});
    const epoch = cp.checkpoint_summary.data.epoch;
    if (epoch >= st.pv.len) return ctx.skip(item, "epoch without a protocol version");
    const cfg = protocol.get(st.pv[epoch], .mainnet) catch return ctx.skip(item, "unsupported protocol version");
    const prev_bcs = try bcs.encodeAlloc(types.CheckpointSummary, a, &prev_cp.checkpoint_summary.data);
    const r = replay.replay(a, cfg, blob, prev_bcs) catch |e| return ctx.fail(item, "replay error {s}", .{@errorName(e)});
    switch (r) {
        .ok => ctx.pass(item),
        .skipped => |why| ctx.skip(item, why),
        .mismatch => |what| ctx.fail(item, "{s} differ from the recorded checkpoint", .{what}),
    }
}
