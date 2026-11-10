//! Conformance suite of the gpu lane: the accelerator's outputs equal the CPU path's on the same
//! inputs (no corpus needed). Skipped, not failed, on a machine with no usable GPU. Opt in with
//! ZUI_GPU=auto|metal|cuda; unset or off skips the suite.
const std = @import("std");
const harness = @import("harness");
const ops = @import("ops.zig");
const check = @import("check.zig");
const gpu_mode = @import("mode.zig");
const engine = @import("engine.zig");
const sig = @import("sig");
const core = @import("core");

pub const suites = [_]harness.Suite{
    .{ .name = "gpu-equal", .lane = "gpu", .doc = "GPU Ed25519 batch verify, Poseidon and BN254 G1 MSM equal the CPU path (skips with no GPU)", .run = runEqual },
    .{ .name = "sig-corpus-gpu", .lane = "gpu", .doc = "sig-corpus (same items, same Rust truth) with every user signature and transaction checked through sig.batch on the GPU engine (ZUI_GPU=auto|metal|cuda; Ed25519 leaves forced to the GPU unless ZUI_SIG_GPU_PATH=table)", .run = runCorpusGpu },
    .{ .name = "sig-vectors-gpu", .lane = "gpu", .doc = "sig-vectors (same items, same Rust truth) with Ed25519 verify, user_sig and user_tx checked through sig.batch on the GPU engine (as sig-corpus-gpu)", .run = runVectorsGpu },
};

fn runCorpusGpu(ctx: *harness.Ctx) !void {
    return withGpuEngine(ctx, sig.conformance.runCorpus);
}

fn runVectorsGpu(ctx: *harness.Ctx) !void {
    return withGpuEngine(ctx, sig.conformance.runVectors);
}

/// Installs the signature engine on the GPU (self-check included), points sig.batch at it and
/// runs the sig suite's own code over its own items.
fn withGpuEngine(ctx: *harness.Ctx, comptime run: fn (*harness.Ctx) anyerror!void) !void {
    const mode = gpu_mode.fromEnv();
    if (mode == .off) {
        ctx.skip(ctx.suite.name, "ZUI_GPU not set (off by default)");
        return;
    }
    const table = if (std.c.getenv("ZUI_SIG_GPU_PATH")) |v| std.mem.eql(u8, std.mem.span(v), "table") else false;
    const e = engine.install(ctx.io, std.heap.page_allocator, .{ .parallel = .on, .gpu = mode, .force = if (table) null else core.dispatch.Path.gpu(ops.max_devices), .caches = false, .log = false }) orelse return error.OutOfMemory;
    defer engine.uninstall();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    e.describe(&w) catch {};
    ctx.stderr.print("{s}: {s}\n", .{ ctx.suite.name, w.buffered() }) catch {};
    if (!e.gpuEd25519()) {
        ctx.skip(ctx.suite.name, "no GPU that passed the Ed25519 self-check");
        return;
    }
    const g0 = ops.Stats.get(&e.accel.stats.gpu_items);
    sig.conformance.forced_path = .accel;
    defer sig.conformance.forced_path = null;
    try run(ctx);
    ctx.stderr.print("{s}: {d} Ed25519 leaves answered by the GPU, {d} canary trips, {d} GPU fallbacks\n", .{ ctx.suite.name, ops.Stats.get(&e.accel.stats.gpu_items) - g0, e.accel.canary_trips.load(.monotonic), ops.Stats.get(&e.accel.stats.fallbacks) }) catch {};
    if (e.accel.canary_trips.load(.monotonic) != 0) return error.GpuCanaryTripped;
}

fn runEqual(ctx: *harness.Ctx) !void {
    const gpa = std.heap.page_allocator;
    // Opt in: nothing opens a GPU unless ZUI_GPU asks for one (off or unset: skipped).
    const mode = gpu_mode.fromEnv();
    if (mode == .off) {
        ctx.skip("gpu-equal", "ZUI_GPU not set (off by default)");
        return;
    }
    var accel = ops.Accel.init(gpa, mode);
    defer accel.deinit();
    if (!accel.active()) {
        ctx.skip("gpu-equal", "no usable GPU backend");
        return;
    }
    accel.forceGpu();
    var rep: check.Report = .{};
    try check.run(gpa, &accel, .{}, &rep);
    if (rep.mismatches == 0) ctx.pass("gpu-equal") else ctx.fail("gpu-equal", "{d} mismatches in {d} checks on {s}", .{ rep.mismatches, rep.checked, accel.name() });
}
