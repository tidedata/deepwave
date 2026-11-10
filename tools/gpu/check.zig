//! deepwave-gpu-check: GPU accelerator equality harness and bench.
//!   deepwave-gpu-check [--backend auto|metal|cuda] [--ed N] [--poseidon N] [--msm N] [--field N] [--bench N]
//!                 [--seed N] [--vectors DIR] [--calibrate] [--sweep] [--sweep-max N]
//! --calibrate times every path and installs the table; --sweep then shows every path against
//! the table's pick (auto). ZUI_SWEEP_THREADS sets the CPU pool lanes, ZUI_GPU_DEVICES caps devices.
//! Runs every operation on the GPU and on the CPU path and compares the outputs; exit 0 only if all
//! are identical. `--bench N` prints CPU against GPU time on batches of N.
const std = @import("std");
const gpu = @import("gpu");

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var mode: gpu.Mode = .auto;
    var cfg: gpu.check.Config = .{};
    var bench_n: usize = 0;
    var vec_dir: ?[]const u8 = null;
    var sweep = false;
    var calibrate = false;
    var sweep_max: usize = 16384;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--sweep")) {
            sweep = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--calibrate")) {
            calibrate = true;
            continue;
        }
        if (i + 1 >= args.len) {
            std.debug.print("{s} needs a value\n", .{a});
            return 2;
        }
        const v = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, a, "--backend")) {
            mode = gpu.Mode.parse(v) orelse {
                std.debug.print("backend: auto|metal|cuda\n", .{});
                return 2;
            };
        } else if (std.mem.eql(u8, a, "--vectors")) vec_dir = v else if (std.mem.eql(u8, a, "--ed")) cfg.ed_items = try std.fmt.parseInt(usize, v, 10) else if (std.mem.eql(u8, a, "--poseidon")) cfg.poseidon_items = try std.fmt.parseInt(usize, v, 10) else if (std.mem.eql(u8, a, "--msm")) cfg.msm_max = try std.fmt.parseInt(usize, v, 10) else if (std.mem.eql(u8, a, "--field")) cfg.field_items = try std.fmt.parseInt(usize, v, 10) else if (std.mem.eql(u8, a, "--seed")) cfg.seed = try std.fmt.parseInt(u64, v, 0) else if (std.mem.eql(u8, a, "--sweep-max")) sweep_max = try std.fmt.parseInt(usize, v, 10) else if (std.mem.eql(u8, a, "--bench")) bench_n = try std.fmt.parseInt(usize, v, 10) else {
            std.debug.print("unknown option {s}\n", .{a});
            return 2;
        }
    }
    // the shared CPU pool: GPU host prep and the pool columns of --sweep (ZUI_SWEEP_THREADS lanes)
    const pool = try gpu.core.pool.Pool.init(init.io, gpa, gpu.check.sweepThreads());
    defer pool.deinit();
    _ = gpu.core.pool.setShared(pool);
    defer _ = gpu.core.pool.setShared(null);
    var accel = gpu.Accel.init(gpa, mode);
    defer accel.deinit();
    if (!accel.active()) {
        std.debug.print("no usable GPU backend (mode {s})\n", .{@tagName(mode)});
        return 3;
    }
    accel.forceGpu();
    std.debug.print("backend: {s} ({s}), {d} device(s), pool {d} lanes\n", .{ @tagName(accel.kind), accel.name(), accel.deviceCount(), pool.lanes() });
    var rep: gpu.check.Report = .{};
    gpu.check.run(gpa, &accel, cfg, &rep) catch |e| {
        std.debug.print("check failed: {s}\n", .{@errorName(e)});
        return 1;
    };
    std.debug.print("checked {d}, mismatches {d}, gpu items {d}, cpu items {d}\n", .{ rep.checked, rep.mismatches, gpu.ops.Stats.get(&accel.stats.gpu_items), gpu.ops.Stats.get(&accel.stats.cpu_items) });
    if (vec_dir) |d| {
        var cnt: gpu.vectors.Counts = .{};
        gpu.vectors.run(gpa, init.io, &accel, d, &rep, &cnt) catch |e| {
            std.debug.print("vectors failed: {s}\n", .{@errorName(e)});
            return 1;
        };
        std.debug.print("vectors: ed25519 {d}, ed25519 batch {d}, poseidon {d}, groth16 msm {d}, groth16 pairing {d}; total mismatches {d}\n", .{ cnt.ed, cnt.ed_batch, cnt.pos, cnt.msm, cnt.pair, rep.mismatches });
    }
    accel.forced = null;
    if (calibrate) {
        const r = try gpu.calibrate.calibrate(gpa, &accel, .{ .max_size = sweep_max });
        accel.table = r.table;
        var buf: [16384]u8 = undefined;
        var w: std.Io.Writer = .fixed(&buf);
        try r.write(&w);
        std.debug.print("calibration ({d} ms):\n{s}", .{ r.elapsed_ms, w.buffered() });
    }
    if (sweep) _ = try gpu.check.sweep(gpa, &accel, sweep_max);
    accel.forceGpu();
    if (bench_n > 0) try gpu.check.bench(gpa, &accel, bench_n);
    return if (rep.mismatches == 0) 0 else 1;
}
