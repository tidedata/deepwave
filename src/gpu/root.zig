//! gpu: optional GPU accelerator. Apple Metal (unified memory) or NVIDIA CUDA
//! (NVRTC + driver API), both loaded at runtime; CPU fallback always. Off by default: nothing here
//! runs unless a caller builds an `Accel` with a mode other than `.off`.
//!   ops.zig      Accel: Ed25519 batch verify, Poseidon batch, BN254 G1 MSM, with CPU fallbacks
//!   backend.zig  Metal/CUDA behind one buffer + launch interface
//!   kernels.zig  the shared kernel source (shaders/*.inc)
//!   check.zig    GPU-vs-CPU equality harness and bench (also the gpu-equal conformance suite)
const std = @import("std");

pub const ops = @import("ops.zig");
pub const backend = @import("backend.zig");
pub const kernels = @import("kernels.zig");
pub const check = @import("check.zig");
pub const calibrate = @import("calibrate.zig");
pub const engine = @import("engine.zig");
pub const metal = @import("metal.zig");
pub const cuda = @import("cuda.zig");
pub const Accel = ops.Accel;
pub const Path = ops.Path;
pub const Mode = ops.Mode;
pub const core = @import("core");

/// The mode the environment asks for: ZUI_GPU=off|auto|metal|cuda (unset or unknown: off).
pub const modeFromEnv = @import("mode.zig").fromEnv;

pub const vectors = @import("vectors.zig");
pub const conformance = @import("conformance.zig");

test {
    std.testing.refAllDecls(@This());
}

test "gpu equality on whatever device is present" {
    var accel = Accel.init(std.testing.allocator, modeFromEnv());
    defer accel.deinit();
    if (!accel.active()) return error.SkipZigTest;
    accel.forceGpu();
    var rep: check.Report = .{};
    try check.run(std.testing.allocator, &accel, .{ .ed_items = 64, .poseidon_items = 32, .msm_max = 40, .field_items = 64 }, &rep);
    try std.testing.expectEqual(@as(u64, 0), rep.mismatches);
}
