//! The GPU kernel source: one C-like dialect shared by Metal (MSL, compiled at runtime by the Metal
//! driver) and CUDA (NVRTC, compiled at runtime, loaded as PTX). The field code is written once as
//! macro-instantiated text (shaders/mont.inc for the two BN254 fields); only the prelude (types and
//! address-space macros) and the entry points differ per backend.
const std = @import("std");
const zk = @import("zk");
const bn = zk.bn254;

pub const Kernel = enum(u8) {
    selftest,
    ed25519,
    poseidon,
    g1_mul,
    g1_add_pairs,

    pub fn entry(k: Kernel) [:0]const u8 {
        return switch (k) {
            .selftest => "selftest_k",
            .ed25519 => "ed25519_k",
            .poseidon => "poseidon_k",
            .g1_mul => "g1_mul_k",
            .g1_add_pairs => "g1_add_pairs_k",
        };
    }

    /// Threads per block / threadgroup.
    pub fn blockSize(k: Kernel) usize {
        return switch (k) {
            .ed25519 => 64,
            else => 64,
        };
    }
};
pub const kernel_count = std.meta.fieldNames(Kernel).len;

fn limbsText(comptime name: []const u8, comptime limbs: [4]u64) []const u8 {
    comptime {
        var s: []const u8 = "CONSTANT u32 " ++ name ++ "[8] = {";
        for (limbs) |l| s = s ++ std.fmt.comptimePrint("{d}u, {d}u, ", .{ @as(u32, @truncate(l)), @as(u32, @truncate(l >> 32)) });
        return s ++ "};\n";
    }
}

fn instance(comptime prefix: []const u8, comptime F: type) []const u8 {
    comptime {
        return "#define MN(x) " ++ prefix ++ "_##x\n" ++
            std.fmt.comptimePrint("#define NINV {d}u\n", .{@as(u32, @truncate(F.inv))}) ++
            limbsText(prefix ++ "_P", F.p) ++ limbsText(prefix ++ "_ONE", F.one.l) ++
            @embedFile("shaders/mont.inc") ++ "#undef MN\n#undef NINV\n";
    }
}

const common = instance("fr", bn.Fr) ++ instance("fq", bn.Fq) ++
    @embedFile("shaders/g1.inc") ++ @embedFile("shaders/poseidon.inc") ++ @embedFile("shaders/ed25519.inc") ++ @embedFile("shaders/body.inc");

pub const metal_source: [:0]const u8 = @embedFile("shaders/prelude_metal.inc") ++ common ++ @embedFile("shaders/entry_metal.inc");
pub const cuda_source: [:0]const u8 = @embedFile("shaders/prelude_cuda.inc") ++ common ++ @embedFile("shaders/entry_cuda.inc");
