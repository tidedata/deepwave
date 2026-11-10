//! The x86-64 kernel tiers, shared by build.zig (which compiles one kernel object per tier) and
//! core/cpu.zig (which picks a tier at runtime). Each tier is an LLVM CPU model plus the extra
//! features the kernels use; a CPU runs a tier's object only if it has every listed feature.
const std = @import("std");
const x86 = std.Target.x86;

pub const Tier = enum(u8) {
    /// The build target as given (x86-64 v1 for a plain `-Dtarget=x86_64-linux-gnu`).
    baseline,
    /// x86-64-v3 (AVX2, BMI2, FMA, LZCNT, MOVBE) plus ADX, AES-NI and PCLMULQDQ.
    avx2,
    /// x86-64-v4 (AVX-512 F/BW/CD/DQ/VL) plus AVX-512 IFMA, ADX, AES-NI and PCLMULQDQ.
    avx512,
};

/// Tiers that get a kernel object, lowest first.
pub const kernel_tiers = [_]Tier{ .avx2, .avx512 };

pub const avx2_features = [_]x86.Feature{
    .avx2, .bmi,  .bmi2,   .fma, .lzcnt, .movbe, .f16c,   .popcnt, .sse4_2,
    .cx16, .sahf, .ssse3, .avx, .adx,   .aes,   .pclmul,
};
pub const avx512_features = avx2_features ++ [_]x86.Feature{
    .avx512f, .avx512bw, .avx512cd, .avx512dq, .avx512vl, .avx512ifma,
};

pub fn features(t: Tier) []const x86.Feature {
    return switch (t) {
        .baseline => &.{},
        .avx2 => &avx2_features,
        .avx512 => &avx512_features,
    };
}

pub fn model(t: Tier) *const std.Target.Cpu.Model {
    return switch (t) {
        .baseline => &x86.cpu.x86_64,
        .avx2 => &x86.cpu.x86_64_v3,
        .avx512 => &x86.cpu.x86_64_v4,
    };
}

/// The highest tier a compile-time feature set already covers.
pub fn ofFeatureSet(set: std.Target.Cpu.Feature.Set) Tier {
    var best: Tier = .baseline;
    for (kernel_tiers) |t| {
        var all = true;
        for (features(t)) |f| {
            if (!set.isEnabled(@intFromEnum(f))) all = false;
        }
        if (all) best = t;
    }
    return best;
}
