//! Data Independent Timing (Arm FEAT_DIT) around secret-key operations.
//!
//! The signing paths are written constant time (no secret-dependent branches or indices), but on
//! Apple M-series cores the timing of ordinary instructions can still depend on the data they
//! touch unless PSTATE.DIT is set (Apple's guidance for cryptographic code; with DIT clear the
//! dudect tests in ed25519.zig and ecvrf.zig measured |t| up to 118 on an M5 Pro, with DIT set
//! all stayed below 10). `Guard.enter` sets DIT and `leave` restores the caller's value.
//!
//! The instruction is emitted only when the comptime target has FEAT_DIT (Armv8.4+, every
//! Apple M core); on any other target both calls compile to nothing.
const std = @import("std");
const builtin = @import("builtin");

pub const available = builtin.cpu.arch == .aarch64 and
    std.Target.aarch64.featureSetHas(builtin.cpu.features, .dit);

pub const Guard = struct {
    was_set: bool,

    pub inline fn enter() Guard {
        if (comptime !available) return .{ .was_set = false };
        const prev = asm volatile ("mrs %[r], dit"
            : [r] "=r" (-> u64),
        );
        asm volatile ("msr dit, #1" ::: .{ .memory = true });
        return .{ .was_set = prev != 0 };
    }

    pub inline fn leave(g: Guard) void {
        if (comptime !available) return;
        if (!g.was_set) asm volatile ("msr dit, #0" ::: .{ .memory = true });
    }
};

test "DIT guard sets and restores the flag" {
    if (comptime !available) return error.SkipZigTest;
    const read = struct {
        fn f() u64 {
            return asm volatile ("mrs %[r], dit"
                : [r] "=r" (-> u64),
            );
        }
    }.f;
    const before = read();
    const g = Guard.enter();
    try std.testing.expect(read() != 0);
    g.leave();
    try std.testing.expectEqual(before, read());
}
