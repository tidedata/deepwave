//! CRC-32C (Castagnoli), the snappy framing checksum. Hardware instruction when the build target
//! has it (aarch64 `crc`, x86 SSE4.2) through the LLVM intrinsics, else slicing-by-8.
const std = @import("std");
const builtin = @import("builtin");

/// The x86 path is written but not enabled: it has not run on x86 hardware yet (no Rosetta on the
/// dev Mac). Flip `x86_verified` after `zig test -mcpu=x86_64_v2` passes on an x86_64 box.
const x86_verified = false;
const has_hw = switch (builtin.cpu.arch) {
    .aarch64 => std.Target.aarch64.featureSetHas(builtin.cpu.features, .crc),
    .x86_64 => x86_verified and std.Target.x86.featureSetHas(builtin.cpu.features, .sse4_2),
    else => false,
};

extern fn @"llvm.aarch64.crc32cx"(u32, u64) u32;
extern fn @"llvm.aarch64.crc32cb"(u32, u32) u32;
extern fn @"llvm.x86.sse42.crc32.64.64"(u64, u64) u64;
extern fn @"llvm.x86.sse42.crc32.32.8"(u32, u8) u32;

const poly: u32 = 0x82F63B78;

const tables: [8][256]u32 = blk: {
    @setEvalBranchQuota(100_000);
    var t: [8][256]u32 = undefined;
    for (0..256) |i| {
        var c: u32 = @intCast(i);
        for (0..8) |_| c = if (c & 1 != 0) (c >> 1) ^ poly else c >> 1;
        t[0][i] = c;
    }
    for (0..256) |i| {
        var c = t[0][i];
        for (1..8) |k| {
            c = t[0][c & 0xff] ^ (c >> 8);
            t[k][i] = c;
        }
    }
    break :blk t;
};

fn soft(crc_in: u32, data: []const u8) u32 {
    var crc = crc_in;
    var p = data;
    while (p.len >= 8) {
        const w = std.mem.readInt(u64, p[0..8], .little) ^ crc;
        crc = tables[7][w & 0xff] ^ tables[6][(w >> 8) & 0xff] ^ tables[5][(w >> 16) & 0xff] ^ tables[4][(w >> 24) & 0xff] ^
            tables[3][(w >> 32) & 0xff] ^ tables[2][(w >> 40) & 0xff] ^ tables[1][(w >> 48) & 0xff] ^ tables[0][w >> 56];
        p = p[8..];
    }
    for (p) |b| crc = tables[0][(crc ^ b) & 0xff] ^ (crc >> 8);
    return crc;
}

fn hard(crc_in: u32, data: []const u8) u32 {
    var crc = crc_in;
    var p = data;
    switch (builtin.cpu.arch) {
        .aarch64 => {
            while (p.len >= 8) : (p = p[8..]) crc = @"llvm.aarch64.crc32cx"(crc, std.mem.readInt(u64, p[0..8], .little));
            for (p) |b| crc = @"llvm.aarch64.crc32cb"(crc, b);
        },
        .x86_64 => {
            var c: u64 = crc;
            while (p.len >= 8) : (p = p[8..]) c = @"llvm.x86.sse42.crc32.64.64"(c, std.mem.readInt(u64, p[0..8], .little));
            crc = @truncate(c);
            for (p) |b| crc = @"llvm.x86.sse42.crc32.32.8"(crc, b);
        },
        else => unreachable,
    }
    return crc;
}

/// CRC-32C of `data` (initial 0xFFFFFFFF, final xor, reflected: the iSCSI/Castagnoli CRC).
pub fn crc32c(data: []const u8) u32 {
    return ~(if (has_hw) hard(0xFFFFFFFF, data) else soft(0xFFFFFFFF, data));
}

pub fn crc32cSoftware(data: []const u8) u32 {
    return ~soft(0xFFFFFFFF, data);
}

test "check value" {
    try std.testing.expectEqual(@as(u32, 0xE3069283), crc32c("123456789"));
    try std.testing.expectEqual(@as(u32, 0xE3069283), crc32cSoftware("123456789"));
    var buf: [1000]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i *% 7);
    for (0..40) |n| try std.testing.expectEqual(crc32cSoftware(buf[n..]), crc32c(buf[n..]));
    try std.testing.expectEqual(std.hash.crc.@"CRC-32/ISCSI".hash(&buf), crc32c(&buf));
}
