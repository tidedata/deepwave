//! Unit-test helpers shared by every lane (CONTRACTS.md section 3). Conformance against
//! Mysten ground truth goes through the `harness` module, not through these.
const std = @import("std");
const hex = @import("hex.zig");

/// Compares bytes and, on mismatch, prints both sides as hex with the first differing offset.
pub fn expectBytes(expected: []const u8, actual: []const u8) !void {
    if (std.mem.eql(u8, expected, actual)) return;
    const n = @min(expected.len, actual.len);
    var first: usize = n;
    for (0..n) |i| if (expected[i] != actual[i]) {
        first = i;
        break;
    };
    std.debug.print("bytes differ at offset {d} (expected len {d}, actual len {d})\n", .{ first, expected.len, actual.len });
    std.debug.print("  expected: {x}\n  actual:   {x}\n", .{ expected, actual });
    return error.TestExpectedEqual;
}

/// Asserts `actual` equals the hex string `expected_hex`.
pub fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    const want = try hex.decodeAlloc(std.testing.allocator, expected_hex);
    defer std.testing.allocator.free(want);
    try expectBytes(want, actual);
}

/// A deterministic PRNG for property tests and simulations. Seed comes from the test name
/// unless ZUI_SEED overrides it at the harness level, so failures always reproduce.
pub fn prng(comptime name: []const u8) std.Random.DefaultPrng {
    return std.Random.DefaultPrng.init(std.hash.Wyhash.hash(0, name));
}

test "expectHex" {
    try expectHex("0x0102", &.{ 1, 2 });
}
