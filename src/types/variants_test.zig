//! Rust truth for the registry variants that no mainnet checkpoint in the corpus contains
//! (CORPUS truth/checkpoint/_unseen.json: 89 of them). testdata/variants_in.txt holds deepwave's
//! encoding of every variant of the 16 enums that have such variants (see roundtrip_test.zig);
//! testdata/variants_rust.txt is what Mysten's sui-types 1.83.1 / move-core-types answers
//! when it decodes the same bytes with the real type and re-encodes them
//! (tools/truth/bcs-types/edge <variants_in.txt>). Rust must accept every one and re-encode it
//! to the same bytes; deepwave must decode them and agree.
const std = @import("std");
const bcs = @import("bcs");
const gen = @import("gen.zig");
const rt = @import("roundtrip_test.zig");
const t = std.testing;

const rust = @embedFile("testdata/variants_rust.txt");

test "every variant of the unseen-variant enums matches Rust" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var seen = std.StringHashMap(void).init(a);
    var lines = std.mem.tokenizeScalar(u8, rust, '\n');
    var n: usize = 0;
    while (lines.next()) |line| {
        var f = std.mem.tokenizeScalar(u8, line, ' ');
        const name = f.next().?;
        const in_hex = f.next().?["in=".len..];
        try t.expectEqualStrings("ok", f.next().?);
        const re_hex = f.next().?["re=".len..];
        try t.expectEqualStrings(in_hex, re_hex);
        const input = try a.alloc(u8, in_hex.len / 2);
        _ = try std.fmt.hexToBytes(input, in_hex);
        const dot = std.mem.indexOfScalar(u8, name, '.').?;
        const ty = name[0..dot];
        try seen.put(try a.dupe(u8, name), {});
        var matched = false;
        inline for (rt.variant_enums) |en| {
            if (std.mem.eql(u8, ty, en)) {
                matched = true;
                const T = @field(gen, en);
                const v = bcs.decode(T, a, input) catch |e| {
                    std.debug.print("{s}: zui rejects ({s}), Rust accepts\n", .{ name, @errorName(e) });
                    return e;
                };
                try t.expectEqualSlices(u8, input, try bcs.encodeAlloc(T, a, &v));
            }
        }
        try t.expect(matched);
        n += 1;
    }
    // Every variant of every listed enum has at least one line.
    inline for (rt.variant_enums) |en| {
        const nv = @typeInfo(@field(gen, en)).@"union".field_names.len;
        for (0..nv) |k| {
            var key: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&key, "{s}.{d}", .{ en, k });
            if (!seen.contains(s)) {
                std.debug.print("missing variant {s}\n", .{s});
                return error.MissingVariant;
            }
        }
    }
    try t.expect(n >= 200);
}
