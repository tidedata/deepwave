const std = @import("std");
const bcs = @import("root.zig");
const t = std.testing;

const Inner = struct { a: u16, b: ?u8 };
const E = union(enum) { x, y: u32, z: Inner, w: struct { u8, bool } };
const S = struct { n: u64, s: bcs.String, v: []const Inner, e: E, big: u128, arr: [3]u8, blob: []const u8 };

fn sample(arena: std.mem.Allocator) !S {
    const v = try arena.alloc(Inner, 2);
    v[0] = .{ .a = 1, .b = null };
    v[1] = .{ .a = 65535, .b = 7 };
    return .{ .n = 1, .s = .{ .@"0" = "h\"i\n" }, .v = v, .e = .{ .z = .{ .a = 3, .b = 4 } }, .big = 1 << 100, .arr = .{ 1, 2, 3 }, .blob = &.{ 0xde, 0xad } };
}

test "round trip, length, tree, view" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const s = try sample(arena);
    const enc = try bcs.encodeAlloc(S, t.allocator, &s);
    defer t.allocator.free(enc);
    try t.expectEqual(enc.len, bcs.encodedLen(S, &s));
    const d = try bcs.decode(S, arena, enc);
    const enc2 = try bcs.encodeAlloc(S, t.allocator, &d);
    defer t.allocator.free(enc2);
    try t.expectEqualSlices(u8, enc, enc2);
    const txt = try bcs.tree.renderAlloc(S, t.allocator, &d);
    defer t.allocator.free(txt);
    try t.expectEqualStrings(
        "{\"n\":1,\"s\":\"h\\\"i\\n\",\"v\":[{\"a\":1,\"b\":null},{\"a\":65535,\"b\":7}],\"e\":{\"z\":{\"a\":3,\"b\":4}},\"big\":\"1267650600228229401496703205376\",\"arr\":\"0x010203\",\"blob\":\"0xdead\"}",
        txt,
    );
    const v = try bcs.View(S).init(enc);
    try t.expectEqual(@as(usize, 2), v.field("v").len());
    var it = v.field("v").iter();
    _ = it.next();
    try t.expectEqual(@as(u32, 1), v.field("e").tag() - 1 + 1 - 1 + 1 - 1);
    try t.expectEqualSlices(u8, &.{ 0xde, 0xad }, v.field("blob").raw());
}

test "errors" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try t.expectError(error.InvalidBool, bcs.decode(bool, a, &.{2}));
    try t.expectError(error.TrailingBytes, bcs.decode(u8, a, &.{ 2, 3 }));
    try t.expectError(error.EndOfInput, bcs.decode(u32, a, &.{ 2, 3 }));
    try t.expectError(error.InvalidEnumTag, bcs.decode(E, a, &.{9}));
    try t.expectError(error.InvalidEnumTag, bcs.decode(?u8, a, &.{2}));
    try t.expectError(error.InvalidUtf8, bcs.decode(bcs.String, a, &.{ 1, 0xff }));
    try t.expectError(error.LengthTooLarge, bcs.decode([]const u8, a, &.{ 0x80, 0x80, 0x80, 0x80, 0x08 }));
    const M = bcs.Map(u8, u8);
    try t.expectError(error.NonCanonical, bcs.decode(M, a, &.{ 2, 5, 0, 5, 1 }));
}

test "depth" {
    const L = union(enum) { nil, cons: *const @This() };
    var buf: [1200]u8 = undefined;
    var i: usize = 0;
    while (i < 499) : (i += 1) buf[i] = 1;
    buf[499] = 0;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    _ = try bcs.decode(L, arena_state.allocator(), buf[0..500]);
    i = 0;
    while (i < 500) : (i += 1) buf[i] = 1;
    buf[500] = 0;
    try t.expectError(error.DepthExceeded, bcs.decode(L, arena_state.allocator(), buf[0..501]));
}

test "writer reports NoSpace and counts exactly" {
    var buf: [3]u8 = undefined;
    var w = bcs.Writer.init(&buf);
    try w.uleb32(300);
    try t.expectError(error.NoSpace, w.int(u16, 1));
    try w.int(u8, 7);
    try t.expectEqualSlices(u8, &.{ 0xac, 0x02, 7 }, w.written());
}

test "u256, u128 and signed round trip" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const v: u256 = (@as(u256, 1) << 255) | 12345;
    const enc = try bcs.encodeAlloc(u256, a, &v);
    try t.expectEqual(@as(usize, 32), enc.len);
    try t.expectEqual(v, try bcs.decode(u256, a, enc));
    const s: i32 = -2;
    const e2 = try bcs.encodeAlloc(i32, a, &s);
    try t.expectEqualSlices(u8, &.{ 0xfe, 0xff, 0xff, 0xff }, e2);
    try t.expectEqual(s, try bcs.decode(i32, a, e2));
}

test "huge declared length does not allocate" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    // 2^31 - 1 elements claimed, 2 bytes of input: must fail with EndOfInput, not allocate.
    try t.expectError(error.EndOfInput, bcs.decode([]const u32, arena_state.allocator(), &.{ 0xff, 0xff, 0xff, 0xff, 0x07, 1, 2 }));
}

test "trusted view walk equals validating skip at every field" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const s = try sample(arena);
    const enc = try bcs.encodeAlloc(S, arena, &s);
    const v = try bcs.View(S).init(enc);
    inline for (.{ "n", "s", "v", "e", "big", "arr", "blob" }) |f| {
        const fv = v.field(f);
        var r = bcs.Reader.init(fv.bytes);
        try bcs.skip(@TypeOf(fv).Type, &r);
        try r.finish();
    }
    const e = v.field("e").payload("z").?;
    try t.expectEqual(@as(u16, 3), std.mem.readInt(u16, e.field("a").bytes[0..2], .little));
    try t.expect(v.field("e").payload("y") == null);
    var it = v.field("v").iter();
    try t.expect(it.next().?.field("b").some() == null);
    try t.expectEqual(@as(u8, 7), it.next().?.field("b").some().?.bytes[0]);
}

test "Map.fromUnsorted sorts by key bytes and rejects duplicates" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const M = bcs.Map(u16, u8);
    const m = try M.fromUnsorted(arena, &.{ .{ .key = 0x0102, .value = 1 }, .{ .key = 0x0300, .value = 2 }, .{ .key = 5, .value = 3 } });
    // little-endian key bytes: 05 00 < 00 03 is false (05 > 00): wire order is 00 03, 02 01, 05 00
    try t.expectEqual(@as(u16, 0x0300), m.entries[0].key);
    try t.expectEqual(@as(u16, 0x0102), m.entries[1].key);
    try t.expectEqual(@as(u16, 5), m.entries[2].key);
    const enc = try bcs.encodeAlloc(M, arena, &m);
    _ = try bcs.decode(M, arena, enc);
    try t.expectError(error.NonCanonical, M.fromUnsorted(arena, &.{ .{ .key = 1, .value = 1 }, .{ .key = 1, .value = 2 } }));
}
