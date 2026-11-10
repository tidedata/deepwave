//! `google.protobuf.Value` trees as prost builds and encodes them (`prost_types::Value`):
//! `Struct.fields` is a `BTreeMap<String, Value>` (entries sorted by key bytes; inserting a key
//! again replaces the value), oneof `kind` members are always written (even 0, false, ""), map
//! entries skip a default key ("") as prost's btree_map encoder does.
const std = @import("std");
const Allocator = std.mem.Allocator;
const proto = @import("proto.zig");

pub const Value = union(enum) {
    null,
    number: f64,
    string: []const u8,
    bool: bool,
    @"struct": []const Entry,
    list: []const Value,
};

pub const Entry = struct { key: []const u8, value: Value };

/// `size_of::<prost_types::Value>()` on 64-bit targets: `Option<Kind>` where `Kind`'s largest
/// variants (String, Struct's BTreeMap, ListValue's Vec) are 24 bytes plus a tag.
pub const value_size: usize = 32;

/// Builder for a `Struct`: BTreeMap insert semantics (a repeated key replaces the value in its
/// slot), sorted on `finish`. Small structs scan linearly; past `index_after` entries a key ->
/// slot hash index takes over, so building is O(n log n) overall (on-chain Display templates can
/// build struct literals with ~16k fields).
pub const StructBuilder = struct {
    items: std.ArrayList(Entry) = .empty,
    index: std.StringHashMapUnmanaged(u32) = .empty,

    const index_after = 16;

    pub fn put(b: *StructBuilder, arena: Allocator, key: []const u8, v: Value) Allocator.Error!void {
        if (b.items.items.len < index_after) {
            for (b.items.items) |*e| if (std.mem.eql(u8, e.key, key)) {
                e.value = v;
                return;
            };
            try b.items.append(arena, .{ .key = key, .value = v });
            return;
        }
        if (b.index.count() == 0) {
            try b.index.ensureTotalCapacity(arena, @intCast(b.items.items.len * 2));
            for (b.items.items, 0..) |e, i| b.index.putAssumeCapacityNoClobber(e.key, @intCast(i));
        }
        const gop = try b.index.getOrPut(arena, key);
        if (gop.found_existing) {
            b.items.items[gop.value_ptr.*].value = v;
            return;
        }
        gop.value_ptr.* = @intCast(b.items.items.len);
        try b.items.append(arena, .{ .key = key, .value = v });
    }

    pub fn finish(b: *StructBuilder) []const Entry {
        std.mem.sort(Entry, b.items.items, {}, lessEntry);
        b.index = .empty; // slots are stale after the sort
        return b.items.items;
    }
};

fn lessEntry(_: void, a: Entry, b: Entry) bool {
    return std.mem.order(u8, a.key, b.key) == .lt;
}

/// Sorts entries in place (BTreeMap order). Callers that build without `StructBuilder` and know
/// the keys are unique use this.
pub fn sortEntries(es: []Entry) void {
    std.mem.sort(Entry, es, {}, lessEntry);
}

/// Writes `v` as message field `field` (a `google.protobuf.Value`).
pub fn write(w: *proto.Writer, field: u32, v: *const Value) proto.Error!void {
    const m = try w.begin(field, 16);
    try writeBody(w, v);
    try w.end(m);
}

/// Value body (its `kind` oneof member).
pub fn writeBody(w: *proto.Writer, v: *const Value) proto.Error!void {
    switch (v.*) {
        .null => try w.uint(1, 0),
        .number => |n| try w.fixed64(2, @bitCast(n)),
        .string => |s| try w.string(3, s),
        .bool => |b| try w.uint(4, @intFromBool(b)),
        .@"struct" => |es| {
            const m = try w.begin(5, 64);
            for (es) |*e| {
                const em = try w.begin(1, e.key.len + 16);
                if (e.key.len != 0) try w.string(1, e.key);
                try write(w, 2, &e.value);
                try w.end(em);
            }
            try w.end(m);
        },
        .list => |vs| {
            const m = try w.begin(6, 64);
            for (vs) |*x| try write(w, 1, x);
            try w.end(m);
        },
    }
}

test "StructBuilder: replace semantics past the index threshold, sorted output" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var b: StructBuilder = .{};
    const n = 5000;
    var i: usize = 0;
    while (i < n) : (i += 1) try b.put(a, try std.fmt.allocPrint(a, "k{d}", .{i}), .{ .number = @floatFromInt(i) });
    // replace early (pre-index) and late (indexed) keys
    try b.put(a, "k3", .{ .bool = true });
    try b.put(a, "k4999", .{ .bool = false });
    try b.put(a, "k0", .null);
    const es = b.finish();
    try std.testing.expectEqual(@as(usize, n), es.len);
    for (es[1..], es[0 .. es.len - 1]) |x, y| try std.testing.expect(std.mem.order(u8, y.key, x.key) == .lt);
    for (es) |e| {
        if (std.mem.eql(u8, e.key, "k3")) try std.testing.expect(e.value.bool);
        if (std.mem.eql(u8, e.key, "k4999")) try std.testing.expect(!e.value.bool);
        if (std.mem.eql(u8, e.key, "k0")) try std.testing.expect(e.value == .null);
        if (std.mem.eql(u8, e.key, "k10")) try std.testing.expectEqual(@as(f64, 10), e.value.number);
    }
}
