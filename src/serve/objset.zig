//! Per-request index of the objects a response may refer to: (id, version) -> BCS(Object).
//! Used for `annotate_effects` (object types of changed and unchanged consensus objects) and for
//! balance changes. Types are decoded lazily, once per lookup.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const typestr = @import("typestr.zig");

pub const Key = [40]u8; // object id ++ version (little endian)

pub fn key(id: *const [32]u8, version: u64) Key {
    var k: Key = undefined;
    @memcpy(k[0..32], id);
    std.mem.writeInt(u64, k[32..40], version, .little);
    return k;
}

/// ObjectReference-like key (`ObjectKey` in sui-types storage).
pub const Ref = struct { id: [32]u8, version: u64 };

/// Object ids are hashes: the first and last bytes of the key (id head, version low bytes)
/// are already well mixed.
pub const KeyContext = struct {
    pub fn hash(_: KeyContext, k: Key) u64 {
        const a = std.mem.readInt(u64, k[0..8], .little);
        const v = std.mem.readInt(u64, k[32..40], .little);
        return (a ^ (v *% 0x9e3779b97f4a7c15)) *% 0xff51afd7ed558ccd;
    }
    pub fn eql(_: KeyContext, a: Key, b: Key) bool {
        return std.mem.eql(u8, &a, &b);
    }
};

pub const Map = std.HashMapUnmanaged(Key, []const u8, KeyContext, 80);

pub const ObjSet = struct {
    map: Map = .empty,
    /// Type strings by the BCS bytes of the object's MoveObjectType: most objects share a few
    /// types, so the decode and the formatting happen once per type.
    types: std.StringHashMapUnmanaged([]const u8) = .empty,

    /// Indexes the raw BCS objects (any order, repeats allowed). Reads only the header: the
    /// object id sits at a fixed place in a Move object, packages are told apart by variant.
    pub fn build(arena: Allocator, raws: []const []const u8) (Allocator.Error || error{InvalidValue})!ObjSet {
        var s: ObjSet = .{};
        try s.map.ensureTotalCapacity(arena, @intCast(raws.len));
        for (raws) |raw| {
            const k = headKey(raw) catch return error.InvalidValue;
            s.map.putAssumeCapacity(k, raw);
        }
        return s;
    }

    pub fn get(s: *const ObjSet, id: *const [32]u8, version: u64) ?[]const u8 {
        return s.map.get(key(id, version));
    }

    /// `object_type_to_string` of the object at (id, version): "package" or the canonical struct
    /// tag. Null when the object is not in the set.
    pub fn typeString(s: *ObjSet, arena: Allocator, id: *const [32]u8, version: u64) !?[]const u8 {
        const raw = s.get(id, version) orelse return null;
        // Object { data: Data, ... }; Data::Move = 0, Data::Package = 1.
        if (raw.len > 0 and raw[0] == 1) return "package";
        const end = typeEnd(raw) catch return error.InvalidValue;
        const tb = raw[1..end];
        if (s.types.get(tb)) |hit| return hit;
        const obj = try bcs.decode(types.Object, arena, raw);
        const str = switch (obj.data) {
            .Package => "package",
            .Move => |mo| blk: {
                var o = typestr.scratch();
                try typestr.moveObjectType(&o, mo.type_);
                break :blk try arena.dupe(u8, o.str());
            },
        };
        try s.types.put(arena, tb, str);
        return str;
    }
};

/// Offset just past the MoveObjectType of a Move object's BCS.
fn typeEnd(raw: []const u8) HErr!usize {
    if (raw.len < 2 or raw[0] != 0) return error.BadTag;
    return switch (raw[1]) {
        0 => try skipStructTag(raw, 2),
        1, 2, 4 => 2,
        3, 5 => try skipTypeTag(raw, 2, 0),
        else => error.BadTag,
    };
}

/// (id, version) of BCS(Object) read from the head, without decoding the type.
pub fn headKey(raw: []const u8) HErr!Key {
    if (raw.len < 1) return error.Truncated;
    var p: usize = 1;
    switch (raw[0]) {
        1 => {
            if (raw.len < 41) return error.Truncated;
            return key(raw[1..33], std.mem.readInt(u64, raw[33..41], .little));
        },
        0 => {
            if (raw.len < 2) return error.Truncated;
            const tag = raw[1];
            p = 2;
            switch (tag) {
                0 => p = try skipStructTag(raw, p),
                1, 2, 4 => {},
                3, 5 => p = try skipTypeTag(raw, p, 0),
                else => return error.BadTag,
            }
            if (p + 9 > raw.len) return error.Truncated;
            const version = std.mem.readInt(u64, raw[p + 1 ..][0..8], .little);
            p += 9;
            // contents: ULEB length, then the bytes; the object id is the first 32 of them
            var len: u64 = 0;
            var shift: u6 = 0;
            while (true) {
                if (p >= raw.len or shift > 28) return error.Truncated;
                const b = raw[p];
                p += 1;
                len |= @as(u64, b & 0x7f) << shift;
                if (b & 0x80 == 0) break;
                shift += 7;
            }
            if (len < 32 or p + 32 > raw.len) return error.Truncated;
            return key(raw[p..][0..32], version);
        },
        else => return error.BadTag,
    }
}

fn uleb(raw: []const u8, p: *usize) HErr!u64 {
    var len: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (p.* >= raw.len or shift > 28) return error.Truncated;
        const b = raw[p.*];
        p.* += 1;
        len |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return len;
        shift += 7;
    }
}

const HErr = error{ Truncated, BadTag };

fn skipStructTag(raw: []const u8, start: usize) HErr!usize {
    var p = start + 32;
    for (0..2) |_| {
        const n = try uleb(raw, &p);
        p += n;
    }
    const n_args = try uleb(raw, &p);
    for (0..n_args) |_| p = try skipTypeTag(raw, p, 0);
    if (p > raw.len) return error.Truncated;
    return p;
}

fn skipTypeTag(raw: []const u8, start: usize, depth: u32) HErr!usize {
    if (depth > 64 or start >= raw.len) return error.Truncated;
    const tag = raw[start];
    const p = start + 1;
    return switch (tag) {
        0, 1, 2, 3, 4, 5, 8, 9, 10 => p,
        6 => try skipTypeTag(raw, p, depth + 1),
        7 => try skipStructTag(raw, p),
        else => error.BadTag,
    };
}
