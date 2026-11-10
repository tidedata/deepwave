//! Wrapper types with hooks: Bytes, String, Map. See codec.zig for the hook protocol.
const std = @import("std");
const Allocator = std.mem.Allocator;
const io = @import("io.zig");
const codec = @import("codec.zig");
const Reader = io.Reader;

/// serde_bytes / `Bytes`: a byte string. As a newtype it counts as a container for depth.
pub const Bytes = struct {
    @"0": []const u8,
    pub const bcs_newtype = true;
};

/// UTF-8 checked string (Rust `String`, `&str`). Not a container for depth.
pub const String = struct {
    @"0": []const u8,
    pub const bcs_min_wire = 1;
    pub const bcs_string = true;

    pub fn bcsDecode(arena: Allocator, r: *Reader) codec.DecodeError!String {
        _ = arena;
        return .{ .@"0" = try readStr(r) };
    }
    pub fn bcsSkip(r: *Reader) io.Error!void {
        _ = try readStr(r);
    }
    pub fn bcsEncode(self: *const String, w: anytype) codec.EncodeError!void {
        try w.uleb32(@intCast(self.@"0".len));
        try w.bytes(self.@"0");
    }
    pub fn str(self: String) []const u8 {
        return self.@"0";
    }
};

pub fn readStr(r: *Reader) io.Error![]const u8 {
    const n = try r.length();
    const s = try r.bytes(n);
    if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
    return s;
}

/// BTreeMap<K, V>: entries must be strictly increasing by serialized key bytes (bcs rule).
pub fn Map(comptime K: type, comptime V: type) type {
    return struct {
        entries: []const Entry,
        const Self = @This();
        pub const Entry = struct { key: K, value: V };
        pub const bcs_map = true;
        pub const bcs_min_wire = 1;

        pub fn bcsDecode(arena: Allocator, r: *Reader) codec.DecodeError!Self {
            const n = try r.length();
            const min = comptime codec.minWire(K) + codec.minWire(V);
            if (min > 0 and n > r.remaining() / min) {
                var i: usize = 0;
                var prev: ?[]const u8 = null;
                while (i < n) : (i += 1) {
                    const s = r.at;
                    try codec.skip(K, r);
                    const kb = r.buf[s..r.at];
                    if (prev) |p| if (std.mem.order(u8, p, kb) != .lt) return error.NonCanonical;
                    prev = kb;
                    try codec.skip(V, r);
                }
                return error.EndOfInput;
            }
            const out = try arena.alloc(Entry, n);
            var prev: ?[]const u8 = null;
            for (out) |*e| {
                const s = r.at;
                e.key = try codec.decodeFrom(K, arena, r);
                const kb = r.buf[s..r.at];
                if (prev) |p| if (std.mem.order(u8, p, kb) != .lt) return error.NonCanonical;
                prev = kb;
                e.value = try codec.decodeFrom(V, arena, r);
            }
            return .{ .entries = out };
        }
        /// Builds a map from entries in any order: sorts them by serialized key bytes (the
        /// canonical BCS order) and fails with `NonCanonical` on a duplicate key, the way
        /// `BTreeMap` collapses nothing and the wire format forbids repeats. Allocates the entry
        /// array and the temporary key encodings from `arena`.
        pub fn fromUnsorted(arena: Allocator, items: []const Entry) codec.DecodeError!Self {
            const Keyed = struct { kb: []const u8, e: Entry };
            const tmp = try arena.alloc(Keyed, items.len);
            for (items, tmp) |e, *k| k.* = .{ .kb = try codec.encodeAlloc(K, arena, &e.key), .e = e };
            std.mem.sort(Keyed, tmp, {}, struct {
                fn lt(_: void, x: Keyed, y: Keyed) bool {
                    return std.mem.order(u8, x.kb, y.kb) == .lt;
                }
            }.lt);
            const out = try arena.alloc(Entry, items.len);
            for (tmp, 0..) |k, i| {
                if (i > 0 and std.mem.eql(u8, tmp[i - 1].kb, k.kb)) return error.NonCanonical;
                out[i] = k.e;
            }
            return .{ .entries = out };
        }
        pub fn bcsSkip(r: *Reader) io.Error!void {
            const n = try r.length();
            var i: usize = 0;
            var prev: ?[]const u8 = null;
            while (i < n) : (i += 1) {
                const s = r.at;
                try codec.skip(K, r);
                const kb = r.buf[s..r.at];
                if (prev) |p| if (std.mem.order(u8, p, kb) != .lt) return error.NonCanonical;
                prev = kb;
                try codec.skip(V, r);
            }
        }
        pub fn bcsEncode(self: *const Self, w: anytype) codec.EncodeError!void {
            try w.uleb32(@intCast(self.entries.len));
            for (self.entries) |*e| {
                try codec.encode(K, &e.key, w);
                try codec.encode(V, &e.value, w);
            }
        }
    };
}

/// Rust `Ord` of a map key type, which decides the order serde (and so the tree text) walks a
/// BTreeMap in; the wire order is different (sorted by serialized bytes, length first).
pub fn keyLess(comptime K: type, a: *const K, b: *const K) bool {
    switch (@typeInfo(K)) {
        .int => return a.* < b.*,
        .array => |ar| {
            if (ar.child == u8) return std.mem.order(u8, a, b) == .lt;
            for (a, b) |*x, *y| {
                if (keyLess(ar.child, x, y)) return true;
                if (keyLess(ar.child, y, x)) return false;
            }
            return false;
        },
        .pointer => |p| {
            if (p.size == .slice and p.child == u8) return std.mem.order(u8, a.*, b.*) == .lt;
            @compileError("keyLess: unsupported key " ++ @typeName(K));
        },
        .@"struct" => |st| {
            if (@hasDecl(K, "bcs_string")) return std.mem.order(u8, a.@"0", b.@"0") == .lt;
            if (@hasDecl(K, "bcs_byte_array")) return std.mem.order(u8, &a.@"0", &b.@"0") == .lt;
            inline for (st.field_names, st.field_types) |n, ft| {
                if (keyLess(ft, &@field(a.*, n), &@field(b.*, n))) return true;
                if (keyLess(ft, &@field(b.*, n), &@field(a.*, n))) return false;
            }
            return false;
        },
        else => @compileError("keyLess: unsupported key " ++ @typeName(K)),
    }
}
