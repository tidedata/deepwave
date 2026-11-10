//! Zero-copy views: validate once with `init`, then reach any field by walking the bytes of the
//! preceding fields (no allocation, nothing is copied). A view never outlives its bytes.
const std = @import("std");
const codec = @import("codec.zig");
const io = @import("io.zig");
const meta = @import("meta.zig");
const Reader = io.Reader;

pub fn View(comptime T: type) type {
    return struct {
        /// Exactly the encoding of one T. Validated by `init`/`take`; do not build by hand.
        bytes: []const u8,
        const Self = @This();
        pub const Type = T;

        /// Validates `bytes` as exactly one T.
        pub fn init(bytes: []const u8) io.Error!Self {
            var r = Reader.init(bytes);
            try codec.skip(T, &r);
            try r.finish();
            return .{ .bytes = bytes };
        }

        /// Validates one T at the reader's cursor, advances past it and returns its view.
        pub fn take(r: *Reader) io.Error!Self {
            const s = r.at;
            try codec.skip(T, r);
            return .{ .bytes = r.buf[s..r.at] };
        }

        /// Copies/decodes the whole value (byte strings still borrow from the view's bytes).
        pub fn decode(self: Self, arena: std.mem.Allocator) codec.DecodeError!T {
            return codec.decode(T, arena, self.bytes);
        }

        // The accessors below trust the bytes (validated by init/take) and cannot fail.

        /// Struct (named or newtype) field.
        pub fn field(self: Self, comptime name: []const u8) View(FieldType(name)) {
            var r = Reader.init(self.bytes);
            inline for (comptime meta.names(T), comptime meta.types(T)) |n, ft| {
                const s = r.at;
                codec.skipTrusted(ft, &r);
                if (comptime std.mem.eql(u8, n, name)) return .{ .bytes = r.buf[s..r.at] };
            }
            unreachable;
        }

        fn FieldType(comptime name: []const u8) type {
            return meta.fieldType(T, name);
        }

        /// Enum: variant index.
        pub fn tag(self: Self) u32 {
            var r = Reader.init(self.bytes);
            return r.uleb32() catch unreachable;
        }

        /// Enum: payload view of variant `name`, or null when another variant is active (the
        /// active variant is input data, so it is checked, never assumed).
        pub fn payload(self: Self, comptime name: []const u8) ?View(PayloadType(name)) {
            const want = comptime std.meta.fieldIndex(T, name) orelse @compileError("no variant " ++ name);
            var r = Reader.init(self.bytes);
            const t = r.uleb32() catch unreachable;
            if (t != want) return null;
            const s = r.at;
            codec.skipTrusted(PayloadType(name), &r);
            return .{ .bytes = r.buf[s..r.at] };
        }

        fn PayloadType(comptime name: []const u8) type {
            return meta.fieldType(T, name);
        }

        /// Option: the inner view, or null.
        pub fn some(self: Self) ?View(@typeInfo(T).optional.child) {
            if (self.bytes[0] == 0) return null;
            var r = Reader.init(self.bytes[1..]);
            const s = r.at;
            codec.skipTrusted(@typeInfo(T).optional.child, &r);
            return .{ .bytes = r.buf[s..r.at] };
        }

        /// Slice: element count.
        pub fn len(self: Self) usize {
            var r = Reader.init(self.bytes);
            return r.length() catch unreachable;
        }

        /// Slice of bytes: the borrowed bytes.
        pub fn raw(self: Self) []const u8 {
            var r = Reader.init(self.bytes);
            const n = r.length() catch unreachable;
            return r.bytes(n) catch unreachable;
        }

        /// Slice: iterate element views in order.
        pub fn iter(self: Self) Iterator {
            var r = Reader.init(self.bytes);
            const n = r.length() catch unreachable;
            return .{ .r = r, .left = n };
        }

        pub const Iterator = struct {
            r: Reader,
            left: usize,
            pub fn next(it: *Iterator) ?View(@typeInfo(T).pointer.child) {
                if (it.left == 0) return null;
                it.left -= 1;
                const s = it.r.at;
                codec.skipTrusted(@typeInfo(T).pointer.child, &it.r);
                return .{ .bytes = it.r.buf[s..it.r.at] };
            }
        };
    };
}
