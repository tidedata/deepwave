//! Ordered byte-key map: sorted chunks of at most `chunk_max` entries. Keys are owned copies.
//! Lookup and seek are two binary searches; insert and remove touch one chunk (plus the chunk
//! directory on a split or an emptied chunk). Iteration is in `std.mem.order` byte order, the
//! order RocksDB gives the node's column families with the default comparator.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const chunk_max = 128;

pub fn Sorted(comptime V: type) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { key: []u8, val: V };
        /// Entries grow 4, 8, ... chunk_max: most owners hold a handful of objects.
        const Chunk = struct {
            n: u32 = 0,
            items: []Entry,
            fn last(c: *const Chunk) []const u8 {
                return c.items[c.n - 1].key;
            }
            fn create(gpa: Allocator, cap: usize) Allocator.Error!*Chunk {
                const c = try gpa.create(Chunk);
                errdefer gpa.destroy(c);
                c.* = .{ .items = try gpa.alloc(Entry, cap) };
                return c;
            }
            fn destroy(c: *Chunk, gpa: Allocator) void {
                gpa.free(c.items);
                gpa.destroy(c);
            }
        };

        chunks: std.ArrayList(*Chunk) = .empty,
        len: usize = 0,

        pub fn deinit(s: *Self, gpa: Allocator) void {
            for (s.chunks.items) |c| {
                for (c.items[0..c.n]) |e| gpa.free(e.key);
                c.destroy(gpa);
            }
            s.chunks.deinit(gpa);
        }

        fn lt(a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }

        /// Index of the first chunk whose last key is >= key (chunks.len when none).
        fn chunkFor(s: *const Self, key: []const u8) usize {
            var lo: usize = 0;
            var hi: usize = s.chunks.items.len;
            while (lo < hi) {
                const mid = (lo + hi) / 2;
                if (lt(s.chunks.items[mid].last(), key)) lo = mid + 1 else hi = mid;
            }
            return lo;
        }

        /// Position of the first entry >= key inside chunk c.
        fn posIn(c: *const Chunk, key: []const u8) usize {
            var lo: usize = 0;
            var hi: usize = c.n;
            while (lo < hi) {
                const mid = (lo + hi) / 2;
                if (lt(c.items[mid].key, key)) lo = mid + 1 else hi = mid;
            }
            return lo;
        }

        pub fn get(s: *const Self, key: []const u8) ?*V {
            const ci = s.chunkFor(key);
            if (ci == s.chunks.items.len) return null;
            const c = s.chunks.items[ci];
            const p = posIn(c, key);
            if (p < c.n and std.mem.eql(u8, c.items[p].key, key)) return &c.items[p].val;
            return null;
        }

        /// Inserts or replaces. Returns a pointer to the stored value.
        pub fn put(s: *Self, gpa: Allocator, key: []const u8, val: V) Allocator.Error!*V {
            if (s.chunks.items.len == 0) {
                const c = try Chunk.create(gpa, 4);
                errdefer c.destroy(gpa);
                try s.chunks.append(gpa, c);
                c.items[0] = .{ .key = try gpa.dupe(u8, key), .val = val };
                c.n = 1;
                s.len = 1;
                return &c.items[0].val;
            }
            var ci = s.chunkFor(key);
            if (ci == s.chunks.items.len) ci -= 1; // beyond every key: append to the last chunk
            var c = s.chunks.items[ci];
            var p = posIn(c, key);
            if (p < c.n and std.mem.eql(u8, c.items[p].key, key)) {
                c.items[p].val = val;
                return &c.items[p].val;
            }
            const owned = try gpa.dupe(u8, key);
            errdefer gpa.free(owned);
            if (c.n == c.items.len and c.items.len < chunk_max) {
                c.items = try gpa.realloc(c.items, @min(chunk_max, c.items.len * 2));
            } else if (c.n == chunk_max) {
                const nc = try Chunk.create(gpa, chunk_max);
                errdefer nc.destroy(gpa);
                try s.chunks.insert(gpa, ci + 1, nc);
                const half = chunk_max / 2;
                @memcpy(nc.items[0 .. chunk_max - half], c.items[half..chunk_max]);
                nc.n = chunk_max - half;
                c.n = half;
                if (p > half) {
                    c = nc;
                    p -= half;
                } else if (p == half and !lt(key, nc.items[0].key)) {
                    c = nc;
                    p = 0;
                }
            }
            std.mem.copyBackwards(Entry, c.items[p + 1 .. c.n + 1], c.items[p..c.n]);
            c.items[p] = .{ .key = owned, .val = val };
            c.n += 1;
            s.len += 1;
            return &c.items[p].val;
        }

        pub fn remove(s: *Self, gpa: Allocator, key: []const u8) bool {
            const ci = s.chunkFor(key);
            if (ci == s.chunks.items.len) return false;
            const c = s.chunks.items[ci];
            const p = posIn(c, key);
            if (p >= c.n or !std.mem.eql(u8, c.items[p].key, key)) return false;
            gpa.free(c.items[p].key);
            std.mem.copyForwards(Entry, c.items[p .. c.n - 1], c.items[p + 1 .. c.n]);
            c.n -= 1;
            s.len -= 1;
            if (c.n == 0) {
                _ = s.chunks.orderedRemove(ci);
                c.destroy(gpa);
            }
            return true;
        }

        pub const Iter = struct {
            s: *const Self,
            ci: usize,
            p: usize,
            pub fn next(it: *Iter) ?*const Entry {
                while (it.ci < it.s.chunks.items.len) {
                    const c = it.s.chunks.items[it.ci];
                    if (it.p < c.n) {
                        defer it.p += 1;
                        return &c.items[it.p];
                    }
                    it.ci += 1;
                    it.p = 0;
                }
                return null;
            }
            pub fn peek(it: *const Iter) ?*const Entry {
                var copy = it.*;
                return copy.next();
            }
        };

        /// Iterator positioned at the first entry >= key.
        pub fn seek(s: *const Self, key: []const u8) Iter {
            const ci = s.chunkFor(key);
            if (ci == s.chunks.items.len) return .{ .s = s, .ci = ci, .p = 0 };
            return .{ .s = s, .ci = ci, .p = posIn(s.chunks.items[ci], key) };
        }
    };
}

test "sorted: random inserts, removes, seeks against a model" {
    const gpa = std.testing.allocator;
    var s: Sorted(u64) = .{};
    defer s.deinit(gpa);
    var model: std.StringArrayHashMapUnmanaged(u64) = .empty;
    defer {
        for (model.keys()) |k| gpa.free(k);
        model.deinit(gpa);
    }
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    var i: usize = 0;
    while (i < 20000) : (i += 1) {
        var kb: [3]u8 = undefined;
        r.bytes(&kb);
        kb[0] &= 0x0f;
        const klen = 1 + r.uintLessThan(usize, 3);
        const key = kb[0..klen];
        if (r.boolean()) {
            _ = try s.put(gpa, key, i);
            const gop = try model.getOrPut(gpa, key);
            if (!gop.found_existing) gop.key_ptr.* = try gpa.dupe(u8, key);
            gop.value_ptr.* = i;
        } else {
            const had = model.fetchSwapRemove(key);
            try std.testing.expectEqual(had != null, s.remove(gpa, key));
            if (had) |kv| gpa.free(kv.key);
        }
    }
    try std.testing.expectEqual(model.count(), s.len);
    const keys = try gpa.dupe([]const u8, model.keys());
    defer gpa.free(keys);
    std.mem.sort([]const u8, keys, {}, struct {
        fn f(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.f);
    var it = s.seek("");
    for (keys) |k| {
        const e = it.next().?;
        try std.testing.expectEqualSlices(u8, k, e.key);
        try std.testing.expectEqual(model.get(k).?, e.val);
    }
    try std.testing.expect(it.next() == null);
    // seek lands on the first key >= probe
    var probe: [2]u8 = .{ 0x07, 0x80 };
    var sk = s.seek(&probe);
    if (sk.next()) |e| try std.testing.expect(std.mem.order(u8, e.key, &probe) != .lt);
}
