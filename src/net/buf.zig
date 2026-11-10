//! Receive-side containers for the QUIC layer: the received-packet-number set that becomes ACK
//! ranges, and a reassembly buffer shared by CRYPTO and STREAM data.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Range = struct { start: u64, end: u64 }; // [start, end)

/// Received packet numbers as at most `cap` disjoint ranges, newest first. Fixed capacity, no
/// allocation; when full the oldest range is forgotten (those packets can no longer be acked,
/// which only makes the peer retransmit, as RFC 9000 section 13.2.3 allows).
pub const PnSet = struct {
    const cap = 48;
    r: [cap]Range = undefined,
    n: usize = 0,

    pub fn largest(s: *const PnSet) ?u64 {
        return if (s.n == 0) null else s.r[0].end - 1;
    }

    pub fn contains(s: *const PnSet, pn: u64) bool {
        for (s.r[0..s.n]) |r| if (pn >= r.start and pn < r.end) return true;
        return false;
    }

    pub fn insert(s: *PnSet, pn: u64) void {
        var i: usize = 0;
        while (i < s.n) : (i += 1) {
            const r = &s.r[i];
            if (pn >= r.start and pn < r.end) return;
            if (pn == r.end) {
                r.end += 1;
                // merge with previous (newer) range if now adjacent
                if (i > 0 and s.r[i - 1].start == r.end) {
                    s.r[i - 1].start = r.start;
                    s.removeAt(i);
                }
                return;
            }
            if (pn + 1 == r.start) {
                r.start = pn;
                if (i + 1 < s.n and s.r[i + 1].end == r.start) {
                    s.r[i + 1].end = r.end;
                    s.removeAt(i);
                }
                return;
            }
            if (pn > r.end) break; // belongs before (newer than) this range
        }
        // insert new single range at index i
        if (s.n == cap) s.n -= 1; // drop oldest
        if (i > s.n) i = s.n;
        var j = s.n;
        while (j > i) : (j -= 1) s.r[j] = s.r[j - 1];
        s.r[i] = .{ .start = pn, .end = pn + 1 };
        s.n += 1;
    }

    fn removeAt(s: *PnSet, i: usize) void {
        var j = i;
        while (j + 1 < s.n) : (j += 1) s.r[j] = s.r[j + 1];
        s.n -= 1;
    }
};

/// Reassembly buffer for one ordered byte stream (CRYPTO or STREAM data). Data may arrive in any
/// order and overlap; `contiguous` is the in-order prefix from the read cursor. The prefix is one
/// array; bytes past a hole are kept as chunks of what actually arrived, so memory follows bytes
/// received, never the highest offset (one byte at the end of a 128 MiB window costs one byte).
pub const RecvBuf = struct {
    /// The contiguous bytes from `base`.
    data: std.ArrayList(u8) = .empty,
    /// Stream offset of data[0].
    base: u64 = 0,
    /// Out-of-order bytes beyond a hole: sorted, disjoint, none touching another or the prefix.
    ooo: std.ArrayList(Chunk) = .empty,
    /// Total length announced by FIN, if any.
    fin_at: ?u64 = null,

    pub const Chunk = struct {
        off: u64,
        bytes: std.ArrayList(u8) = .empty,
        fn end(c: *const Chunk) u64 {
            return c.off + c.bytes.items.len;
        }
    };
    /// Holes one buffer tolerates; a peer fragmenting more than this is refused.
    pub const max_chunks = 4096;
    pub const InsertError = Allocator.Error || error{Fragmented};

    pub fn deinit(b: *RecvBuf, gpa: Allocator) void {
        b.data.deinit(gpa);
        for (b.ooo.items) |*c| c.bytes.deinit(gpa);
        b.ooo.deinit(gpa);
    }

    /// Drops every buffered byte (capacity of the prefix array and chunk list kept).
    pub fn discard(b: *RecvBuf, gpa: Allocator) void {
        b.data.clearRetainingCapacity();
        for (b.ooo.items) |*c| c.bytes.deinit(gpa);
        b.ooo.clearRetainingCapacity();
    }

    /// Bytes held (prefix and chunks).
    pub fn held(b: *const RecvBuf) usize {
        var n = b.data.items.len;
        for (b.ooo.items) |*c| n += c.bytes.items.len;
        return n;
    }

    fn cend(b: *const RecvBuf) u64 {
        return b.base + b.data.items.len;
    }

    /// Highest offset received so far.
    pub fn highest(b: *const RecvBuf) u64 {
        return if (b.ooo.items.len == 0) b.cend() else b.ooo.items[b.ooo.items.len - 1].end();
    }

    pub fn insert(b: *RecvBuf, gpa: Allocator, off: u64, bytes: []const u8) InsertError!void {
        if (bytes.len == 0) return;
        const end = off + bytes.len;
        const ce = b.cend();
        if (end <= ce) return; // already have it
        if (off <= ce) {
            try b.data.appendSlice(gpa, bytes[@intCast(ce - off)..]);
            b.absorb(gpa);
            return;
        }
        // past a hole: fill only the gaps between the chunks already held
        var o = off;
        var src = bytes;
        var i: usize = 0;
        while (i < b.ooo.items.len and b.ooo.items[i].end() <= o) i += 1;
        while (src.len > 0) {
            if (i < b.ooo.items.len and b.ooo.items[i].off <= o) {
                // overlaps chunk i: skip what it covers
                const ch_end = b.ooo.items[i].end();
                if (o + src.len <= ch_end) break;
                src = src[@intCast(ch_end - o)..];
                o = ch_end;
                i += 1;
                continue;
            }
            const gap_end = if (i < b.ooo.items.len) b.ooo.items[i].off else std.math.maxInt(u64);
            const take: usize = @intCast(@min(@as(u64, src.len), gap_end - o));
            if (i > 0 and b.ooo.items[i - 1].end() == o) {
                try b.ooo.items[i - 1].bytes.appendSlice(gpa, src[0..take]);
            } else {
                if (b.ooo.items.len >= max_chunks) return error.Fragmented;
                var c: Chunk = .{ .off = o };
                try c.bytes.appendSlice(gpa, src[0..take]);
                b.ooo.insert(gpa, i, c) catch |e| {
                    c.bytes.deinit(gpa);
                    return e;
                };
                i += 1;
            }
            o += take;
            src = src[take..];
            // the piece filled the gap up to chunk i: merge that chunk into the one before, and
            // go on from inside it (what it covers is skipped above)
            if (i < b.ooo.items.len and b.ooo.items[i].off == o) {
                var nx = b.ooo.orderedRemove(i);
                defer nx.bytes.deinit(gpa);
                try b.ooo.items[i - 1].bytes.appendSlice(gpa, nx.bytes.items);
                i -= 1;
            }
        }
    }

    /// Moves chunks the prefix has reached into it.
    fn absorb(b: *RecvBuf, gpa: Allocator) void {
        while (b.ooo.items.len > 0) {
            const ce = b.cend();
            const c = &b.ooo.items[0];
            if (c.off > ce) return;
            if (c.end() > ce) {
                // appendSlice can fail; keep the chunk then (it is still correct data)
                b.data.appendSlice(gpa, c.bytes.items[@intCast(ce - c.off)..]) catch return;
            }
            var done = b.ooo.orderedRemove(0);
            done.bytes.deinit(gpa);
        }
    }

    /// In-order bytes available from the beginning of unconsumed data. Borrowed; invalidated by
    /// `insert` and `consume`.
    pub fn contiguous(b: *const RecvBuf) []const u8 {
        return b.data.items;
    }

    /// True when FIN was seen and every byte up to it has arrived.
    pub fn complete(b: *const RecvBuf) bool {
        const f = b.fin_at orelse return false;
        return b.cend() >= f;
    }

    pub fn consume(b: *RecvBuf, n: usize) void {
        std.debug.assert(n <= b.data.items.len);
        const rest = b.data.items.len - n;
        std.mem.copyForwards(u8, b.data.items[0..rest], b.data.items[n..]);
        b.data.shrinkRetainingCapacity(rest);
        b.base += n;
    }
};

test "PnSet merges" {
    var s: PnSet = .{};
    for ([_]u64{ 5, 3, 4, 10, 1, 2, 0, 11 }) |p| s.insert(p);
    try std.testing.expectEqual(@as(usize, 2), s.n);
    try std.testing.expectEqual(@as(u64, 10), s.r[0].start);
    try std.testing.expectEqual(@as(u64, 12), s.r[0].end);
    try std.testing.expectEqual(@as(u64, 0), s.r[1].start);
    try std.testing.expectEqual(@as(u64, 6), s.r[1].end);
    try std.testing.expect(s.contains(4) and !s.contains(7));
}

test "RecvBuf out of order and overlap" {
    const gpa = std.testing.allocator;
    var b: RecvBuf = .{};
    defer b.deinit(gpa);
    try b.insert(gpa, 5, "world");
    try std.testing.expectEqual(@as(usize, 0), b.contiguous().len);
    try b.insert(gpa, 0, "hellowor");
    try std.testing.expectEqualStrings("helloworld", b.contiguous());
    b.fin_at = 10;
    try std.testing.expect(b.complete());
    b.consume(5);
    try std.testing.expectEqualStrings("world", b.contiguous());
}

test "RecvBuf holds what arrived, not up to the highest offset" {
    const gpa = std.testing.allocator;
    var b: RecvBuf = .{};
    defer b.deinit(gpa);
    try b.insert(gpa, (128 << 20) - 1, "x");
    try std.testing.expectEqual(@as(usize, 1), b.held());
    try std.testing.expectEqual(@as(u64, 128 << 20), b.highest());
    try std.testing.expectEqual(@as(usize, 0), b.contiguous().len);
    try std.testing.expect(b.data.capacity < 4096);
}

test "RecvBuf reassembles random overlapping pieces" {
    const gpa = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    var want: [4000]u8 = undefined;
    for (&want, 0..) |*x, i| x.* = @truncate(i *% 7 +% 3);
    for (0..300) |_| {
        var b: RecvBuf = .{};
        defer b.deinit(gpa);
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(gpa);
        var have: [4000]bool = @splat(false);
        var guard: usize = 0;
        while (b.base < want.len and guard < 20000) : (guard += 1) {
            // mostly anywhere, sometimes at the prefix end (as retransmissions fill holes)
            const pe: usize = @intCast(b.base + b.contiguous().len);
            const o = if (r.uintLessThan(u8, 4) == 0) pe -| r.uintLessThan(usize, 50) else r.uintLessThan(usize, want.len);
            const l = 1 + r.uintLessThan(usize, @min(300, want.len - o));
            try b.insert(gpa, o, want[o..][0..l]);
            for (o..o + l) |k| have[k] = true;
            // contiguous never runs past a hole and always matches
            const c = b.contiguous();
            for (c, 0..) |x, k| try std.testing.expectEqual(want[b.base + k], x);
            const pre = b.base + c.len;
            if (pre < want.len) try std.testing.expect(!have[pre]);
            if (r.boolean() and c.len > 0) {
                const n = r.uintLessThan(usize, c.len + 1);
                try got.appendSlice(gpa, c[0..n]);
                b.consume(n);
            }
            // chunks sorted, disjoint, not touching
            var prev_end: u64 = b.base + b.contiguous().len;
            for (b.ooo.items) |*ch| {
                try std.testing.expect(ch.off > prev_end);
                for (ch.bytes.items, 0..) |x, k| try std.testing.expectEqual(want[ch.off + k], x);
                prev_end = ch.end();
            }
            if (b.base + b.contiguous().len == want.len) break;
        }
        try std.testing.expectEqual(@as(u64, want.len), b.base + b.contiguous().len);
        try std.testing.expectEqual(@as(usize, 0), b.ooo.items.len);
    }
}

test "RecvBuf refuses unbounded fragmentation" {
    const gpa = std.testing.allocator;
    var b: RecvBuf = .{};
    defer b.deinit(gpa);
    var k: u64 = 0;
    while (k < RecvBuf.max_chunks) : (k += 1) try b.insert(gpa, 10 + 2 * k, "x");
    try std.testing.expectError(error.Fragmented, b.insert(gpa, 10 + 2 * k, "x"));
}
