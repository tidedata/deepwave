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
/// order and overlap; `contiguous` is the in-order prefix from the read cursor.
pub const RecvBuf = struct {
    data: std.ArrayList(u8) = .empty,
    /// Stream offset of data[0].
    base: u64 = 0,
    /// Received ranges, sorted, disjoint, absolute offsets.
    ranges: std.ArrayList(Range) = .empty,
    /// Total length announced by FIN, if any.
    fin_at: ?u64 = null,

    pub fn deinit(b: *RecvBuf, gpa: Allocator) void {
        b.data.deinit(gpa);
        b.ranges.deinit(gpa);
    }

    /// Highest offset received so far (for flow control accounting).
    pub fn highest(b: *const RecvBuf) u64 {
        return if (b.ranges.items.len == 0) b.base else b.ranges.items[b.ranges.items.len - 1].end;
    }

    pub fn insert(b: *RecvBuf, gpa: Allocator, off: u64, bytes: []const u8) Allocator.Error!void {
        if (bytes.len == 0) return;
        const end = off + bytes.len;
        if (end <= b.base) return; // already consumed
        var o = off;
        var src = bytes;
        if (o < b.base) {
            src = src[b.base - o ..];
            o = b.base;
        }
        const rel_end: usize = @intCast(end - b.base);
        if (b.data.items.len < rel_end) try b.data.resize(gpa, rel_end);
        @memcpy(b.data.items[@intCast(o - b.base)..][0..src.len], src);
        try b.addRange(gpa, o, end);
    }

    fn addRange(b: *RecvBuf, gpa: Allocator, start: u64, end: u64) Allocator.Error!void {
        var s = start;
        var e = end;
        var i: usize = 0;
        var first: ?usize = null;
        var last: usize = 0;
        while (i < b.ranges.items.len) : (i += 1) {
            const r = b.ranges.items[i];
            if (r.end < s) continue;
            if (r.start > e) break;
            if (first == null) first = i;
            last = i;
            s = @min(s, r.start);
            e = @max(e, r.end);
        }
        if (first) |f| {
            b.ranges.items[f] = .{ .start = s, .end = e };
            const remove = last - f;
            if (remove > 0) {
                const tail = b.ranges.items.len - (last + 1);
                std.mem.copyForwards(Range, b.ranges.items[f + 1 ..][0..tail], b.ranges.items[last + 1 ..]);
                b.ranges.shrinkRetainingCapacity(b.ranges.items.len - remove);
            }
        } else {
            try b.ranges.insert(gpa, i, .{ .start = s, .end = e });
        }
    }

    /// In-order bytes available from the beginning of unconsumed data. Borrowed; invalidated by
    /// `insert` and `consume`.
    pub fn contiguous(b: *const RecvBuf) []const u8 {
        if (b.ranges.items.len == 0) return &.{};
        const r = b.ranges.items[0];
        if (r.start > b.base) return &.{};
        return b.data.items[0..@intCast(r.end - b.base)];
    }

    /// True when FIN was seen and every byte up to it has arrived.
    pub fn complete(b: *const RecvBuf) bool {
        const f = b.fin_at orelse return false;
        return b.base + b.contiguous().len >= f;
    }

    pub fn consume(b: *RecvBuf, n: usize) void {
        std.debug.assert(n <= b.contiguous().len);
        const rest = b.data.items.len - n;
        std.mem.copyForwards(u8, b.data.items[0..rest], b.data.items[n..]);
        b.data.shrinkRetainingCapacity(rest);
        b.base += n;
        // trim ranges
        var w: usize = 0;
        for (b.ranges.items) |r| {
            if (r.end <= b.base) continue;
            b.ranges.items[w] = .{ .start = @max(r.start, b.base), .end = r.end };
            w += 1;
        }
        b.ranges.shrinkRetainingCapacity(w);
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
