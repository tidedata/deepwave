//! Validation of serialized RoaringBitmaps exactly as `sui_serde::deserialize_sui_bitmap` does:
//! the roaring crate's `deserialize_from` (0.11.4, which rejects unsorted container keys,
//! unsorted/duplicate array values, a wrong bitmap cardinality, empty or overlapping run
//! containers) followed by the cardinality cap MAX_VALIDATOR_COUNT = 150. Only a prefix of
//! the input is read, as in Rust: bytes after the bitmap are not an error here.
const std = @import("std");

pub const max_cardinality: u64 = 150;
const cookie_no_run: u32 = 12346;
const cookie_run: u16 = 12347;
const array_limit: u32 = 4096;

pub const Error = error{InvalidValue};

const Cursor = struct {
    b: []const u8,
    at: usize = 0,
    fn take(c: *Cursor, n: usize) Error![]const u8 {
        if (c.b.len - c.at < n) return error.InvalidValue;
        defer c.at += n;
        return c.b[c.at..][0..n];
    }
    fn u16le(c: *Cursor) Error!u16 {
        return std.mem.readInt(u16, (try c.take(2))[0..2], .little);
    }
    fn u32le(c: *Cursor) Error!u32 {
        return std.mem.readInt(u32, (try c.take(4))[0..4], .little);
    }
};

pub const Info = struct { card: u64, max: ?u32 };

/// Returns the cardinality of the bitmap, or InvalidValue when Rust would reject the bytes.
pub fn validate(bytes: []const u8) Error!u64 {
    return (try validateInfo(bytes)).card;
}

/// Like `validate`, also returns the largest member (null for the empty bitmap).
pub fn validateInfo(bytes: []const u8) Error!Info {
    var c: Cursor = .{ .b = bytes };
    const cookie = try c.u32le();
    var size: usize = undefined;
    var has_offsets: bool = undefined;
    var has_run: bool = undefined;
    if (cookie == cookie_no_run) {
        size = try c.u32le();
        has_offsets = true;
        has_run = false;
    } else if (@as(u16, @truncate(cookie)) == cookie_run) {
        size = (cookie >> 16) + 1;
        has_offsets = size >= 4;
        has_run = true;
    } else return error.InvalidValue;

    const run_bitmap: []const u8 = if (has_run) try c.take((size + 7) / 8) else &.{};
    if (size > 65536) return error.InvalidValue;
    const desc = try c.take(size * 4);
    if (has_offsets) _ = try c.take(size * 4);

    var total: u64 = 0;
    var max: ?u32 = null;
    var last_key: ?u16 = null;
    var i: usize = 0;
    while (i < size) : (i += 1) {
        const key = std.mem.readInt(u16, desc[i * 4 ..][0..2], .little);
        if (last_key) |lk| if (key <= lk) return error.InvalidValue;
        last_key = key;
        const card: u32 = @as(u32, std.mem.readInt(u16, desc[i * 4 + 2 ..][0..2], .little)) + 1;
        const is_run = has_run and (run_bitmap[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
        if (is_run) {
            const runs = try c.u16le();
            if (runs == 0) return error.InvalidValue;
            var last_end: ?u16 = null;
            var r: usize = 0;
            while (r < runs) : (r += 1) {
                const s = try c.u16le();
                const len = try c.u16le();
                const end = std.math.add(u16, s, len) catch return error.InvalidValue;
                if (last_end) |le| if (s <= le +| 1) return error.InvalidValue;
                last_end = end;
                total += @as(u64, len) + 1;
                max = (@as(u32, key) << 16) | end;
            }
        } else if (card <= array_limit) {
            const vals = try c.take(card * 2);
            var prev: u16 = std.mem.readInt(u16, vals[0..2], .little);
            var k: usize = 1;
            while (k < card) : (k += 1) {
                const cur = std.mem.readInt(u16, vals[k * 2 ..][0..2], .little);
                if (cur <= prev) return error.InvalidValue;
                prev = cur;
            }
            total += card;
            max = (@as(u32, key) << 16) | prev;
        } else {
            const words = try c.take(8192);
            var pop: u64 = 0;
            var k: usize = 0;
            while (k < 1024) : (k += 1) pop += @popCount(std.mem.readInt(u64, words[k * 8 ..][0..8], .little));
            if (pop != card) return error.InvalidValue;
            total += card;
            var k2: usize = 1024;
            while (k2 > 0) {
                k2 -= 1;
                const wv = std.mem.readInt(u64, words[k2 * 8 ..][0..8], .little);
                if (wv != 0) {
                    max = (@as(u32, key) << 16) | @as(u32, @intCast(k2 * 64 + 63 - @clz(wv)));
                    break;
                }
            }
        }
    }
    if (total > max_cardinality) return error.InvalidValue;
    return .{ .card = total, .max = max };
}

pub const max_canonical = 8 + 150 * 8 + 150 * 2;

/// The bytes Rust re-serializes for a bitmap that `validate` accepted: sui's
/// `deserialize_sui_bitmap` rebuilds the set by inserting every member into a fresh
/// RoaringBitmap, so the output is always the no-run cookie with array containers only.
pub fn canonical(bytes: []const u8, out: *[max_canonical]u8) Error![]const u8 {
    const info = try validateInfo(bytes);
    var vals: [150]u32 = undefined;
    var n: usize = 0;
    var c: Cursor = .{ .b = bytes };
    const cookie = try c.u32le();
    var size: usize = undefined;
    var has_offsets = true;
    var has_run = false;
    if (cookie == cookie_no_run) {
        size = try c.u32le();
    } else {
        size = (cookie >> 16) + 1;
        has_offsets = size >= 4;
        has_run = true;
    }
    const run_bitmap: []const u8 = if (has_run) try c.take((size + 7) / 8) else &.{};
    const desc = try c.take(size * 4);
    if (has_offsets) _ = try c.take(size * 4);
    for (0..size) |i| {
        const key: u32 = std.mem.readInt(u16, desc[i * 4 ..][0..2], .little);
        const card: u32 = @as(u32, std.mem.readInt(u16, desc[i * 4 + 2 ..][0..2], .little)) + 1;
        const is_run = has_run and (run_bitmap[i / 8] & (@as(u8, 1) << @intCast(i % 8))) != 0;
        if (is_run) {
            const runs = try c.u16le();
            for (0..runs) |_| {
                const s = try c.u16le();
                const len = try c.u16le();
                var v: u32 = s;
                while (v <= @as(u32, s) + len) : (v += 1) {
                    vals[n] = (key << 16) | v;
                    n += 1;
                }
            }
        } else if (card <= array_limit) {
            const raw = try c.take(card * 2);
            for (0..card) |k| {
                vals[n] = (key << 16) | std.mem.readInt(u16, raw[k * 2 ..][0..2], .little);
                n += 1;
            }
        } else unreachable; // a bitmap container has > 4096 members, over the cap
    }
    std.debug.assert(n == info.card);
    // Group by high 16 bits (values are sorted ascending).
    var keys: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        if (i == 0 or (vals[i] >> 16) != (vals[i - 1] >> 16)) keys += 1;
    }
    std.mem.writeInt(u32, out[0..4], cookie_no_run, .little);
    std.mem.writeInt(u32, out[4..8], @intCast(keys), .little);
    var d: usize = 8;
    var off: u32 = @intCast(8 + keys * 8);
    const hdr_end = off;
    var at: usize = hdr_end;
    i = 0;
    while (i < n) {
        var j = i;
        while (j < n and (vals[j] >> 16) == (vals[i] >> 16)) j += 1;
        std.mem.writeInt(u16, out[d..][0..2], @intCast(vals[i] >> 16), .little);
        std.mem.writeInt(u16, out[d + 2 ..][0..2], @intCast(j - i - 1), .little);
        d += 4;
        i = j;
    }
    i = 0;
    while (i < n) {
        var j = i;
        while (j < n and (vals[j] >> 16) == (vals[i] >> 16)) j += 1;
        std.mem.writeInt(u32, out[d..][0..4], off, .little);
        d += 4;
        off += @intCast((j - i) * 2);
        i = j;
    }
    for (vals[0..n]) |v| {
        std.mem.writeInt(u16, out[at..][0..2], @truncate(v), .little);
        at += 2;
    }
    return out[0..at];
}

fn build(comptime n: usize, comptime vals: [n]u16) [8 + 4 + 4 + n * 2]u8 {
    var out: [8 + 4 + 4 + n * 2]u8 = undefined;
    std.mem.writeInt(u32, out[0..4], cookie_no_run, .little);
    std.mem.writeInt(u32, out[4..8], 1, .little);
    std.mem.writeInt(u16, out[8..10], 0, .little);
    std.mem.writeInt(u16, out[10..12], n - 1, .little);
    std.mem.writeInt(u32, out[12..16], 16, .little);
    for (vals, 0..) |v, i| std.mem.writeInt(u16, out[16 + i * 2 ..][0..2], v, .little);
    return out;
}

test "roaring" {
    const t = std.testing;
    const ok = build(3, .{ 1, 5, 9 });
    try t.expectEqual(@as(u64, 3), try validate(&ok));
    const dup = build(3, .{ 1, 5, 5 });
    try t.expectError(error.InvalidValue, validate(&dup));
    const unsorted = build(2, .{ 5, 1 });
    try t.expectError(error.InvalidValue, validate(&unsorted));
    try t.expectError(error.InvalidValue, validate(&.{ 1, 2, 3 }));
    try t.expectError(error.InvalidValue, validate(ok[0 .. ok.len - 1]));
}
