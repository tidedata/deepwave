//! Minimal BCS writer and reader for the fastcrypto-tbls and Sui randomness wire types. These
//! are all fixed-shape (tuples of fixed-size group elements, u16/u64 integers, vectors with ULEB
//! lengths), so a cursor reader with explicit bounds is enough and keeps every allocation under
//! the caller's budget.
const std = @import("std");
const group = @import("group.zig");

pub const Error = error{ Truncated, TrailingBytes, InvalidEncoding, TooLarge, OutOfMemory };

pub const Writer = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }
    pub fn deinit(w: *Writer) void {
        w.buf.deinit(w.gpa);
    }
    pub fn toOwnedSlice(w: *Writer) Error![]u8 {
        return w.buf.toOwnedSlice(w.gpa);
    }
    pub fn bytesRaw(w: *Writer, b: []const u8) Error!void {
        try w.buf.appendSlice(w.gpa, b);
    }
    pub fn u8_(w: *Writer, x: u8) Error!void {
        try w.buf.append(w.gpa, x);
    }
    pub fn u16_(w: *Writer, x: u16) Error!void {
        var b: [2]u8 = undefined;
        std.mem.writeInt(u16, &b, x, .little);
        try w.bytesRaw(&b);
    }
    pub fn u32_(w: *Writer, x: u32) Error!void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, x, .little);
        try w.bytesRaw(&b);
    }
    pub fn u64_(w: *Writer, x: u64) Error!void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, x, .little);
        try w.bytesRaw(&b);
    }
    pub fn uleb(w: *Writer, x: u64) Error!void {
        var v = x;
        while (true) {
            const byte: u8 = @intCast(v & 0x7f);
            v >>= 7;
            if (v == 0) {
                try w.u8_(byte);
                return;
            }
            try w.u8_(byte | 0x80);
        }
    }
    pub fn bytesVec(w: *Writer, b: []const u8) Error!void {
        try w.uleb(b.len);
        try w.bytesRaw(b);
    }
    pub fn scalar(w: *Writer, s: group.Scalar) Error!void {
        try w.bytesRaw(&group.scalarToBytes(s));
    }
    pub fn g2(w: *Writer, p: group.G2P) Error!void {
        try w.bytesRaw(&group.g2ToBytes(p));
    }
    pub fn g1(w: *Writer, p: group.G1P) Error!void {
        try w.bytesRaw(&group.g1ToBytes(p));
    }
};

pub const Reader = struct {
    b: []const u8,
    pos: usize = 0,

    pub fn init(b: []const u8) Reader {
        return .{ .b = b };
    }
    pub fn remaining(r: *const Reader) usize {
        return r.b.len - r.pos;
    }
    pub fn finish(r: *const Reader) Error!void {
        if (r.pos != r.b.len) return error.TrailingBytes;
    }
    pub fn take(r: *Reader, n: usize) Error![]const u8 {
        if (r.remaining() < n) return error.Truncated;
        const s = r.b[r.pos..][0..n];
        r.pos += n;
        return s;
    }
    pub fn u8_(r: *Reader) Error!u8 {
        return (try r.take(1))[0];
    }
    pub fn u16_(r: *Reader) Error!u16 {
        return std.mem.readInt(u16, (try r.take(2))[0..2], .little);
    }
    pub fn u32_(r: *Reader) Error!u32 {
        return std.mem.readInt(u32, (try r.take(4))[0..4], .little);
    }
    pub fn u64_(r: *Reader) Error!u64 {
        return std.mem.readInt(u64, (try r.take(8))[0..8], .little);
    }
    /// Canonical ULEB128 up to u32 (BCS sequence lengths).
    pub fn uleb(r: *Reader) Error!u32 {
        var v: u64 = 0;
        var shift: u6 = 0;
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            const byte = try r.u8_();
            v |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) {
                if (i > 0 and byte == 0) return error.InvalidEncoding; // non canonical
                if (v > std.math.maxInt(u32)) return error.InvalidEncoding;
                return @intCast(v);
            }
            shift += 7;
        }
        return error.InvalidEncoding;
    }
    /// A sequence length, bounded by what the remaining input can hold at `min_elem` bytes each.
    pub fn seqLen(r: *Reader, min_elem: usize) Error!usize {
        const n = try r.uleb();
        if (min_elem != 0 and n > r.remaining() / min_elem) return error.Truncated;
        return n;
    }
    pub fn scalar(r: *Reader) Error!group.Scalar {
        const b = try r.take(32);
        return group.scalarFromBytes(b[0..32]) orelse error.InvalidEncoding;
    }
    pub fn g2(r: *Reader) Error!group.G2P {
        const b = try r.take(96);
        return group.g2FromBytes(b[0..96]) orelse error.InvalidEncoding;
    }
    pub fn g1(r: *Reader) Error!group.G1P {
        const b = try r.take(48);
        return group.g1FromBytes(b[0..48]) orelse error.InvalidEncoding;
    }
};

test "uleb roundtrip" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.uleb(300);
    try w.uleb(0);
    try w.uleb(127);
    var r = Reader.init(w.buf.items);
    try std.testing.expectEqual(@as(u32, 300), try r.uleb());
    try std.testing.expectEqual(@as(u32, 0), try r.uleb());
    try std.testing.expectEqual(@as(u32, 127), try r.uleb());
    try r.finish();
}
