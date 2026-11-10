//! Tiny little-endian binary writer and reader for the authority's own durable records
//! (epoch log groups, WAL entries). Not a Sui wire format: nothing here is visible to peers.
//! Fixed budgets: the reader never allocates, every length is checked against the remaining
//! bytes, and malformed input is an error value.
const std = @import("std");

pub const Error = error{ Truncated, Invalid };

pub const Writer = struct {
    gpa: std.mem.Allocator,
    buf: std.ArrayList(u8) = .empty,

    pub fn init(gpa: std.mem.Allocator) Writer {
        return .{ .gpa = gpa };
    }
    pub fn deinit(w: *Writer) void {
        w.buf.deinit(w.gpa);
    }
    pub fn bytes(w: *const Writer) []const u8 {
        return w.buf.items;
    }
    pub fn u8_(w: *Writer, v: u8) !void {
        try w.buf.append(w.gpa, v);
    }
    pub fn u32_(w: *Writer, v: u32) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, v, .little);
        try w.buf.appendSlice(w.gpa, &b);
    }
    pub fn u64_(w: *Writer, v: u64) !void {
        var b: [8]u8 = undefined;
        std.mem.writeInt(u64, &b, v, .little);
        try w.buf.appendSlice(w.gpa, &b);
    }
    pub fn raw(w: *Writer, s: []const u8) !void {
        try w.buf.appendSlice(w.gpa, s);
    }
    /// u32 length prefix then the bytes.
    pub fn blob(w: *Writer, s: []const u8) !void {
        try w.u32_(@intCast(s.len));
        try w.raw(s);
    }
};

pub const Reader = struct {
    buf: []const u8,
    at: usize = 0,

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }
    pub fn remaining(r: *const Reader) usize {
        return r.buf.len - r.at;
    }
    pub fn u8_(r: *Reader) Error!u8 {
        if (r.remaining() < 1) return error.Truncated;
        defer r.at += 1;
        return r.buf[r.at];
    }
    pub fn u32_(r: *Reader) Error!u32 {
        if (r.remaining() < 4) return error.Truncated;
        defer r.at += 4;
        return std.mem.readInt(u32, r.buf[r.at..][0..4], .little);
    }
    pub fn u64_(r: *Reader) Error!u64 {
        if (r.remaining() < 8) return error.Truncated;
        defer r.at += 8;
        return std.mem.readInt(u64, r.buf[r.at..][0..8], .little);
    }
    pub fn raw(r: *Reader, n: usize) Error![]const u8 {
        if (r.remaining() < n) return error.Truncated;
        defer r.at += n;
        return r.buf[r.at..][0..n];
    }
    pub fn id(r: *Reader) Error![32]u8 {
        return (try r.raw(32))[0..32].*;
    }
    pub fn blob(r: *Reader) Error![]const u8 {
        const n = try r.u32_();
        return r.raw(n);
    }
};

test "writer reader round trip" {
    var w = Writer.init(std.testing.allocator);
    defer w.deinit();
    try w.u8_(7);
    try w.u32_(0xdeadbeef);
    try w.u64_(1 << 40);
    try w.blob("hello");
    var r = Reader.init(w.bytes());
    try std.testing.expectEqual(@as(u8, 7), try r.u8_());
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), try r.u32_());
    try std.testing.expectEqual(@as(u64, 1 << 40), try r.u64_());
    try std.testing.expectEqualStrings("hello", try r.blob());
    try std.testing.expectError(error.Truncated, r.u8_());
}
