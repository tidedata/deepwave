//! BCS reader and writers. The reader borrows its input and never allocates; the writers use
//! caller buffers (or only count). Semantics follow crates.io `bcs` 0.1.6 exactly:
//! canonical ULEB128 for u32 only, bool bytes 0/1, container depth counted on named containers.
const std = @import("std");
const core = @import("core");

/// Decode errors: the shared core set plus `InvalidValue`, a value that parses but fails the
/// Rust type's own validation (identifier syntax, digest length, roaring bitmap, ...).
pub const Error = core.DecodeError || error{InvalidValue};

pub const max_sequence_length: u32 = (1 << 31) - 1;
pub const max_container_depth: u16 = 500;

pub const Reader = struct {
    buf: []const u8,
    at: usize = 0,
    /// Remaining container depth; `enter` fails at zero, like bcs `enter_named_container`.
    depth: u16 = max_container_depth,

    pub fn init(input: []const u8) Reader {
        return .{ .buf = input };
    }

    pub fn initWithLimit(input: []const u8, limit: u16) Reader {
        return .{ .buf = input, .depth = limit };
    }

    pub inline fn remaining(r: *const Reader) usize {
        return r.buf.len - r.at;
    }

    pub inline fn pos(r: *const Reader) usize {
        return r.at;
    }

    /// Reads a little-endian integer (u8 .. u256, also signed). Hot path: one bounds check.
    pub inline fn int(r: *Reader, comptime T: type) Error!T {
        const n = @sizeOf(T);
        if (r.buf.len - r.at < n) return error.EndOfInput;
        const v = std.mem.readInt(T, r.buf[r.at..][0..n], .little);
        r.at += n;
        return v;
    }

    pub inline fn boolean(r: *Reader) Error!bool {
        if (r.at >= r.buf.len) return error.EndOfInput;
        const b = r.buf[r.at];
        if (b > 1) {
            r.at += 1;
            return error.InvalidBool;
        }
        r.at += 1;
        return b == 1;
    }

    /// Canonical ULEB128 of a u32, exactly as bcs 0.1.6 `parse_u32_from_uleb128`.
    pub inline fn uleb32(r: *Reader) Error!u32 {
        // Fast path: one byte.
        if (r.at < r.buf.len) {
            const b0 = r.buf[r.at];
            if (b0 < 0x80) {
                r.at += 1;
                return b0;
            }
        }
        return r.uleb32Slow();
    }

    fn uleb32Slow(r: *Reader) Error!u32 {
        var value: u64 = 0;
        var shift: u6 = 0;
        while (shift < 32) : (shift += 7) {
            if (r.at >= r.buf.len) return error.EndOfInput;
            const byte = r.buf[r.at];
            r.at += 1;
            const digit = byte & 0x7f;
            value |= @as(u64, digit) << shift;
            if (digit == byte) {
                if (shift > 0 and digit == 0) return error.InvalidUleb;
                if (value > std.math.maxInt(u32)) return error.InvalidUleb;
                return @intCast(value);
            }
        }
        return error.InvalidUleb;
    }

    /// A sequence length: ULEB128, at most 2^31 - 1. It is NOT compared with the input size
    /// (bcs reports the element error that comes first); callers that allocate must bound it
    /// themselves, see `lengthFor`.
    pub inline fn length(r: *Reader) Error!usize {
        const n = try r.uleb32();
        if (n > max_sequence_length) return error.LengthTooLarge;
        return n;
    }

    /// Borrowed bytes.
    pub inline fn bytes(r: *Reader, n: usize) Error![]const u8 {
        if (r.buf.len - r.at < n) return error.EndOfInput;
        const s = r.buf[r.at..][0..n];
        r.at += n;
        return s;
    }

    pub inline fn enter(r: *Reader) Error!void {
        if (r.depth == 0) return error.DepthExceeded;
        r.depth -= 1;
    }

    pub inline fn leave(r: *Reader) void {
        r.depth += 1;
    }

    pub fn finish(r: *const Reader) Error!void {
        if (r.at != r.buf.len) return error.TrailingBytes;
    }
};

/// Fixed-buffer writer; never allocates.
pub const Writer = struct {
    buf: []u8,
    at: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub inline fn int(w: *Writer, comptime T: type, v: T) error{NoSpace}!void {
        const n = @sizeOf(T);
        if (w.buf.len - w.at < n) return error.NoSpace;
        std.mem.writeInt(T, w.buf[w.at..][0..n], v, .little);
        w.at += n;
    }

    pub inline fn uleb32(w: *Writer, v: u32) error{NoSpace}!void {
        var x = v;
        while (x >= 0x80) {
            if (w.at >= w.buf.len) return error.NoSpace;
            w.buf[w.at] = @as(u8, @truncate(x)) | 0x80;
            w.at += 1;
            x >>= 7;
        }
        if (w.at >= w.buf.len) return error.NoSpace;
        w.buf[w.at] = @truncate(x);
        w.at += 1;
    }

    pub inline fn bytes(w: *Writer, b: []const u8) error{NoSpace}!void {
        if (w.buf.len - w.at < b.len) return error.NoSpace;
        @memcpy(w.buf[w.at..][0..b.len], b);
        w.at += b.len;
    }

    pub fn written(w: *const Writer) []const u8 {
        return w.buf[0..w.at];
    }
};

/// Same interface as `Writer`, but only counts (encodedLen).
pub const CountingWriter = struct {
    n: usize = 0,

    pub inline fn int(w: *CountingWriter, comptime T: type, v: T) error{NoSpace}!void {
        _ = v;
        w.n += @sizeOf(T);
    }
    pub inline fn uleb32(w: *CountingWriter, v: u32) error{NoSpace}!void {
        w.n += ulebLen(v);
    }
    pub inline fn bytes(w: *CountingWriter, b: []const u8) error{NoSpace}!void {
        w.n += b.len;
    }
};

pub inline fn ulebLen(v: u32) usize {
    if (v < 0x80) return 1;
    if (v < 0x4000) return 2;
    if (v < 0x200000) return 3;
    if (v < 0x10000000) return 4;
    return 5;
}

test "uleb32 edges" {
    const t = std.testing;
    var r = Reader.init(&.{ 0xff, 0xff, 0xff, 0xff, 0x0f });
    try t.expectEqual(@as(u32, std.math.maxInt(u32)), try r.uleb32());
    r = Reader.init(&.{ 0x80, 0x00 });
    try t.expectError(error.InvalidUleb, r.uleb32());
    r = Reader.init(&.{ 0xff, 0xff, 0xff, 0xff, 0x10 });
    try t.expectError(error.InvalidUleb, r.uleb32());
    r = Reader.init(&.{ 0x80, 0x80, 0x80, 0x80, 0x80 });
    try t.expectError(error.InvalidUleb, r.uleb32());
    r = Reader.init(&.{0x80});
    try t.expectError(error.EndOfInput, r.uleb32());
}
