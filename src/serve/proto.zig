//! Protobuf wire writer producing exactly prost's bytes: fields in the order the caller emits
//! them (renderers emit in field-number order), minimal varints, `optional` scalars written
//! whenever present, repeated scalars packed, nested messages length-prefixed. Writes into a
//! caller-provided buffer (no allocation); nested messages reserve the length prefix from a
//! size hint and shift the body by the difference when the hint's varint width was wrong.
const std = @import("std");

pub const Error = error{NoSpace};

/// Largest message a renderer retries for (a frame over this is reported, not grown into).
pub const max_message: usize = 1 << 30;

pub const wire_varint = 0;
pub const wire_len = 2;

pub fn varintLen(v: u64) usize {
    const bits = 64 - @clz(v | 1);
    return (bits + 6) / 7;
}

pub const Writer = struct {
    buf: []u8,
    len: usize = 0,
    /// After an `error.NoSpace` from this writer: the length the failed write needed (callers
    /// that grow the buffer size the retry from it; a NoSpace with `need == 0` came from
    /// elsewhere and is not an overflow of this buffer).
    need: usize = 0,

    pub fn init(buf: []u8) Writer {
        return .{ .buf = buf };
    }

    pub fn bytesWritten(w: *const Writer) []const u8 {
        return w.buf[0..w.len];
    }

    /// After an `error.NoSpace`: the capacity to retry with when this writer's buffer was too
    /// small (at least double, at least what the failed write needed), null when the NoSpace came
    /// from somewhere else (retrying with a bigger buffer would fail the same way forever).
    pub fn retryCap(w: *const Writer) ?usize {
        if (w.need <= w.buf.len) return null;
        const cap = @max(w.buf.len * 2, w.need + w.need / 4);
        return if (cap > max_message) null else cap;
    }

    inline fn room(w: *Writer, n: usize) Error!void {
        if (w.buf.len - w.len < n) {
            w.need = w.len + n;
            return error.NoSpace;
        }
    }

    pub fn varint(w: *Writer, v: u64) Error!void {
        try w.room(10);
        var x = v;
        var i = w.len;
        while (x >= 0x80) : (x >>= 7) {
            w.buf[i] = @as(u8, @truncate(x)) | 0x80;
            i += 1;
        }
        w.buf[i] = @truncate(x);
        w.len = i + 1;
    }

    pub fn tag(w: *Writer, field: u32, wire: u3) Error!void {
        try w.varint((@as(u64, field) << 3) | wire);
    }

    /// `optional uint64/uint32/int64/int32/bool/enum` field, written because it is present.
    pub fn uint(w: *Writer, field: u32, v: u64) Error!void {
        try w.tag(field, wire_varint);
        try w.varint(v);
    }

    /// Appends already encoded fields.
    pub fn rawAppend(w: *Writer, data: []const u8) Error!void {
        try w.room(data.len);
        @memcpy(w.buf[w.len..][0..data.len], data);
        w.len += data.len;
    }

    pub fn bytes(w: *Writer, field: u32, data: []const u8) Error!void {
        try w.tag(field, wire_len);
        try w.varint(data.len);
        try w.room(data.len);
        @memcpy(w.buf[w.len..][0..data.len], data);
        w.len += data.len;
    }

    pub const string = bytes;

    /// `double`/`fixed64` field (wire type 1).
    pub fn fixed64(w: *Writer, field: u32, v: u64) Error!void {
        try w.tag(field, 1);
        try w.room(8);
        std.mem.writeInt(u64, w.buf[w.len..][0..8], v, .little);
        w.len += 8;
    }

    /// Packed repeated varints (proto3 default for scalar repeated fields).
    pub fn packedUints(w: *Writer, field: u32, vs: []const u64) Error!void {
        if (vs.len == 0) return;
        var n: usize = 0;
        for (vs) |v| n += varintLen(v);
        try w.tag(field, wire_len);
        try w.varint(n);
        for (vs) |v| try w.varint(v);
    }

    pub const Mark = struct { field_pos: usize, body: usize, reserved: u8 };

    /// Starts a nested message. `hint` is the expected body size: a right guess avoids moving
    /// the body when the message ends.
    pub fn begin(w: *Writer, field: u32, hint: usize) Error!Mark {
        try w.tag(field, wire_len);
        const reserved = varintLen(hint);
        try w.room(reserved);
        const m: Mark = .{ .field_pos = w.len, .body = w.len + reserved, .reserved = @intCast(reserved) };
        w.len += reserved;
        return m;
    }

    /// Ends the message: writes the real length and closes any gap.
    pub fn end(w: *Writer, m: Mark) Error!void {
        const n = w.len - m.body;
        const need = varintLen(n);
        if (need != m.reserved) {
            if (need > m.reserved) try w.room(need - m.reserved);
            const new_body = m.field_pos + need;
            @memmove(w.buf[new_body..][0..n], w.buf[m.body..][0..n]);
            w.len = new_body + n;
        }
        var x: u64 = n;
        var i = m.field_pos;
        while (x >= 0x80) : (x >>= 7) {
            w.buf[i] = @as(u8, @truncate(x)) | 0x80;
            i += 1;
        }
        w.buf[i] = @truncate(x);
    }
};

/// Reads varints and fields; used by tests and by request decoding.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub const Field = struct { number: u32, wire: u3, varint: u64 = 0, data: []const u8 = &.{} };
    pub const DecodeError = error{Malformed};

    pub fn init(buf: []const u8) Reader {
        return .{ .buf = buf };
    }

    pub fn varint(r: *Reader) DecodeError!u64 {
        var v: u64 = 0;
        var shift: u7 = 0;
        while (true) {
            if (r.pos >= r.buf.len or shift > 63) return error.Malformed;
            const b = r.buf[r.pos];
            r.pos += 1;
            v |= @as(u64, b & 0x7f) << @intCast(shift);
            if (b < 0x80) return v;
            shift += 7;
        }
    }

    /// Next field, or null at the end. Groups (wire type 3) are skipped like prost's
    /// `skip_field`; a stray end-group (4) is malformed.
    pub fn next(r: *Reader) DecodeError!?Field {
        // a loop, not recursion: a request may hold millions of empty groups back to back
        var k: u64 = undefined;
        while (true) {
            if (r.pos == r.buf.len) return null;
            k = try r.varint();
            const n = k >> 3;
            if (n == 0 or n > 0x1fffffff) return error.Malformed;
            if (@as(u3, @truncate(k)) != 3) break;
            try r.skipGroup(@intCast(n), 0);
        }
        const number = k >> 3;
        const wire: u3 = @truncate(k);
        var f: Field = .{ .number = @intCast(number), .wire = wire };
        switch (wire) {
            0 => f.varint = try r.varint(),
            1 => f.data = try r.take(8),
            2 => f.data = try r.take(try r.varint()),
            5 => f.data = try r.take(4),
            else => return error.Malformed,
        }
        return f;
    }

    /// prost rejects a known field whose wire type is not the field's own (`invalid wire type`).
    pub fn varintOf(f: Field) DecodeError!u64 {
        if (f.wire != 0) return error.Malformed;
        return f.varint;
    }

    /// A length-delimited field (message or bytes).
    pub fn bytesOf(f: Field) DecodeError![]const u8 {
        if (f.wire != 2) return error.Malformed;
        return f.data;
    }

    /// A `string` field: length-delimited and valid UTF-8 (prost's `merge_one_copy` check).
    pub fn stringOf(f: Field) DecodeError![]const u8 {
        const d = try bytesOf(f);
        if (!std.unicode.utf8ValidateSlice(d)) return error.Malformed;
        return d;
    }

    fn skipGroup(r: *Reader, tag: u32, depth: u32) DecodeError!void {
        if (depth > 100) return error.Malformed;
        while (true) {
            const k = try r.varint();
            const n = k >> 3;
            if (n == 0 or n > 0x1fffffff) return error.Malformed;
            switch (@as(u3, @truncate(k))) {
                0 => _ = try r.varint(),
                1 => _ = try r.take(8),
                2 => _ = try r.take(try r.varint()),
                5 => _ = try r.take(4),
                3 => try r.skipGroup(@intCast(n), depth + 1),
                4 => if (n == tag) return else return error.Malformed,
                else => return error.Malformed,
            }
        }
    }

    fn take(r: *Reader, n: u64) DecodeError![]const u8 {
        if (n > r.buf.len - r.pos) return error.Malformed;
        const s = r.buf[r.pos..][0..@intCast(n)];
        r.pos += @intCast(n);
        return s;
    }
};

test "varints and nesting shift" {
    var buf: [1024]u8 = undefined;
    var w = Writer.init(&buf);
    try w.uint(1, 300);
    const m = try w.begin(2, 5); // hint wrong: body will be 200+ bytes
    var big: [200]u8 = @splat(7);
    try w.bytes(1, &big);
    try w.end(m);
    const m2 = try w.begin(3, 1000); // hint too large, body tiny
    try w.uint(1, 1);
    try w.end(m2);
    var r = Reader.init(w.bytesWritten());
    const f1 = (try r.next()).?;
    try std.testing.expectEqual(@as(u64, 300), f1.varint);
    const f2 = (try r.next()).?;
    var r2 = Reader.init(f2.data);
    try std.testing.expectEqual(@as(usize, 200), (try r2.next()).?.data.len);
    const f3 = (try r.next()).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x08, 0x01 }, f3.data);
    try std.testing.expect((try r.next()) == null);
}

test "groups in unknown fields: skipped in a loop, nested, mismatched end" {
    const gpa = std.testing.allocator;
    // 2,000,000 empty groups (field 3) then field 1 = 5: no recursion per group
    const n = 2_000_000;
    const buf = try gpa.alloc(u8, n * 2 + 2);
    defer gpa.free(buf);
    for (0..n) |i| {
        buf[2 * i] = 0x1b;
        buf[2 * i + 1] = 0x1c;
    }
    buf[n * 2] = 0x08;
    buf[n * 2 + 1] = 0x05;
    var r = Reader.init(buf);
    const f = (try r.next()).?;
    try std.testing.expectEqual(@as(u32, 1), f.number);
    try std.testing.expectEqual(@as(u64, 5), f.varint);
    try std.testing.expect((try r.next()) == null);
    // a group holding a nested group and a varint, then a trailing group at the end
    var r2 = Reader.init(&.{ 0x1b, 0x23, 0x24, 0x08, 0x01, 0x1c, 0x10, 0x07, 0x1b, 0x1c });
    try std.testing.expectEqual(@as(u64, 7), (try r2.next()).?.varint);
    try std.testing.expect((try r2.next()) == null);
    // end tag of another field
    var r3 = Reader.init(&.{ 0x1b, 0x24 });
    try std.testing.expectError(error.Malformed, r3.next());
}

test "retryCap: grow only on this writer's own overflow" {
    var small: [4]u8 = undefined;
    var w = Writer.init(&small);
    try std.testing.expectError(error.NoSpace, w.bytes(1, "hello"));
    try std.testing.expect(w.retryCap().? >= 7);
    var big: [64]u8 = undefined;
    var w2 = Writer.init(&big);
    try w2.uint(1, 5);
    try std.testing.expect(w2.retryCap() == null); // a NoSpace from elsewhere is not retried
}
