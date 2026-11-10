//! CBOR exactly as ciborium 0.2.0 reads it into `ciborium::value::Value` (the decoder Sui's
//! nitro_attestation native uses), plus the encode-then-decode round trip
//! `CoseSign1::parse_and_validate` puts every COSE_Sign1 through.
//!
//! What ciborium accepts (and so what this accepts), from ciborium-ll 0.2.0 and
//! ciborium 0.2.0 `de`:
//! - any integer width, minimal or not; minors 28..30 are errors, 31 on an int or tag is an error;
//! - simple values 20/21 (bool) and 22/23 (null) in either the one-byte or the two-byte form;
//!   any other simple value is an error; floats of 16, 32 and 64 bits;
//! - indefinite byte and text strings whose chunks are definite strings of the same major
//!   type, or (a ciborium-ll quirk) nested indefinite strings of the same type;
//!   every text chunk must be valid UTF-8 on its own;
//! - tags 2 and 3 over a definite byte string of at most 16 bytes are integers (an error for
//!   tag 3 when the magnitude is 2^127 or more); every other tag is `Tag(t, value)`;
//! - arrays, maps and non-integer tags nest at most 256 deep; bytes after the value are ignored.
//!
//! Integers are `i128` in [-2^64, 2^64 - 1]; a bignum outside that stays a tag over its minimal
//! big-endian magnitude, as ciborium's `From<u128>`/`From<i128>` build it.
const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{Invalid} || Allocator.Error;

pub const Value = union(enum) {
    int: i128,
    bytes: []const u8,
    float: f64,
    text: []const u8,
    bool: bool,
    null,
    tag: Tagged,
    array: []const Value,
    map: []const Pair,

    pub const Tagged = struct { tag: u64, v: *const Value };

    /// Derived `PartialEq` of ciborium's `Value` (floats compare as f64).
    pub fn eql(a: *const Value, b: *const Value) bool {
        if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
        return switch (a.*) {
            .int => |x| x == b.int,
            .bytes => |x| std.mem.eql(u8, x, b.bytes),
            .float => |x| x == b.float,
            .text => |x| std.mem.eql(u8, x, b.text),
            .bool => |x| x == b.bool,
            .null => true,
            .tag => |x| x.tag == b.tag.tag and eql(x.v, b.tag.v),
            .array => |x| blk: {
                if (x.len != b.array.len) break :blk false;
                for (x, b.array) |*p, *q| if (!eql(p, q)) break :blk false;
                break :blk true;
            },
            .map => |x| blk: {
                if (x.len != b.map.len) break :blk false;
                for (x, b.map) |*p, *q| if (!eql(&p.k, &q.k) or !eql(&p.v, &q.v)) break :blk false;
                break :blk true;
            },
        };
    }
};

pub const Pair = struct { k: Value, v: Value };

pub const tag_bigpos: u64 = 2;
pub const tag_bigneg: u64 = 3;
const recursion_limit: u32 = 256;

const Header = union(enum) {
    pos: u64,
    neg: u64,
    float: f64,
    simple: u8,
    tag: u64,
    brk,
    bytes: ?u64,
    text: ?u64,
    array: ?u64,
    map: ?u64,
};

pub const Decoder = struct {
    in: []const u8,
    pos: usize = 0,
    recurse: u32 = recursion_limit,
    arena: Allocator,

    pub fn init(arena: Allocator, in: []const u8) Decoder {
        return .{ .in = in, .arena = arena };
    }

    fn take(d: *Decoder, n: u64) Error![]const u8 {
        if (n > d.in.len - d.pos) return error.Invalid;
        const s = d.in[d.pos..][0..@intCast(n)];
        d.pos += @intCast(n);
        return s;
    }

    fn header(d: *Decoder) Error!Header {
        const b = (try d.take(1))[0];
        const major = b >> 5;
        const minor = b & 0x1f;
        // null = indefinite (minor 31)
        const arg: ?u64 = switch (minor) {
            0...23 => minor,
            24 => (try d.take(1))[0],
            25 => std.mem.readInt(u16, (try d.take(2))[0..2], .big),
            26 => std.mem.readInt(u32, (try d.take(4))[0..4], .big),
            27 => std.mem.readInt(u64, (try d.take(8))[0..8], .big),
            31 => null,
            else => return error.Invalid,
        };
        return switch (major) {
            0 => .{ .pos = arg orelse return error.Invalid },
            1 => .{ .neg = arg orelse return error.Invalid },
            2 => .{ .bytes = arg },
            3 => .{ .text = arg },
            4 => .{ .array = arg },
            5 => .{ .map = arg },
            6 => .{ .tag = arg orelse return error.Invalid },
            else => switch (minor) {
                0...23 => .{ .simple = minor },
                24 => .{ .simple = @intCast(arg.?) },
                25 => .{ .float = halfToF64(@intCast(arg.?)) },
                26 => .{ .float = @floatCast(@as(f32, @bitCast(@as(u32, @intCast(arg.?))))) },
                27 => .{ .float = @bitCast(arg.?) },
                else => .brk,
            },
        };
    }

    fn peek(d: *Decoder) Error!Header {
        const save = d.pos;
        const h = try d.header();
        d.pos = save;
        return h;
    }

    /// ciborium-ll `Segments` over a string whose first header is `first`: definite, or
    /// indefinite with definite chunks of the same major type and nested indefinite strings.
    fn string(d: *Decoder, first: ?u64, comptime text: bool) Error![]const u8 {
        if (first) |n| {
            const s = try d.take(n);
            if (text and !textValid(s)) return error.Invalid;
            return s;
        }
        var out: std.ArrayList(u8) = .empty;
        var nested: usize = 1;
        while (true) {
            const h = try d.header();
            switch (h) {
                .brk => {
                    if (nested == 1) return out.items;
                    nested -= 1;
                },
                .bytes => |l| {
                    if (text) return error.Invalid;
                    if (l) |n| try out.appendSlice(d.arena, try d.take(n)) else nested += 1;
                },
                .text => |l| {
                    if (!text) return error.Invalid;
                    if (l) |n| {
                        const s = try d.take(n);
                        if (!textValid(s)) return error.Invalid;
                        try out.appendSlice(d.arena, s);
                    } else nested += 1;
                },
                else => return error.Invalid,
            }
        }
    }

    fn enter(d: *Decoder) Error!void {
        if (d.recurse == 0) return error.Invalid;
        d.recurse -= 1;
    }

    fn leave(d: *Decoder) void {
        d.recurse += 1;
    }

    /// `Value::deserialize` (`deserialize_any`).
    pub fn value(d: *Decoder) Error!Value {
        const h = try d.header();
        return d.valueFrom(h);
    }

    fn valueFrom(d: *Decoder, h: Header) Error!Value {
        switch (h) {
            .pos => |x| return .{ .int = x },
            .neg => |x| return .{ .int = -1 - @as(i128, x) },
            .bytes => |l| return .{ .bytes = try d.string(l, false) },
            .text => |l| return .{ .text = try d.string(l, true) },
            .array => |l| {
                try d.enter();
                defer d.leave();
                var out: std.ArrayList(Value) = .empty;
                if (l) |n| {
                    var i: u64 = 0;
                    while (i < n) : (i += 1) try out.append(d.arena, try d.value());
                } else while (true) {
                    const e = try d.header();
                    if (e == .brk) break;
                    try out.append(d.arena, try d.valueFrom(e));
                }
                return .{ .array = out.items };
            },
            .map => |l| {
                try d.enter();
                defer d.leave();
                return .{ .map = try d.entries(l) };
            },
            .tag => |t| {
                const next = try d.peek();
                if ((t == tag_bigpos or t == tag_bigneg) and next == .bytes) {
                    if (next.bytes) |n| if (n <= 16) {
                        _ = try d.header();
                        return bignum(d.arena, t == tag_bigneg, try d.take(n));
                    };
                }
                try d.enter();
                defer d.leave();
                const inner = try d.arena.create(Value);
                inner.* = try d.value();
                return .{ .tag = .{ .tag = t, .v = inner } };
            },
            .float => |f| return .{ .float = f },
            .simple => |s| return switch (s) {
                20 => .{ .bool = false },
                21 => .{ .bool = true },
                22, 23 => .null,
                else => error.Invalid,
            },
            .brk => return error.Invalid,
        }
    }

    fn entries(d: *Decoder, l: ?u64) Error![]const Pair {
        var out: std.ArrayList(Pair) = .empty;
        if (l) |n| {
            var i: u64 = 0;
            while (i < n) : (i += 1) {
                const k = try d.value();
                try out.append(d.arena, .{ .k = k, .v = try d.value() });
            }
        } else while (true) {
            const e = try d.header();
            if (e == .brk) break;
            const k = try d.valueFrom(e);
            try out.append(d.arena, .{ .k = k, .v = try d.value() });
        }
        return out.items;
    }

    /// `deserialize_map` with a visitor that reads `Value` entries: tags before the map are
    /// skipped (bignum tags included), anything else that is not a map is an error.
    pub fn mapSkippingTags(d: *Decoder) Error![]const Pair {
        while (true) {
            const h = try d.header();
            switch (h) {
                .tag => continue,
                .map => |l| {
                    try d.enter();
                    defer d.leave();
                    return d.entries(l);
                },
                else => return error.Invalid,
            }
        }
    }
};

/// A definite text string as ciborium reads it: in windows of its 4096-byte scratch buffer,
/// each of which must be valid UTF-8 on its own. (ciborium-ll's `Text` parser carries an
/// incomplete trailing character into the next window but never clears that state, so a
/// string whose character straddles a window boundary always ends in a syntax error.)
pub fn textValid(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) : (i += scratch_len) {
        if (!std.unicode.utf8ValidateSlice(s[i..@min(s.len, i + scratch_len)])) return false;
    }
    return true;
}

const scratch_len = 4096;

/// ciborium's integer path for tags 2/3 over at most 16 bytes, then `From<u128>`/`From<i128>`.
fn bignum(arena: Allocator, neg: bool, b: []const u8) Error!Value {
    var raw: u128 = 0;
    for (b) |x| raw = (raw << 8) | x;
    if (!neg) {
        if (raw <= std.math.maxInt(u64)) return .{ .int = @intCast(raw) };
        return bigTag(arena, tag_bigpos, raw);
    }
    if (raw > std.math.maxInt(i128)) return error.Invalid; // "integer too large"
    if (raw <= std.math.maxInt(u64)) return .{ .int = -1 - @as(i128, @intCast(raw)) };
    return bigTag(arena, tag_bigneg, raw);
}

fn bigTag(arena: Allocator, t: u64, raw: u128) Error!Value {
    var be: [16]u8 = undefined;
    std.mem.writeInt(u128, &be, raw, .big);
    var i: usize = 0;
    while (i < 16 and be[i] == 0) i += 1;
    const inner = try arena.create(Value);
    inner.* = .{ .bytes = try arena.dupe(u8, be[i..]) };
    return .{ .tag = .{ .tag = t, .v = inner } };
}

/// The value ciborium reads back after writing `v` (`into_writer` then `from_reader`): only a
/// tag 2/3 directly over a byte string of at most 16 bytes changes (it becomes an integer, or an
/// error for an oversized negative). Floats, integers and strings come back as they were.
pub fn roundTrip(arena: Allocator, v: *const Value) Error!Value {
    return switch (v.*) {
        .int, .bytes, .float, .bool, .null => v.*,
        // written as one definite string, so read back in 4096-byte windows
        .text => |t| if (textValid(t)) v.* else error.Invalid,
        .array => |a| blk: {
            const out = try arena.alloc(Value, a.len);
            for (a, out) |*x, *o| o.* = try roundTrip(arena, x);
            break :blk .{ .array = out };
        },
        .map => |m| blk: {
            const out = try arena.alloc(Pair, m.len);
            for (m, out) |*x, *o| o.* = .{ .k = try roundTrip(arena, &x.k), .v = try roundTrip(arena, &x.v) };
            break :blk .{ .map = out };
        },
        .tag => |t| blk: {
            if ((t.tag == tag_bigpos or t.tag == tag_bigneg) and t.v.* == .bytes and t.v.bytes.len <= 16) {
                // the written form is a definite byte string; leading zeros are skipped on read
                break :blk try bignum(arena, t.tag == tag_bigneg, t.v.bytes);
            }
            const inner = try arena.create(Value);
            inner.* = try roundTrip(arena, t.v);
            break :blk .{ .tag = .{ .tag = t.tag, .v = inner } };
        },
    };
}

/// half 1.8.2 `f16::to_f64` (software path).
fn halfToF64(h: u16) f64 {
    // exact: every f16 value (including NaN payloads, shifted) is an f64
    const sign: u64 = @as(u64, h & 0x8000) << 48;
    const exp: u16 = h & 0x7c00;
    const man: u64 = h & 0x03ff;
    if (h & 0x7fff == 0) return @bitCast(sign);
    if (exp == 0x7c00) {
        if (man == 0) return @bitCast(sign | 0x7ff0_0000_0000_0000);
        return @bitCast(sign | 0x7ff8_0000_0000_0000 | (man << 42));
    }
    if (exp == 0) {
        // subnormal: normalise
        const e: u6 = @intCast(@clz(@as(u16, @intCast(man))) - 6);
        const exp64: u64 = @as(u64, 1023 - 15 - @as(u64, e)) << 52;
        const man64: u64 = ((man << (e + 1)) & 0x3ff) << 42;
        return @bitCast(sign | exp64 | man64);
    }
    const exp64: u64 = (@as(u64, exp >> 10) + 1023 - 15) << 52;
    return @bitCast(sign | exp64 | (man << 42));
}

// ---- writing (canonical, as ciborium's serializer writes the values the native builds) -------

pub fn writeHead(out: *std.ArrayList(u8), arena: Allocator, major: u8, n: u64) Allocator.Error!void {
    const m = major << 5;
    if (n < 24) {
        try out.append(arena, m | @as(u8, @intCast(n)));
    } else if (n <= 0xff) {
        try out.appendSlice(arena, &.{ m | 24, @intCast(n) });
    } else if (n <= 0xffff) {
        try out.append(arena, m | 25);
        try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u16, @intCast(n))));
    } else if (n <= 0xffff_ffff) {
        try out.append(arena, m | 26);
        try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u32, @intCast(n))));
    } else {
        try out.append(arena, m | 27);
        try out.appendSlice(arena, &std.mem.toBytes(std.mem.nativeToBig(u64, n)));
    }
}

pub fn decode(arena: Allocator, in: []const u8) Error!Value {
    var d = Decoder.init(arena, in);
    return d.value();
}

test "integers and bignums" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try std.testing.expectEqual(@as(i128, -35), (try decode(a, &.{0x38, 0x22})).int);
    try std.testing.expectEqual(@as(i128, 1), (try decode(a, &.{ 0xc2, 0x43, 0, 0, 1 })).int);
    try std.testing.expectError(error.Invalid, decode(a, &([_]u8{ 0xc3, 0x50 } ++ @as([16]u8, @splat(0x80)))));
    const big = try decode(a, &([_]u8{ 0xc2, 0x50 } ++ @as([16]u8, @splat(0xff))));
    try std.testing.expect(big == .tag and big.tag.v.bytes.len == 16);
    try std.testing.expectError(error.Invalid, decode(a, &.{0x1c}));
    try std.testing.expect((try decode(a, &.{ 0xf8, 0x14 })).bool == false);
    try std.testing.expectError(error.Invalid, decode(a, &.{0xf3}));
}

test "half floats" {
    try std.testing.expectEqual(@as(f64, 1.0), halfToF64(0x3c00));
    try std.testing.expectEqual(@as(f64, -2.0), halfToF64(0xc000));
    try std.testing.expectEqual(@as(f64, 5.960464477539063e-8), halfToF64(0x0001));
    try std.testing.expectEqual(@as(f64, 65504.0), halfToF64(0x7bff));
    try std.testing.expect(std.math.isNan(halfToF64(0x7e00)));
}
