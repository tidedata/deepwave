//! HPACK (RFC 7541): integer coding, Huffman decode, static and dynamic tables, and the small
//! response-side encoder (literals only, no Huffman) the gRPC server needs.
const std = @import("std");
const Allocator = std.mem.Allocator;
const huff = @import("huff_table.zig");

pub const Error = error{ Malformed, TooLarge, OutOfMemory };

pub const Header = struct { name: []const u8, value: []const u8 };

const static_table = [_]Header{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

// ---- Huffman decode: per-length sorted (code, symbol) lists, built at comptime ----

const Entry = struct { code: u32, sym: u8 };
const by_len = blk: {
    @setEvalBranchQuota(1_000_000);
    var counts: [31]usize = @splat(0);
    for (huff.lens) |l| counts[l] += 1;
    var out: [31][]const Entry = undefined;
    for (0..31) |l| {
        var arr: [counts[l]]Entry = undefined;
        var n: usize = 0;
        for (0..256) |s| {
            if (huff.lens[s] == l) {
                arr[n] = .{ .code = huff.codes[s], .sym = @intCast(s) };
                n += 1;
            }
        }
        std.mem.sort(Entry, &arr, {}, struct {
            fn lt(_: void, a: Entry, b: Entry) bool {
                return a.code < b.code;
            }
        }.lt);
        const fin = arr;
        out[l] = &fin;
    }
    break :blk out;
};

/// Decodes a Huffman string into `out`. Padding must be a prefix of EOS (all ones, under 8 bits).
pub fn huffmanDecode(out: *std.ArrayList(u8), gpa: Allocator, in: []const u8) Error!void {
    var code: u32 = 0;
    var nbits: u6 = 0;
    for (in) |byte| {
        var i: u4 = 8;
        while (i > 0) {
            i -= 1;
            code = (code << 1) | ((byte >> @intCast(i)) & 1);
            nbits += 1;
            if (nbits >= 5 and nbits <= 30) {
                const list = by_len[nbits];
                var lo: usize = 0;
                var hi: usize = list.len;
                while (lo < hi) {
                    const mid = (lo + hi) / 2;
                    if (list[mid].code == code) {
                        try out.append(gpa, list[mid].sym);
                        code = 0;
                        nbits = 0;
                        break;
                    } else if (list[mid].code < code) lo = mid + 1 else hi = mid;
                }
            }
            if (nbits > 30) return error.Malformed;
        }
    }
    if (nbits > 7) return error.Malformed;
    if (nbits > 0 and code != (@as(u32, 1) << @intCast(nbits)) - 1) return error.Malformed;
}

// ---- integers and strings ----

pub fn readInt(buf: []const u8, pos: *usize, prefix_bits: u4) Error!u64 {
    if (pos.* >= buf.len) return error.Malformed;
    const mask: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    var v: u64 = buf[pos.*] & mask;
    pos.* += 1;
    if (v < mask) return v;
    var shift: u6 = 0;
    while (true) {
        if (pos.* >= buf.len or shift > 56) return error.Malformed;
        const b = buf[pos.*];
        pos.* += 1;
        v += @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return v;
        shift += 7;
    }
}

pub fn writeInt(out: *std.ArrayList(u8), gpa: Allocator, first: u8, prefix_bits: u4, value: u64) Allocator.Error!void {
    const max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < max) {
        try out.append(gpa, first | @as(u8, @intCast(value)));
        return;
    }
    try out.append(gpa, first | @as(u8, @intCast(max)));
    var v = value - max;
    while (v >= 128) : (v >>= 7) try out.append(gpa, @as(u8, @truncate(v)) | 0x80);
    try out.append(gpa, @intCast(v));
}

// ---- decoder ----

pub const Decoder = struct {
    gpa: Allocator,
    /// Newest entry first.
    dyn: std.ArrayList(struct { name: []u8, value: []u8 }) = .empty,
    dyn_size: usize = 0,
    max_size: usize = 4096,
    limit: usize = 4096,
    scratch: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator) Decoder {
        return .{ .gpa = gpa };
    }

    pub fn deinit(d: *Decoder) void {
        for (d.dyn.items) |e| {
            d.gpa.free(e.name);
            d.gpa.free(e.value);
        }
        d.dyn.deinit(d.gpa);
        d.scratch.deinit(d.gpa);
    }

    fn evict(d: *Decoder, room: usize) void {
        while (d.dyn.items.len > 0 and d.dyn_size + room > d.max_size) {
            const e = d.dyn.pop().?;
            d.dyn_size -= 32 + e.name.len + e.value.len;
            d.gpa.free(e.name);
            d.gpa.free(e.value);
        }
    }

    fn insert(d: *Decoder, name: []const u8, value: []const u8) Error!void {
        const sz = 32 + name.len + value.len;
        d.evict(sz);
        if (sz > d.max_size) return;
        const n = try d.gpa.dupe(u8, name);
        errdefer d.gpa.free(n);
        const v = try d.gpa.dupe(u8, value);
        errdefer d.gpa.free(v);
        try d.dyn.insert(d.gpa, 0, .{ .name = n, .value = v });
        d.dyn_size += sz;
    }

    fn lookup(d: *const Decoder, idx: u64) Error!Header {
        if (idx == 0) return error.Malformed;
        if (idx <= static_table.len) return static_table[idx - 1];
        const di = idx - static_table.len - 1;
        if (di >= d.dyn.items.len) return error.Malformed;
        const e = d.dyn.items[di];
        return .{ .name = e.name, .value = e.value };
    }

    /// Reads a string literal; the result lives in `arena` unless it borrows `buf` (raw).
    fn readString(d: *Decoder, arena: Allocator, buf: []const u8, pos: *usize) Error![]const u8 {
        if (pos.* >= buf.len) return error.Malformed;
        const huffman = buf[pos.*] & 0x80 != 0;
        const n = try readInt(buf, pos, 7);
        if (n > buf.len - pos.*) return error.Malformed;
        const raw = buf[pos.*..][0..@intCast(n)];
        pos.* += @intCast(n);
        if (!huffman) return raw;
        d.scratch.clearRetainingCapacity();
        try huffmanDecode(&d.scratch, d.gpa, raw);
        return arena.dupe(u8, d.scratch.items);
    }

    /// Decodes one complete header block. Header strings are valid as long as `arena` and `block`
    /// live. Calls `sink(ctx, name, value)` per header.
    pub fn decode(d: *Decoder, arena: Allocator, block: []const u8, ctx: anytype, comptime sink: fn (@TypeOf(ctx), []const u8, []const u8) Error!void) Error!void {
        var pos: usize = 0;
        var seen_field = false;
        while (pos < block.len) {
            const b = block[pos];
            if (b & 0x80 != 0) {
                const idx = try readInt(block, &pos, 7);
                const h = try d.lookup(idx);
                try sink(ctx, try arena.dupe(u8, h.name), try arena.dupe(u8, h.value));
                seen_field = true;
            } else if (b & 0xc0 == 0x40 or b & 0xf0 == 0x00 or b & 0xf0 == 0x10) {
                const incr = b & 0xc0 == 0x40;
                const idx = try readInt(block, &pos, if (incr) 6 else 4);
                const name = if (idx == 0) try d.readString(arena, block, &pos) else try arena.dupe(u8, (try d.lookup(idx)).name);
                const value = try d.readString(arena, block, &pos);
                try sink(ctx, name, value);
                if (incr) try d.insert(name, value);
                seen_field = true;
            } else if (b & 0xe0 == 0x20) {
                if (seen_field) return error.Malformed;
                const sz = try readInt(block, &pos, 5);
                if (sz > d.limit) return error.Malformed;
                d.max_size = @intCast(sz);
                d.evict(0);
            } else return error.Malformed;
        }
    }
};

// ---- response encoder (literals without indexing) ----

pub fn encodeLiteral(out: *std.ArrayList(u8), gpa: Allocator, name: []const u8, value: []const u8) Allocator.Error!void {
    try out.append(gpa, 0x00); // literal without indexing, new name
    try writeInt(out, gpa, 0, 7, name.len);
    try out.appendSlice(gpa, name);
    try writeInt(out, gpa, 0, 7, value.len);
    try out.appendSlice(gpa, value);
}

const testing = std.testing;

fn collect(list: *std.ArrayList(Header), _: []const u8, _: []const u8) Error!void {
    _ = list;
}

const Collector = struct {
    arena: Allocator,
    items: std.ArrayList(Header) = .empty,
    fn push(c: *Collector, n: []const u8, v: []const u8) Error!void {
        try c.items.append(c.arena, .{ .name = n, .value = v });
    }
};

test "RFC 7541 C.4 requests with Huffman and dynamic table" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Decoder.init(testing.allocator);
    defer d.deinit();
    var c: Collector = .{ .arena = arena };
    // C.4.1
    const r1 = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    try d.decode(arena, &r1, &c, Collector.push);
    try testing.expectEqual(@as(usize, 4), c.items.items.len);
    try testing.expectEqualStrings(":authority", c.items.items[3].name);
    try testing.expectEqualStrings("www.example.com", c.items.items[3].value);
    // C.4.2 (uses the dynamic table entry)
    c.items.clearRetainingCapacity();
    const r2 = [_]u8{ 0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    try d.decode(arena, &r2, &c, Collector.push);
    try testing.expectEqualStrings("www.example.com", c.items.items[3].value);
    try testing.expectEqualStrings("cache-control", c.items.items[4].name);
    try testing.expectEqualStrings("no-cache", c.items.items[4].value);
    // C.4.3
    c.items.clearRetainingCapacity();
    const r3 = [_]u8{ 0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf };
    try d.decode(arena, &r3, &c, Collector.push);
    try testing.expectEqualStrings("custom-key", c.items.items[4].name);
    try testing.expectEqualStrings("custom-value", c.items.items[4].value);
}

test "RFC 7541 C.3 raw requests and integer coding" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var d = Decoder.init(testing.allocator);
    defer d.deinit();
    var c: Collector = .{ .arena = arena };
    const r1 = [_]u8{ 0x82, 0x86, 0x84, 0x41, 0x0f, 'w', 'w', 'w', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm' };
    try d.decode(arena, &r1, &c, Collector.push);
    try testing.expectEqualStrings("www.example.com", c.items.items[3].value);
    // C.1.2: 1337 with a 5-bit prefix
    var pos: usize = 0;
    try testing.expectEqual(@as(u64, 1337), try readInt(&[_]u8{ 0x1f, 0x9a, 0x0a }, &pos, 5));
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try writeInt(&out, testing.allocator, 0, 5, 1337);
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x9a, 0x0a }, out.items);
}

test "huffman malformed padding" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    // 'a' = 00011 (5 bits) + 3 padding bits that are not ones
    try testing.expectError(error.Malformed, huffmanDecode(&out, testing.allocator, &.{0b00011000}));
}
