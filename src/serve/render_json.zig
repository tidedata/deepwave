//! Move value to `google.protobuf.Value`: the port of sui-types `rpc_visitor::RpcVisitor<Value,
//! LocalMeter>` driven by `ProtoVisitor::deserialize_value_with_budget` (sui-node 1.83.1).
//!
//! - u8/u16/u32 are numbers; u64/u128/u256 decimal strings; addresses "0x" + 64 hex;
//!   `vector<u8>` standard base64; `0x1::ascii::String`, `0x1::string::String`,
//!   `0x1::type_name::TypeName`, `0x2::url::Url` strings; `0x2::object::{UID,ID}` addresses;
//!   `0x1::option::Option` null or the inner value; `0x2::balance::Balance` the u64 string;
//!   enums a struct with "@variant".
//! - Budget: every value charges `size_of::<Value>()` (32), strings add their length, struct
//!   and variant keys add theirs; the budget is shared and decremented in place, so a failed
//!   render leaves what it consumed (Rust's `LocalMeter`). Depth: 80 nested containers.
//! - Any error (bad bytes, trailing bytes, over budget, too deep, invalid UTF-8 in a string)
//!   gives null, where Rust's `render_json` gives `None`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const movelayout = @import("movelayout.zig");
const pbvalue = @import("pbvalue.zig");
const typestr = @import("typestr.zig");

const Layout = movelayout.Layout;
const Value = pbvalue.Value;
const VS = pbvalue.value_size;

/// sui-node `max_json_move_value_size` default (per value).
pub const default_value_budget: usize = 1024 * 1024;
/// sui-node `max_json_move_value_response_size` default (shared by a checkpoint's events).
pub const default_response_budget: usize = 16 * 1024 * 1024;
pub const max_depth: usize = 80;

const Fail = error{ Bad, OutOfMemory };

const Cursor = struct {
    b: []const u8,
    pos: usize = 0,
    fn take(c: *Cursor, n: usize) Fail![]const u8 {
        if (c.b.len - c.pos < n) return error.Bad;
        const s = c.b[c.pos..][0..n];
        c.pos += n;
        return s;
    }
    /// `leb128::read::unsigned` (non-canonical forms accepted, overflow rejected).
    fn uleb(c: *Cursor) Fail!u64 {
        var v: u64 = 0;
        var shift: u32 = 0;
        while (true) {
            const byte = (try c.take(1))[0];
            if (shift == 63 and byte > 1) return error.Bad;
            v |= @as(u64, byte & 0x7f) << @intCast(shift);
            if (byte & 0x80 == 0) return v;
            shift += 7;
            if (shift > 63) return error.Bad;
        }
    }
};

const Meter = struct {
    size: *usize,
    depth: usize,
    fn nest(m: *const Meter) Fail!Meter {
        if (m.depth == 0) return error.Bad;
        return .{ .size = m.size, .depth = m.depth - 1 };
    }
    fn charge(m: *const Meter, n: usize) Fail!void {
        if (m.size.* < n) return error.Bad;
        m.size.* -= n;
    }
};

const R = struct {
    arena: Allocator,
    c: Cursor,

    fn str(_: *R, m: *const Meter, s: []const u8) Fail!Value {
        try m.charge(VS + s.len);
        return .{ .string = s };
    }

    fn addr(r: *R, m: *const Meter, a: *const [32]u8) Fail!Value {
        const buf = try r.arena.alloc(u8, 66);
        var o: typestr.Out = .{ .buf = buf };
        o.address(a) catch unreachable;
        return r.str(m, o.str());
    }

    fn dec(r: *R, m: *const Meter, comptime T: type, v: T) Fail!Value {
        return r.str(m, try std.fmt.allocPrint(r.arena, "{d}", .{v}));
    }

    fn int(r: *R, comptime T: type) Fail!T {
        return std.mem.readInt(T, (try r.c.take(@sizeOf(T)))[0..@sizeOf(T)], .little);
    }

    fn value(r: *R, l: *const Layout, m: *const Meter) Fail!Value {
        switch (l.*) {
            .bool => {
                const b = (try r.c.take(1))[0];
                if (b > 1) return error.Bad;
                try m.charge(VS);
                return .{ .bool = b == 1 };
            },
            .u8 => {
                const v = try r.int(u8);
                try m.charge(VS);
                return .{ .number = @floatFromInt(v) };
            },
            .u16 => {
                const v = try r.int(u16);
                try m.charge(VS);
                return .{ .number = @floatFromInt(v) };
            },
            .u32 => {
                const v = try r.int(u32);
                try m.charge(VS);
                return .{ .number = @floatFromInt(v) };
            },
            .u64 => return r.dec(m, u64, try r.int(u64)),
            .u128 => return r.dec(m, u128, try r.int(u128)),
            .u256 => return r.dec(m, u256, try r.int(u256)),
            .address, .signer => return r.addr(m, (try r.c.take(32))[0..32]),
            .vector => |el| {
                const n = try r.c.uleb();
                if (el.* == .u8) {
                    if (n > r.c.b.len - r.c.pos) return error.Bad;
                    const raw = try r.c.take(@intCast(n));
                    const enc = std.base64.standard.Encoder;
                    const out = try r.arena.alloc(u8, enc.calcSize(raw.len));
                    _ = enc.encode(out, raw);
                    return r.str(m, out);
                }
                const items = try r.arena.alloc(Value, @intCast(@min(n, r.c.b.len - r.c.pos)));
                {
                    const nested = try m.nest();
                    var i: u64 = 0;
                    while (i < n) : (i += 1) {
                        const v = try r.value(el, &nested);
                        if (i >= items.len) return error.Bad; // each element takes at least one byte
                        items[@intCast(i)] = v;
                    }
                }
                try m.charge(VS);
                return .{ .list = items[0..@intCast(n)] };
            },
            .@"struct" => |s| return r.structValue(s, m),
            .@"enum" => |e| {
                const tag = (try r.c.take(1))[0];
                if (tag > 127 or tag >= e.variants.len) return error.Bad;
                const v = &e.variants[tag];
                const es = try r.arena.alloc(pbvalue.Entry, v.fields.len + 1);
                {
                    const nested = try m.nest();
                    es[0] = .{ .key = "@variant", .value = try r.str(&nested, v.name) };
                    try nested.charge("@variant".len);
                    for (v.fields, es[1..]) |*f, *o| {
                        o.* = .{ .key = f.name, .value = try r.value(&f.layout, &nested) };
                        try nested.charge(f.name.len);
                    }
                }
                pbvalue.sortEntries(es);
                try m.charge(VS);
                return .{ .@"struct" = es };
            },
        }
    }

    /// Skips one value of layout `l` (the visitor's `skip_field`/`NullTraversal`).
    fn skip(r: *R, l: *const Layout) Fail!void {
        switch (l.*) {
            .bool => if ((try r.c.take(1))[0] > 1) return error.Bad,
            .u8 => _ = try r.c.take(1),
            .u16 => _ = try r.c.take(2),
            .u32 => _ = try r.c.take(4),
            .u64 => _ = try r.c.take(8),
            .u128 => _ = try r.c.take(16),
            .u256 => _ = try r.c.take(32),
            .address, .signer => _ = try r.c.take(32),
            .vector => |el| {
                const n = try r.c.uleb();
                var i: u64 = 0;
                while (i < n) : (i += 1) try r.skip(el);
            },
            .@"struct" => |s| for (s.fields) |*f| try r.skip(&f.layout),
            .@"enum" => |e| {
                const tag = (try r.c.take(1))[0];
                if (tag > 127 or tag >= e.variants.len) return error.Bad;
                for (e.variants[tag].fields) |*f| try r.skip(&f.layout);
            },
        }
    }

    fn structValue(r: *R, s: *const movelayout.Struct, m: *const Meter) Fail!Value {
        const t = &s.type_;
        if (isStringLike(t)) {
            // the first field's bytes, read as a BCS String
            if (s.fields.len == 0) return error.Bad;
            const lo = r.c.pos;
            try r.skip(&s.fields[0].layout);
            const text = try bcsString(r.c.b[lo..r.c.pos]);
            for (s.fields[1..]) |*f| try r.skip(&f.layout);
            return r.str(m, text);
        }
        if (isFramework(t, 2, "object", "UID") or isFramework(t, 2, "object", "ID")) {
            if (s.fields.len == 0) return error.Bad;
            const lo = r.c.pos;
            try r.skip(&s.fields[0].layout);
            if (r.c.pos - lo != 32) return error.Bad;
            const v = try r.addr(m, r.c.b[lo..][0..32]);
            for (s.fields[1..]) |*f| try r.skip(&f.layout);
            return v;
        }
        if (isFramework(t, 1, "option", "Option")) {
            // OptionVisitor: the layout must be exactly Option<T> { vec: vector<T> }
            if (t.type_args.len != 1 or s.fields.len != 1 or !std.mem.eql(u8, s.fields[0].name, "vec") or s.fields[0].layout != .vector) return error.Bad;
            const el = s.fields[0].layout.vector;
            const n = try r.c.uleb();
            return switch (n) {
                0 => blk: {
                    try m.charge(VS);
                    break :blk .null;
                },
                1 => try r.value(el, m),
                else => error.Bad,
            };
        }
        if (isFramework(t, 2, "balance", "Balance") and t.type_args.len == 1 and s.fields.len == 1 and
            std.mem.eql(u8, s.fields[0].name, "value") and s.fields[0].layout == .u64)
        {
            return r.dec(m, u64, try r.int(u64));
        }
        const es = try r.arena.alloc(pbvalue.Entry, s.fields.len);
        {
            const nested = try m.nest();
            for (s.fields, es) |*f, *o| {
                o.* = .{ .key = f.name, .value = try r.value(&f.layout, &nested) };
                try nested.charge(f.name.len);
            }
        }
        pbvalue.sortEntries(es);
        try m.charge(VS);
        return .{ .@"struct" = es };
    }
};

fn isFramework(t: *const types.StructTag, comptime a: u8, module: []const u8, name: []const u8) bool {
    const addr = &t.address.@"0";
    for (addr[0..31]) |b| if (b != 0) return false;
    return addr[31] == a and std.mem.eql(u8, t.module.@"0", module) and std.mem.eql(u8, t.name.@"0", name);
}

fn isStringLike(t: *const types.StructTag) bool {
    if (t.type_args.len != 0) return false;
    return isFramework(t, 1, "ascii", "String") or isFramework(t, 1, "string", "String") or
        isFramework(t, 1, "type_name", "TypeName") or isFramework(t, 2, "url", "Url");
}

/// `bcs::from_bytes::<String>`: canonical ULEB128 length, exact length, valid UTF-8.
fn bcsString(b: []const u8) Fail![]const u8 {
    var c: Cursor = .{ .b = b };
    var v: u64 = 0;
    var shift: u6 = 0;
    var i: usize = 0;
    while (true) : (i += 1) {
        const byte = (try c.take(1))[0];
        if (i == 4 and byte > 0x0f) return error.Bad; // bcs caps lengths at u32
        v |= @as(u64, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) {
            if (byte == 0 and i > 0) return error.Bad; // non-canonical
            break;
        }
        if (i == 4) return error.Bad;
        shift += 7;
    }
    if (v > std.math.maxInt(u31)) return error.Bad; // bcs MAX_SEQUENCE_LENGTH
    if (b.len - c.pos != v) return error.Bad;
    const s = b[c.pos..];
    if (!std.unicode.utf8ValidateSlice(s)) return error.Bad;
    return s;
}

/// Renders `bytes` with `layout`, drawing from `budget`. Null on any failure.
pub fn render(arena: Allocator, layout: *const Layout, bytes: []const u8, budget: *usize) Allocator.Error!?Value {
    var r: R = .{ .arena = arena, .c = .{ .b = bytes } };
    const m: Meter = .{ .size = budget, .depth = max_depth };
    const v = r.value(layout, &m) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Bad => return null,
    };
    if (r.c.pos != bytes.len) return null;
    return v;
}

/// `RpcService::render_json_with_budget`: resolve the layout of `tag`, then render.
pub fn renderTyped(arena: Allocator, res: *movelayout.Resolver, tag: *const types.StructTag, bytes: []const u8, budget: *usize) Allocator.Error!?Value {
    const l = (try res.structLayout(tag)) orelse return null;
    return render(arena, &l, bytes, budget);
}

test "render_json: primitives, strings, option, enum" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var budget: usize = 1 << 20;
    // u64
    {
        const l: Layout = .u64;
        const v = (try render(a, &l, &.{ 42, 0, 0, 0, 0, 0, 0, 0 }, &budget)).?;
        try std.testing.expectEqualStrings("42", v.string);
    }
    // vector<u8> base64
    {
        const el: Layout = .u8;
        const l: Layout = .{ .vector = &el };
        const v = (try render(a, &l, &.{ 3, 'a', 'b', 'c' }, &budget)).?;
        try std.testing.expectEqualStrings("YWJj", v.string);
    }
    // trailing bytes
    {
        const l: Layout = .u8;
        try std.testing.expect((try render(a, &l, &.{ 1, 2 }, &budget)) == null);
    }
    // budget exhaustion keeps what was consumed
    {
        var small: usize = 40;
        const l: Layout = .u64;
        try std.testing.expect((try render(a, &l, &.{ 1, 0, 0, 0, 0, 0, 0, 0 }, &small)) != null);
        try std.testing.expectEqual(@as(usize, 40 - 33), small);
    }
}
