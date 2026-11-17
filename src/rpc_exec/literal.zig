//! Literal inputs of transaction resolution (sui-rpc-api
//! `transaction_execution_service/simulate/resolve/literal.rs`, mainnet-v1.83.1): an `Input` whose
//! `literal` (a `google.protobuf.Value`) becomes a Pure input, BCS-encoded as the Move type the
//! commands use it as. The type inference over the input's uses lives in resolve.zig
//! (`determine_literal_type`); this file holds the value (as prost decodes it), the normalized
//! type (`move_binary_format::normalized::Type`: equality and Display) and
//! `resolve_literal_to_type`.
//!
//! What Rust does, kept here as is:
//! - numbers are f64 cast `as u64` (saturating: negative and NaN give 0, too large gives
//!   u64::MAX, fractions truncate), then `TryFrom<u64>` into the target width;
//! - decimal strings parse with Rust's `FromStr` (u8..u128: an optional `+`) or
//!   `move_core_types::u256::U256::from_str` (leading zeros trimmed, an empty string is 0);
//! - addresses parse as `ObjectID::from_str`, and their error says "as bool" (Rust's message);
//! - `vector<u8>` takes a list only (no string form), `0x1::string::String` and
//!   `0x1::ascii::String` take a string unchecked, `0x1::option::Option<T>` takes null or a value;
//!   any other datatype (`0x2::object::ID` included), signer, a reference or a type parameter is
//!   refused.
const std = @import("std");
const types = @import("types");
const serve = @import("serve");
const mf = @import("move_format");

const resolve = @import("resolve.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const proto = serve.proto;
const ff = mf.file_format;

pub const DecodeError = proto.Reader.DecodeError || Allocator.Error;

// ---- the value ---------------------------------------------------------------------------------

/// `google.protobuf.Value` as prost decodes it (`kind` oneof; a struct's contents are never read).
pub const Lit = union(enum) {
    /// `kind` unset
    none,
    null_value,
    number: f64,
    string: []const u8,
    bool_value: bool,
    struct_value,
    list: []const Lit,
};

/// prost's recursion budget left for the literal: `DecodeContext` starts at 100 for the
/// SimulateTransactionRequest and each nested message takes one (Transaction, TransactionKind,
/// ProgrammableTransaction, Input), so the literal Value decodes at 95 and a message nested in a
/// message at 0 fails to decode (48 nested lists decode, a value inside the 48th does not).
pub const recursion_limit = 95;

/// Decodes the `literal` field's bytes (every occurrence concatenated: prost merges them).
pub fn decode(arena: Allocator, msg: []const u8) DecodeError!Lit {
    return decodeValue(arena, msg, recursion_limit);
}

/// prost `Value::merge_field`: a field of another `kind` replaces the oneof, a second
/// `list_value` merges into the first (its values append), unknown fields are skipped.
fn decodeValue(arena: Allocator, msg: []const u8, limit: u32) DecodeError!Lit {
    var v: Lit = .none;
    var list: std.ArrayList(Lit) = .empty;
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| switch (f.number) {
        1 => {
            _ = try proto.Reader.varintOf(f);
            v = .null_value;
        },
        2 => {
            if (f.wire != 1) return error.Malformed;
            v = .{ .number = @bitCast(std.mem.readInt(u64, f.data[0..8], .little)) };
        },
        3 => v = .{ .string = try proto.Reader.stringOf(f) },
        4 => v = .{ .bool_value = (try proto.Reader.varintOf(f)) != 0 },
        5 => {
            const b = try proto.Reader.bytesOf(f);
            if (limit == 0) return error.Malformed;
            try checkStruct(arena, b, limit - 1);
            v = .struct_value;
        },
        6 => {
            const b = try proto.Reader.bytesOf(f);
            if (limit == 0) return error.Malformed;
            if (v != .list) list = .empty;
            var lr = proto.Reader.init(b);
            while (try lr.next()) |g| if (g.number == 1) {
                const e = try proto.Reader.bytesOf(g);
                if (limit - 1 == 0) return error.Malformed;
                try list.append(arena, try decodeValue(arena, e, limit - 2));
            };
            v = .{ .list = list.items };
        },
        else => {},
    };
    return v;
}

/// `Struct { map<string, Value> fields = 1 }`: decoded for its errors only.
fn checkStruct(arena: Allocator, msg: []const u8, limit: u32) DecodeError!void {
    var r = proto.Reader.init(msg);
    while (try r.next()) |f| if (f.number == 1) {
        const entry = try proto.Reader.bytesOf(f);
        if (limit == 0) return error.Malformed;
        var er = proto.Reader.init(entry);
        while (try er.next()) |g| switch (g.number) {
            1 => _ = try proto.Reader.stringOf(g),
            2 => {
                const b = try proto.Reader.bytesOf(g);
                if (limit - 1 == 0) return error.Malformed;
                _ = try decodeValue(arena, b, limit - 2);
            },
            else => {},
        };
    };
}

// ---- the type ----------------------------------------------------------------------------------

/// `move_binary_format::normalized::Type`.
pub const LType = union(enum) {
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    u256,
    address,
    signer,
    vector: *const LType,
    datatype: Datatype,
    reference: struct { mutable: bool, to: *const LType },
    type_param: u16,

    pub const Datatype = struct { address: Id, module: []const u8, name: []const u8, args: []const LType };

    /// `#[derive(PartialEq)]`.
    pub fn eql(a: *const LType, b: *const LType) bool {
        if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
        return switch (a.*) {
            .vector => |x| eql(x, b.vector),
            .reference => |x| x.mutable == b.reference.mutable and eql(x.to, b.reference.to),
            .type_param => |x| x == b.type_param,
            .datatype => |x| blk: {
                const y = b.datatype;
                if (!std.mem.eql(u8, &x.address, &y.address) or !std.mem.eql(u8, x.module, y.module) or
                    !std.mem.eql(u8, x.name, y.name) or x.args.len != y.args.len) break :blk false;
                for (x.args, y.args) |*p, *q| if (!eql(p, q)) break :blk false;
                break :blk true;
            },
            else => true,
        };
    }

    /// `Display`: `0x{short_str_lossless}::m::S<A, B>`, `vector<T>`, `&T`, `&mut T`, `T{i}`.
    pub fn display(t: *const LType, arena: Allocator) Allocator.Error![]const u8 {
        var out: std.ArrayList(u8) = .empty;
        try t.write(arena, &out);
        return out.items;
    }

    fn write(t: *const LType, arena: Allocator, out: *std.ArrayList(u8)) Allocator.Error!void {
        switch (t.*) {
            .datatype => |d| {
                try out.appendSlice(arena, "0x");
                try appendShortHex(arena, out, &d.address);
                try out.appendSlice(arena, "::");
                try out.appendSlice(arena, d.module);
                try out.appendSlice(arena, "::");
                try out.appendSlice(arena, d.name);
                if (d.args.len > 0) {
                    try out.append(arena, '<');
                    for (d.args, 0..) |*a, i| {
                        if (i > 0) try out.appendSlice(arena, ", ");
                        try a.write(arena, out);
                    }
                    try out.append(arena, '>');
                }
            },
            .vector => |x| {
                try out.appendSlice(arena, "vector<");
                try x.write(arena, out);
                try out.append(arena, '>');
            },
            .reference => |r| {
                try out.appendSlice(arena, if (r.mutable) "&mut " else "&");
                try r.to.write(arena, out);
            },
            .type_param => |i| try out.print(arena, "T{d}", .{i}),
            else => try out.appendSlice(arena, @tagName(t.*)),
        }
    }
};

/// `AccountAddress::short_str_lossless`: lowercase hex without leading zeros, "0" for zero.
fn appendShortHex(arena: Allocator, out: *std.ArrayList(u8), a: *const Id) Allocator.Error!void {
    const hex = std.fmt.bytesToHex(a.*, .lower);
    var i: usize = 0;
    while (i < hex.len and hex[i] == '0') i += 1;
    try out.appendSlice(arena, if (i == hex.len) "0" else hex[i..]);
}

/// A function parameter's type (`normalized::Type::new` over a signature token): datatypes carry
/// their module handle's address and names.
pub fn fromToken(arena: Allocator, cm: *const ff.CompiledModule, t: ff.Token) Allocator.Error!LType {
    const n = t[0];
    return switch (n.tag) {
        .Bool => .bool,
        .U8 => .u8,
        .U16 => .u16,
        .U32 => .u32,
        .U64 => .u64,
        .U128 => .u128,
        .U256 => .u256,
        .Address => .address,
        .Signer => .signer,
        .Vector => .{ .vector = try boxed(arena, try fromToken(arena, cm, ff.inner(t))) },
        .Reference, .MutableReference => .{ .reference = .{
            .mutable = n.tag == .MutableReference,
            .to = try boxed(arena, try fromToken(arena, cm, ff.inner(t))),
        } },
        .TypeParameter => .{ .type_param = n.idx },
        .Datatype, .DatatypeInstantiation => blk: {
            const dh = cm.datatypeHandleAt(n.idx);
            const mh = cm.moduleHandleAt(dh.module);
            var args: []const LType = &.{};
            if (n.tag == .DatatypeInstantiation) {
                const xs = try arena.alloc(LType, n.arity);
                var it = ff.ArgIter.init(t);
                for (xs) |*a| a.* = try fromToken(arena, cm, it.next().?);
                args = xs;
            }
            break :blk .{ .datatype = .{
                .address = cm.address_identifiers[mh.address],
                .module = cm.identifierAt(mh.name),
                .name = cm.identifierAt(dh.name),
                .args = args,
            } };
        },
    };
}

/// `normalized::Type::from_type_tag` (a MakeMoveVector element type).
pub fn fromTypeInput(arena: Allocator, t: *const types.TypeInput) Allocator.Error!LType {
    return switch (t.*) {
        .bool => .bool,
        .u8 => .u8,
        .u16 => .u16,
        .u32 => .u32,
        .u64 => .u64,
        .u128 => .u128,
        .u256 => .u256,
        .address => .address,
        .signer => .signer,
        .vector => |x| .{ .vector = try boxed(arena, try fromTypeInput(arena, x)) },
        .@"struct" => |s| blk: {
            const args = try arena.alloc(LType, s.type_args.len);
            for (s.type_args, args) |*a, *o| o.* = try fromTypeInput(arena, a);
            break :blk .{ .datatype = .{ .address = s.address.@"0", .module = s.module.@"0", .name = s.name.@"0", .args = args } };
        },
    };
}

fn boxed(arena: Allocator, t: LType) Allocator.Error!*const LType {
    const p = try arena.create(LType);
    p.* = t;
    return p;
}

// ---- resolve_literal_to_type -------------------------------------------------------------------

/// The Pure bytes, or the INVALID_ARGUMENT message.
pub const Encoded = union(enum) { ok: []const u8, err: []const u8 };

pub fn encode(arena: Allocator, ty: *const LType, v: *const Lit) Allocator.Error!Encoded {
    var buf: std.ArrayList(u8) = .empty;
    if (try toType(arena, &buf, ty, v)) |msg| return .{ .err = msg };
    return .{ .ok = buf.items };
}

const Msg = ?[]const u8;

fn isStd(d: *const LType.Datatype, module: []const u8, name: []const u8) bool {
    var one: Id = @splat(0);
    one[31] = 1;
    return std.mem.eql(u8, &d.address, &one) and std.mem.eql(u8, d.module, module) and std.mem.eql(u8, d.name, name);
}

fn toType(arena: Allocator, buf: *std.ArrayList(u8), ty: *const LType, v: *const Lit) Allocator.Error!Msg {
    switch (ty.*) {
        .bool => return asBool(arena, buf, v),
        .u8 => return asNumber(u8, "u8", arena, buf, v),
        .u16 => return asNumber(u16, "u16", arena, buf, v),
        .u32 => return asNumber(u32, "u32", arena, buf, v),
        .u64 => return asNumber(u64, "u64", arena, buf, v),
        .u128 => return asNumber(u128, "u128", arena, buf, v),
        .u256 => return asNumber(u256, "move_core_types::u256::U256", arena, buf, v),
        .address => return asAddress(arena, buf, v),
        .datatype => |*d| {
            if ((isStd(d, "ascii", "String") or isStd(d, "string", "String")) and d.args.len == 0) return asString(arena, buf, v);
            if (isStd(d, "option", "Option") and d.args.len == 1) return asOption(arena, buf, &d.args[0], v);
        },
        .vector => |inner| return asVector(arena, buf, inner, v),
        .signer, .type_param, .reference => {},
    }
    return try std.fmt.allocPrint(arena, "literal cannot be resolved into type {s}", .{try ty.display(arena)});
}

fn asBool(arena: Allocator, buf: *std.ArrayList(u8), v: *const Lit) Allocator.Error!Msg {
    const b = switch (v.*) {
        .bool_value => |b| b,
        // `bool::from_str`
        .string => |s| if (std.mem.eql(u8, s, "true")) true else if (std.mem.eql(u8, s, "false")) false else return "literal cannot be resolved as bool: provided string was not `true` or `false`",
        else => return "literal cannot be resolved into type bool",
    };
    try buf.append(arena, @intFromBool(b));
    return null;
}

/// Rust `f64 as u64`: saturating, NaN to 0, toward zero.
fn saturatingU64(x: f64) u64 {
    if (std.math.isNan(x) or x <= 0) return 0;
    if (x >= 18446744073709551616.0) return std.math.maxInt(u64);
    return @intFromFloat(x);
}

const int_empty = "cannot parse integer from empty string";
const int_invalid = "invalid digit found in string";
const int_too_large = "number too large to fit in target type";
const u256_invalid = "a character is not in the range 0-9";
const u256_too_large = "the number is too large for the type";

const Parsed = union(enum) { ok: u256, err: []const u8 };

/// Rust `uN::from_str` (`from_str_radix(s, 10)`): empty is Empty; a lone sign, a `-` or any
/// non-digit is InvalidDigit; one leading `+` is skipped; digits left to right, each checked for
/// a digit before the overflow (PosOverflow).
fn parseRust(comptime T: type, s: []const u8) Parsed {
    if (s.len == 0) return .{ .err = int_empty };
    if (s.len == 1 and (s[0] == '+' or s[0] == '-')) return .{ .err = int_invalid };
    const digits = if (s[0] == '+') s[1..] else s;
    var r: T = 0;
    for (digits) |c| {
        const mul = @mulWithOverflow(r, 10);
        if (c < '0' or c > '9') return .{ .err = int_invalid };
        if (mul[1] != 0) return .{ .err = int_too_large };
        const add = @addWithOverflow(mul[0], @as(T, @intCast(c - '0')));
        if (add[1] != 0) return .{ .err = int_too_large };
        r = add[0];
    }
    return .{ .ok = r };
}

/// `move_core_types::u256::U256::from_str`: leading `0`s trimmed, then uint's `from_dec_str`
/// (an empty string is 0).
fn parseU256(s: []const u8) Parsed {
    var i: usize = 0;
    while (i < s.len and s[i] == '0') i += 1;
    var r: u256 = 0;
    for (s[i..]) |c| {
        const d = c -% '0';
        if (d > 9) return .{ .err = u256_invalid };
        const mul = @mulWithOverflow(r, 10);
        if (mul[1] != 0) return .{ .err = u256_too_large };
        const add = @addWithOverflow(mul[0], @as(u256, d));
        if (add[1] != 0) return .{ .err = u256_too_large };
        r = add[0];
    }
    return .{ .ok = r };
}

fn asNumber(comptime T: type, comptime name: []const u8, arena: Allocator, buf: *std.ArrayList(u8), v: *const Lit) Allocator.Error!Msg {
    const n: T = switch (v.*) {
        .number => |x| blk: {
            const u = saturatingU64(x);
            // `TryFrom<u64>`: fallible below u64 only
            if (@bitSizeOf(T) < 64 and u > std.math.maxInt(T))
                return "literal cannot be resolved as " ++ name ++ ": out of range integral type conversion attempted";
            break :blk @intCast(u);
        },
        .string => |s| switch (if (T == u256) parseU256(s) else parseRust(T, s)) {
            .ok => |x| @intCast(x),
            .err => |e| return try std.fmt.allocPrint(arena, "literal cannot be resolved as " ++ name ++ ": {s}", .{e}),
        },
        else => return "literal cannot be resolved into type " ++ name,
    };
    var b: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &b, n, .little);
    try buf.appendSlice(arena, &b);
    return null;
}

fn asAddress(arena: Allocator, buf: *std.ArrayList(u8), v: *const Lit) Allocator.Error!Msg {
    switch (v.*) {
        .string => |s| {
            const id = resolve.parseObjectId(s) orelse
                return "literal cannot be resolved as bool: " ++ resolve.object_id_parse_error;
            try buf.appendSlice(arena, &id);
            return null;
        },
        else => return "literal cannot be resolved into type address",
    }
}

fn uleb(arena: Allocator, buf: *std.ArrayList(u8), n: u32) Allocator.Error!void {
    var x = n;
    while (x >= 0x80) : (x >>= 7) try buf.append(arena, @as(u8, @truncate(x)) | 0x80);
    try buf.append(arena, @truncate(x));
}

fn asString(arena: Allocator, buf: *std.ArrayList(u8), v: *const Lit) Allocator.Error!Msg {
    switch (v.*) {
        .string => |s| {
            try uleb(arena, buf, @intCast(s.len));
            try buf.appendSlice(arena, s);
            return null;
        },
        else => return "literal cannot be resolved into string",
    }
}

fn asOption(arena: Allocator, buf: *std.ArrayList(u8), inner: *const LType, v: *const Lit) Allocator.Error!Msg {
    switch (v.*) {
        .null_value => {
            try buf.append(arena, 0);
            return null;
        },
        .bool_value, .number, .string, .list => {
            try buf.append(arena, 1);
            return toType(arena, buf, inner, v);
        },
        .struct_value, .none => return "literal cannot be resolved into Option",
    }
}

fn asVector(arena: Allocator, buf: *std.ArrayList(u8), inner: *const LType, v: *const Lit) Allocator.Error!Msg {
    switch (v.*) {
        .list => |xs| {
            try uleb(arena, buf, @truncate(xs.len));
            for (xs) |*x| if (try toType(arena, buf, inner, x)) |m| return m;
            return null;
        },
        else => return try std.fmt.allocPrint(arena, "literal cannot be resolved into type Vector<{s}>", .{try inner.display(arena)}),
    }
}

// ---- tests (literal.rs's own cases, and answers of a 1.83.1 fullnode) --------------------------

const testing = std.testing;

fn expectOk(ty: LType, v: Lit, want: []const u8) !void {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    switch (try encode(a.allocator(), &ty, &v)) {
        .ok => |b| try testing.expectEqualSlices(u8, want, b),
        .err => |m| {
            std.debug.print("{any} as {s}: unexpected error \"{s}\"\n", .{ v, try ty.display(a.allocator()), m });
            return error.TestUnexpectedResult;
        },
    }
}

fn expectErr(ty: LType, v: Lit, want: []const u8) !void {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    switch (try encode(a.allocator(), &ty, &v)) {
        .ok => |b| {
            std.debug.print("{any} as {s}: unexpected bytes {x}\n", .{ v, try ty.display(a.allocator()), b });
            return error.TestUnexpectedResult;
        },
        .err => |m| try testing.expectEqualStrings(want, m),
    }
}

fn stdType(module: []const u8, name: []const u8, args: []const LType) LType {
    var one: Id = @splat(0);
    one[31] = 1;
    return .{ .datatype = .{ .address = one, .module = module, .name = name, .args = args } };
}

fn rep(comptime n: usize, comptime b: u8) [n]u8 {
    return @splat(b);
}

const t_u8: LType = .u8;
const t_bool: LType = .bool;
const t_address: LType = .address;

const two_hex = "0x0000000000000000000000000000000000000000000000000000000000000002";
const two: Id = blk: {
    var x: Id = @splat(0);
    x[31] = 2;
    break :blk x;
};

test "literal bool: true/false values and strings, every other kind refused" {
    try expectOk(.bool, .{ .bool_value = true }, &.{1});
    try expectOk(.bool, .{ .bool_value = false }, &.{0});
    try expectOk(.bool, .{ .string = "true" }, &.{1});
    try expectOk(.bool, .{ .string = "false" }, &.{0});
    try expectErr(.bool, .null_value, "literal cannot be resolved into type bool");
    try expectErr(.bool, .{ .number = 0 }, "literal cannot be resolved into type bool");
    try expectErr(.bool, .{ .list = &.{} }, "literal cannot be resolved into type bool");
    try expectErr(.bool, .{ .string = "True" }, "literal cannot be resolved as bool: provided string was not `true` or `false`");
    try expectErr(.bool, .{ .string = "foo" }, "literal cannot be resolved as bool: provided string was not `true` or `false`");
}

test "literal integers: f64 cast as u64 then TryFrom, strings through FromStr" {
    try expectOk(.u8, .{ .number = 255 }, &.{0xff});
    try expectOk(.u8, .{ .string = "0" }, &.{0});
    try expectOk(.u8, .{ .string = "+5" }, &.{5});
    try expectOk(.u8, .{ .number = 3.9 }, &.{3});
    try expectOk(.u8, .{ .number = -1 }, &.{0});
    try expectOk(.u16, .{ .number = 65535 }, &.{ 0xff, 0xff });
    try expectOk(.u16, .{ .string = "1" }, &.{ 1, 0 });
    try expectOk(.u32, .{ .number = 4294967295 }, &.{ 0xff, 0xff, 0xff, 0xff });
    try expectOk(.u32, .{ .string = "7" }, &.{ 7, 0, 0, 0 });
    const max64 = (comptime rep(8, 0xff));
    try expectOk(.u64, .{ .number = 18446744073709551615.0 }, &max64);
    try expectOk(.u64, .{ .string = "18446744073709551615" }, &max64);
    try expectOk(.u64, .{ .number = std.math.inf(f64) }, &max64);
    try expectOk(.u64, .{ .number = std.math.nan(f64) }, &((comptime rep(8, 0))));
    try expectOk(.u64, .{ .number = 1e300 }, &max64);
    try expectOk(.u64, .{ .number = -1e300 }, &((comptime rep(8, 0))));
    try expectOk(.u128, .{ .number = 5 }, &([_]u8{5} ++ (comptime rep(15, 0))));
    try expectOk(.u128, .{ .string = "340282366920938463463374607431768211455" }, &((comptime rep(16, 0xff))));
    try expectOk(.u256, .{ .number = 7 }, &([_]u8{7} ++ (comptime rep(31, 0))));
    try expectOk(.u256, .{ .string = "115792089237316195423570985008687907853269984665640564039457584007913129639935" }, &((comptime rep(32, 0xff))));
    try expectOk(.u256, .{ .string = "000123" }, &([_]u8{123} ++ (comptime rep(31, 0))));
    try expectOk(.u256, .{ .string = "" }, &((comptime rep(32, 0))));

    try expectErr(.u8, .{ .number = 300 }, "literal cannot be resolved as u8: out of range integral type conversion attempted");
    try expectErr(.u8, .{ .number = std.math.inf(f64) }, "literal cannot be resolved as u8: out of range integral type conversion attempted");
    try expectErr(.u16, .{ .number = 65536 }, "literal cannot be resolved as u16: out of range integral type conversion attempted");
    try expectErr(.u8, .{ .string = "300" }, "literal cannot be resolved as u8: number too large to fit in target type");
    try expectErr(.u8, .{ .string = "" }, "literal cannot be resolved as u8: cannot parse integer from empty string");
    try expectErr(.u8, .{ .string = "-1" }, "literal cannot be resolved as u8: invalid digit found in string");
    try expectErr(.u8, .{ .string = "+" }, "literal cannot be resolved as u8: invalid digit found in string");
    try expectErr(.u8, .{ .string = "1.5" }, "literal cannot be resolved as u8: invalid digit found in string");
    try expectErr(.u8, .{ .string = "9999x" }, "literal cannot be resolved as u8: number too large to fit in target type");
    try expectErr(.u8, .{ .string = "foo" }, "literal cannot be resolved as u8: invalid digit found in string");
    try expectErr(.u32, .{ .string = "4294967296" }, "literal cannot be resolved as u32: number too large to fit in target type");
    try expectErr(.u64, .{ .string = "18446744073709551616" }, "literal cannot be resolved as u64: number too large to fit in target type");
    try expectErr(.u128, .{ .string = "340282366920938463463374607431768211456" }, "literal cannot be resolved as u128: number too large to fit in target type");
    try expectErr(.u256, .{ .string = "abc" }, "literal cannot be resolved as move_core_types::u256::U256: a character is not in the range 0-9");
    try expectErr(.u256, .{ .string = "+1" }, "literal cannot be resolved as move_core_types::u256::U256: a character is not in the range 0-9");
    try expectErr(.u256, .{ .string = "115792089237316195423570985008687907853269984665640564039457584007913129639936" }, "literal cannot be resolved as move_core_types::u256::U256: the number is too large for the type");
    try expectErr(.u256, .{ .string = "115792089237316195423570985008687907853269984665640564039457584007913129639936x" }, "literal cannot be resolved as move_core_types::u256::U256: the number is too large for the type");
    for ([_]Lit{ .{ .bool_value = true }, .null_value, .{ .list = &.{} }, .struct_value, .none }) |v| {
        try expectErr(.u8, v, "literal cannot be resolved into type u8");
        try expectErr(.u128, v, "literal cannot be resolved into type u128");
        try expectErr(.u256, v, "literal cannot be resolved into type move_core_types::u256::U256");
    }
}

test "literal address: ObjectID::from_str, its error rendered \"as bool\"" {
    try expectOk(.address, .{ .string = two_hex }, &two);
    try expectOk(.address, .{ .string = two_hex[2..] }, &two);
    try expectOk(.address, .{ .string = "0x2" }, &two);
    try expectOk(.address, .{ .string = "0x" }, &((comptime rep(32, 0))));
    try expectOk(.address, .{ .string = "0x0x" ++ two_hex[2..] }, &two); // from_hex_literal retries the rest
    try expectOk(.address, .{ .string = "0xx" ++ &(comptime rep(61, '0')) ++ "2" }, &two); // padded back to a 0x prefix
    try expectOk(.address, .{ .string = "0xABCDEF" }, &((comptime rep(29, 0)) ++ [_]u8{ 0xab, 0xcd, 0xef }));
    const bad = "literal cannot be resolved as bool: ObjectID hex literal must start with 0x";
    try expectErr(.address, .{ .string = "foo" }, bad);
    try expectErr(.address, .{ .string = "2" }, bad);
    try expectErr(.address, .{ .string = "0x" ++ &(comptime rep(65, '0')) ++ "2" }, bad);
    try expectErr(.address, .{ .number = 5 }, "literal cannot be resolved into type address");
    try expectErr(.address, .null_value, "literal cannot be resolved into type address");
}

test "literal strings, options and vectors" {
    const utf8 = stdType("string", "String", &.{});
    const ascii = stdType("ascii", "String", &.{});
    try expectOk(utf8, .{ .string = "hello" }, "\x05hello");
    try expectOk(ascii, .{ .string = "" }, &.{0});
    try expectOk(ascii, .{ .string = "h\xc3\xa9" }, "\x03h\xc3\xa9"); // unchecked
    try expectErr(utf8, .{ .number = 5 }, "literal cannot be resolved into string");
    try expectErr(ascii, .null_value, "literal cannot be resolved into string");
    try expectErr(stdType("string", "String", &.{.u8}), .{ .string = "x" }, "literal cannot be resolved into type 0x1::string::String<u8>");

    const opt_u64 = stdType("option", "Option", &.{.u64});
    try expectOk(opt_u64, .null_value, &.{0});
    try expectOk(opt_u64, .{ .number = 5 }, &([_]u8{ 1, 5 } ++ (comptime rep(7, 0))));
    try expectOk(opt_u64, .{ .string = "6" }, &([_]u8{ 1, 6 } ++ (comptime rep(7, 0))));
    try expectOk(stdType("option", "Option", &.{.address}), .{ .string = two_hex }, &([_]u8{1} ++ two));
    try expectOk(stdType("option", "Option", &.{.bool}), .{ .bool_value = true }, &.{ 1, 1 });
    try expectErr(stdType("option", "Option", &.{.bool}), .{ .number = 0 }, "literal cannot be resolved into type bool");
    try expectErr(opt_u64, .struct_value, "literal cannot be resolved into Option");
    try expectErr(opt_u64, .none, "literal cannot be resolved into Option");
    try expectErr(stdType("option", "Option", &.{ .u8, .u8 }), .null_value, "literal cannot be resolved into type 0x1::option::Option<u8, u8>");
    const inner_opt = stdType("option", "Option", &.{.u8});
    try expectOk(stdType("option", "Option", &.{inner_opt}), .{ .number = 1 }, &.{ 1, 1, 1 });

    const vec_u8: LType = .{ .vector = &t_u8 };
    try expectOk(vec_u8, .{ .list = &.{ .{ .number = 104 }, .{ .number = 105 } } }, "\x02hi");
    try expectOk(vec_u8, .{ .list = &.{} }, &.{0});
    try expectErr(vec_u8, .{ .string = "hi" }, "literal cannot be resolved into type Vector<u8>");
    const vv: LType = .{ .vector = &vec_u8 };
    try expectOk(vv, .{ .list = &.{.{ .list = &.{.{ .number = 9 }} }} }, &.{ 1, 1, 9 });
    try expectErr(vv, .{ .list = &.{ .{ .list = &.{.{ .number = 1 }} }, .{ .list = &.{.{ .number = 300 }} } } }, "literal cannot be resolved as u8: out of range integral type conversion attempted");
    const vs: LType = .{ .vector = &utf8 };
    const vvs: LType = .{ .vector = &vs };
    try expectErr(vvs, .{ .number = 1 }, "literal cannot be resolved into type Vector<vector<0x1::string::String>>");
    try expectErr(.{ .vector = &t_address }, .{ .list = &.{ .{ .string = two_hex }, .{ .number = 5 } } }, "literal cannot be resolved into type address");
    // the length is ULEB128
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const many = try a.allocator().alloc(Lit, 256);
    @memset(many, .{ .bool_value = true });
    try expectOk(.{ .vector = &t_bool }, .{ .list = many }, &([_]u8{ 0x80, 0x02 } ++ (comptime rep(256, 1))));
}

test "literal types sui-node refuses, named by normalized::Type's Display" {
    var lz: Id = @splat(0);
    lz[31] = 0xab;
    var usdc: Id = undefined;
    _ = try std.fmt.hexToBytes(&usdc, "dba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7");
    const id: LType = .{ .datatype = .{ .address = two, .module = "object", .name = "ID", .args = &.{} } };
    try expectErr(id, .{ .string = "0x2" }, "literal cannot be resolved into type 0x2::object::ID");
    try expectErr(.{ .datatype = .{ .address = usdc, .module = "usdc", .name = "USDC", .args = &.{} } }, .{ .number = 1 }, "literal cannot be resolved into type 0xdba34672e30cb065b1f93e3ab55318768fd6fef66c15942c9f7cb846e2f900e7::usdc::USDC");
    try expectErr(.{ .datatype = .{ .address = lz, .module = "m", .name = "S", .args = &.{ .u8, .{ .vector = &t_address } } } }, .{ .number = 1 }, "literal cannot be resolved into type 0xab::m::S<u8, vector<address>>");
    try expectErr(.signer, .{ .number = 1 }, "literal cannot be resolved into type signer");
    try expectErr(.{ .type_param = 0 }, .{ .number = 5 }, "literal cannot be resolved into type T0");
    const utf8 = stdType("string", "String", &.{});
    try expectErr(.{ .reference = .{ .mutable = false, .to = &utf8 } }, .{ .string = "x" }, "literal cannot be resolved into type &0x1::string::String");
    const bal: LType = .{ .datatype = .{ .address = two, .module = "balance", .name = "Balance", .args = &.{.{ .type_param = 0 }} } };
    try expectErr(.{ .reference = .{ .mutable = true, .to = &bal } }, .{ .number = 1 }, "literal cannot be resolved into type &mut 0x2::balance::Balance<T0>");
}

fn pbLen(al: Allocator, out: *std.ArrayList(u8), field: u32, body: []const u8) !void {
    try out.append(al, @intCast(field << 3 | 2));
    try uleb(al, out, @intCast(body.len));
    try out.appendSlice(al, body);
}

test "literal values decode like prost: merged occurrences, last kind wins, the recursion limit" {
    var a: std.heap.ArenaAllocator = .init(testing.allocator);
    defer a.deinit();
    const al = a.allocator();
    // list_value [1] then list_value [2]: one list [1, 2]
    const one_num = [_]u8{ 0x11, 0, 0, 0, 0, 0, 0, 0xf0, 0x3f }; // number_value 1.0
    const two_num = [_]u8{ 0x11, 0, 0, 0, 0, 0, 0, 0, 0x40 }; // number_value 2.0
    var l1: std.ArrayList(u8) = .empty;
    try pbLen(al, &l1, 1, &one_num);
    var l2: std.ArrayList(u8) = .empty;
    try pbLen(al, &l2, 1, &two_num);
    var msg: std.ArrayList(u8) = .empty;
    try pbLen(al, &msg, 6, l1.items);
    try pbLen(al, &msg, 6, l2.items);
    const merged = try decode(al, msg.items);
    try testing.expectEqual(@as(usize, 2), merged.list.len);
    try testing.expectEqual(@as(f64, 2), merged.list[1].number);
    // struct then number: the number; an unknown field is skipped
    const sn = [_]u8{ 0x2a, 0x00, 0x48, 0x01 } ++ one_num;
    try testing.expectEqual(@as(f64, 1), (try decode(al, &sn)).number);
    try testing.expectEqual(Lit.none, try decode(al, &.{}));
    // null_value as length-delimited: invalid wire type
    try testing.expectError(error.Malformed, decode(al, &.{ 0x0a, 0x00 }));
    // invalid UTF-8 string
    try testing.expectError(error.Malformed, decode(al, &.{ 0x1a, 0x01, 0xff }));
    // 48 nested lists decode; a value inside the 48th does not
    for ([_]bool{ false, true }) |inner| {
        var cur: []const u8 = if (inner) &one_num else &.{};
        var lists: usize = 0;
        if (!inner) {
            cur = &.{ 0x32, 0x00 }; // Value { list_value {} }
            lists = 1;
        }
        while (lists < 48) : (lists += 1) {
            var lb: std.ArrayList(u8) = .empty;
            try pbLen(al, &lb, 1, cur);
            var vb: std.ArrayList(u8) = .empty;
            try pbLen(al, &vb, 6, lb.items);
            cur = vb.items;
        }
        if (inner) try testing.expectError(error.Malformed, decode(al, cur)) else _ = try decode(al, cur);
    }
}
