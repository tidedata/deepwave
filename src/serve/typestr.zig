//! Canonical type strings: `to_canonical_string(true)` of move-core-types TypeTag / StructTag
//! (full-width 0x addresses, `,` without space between type arguments) and the object type
//! forms Sui derives from `MoveObjectType`.
const std = @import("std");
const types = @import("types");

pub const Error = error{NoSpace};

pub const Out = struct {
    buf: []u8,
    len: usize = 0,
    /// Grows (into this thread's scratch buffer, see `scratch`) instead of failing.
    grow: bool = false,

    pub fn str(o: *const Out) []const u8 {
        return o.buf[0..o.len];
    }
    fn room(o: *Out, n: usize) Error!void {
        if (o.buf.len - o.len >= n) return;
        if (!o.grow) return error.NoSpace;
        const want = @max(o.len + n, @max(o.buf.len * 2, 1024));
        const nb = std.heap.page_allocator.alloc(u8, want) catch return error.NoSpace;
        @memcpy(nb[0..o.len], o.buf[0..o.len]);
        if (tl_scratch.len != 0 and o.buf.ptr == tl_scratch.ptr) std.heap.page_allocator.free(tl_scratch);
        tl_scratch = nb;
        o.buf = nb;
    }
    fn lit(o: *Out, s: []const u8) Error!void {
        try o.room(s.len);
        @memcpy(o.buf[o.len..][0..s.len], s);
        o.len += s.len;
    }
    pub fn address(o: *Out, a: *const [32]u8) Error!void {
        try o.room(66);
        o.buf[o.len] = '0';
        o.buf[o.len + 1] = 'x';
        const hex = "0123456789abcdef";
        for (a, 0..) |b, i| {
            o.buf[o.len + 2 + 2 * i] = hex[b >> 4];
            o.buf[o.len + 3 + 2 * i] = hex[b & 15];
        }
        o.len += 66;
    }
};

threadlocal var tl_scratch: []u8 = &.{};

/// An `Out` for a type string of any length (Move types nest and take up to 32 type arguments,
/// so a fixed buffer can always be outgrown on chain): it writes into this thread's scratch
/// buffer, which grows and is kept for the next call. The string is valid until the next
/// `scratch()` on this thread.
pub fn scratch() Out {
    return .{ .buf = tl_scratch, .grow = true };
}

pub fn typeTag(o: *Out, t: types.TypeTag) Error!void {
    switch (t) {
        .bool => try o.lit("bool"),
        .u8 => try o.lit("u8"),
        .u16 => try o.lit("u16"),
        .u32 => try o.lit("u32"),
        .u64 => try o.lit("u64"),
        .u128 => try o.lit("u128"),
        .u256 => try o.lit("u256"),
        .address => try o.lit("address"),
        .signer => try o.lit("signer"),
        .vector => |inner| {
            try o.lit("vector<");
            try typeTag(o, inner.*);
            try o.lit(">");
        },
        .@"struct" => |s| try structTag(o, s),
    }
}

pub fn structTag(o: *Out, s: types.StructTag) Error!void {
    try o.address(&s.address.@"0");
    try o.lit("::");
    try o.lit(s.module.str());
    try o.lit("::");
    try o.lit(s.name.str());
    if (s.type_args.len > 0) {
        try o.lit("<");
        for (s.type_args, 0..) |a, i| {
            if (i > 0) try o.lit(",");
            try typeTag(o, a);
        }
        try o.lit(">");
    }
}

const addr2: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 2;
    break :blk a;
};
const addr3: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 3;
    break :blk a;
};

fn sui(o: *Out, mod_name: []const u8, name: []const u8) Error!void {
    try o.address(&addr2);
    try o.lit("::");
    try o.lit(mod_name);
    try o.lit("::");
    try o.lit(name);
}

/// Canonical string of a `MoveObjectType` (what `MoveObject::type_().to_canonical_string(true)`
/// prints).
pub fn moveObjectType(o: *Out, t: types.MoveObjectType) Error!void {
    switch (t.@"0") {
        .Other => |s| try structTag(o, s),
        .GasCoin => {
            try sui(o, "coin", "Coin");
            try o.lit("<");
            try sui(o, "sui", "SUI");
            try o.lit(">");
        },
        .StakedSui => {
            try o.address(&addr3);
            try o.lit("::staking_pool::StakedSui");
        },
        .Coin => |inner| {
            try sui(o, "coin", "Coin");
            try o.lit("<");
            try typeTag(o, inner);
            try o.lit(">");
        },
        .SuiBalanceAccumulatorField => try accumulatorField(o, null),
        .BalanceAccumulatorField => |inner| try accumulatorField(o, inner),
    }
}

// Field<Key<Balance<T>>,U128> in 0x2.
fn accumulatorField(o: *Out, inner: ?types.TypeTag) Error!void {
    try sui(o, "dynamic_field", "Field");
    try o.lit("<");
    try sui(o, "accumulator", "Key");
    try o.lit("<");
    try sui(o, "balance", "Balance");
    try o.lit("<");
    if (inner) |t| try typeTag(o, t) else try sui(o, "sui", "SUI");
    try o.lit(">>,");
    try sui(o, "accumulator", "U128");
    try o.lit(">");
}

pub fn typeInput(o: *Out, t: types.TypeInput) Error!void {
    switch (t) {
        .bool => try o.lit("bool"),
        .u8 => try o.lit("u8"),
        .u16 => try o.lit("u16"),
        .u32 => try o.lit("u32"),
        .u64 => try o.lit("u64"),
        .u128 => try o.lit("u128"),
        .u256 => try o.lit("u256"),
        .address => try o.lit("address"),
        .signer => try o.lit("signer"),
        .vector => |inner| {
            try o.lit("vector<");
            try typeInput(o, inner.*);
            try o.lit(">");
        },
        .@"struct" => |s| {
            try o.address(&s.address.@"0");
            try o.lit("::");
            try o.lit(s.module.@"0");
            try o.lit("::");
            try o.lit(s.name.@"0");
            if (s.type_args.len > 0) {
                try o.lit("<");
                for (s.type_args, 0..) |a, i| {
                    if (i > 0) try o.lit(",");
                    try typeInput(o, a);
                }
                try o.lit(">");
            }
        },
    }
}

test "scratch: type strings of any length" {
    var params: [40]types.TypeTag = undefined;
    for (&params) |*t| t.* = .address;
    var inner: types.StructTag = undefined;
    _ = &inner;
    var o = scratch();
    var n: usize = 0;
    while (n < 200) : (n += 1) try o.address(&@as([32]u8, @splat(0xab)));
    try std.testing.expectEqual(@as(usize, 200 * 66), o.str().len);
    try std.testing.expectEqualStrings("0xabab", o.str()[0..6]);
    var fixed_buf: [70]u8 = undefined;
    var f: Out = .{ .buf = &fixed_buf };
    try f.address(&@as([32]u8, @splat(1)));
    try std.testing.expectError(error.NoSpace, f.address(&@as([32]u8, @splat(1))));
}
