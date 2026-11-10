//! Type strings to TypeTag/StructTag, accepting what move-core-types `StructTag::from_str` and
//! sui-sdk-types `StructTag::from_str` accept for well-formed input: `0x`-prefixed hex addresses of
//! 1 to 64 digits (left-padded), `::`-separated module and name identifiers, `<...>` type arguments
//! separated by `,` with optional spaces, the primitive names and `vector<T>`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");

pub const Error = error{ Invalid, OutOfMemory };

const P = struct {
    s: []const u8,
    i: usize = 0,
    arena: Allocator,

    fn ws(p: *P) void {
        while (p.i < p.s.len and (p.s[p.i] == ' ' or p.s[p.i] == '\t' or p.s[p.i] == '\n')) p.i += 1;
    }
    fn eat(p: *P, lit: []const u8) bool {
        if (std.mem.startsWith(u8, p.s[p.i..], lit)) {
            p.i += lit.len;
            return true;
        }
        return false;
    }
    fn ident(p: *P) Error![]const u8 {
        const start = p.i;
        while (p.i < p.s.len and (std.ascii.isAlphanumeric(p.s[p.i]) or p.s[p.i] == '_')) p.i += 1;
        const id = p.s[start..p.i];
        if (!types.Identifier.isValid(id)) return error.Invalid;
        return id;
    }
    fn address(p: *P) Error![32]u8 {
        if (!p.eat("0x")) return error.Invalid;
        const start = p.i;
        while (p.i < p.s.len and std.ascii.isHex(p.s[p.i])) p.i += 1;
        const hex = p.s[start..p.i];
        if (hex.len == 0 or hex.len > 64) return error.Invalid;
        var padded: [64]u8 = @splat('0');
        @memcpy(padded[64 - hex.len ..], hex);
        var out: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, &padded) catch return error.Invalid;
        return out;
    }
    fn typeTag(p: *P, depth: u32) Error!types.TypeTag {
        if (depth > 64) return error.Invalid;
        p.ws();
        const prims = [_]struct { []const u8, types.TypeTag }{
            .{ "bool", .bool }, .{ "u8", .u8 },         .{ "u16", .u16 },       .{ "u32", .u32 },
            .{ "u64", .u64 },   .{ "u128", .u128 },     .{ "u256", .u256 },     .{ "address", .address },
            .{ "signer", .signer },
        };
        if (p.i < p.s.len and p.s[p.i] != '0') {
            if (p.eat("vector")) {
                p.ws();
                if (!p.eat("<")) return error.Invalid;
                const inner = try p.arena.create(types.TypeTag);
                inner.* = try p.typeTag(depth + 1);
                p.ws();
                if (!p.eat(">")) return error.Invalid;
                return .{ .vector = inner };
            }
            const id = try p.ident();
            for (prims) |pr| if (std.mem.eql(u8, id, pr[0])) return pr[1];
            return error.Invalid;
        }
        return .{ .@"struct" = try p.structTag(depth) };
    }
    fn structTag(p: *P, depth: u32) Error!types.StructTag {
        p.ws();
        const a = try p.address();
        if (!p.eat("::")) return error.Invalid;
        const m = try p.ident();
        if (!p.eat("::")) return error.Invalid;
        const n = try p.ident();
        var args: std.ArrayList(types.TypeTag) = .empty;
        p.ws();
        if (p.eat("<")) {
            while (true) {
                try args.append(p.arena, try p.typeTag(depth + 1));
                p.ws();
                if (p.eat(">")) break;
                if (!p.eat(",")) return error.Invalid;
            }
            if (args.items.len == 0) return error.Invalid;
        }
        return .{ .address = .{ .@"0" = a }, .module = .{ .@"0" = m }, .name = .{ .@"0" = n }, .type_args = args.items };
    }
};

pub fn structTag(arena: Allocator, s: []const u8) Error!types.StructTag {
    var p: P = .{ .s = s, .arena = arena };
    const t = try p.structTag(0);
    p.ws();
    if (p.i != s.len) return error.Invalid;
    return t;
}

pub fn typeTag(arena: Allocator, s: []const u8) Error!types.TypeTag {
    var p: P = .{ .s = s, .arena = arena };
    const t = try p.typeTag(0);
    p.ws();
    if (p.i != s.len) return error.Invalid;
    return t;
}

test "typeparse" {
    var a = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer a.deinit();
    const t = try structTag(a.allocator(), "0x2::coin::Coin<0x2::sui::SUI>");
    try std.testing.expectEqualStrings("Coin", t.name.@"0");
    try std.testing.expectEqual(@as(u8, 2), t.address.@"0"[31]);
    const u = try structTag(a.allocator(), "0x2::dynamic_field::Field<vector<u8>, 0xabc::m::S<u64,address>>");
    try std.testing.expectEqual(@as(usize, 2), u.type_args.len);
    try std.testing.expectError(error.Invalid, structTag(a.allocator(), "0x2::coin"));
    try std.testing.expectError(error.Invalid, structTag(a.allocator(), "u64"));
}
