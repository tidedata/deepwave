//! `derive_balance_changes_2` (sui-types balance_change.rs): per (address, coin type) net coin
//! balance change of one transaction, from the checkpoint's object set, plus accumulator
//! (address balance) events. Rendered as `BalanceChange { address, coin_type, amount }`.
const std = @import("std");
const Allocator = std.mem.Allocator;
const types = @import("types");
const bcs = @import("bcs");
const proto = @import("proto.zig");
const ro = @import("render_object.zig");
const typestr = @import("typestr.zig");

pub const Key = [40]u8; // object id ++ version (little endian)
pub const ObjMap = @import("objset.zig").Map;

pub fn key(id: *const [32]u8, version: u64) Key {
    var k: Key = undefined;
    @memcpy(k[0..32], id);
    std.mem.writeInt(u64, k[32..40], version, .little);
    return k;
}

pub const Error = ro.Error;

pub const Change = struct { address: [32]u8, coin_type: types.TypeTag, coin: i128 = 0, addr: i128 = 0 };

const sui_type: types.TypeTag = .{ .@"struct" = .{
    .address = .{ .@"0" = blk: {
        var a: [32]u8 = @splat(0);
        a[31] = 2;
        break :blk a;
    } },
    .module = .{ .@"0" = "sui" },
    .name = .{ .@"0" = "SUI" },
    .type_args = &.{},
} };

fn variantRank(t: types.TypeTag) u8 {
    return switch (t) {
        .bool => 0,
        .u8 => 1,
        .u64 => 2,
        .u128 => 3,
        .address => 4,
        .signer => 5,
        .vector => 6,
        .@"struct" => 7,
        .u16 => 8,
        .u32 => 9,
        .u256 => 10,
    };
}

/// Rust's derived `Ord` for `TypeTag`.
fn cmpType(a: types.TypeTag, b: types.TypeTag) std.math.Order {
    const ra = variantRank(a);
    const rb = variantRank(b);
    if (ra != rb) return std.math.order(ra, rb);
    switch (a) {
        .vector => |x| return cmpType(x.*, b.vector.*),
        .@"struct" => |x| {
            const y = b.@"struct";
            var o = std.mem.order(u8, &x.address.@"0", &y.address.@"0");
            if (o != .eq) return o;
            o = std.mem.order(u8, x.module.str(), y.module.str());
            if (o != .eq) return o;
            o = std.mem.order(u8, x.name.str(), y.name.str());
            if (o != .eq) return o;
            const n = @min(x.type_args.len, y.type_args.len);
            for (0..n) |i| {
                o = cmpType(x.type_args[i], y.type_args[i]);
                if (o != .eq) return o;
            }
            return std.math.order(x.type_args.len, y.type_args.len);
        },
        else => return .eq,
    }
}

fn cmpKey(a: Change, b: Change) std.math.Order {
    const o = std.mem.order(u8, &a.address, &b.address);
    if (o != .eq) return o;
    return cmpType(a.coin_type, b.coin_type);
}

fn coinType(mo: types.MoveObject) ?types.TypeTag {
    return switch (mo.type_.@"0") {
        .GasCoin => sui_type,
        .Coin => |t| t,
        else => null,
    };
}

const Acc = struct {
    list: std.ArrayList(Change) = .empty,

    fn add(acc: *Acc, arena: Allocator, address: [32]u8, t: types.TypeTag, coin: i128, addr: i128) !void {
        for (acc.list.items) |*c| {
            if (std.mem.eql(u8, &c.address, &address) and cmpType(c.coin_type, t) == .eq) {
                c.coin += coin;
                c.addr += addr;
                return;
            }
        }
        try acc.list.append(arena, .{ .address = address, .coin_type = t, .coin = coin, .addr = addr });
    }

    /// Only coin objects count: the BCS head (Move object, GasCoin or Coin type tag) tells, so
    /// nothing else is decoded.
    fn addObject(acc: *Acc, arena: Allocator, raw: []const u8, sign: i128) Error!void {
        if (raw.len < 2 or raw[0] != 0 or (raw[1] != 1 and raw[1] != 3)) return;
        const obj = try bcs.decode(types.Object, arena, raw);
        const mo = switch (obj.data) {
            .Move => |m| m,
            .Package => return,
        };
        const address = switch (obj.owner) {
            .AddressOwner => |a| a.@"0",
            .ConsensusAddressOwner => |c| c.owner.@"0",
            .Party => return error.Unsupported,
            else => return,
        };
        const t = coinType(mo) orelse return;
        if (mo.contents.len != 40) return error.InvalidValue;
        const bal = std.mem.readInt(u64, mo.contents[32..40], .little);
        try acc.add(arena, address, t, sign * @as(i128, bal), 0);
    }
};

/// Balance changes of one transaction in BTreeMap key order, zero nets removed.
pub fn derive(arena: Allocator, eff: types.TransactionEffects, objs: *const ObjMap) Error![]const Change {
    var acc: Acc = .{};
    switch (eff) {
        .V2 => |v| {
            for (v.changed_objects) |e| {
                switch (e.@"1".input_state) {
                    .Exist => |x| if (objs.get(key(&e.@"0".@"0".@"0", x.@"0".@"0".@"0"))) |o| try acc.addObject(arena, o, -1),
                    .NotExist => {},
                }
            }
            for (v.changed_objects) |e| {
                switch (e.@"1".output_state) {
                    .ObjectWrite => if (objs.get(key(&e.@"0".@"0".@"0", v.lamport_version.@"0"))) |o| try acc.addObject(arena, o, 1),
                    else => {},
                }
            }
            for (v.changed_objects) |e| switch (e.@"1".output_state) {
                .AccumulatorWriteV1 => |w| {
                    // Balance<T> events only, integer values only
                    const ty = w.address.ty;
                    if (ty != .@"struct") continue;
                    const s = ty.@"struct";
                    if (!isBalance(s)) continue;
                    const amt: i128 = switch (w.value) {
                        .Integer => |x| x,
                        else => continue,
                    };
                    const signed: i128 = switch (w.operation) {
                        .Split => -amt,
                        .Merge => amt,
                    };
                    try acc.add(arena, w.address.address.@"0", s.type_args[0], 0, signed);
                },
                else => {},
            };
        },
        .V1 => |v| {
            for (v.modified_at_versions) |e| if (objs.get(key(&e.@"0".@"0".@"0", e.@"1".@"0"))) |o| try acc.addObject(arena, o, -1);
            for (v.mutated) |e| if (objs.get(key(&e.@"0".@"0".@"0".@"0", e.@"0".@"1".@"0"))) |o| try acc.addObject(arena, o, 1);
            for (v.created) |e| if (objs.get(key(&e.@"0".@"0".@"0".@"0", e.@"0".@"1".@"0"))) |o| try acc.addObject(arena, o, 1);
            for (v.unwrapped) |e| if (objs.get(key(&e.@"0".@"0".@"0".@"0", e.@"0".@"1".@"0"))) |o| try acc.addObject(arena, o, 1);
        },
    }
    std.mem.sort(Change, acc.list.items, {}, struct {
        fn lt(_: void, a: Change, b: Change) bool {
            return cmpKey(a, b) == .lt;
        }
    }.lt);
    // drop zero-net entries (both the detailed and the final filter)
    var n: usize = 0;
    for (acc.list.items) |c| {
        if (c.coin + c.addr == 0) continue;
        acc.list.items[n] = c;
        n += 1;
    }
    return acc.list.items[0..n];
}

fn isBalance(s: types.StructTag) bool {
    const a = s.address.@"0";
    for (a[0..31]) |b| if (b != 0) return false;
    return a[31] == 2 and std.mem.eql(u8, s.module.str(), "balance") and std.mem.eql(u8, s.name.str(), "Balance") and s.type_args.len == 1;
}

pub fn write(w: *proto.Writer, field: u32, c: Change) Error!void {
    const m = try w.begin(field, 200);
    try ro.addrStr(w, 1, &c.address);
    var o = typestr.scratch();
    try typestr.typeTag(&o, c.coin_type);
    try w.string(2, o.str());
    var nb: [48]u8 = undefined;
    const amount = c.coin + c.addr;
    const s = std.fmt.bufPrint(&nb, "{d}", .{amount}) catch unreachable;
    try w.string(3, s);
    try w.end(m);
}
