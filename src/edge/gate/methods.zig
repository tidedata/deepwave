//! The methods a gate prices and meters, as small integers. The table is fixed when the node
//! starts (every gRPC path the service routes, every zui/1 method), so a caller sending made-up
//! paths cannot grow anything: whatever is not in the table is method 0, "other".
//!
//! Names are written as the contract writes them: `sui.rpc.v2.LedgerService/GetObject`, without
//! a leading slash.
const std = @import("std");
const contract = @import("contract.zig");

pub const max_methods = 96;

pub const Kind = enum(u8) {
    normal,
    /// Costs 0 and is never limited or metered (health checks, reflection, service info).
    free,
    /// A server stream: one call at open, counted against `max_streams` while open.
    stream,
    /// A batch read: the caller states how many items it asks for (`per_item` pricing).
    batch,
};

pub const Def = struct { name: []const u8, kind: Kind = .normal };

pub const Methods = struct {
    names: [max_methods][]const u8 = @splat(""),
    kinds: [max_methods]Kind = @splat(.normal),
    n: u8 = 1,
    /// Open addressing over the name hash; 0: empty.
    index: [256]u8 = @splat(0),

    pub const other: u8 = 0;

    /// `defs` must outlive the table (static strings). Entries past `max_methods - 1` are left
    /// out and count as "other".
    pub fn init(defs: []const Def) Methods {
        var m: Methods = .{};
        m.names[0] = "other";
        for (defs) |d| {
            if (m.n == max_methods) break;
            const name = contract.methodName(d.name);
            if (name.len == 0 or m.id(name) != other) continue;
            m.names[m.n] = name;
            m.kinds[m.n] = d.kind;
            var i: u8 = @truncate(std.hash.Wyhash.hash(0, name));
            while (m.index[i] != 0) i +%= 1;
            m.index[i] = m.n;
            m.n += 1;
        }
        return m;
    }

    /// The id of a gRPC `:path` or a bare name; `other` when it is not in the table.
    pub fn id(m: *const Methods, path: []const u8) u8 {
        const name = contract.methodName(path);
        var i: u8 = @truncate(std.hash.Wyhash.hash(0, name));
        while (true) : (i +%= 1) {
            const k = m.index[i];
            if (k == 0) return other;
            if (std.mem.eql(u8, m.names[k], name)) return k;
        }
    }

    pub fn name_(m: *const Methods, k: u8) []const u8 {
        return m.names[if (k < m.n) k else other];
    }
};

/// One price table: what each method of a `Methods` table costs under one resolve or free
/// answer. Many keys share one (a plan's table), see `state.Prices`.
pub const PriceSet = struct {
    /// Units per call.
    w: [max_methods]u32 = @splat(1),
    /// Batch reads: units = 1 + ceil(ids / n) when n is not 0.
    per_item: [max_methods]u32 = @splat(0),
    /// Streams: n units per started minute open when n is not 0.
    per_minute: [max_methods]u32 = @splat(0),

    pub fn build(m: *const Methods, p: contract.Pricing) PriceSet {
        var s: PriceSet = .{};
        @memset(&s.w, p.default);
        for (p.weights) |x| {
            const k = m.id(x.method);
            if (k != Methods.other) s.w[k] = x.n;
        }
        for (p.per_item) |x| {
            const k = m.id(x.method);
            if (k != Methods.other) s.per_item[k] = x.n;
        }
        for (p.per_minute) |x| {
            const k = m.id(x.method);
            if (k != Methods.other) s.per_minute[k] = x.n;
        }
        return s;
    }

    pub fn hash(s: *const PriceSet) u64 {
        return std.hash.Wyhash.hash(0x67617465, std.mem.asBytes(s)) | 1;
    }
};

/// Units of one call. `items`: how many items a batch read asks for (null: not a batch, or
/// unknown). A stream priced per minute costs its first minute at open.
pub fn price(w: u32, per_item: u32, per_minute: u32, kind: Kind, items: ?u32) u32 {
    if (kind == .stream and per_minute != 0) return per_minute;
    if (kind == .batch and per_item != 0) if (items) |n| {
        return 1 +| (n / per_item + @intFromBool(n % per_item != 0));
    };
    return w;
}

/// `units` multiplied by `forward_weight_mult` (thousandths), rounded up.
pub fn forwarded(units: u32, milli: u32) u32 {
    const x = (@as(u64, units) * milli + 999) / 1000;
    return @intCast(@min(x, std.math.maxInt(u32)));
}

test "methods: ids by path or name, everything else is other" {
    const defs = [_]Def{
        .{ .name = "/sui.rpc.v2.LedgerService/GetObject" },
        .{ .name = "sui.rpc.v2.LedgerService/BatchGetObjects", .kind = .batch },
        .{ .name = "/grpc.health.v1.Health/Check", .kind = .free },
        .{ .name = "/sui.rpc.v2.SubscriptionService/SubscribeCheckpoints", .kind = .stream },
        .{ .name = "/sui.rpc.v2.LedgerService/GetObject" }, // listed twice: once
    };
    const m = Methods.init(&defs);
    try std.testing.expectEqual(@as(u8, 5), m.n);
    const get = m.id("/sui.rpc.v2.LedgerService/GetObject");
    try std.testing.expect(get != Methods.other);
    try std.testing.expectEqual(get, m.id("sui.rpc.v2.LedgerService/GetObject"));
    try std.testing.expectEqualStrings("sui.rpc.v2.LedgerService/GetObject", m.name_(get));
    try std.testing.expectEqual(Kind.free, m.kinds[m.id("/grpc.health.v1.Health/Check")]);
    try std.testing.expectEqual(Methods.other, m.id("/made.up/Path"));
    try std.testing.expectEqual(Methods.other, m.id(""));
    try std.testing.expectEqualStrings("other", m.name_(Methods.other));
    // more definitions than the table holds: the rest are "other", nothing overflows
    var many: [200]Def = undefined;
    var names: [200][12]u8 = undefined;
    for (&many, 0..) |*d, i| d.* = .{ .name = std.fmt.bufPrint(&names[i], "/s.S/M{d}", .{i}) catch unreachable };
    const full = Methods.init(&many);
    try std.testing.expectEqual(@as(u8, max_methods), full.n);
    try std.testing.expect(full.id("/s.S/M0") != Methods.other);
    try std.testing.expectEqual(Methods.other, full.id("/s.S/M199"));
}

test "prices: weights, per item (1 + ceil(ids / n)), per minute, the forward multiplier" {
    const defs = [_]Def{
        .{ .name = "a.A/Get" },
        .{ .name = "a.A/Batch", .kind = .batch },
        .{ .name = "a.A/Watch", .kind = .stream },
    };
    const m = Methods.init(&defs);
    const s = PriceSet.build(&m, .{
        .default = 2,
        .weights = &.{ .{ .method = "a.A/Get", .n = 5 }, .{ .method = "not.in/Table", .n = 99 }, .{ .method = "a.A/Watch", .n = 10 } },
        .per_item = &.{.{ .method = "a.A/Batch", .n = 10 }},
        .per_minute = &.{.{ .method = "a.A/Watch", .n = 7 }},
    });
    const get = m.id("a.A/Get");
    const batch = m.id("a.A/Batch");
    const watch = m.id("a.A/Watch");
    try std.testing.expectEqual(@as(u32, 5), price(s.w[get], s.per_item[get], s.per_minute[get], .normal, null));
    try std.testing.expectEqual(@as(u32, 2), price(s.w[0], s.per_item[0], s.per_minute[0], .normal, null)); // other: the default
    // batch: 1 + ceil(ids / 10)
    inline for (.{ .{ 0, 1 }, .{ 1, 2 }, .{ 10, 2 }, .{ 11, 3 }, .{ 1000, 101 } }) |c| {
        try std.testing.expectEqual(@as(u32, c[1]), price(s.w[batch], s.per_item[batch], s.per_minute[batch], .batch, c[0]));
    }
    // the item count is unknown, or the table has no per-item price: the flat weight
    try std.testing.expectEqual(@as(u32, 2), price(s.w[batch], s.per_item[batch], 0, .batch, null));
    try std.testing.expectEqual(@as(u32, 2), price(s.w[batch], 0, 0, .batch, 50));
    // stream: the first minute at open, or the flat weight without a per-minute price
    try std.testing.expectEqual(@as(u32, 7), price(s.w[watch], 0, s.per_minute[watch], .stream, null));
    try std.testing.expectEqual(@as(u32, 10), price(s.w[watch], 0, 0, .stream, null));
    try std.testing.expectEqual(@as(u32, 5), forwarded(5, 1000));
    try std.testing.expectEqual(@as(u32, 8), forwarded(5, 1500)); // 7.5 rounds up
    try std.testing.expectEqual(@as(u32, 15), forwarded(5, 3000));
    try std.testing.expectEqual(@as(u32, 0), forwarded(0, 3000));
    const same = PriceSet.build(&m, .{ .default = 2, .weights = &.{ .{ .method = "/a.A/Watch", .n = 10 }, .{ .method = "a.A/Get", .n = 5 } }, .per_item = &.{.{ .method = "a.A/Batch", .n = 10 }}, .per_minute = &.{.{ .method = "a.A/Watch", .n = 7 }} });
    try std.testing.expectEqual(s.hash(), same.hash());
}
