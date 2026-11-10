//! zui/1 index methods (NATIVE-PROTOCOL.md 4.1): list_owned_objects, get_balance, list_balances
//! on the on-disk owner/balance index (src/index, `--indexes`). Rows are read under the index's
//! shared lock with a store snapshot taken inside it (the same pin as StateService), so every
//! (id, version) row has its object in the snapshot. Cursors are opaque: the owner-index suffix
//! (owned) or the BCS coin TypeTag (balances) to resume at, inclusive.
const std = @import("std");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
const store = @import("store");
const serve = @import("serve");
const index = @import("index");
const proto = @import("proto.zig");
const W = proto.W;
const R = proto.R;

pub const max_page = 1000;
pub const default_page = 50;
/// Coin objects counted per balance row (beyond it the count is capped).
pub const max_coin_count = 100_000;

pub const Error = error{ Unavailable, Malformed, OutOfMemory } || anyerror;

fn pageSize(limit: u32) usize {
    if (limit == 0) return default_page;
    return @min(@as(usize, limit), max_page);
}

/// The pin: index read lock plus a snapshot taken under it.
const Pin = struct {
    ix: *index.Index,
    snap: store.Snapshot,

    fn take(ix: *index.Index, st: *store.Store) error{Unavailable}!Pin {
        if (!ix.ready.load(.acquire)) return error.Unavailable; // fast start: still building
        ix.lock.lockShared();
        return .{ .ix = ix, .snap = st.snapshot() };
    }
    fn unlock(p: *Pin) void {
        p.ix.lock.unlockShared();
    }
};

pub fn canonical(arena: Allocator, t: types.TypeTag) ![]const u8 {
    var cap: usize = 256;
    while (true) : (cap *= 4) {
        const buf = try arena.alloc(u8, cap);
        var o: serve.typestr.Out = .{ .buf = buf };
        serve.typestr.typeTag(&o, t) catch |e| {
            if (cap > 1 << 20) return e;
            continue;
        };
        return o.str();
    }
}

const sui_framework: [32]u8 = blk: {
    var x: [32]u8 = @splat(0);
    x[31] = 2;
    break :blk x;
};

/// BCS StructTag of `0x2::coin::Coin<coin>`: the owner-index type prefix of its coin objects.
fn coinStructBcs(arena: Allocator, coin: types.TypeTag) ![]const u8 {
    const args = try arena.alloc(types.TypeTag, 1);
    args[0] = coin;
    const st: types.StructTag = .{ .address = .{ .@"0" = sui_framework }, .module = .{ .@"0" = "coin" }, .name = .{ .@"0" = "Coin" }, .type_args = args };
    return bcs.encodeAlloc(types.StructTag, arena, &st);
}

/// Coin<T> objects the owner holds (index rows), capped at `max_coin_count`. Lock held.
fn coinCount(a: Allocator, ix: *index.Index, owner: *const [32]u8, coin: types.TypeTag) !u64 {
    const prefix = try coinStructBcs(a, coin);
    var it = try ix.ownedIter(a, .address, owner, prefix);
    var n: u64 = 0;
    while (try it.next()) |e| {
        if (!std.mem.startsWith(u8, e.key, prefix)) break;
        n += 1;
        if (n >= max_coin_count) break;
    }
    return n;
}

fn nonNeg(v: i128) u128 {
    return if (v < 0) 0 else @intCast(v);
}

fn writeBalance(w: W, ts: []const u8, bal: index.Bal, coins: u64, as_of: u64) !void {
    const coin = nonNeg(bal.coin);
    const addr = nonNeg(bal.address);
    try w.str(ts);
    try w.int(u128, coin +| addr);
    try w.int(u128, coin);
    try w.int(u128, addr);
    try w.int(u64, coins);
    try w.int(u64, as_of);
}

/// GetBalance: `BalanceReq` body to a `Balance`.
pub fn getBalance(a: Allocator, ix: *index.Index, st: *store.Store, body: []const u8, w: W) !void {
    var r: R = .{ .b = body };
    const owner = (try r.fixed(32)).*;
    const tt = try r.str();
    try r.done();
    const st_tag = index.typeparse.structTag(a, tt) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    const tag: types.TypeTag = .{ .@"struct" = st_tag };
    const tb = try bcs.encodeAlloc(types.TypeTag, a, &tag);
    var pin = try Pin.take(ix, st);
    defer pin.snap.release();
    const bal, const coins = blk: {
        defer pin.unlock();
        break :blk .{ try ix.balance(a, &owner, tb), try coinCount(a, ix, &owner, tag) };
    };
    try proto.okHeader(w.out, a, 0);
    try writeBalance(w, try canonical(a, tag), bal, coins, pin.snap.highestCommitted() orelse 0);
}

/// ListBalances: `BalancesReq` to a `BalancePage`.
pub fn listBalances(a: Allocator, ix: *index.Index, st: *store.Store, body: []const u8, w: W) !void {
    var r: R = .{ .b = body };
    const owner = (try r.fixed(32)).*;
    const cursor: []const u8 = if (try r.option()) try r.bytes() else "";
    const n = pageSize(try r.int(u32));
    try r.done();
    const Row = struct { key: []const u8, tag: types.TypeTag, val: index.Bal, coins: u64 };
    var rows: std.ArrayList(Row) = .empty;
    var next: ?[]const u8 = null;
    var pin = try Pin.take(ix, st);
    defer pin.snap.release();
    {
        defer pin.unlock();
        defer for (rows.items) |*row| {
            row.coins = coinCount(a, ix, &owner, row.tag) catch 0;
        };
        var it = try ix.balanceIter(a, &owner, cursor);
        while (try it.next()) |e| {
            if (rows.items.len == n) {
                next = try a.dupe(u8, e.key);
                break;
            }
            // decode from a copy: the iterator's key buffer is reused, and BCS decoding borrows
            const key = try a.dupe(u8, e.key);
            const val = e.val;
            const tag = bcs.decode(types.TypeTag, a, key) catch continue;
            try rows.append(a, .{ .key = key, .tag = tag, .val = val, .coins = 0 });
        }
    }
    const as_of = pin.snap.highestCommitted() orelse 0;
    try proto.okHeader(w.out, a, 0);
    try w.uleb(rows.items.len);
    for (rows.items) |row| try writeBalance(w, try canonical(a, row.tag), row.val, row.coins, as_of);
    try w.optBytes(next);
    try w.int(u64, as_of);
}

/// ListOwnedObjects: `OwnedReq` to an `OwnedPage` (objects are `Found` only).
pub fn listOwned(a: Allocator, ix: *index.Index, st: *store.Store, body: []const u8, w: W) !void {
    var r: R = .{ .b = body };
    const owner = (try r.fixed(32)).*;
    const type_text: ?[]const u8 = if (try r.option()) try r.str() else null;
    const cursor: ?[]const u8 = if (try r.option()) try r.bytes() else null;
    const n = pageSize(try r.int(u32));
    try r.done();
    // Type filter: without type params every instantiation matches (the prefix drops the
    // empty type-args length byte), with params only that instantiation.
    var prefix: []const u8 = "";
    if (type_text) |tt| {
        const t = index.typeparse.structTag(a, tt) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.Malformed,
        };
        const fb = try bcs.encodeAlloc(types.StructTag, a, &t);
        prefix = if (t.type_args.len == 0) fb[0 .. fb.len - 1] else fb;
    }
    if (cursor) |c| if (!std.mem.startsWith(u8, c, prefix)) return error.Malformed;
    const Row = struct { id: [32]u8, ver: u64 };
    var rows: std.ArrayList(Row) = .empty;
    var next: ?[]const u8 = null;
    var pin = try Pin.take(ix, st);
    defer pin.snap.release();
    {
        defer pin.unlock();
        var it = try ix.ownedIter(a, .address, &owner, cursor orelse prefix);
        while (try it.next()) |e| {
            if (!std.mem.startsWith(u8, e.key, prefix)) break;
            if (rows.items.len == n) {
                next = try a.dupe(u8, e.key);
                break;
            }
            const row = index.splitOwnerSuffix(e.key) catch continue;
            try rows.append(a, .{ .id = row.id.*, .ver = e.ver });
        }
    }
    try proto.okHeader(w.out, a, 0);
    // count first: objects the snapshot lacks (cannot happen under the pin) are skipped
    var found: std.ArrayList(store.ObjectRef) = .empty;
    for (rows.items) |row| if (try pin.snap.objectAtChecked(&row.id, row.ver)) |o| try found.append(a, o);
    try w.uleb(found.items.len);
    for (found.items) |o| {
        try w.uleb(0); // Found
        try w.int(u64, o.version);
        try w.fixed(&o.digest);
        try w.bytes(o.bytes);
    }
    try w.optBytes(next);
    try w.int(u64, pin.snap.highestCommitted() orelse 0);
}

// ---------------------------------------------------------------- tests

test "page size defaults and caps" {
    try std.testing.expectEqual(@as(usize, default_page), pageSize(0));
    try std.testing.expectEqual(@as(usize, 7), pageSize(7));
    try std.testing.expectEqual(@as(usize, max_page), pageSize(50_000));
}

test "Coin<T> prefix is the owner-index type key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const sui = try index.typeparse.typeTag(a, "0x2::sui::SUI");
    const p = try coinStructBcs(a, sui);
    const want = try index.typeparse.structTag(a, "0x2::coin::Coin<0x2::sui::SUI>");
    try std.testing.expectEqualSlices(u8, try bcs.encodeAlloc(types.StructTag, a, &want), p);
    try std.testing.expectEqualStrings("0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI", try canonical(a, sui));
}
