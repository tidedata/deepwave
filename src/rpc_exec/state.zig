//! Pre-state reads for simulation (CONTRACTS 6.7): what `TransactionInputLoader` and the
//! backing store answer. Every returned slice borrows the underlying snapshot or map (no copy);
//! it is valid while the snapshot is held.
const std = @import("std");
const store = @import("store");
const exec = @import("exec");

const Id = [32]u8;

/// Why an owner-index read failed (sui-node: the rpc-store iterator's errors answer INTERNAL; a
/// node whose index is still being built answers UNAVAILABLE, as its StateService does).
pub const OwnedError = error{ Unavailable, Internal, OutOfMemory };

/// The owner index behind gas selection: `owned_objects_iter(owner, Some(GasCoin::type_()))`.
/// `get` answers the ids of `owner`'s `0x2::coin::Coin<0x2::sui::SUI>` rows (address-owned and
/// consensus-address-owned, the index does not tell them apart) in index order: balance
/// descending, then id ascending; at most `limit`.
pub const GasCoinSource = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, arena: std.mem.Allocator, owner: *const Id, limit: usize) OwnedError![]const Id,
};

pub const State = struct {
    ctx: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The live version of `id` (any owner kind, packages included), raw BCS `Object`.
        latest: *const fn (ctx: *const anyopaque, id: *const Id) ?[]const u8,
        /// `id` at exactly `version`.
        at: *const fn (ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8,
        /// `read_child_object`: the newest version of `id` at or below `upper`.
        child_at_most: *const fn (ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8,
        /// Gas selection (`GasCoinSource.get`). Null when the source has no owner index
        /// (sui-node: `indexes()` is None, gas selection answers NOT_FOUND).
        owned_gas_coins: ?*const fn (ctx: *const anyopaque, arena: std.mem.Allocator, owner: *const Id, limit: usize) OwnedError![]const Id = null,
    };

    pub fn latest(s: State, id: *const Id) ?[]const u8 {
        return s.vtable.latest(s.ctx, id);
    }
    pub fn at(s: State, id: *const Id, version: u64) ?[]const u8 {
        return s.vtable.at(s.ctx, id, version);
    }
    pub fn childAtMost(s: State, id: *const Id, upper: u64) ?[]const u8 {
        return s.vtable.child_at_most(s.ctx, id, upper);
    }
    /// Null: the source has no owner index.
    pub fn ownedGasCoins(s: State, arena: std.mem.Allocator, owner: *const Id, limit: usize) OwnedError!?[]const Id {
        const f = s.vtable.owned_gas_coins orelse return null;
        return try f(s.ctx, arena, owner, limit);
    }

    /// Reads from a store snapshot: the live table for `latest` (a child's live version never
    /// exceeds its parent's version bound, so `child_at_most` is the live version when it fits).
    pub fn fromSnapshot(snap: *const store.Snapshot) State {
        return .{ .ctx = snap, .vtable = &snap_vtable };
    }
};

fn snapOf(ctx: *const anyopaque) *const store.Snapshot {
    return @ptrCast(@alignCast(ctx));
}
fn snapLatest(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
    const r = snapOf(ctx).liveObject(id) orelse return null;
    return r.bytes;
}
fn snapAt(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
    return snapOf(ctx).objectAt(id, version);
}
fn snapChild(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
    const r = snapOf(ctx).liveObject(id) orelse return null;
    return if (r.version <= upper) r.bytes else null;
}
const snap_vtable: State.VTable = .{ .latest = snapLatest, .at = snapAt, .child_at_most = snapChild };

/// A store snapshot plus the node's owner index (deepwave with `--indexes`): what sui-node's
/// simulate reads, the object store and the rpc-store index. The index trails the store (it is
/// fed after a checkpoint commits); a listed coin the snapshot no longer holds live is skipped by
/// gas selection, as sui-node's `get_object` returning None is.
pub const IndexedSnapshot = struct {
    snap: *const store.Snapshot,
    coins: GasCoinSource,

    pub fn state(s: *const IndexedSnapshot) State {
        return .{ .ctx = s, .vtable = &indexed_vtable };
    }

    fn of(ctx: *const anyopaque) *const IndexedSnapshot {
        return @ptrCast(@alignCast(ctx));
    }
    fn latestFn(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        return snapLatest(of(ctx).snap, id);
    }
    fn atFn(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        return snapAt(of(ctx).snap, id, version);
    }
    fn childFn(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        return snapChild(of(ctx).snap, id, upper);
    }
    fn coinsFn(ctx: *const anyopaque, arena: std.mem.Allocator, owner: *const Id, limit: usize) OwnedError![]const Id {
        const c = of(ctx).coins;
        return c.get(c.ctx, arena, owner, limit);
    }
    const indexed_vtable: State.VTable = .{ .latest = latestFn, .at = atFn, .child_at_most = childFn, .owned_gas_coins = coinsFn };
};

/// A pre-state held as one object per id (the suite's recorded pre-states, tests). Versions are
/// read from the object bytes (`Object` BCS: data, then the version right after the type).
pub const MapState = struct {
    map: std.AutoHashMapUnmanaged(Id, Entry) = .empty,

    pub const Entry = struct { version: u64, raw: []const u8 };

    pub fn put(m: *MapState, gpa: std.mem.Allocator, id: Id, version: u64, raw: []const u8) !void {
        try m.map.put(gpa, id, .{ .version = version, .raw = raw });
    }

    pub fn state(m: *const MapState) State {
        return .{ .ctx = m, .vtable = &map_vtable };
    }

    fn of(ctx: *const anyopaque) *const MapState {
        return @ptrCast(@alignCast(ctx));
    }
    fn latestFn(ctx: *const anyopaque, id: *const Id) ?[]const u8 {
        return if (of(ctx).map.get(id.*)) |e| e.raw else null;
    }
    fn atFn(ctx: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const e = of(ctx).map.get(id.*) orelse return null;
        return if (e.version == version) e.raw else null;
    }
    fn childFn(ctx: *const anyopaque, id: *const Id, upper: u64) ?[]const u8 {
        const e = of(ctx).map.get(id.*) orelse return null;
        return if (e.version <= upper) e.raw else null;
    }
    /// The owner index of the map's objects (the truth tool's pre-state `RpcIndexes`: rows for
    /// `AddressOwner(owner)` and `ConsensusAddressOwner { owner }` objects of type
    /// `Coin<SUI>`, keyed `(!balance, id)`).
    fn coinsFn(ctx: *const anyopaque, arena: std.mem.Allocator, owner: *const Id, limit: usize) OwnedError![]const Id {
        const Row = struct { balance: u64, id: Id };
        var rows: std.ArrayList(Row) = .empty;
        var it = of(ctx).map.iterator();
        while (it.next()) |kv| {
            const raw = kv.value_ptr.raw;
            const v = exec.objects.ObjectView.parse(raw) catch continue;
            const balance = gasCoinBalance(raw, &v) orelse continue;
            const o = raw[v.owner_at..];
            const addr: *const [32]u8 = switch (o[0]) {
                0 => if (o.len >= 33) o[1..33] else continue, // AddressOwner
                4 => if (o.len >= 41) o[9..41] else continue, // ConsensusAddressOwner { start_version, owner }
                else => continue,
            };
            if (!std.mem.eql(u8, addr, owner)) continue;
            try rows.append(arena, .{ .balance = balance, .id = v.id });
        }
        std.mem.sort(Row, rows.items, {}, struct {
            fn lt(_: void, a: Row, b: Row) bool {
                if (a.balance != b.balance) return a.balance > b.balance;
                return std.mem.order(u8, &a.id, &b.id) == .lt;
            }
        }.lt);
        const n = @min(limit, rows.items.len);
        const out = try arena.alloc(Id, n);
        for (out, rows.items[0..n]) |*o, r| o.* = r.id;
        return out;
    }
    const map_vtable: State.VTable = .{ .latest = latestFn, .at = atFn, .child_at_most = childFn, .owned_gas_coins = coinsFn };
};

/// The balance of a `Coin<SUI>` object (`MoveObjectType::GasCoin`, contents id || u64 balance).
pub fn gasCoinBalance(raw: []const u8, v: *const exec.objects.ObjectView) ?u64 {
    if (v.is_package or raw.len < 2 or raw[0] != 0 or raw[1] != 1) return null;
    const c = v.contents();
    if (c.len != 40) return null;
    return std.mem.readInt(u64, c[32..40], .little);
}

test "map state answers by id and version" {
    const gpa = std.testing.allocator;
    var m: MapState = .{};
    defer m.map.deinit(gpa);
    const id: Id = @splat(7);
    try m.put(gpa, id, 5, "obj");
    const s = m.state();
    try std.testing.expectEqualStrings("obj", s.latest(&id).?);
    try std.testing.expect(s.at(&id, 4) == null);
    try std.testing.expectEqualStrings("obj", s.at(&id, 5).?);
    try std.testing.expect(s.childAtMost(&id, 4) == null);
    try std.testing.expectEqualStrings("obj", s.childAtMost(&id, 9).?);
}

test "map state owner index: Coin<SUI> of the owner (address and consensus-address), richest first" {
    const types = @import("types");
    const bcs = @import("bcs");
    const gpa = std.testing.allocator;
    var a: std.heap.ArenaAllocator = .init(gpa);
    defer a.deinit();
    const al = a.allocator();
    const owner: Id = @splat(0xab);
    const other: Id = @splat(0xcd);
    const Coin = struct { id: u8, owner: types.Owner, bal: u64, sui: bool = true };
    const coins = [_]Coin{
        .{ .id = 1, .owner = .{ .AddressOwner = .{ .@"0" = owner } }, .bal = 5 },
        .{ .id = 2, .owner = .{ .ConsensusAddressOwner = .{ .start_version = .{ .@"0" = 1 }, .owner = .{ .@"0" = owner } } }, .bal = 900 },
        .{ .id = 3, .owner = .{ .AddressOwner = .{ .@"0" = other } }, .bal = 1000 },
        .{ .id = 4, .owner = .{ .AddressOwner = .{ .@"0" = owner } }, .bal = 900 },
        .{ .id = 5, .owner = .{ .AddressOwner = .{ .@"0" = owner } }, .bal = 7777, .sui = false },
        .{ .id = 6, .owner = .{ .ObjectOwner = .{ .@"0" = owner } }, .bal = 9999 },
    };
    const usdc: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = @splat(0x77) }, .module = .{ .@"0" = "usdc" }, .name = .{ .@"0" = "USDC" }, .type_args = &.{} } };
    var m: MapState = .{};
    defer m.map.deinit(gpa);
    for (coins) |c| {
        var contents: [40]u8 = @splat(0);
        contents[31] = c.id;
        std.mem.writeInt(u64, contents[32..40], c.bal, .little);
        const o: types.Object = .{
            .data = .{ .Move = .{ .type_ = .{ .@"0" = if (c.sui) .GasCoin else .{ .Coin = usdc } }, .has_public_transfer = true, .version = .{ .@"0" = 3 }, .contents = try al.dupe(u8, &contents) } },
            .owner = c.owner,
            .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0) } },
            .storage_rebate = 0,
        };
        var id: Id = @splat(0);
        id[31] = c.id;
        try m.put(gpa, id, 3, try bcs.encodeAlloc(types.Object, al, &o));
    }
    const ids = (try m.state().ownedGasCoins(al, &owner, 10)).?;
    try std.testing.expectEqual(@as(usize, 3), ids.len);
    try std.testing.expectEqual(@as(u8, 2), ids[0][31]); // 900, lower id first
    try std.testing.expectEqual(@as(u8, 4), ids[1][31]);
    try std.testing.expectEqual(@as(u8, 1), ids[2][31]);
    try std.testing.expectEqual(@as(usize, 1), (try m.state().ownedGasCoins(al, &owner, 1)).?.len);
    try std.testing.expect((try State.fromSnapshot(undefined).ownedGasCoins(al, &owner, 1)) == null);
}
