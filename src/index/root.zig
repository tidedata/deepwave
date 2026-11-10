//! index: the live-state secondary indexes behind sui.rpc.v2 StateService (DROP-IN.md G4), with
//! the key layouts and orderings of sui-node 1.83.1's embedded `sui-rpc-store`:
//!
//! - owner index (`object_by_owner`): per owner `kind(1) || address(32)` a sorted set of
//!   `bcs(StructTag) || balance_tag(1) || !balance(8 BE)? || object_id(32)` -> version. Kind 0 is
//!   AddressOwner (ConsensusAddressOwner folds into it), 1 is ObjectOwner (dynamic fields and
//!   objects sent to an object). Shared and immutable objects are not listed by any method and are
//!   not kept. Coins carry their balance inverted so the richest coin of a type sorts first.
//! - balance index (`balance`): per owner a sorted map `bcs(TypeTag coin type)` -> (coin, address)
//!   sums: address-owned `Coin<T>` objects add to `coin`, accumulator fields
//!   (`Field<Key<Balance<T>>, U128>` under 0xacc) add to `address`. Rows that reach zero are
//!   dropped (sui-node drops them at its next compaction; until then it lists them with balance 0).
//! - coin index (`object_by_type`, restricted to the three wrapper types GetCoinInfo looks up):
//!   `kind(1) || bcs(TypeTag coin type) || object_id(32)` for CoinMetadata<T> (0),
//!   TreasuryCap<T> (1), RegulatedCoinMetadata<T> (2); the lowest id wins, as the node's first row.
//!
//! The index is a function of the live object set only, so it is built the same way from a restored
//! live set (`insert` per object) and kept current by the commit path (`applyChanges` per
//! checkpoint: old live state out, new state in). Readers hold `lock` shared for one request.
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const bcs = @import("bcs");
const types = @import("types");
pub const sorted = @import("sorted.zig");
pub const state = @import("state.zig");
pub const typeparse = @import("typeparse.zig");
pub const dflayout = @import("dflayout.zig");
pub const conformance = @import("conformance.zig");
pub const feed = @import("feed.zig");
pub const lsm = @import("lsm.zig");
pub const bulk = @import("bulk.zig");

pub const Kind = enum(u8) { address = 0, object = 1 };
pub const CoinWrapper = enum(u8) { metadata = 0, treasury = 1, regulated = 2 };

pub const OwnerKey = [33]u8;
pub const Bal = struct { coin: i128 = 0, address: i128 = 0 };

pub const accumulator_root: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[30] = 0x0a;
    a[31] = 0xcc;
    break :blk a;
};

pub fn ownerKey(kind: Kind, addr: *const [32]u8) OwnerKey {
    var k: OwnerKey = undefined;
    k[0] = @intFromEnum(kind);
    @memcpy(k[1..], addr);
    return k;
}

/// Readers-writer lock (no Io needed): a short spin, then a futex sleep (Linux futex, Darwin
/// ulock). Readers hold it only to copy one page's index rows out (state.zig), never across store
/// reads or rendering; the writer is one checkpoint's `applyChanges`. A writer that holds or waits
/// for the lock blocks new readers, so a stream of requests cannot starve the commit path.
///
/// State word: bit 31 writer (held or claimed), bit 30 someone sleeps on the word, bits 0..29
/// readers inside. Every transition a sleeper waits for (writer bit cleared, readers reaching 0)
/// wakes all sleepers when bit 30 was set; they re-check and sleep again if they must.
pub const RwLock = struct {
    state: std.atomic.Value(u32) = .init(0),
    const writer: u32 = 1 << 31;
    const waiting: u32 = 1 << 30;
    const readers: u32 = waiting - 1;
    const spins = 128;

    pub fn lockShared(l: *RwLock) void {
        var n: u32 = 0;
        while (true) {
            const s = l.state.load(.monotonic);
            if (s & writer == 0) {
                if (l.state.cmpxchgWeak(s, s + 1, .acquire, .monotonic) == null) return;
                continue;
            }
            n = l.pause(s, n);
        }
    }

    pub fn tryLockShared(l: *RwLock) bool {
        const s = l.state.load(.monotonic);
        return s & writer == 0 and l.state.cmpxchgStrong(s, s + 1, .acquire, .monotonic) == null;
    }

    pub fn unlockShared(l: *RwLock) void {
        const prev = l.state.fetchSub(1, .release);
        // The last reader out lets a writer that sleeps waiting for the drain in.
        if (prev & readers == 1 and prev & waiting != 0) l.wakeAll();
    }

    pub fn lock(l: *RwLock) void {
        var n: u32 = 0;
        while (true) {
            const s = l.state.load(.monotonic);
            if (s & writer == 0) {
                if (l.state.cmpxchgWeak(s, s | writer, .acquire, .monotonic) == null) break;
                continue;
            }
            n = l.pause(s, n);
        }
        n = 0;
        while (true) {
            const s = l.state.load(.acquire);
            if (s & readers == 0) return;
            n = l.pause(s, n);
        }
    }

    pub fn tryLock(l: *RwLock) bool {
        const s = l.state.load(.monotonic);
        return s & (writer | readers) == 0 and l.state.cmpxchgStrong(s, s | writer, .acquire, .monotonic) == null;
    }

    pub fn unlock(l: *RwLock) void {
        const prev = l.state.fetchAnd(~(writer | waiting), .release);
        if (prev & waiting != 0) futexWake(&l.state.raw);
    }

    /// Readers inside, and whether a writer holds or claims the lock (tests, metrics).
    pub fn readersInside(l: *const RwLock) u32 {
        return l.state.load(.monotonic) & readers;
    }
    pub fn writerIn(l: *const RwLock) bool {
        return l.state.load(.monotonic) & writer != 0;
    }
    pub fn hasSleepers(l: *const RwLock) bool {
        return l.state.load(.monotonic) & waiting != 0;
    }

    /// One wait step on state `s`: spin first, then mark the word and sleep until it changes.
    fn pause(l: *RwLock, s: u32, n: u32) u32 {
        if (n < spins) {
            std.atomic.spinLoopHint();
            return n + 1;
        }
        const marked = s | waiting;
        if (s & waiting == 0 and l.state.cmpxchgWeak(s, marked, .monotonic, .monotonic) != null) return n;
        futexWait(&l.state.raw, marked);
        return n;
    }

    fn wakeAll(l: *RwLock) void {
        // Clear the mark before waking: woken sleepers set it again if they still must wait.
        _ = l.state.fetchAnd(~waiting, .monotonic);
        futexWake(&l.state.raw);
    }
};

fn futexWait(ptr: *const u32, expect: u32) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.futex_4arg(ptr, .{ .cmd = .WAIT, .private = true }, expect, null);
    } else if (comptime builtin.os.tag.isDarwin()) {
        _ = std.c.__ulock_wait(.{ .op = .COMPARE_AND_WAIT, .NO_ERRNO = true }, ptr, expect, 0);
    } else std.atomic.spinLoopHint();
}

fn futexWake(ptr: *const u32) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.futex_3arg(ptr, .{ .cmd = .WAKE, .private = true }, std.math.maxInt(i32));
    } else if (comptime builtin.os.tag.isDarwin()) {
        _ = std.c.__ulock_wake(.{ .op = .COMPARE_AND_WAIT, .NO_ERRNO = true, .WAKE_ALL = true }, ptr, 0);
    }
}

pub const Table = enum(u8) { owner = 0, balance = 1, coin = 2 };

pub const Index = struct {
    gpa: Allocator,
    lock: RwLock = .{},
    db: lsm.Db,
    /// Checkpoint the index reflects (null when built from a live set with no checkpoint).
    /// Written by the index's writer; other threads read `liveCheckpoint` (set together through
    /// `setCheckpoint`).
    checkpoint: ?u64 = null,
    /// `checkpoint` for readers on other threads (/health, the served tip): maxInt = none.
    live: std.atomic.Value(u64) = .init(std.math.maxInt(u64)),
    /// False while a fast-start background build or catch-up owns the index (lane fast-start):
    /// StateService answers UNAVAILABLE and the commit feed leaves the index alone.
    ready: std.atomic.Value(bool) = .init(true),
    /// Objects inserted and checkpoint changes applied since open (stats).
    inserted: u64 = 0,
    changes: u64 = 0,

    /// In memory (tests, fixtures).
    pub fn init(gpa: Allocator) !Index {
        return .{ .gpa = gpa, .db = try lsm.Db.memory(gpa) };
    }

    /// On disk under `dir` (`<node dir>/state-index`). The caller then calls `prepare` to build or
    /// replay, and `startBackground`.
    pub fn open(gpa: Allocator, io: std.Io, dir: []const u8, opts: lsm.Options) !*Index {
        const ix = try gpa.create(Index);
        errdefer gpa.destroy(ix);
        ix.* = .{ .gpa = gpa, .db = try lsm.Db.open(gpa, io, dir, opts) };
        ix.setCheckpoint(ix.db.watermark());
        return ix;
    }

    pub fn deinit(ix: *Index) void {
        ix.db.deinit();
    }

    /// Sets the checkpoint the index reflects (the writer's `checkpoint` and the readers' copy).
    pub fn setCheckpoint(ix: *Index, seq: ?u64) void {
        ix.checkpoint = seq;
        ix.live.store(seq orelse std.math.maxInt(u64), .release);
    }

    /// The checkpoint the index has committed, readable from any thread (null: none yet).
    pub fn liveCheckpoint(ix: *const Index) ?u64 {
        const v = ix.live.load(.acquire);
        return if (v == std.math.maxInt(u64)) null else v;
    }

    pub fn startBackground(ix: *Index) !void {
        try ix.db.startBackground(&ix.lock);
    }

    // ------------------------------------------------------------------ writes

    /// Adds one live object (BCS(Object)). Objects the node does not index are ignored.
    pub fn insert(ix: *Index, raw: []const u8) !void {
        try ix.apply(raw, 1);
        ix.inserted += 1;
    }

    /// Removes one object version that was live (the same bytes `insert` saw).
    pub fn remove(ix: *Index, raw: []const u8) !void {
        try ix.apply(raw, -1);
    }

    /// One checkpoint's object changes, in transaction order: for each touched id, `old` is the
    /// state before the change (null if it did not exist or was not live) and `new` the state
    /// after (null for deleted or wrapped). Takes the write lock once.
    pub const Change = struct { old: ?[]const u8, new: ?[]const u8 };
    ///
    /// Every object is decoded and turned into index rows before the write lock is taken (lane
    /// serve-tail 5982bb1, ported to the disk index): the lock is held only for the memtable
    /// inserts. Decoding under the lock held ListOwnedObjects, ListDynamicFields, ListBalances,
    /// GetBalance and GetCoinInfo behind a whole checkpoint's BCS decoding on every commit.
    pub fn applyChanges(ix: *Index, seq: ?u64, changes: []const Change) !void {
        var arena_state = std.heap.ArenaAllocator.init(ix.gpa);
        defer arena_state.deinit();
        const rows = try ix.planChanges(arena_state.allocator(), changes);
        ix.lock.lock();
        const backlog = ix.applyRowsHeld(seq, rows, changes.len) catch |e| {
            ix.lock.unlock();
            return e;
        };
        ix.lock.unlock();
        // Flushed memtables are freed here, on the thread that allocated them (lsm.Db.retired).
        ix.db.reclaim();
        // Backpressure: the background thread is behind on flushes.
        if (backlog) while (ix.db.frozenBacklog()) {
            ix.db.stats.frozen_waits += 1;
            if (ix.db.io) |io| io.sleep(.fromMilliseconds(5), .awake) catch {} else break;
        };
    }

    /// `applyChanges` for a caller that already holds `lock` exclusively. Returns true when the
    /// caller should let the background flush catch up (after releasing the lock).
    pub fn applyChangesHeld(ix: *Index, seq: ?u64, changes: []const Change) !bool {
        var arena_state = std.heap.ArenaAllocator.init(ix.gpa);
        defer arena_state.deinit();
        return ix.applyRowsHeld(seq, try ix.planChanges(arena_state.allocator(), changes), changes.len);
    }

    /// One planned index row (key and value in the planning arena).
    pub const Planned = struct { key: []const u8, val: lsm.Val };

    /// Test hook: called after each change is planned (the index lock must be free there).
    pub var test_on_plan: ?*const fn (ix: *Index) void = null;

    /// The rows of `changes`, in order (each change: the old state out, then the new in). Touches
    /// nothing in the index; runs without the lock.
    pub fn planChanges(ix: *Index, arena: Allocator, changes: []const Change) ![]const Planned {
        var p: Planner = .{ .arena = arena };
        for (changes) |c| {
            if (c.old) |o| try rowsOf(arena, o, -1, .{ .ctx = &p, .f = Planner.emit });
            if (c.new) |n| try rowsOf(arena, n, 1, .{ .ctx = &p, .f = Planner.emit });
            if (builtin.is_test) if (test_on_plan) |h| h(ix);
        }
        return p.rows.items;
    }

    const Planner = struct {
        arena: Allocator,
        rows: std.ArrayList(Planned) = .empty,
        fn emit(ctx: *anyopaque, key: []const u8, val: lsm.Val) anyerror!void {
            const p: *Planner = @ptrCast(@alignCast(ctx));
            // rowsOf allocates keys in the same arena, so they stay valid.
            try p.rows.append(p.arena, .{ .key = key, .val = val });
        }
    };

    fn applyRowsHeld(ix: *Index, seq: ?u64, rows: []const Planned, n_changes: usize) !bool {
        for (rows) |r| try ix.db.apply(r.key, r.val);
        ix.changes += n_changes;
        if (seq) |s| {
            ix.setCheckpoint(s);
            return try ix.db.endCheckpoint(s);
        }
        return false;
    }

    fn apply(ix: *Index, raw: []const u8, sign: i2) !void {
        var arena_state = std.heap.ArenaAllocator.init(ix.gpa);
        defer arena_state.deinit();
        try rowsOf(arena_state.allocator(), raw, sign, .{ .ctx = &ix.db, .f = dbEmit });
    }

    fn dbEmit(ctx: *anyopaque, key: []const u8, val: lsm.Val) anyerror!void {
        const db: *lsm.Db = @ptrCast(@alignCast(ctx));
        try db.apply(key, val);
    }

    // ------------------------------------------------------------------ reads (hold lock shared)
    // Iterators and their block buffers come from `a` (the request arena); keys they return are
    // valid until their next call.

    pub const Owned = struct {
        m: lsm.MergeIter,
        prefix: [34]u8,
        pub const Row = struct { key: []const u8, ver: u64 };
        /// The next row of the owner: its owner-index suffix and version.
        pub fn next(it: *Owned) !?Row {
            const e = try it.m.next() orelse return null;
            if (!std.mem.startsWith(u8, e.key, &it.prefix)) return null;
            return .{ .key = e.key[it.prefix.len..], .ver = e.val.version() };
        }
    };

    /// The owner's rows from the first suffix >= `start`.
    pub fn ownedIter(ix: *const Index, a: Allocator, kind: Kind, addr: *const [32]u8, start: []const u8) !Owned {
        var it: Owned = .{ .m = undefined, .prefix = undefined };
        it.prefix[0] = @intFromEnum(Table.owner);
        it.prefix[1..34].* = ownerKey(kind, addr);
        const k = try a.alloc(u8, 34 + start.len);
        @memcpy(k[0..34], &it.prefix);
        @memcpy(k[34..], start);
        it.m = try ix.db.iter(a, k);
        return it;
    }

    pub const Balances = struct {
        m: lsm.MergeIter,
        prefix: [33]u8,
        pub const Row = struct { key: []const u8, val: Bal };
        /// The next (BCS coin TypeTag, balance) of the owner; zero sums are skipped.
        pub fn next(it: *Balances) !?Row {
            const e = try it.m.next() orelse return null;
            if (!std.mem.startsWith(u8, e.key, &it.prefix)) return null;
            const p = e.val.pair();
            return .{ .key = e.key[it.prefix.len..], .val = .{ .coin = p[0], .address = p[1] } };
        }
    };

    pub fn balanceIter(ix: *const Index, a: Allocator, owner: *const [32]u8, start: []const u8) !Balances {
        var it: Balances = .{ .m = undefined, .prefix = undefined };
        it.prefix[0] = @intFromEnum(Table.balance);
        it.prefix[1..33].* = owner.*;
        const k = try a.alloc(u8, 33 + start.len);
        @memcpy(k[0..33], &it.prefix);
        @memcpy(k[33..], start);
        it.m = try ix.db.iter(a, k);
        return it;
    }

    /// The balance of one coin type (BCS TypeTag); zero when the owner has none.
    pub fn balance(ix: *const Index, a: Allocator, owner: *const [32]u8, coin_type_bcs: []const u8) !Bal {
        var it = try ix.balanceIter(a, owner, coin_type_bcs);
        const r = try it.next() orelse return .{};
        if (!std.mem.eql(u8, r.key, coin_type_bcs)) return .{};
        return r.val;
    }

    /// Lowest object id of wrapper `kind` for `coin_type_bcs` (BCS of the coin TypeTag).
    pub fn coinObject(ix: *const Index, a: Allocator, kind: CoinWrapper, coin_type_bcs: []const u8) !?[32]u8 {
        const prefix = try a.alloc(u8, 2 + coin_type_bcs.len);
        prefix[0] = @intFromEnum(Table.coin);
        prefix[1] = @intFromEnum(kind);
        @memcpy(prefix[2..], coin_type_bcs);
        var m = try ix.db.iter(a, prefix);
        const e = try m.next() orelse return null;
        if (e.key.len != prefix.len + 32 or !std.mem.startsWith(u8, e.key, prefix)) return null;
        return e.key[prefix.len..][0..32].*;
    }

    /// Every live row in key order (tests, suites).
    pub fn all(ix: *const Index, a: Allocator) !lsm.MergeIter {
        return ix.db.iter(a, "");
    }
};

/// The index rows of one object version (BCS(Object)): `sign` +1 adds it, -1 removes it. Objects
/// the node does not index emit nothing.
pub fn rowsOf(arena: Allocator, raw: []const u8, sign: i2, emit: lsm.Emit) anyerror!void {
    const obj = bcs.decode(types.Object, arena, raw) catch return; // undecodable: not indexable
    const mo = switch (obj.data) {
        .Move => |m| m,
        .Package => return,
    };
    const id: *const [32]u8 = mo.contents[0..32];
    const ty = try objectStructTag(arena, mo.type_);
    const ty_bcs = try bcs.encodeAlloc(types.StructTag, arena, &ty);
    const coin_bal = coinBalance(mo);

    // owner index
    const okind: ?OwnerKey = switch (obj.owner) {
        .AddressOwner => |a| ownerKey(.address, &a.@"0"),
        .ConsensusAddressOwner => |c| ownerKey(.address, &c.owner.@"0"),
        .ObjectOwner => |a| ownerKey(.object, &a.@"0"),
        else => null,
    };
    if (okind) |ok| {
        const suffix = try ownerSuffix(arena, ty_bcs, coin_bal, id);
        const key = try arena.alloc(u8, 1 + ok.len + suffix.len);
        key[0] = @intFromEnum(Table.owner);
        @memcpy(key[1..][0..ok.len], &ok);
        @memcpy(key[1 + ok.len ..], suffix);
        var ver: [8]u8 = undefined;
        std.mem.writeInt(u64, &ver, mo.version.@"0", .little);
        try emit.f(emit.ctx, key, if (sign > 0) lsm.Val.put(&ver) else lsm.Val.del);
    }

    // balance index: address-owned coins, and accumulator balances
    switch (obj.owner) {
        .AddressOwner, .ConsensusAddressOwner => if (coin_bal) |b| {
            const owner = switch (obj.owner) {
                .AddressOwner => |a| a.@"0",
                .ConsensusAddressOwner => |c| c.owner.@"0",
                else => unreachable,
            };
            try emitBalance(arena, emit, &owner, ty.type_args[0], @as(i128, b) * sign, 0);
        },
        .ObjectOwner => |p| if (std.mem.eql(u8, &p.@"0", &accumulator_root)) {
            if (accumulatorBalance(mo)) |ab| try emitBalance(arena, emit, &ab.owner, ab.coin_type, 0, @as(i128, @intCast(ab.value)) * sign);
        },
        else => {},
    }

    // coin index: CoinMetadata<T>, TreasuryCap<T>, RegulatedCoinMetadata<T> of any owner
    if (coinWrapper(ty)) |cw| {
        const k = try coinKey(arena, cw.kind, cw.coin, id);
        const key = try arena.alloc(u8, 1 + k.len);
        key[0] = @intFromEnum(Table.coin);
        @memcpy(key[1..], k);
        try emit.f(emit.ctx, key, if (sign > 0) lsm.Val.put("") else lsm.Val.del);
    }
}

fn emitBalance(arena: Allocator, emit: lsm.Emit, owner: *const [32]u8, coin_t: types.TypeTag, coin: i128, address: i128) !void {
    const tk = try bcs.encodeAlloc(types.TypeTag, arena, &coin_t);
    const key = try arena.alloc(u8, 33 + tk.len);
    key[0] = @intFromEnum(Table.balance);
    @memcpy(key[1..33], owner);
    @memcpy(key[33..], tk);
    try emit.f(emit.ctx, key, lsm.Val.delta(coin, address));
}

/// `bcs(StructTag) || balance_tag || !balance BE? || id`.
pub fn ownerSuffix(arena: Allocator, ty_bcs: []const u8, balance: ?u64, id: *const [32]u8) ![]u8 {
    const n = ty_bcs.len + 1 + @as(usize, if (balance != null) 8 else 0) + 32;
    const k = try arena.alloc(u8, n);
    @memcpy(k[0..ty_bcs.len], ty_bcs);
    var p = ty_bcs.len;
    if (balance) |b| {
        k[p] = 1;
        std.mem.writeInt(u64, k[p + 1 ..][0..8], ~b, .big);
        p += 9;
    } else {
        k[p] = 0;
        p += 1;
    }
    @memcpy(k[p..][0..32], id);
    return k;
}

/// Splits an owner-index suffix back into its parts. `ty_bcs` is found by BCS-skipping a StructTag.
pub const OwnerRow = struct { ty_bcs: []const u8, balance: ?u64, id: *const [32]u8 };
pub fn splitOwnerSuffix(key: []const u8) !OwnerRow {
    var r = bcs.Reader.init(key);
    try bcs.skip(types.StructTag, &r);
    const tl = r.pos();
    const tag = key[tl];
    if (tag == 1) return .{ .ty_bcs = key[0..tl], .balance = ~std.mem.readInt(u64, key[tl + 1 ..][0..8], .big), .id = key[tl + 9 ..][0..32] };
    return .{ .ty_bcs = key[0..tl], .balance = null, .id = key[tl + 1 ..][0..32] };
}

fn coinKey(arena: Allocator, kind: CoinWrapper, coin: types.TypeTag, id: *const [32]u8) ![]u8 {
    const tb = try bcs.encodeAlloc(types.TypeTag, arena, &coin);
    const k = try arena.alloc(u8, 1 + tb.len + 32);
    k[0] = @intFromEnum(kind);
    @memcpy(k[1..][0..tb.len], tb);
    @memcpy(k[1 + tb.len ..][0..32], id);
    return k;
}

fn addrN(n: u8) types.AccountAddress {
    var a: [32]u8 = @splat(0);
    a[31] = n;
    return .{ .@"0" = a };
}
fn ident(s: []const u8) types.Identifier {
    return .{ .@"0" = s };
}
fn st(arena: Allocator, a: u8, m: []const u8, n: []const u8, args: []const types.TypeTag) !types.StructTag {
    return .{ .address = addrN(a), .module = ident(m), .name = ident(n), .type_args = try arena.dupe(types.TypeTag, args) };
}

/// The full StructTag of a `MoveObjectType` (what `StructTag::from(object.type_())` gives).
pub fn objectStructTag(arena: Allocator, t: types.MoveObjectType) !types.StructTag {
    const sui_t: types.TypeTag = .{ .@"struct" = try st(arena, 2, "sui", "SUI", &.{}) };
    return switch (t.@"0") {
        .Other => |s| s,
        .GasCoin => try st(arena, 2, "coin", "Coin", &.{sui_t}),
        .StakedSui => try st(arena, 3, "staking_pool", "StakedSui", &.{}),
        .Coin => |inner| try st(arena, 2, "coin", "Coin", &.{inner}),
        .SuiBalanceAccumulatorField, .BalanceAccumulatorField => blk: {
            const inner: types.TypeTag = switch (t.@"0") {
                .BalanceAccumulatorField => |i| i,
                else => sui_t,
            };
            const bal: types.TypeTag = .{ .@"struct" = try st(arena, 2, "balance", "Balance", &.{inner}) };
            const key: types.TypeTag = .{ .@"struct" = try st(arena, 2, "accumulator", "Key", &.{bal}) };
            const u128_t: types.TypeTag = .{ .@"struct" = try st(arena, 2, "accumulator", "U128", &.{}) };
            break :blk try st(arena, 2, "dynamic_field", "Field", &.{ key, u128_t });
        },
    };
}

/// `Object::as_coin_maybe`: the balance of a `Coin<T>` (gas coin included).
pub fn coinBalance(mo: types.MoveObject) ?u64 {
    switch (mo.type_.@"0") {
        .GasCoin, .Coin => {},
        else => return null,
    }
    if (mo.contents.len != 40) return null;
    return std.mem.readInt(u64, mo.contents[32..40], .little);
}

fn isSui(s: types.StructTag, m: []const u8, n: []const u8) bool {
    return std.mem.eql(u8, &s.address.@"0", &addrN(2).@"0") and std.mem.eql(u8, s.module.@"0", m) and std.mem.eql(u8, s.name.@"0", n);
}

const AccBal = struct { owner: [32]u8, coin_type: types.TypeTag, value: u128 };

/// An address balance: `Field<Key<Balance<T>>, U128>` = id(32) || owner(32) || u128 LE, with
/// a struct T and a positive value (balance.rs `address_balance_info`).
fn accumulatorBalance(mo: types.MoveObject) ?AccBal {
    const coin_t: types.TypeTag = switch (mo.type_.@"0") {
        .BalanceAccumulatorField => |i| i,
        .SuiBalanceAccumulatorField => .{ .@"struct" = .{ .address = addrN(2), .module = ident("sui"), .name = ident("SUI"), .type_args = &.{} } },
        else => return null,
    };
    if (coin_t != .@"struct") return null;
    if (mo.contents.len != 80) return null;
    const v = std.mem.readInt(u128, mo.contents[64..80], .little);
    if (v == 0 or v > std.math.maxInt(i128)) return null;
    return .{ .owner = mo.contents[32..64].*, .coin_type = coin_t, .value = v };
}

fn coinWrapper(t: types.StructTag) ?struct { kind: CoinWrapper, coin: types.TypeTag } {
    if (t.type_args.len != 1) return null;
    if (isSui(t, "coin", "CoinMetadata")) return .{ .kind = .metadata, .coin = t.type_args[0] };
    if (isSui(t, "coin", "TreasuryCap")) return .{ .kind = .treasury, .coin = t.type_args[0] };
    if (isSui(t, "coin", "RegulatedCoinMetadata")) return .{ .kind = .regulated, .coin = t.type_args[0] };
    return null;
}

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(state);
    std.testing.refAllDecls(typeparse);
    std.testing.refAllDecls(dflayout);
    std.testing.refAllDecls(feed);
    std.testing.refAllDecls(feed.Feed);
    std.testing.refAllDecls(Index);
    _ = @import("live_test.zig");
    _ = @import("lsm_test.zig");
    _ = @import("bulk_test.zig");
    _ = lsm;
    _ = bulk;
}
