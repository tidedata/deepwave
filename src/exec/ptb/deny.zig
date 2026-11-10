//! Coin deny list v2 during execution (`sui-types/src/deny_list_v2.rs`
//! `check_coin_deny_list_v2_during_execution`), shared by the Move-call executor (`run.zig`
//! finish) and the coin executor (`coin_ptb.zig`).
//!
//! The owners that receive a non-SUI coin (a written `Coin<T>` with an address, object or
//! consensus-address owner, or a `Balance<T>` accumulator event) are grouped by the coin type's
//! canonical string (`to_canonical_string(false)`). First, for every type, in string order, the
//! per-type config is read: the dynamic object field of 0x403 under
//! `Wrapper<ConfigKey { 0, type bytes }>`; its value, read as `Config { id }`, names the config.
//! Then, for each type that has one, in the same order, the global pause setting
//! (`GlobalPauseKey`) and each owner's setting (`AddressKey`, owners in byte order) are the
//! config's dynamic fields `Setting<bool>`, read with `read_value(Some(epoch))`; the first one
//! that reads true is the result and ends the reads. Any read or decode failure counts as not
//! set, as in Rust (`.ok()?`, `unwrap_or(false)`).
//!
//! The reads go to the store's latest object (`ObjectStore::get_object`), outside the
//! transaction's inputs: `Store.get`, one call per read, in Rust's order (`check`). The callers
//! run the check before they charge for it (`charge_coin_transfers`), as `context::finish` does.
const std = @import("std");
const types = @import("types");
const hash = @import("hash");
const objects = @import("../objects.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;

/// The store's latest version of an object (full object BCS), or null.
pub const Store = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, id: *const Id) ?[]const u8,
};

/// One (coin type, receiving owner) pair; `ty` is the canonical string, without `0x`.
/// `ty` is the canonical coin type string (the config key); `tag` the TypeTag, when known.
pub const Pair = struct { ty: []const u8, owner: Id, tag: ?types.TypeTag = null };

pub const deny_list_id: Id = blk: {
    var a: Id = @splat(0);
    a[30] = 0x04;
    a[31] = 0x03;
    break :blk a;
};

/// `TypeTag::to_canonical_string(false)`.
pub fn canonical(arena: Allocator, t: *const types.TypeTag) Allocator.Error![]const u8 {
    var w: std.Io.Writer.Allocating = .init(arena);
    writeCanonical(&w.writer, t) catch return error.OutOfMemory;
    return w.written();
}

fn writeCanonical(w: *std.Io.Writer, t: *const types.TypeTag) !void {
    switch (t.*) {
        .bool => try w.writeAll("bool"),
        .u8 => try w.writeAll("u8"),
        .u16 => try w.writeAll("u16"),
        .u32 => try w.writeAll("u32"),
        .u64 => try w.writeAll("u64"),
        .u128 => try w.writeAll("u128"),
        .u256 => try w.writeAll("u256"),
        .address => try w.writeAll("address"),
        .signer => try w.writeAll("signer"),
        .vector => |e| {
            try w.writeAll("vector<");
            try writeCanonical(w, e);
            try w.writeAll(">");
        },
        .@"struct" => |*s| {
            try w.print("{x}::{s}::{s}", .{ &s.address.@"0", s.module.@"0", s.name.@"0" });
            for (s.type_args, 0..) |*a, i| {
                try w.writeAll(if (i == 0) "<" else ",");
                try writeCanonical(w, a);
            }
            if (s.type_args.len > 0) try w.writeAll(">");
        },
    }
}

/// Adds (ty, owner) unless present. Returns whether it was new.
pub fn addPair(arena: Allocator, list: *std.ArrayList(Pair), ty: []const u8, owner: Id, tag: ?types.TypeTag) !void {
    for (list.items) |x| if (std.mem.eql(u8, x.ty, ty) and std.mem.eql(u8, &x.owner, &owner)) return;
    try list.append(arena, .{ .ty = ty, .owner = owner, .tag = tag });
}

pub const Denied = union(enum) {
    pause: []const u8,
    address: struct { address: Id, coin_type: []const u8 },

    pub fn kind(d: Denied) types.ExecutionErrorKind {
        return switch (d) {
            .pause => |t| .{ .CoinTypeGlobalPause = .{ .coin_type = .{ .@"0" = t } } },
            .address => |a| .{ .AddressDeniedForCoin = .{ .address = .{ .@"0" = a.address }, .coin_type = .{ .@"0" = a.coin_type } } },
        };
    }
};

fn lessPair(_: void, a: Pair, b: Pair) bool {
    return switch (std.mem.order(u8, a.ty, b.ty)) {
        .lt => true,
        .gt => false,
        .eq => std.mem.order(u8, &a.owner, &b.owner) == .lt,
    };
}

/// `derive_dynamic_field_id(parent, key_type, key)`.
fn fieldId(parent: *const Id, key_type: []const u8, key: []const u8) Id {
    var len_le: [8]u8 = undefined;
    std.mem.writeInt(u64, &len_le, key.len, .little);
    return hash.blake2b256(&.{ &[_]u8{0xf0}, parent, &len_le, key, key_type });
}

/// BCS TypeTag of `0x2::<module>::<name><args>` for a struct with no type arguments, or one
/// struct argument given as BCS (`inner`).
fn fwTag(buf: []u8, module: []const u8, name: []const u8, inner: ?[]const u8) []const u8 {
    var n: usize = 0;
    buf[n] = 7; // TypeTag::Struct
    n += 1;
    @memset(buf[n..][0..32], 0);
    buf[n + 31] = 2;
    n += 32;
    buf[n] = @intCast(module.len);
    n += 1;
    @memcpy(buf[n..][0..module.len], module);
    n += module.len;
    buf[n] = @intCast(name.len);
    n += 1;
    @memcpy(buf[n..][0..name.len], name);
    n += name.len;
    if (inner) |t| {
        buf[n] = 1;
        n += 1;
        @memcpy(buf[n..][0..t.len], t);
        n += t.len;
    } else {
        buf[n] = 0;
        n += 1;
    }
    return buf[0..n];
}

/// Contents of a Move object that the store has at `id`, or null.
fn moveContents(store: Store, id: *const Id) ?[]const u8 {
    const raw = store.get(store.ctx, id) orelse return null;
    const v = objects.ObjectView.parse(raw) catch return null;
    if (v.is_package) return null;
    return v.contents();
}

fn appendUleb(buf: []u8, n: usize) usize {
    var x = n;
    var i: usize = 0;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            buf[i] = b;
            return i + 1;
        }
        buf[i] = b | 0x80;
        i += 1;
    }
}

/// `get_per_type_coin_deny_list_v2`: the config id, or null when the type has no config (or
/// the field does not decode as `Field<Wrapper<ConfigKey>, Config>`).
fn configOf(arena: Allocator, store: Store, ty: []const u8) !?Id {
    // key: Wrapper<ConfigKey { per_type_index: 0, per_type_key: ty bytes }>
    const key = try arena.alloc(u8, 8 + 10 + ty.len);
    @memset(key[0..8], 0);
    var n: usize = 8 + appendUleb(key[8..], ty.len);
    @memcpy(key[n..][0..ty.len], ty);
    n += ty.len;
    var inner_buf: [64]u8 = undefined;
    const inner = fwTag(&inner_buf, "deny_list", "ConfigKey", null);
    var tag_buf: [160]u8 = undefined;
    const key_type = fwTag(&tag_buf, "dynamic_object_field", "Wrapper", inner);
    const fid = fieldId(&deny_list_id, key_type, key[0..n]);
    const c = moveContents(store, &fid) orelse return null;
    // Field<K, Config>: id(32) ++ key ++ Config { id: UID }(32), all bytes consumed
    if (c.len != 32 + n + 32) return null;
    if (!std.mem.eql(u8, c[32..][0..n], key[0..n])) return null;
    return c[32 + n ..][0..32].*;
}

/// `read_config_setting::<K, bool>(..., Some(epoch))`, `unwrap_or(false)`.
fn setting(store: Store, config: *const Id, key_name: []const u8, key: []const u8, epoch: u64) bool {
    var tag_buf: [64]u8 = undefined;
    const key_type = fwTag(&tag_buf, "deny_list", key_name, null);
    const fid = fieldId(config, key_type, key);
    const c = moveContents(store, &fid) orelse return false;
    // Field<K, Setting<bool>>: id(32) ++ key ++ Option<SettingData<bool>>
    if (c.len < 32 + key.len or !std.mem.eql(u8, c[32..][0..key.len], key)) return false;
    var r = c[32 + key.len ..];
    const Opt = struct {
        fn boolOpt(b: *[]const u8) error{Bad}!?bool {
            if (b.len < 1) return error.Bad;
            const tag = b.*[0];
            b.* = b.*[1..];
            switch (tag) {
                0 => return null,
                1 => {
                    if (b.len < 1 or b.*[0] > 1) return error.Bad;
                    const v = b.*[0] == 1;
                    b.* = b.*[1..];
                    return v;
                },
                else => return error.Bad,
            }
        }
    };
    if (r.len < 1) return false;
    const has = r[0];
    r = r[1..];
    if (has == 0) return false; // data None: read_value None
    if (has != 1 or r.len < 8) return false;
    const newer_epoch = std.mem.readInt(u64, r[0..8], .little);
    r = r[8..];
    const newer = Opt.boolOpt(&r) catch return false;
    const older = Opt.boolOpt(&r) catch return false;
    if (r.len != 0) return false;
    const v = if (epoch > newer_epoch) newer else older;
    return v orelse false;
}

/// The deny-list result for `pairs` (deduplicated); sorts `pairs`. null: no denial.
///
/// The store reads are in Rust's order (`check_coin_deny_list_v2_during_execution`): first the
/// per-type config field of every coin type, in type string order (the `filter_map` over the
/// types is collected into `regulated_coin_owners` before anything else runs); then, for the
/// types that have a config, in the same order, the global pause setting and each owner's
/// setting in address order (`check_new_regulated_coin_owners`), which stops at the first
/// setting that reads true. So a denial of one type leaves the settings of the later types
/// unread, and their config fields read.
pub fn check(arena: Allocator, store: Store, epoch: u64, pairs: []Pair) !?Denied {
    std.mem.sort(Pair, pairs, {}, lessPair);
    const Regulated = struct { first: usize, end: usize, cfg: Id };
    var regulated: std.ArrayList(Regulated) = .empty;
    var i: usize = 0;
    while (i < pairs.len) {
        const ty = pairs[i].ty;
        var j = i;
        while (j < pairs.len and std.mem.eql(u8, pairs[j].ty, ty)) j += 1;
        if (try configOf(arena, store, ty)) |cfg| try regulated.append(arena, .{ .first = i, .end = j, .cfg = cfg });
        i = j;
    }
    for (regulated.items) |*g| {
        const ty = pairs[g.first].ty;
        if (setting(store, &g.cfg, "GlobalPauseKey", &.{0}, epoch)) return .{ .pause = ty };
        for (pairs[g.first..g.end]) |p| {
            if (setting(store, &g.cfg, "AddressKey", &p.owner, epoch))
                return .{ .address = .{ .address = p.owner, .coin_type = ty } };
        }
    }
    return null;
}

test "canonical type strings" {
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var addr: [32]u8 = @splat(0);
    addr[31] = 2;
    const inner: types.TypeTag = .u64;
    const args = [_]types.TypeTag{ .{ .vector = &inner }, .address };
    const t: types.TypeTag = .{ .@"struct" = .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = "m" }, .name = .{ .@"0" = "S" }, .type_args = &args } };
    try std.testing.expectEqualStrings("0000000000000000000000000000000000000000000000000000000000000002::m::S<vector<u64>,address>", try canonical(arena, &t));
}

test "setting read_value by epoch" {
    // a store holding one AddressKey setting under config 0x..77
    const S = struct {
        var raw: []const u8 = &.{};
        var id: Id = undefined;
        fn get(_: *const anyopaque, want: *const Id) ?[]const u8 {
            return if (std.mem.eql(u8, want, &id)) raw else null;
        }
    };
    var cfg: Id = @splat(0);
    cfg[31] = 0x77;
    const owner: Id = @splat(0xab);
    var tag_buf: [64]u8 = undefined;
    S.id = fieldId(&cfg, fwTag(&tag_buf, "deny_list", "AddressKey", null), &owner);
    // Object: Move data, Other type, has_public_transfer, version, contents, owner, prev tx, rebate
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(std.testing.allocator);
    const ga = std.testing.allocator;
    try b.append(ga, 0); // Data::Move
    try b.append(ga, 0); // MoveObjectType::Other
    try b.appendSlice(ga, fwTag(&tag_buf, "config", "Setting", &[_]u8{1})[1..]); // StructTag (no TypeTag tag byte)
    try b.append(ga, 0); // has_public_transfer
    try b.appendSlice(ga, &[_]u8{ 5, 0, 0, 0, 0, 0, 0, 0 });
    var contents: [32 + 32 + 1 + 8 + 2 + 2]u8 = undefined;
    @memcpy(contents[0..32], &S.id);
    @memcpy(contents[32..64], &owner);
    contents[64] = 1;
    std.mem.writeInt(u64, contents[65..73], 10, .little);
    contents[73..77].* = .{ 1, 1, 1, 0 }; // newer Some(true), older Some(false)
    try b.append(ga, contents.len);
    try b.appendSlice(ga, &contents);
    try b.append(ga, 1); // Owner::ObjectOwner
    try b.appendSlice(ga, &cfg);
    try b.append(ga, 32); // previous_transaction (a 32-byte vector)
    try b.appendSlice(ga, &@as([32]u8, @splat(0)));
    try b.appendSlice(ga, &@as([8]u8, @splat(0)));
    S.raw = b.items;
    const store: Store = .{ .ctx = undefined, .get = S.get };
    try std.testing.expect(!setting(store, &cfg, "AddressKey", &owner, 10));
    try std.testing.expect(setting(store, &cfg, "AddressKey", &owner, 11));
    const other: Id = @splat(0xac);
    try std.testing.expect(!setting(store, &cfg, "AddressKey", &other, 11));
}

// The store reads of the check against Mysten's executor (`deny_order_vectors.zig`): the
// vectors that are charged in full (two coin types, no config object, the global pause, the
// sender against the recipient, settings by epoch). Effects byte for byte, reads in call order.
test "deny list reads follow Rust's order: every type's config, then the settings (coin executor)" {
    const vectors = @import("deny_order_vectors.zig");
    try std.testing.expectEqual(@as(usize, 24), try vectors.run(std.testing.allocator, std.testing.io, .charged, .coin));
}

test "deny list reads follow Rust's order: every type's config, then the settings (Move-call executor)" {
    const vectors = @import("deny_order_vectors.zig");
    try std.testing.expectEqual(@as(usize, 24), try vectors.run(std.testing.allocator, std.testing.io, .charged, .move));
}

/// Replay's deny-list state (`$ZUI_CORPUS/deny/objects.bin.zst`, `zui-truth-exec
/// deny-snapshot`): every version of the 0x403 per-type config fields and of each config's
/// settings, with the epoch that wrote it. A read at epoch E takes the newest version written
/// in epoch E or before. Settings are epoch-gated (`read_value(Some(E))` gives the value as of
/// the start of E for any version current during E), so this gives the same check results as
/// the validator's latest object at any point of E.
pub const Snapshot = struct {
    pub const path = "deny/objects.bin.zst";
    const Entry = struct { epoch: u64, raw: []const u8 };
    map: std.AutoHashMapUnmanaged(Id, []Entry) = .empty,
    loaded: bool = false,

    /// Parses the decompressed records `u32 LE length ++ u64 LE epoch ++ BCS Object`.
    pub fn parse(arena: Allocator, raw: []const u8) !Snapshot {
        var lists: std.AutoArrayHashMapUnmanaged(Id, std.ArrayList(Entry)) = .empty;
        var at: usize = 0;
        while (at < raw.len) {
            if (raw.len - at < 4) return error.Truncated;
            const n = std.mem.readInt(u32, raw[at..][0..4], .little);
            at += 4;
            if (raw.len - at < n or n < 8) return error.Truncated;
            const rec = raw[at..][0..n];
            at += n;
            const o = rec[8..];
            const k = try objects.keyOf(o);
            const gop = try lists.getOrPut(arena, k.id);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(arena, .{ .epoch = std.mem.readInt(u64, rec[0..8], .little), .raw = o });
        }
        var s: Snapshot = .{ .loaded = true };
        for (lists.keys(), lists.values()) |id, *l| {
            std.mem.sort(Entry, l.items, {}, struct {
                fn lt(_: void, a: Entry, b: Entry) bool {
                    return (objects.keyOf(a.raw) catch unreachable).version < (objects.keyOf(b.raw) catch unreachable).version;
                }
            }.lt);
            try s.map.put(arena, id, l.items);
        }
        return s;
    }

    /// A version of `id` was written during `epoch`.
    pub fn writtenIn(s: *const Snapshot, id: *const Id, epoch: u64) bool {
        const l = s.map.get(id.*) orelse return false;
        for (l) |e| if (e.epoch == epoch) return true;
        return false;
    }

    pub fn get(s: *const Snapshot, id: *const Id, epoch: u64) ?[]const u8 {
        const l = s.map.get(id.*) orelse return null;
        var best: ?[]const u8 = null;
        for (l) |e| if (e.epoch <= epoch) {
            best = e.raw;
        };
        return best;
    }
};
