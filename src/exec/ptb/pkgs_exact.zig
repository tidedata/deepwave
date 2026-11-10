//! Exactness test of the package cache (pkgs.zig): the same transactions through the old path
//! (every thread parses and deserializes its own packages, one cache per epoch, started cold)
//! and through the shared paths (`pkgs.shared_enabled`: the process-wide parsed-package table;
//! `pkgs.keep_across_epochs`: caches keyed by protocol version, chain and system package
//! versions). Everything a transaction returns is compared byte for byte: effects (status,
//! gas summary, object changes), events, written objects, runtime loads, and the reason when
//! the executor declines or errors.
//!
//! The world is made from the embedded framework snapshots, so the test needs no corpus:
//!
//!   epoch  protocol  system packages in force
//!   10     139       snapshot 139
//!   11     139       the same (a plain epoch change)
//!   12     140       snapshot 140 (0x1, 0x2 and 0x3 upgraded in place)
//!   13     140       the same
//!   14     141       the same (the protocol version changes, no package does)
//!   15     141       0x2 of snapshot 142 (a system package changes, the protocol does not)
//!   16     142       the same
//!
//! plus a user package (deepbook's modules re-addressed to a non-system id) and an upgraded
//! version of it, which exist in every epoch. Two transactions publish and upgrade a package
//! (they go through the thread's per-transaction package store and never enter the shared
//! table).
//!
//! Variants of the world for the cases one fixed corpus on one chain cannot show: a live
//! source where the user packages appear after transactions already missed them (`live`), a
//! system package that first exists at an epoch change (`dee9_from`), and a package in binary
//! format 7 at protocol 53 and 54, which testnet deserializes and mainnet refuses (`buildOld`).
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const protocol = @import("protocol");
const natives = @import("natives");
const move_format = @import("move_format");
const move_vm = @import("move_vm");
const objects = @import("../objects.zig");
const packages = @import("../packages.zig");
const coin_ptb = @import("../coin_ptb.zig");
const ptb = @import("root.zig");
const pkgs = @import("pkgs.zig");
const typing = @import("typing.zig");

const Allocator = std.mem.Allocator;
const Id = [32]u8;
const testing = std.testing;
const PayRef = @typeInfo(@FieldType(types.GasData, "payment")).pointer.child;

fn sysId(tail: u16) Id {
    var id: Id = @splat(0);
    std.mem.writeInt(u16, id[30..32], tail, .big);
    return id;
}

const sender: Id = @splat(0xab);
const gas_id: Id = blk: {
    var x: Id = @splat(0);
    x[0] = 0x5a;
    x[31] = 9;
    break :blk x;
};
/// The user package (version 1) and its upgrade (version 2, same runtime id).
const user_v1: Id = @splat(0x71);
const user_v2: Id = @splat(0x72);
/// The sender's UpgradeCap for `user_v1`, at version 5.
const cap_id: Id = blk: {
    var x: Id = @splat(0);
    x[0] = 0x5c;
    x[31] = 4;
    break :blk x;
};
/// `buildOld`: a user package whose modules are in binary format 7.
const user_f7: Id = @splat(0x7f);

pub const EpochInfo = struct {
    epoch: u64,
    pv: u64,
    chain: protocol.Chain = .mainnet,
    /// A live world's user packages are served from this visit on (true) or hidden (false).
    show: ?bool = null,
};
pub const epochs = [_]EpochInfo{
    .{ .epoch = 10, .pv = 139 },
    .{ .epoch = 11, .pv = 139 },
    .{ .epoch = 12, .pv = 140 },
    .{ .epoch = 13, .pv = 140 },
    .{ .epoch = 14, .pv = 141 },
    .{ .epoch = 15, .pv = 141 },
    .{ .epoch = 16, .pv = 142 },
};

pub const Tx = struct { name: []const u8, raw: []const u8, data: types.TransactionDataV1 };

pub const World = struct {
    arena: Allocator,
    store: packages.Store = .{ .loaded = true },
    gas_raw: []const u8 = &.{},
    cap_raw: []const u8 = &.{},
    txs: std.ArrayList(Tx) = .empty,
    /// A live world: the user packages, served by `store.lookup` while `visible.*` is set.
    hidden: std.AutoHashMapUnmanaged(Id, []const u8) = .empty,
    visible: *bool = undefined,

    fn get(p: *const anyopaque, id: *const Id, version: u64) ?[]const u8 {
        const w: *const World = @ptrCast(@alignCast(p));
        if (std.mem.eql(u8, id, &gas_id) and version == 7) return w.gas_raw;
        if (std.mem.eql(u8, id, &cap_id) and version == 5 and w.cap_raw.len != 0) return w.cap_raw;
        return null;
    }

    /// `store.lookup` of a live world (any thread; the bytes live as long as the world).
    fn live(p: *const anyopaque, id: *const Id, _: u64) ?[]const u8 {
        const w: *const World = @ptrCast(@alignCast(p));
        if (!w.visible.*) return null;
        return w.hidden.get(id.*);
    }

    fn txIndex(w: *const World, name: []const u8) usize {
        for (w.txs.items, 0..) |t, i| if (std.mem.eql(u8, t.name, name)) return i;
        unreachable;
    }

    pub fn lookup(w: *const World) coin_ptb.ObjectLookup {
        return .{ .ctx = w, .get = get };
    }

    fn systemWrite(w: *World, p: *const natives.framework.Package, version: u64, visible_from: u64) !void {
        const prev: Id = @splat(@truncate(version));
        const raw = try natives.framework.packageObjectBcs(w.arena, p, version, &prev);
        const gop = try w.store.system.getOrPut(w.arena, p.id);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(w.arena, .{ .epoch = visible_from, .raw = raw });
    }

    fn add(w: *World, name: []const u8, inputs: []const types.CallArg, commands: []const types.Command, budget: u64) !void {
        const a = w.arena;
        const pay = try a.alloc(PayRef, 1);
        pay[0] = .{ .{ .@"0" = .{ .@"0" = gas_id } }, .{ .@"0" = 7 }, .{ .@"0" = .{ .@"0" = @splat(9) } } };
        const data: types.TransactionDataV1 = .{
            .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs, .commands = commands } },
            .sender = .{ .@"0" = sender },
            .gas_data = .{ .payment = pay, .owner = .{ .@"0" = sender }, .price = 1000, .budget = budget },
            .expiration = .None,
        };
        // The kept copy is decoded back from the bytes: it owns every nested slice (the
        // callers pass literals that live only for the call).
        const raw = try bcs.encodeAlloc(types.TransactionData, a, &.{ .V1 = data });
        const td = try bcs.decode(types.TransactionData, a, raw);
        try w.txs.append(a, .{ .name = name, .raw = raw, .data = td.V1 });
    }
};

fn samePackage(x: *const natives.framework.Package, y: *const natives.framework.Package) bool {
    if (x.modules.len != y.modules.len) return false;
    for (x.modules, y.modules) |m, n| if (!std.mem.eql(u8, m, n)) return false;
    return true;
}

fn find(v: *const natives.framework.Version, id: *const Id) ?*const natives.framework.Package {
    for (v.packages) |*p| if (std.mem.eql(u8, &p.id, id)) return p;
    return null;
}

/// The modules of `p` with their own address replaced by `to` (a consistent package under a
/// new id: every same-package reference goes through that address identifier).
fn readdress(a: Allocator, p: *const natives.framework.Package, to: Id) ![]const []const u8 {
    return readdressAs(a, p, to, null);
}

/// `readdress`, with the modules written in binary format `version` (null: each one's own).
fn readdressAs(a: Allocator, p: *const natives.framework.Package, to: Id, version: ?u32) ![]const []const u8 {
    const cfg: move_format.BinaryConfig = .{};
    const out = try a.alloc([]const u8, p.modules.len);
    for (p.modules, out) |bytes, *o| {
        var m = switch (try move_format.deserialize(a, bytes, &cfg)) {
            .ok => |m| m,
            .err => return error.BadModule,
        };
        const addrs = try a.dupe([32]u8, m.address_identifiers);
        addrs[m.selfHandle().address] = to;
        m.address_identifiers = addrs;
        if (version) |v| m.version = v;
        o.* = try move_format.serializeAlloc(a, &m, version orelse m.version);
    }
    return out;
}

/// Coin<SUI> with 100 SUI at version 7, owned by the sender.
fn gasObject(a: Allocator) ![]const u8 {
    var contents: [40]u8 = undefined;
    @memcpy(contents[0..32], &gas_id);
    std.mem.writeInt(u64, contents[32..40], 100_000_000_000, .little);
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = .{ .@"0" = .GasCoin }, .has_public_transfer = true, .version = .{ .@"0" = 7 }, .contents = try a.dupe(u8, &contents) } },
        .owner = .{ .AddressOwner = .{ .@"0" = sender } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0x33) } },
        .storage_rebate = 988_000,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

/// `0x2::package::UpgradeCap { id, package, version: 1, policy: 0 }` for `package`, at
/// version 5, owned by the sender.
fn upgradeCap(a: Allocator, package: Id) ![]const u8 {
    var contents: [32 + 32 + 8 + 1]u8 = undefined;
    @memcpy(contents[0..32], &cap_id);
    @memcpy(contents[32..64], &package);
    std.mem.writeInt(u64, contents[64..72], 1, .little);
    contents[72] = 0;
    const o: types.Object = .{
        .data = .{ .Move = .{
            .type_ = .{ .@"0" = .{ .Other = .{ .address = .{ .@"0" = sysId(2) }, .module = .{ .@"0" = "package" }, .name = .{ .@"0" = "UpgradeCap" }, .type_args = &.{} } } },
            .has_public_transfer = true,
            .version = .{ .@"0" = 5 },
            .contents = try a.dupe(u8, &contents),
        } },
        .owner = .{ .AddressOwner = .{ .@"0" = sender } },
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0x34) } },
        .storage_rebate = 1_000_000,
    };
    return bcs.encodeAlloc(types.Object, a, &o);
}

fn oid(id: Id) types.ObjectID {
    return .{ .@"0" = .{ .@"0" = id } };
}

pub const Options = struct {
    /// The user packages come from a live source (`store.lookup`) that serves them only while
    /// `World.visible.*` is set, instead of the fixed corpus.
    live: bool = false,
    /// The first epoch whose store has deepbook (0xdee9); the world then has a transaction
    /// that calls it.
    dee9_from: u64 = 10,
};

fn pureU64(a: Allocator, v: u64) !types.CallArg {
    const b = try a.alloc(u8, 8);
    std.mem.writeInt(u64, b[0..8], v, .little);
    return .{ .Pure = b };
}

fn pureBytes(a: Allocator, v: []const u8) !types.CallArg {
    std.debug.assert(v.len < 128);
    const b = try a.alloc(u8, v.len + 1);
    b[0] = @intCast(v.len);
    @memcpy(b[1..], v);
    return .{ .Pure = b };
}

fn structInput(addr: Id, module: []const u8, name: []const u8, args: []const types.TypeInput) types.TypeInput {
    return .{ .@"struct" = .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = module }, .name = .{ .@"0" = name }, .type_args = args } };
}

fn call(pkg: Id, module: []const u8, function: []const u8, ty: []const types.TypeInput, args: []const types.Argument) types.Command {
    return .{ .MoveCall = .{ .package = .{ .@"0" = .{ .@"0" = pkg } }, .module = .{ .@"0" = module }, .function = .{ .@"0" = function }, .type_arguments = ty, .arguments = args } };
}

pub fn build(arena: Allocator) !*World {
    return buildWith(arena, .{});
}

pub fn buildWith(arena: Allocator, opts: Options) !*World {
    const a = arena;
    const w = try a.create(World);
    w.* = .{ .arena = a };
    w.visible = try a.create(bool);
    w.visible.* = true;
    if (opts.live) w.store.lookup = .{ .ctx = w, .get = World.live };
    const vers = try natives.framework.load(a);
    const s139 = natives.framework.snapshot(vers, 139).?;
    const s140 = natives.framework.snapshot(vers, 140).?;
    const s142 = natives.framework.snapshot(vers, 142).?;
    try testing.expectEqual(@as(u64, 139), s139.version);
    try testing.expectEqual(@as(u64, 140), s140.version);
    try testing.expectEqual(@as(u64, 142), s142.version);
    // epoch 10: every package of snapshot 139; epoch 12: the packages snapshot 140 changed;
    // epoch 15: the packages snapshot 142 changed.
    for (s139.packages) |*p| try w.systemWrite(p, 39, if (std.mem.eql(u8, &p.id, &sysId(0xdee9))) opts.dee9_from else 10);
    var changed_140: usize = 0;
    for (s140.packages) |*p| if (!samePackage(p, find(s139, &p.id).?)) {
        try w.systemWrite(p, 40, 12);
        changed_140 += 1;
    };
    var changed_142: usize = 0;
    for (s142.packages) |*p| if (!samePackage(p, find(s140, &p.id).?)) {
        try w.systemWrite(p, 41, 15);
        changed_142 += 1;
    };
    // the upgrades the test relies on are really in the snapshots
    try testing.expect(changed_140 >= 1);
    try testing.expect(changed_142 >= 1);

    // The user package: deepbook's modules under a non-system id, and an upgrade of it (a new
    // storage id and version over the same runtime id).
    const dee9 = find(s139, &sysId(0xdee9)).?;
    const one = sysId(1);
    const two = sysId(2);
    const user: natives.framework.Package = .{ .id = user_v1, .modules = try readdress(a, dee9, user_v1), .deps = &.{ one, two } };
    const prev: Id = @splat(0x70);
    const obj_v1 = try natives.framework.packageObjectBcs(a, &user, 1, &prev);
    const obj_v2 = try a.dupe(u8, obj_v1);
    @memcpy(obj_v2[1..33], &user_v2);
    std.mem.writeInt(u64, obj_v2[33..41], 2, .little);
    const user_map = if (opts.live) &w.hidden else &w.store.user;
    try user_map.put(a, user_v1, obj_v1);
    try user_map.put(a, user_v2, obj_v2);

    w.gas_raw = try gasObject(a);
    w.cap_raw = try upgradeCap(a, user_v1);

    const sui = structInput(two, "sui", "SUI", &.{});
    const coin_sui = structInput(two, "coin", "Coin", try a.dupe(types.TypeInput, &.{sui}));
    const budget: u64 = 50_000_000;
    const addr_arg: types.CallArg = .{ .Pure = try a.dupe(u8, &sender) };

    // framework calls that succeed
    try w.add("coin zero + destroy_zero", &.{}, &.{
        call(two, "coin", "zero", &.{sui}, &.{}),
        call(two, "coin", "destroy_zero", &.{sui}, &.{.{ .Result = 0 }}),
    }, budget);
    try w.add("split + transfer", &.{ try pureU64(a, 1000), addr_arg }, &.{
        .{ .SplitCoins = .{ .GasCoin, &.{.{ .Input = 0 }} } },
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 1 } } },
    }, budget);
    try w.add("coin zero + public_transfer", &.{addr_arg}, &.{
        call(two, "coin", "zero", &.{sui}, &.{}),
        call(two, "transfer", "public_transfer", &.{coin_sui}, &.{ .{ .Result = 0 }, .{ .Input = 0 } }),
    }, budget);
    try w.add("string utf8", &.{try pureBytes(a, "package cache")}, &.{
        call(one, "string", "utf8", &.{}, &.{.{ .Input = 0 }}),
    }, budget);
    try w.add("type_name of Coin<SUI>", &.{}, &.{
        call(one, "type_name", "get", &.{coin_sui}, &.{}),
    }, budget);
    try w.add("hash natives", &.{try pureBytes(a, "abc")}, &.{
        call(one, "hash", "sha2_256", &.{}, &.{.{ .Input = 0 }}),
        call(two, "hash", "keccak256", &.{}, &.{.{ .Result = 0 }}),
    }, budget);
    try w.add("make vec + length", &.{ try pureU64(a, 4), try pureU64(a, 5) }, &.{
        .{ .MakeMoveVec = .{ .u64, &.{ .{ .Input = 0 }, .{ .Input = 1 } } } },
        call(one, "vector", "length", &.{.u64}, &.{.{ .Result = 0 }}),
    }, budget);
    try w.add("table new + destroy_empty", &.{}, &.{
        call(two, "table", "new", &.{ .u64, .u64 }, &.{}),
        call(two, "table", "destroy_empty", &.{ .u64, .u64 }, &.{.{ .Result = 0 }}),
    }, budget);
    try w.add("bcs to_bytes", &.{addr_arg}, &.{
        call(two, "bcs", "to_bytes", &.{.address}, &.{.{ .Input = 0 }}),
    }, budget);
    // failures: abort, out of gas, a missing function, wrong type arguments, a private call
    try w.add("address from_bytes aborts", &.{try pureBytes(a, "short")}, &.{
        call(two, "address", "from_bytes", &.{}, &.{.{ .Input = 0 }}),
    }, budget);
    try w.add("out of gas", &.{try pureBytes(a, "abc")}, &.{
        call(one, "hash", "sha2_256", &.{}, &.{.{ .Input = 0 }}),
        call(two, "hash", "keccak256", &.{}, &.{.{ .Result = 0 }}),
        call(two, "table", "new", &.{ .u64, .u64 }, &.{}),
        call(two, "table", "destroy_empty", &.{ .u64, .u64 }, &.{.{ .Result = 2 }}),
    }, 1_000_000);
    try w.add("missing function", &.{}, &.{
        call(two, "coin", "no_such_function", &.{sui}, &.{}),
    }, budget);
    try w.add("missing module", &.{}, &.{
        call(two, "no_such_module", "f", &.{}, &.{}),
    }, budget);
    try w.add("wrong type argument count", &.{}, &.{
        call(two, "coin", "zero", &.{ sui, sui }, &.{}),
    }, budget);
    try w.add("event emit from outside the module", &.{try pureU64(a, 1)}, &.{
        call(two, "event", "emit", &.{.u64}, &.{.{ .Input = 0 }}),
    }, budget);
    try w.add("missing package", &.{}, &.{
        call(@splat(0x77), "m", "f", &.{}, &.{}),
    }, budget);
    // the user package, its upgrade, and types it defines
    try w.add("user math mul", &.{ try pureU64(a, 3_000_000_000), try pureU64(a, 5) }, &.{
        call(user_v1, "math", "mul", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
    }, budget);
    try w.add("user v2 math mul", &.{ try pureU64(a, 7_000_000_000), try pureU64(a, 9) }, &.{
        call(user_v2, "math", "mul", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
    }, budget);
    try w.add("user v1 then v2", &.{ try pureU64(a, 2_000_000_000), try pureU64(a, 9) }, &.{
        call(user_v1, "math", "mul", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
        call(user_v2, "math", "mul", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
    }, budget);
    try w.add("user create_account + transfer", &.{addr_arg}, &.{
        call(user_v1, "clob_v2", "create_account", &.{}, &.{}),
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 0 } } },
    }, budget);
    try w.add("user v2 create_account + transfer", &.{addr_arg}, &.{
        call(user_v2, "clob_v2", "create_account", &.{}, &.{}),
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 0 } } },
    }, budget);
    try w.add("type_name of a user type", &.{}, &.{
        call(one, "type_name", "get", &.{structInput(user_v1, "custodian_v2", "AccountCap", &.{})}, &.{}),
    }, budget);
    try w.add("type_name of a user type by its upgrade's id", &.{}, &.{
        call(one, "type_name", "get", &.{structInput(user_v2, "custodian_v2", "AccountCap", &.{})}, &.{}),
    }, budget);
    // Publish and Upgrade: the user package's modules under address 0x0 (what a publisher
    // signs). The new package lives in the thread's runtime and its per-transaction package
    // store for the transaction only.
    const payload = try readdress(a, dee9, @splat(0));
    const deps = try a.dupe(types.ObjectID, &.{ oid(one), oid(two) });
    const big: u64 = 5_000_000_000;
    try w.add("publish + transfer the cap", &.{addr_arg}, &.{
        .{ .Publish = .{ payload, deps } },
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 0 } } },
    }, big);
    try w.add("publish without a dependency", &.{addr_arg}, &.{
        .{ .Publish = .{ payload, deps[0..1] } },
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 0 } } },
    }, big);
    const digest = try typing.packageDigest(a, payload, &.{ one, two });
    const cap_arg: types.CallArg = .{ .Object = .{ .ImmOrOwnedObject = .{ oid(cap_id), .{ .@"0" = 5 }, .{ .@"0" = .{ .@"0" = @splat(0x35) } } } } };
    const policy_arg: types.CallArg = .{ .Pure = try a.dupe(u8, &.{0}) };
    try w.add("upgrade the user package", &.{ cap_arg, policy_arg, try pureBytes(a, &digest) }, &.{
        call(two, "package", "authorize_upgrade", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 }, .{ .Input = 2 } }),
        .{ .Upgrade = .{ payload, deps, oid(user_v1), .{ .Result = 0 } } },
        call(two, "package", "commit_upgrade", &.{}, &.{ .{ .Input = 0 }, .{ .Result = 1 } }),
    }, big);
    var wrong = digest;
    wrong[0] ^= 1;
    try w.add("upgrade with the wrong digest", &.{ cap_arg, policy_arg, try pureBytes(a, &wrong) }, &.{
        call(two, "package", "authorize_upgrade", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 }, .{ .Input = 2 } }),
        .{ .Upgrade = .{ payload, deps, oid(user_v1), .{ .Result = 0 } } },
        call(two, "package", "commit_upgrade", &.{}, &.{ .{ .Input = 0 }, .{ .Result = 1 } }),
    }, big);
    if (opts.dee9_from != 10) try w.add("deepbook math mul", &.{ try pureU64(a, 3_000_000_000), try pureU64(a, 5) }, &.{
        call(sysId(0xdee9), "math", "mul", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
    }, budget);
    return w;
}

/// Protocol 53 and 54, where testnet reads binary format 7 and mainnet stops at 6: the system
/// packages of the snapshot in force at 53, and a user package (deepbook's modules under
/// `user_f7`) written in format 7. One store serves both chains, so one shared-table entry
/// holds the package for both.
pub fn buildOld(arena: Allocator) !*World {
    const a = arena;
    const w = try a.create(World);
    w.* = .{ .arena = a };
    w.visible = try a.create(bool);
    w.visible.* = true;
    const vers = try natives.framework.load(a);
    const snap = natives.framework.snapshot(vers, 53).?;
    try testing.expect(snap.version <= 53);
    for (snap.packages) |*p| try w.systemWrite(p, 7, 0);
    const dee9 = find(snap, &sysId(0xdee9)).?;
    const one = sysId(1);
    const two = sysId(2);
    const user: natives.framework.Package = .{ .id = user_f7, .modules = try readdressAs(a, dee9, user_f7, move_format.file_format.VERSION_7), .deps = &.{ one, two } };
    const prev: Id = @splat(0x6f);
    try w.store.user.put(a, user_f7, try natives.framework.packageObjectBcs(a, &user, 1, &prev));
    w.gas_raw = try gasObject(a);

    const sui = structInput(two, "sui", "SUI", &.{});
    const budget: u64 = 50_000_000;
    const addr_arg: types.CallArg = .{ .Pure = try a.dupe(u8, &sender) };
    try w.add("coin zero + destroy_zero", &.{}, &.{
        call(two, "coin", "zero", &.{sui}, &.{}),
        call(two, "coin", "destroy_zero", &.{sui}, &.{.{ .Result = 0 }}),
    }, budget);
    try w.add("split + transfer", &.{ try pureU64(a, 1000), addr_arg }, &.{
        .{ .SplitCoins = .{ .GasCoin, &.{.{ .Input = 0 }} } },
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 1 } } },
    }, budget);
    try w.add("string utf8", &.{try pureBytes(a, "package cache")}, &.{
        call(one, "string", "utf8", &.{}, &.{.{ .Input = 0 }}),
    }, budget);
    try w.add("format 7 math mul", &.{ try pureU64(a, 3_000_000_000), try pureU64(a, 5) }, &.{
        call(user_f7, "math", "mul", &.{}, &.{ .{ .Input = 0 }, .{ .Input = 1 } }),
    }, budget);
    try w.add("format 7 create_account + transfer", &.{addr_arg}, &.{
        call(user_f7, "clob_v2", "create_account", &.{}, &.{}),
        .{ .TransferObjects = .{ &.{.{ .Result = 0 }}, .{ .Input = 0 } } },
    }, budget);
    try w.add("missing package", &.{}, &.{
        call(@splat(0x77), "m", "f", &.{}, &.{}),
    }, budget);
    return w;
}

pub const Mode = struct {
    /// `pkgs.shared_enabled`.
    shared: bool,
    /// `pkgs.keep_across_epochs`.
    keep: bool,
    /// Drop this thread's caches before every epoch visit (each visit starts cold).
    cold: bool = false,

    pub const old_cold: Mode = .{ .shared = false, .keep = false, .cold = true };
    pub const old: Mode = .{ .shared = false, .keep = false };
};

/// Everything one execution returned, as bytes.
fn dump(a: Allocator, r: anyerror!ptb.Outcome) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    const o = r catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            try out.appendSlice(a, "error ");
            try out.appendSlice(a, @errorName(e));
            return out.items;
        },
    };
    const S = struct {
        fn blob(al: Allocator, l: *std.ArrayList(u8), b: []const u8) !void {
            var n: [8]u8 = undefined;
            std.mem.writeInt(u64, &n, b.len, .little);
            try l.appendSlice(al, &n);
            try l.appendSlice(al, b);
        }
    };
    switch (o) {
        .unsupported => |why| {
            try out.appendSlice(a, "unsupported ");
            try out.appendSlice(a, why);
        },
        .done => |d| {
            try out.appendSlice(a, "done ");
            try S.blob(a, &out, d.effects);
            try S.blob(a, &out, d.events orelse "<no events>");
            for (d.written) |x| {
                try out.appendSlice(a, &x.id);
                try S.blob(a, &out, x.bytes);
            }
            try out.appendSlice(a, "loaded");
            for (d.loaded) |x| {
                try out.appendSlice(a, &x.id);
                try out.appendSlice(a, std.mem.asBytes(&x.version));
            }
            try out.appendSlice(a, "deny");
            for (d.deny_pairs) |x| {
                try S.blob(a, &out, x.t);
                try out.appendSlice(a, &x.o);
            }
        },
    }
    return out.items;
}

/// What the store serves at `epoch` is what the thread's cache for `epoch` holds: every
/// package the cache answered for is the store's object for that epoch (the same bytes at the
/// same address), and every miss it remembers is still a miss.
///
/// `misses`: also check the remembered misses. Off for the old path over a live source, which
/// keeps an input-object miss until its epoch's cache goes, whatever the source says later.
fn checkCacheAgainstStore(gpa: Allocator, w: *const World, e: EpochInfo, misses: bool) !void {
    const c = try pkgs.cacheFor(gpa, &w.store, e.epoch, e.pv, e.chain);
    var it = c.map.iterator();
    while (it.next()) |kv| {
        const want = w.store.get(kv.key_ptr, e.epoch);
        if (kv.value_ptr.*) |p| {
            try testing.expect(want != null);
            try testing.expectEqual(want.?.ptr, p.raw.ptr);
            try testing.expectEqual(want.?.len, p.raw.len);
            try testing.expectEqual(want.?.ptr, p.view.raw.ptr);
            const v = try objects.ObjectView.parse(want.?);
            try testing.expectEqual(v.version, p.version);
            try testing.expectEqualSlices(u8, &v.id, &p.version_id);
            if (p.vm) |vm| {
                try testing.expectEqual(p.version, vm.version);
                try testing.expectEqualSlices(u8, &p.version_id, &vm.version_id);
                try testing.expectEqualSlices(u8, &p.original_id, &vm.original_id);
            }
        } else if (misses) try testing.expect(want == null);
    }
    var ot = c.objs.iterator();
    while (ot.next()) |kv| {
        const want = w.store.get(kv.key_ptr, e.epoch);
        if (kv.value_ptr.*) |po| {
            try testing.expect(want != null);
            try testing.expectEqual(want.?.ptr, po.view.raw.ptr);
            try testing.expectEqual(want.?.len, po.view.raw.len);
        } else if (misses) try testing.expect(want == null);
    }
}

/// Runs every transaction at each epoch of `order` (indices into `epochs`) on the calling
/// thread under the switches as they stand; one result per (visit, transaction), in order.
/// `cold`: the thread's caches are dropped before every visit. They are dropped before and after.
pub fn runOn(gpa: Allocator, out_arena: Allocator, w: *const World, cold: bool, order: []const usize) ![]const []const u8 {
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    const visits = try scratch.allocator().alloc(EpochInfo, order.len);
    for (order, visits) |ei, *v| v.* = epochs[ei];
    return runVisits(gpa, out_arena, w, cold, visits, true);
}

/// `runOn` over any visits (epoch, protocol version, chain; `show` first sets what a live world
/// serves). `misses`: see `checkCacheAgainstStore`.
pub fn runVisits(gpa: Allocator, out_arena: Allocator, w: *const World, cold: bool, visits: []const EpochInfo, misses: bool) ![]const []const u8 {
    pkgs.releaseThreadCaches();
    defer pkgs.releaseThreadCaches();
    var out: std.ArrayList([]const u8) = .empty;
    var scratch = std.heap.ArenaAllocator.init(gpa);
    defer scratch.deinit();
    for (visits) |e| {
        if (e.show) |s| w.visible.* = s;
        if (cold) pkgs.releaseThreadCaches();
        const env: ptb.Env = .{
            .gpa = gpa,
            .cfg = try protocol.get(e.pv, e.chain),
            .pv = e.pv,
            .epoch = e.epoch,
            .epoch_start_ms = 1_700_000_000_000 + e.epoch * 86_400_000,
            .rgp = 1000,
            .pkgs = &w.store,
        };
        for (w.txs.items) |*t| {
            _ = scratch.reset(.retain_capacity);
            const r = ptb.execute(scratch.allocator(), env, t.raw, &t.data, .{ .objs = w.lookup(), .effects = null, .unchanged_loaded = null });
            try out.append(out_arena, try dump(out_arena, r));
            try checkCacheAgainstStore(gpa, w, e, misses);
        }
    }
    return out.items;
}

/// `runOn` under `mode`'s switches (restored afterwards).
pub fn runAll(gpa: Allocator, out_arena: Allocator, w: *const World, mode: Mode, order: []const usize) ![]const []const u8 {
    pkgs.readEnv(); // so the environment cannot flip a switch mid-run
    const saved = .{ pkgs.shared_enabled, pkgs.keep_across_epochs };
    defer {
        pkgs.shared_enabled = saved[0];
        pkgs.keep_across_epochs = saved[1];
    }
    pkgs.shared_enabled = mode.shared;
    pkgs.keep_across_epochs = mode.keep;
    return runOn(gpa, out_arena, w, mode.cold, order);
}

/// `runVisits` under `mode`'s switches (restored afterwards).
pub fn runAllVisits(gpa: Allocator, out_arena: Allocator, w: *const World, mode: Mode, visits: []const EpochInfo, misses: bool) ![]const []const u8 {
    pkgs.readEnv();
    const saved = .{ pkgs.shared_enabled, pkgs.keep_across_epochs };
    defer {
        pkgs.shared_enabled = saved[0];
        pkgs.keep_across_epochs = saved[1];
    }
    pkgs.shared_enabled = mode.shared;
    pkgs.keep_across_epochs = mode.keep;
    return runVisits(gpa, out_arena, w, mode.cold, visits, misses);
}

/// The six settings of the two switches, cold per visit and warm, that are not the old path.
const new_modes = [_]Mode{
    .{ .shared = true, .keep = false, .cold = true },
    .{ .shared = true, .keep = false },
    .{ .shared = false, .keep = true, .cold = true },
    .{ .shared = false, .keep = true },
    .{ .shared = true, .keep = true, .cold = true },
    .{ .shared = true, .keep = true },
};

fn modeName(buf: []u8, mode: Mode) []const u8 {
    return std.fmt.bufPrint(buf, "shared={} keep={} cold={}", .{ mode.shared, mode.keep, mode.cold }) catch "mode";
}

/// The effects status of a `dump`ed result, or null when the transaction did not end in effects.
fn statusOf(a: Allocator, r: []const u8) !?types.ExecutionStatus {
    if (!std.mem.startsWith(u8, r, "done ")) return null;
    const fx = try bcs.decode(types.TransactionEffects, a, r[13..][0..std.mem.readInt(u64, r[5..13], .little)]);
    return fx.V2.status;
}

fn expectSameVisits(w: *const World, visits: []const EpochInfo, want: []const []const u8, have: []const []const u8, what: []const u8) !void {
    try testing.expectEqual(want.len, have.len);
    const n = w.txs.items.len;
    for (want, have, 0..) |x, y, i| {
        if (std.mem.eql(u8, x, y)) continue;
        const e = visits[i / n];
        std.debug.print("{s}: visit {d} (epoch {d}, protocol {d}, {s}), transaction \"{s}\" differs\n  want {x}\n  have {x}\n", .{ what, i / n, e.epoch, e.pv, @tagName(e.chain), w.txs.items[i % n].name, x[0..@min(x.len, 200)], y[0..@min(y.len, 200)] });
        return error.TestExpectedEqual;
    }
}

pub fn expectSame(w: *const World, order: []const usize, want: []const []const u8, have: []const []const u8, what: []const u8) !void {
    try testing.expectEqual(want.len, have.len);
    const n = w.txs.items.len;
    for (want, have, 0..) |x, y, i| {
        if (std.mem.eql(u8, x, y)) continue;
        std.debug.print("{s}: visit {d} (epoch {d}), transaction \"{s}\" differs\n  want {x}\n  have {x}\n", .{ what, i / n, epochs[order[i / n]].epoch, w.txs.items[i % n].name, x[0..@min(x.len, 200)], y[0..@min(y.len, 200)] });
        return error.TestExpectedEqual;
    }
}

/// Every epoch in order, then back and forth across each boundary (an epoch change, the
/// framework upgrade, the protocol-only change, the package-only change), then a second pass.
pub const order_full = [_]usize{ 0, 1, 2, 3, 4, 5, 6, 0, 2, 1, 3, 2, 4, 3, 5, 4, 6, 5, 1, 0, 6, 0, 1, 2, 3, 4, 5, 6 };

test "package cache exactness: old cold per-epoch caches against the shared table and the cross-epoch key" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try build(a);
    const order: []const usize = &order_full;
    const want = try runAll(gpa, a, w, Mode.old_cold, order);

    // The reference means something: the plain calls succeed (the failures are the cases
    // written to fail), and the store really changes system packages where the table at the
    // top says so. A cache that kept a package across such a change is caught by
    // `checkCacheAgainstStore` after every transaction.
    const n = w.txs.items.len;
    var done: usize = 0;
    var success: usize = 0;
    for (want[0..n]) |r| {
        if (!std.mem.startsWith(u8, r, "done ")) continue;
        done += 1;
        const fx = try bcs.decode(types.TransactionEffects, a, r[13..][0..std.mem.readInt(u64, r[5..13], .little)]);
        if (fx.V2.status == .Success) success += 1;
    }
    try testing.expectEqual(n - 1, done); // all but "missing package"
    try testing.expect(success >= 13);
    // Publish and Upgrade really ran, at every epoch: both succeed, and the two written to
    // fail do so in effects.
    for (0..epochs.len) |v| {
        const at = want[v * n ..][0..n];
        try testing.expect((try statusOf(a, at[w.txIndex("publish + transfer the cap")])).? == .Success);
        try testing.expect((try statusOf(a, at[w.txIndex("upgrade the user package")])).? == .Success);
        try testing.expect((try statusOf(a, at[w.txIndex("publish without a dependency")])).? == .Failure);
        try testing.expect((try statusOf(a, at[w.txIndex("upgrade with the wrong digest")])).? == .Failure);
    }
    const two = sysId(2);
    const at = struct {
        fn f(world: *const World, id: *const Id, epoch: u64) [*]const u8 {
            return world.store.get(id, epoch).?.ptr;
        }
    }.f;
    try testing.expect(at(w, &two, 10) == at(w, &two, 11));
    try testing.expect(at(w, &two, 11) != at(w, &two, 12)); // the framework upgrade
    try testing.expect(at(w, &two, 12) == at(w, &two, 14));
    try testing.expect(at(w, &two, 14) != at(w, &two, 15)); // 0x2 alone, same protocol version
    try testing.expect(at(w, &two, 15) == at(w, &two, 16));
    try testing.expect(at(w, &sysId(1), 11) != at(w, &sysId(1), 12));
    try testing.expect(at(w, &sysId(1), 12) == at(w, &sysId(1), 16));

    // The old path warm equals the old path cold (the test is deterministic).
    try expectSame(w, order, want, try runAll(gpa, a, w, Mode.old, order), "old path, warm");
    // Each switch alone and both together, cold per visit and warm.
    for (new_modes) |mode| {
        var name: [64]u8 = undefined;
        try expectSame(w, order, want, try runAll(gpa, a, w, mode, order), modeName(&name, mode));
    }
}

const in_order = [_]usize{ 0, 1, 2, 3, 4, 5, 6 };
/// Package objects the transactions touch over the seven epochs: 0x1 and 0x3 in two versions,
/// 0x2 in three, the user package and its upgrade.
const distinct_packages = 9;

const Counters = struct {
    cold: u64,
    hits: u64,
    module_loads: u64,
    module_hits: u64,
    predecoded: u64,

    fn now() Counters {
        const t = &pkgs.shared;
        return .{
            .cold = t.cold_loads.load(.monotonic),
            .hits = t.hits.load(.monotonic),
            .module_loads = t.module_loads.load(.monotonic),
            .module_hits = t.module_hits.load(.monotonic),
            .predecoded = move_vm.loader.predecoded_loads.load(.monotonic),
        };
    }
};

/// An empty table: no thread cache of this thread pins anything, nothing unpinned is kept.
fn emptyTable() !void {
    pkgs.releaseThreadCaches();
    pkgs.shared.clear();
    try testing.expectEqual(@as(u64, 0), pkgs.shared.entries.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), pkgs.shared.bytes_held.load(.monotonic));
}

test "package cache: the shared table parses and deserializes each package once for the process" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try build(a);
    try emptyTable();
    defer pkgs.shared.clear();

    // The old path does not touch the table.
    const c0 = Counters.now();
    const want = try runAll(gpa, a, w, Mode.old_cold, &in_order);
    try testing.expectEqualDeep(c0, Counters.now());

    // First run, every visit on a cold thread cache: each package object is parsed once, and
    // its modules are deserialized once per binary config, however many caches load it.
    const one = try runAll(gpa, a, w, .{ .shared = true, .keep = false, .cold = true }, &in_order);
    try expectSame(w, &in_order, want, one, "shared, first run");
    const c1 = Counters.now();
    try testing.expectEqual(@as(u64, distinct_packages), c1.cold - c0.cold);
    try testing.expectEqual(@as(u64, distinct_packages), pkgs.shared.entries.load(.monotonic));
    try testing.expect(c1.module_loads - c0.module_loads >= distinct_packages);
    try testing.expect(c1.module_loads - c0.module_loads <= distinct_packages * 3);
    try testing.expect(c1.hits > c0.hits); // seven cold caches shared nine parses
    try testing.expect(c1.predecoded > c0.predecoded);
    try testing.expect(pkgs.shared.bytes_held.load(.monotonic) > 0);

    // Second run, cold thread caches again: nothing is parsed, deserialized or hashed again.
    const two = try runAll(gpa, a, w, .{ .shared = true, .keep = false, .cold = true }, &in_order);
    try expectSame(w, &in_order, want, two, "shared, second run");
    const c2 = Counters.now();
    try testing.expectEqual(c1.cold, c2.cold);
    try testing.expectEqual(c1.module_loads, c2.module_loads);
    try testing.expect(c2.hits > c1.hits);
    try testing.expect(c2.module_hits > c1.module_hits);
    try testing.expectEqual(c1.predecoded - c0.predecoded, c2.predecoded - c1.predecoded);

    // Nothing is pinned once the thread's caches are gone: the table can be emptied.
    try emptyTable();
}

test "package cache: the shared table stays within its budget once caches let go, and what it dropped loads again the same" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try build(a);
    try emptyTable();
    const saved = pkgs.shared.max_bytes;
    defer {
        pkgs.shared.max_bytes = saved;
        pkgs.shared.clear();
    }
    const want = try runAll(gpa, a, w, Mode.old_cold, &in_order);
    const mode: Mode = .{ .shared = true, .keep = false, .cold = true };

    // What the nine packages take with room for all of them.
    try expectSame(w, &in_order, want, try runAll(gpa, a, w, mode, &in_order), "shared, roomy");
    const full = pkgs.shared.bytes_held.load(.monotonic);
    try testing.expect(full > 100_000); // the framework alone is some 180 KB of modules
    try testing.expect(full <= saved);

    // Half of that: the table ends within the budget, having evicted, and results are the same.
    try emptyTable();
    pkgs.shared.max_bytes = full / 2;
    const ev0 = pkgs.shared.evictions.load(.monotonic);
    try expectSame(w, &in_order, want, try runAll(gpa, a, w, mode, &in_order), "shared, half budget");
    try testing.expect(pkgs.shared.bytes_held.load(.monotonic) <= full / 2);
    try testing.expect(pkgs.shared.entries.load(.monotonic) < distinct_packages);
    try testing.expect(pkgs.shared.evictions.load(.monotonic) > ev0);

    // No budget at all: every package leaves the table as soon as no cache holds it. While a
    // cache holds it (a warm run), it stays, over the budget.
    try emptyTable();
    pkgs.shared.max_bytes = 0;
    try expectSame(w, &in_order, want, try runAll(gpa, a, w, mode, &in_order), "shared, no budget");
    try testing.expectEqual(@as(u64, 0), pkgs.shared.entries.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), pkgs.shared.bytes_held.load(.monotonic));
    try expectSame(w, &in_order, want, try runAll(gpa, a, w, .{ .shared = true, .keep = true }, &in_order), "shared, no budget, warm");
    try testing.expectEqual(@as(u64, 0), pkgs.shared.entries.load(.monotonic));
}

const Worker = struct {
    w: *const World,
    cold: bool,
    order: []const usize,
    arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator),
    out: []const []const u8 = &.{},
    err: ?anyerror = null,

    fn run(x: *Worker) void {
        x.out = runOn(std.heap.smp_allocator, x.arena.allocator(), x.w, x.cold, x.order) catch |e| {
            x.err = e;
            return;
        };
    }
};

test "package cache: four threads on the shared table at once get the old path's results" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try build(a);
    const n = w.txs.items.len;
    // one block of results per epoch, from the old path started cold
    const want = try runAll(gpa, a, w, Mode.old_cold, &in_order);

    pkgs.readEnv();
    const saved = .{ pkgs.shared_enabled, pkgs.keep_across_epochs };
    defer {
        pkgs.shared_enabled = saved[0];
        pkgs.keep_across_epochs = saved[1];
        pkgs.shared.clear();
    }
    // What one thread loads from an empty table: the threads together must load the same.
    try emptyTable();
    const c0 = Counters.now();
    pkgs.shared_enabled = true;
    pkgs.keep_across_epochs = false;
    _ = try runOn(gpa, a, w, true, &order_full);
    const c1 = Counters.now();
    try testing.expectEqual(@as(u64, distinct_packages), c1.cold - c0.cold);

    for ([_]bool{ false, true }) |keep| {
        try emptyTable();
        pkgs.keep_across_epochs = keep;
        const before = Counters.now();
        var workers: [4]Worker = undefined;
        var threads: [4]std.Thread = undefined;
        for (&workers, 0..) |*x, i| {
            // each thread starts at another point of the tour; two of them cold per visit
            const order = try a.alloc(usize, order_full.len);
            for (order, 0..) |*o, k| o.* = order_full[(k + i * 5) % order_full.len];
            x.* = .{ .w = w, .cold = i % 2 == 0, .order = order };
        }
        defer for (&workers) |*x| x.arena.deinit();
        for (&threads, &workers) |*t, *x| t.* = try std.Thread.spawn(.{ .stack_size = 64 << 20 }, Worker.run, .{x});
        for (threads) |t| t.join();
        for (&workers) |*x| {
            if (x.err) |e| return e;
            try testing.expectEqual(x.order.len * n, x.out.len);
            for (x.order, 0..) |ei, v| for (0..n) |i| {
                if (std.mem.eql(u8, want[ei * n + i], x.out[v * n + i])) continue;
                std.debug.print("keep={}: a thread's visit {d} (epoch {d}), transaction \"{s}\" differs\n", .{ keep, v, epochs[ei].epoch, w.txs.items[i].name });
                return error.TestExpectedEqual;
            };
        }
        // Parsed once and deserialized once per binary config, whatever the interleaving.
        const after = Counters.now();
        try testing.expectEqual(c1.cold - c0.cold, after.cold - before.cold);
        try testing.expectEqual(c1.module_loads - c0.module_loads, after.module_loads - before.module_loads);
    }
}

test "package cache: a cache moves to another epoch only when the protocol version and every system package are the same" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try build(a);
    pkgs.readEnv();
    const saved = pkgs.keep_across_epochs;
    defer pkgs.keep_across_epochs = saved;
    pkgs.releaseThreadCaches();
    defer pkgs.releaseThreadCaches();

    // The key's system package part, by epoch (the table at the top of the file).
    const sv = struct {
        fn f(world: *const World, epoch: u64) pkgs.SysVersions {
            return pkgs.systemVersions(&world.store, epoch).?;
        }
    }.f;
    try testing.expectEqualDeep(sv(w, 10), sv(w, 11));
    try testing.expect(!std.meta.eql(sv(w, 11), sv(w, 12)));
    try testing.expectEqualDeep(sv(w, 12), sv(w, 13));
    try testing.expectEqualDeep(sv(w, 13), sv(w, 14));
    try testing.expect(!std.meta.eql(sv(w, 14), sv(w, 15)));
    try testing.expectEqualDeep(sv(w, 15), sv(w, 16));
    for (sv(w, 10)) |v| try testing.expectEqual(@as(?u64, 39), v);
    try testing.expectEqual(@as(?u64, 41), sv(w, 15)[1]); // 0x2

    const two = sysId(2);
    const S = struct {
        fn cache(world: *const World, e: EpochInfo) !*pkgs.Cache {
            const c = try pkgs.cacheFor(testing.allocator, &world.store, e.epoch, e.pv, .mainnet);
            try testing.expectEqual(e.epoch, c.epoch);
            try testing.expectEqual(e.pv, c.pv);
            return c;
        }
    };

    // Off: one cache per epoch, as before.
    pkgs.keep_across_epochs = false;
    const moves0 = pkgs.epoch_moves.load(.monotonic);
    try testing.expect(try S.cache(w, epochs[0]) != try S.cache(w, epochs[1]));
    try testing.expectEqual(moves0, pkgs.epoch_moves.load(.monotonic));
    pkgs.releaseThreadCaches();

    // On: the cache follows the thread across a plain epoch change and back, and stops at a
    // protocol change (13 to 14, 15 to 16) and at a system package change (11 to 12, 14 to 15).
    pkgs.keep_across_epochs = true;
    const c10 = try S.cache(w, epochs[0]);
    try testing.expect((try c10.get(&two)) != null);
    const c11 = try S.cache(w, epochs[1]);
    try testing.expectEqual(c10, c11);
    try testing.expectEqual(c10, try S.cache(w, epochs[0]));
    try testing.expectEqual(c10, try S.cache(w, epochs[1]));
    try testing.expectEqual(moves0 + 3, pkgs.epoch_moves.load(.monotonic));
    const c12 = try S.cache(w, epochs[2]);
    try testing.expect(c12 != c10);
    try testing.expectEqual(c12, try S.cache(w, epochs[3]));
    const c14 = try S.cache(w, epochs[4]);
    try testing.expect(c14 != c12);
    const c15 = try S.cache(w, epochs[5]);
    try testing.expect(c15 != c14);
    try testing.expectEqual(moves0 + 4, pkgs.epoch_moves.load(.monotonic));
    pkgs.releaseThreadCaches();
    const c16 = try S.cache(w, epochs[6]);
    try testing.expectEqual(c16, try S.cache(w, epochs[6]));
    try testing.expectEqual(moves0 + 4, pkgs.epoch_moves.load(.monotonic));
    pkgs.releaseThreadCaches();

    // A cache that holds a system package other than the version its key names is left alone
    // (a live source that changed its answer between the key and the load).
    const c = try S.cache(w, epochs[2]);
    const fake = try c.arena.allocator().create(pkgs.Pkg);
    fake.* = .{ .raw = &.{}, .view = undefined, .version_id = two, .original_id = two, .version = 999, .linkage = &.{}, .type_origins = &.{}, .modules = &.{}, .gas_size = 0 };
    try c.map.put(c.gpa, two, fake);
    const refused0 = pkgs.epoch_moves_refused.load(.monotonic);
    const fresh = try S.cache(w, epochs[3]);
    try testing.expect(fresh != c);
    try testing.expectEqual(refused0 + 1, pkgs.epoch_moves_refused.load(.monotonic));
    try testing.expectEqual(@as(u64, 12), c.epoch);
    // The same for a miss it remembers for a system package the new epoch has: the miss
    // does not move with the cache.
    pkgs.releaseThreadCaches();
    const m = try S.cache(w, epochs[2]);
    try m.map.put(m.gpa, two, null);
    const with_miss = try S.cache(w, epochs[3]);
    try testing.expect(with_miss != m);
    try testing.expectEqual(refused0 + 2, pkgs.epoch_moves_refused.load(.monotonic));
    try testing.expect((try with_miss.get(&two)) != null);
    pkgs.releaseThreadCaches();
    const mo = try S.cache(w, epochs[2]);
    try mo.objs.put(mo.gpa, two, null);
    try testing.expect(try S.cache(w, epochs[3]) != mo);
    try testing.expectEqual(refused0 + 3, pkgs.epoch_moves_refused.load(.monotonic));
    // A cache made while the switch was off has no key and stays with its epoch.
    pkgs.releaseThreadCaches();
    pkgs.keep_across_epochs = false;
    const plain = try S.cache(w, epochs[0]);
    pkgs.keep_across_epochs = true;
    try testing.expect(try S.cache(w, epochs[1]) != plain);
}

test "package cache exactness over a live source: packages that appear after transactions missed them" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try buildWith(a, .{ .live = true });
    try testing.expect(w.store.lookup != null);
    const n = w.txs.items.len;
    // Epoch 10 without the user packages, epoch 10 again once the source has them (a package
    // published elsewhere, a node catching up), then the next epoch.
    const visits = [_]EpochInfo{
        .{ .epoch = 10, .pv = 139, .show = false },
        .{ .epoch = 10, .pv = 139, .show = true },
        .{ .epoch = 11, .pv = 139, .show = true },
    };
    defer pkgs.shared.clear();

    // The old path with a cold cache per visit: what the source holds at each visit.
    const cold = try runAllVisits(gpa, a, w, Mode.old_cold, &visits, true);
    for ([_][]const u8{ "user math mul", "user v1 then v2", "type_name of a user type", "upgrade the user package" }) |name| {
        const i = w.txIndex(name);
        try testing.expect(std.mem.startsWith(u8, cold[i], "unsupported "));
        try testing.expect(std.mem.startsWith(u8, cold[n + i], "done "));
        try testing.expect(std.mem.startsWith(u8, cold[2 * n + i], "done "));
    }
    try testing.expect((try statusOf(a, cold[n + w.txIndex("upgrade the user package")])).? == .Success);

    // The old path warm: a thread's cache keeps an input-object miss until its epoch's cache
    // goes, so the second visit of epoch 10 still answers as the first did, and epoch 11
    // (a new cache) finds the packages.
    const stale = try a.alloc([]const u8, 3 * n);
    @memcpy(stale[0..n], cold[0..n]);
    @memcpy(stale[n .. 2 * n], cold[0..n]);
    @memcpy(stale[2 * n ..], cold[2 * n ..]);
    try expectSameVisits(w, &visits, stale, try runAllVisits(gpa, a, w, Mode.old, &visits, false), "old path, warm");

    for (new_modes) |mode| {
        var name: [64]u8 = undefined;
        // Without keep_across_epochs the shared table changes nothing: the old path's
        // results on the same inputs, its kept miss included. With it a cache outlives its
        // epoch and so asks a live source again after a miss: every visit gets what the old
        // path gets from a cold cache, and no miss it remembers is stale.
        const fresh = mode.cold or mode.keep;
        const have = try runAllVisits(gpa, a, w, mode, &visits, fresh);
        try expectSameVisits(w, &visits, if (fresh) cold else stale, have, modeName(&name, mode));
    }
}

test "package cache exactness: a system package that first exists at an epoch change" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // deepbook (0xdee9) is in the store from epoch 13 on; 12 and 13 share a protocol version.
    const w = try buildWith(a, .{ .dee9_from = 13 });
    const n = w.txs.items.len;
    const order = [_]usize{ 2, 3, 2, 3, 4, 1, 2, 3, 3, 2 };
    defer pkgs.shared.clear();
    const want = try runAll(gpa, a, w, Mode.old_cold, &order);
    const tx = w.txIndex("deepbook math mul");
    try testing.expect(std.mem.startsWith(u8, want[tx], "unsupported ")); // epoch 12
    try testing.expect(std.mem.startsWith(u8, want[n + tx], "done ")); // epoch 13
    try testing.expectEqualSlices(u8, want[tx], want[2 * n + tx]); // back in 12: still missing
    try testing.expectEqualSlices(u8, want[n + tx], want[3 * n + tx]);
    // Its absence is part of the cross-epoch key, so no cache that remembers the miss of
    // epoch 12 serves epoch 13.
    try testing.expectEqual(epochs[2].pv, epochs[3].pv);
    const dee9: usize = 4;
    try testing.expectEqualSlices(u8, &sysId(0xdee9), &pkgs.system_ids[dee9]);
    try testing.expectEqual(@as(?u64, null), pkgs.systemVersions(&w.store, 12).?[dee9]);
    try testing.expectEqual(@as(?u64, 39), pkgs.systemVersions(&w.store, 13).?[dee9]);

    try expectSame(w, &order, want, try runAll(gpa, a, w, Mode.old, &order), "old path, warm");
    for (new_modes) |mode| {
        var name: [64]u8 = undefined;
        try expectSame(w, &order, want, try runAll(gpa, a, w, mode, &order), modeName(&name, mode));
    }
}

test "package cache exactness across chains: a format 7 package at protocol 53 and 54, which testnet reads and mainnet refuses" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const w = try buildOld(a);
    const n = w.txs.items.len;
    // The chains differ in the binary format they read at 53 and 54, on one store.
    for ([_]u64{ 53, 54 }) |pv| {
        try testing.expectEqual(@as(u64, 6), try (try protocol.get(pv, .mainnet)).get("move_binary_format_version"));
        try testing.expectEqual(@as(u64, 7), try (try protocol.get(pv, .testnet)).get("move_binary_format_version"));
    }
    const visits = [_]EpochInfo{
        .{ .epoch = 20, .pv = 53, .chain = .mainnet },
        .{ .epoch = 20, .pv = 53, .chain = .testnet },
        .{ .epoch = 21, .pv = 53, .chain = .testnet },
        .{ .epoch = 21, .pv = 53, .chain = .mainnet },
        .{ .epoch = 22, .pv = 54, .chain = .testnet },
        .{ .epoch = 22, .pv = 54, .chain = .mainnet },
        .{ .epoch = 20, .pv = 53, .chain = .testnet },
        .{ .epoch = 20, .pv = 53, .chain = .mainnet },
    };
    try emptyTable();
    defer pkgs.shared.clear();
    const want = try runAllVisits(gpa, a, w, Mode.old_cold, &visits, true);
    // The reference means something: the framework calls run on both chains, and the format 7
    // package runs on testnet and is no package mainnet can load.
    for (visits, 0..) |e, v| {
        const at = want[v * n ..][0..n];
        try testing.expect((try statusOf(a, at[w.txIndex("coin zero + destroy_zero")])).? == .Success);
        try testing.expect((try statusOf(a, at[w.txIndex("split + transfer")])).? == .Success);
        for ([_][]const u8{ "format 7 math mul", "format 7 create_account + transfer" }) |name| {
            const r = at[w.txIndex(name)];
            const st = try statusOf(a, r);
            if (e.chain == .testnet) {
                try testing.expect(st != null and st.? == .Success);
            } else try testing.expect(st == null or st.? != .Success);
        }
    }

    try expectSameVisits(w, &visits, want, try runAllVisits(gpa, a, w, Mode.old, &visits, true), "old path, warm");
    for (new_modes) |mode| {
        var name: [64]u8 = undefined;
        // each mode from an empty table, so the entry is made by whichever chain comes first
        try emptyTable();
        try expectSameVisits(w, &visits, want, try runAllVisits(gpa, a, w, mode, &visits, true), modeName(&name, mode));
    }
    // And with testnet first.
    var rev: [visits.len]EpochInfo = undefined;
    for (&rev, 0..) |*r, i| r.* = visits[i ^ 1];
    const want_rev = try runAllVisits(gpa, a, w, Mode.old_cold, &rev, true);
    for (0..visits.len) |v| for (0..n) |i| try testing.expectEqualSlices(u8, want[(v ^ 1) * n + i], want_rev[v * n + i]);
    for (new_modes) |mode| {
        var name: [64]u8 = undefined;
        try emptyTable();
        try expectSameVisits(w, &rev, want_rev, try runAllVisits(gpa, a, w, mode, &rev, true), modeName(&name, mode));
    }

    // One entry holds the package for both chains: parsed once, its modules kept per binary
    // config, deserialized under testnet's and refused under mainnet's.
    try emptyTable();
    const c0 = Counters.now();
    _ = try runAllVisits(gpa, a, w, .{ .shared = true, .keep = true }, &visits, true);
    const raw = w.store.get(&user_f7, 20).?;
    const e = (try pkgs.shared.acquire(raw)).?;
    defer pkgs.shared.release(e);
    var configs: usize = 0;
    var read: usize = 0;
    var d = e.decoded;
    while (d) |x| : (d = x.next) {
        configs += 1;
        if (x.pre != null) read += 1;
    }
    try testing.expect(configs >= 2);
    try testing.expect(read >= 1);
    try testing.expect(read < configs);
    // parsed once for the process whatever the chain: the system packages and this one
    try testing.expectEqual(pkgs.shared.entries.load(.monotonic), Counters.now().cold - c0.cold);
}
