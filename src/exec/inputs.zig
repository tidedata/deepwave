//! Transaction inputs as execution sees them (sui-types `InputObjects`): the objects a
//! programmable transaction names (owned, shared at their assigned versions, gas coins, the
//! packages its commands use) and its receiving refs. From them exec derives the two
//! effects fields that do not depend on Move execution:
//!   - `lamport_version`: one more than the largest Move-object input version (shared objects at
//!     their assigned version, stream-ended consensus versions, every receiving ref);
//!   - `dependencies`: the previous transaction of every input object (packages included), plus
//!     each receiving object actually received, minus the genesis marker, sorted.
//! `check` runs both against the certified effects of every effects-v2 programmable transaction
//! (a diagnostic inside exec-replay): shared versions and received objects are read from the
//! certified effects and the checkpoint's input objects, which is where consensus put them.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const objects = @import("objects.zig");
const packages = @import("packages.zig");

const Allocator = std.mem.Allocator;

pub const Missing = enum { owned, shared, receiving, gas, system_package, package };
pub const Result = union(enum) { ok, not_applicable, missing_input: Missing, mismatch: []const u8 };

const zero: [32]u8 = @splat(0);

/// sui-types `ParsedDigest::is_coin_reservation_digest`: an ImmOrOwned or gas ref whose digest
/// ends in 20 bytes of 0xac reserves address-balance funds; it names no object
/// (`CallArg::input_objects` and `TransactionData::input_objects` drop it).
pub fn isCoinReservation(digest: *const [32]u8) bool {
    for (digest[12..32]) |b| if (b != 0xac) return false;
    return true;
}

/// The input checks Rust runs before a transaction can be signed that depend on the transaction
/// alone, so a certified transaction never fails them (`ProgrammableTransaction::input_objects`,
/// which execution also calls, and sui-transaction-checks `check_objects`). Executors call this
/// first: a hit means the transaction is not one a validator certified, and execution must not
/// produce effects for it.
///
/// Receiving refs are not checked. `check_receiving_objects` rejects one that names an input
/// object or another receiving ref only when the object is still at that version at signing
/// time: a ref to an object that was already received skips the check, so a certified
/// transaction can carry `Receiving(X, v)` next to `ImmOrOwned(X, w)` or twice.
pub const SigningError = error{
    /// Two object arguments name the same id (owned, immutable or shared).
    DuplicateObjectRefInput,
    /// A gas coin appears twice in the payment, or is also an object argument: the gas coins
    /// join the input objects (`TransactionData::input_objects`) and every mutable input must
    /// be unique.
    MutableObjectUsedMoreThanOnce,
};

/// `signingCheck` on a programmable transaction. System kinds have no user inputs and pass.
pub fn signingCheck(arena: Allocator, data: *const types.TransactionDataV1) (SigningError || Allocator.Error)!void {
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return,
    };
    var seen: std.AutoHashMapUnmanaged([32]u8, void) = .empty;
    // ProgrammableTransaction::input_objects: every object argument, coin reservations and
    // receiving refs excluded.
    for (pt.inputs) |*arg| switch (arg.*) {
        .Object => |*oa| {
            const id: [32]u8 = switch (oa.*) {
                .ImmOrOwnedObject => |r| if (isCoinReservation(&r[2].@"0".@"0")) continue else r[0].@"0".@"0",
                .SharedObject => |s| s.id.@"0".@"0",
                .Receiving => continue,
            };
            if ((try seen.getOrPut(arena, id)).found_existing) return error.DuplicateObjectRefInput;
        },
        else => {},
    };
    // TransactionData::input_objects appends the gas coins (reservations excluded); check_objects
    // then rejects a mutable object that appears twice.
    for (data.gas_data.payment) |r| {
        if (isCoinReservation(&r[2].@"0".@"0")) continue;
        if ((try seen.getOrPut(arena, r[0].@"0".@"0")).found_existing) return error.MutableObjectUsedMoreThanOnce;
    }
}

/// A shared input's consensus-assigned version (`SharedInput` in Rust): an existing object at
/// `version`, a cancelled transaction's marker version, or a consensus stream that ended
/// (the object was deleted or left consensus) at `version`.
pub const Assigned = struct {
    id: [32]u8,
    version: u64,
    kind: enum { object, cancelled, stream_ended } = .object,
};

pub fn findAssigned(list: []const Assigned, id: *const [32]u8) ?Assigned {
    for (list) |a| if (std.mem.eql(u8, &a.id, id)) return a;
    return null;
}

/// The consensus-assigned versions of a programmable transaction's shared inputs, read back
/// from its certified effects (replay; a node has them from consensus). Empty, without
/// decoding the effects, when the transaction has no shared input. A shared input the effects
/// do not mention is left out (the executor then reports it unassigned).
pub fn assignedFromEffects(arena: Allocator, data: *const types.TransactionDataV1, effects_raw: []const u8) ![]const Assigned {
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return &.{},
    };
    var any = false;
    for (pt.inputs) |*arg| switch (arg.*) {
        .Object => |*oa| if (oa.* == .SharedObject) {
            any = true;
        },
        else => {},
    };
    if (!any) return &.{};
    const fx = try @import("bcs").decode(types.TransactionEffects, arena, effects_raw);
    var out: std.ArrayList(Assigned) = .empty;
    for (pt.inputs) |*arg| switch (arg.*) {
        .Object => |*oa| switch (oa.*) {
            .SharedObject => |s| {
                const id = s.id.@"0".@"0";
                switch (fx) {
                    .V2 => |*v| if (sharedVersion(v, &id)) |sv| try out.append(arena, .{
                        .id = id,
                        .version = sv.version,
                        .kind = if (sv.cancelled) .cancelled else if (sv.stream_ended) .stream_ended else .object,
                    }),
                    .V1 => |*v| for (v.shared_objects) |r| if (std.mem.eql(u8, &r[0].@"0".@"0", &id)) {
                        try out.append(arena, .{ .id = id, .version = r[1].@"0" });
                        break;
                    },
                }
            },
            else => {},
        },
        else => {},
    };
    return out.items;
}

fn findInput(views: []const objects.ObjectView, id: *const [32]u8, version: ?u64) ?*const objects.ObjectView {
    var best: ?*const objects.ObjectView = null;
    for (views) |*v| if (std.mem.eql(u8, &v.id, id)) {
        if (version) |ver| {
            if (v.version == ver) return v;
        } else if (best == null or v.version > best.?.version) best = v;
    };
    return best;
}

/// The version consensus assigned to a shared input, from the certified effects: the input
/// state of a mutated shared object, or the version of a read-only / stream-ended / cancelled one.
fn sharedVersion(fx: *const types.TransactionEffectsV2, id: *const [32]u8) ?struct { version: u64, cancelled: bool, stream_ended: bool } {
    for (fx.changed_objects) |*c| if (std.mem.eql(u8, &c[0].@"0".@"0", id)) switch (c[1].input_state) {
        .Exist => |e| return .{ .version = e[0][0].@"0", .cancelled = false, .stream_ended = false },
        .NotExist => {},
    };
    for (fx.unchanged_consensus_objects) |*u| if (std.mem.eql(u8, &u[0].@"0".@"0", id)) switch (u[1]) {
        .ReadOnlyRoot => |r| return .{ .version = r[0].@"0", .cancelled = false, .stream_ended = false },
        .MutateConsensusStreamEnded, .ReadConsensusStreamEnded => |v| return .{ .version = v.@"0", .cancelled = false, .stream_ended = true },
        .Cancelled => |v| return .{ .version = v.@"0", .cancelled = true, .stream_ended = false },
        .PerEpochConfig => return null,
    };
    return null;
}

fn typeInputPackages(arena: Allocator, out: *std.ArrayList([32]u8), t: *const types.TypeInput) !void {
    switch (t.*) {
        .vector => |e| try typeInputPackages(arena, out, e),
        .@"struct" => |*st| {
            try out.append(arena, st.address.@"0");
            for (st.type_args) |*a| try typeInputPackages(arena, out, a);
        },
        else => {},
    }
}

pub fn check(
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    blob: []const u8,
    idx: *const types.CheckpointIndex,
    tx: *const types.index.Tx,
    data: *const types.TransactionDataV1,
    fx: *const types.TransactionEffects,
    pkgs: ?*const packages.Store,
    epoch: u64,
    table: ?*const objects.ObjectTable,
    db: ?*const objects.ObjectDb,
) !Result {
    const v = switch (fx.*) {
        .V2 => |*v| v,
        .V1 => return .not_applicable,
    };
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return .not_applicable,
    };
    const ins = idx.objs[tx.in_first..][0..tx.in_count];
    const views = try arena.alloc(objects.ObjectView, ins.len);
    for (ins, views) |r, *iv| iv.* = try objects.ObjectView.parse(r.slice(blob));
    const Find = struct {
        views: []const objects.ObjectView,
        table: ?*const objects.ObjectTable,
        db: ?*const objects.ObjectDb,
        arena: Allocator,
        /// The transaction's input objects, then every object its checkpoint carries (a
        /// read-only shared input may be another transaction's output, e.g. the Clock written
        /// by the checkpoint's prologue), then the corpus read-only objects (exact versions).
        fn at(f: @This(), id: *const [32]u8, version: u64) !?*const objects.ObjectView {
            if (findInput(f.views, id, version)) |o| return o;
            const k: objects.Key = .{ .id = id.*, .version = version };
            const raw = (if (f.table) |t| t.get(k) else null) orelse (if (f.db) |d| d.get(k) else null) orelse return null;
            const o = try f.arena.create(objects.ObjectView);
            o.* = try objects.ObjectView.parse(raw);
            return o;
        }
    };
    const find: Find = .{ .views = views, .table = table, .db = db, .arena = arena };

    // `disable_effects_tx_dependencies`: effects carry no dependencies at all.
    const no_deps = cfg.feature_flags.disable_effects_tx_dependencies;
    var max_version: u64 = 0;
    var deps: std.ArrayList([32]u8) = .empty;

    const Add = struct {
        fn obj(d: *std.ArrayList([32]u8), a: Allocator, o: *const objects.ObjectView, max: *u64) !void {
            if (!o.is_package) max.* = @max(max.*, o.version);
            try d.append(a, o.raw[o.prev_tx_at + 1 ..][0..32].*);
        }
    };

    for (pt.inputs) |*arg| switch (arg.*) {
        .Pure, .FundsWithdrawal => {},
        .Object => |*oa| switch (oa.*) {
            .ImmOrOwnedObject => |r| {
                if (isCoinReservation(&r[2].@"0".@"0")) continue;
                const o = try find.at(&r[0].@"0".@"0", r[1].@"0") orelse return .{ .missing_input = .owned };
                try Add.obj(&deps, arena, o, &max_version);
            },
            .SharedObject => |s| {
                const sv = sharedVersion(v, &s.id.@"0".@"0") orelse {
                    // Read at the per-epoch config version or not reported: take the object as read.
                    const o = findInput(views, &s.id.@"0".@"0", null) orelse return .{ .missing_input = .shared };
                    try Add.obj(&deps, arena, o, &max_version);
                    continue;
                };
                if (sv.cancelled) continue;
                if (sv.stream_ended) {
                    max_version = @max(max_version, sv.version);
                    continue;
                }
                const o = try find.at(&s.id.@"0".@"0", sv.version) orelse return .{ .missing_input = .shared };
                try Add.obj(&deps, arena, o, &max_version);
            },
            .Receiving => |r| {
                max_version = @max(max_version, r[1].@"0");
                // Received: the object was loaded at the ref's version and changed by the tx.
                for (v.changed_objects) |*c| if (std.mem.eql(u8, &c[0].@"0".@"0", &r[0].@"0".@"0")) switch (c[1].input_state) {
                    .Exist => |e| if (e[0][0].@"0" == r[1].@"0") {
                        const o = try find.at(&r[0].@"0".@"0", r[1].@"0") orelse return .{ .missing_input = .receiving };
                        try deps.append(arena, o.raw[o.prev_tx_at + 1 ..][0..32].*);
                    },
                    .NotExist => {},
                };
            },
        },
    };
    for (data.gas_data.payment) |r| {
        if (isCoinReservation(&r[2].@"0".@"0")) continue;
        const o = try find.at(&r[0].@"0".@"0", r[1].@"0") orelse return .{ .missing_input = .gas };
        try Add.obj(&deps, arena, o, &max_version);
    }
    // Packages named by commands (sui-types `Command::input_objects`): the MoveCall package
    // and every package in its type arguments, the MakeMoveVec type's packages,
    // Publish/Upgrade dependencies and the upgraded package. Packages never enter the lamport
    // version; they only matter as dependencies. A checkpoint does not carry them: they come
    // from the corpus `packages/` part (packages.zig).
    if (!no_deps) {
        var pkg_ids: std.ArrayList([32]u8) = .empty;
        for (pt.commands) |*cmd| switch (cmd.*) {
            .MoveCall => |*mc| {
                try pkg_ids.append(arena, mc.package.@"0".@"0");
                for (mc.type_arguments) |*ta| try typeInputPackages(arena, &pkg_ids, ta);
            },
            .MakeMoveVec => |*mv| if (mv[0]) |*ta| try typeInputPackages(arena, &pkg_ids, ta),
            .Publish => |*p| for (p[1]) |d| try pkg_ids.append(arena, d.@"0".@"0"),
            .Upgrade => |*u| {
                for (u[1]) |d| try pkg_ids.append(arena, d.@"0".@"0");
                try pkg_ids.append(arena, u[2].@"0".@"0");
            },
            else => {},
        };
        for (pkg_ids.items) |*pid| {
            const raw = if (findInput(views, pid, null)) |o| o.raw else if (pkgs) |ps| ps.get(pid, epoch) orelse return .{ .missing_input = if (packages.isSystemPackage(pid)) .system_package else .package } else return .{ .missing_input = .package };
            const o = try objects.ObjectView.parse(raw);
            try deps.append(arena, o.raw[o.prev_tx_at + 1 ..][0..32].*);
        }
    }

    if (no_deps) deps.clearRetainingCapacity();
    // Sorted set minus the genesis marker.
    std.mem.sort([32]u8, deps.items, {}, struct {
        fn lt(_: void, a: [32]u8, b: [32]u8) bool {
            return std.mem.order(u8, &a, &b) == .lt;
        }
    }.lt);
    var out: std.ArrayList([32]u8) = .empty;
    for (deps.items) |d| {
        if (std.mem.eql(u8, &d, &zero)) continue;
        if (out.items.len > 0 and std.mem.eql(u8, &out.items[out.items.len - 1], &d)) continue;
        try out.append(arena, d);
    }

    const lamport = max_version + 1;
    if (lamport != v.lamport_version.@"0")
        return .{ .mismatch = try std.fmt.allocPrint(arena, "lamport {d}, exec {d}", .{ v.lamport_version.@"0", lamport }) };
    if (out.items.len != v.dependencies.len)
        return .{ .mismatch = try std.fmt.allocPrint(arena, "{d} dependencies, exec {d}", .{ v.dependencies.len, out.items.len }) };
    for (out.items, v.dependencies) |a, b| if (!std.mem.eql(u8, &a, &b.@"0".@"0"))
        return .{ .mismatch = try std.fmt.allocPrint(arena, "dependency {x}, exec {x}", .{ &b.@"0".@"0", &a }) };
    return .ok;
}

// ---- tests: signing checks, and coin PTBs with shared and receiving inputs (synthetic: the
// corpus has no duplicate or gas-as-argument transaction, since validators reject them).

const testing = std.testing;
const PayRef = @typeInfo(@FieldType(types.GasData, "payment")).pointer.child;
const ChangeT = @typeInfo(@FieldType(types.TransactionEffectsV2, "changed_objects")).pointer.child;
const UnchangedT = @typeInfo(@FieldType(types.TransactionEffectsV2, "unchanged_consensus_objects")).pointer.child;
const bcs_t = @import("bcs");

fn tId(n: u8) [32]u8 {
    var x: [32]u8 = @splat(0);
    x[0] = 0x5a;
    x[31] = n;
    return x;
}

fn tRef(n: u8, version: u64) PayRef {
    return .{ .{ .@"0" = .{ .@"0" = tId(n) } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = @splat(n) } } };
}

fn tData(inputs_: []const types.CallArg, commands: []const types.Command, payment: []const PayRef) types.TransactionDataV1 {
    return .{
        .kind = .{ .ProgrammableTransaction = .{ .inputs = inputs_, .commands = commands } },
        .sender = .{ .@"0" = @splat(0xab) },
        .gas_data = .{ .payment = payment, .owner = .{ .@"0" = @splat(0xab) }, .price = 1000, .budget = 5_000_000 },
        .expiration = .None,
    };
}

fn tShared(n: u8, initial: u64, m: types.SharedObjectMutability) types.CallArg {
    return .{ .Object = .{ .SharedObject = .{ .id = .{ .@"0" = .{ .@"0" = tId(n) } }, .initial_shared_version = .{ .@"0" = initial }, .mutability = m } } };
}

test "signing checks: duplicate inputs and gas coins as arguments are rejected" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const owned1: types.CallArg = .{ .Object = .{ .ImmOrOwnedObject = tRef(1, 5) } };
    const recv1: types.CallArg = .{ .Object = .{ .Receiving = tRef(1, 5) } };
    const recv3: types.CallArg = .{ .Object = .{ .Receiving = tRef(3, 5) } };
    const pure: types.CallArg = .{ .Pure = &.{ 1, 2 } };
    const gas = [_]PayRef{tRef(9, 7)};
    const gas2 = [_]PayRef{ tRef(9, 7), tRef(9, 7) };
    // A valid one: an owned input, a shared input, a receiving ref and a gas coin, all distinct.
    try signingCheck(a, &tData(&.{ owned1, tShared(2, 1, .Mutable), recv3, pure }, &.{}, &gas));
    // The same owned object twice, or owned and shared with one id.
    try testing.expectError(error.DuplicateObjectRefInput, signingCheck(a, &tData(&.{ owned1, owned1 }, &.{}, &gas)));
    try testing.expectError(error.DuplicateObjectRefInput, signingCheck(a, &tData(&.{ owned1, tShared(1, 1, .Immutable) }, &.{}, &gas)));
    // The same shared object twice, even with different mutability.
    try testing.expectError(error.DuplicateObjectRefInput, signingCheck(a, &tData(&.{ tShared(2, 1, .Mutable), tShared(2, 1, .Immutable) }, &.{}, &gas)));
    // A receiving ref naming an input object, another receiving ref or the gas coin passes:
    // whether signing rejects it depends on whether the object was already received.
    try signingCheck(a, &tData(&.{ owned1, recv1 }, &.{}, &gas));
    try signingCheck(a, &tData(&.{ recv3, recv3 }, &.{}, &gas));
    // The gas coin also passed as an argument, or listed twice in the payment.
    const gas_arg: types.CallArg = .{ .Object = .{ .ImmOrOwnedObject = tRef(9, 7) } };
    try testing.expectError(error.MutableObjectUsedMoreThanOnce, signingCheck(a, &tData(&.{gas_arg}, &.{}, &gas)));
    try testing.expectError(error.MutableObjectUsedMoreThanOnce, signingCheck(a, &tData(&.{}, &.{}, &gas2)));
    const recv9: types.CallArg = .{ .Object = .{ .Receiving = tRef(9, 7) } };
    try signingCheck(a, &tData(&.{recv9}, &.{}, &gas));
    // Coin reservations name no object: two of them never collide.
    var res = tRef(4, 0);
    @memset(res[2].@"0".@"0"[12..], 0xac);
    const res_arg: types.CallArg = .{ .Object = .{ .ImmOrOwnedObject = res } };
    try signingCheck(a, &tData(&.{ res_arg, res_arg }, &.{}, &gas));
}

/// Object bytes: a Move object of `type_` with `contents` (id first), owner bytes as given.
fn tObject(a: Allocator, mot: types.MoveObjectType, public: bool, version: u64, contents: []const u8, owner: types.Owner, rebate: u64) ![]const u8 {
    const o: types.Object = .{
        .data = .{ .Move = .{ .type_ = mot, .has_public_transfer = public, .version = .{ .@"0" = version }, .contents = contents } },
        .owner = owner,
        .previous_transaction = .{ .@"0" = .{ .@"0" = @splat(0x33) } },
        .storage_rebate = rebate,
    };
    return bcs_t.encodeAlloc(types.Object, a, &o);
}

const TLookup = struct {
    objs: []const []const u8,
    fn get(ctx: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8 {
        const l: *const TLookup = @ptrCast(@alignCast(ctx));
        for (l.objs) |raw| {
            const v = objects.ObjectView.parse(raw) catch continue;
            if (std.mem.eql(u8, &v.id, id) and v.version == version) return raw;
        }
        return null;
    }
};

test "coin PTB: shared inputs at their assigned versions and an unused receiving ref" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const coin_ptb = @import("coin_ptb.zig");
    const sender: [32]u8 = @splat(0xab);
    const other_t: types.MoveObjectType = .{ .@"0" = .{ .Other = .{ .address = .{ .@"0" = tId(0x20) }, .module = .{ .@"0" = "m" }, .name = .{ .@"0" = "S" }, .type_args = &.{} } } };
    // gas coin 9 at version 7 (1 SUI); shared 2 (mutable, assigned 40), shared 3 (read-only,
    // assigned 55); receiving ref 4 at version 60, which sets the lamport version.
    const gas_contents = tId(9) ++ [_]u8{ 0x00, 0xca, 0x9a, 0x3b, 0, 0, 0, 0 };
    const gas_raw = try tObject(a, .{ .@"0" = .GasCoin }, true, 7, &gas_contents, .{ .AddressOwner = .{ .@"0" = sender } }, 988_000);
    const s2 = try tObject(a, other_t, false, 40, &(tId(2) ++ [_]u8{ 1, 2, 3 }), .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 11 } } }, 1_500_000);
    const s3 = try tObject(a, other_t, false, 55, &(tId(3) ++ [_]u8{4}), .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 12 } } }, 1_400_000);
    const lookup: TLookup = .{ .objs = &.{ gas_raw, s2, s3 } };
    const assigned = [_]Assigned{ .{ .id = tId(2), .version = 40 }, .{ .id = tId(3), .version = 55 } };
    const ins = [_]types.CallArg{ tShared(2, 11, .Mutable), tShared(3, 12, .Immutable), .{ .Object = .{ .Receiving = tRef(4, 60) } } };
    const gas = [_]PayRef{tRef(9, 7)};
    var data = tData(&ins, &.{}, &gas);
    const raw_td = try bcs_t.encodeAlloc(types.TransactionData, a, &.{ .V1 = data });

    // Execution version 3 (dynamic executor, effects V2) and the latest protocol (static).
    for ([_]u64{ 107, protocol.max_protocol_version }) |pv| {
        const cfg = try protocol.get(pv, .mainnet);
        const out = switch (try coin_ptb.execute(a, cfg, 9, 1000, raw_td, &data, .{ .ctx = &lookup, .get = TLookup.get, .assigned = &assigned })) {
            .done => |o| o,
            .unsupported => |why| {
                std.debug.print("unsupported at protocol {d}: {s}\n", .{ pv, why });
                return error.TestUnexpectedResult;
            },
        };
        const fx = (try bcs_t.decode(types.TransactionEffects, a, out.effects)).V2;
        try testing.expect(fx.status == .Success);
        try testing.expectEqual(@as(u64, 61), fx.lamport_version.@"0");
        // gas coin and the mutable shared object change; the read-only one is a root.
        try testing.expectEqual(@as(usize, 2), fx.changed_objects.len);
        var saw_shared = false;
        for (fx.changed_objects) |c| if (std.mem.eql(u8, &c[0].@"0".@"0", &tId(2))) {
            saw_shared = true;
            try testing.expectEqual(@as(u64, 40), c[1].input_state.Exist[0][0].@"0");
            try testing.expect(c[1].input_state.Exist[1] == .Shared);
            try testing.expect(c[1].output_state.ObjectWrite[1] == .Shared);
            try testing.expect(c[1].id_operation == .None);
        };
        try testing.expect(saw_shared);
        try testing.expectEqual(@as(usize, 1), fx.unchanged_consensus_objects.len);
        try testing.expectEqualSlices(u8, &tId(3), &fx.unchanged_consensus_objects[0][0].@"0".@"0");
        try testing.expectEqual(@as(u64, 55), fx.unchanged_consensus_objects[0][1].ReadOnlyRoot[0].@"0");
        // dependencies: the gas coin's and both shared inputs' previous transaction (one
        // digest here); the unreceived ref adds none.
        try testing.expectEqual(@as(usize, if (cfg.feature_flags.disable_effects_tx_dependencies) 0 else 1), fx.dependencies.len);
        // the shared object is written back unchanged at the lamport version, owner kept
        for (out.written) |w| if (std.mem.eql(u8, &w.id, &tId(2))) {
            const o = try bcs_t.decode(types.Object, a, w.bytes);
            try testing.expectEqual(@as(u64, 61), o.data.Move.version.@"0");
            try testing.expectEqualSlices(u8, s2[0..2], w.bytes[0..2]);
            try testing.expectEqualSlices(u8, (try bcs_t.decode(types.Object, a, s2)).data.Move.contents, o.data.Move.contents);
            try testing.expectEqual(@as(u64, 11), o.owner.Shared.initial_shared_version.@"0");
        };
        try testing.expectEqual(@as(usize, 2), out.written.len);
    }

    // Without an assigned version the input is unsupported, never guessed.
    const cfg = try protocol.get(107, .mainnet);
    try testing.expect(try coin_ptb.execute(a, cfg, 9, 1000, raw_td, &data, .{ .ctx = &lookup, .get = TLookup.get }) == .unsupported);
    // A command naming the shared input is outside the coin slice.
    const cmds = [_]types.Command{.{ .TransferObjects = .{ &.{.{ .Input = 0 }}, .{ .Input = 1 } } }};
    var data2 = tData(&ins, &cmds, &gas);
    try testing.expect(try coin_ptb.execute(a, cfg, 9, 1000, raw_td, &data2, .{ .ctx = &lookup, .get = TLookup.get, .assigned = &assigned }) == .unsupported);
    // A transaction a validator would reject at signing is an error.
    const dup = [_]types.CallArg{ tShared(2, 11, .Mutable), tShared(2, 11, .Immutable) };
    var data3 = tData(&dup, &.{}, &gas);
    try testing.expectError(error.DuplicateObjectRefInput, coin_ptb.execute(a, cfg, 9, 1000, raw_td, &data3, .{ .ctx = &lookup, .get = TLookup.get, .assigned = &assigned }));
    // A receiving ref may name an input object (here the gas coin) when that version was
    // already received at signing: it only enters the lamport version.
    const recv_gas = [_]types.CallArg{ tShared(2, 11, .Mutable), .{ .Object = .{ .Receiving = tRef(9, 90) } } };
    var data5 = tData(&recv_gas, &.{}, &gas);
    const out5 = switch (try coin_ptb.execute(a, cfg, 9, 1000, raw_td, &data5, .{ .ctx = &lookup, .get = TLookup.get, .assigned = &assigned })) {
        .done => |o| o,
        .unsupported => return error.TestUnexpectedResult,
    };
    try testing.expectEqual(@as(u64, 91), (try bcs_t.decode(types.TransactionEffects, a, out5.effects)).V2.lamport_version.@"0");
    const gas_dup = [_]types.CallArg{.{ .Object = .{ .ImmOrOwnedObject = tRef(9, 7) } }};
    var data4 = tData(&gas_dup, &.{}, &gas);
    try testing.expectError(error.MutableObjectUsedMoreThanOnce, coin_ptb.execute(a, cfg, 9, 1000, raw_td, &data4, .{ .ctx = &lookup, .get = TLookup.get }));
}

test "assigned versions from certified effects V2 and V1" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ins = [_]types.CallArg{ tShared(2, 11, .Mutable), tShared(3, 12, .Immutable), tShared(5, 13, .Immutable) };
    const data = tData(&ins, &.{}, &.{});
    const d2: types.ObjectDigest = .{ .@"0" = .{ .@"0" = @splat(2) } };
    const changes = [_]ChangeT{.{ .{ .@"0" = .{ .@"0" = tId(2) } }, .{
        .input_state = .{ .Exist = .{ .{ .{ .@"0" = 40 }, d2 }, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 11 } } } } },
        .output_state = .{ .ObjectWrite = .{ d2, .{ .Shared = .{ .initial_shared_version = .{ .@"0" = 11 } } } } },
        .id_operation = .None,
    } }};
    const unchanged = [_]UnchangedT{
        .{ .{ .@"0" = .{ .@"0" = tId(3) } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = 55 }, d2 } } },
        .{ .{ .@"0" = .{ .@"0" = tId(5) } }, .{ .Cancelled = .{ .@"0" = 0xffff_ffff_ffff_fffd } } },
    };
    const zero_gas: types.GasCostSummary = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 };
    const fx2: types.TransactionEffects = .{ .V2 = .{
        .status = .Success, .executed_epoch = 1, .gas_used = zero_gas, .transaction_digest = .{ .@"0" = .{ .@"0" = @splat(1) } },
        .gas_object_index = null, .events_digest = null, .dependencies = &.{}, .lamport_version = .{ .@"0" = 56 },
        .changed_objects = &changes, .unchanged_consensus_objects = &unchanged, .aux_data_digest = null,
    } };
    const got = try assignedFromEffects(a, &data, try bcs_t.encodeAlloc(types.TransactionEffects, a, &fx2));
    try testing.expectEqual(@as(usize, 3), got.len);
    try testing.expectEqual(@as(u64, 40), got[0].version);
    try testing.expectEqual(@as(u64, 55), got[1].version);
    try testing.expect(got[1].kind == .object);
    try testing.expect(got[2].kind == .cancelled);
    // No shared input: nothing decoded.
    try testing.expectEqual(@as(usize, 0), (try assignedFromEffects(a, &tData(&.{}, &.{}, &.{}), "not effects")).len);
}
