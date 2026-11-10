//! The object runtime (`sui-move-natives` latest `object_runtime/{mod,object_store,fingerprint}.rs`,
//! mainnet-v1.83.1): new/deleted ids, transfers, events, accumulator events, the child object
//! store behind dynamic fields, receiving, config reads, object funds and the scratch pad.
//!
//! Semantics follow the Rust exactly, including limit checks, the order of every map the results
//! expose (IndexMap/IndexSet insertion order, BTreeMap id order) and which errors are VM errors.
//! Representation is ours: values are `types.layout.Value` (immutable slices, so a "copy" shares
//! them), a child object's value lives in an arena-allocated slot so a returned `&Child` stays
//! valid, and storage is reached through `Resolver` (exec supplies one over its object source).
const std = @import("std");
const types = @import("types");
const bcs = @import("bcs");
const protocol = @import("protocol");
const move_format = @import("move_format");

pub const Allocator = std.mem.Allocator;
pub const Value = types.layout.Value;
pub const Layout = types.layout.MoveTypeLayout;
pub const TypeTag = types.TypeTag;
pub const StructTag = types.StructTag;
pub const Identifier = types.Identifier;
pub const StatusCode = move_format.StatusCode;
pub const ProtocolConfig = protocol.ProtocolConfig;
pub const Id = [32]u8;

pub const VmError = struct { status: StatusCode, sub: ?u64 = null };

/// `VMMemoryLimitExceededSubStatusCode`.
pub const Mem = struct {
    pub const EVENT_COUNT: u64 = 0;
    pub const EVENT_SIZE: u64 = 1;
    pub const NEW_ID_COUNT: u64 = 2;
    pub const DELETED_ID_COUNT: u64 = 3;
    pub const TRANSFER_ID_COUNT: u64 = 4;
    pub const CACHE: u64 = 5;
    pub const STORE: u64 = 6;
    pub const TOTAL_EVENT_SIZE: u64 = 7;
    pub const SCRATCH_SIZE: u64 = 8;
    pub const ACCUMULATOR_EVENT_COUNT: u64 = 9;
};

fn memErr(sub: u64) VmError {
    return .{ .status = .MEMORY_LIMIT_EXCEEDED, .sub = sub };
}
const invariant: VmError = .{ .status = .UNKNOWN_INVARIANT_VIOLATION_ERROR };

// ---- fully annotated layouts --------------------------------------------------------------
//
// `annotated_value::MoveTypeLayout` (same BCS shape, so the VM or a truth file hands it over as
// is). The object runtime uses it only to find the UIDs inside a value (`get_all_uids`).

pub const ALayout = union(enum) {
    bool: void,
    u8: void,
    u64: void,
    u128: void,
    address: void,
    vector: *const ALayout,
    @"struct": *const AStruct,
    signer: void,
    u16: void,
    u32: void,
    u256: void,
    @"enum": *const AEnum,
};
pub const AField = struct { name: Identifier, layout: ALayout };
pub const AStruct = struct { type_: StructTag, fields: []const AField };
pub const AVariant = struct { key: struct { name: Identifier, tag: u16 }, fields: []const AField };
pub const AEnum = struct { type_: StructTag, variants: []const AVariant };

fn isUid(s: *const StructTag) bool {
    var two: Id = @splat(0);
    two[31] = 2;
    return std.mem.eql(u8, &s.address.@"0", &two) and std.mem.eql(u8, s.module.@"0", "object") and
        std.mem.eql(u8, s.name.@"0", "UID") and s.type_args.len == 0;
}

/// `get_all_uids`: every address inside a `0x2::object::UID` in `v` (a BTreeSet: sorted, unique).
pub fn allUids(gpa: Allocator, v: *const Value, l: *const ALayout) Allocator.Error![]Id {
    var out: std.ArrayList(Id) = .empty;
    try collect(gpa, v, l, false, &out);
    std.mem.sort(Id, out.items, {}, idLess);
    var n: usize = 0;
    for (out.items) |x| {
        if (n > 0 and std.mem.eql(u8, &out.items[n - 1], &x)) continue;
        out.items[n] = x;
        n += 1;
    }
    return out.items[0..n];
}

fn collect(gpa: Allocator, v: *const Value, l: *const ALayout, in_uid: bool, out: *std.ArrayList(Id)) Allocator.Error!void {
    switch (l.*) {
        .address => if (in_uid) try out.append(gpa, v.address),
        .vector => |el| if (v.* == .vector) for (v.vector) |*e| try collect(gpa, e, el, in_uid, out),
        .@"struct" => |s| {
            const u = in_uid or isUid(&s.type_);
            for (v.@"struct", s.fields) |*f, *fl| try collect(gpa, f, &fl.layout, u, out);
        },
        .@"enum" => |e| {
            const va = v.variant;
            for (e.variants) |*vr| if (vr.key.tag == va.tag) {
                for (va.fields, vr.fields) |*f, *fl| try collect(gpa, f, &fl.layout, in_uid, out);
                break;
            };
        },
        else => {},
    }
}

pub fn idLess(_: void, a: Id, b: Id) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

// ---- small helpers --------------------------------------------------------------------------

pub fn tagEql(a: *const TypeTag, b: *const TypeTag) bool {
    if (std.meta.activeTag(a.*) != std.meta.activeTag(b.*)) return false;
    return switch (a.*) {
        .vector => |e| tagEql(e, b.vector),
        .@"struct" => |s| structEql(&s, &b.@"struct"),
        else => true,
    };
}

pub fn structEql(a: *const StructTag, b: *const StructTag) bool {
    if (!std.mem.eql(u8, &a.address.@"0", &b.address.@"0")) return false;
    if (!std.mem.eql(u8, a.module.@"0", b.module.@"0")) return false;
    if (!std.mem.eql(u8, a.name.@"0", b.name.@"0")) return false;
    if (a.type_args.len != b.type_args.len) return false;
    for (a.type_args, b.type_args) |*x, *y| if (!tagEql(x, y)) return false;
    return true;
}

/// `Value::equals` on two values of the same type (either `vector<u8>` form).
pub fn valueEql(a: *const Value, b: *const Value) bool {
    return a.eql(b);
}

/// `get_object_id`: Object { id: UID { id: ID { bytes } } .. }.
pub fn objectId(v: *const Value) Id {
    return v.@"struct"[0].@"struct"[0].@"struct"[0].address;
}

pub fn tagBcs(gpa: Allocator, t: *const TypeTag) Allocator.Error![]u8 {
    var cw: bcs.CountingWriter = .{};
    bcs.encode(TypeTag, t, &cw) catch unreachable;
    const buf = try gpa.alloc(u8, cw.n);
    var w = bcs.Writer.init(buf);
    bcs.encode(TypeTag, t, &w) catch unreachable;
    return buf;
}

// ---- owners ---------------------------------------------------------------------------------

pub const Owner = union(enum) {
    address: Id,
    object: Id,
    /// Shared { initial_shared_version }
    shared: u64,
    immutable: void,
    consensus: struct { start: u64, owner: Id },
    /// Party { .. }: the BCS of the whole owner (only input objects carry one).
    party: []const u8,

    pub fn fromTypes(gpa: Allocator, o: *const types.Owner) Allocator.Error!Owner {
        return switch (o.*) {
            .AddressOwner => |a| .{ .address = a.@"0" },
            .ObjectOwner => |a| .{ .object = a.@"0" },
            .Shared => |s| .{ .shared = s.initial_shared_version.@"0" },
            .Immutable => .immutable,
            .ConsensusAddressOwner => |c| .{ .consensus = .{ .start = c.start_version.@"0", .owner = c.owner.@"0" } },
            .Party => .{ .party = try bcs.encodeAlloc(types.Owner, gpa, o) },
        };
    }

    /// BCS of `sui_types::object::Owner`.
    pub fn encode(o: Owner, gpa: Allocator) Allocator.Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        switch (o) {
            .address => |a| {
                try out.append(gpa, 0);
                try out.appendSlice(gpa, &a);
            },
            .object => |a| {
                try out.append(gpa, 1);
                try out.appendSlice(gpa, &a);
            },
            .shared => |v| {
                try out.append(gpa, 2);
                try appendU64(gpa, &out, v);
            },
            .immutable => try out.append(gpa, 3),
            .consensus => |c| {
                try out.append(gpa, 4);
                try appendU64(gpa, &out, c.start);
                try out.appendSlice(gpa, &c.owner);
            },
            .party => |raw| try out.appendSlice(gpa, raw),
        }
        return out.items;
    }

    fn sameAs(new: Owner, old: Owner) bool {
        return switch (new) {
            .shared => old == .shared,
            .consensus => |c| old == .consensus and std.mem.eql(u8, &c.owner, &old.consensus.owner),
            // a Party owner is never produced by a native, so it never equals an old one
            .party => false,
            .address => |a| old == .address and std.mem.eql(u8, &a, &old.address),
            .object => |a| old == .object and std.mem.eql(u8, &a, &old.object),
            .immutable => old == .immutable,
        };
    }
};

fn appendU64(gpa: Allocator, out: *std.ArrayList(u8), v: u64) Allocator.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .little);
    try out.appendSlice(gpa, &b);
}

// ---- storage --------------------------------------------------------------------------------

/// An object as storage returns it.
pub const StoredObject = struct {
    id: Id,
    owner: Owner,
    version: u64,
    previous_transaction: Id = @splat(0),
    storage_rebate: u64 = 0,
    digest: Id = @splat(0),
    /// null for a package.
    move: ?struct { type_: *const TypeTag, contents: []const u8 },
};

pub const ResolveError = error{Storage};
/// `SequenceNumber::MAX` (sui-types base_types.rs).
pub const sequence_number_max: u64 = 0x7fff_ffff_ffff_ffff;
pub const PackageInfo = struct { original_id: Id, size: u64 };

/// `RuntimeObjectResolver` + `ImplicitSystemObjectResolver`: the storage the runtime reads.
pub const Resolver = struct {
    ctx: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        /// `read_child_object(parent, child, child_version_upper_bound)`
        read_child: *const fn (ctx: *anyopaque, parent: *const Id, child: *const Id, upper: u64) ResolveError!?*const StoredObject,
        /// `get_object_received_at_version(owner, child, version, epoch)`
        received_at: *const fn (ctx: *anyopaque, owner: *const Id, child: *const Id, version: u64, epoch: u64) ResolveError!?*const StoredObject,
        /// `get_package_at_version(id, version)`
        package_at: *const fn (ctx: *anyopaque, id: *const Id, version: u64) ?PackageInfo,
        /// `object_available_balance(owner, type)`
        available_balance: *const fn (ctx: *anyopaque, owner: *const Id, ty: *const TypeTag) ResolveError!u128,
        /// `ImplicitSystemObjectResolver::clock` (v142 `clock::borrow`): the Clock's Move contents
        /// at the version assigned to the transaction, recorded as a read-only consensus object.
        /// null (no resolver support, or the read failed): an invariant violation.
        clock: ?*const fn (ctx: *anyopaque) ResolveError!?[]const u8 = null,
    };
};

/// `MovePackage::original_package_id` and `object_size_for_gas_metering` over a package object
/// (helper for resolvers).
pub fn packageInfo(arena: Allocator, pkg: *const types.MovePackage) !PackageInfo {
    var size: u64 = 8;
    for (pkg.module_map.entries) |e| size += e.key.@"0".len + e.value.len;
    for (pkg.type_origin_table) |t| size += t.module_name.@"0".len + t.datatype_name.@"0".len + 32;
    size += pkg.linkage_table.entries.len * (32 + 32 + 8);
    if (pkg.version.@"0" == 1) return .{ .original_id = pkg.id.@"0".@"0", .size = size };
    const first = pkg.module_map.entries[0].value;
    const cfg: move_format.BinaryConfig = .{};
    const r = try move_format.deserialize(arena, first, &cfg);
    const m = switch (r) {
        .ok => |m| m,
        else => return error.BadModule,
    };
    return .{ .original_id = m.selfAddress().*, .size = size };
}

// ---- the runtime ----------------------------------------------------------------------------

pub const CacheInfo = union(enum) {
    cached_object,
    cached_value,
    /// loaded from storage: BCS length of the contents, null if not found
    loaded: ?u64,
};

pub const Fingerprint = union(enum) {
    empty,
    preexisting: struct { owner: Id, ty: *const TypeTag, value: Value },
};

/// exec-history-vm: children are modified by the old dirty flag (v0..v2, and v3 before
/// `minimize_child_object_mutations`), not by fingerprint.
pub fn legacyDirty(cfg: *const ProtocolConfig) bool {
    return (cfg.execution_version orelse 0) < 3 or !cfg.feature_flags.minimize_child_object_mutations;
}

pub const ChildObject = struct {
    owner: Id,
    ty: *const TypeTag,
    exists: bool,
    /// The slot a returned `&Child` points at.
    value: Value,
    fp: Fingerprint,
    /// exec-history-vm: the old `GlobalValue` dirty status (written through a mutable borrow, or
    /// removed and added again): v0..v2 and before `minimize_child_object_mutations` a child is
    /// modified when dirty, whatever its final value.
    dirty: bool = false,
};

pub const Transfer = struct { owner: Owner, ty: *const TypeTag, value: Value };
pub const Event = struct { ty: *const TypeTag, value: Value };
pub const AccAction = enum(u8) { merge = 0, split = 1 };
pub const AccValue = union(enum) { u64: u64, event_ref: u64 };
pub const AccEvent = struct { accumulator_id: Id, action: AccAction, target_addr: Id, target_ty: *const TypeTag, value: AccValue };
pub const LoadedMeta = struct { version: u64, digest: Id, storage_rebate: u64, owner: Owner, previous_transaction: Id };
pub const InputObject = struct { id: Id, version: u64, owner: Owner, contained_uids: []const Id };

pub const TransferResult = enum { new, same_owner, owner_changed };
pub const FundsSufficiency = union(enum) { sufficient, insufficient, overflow, load_error };

const Funds = struct { available: u256 = 0, queried: bool = false };
const ConfigSetting = struct { config: Id, ty: *const TypeTag, value: Value };

pub fn Res(comptime T: type) type {
    return union(enum) { ok: T, err: VmError };
}

pub const Loaded = struct { info: CacheInfo, child: *ChildObject };
pub const Fetch = union(enum) { err: VmError, mismatched, loaded: Loaded };
pub const Receive = union(enum) { err: VmError, none, mismatched, loaded: Value };

const framework_objects = [_]u16{ 0x5, 0x6, 0x7, 0x8, 0x403, 0x9, 0xacc, 0xc, 0xd, 0xa, 0xfa };

/// exec-history-vm: how many of `framework_objects` each execution version knows (v0: system
/// state and clock; v1 adds authenticator state; v2 randomness and deny list; v3 bridge,
/// accumulator root, coin and display registries, address alias; latest the forwarding registry).
const framework_objects_by_version = [_]usize{ 2, 3, 5, 10, framework_objects.len };

fn isFrameworkObject(id: *const Id, cfg: *const ProtocolConfig) bool {
    for (id[0..30]) |b| if (b != 0) return false;
    const short = std.mem.readInt(u16, id[30..32], .big);
    const ev = @min(cfg.execution_version orelse 0, framework_objects_by_version.len - 1);
    for (framework_objects[0..framework_objects_by_version[ev]]) |f| if (f == short) return true;
    return false;
}

/// Accumulator key (address, type) hashed and compared structurally: no per-call BCS or
/// allocation. Rust keys the same maps by (AccumulatorAddress, TypeTag).
pub const AccKey = struct { addr: Id, ty: *const TypeTag };

const AccCtx = struct {
    pub fn hash(_: AccCtx, k: AccKey) u64 {
        var h = std.hash.Wyhash.init(0);
        h.update(&k.addr);
        hashTag(&h, k.ty);
        return h.final();
    }
    pub fn eql(_: AccCtx, a: AccKey, b: AccKey) bool {
        return std.mem.eql(u8, &a.addr, &b.addr) and (a.ty == b.ty or tagEql(a.ty, b.ty));
    }
};

fn hashTag(h: *std.hash.Wyhash, t: *const TypeTag) void {
    h.update(&[_]u8{@intFromEnum(std.meta.activeTag(t.*))});
    switch (t.*) {
        .vector => |e| hashTag(h, e),
        .@"struct" => |st| {
            h.update(&st.address.@"0");
            h.update(st.module.@"0");
            h.update(&[_]u8{0});
            h.update(st.name.@"0");
            h.update(&[_]u8{ 0, @truncate(st.type_args.len) });
            for (st.type_args) |*a| hashTag(h, a);
        },
        else => {},
    }
}

fn AccMap(comptime V: type) type {
    return std.HashMapUnmanaged(AccKey, V, AccCtx, std.hash_map.default_max_load_percentage);
}

const ScratchEntry = struct { ty: *const TypeTag, value: Value, layout: ?*const Layout };

pub const ObjectRuntime = struct {
    is_metered: bool = true,
    epoch: u64 = 0,
    resolver: ?Resolver = null,

    input_objects: std.AutoHashMapUnmanaged(Id, Owner) = .empty,
    root_version: std.AutoHashMapUnmanaged(Id, u64) = .empty,
    wrapped: std.AutoArrayHashMapUnmanaged(Id, Id) = .empty,
    cached: std.AutoArrayHashMapUnmanaged(Id, ?*const StoredObject) = .empty,
    store: std.AutoArrayHashMapUnmanaged(Id, *ChildObject) = .empty,
    config_cache: std.AutoHashMapUnmanaged(Id, ConfigSetting) = .empty,

    new_ids: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    generated_ids: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    deleted_ids: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    transfers: std.AutoArrayHashMapUnmanaged(Id, Transfer) = .empty,
    events: std.ArrayList(Event) = .empty,
    acc_events: std.ArrayList(AccEvent) = .empty,
    total_events_size: u64 = 0,
    total_events_emitted: u64 = 0,
    received: std.AutoArrayHashMapUnmanaged(Id, LoadedMeta) = .empty,
    settlement_input_sui: u64 = 0,
    settlement_output_sui: u64 = 0,
    merge_totals: AccMap(u128) = .empty,
    split_totals: AccMap(u128) = .empty,
    funds: AccMap(Funds) = .empty,

    /// `ObjectRuntime::clock`: the Clock loaded by the first `clock::borrow`; every later borrow
    /// in the transaction references the same value.
    clock: ?*Value = null,

    /// `ScratchRuntime` (its own extension in Rust; it lives here).
    scratch: std.AutoHashMapUnmanaged(Id, ScratchEntry) = .empty,

    /// `ObjectRuntime::new` input objects: owners and the root version of every UID they hold.
    pub fn addInput(rt: *ObjectRuntime, gpa: Allocator, in: InputObject) Allocator.Error!void {
        try rt.input_objects.put(gpa, in.id, in.owner);
        for (in.contained_uids) |u| {
            try rt.root_version.put(gpa, u, in.version);
            if (!std.mem.eql(u8, &u, &in.id)) try rt.wrapped.put(gpa, u, in.id);
        }
    }

    fn limit(rt: *const ObjectRuntime, cfg: *const ProtocolConfig, comptime metered: []const u8, comptime system: []const u8) ?u64 {
        const v = if (rt.is_metered) cfg.getOpt(metered) else cfg.getOpt(system);
        return if (v) |x| @intCast(x) else null;
    }

    // ---- ids ----

    /// exec-history-vm: v0 and v1 keep new/deleted ids and transfers in a `LinkedHashMap`, whose
    /// insert of a present key moves it to the back (v2 on use `IndexMap`/`IndexSet`, which keep
    /// the first position). Seen when one id is deleted twice (`coin::join` over equal ids).
    fn linkedPut(comptime V: type, m: *std.AutoArrayHashMapUnmanaged(Id, V), gpa: Allocator, cfg: *const ProtocolConfig, id: Id, v: V) Allocator.Error!void {
        if ((cfg.execution_version orelse 0) < 2) _ = m.orderedRemove(id);
        try m.put(gpa, id, v);
    }

    pub fn newId(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, id: Id) Allocator.Error!?VmError {
        if (rt.limit(cfg, "max_num_new_move_object_ids", "max_num_new_move_object_ids_system_tx")) |l|
            if (rt.new_ids.count() >= l) return memErr(Mem.NEW_ID_COUNT);
        if (rt.deleted_ids.orderedRemove(id)) return null;
        try rt.generated_ids.put(gpa, id, {});
        try linkedPut(void, &rt.new_ids, gpa, cfg, id, {});
        return null;
    }

    /// 1.84 `inherit_root_version_from_parent`: `id` keeps a root version it already has
    /// (`entry(id).or_insert(v)`; 1.83 raised an invariant violation on a different one).
    pub fn newIdFromHash(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, id: Id) Allocator.Error!?VmError {
        if (try rt.newId(gpa, cfg, id)) |e| return e;
        if (rt.root_version.get(parent)) |v| {
            const gop = try rt.root_version.getOrPut(gpa, id);
            if (!gop.found_existing) gop.value_ptr.* = v;
        }
        return null;
    }

    /// `ObjectRuntime::input_owner`.
    pub fn inputOwner(rt: *const ObjectRuntime, id: *const Id) ?Owner {
        return rt.input_objects.get(id.*);
    }

    /// `ObjectRuntime::borrow_clock`: the Clock `{ id: UID, timestamp_ms: u64 }`, read once from
    /// the resolver and deserialized (`Value::simple_deserialize`, so exactly 40 bytes).
    pub fn borrowClock(rt: *ObjectRuntime, gpa: Allocator) Allocator.Error!Res(*Value) {
        if (rt.clock) |v| return .{ .ok = v };
        const r = rt.resolver orelse return .{ .err = invariant };
        const f = r.vtable.clock orelse return .{ .err = invariant };
        const contents = (f(r.ctx) catch return .{ .err = invariant }) orelse return .{ .err = invariant };
        if (contents.len != 40) return .{ .err = .{ .status = .FAILED_TO_DESERIALIZE_RESOURCE } };
        const vals = try gpa.alloc(Value, 5);
        vals[0] = .{ .address = contents[0..32].* };
        vals[1] = .{ .@"struct" = vals[0..1] }; // ID { bytes }
        vals[2] = .{ .@"struct" = vals[1..2] }; // UID { id }
        vals[3] = .{ .u64 = std.mem.readInt(u64, contents[32..40], .little) };
        const fields = try gpa.alloc(Value, 2);
        fields[0] = vals[2];
        fields[1] = vals[3];
        vals[4] = .{ .@"struct" = fields };
        rt.clock = &vals[4];
        return .{ .ok = &vals[4] };
    }

    pub fn deleteId(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, id: Id) Allocator.Error!?VmError {
        if (rt.limit(cfg, "max_num_deleted_move_object_ids", "max_num_deleted_move_object_ids_system_tx")) |l|
            if (rt.deleted_ids.count() >= l) return memErr(Mem.DELETED_ID_COUNT);
        if (!rt.new_ids.orderedRemove(id)) try linkedPut(void, &rt.deleted_ids, gpa, cfg, id, {});
        return null;
    }

    // ---- transfers and events ----

    pub fn transfer(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, owner: Owner, ty: *const TypeTag, obj: Value, end_of_transaction: bool) Allocator.Error!Res(TransferResult) {
        const id = objectId(&obj);
        const fw = isFrameworkObject(&id, cfg);
        const result: TransferResult = if (rt.new_ids.contains(id))
            .new
        else if (rt.input_objects.get(id)) |prev|
            (if (owner.sameAs(prev)) .same_owner else .owner_changed)
        else if (fw) blk: {
            // exec-history-vm: v0 calls a framework object new without adding it to new_ids
            // (its write kind is then Create for the system state, Unwrap for the clock)
            if ((cfg.execution_version orelse 0) > 0) {
                try rt.new_ids.put(gpa, id, {});
                try rt.generated_ids.put(gpa, id, {});
            }
            break :blk .new;
        } else .owner_changed;
        if (end_of_transaction and result == .owner_changed) return .{ .err = invariant };
        if (rt.is_metered and !fw and !end_of_transaction) {
            if (cfg.getOpt("max_num_transferred_move_object_ids")) |l|
                if (rt.transfers.count() >= l) return .{ .err = memErr(Mem.TRANSFER_ID_COUNT) };
        } else if (cfg.getOpt("max_num_transferred_move_object_ids_system_tx")) |l| {
            if (rt.transfers.count() >= l) return .{ .err = memErr(Mem.TRANSFER_ID_COUNT) };
        }
        try linkedPut(Transfer, &rt.transfers, gpa, cfg, id, .{ .owner = owner, .ty = ty, .value = obj });
        return .{ .ok = result };
    }

    pub fn emitEvent(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, ty: *const TypeTag, v: Value) Allocator.Error!?VmError {
        const max: u64 = @intCast(cfg.getOpt("max_num_event_emit") orelse std.math.maxInt(u64));
        if (rt.events.items.len >= max) return memErr(Mem.EVENT_COUNT);
        try rt.events.append(gpa, .{ .ty = ty, .value = v });
        rt.total_events_emitted += 1;
        return null;
    }

    /// Preallocates the per-transaction tables so the common case never grows them.
    pub fn reserve(rt: *ObjectRuntime, gpa: Allocator, n: u32) Allocator.Error!void {
        try rt.new_ids.ensureTotalCapacity(gpa, n);
        try rt.generated_ids.ensureTotalCapacity(gpa, n);
        try rt.deleted_ids.ensureTotalCapacity(gpa, n);
        try rt.transfers.ensureTotalCapacity(gpa, n);
        try rt.events.ensureTotalCapacity(gpa, n);
        try rt.acc_events.ensureTotalCapacity(gpa, n);
        try rt.merge_totals.ensureTotalCapacity(gpa, n);
        try rt.split_totals.ensureTotalCapacity(gpa, n);
        try rt.funds.ensureTotalCapacity(gpa, n);
    }

    pub fn emitAccumulatorEvent(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, acc_id: Id, action: AccAction, target: Id, ty: *const TypeTag, value: AccValue) Allocator.Error!?VmError {
        if (cfg.getOpt("max_num_accumulator_events")) |max|
            if (rt.acc_events.items.len >= max) return memErr(Mem.ACCUMULATOR_EVENT_COUNT);
        if (value == .u64) {
            const amount = value.u64;
            const key: AccKey = .{ .addr = target, .ty = ty };
            const totals = if (action == .merge) &rt.merge_totals else &rt.split_totals;
            const cur = totals.get(key) orelse 0;
            const total = cur + amount;
            if (total > std.math.maxInt(u64)) return .{ .status = .ARITHMETIC_ERROR };
            try totals.put(gpa, key, total);
            if (action == .merge and cfg.feature_flags.check_object_funds_withdraw_in_execution) {
                const e = try rt.funds.getOrPut(gpa, key);
                if (!e.found_existing) e.value_ptr.* = .{};
                const sum = @addWithOverflow(e.value_ptr.available, @as(u256, amount));
                if (sum[1] != 0) return .{ .status = .ARITHMETIC_ERROR };
                e.value_ptr.available = sum[0];
            }
        }
        try rt.acc_events.append(gpa, .{ .accumulator_id = acc_id, .action = action, .target_addr = target, .target_ty = ty, .value = value });
        return null;
    }

    pub fn fundsNeedsStoreRead(rt: *ObjectRuntime, gpa: Allocator, owner: Id, ty: *const TypeTag, amount: u256) Allocator.Error!bool {
        _ = gpa;
        const key: AccKey = .{ .addr = owner, .ty = ty };
        const f = rt.funds.get(key) orelse Funds{};
        return f.available < amount and !f.queried;
    }

    pub fn checkFundsSufficiency(rt: *ObjectRuntime, gpa: Allocator, owner: Id, ty: *const TypeTag, amount: u256) Allocator.Error!FundsSufficiency {
        const key: AccKey = .{ .addr = owner, .ty = ty };
        const e = try rt.funds.getOrPut(gpa, key);
        if (!e.found_existing) e.value_ptr.* = .{};
        const f = e.value_ptr;
        if (f.available < amount and !f.queried) {
            const settled: u128 = if (rt.resolver) |r| r.vtable.available_balance(r.ctx, &owner, ty) catch return .load_error else 0;
            const sum = @addWithOverflow(f.available, @as(u256, settled));
            if (sum[1] != 0) return .overflow;
            f.available = sum[0];
            f.queried = true;
        }
        if (f.available >= amount) {
            f.available -= amount;
            return .sufficient;
        }
        return .insufficient;
    }

    pub fn recordSettlement(rt: *ObjectRuntime, input_sui: u64, output_sui: u64) void {
        rt.settlement_input_sui +%= input_sui;
        rt.settlement_output_sui +%= output_sui;
    }

    // ---- child objects ----

    /// `fetch_child_object_unbounded!`
    fn fetchUnbounded(rt: *ObjectRuntime, parent: *const Id, child: *const Id, upper: u64, had_root: bool) Res(?*const StoredObject) {
        const r = rt.resolver orelse return .{ .ok = null };
        const obj = (r.vtable.read_child(r.ctx, parent, child, upper) catch return .{ .err = .{ .status = .STORAGE_ERROR } }) orelse return .{ .ok = null };
        if (!had_root) return .{ .err = .{ .status = .STORAGE_ERROR } };
        switch (obj.owner) {
            .object => |o| if (!std.mem.eql(u8, &o, parent)) return .{ .err = .{ .status = .STORAGE_ERROR } },
            else => return .{ .err = .{ .status = .STORAGE_ERROR } },
        }
        if (obj.move == null) return .{ .err = .{ .status = .STORAGE_ERROR } };
        return .{ .ok = obj };
    }

    /// `Inner::get_or_fetch_object_from_store`
    fn fromStore(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, child: Id) Allocator.Error!Res(struct { CacheInfo, ?*const StoredObject }) {
        const count = rt.cached.count();
        const rv = rt.root_version.get(parent);
        if (rt.cached.get(child)) |o| return .{ .ok = .{ .cached_object, o } };
        const obj = switch (rt.fetchUnbounded(&parent, &child, rv orelse 0, rv != null)) {
            .err => |e| return .{ .err = e },
            .ok => |o| o,
        };
        if (rt.limit(cfg, "object_runtime_max_num_cached_objects", "object_runtime_max_num_cached_objects_system_tx")) |l|
            if (count >= l) return .{ .err = memErr(Mem.CACHE) };
        try rt.cached.put(gpa, child, obj);
        return .{ .ok = .{ .{ .loaded = if (obj) |o| o.move.?.contents.len else null }, obj } };
    }

    pub fn childExists(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, child: Id) Allocator.Error!Res(struct { CacheInfo, bool }) {
        if (rt.store.get(child)) |c| return .{ .ok = .{ .cached_value, c.exists } };
        return switch (try rt.fromStore(gpa, cfg, parent, child)) {
            .err => |e| .{ .err = e },
            .ok => |r| .{ .ok = .{ r[0], r[1] != null } },
        };
    }

    pub fn childExistsWithType(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, child: Id, ty: *const TypeTag) Allocator.Error!Res(struct { CacheInfo, bool }) {
        if (rt.store.get(child)) |c| return .{ .ok = .{ .cached_value, c.exists and tagEql(c.ty, ty) } };
        return switch (try rt.fromStore(gpa, cfg, parent, child)) {
            .err => |e| .{ .err = e },
            .ok => |r| .{ .ok = .{ r[0], if (r[1]) |o| tagEql(o.move.?.type_, ty) else false } },
        };
    }

    /// `ChildObjectStore::get_or_fetch_object`
    pub fn getOrFetch(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, child: Id, layout: *const Layout, alayout: *const ALayout, ty: *const TypeTag) Allocator.Error!Fetch {
        const entries = rt.store.count();
        if (rt.store.get(child)) |c| {
            if (!tagEql(c.ty, ty)) return .mismatched;
            return .{ .loaded = .{ .info = .cached_value, .child = c } };
        }
        // Inner::fetch_object_impl
        const info, const obj = switch (try rt.fromStore(gpa, cfg, parent, child)) {
            .err => |e| return .{ .err = e },
            .ok => |r| r,
        };
        var co: ChildObject = .{ .owner = parent, .ty = ty, .exists = false, .value = .{ .bool = false }, .fp = .empty };
        if (obj) |o| {
            const mo = o.move.?;
            if (!tagEql(mo.type_, ty)) return .mismatched;
            const v = types.layout.decodePacked(gpa, layout, mo.contents) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .{ .err = .{ .status = .FAILED_TO_DESERIALIZE_RESOURCE } },
            };
            if (v != .@"struct") return .{ .err = .{ .status = .STORAGE_ERROR } };
            co.exists = true;
            co.value = v;
            co.fp = .{ .preexisting = .{ .owner = parent, .ty = ty, .value = v } };
            const uids = try allUids(gpa, &v, alayout);
            if (rt.root_version.get(parent)) |rv| {
                for (uids) |u| {
                    try rt.root_version.put(gpa, u, rv);
                    if (!std.mem.eql(u8, &u, &child)) try rt.wrapped.put(gpa, u, child);
                }
            }
        }
        if (rt.limit(cfg, "object_runtime_max_num_store_entries", "object_runtime_max_num_store_entries_system_tx")) |l|
            if (entries >= l) return .{ .err = memErr(Mem.STORE) };
        const slot = try gpa.create(ChildObject);
        slot.* = co;
        try rt.store.put(gpa, child, slot);
        return .{ .loaded = .{ .info = info, .child = slot } };
    }

    /// `ChildObjectStore::add_object`
    pub fn addChild(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, child: Id, ty: *const TypeTag, v: Value) Allocator.Error!?VmError {
        if (rt.limit(cfg, "object_runtime_max_num_store_entries", "object_runtime_max_num_store_entries_system_tx")) |l|
            if (rt.store.count() >= l) return memErr(Mem.STORE);
        var fp: Fingerprint = .empty;
        var readded = false;
        const ev = cfg.execution_version orelse 0;
        if (ev == 0) {
            // exec-history-vm: v0 `add_object` inserts a fresh value first (replacing any entry),
            // then fails if the replaced one still existed; the new value stays and is written.
            const prev = rt.store.get(child);
            if (v != .@"struct") return invariant;
            const slot = try gpa.create(ChildObject);
            slot.* = .{ .owner = parent, .ty = ty, .exists = true, .value = v, .fp = .empty };
            try rt.store.put(gpa, child, slot);
            if (prev) |p| if (p.exists) return invariant;
            return null;
        }
        if (rt.store.fetchSwapRemove(child)) |kv| {
            if (kv.value.exists) return invariant;
            readded = true;
            if (ev >= 3 or cfg.feature_flags.loaded_child_object_format) {
                // exec-history-vm: v1/v2 at protocol 22 check the type is unchanged (dropped at 23)
                if (ev < 3 and !cfg.feature_flags.loaded_child_object_format_type and !tagEql(kv.value.ty, ty)) return invariant;
                fp = kv.value.fp;
            }
            // else (v1 before protocol 22): the re-added value starts fresh (`GlobalValue::none`),
            // so removing it again leaves no effect at all
        }
        if (v != .@"struct") return invariant;
        const slot = try gpa.create(ChildObject);
        // exec-history-vm: under the old rule a child removed and added again is dirty.
        const legacy = (cfg.execution_version orelse 0) < 3 or !cfg.feature_flags.minimize_child_object_mutations;
        slot.* = .{ .owner = parent, .ty = ty, .exists = true, .value = v, .fp = fp, .dirty = readded and legacy };
        try rt.store.put(gpa, child, slot);
        return null;
    }

    /// `ObjectRuntime::receive_object`
    pub fn receiveObject(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, parent: Id, child: Id, version: u64, layout: *const Layout, alayout: *const ALayout, ty: *const TypeTag) Allocator.Error!Receive {
        const r = rt.resolver orelse return .none;
        const obj = (r.vtable.received_at(r.ctx, &parent, &child, version, rt.epoch) catch return .{ .err = .{ .status = .STORAGE_ERROR } }) orelse return .none;
        if (!(obj.owner == .address and std.mem.eql(u8, &obj.owner.address, &parent))) return .{ .err = .{ .status = .STORAGE_ERROR } };
        if (obj.version != version) return .{ .err = .{ .status = .STORAGE_ERROR } };
        const mo = obj.move orelse return .{ .err = .{ .status = .STORAGE_ERROR } };
        const meta: LoadedMeta = .{ .version = version, .digest = obj.digest, .storage_rebate = obj.storage_rebate, .owner = obj.owner, .previous_transaction = obj.previous_transaction };
        var out: Receive = undefined;
        if (!tagEql(mo.type_, ty)) {
            out = .mismatched;
        } else {
            const v = types.layout.decodePacked(gpa, layout, mo.contents) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .{ .err = .{ .status = .FAILED_TO_DESERIALIZE_RESOURCE } },
            };
            const uids = try allUids(gpa, &v, alayout);
            for (uids) |u| {
                try rt.root_version.put(gpa, u, version);
                if (!std.mem.eql(u8, &u, &child)) try rt.wrapped.put(gpa, u, child);
            }
            out = .{ .loaded = v };
        }
        if (cfg.feature_flags.early_return_receive_object_mismatched_type and out == .mismatched and rt.received.contains(child))
            return .mismatched;
        const gop = try rt.received.getOrPut(gpa, child);
        if (gop.found_existing) return .{ .err = invariant };
        gop.value_ptr.* = meta;
        return out;
    }

    /// `config_setting_unsequenced_read`: null when there is no setting (or any error, which
    /// Rust logs and maps to None).
    pub fn configRead(rt: *ObjectRuntime, gpa: Allocator, config: Id, name: Id, layout: *const Layout, ty: *const TypeTag) Allocator.Error!?Value {
        if (rt.config_cache.get(name)) |s| {
            if (!tagEql(s.ty, ty)) return null;
            if (!std.mem.eql(u8, &s.config, &config)) return null;
            return s.value;
        }
        // SequenceNumber::MAX is 0x7fff_ffff_ffff_ffff (not u64::MAX): the bound a resolver sees
        const obj = switch (rt.fetchUnbounded(&config, &name, sequence_number_max, true)) {
            .err => return null,
            .ok => |o| o orelse return null,
        };
        const v = types.layout.decodePacked(gpa, layout, obj.move.?.contents) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null,
        };
        try rt.config_cache.put(gpa, name, .{ .config = config, .ty = ty, .value = v });
        return v;
    }

    pub fn packageAt(rt: *const ObjectRuntime, id: Id, version: u64) ?PackageInfo {
        const r = rt.resolver orelse return null;
        return r.vtable.package_at(r.ctx, &id, version);
    }

    // ---- scratch pad (ScratchRuntime) ----

    pub const AddResult = enum { inserted, duplicate, limit_exceeded };

    pub fn scratchAdd(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig, key: Id, ty: *const TypeTag, v: Value, layout: ?*const Layout) Allocator.Error!AddResult {
        if (rt.scratch.contains(key)) return .duplicate;
        if (cfg.getOpt("max_scratch_pad_size")) |max| if (rt.scratch.count() >= max) return .limit_exceeded;
        try rt.scratch.put(gpa, key, .{ .ty = ty, .value = v, .layout = layout });
        return .inserted;
    }

    pub fn scratchGet(rt: *const ObjectRuntime, key: Id) ?ScratchEntry {
        return rt.scratch.get(key);
    }

    pub fn scratchRemove(rt: *ObjectRuntime, key: Id) ?ScratchEntry {
        const kv = rt.scratch.fetchRemove(key) orelse return null;
        return kv.value;
    }

    // ---- end of transaction ----

    pub const Write = struct { id: Id, owner: Owner, ty: *const TypeTag, value: Value };
    pub const LoadedChild = struct { id: Id, version: u64, modified: bool };
    pub const Results = struct {
        writes: []const Write,
        events: []const Event,
        acc_events: []const AccEvent,
        loaded: []const LoadedChild,
        created: []const Id,
        deleted: []const Id,
        generated: []const Id,
        wrapped: []const [2]Id,
        settlement_input_sui: u64,
        settlement_output_sui: u64,
        /// exec-history-vm, v0 only (`finishFor`): children whose effect is `Op::Delete` and that
        /// are neither transferred, nor id-deleted, nor new, in id order (v0 `wrapped_children`
        /// before the adapter removes its `external_transfers`).
        v0_wrapped_children: []const Id = &.{},
    };
    pub const FinishError = union(enum) { circular: Id, invariant };
    pub const Finish = union(enum) { ok: Results, err: FinishError };

    fn sortedKeys(gpa: Allocator, keys: []const Id) Allocator.Error![]Id {
        const out = try gpa.dupe(Id, keys);
        std.mem.sort(Id, out, {}, idLess);
        return out;
    }

    /// `ObjectRuntime::finish` (consumes the state; the runtime is not used afterwards).
    /// exec-history-vm: a write through `slot` (a child's value, as `borrow_child_object_mut`
    /// returned it) marks that child dirty (old rule, `legacyDirty`).
    pub fn markDirtySlot(rt: *ObjectRuntime, slot: *const Value) void {
        for (rt.store.values()) |co| if (&co.value == slot) {
            co.dirty = true;
        };
    }

    /// `finish` in the shape of the cut's `RuntimeResults` (exec-history-vm): v0 reports loaded
    /// children without a modified flag and no created-id set (its writes carry kinds instead).
    pub fn finishFor(rt: *ObjectRuntime, gpa: Allocator, cfg: *const ProtocolConfig) Allocator.Error!Finish {
        var f = try rt.finish(gpa);
        if ((cfg.execution_version orelse 0) == 0) switch (f) {
            .ok => |*r| {
                const lo = try gpa.alloc(LoadedChild, r.loaded.len);
                for (lo, r.loaded) |*o, l| o.* = .{ .id = l.id, .version = l.version, .modified = false };
                r.loaded = lo;
                // v0 knows created objects only as writes of kind Create
                // (in write order), and deletions in the order they happened
                // (`WriteKind::Create`: in new_ids, or the system state object when it is neither an
                // input nor a loaded child)
                var cr: std.ArrayList(Id) = .empty;
                const system_state: Id = comptime blk: {
                    var x: Id = @splat(0);
                    x[31] = 5;
                    break :blk x;
                };
                for (r.writes) |w| {
                    const create = for (r.created) |id| {
                        if (std.mem.eql(u8, &w.id, &id)) break true;
                    } else std.mem.eql(u8, &w.id, &system_state) and !rt.input_objects.contains(w.id) and
                        for (r.loaded) |l| {
                            if (std.mem.eql(u8, &l.id, &w.id)) break false;
                        } else true;
                    if (create) try cr.append(gpa, w.id);
                }
                r.created = cr.items;
                r.deleted = try gpa.dupe(Id, rt.deleted_ids.keys());
                var wc: std.ArrayList(Id) = .empty;
                for (try sortedKeys(gpa, rt.store.keys())) |id| {
                    const c = rt.store.get(id).?;
                    if (c.exists or c.fp != .preexisting) continue; // Op::Delete only
                    if (rt.transfers.contains(id) or rt.deleted_ids.contains(id) or rt.new_ids.contains(id)) continue;
                    try wc.append(gpa, id);
                }
                r.v0_wrapped_children = wc.items;
            },
            .err => {},
        };
        return f;
    }

    pub fn finish(rt: *ObjectRuntime, gpa: Allocator) Allocator.Error!Finish {
        // loaded_runtime_objects: cached objects found in storage, then received (BTreeMap)
        var loaded: std.AutoArrayHashMapUnmanaged(Id, LoadedChild) = .empty;
        for (rt.cached.keys(), rt.cached.values()) |id, o| if (o) |obj| try loaded.put(gpa, id, .{ .id = id, .version = obj.version, .modified = false });
        for (rt.received.keys(), rt.received.values()) |id, m| try loaded.put(gpa, id, .{ .id = id, .version = m.version, .modified = false });

        // child object effects, in id order
        const child_ids = try sortedKeys(gpa, rt.store.keys());
        for (child_ids) |id| {
            const c = rt.store.get(id).?;
            const final: ?Value = if (c.exists) c.value else null;
            const changed = switch (c.fp) {
                .empty => final != null,
                .preexisting => |p| if (final) |f|
                    !(std.mem.eql(u8, &p.owner, &c.owner) and tagEql(p.ty, c.ty) and valueEql(&p.value, &f))
                else
                    true,
            };
            // exec-history-vm: the old rule also writes back a dirty child with an equal value.
            const legacy_dirty = c.dirty and final != null; // set only under the old rule
            if (!changed and !legacy_dirty) continue;
            if (loaded.getPtr(id)) |l| l.modified = true;
            if (final) |f| try rt.transfers.put(gpa, id, .{ .owner = .{ .object = c.owner }, .ty = c.ty, .value = f });
        }

        // check_circular_ownership
        var owners: std.AutoHashMapUnmanaged(Id, Id) = .empty;
        for (rt.transfers.keys(), rt.transfers.values()) |id, t| {
            _ = owners.remove(id);
            switch (t.owner) {
                .object => |new_owner| {
                    var cur = new_owner;
                    while (true) {
                        if (std.mem.eql(u8, &cur, &id)) return .{ .err = .{ .circular = cur } };
                        cur = owners.get(cur) orelse break;
                    }
                    try owners.put(gpa, id, new_owner);
                },
                else => {},
            }
        }

        const writes = try gpa.alloc(Write, rt.transfers.count());
        for (writes, rt.transfers.keys(), rt.transfers.values()) |*w, id, t| {
            if (loaded.getPtr(id)) |l| l.modified = true;
            w.* = .{ .id = id, .owner = t.owner, .ty = t.ty, .value = t.value };
        }
        for (rt.deleted_ids.keys()) |id| if (loaded.getPtr(id)) |l| {
            l.modified = true;
        };
        for (rt.received.keys()) |id| {
            const l = loaded.getPtr(id) orelse return .{ .err = .invariant };
            l.modified = true;
        }

        const loaded_ids = try sortedKeys(gpa, loaded.keys());
        const lo = try gpa.alloc(LoadedChild, loaded_ids.len);
        for (lo, loaded_ids) |*o, id| o.* = loaded.get(id).?;

        const wrapped_ids = try sortedKeys(gpa, rt.wrapped.keys());
        const wr = try gpa.alloc([2]Id, wrapped_ids.len);
        for (wr, wrapped_ids) |*o, id| o.* = .{ id, rt.wrapped.get(id).? };

        return .{ .ok = .{
            .writes = writes,
            .events = rt.events.items,
            .acc_events = rt.acc_events.items,
            .loaded = lo,
            .created = rt.new_ids.keys(),
            .deleted = rt.deleted_ids.keys(),
            .generated = try sortedKeys(gpa, rt.generated_ids.keys()),
            .wrapped = wr,
            .settlement_input_sui = rt.settlement_input_sui,
            .settlement_output_sui = rt.settlement_output_sui,
        } };
    }
};

test "uid collection and value equality" {
    const a = std.testing.allocator;
    _ = a;
    var two: Id = @splat(0);
    two[31] = 2;
    const id_tag: StructTag = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "object" }, .name = .{ .@"0" = "ID" }, .type_args = &.{} };
    const uid_tag: StructTag = .{ .address = .{ .@"0" = two }, .module = .{ .@"0" = "object" }, .name = .{ .@"0" = "UID" }, .type_args = &.{} };
    const id_l: AStruct = .{ .type_ = id_tag, .fields = &.{.{ .name = .{ .@"0" = "bytes" }, .layout = .address }} };
    const uid_l: AStruct = .{ .type_ = uid_tag, .fields = &.{.{ .name = .{ .@"0" = "id" }, .layout = .{ .@"struct" = &id_l } }} };
    const obj_l: AStruct = .{ .type_ = id_tag, .fields = &.{
        .{ .name = .{ .@"0" = "id" }, .layout = .{ .@"struct" = &uid_l } },
        .{ .name = .{ .@"0" = "x" }, .layout = .address },
    } };
    const l: ALayout = .{ .@"struct" = &obj_l };
    const v: Value = .{ .@"struct" = &.{
        .{ .@"struct" = &.{.{ .@"struct" = &.{.{ .address = @splat(7) }} }} },
        .{ .address = @splat(9) },
    } };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const uids = try allUids(arena.allocator(), &v, &l);
    try std.testing.expectEqual(@as(usize, 1), uids.len);
    try std.testing.expectEqual(@as(u8, 7), uids[0][0]);
    try std.testing.expect(valueEql(&v, &v));
    try std.testing.expectEqual(@as(u8, 7), objectId(&v)[5]);
}
