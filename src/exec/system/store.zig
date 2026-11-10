//! The part of sui-adapter's `TemporaryStore` that system transactions use, on the unmetered
//! path of execution version 4 (bump-only gas model, effects V2):
//!   TemporaryStore::new (lamport timestamp, transaction dependencies, mutable input refs),
//!   ExecutionResultsV2 (written / modified / created / deleted, loaded runtime objects),
//!   GasCharger::meter_storage for `PaymentMetadata::Unmetered` (ensure_active_inputs_mutated,
//!   collect_storage_and_rebate with `track_mutation(unmetered)`), GasCharger::charge
//!   (conserve_unmetered_storage_rebate into 0x5), TemporaryStore::into_effects
//!   (update_version_and_previous_tx, EffectsObjectChange::new per id in id order,
//!   compute_unchanged_consensus_objects, TransactionEffects::new_from_execution_v2).
//!
//! Objects stay raw BCS. A write keeps the bytes of its `Data` up to the version (Data tag,
//! MoveObjectType, has_public_transfer), its contents and its owner; the version, previous
//! transaction and storage rebate are filled in at `intoEffects`.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const bcs = @import("bcs");
const objects = @import("../objects.zig");

const Allocator = std.mem.Allocator;
const ObjectView = objects.ObjectView;

const zero32: [32]u8 = @splat(0);
pub const system_state_id: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[31] = 5;
    break :blk a;
};

pub const Written = struct { id: [32]u8, bytes: []const u8 };
pub const Output = struct { effects: []const u8, events: ?[]const u8, written: []const Written };

/// A Move object the transaction writes.
pub const Write = struct {
    id: [32]u8,
    /// `Data::Move` bytes before the version: tag 0, MoveObjectType, has_public_transfer.
    header: []const u8,
    contents: []const u8,
    /// BCS `Owner`.
    owner: []const u8,
    /// New storage_rebate (collect_storage_and_rebate; 0 on the unmetered path).
    rebate: u64 = 0,
    // filled by intoEffects
    bytes: []const u8 = &.{},
};

/// `DynamicallyLoadedObjectMetadata` / a mutable input ref: the object as read.
const Meta = struct {
    version: u64,
    /// The object as read; its digest is computed only for the effects of a changed object.
    raw: []const u8,
    owner: []const u8,
    rebate: u64,
    prev_tx: [32]u8,

    fn of(v: *const ObjectView) Meta {
        return .{ .version = v.version, .raw = v.raw, .owner = v.ownerBytes(), .rebate = v.storageRebate(), .prev_tx = v.raw[v.prev_tx_at + 1 ..][0..32].* };
    }
};

/// `TemporaryStore::upgrade_system_package`: a system package written in place. `bytes` is the
/// whole new object at its final version (Rust writes it one below and lets
/// `update_version_and_previous_tx` increment it); `old` is the package the epoch loaded
/// (`get_object_modified_at` falls back to the store for a system package).
pub const PackageWrite = struct { bytes: []const u8, old: ?[]const u8 };

pub const Access = enum { read, mutable, non_exclusive };
const Input = struct { view: ObjectView, access: Access, shared: bool };

pub const Error = error{ OutOfMemory, InvariantViolation, Unsupported };

pub const Store = struct {
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    tx_digest: [32]u8,
    inputs: std.AutoArrayHashMapUnmanaged([32]u8, Input) = .empty,
    deps: std.ArrayList([32]u8) = .empty,
    max_version: u64 = 0,
    written: std.AutoArrayHashMapUnmanaged([32]u8, Write) = .empty,
    modified: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    created: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    deleted: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    loaded: std.AutoArrayHashMapUnmanaged([32]u8, Meta) = .empty,
    /// System packages written by `upgrade_system_package`: the new package object (final
    /// version and previous transaction already in place) and the package it replaces.
    packages: std.AutoArrayHashMapUnmanaged([32]u8, PackageWrite) = .empty,
    /// Why the store refused (with error.Unsupported).
    why: []const u8 = "",
    status: types.ExecutionStatus = .Success,

    pub fn init(arena: Allocator, cfg: *const protocol.ProtocolConfig, epoch: u64, tx_digest: [32]u8) Store {
        return .{ .arena = arena, .cfg = cfg, .epoch = epoch, .tx_digest = tx_digest };
    }

    /// An input object (`InputObjects`): raises the lamport timestamp (Move objects only) and
    /// adds its previous transaction as a dependency. `.mutable`: an exclusive mutable input
    /// (`exclusive_mutable_inputs`); `.non_exclusive`: a shared non-exclusive write, whose
    /// write must leave it unchanged and is then dropped (`record_execution_results`).
    pub fn addInput(s: *Store, raw: []const u8, access: Access) Error!void {
        const v = ObjectView.parse(raw) catch return error.InvariantViolation;
        const owner = v.ownerBytes();
        const shared = owner.len > 0 and owner[0] == 2;
        if (!v.is_package) s.max_version = @max(s.max_version, v.version);
        try s.deps.append(s.arena, raw[v.prev_tx_at + 1 ..][0..32].*);
        try s.inputs.put(s.arena, v.id, .{ .view = v, .access = access, .shared = shared });
    }

    /// A package named by a command (`Command::input_objects`): a dependency only.
    pub fn addPackageDependency(s: *Store, raw: []const u8) Error!void {
        // A package is owned Immutable, so its object ends `.. 03 | 20 prev_tx[32] | rebate u64`;
        // no need to walk its modules to find the previous transaction.
        if (raw.len > 1 + 42 and raw[0] == 1 and raw[raw.len - 42] == 3 and raw[raw.len - 41] == 32) {
            try s.deps.append(s.arena, raw[raw.len - 40 ..][0..32].*);
            return;
        }
        const v = ObjectView.parse(raw) catch return error.InvariantViolation;
        try s.deps.append(s.arena, raw[v.prev_tx_at + 1 ..][0..32].*);
    }

    pub fn input(s: *const Store, id: *const [32]u8) ?*const ObjectView {
        const i = s.inputs.getPtr(id.*) orelse return null;
        return &i.view;
    }

    /// `save_loaded_runtime_objects`: a child object read during execution, as read.
    pub fn loadedChild(s: *Store, raw: []const u8) Error!void {
        const v = ObjectView.parse(raw) catch return error.InvariantViolation;
        try s.loaded.put(s.arena, v.id, Meta.of(&v));
    }

    /// A written object. `modified`: the id existed before (input or loaded child);
    /// `created`: a new id.
    pub fn write(s: *Store, w: Write, how: enum { modified, created, unwrapped }) Error!void {
        try s.written.put(s.arena, w.id, w);
        switch (how) {
            .modified => try s.modified.put(s.arena, w.id, {}),
            .created => try s.created.put(s.arena, w.id, {}),
            .unwrapped => {},
        }
    }

    /// `DeleteKind::UnwrapThenDelete`: an object that was wrapped before the transaction and is
    /// deleted by it (no input state).
    pub fn unwrapDelete(s: *Store, id: [32]u8) Error!void {
        try s.deleted.put(s.arena, id, {});
    }

    /// `DeleteKind::Wrap`: an object that existed before (input or loaded child) and is now
    /// wrapped: modified, neither written nor deleted.
    pub fn wrap(s: *Store, id: [32]u8) Error!void {
        try s.modified.put(s.arena, id, {});
    }

    /// `upgrade_system_package`: modified, written. `new` is the final object; `old` the
    /// package object it replaces.
    pub fn upgradePackage(s: *Store, id: [32]u8, new: []const u8, old: []const u8) Error!void {
        try s.packages.put(s.arena, id, .{ .bytes = new, .old = old });
        try s.modified.put(s.arena, id, {});
    }

    /// A package published by the transaction (`Publish` in system mode): created, written.
    pub fn createPackage(s: *Store, id: [32]u8, bytes: []const u8) Error!void {
        try s.packages.put(s.arena, id, .{ .bytes = bytes, .old = null });
        try s.created.put(s.arena, id, {});
    }

    /// A deleted object that existed before the transaction.
    pub fn delete(s: *Store, id: [32]u8) Error!void {
        try s.modified.put(s.arena, id, {});
        try s.deleted.put(s.arena, id, {});
    }

    /// The written object as an input write (header, contents and owner of the input).
    pub fn inputAsWrite(v: *const ObjectView) Write {
        return .{ .id = v.id, .header = v.raw[0..v.version_at], .contents = v.contents(), .owner = v.ownerBytes() };
    }

    /// `get_object_modified_at`: the metadata of a modified id (mutable input, else loaded child).
    fn modifiedAt(s: *const Store, id: *const [32]u8) ?Meta {
        if (!s.modified.contains(id.*)) return null;
        if (s.inputs.getPtr(id.*)) |i| if (i.access == .mutable) return Meta.of(&i.view);
        if (s.loaded.get(id.*)) |m| return m;
        if (s.packages.get(id.*)) |p| {
            const v = ObjectView.parse(p.old orelse return null) catch return null;
            return Meta.of(&v);
        }
        return null;
    }

    fn unsupported(s: *Store, why: []const u8) Error {
        s.why = why;
        return error.Unsupported;
    }

    /// Unmetered gas charge and effects V2 (`execute_transaction` tail through `into_effects`).
    pub fn intoEffects(s: *Store, events: ?[]const u8) Error!Output {
        return s.intoEffectsWith(events, .Success);
    }

    /// A failed system transaction (`GasCharger::handle_error`, Unmetered): every write,
    /// creation, deletion, loaded child and event of the execution is dropped (`reset` ->
    /// `drop_writes`), the mutable inputs are still bumped (`ensure_active_inputs_mutated`) and
    /// their rebates go to 0x5 as usual; the effects carry `status`.
    pub fn intoFailure(s: *Store, status: types.ExecutionStatus) Error!Output {
        s.written.clearRetainingCapacity();
        s.modified.clearRetainingCapacity();
        s.created.clearRetainingCapacity();
        s.deleted.clearRetainingCapacity();
        s.loaded.clearRetainingCapacity();
        s.packages.clearRetainingCapacity();
        return s.intoEffectsWith(null, status);
    }

    fn intoEffectsWith(s: *Store, events: ?[]const u8, status: types.ExecutionStatus) Error!Output {
        const a = s.arena;
        s.status = status;

        // record_execution_results: a non-exclusive write input must be written back unchanged
        // (data and owner); its write is dropped.
        for (s.inputs.keys(), s.inputs.values()) |id, *i| if (i.access == .non_exclusive) {
            const w = s.written.getPtr(id) orelse return s.unsupported("non-exclusive write input deleted (NonExclusiveWriteInputObjectModified)");
            if (!std.mem.eql(u8, w.header, i.view.raw[0..i.view.version_at]) or !std.mem.eql(u8, w.contents, i.view.contents()) or !std.mem.eql(u8, w.owner, i.view.ownerBytes()))
                return s.unsupported("non-exclusive write input modified (NonExclusiveWriteInputObjectModified)");
            _ = s.written.orderedRemove(id);
            _ = s.modified.orderedRemove(id);
        };
        // meter_storage (Unmetered): ensure_active_inputs_mutated.
        for (s.inputs.keys(), s.inputs.values()) |id, *i| if (i.access == .mutable and !s.modified.contains(id)) {
            try s.write(inputAsWrite(&i.view), .modified);
        };
        // collect_storage_and_rebate: every written object's previous rebate, then every
        // modified id that is not written (deleted); unmetered, new rebates are 0.
        var unmetered: u64 = 0;
        for (s.written.keys(), s.written.values()) |id, *w| {
            const old = if (s.modifiedAt(&id)) |m| m.rebate else 0;
            unmetered = std.math.add(u64, unmetered, old) catch return error.InvariantViolation;
            w.rebate = 0;
        }
        for (s.packages.values()) |*p| if (p.old) |old_raw| {
            const old = ObjectView.parse(old_raw) catch return error.InvariantViolation;
            unmetered = std.math.add(u64, unmetered, old.storageRebate()) catch return error.InvariantViolation;
        };
        for (s.modified.keys()) |id| if (!s.written.contains(id) and !s.packages.contains(id)) {
            const m = s.modifiedAt(&id) orelse return error.InvariantViolation;
            unmetered = std.math.add(u64, unmetered, m.rebate) catch return error.InvariantViolation;
        };
        // charge (Unmetered): conserve_unmetered_storage_rebate.
        if (unmetered != 0) {
            const w = s.written.getPtr(system_state_id) orelse blk: {
                const i = s.inputs.getPtr(system_state_id) orelse return s.unsupported("unmetered storage rebate without 0x5 among the inputs (Rust panics)");
                try s.write(inputAsWrite(&i.view), .modified);
                break :blk s.written.getPtr(system_state_id).?;
            };
            if (w.rebate != 0) return error.InvariantViolation;
            w.rebate = unmetered;
            try s.modified.put(a, system_state_id, {});
        }

        // update_version_and_previous_tx.
        const lamport = s.max_version + 1;
        for (s.written.keys(), s.written.values()) |id, *w| {
            var owner = w.owner;
            if (owner.len == 9 and owner[0] == 2) {
                var o = try a.dupe(u8, owner);
                if (s.created.contains(id)) {
                    std.mem.writeInt(u64, o[1..9], lamport, .little);
                } else if (s.cfg.feature_flags.reshare_at_same_initial_version) {
                    if (s.inputs.getPtr(id)) |i| {
                        const io = i.view.ownerBytes();
                        if (io.len == 9 and io[0] == 2) @memcpy(o[1..9], io[1..9]);
                    }
                }
                owner = o;
                w.owner = o;
            }
            w.bytes = try objectBytes(a, w, lamport, &s.tx_digest);
        }

        // Dependencies: sorted set of the inputs' previous transactions minus the genesis marker.
        var deps: std.ArrayList(types.TransactionDigest) = .empty;
        if (!s.cfg.feature_flags.disable_effects_tx_dependencies) {
            std.mem.sort([32]u8, s.deps.items, {}, lessBytes);
            for (s.deps.items, 0..) |d, k| {
                if (std.mem.eql(u8, &d, &zero32)) continue;
                if (k > 0 and std.mem.eql(u8, &s.deps.items[k - 1], &d)) continue;
                try deps.append(a, .{ .@"0" = .{ .@"0" = d } });
            }
        }

        if (!s.cfg.feature_flags.enable_effects_v2) return s.effectsV1(events, lamport, deps.items);

        // get_object_changes: every created, deleted, modified or written id, in id order.
        var ids: std.ArrayList([32]u8) = .empty;
        for (s.created.keys()) |id| try ids.append(a, id);
        for (s.deleted.keys()) |id| try ids.append(a, id);
        for (s.modified.keys()) |id| try ids.append(a, id);
        for (s.written.keys()) |id| try ids.append(a, id);
        std.mem.sort([32]u8, ids.items, {}, lessBytes);
        const Change = @typeInfo(@FieldType(types.TransactionEffectsV2, "changed_objects")).pointer.child;
        var changes: std.ArrayList(Change) = .empty;
        for (ids.items, 0..) |id, k| {
            if (k > 0 and std.mem.eql(u8, &ids.items[k - 1], &id)) continue;
            const in: types.ObjectIn = if (s.modifiedAt(&id)) |m|
                .{ .Exist = .{ .{ .{ .@"0" = m.version }, .{ .@"0" = .{ .@"0" = types.digest.objectDigest(m.raw) } } }, try decodeOwner(a, m.owner) } }
            else
                .NotExist;
            const out: types.ObjectOut = if (s.written.getPtr(id)) |w|
                .{ .ObjectWrite = .{ .{ .@"0" = .{ .@"0" = types.digest.objectDigest(w.bytes) } }, try decodeOwner(a, w.owner) } }
            else if (s.packages.get(id)) |p|
                .{ .PackageWrite = .{ .{ .@"0" = std.mem.readInt(u64, p.bytes[33..41], .little) }, .{ .@"0" = .{ .@"0" = types.digest.objectDigest(p.bytes) } } } }
            else
                .NotExist;
            const op: types.IDOperation = if (s.created.contains(id)) .Created else if (s.deleted.contains(id)) .Deleted else .None;
            try changes.append(a, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .input_state = in, .output_state = out, .id_operation = op } });
        }

        // compute_unchanged_consensus_objects: shared inputs that did not change (read-only).
        const Unchanged = @typeInfo(@FieldType(types.TransactionEffectsV2, "unchanged_consensus_objects")).pointer.child;
        var unchanged: std.ArrayList(Unchanged) = .empty;
        for (s.inputs.keys(), s.inputs.values()) |id, *i| if (i.shared) {
            var changed = false;
            for (changes.items) |c| if (std.mem.eql(u8, &c[0].@"0".@"0", &id)) {
                changed = true;
                break;
            };
            if (!changed) try unchanged.append(a, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = i.view.version }, .{ .@"0" = .{ .@"0" = i.view.digest() } } } } });
        };

        const fx: types.TransactionEffects = .{ .V2 = .{
            .status = s.status,
            .executed_epoch = s.epoch,
            .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
            .transaction_digest = .{ .@"0" = .{ .@"0" = s.tx_digest } },
            .gas_object_index = null,
            .events_digest = if (events) |e| .{ .@"0" = .{ .@"0" = types.digest.eventsDigest(e) } } else null,
            .dependencies = deps.items,
            .lamport_version = .{ .@"0" = lamport },
            .changed_objects = changes.items,
            .unchanged_consensus_objects = unchanged.items,
            .aux_data_digest = null,
        } };
        const written = try a.alloc(Written, s.written.count() + s.packages.count());
        for (s.written.values(), written[0..s.written.count()]) |w, *o| o.* = .{ .id = w.id, .bytes = w.bytes };
        for (s.packages.keys(), s.packages.values(), written[s.written.count()..]) |id, p, *o| o.* = .{ .id = id, .bytes = p.bytes };
        return .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, a, &fx), .events = events, .written = written };
    }

    /// Effects V1 (execution versions 0 to 2 without effects V2: `TemporaryStore::to_effects`,
    /// `TransactionEffects::new_from_execution_v1`). The written map and the deleted map are
    /// BTreeMaps, so every list is in id order:
    ///   modified_at_versions: every Mutate write (its version before the transaction), then
    ///   every Normal or Wrap deletion (its old version);
    ///   created / mutated / unwrapped: the written objects by WriteKind;
    ///   deleted / unwrapped_then_deleted / wrapped: (id, lamport, the deleted or wrapped digest);
    ///   shared_objects: the shared inputs as read, in input order;
    ///   gas_object: none (system transactions): (0x0, 0, ObjectDigest::MIN), AddressOwner(0x0).
    fn effectsV1(s: *Store, events: ?[]const u8, lamport: u64, deps: []const types.TransactionDigest) Error!Output {
        const a = s.arena;
        // Every written id (Move objects and system packages), in id order.
        var wids: std.ArrayList([32]u8) = .empty;
        for (s.written.keys()) |id| try wids.append(a, id);
        for (s.packages.keys()) |id| try wids.append(a, id);
        std.mem.sort([32]u8, wids.items, {}, lessId);
        var dids: std.ArrayList([32]u8) = .empty;
        for (s.modified.keys()) |id| if (!s.written.contains(id) and !s.packages.contains(id)) try dids.append(a, id);
        for (s.deleted.keys()) |id| if (!s.modified.contains(id)) try dids.append(a, id);
        std.mem.sort([32]u8, dids.items, {}, lessId);

        var mav: std.ArrayList(@typeInfo(@FieldType(types.TransactionEffectsV1, "modified_at_versions")).pointer.child) = .empty;
        var created: std.ArrayList(RefOwner) = .empty;
        var mutated: std.ArrayList(RefOwner) = .empty;
        var unwrapped: std.ArrayList(RefOwner) = .empty;
        for (wids.items) |id| {
            const bytes, const owner_raw, const version = if (s.written.getPtr(id)) |w|
                .{ w.bytes, w.owner, lamport }
            else blk: {
                const p = s.packages.get(id).?;
                break :blk .{ p.bytes, &[_]u8{3}, std.mem.readInt(u64, p.bytes[33..41], .little) };
            };
            const ro: RefOwner = .{ refOf(id, version, types.digest.objectDigest(bytes)), try decodeOwner(a, owner_raw) };
            if (s.modified.contains(id)) {
                const m = s.modifiedAt(&id) orelse return error.InvariantViolation;
                try mav.append(a, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = m.version } });
                try mutated.append(a, ro);
            } else if (s.created.contains(id)) {
                try created.append(a, ro);
            } else {
                try unwrapped.append(a, ro);
            }
        }
        var deleted: std.ArrayList(Ref) = .empty;
        var unwrapped_then_deleted: std.ArrayList(Ref) = .empty;
        var wrapped: std.ArrayList(Ref) = .empty;
        for (dids.items) |id| {
            if (s.modified.contains(id)) {
                const m = s.modifiedAt(&id) orelse return error.InvariantViolation;
                try mav.append(a, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = m.version } });
                if (s.deleted.contains(id)) {
                    try deleted.append(a, refOf(id, lamport, @splat(99)));
                } else {
                    try wrapped.append(a, refOf(id, lamport, @splat(88)));
                }
            } else {
                try unwrapped_then_deleted.append(a, refOf(id, lamport, @splat(99)));
            }
        }
        var shared: std.ArrayList(Ref) = .empty;
        for (s.inputs.keys(), s.inputs.values()) |id, *i| if (i.shared) {
            try shared.append(a, refOf(id, i.view.version, i.view.digest()));
        };
        const fx: types.TransactionEffects = .{ .V1 = .{
            .status = s.status,
            .executed_epoch = s.epoch,
            .gas_used = .{ .computationCost = 0, .storageCost = 0, .storageRebate = 0, .nonRefundableStorageFee = 0 },
            .modified_at_versions = mav.items,
            .shared_objects = shared.items,
            .transaction_digest = .{ .@"0" = .{ .@"0" = s.tx_digest } },
            .created = created.items,
            .mutated = mutated.items,
            .unwrapped = unwrapped.items,
            .deleted = deleted.items,
            .unwrapped_then_deleted = unwrapped_then_deleted.items,
            .wrapped = wrapped.items,
            .gas_object = .{ refOf(zero32, 0, zero32), .{ .AddressOwner = .{ .@"0" = zero32 } } },
            .events_digest = if (events) |e| .{ .@"0" = .{ .@"0" = types.digest.eventsDigest(e) } } else null,
            .dependencies = deps,
        } };
        const written = try a.alloc(Written, s.written.count() + s.packages.count());
        for (s.written.values(), written[0..s.written.count()]) |w, *o| o.* = .{ .id = w.id, .bytes = w.bytes };
        for (s.packages.keys(), s.packages.values(), written[s.written.count()..]) |id, p, *o| o.* = .{ .id = id, .bytes = p.bytes };
        return .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, a, &fx), .events = events, .written = written };
    }
};

const Ref = struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest };
const RefOwner = struct { Ref, types.Owner };

fn refOf(id: [32]u8, version: u64, digest: [32]u8) Ref {
    return .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = digest } } };
}

fn lessId(_: void, x: [32]u8, y: [32]u8) bool {
    return std.mem.order(u8, &x, &y) == .lt;
}

fn lessBytes(_: void, x: [32]u8, y: [32]u8) bool {
    return std.mem.order(u8, &x, &y) == .lt;
}

fn decodeOwner(a: Allocator, raw: []const u8) Error!types.Owner {
    return bcs.decode(types.Owner, a, raw) catch error.InvariantViolation;
}

/// `Object { Data::Move(MoveObject { .., version, contents }), owner, previous_transaction,
/// storage_rebate }`.
pub fn objectBytes(a: Allocator, w: *const Write, version: u64, prev_tx: *const [32]u8) Error![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.ensureTotalCapacity(a, w.header.len + 8 + 5 + w.contents.len + w.owner.len + 33 + 8);
    buf.appendSliceAssumeCapacity(w.header);
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, version, .little);
    buf.appendSliceAssumeCapacity(&v8);
    var n = w.contents.len;
    while (true) {
        const b: u8 = @intCast(n & 0x7f);
        n >>= 7;
        if (n == 0) {
            buf.appendAssumeCapacity(b);
            break;
        }
        buf.appendAssumeCapacity(b | 0x80);
    }
    buf.appendSliceAssumeCapacity(w.contents);
    buf.appendSliceAssumeCapacity(w.owner);
    buf.appendAssumeCapacity(32);
    buf.appendSliceAssumeCapacity(prev_tx);
    std.mem.writeInt(u64, &v8, w.rebate, .little);
    buf.appendSliceAssumeCapacity(&v8);
    return buf.items;
}

// ---- tests ----------------------------------------------------------------------------------

const testing = std.testing;
const test_digest: [32]u8 = @splat(0x77);

fn testObject(a: Allocator, id: [32]u8, version: u64, owner: []const u8, rebate: u64, contents_tail: []const u8) ![]const u8 {
    // Data::Move of an `Other` struct type 0x2::m::T, has_public_transfer false.
    var header: std.ArrayList(u8) = .empty;
    try header.append(a, 0);
    const mot: types.MoveObjectType = .{ .@"0" = .{ .Other = .{ .address = .{ .@"0" = blk: {
        var x: [32]u8 = @splat(0);
        x[31] = 2;
        break :blk x;
    } }, .module = .{ .@"0" = "m" }, .name = .{ .@"0" = "T" }, .type_args = &.{} } } };
    try header.appendSlice(a, try bcs.encodeAlloc(types.MoveObjectType, a, &mot));
    try header.append(a, 0);
    const contents = try std.mem.concat(a, u8, &.{ &id, contents_tail });
    return objectBytes(a, &.{ .id = id, .header = header.items, .contents = contents, .owner = owner, .rebate = rebate }, version, &@as([32]u8, @splat(0x11)));
}

fn sharedOwner(a: Allocator, initial: u64) ![]const u8 {
    const o = try a.alloc(u8, 9);
    o[0] = 2;
    std.mem.writeInt(u64, o[1..9], initial, .little);
    return o;
}

fn idOf(n: u8) [32]u8 {
    var x: [32]u8 = @splat(0);
    x[31] = n;
    return x;
}

test "store: a failed system call drops every write and still bumps the mutable inputs" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const cfg = try protocol.get(protocol.max_protocol_version, .mainnet);
    var s = Store.init(a, cfg, 9, test_digest);
    const rnd = try testObject(a, idOf(8), 40, try sharedOwner(a, 3), 0, &.{ 1, 2, 3 });
    try s.addInput(rnd, .mutable);
    // What the call did before aborting (Rust drops it in `reset`).
    var w = Store.inputAsWrite(s.input(&idOf(8)).?);
    w.contents = try std.mem.concat(a, u8, &.{ &idOf(8), &[_]u8{ 9, 9, 9 } });
    try s.write(w, .modified);
    try s.write(.{ .id = idOf(0x44), .header = w.header, .contents = try std.mem.concat(a, u8, &.{ &idOf(0x44), &[_]u8{0} }), .owner = w.owner }, .created);
    const status: types.ExecutionStatus = .{ .Failure = .{ .@"error" = .{ .MoveAbort = .{ .{
        .module = .{ .address = .{ .@"0" = idOf(2) }, .name = .{ .@"0" = "random" } },
        .function = 3,
        .instruction = 17,
        .function_name = .{ .@"0" = "update_randomness_state" },
    }, 5 } }, .command = 0 } };
    const out = try s.intoFailure(status);
    try testing.expect(out.events == null);
    try testing.expectEqual(@as(usize, 1), out.written.len);
    const fx = (try bcs.decode(types.TransactionEffects, a, out.effects)).V2;
    try testing.expect(fx.status == .Failure);
    try testing.expectEqual(@as(?u64, 0), fx.status.Failure.command);
    try testing.expectEqual(@as(u64, 5), fx.status.Failure.@"error".MoveAbort[1]);
    try testing.expectEqual(@as(u64, 41), fx.lamport_version.@"0");
    try testing.expectEqual(@as(usize, 1), fx.changed_objects.len);
    // The input is written back unchanged at the lamport version (its contents are the input's).
    const v = try ObjectView.parse(out.written[0].bytes);
    try testing.expectEqual(@as(u64, 41), v.version);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, v.contents()[32..]);
    try testing.expect(fx.changed_objects[0][1].id_operation == .None);
}

test "store: write kinds (created, unwrapped, wrapped, unwrap then delete) in effects V2 and V1" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    inline for (.{ protocol.max_protocol_version, 30 }) |pv| {
        const cfg = try protocol.get(pv, .mainnet);
        var s = Store.init(a, cfg, 9, test_digest);
        const owner5 = try sharedOwner(a, 1);
        try s.addInput(try testObject(a, idOf(5), 100, owner5, 0, &.{}), .mutable);
        // A loaded child (owned by 0x5) that ends wrapped, another that is deleted.
        const child_owner = [_]u8{1} ++ idOf(5);
        try s.loadedChild(try testObject(a, idOf(0x21), 60, &child_owner, 7, &.{}));
        try s.loadedChild(try testObject(a, idOf(0x22), 61, &child_owner, 3, &.{}));
        try s.wrap(idOf(0x21));
        try s.delete(idOf(0x22));
        // An object unwrapped and written; one unwrapped and deleted; one created.
        const hdr = Store.inputAsWrite(s.input(&idOf(5)).?).header;
        try s.write(.{ .id = idOf(0x31), .header = hdr, .contents = try std.mem.concat(a, u8, &.{ &idOf(0x31), &[_]u8{1} }), .owner = &child_owner }, .unwrapped);
        try s.unwrapDelete(idOf(0x32));
        try s.write(.{ .id = idOf(0x33), .header = hdr, .contents = &idOf(0x33), .owner = &child_owner }, .created);
        const out = try s.intoEffects(null);
        const fx = try bcs.decode(types.TransactionEffects, a, out.effects);
        switch (fx) {
            .V2 => |e| {
                try testing.expect(pv >= 33);
                for (e.changed_objects) |c| {
                    const n = c[0].@"0".@"0"[31];
                    const ch = c[1];
                    switch (n) {
                        0x21 => try testing.expect(ch.input_state == .Exist and ch.output_state == .NotExist and ch.id_operation == .None),
                        0x22 => try testing.expect(ch.input_state == .Exist and ch.output_state == .NotExist and ch.id_operation == .Deleted),
                        0x31 => try testing.expect(ch.input_state == .NotExist and ch.output_state == .ObjectWrite and ch.id_operation == .None),
                        0x32 => try testing.expect(ch.input_state == .NotExist and ch.output_state == .NotExist and ch.id_operation == .Deleted),
                        0x33 => try testing.expect(ch.input_state == .NotExist and ch.output_state == .ObjectWrite and ch.id_operation == .Created),
                        5 => try testing.expect(ch.id_operation == .None and ch.output_state == .ObjectWrite),
                        else => return error.TestUnexpectedResult,
                    }
                }
                try testing.expectEqual(@as(usize, 6), e.changed_objects.len);
            },
            .V1 => |e| {
                try testing.expect(pv < 33);
                try testing.expectEqual(@as(usize, 1), e.created.len);
                try testing.expectEqual(@as(u8, 0x33), e.created[0][0][0].@"0".@"0"[31]);
                try testing.expectEqual(@as(usize, 1), e.unwrapped.len);
                try testing.expectEqual(@as(usize, 1), e.mutated.len); // 0x5, with the rebates
                try testing.expectEqual(@as(usize, 1), e.deleted.len);
                try testing.expectEqual(@as(usize, 1), e.unwrapped_then_deleted.len);
                try testing.expectEqual(@as(usize, 1), e.wrapped.len);
                try testing.expectEqual(@as(u8, 88), e.wrapped[0][2].@"0".@"0"[0]);
                // modified_at_versions: the Mutate writes, then the Normal and Wrap deletions.
                try testing.expectEqual(@as(usize, 3), e.modified_at_versions.len);
                try testing.expectEqual(@as(u64, 100), e.modified_at_versions[0][1].@"0");
                try testing.expectEqual(@as(u64, 60), e.modified_at_versions[1][1].@"0");
                try testing.expectEqual(@as(u64, 61), e.modified_at_versions[2][1].@"0");
                try testing.expectEqual(@as(usize, 1), e.shared_objects.len);
                // 0x5 receives the rebates of the wrapped and the deleted child.
                const w5 = for (out.written) |w| {
                    if (w.id[31] == 5) break w.bytes;
                } else return error.TestUnexpectedResult;
                try testing.expectEqual(@as(u64, 10), (try ObjectView.parse(w5)).storageRebate());
            },
        }
    }
}
