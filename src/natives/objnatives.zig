//! Natives over the object runtime (sui-move-natives latest, mainnet-v1.83.1): object,
//! transfer, event, dynamic_field (child objects), accumulator, accumulator_settlement,
//! funds_accumulator, config, package and scratch. Charges, aborts and VM errors follow the Rust
//! natives line by line; the runtime itself is objrt.zig.
const std = @import("std");
const types = @import("types");
const abi = @import("abi.zig");
const objrt = @import("objrt.zig");

const Ctx = abi.Ctx;
const Value = abi.Value;
const Layout = abi.Layout;
const TyArg = abi.TyArg;
const Outcome = abi.Outcome;
const Error = abi.Error;
const TypeTag = abi.TypeTag;
const Id = objrt.Id;

inline fn rt(c: *Ctx) *objrt.ObjectRuntime {
    return c.rt;
}

/// `context.type_to_type_tag(ty)` must be a struct ("Sui verifier guarantees this is a struct").
fn structTag(t: TyArg) ?*const TypeTag {
    return if (t.tag.* == .@"struct") t.tag else null;
}

fn sizeOf(v: *const Value, l: *const Layout) u64 {
    return abi.abstractSize(v, l, .{ .include_vector_size = true });
}

// ---- object ---------------------------------------------------------------------------------

pub fn borrow_uid(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("object_borrow_uid_cost_base"))) return c.oog();
    // obj.borrow_field(0): a reference to the object's first field
    return c.okRef(@constCast(&args[0].@"struct"[0]));
}

pub fn delete_impl(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("object_delete_impl_cost_base"))) return c.oog();
    if (try rt(c).deleteId(c.arena, c.cfg, args[0].address)) |e| return Ctx.vmErr(e);
    return c.ok0();
}

pub fn record_new_uid(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("object_record_new_uid_cost_base"))) return c.oog();
    if (try rt(c).newId(c.arena, c.cfg, args[0].address)) |e| return Ctx.vmErr(e);
    return c.ok0();
}

pub fn record_new_uid_from_hash(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("object_record_new_uid_from_hash_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    if (try rt(c).newIdFromHash(c.arena, c.cfg, args[0].address, args[1].address)) |e| return Ctx.vmErr(e);
    return c.ok0();
}

/// v142 `object::is_shared_input_impl(id)`: whether `id` is a shared input of the transaction.
pub fn is_shared_input_impl(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("object_is_shared_input_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const owner = rt(c).inputOwner(&args[0].address);
    return c.ok1(.{ .bool = owner != null and owner.? == .shared });
}

// ---- clock ----------------------------------------------------------------------------------

/// v142 `clock::native_borrow(): &Clock`: a reference to the transaction's Clock, read
/// implicitly (no Clock input needed) at its assigned version.
pub fn clock_native_borrow(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    const base = c.popt("clock_borrow_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    return switch (try rt(c).borrowClock(c.arena)) {
        .err => |e| Ctx.vmErr(e),
        .ok => |v| c.okRef(v),
    };
}

// ---- transfer -------------------------------------------------------------------------------

const E_SHARED_NON_NEW_OBJECT: u64 = 0;
const E_BCS_SERIALIZATION_FAILURE_T: u64 = 1;
const E_RECEIVING_OBJECT_TYPE_MISMATCH: u64 = 2;
const E_UNABLE_TO_RECEIVE_OBJECT: u64 = 3;
const E_NOT_SUPPORTED_T: u64 = 5;

fn doTransfer(c: *Ctx, owner: objrt.Owner, t: TyArg, obj: Value) Error!objrt.Res(objrt.TransferResult) {
    const tag = structTag(t) orelse return .{ .err = .{ .status = .UNKNOWN_INVARIANT_VIOLATION_ERROR } };
    return rt(c).transfer(c.arena, c.cfg, owner, tag, obj, false);
}

pub fn transfer_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("transfer_transfer_internal_cost_base"))) return c.oog();
    return switch (try doTransfer(c, .{ .address = args[1].address }, tys[0], args[0])) {
        .err => |e| Ctx.vmErr(e),
        .ok => c.ok0(),
    };
}

pub fn party_transfer_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const ALL: u64 = 0b1111;
    if (!c.flag("enable_party_transfer")) return c.abort(E_NOT_SUPPORTED_T);
    const base = c.popt("transfer_party_transfer_internal_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const permissions = try args[3].items(c.arena);
    const addresses = try args[2].items(c.arena);
    const default_permissions = args[1].u64;
    if (permissions.len != 1) return Ctx.invariant();
    if (permissions[0].u64 != ALL or default_permissions != 0) return Ctx.invariant();
    if (addresses.len != 1) return Ctx.invariant();
    const owner: objrt.Owner = .{ .consensus = .{ .start = 0, .owner = addresses[0].address } };
    return switch (try doTransfer(c, owner, tys[0], args[0])) {
        .err => |e| Ctx.vmErr(e),
        .ok => c.ok0(),
    };
}

pub fn freeze_object_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("transfer_freeze_object_cost_base"))) return c.oog();
    return switch (try doTransfer(c, .immutable, tys[0], args[0])) {
        .err => |e| Ctx.vmErr(e),
        .ok => c.ok0(),
    };
}

pub fn share_object_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("transfer_share_object_cost_base"))) return c.oog();
    return switch (try doTransfer(c, .{ .shared = 0 }, tys[0], args[0])) {
        .err => |e| Ctx.vmErr(e),
        .ok => |r| if (r == .owner_changed) c.abort(E_SHARED_NON_NEW_OBJECT) else c.ok0(),
    };
}

pub fn receive_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("transfer_receive_object_cost_base"))) return c.oog();
    const t = tys[0];
    if (!c.charge(c.p("transfer_receive_object_type_cost_per_byte") *| abi.typeSize(t.tag))) return c.oog();
    const version = args[2].u64;
    const child_id = args[1].@"struct"[0].address;
    const parent = args[0].address;
    const tag = structTag(t) orelse return Ctx.invariant();
    const layout = t.layout orelse return c.abort(E_BCS_SERIALIZATION_FAILURE_T);
    const ann = t.annotated orelse return c.abort(E_BCS_SERIALIZATION_FAILURE_T);
    const v = switch (try rt(c).receiveObject(c.arena, c.cfg, parent, child_id, version, layout, ann, tag)) {
        .err => |e| return Ctx.vmErr(e),
        .none => return c.abort(E_UNABLE_TO_RECEIVE_OBJECT),
        .mismatched => return c.abort(E_RECEIVING_OBJECT_TYPE_MISMATCH),
        .loaded => |v| v,
    };
    if (!c.charge(c.p("transfer_receive_object_cost_per_byte") *| sizeOf(&v, layout))) return c.oog();
    return c.ok1(v);
}

// ---- event ----------------------------------------------------------------------------------

const StreamRef = struct { accumulator_id: Id, stream_id: Id, head: TyArg };

fn emitImpl(c: *Ctx, t: TyArg, ev: Value, stream: ?StreamRef) Error!Outcome {
    if (!c.charge(c.p("event_emit_cost_base"))) return c.oog();
    const walk = t.traversal() orelse return Ctx.invariant();
    const value_size = abi.objectRuntimeSize(c.cfg, &ev, walk); // exec-history-vm: legacy before 104
    if (!c.charge(c.p("event_emit_value_size_derivation_cost_per_byte") *| value_size)) return c.oog();
    const tag = structTag(t) orelse return Ctx.invariant();
    const tag_size = abi.structAbstractSize(&tag.@"struct");
    if (!c.charge(c.p("event_emit_tag_size_derivation_cost_per_byte") *| tag_size)) return c.oog();
    if (stream != null) {
        const auth = c.popt("event_emit_auth_stream_cost") orelse return Ctx.invariant();
        if (!c.charge(auth)) return c.oog();
    }
    const ev_size = tag_size +| value_size;
    if (ev_size > c.p("max_event_emit_size")) return Ctx.vmErr(.{ .status = .MEMORY_LIMIT_EXCEEDED, .sub = objrt.Mem.EVENT_SIZE });
    if (c.popt("max_event_emit_size_total")) |total_max| {
        const total = rt(c).total_events_size +| ev_size;
        if (total > total_max) return Ctx.vmErr(.{ .status = .MEMORY_LIMIT_EXCEEDED, .sub = objrt.Mem.TOTAL_EVENT_SIZE });
        rt(c).total_events_size = total;
    }
    if (!c.charge(c.p("event_emit_output_cost_per_byte") *| ev_size)) return c.oog();
    if (try rt(c).emitEvent(c.arena, c.cfg, tag, ev)) |e| return Ctx.vmErr(e);
    if (stream) |s| {
        if (rt(c).total_events_emitted == 0) return Ctx.invariant();
        const idx = rt(c).total_events_emitted - 1;
        if (try rt(c).emitAccumulatorEvent(c.arena, c.cfg, s.accumulator_id, .merge, s.stream_id, s.head.tag, .{ .event_ref = idx })) |e| return Ctx.vmErr(e);
    }
    return c.ok0();
}

pub fn emit(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    return emitImpl(c, tys[0], args[0], null);
}

pub fn emit_authenticated_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.flag("enable_authenticated_event_streams")) return c.abort(0); // NOT_SUPPORTED
    return emitImpl(c, tys[1], args[2], .{ .accumulator_id = args[0].address, .stream_id = args[1].address, .head = tys[0] });
}

// ---- dynamic_field --------------------------------------------------------------------------

const E_KEY_DOES_NOT_EXIST: u64 = 1;
const E_FIELD_TYPE_MISMATCH: u64 = 2;
const E_BCS_SERIALIZATION_FAILURE: u64 = 3;
const PRE_EXISTING_ABSTRACT_SIZE: u64 = 2;
const BORROW_ABSTRACT_SIZE: u64 = 8;
const REFERENCE_SIZE: u64 = 8;

/// `charge_cache_or_load_gas!`
fn chargeCacheOrLoad(c: *Ctx, info: objrt.CacheInfo) bool {
    switch (info) {
        .cached_object, .cached_value => return true,
        .loaded => |n| {
            if (!c.flag("object_runtime_charge_cache_load_gas")) return true;
            return c.charge(@max(n orelse 0, 1));
        },
    }
}

const Got = union(enum) { out: Outcome, loaded: objrt.Loaded, layout: *const Layout };

/// `get_or_fetch_object!`: charges the type, resolves the layouts and fetches the child.
fn getOrFetch(c: *Ctx, t: TyArg, parent: Id, child: Id, ty_cost_per_byte: u64) Error!struct { Outcome, ?objrt.Loaded, ?*const Layout } {
    if (!c.charge(ty_cost_per_byte *| abi.typeSize(t.tag))) return .{ c.oog(), null, null };
    const tag = structTag(t) orelse return .{ Ctx.invariant(), null, null };
    const layout = t.layout orelse return .{ c.abort(E_BCS_SERIALIZATION_FAILURE), null, null };
    const ann = t.annotated orelse return .{ c.abort(E_BCS_SERIALIZATION_FAILURE), null, null };
    return switch (try rt(c).getOrFetch(c.arena, c.cfg, parent, child, layout, ann, tag)) {
        .err => |e| .{ Ctx.vmErr(e), null, null },
        .mismatched => .{ c.abort(E_FIELD_TYPE_MISMATCH), null, null },
        .loaded => |l| .{ undefined, l, layout },
    };
}

pub fn add_child_object(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("dynamic_field_add_child_object_cost_base"))) return c.oog();
    const child = args[1];
    const parent = args[0].address;
    const t = tys[0];
    // exec-history-vm: before abstract_size_in_object_runtime the child's legacy size.
    const add_size = if (abi.legacyObjectSizes(c.cfg)) abi.legacySize(&child, t.traversal() orelse return Ctx.invariant()) else PRE_EXISTING_ABSTRACT_SIZE;
    if (!c.charge(c.p("dynamic_field_add_child_object_value_cost_per_byte") *| add_size)) return c.oog();
    const child_id = objrt.objectId(&child);
    if (!c.charge(c.p("dynamic_field_add_child_object_type_cost_per_byte") *| abi.typeSize(t.tag))) return c.oog();
    const tag = structTag(t) orelse return Ctx.invariant();
    if (!c.charge(c.p("dynamic_field_add_child_object_struct_tag_cost_per_byte") *| abi.structAbstractSize(&tag.@"struct"))) return c.oog();
    // generate_df_type_layouts: the layout is computed and dropped (None is not an error)
    if (try rt(c).addChild(c.arena, c.cfg, parent, child_id, tag, child)) |e| return Ctx.vmErr(e);
    return c.ok0();
}

fn borrowChild(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("dynamic_field_borrow_child_object_cost_base"))) return c.oog();
    const child_id = args[1].address;
    // parent: &UID -> read_ref -> UID { id: ID { bytes } }
    const parent = args[0].@"struct"[0].@"struct"[0].address;
    const out, const got, const layout = try getOrFetch(c, tys[0], parent, child_id, c.p("dynamic_field_borrow_child_object_type_cost_per_byte"));
    const l = got orelse return out;
    if (!l.child.exists) return c.abort(E_KEY_DOES_NOT_EXIST);
    if (!chargeCacheOrLoad(c, l.info)) return c.oog();
    const size: u64 = if (abi.legacyObjectSizes(c.cfg)) abi.LEGACY_REFERENCE_SIZE else switch (l.info) {
        .cached_value => BORROW_ABSTRACT_SIZE,
        .cached_object, .loaded => REFERENCE_SIZE +| sizeOf(&l.child.value, layout.?),
    };
    if (!c.charge(c.p("dynamic_field_borrow_child_object_child_ref_cost_per_byte") *| size)) return c.oog();
    return c.okRef(&l.child.value);
}

pub fn borrow_child_object(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    return borrowChild(c, tys, args);
}

pub fn borrow_child_object_mut(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    return borrowChild(c, tys, args);
}

pub fn remove_child_object(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("dynamic_field_remove_child_object_cost_base"))) return c.oog();
    const child_id = args[1].address;
    const parent = args[0].address;
    const out, const got, const layout = try getOrFetch(c, tys[0], parent, child_id, c.p("dynamic_field_remove_child_object_type_cost_per_byte"));
    const l = got orelse return out;
    if (!l.child.exists) return c.abort(E_KEY_DOES_NOT_EXIST);
    const v = l.child.value;
    l.child.exists = false;
    if (!chargeCacheOrLoad(c, l.info)) return c.oog();
    const size: u64 = if (abi.legacyObjectSizes(c.cfg)) abi.legacySize(&v, layout.?) else switch (l.info) {
        .cached_value => PRE_EXISTING_ABSTRACT_SIZE,
        .cached_object, .loaded => sizeOf(&v, layout.?),
    };
    if (!c.charge(c.p("dynamic_field_remove_child_object_child_cost_per_byte") *| size)) return c.oog();
    return c.ok1(v);
}

pub fn has_child_object(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("dynamic_field_has_child_object_cost_base"))) return c.oog();
    const child_id = args[1].address;
    const parent = args[0].address;
    const info, const has = switch (try rt(c).childExists(c.arena, c.cfg, parent, child_id)) {
        .err => |e| return Ctx.vmErr(e),
        .ok => |r| r,
    };
    if (!chargeCacheOrLoad(c, info)) return c.oog();
    return c.ok1(.{ .bool = has });
}

pub fn has_child_object_with_ty(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("dynamic_field_has_child_object_with_ty_cost_base"))) return c.oog();
    const child_id = args[1].address;
    const parent = args[0].address;
    const t = tys[0];
    if (!c.charge(c.p("dynamic_field_has_child_object_with_ty_type_cost_per_byte") *| abi.typeSize(t.tag))) return c.oog();
    const tag = structTag(t) orelse return Ctx.invariant();
    if (!c.charge(c.p("dynamic_field_has_child_object_with_ty_type_tag_cost_per_byte") *| abi.structAbstractSize(&tag.@"struct"))) return c.oog();
    const info, const has = switch (try rt(c).childExistsWithType(c.arena, c.cfg, parent, child_id, tag)) {
        .err => |e| return Ctx.vmErr(e),
        .ok => |r| r,
    };
    if (!chargeCacheOrLoad(c, info)) return c.oog();
    return c.ok1(.{ .bool = has });
}

// ---- accumulator, accumulator_settlement, funds_accumulator -----------------------------------

fn accEvent(c: *Ctx, tys: []const TyArg, args: []Value, action: objrt.AccAction) Error!Outcome {
    if (!c.charge(c.p("event_emit_cost_base"))) return c.oog();
    const amount = args[2].u64;
    const recipient = args[1].address;
    const acc = args[0].address;
    if (try rt(c).emitAccumulatorEvent(c.arena, c.cfg, acc, action, recipient, tys[0].tag, .{ .u64 = amount })) |e| return Ctx.vmErr(e);
    return c.ok0();
}

pub fn emit_deposit_event(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    return accEvent(c, tys, args, .merge);
}

pub fn emit_withdraw_event(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    return accEvent(c, tys, args, .split);
}

pub fn record_settlement_sui_conservation(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    rt(c).recordSettlement(args[0].u64, args[1].u64);
    return c.ok0();
}

const E_OVERFLOW: u64 = 0;
const E_ADDRESS_BALANCE_NOT_ENABLED: u64 = 1;
const E_ACCUMULATOR_TYPE_TOO_LARGE: u64 = 4;
const E_OBJECT_FUNDS_INSUFFICIENT: u64 = 5;

/// `TypeTag::node_count`.
fn nodeCount(t: *const TypeTag) u64 {
    return 1 +| switch (t.*) {
        .vector => |e| nodeCount(e),
        .@"struct" => |s| blk: {
            var n: u64 = 0;
            for (s.type_args) |*a| n +|= nodeCount(a);
            break :blk n;
        },
        else => 0,
    };
}

/// `check_accumulator_type_bounds`
fn typeInBounds(c: *const Ctx, t: *const TypeTag) bool {
    const max = c.popt("max_accumulator_type_nodes") orelse return true;
    return nodeCount(t) <= max;
}

pub fn add_to_accumulator_address(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("event_emit_cost_base"))) return c.oog();
    const tag = tys[0].tag;
    if (args[2] != .@"struct") return Ctx.invariant();
    const fields = args[2].@"struct";
    if (fields.len != 1 or fields[0] != .u64) return Ctx.invariant();
    const recipient = args[1].address;
    const acc = args[0].address;
    if (!c.flag("enable_accumulators")) return c.abort(E_ADDRESS_BALANCE_NOT_ENABLED);
    if (!typeInBounds(c, tag)) return c.abort(E_ACCUMULATOR_TYPE_TOO_LARGE);
    if (try rt(c).emitAccumulatorEvent(c.arena, c.cfg, acc, .merge, recipient, tag, .{ .u64 = fields[0].u64 })) |e| return Ctx.vmErr(e);
    return c.ok0();
}

pub fn withdraw_from_accumulator_address(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.charge(c.p("event_emit_cost_base"))) return c.oog();
    const tag = tys[0].tag;
    const value = args[2].u256;
    const owner = args[1].address;
    const acc = args[0].address;
    if (value > std.math.maxInt(u64)) return c.abort(E_OVERFLOW);
    const amount: u64 = @intCast(value);
    if (!typeInBounds(c, tag)) return c.abort(E_ACCUMULATOR_TYPE_TOO_LARGE);
    if (try rt(c).emitAccumulatorEvent(c.arena, c.cfg, acc, .split, owner, tag, .{ .u64 = amount })) |e| return Ctx.vmErr(e);
    const fields = try c.arena.alloc(Value, 1);
    fields[0] = .{ .u64 = amount };
    return c.ok1(.{ .@"struct" = fields });
}

pub fn reserve_object_funds_for_withdrawal(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    if (!c.flag("check_object_funds_withdraw_in_execution")) return c.ok0();
    const base = c.popt("reserve_object_funds_for_withdrawal_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const tag = tys[0].tag;
    const limit = args[1].u256;
    const owner = args[0].address;
    if (try rt(c).fundsNeedsStoreRead(c.arena, owner, tag, limit)) {
        const cold = c.popt("reserve_object_funds_for_withdrawal_cold_read_cost") orelse return Ctx.invariant();
        if (!c.charge(cold)) return c.oog();
    }
    return switch (try rt(c).checkFundsSufficiency(c.arena, owner, tag, limit)) {
        .sufficient => c.ok0(),
        .insufficient => c.abort(E_OBJECT_FUNDS_INSUFFICIENT),
        .overflow => c.abort(E_OVERFLOW),
        .load_error => Ctx.invariant(),
    };
}

// ---- config ---------------------------------------------------------------------------------

/// `read_setting_impl<FieldSettingValue, SettingValue, SettingDataValue, Value>(config, name, epoch)`
pub fn read_setting_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("config_read_setting_impl_cost_base") orelse return Ctx.invariant();
    const per_byte = c.popt("config_read_setting_impl_cost_per_byte") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const value_ty = tys[3];
    const current_epoch = args[2].u64;
    const name = args[1].address;
    const config = args[0].address;
    const field_tag = structTag(tys[0]) orelse return Ctx.invariant();
    const field_layout = tys[0].layout orelse return c.abort(2); // E_BCS_SERIALIZATION_FAILURE
    const v_walk = value_ty.traversal() orelse return Ctx.invariant();
    // Option<Value> = struct { vec: vector<Value> }
    const vec_l = try c.arena.create(Layout);
    vec_l.* = .{ .vector = v_walk };
    const opt_fields = try c.arena.alloc(Layout, 1);
    opt_fields[0] = vec_l.*;
    const opt_s = try c.arena.create(types.layout.MoveStructLayout);
    opt_s.* = .{ .@"0" = opt_fields };
    const opt_l: Layout = .{ .@"struct" = opt_s };

    const none: Value = .{ .@"struct" = try c.arena.dupe(Value, &.{.{ .vector = &.{} }}) };
    var result = none;
    if (try rt(c).configRead(c.arena, config, name, field_layout, field_tag)) |field| {
        // Field { id, name, value: Setting { data: Option<SettingData> } }
        const f = field.@"struct";
        if (f.len != 3) return Ctx.invariant();
        const setting = f[2].@"struct";
        if (setting.len != 1) return Ctx.invariant();
        const data_opt = setting[0].@"struct";
        if (data_opt.len != 1) return Ctx.invariant();
        const data_vec = data_opt[0].vector;
        if (data_vec.len != 0) {
            const data = data_vec[0].@"struct";
            if (data.len != 3) return Ctx.invariant();
            const newer_epoch = data[0].u64;
            result = if (current_epoch > newer_epoch) data[1] else data[2];
        }
    }
    if (!c.charge(per_byte *| abi.objectRuntimeSize(c.cfg, &result, &opt_l))) return c.oog();
    return c.ok1(result);
}

// ---- package --------------------------------------------------------------------------------

pub fn original_package_id_impl(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("package_original_package_id_impl_cost_base") orelse return Ctx.invariant();
    const per_byte = c.popt("package_original_package_id_impl_cost_per_byte") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const version = args[1].u64;
    const id = args[0].address;
    const info = rt(c).packageAt(id, version) orelse return c.abort(6); // E_INVALID_PACKAGE_VERSION
    if (!c.charge(per_byte *| info.size)) return c.oog();
    return c.ok1(.{ .address = info.original_id });
}

// ---- scratch --------------------------------------------------------------------------------

const E_ENTRY_ALREADY_EXISTS: u64 = 0;
const E_ENTRY_DOES_NOT_EXIST: u64 = 1;
const E_ENTRY_TYPE_MISMATCH: u64 = 2;

pub fn scratch_add_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("scratch_add_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const key = args[0].address;
    return switch (try rt(c).scratchAdd(c.arena, c.cfg, key, tys[0].runtimeTag(), args[1], tys[0].traversal())) {
        .inserted => c.ok0(),
        .duplicate => c.abort(E_ENTRY_ALREADY_EXISTS),
        .limit_exceeded => Ctx.vmErr(.{ .status = .MEMORY_LIMIT_EXCEEDED, .sub = objrt.Mem.SCRATCH_SIZE }),
    };
}

pub fn scratch_read_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("scratch_read_cost_base") orelse return Ctx.invariant();
    const per = c.popt("scratch_read_value_cost") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const e = rt(c).scratchGet(args[0].address) orelse return c.abort(E_ENTRY_DOES_NOT_EXIST);
    if (!objrt.tagEql(e.ty, tys[0].runtimeTag())) return c.abort(E_ENTRY_TYPE_MISMATCH);
    const walk = e.layout orelse return Ctx.invariant();
    if (!c.charge(per *| sizeOf(&e.value, walk))) return c.oog();
    return c.ok1(e.value);
}

pub fn scratch_remove_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("scratch_remove_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    const e = rt(c).scratchRemove(args[0].address) orelse return c.abort(E_ENTRY_DOES_NOT_EXIST);
    if (!objrt.tagEql(e.ty, tys[0].runtimeTag())) return c.abort(E_ENTRY_TYPE_MISMATCH);
    return c.ok1(e.value);
}

pub fn scratch_exists_impl(c: *Ctx, _: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("scratch_exists_cost_base") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    return c.ok1(.{ .bool = rt(c).scratchGet(args[0].address) != null });
}

pub fn scratch_exists_with_type_impl(c: *Ctx, tys: []const TyArg, args: []Value) Error!Outcome {
    const base = c.popt("scratch_exists_with_type_cost_base") orelse return Ctx.invariant();
    const per = c.popt("scratch_exists_with_type_type_cost") orelse return Ctx.invariant();
    if (!c.charge(base)) return c.oog();
    if (!c.charge(per *| abi.typeSize(tys[0].tag))) return c.oog();
    const e = rt(c).scratchGet(args[0].address);
    return c.ok1(.{ .bool = if (e) |x| objrt.tagEql(x.ty, tys[0].runtimeTag()) else false });
}

// ---- tx_context (needs the runtime) -----------------------------------------------------------

/// `last_created_id` (test-only in Move; registered in `all_natives`).
pub fn last_created_id(c: *Ctx, _: []const TyArg, _: []Value) Error!Outcome {
    if (!c.charge(c.p("tx_context_derive_id_cost_base"))) return c.oog();
    if (c.tx.ids_created == 0) return c.abort(1); // E_NO_IDS_CREATED
    const id = abi.TxContext.deriveId(&c.tx.digest, c.tx.ids_created - 1);
    if (try rt(c).newId(c.arena, c.cfg, id)) |e| return Ctx.vmErr(e);
    return c.ok1(.{ .address = id });
}

// ---- protocol 142 natives (1.84) --------------------------------------------------------------

const protocol = @import("protocol");

const TestWorld = struct {
    clock_bytes: ?[]const u8,
    reads: u32 = 0,
    fn readChild(_: *anyopaque, _: *const Id, _: *const Id, _: u64) objrt.ResolveError!?*const objrt.StoredObject {
        return null;
    }
    fn receivedAt(_: *anyopaque, _: *const Id, _: *const Id, _: u64, _: u64) objrt.ResolveError!?*const objrt.StoredObject {
        return null;
    }
    fn packageAt(_: *anyopaque, _: *const Id, _: u64) ?objrt.PackageInfo {
        return null;
    }
    fn balance(_: *anyopaque, _: *const Id, _: *const TypeTag) objrt.ResolveError!u128 {
        return 0;
    }
    fn clock(ctx: *anyopaque) objrt.ResolveError!?[]const u8 {
        const w: *TestWorld = @ptrCast(@alignCast(ctx));
        w.reads += 1;
        return w.clock_bytes;
    }
    const vt: objrt.Resolver.VTable = .{ .read_child = readChild, .received_at = receivedAt, .package_at = packageAt, .available_balance = balance, .clock = clock };
    const vt_no_clock: objrt.Resolver.VTable = .{ .read_child = readChild, .received_at = receivedAt, .package_at = packageAt, .available_balance = balance };
};

fn testCtx(arena: std.mem.Allocator, pv: u64, tx: *abi.TxContext, r: *objrt.ObjectRuntime) !Ctx {
    return Ctx.init(arena, try protocol.get(pv, .mainnet), 1_000_000, tx, r);
}

const test_tx: abi.TxContext = .{ .sender = @splat(1), .digest = @splat(2), .epoch = 1, .epoch_timestamp_ms = 0, .rgp = 1, .gas_price = 1, .gas_budget = 1, .sponsor = null };

test "object::is_shared_input_impl: shared inputs only, 52 gas at 142, missing param before" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tx = test_tx;
    var r: objrt.ObjectRuntime = .{};
    const shared: Id = @splat(0x51);
    const owned: Id = @splat(0x52);
    try r.input_objects.put(a, shared, .{ .shared = 7 });
    try r.input_objects.put(a, owned, .{ .address = @splat(1) });
    var c = try testCtx(a, 142, &tx, &r);
    const cases = [_]struct { Id, bool }{ .{ shared, true }, .{ owned, false }, .{ @splat(0x53), false } };
    for (cases) |cs| {
        c.enter(1_000_000);
        var args = [_]Value{.{ .address = cs[0] }};
        const out = try is_shared_input_impl(&c, &.{}, &args);
        try std.testing.expectEqual(@as(u64, 52), out.ok.cost);
        try std.testing.expectEqual(cs[1], out.ok.rets[0].bool);
    }
    // out of gas below the base cost
    c.enter(51);
    var args = [_]Value{.{ .address = shared }};
    try std.testing.expect((try is_shared_input_impl(&c, &.{}, &args)) != .ok);
    // 141: no `object_is_shared_input_cost_base` (safe_unwrap: invariant violation)
    var c141 = try testCtx(a, 141, &tx, &r);
    try std.testing.expectEqual(abi.StatusCode.UNKNOWN_INVARIANT_VIOLATION_ERROR, (try is_shared_input_impl(&c141, &.{}, &args)).err.status);
}

test "clock::native_borrow: one Clock per transaction, 52 gas, invariant without the read" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var tx = test_tx;
    var contents: [40]u8 = undefined;
    @memcpy(contents[0..32], &@as(Id, blk: {
        var x: Id = @splat(0);
        x[31] = 6;
        break :blk x;
    }));
    std.mem.writeInt(u64, contents[32..40], 1_762_600_000_123, .little);
    var w: TestWorld = .{ .clock_bytes = &contents };
    var r: objrt.ObjectRuntime = .{ .resolver = .{ .ctx = &w, .vtable = &TestWorld.vt } };
    var c = try testCtx(a, 142, &tx, &r);
    c.enter(1_000_000);
    const o1 = try clock_native_borrow(&c, &.{}, &.{});
    try std.testing.expectEqual(@as(u64, 52), o1.ok.cost);
    const v = o1.ok.ref.?;
    try std.testing.expectEqual(@as(u64, 1_762_600_000_123), v.@"struct"[1].u64);
    try std.testing.expectEqual(@as(u8, 6), v.@"struct"[0].@"struct"[0].@"struct"[0].address[31]);
    c.enter(1_000_000);
    const o2 = try clock_native_borrow(&c, &.{}, &.{});
    try std.testing.expectEqual(v, o2.ok.ref.?);
    try std.testing.expectEqual(@as(u32, 1), w.reads);
    // a Clock that is not 40 bytes fails to deserialize
    var bad_w: TestWorld = .{ .clock_bytes = contents[0..39] };
    var r_bad: objrt.ObjectRuntime = .{ .resolver = .{ .ctx = &bad_w, .vtable = &TestWorld.vt } };
    var c_bad = try testCtx(a, 142, &tx, &r_bad);
    try std.testing.expectEqual(abi.StatusCode.FAILED_TO_DESERIALIZE_RESOURCE, (try clock_native_borrow(&c_bad, &.{}, &.{})).err.status);
    // no implicit read available: invariant violation
    var r_none: objrt.ObjectRuntime = .{ .resolver = .{ .ctx = &w, .vtable = &TestWorld.vt_no_clock } };
    var c_none = try testCtx(a, 142, &tx, &r_none);
    try std.testing.expectEqual(abi.StatusCode.UNKNOWN_INVARIANT_VIOLATION_ERROR, (try clock_native_borrow(&c_none, &.{}, &.{})).err.status);
    // out of gas before the read
    var r_oog: objrt.ObjectRuntime = .{ .resolver = .{ .ctx = &w, .vtable = &TestWorld.vt } };
    var c_oog = try testCtx(a, 142, &tx, &r_oog);
    c_oog.enter(51);
    try std.testing.expect((try clock_native_borrow(&c_oog, &.{}, &.{})) != .ok);
    try std.testing.expect(r_oog.clock == null);
}

test "derived_object root version: an id keeps the root version it has (1.84)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var r: objrt.ObjectRuntime = .{};
    const cfg = try protocol.get(142, .mainnet);
    const parent: Id = @splat(0x61);
    const child: Id = @splat(0x62);
    try r.root_version.put(a, parent, 10);
    try r.root_version.put(a, child, 4);
    try std.testing.expect((try r.newIdFromHash(a, cfg, parent, child)) == null);
    try std.testing.expectEqual(@as(u64, 4), r.root_version.get(child).?);
    const fresh: Id = @splat(0x63);
    try std.testing.expect((try r.newIdFromHash(a, cfg, parent, fresh)) == null);
    try std.testing.expectEqual(@as(u64, 10), r.root_version.get(fresh).?);
}
