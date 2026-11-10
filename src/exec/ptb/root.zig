//! exec-move (CONTRACTS 6.4.3): programmable transactions with Move calls on execution version 4
//! (`sui-execution/latest`, gas model 15 and later, bump-only charging), through move_vm and the
//! natives object runtime.
//!
//! Pipeline (`execute_transaction_to_effects`): TemporaryStore over the inputs (owned, shared at
//! the versions consensus assigned, gas coins, the packages the commands name), smash_gas,
//! charge_input_objects, static_programmable_transactions::execute (translation with its meters,
//! verification, Context::new, commands, Context::finish, ObjectRuntime::finish, finish_gas_coin,
//! context::finish with the coin deny-list charge), round_computation, meter_storage,
//! handle_error, apply_payment, into_effects (effects V2).
//!
//! Replay inputs: the transaction's object inputs come from the checkpoint (and the corpus
//! read-only objects); shared versions and the versions of runtime-loaded objects come from the
//! certified effects (which record what consensus assigned and what the transaction read) and,
//! for read-only runtime loads, from the archive's `unchanged_loaded_runtime_objects`.
//!
//! Anything outside the modeled set returns `.unsupported` with a reason (counted as a skip).
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const bcs = @import("bcs");
const move_vm = @import("move_vm");
const natives = @import("natives");
const objects = @import("../objects.zig");
const gas_mod = @import("../gas.zig");
const inputs_mod = @import("../inputs.zig");
const packages = @import("../packages.zig");
const coin_ptb = @import("../coin_ptb.zig");
pub const pkgs = @import("pkgs.zig");
pub const typing = @import("typing.zig");
pub const run = @import("run.zig");
pub const archive = @import("archive.zig");
pub const deny = @import("deny.zig");
pub const borrow = @import("borrow.zig");
pub const compat = @import("compat.zig");
const versions = @import("../versions/root.zig");
const dynamic = @import("../versions/dynamic.zig");

const Allocator = std.mem.Allocator;
const ObjectView = objects.ObjectView;
const SuiGasStatus = gas_mod.SuiGasStatus;
const objrt = natives.objrt;
const Id = [32]u8;

pub const Env = struct {
    /// Long-lived allocator for the per-thread package caches.
    gpa: Allocator,
    cfg: *const protocol.ProtocolConfig,
    pv: u64,
    epoch: u64,
    epoch_start_ms: u64,
    rgp: u64,
    pkgs: *const packages.Store,
    /// The package store holds every package that exists (a node's store, a simulation's
    /// snapshot, a synthetic vector's set): a package it lacks is `get_package`'s
    /// InvalidLinkage. Corpus replay leaves it off, where a missing package is a corpus gap.
    authoritative_packages: bool = false,
    /// The transaction digest the executor is given (Rust's `execute_transaction_to_effects`
    /// takes it apart from the data); null: the digest of the transaction data.
    tx_digest: ?Id = null,
};

pub const Ref = archive.Ref;

pub const Inputs = struct {
    /// (id, version) -> object bytes: the checkpoint's objects, the archive's object set and the
    /// corpus read-only objects.
    objs: coin_ptb.ObjectLookup,
    /// The certified effects: shared input versions and the versions of modified runtime loads.
    /// Null for simulation (rpc-exec), where `state` answers those reads from a pre-state snapshot.
    effects: ?*const types.TransactionEffectsV2,
    /// `unchanged_loaded_runtime_objects` of the transaction (archive); null when unknown.
    unchanged_loaded: ?[]const Ref,
    /// The scheduler found the transaction's funds withdrawals (address-balance gas included)
    /// above the available balances: an `InsufficientFundsForWithdraw` early error, which
    /// short-circuits execution (`ExecutionOrEarlyError`). Replay reads it from the certified status.
    insufficient_funds: bool = false,
    /// `get_unsettled_object_withdraw(field, accumulator_version)`: withdrawals from an object's
    /// balance by the transactions executed earlier at the same accumulator version (the
    /// scheduler's record; replay sums the Split writes of the checkpoint's earlier
    /// transactions since the last root settlement). null: object balance reads unsupported.
    unsettled: ?Unsettled = null,
    // ---- PreState/simulation hooks (rpc-exec, CONTRACTS 6.6b). Defaults keep replay unchanged.
    /// Simulation pre-state: consulted only when `effects` is null.
    state: ?PreState = null,
    /// Candidate coin types of the coin reservations (`typing.Ptb.accumulator_types`; rpc-exec
    /// resolves each through the accumulator field). null: the effects' accumulator write types.
    reservation_types: ?[]const types.TypeTag = null,
    /// `execution_mode::DevInspect` command results (`Mode::TRACK_EXECUTION`): `Output.command_results`
    /// holds one entry per executed command when the transaction succeeds. Effects are unchanged.
    track_results: bool = false,
    /// `DevInspect<true>` (checks disabled). Not modeled yet: `true` is `.unsupported`.
    skip_all_checks: bool = false,
};

/// Simulation pre-state (rpc-exec): what `TransactionInputLoader::read_objects_for_simulation`
/// and the backing store answer when no certified effects exist.
pub const PreState = struct {
    ctx: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The live version of a consensus (shared) object; null when the store has none.
        shared_latest: *const fn (ctx: *const anyopaque, id: *const [32]u8) ?u64,
        /// `read_child_object`: raw BCS `Object` of the newest version of `child` at or below
        /// `upper`; null when none exists.
        child_at_most: *const fn (ctx: *const anyopaque, child: *const [32]u8, upper: u64) ?[]const u8,
        /// `AccountFundsRead`: the available balance of `owner` for coin type `ty`; null when
        /// the pre-state cannot answer (the transaction is then `.unsupported`).
        address_balance: *const fn (ctx: *const anyopaque, owner: *const [32]u8, ty: *const types.TypeTag) ?u128,
    };
};

pub const Unsettled = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, arena: Allocator, field: *const Id) anyerror!u128,
};

/// One value of a DevInspect command result (`ExecutionResults::V2`): BCS bytes and type;
/// `arg` is set for a `&mut` argument's value after the command (`mutated_by_ref`).
pub const TrackedValue = run.TrackedValue;
/// One command's DevInspect results: `(argument_updates, return_values)`.
pub const CommandResult = run.CommandResult;

pub const Output = struct {
    /// `Inputs.track_results`: one entry per executed command (rpc-exec command_outputs), set
    /// when execution succeeded (Rust's `execution_result` is `Err` otherwise).
    command_results: ?[]const CommandResult = null,
    effects: []const u8,
    /// BCS `TransactionEvents`, when the transaction emitted events.
    events: ?[]const u8,
    written: []const coin_ptb.Written,
    /// Every object read through the backing store at runtime (children, received objects),
    /// packages excluded: `TrackingBackingStore::into_read_objects` (rpc-exec).
    loaded: []const Ref = &.{},
    /// context::finish's deny list v2 (coin type, owner) pairs, also when the transaction later
    /// reverts (rpc-exec replays the config reads).
    deny_pairs: []const run.DenyPair = &.{},
};

pub const Outcome = union(enum) {
    done: Output,
    unsupported: []const u8,
};

const zero32: Id = @splat(0);
const deny_list_id: Id = blk: {
    var a: Id = @splat(0);
    a[30] = 0x04;
    a[31] = 0x03;
    break :blk a;
};

/// One object of `TemporaryStore::input_objects` (packages included).
const Input = struct {
    raw: []const u8,
    view: ObjectView,
    owner: types.Owner,
    /// The object digest, computed on first use (effects input state).
    digest: ?Id = null,
    /// `object_size_for_gas_metering`, when known ahead (package objects, from the cache).
    gas_size: ?u64 = null,

    fn objectDigest(x: *Input) Id {
        if (x.digest == null) x.digest = x.view.digest();
        return x.digest.?;
    }
};

/// `get_object_modified_at` metadata.
const Meta = struct {
    version: u64,
    digest: Id,
    owner: types.Owner,
    rebate: u64,
    prev_tx: Id,
    /// Set while `digest` is not computed yet (runtime loads: only a modified one needs it).
    raw: ?[]const u8 = null,
};

const Write = struct {
    id: Id,
    /// Data tag, MoveObjectType and has_public_transfer (everything before the version).
    type_bytes: []const u8,
    contents: []const u8,
    owner: types.Owner,
    storage_rebate: u64 = 0,
    bytes: []const u8 = &.{},
    /// `objectDigest(bytes)`, filled by `hashAll` in one multi-buffer pass.
    digest: Id = zero32,
    /// A published package: BCS `MovePackage` (`Data::Package`, its version inside).
    package: ?struct { version: u64, bcs: []const u8 } = null,
};

const Results = struct {
    written: std.AutoArrayHashMapUnmanaged(Id, Write) = .empty,
    modified: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    created: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    deleted: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    /// Accumulator events, in order (`execution_results.accumulator_events`).
    acc: std.ArrayList(run.AccWrite) = .empty,

    fn dropWrites(r: *Results) void {
        r.acc.clearRetainingCapacity();
        r.written.clearRetainingCapacity();
        r.modified.clearRetainingCapacity();
        r.created.clearRetainingCapacity();
        r.deleted.clearRetainingCapacity();
    }
};

/// A shared input as `SharedInput`: an existing object, or one of a cancelled transaction (its
/// version is the cancellation reason).
const SharedRef = struct { id: Id, version: u64, digest: Id = zero32, cancelled: bool = false };

const cancelled_read: u64 = 1 << 63;
const congested: u64 = (1 << 63) + 1;
const randomness_unavailable: u64 = (1 << 63) + 2;

const Exec = struct {
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    tx_digest: Id,
    sender: Id,
    budget: u64,
    gas: SuiGasStatus,
    inputs: std.AutoArrayHashMapUnmanaged(Id, Input) = .empty,
    mutable: std.AutoArrayHashMapUnmanaged(Id, void) = .empty,
    shared: std.ArrayList(SharedRef) = .empty,
    gas_ids: []const Id = &.{},
    /// The smash target is an address-balance reservation: the payer (gas owner).
    payer: ?Id = null,
    /// Address-balance payment methods (coin reservations, or the whole budget when the payment
    /// is empty), merged into one by location (`PaymentKind::smash`): the gas owner and the sum.
    ab_owner: Id = zero32,
    ab_amount: u64 = 0,
    ab_present: bool = false,
    /// `total_smashed`: the coins' values plus the reservations.
    total_smashed: u64 = 0,
    /// `gas_charge_location`: the payer's balance, or a coin (the smashed coin, or the ephemeral
    /// coin after a transfer).
    charge_coin: ?Id = null,
    /// The charged address balance when `charge_coin` is null.
    charge_addr: Id = zero32,
    results: Results = .{},
    /// Runtime-loaded objects (children, received): their metadata as loaded.
    loaded: std.AutoArrayHashMapUnmanaged(Id, Meta) = .empty,
    lamport: u64 = 0,
    /// `PaymentKind::gasless()`: no gas payment, nothing charged, the gasless post-execution
    /// requirements checked instead of the storage charge.
    gasless: bool = false,
    /// Gasless: the funds-withdrawal reservations checked against the unused remainder (null
    /// on the legacy path without `gasless_verify_remaining_balance`).
    gasless_reservations: ?[]const GaslessKey = null,
    per_epoch_deny_list: bool = false,
    /// exec-history: gas model below 4 (`handle_storage_and_rebate_v1`).
    storage_v1: bool = false,
    /// `Inputs.track_results` (DevInspect command results).
    track: bool = false,
    /// exec-history: the certified effects (`Inputs.effects`), for v0's unwrap-then-delete
    /// tombstone versions before `simplified_unwrap_then_delete`.
    cert: ?*const types.TransactionEffectsV2 = null,
    /// `loaded_system_objects`: the accumulator root as read by `object_available_balance`
    /// (its assigned version and that object's digest).
    root_read: ?struct { version: u64, digest: Id } = null,
    /// `loaded_system_objects`: the Clock as read by v142 `clock::borrow`.
    clock_read: ?struct { version: u64, digest: Id } = null,
    events: []const types.Event = &.{},

    /// A shared input's digest: the input object's (hashed once, shared with `modifiedAt`).
    fn sharedDigest(e: *Exec, s: *const SharedRef) Id {
        const in = e.inputs.getPtr(s.id) orelse return s.digest;
        return in.objectDigest();
    }

    fn modifiedAt(e: *Exec, id: *const Id) ?Meta {
        if (!e.results.modified.contains(id.*)) return null;
        if (e.inputs.getPtr(id.*)) |in| return .{
            .version = in.view.version,
            .digest = in.objectDigest(),
            .owner = in.owner,
            .rebate = in.view.storageRebate(),
            .prev_tx = in.raw[in.view.prev_tx_at + 1 ..][0..32].*,
        };
        const m = e.loaded.getPtr(id.*) orelse return null;
        if (m.raw) |raw| {
            m.digest = types.digest.objectDigest(raw);
            m.raw = null;
        }
        return m.*;
    }

    /// The storage rebate of a modified object's prior version (no digest).
    fn modifiedRebate(e: *const Exec, id: *const Id) ?u64 {
        if (!e.results.modified.contains(id.*)) return null;
        if (e.inputs.getPtr(id.*)) |in| return in.view.storageRebate();
        return if (e.loaded.get(id.*)) |m| m.rebate else null;
    }

    fn inputWrite(e: *Exec, id: *const Id) Write {
        const in = e.inputs.getPtr(id.*).?;
        return .{
            .id = id.*,
            .type_bytes = in.raw[0..in.view.version_at],
            .contents = in.view.contents(),
            .owner = in.owner,
            .storage_rebate = in.view.storageRebate(),
        };
    }

    fn mutateInput(e: *Exec, w: Write) !void {
        try e.results.modified.put(e.arena, w.id, {});
        try e.results.written.put(e.arena, w.id, w);
    }

    fn readObject(e: *Exec, id: *const Id) Write {
        if (e.results.written.get(id.*)) |w| return w;
        return e.inputWrite(id);
    }

    fn ensureActiveInputsMutated(e: *Exec) !void {
        for (e.mutable.keys()) |id| {
            if (e.results.modified.contains(id)) continue;
            try e.mutateInput(e.inputWrite(&id));
        }
    }

    fn oldRebate(e: *Exec, id: *const Id) u64 {
        return e.modifiedRebate(id) orelse 0;
    }

    fn collectStorageAndRebate(e: *Exec) !?gas_mod.GasError {
        for (e.results.written.values()) |*w| {
            const size = try writeSizeForGasMetering(e.arena, w);
            const rebate = e.oldRebate(&w.id);
            const new_rebate = (try e.gas.trackStorageMutation(e.arena, w.id, size, rebate)) orelse return .InvariantViolation;
            w.storage_rebate = new_rebate;
        }
        return e.collectRebate();
    }

    fn collectRebate(e: *Exec) !?gas_mod.GasError {
        for (e.results.modified.keys()) |id| {
            if (e.results.written.contains(id)) continue;
            const rebate = e.oldRebate(&id);
            _ = (try e.gas.trackStorageMutation(e.arena, id, 0, rebate)) orelse return .InvariantViolation;
        }
        return null;
    }

    /// `AccumulatorEvent::from_balance_change` for Balance<SUI> of `addr`.
    fn balanceChange(e: *Exec, addr: Id, change: i64) !void {
        if (change == 0) return;
        try e.results.acc.append(e.arena, try run.balanceWrite(e.arena, addr, change));
    }

    /// gas_charger.rs `SmashMetadata::smash_gas`: the target is the first payment method; the
    /// other coins are deleted, a smashed reservation is withdrawn from its balance, and the
    /// target receives the total (a coin's value, or the balance deposit above its reservation).
    fn smashGas(e: *Exec) !void {
        if (e.gasless) return;
        var total: u64 = e.ab_amount;
        for (e.gas_ids) |*id| {
            const in = e.inputs.getPtr(id.*).?;
            if (in.view.is_package or in.raw.len < 2 or in.raw[1] != 1) return error.Unsupported;
            total = std.math.add(u64, total, coinValue(in.view.contents())) catch return error.Unsupported;
        }
        e.total_smashed = total;
        if (e.payer) |payer| {
            e.charge_coin = null;
            e.charge_addr = payer;
            for (e.gas_ids) |id| {
                try e.results.modified.put(e.arena, id, {});
                try e.results.deleted.put(e.arena, id, {});
            }
            const deposit = total - e.ab_amount;
            if (deposit != 0) try e.results.acc.append(e.arena, try run.balanceWrite(e.arena, payer, std.math.cast(i64, deposit) orelse return error.Unsupported));
            return;
        }
        e.charge_coin = e.gas_ids[0];
        for (e.gas_ids[1..]) |id| {
            try e.results.modified.put(e.arena, id, {});
            try e.results.deleted.put(e.arena, id, {});
        }
        if (e.ab_present) {
            const neg = -(std.math.cast(i64, e.ab_amount) orelse return error.Unsupported);
            try e.results.acc.append(e.arena, try run.balanceWrite(e.arena, e.ab_owner, neg));
        }
        var w = e.inputWrite(&e.gas_ids[0]);
        w.contents = try setCoinValue(e.arena, w.contents, total);
        try e.mutateInput(w);
    }

    fn reset(e: *Exec) !void {
        e.results.dropWrites();
        e.gas.resetStorageCostAndRebate();
        try e.smashGas();
        try e.ensureActiveInputsMutated();
        e.events = &.{};
    }

    fn meterStorage(e: *Exec) !?gas_mod.GasError {
        if (e.gasless) {
            // `PaymentMetadata::Gasless`: the requirements, then storage collected, not charged
            if (!try e.gaslessRequirementsMet()) return .InsufficientGas;
            try e.ensureActiveInputsMutated();
            return try e.collectStorageAndRebate();
        }
        try e.ensureActiveInputsMutated();
        if (try e.collectStorageAndRebate()) |err| return err;
        return try e.gas.chargeStorageAndRebate();
    }

    /// temporary_store.rs `check_gasless_execution_requirements_with_reservations`: nothing
    /// written, exactly the input coins deleted, every positive net balance change of an allowed
    /// token at least its minimum, and every reservation's unused remainder 0 or at least it.
    fn gaslessRequirementsMet(e: *Exec) !bool {
        if (e.results.written.count() != 0) return false;
        var coins: usize = 0;
        for (e.inputs.keys(), e.inputs.values()) |id, *x| {
            if (x.view.is_package or x.raw.len < 2 or x.raw[0] != 0) continue;
            if (x.raw[1] != 1 and x.raw[1] != 3) continue; // GasCoin, Coin(T)
            coins += 1;
            if (!e.results.deleted.contains(id)) return false;
        }
        if (e.results.deleted.count() != coins) return false;
        var nets: std.ArrayList(struct { key: GaslessKey, net: i128 }) = .empty;
        for (e.results.acc.items) |*w| {
            const st = switch (w.ty) {
                .@"struct" => |st| st,
                else => continue,
            };
            if (!isStruct(&st, 2, "balance", "Balance") or st.type_args.len != 1) continue;
            const amount: i128 = switch (w.value) {
                .Integer => |v| v,
                else => continue,
            };
            const signed: i128 = if (w.op == .Split) -amount else amount;
            const tb = try bcs.encodeAlloc(types.TypeTag, e.arena, &st.type_args[0]);
            for (nets.items) |*n| {
                if (std.mem.eql(u8, &n.key.owner, &w.addr) and std.mem.eql(u8, n.key.ty, tb)) {
                    n.net += signed;
                    break;
                }
            } else try nets.append(e.arena, .{ .key = .{ .owner = w.addr, .ty = tb, .amount = 0 }, .net = signed });
        }
        for (nets.items) |n| {
            if (n.net <= 0) continue;
            if (try gaslessMinimum(e.arena, e.cfg, n.key.ty)) |min| if (n.net < min) return false;
        }
        if (e.gasless_reservations) |rs| for (rs) |r| {
            var net: i128 = 0;
            for (nets.items) |n| if (std.mem.eql(u8, &n.key.owner, &r.owner) and std.mem.eql(u8, n.key.ty, r.ty)) {
                net = n.net;
            };
            const remaining = @as(i128, r.amount) + net;
            if (remaining > 0) if (try gaslessMinimum(e.arena, e.cfg, r.ty)) |min| if (min > 0 and remaining < min) return false;
        };
        return true;
    }

    fn handleError(e: *Exec) !void {
        try e.reset();
        if (try e.meterStorage()) |_| {
            try e.reset();
            e.gas.adjustComputationOnOutOfGas();
            if (try e.collectRebate()) |_| return error.Unsupported;
        }
    }

    /// gas_charger.rs `legacy::legacy_charge_gas` with `compute_storage_and_rebate` (gas models
    /// below 15). Returns the execution error after charging.
    fn legacyChargeGas(e: *Exec, err_in: ?pkgs.Fail, is_move_abort: bool, refresh_location: bool) !?pkgs.Fail {
        var err = err_in;
        if (try e.gas.bucketizeComputation(is_move_abort)) |ge| {
            if (err == null) err = .{ .kind = gasErrKind(ge) };
        }
        if (err != null) try e.reset();
        try e.ensureActiveInputsMutated();
        if (try e.collectStorageAndRebate()) |_| return error.Unsupported;
        const coin0 = e.charge_coin;
        const addr0 = e.charge_addr;
        // exec-history: `handle_storage_and_rebate_v1` below gas model 4 (no second try with
        // the inputs only)
        if (e.storage_v1) {
            if (try e.gas.chargeStorageAndRebate()) |ge| {
                try e.reset();
                e.gas.adjustComputationOnOutOfGas();
                try e.ensureActiveInputsMutated();
                if (try e.collectRebate()) |_| return error.Unsupported;
                if (err == null) err = .{ .kind = gasErrKind(ge) };
            }
        } else if (try e.gas.chargeStorageAndRebate()) |ge| {
            try e.reset();
            try e.ensureActiveInputsMutated();
            if (try e.collectStorageAndRebate()) |_| return error.Unsupported;
            if (try e.gas.chargeStorageAndRebate()) |ge2| {
                try e.reset();
                e.gas.adjustComputationOnOutOfGas();
                try e.ensureActiveInputsMutated();
                if (try e.collectRebate()) |_| return error.Unsupported;
                if (err == null) err = .{ .kind = gasErrKind(ge2) };
            } else if (err == null) err = .{ .kind = gasErrKind(ge) };
        }
        if (!refresh_location) {
            e.charge_coin = coin0;
            e.charge_addr = addr0;
        }
        return err;
    }

    fn applyPayment(e: *Exec, summary: gas_mod.GasCostSummary) !void {
        const net = summary.netGasUsage() catch return error.Unsupported;
        const coin = e.charge_coin orelse {
            if (net != 0) try e.balanceChange(e.charge_addr, -net);
            return;
        };
        var w = e.results.written.get(coin) orelse e.inputWrite(&coin);
        const bal = coinValue(w.contents);
        const new_bal = if (net >= 0)
            std.math.sub(u64, bal, @intCast(net)) catch return error.Unsupported
        else
            std.math.add(u64, bal, @intCast(-net)) catch return error.Unsupported;
        w.contents = try setCoinValue(e.arena, w.contents, new_bal);
        try e.results.modified.put(e.arena, w.id, {});
        try e.results.written.put(e.arena, w.id, w);
    }
};

/// (owner, coin type `T` as BCS TypeTag bytes) and a reserved amount.
const GaslessKey = struct { owner: Id, ty: []const u8, amount: u64 };

/// The minimum transfer of an allowed gasless token (`get_gasless_allowed_token_types`), by the
/// BCS bytes of its TypeTag; null when the type is not in the list.
fn gaslessMinimum(arena: Allocator, cfg: *const protocol.ProtocolConfig, ty: []const u8) !?u64 {
    const list = cfg.gasless_allowed_token_types orelse return null;
    for (list) |entry| {
        const tag = parseStructTag(arena, entry[0]) catch return error.Unsupported;
        const tb = try bcs.encodeAlloc(types.TypeTag, arena, &tag);
        if (std.mem.eql(u8, tb, ty)) return entry[1];
    }
    return null;
}

/// `0x<hex>::module::Name` (no type arguments; the allowlist's form).
fn parseStructTag(arena: Allocator, s: []const u8) !types.TypeTag {
    var it = std.mem.splitSequence(u8, s, "::");
    const a = it.next() orelse return error.Unsupported;
    const m = it.next() orelse return error.Unsupported;
    const n = it.next() orelse return error.Unsupported;
    if (it.next() != null or std.mem.indexOfScalar(u8, n, '<') != null) return error.Unsupported;
    const hex = if (std.mem.startsWith(u8, a, "0x")) a[2..] else a;
    if (hex.len == 0 or hex.len > 64) return error.Unsupported;
    var padded: [64]u8 = @splat('0');
    @memcpy(padded[64 - hex.len ..], hex);
    var addr: Id = undefined;
    _ = std.fmt.hexToBytes(&addr, &padded) catch return error.Unsupported;
    return .{ .@"struct" = .{ .address = .{ .@"0" = addr }, .module = .{ .@"0" = m }, .name = .{ .@"0" = n }, .type_args = try arena.alloc(types.TypeTag, 0) } };
}

/// `T` of every `Balance<T>` accumulator object the effects write.
fn accumulatorCoinTypes(arena: Allocator, fx: *const types.TransactionEffectsV2) ![]const types.TypeTag {
    var out: std.ArrayList(types.TypeTag) = .empty;
    for (fx.changed_objects) |*c| switch (c[1].output_state) {
        .AccumulatorWriteV1 => |*w| switch (w.address.ty) {
            .@"struct" => |st| if (isStruct(&st, 2, "balance", "Balance") and st.type_args.len == 1) try out.append(arena, st.type_args[0]),
            else => {},
        },
        else => {},
    };
    return out.items;
}

fn usesGasCoin(pt: *const types.ProgrammableTransaction) bool {
    const S = struct {
        fn any(args: []const types.Argument) bool {
            for (args) |a| if (a == .GasCoin) return true;
            return false;
        }
    };
    for (pt.commands) |*c| switch (c.*) {
        .MoveCall => |*mc| if (S.any(mc.arguments)) return true,
        .TransferObjects => |t| if (S.any(t[0]) or t[1] == .GasCoin) return true,
        .SplitCoins => |t| if (t[0] == .GasCoin or S.any(t[1])) return true,
        .MergeCoins => |t| if (t[0] == .GasCoin or S.any(t[1])) return true,
        .MakeMoveVec => |t| if (S.any(t[1])) return true,
        .Publish => {},
        .Upgrade => |t| if (t[3] == .GasCoin) return true,
    };
    return false;
}

fn coinValue(contents: []const u8) u64 {
    return std.mem.readInt(u64, contents[32..40], .little);
}

fn setCoinValue(arena: Allocator, contents: []const u8, v: u64) ![]const u8 {
    const c = try arena.dupe(u8, contents);
    std.mem.writeInt(u64, c[32..40], v, .little);
    return c;
}

fn writeBytes(arena: Allocator, w: *const Write, version: u64, prev_tx: *const Id) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    if (w.package) |pk| {
        try buf.append(arena, 1);
        try buf.appendSlice(arena, pk.bcs);
        try buf.appendSlice(arena, try bcs.encodeAlloc(types.Owner, arena, &w.owner));
        try buf.append(arena, 32);
        try buf.appendSlice(arena, prev_tx);
        var r8: [8]u8 = undefined;
        std.mem.writeInt(u64, &r8, w.storage_rebate, .little);
        try buf.appendSlice(arena, &r8);
        return buf.items;
    }
    try buf.appendSlice(arena, w.type_bytes);
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, version, .little);
    try buf.appendSlice(arena, &v8);
    try appendUleb(arena, &buf, w.contents.len);
    try buf.appendSlice(arena, w.contents);
    try buf.appendSlice(arena, try bcs.encodeAlloc(types.Owner, arena, &w.owner));
    try buf.append(arena, 32);
    try buf.appendSlice(arena, prev_tx);
    std.mem.writeInt(u64, &v8, w.storage_rebate, .little);
    try buf.appendSlice(arena, &v8);
    return buf.items;
}

fn appendUleb(arena: Allocator, buf: *std.ArrayList(u8), n: usize) !void {
    var x = n;
    while (true) {
        const b: u8 = @intCast(x & 0x7f);
        x >>= 7;
        if (x == 0) {
            try buf.append(arena, b);
            return;
        }
        try buf.append(arena, b | 0x80);
    }
}

fn writeSizeForGasMetering(arena: Allocator, w: *const Write) !u64 {
    const raw = try writeBytes(arena, w, 0, &zero32);
    const v = try ObjectView.parse(raw);
    return objects.sizeForGasMetering(arena, &v);
}

fn isFramework(a: *const Id, b: u8) bool {
    for (a[0..31]) |x| if (x != 0) return false;
    return a[31] == b;
}

fn isStruct(st: *const types.StructTag, addr: u8, module: []const u8, name: []const u8) bool {
    return isFramework(&st.address.@"0", addr) and std.mem.eql(u8, st.module.@"0", module) and std.mem.eql(u8, st.name.@"0", name);
}

/// `MoveObjectType::from(StructTag)` (accumulator fields are not modeled).
fn moveObjectType(st: *const types.StructTag) error{Unsupported}!types.MoveObjectType_ {
    if (isStruct(st, 2, "coin", "Coin") and st.type_args.len == 1) {
        const t = &st.type_args[0];
        if (t.* == .@"struct" and isStruct(&t.@"struct", 2, "sui", "SUI") and t.@"struct".type_args.len == 0) return .GasCoin;
        return .{ .Coin = t.* };
    }
    if (isStruct(st, 3, "staking_pool", "StakedSui") and st.type_args.len == 0) return .StakedSui;
    if (isStruct(st, 2, "dynamic_field", "Field") and st.type_args.len == 2) {
        const k = &st.type_args[0];
        if (k.* == .@"struct" and isStruct(&k.@"struct", 2, "accumulator", "Key")) return error.Unsupported;
    }
    return .{ .Other = st.* };
}

fn typeBytes(arena: Allocator, st: *const types.StructTag, has_public_transfer: bool) ![]const u8 {
    const mt: types.MoveObjectType = .{ .@"0" = try moveObjectType(st) };
    var buf: std.ArrayList(u8) = .empty;
    try buf.append(arena, 0); // Data::Move
    try buf.appendSlice(arena, try bcs.encodeAlloc(types.MoveObjectType, arena, &mt));
    try buf.append(arena, @intFromBool(has_public_transfer));
    return buf.items;
}

fn lessBytes(_: void, a: Id, b: Id) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn unsupported(arena: Allocator, comptime fmt: []const u8, args: anytype) Outcome {
    return .{ .unsupported = std.fmt.allocPrint(arena, fmt, args) catch "unsupported" };
}

/// The version consensus assigned to a shared input (certified effects).
const SharedVersion = struct { version: u64, special: bool };
fn sharedVersion(in: *const Inputs, id: *const Id) ?SharedVersion {
    const fx = in.effects orelse {
        const st = in.state orelse return null;
        return .{ .version = st.vtable.shared_latest(st.ctx, id) orelse return null, .special = false };
    };
    for (fx.changed_objects) |*c| if (std.mem.eql(u8, &c[0].@"0".@"0", id)) switch (c[1].input_state) {
        .Exist => |x| return .{ .version = x[0][0].@"0", .special = false },
        .NotExist => {},
    };
    for (fx.unchanged_consensus_objects) |*u| if (std.mem.eql(u8, &u[0].@"0".@"0", id)) switch (u[1]) {
        .ReadOnlyRoot => |r| return .{ .version = r[0].@"0", .special = false },
        .MutateConsensusStreamEnded, .ReadConsensusStreamEnded, .Cancelled => |v| return .{ .version = v.@"0", .special = true },
        .PerEpochConfig => return null,
    };
    return null;
}

fn typeInputPackages(arena: Allocator, out: *std.ArrayList(Id), t: *const types.TypeInput) !void {
    switch (t.*) {
        .vector => |x| try typeInputPackages(arena, out, x),
        .@"struct" => |*st| {
            try out.append(arena, st.address.@"0");
            for (st.type_args) |*a| try typeInputPackages(arena, out, a);
        },
        else => {},
    }
}

// ---------------------------------------------------------------------------------------------
// Object resolver for the object runtime: runtime loads answered from the certified read set.

const Resolve = struct {
    arena: Allocator,
    objs: coin_ptb.ObjectLookup,
    fx: ?*const types.TransactionEffectsV2,
    state: ?PreState = null,
    unchanged: ?[]const Ref,
    unsettled: ?Unsettled = null,
    cache: *pkgs.Cache,
    e: *Exec,
    gap: ?[]const u8 = null,

    fn stored(r: *Resolve, id: *const Id, version: u64) ?*const objrt.StoredObject {
        const raw = r.objs.get(r.objs.ctx, id, version) orelse {
            r.gap = "runtime-loaded object not in corpus";
            return null;
        };
        return r.storedFrom(raw) catch {
            r.gap = "runtime-loaded object does not parse";
            return null;
        };
    }

    fn storedFrom(r: *Resolve, raw: []const u8) !*const objrt.StoredObject {
        return r.storedFromDigest(raw, false);
    }

    /// A runtime load recorded in `e.loaded`; the object digest only when asked (`received_at`
    /// metadata), else on demand when the object turns out modified.
    fn storedFromDigest(r: *Resolve, raw: []const u8, with_digest: bool) !*const objrt.StoredObject {
        var owner: types.Owner = undefined;
        const so = try r.storedObjectOwner(raw, with_digest, &owner);
        try r.e.loaded.put(r.arena, so.id, .{ .version = so.version, .digest = so.digest, .owner = owner, .rebate = so.storage_rebate, .prev_tx = so.previous_transaction, .raw = if (with_digest) null else raw });
        return so;
    }

    fn storedObject(r: *Resolve, raw: []const u8) !*const objrt.StoredObject {
        return r.storedObjectDigest(raw, false);
    }

    fn storedObjectDigest(r: *Resolve, raw: []const u8, with_digest: bool) !*const objrt.StoredObject {
        var owner: types.Owner = undefined;
        return r.storedObjectOwner(raw, with_digest, &owner);
    }

    /// The stored object of `raw`, its decoded owner in `owner_out` (one parse).
    fn storedObjectOwner(r: *Resolve, raw: []const u8, with_digest: bool, owner_out: *types.Owner) !*const objrt.StoredObject {
        const view = try ObjectView.parse(raw);
        if (view.is_package) return error.Package;
        const owner = try bcs.decode(types.Owner, r.arena, raw[view.owner_at..view.prev_tx_at]);
        owner_out.* = owner;
        const st = try typing.objectTag(r.arena, raw);
        const tag = try r.arena.create(types.TypeTag);
        tag.* = .{ .@"struct" = st };
        const so = try r.arena.create(objrt.StoredObject);
        so.* = .{
            .id = view.id,
            .owner = try objrt.Owner.fromTypes(r.arena, &owner),
            .version = view.version,
            .previous_transaction = raw[view.prev_tx_at + 1 ..][0..32].*,
            .storage_rebate = view.storageRebate(),
            .digest = if (with_digest) view.digest() else @splat(0),
            .move = .{ .type_ = tag, .contents = view.contents() },
        };
        return so;
    }

    fn readChild(ctx: *anyopaque, parent: *const Id, child: *const Id, upper: u64) objrt.ResolveError!?*const objrt.StoredObject {
        const r: *Resolve = @ptrCast(@alignCast(ctx));
        _ = parent;
        // `config_setting_unsequenced_read`: the store's latest version (read_child_object with
        // SequenceNumber::MAX), not recorded in the effects. Settings are epoch-gated
        // (`read_setting_impl`), so a version current at any point of the epoch reads the same,
        // unless one was written during the epoch (the next-epoch value can change).
        if (upper == objrt.sequence_number_max) {
            const latest = r.objs.latest orelse {
                r.gap = "per-epoch config read without the store's latest objects";
                return null;
            };
            if (r.objs.latest_unstable) |f| if (f(r.objs.ctx, child)) {
                r.gap = "config setting written during the epoch";
                return null;
            };
            const raw = latest(r.objs.ctx, child) orelse return null;
            return r.storedObject(raw) catch {
                r.gap = "config setting does not parse";
                return null;
            };
        }
        const fx = r.fx orelse {
            const st = r.state orelse {
                r.gap = "runtime load without effects or pre-state";
                return null;
            };
            const raw = st.vtable.child_at_most(st.ctx, child, upper) orelse return null;
            return r.storedFrom(raw) catch {
                r.gap = "runtime-loaded object does not parse";
                return null;
            };
        };
        // An accumulator write's change entry says nothing about the accumulator object's prior
        // state (its input state is always NotExist): its read comes from the unchanged list.
        for (fx.changed_objects) |*c| if (std.mem.eql(u8, &c[0].@"0".@"0", child) and c[1].output_state != .AccumulatorWriteV1) switch (c[1].input_state) {
            .Exist => |x| return r.stored(child, x[0][0].@"0"),
            .NotExist => return null,
        };
        const list = r.unchanged orelse {
            // A node executing a certified checkpoint without the archive's list (p2p state
            // sync): `read_child_object` on its store, the newest version at or below the bound.
            // The certified effects check the result.
            if (r.state) |st| {
                const raw = st.vtable.child_at_most(st.ctx, child, upper) orelse return null;
                return r.storedFrom(raw) catch {
                    r.gap = "runtime-loaded object does not parse";
                    return null;
                };
            }
            r.gap = "read-only runtime load without the archive";
            return null;
        };
        for (list) |l| if (std.mem.eql(u8, &l.id, child)) return r.stored(child, l.version);
        return null;
    }

    fn receivedAt(ctx: *anyopaque, owner: *const Id, child: *const Id, version: u64, epoch: u64) objrt.ResolveError!?*const objrt.StoredObject {
        _ = epoch;
        const r: *Resolve = @ptrCast(@alignCast(ctx));
        const raw = r.objs.get(r.objs.ctx, child, version) orelse {
            r.gap = "receiving object not in corpus";
            return null;
        };
        // The store keeps the version after it is received; Sui's Received marker hides it
        // (the same answer as a wrong owner, never a load).
        if (r.objs.received) |f| if (f(r.objs.ctx, child, version)) return null;
        const so = r.storedFromDigest(raw, true) catch {
            r.gap = "receiving object does not parse";
            return null;
        };
        switch (so.owner) {
            .address => |a| if (!std.mem.eql(u8, &a, owner)) return null,
            else => return null,
        }
        return so;
    }

    fn packageAt(ctx: *anyopaque, id: *const Id, version: u64) ?objrt.PackageInfo {
        const r: *Resolve = @ptrCast(@alignCast(ctx));
        const p = (r.cache.get(id) catch return null) orelse return null;
        if (p.version != version) return null;
        return .{ .original_id = p.original_id, .size = p.gas_size };
    }

    /// `object_available_balance`: the accumulator field `Key<ty>` of `owner` as of the
    /// accumulator root version (the archive's read of it), minus the unsettled object
    /// withdrawals of the checkpoint, which replay does not have: an object owner's read is
    /// unsupported, an address's has none.
    fn availableBalance(ctx: *anyopaque, owner: *const Id, ty: *const types.TypeTag) objrt.ResolveError!u128 {
        const r: *Resolve = @ptrCast(@alignCast(ctx));
        const two: types.AccountAddress = .{ .@"0" = blk: {
            var a: Id = @splat(0);
            a[31] = 2;
            break :blk a;
        } };
        const key_args = r.arena.alloc(types.TypeTag, 1) catch return error.Storage;
        key_args[0] = ty.*;
        const key: types.TypeTag = .{ .@"struct" = .{ .address = two, .module = .{ .@"0" = "accumulator" }, .name = .{ .@"0" = "Key" }, .type_args = key_args } };
        const tag = bcs.encodeAlloc(types.TypeTag, r.arena, &key) catch return error.Storage;
        var root: Id = @splat(0);
        root[30] = 0x0a;
        root[31] = 0xcc;
        var len_le: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_le, 32, .little);
        const field = @import("hash").blake2b256(&.{ &[_]u8{0xf0}, &root, &len_le, owner, tag });
        // load_implicitly_read_system_object(0xacc) at the version the scheduler assigned (replay:
        // the certified read-only entry's version), recorded for the effects
        if (r.fx == null) return r.stateBalance(&root, owner, ty);
        if (r.e.root_read == null) {
            const v = for (r.fx.?.unchanged_consensus_objects) |*u| {
                if (std.mem.eql(u8, &u[0].@"0".@"0", &root)) switch (u[1]) {
                    .ReadOnlyRoot => |vd| break vd[0].@"0",
                    else => {},
                };
            } else {
                r.gap = "accumulator root version not assigned";
                return 0;
            };
            const raw = r.objs.get(r.objs.ctx, &root, v) orelse {
                r.gap = "accumulator root not in corpus";
                return 0;
            };
            r.e.root_read = .{ .version = v, .digest = (ObjectView.parse(raw) catch return error.Storage).digest() };
        }
        var unsettled: u128 = 0;
        if (r.e.inputs.contains(owner.*) or r.e.loaded.contains(owner.*)) {
            const u = r.unsettled orelse {
                r.gap = "object balance read";
                return 0;
            };
            unsettled = u.get(u.ctx, r.arena, &field) catch {
                r.gap = "unsettled object withdrawals";
                return 0;
            };
        }
        const list = r.unchanged orelse {
            // Node without the archive's list (see readChild): the store's newest field version.
            if (r.state) |st| {
                const raw = st.vtable.child_at_most(st.ctx, &field, std.math.maxInt(u64)) orelse {
                    if (unsettled != 0) return error.Storage;
                    return 0;
                };
                const so = r.storedFrom(raw) catch return error.Storage;
                const mv = so.move orelse return error.Storage;
                if (mv.contents.len != 32 + 32 + 16) return error.Storage;
                const settled = std.mem.readInt(u128, mv.contents[64..80], .little);
                return std.math.sub(u128, settled, unsettled) catch error.Storage;
            }
            r.gap = "address balance read without the archive";
            return 0;
        };
        for (list) |l| if (std.mem.eql(u8, &l.id, &field)) {
            const so = r.stored(&field, l.version) orelse return 0;
            const mv = so.move orelse return error.Storage;
            // Field<Key<T>, U128> { id: UID, name: Key { address }, value: U128 { value } }
            if (mv.contents.len != 32 + 32 + 16) return error.Storage;
            const settled = std.mem.readInt(u128, mv.contents[64..80], .little);
            return std.math.sub(u128, settled, unsettled) catch error.Storage;
        };
        if (unsettled != 0) return error.Storage;
        r.gap = "address balance not in the archive";
        return 0;
    }

    /// Simulation (no effects): the root read is `SystemObjectVersions::from_inputs_or_latest_in_store`
    /// and the balance comes from the pre-state.
    fn stateBalance(r: *Resolve, root: *const Id, owner: *const Id, ty: *const types.TypeTag) objrt.ResolveError!u128 {
        const st = r.state orelse {
            r.gap = "address balance read without effects or pre-state";
            return 0;
        };
        if (r.e.root_read == null) {
            const v = if (r.e.inputs.get(root.*)) |i| i.view.version else st.vtable.shared_latest(st.ctx, root) orelse {
                r.gap = "accumulator root not in the pre-state";
                return 0;
            };
            const raw = r.objs.get(r.objs.ctx, root, v) orelse {
                r.gap = "accumulator root not in the pre-state";
                return 0;
            };
            r.e.root_read = .{ .version = v, .digest = (ObjectView.parse(raw) catch return error.Storage).digest() };
        }
        if (st.vtable.address_balance(st.ctx, owner, ty)) |b| return b;
        r.gap = "address balance not in the pre-state";
        return 0;
    }

    /// `ImplicitSystemObjectResolver::clock` (v142 `clock::borrow`):
    /// `load_implicitly_read_system_object(0x6)`. A declared Clock input is that object; else the
    /// version the scheduler assigned (replay: the certified read-only entry; simulation: the
    /// store's latest). Recorded for the effects.
    fn clock(ctx: *anyopaque) objrt.ResolveError!?[]const u8 {
        const r: *Resolve = @ptrCast(@alignCast(ctx));
        const id = clock_id;
        const v: u64 = if (r.e.inputs.get(id)) |i| i.view.version else if (r.fx) |fx| for (fx.unchanged_consensus_objects) |*u| {
            if (std.mem.eql(u8, &u[0].@"0".@"0", &id)) switch (u[1]) {
                .ReadOnlyRoot => |vd| break vd[0].@"0",
                else => {},
            };
        } else {
            r.gap = "clock version not assigned";
            return null;
        } else blk: {
            const st = r.state orelse {
                r.gap = "clock read without effects or pre-state";
                return null;
            };
            break :blk st.vtable.shared_latest(st.ctx, &id) orelse {
                r.gap = "clock not in the pre-state";
                return null;
            };
        };
        const raw = r.objs.get(r.objs.ctx, &id, v) orelse {
            r.gap = "clock not in corpus";
            return null;
        };
        const so = r.storedObjectDigest(raw, true) catch {
            r.gap = "clock does not parse";
            return null;
        };
        const mv = so.move orelse return null;
        r.e.clock_read = .{ .version = v, .digest = so.digest };
        return mv.contents;
    }

    const vtable: objrt.Resolver.VTable = .{ .read_child = readChild, .received_at = receivedAt, .package_at = packageAt, .available_balance = availableBalance, .clock = clock };
};

const clock_id: Id = blk: {
    var a: Id = @splat(0);
    a[31] = 6;
    break :blk a;
};

// ---------------------------------------------------------------------------------------------
// Gas: the exec gas status and the VM meter are the same `GasStatus` in Rust.

fn toMeter(g: *const gas_mod.MoveGasStatus, m: *move_vm.Meter) void {
    inline for (@typeInfo(gas_mod.MoveGasStatus).@"struct".field_names) |n| {
        if (comptime @hasField(move_vm.Meter, n) and @FieldType(move_vm.Meter, n) == @FieldType(gas_mod.MoveGasStatus, n)) @field(m, n) = @field(g, n);
    }
    m.charge_enabled = g.metering;
}

fn fromMeter(m: *const move_vm.Meter, g: *gas_mod.MoveGasStatus) void {
    inline for (@typeInfo(gas_mod.MoveGasStatus).@"struct".field_names) |n| {
        if (comptime @hasField(move_vm.Meter, n) and @FieldType(move_vm.Meter, n) == @FieldType(gas_mod.MoveGasStatus, n)) @field(g, n) = @field(m, n);
    }
}

// ---------------------------------------------------------------------------------------------

/// Per-stage time (bench profiling; null: off, no clock reads). Stages: 0 prologue (inputs,
/// gas smash), 1 loading and linkage, 2 typing, meter and verify, 3 VM session and inputs to
/// values, 4 commands (interpreter), 5 finish (object runtime results, deny list), 6 epilogue
/// (storage, effects, digests).
pub var profile: ?*[8]u64 = null;
pub const stage_names = [_][]const u8{ "prologue", "load+link", "typing", "vm-init", "commands", "finish", "epilogue", "other" };

fn clockNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Adds the time since `t.*` to stage `stage` and restarts the clock.
fn lap(stage: usize, t: *u64) void {
    const pr = profile orelse return;
    const now = clockNs();
    pr[stage] += now - t.*;
    t.* = now;
}

pub fn execute(arena: Allocator, env: Env, tx_data_raw: []const u8, data: *const types.TransactionDataV1, in: Inputs) !Outcome {
    var t_prof: u64 = if (profile != null) clockNs() else 0;
    defer lap(6, &t_prof);
    const cfg = env.cfg;
    const gm = try cfg.get("gas_model_version");
    const ev = cfg.getOpt("execution_version") orelse 0;
    // exec-history (CONTRACTS 6.6b): the older cuts that run this static executor.
    if (ev != 4 and !versions.moveSupported(cfg)) return unsupported(arena, "execution version {d}", .{ev});
    // Inputs a validator rejects at signing (an object argument twice, a gas coin twice or also
    // an argument) never reach a certificate: an error, not a skip (as in the coin executor).
    try inputs_mod.signingCheck(arena, data);
    // Gas models 4 to 14 take the legacy path (`legacy::execute_transaction_inner`): one summed
    // input read charge and `legacy_charge_gas`.
    const bump_only = protocol.gas.bumpOnlyEnabled(gm);
    // exec-history: gas models 1..3 only on the dynamic cuts (storage v1 in legacyChargeGas)
    if (gm < 4 and versions.executorOf(cfg) != .dynamic) return unsupported(arena, "gas model {d}", .{gm});
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return unsupported(arena, "not programmable", .{}),
    };
    if (in.track_results and versions.executorOf(cfg) == .dynamic) return unsupported(arena, "command results (DevInspect) on a dynamic cut", .{});
    if (in.skip_all_checks) return unsupported(arena, "DevInspect<true> (checks disabled) not modeled", .{});
    // is_gasless_transaction: address-balance gas at price 0 (`PaymentKind::gasless`; the legacy
    // path also needs `enable_gasless`)
    const gasless = data.gas_data.payment.len == 0 and data.gas_data.price == 0 and (bump_only or cfg.feature_flags.enable_gasless);
    if (data.gas_data.price == 0 and !gasless) return unsupported(arena, "zero gas price", .{});
    if (gasless and usesGasCoin(pt)) return unsupported(arena, "gasless transaction using the gas coin", .{});
    // check_gas: a gasless transaction meters against `gasless_max_computation_units * rgp`
    // at the reference gas price
    const rgp_eff = @max(env.rgp, 1);
    const gas_budget = if (gasless)
        std.math.mul(u64, cfg.gasless_max_computation_units orelse return unsupported(arena, "gasless without a computation cap", .{}), rgp_eff) catch return unsupported(arena, "gasless cap overflow", .{})
    else
        data.gas_data.budget;
    const gas_price = if (gasless) rgp_eff else data.gas_data.price;
    if (data.gas_data.payment.len == 0 and !cfg.feature_flags.enable_address_balance_gas_payments) return unsupported(arena, "address-balance gas payment before the feature", .{});
    if (data.gas_data.payment.len == 0 and !cfg.feature_flags.gasless_transaction_drop_safety) return unsupported(arena, "address-balance gas without a gas coin", .{});

    var e: Exec = .{
        .arena = arena,
        .cfg = cfg,
        .epoch = env.epoch,
        .tx_digest = env.tx_digest orelse types.digest.transactionDataDigest(tx_data_raw),
        .sender = data.sender.@"0",
        .budget = gas_budget,
        .gas = try SuiGasStatus.initWithBudget(cfg, gas_budget, gas_price, env.rgp),
        .gasless = gasless,
        .storage_v1 = gm < 4,
        .cert = in.effects,
        .track = in.track_results,
    };

    // ---- inputs
    var max_v: u64 = 0;
    var deps: std.ArrayList(Id) = .empty;
    const srcs = try arena.alloc(?typing.ObjSource, pt.inputs.len);
    var receiving: std.ArrayList(ReceivingRef) = .empty;
    var reservations: []?typing.Reservation = &.{};
    var cancel_reason: ?u64 = null;
    var any_cancelled = false;
    var cancelled_ids: std.ArrayList(types.ObjectID) = .empty;
    for (pt.inputs, srcs, 0..) |*arg, *src, ri| {
        src.* = null;
        switch (arg.*) {
            .Pure => {},
            .FundsWithdrawal => {},
            .Object => |*oa| switch (oa.*) {
                .ImmOrOwnedObject => |r| {
                    if (inputs_mod.isCoinReservation(&r[2].@"0".@"0")) {
                        // transaction_rewriting: a sender FundsWithdrawal of the accumulator's type
                        if (reservations.len == 0) {
                            reservations = try arena.alloc(?typing.Reservation, pt.inputs.len);
                            @memset(reservations, null);
                        }
                        reservations[ri] = .{ .accumulator = typing.unmaskReservation(cfg.chain, &r[0].@"0".@"0"), .amount = std.mem.readInt(u64, r[2].@"0".@"0"[0..8], .little) };
                        continue;
                    }
                    const id = r[0].@"0".@"0";
                    const raw = in.objs.get(in.objs.ctx, &id, r[1].@"0") orelse return unsupported(arena, "input object not available", .{});
                    const view = try ObjectView.parse(raw);
                    const owner = try bcs.decode(types.Owner, arena, raw[view.owner_at..view.prev_tx_at]);
                    std.debug.assert(!e.inputs.contains(id)); // signingCheck
                    try e.inputs.put(arena, id, .{ .raw = raw, .view = view, .owner = owner });
                    if (owner != .Immutable) try e.mutable.put(arena, id, {});
                    src.* = .{ .raw = raw, .shared_mutable = null };
                },
                .SharedObject => |s| {
                    const id = s.id.@"0".@"0";
                    const sv = sharedVersion(&in, &id) orelse return unsupported(arena, "shared input version not in effects", .{});
                    if (sv.special) {
                        // `CancelledTransactionSharedObject`: no object; get_cancelled_objects
                        if (sv.version < cancelled_read) return unsupported(arena, "consensus stream ended shared input", .{});
                        if (sv.version == congested or sv.version == randomness_unavailable) {
                            if (cancel_reason) |cr| if (cr != sv.version) return unsupported(arena, "two cancellation reasons", .{});
                            cancel_reason = sv.version;
                            try cancelled_ids.append(arena, .{ .@"0" = .{ .@"0" = id } });
                        } else if (sv.version != cancelled_read) return unsupported(arena, "cancellation version", .{});
                        any_cancelled = true;
                        try e.shared.append(arena, .{ .id = id, .version = sv.version, .cancelled = true });
                        continue;
                    }
                    const mutable = switch (s.mutability) {
                        .Mutable => true,
                        .Immutable => false,
                        else => return unsupported(arena, "non-exclusive write input", .{}),
                    };
                    const raw = in.objs.get(in.objs.ctx, &id, sv.version) orelse return unsupported(arena, "shared input not available", .{});
                    const view = try ObjectView.parse(raw);
                    const owner = try bcs.decode(types.Owner, arena, raw[view.owner_at..view.prev_tx_at]);
                    std.debug.assert(!e.inputs.contains(id)); // signingCheck
                    try e.inputs.put(arena, id, .{ .raw = raw, .view = view, .owner = owner });
                    if (mutable) try e.mutable.put(arena, id, {});
                    // the digest is read from the input when the effects need it (sharedDigest)
                    try e.shared.append(arena, .{ .id = id, .version = view.version });
                    src.* = .{ .raw = raw, .shared_mutable = mutable };
                },
                .Receiving => |r| {
                    max_v = @max(max_v, r[1].@"0");
                    try receiving.append(arena, .{ .id = r[0].@"0".@"0", .version = r[1].@"0", .digest = r[2].@"0".@"0" });
                },
            },
        }
    }
    // payment_kind: coin reservations are address-balance methods of the gas owner (merged into
    // one); an empty payment reserves the budget from the gas owner's balance.
    var gas_list: std.ArrayList(Id) = .empty;
    e.ab_owner = data.gas_data.owner.@"0";
    if (gasless) {
        // no payment: no gas coin, no balance charged (`payer` only keeps the effects' gas
        // object index empty)
        e.payer = e.ab_owner;
        for (pt.inputs) |*arg| switch (arg.*) {
            .Object => |*oa| switch (oa.*) {
                .ImmOrOwnedObject => |r| if (inputs_mod.isCoinReservation(&r[2].@"0".@"0")) return unsupported(arena, "gasless transaction with a coin reservation input", .{}),
                else => {},
            },
            else => {},
        };
        // compute_input_reservations (always on the bump-only path) / the legacy
        // `gasless_withdrawal_reservations` (behind `gasless_verify_remaining_balance`)
        if (bump_only or cfg.feature_flags.gasless_verify_remaining_balance) {
            var rs: std.ArrayList(GaslessKey) = .empty;
            for (pt.inputs) |*arg| switch (arg.*) {
                .FundsWithdrawal => |*fw| {
                    const owner: Id = switch (fw.withdraw_from) {
                        .Sender => e.sender,
                        .Sponsor => data.gas_data.owner.@"0",
                        .SenderAllowance => |sa| sa.funder.@"0",
                    };
                    const ty = try bcs.encodeAlloc(types.TypeTag, arena, &fw.type_arg.Balance);
                    const amount = fw.reservation.MaxAmountU64;
                    for (rs.items) |*r| {
                        if (std.mem.eql(u8, &r.owner, &owner) and std.mem.eql(u8, r.ty, ty)) {
                            r.amount +|= amount;
                            break;
                        }
                    } else try rs.append(arena, .{ .owner = owner, .ty = ty, .amount = amount });
                },
                else => {},
            };
            e.gasless_reservations = rs.items;
        }
    } else if (data.gas_data.payment.len == 0) {
        e.ab_present = true;
        e.ab_amount = data.gas_data.budget;
        e.payer = e.ab_owner;
    }
    for (data.gas_data.payment, 0..) |r, pi| {
        if (inputs_mod.isCoinReservation(&r[2].@"0".@"0")) {
            const amount = std.mem.readInt(u64, r[2].@"0".@"0"[0..8], .little);
            e.ab_amount = std.math.add(u64, e.ab_amount, amount) catch return unsupported(arena, "reservation overflow", .{});
            e.ab_present = true;
            if (pi == 0) e.payer = e.ab_owner;
            continue;
        }
        const id = r[0].@"0".@"0";
        // signingCheck: no gas coin twice in the payment or also an object argument
        std.debug.assert(!e.inputs.contains(id));
        const raw = in.objs.get(in.objs.ctx, &id, r[1].@"0") orelse return unsupported(arena, "gas coin not available", .{});
        const view = try ObjectView.parse(raw);
        const owner = try bcs.decode(types.Owner, arena, raw[view.owner_at..view.prev_tx_at]);
        if (owner != .AddressOwner) return unsupported(arena, "gas coin owner kind", .{});
        try e.inputs.put(arena, id, .{ .raw = raw, .view = view, .owner = owner });
        try e.mutable.put(arena, id, {});
        try gas_list.append(arena, id);
    }
    e.gas_ids = gas_list.items;
    const gas_ids = e.gas_ids;
    for (e.inputs.values()) |*x| max_v = @max(max_v, x.view.version);
    e.lamport = max_v + 1;

    // packages named by the commands (`Command::input_objects`)
    {
        var ids: std.ArrayList(Id) = .empty;
        for (pt.commands) |*cmd| switch (cmd.*) {
            .MoveCall => |*mc| {
                try ids.append(arena, mc.package.@"0".@"0");
                for (mc.type_arguments) |*ta| try typeInputPackages(arena, &ids, ta);
            },
            .MakeMoveVec => |*mv| if (mv[0]) |*ta| try typeInputPackages(arena, &ids, ta),
            .Publish => |*x| for (x[1]) |d| try ids.append(arena, d.@"0".@"0"),
            .Upgrade => |*x| {
                for (x[1]) |d| try ids.append(arena, d.@"0".@"0");
                try ids.append(arena, x[2].@"0".@"0");
            },
            else => {},
        };
        const pcache = try pkgs.cacheFor(env.gpa, env.pkgs, env.epoch, env.pv, env.cfg.chain);
        for (ids.items) |*pid| {
            if (e.inputs.contains(pid.*)) continue;
            // an authoritative store without the package: no input object, and the linkage
            // analysis fails the transaction (`Linker.pkg`)
            const po = (try pcache.packageObject(pid)) orelse if (env.authoritative_packages) continue else return unsupported(arena, "package not in corpus", .{});
            try e.inputs.put(arena, pid.*, .{ .raw = po.view.raw, .view = po.view, .owner = po.owner, .gas_size = po.gas_size });
        }
    }
    if (!cfg.feature_flags.disable_effects_tx_dependencies) {
        for (e.inputs.values()) |*x| try deps.append(arena, x.raw[x.view.prev_tx_at + 1 ..][0..32].*);
    }

    // ---- execute_transaction_to_outcome: the IFFW short-circuit, `Outcome::BumpOnly`
    // (`into_bump_only`: only the mutable inputs' version bumps, no gas, no gas object). The
    // legacy path (gas model < 15) short-circuits the same way once `early_exit_on_iffw` is on
    // (`legacy::execute_transaction_inner`: ensure_active_inputs_mutated, gasless charger);
    // before it, mainnet gates on the assigned accumulator version.
    if (in.insufficient_funds and !bump_only and !cfg.feature_flags.early_exit_on_iffw)
        return unsupported(arena, "insufficient funds early error before early_exit_on_iffw", .{});
    if (in.insufficient_funds) {
        try e.ensureActiveInputsMutated();
        e.payer = data.gas_data.owner.@"0";
        try finishDeps(arena, &deps, &.{}, &e);
        return .{ .done = try intoEffects(&e, .{}, .{ .kind = .InsufficientFundsForWithdraw }, deps.items) };
    }

    // get_early_execution_error: a cancelled transaction fails without running
    var early: ?types.ExecutionErrorKind = null;
    if (cancel_reason) |cr| {
        early = if (cr == congested)
            .{ .ExecutionCancelledDueToSharedObjectCongestion = .{ .congested_objects = .{ .@"0" = cancelled_ids.items } } }
        else
            .ExecutionCancelledDueToRandomnessUnavailable;
    } else if (any_cancelled) return unsupported(arena, "cancelled input without a reason", .{});

    // ---- GasCharger::new: smash
    e.smashGas() catch return unsupported(arena, "gas smash", .{});

    // ---- execute_transaction
    var diag: pkgs.Diag = .{};
    var exec_err: ?pkgs.Fail = null;
    var aborted = false;
    if (!bump_only) {
        // charge_input_objects_legacy: one storage read of the summed sizes
        var total: u64 = 0;
        for (e.inputs.keys(), e.inputs.values()) |*id, *x| {
            if (packages.isSystemPackage(id)) continue;
            total += x.gas_size orelse try objects.sizeForGasMetering(arena, &x.view);
        }
        if (e.gas.chargeStorageRead(total)) |_| exec_err = .{ .kind = .InsufficientGas };
    } else {
        const ids = try arena.dupe(Id, e.inputs.keys());
        std.mem.sort(Id, ids, {}, lessBytes);
        for (ids) |*id| {
            if (packages.isSystemPackage(id)) continue;
            const x = e.inputs.getPtr(id.*).?;
            const size = x.gas_size orelse try objects.sizeForGasMetering(arena, &x.view);
            const r = if (x.view.is_package) e.gas.chargePackageObjectRead(size) else e.gas.chargeStorageRead(size);
            if (r) |_| {
                exec_err = .{ .kind = .InsufficientGas };
                break;
            }
        }
    }
    var res: ?run.Results = null;
    var gap: ?[]const u8 = null;
    // execute_ptb ran (round_computation happens only then on the bump-only path)
    var ran = false;
    if (exec_err == null) if (early) |k| {
        exec_err = .{ .kind = k };
    };
    if (exec_err == null) {
        ran = true;
        const cache = try pkgs.cacheFor(env.gpa, env.pkgs, env.epoch, env.pv, env.cfg.chain);
        var linker: pkgs.Linker = .{ .arena = arena, .cache = cache, .cfg = cfg, .diag = &diag, .authoritative = env.authoritative_packages };
        var meter = move_vm.Meter.init(gm, gas_budget, e.gas.move.gas_price);
        toMeter(&e.gas.move, &meter);
        var p: typing.Ptb = .{
            .arena = arena,
            .cfg = cfg,
            .linker = &linker,
            .diag = &diag,
            .meter = &meter,
            .pt = pt,
            .sender = e.sender,
            .sponsor = if (std.mem.eql(u8, &data.gas_data.owner.@"0", &e.sender)) null else data.gas_data.owner.@"0",
            .reservations = reservations,
            .accumulator_types = if (reservations.len == 0) &.{} else if (in.reservation_types) |t| t else if (in.effects) |fx| try accumulatorCoinTypes(arena, fx) else return unsupported(arena, "coin reservation types unknown", .{}),
        };
        var resolve: Resolve = .{ .arena = arena, .objs = in.objs, .fx = in.effects, .state = in.state, .unchanged = in.unchanged_loaded, .unsettled = in.unsettled, .cache = cache, .e = &e };
        var host: move_vm.Host = .{
            .cfg = cfg,
            .tx = .{
                .sender = e.sender,
                .digest = e.tx_digest,
                .epoch = env.epoch,
                .epoch_timestamp_ms = env.epoch_start_ms,
                .rgp = env.rgp,
                .gas_price = gas_price,
                .gas_budget = data.gas_data.budget,
                .sponsor = if (std.mem.eql(u8, &data.gas_data.owner.@"0", &e.sender)) null else data.gas_data.owner.@"0",
            },
            .tx_arena = arena,
            .ty_cache = &cache.ty_args,
        };
        host.rt.epoch = env.epoch;
        host.rt.resolver = .{ .ctx = &resolve, .vtable = &Resolve.vtable };
        lap(0, &t_prof);
        defer {
            if (profile != null) t_prof = clockNs();
        }
        // exec-history: the dynamic cuts run versions/dynamic.zig over the same driver
        const run_res = if (versions.executorOf(cfg) == .dynamic) runDynamic(&e, &p, srcs, &host, cache, gas_ids) else runPtb(&e, &p, srcs, &host, cache, gas_ids);
        const outcome = run_res catch |err| switch (err) {
            error.Unsupported => {
                fromMeter(&meter, &e.gas.move);
                return .{ .unsupported = diag.why };
            },
            error.Fail => null,
            error.OutOfMemory => return error.OutOfMemory,
            else => |x| {
                fromMeter(&meter, &e.gas.move);
                return unsupported(arena, "VM load error {s}", .{@errorName(x)});
            },
        };
        fromMeter(&meter, &e.gas.move);
        gap = resolve.gap;
        if (outcome) |o| {
            res = o;
        } else {
            exec_err = diag.fail;
            aborted = diag.fail.kind == .MoveAbort;
        }
    }
    if (gap) |g| return .{ .unsupported = g };

    // context::finish (after the VM): deny-list charge, then record the results.
    if (res) |r| {
        if (r.non_gas_coin_owners > 0) {
            const cost_per_byte = cfg.getOpt("dynamic_field_borrow_child_object_type_cost_per_byte") orelse 0;
            if (e.gas.chargeStorageRead(1000 * cost_per_byte * r.non_gas_coin_owners)) |_| {
                exec_err = .{ .kind = .InsufficientGas };
            }
            if (!e.inputs.contains(deny_list_id)) e.per_epoch_deny_list = true;
            // check_coin_deny_list_v2_during_execution: charge_coin_transfers, then the result
            // Simulation without `objs.latest` (rpc-exec): the caller checks `Output.deny_pairs`.
            if (exec_err == null) if (in.objs.latest) |latest| {
                if (try deny.check(arena, .{ .ctx = in.objs.ctx, .get = latest }, env.epoch, r.deny_pairs)) |d|
                    exec_err = .{ .kind = d.kind() };
            } else if (in.effects != null) return unsupported(arena, "coin deny list state not available", .{});
        }
        if (exec_err == null) try record(&e, &r);
    }

    if (!bump_only and gasless and exec_err == null) {
        if (!try e.gaslessRequirementsMet()) exec_err = .{ .kind = .InsufficientGas };
    }
    if (!bump_only) {
        exec_err = e.legacyChargeGas(exec_err, aborted and versions.abortAwareBucketing(cfg), protocol.gas.refreshGasPaymentLocation(gm)) catch |err| switch (err) {
            error.Unsupported => return unsupported(arena, "legacy charge path", .{}),
            else => |x| return x,
        };
    } else {
        // ---- round_computation (execute_ptb), meter_storage
        if (ran) if (try e.gas.bucketizeComputation(aborted)) |ge| {
            if (exec_err == null) exec_err = .{ .kind = gasErrKind(ge) };
        };
        if (exec_err == null) {
            if (try e.meterStorage()) |ge| exec_err = .{ .kind = gasErrKind(ge) };
        }
        if (exec_err != null) e.handleError() catch return unsupported(arena, "handle_error path", .{});
    }
    var summary = e.gas.summary();
    if (gasless) {
        // `charge` for Gasless: nothing on failure; on success the sender's rebate is absorbed
        // as computation
        summary = if (exec_err != null) .{} else .{
            .computation_cost = summary.storage_rebate,
            .storage_cost = 0,
            .storage_rebate = summary.storage_rebate,
            .non_refundable_storage_fee = summary.non_refundable_storage_fee,
        };
        if (exec_err == null and e.gas.summary().storage_cost != 0) return unsupported(arena, "gasless storage cost", .{});
    } else e.applyPayment(summary) catch return unsupported(arena, "apply_payment", .{});

    // ---- into_effects
    try finishDeps(arena, &deps, receiving.items, &e);
    var out = try intoEffects(&e, summary, exec_err, deps.items);
    if (res) |r| if (r.deny_pairs.len > 0) {
        const dp = try arena.alloc(run.DenyPair, r.deny_pairs.len);
        for (r.deny_pairs, dp) |p, *d| d.* = .{ .t = try bcs.encodeAlloc(types.TypeTag, arena, &p.tag.?), .o = p.owner };
        out.deny_pairs = dp;
    };
    // DevInspect results exist only for a successful execution (`execution_result` is Err when
    // the status is a failure, and sui-rpc-api renders no command outputs then)
    if (in.track_results and exec_err == null) out.command_results = if (res) |r| r.command_results orelse &.{} else &.{};
    return .{ .done = out };
}

const ReceivingRef = struct { id: Id, version: u64, digest: Id };

/// Receiving objects actually received add their previous transaction; then sorted, deduplicated
/// and without the genesis marker.
fn finishDeps(arena: Allocator, deps: *std.ArrayList(Id), receiving: []const ReceivingRef, e: *const Exec) !void {
    if (!e.cfg.feature_flags.disable_effects_tx_dependencies) {
        for (receiving) |rc| if (e.loaded.get(rc.id)) |m| {
            if (m.version == rc.version and std.mem.eql(u8, &m.digest, &rc.digest) and m.owner == .AddressOwner) try deps.append(arena, m.prev_tx);
        };
    }
    std.mem.sort(Id, deps.items, {}, lessBytes);
    var w: usize = 0;
    for (deps.items) |d| {
        if (std.mem.eql(u8, &d, &zero32)) continue;
        if (w > 0 and std.mem.eql(u8, &deps.items[w - 1], &d)) continue;
        deps.items[w] = d;
        w += 1;
    }
    deps.shrinkRetainingCapacity(w);
}

fn gasErrKind(g: gas_mod.GasError) types.ExecutionErrorKind {
    return switch (g) {
        .InsufficientGas => .InsufficientGas,
        .InvariantViolation => .InvariantViolation,
    };
}

/// Translation, verification and execution. Returns null on an execution failure (`diag.fail`).
fn runPtb(e: *Exec, p: *typing.Ptb, srcs: []const ?typing.ObjSource, host: *move_vm.Host, cache: *pkgs.Cache, gas_ids: []const Id) (pkgs.Error || move_vm.loader.LoadError)!?run.Results {
    var t: u64 = if (profile != null) clockNs() else 0;
    defer lap(5, &t);
    try typing.load(p, srcs);
    lap(1, &t);
    try typing.typeTx(p);
    try typing.typingMeter(p);
    try typing.verify(p);
    lap(2, &t);
    const arena = p.arena;
    // A transaction that publishes or upgrades links against packages that leave the runtime
    // at its end: its own link context. Every other one shares the cache's by linkage.
    const own_link = for (p.cmds.items) |*c| {
        if (c.tag == .publish or c.tag == .upgrade) break true;
    } else false;
    const link = if (own_link) blk: {
        const lc = try arena.create(move_vm.LinkCtx);
        lc.* = move_vm.LinkCtx.init(cache.rt, try pkgs.rootPackage(arena, cache.rt, p.unified));
        break :blk lc;
    } else try cache.linkCtx(p.unified);
    defer if (own_link) link.deinit();
    const ecfg = versions.execConfig(p.cfg) catch return p.diag.unsupported("execution config");
    var sess = try move_vm.Session.init(arena, link, p.meter, ecfg);
    sess.natives = try versions.nativeTable(arena, p.cfg, host.table());
    sess.ext = host;
    var r: run.Run = .{
        .p = p,
        .arena = arena,
        .host = host,
        .sess = sess,
        .link = link,
        .budget = e.budget,
        .sender = e.sender,
        .gas = if (e.gasless) .{ .owner = .{ .AddressOwner = .{ .@"0" = e.sender } }, .absent = true } else if (e.payer) |payer| .{ .owner = .{ .AddressOwner = .{ .@"0" = payer } }, .ephemeral = true, .amount = e.total_smashed } else .{
            .id = gas_ids[0],
            .version = e.inputs.getPtr(gas_ids[0]).?.view.version,
            .owner = e.inputs.getPtr(gas_ids[0]).?.owner,
            .contents = e.results.written.get(gas_ids[0]).?.contents,
        },
        .objs = try arena.alloc(move_vm.Value, p.objects.items.len),
        .pure = try arena.alloc(move_vm.Value, p.pure.items.len),
        .recv = try arena.alloc(move_vm.Value, p.receiving.items.len),
        .track = e.track,
    };
    @memset(r.objs, move_vm.Value.invalid);
    @memset(r.pure, move_vm.Value.invalid);
    @memset(r.recv, move_vm.Value.invalid);
    defer for (r.call_links.items) |lc| lc.deinit();
    // Rust's package store lives for one transaction: published and upgraded packages leave
    // the thread's runtime with it (committed ones load again from storage)
    defer cache.endTransaction(r.published.items);
    try run.init(&r);
    lap(3, &t);
    try run.commands(&r);
    lap(4, &t);
    return try run.finish(&r);
}

/// exec-history: the dynamic executor (`programmable_transactions`) of the cuts before v3 static.
fn runDynamic(e: *Exec, p: *typing.Ptb, srcs: []const ?typing.ObjSource, host: *move_vm.Host, cache: *pkgs.Cache, gas_ids: []const Id) (pkgs.Error || move_vm.loader.LoadError)!?run.Results {
    if (e.gasless or e.payer != null or gas_ids.len == 0) return p.diag.unsupported("address-balance gas on a dynamic cut");
    const gid = gas_ids[0];
    return try dynamic.execute(p, srcs, host, cache, .{
        .budget = e.budget,
        .sender = e.sender,
        .gas = .{ .raw = e.inputs.getPtr(gid).?.raw, .contents = e.results.written.get(gid).?.contents },
    });
}

/// `record_execution_results` into the smashed state.
fn record(e: *Exec, r: *const run.Results) !void {
    const arena = e.arena;
    e.events = r.events;
    try e.results.acc.appendSlice(arena, r.acc);
    if (e.payer != null and r.gas_transferred) e.charge_coin = r.gas_id;
    if (r.gas_send_to) |rcpt| {
        e.charge_coin = null;
        e.charge_addr = rcpt;
    }
    for (r.deleted) |id| {
        _ = e.results.written.swapRemove(id);
        _ = e.results.created.swapRemove(id);
    }
    for (r.writes) |*w| {
        _ = e.results.deleted.swapRemove(w.id);
        try e.results.written.put(arena, w.id, .{
            .id = w.id,
            .type_bytes = typeBytes(arena, &w.tag, w.has_public_transfer) catch return error.Unsupported,
            .contents = w.contents,
            .owner = w.owner,
        });
    }
    for (r.packages) |*pk| {
        try e.results.written.put(arena, pk.id, .{ .id = pk.id, .type_bytes = &.{}, .contents = &.{}, .owner = .Immutable, .package = .{ .version = pk.version, .bcs = pk.bytes } });
        try e.results.created.put(arena, pk.id, {});
    }
    for (r.modified) |id| try e.results.modified.put(arena, id, {});
    for (r.created) |id| try e.results.created.put(arena, id, {});
    for (r.deleted) |id| try e.results.deleted.put(arena, id, {});
}

/// Every object digest the effects need, in one multi-buffer Blake2b pass (`digestOfMany`):
/// the written objects' new digests, the modified inputs' and runtime loads' prior digests, and
/// the shared inputs' (read-only roots). Same values as hashing each one on use.
fn hashAll(e: *Exec) !void {
    const Slot = union(enum) { write: *Write, input: *Input, loaded: *Meta };
    var raws: std.ArrayList([]const u8) = .empty;
    var slots: std.ArrayList(Slot) = .empty;
    for (e.results.written.values()) |*w| {
        try raws.append(e.arena, w.bytes);
        try slots.append(e.arena, .{ .write = w });
    }
    for (e.results.modified.keys()) |id| {
        if (e.inputs.getPtr(id)) |in| {
            if (in.digest == null) {
                in.digest = zero32; // queued once
                try raws.append(e.arena, in.raw);
                try slots.append(e.arena, .{ .input = in });
            }
        } else if (e.loaded.getPtr(id)) |m| if (m.raw) |raw| {
            m.raw = null;
            try raws.append(e.arena, raw);
            try slots.append(e.arena, .{ .loaded = m });
        };
    }
    for (e.shared.items) |sh| if (!sh.cancelled) if (e.inputs.getPtr(sh.id)) |in| if (in.digest == null) {
        in.digest = zero32;
        try raws.append(e.arena, in.raw);
        try slots.append(e.arena, .{ .input = in });
    };
    if (raws.items.len == 0) return;
    const out = try e.arena.alloc(Id, raws.items.len);
    types.digest.digestOfMany("Object", raws.items, out);
    for (slots.items, out) |sl, d| switch (sl) {
        .write => |w| w.digest = d,
        .input => |in| in.digest = d,
        .loaded => |m| m.digest = d,
    };
}

fn intoEffects(e: *Exec, summary: gas_mod.GasCostSummary, err: ?pkgs.Fail, deps: []const Id) !Output {
    const arena = e.arena;
    // update_version_and_previous_tx
    var written: std.ArrayList(coin_ptb.Written) = .empty;
    for (e.results.written.values()) |*w| {
        switch (w.owner) {
            .Shared => |*s| {
                if (e.results.created.contains(w.id)) s.initial_shared_version = .{ .@"0" = e.lamport };
                if (e.cfg.feature_flags.reshare_at_same_initial_version) if (e.inputs.getPtr(w.id)) |x| switch (x.owner) {
                    .Shared => |ps| s.initial_shared_version = ps.initial_shared_version,
                    else => {},
                };
            },
            .ConsensusAddressOwner => |*c| {
                const prev: ?types.Owner = if (e.inputs.getPtr(w.id)) |x| x.owner else null;
                c.start_version = .{ .@"0" = e.lamport };
                if (prev) |po| switch (po) {
                    .ConsensusAddressOwner => |pc| if (std.mem.eql(u8, &pc.owner.@"0", &c.owner.@"0")) {
                        c.start_version = pc.start_version;
                    },
                    else => {},
                };
            },
            else => {},
        }
        w.bytes = try writeBytes(arena, w, e.lamport, &e.tx_digest);
        try written.append(arena, .{ .id = w.id, .bytes = w.bytes });
    }
    try hashAll(e);
    // exec-history: TransactionEffectsV1 before `enable_effects_v2` (protocols before 33)
    if (!e.cfg.feature_flags.enable_effects_v2) return effectsV1(e, summary, err, deps, written.items);
    var ids: std.ArrayList(Id) = .empty;
    for (e.results.created.keys()) |id| try ids.append(arena, id);
    for (e.results.deleted.keys()) |id| try ids.append(arena, id);
    for (e.results.modified.keys()) |id| try ids.append(arena, id);
    for (e.results.written.keys()) |id| try ids.append(arena, id);
    std.mem.sort(Id, ids.items, {}, lessBytes);
    var changes: std.ArrayList(struct { types.ObjectID, types.EffectsObjectChange }) = .empty;
    var gas_index: ?u32 = null;
    for (ids.items, 0..) |id, k| {
        if (k > 0 and std.mem.eql(u8, &ids.items[k - 1], &id)) continue;
        const in_state: types.ObjectIn = if (e.modifiedAt(&id)) |m|
            .{ .Exist = .{ .{ .{ .@"0" = m.version }, .{ .@"0" = .{ .@"0" = m.digest } } }, m.owner } }
        else
            .NotExist;
        const out_state: types.ObjectOut = if (e.results.written.getPtr(id)) |w| if (w.package) |pk|
            .{ .PackageWrite = .{ .{ .@"0" = pk.version }, .{ .@"0" = .{ .@"0" = w.digest } } } }
        else
            .{ .ObjectWrite = .{ .{ .@"0" = .{ .@"0" = w.digest } }, w.owner } }
        else
            .NotExist;
        const op: types.IDOperation = if (e.results.created.contains(id)) .Created else if (e.results.deleted.contains(id)) .Deleted else .None;
        if (e.payer == null and std.mem.eql(u8, &id, &e.gas_ids[0])) gas_index = @intCast(changes.items.len);
        try changes.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .input_state = in_state, .output_state = out_state, .id_operation = op } });
    }
    // accumulator writes (`merge_accumulator_events`: one per accumulator object), in id order
    // with the objects
    if (e.results.acc.items.len > 0) {
        var groups: std.AutoArrayHashMapUnmanaged(Id, std.ArrayList(run.AccWrite)) = .empty;
        for (e.results.acc.items) |w| {
            const gop = try groups.getOrPut(arena, w.id);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(arena, w);
        }
        for (groups.keys(), groups.values()) |id, list| {
            const first = list.items[0];
            var out: types.AccumulatorWriteV1 = .{ .address = .{ .address = .{ .@"0" = first.addr }, .ty = first.ty }, .operation = first.op, .value = first.value };
            if (list.items.len > 1) switch (first.value) {
                .Integer => {
                    var merge: u64 = 0;
                    var split: u64 = 0;
                    for (list.items) |w| switch (w.value) {
                        .Integer => |v| if (w.op == .Merge) {
                            merge = std.math.add(u64, merge, v) catch return error.Unsupported;
                        } else {
                            split = std.math.add(u64, split, v) catch return error.Unsupported;
                        },
                        else => return error.Unsupported,
                    };
                    out.operation = if (merge >= split) .Merge else .Split;
                    out.value = .{ .Integer = if (merge >= split) merge - split else split - merge };
                },
                .EventDigest => {
                    const El = @typeInfo(@FieldType(types.AccumulatorValue, "EventDigest")).pointer.child;
                    var all: std.ArrayList(El) = .empty;
                    for (list.items) |w| switch (w.value) {
                        .EventDigest => |d| try all.appendSlice(arena, d),
                        else => return error.Unsupported,
                    };
                    out.operation = .Merge;
                    out.value = .{ .EventDigest = all.items };
                },
                .IntegerTuple => return error.Unsupported,
            };
            try changes.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .input_state = .NotExist, .output_state = .{ .AccumulatorWriteV1 = out }, .id_operation = .None } });
        }
        const C = @TypeOf(changes.items[0]);
        std.mem.sort(C, changes.items, {}, struct {
            fn lt(_: void, x: C, y: C) bool {
                return std.mem.order(u8, &x[0].@"0".@"0", &y[0].@"0".@"0") == .lt;
            }
        }.lt);
        if (gas_index != null) for (changes.items, 0..) |c, k| {
            if (std.mem.eql(u8, &c[0].@"0".@"0", &e.gas_ids[0])) gas_index = @intCast(k);
        };
    }
    var unchanged: std.ArrayList(struct { types.ObjectID, types.UnchangedConsensusKind }) = .empty;
    for (e.shared.items) |s| {
        if (s.cancelled) {
            try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = s.id } }, .{ .Cancelled = .{ .@"0" = s.version } } });
            continue;
        }
        var changed = false;
        for (ids.items) |id| if (std.mem.eql(u8, &id, &s.id)) {
            changed = true;
            break;
        };
        if (changed) continue;
        try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = s.id } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = s.version }, .{ .@"0" = .{ .@"0" = e.sharedDigest(&s) } } } } });
    }
    if (e.per_epoch_deny_list) try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = deny_list_id } }, .PerEpochConfig });
    // `loaded_system_objects` in id order (0x6 before 0xacc), each skipped when the effects
    // already record it as changed or unchanged.
    if (e.clock_read) |cr| {
        var recorded = false;
        for (ids.items) |id| if (std.mem.eql(u8, &id, &clock_id)) {
            recorded = true;
        };
        for (unchanged.items) |u| if (std.mem.eql(u8, &u[0].@"0".@"0", &clock_id)) {
            recorded = true;
        };
        if (!recorded) try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = clock_id } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = cr.version }, .{ .@"0" = .{ .@"0" = cr.digest } } } } });
    }
    if (e.root_read) |rr| {
        var root: Id = @splat(0);
        root[30] = 0x0a;
        root[31] = 0xcc;
        var recorded = false;
        for (ids.items) |id| if (std.mem.eql(u8, &id, &root)) {
            recorded = true;
        };
        for (unchanged.items) |u| if (std.mem.eql(u8, &u[0].@"0".@"0", &root)) {
            recorded = true;
        };
        if (!recorded) try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = root } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = rr.version }, .{ .@"0" = .{ .@"0" = rr.digest } } } } });
    }
    const dep_list = try arena.alloc(types.TransactionDigest, deps.len);
    for (deps, dep_list) |d, *o| o.* = .{ .@"0" = .{ .@"0" = d } };
    var events_raw: ?[]const u8 = null;
    var events_digest: ?types.TransactionEventsDigest = null;
    if (e.events.len > 0) {
        const te: types.TransactionEvents = .{ .data = e.events };
        const raw = try bcs.encodeAlloc(types.TransactionEvents, arena, &te);
        events_raw = raw;
        events_digest = .{ .@"0" = .{ .@"0" = types.digest.eventsDigest(raw) } };
    }
    const status: types.ExecutionStatus = if (err) |x| .{ .Failure = .{ .@"error" = x.kind, .command = x.command } } else .Success;
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = status,
        .executed_epoch = e.epoch,
        .gas_used = .{
            .computationCost = summary.computation_cost,
            .storageCost = summary.storage_cost,
            .storageRebate = summary.storage_rebate,
            .nonRefundableStorageFee = summary.non_refundable_storage_fee,
        },
        .transaction_digest = .{ .@"0" = .{ .@"0" = e.tx_digest } },
        .gas_object_index = gas_index,
        .events_digest = events_digest,
        .dependencies = dep_list,
        .lamport_version = .{ .@"0" = e.lamport },
        .changed_objects = changes.items,
        .unchanged_consensus_objects = unchanged.items,
        .aux_data_digest = null,
    } };
    const loaded = try arena.alloc(Ref, e.loaded.count());
    for (e.loaded.keys(), e.loaded.values(), loaded) |id, m, *l| l.* = .{ .id = id, .version = m.version };
    return .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, arena, &fx), .events = events_raw, .written = written.items, .loaded = loaded };
}

/// exec-history: v0..v2 `TemporaryStore::into_effects_v1` (written objects in id order: mutated
/// when `get_object_modified_at` knows them, else created, else unwrapped; modified and not written:
/// deleted or wrapped; deleted and not modified: unwrapped then deleted; `modified_at_versions` the
/// mutated ones, then the deleted/wrapped ones).
fn effectsV1(e: *Exec, summary: gas_mod.GasCostSummary, err: ?pkgs.Fail, deps: []const Id, written: []const coin_ptb.Written) !Output {
    const arena = e.arena;
    const ORef = struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest };
    const RefOwner = struct { ORef, types.Owner };
    const At = struct { types.ObjectID, types.SequenceNumber };
    const ref = struct {
        fn f(id: Id, v: u64, d: Id) ORef {
            return .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = v }, .{ .@"0" = .{ .@"0" = d } } };
        }
    }.f;
    var modified_at: std.ArrayList(At) = .empty;
    var deleted_at: std.ArrayList(At) = .empty;
    var created: std.ArrayList(RefOwner) = .empty;
    var mutated: std.ArrayList(RefOwner) = .empty;
    var unwrapped: std.ArrayList(RefOwner) = .empty;
    var deleted: std.ArrayList(ORef) = .empty;
    var unwrapped_then_deleted: std.ArrayList(ORef) = .empty;
    var wrapped: std.ArrayList(ORef) = .empty;
    var gas_object: RefOwner = .{ ref(zero32, 0, zero32), .{ .AddressOwner = .{ .@"0" = zero32 } } };

    const wids = try arena.dupe(Id, e.results.written.keys());
    std.mem.sort(Id, wids, {}, lessBytes);
    for (wids) |id| {
        const w = e.results.written.getPtr(id).?;
        const version = if (w.package) |pk| pk.version else e.lamport;
        const r: RefOwner = .{ ref(id, version, w.digest), w.owner };
        if (e.modifiedAt(&id)) |m| {
            try modified_at.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = m.version } });
            try mutated.append(arena, r);
        } else if (e.results.created.contains(id)) {
            try created.append(arena, r);
        } else try unwrapped.append(arena, r);
        if (e.gas_ids.len > 0 and std.mem.eql(u8, &id, &e.gas_ids[0])) gas_object = r;
    }
    const mids = try arena.dupe(Id, e.results.modified.keys());
    std.mem.sort(Id, mids, {}, lessBytes);
    for (mids) |id| {
        if (e.results.written.contains(id)) continue;
        const m = e.modifiedAt(&id) orelse return error.Unsupported;
        try deleted_at.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = m.version } });
        if (e.results.deleted.contains(id))
            try deleted.append(arena, ref(id, e.lamport, @splat(99)))
        else
            try wrapped.append(arena, ref(id, e.lamport, @splat(88)));
    }
    const dids = try arena.dupe(Id, e.results.deleted.keys());
    std.mem.sort(Id, dids, {}, lessBytes);
    // v0 before `simplified_unwrap_then_delete` (protocol 16): `UnwrapThenDeleteDEPRECATED` takes
    // the version of the object's tombstone (`get_latest_parent_entry_ref_deprecated`) into
    // `modified_at_versions`; an object that never existed in storage leaves no entry at all.
    // The tombstone is read from the certified effects (the follower's record of that version).
    const deprecated_utd = versions.executionVersion(e.cfg) == 0 and !e.cfg.feature_flags.simplified_unwrap_then_delete;
    for (dids) |id| {
        if (e.results.modified.contains(id)) continue;
        if (deprecated_utd) {
            const fx = e.cert orelse return error.Unsupported;
            const old: ?u64 = for (fx.changed_objects) |ch| {
                if (std.mem.eql(u8, &ch[0].@"0".@"0", &id)) switch (ch[1].input_state) {
                    .Exist => |x| break x[0][0].@"0",
                    .NotExist => break null,
                };
            } else null;
            const v = old orelse continue;
            try deleted_at.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = v } });
        }
        try unwrapped_then_deleted.append(arena, ref(id, e.lamport, @splat(99)));
    }
    // v0 lists every delete kind's old version in one id-ordered map
    if (deprecated_utd) std.mem.sort(At, deleted_at.items, {}, struct {
        fn f(_: void, a: At, b: At) bool {
            return std.mem.order(u8, &a[0].@"0".@"0", &b[0].@"0".@"0") == .lt;
        }
    }.f);
    try modified_at.appendSlice(arena, deleted_at.items);
    var shared: std.ArrayList(ORef) = .empty;
    for (e.shared.items) |x| {
        if (x.cancelled) return error.Unsupported;
        try shared.append(arena, ref(x.id, x.version, e.sharedDigest(&x)));
    }
    const dep_list = try arena.alloc(types.TransactionDigest, deps.len);
    for (deps, dep_list) |d, *o| o.* = .{ .@"0" = .{ .@"0" = d } };
    var events_raw: ?[]const u8 = null;
    var events_digest: ?types.TransactionEventsDigest = null;
    if (e.events.len > 0) {
        const te: types.TransactionEvents = .{ .data = e.events };
        const raw = try bcs.encodeAlloc(types.TransactionEvents, arena, &te);
        events_raw = raw;
        events_digest = .{ .@"0" = .{ .@"0" = types.digest.eventsDigest(raw) } };
    }
    const status: types.ExecutionStatus = if (err) |x| .{ .Failure = .{ .@"error" = x.kind, .command = x.command } } else .Success;
    const fx: types.TransactionEffects = .{ .V1 = .{
        .status = status,
        .executed_epoch = e.epoch,
        .gas_used = .{
            .computationCost = summary.computation_cost,
            .storageCost = summary.storage_cost,
            .storageRebate = summary.storage_rebate,
            .nonRefundableStorageFee = summary.non_refundable_storage_fee,
        },
        .modified_at_versions = modified_at.items,
        .shared_objects = shared.items,
        .transaction_digest = .{ .@"0" = .{ .@"0" = e.tx_digest } },
        .created = created.items,
        .mutated = mutated.items,
        .unwrapped = unwrapped.items,
        .deleted = deleted.items,
        .unwrapped_then_deleted = unwrapped_then_deleted.items,
        .wrapped = wrapped.items,
        .gas_object = gas_object,
        .events_digest = events_digest,
        .dependencies = dep_list,
    } };
    const loaded = try arena.alloc(Ref, e.loaded.count());
    for (e.loaded.keys(), e.loaded.values(), loaded) |id, m, *l| l.* = .{ .id = id, .version = m.version };
    return .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, arena, &fx), .events = events_raw, .written = written, .loaded = loaded };
}

/// exec-history: the certified V1 effects as the driver's V2 view (`Inputs.effects`): what it
/// reads from them is the input version of each changed object (`modified_at_versions`; created
/// ones NotExist) and the shared inputs' versions (`shared_objects`, read-only when unmodified).
/// Digests and owners of input states are not read (left zero / address 0).
pub fn v2View(arena: Allocator, v1: *const types.TransactionEffectsV1) !*types.TransactionEffectsV2 {
    const C = struct { types.ObjectID, types.EffectsObjectChange };
    var changes: std.ArrayList(C) = .empty;
    const none: types.Owner = .{ .AddressOwner = .{ .@"0" = zero32 } };
    for (v1.modified_at_versions) |m| try changes.append(arena, .{ m[0], .{
        .input_state = .{ .Exist = .{ .{ m[1], .{ .@"0" = .{ .@"0" = zero32 } } }, none } },
        .output_state = .NotExist,
        .id_operation = .None,
    } });
    for (v1.created) |c| try changes.append(arena, .{ c[0][0], .{ .input_state = .NotExist, .output_state = .NotExist, .id_operation = .Created } });
    var unchanged: std.ArrayList(struct { types.ObjectID, types.UnchangedConsensusKind }) = .empty;
    for (v1.shared_objects) |sref| {
        const modified = for (v1.modified_at_versions) |m| {
            if (std.mem.eql(u8, &m[0].@"0".@"0", &sref[0].@"0".@"0")) break true;
        } else false;
        if (!modified) try unchanged.append(arena, .{ sref[0], .{ .ReadOnlyRoot = .{ sref[1], sref[2] } } });
    }
    const out = try arena.create(types.TransactionEffectsV2);
    out.* = .{
        .status = v1.status,
        .executed_epoch = v1.executed_epoch,
        .gas_used = v1.gas_used,
        .transaction_digest = v1.transaction_digest,
        .gas_object_index = null,
        .events_digest = v1.events_digest,
        .dependencies = v1.dependencies,
        .lamport_version = .{ .@"0" = 0 },
        .changed_objects = changes.items,
        .unchanged_consensus_objects = unchanged.items,
        .aux_data_digest = null,
    };
    return out;
}

test {
    std.testing.refAllDecls(@This());
}
