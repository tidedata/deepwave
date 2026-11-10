//! Execution of coin-only programmable transactions (SplitCoins, MergeCoins, TransferObjects)
//! paid by gas coins, on every execution version. This is the first vertical slice of the
//! adapter (CONTRACTS 6.4.1 part 3).
//!
//! - Execution version 4 (`sui-execution/latest`), and version 3 once `enable_ptb_execution_v2`
//!   is on, run the static PTB executor. From gas model 15 the bump-only pipeline applies:
//!   execute_transaction_to_effects -> execute_transaction_to_outcome -> execute_transaction:
//!   TemporaryStore::new, GasCharger::new (smash_gas), charge_input_objects,
//!   static_programmable_transactions::execute (translation meter, Context::new, commands,
//!   Context::finish, ObjectRuntime::finish, finish_gas_coin, context::finish with the coin
//!   deny-list charge), round_computation, meter_storage, handle_error, charge (apply_payment),
//!   TemporaryStore::into_effects (update_version_and_previous_tx, effects V2). Below gas model
//!   15 it is `charge_input_objects_legacy` and `legacy_charge_gas`.
//! - Execution versions 0 to 3 before that flag run the dynamic executor
//!   (`programmable_transactions/execution.rs`). It has no translation meter, it checks
//!   arguments when it reaches a command, it splits coins one amount at a time, and it rejects
//!   non-public transfers at run time. Charging goes through `charge_gas`, with
//!   `handle_storage_and_rebate_v1` below gas model 4. Effects are V1 until `enable_effects_v2`.
//!
//! Anything this slice does not model returns `.unsupported` with a reason, never a guess:
//! - argument and typing errors other than InvalidTransferObject and MergeCoins TypeMismatch.
//!   The static executor reports them before execution. The dynamic executor reports them when
//!   it reaches the command, so the slice runs up to that command (`StaticResult.cutoff`).
//! - shared, receiving and withdrawal inputs, address-balance gas payment, coin reservations,
//!   and non-coin objects in SplitCoins/MergeCoins.
//! - Move gas of the static executor. Its meter charges a few hundred internal units at most for
//!   these commands, far below the 1000-unit floor of `half_digits_rounding`, so computation
//!   cost is `1000 * gas price` whatever the exact charges are. The model charges every input
//!   object read exactly (`charge_input_objects`, the coin deny-list charge). It charges the value
//!   copies, moves, borrows and command pops of `Context` with the abstract sizes of coins (48),
//!   u64 (8), address (32) and references (8), and approximates the typing meter's type-node and
//!   reference charges from the inputs. A transaction whose modeled Move gas reaches 500 units
//!   is reported unsupported, so a pass never depends on the approximation. The dynamic
//!   executor meters only Move calls, so its gas (the storage reads) is exact.
const std = @import("std");
const types = @import("types");
const protocol = @import("protocol");
const bcs = @import("bcs");
const natives = @import("natives");
const objects = @import("objects.zig");
const gas_mod = @import("gas.zig");
const inputs = @import("inputs.zig");
const deny = @import("ptb/deny.zig");

const Allocator = std.mem.Allocator;
const ObjectView = objects.ObjectView;
const SuiGasStatus = gas_mod.SuiGasStatus;

pub const ObjectLookup = struct {
    ctx: *const anyopaque,
    get: *const fn (ctx: *const anyopaque, id: *const [32]u8, version: u64) ?[]const u8,
    /// The store's latest object at execution (`ObjectStore::get_object`), for reads outside
    /// the inputs: the coin deny list v2 (`ptb/deny.zig`). null: a transaction that would read
    /// it is unsupported.
    latest: ?*const fn (ctx: *const anyopaque, id: *const [32]u8) ?[]const u8 = null,
    /// True when the store's latest version of `id` may not be the one the transaction saw (a
    /// replay snapshot with a version written during the executing epoch). null: always exact.
    latest_unstable: ?*const fn (ctx: *const anyopaque, id: *const [32]u8) bool = null,
    /// `have_received_object_at_version`: true when a transaction executed before this one
    /// already received `id` at `version` (Sui's per-epoch Received marker). `receive` of such a
    /// ref finds no object (`EUnableToReceiveObject`) although the store still holds that
    /// version. null: no transaction before this one is known (the replay corpus).
    received: ?*const fn (ctx: *const anyopaque, id: *const [32]u8, version: u64) bool = null,
    /// The versions consensus assigned to the transaction's shared inputs (exec-system,
    /// CONTRACTS 6.4.2). A shared input without one is unsupported.
    assigned: []const inputs.Assigned = &.{},
};

pub const Written = struct { id: [32]u8, bytes: []const u8 };

pub const Output = struct {
    effects: []const u8,
    written: []const Written,
};

pub const Outcome = union(enum) {
    done: Output,
    unsupported: []const u8,
};

const zero32: [32]u8 = @splat(0);
const deny_list_id: [32]u8 = blk: {
    var a: [32]u8 = @splat(0);
    a[30] = 0x04;
    a[31] = 0x03;
    break :blk a;
};

/// Abstract memory sizes (move-vm-runtime `views.rs`, include_vector_size, no traversal).
const coin_size: u64 = 2 + 2 + 2 + 32 + 2 + 8;
const u64_size: u64 = 8;
const address_size: u64 = 32;
const reference_size: u64 = 8;

const Unsupported = error{Unsupported};

/// One input object of the transaction (`TemporaryStore::input_objects`).
const Input = struct {
    raw: []const u8,
    view: ObjectView,
    /// AddressOwner, or null for Immutable and consensus objects.
    owner_addr: ?[32]u8,
    coin: bool,
    /// The owner's BCS bytes as stored.
    owner_raw: []const u8 = &.{},
    /// A shared (consensus) input at its assigned version, never used by a command: written back
    /// unchanged when mutable (`ensure_active_inputs_mutated`), else listed as a read-only root.
    shared: bool = false,
};

/// An object the transaction writes: header bytes of the source (Data tag, type,
/// has_public_transfer), the version it had (0 when new), the contents and the new owner.
const Write = struct {
    id: [32]u8,
    type_bytes: []const u8, // raw[0 .. version_at] of a source object: tag, type, has_public_transfer
    old_version: u64,
    contents: []const u8,
    owner: [32]u8,
    storage_rebate: u64,
    /// A consensus object written back with its owner unchanged (these BCS bytes, not
    /// AddressOwner(owner)).
    owner_raw: ?[]const u8 = null,
    // filled by into_effects
    bytes: []const u8 = &.{},
};

const Value = union(enum) {
    coin: struct { id: [32]u8, balance: u64, header: []const u8 },
    object: u16, // index into `inputs`
};

const Results = struct {
    written: std.AutoArrayHashMapUnmanaged([32]u8, Write) = .empty,
    modified: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    created: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    deleted: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,

    fn dropWrites(r: *Results) void {
        r.written.clearRetainingCapacity();
        r.modified.clearRetainingCapacity();
        r.created.clearRetainingCapacity();
        r.deleted.clearRetainingCapacity();
    }
};

const Exec = struct {
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    tx_digest: [32]u8,
    sender: [32]u8,
    budget: u64,
    gas: SuiGasStatus,
    /// id -> input object (owned/immutable inputs and gas coins).
    inputs: std.AutoArrayHashMapUnmanaged([32]u8, Input) = .empty,
    /// Exclusive mutable inputs: id -> (version, digest, owner).
    mutable: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    gas_ids: []const [32]u8 = &.{},
    /// Shared inputs in transaction order (`InputObjects::filter_shared_objects`).
    shared_ids: std.ArrayList([32]u8) = .empty,
    total_smashed: u64 = 0,
    results: Results = .{},
    lamport: u64 = 0,
    ids_created: u64 = 0,
    non_gas_coin_owners: u64 = 0,
    per_epoch_deny_list: bool = false,
    /// Execution versions 0 to 3 before `enable_ptb_execution_v2`: the dynamic executor of
    /// `programmable_transactions/execution.rs` (no translation meter, runtime argument checks).
    dynamic: bool = false,
    /// See `StaticResult.cutoff`.
    cutoff: ?struct { at: usize, reason: []const u8 } = null,
    unsupported_reason: ?[]const u8 = null,
    /// The object store (latest reads for the deny list) and the executing epoch.
    objs: ObjectLookup = undefined,
    epoch: u64 = 0,
    /// `context::finish` charges coin transfers against the deny list (deny list v2).
    deny_list_v2: bool = true,
    /// `enable_effects_v2` off: TransactionEffectsV1.
    effects_v1: bool = false,
    /// gas model below 4: `handle_storage_and_rebate_v1` charges the budget on storage OOG.
    storage_v1: bool = false,

    fn input(e: *Exec, id: *const [32]u8) *const Input {
        return e.inputs.getPtr(id.*).?;
    }

    fn inputWrite(e: *Exec, id: *const [32]u8) Write {
        const in = e.input(id);
        return .{
            .id = id.*,
            .type_bytes = in.raw[0..in.view.version_at],
            .old_version = in.view.version,
            .contents = in.view.contents(),
            .owner = in.owner_addr orelse zero32,
            .storage_rebate = in.view.storageRebate(),
            .owner_raw = if (in.shared) in.owner_raw else null,
        };
    }

    // ---- TemporaryStore

    fn mutateInput(e: *Exec, w: Write) !void {
        try e.results.modified.put(e.arena, w.id, {});
        try e.results.written.put(e.arena, w.id, w);
    }

    fn deleteInput(e: *Exec, id: [32]u8) !void {
        try e.results.modified.put(e.arena, id, {});
        try e.results.deleted.put(e.arena, id, {});
    }

    fn readObject(e: *Exec, id: *const [32]u8) Write {
        if (e.results.written.get(id.*)) |w| return w;
        return e.inputWrite(id);
    }

    fn ensureActiveInputsMutated(e: *Exec) !void {
        for (e.mutable.keys()) |id| {
            if (e.results.modified.contains(id)) continue;
            try e.mutateInput(e.inputWrite(&id));
        }
    }

    /// `get_object_modified_at(id).storage_rebate` for a modified id (all are inputs here).
    fn oldRebate(e: *Exec, id: *const [32]u8) u64 {
        if (!e.results.modified.contains(id.*)) return 0;
        return e.input(id).view.storageRebate();
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

    // ---- GasCharger

    fn smashGas(e: *Exec) !void {
        var total: u64 = 0;
        for (e.gas_ids) |*id| {
            const in = e.input(id);
            if (!isGasCoinType(in)) return error.Unsupported;
            total = std.math.add(u64, total, coinValue(in.view.contents())) catch return error.Unsupported;
        }
        e.total_smashed = total;
        for (e.gas_ids[1..]) |id| try e.deleteInput(id);
        var w = e.inputWrite(&e.gas_ids[0]);
        w.contents = try setCoinValue(e.arena, w.contents, total);
        try e.mutateInput(w);
    }

    fn reset(e: *Exec) !void {
        e.results.dropWrites();
        e.gas.resetStorageCostAndRebate();
        try e.smashGas();
        try e.ensureActiveInputsMutated();
    }

    fn meterStorage(e: *Exec) !?gas_mod.GasError {
        try e.ensureActiveInputsMutated();
        if (try e.collectStorageAndRebate()) |err| return err;
        return try e.gas.chargeStorageAndRebate();
    }

    fn handleError(e: *Exec) !void {
        try e.reset();
        if (try e.meterStorage()) |_| {
            try e.reset();
            e.gas.adjustComputationOnOutOfGas();
            if (try e.collectRebate()) |_| return error.Unsupported;
        }
    }

    /// gas_charger.rs `legacy::legacy_charge_gas` (gas model below 15) with
    /// `compute_storage_and_rebate`. Returns the execution error after charging.
    fn legacyChargeGas(e: *Exec, err_in: ?ExecError) !?ExecError {
        var err = err_in;
        if (try e.gas.bucketizeComputation(false)) |ge| {
            if (err == null) err = .{ .kind = gasErrKind(ge), .command = null };
        }
        if (err != null) try e.reset();
        try e.ensureActiveInputsMutated();
        if (try e.collectStorageAndRebate()) |_| return error.Unsupported;
        if (e.storage_v1) {
            // handle_storage_and_rebate_v1
            if (try e.gas.chargeStorageAndRebate()) |ge| {
                try e.reset();
                e.gas.adjustComputationOnOutOfGas();
                try e.ensureActiveInputsMutated();
                if (try e.collectRebate()) |_| return error.Unsupported;
                if (err == null) err = .{ .kind = gasErrKind(ge), .command = null };
            }
            return err;
        }
        if (try e.gas.chargeStorageAndRebate()) |ge| {
            try e.reset();
            try e.ensureActiveInputsMutated();
            if (try e.collectStorageAndRebate()) |_| return error.Unsupported;
            if (try e.gas.chargeStorageAndRebate()) |ge2| {
                try e.reset();
                e.gas.adjustComputationOnOutOfGas();
                try e.ensureActiveInputsMutated();
                if (try e.collectRebate()) |_| return error.Unsupported;
                if (err == null) err = .{ .kind = gasErrKind(ge2), .command = null };
            } else if (err == null) err = .{ .kind = gasErrKind(ge), .command = null };
        }
        return err;
    }

    fn applyPayment(e: *Exec, summary: gas_mod.GasCostSummary) !void {
        const net = summary.netGasUsage() catch return error.Unsupported;
        var w = e.readObject(&e.gas_ids[0]);
        const bal = coinValue(w.contents);
        // gas.rs deduct_gas: checked arithmetic (a panic cannot happen on a certified tx).
        const new_bal = if (net >= 0)
            std.math.sub(u64, bal, @intCast(net)) catch return error.Unsupported
        else
            std.math.add(u64, bal, @intCast(-net)) catch return error.Unsupported;
        w.contents = try setCoinValue(e.arena, w.contents, new_bal);
        // mutate_new_or_input_object: the gas coin is an input.
        try e.results.modified.put(e.arena, w.id, {});
        try e.results.written.put(e.arena, w.id, w);
    }
};

fn coinValue(contents: []const u8) u64 {
    return std.mem.readInt(u64, contents[32..40], .little);
}

fn setCoinValue(arena: Allocator, contents: []const u8, v: u64) ![]const u8 {
    const c = try arena.dupe(u8, contents);
    std.mem.writeInt(u64, c[32..40], v, .little);
    return c;
}

/// `Data::Move` with `MoveObjectType::GasCoin` (tag 1 after the Data tag 0).
fn isGasCoinType(in: *const Input) bool {
    return !in.view.is_package and in.raw.len > 2 and in.raw[1] == 1;
}

/// Coin<T> objects: `GasCoin` or `Coin(T)` (tag 3); 40-byte contents (UID, balance).
fn isCoinType(raw: []const u8, view: *const ObjectView) bool {
    if (view.is_package or raw.len < 2 or view.contents_len != 40) return false;
    return raw[1] == 1 or raw[1] == 3;
}

/// Bytes of the written object: `Object { Data::Move(MoveObject), owner, previous_transaction,
/// storage_rebate }` at `version`.
fn writeBytes(arena: Allocator, w: *const Write, version: u64, prev_tx: *const [32]u8) ![]const u8 {
    var buf: std.ArrayList(u8) = .empty;
    try buf.appendSlice(arena, w.type_bytes);
    var v8: [8]u8 = undefined;
    std.mem.writeInt(u64, &v8, version, .little);
    try buf.appendSlice(arena, &v8);
    try appendUleb(arena, &buf, w.contents.len);
    try buf.appendSlice(arena, w.contents);
    if (w.owner_raw) |o| try buf.appendSlice(arena, o) else {
        try buf.append(arena, 0); // Owner::AddressOwner
        try buf.appendSlice(arena, &w.owner);
    }
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
    const raw = try writeBytes(arena, w, w.old_version, &zero32);
    const v = try ObjectView.parse(raw);
    return objects.sizeForGasMetering(arena, &v);
}

// ---- static shape checks (the typing errors this slice does not construct)

const Slot = enum { empty, coin, object };

fn unsupported(arena: Allocator, comptime fmt: []const u8, args: anytype) Outcome {
    return .{ .unsupported = std.fmt.allocPrint(arena, fmt, args) catch "unsupported" };
}

/// Runs the transaction. `objs` resolves (id, version) to object bytes (the checkpoint's input
/// objects plus the corpus read-only objects).
fn word(n: u64) []const u8 {
    const w = [_][]const u8{ "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve", "thirteen", "fourteen", "fifteen" };
    return if (n < w.len) w[n] else "many";
}

pub fn execute(
    arena: Allocator,
    cfg: *const protocol.ProtocolConfig,
    epoch: u64,
    rgp: u64,
    tx_data_raw: []const u8,
    data: *const types.TransactionDataV1,
    objs: ObjectLookup,
) !Outcome {
    const gm = try cfg.get("gas_model_version");
    const ev = cfg.getOpt("execution_version") orelse 0;
    // Execution version 3 runs the same static PTB pipeline once `enable_ptb_execution_v2` is on
    // (`programmable_transactions::execution::execute`), with gas_charger.rs `charge_gas`,
    // which matches latest's legacy charge path at gas models of 4 and above.
    const static_ptb = ev == 4 or (ev == 3 and cfg.feature_flags.enable_ptb_execution_v2);
    const pt = switch (data.kind) {
        .ProgrammableTransaction => |*p| p,
        else => return unsupported(arena, "not programmable", .{}),
    };
    if (data.gas_data.payment.len == 0) return unsupported(arena, "address-balance gas payment", .{});
    // Inputs a validator rejects at signing (duplicates, a gas coin also passed as an argument)
    // never reach a certificate: an error, not a skip.
    try inputs.signingCheck(arena, data);

    var e: Exec = .{
        .arena = arena,
        .cfg = cfg,
        .tx_digest = types.digest.transactionDataDigest(tx_data_raw),
        .sender = data.sender.@"0",
        .budget = data.gas_data.budget,
        .gas = try SuiGasStatus.initWithBudget(cfg, data.gas_data.budget, data.gas_data.price, rgp),
        .dynamic = !static_ptb,
        // v0 to v2 have no deny-list charge; v3's dynamic executor gates it on deny list v2.
        .deny_list_v2 = static_ptb or (ev == 3 and cfg.feature_flags.enable_coin_deny_list_v2),
        .effects_v1 = !cfg.feature_flags.enable_effects_v2,
        .storage_v1 = gm < 4,
        .objs = objs,
        .epoch = epoch,
    };
    if (e.effects_v1 and ev >= 3) return unsupported(arena, "effects v1 at execution version {d}", .{ev});

    // ---- inputs (CheckedInputObjects): object args, then gas coins
    const n_inputs = pt.inputs.len;
    const input_obj_id = try arena.alloc(?[32]u8, n_inputs);
    var receiving_max: u64 = 0;
    for (pt.inputs, input_obj_id) |*arg, *slot| {
        slot.* = null;
        switch (arg.*) {
            .Pure => {},
            .FundsWithdrawal => return unsupported(arena, "withdrawal input", .{}),
            .Object => |*oa| switch (oa.*) {
                .ImmOrOwnedObject => |r| {
                    if (inputs.isCoinReservation(&r[2].@"0".@"0")) return unsupported(arena, "coin reservation input", .{});
                    const id = r[0].@"0".@"0";
                    const raw = objs.get(objs.ctx, &id, r[1].@"0") orelse return unsupported(arena, "input object not available", .{});
                    const view = try ObjectView.parse(raw);
                    if (view.is_package) return unsupported(arena, "package as object input", .{});
                    const owner = raw[view.owner_at..view.prev_tx_at];
                    const owner_addr: ?[32]u8 = switch (owner[0]) {
                        0 => owner[1..33].*,
                        3 => null,
                        else => return unsupported(arena, "input owner kind {d}", .{owner[0]}),
                    };
                    try e.inputs.put(arena, id, .{ .raw = raw, .view = view, .owner_addr = owner_addr, .coin = isCoinType(raw, &view), .owner_raw = owner });
                    if (owner_addr != null) try e.mutable.put(arena, id, {});
                    slot.* = id;
                },
                .SharedObject => |s| {
                    // The object at its consensus-assigned version. Lamport version,
                    // dependencies and the input-object read charge take it like any input.
                    const id = s.id.@"0".@"0";
                    const a = inputs.findAssigned(objs.assigned, &id) orelse return unsupported(arena, "shared input version not assigned", .{});
                    if (a.kind != .object) return unsupported(arena, "cancelled or stream-ended shared input", .{});
                    const mutable = switch (s.mutability) {
                        .Mutable => true,
                        .Immutable => false,
                        .NonExclusiveWrite => return unsupported(arena, "non-exclusive write input", .{}),
                    };
                    const raw = objs.get(objs.ctx, &id, a.version) orelse return unsupported(arena, "shared input not available", .{});
                    const view = try ObjectView.parse(raw);
                    if (view.is_package) return unsupported(arena, "package as shared input", .{});
                    const owner = raw[view.owner_at..view.prev_tx_at];
                    // Owner::Shared or Owner::ConsensusAddressOwner.
                    if (owner[0] != 2 and owner[0] != 4) return unsupported(arena, "shared input owner kind {d}", .{owner[0]});
                    // A coin among consensus objects would need the deny-list owner rules.
                    if (isCoinType(raw, &view)) return unsupported(arena, "shared coin input", .{});
                    try e.inputs.put(arena, id, .{ .raw = raw, .view = view, .owner_addr = null, .coin = false, .owner_raw = owner, .shared = true });
                    if (mutable) try e.mutable.put(arena, id, {});
                    try e.shared_ids.append(arena, id);
                    slot.* = id;
                },
                // Not an input object (no read charge, no dependency unless received, which a
                // coin command never does); its version still enters the lamport version.
                // Execution version 0 never loads a receiving input (v0 context.rs: unreachable)
                // and leaves receiving refs out of the lamport version.
                .Receiving => |r| {
                    if (ev == 0) return unsupported(arena, "receiving input on execution version 0", .{});
                    receiving_max = @max(receiving_max, r[1].@"0");
                },
            },
        }
    }
    const gas_ids = try arena.alloc([32]u8, data.gas_data.payment.len);
    for (data.gas_data.payment, gas_ids) |r, *gid| {
        if (inputs.isCoinReservation(&r[2].@"0".@"0")) return unsupported(arena, "coin reservation gas payment", .{});
        const id = r[0].@"0".@"0";
        const raw = objs.get(objs.ctx, &id, r[1].@"0") orelse return unsupported(arena, "gas coin not available", .{});
        const view = try ObjectView.parse(raw);
        const owner = raw[view.owner_at..view.prev_tx_at];
        if (owner[0] != 0) return unsupported(arena, "gas coin owner kind {d}", .{owner[0]});
        try e.inputs.put(arena, id, .{ .raw = raw, .view = view, .owner_addr = owner[1..33].*, .coin = true, .owner_raw = owner });
        try e.mutable.put(arena, id, {});
        gid.* = id;
    }
    e.gas_ids = gas_ids;

    // lamport version and dependencies
    var max_v: u64 = receiving_max;
    for (e.inputs.values()) |*in| max_v = @max(max_v, in.view.version);
    e.lamport = max_v + 1;
    // Commands here only take coins; a consensus input a command names is outside the slice.
    if (sharedUsed(pt, input_obj_id, &e)) return unsupported(arena, "shared input used by a coin command", .{});
    var deps: std.ArrayList([32]u8) = .empty;
    if (!cfg.feature_flags.disable_effects_tx_dependencies) {
        for (e.inputs.values()) |*in| {
            const d = in.raw[in.view.prev_tx_at + 1 ..][0..32].*;
            if (!std.mem.eql(u8, &d, &zero32)) try deps.append(arena, d);
        }
        std.mem.sort([32]u8, deps.items, {}, lessBytes);
        var w: usize = 0;
        for (deps.items) |d| {
            if (w > 0 and std.mem.eql(u8, &deps.items[w - 1], &d)) continue;
            deps.items[w] = d;
            w += 1;
        }
        deps.shrinkRetainingCapacity(w);
    }

    // ---- static shape check (typing errors are not modeled)
    const static_result = staticCheck(arena, pt, &e, input_obj_id);
    if (static_result == .unsupported) return .{ .unsupported = static_result.unsupported };
    const typing_err: ?ExecError = if (static_result == .typing) static_result.typing else null;
    if (static_result == .cutoff) e.cutoff = .{ .at = static_result.cutoff.at, .reason = static_result.cutoff.reason };

    // ---- GasCharger::new: smash
    e.smashGas() catch return unsupported(arena, "gas smash", .{});

    // ---- execute_transaction
    var exec_err: ?ExecError = null;
    const bump_only = protocol.gas.bumpOnlyEnabled(gm);
    if (bump_only) {
        // charge_input_objects: every input object, in id order, by storage read size.
        const ids = try arena.dupe([32]u8, e.inputs.keys());
        std.mem.sort([32]u8, ids, {}, lessBytes);
        for (ids) |*id| {
            const in = e.input(id);
            const size = try objects.sizeForGasMetering(arena, &in.view);
            if (e.gas.chargeStorageRead(size)) |_| {
                exec_err = .{ .kind = .InsufficientGas, .command = null };
                break;
            }
        }
    } else {
        // charge_input_objects_legacy: one storage-read charge for the summed sizes of every
        // input object (system packages excepted; this slice has no package inputs).
        var total: u64 = 0;
        for (e.inputs.values()) |*in| total += try objects.sizeForGasMetering(arena, &in.view);
        if (e.gas.chargeStorageRead(total)) |_| exec_err = .{ .kind = .InsufficientGas, .command = null };
    }
    if (exec_err == null) {
        exec_err = runPtb(&e, pt, input_obj_id, typing_err) catch |err| switch (err) {
            error.Unsupported => return .{ .unsupported = e.unsupported_reason orelse "execution path not modeled" },
            else => |x| return x,
        };
        if (!e.dynamic) {
            // The modeled meter is exact only for what it charges; the typing meter's type
            // nodes and references are approximated. `translationSlack` bounds everything the
            // approximation can miss (exact type node counts of the objects, every type
            // occurrence, quadratic references, live references), so a pass never depends on
            // the approximation, even for deep generic coin types or 1,024-command PTBs.
            const slack = translationSlack(&e, pt, input_obj_id) orelse return unsupported(arena, "object type does not parse", .{});
            const bound = e.gas.gasUsed() +| slack;
            if (bound >= 500) return unsupported(arena, "modeled Move gas {d} units (near the rounding floor)", .{bound});
        }
        if (bump_only) {
            // execute_ptb: round_computation (is_move_abort is false: coin commands never abort).
            if (try e.gas.bucketizeComputation(false)) |ge| {
                if (exec_err == null) exec_err = .{ .kind = gasErrKind(ge), .command = null };
            }
            if (exec_err == null) {
                if (try e.meterStorage()) |ge| exec_err = .{ .kind = gasErrKind(ge), .command = null };
            }
        }
    }
    if (bump_only) {
        if (exec_err != null) e.handleError() catch return unsupported(arena, "handle_error path", .{});
    } else {
        exec_err = e.legacyChargeGas(exec_err) catch |err| switch (err) {
            error.Unsupported => return unsupported(arena, "legacy charge path", .{}),
            else => |x| return x,
        };
    }
    const summary = e.gas.summary();
    e.applyPayment(summary) catch return unsupported(arena, "apply_payment", .{});

    // ---- into_effects
    return .{ .done = try intoEffects(&e, epoch, summary, exec_err, deps.items) };
}

/// True when a command names a shared input (by value or by reference).
fn sharedUsed(pt: *const types.ProgrammableTransaction, input_obj_id: []const ?[32]u8, e: *Exec) bool {
    if (e.shared_ids.items.len == 0) return false;
    const Check = struct {
        fn arg(a: types.Argument, ids: []const ?[32]u8, ex: *Exec) bool {
            const i = switch (a) {
                .Input => |i| i,
                else => return false,
            };
            if (i >= ids.len) return false;
            const id = ids[i] orelse return false;
            return ex.input(&id).shared;
        }
    };
    for (pt.commands) |*cmd| switch (cmd.*) {
        .SplitCoins => |*sc| {
            if (Check.arg(sc[0], input_obj_id, e)) return true;
            for (sc[1]) |a| if (Check.arg(a, input_obj_id, e)) return true;
        },
        .MergeCoins => |*mc| {
            if (Check.arg(mc[0], input_obj_id, e)) return true;
            for (mc[1]) |a| if (Check.arg(a, input_obj_id, e)) return true;
        },
        .TransferObjects => |*to| {
            if (Check.arg(to[1], input_obj_id, e)) return true;
            for (to[0]) |a| if (Check.arg(a, input_obj_id, e)) return true;
        },
        else => {},
    };
    return false;
}

/// The effects owner of an input or written object: AddressOwner(addr), or the stored owner
/// of a consensus object.
fn ownerOf(arena: Allocator, raw: ?[]const u8, addr: [32]u8) !types.Owner {
    if (raw) |o| return bcs.decode(types.Owner, arena, o);
    return .{ .AddressOwner = .{ .@"0" = addr } };
}

fn inputOwner(arena: Allocator, in: *const Input) !types.Owner {
    return ownerOf(arena, if (in.shared) in.owner_raw else null, in.owner_addr orelse zero32);
}

fn lessBytes(_: void, a: [32]u8, b: [32]u8) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

const ExecError = struct {
    kind: enum { InsufficientGas, InvariantViolation, InsufficientCoinBalance, CoinBalanceOverflow, InvalidTransferObject, InvalidTransferObjectKind, TypeMismatch, Denied },
    command: ?u64,
    /// CommandArgumentError argument index.
    arg_idx: u16 = 0,
    /// kind Denied: the coin deny list v2 result.
    denied: ?deny.Denied = null,
};

const StaticResult = union(enum) {
    ok,
    /// Dynamic executor: the transaction is modeled until command `at` (or the end-of-program
    /// checks when `at` is the command count); reaching it is unsupported.
    cutoff: struct { at: usize, reason: []const u8 },
    unsupported: []const u8,
    /// A typing error (`typing/translate.rs`) Rust reports before execution.
    typing: ExecError,
};

fn gasErrKind(g: gas_mod.GasError) @FieldType(ExecError, "kind") {
    return switch (g) {
        .InsufficientGas => .InsufficientGas,
        .InvariantViolation => .InvariantViolation,
    };
}

/// Static checks Rust's loading/typing/verification would fail on. Returns a reason when the
/// transaction falls outside the modeled subset.
fn staticCheck(arena: Allocator, pt: *const types.ProgrammableTransaction, e: *Exec, input_obj_id: []const ?[32]u8) StaticResult {
    var at: usize = 0;
    return switch (staticCheckInner(arena, pt, e, input_obj_id, &at)) {
        .ok => .ok,
        // The dynamic executor finds argument errors when it reaches the command (an earlier
        // command's runtime error wins), and unused values after the last command.
        .unsupported => |r| if (e.dynamic) .{ .cutoff = .{ .at = at, .reason = r } } else .{ .unsupported = r },
        .typing => |t| .{ .typing = t },
    };
}

const Inner = union(enum) { ok, unsupported: []const u8, typing: ExecError };

fn staticCheckInner(arena: Allocator, pt: *const types.ProgrammableTransaction, e: *Exec, input_obj_id: []const ?[32]u8, at: *usize) Inner {
    // Track presence of every location: gas, object inputs, results.
    var gas_present = true;
    const in_present = arena.alloc(bool, input_obj_id.len) catch return .{ .unsupported = "oom" };
    @memset(in_present, true);
    var results: std.ArrayList([]?[]const u8) = .empty; // per result: coin header or null if moved
    for (pt.commands, 0..) |*cmd, ci| {
        at.* = ci;
        switch (cmd.*) {
            .SplitCoins => |*sc| {
                const hdr = coinHeaderAt(e, sc[0], input_obj_id, in_present, gas_present, results.items) orelse return .{ .unsupported = "SplitCoins source not an available coin" };
                for (sc[1]) |a| if (!pureAt(pt, a, 8)) return .{ .unsupported = "SplitCoins amount not an 8-byte pure input" };
                const r = arena.alloc(?[]const u8, sc[1].len) catch return .{ .unsupported = "oom" };
                for (r) |*x| x.* = hdr;
                results.append(arena, r) catch return .{ .unsupported = "oom" };
            },
            .MergeCoins => |*mc| {
                const hdr = coinHeaderAt(e, mc[0], input_obj_id, in_present, gas_present, results.items) orelse return .{ .unsupported = "MergeCoins target not an available coin" };
                for (mc[1]) |a| {
                    if (a == .GasCoin) return .{ .unsupported = "gas coin merged by value" };
                    if (std.meta.eql(a, mc[0])) return .{ .unsupported = "MergeCoins source equals target" };
                    _ = coinHeaderAt(e, a, input_obj_id, in_present, gas_present, results.items) orelse return .{ .unsupported = "MergeCoins source not an available coin" };
                }
                for (mc[1], 1..) |a, k| {
                    const h = coinHeaderAt(e, a, input_obj_id, in_present, gas_present, results.items).?;
                    if (!std.mem.eql(u8, typeOfHeader(h), typeOfHeader(hdr))) {
                        // typing/translate.rs `arguments(.., 1, coin_locs, coin_type)`: TypeMismatch
                        // at the first coin of another type. The dynamic executor fails the same
                        // way when it reaches the command, so nothing after it matters.
                        if (e.dynamic) return .ok;
                        return .{ .typing = .{ .kind = .TypeMismatch, .command = ci, .arg_idx = @intCast(k) } };
                    }
                }
                for (mc[1]) |a| if (!take(a, in_present, &gas_present, results.items, input_obj_id, e)) return .{ .unsupported = "MergeCoins source unavailable" };
                results.append(arena, &.{}) catch return .{ .unsupported = "oom" };
            },
            .TransferObjects => |*to| {
                if (!pureAt(pt, to[1], 32)) return .{ .unsupported = "recipient not a 32-byte pure input" };
                for (to[0], 0..) |a, i| {
                    for (to[0][0..i]) |b| if (std.meta.eql(a, b)) return .{ .unsupported = "object transferred twice" };
                    if (!take(a, in_present, &gas_present, results.items, input_obj_id, e)) return .{ .unsupported = "transferred object unavailable or immutable" };
                    // TRANSFER_OBJECTS_CONSTRAINT (key + store): an object's has_public_transfer.
                    if (a == .Input) {
                        const in = e.input(&input_obj_id[a.Input].?);
                        if (!e.dynamic and in.raw[in.view.version_at - 1] == 0) return .{ .typing = .{ .kind = .InvalidTransferObject, .command = ci, .arg_idx = @intCast(i) } };
                    }
                }
                results.append(arena, &.{}) catch return .{ .unsupported = "oom" };
            },
            else => return .{ .unsupported = "not a coin command" },
        }
    }
    at.* = pt.commands.len;
    for (results.items) |r| for (r) |x| if (x != null) return .{ .unsupported = "unused coin result (UnusedValueWithoutDrop)" };
    return .ok;
}

/// Data tag + MoveObjectType bytes (without has_public_transfer).
fn typeOfHeader(h: []const u8) []const u8 {
    return h[0 .. h.len - 1];
}

fn pureAt(pt: *const types.ProgrammableTransaction, a: types.Argument, len: usize) bool {
    const i = switch (a) {
        .Input => |i| i,
        else => return false,
    };
    if (i >= pt.inputs.len) return false;
    return switch (pt.inputs[i]) {
        .Pure => |b| b.len == len,
        else => false,
    };
}

fn coinHeaderAt(e: *Exec, a: types.Argument, input_obj_id: []const ?[32]u8, in_present: []const bool, gas_present: bool, results: []const []?[]const u8) ?[]const u8 {
    switch (a) {
        .GasCoin => {
            if (!gas_present) return null;
            const in = e.input(&e.gas_ids[0]);
            return in.raw[0..in.view.version_at];
        },
        .Input => |i| {
            if (i >= input_obj_id.len or !in_present[i]) return null;
            const id = input_obj_id[i] orelse return null;
            const in = e.input(&id);
            if (!in.coin or in.owner_addr == null) return null;
            return in.raw[0..in.view.version_at];
        },
        .Result => |i| {
            if (i >= results.len or results[i].len != 1) return null;
            return results[i][0];
        },
        .NestedResult => |nr| {
            if (nr[0] >= results.len or nr[1] >= results[nr[0]].len) return null;
            return results[nr[0]][nr[1]];
        },
    }
}

fn take(a: types.Argument, in_present: []bool, gas_present: *bool, results: []const []?[]const u8, input_obj_id: []const ?[32]u8, e: *Exec) bool {
    switch (a) {
        .GasCoin => {
            if (!gas_present.*) return false;
            gas_present.* = false;
        },
        .Input => |i| {
            if (i >= input_obj_id.len or !in_present[i]) return false;
            const id = input_obj_id[i] orelse return false;
            if (e.input(&id).owner_addr == null) return false;
            in_present[i] = false;
        },
        .Result => |i| {
            if (i >= results.len or results[i].len != 1 or results[i][0] == null) return false;
            results[i][0] = null;
        },
        .NestedResult => |nr| {
            if (nr[0] >= results.len or nr[1] >= results[nr[0]].len or results[nr[0]][nr[1]] == null) return false;
            results[nr[0]][nr[1]] = null;
        },
    }
    return true;
}

// ---- PTB execution (static_programmable_transactions::execute for coin commands)

const Transfer = struct { owner: [32]u8, value: Value };

const Ptb = struct {
    e: *Exec,
    pt: *const types.ProgrammableTransaction,
    input_obj_id: []const ?[32]u8,
    gas: ?Value,
    objects: []?Value,
    results: std.ArrayList([]?Value) = .empty,
    pure_u64_loaded: []bool,
    pure_addr_loaded: []bool,
    /// ObjectRuntime state.
    new_ids: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    deleted_ids: std.AutoArrayHashMapUnmanaged([32]u8, void) = .empty,
    transfers: std.AutoArrayHashMapUnmanaged([32]u8, Transfer) = .empty,

    fn meter(p: *Ptb) *gas_mod.MoveGasStatus {
        return &p.e.gas.move;
    }

    fn charge(p: *Ptb, instr: u64, pushes: u64, pops: u64, incr: u64, decr: u64) !void {
        // The dynamic executor meters only Move calls; its coin commands charge nothing.
        if (p.e.dynamic) return;
        p.meter().charge(instr, pushes, pops, incr, decr) catch return error.Unsupported;
    }
    fn copyLoc(p: *Ptb, size: u64) !void {
        try p.charge(1, 1, 0, size, 0);
    }
    fn storeLoc(p: *Ptb, size: u64) !void {
        try p.charge(1, 0, 1, 0, size);
    }
    fn moveLoc(p: *Ptb) !void {
        // reweight_move_loc (gas model > 10): REFERENCE_SIZE.
        try p.charge(1, 1, 0, reference_size, 0);
    }
    fn pop(p: *Ptb, size: u64) !void {
        try p.charge(1, 0, 1, 0, size);
    }
    fn borrowLoc(p: *Ptb) !void {
        try p.charge(1, 1, 0, reference_size, 0); // MutBorrowLoc
    }

    fn deduct(p: *Ptb, amount: u64) !void {
        p.meter().deductGas(amount) catch return error.Unsupported;
    }

    fn pureIndex(a: types.Argument) u16 {
        return a.Input;
    }

    fn copyPureU64(p: *Ptb, a: types.Argument) !u64 {
        const i = pureIndex(a);
        if (!p.pure_u64_loaded[i]) {
            try p.copyLoc(u64_size);
            try p.storeLoc(u64_size);
            p.pure_u64_loaded[i] = true;
        }
        try p.copyLoc(u64_size);
        return std.mem.readInt(u64, p.pt.inputs[i].Pure[0..8], .little);
    }

    fn copyPureAddress(p: *Ptb, a: types.Argument) ![32]u8 {
        const i = pureIndex(a);
        if (!p.pure_addr_loaded[i]) {
            try p.copyLoc(address_size);
            try p.storeLoc(address_size);
            p.pure_addr_loaded[i] = true;
        }
        try p.copyLoc(address_size);
        return p.pt.inputs[i].Pure[0..32].*;
    }

    fn slot(p: *Ptb, a: types.Argument) !*?Value {
        return switch (a) {
            .GasCoin => &p.gas,
            .Input => |i| &p.objects[i],
            .Result => |i| &p.results.items[i][0],
            .NestedResult => |nr| &p.results.items[nr[0]][nr[1]],
        };
    }

    fn borrowCoin(p: *Ptb, a: types.Argument) !*@FieldType(Value, "coin") {
        try p.borrowLoc();
        const s = try p.slot(a);
        if (s.* == null or s.*.? != .coin) return error.Unsupported;
        return &s.*.?.coin;
    }

    fn moveValue(p: *Ptb, a: types.Argument) !Value {
        try p.moveLoc();
        const s = try p.slot(a);
        const v = s.* orelse return error.Unsupported;
        s.* = null;
        return v;
    }

    fn freshId(p: *Ptb) ![32]u8 {
        const id = natives.abi.TxContext.deriveId(&p.e.tx_digest, p.e.ids_created);
        p.e.ids_created += 1;
        const lim = p.e.cfg.getOpt("max_num_new_move_object_ids") orelse std.math.maxInt(u64);
        if (p.new_ids.count() >= lim) return error.Unsupported;
        if (!p.deleted_ids.swapRemove(id)) try p.new_ids.put(p.e.arena, id, {});
        return id;
    }

    fn deleteId(p: *Ptb, id: [32]u8) !void {
        if (!p.new_ids.swapRemove(id)) try p.deleted_ids.put(p.e.arena, id, {});
    }

    fn valueId(p: *Ptb, v: Value) [32]u8 {
        return switch (v) {
            .coin => |c| c.id,
            .object => |i| p.input_obj_id[i].?,
        };
    }

    fn transfer(p: *Ptb, owner: [32]u8, v: Value) !void {
        try p.transfers.put(p.e.arena, p.valueId(v), .{ .owner = owner, .value = v });
    }
};

fn runPtb(e: *Exec, pt: *const types.ProgrammableTransaction, input_obj_id: []const ?[32]u8, typing_err: ?ExecError) !?ExecError {
    const arena = e.arena;
    var p: Ptb = .{
        .e = e,
        .pt = pt,
        .input_obj_id = input_obj_id,
        .gas = null,
        .objects = try arena.alloc(?Value, pt.inputs.len),
        .pure_u64_loaded = try arena.alloc(bool, pt.inputs.len),
        .pure_addr_loaded = try arena.alloc(bool, pt.inputs.len),
    };
    @memset(p.pure_u64_loaded, false);
    @memset(p.pure_addr_loaded, false);

    if (!e.dynamic) try translationMeter(&p, pt, input_obj_id);
    if (!e.dynamic) if (typing_err) |te| return te;
    return runCommands(&p, pt, input_obj_id);
}

fn translationMeter(p: *Ptb, pt: *const types.ProgrammableTransaction, input_obj_id: []const ?[32]u8) !void {
    const e = p.e;
    // Translation meter (pre_translation, loading, typing): units deducted directly.
    try p.deduct(@max(pt.inputs.len, 1) * (e.cfg.getOpt("translation_per_input_base_charge") orelse 0));
    for (pt.inputs) |*arg| switch (arg.*) {
        .Pure => |b| try p.deduct(@max(b.len, 1) * (e.cfg.getOpt("translation_pure_input_per_byte_charge") orelse 0)),
        else => {},
    };
    for (pt.commands) |*cmd| {
        const n: u64 = switch (cmd.*) {
            .TransferObjects => |*t| t[0].len + 1,
            .SplitCoins => |*s| s[1].len + 1,
            .MergeCoins => |*m| m[1].len + 1,
            else => unreachable,
        };
        try p.deduct(@max(n, 1) * (e.cfg.getOpt("translation_per_command_base_charge") orelse 0));
    }
    const node_charge = e.cfg.getOpt("translation_per_type_node_charge") orelse 0;
    var n_obj: u64 = 0;
    for (input_obj_id) |o| if (o != null) {
        n_obj += 1;
        try p.deduct(2 * node_charge); // Coin<T> (two nodes) or an object type, loading meter
    };
    // typing meter: type nodes of the typed transaction's types; at least one charge each.
    try p.deduct(@max(2 * (n_obj + 1), 1) * node_charge);
    try p.deduct(e.cfg.getOpt("translation_per_reference_node_charge") orelse 0);
}

/// Gas units (rounded up) the translation and typing meters can charge beyond what
/// `translationMeter` models, as an upper bound:
/// - loading: every object input's type at its exact node count (modeled: 2 each);
/// - typing nodes: each pure input at up to two types (u64, address: one node each), each
///   object input's type, and per command its arguments plus the coin type, each at most
///   `K + 1` nodes (`K` the largest object type, `+ 1` for a reference);
/// - typing references: `n (n + 1) / 2` with `n` at most one reference per command;
/// - live references (`max_ptb_live_references`): at most one per command, `1` each.
/// Returns null when an object type does not parse.
fn translationSlack(e: *const Exec, pt: *const types.ProgrammableTransaction, input_obj_id: []const ?[32]u8) ?u64 {
    var k: u64 = 2; // the gas coin: Coin<SUI>
    var loading: u64 = 2; // the gas coin too, in case the loaded inputs carry it
    var objs: u64 = 1; // object inputs plus the gas coin
    for (input_obj_id) |o| if (o) |id| {
        const n = objectTypeNodes(e.inputs.getPtr(id).?.raw) orelse return null;
        k = @max(k, n);
        loading +|= n;
        objs += 1;
    };
    return slackUnits(e.cfg, pt, k, loading, objs);
}

fn slackUnits(cfg: *const protocol.ProtocolConfig, pt: *const types.ProgrammableTransaction, k: u64, loading: u64, objs: u64) u64 {
    var n_pure: u64 = 0;
    for (pt.inputs) |*arg| n_pure += @intFromBool(arg.* == .Pure);
    var occurrences: u64 = 0;
    for (pt.commands) |*cmd| occurrences +|= switch (cmd.*) {
        .TransferObjects => |*t| t[0].len + 2,
        .SplitCoins => |*sc| sc[1].len + 2,
        .MergeCoins => |*m| m[1].len + 2,
        else => unreachable,
    };
    const nodes = 2 *| n_pure +| objs *| k +| occurrences *| (k +| 1);
    const c: u64 = pt.commands.len;
    const refs = c *| (c + 1) / 2;
    const node_charge = cfg.getOpt("translation_per_type_node_charge") orelse 0;
    const ref_charge = cfg.getOpt("translation_per_reference_node_charge") orelse 0;
    const live_charge = cfg.getOpt("translation_per_live_reference_charge") orelse 0;
    const internal = (loading +| nodes) *| node_charge +| refs *| ref_charge +| c *| live_charge;
    return internal / gas_mod.internal_unit_multiplier + 1;
}

test "translation slack covers 1,024 coin commands on a deep coin type" {
    // 1,024 SplitCoins of a coin input whose type has 256 nodes (Coin<T> with a deeply nested
    // generic T, e.g. from `balance::create_supply`): Rust's typing meter alone charges about
    // 1,050 gas units (references 1024 * 1025 / 2 internal units plus 1024 * (257 + 1 + 256)
    // type nodes), past the 1,000-unit floor, while the modeled charges are a few units. The
    // slack must reach the 500-unit cutoff.
    const cfg = try protocol.get(protocol.max_protocol_version, .mainnet);
    var cmds: [1025]types.Command = undefined;
    const amount = [_]types.Argument{.{ .Input = 0 }};
    for (cmds[0..1024]) |*c| c.* = .{ .SplitCoins = .{ .GasCoin, &amount } };
    cmds[1024] = .{ .MergeCoins = .{ .GasCoin, &.{} } };
    const ins = [_]types.CallArg{.{ .Pure = &@as([8]u8, @splat(0)) }};
    const pt: types.ProgrammableTransaction = .{ .inputs = &ins, .commands = &cmds };
    try std.testing.expect(slackUnits(cfg, &pt, 256, 256, 2) >= 500);
    // A plain coin transfer stays far below it.
    const small: types.ProgrammableTransaction = .{ .inputs = &ins, .commands = cmds[0..2] };
    try std.testing.expect(slackUnits(cfg, &small, 2, 2, 2) < 5);
}

/// Type node count of a Move object's type (`Type::node_count` of the loaded type), from the
/// object bytes: `Data::Move` tag, then `MoveObjectType` (Other(StructTag) | GasCoin | StakedSui
/// | Coin(TypeTag)). Counted iteratively over the BCS (prefix order), no recursion.
fn objectTypeNodes(raw: []const u8) ?u64 {
    if (raw.len < 2 or raw[0] != 0) return null;
    var at: usize = 2;
    var nodes: u64 = 0;
    var pending: u64 = 0;
    switch (raw[1]) {
        0 => {
            nodes = 1;
            pending = skipStructHead(raw, &at) orelse return null;
        },
        1 => return 2,
        2 => return 1,
        3 => {
            nodes = 1;
            pending = 1;
        },
        else => return null,
    }
    while (pending > 0) {
        if (at >= raw.len) return null;
        const tag = raw[at];
        at += 1;
        pending -= 1;
        nodes += 1;
        switch (tag) {
            0, 1, 2, 3, 4, 5, 8, 9, 10 => {},
            6 => pending += 1,
            7 => pending +|= skipStructHead(raw, &at) orelse return null,
            else => return null,
        }
    }
    return nodes;
}

/// Skips a StructTag's address, module and name; returns its type parameter count.
fn skipStructHead(raw: []const u8, at: *usize) ?u64 {
    at.* += 32;
    for (0..2) |_| {
        const n = readUleb(raw, at) orelse return null;
        if (n > raw.len) return null;
        at.* += @intCast(n);
    }
    if (at.* > raw.len) return null;
    return readUleb(raw, at);
}

fn readUleb(raw: []const u8, at: *usize) ?u64 {
    var v: u64 = 0;
    var shift: u6 = 0;
    while (true) {
        if (at.* >= raw.len) return null;
        const b = raw[at.*];
        at.* += 1;
        v |= @as(u64, b & 0x7f) << shift;
        if (b & 0x80 == 0) return v;
        if (shift >= 28) return null; // BCS lengths fit in u32
        shift += 7;
    }
}

test "object type node counts" {
    // Coin(TypeTag::Struct(0x2::sui::SUI)): Coin<SUI> = 2 nodes.
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    const a = std.testing.allocator;
    try buf.appendSlice(a, &.{ 0, 3, 7 });
    try buf.appendSlice(a, &@as([32]u8, @splat(0)));
    try buf.appendSlice(a, &.{ 3, 's', 'u', 'i', 3, 'S', 'U', 'I', 0 });
    try std.testing.expectEqual(@as(?u64, 2), objectTypeNodes(buf.items));
    // Coin<W<vector<u8>, W<u64>>> = Coin, W, vector, u8, W, u64 = 6 nodes.
    buf.clearRetainingCapacity();
    try buf.appendSlice(a, &.{ 0, 3, 7 });
    try buf.appendSlice(a, &@as([32]u8, @splat(1)));
    try buf.appendSlice(a, &.{ 1, 'm', 1, 'W', 2, 6, 1, 7 });
    try buf.appendSlice(a, &@as([32]u8, @splat(1)));
    try buf.appendSlice(a, &.{ 1, 'm', 1, 'W', 1, 2 });
    try std.testing.expectEqual(@as(?u64, 6), objectTypeNodes(buf.items));
    try std.testing.expectEqual(@as(?u64, 2), objectTypeNodes(&.{ 0, 1 }));
    try std.testing.expectEqual(@as(?u64, 1), objectTypeNodes(&.{ 0, 2 }));
    try std.testing.expectEqual(@as(?u64, null), objectTypeNodes(&.{ 0, 3, 7, 1 }));
}

fn runCommands(p: *Ptb, pt: *const types.ProgrammableTransaction, input_obj_id: []const ?[32]u8) !?ExecError {
    const e = p.e;
    const arena = e.arena;

    // Context::new: object inputs in input order, then the gas coin.
    for (pt.inputs, 0..) |_, i| {
        p.objects[i] = null;
        const id = input_obj_id[i] orelse continue;
        const in = e.input(&id);
        const v: Value = if (in.coin)
            .{ .coin = .{ .id = id, .balance = coinValue(in.view.contents()), .header = in.raw[0..in.view.version_at] } }
        else
            .{ .object = @intCast(i) };
        const size = if (in.coin) coin_size else @as(u64, in.view.contents_len) * 8 + 64;
        try p.copyLoc(size);
        try p.storeLoc(size);
        p.objects[i] = v;
    }
    {
        const gid = e.gas_ids[0];
        const gin = e.input(&gid);
        try p.copyLoc(coin_size);
        try p.storeLoc(coin_size);
        var bal = e.total_smashed;
        if (bal < e.budget) return error.Unsupported;
        bal -= e.budget;
        p.gas = .{ .coin = .{ .id = gid, .balance = bal, .header = gin.raw[0..gin.view.version_at] } };
    }

    for (pt.commands, 0..) |*cmd, ci| {
        const cidx: u64 = ci;
        if (e.cutoff) |c| if (c.at == ci) {
            e.unsupported_reason = c.reason;
            return error.Unsupported;
        };
        switch (cmd.*) {
            .SplitCoins => |*sc| if (e.dynamic) {
                // execution.rs: each amount splits off in turn (`Coin::split`); a short balance
                // fails with InsufficientCoinBalance whatever the earlier amounts were.
                const coin = try p.borrowCoin(sc[0]);
                const res = try arena.alloc(?Value, sc[1].len);
                for (sc[1], res) |a, *r| {
                    const amount = try p.copyPureU64(a);
                    const id = try p.freshId();
                    if (coin.balance < amount) return .{ .kind = .InsufficientCoinBalance, .command = cidx };
                    coin.balance -= amount;
                    r.* = .{ .coin = .{ .id = id, .balance = amount, .header = coin.header } };
                }
                try p.results.append(arena, res);
            } else {
                const coin = try p.borrowCoin(sc[0]);
                var amounts = try arena.alloc(u64, sc[1].len);
                var total: u64 = 0;
                var overflow = false;
                for (sc[1], 0..) |a, k| {
                    amounts[k] = try p.copyPureU64(a);
                }
                for (amounts) |a| total = std.math.add(u64, total, a) catch blk: {
                    overflow = true;
                    break :blk total;
                };
                if (overflow) return .{ .kind = .CoinBalanceOverflow, .command = cidx };
                try p.copyLoc(reference_size);
                try p.pop(reference_size);
                if (coin.balance < total) return .{ .kind = .InsufficientCoinBalance, .command = cidx };
                coin.balance -= total;
                const header = coin.header;
                const res = try arena.alloc(?Value, amounts.len);
                for (amounts, res) |a, *r| r.* = .{ .coin = .{ .id = try p.freshId(), .balance = a, .header = header } };
                try p.charge(1, 0, 1 + sc[1].len, 0, 1);
                try p.results.append(arena, res);
            },
            .MergeCoins => |*mc| {
                const target = try p.borrowCoin(mc[0]);
                var additional: u64 = 0;
                var overflow = false;
                for (mc[1], 1..) |a, k| {
                    const v = try p.moveValue(a);
                    if (v != .coin) return error.Unsupported;
                    // execution.rs: `target.type_ != coin.type_` (every source was taken first;
                    // the static check guarantees they are all available).
                    if (!std.mem.eql(u8, typeOfHeader(v.coin.header), typeOfHeader(target.header)))
                        return .{ .kind = .TypeMismatch, .command = cidx, .arg_idx = @intCast(k) };
                    try p.deleteId(v.coin.id);
                    additional = std.math.add(u64, additional, v.coin.balance) catch blk: {
                        overflow = true;
                        break :blk additional;
                    };
                }
                if (overflow) return .{ .kind = .CoinBalanceOverflow, .command = cidx };
                try p.copyLoc(reference_size);
                try p.pop(reference_size);
                target.balance = std.math.add(u64, target.balance, additional) catch return .{ .kind = .CoinBalanceOverflow, .command = cidx };
                try p.charge(1, 0, 1 + mc[1].len, 0, 1);
                try p.results.append(arena, &.{});
            },
            .TransferObjects => |*to| {
                const vals = try arena.alloc(Value, to[0].len);
                for (to[0], vals) |a, *v| v.* = try p.moveValue(a);
                const recipient = try p.copyPureAddress(to[1]);
                for (vals) |v| {
                    // execution.rs `ensure_public_transfer_eligible` (the static executor rejects
                    // these at typing).
                    if (e.dynamic and v == .object) {
                        const in = e.input(&input_obj_id[v.object].?);
                        if (in.raw[in.view.version_at - 1] == 0) return .{ .kind = .InvalidTransferObjectKind, .command = cidx };
                    }
                    try p.transfer(recipient, v);
                }
                try p.charge(1, 0, to[0].len + 1, 0, 1);
                try p.results.append(arena, &.{});
            },
            else => unreachable,
        }
    }

    if (e.cutoff) |c| if (c.at == pt.commands.len) {
        e.unsupported_reason = c.reason;
        return error.Unsupported;
    };
    // Context::finish: mutable inputs still in place go back to their owner; then the gas coin.
    var loaded = std.AutoArrayHashMapUnmanaged([32]u8, u64).empty; // id -> input version
    for (pt.inputs, 0..) |_, i| {
        const id = input_obj_id[i] orelse continue;
        const in = e.input(&id);
        const owner = in.owner_addr orelse continue; // immutable: not usable mutably
        try loaded.put(arena, id, in.view.version);
        if (p.objects[i]) |v| try p.transfer(owner, v);
    }
    {
        const gid = e.gas_ids[0];
        try loaded.put(arena, gid, e.input(&gid).view.version);
        if (p.gas) |v| try p.transfer(e.input(&gid).owner_addr.?, v);
    }
    // finish_gas_coin: refund the budget to the gas coin's write.
    {
        const t = p.transfers.getPtr(e.gas_ids[0]) orelse return error.Unsupported;
        if (t.value != .coin) return error.Unsupported;
        t.value.coin.balance = std.math.add(u64, t.value.coin.balance, e.budget) catch return .{ .kind = .CoinBalanceOverflow, .command = null };
    }

    // Written objects.
    var written = std.AutoArrayHashMapUnmanaged([32]u8, Write).empty;
    for (p.transfers.keys(), p.transfers.values()) |id, t| {
        const old_version = loaded.get(id) orelse 0;
        var w: Write = switch (t.value) {
            .coin => |c| blk: {
                var contents = try arena.alloc(u8, 40);
                contents[0..32].* = id;
                std.mem.writeInt(u64, contents[32..40], c.balance, .little);
                break :blk .{ .id = id, .type_bytes = c.header, .old_version = old_version, .contents = contents, .owner = t.owner, .storage_rebate = 0 };
            },
            .object => |i| blk: {
                const in = e.input(&input_obj_id[i].?);
                break :blk .{ .id = id, .type_bytes = in.raw[0..in.view.version_at], .old_version = old_version, .contents = in.view.contents(), .owner = t.owner, .storage_rebate = 0 };
            },
        };
        // Object::new_move: storage_rebate 0 until collect_storage_and_rebate.
        w.storage_rebate = 0;
        if (cfgMaxObjectSize(e.cfg)) |max| if (w.contents.len > max) return error.Unsupported;
        try written.put(arena, id, w);
    }

    // context::finish: coin deny list (non-SUI coin owners) and its storage-read charge.
    if (e.deny_list_v2) {
        var pairs: std.ArrayList(deny.Pair) = .empty;
        for (written.values()) |*w| {
            if (w.type_bytes.len < 2 or w.type_bytes[1] != 3) continue; // Coin(T), T != SUI
            // header: Data tag, MoveObjectType::Coin tag, TypeTag T, has_public_transfer
            const t = bcs.decode(types.TypeTag, arena, w.type_bytes[2 .. w.type_bytes.len - 1]) catch return error.Unsupported;
            try deny.addPair(arena, &pairs, try deny.canonical(arena, &t), w.owner, t);
        }
        const n: u64 = pairs.items.len;
        if (n > 0) {
            const cost_per_byte = e.cfg.getOpt("dynamic_field_borrow_child_object_type_cost_per_byte") orelse 0;
            const cost = 1000 * cost_per_byte * n;
            // check_coin_deny_list records 0x403 as a loaded per-epoch config object before
            // charge_coin_transfers runs, so it stays in the effects when the charge fails.
            if (!e.inputs.contains(deny_list_id)) e.per_epoch_deny_list = true;
            if (e.gas.chargeStorageRead(cost)) |_| return .{ .kind = .InsufficientGas, .command = null };
            e.non_gas_coin_owners = n;
            // check_coin_deny_list_v2_during_execution: the result after the charge
            const latest = e.objs.latest orelse {
                e.unsupported_reason = "coin deny list state not available";
                return error.Unsupported;
            };
            if (try deny.check(arena, .{ .ctx = e.objs.ctx, .get = latest }, e.epoch, pairs.items)) |d|
                return .{ .kind = .Denied, .command = null, .denied = d };
        }
    }

    // record_execution_results (merge into the smashed state).
    for (written.values()) |w| try e.results.written.put(arena, w.id, w);
    for (loaded.keys()) |id| try e.results.modified.put(arena, id, {});
    for (p.new_ids.keys()) |id| try e.results.created.put(arena, id, {});
    for (p.deleted_ids.keys()) |id| {
        try e.results.deleted.put(arena, id, {});
        _ = e.results.written.swapRemove(id);
        try e.results.modified.put(arena, id, {});
    }
    return null;
}

fn cfgMaxObjectSize(cfg: *const protocol.ProtocolConfig) ?u64 {
    return cfg.getOpt("max_move_object_size");
}

fn intoEffects(e: *Exec, epoch: u64, summary: gas_mod.GasCostSummary, err: ?ExecError, deps: []const [32]u8) !Output {
    const arena = e.arena;
    // update_version_and_previous_tx + object bytes.
    var written: std.ArrayList(Written) = .empty;
    for (e.results.written.values()) |*w| {
        w.bytes = try writeBytes(arena, w, e.lamport, &e.tx_digest);
        try written.append(arena, .{ .id = w.id, .bytes = w.bytes });
    }
    if (e.effects_v1) return .{ .effects = try effectsV1(e, epoch, summary, err, deps), .written = written.items };
    // changed objects: created, deleted, modified and written ids, sorted.
    var ids: std.ArrayList([32]u8) = .empty;
    for (e.results.created.keys()) |id| try ids.append(arena, id);
    for (e.results.deleted.keys()) |id| try ids.append(arena, id);
    for (e.results.modified.keys()) |id| try ids.append(arena, id);
    for (e.results.written.keys()) |id| try ids.append(arena, id);
    std.mem.sort([32]u8, ids.items, {}, lessBytes);
    var changes: std.ArrayList(struct { types.ObjectID, types.EffectsObjectChange }) = .empty;
    var gas_index: ?u32 = null;
    for (ids.items, 0..) |id, k| {
        if (k > 0 and std.mem.eql(u8, &ids.items[k - 1], &id)) continue;
        const in_state: types.ObjectIn = if (e.results.modified.contains(id)) blk: {
            const in = e.input(&id);
            break :blk .{ .Exist = .{ .{ .{ .@"0" = in.view.version }, .{ .@"0" = .{ .@"0" = in.view.digest() } } }, try inputOwner(arena, in) } };
        } else .NotExist;
        const out_state: types.ObjectOut = if (e.results.written.getPtr(id)) |w|
            .{ .ObjectWrite = .{ .{ .@"0" = .{ .@"0" = types.digest.objectDigest(w.bytes) } }, try ownerOf(arena, w.owner_raw, w.owner) } }
        else
            .NotExist;
        const op: types.IDOperation = if (e.results.created.contains(id)) .Created else if (e.results.deleted.contains(id)) .Deleted else .None;
        if (std.mem.eql(u8, &id, &e.gas_ids[0])) gas_index = @intCast(changes.items.len);
        try changes.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .input_state = in_state, .output_state = out_state, .id_operation = op } });
    }
    var unchanged: std.ArrayList(struct { types.ObjectID, types.UnchangedConsensusKind }) = .empty;
    // compute_unchanged_consensus_objects: shared inputs in transaction order that did not
    // change (read-only roots at their input version), then the per-epoch config objects.
    for (e.shared_ids.items) |id| {
        if (e.results.modified.contains(id) or e.results.written.contains(id) or e.results.deleted.contains(id)) continue;
        const in = e.input(&id);
        try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .ReadOnlyRoot = .{ .{ .@"0" = in.view.version }, .{ .@"0" = .{ .@"0" = in.view.digest() } } } } });
    }
    if (e.per_epoch_deny_list) try unchanged.append(arena, .{ .{ .@"0" = .{ .@"0" = deny_list_id } }, .PerEpochConfig });
    const dep_list = try arena.alloc(types.TransactionDigest, deps.len);
    for (deps, dep_list) |d, *o| o.* = .{ .@"0" = .{ .@"0" = d } };
    const status = statusOf(err);
    const fx: types.TransactionEffects = .{ .V2 = .{
        .status = status,
        .executed_epoch = epoch,
        .gas_used = .{
            .computationCost = summary.computation_cost,
            .storageCost = summary.storage_cost,
            .storageRebate = summary.storage_rebate,
            .nonRefundableStorageFee = summary.non_refundable_storage_fee,
        },
        .transaction_digest = .{ .@"0" = .{ .@"0" = e.tx_digest } },
        .gas_object_index = gas_index,
        .events_digest = null,
        .dependencies = dep_list,
        .lamport_version = .{ .@"0" = e.lamport },
        .changed_objects = changes.items,
        .unchanged_consensus_objects = unchanged.items,
        .aux_data_digest = null,
    } };
    return .{ .effects = try bcs.encodeAlloc(types.TransactionEffects, arena, &fx), .written = written.items };
}

fn statusOf(err: ?ExecError) types.ExecutionStatus {
    return if (err) |x| .{ .Failure = .{ .@"error" = switch (x.kind) {
        .InsufficientGas => .InsufficientGas,
        .InvariantViolation => .InvariantViolation,
        .InsufficientCoinBalance => .InsufficientCoinBalance,
        .CoinBalanceOverflow => .CoinBalanceOverflow,
        .InvalidTransferObject => .{ .CommandArgumentError = .{ .arg_idx = x.arg_idx, .kind = .InvalidTransferObject } },
        .InvalidTransferObjectKind => .InvalidTransferObject,
        .TypeMismatch => .{ .CommandArgumentError = .{ .arg_idx = x.arg_idx, .kind = .TypeMismatch } },
        .Denied => x.denied.?.kind(),
    }, .command = x.command } } else .Success;
}

fn objRef(id: [32]u8, version: u64, digest: [32]u8) struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest } {
    return .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = version }, .{ .@"0" = .{ .@"0" = digest } } };
}

const object_digest_deleted: [32]u8 = @splat(99);
const object_digest_wrapped: [32]u8 = @splat(88);

/// temporary_store.rs `into_effects_v1` (v1/v2; v0's `to_effects` builds the same lists): written
/// objects in id order (mutated when they were inputs, else created or unwrapped), then the
/// modified objects not written in id order (deleted or wrapped), then deleted ids never
/// loaded; `modified_at_versions` lists the mutated, then the deleted.
fn effectsV1(e: *Exec, epoch: u64, summary: gas_mod.GasCostSummary, err: ?ExecError, deps: []const [32]u8) ![]const u8 {
    const arena = e.arena;
    const Ref = struct { types.ObjectID, types.SequenceNumber, types.ObjectDigest };
    const RefOwner = struct { Ref, types.Owner };
    var modified_at: std.ArrayList(struct { types.ObjectID, types.SequenceNumber }) = .empty;
    var deleted_at: std.ArrayList(struct { types.ObjectID, types.SequenceNumber }) = .empty;
    var created: std.ArrayList(RefOwner) = .empty;
    var mutated: std.ArrayList(RefOwner) = .empty;
    var unwrapped: std.ArrayList(RefOwner) = .empty;
    var deleted: std.ArrayList(Ref) = .empty;
    var unwrapped_then_deleted: std.ArrayList(Ref) = .empty;
    var wrapped: std.ArrayList(Ref) = .empty;
    var gas_object: ?RefOwner = null;

    const wids = try arena.dupe([32]u8, e.results.written.keys());
    std.mem.sort([32]u8, wids, {}, lessBytes);
    for (wids) |id| {
        const w = e.results.written.getPtr(id).?;
        const r: RefOwner = .{ objRef(id, e.lamport, types.digest.objectDigest(w.bytes)), try ownerOf(arena, w.owner_raw, w.owner) };
        if (e.results.modified.contains(id)) {
            try modified_at.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = e.input(&id).view.version } });
            try mutated.append(arena, r);
        } else if (e.results.created.contains(id)) {
            try created.append(arena, r);
        } else try unwrapped.append(arena, r);
        if (std.mem.eql(u8, &id, &e.gas_ids[0])) gas_object = r;
    }
    const mids = try arena.dupe([32]u8, e.results.modified.keys());
    std.mem.sort([32]u8, mids, {}, lessBytes);
    for (mids) |id| {
        if (e.results.written.contains(id)) continue;
        try deleted_at.append(arena, .{ .{ .@"0" = .{ .@"0" = id } }, .{ .@"0" = e.input(&id).view.version } });
        if (e.results.deleted.contains(id))
            try deleted.append(arena, objRef(id, e.lamport, object_digest_deleted))
        else
            try wrapped.append(arena, objRef(id, e.lamport, object_digest_wrapped));
    }
    const dids = try arena.dupe([32]u8, e.results.deleted.keys());
    std.mem.sort([32]u8, dids, {}, lessBytes);
    for (dids) |id| {
        if (e.results.modified.contains(id)) continue;
        try unwrapped_then_deleted.append(arena, objRef(id, e.lamport, object_digest_deleted));
    }
    try modified_at.appendSlice(arena, deleted_at.items);
    // shared_objects: every shared input at its input version, in transaction order.
    const shared_refs = try arena.alloc(Ref, e.shared_ids.items.len);
    for (e.shared_ids.items, shared_refs) |id, *o| {
        const in = e.input(&id);
        o.* = objRef(id, in.view.version, in.view.digest());
    }
    const dep_list = try arena.alloc(types.TransactionDigest, deps.len);
    for (deps, dep_list) |d, *o| o.* = .{ .@"0" = .{ .@"0" = d } };
    const fx: types.TransactionEffects = .{ .V1 = .{
        .status = statusOf(err),
        .executed_epoch = epoch,
        .gas_used = .{
            .computationCost = summary.computation_cost,
            .storageCost = summary.storage_cost,
            .storageRebate = summary.storage_rebate,
            .nonRefundableStorageFee = summary.non_refundable_storage_fee,
        },
        .modified_at_versions = modified_at.items,
        .shared_objects = shared_refs,
        .transaction_digest = .{ .@"0" = .{ .@"0" = e.tx_digest } },
        .created = created.items,
        .mutated = mutated.items,
        .unwrapped = unwrapped.items,
        .deleted = deleted.items,
        .unwrapped_then_deleted = unwrapped_then_deleted.items,
        .wrapped = wrapped.items,
        .gas_object = gas_object orelse return error.Unsupported,
        .events_digest = null,
        .dependencies = dep_list,
    } };
    return bcs.encodeAlloc(types.TransactionEffects, arena, &fx);
}
